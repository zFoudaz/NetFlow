use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use thiserror::Error;
use uuid::Uuid;

use crate::model::SavedWorkflow;

/// Errors returned by [`WorkflowStore`] operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("invalid workflow id '{0}'")]
    InvalidId(String),
    #[error("workflow name must not be empty")]
    InvalidName,
    #[error("a workflow named '{0}' already exists")]
    DuplicateName(String),
    #[error("workflow '{0}' was not found")]
    NotFound(String),
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Returns the default per-user NetFlow data directory (`%APPDATA%\NetFlow`).
pub(crate) fn default_netflow_dir() -> PathBuf {
    if let Some(appdata) = std::env::var_os("APPDATA").filter(|v| !v.is_empty()) {
        return PathBuf::from(appdata).join("NetFlow");
    }
    if let Some(home) = std::env::var_os("HOME").filter(|v| !v.is_empty()) {
        return PathBuf::from(home).join(".config").join("NetFlow");
    }
    std::env::temp_dir().join("NetFlow")
}

/// Returns the default per-user directory for NetFlow saved workflows (`%APPDATA%\NetFlow\workflows`).
pub fn default_workflows_dir() -> PathBuf {
    default_netflow_dir().join("workflows")
}

/// Persistent store for named NetFlow workflows backed by `<id>.json` files.
#[derive(Debug, Clone)]
pub struct WorkflowStore {
    dir: PathBuf,
}

impl WorkflowStore {
    /// Creates a new [`WorkflowStore`] rooted at `dir`.
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Returns the root directory used by this store.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Lists all saved workflows sorted by `updated_at` descending.
    pub fn list(&self) -> Result<Vec<SavedWorkflow>, StorageError> {
        if !self.dir.exists() {
            return Ok(Vec::new());
        }

        let mut workflows = Vec::new();
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() && path.extension() == Some(OsStr::new("json")) {
                let bytes = fs::read(&path)?;
                let workflow: SavedWorkflow = serde_json::from_slice(&bytes)?;
                workflows.push(workflow);
            }
        }

        workflows.sort_by(compare_updated_at_desc);
        Ok(workflows)
    }

    /// Loads a single saved workflow by ID.
    pub fn load(&self, id: &str) -> Result<SavedWorkflow, StorageError> {
        validate_id(id)?;
        let path = self.workflow_path(id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(StorageError::NotFound(id.to_string()));
            }
            Err(err) => return Err(StorageError::Io(err)),
        };
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Persists a workflow atomically as `<id>.json`, creating the store directory if needed.
    pub fn save(&self, workflow: &SavedWorkflow) -> Result<SavedWorkflow, StorageError> {
        validate_id(&workflow.id)?;
        let name = normalize_name(&workflow.name)?;
        fs::create_dir_all(&self.dir)?;
        self.ensure_unique_name(&name, Some(&workflow.id))?;

        let updated_at = if workflow.updated_at.trim().is_empty() {
            now_rfc3339()
        } else {
            workflow.updated_at.clone()
        };

        let to_save = SavedWorkflow {
            id: workflow.id.clone(),
            name,
            updated_at,
            graph: workflow.graph.clone(),
        };

        self.write_workflow(&to_save)?;
        Ok(to_save)
    }

    /// Renames an existing workflow without changing its ID.
    pub fn rename(&self, id: &str, new_name: &str) -> Result<SavedWorkflow, StorageError> {
        let mut workflow = self.load(id)?;
        let name = normalize_name(new_name)?;
        self.ensure_unique_name(&name, Some(id))?;

        workflow.name = name;
        workflow.updated_at = now_rfc3339();
        self.write_workflow(&workflow)?;
        Ok(workflow)
    }

    /// Duplicates an existing workflow under a fresh UUID and new name.
    pub fn duplicate(&self, id: &str, new_name: &str) -> Result<SavedWorkflow, StorageError> {
        let source = self.load(id)?;
        let name = normalize_name(new_name)?;
        self.ensure_unique_name(&name, None)?;

        let duplicated = SavedWorkflow {
            id: Uuid::new_v4().to_string(),
            name,
            updated_at: now_rfc3339(),
            graph: source.graph,
        };
        self.write_workflow(&duplicated)?;
        Ok(duplicated)
    }

    /// Deletes a saved workflow by ID.
    pub fn delete(&self, id: &str) -> Result<(), StorageError> {
        validate_id(id)?;
        let path = self.workflow_path(id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                Err(StorageError::NotFound(id.to_string()))
            }
            Err(err) => Err(StorageError::Io(err)),
        }
    }

    fn workflow_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.json"))
    }

    fn ensure_unique_name(&self, name: &str, ignore_id: Option<&str>) -> Result<(), StorageError> {
        let target_lower = name.to_lowercase();
        for existing in self.list()? {
            if Some(existing.id.as_str()) == ignore_id {
                continue;
            }
            if existing.name.trim().to_lowercase() == target_lower {
                return Err(StorageError::DuplicateName(name.to_string()));
            }
        }
        Ok(())
    }

    fn write_workflow(&self, workflow: &SavedWorkflow) -> Result<(), StorageError> {
        let bytes = serde_json::to_vec_pretty(workflow)?;
        let target = self.workflow_path(&workflow.id);
        write_atomic(&target, &bytes)?;
        Ok(())
    }
}

fn validate_id(id: &str) -> Result<(), StorageError> {
    if id.trim().is_empty()
        || id != id.trim()
        || id == "."
        || id.ends_with('.')
        || id.contains('/')
        || id.contains('\\')
        || id.contains("..")
        || id.contains(':')
        || id.contains('\0')
    {
        return Err(StorageError::InvalidId(id.to_string()));
    }

    let mut components = Path::new(id).components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(part)), None) if part == OsStr::new(id) => Ok(()),
        _ => Err(StorageError::InvalidId(id.to_string())),
    }
}

fn normalize_name(name: &str) -> Result<String, StorageError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(StorageError::InvalidName);
    }
    Ok(trimmed.to_string())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn compare_updated_at_desc(a: &SavedWorkflow, b: &SavedWorkflow) -> std::cmp::Ordering {
    let ord = match (
        DateTime::parse_from_rfc3339(&a.updated_at),
        DateTime::parse_from_rfc3339(&b.updated_at),
    ) {
        (Ok(dt_a), Ok(dt_b)) => dt_b.cmp(&dt_a),
        _ => b.updated_at.cmp(&a.updated_at),
    };
    ord.then_with(|| a.id.cmp(&b.id))
}

pub(crate) fn write_atomic(target: &Path, bytes: &[u8]) -> io::Result<()> {
    let parent = target.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "target path has no parent")
    })?;
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid target file name")
        })?;

    let tmp_path = parent.join(format!("{file_name}.{}.tmp", Uuid::new_v4()));

    let write_result = (|| -> io::Result<()> {
        let mut file: File = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)?;
        file.write_all(bytes)?;
        file.flush()?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(err) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    if let Err(err) = fs::rename(&tmp_path, target) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        NodeKind, VpnNodeSettings, VpnProvider, WorkflowEdge, WorkflowGraph, WorkflowNode,
    };

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "netflow_storage_test_{}_{}",
                prefix,
                Uuid::new_v4()
            ));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self) -> &PathBuf {
            &self.0
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn sample_graph(interface_alias: &str) -> WorkflowGraph {
        WorkflowGraph {
            nodes: vec![
                WorkflowNode {
                    id: "if-1".to_string(),
                    x: 100.0,
                    y: 200.0,
                    kind: NodeKind::Interface {
                        interface_alias: interface_alias.to_string(),
                        is_default: false,
                    },
                },
                WorkflowNode {
                    id: "vpn-1".to_string(),
                    x: 350.0,
                    y: 200.0,
                    kind: NodeKind::Vpn {
                        provider: VpnProvider::Karing,
                        is_default: true,
                        settings: VpnNodeSettings {
                            karing_port_override: Some(3067),
                            openvpn_adapter_override: None,
                            openvpn_server_ip_override: None,
                        },
                    },
                },
                WorkflowNode {
                    id: "apps-1".to_string(),
                    x: 600.0,
                    y: 200.0,
                    kind: NodeKind::Apps {
                        apps: vec!["game.exe".to_string(), "discord.exe".to_string()],
                    },
                },
            ],
            edges: vec![
                WorkflowEdge {
                    id: "e-1".to_string(),
                    source: "if-1".to_string(),
                    target: "vpn-1".to_string(),
                },
                WorkflowEdge {
                    id: "e-2".to_string(),
                    source: "vpn-1".to_string(),
                    target: "apps-1".to_string(),
                },
            ],
        }
    }

    #[test]
    fn test_save_list_load_roundtrip() {
        let temp = TempDirGuard::new("roundtrip");
        let store_dir = temp.path().join("nested").join("workflows");
        let store = WorkflowStore::new(store_dir);

        assert!(store.list().expect("list on missing dir").is_empty());

        let gaming = SavedWorkflow {
            id: "wf-gaming".to_string(),
            name: "Gaming".to_string(),
            updated_at: "2026-11-24T01:00:00Z".to_string(),
            graph: sample_graph("Ethernet"),
        };
        let work = SavedWorkflow {
            id: "wf-work".to_string(),
            name: "Work".to_string(),
            updated_at: "2026-11-24T02:00:00Z".to_string(),
            graph: sample_graph("Wi-Fi"),
        };

        store.save(&gaming).expect("save gaming");
        store.save(&work).expect("save work");

        let listed = store.list().expect("list workflows");
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, "wf-work");
        assert_eq!(listed[1].id, "wf-gaming");

        let loaded_gaming = store.load("wf-gaming").expect("load gaming");
        assert_eq!(loaded_gaming, gaming);

        let loaded_work = store.load("wf-work").expect("load work");
        assert_eq!(loaded_work, work);
    }

    #[test]
    fn test_rename_duplicate_delete_workflow() {
        let temp = TempDirGuard::new("ops");
        let store = WorkflowStore::new(temp.path().to_path_buf());

        let original = SavedWorkflow {
            id: "wf-orig".to_string(),
            name: "Gaming".to_string(),
            updated_at: "2026-11-24T01:00:00Z".to_string(),
            graph: sample_graph("Ethernet"),
        };
        store.save(&original).expect("save original");

        let duplicated = store
            .duplicate("wf-orig", "Gaming Copy")
            .expect("duplicate workflow");
        assert_ne!(duplicated.id, original.id);
        assert!(!duplicated.id.is_empty());
        assert_eq!(duplicated.name, "Gaming Copy");
        assert_eq!(duplicated.graph, original.graph);
        assert!(temp.path().join(format!("{}.json", duplicated.id)).is_file());

        let renamed = store
            .rename("wf-orig", "Low Latency Gaming")
            .expect("rename workflow");
        assert_eq!(renamed.id, original.id);
        assert_eq!(renamed.name, "Low Latency Gaming");

        let reloaded = store.load(&original.id).expect("reload renamed");
        assert_eq!(reloaded.name, "Low Latency Gaming");

        store.delete(&duplicated.id).expect("delete duplicate");
        assert!(!temp.path().join(format!("{}.json", duplicated.id)).exists());
        assert!(matches!(
            store.load(&duplicated.id),
            Err(StorageError::NotFound(_))
        ));
    }

    #[test]
    fn test_atomic_write_and_missing_adapter_workflow_loads_cleanly() {
        let temp = TempDirGuard::new("atomic");
        let store = WorkflowStore::new(temp.path().to_path_buf());

        let initial = SavedWorkflow {
            id: "wf-offline".to_string(),
            name: "Travel Rig".to_string(),
            updated_at: "2026-11-24T01:00:00Z".to_string(),
            graph: sample_graph("Ethernet 99"),
        };
        store.save(&initial).expect("initial save");

        // Overwrite existing file to verify atomic replacement works cleanly on Windows.
        let updated = SavedWorkflow {
            id: "wf-offline".to_string(),
            name: "Travel Rig".to_string(),
            updated_at: "2026-11-24T03:00:00Z".to_string(),
            graph: sample_graph("Ethernet 99"),
        };
        store.save(&updated).expect("overwrite existing workflow");

        // Ensure no temporary files remain and only `<id>.json` exists.
        let entries: Vec<_> = fs::read_dir(temp.path())
            .expect("read dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(entries, vec!["wf-offline.json".to_string()]);

        // Verify leftover `.tmp` files are ignored by list() and write_atomic cleans up on rename failure.
        fs::write(temp.path().join("stray.json.tmp"), b"corrupt").expect("write stray tmp");
        let listed = store.list().expect("list ignores tmp");
        assert_eq!(listed.len(), 1);

        // If target is a directory, rename fails and leaves no leftover `.tmp` files.
        let dir_target = temp.path().join("blocked.json");
        fs::create_dir(&dir_target).expect("create blocking dir");
        assert!(write_atomic(&dir_target, b"{}").is_err());
        let leftover_tmp: Vec<_> = fs::read_dir(temp.path())
            .expect("read dir")
            .filter_map(|e| {
                let name = e.ok()?.file_name().to_string_lossy().into_owned();
                name.starts_with("blocked.json.").then_some(name)
            })
            .collect();
        assert!(leftover_tmp.is_empty());

        let loaded = store
            .load("wf-offline")
            .expect("load missing adapter workflow");
        assert_eq!(loaded, updated);
    }

    #[test]
    fn test_rejects_empty_or_duplicate_workflow_name() {
        let temp = TempDirGuard::new("validation");
        let store = WorkflowStore::new(temp.path().to_path_buf());

        let empty_name = SavedWorkflow {
            id: "wf-1".to_string(),
            name: "   ".to_string(),
            updated_at: "2026-11-24T01:00:00Z".to_string(),
            graph: sample_graph("Ethernet"),
        };
        assert!(matches!(
            store.save(&empty_name),
            Err(StorageError::InvalidName)
        ));

        let wf1 = SavedWorkflow {
            id: "wf-1".to_string(),
            name: "Gaming".to_string(),
            updated_at: "2026-11-24T01:00:00Z".to_string(),
            graph: sample_graph("Ethernet"),
        };
        store.save(&wf1).expect("save wf-1");

        // Case-insensitive duplicate with surrounding whitespace must be rejected for another ID.
        let wf2 = SavedWorkflow {
            id: "wf-2".to_string(),
            name: "  gaming  ".to_string(),
            updated_at: "2026-11-24T02:00:00Z".to_string(),
            graph: sample_graph("Wi-Fi"),
        };
        assert!(matches!(
            store.save(&wf2),
            Err(StorageError::DuplicateName(_))
        ));

        // Saving the same ID with its own name (updating) must succeed.
        store.save(&wf1).expect("updating same workflow succeeds");

        // Renaming to empty or duplicate fails.
        assert!(matches!(
            store.rename("wf-1", "   "),
            Err(StorageError::InvalidName)
        ));

        let wf3 = SavedWorkflow {
            id: "wf-3".to_string(),
            name: "Work".to_string(),
            updated_at: "2026-11-24T02:30:00Z".to_string(),
            graph: sample_graph("Wi-Fi"),
        };
        store.save(&wf3).expect("save wf-3");

        assert!(matches!(
            store.rename("wf-3", "GAMING"),
            Err(StorageError::DuplicateName(_))
        ));
        assert!(matches!(
            store.duplicate("wf-1", "work"),
            Err(StorageError::DuplicateName(_))
        ));
    }

    #[test]
    fn test_rejects_invalid_or_traversal_ids() {
        let temp = TempDirGuard::new("traversal");
        let store = WorkflowStore::new(temp.path().to_path_buf());

        for bad_id in [
            "",
            "   ",
            " wf-1",
            "wf-1.",
            "../evil",
            "..\\evil",
            "a/b",
            "a\\b",
            "C:evil",
            "..",
            ".",
        ] {
            assert!(
                matches!(store.load(bad_id), Err(StorageError::InvalidId(_))),
                "load should reject id {:?}",
                bad_id
            );
            assert!(
                matches!(store.delete(bad_id), Err(StorageError::InvalidId(_))),
                "delete should reject id {:?}",
                bad_id
            );
            assert!(
                matches!(
                    store.rename(bad_id, "Valid"),
                    Err(StorageError::InvalidId(_))
                ),
                "rename should reject id {:?}",
                bad_id
            );
            assert!(
                matches!(
                    store.duplicate(bad_id, "Valid"),
                    Err(StorageError::InvalidId(_))
                ),
                "duplicate should reject id {:?}",
                bad_id
            );
            let wf = SavedWorkflow {
                id: bad_id.to_string(),
                name: "Valid".to_string(),
                updated_at: "2026-11-24T01:00:00Z".to_string(),
                graph: sample_graph("Ethernet"),
            };
            assert!(
                matches!(store.save(&wf), Err(StorageError::InvalidId(_))),
                "save should reject id {:?}",
                bad_id
            );
        }
    }

    #[test]
    fn test_default_workflows_dir_ends_with_netflow_workflows() {
        let dir = default_workflows_dir();
        let components: Vec<_> = dir
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect();
        let len = components.len();
        assert!(len >= 2);
        assert_eq!(components[len - 2], "NetFlow");
        assert_eq!(components[len - 1], "workflows");
    }
}
