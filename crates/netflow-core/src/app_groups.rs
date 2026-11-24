use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::storage::{default_netflow_dir, write_atomic};

/// Reusable named group of Windows executables persisted for drag-and-drop onto any workflow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedAppGroup {
    pub id: String,
    pub name: String,
    pub apps: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon_data_url: Option<String>,
    pub updated_at: String,
}

/// Errors returned by [`AppGroupStore`] operations.
#[derive(Debug, Error)]
pub enum AppGroupStoreError {
    #[error("group name must not be empty")]
    InvalidName,
    #[error("group must contain at least one executable")]
    EmptyApps,
    #[error("app group '{0}' was not found")]
    NotFound(String),
    #[error("app groups file at '{path}' is corrupted: {source}")]
    Corrupted {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Returns the default per-user saved app groups file path (`%APPDATA%\NetFlow\app-groups.json`).
pub fn default_app_groups_path() -> PathBuf {
    default_netflow_dir().join("app-groups.json")
}

/// Atomic JSON store for reusable [`SavedAppGroup`] presets.
#[derive(Debug, Clone)]
pub struct AppGroupStore {
    path: PathBuf,
}

impl AppGroupStore {
    /// Creates a new [`AppGroupStore`] targeting `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the storage file path used by this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Lists all saved app groups sorted by `updated_at` descending (tie-broken by `name` ascending).
    pub fn list(&self) -> Result<Vec<SavedAppGroup>, AppGroupStoreError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => return Err(AppGroupStoreError::Io(err)),
        };

        let mut groups: Vec<SavedAppGroup> =
            serde_json::from_slice(&bytes).map_err(|source| AppGroupStoreError::Corrupted {
                path: self.path.clone(),
                source,
            })?;
        groups.sort_by(compare_groups_desc);
        Ok(groups)
    }

    /// Normalizes and upserts a [`SavedAppGroup`], deduplicating executables and matching by ID or case-insensitive name.
    pub fn save(&self, group: SavedAppGroup) -> Result<SavedAppGroup, AppGroupStoreError> {
        let name = group.name.trim();
        if name.is_empty() {
            return Err(AppGroupStoreError::InvalidName);
        }

        let apps = normalize_group_apps(&group.apps);
        if apps.is_empty() {
            return Err(AppGroupStoreError::EmptyApps);
        }

        let mut groups = self.list()?;
        let requested_id = group.id.trim();
        let existing_idx = groups.iter().position(|existing| {
            (!requested_id.is_empty() && existing.id == requested_id)
                || existing.name.eq_ignore_ascii_case(name)
        });

        let resolved_id = match existing_idx {
            Some(idx) => groups[idx].id.clone(),
            None if !requested_id.is_empty() => requested_id.to_string(),
            None => Uuid::new_v4().to_string(),
        };

        let icon_data_url = group
            .icon_data_url
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty());

        let saved = SavedAppGroup {
            id: resolved_id,
            name: name.to_string(),
            apps,
            icon_data_url,
            updated_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
        };

        if let Some(idx) = existing_idx {
            groups[idx] = saved.clone();
        } else {
            groups.push(saved.clone());
        }

        groups.sort_by(compare_groups_desc);
        self.write_all(&groups)?;
        Ok(saved)
    }

    /// Deletes a saved app group by `id`.
    pub fn delete(&self, id: &str) -> Result<(), AppGroupStoreError> {
        let mut groups = self.list()?;
        let initial_len = groups.len();
        groups.retain(|group| group.id != id);
        if groups.len() == initial_len {
            return Err(AppGroupStoreError::NotFound(id.to_string()));
        }
        self.write_all(&groups)
    }

    fn write_all(&self, groups: &[SavedAppGroup]) -> Result<(), AppGroupStoreError> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(groups)?;
        write_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

fn normalize_group_apps(apps: &[String]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for raw in apps {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        if seen.insert(normalized.clone()) {
            out.push(normalized);
        }
    }
    out
}

fn compare_groups_desc(a: &SavedAppGroup, b: &SavedAppGroup) -> std::cmp::Ordering {
    let parsed_a = DateTime::parse_from_rfc3339(&a.updated_at).ok();
    let parsed_b = DateTime::parse_from_rfc3339(&b.updated_at).ok();
    let time_cmp = match (parsed_a, parsed_b) {
        (Some(ta), Some(tb)) => tb.cmp(&ta),
        _ => b.updated_at.cmp(&a.updated_at),
    };
    time_cmp.then_with(|| a.name.to_ascii_lowercase().cmp(&b.name.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "netflow_app_groups_test_{prefix}_{}",
                Uuid::new_v4()
            ));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn test_app_group_store_save_list_dedup_by_name_and_delete() {
        let temp = TempDirGuard::new("roundtrip");
        let path = temp.path().join("nested").join("app-groups.json");
        let store = AppGroupStore::new(path.clone());

        assert_eq!(store.path(), path.as_path());
        assert!(store.list().expect("missing file returns empty").is_empty());

        let created = store
            .save(SavedAppGroup {
                id: String::new(),
                name: "  Browsers  ".to_string(),
                apps: vec![
                    " Chrome.exe ".to_string(),
                    "firefox.exe".to_string(),
                    "CHROME.EXE".to_string(),
                    "   ".to_string(),
                ],
                icon_data_url: Some(" data:image/png;base64,AAAA ".to_string()),
                updated_at: String::new(),
            })
            .expect("save browsers group");

        assert!(!created.id.is_empty());
        assert_eq!(created.name, "Browsers");
        assert_eq!(created.apps, vec!["chrome.exe", "firefox.exe"]);
        assert_eq!(
            created.icon_data_url.as_deref(),
            Some("data:image/png;base64,AAAA")
        );
        assert!(!created.updated_at.is_empty());
        assert!(path.is_file());

        // Saving again with matching case-insensitive name updates in place and keeps same ID
        let updated = store
            .save(SavedAppGroup {
                id: String::new(),
                name: "browsers".to_string(),
                apps: vec!["msedge.exe".to_string()],
                icon_data_url: None,
                updated_at: String::new(),
            })
            .expect("upsert by name");
        assert_eq!(updated.id, created.id);
        assert_eq!(updated.name, "browsers");
        assert_eq!(updated.apps, vec!["msedge.exe"]);

        let listed = store.list().expect("list saved groups");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0], updated);

        store.delete(&updated.id).expect("delete group");
        assert!(store.list().expect("list after delete").is_empty());
        assert!(matches!(
            store.delete(&updated.id),
            Err(AppGroupStoreError::NotFound(_))
        ));
    }

    #[test]
    fn test_app_group_store_rejects_invalid_inputs_and_corrupted_json() {
        let temp = TempDirGuard::new("validation");
        let path = temp.path().join("app-groups.json");
        let store = AppGroupStore::new(path.clone());

        assert!(matches!(
            store.save(SavedAppGroup {
                id: String::new(),
                name: "   ".to_string(),
                apps: vec!["chrome.exe".to_string()],
                icon_data_url: None,
                updated_at: String::new(),
            }),
            Err(AppGroupStoreError::InvalidName)
        ));

        assert!(matches!(
            store.save(SavedAppGroup {
                id: String::new(),
                name: "Empty".to_string(),
                apps: vec!["   ".to_string()],
                icon_data_url: None,
                updated_at: String::new(),
            }),
            Err(AppGroupStoreError::EmptyApps)
        ));

        fs::write(&path, b"{not valid json").expect("write corrupt json");
        assert!(matches!(
            store.list(),
            Err(AppGroupStoreError::Corrupted { .. })
        ));
    }

    #[test]
    fn test_default_app_groups_path_ends_with_netflow_app_groups_json() {
        let path = default_app_groups_path();
        assert_eq!(
            path.file_name().and_then(|n| n.to_str()),
            Some("app-groups.json")
        );
        assert_eq!(
            path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()),
            Some("NetFlow")
        );
    }
}
