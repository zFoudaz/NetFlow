use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::storage::{default_netflow_dir, write_atomic};

/// Persistent user preferences for NetFlow startup and automatic routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct AppSettings {
    pub start_with_windows: bool,
    pub auto_apply_last_workflow: bool,
    pub last_active_workflow_id: Option<String>,
}

/// Errors returned by [`SettingsStore`] operations.
#[derive(Debug, Error)]
pub enum SettingsError {
    #[error("settings file at '{path}' is corrupted: {source}")]
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

/// Returns the default per-user NetFlow settings file path (`%APPDATA%\NetFlow\settings.json`).
pub fn default_settings_path() -> PathBuf {
    default_netflow_dir().join("settings.json")
}

/// Atomic JSON store for [`AppSettings`].
#[derive(Debug, Clone)]
pub struct SettingsStore {
    path: PathBuf,
}

impl SettingsStore {
    /// Creates a new [`SettingsStore`] targeting `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the settings file path used by this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads persisted [`AppSettings`], returning `AppSettings::default()` when absent.
    pub fn load(&self) -> Result<AppSettings, SettingsError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(AppSettings::default()),
            Err(err) => return Err(SettingsError::Io(err)),
        };

        serde_json::from_slice(&bytes).map_err(|source| SettingsError::Corrupted {
            path: self.path.clone(),
            source,
        })
    }

    /// Atomically persists `settings` to disk via temp file + flush + `sync_all` + rename.
    pub fn save(&self, settings: &AppSettings) -> Result<(), SettingsError> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(settings)?;
        write_atomic(&self.path, &bytes)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "netflow_settings_test_{prefix}_{}",
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
    fn test_settings_store_default_when_missing_and_roundtrip() {
        let temp = TempDirGuard::new("roundtrip");
        let path = temp.path().join("nested").join("settings.json");
        let store = SettingsStore::new(path.clone());

        assert_eq!(store.path(), path.as_path());
        assert_eq!(store.load().expect("missing file returns default"), AppSettings::default());

        let updated = AppSettings {
            start_with_windows: true,
            auto_apply_last_workflow: true,
            last_active_workflow_id: Some("wf-123".to_string()),
        };
        store.save(&updated).expect("save settings");
        assert!(path.is_file());

        let raw = fs::read_to_string(&path).expect("read settings json");
        assert!(raw.contains("\"startWithWindows\""));
        assert!(raw.contains("\"autoApplyLastWorkflow\""));
        assert!(raw.contains("\"lastActiveWorkflowId\""));

        assert_eq!(store.load().expect("reload saved settings"), updated);
    }

    #[test]
    fn test_settings_store_reports_corrupted_json() {
        let temp = TempDirGuard::new("corrupt");
        let path = temp.path().join("settings.json");
        fs::write(&path, b"{not valid json").expect("write corrupt settings");

        let store = SettingsStore::new(path);
        let err = store.load().expect_err("corrupted JSON should error");
        assert!(matches!(err, SettingsError::Corrupted { .. }));
    }

    #[test]
    fn test_default_settings_path_ends_with_netflow_settings_json() {
        let path = default_settings_path();
        assert_eq!(path.file_name().and_then(|n| n.to_str()), Some("settings.json"));
        assert_eq!(
            path.parent().and_then(|p| p.file_name()).and_then(|n| n.to_str()),
            Some("NetFlow")
        );
    }
}
