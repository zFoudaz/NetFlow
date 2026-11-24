use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::VpnProvider;
use crate::storage::{default_netflow_dir, write_atomic};

/// Errors returned by [`RecoveryStore`] operations.
#[derive(Debug, Error)]
pub enum RecoveryError {
    /// Existing recovery snapshot could not be parsed as valid JSON.
    #[error("recovery snapshot at '{path}' is corrupted: {source}")]
    Corrupted {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    /// Underlying filesystem I/O failure.
    #[error("i/o error: {0}")]
    Io(#[from] io::Error),
    /// Snapshot serialization failure.
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Snapshot of a single IPv4 or IPv6 routing table entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RouteRecord {
    pub interface_index: u32,
    pub destination_prefix: String,
    pub next_hop: String,
    pub route_metric: u32,
    pub is_ipv6: bool,
}

/// Pre-NetFlow IP interface metric settings captured before modification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InterfaceMetricSnapshot {
    pub interface_index: u32,
    pub is_ipv6: bool,
    pub original_metric: u32,
    pub automatic_metric: bool,
}

/// Pre-NetFlow Windows Internet Settings system proxy values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemProxySnapshot {
    pub proxy_enable: u32,
    pub proxy_server: Option<String>,
    pub proxy_override: Option<String>,
}

/// Pre-NetFlow baseline and NetFlow-applied routing state for a single VPN provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnRecoveryEntry {
    pub provider: VpnProvider,
    pub removed_routes: Vec<RouteRecord>,
    pub added_routes: Vec<RouteRecord>,
    pub metric_snapshots: Vec<InterfaceMetricSnapshot>,
    pub warp_previous_mode: Option<String>,
}

/// Full crash-recovery snapshot persisted before NetFlow mutates OS network state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecoverySnapshot {
    pub created_at: String,
    pub system_proxy: Option<SystemProxySnapshot>,
    pub vpn_entries: HashMap<VpnProvider, VpnRecoveryEntry>,
    pub pinned_host_routes: Vec<RouteRecord>,
}

impl RecoverySnapshot {
    /// Inserts a VPN recovery entry only if no baseline entry for `entry.provider` exists yet.
    ///
    /// Returns `true` if inserted, or `false` if a pre-existing baseline entry was preserved
    /// (preventing hot-switch operations from overwriting pre-NetFlow state).
    pub fn insert_vpn_if_absent(&mut self, entry: VpnRecoveryEntry) -> bool {
        match self.vpn_entries.entry(entry.provider) {
            Entry::Occupied(_) => false,
            Entry::Vacant(slot) => {
                slot.insert(entry);
                true
            }
        }
    }
}

/// Returns the default per-user recovery snapshot path (`%APPDATA%\NetFlow\recovery.json`).
pub fn default_recovery_path() -> PathBuf {
    default_netflow_dir().join("recovery.json")
}

/// Atomic file store for crash-recovery snapshots.
#[derive(Debug, Clone)]
pub struct RecoveryStore {
    path: PathBuf,
}

impl RecoveryStore {
    /// Creates a new [`RecoveryStore`] targeting `path`.
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// Returns the recovery snapshot file path used by this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Loads the persisted [`RecoverySnapshot`], returning `Ok(None)` if no snapshot file exists.
    ///
    /// Returns `Err(RecoveryError::Corrupted { .. })` if the file exists but cannot be parsed.
    pub fn load(&self) -> Result<Option<RecoverySnapshot>, RecoveryError> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(RecoveryError::Io(err)),
        };

        let snapshot = serde_json::from_slice(&bytes).map_err(|source| RecoveryError::Corrupted {
            path: self.path.clone(),
            source,
        })?;
        Ok(Some(snapshot))
    }

    /// Atomically writes `snapshot` to disk via temp file + flush + `sync_all` + rename.
    pub fn save_atomic(&self, snapshot: &RecoverySnapshot) -> Result<(), RecoveryError> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(snapshot)?;
        write_atomic(&self.path, &bytes)?;
        Ok(())
    }

    /// Removes the recovery snapshot file if present; succeeds idempotently when already absent.
    pub fn clear(&self) -> Result<(), RecoveryError> {
        match fs::remove_file(&self.path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(RecoveryError::Io(err)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Component, PathBuf};

    use uuid::Uuid;

    use super::*;
    use crate::model::VpnProvider;

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "netflow_recovery_test_{}_{}",
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

    #[test]
    fn test_save_atomic_load_clear_roundtrip() {
        let temp = TempDirGuard::new("roundtrip");
        let recovery_path = temp.path().join("nested").join("recovery.json");
        let store = RecoveryStore::new(recovery_path.clone());

        assert_eq!(store.path(), recovery_path.as_path());
        assert_eq!(store.load().expect("load when absent"), None);
        store.clear().expect("clear when already absent is idempotent");

        let mut vpn_entries = HashMap::new();
        vpn_entries.insert(
            VpnProvider::CloudflareWarp,
            VpnRecoveryEntry {
                provider: VpnProvider::CloudflareWarp,
                removed_routes: vec![
                    RouteRecord {
                        interface_index: 12,
                        destination_prefix: "0.0.0.0/0".to_string(),
                        next_hop: "172.16.0.1".to_string(),
                        route_metric: 5,
                        is_ipv6: false,
                    },
                    RouteRecord {
                        interface_index: 12,
                        destination_prefix: "::/0".to_string(),
                        next_hop: "fe80::1".to_string(),
                        route_metric: 5,
                        is_ipv6: true,
                    },
                ],
                added_routes: vec![RouteRecord {
                    interface_index: 7,
                    destination_prefix: "162.159.192.1/32".to_string(),
                    next_hop: "192.168.1.1".to_string(),
                    route_metric: 10,
                    is_ipv6: false,
                }],
                metric_snapshots: vec![
                    InterfaceMetricSnapshot {
                        interface_index: 7,
                        is_ipv6: false,
                        original_metric: 25,
                        automatic_metric: true,
                    },
                    InterfaceMetricSnapshot {
                        interface_index: 7,
                        is_ipv6: true,
                        original_metric: 35,
                        automatic_metric: false,
                    },
                ],
                warp_previous_mode: Some("warp".to_string()),
            },
        );

        let snapshot = RecoverySnapshot {
            created_at: "2026-11-24T04:00:00Z".to_string(),
            system_proxy: Some(SystemProxySnapshot {
                proxy_enable: 1,
                proxy_server: Some("127.0.0.1:7890".to_string()),
                proxy_override: Some("localhost;127.*;10.*".to_string()),
            }),
            vpn_entries,
            pinned_host_routes: vec![RouteRecord {
                interface_index: 7,
                destination_prefix: "1.1.1.1/32".to_string(),
                next_hop: "192.168.1.1".to_string(),
                route_metric: 15,
                is_ipv6: false,
            }],
        };

        store.save_atomic(&snapshot).expect("save atomic");
        assert!(recovery_path.is_file());

        // Verify camelCase serialization format on disk.
        let raw = fs::read_to_string(&recovery_path).expect("read saved recovery.json");
        assert!(raw.contains("\"createdAt\""));
        assert!(raw.contains("\"systemProxy\""));
        assert!(raw.contains("\"vpnEntries\""));
        assert!(raw.contains("\"pinnedHostRoutes\""));
        assert!(raw.contains("\"warpPreviousMode\""));
        assert!(raw.contains("\"automaticMetric\""));

        let loaded = store
            .load()
            .expect("load saved snapshot")
            .expect("snapshot exists");
        assert_eq!(loaded, snapshot);

        // Overwrite atomically and verify no stray .tmp files remain.
        let mut updated = snapshot.clone();
        updated.created_at = "2026-11-24T04:05:00Z".to_string();
        store.save_atomic(&updated).expect("overwrite atomic");

        let dir_entries: Vec<_> = fs::read_dir(recovery_path.parent().expect("parent"))
            .expect("read parent dir")
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert_eq!(dir_entries, vec!["recovery.json".to_string()]);
        assert_eq!(store.load().expect("reload updated"), Some(updated));

        store.clear().expect("clear existing snapshot");
        assert!(!recovery_path.exists());
        assert_eq!(store.load().expect("load after clear"), None);
        store.clear().expect("second clear is idempotent");
    }

    #[test]
    fn test_preserves_existing_vpn_entry_when_merging_hot_switch() {
        let mut snapshot = RecoverySnapshot {
            created_at: "2026-11-24T04:00:00Z".to_string(),
            system_proxy: None,
            vpn_entries: HashMap::new(),
            pinned_host_routes: Vec::new(),
        };

        let baseline_karing = VpnRecoveryEntry {
            provider: VpnProvider::Karing,
            removed_routes: vec![RouteRecord {
                interface_index: 19,
                destination_prefix: "0.0.0.0/0".to_string(),
                next_hop: "172.19.0.1".to_string(),
                route_metric: 1,
                is_ipv6: false,
            }],
            added_routes: Vec::new(),
            metric_snapshots: vec![InterfaceMetricSnapshot {
                interface_index: 19,
                is_ipv6: false,
                original_metric: 5,
                automatic_metric: false,
            }],
            warp_previous_mode: None,
        };

        assert!(snapshot.insert_vpn_if_absent(baseline_karing.clone()));

        // During a hot-switch, NetFlow must NOT overwrite the pre-NetFlow baseline for Karing.
        let hot_switch_karing = VpnRecoveryEntry {
            provider: VpnProvider::Karing,
            removed_routes: Vec::new(),
            added_routes: vec![RouteRecord {
                interface_index: 19,
                destination_prefix: "0.0.0.0/1".to_string(),
                next_hop: "172.19.0.1".to_string(),
                route_metric: 50,
                is_ipv6: false,
            }],
            metric_snapshots: Vec::new(),
            warp_previous_mode: None,
        };

        assert!(!snapshot.insert_vpn_if_absent(hot_switch_karing));
        assert_eq!(
            snapshot.vpn_entries.get(&VpnProvider::Karing),
            Some(&baseline_karing)
        );

        // A new provider (e.g. OpenVpn) introduced by the hot-switch IS recorded.
        let openvpn_entry = VpnRecoveryEntry {
            provider: VpnProvider::OpenVpn,
            removed_routes: Vec::new(),
            added_routes: Vec::new(),
            metric_snapshots: Vec::new(),
            warp_previous_mode: None,
        };
        assert!(snapshot.insert_vpn_if_absent(openvpn_entry.clone()));
        assert_eq!(
            snapshot.vpn_entries.get(&VpnProvider::OpenVpn),
            Some(&openvpn_entry)
        );
    }

    #[test]
    fn test_corrupted_recovery_json_returns_typed_error_without_panicking() {
        let temp = TempDirGuard::new("corrupted");
        let recovery_path = temp.path().join("recovery.json");
        fs::write(&recovery_path, b"{ \"createdAt\": \"2026-11-24\", broken")
            .expect("write corrupted json");

        let store = RecoveryStore::new(recovery_path.clone());
        let err = store
            .load()
            .expect_err("corrupted JSON should return RecoveryError::Corrupted");
        assert!(matches!(err, RecoveryError::Corrupted { .. }));
        assert!(err.to_string().contains("corrupted"));

        // Truncated/empty file also returns Corrupted without panicking.
        fs::write(&recovery_path, b"").expect("write empty file");
        let empty_err = store
            .load()
            .expect_err("empty file should return RecoveryError::Corrupted");
        assert!(matches!(empty_err, RecoveryError::Corrupted { .. }));
    }

    #[test]
    fn test_default_recovery_path_ends_with_netflow_recovery_json() {
        let path = default_recovery_path();
        let components: Vec<_> = path
            .components()
            .filter_map(|c| match c {
                Component::Normal(s) => s.to_str(),
                _ => None,
            })
            .collect();
        let len = components.len();
        assert!(len >= 2);
        assert_eq!(components[len - 2], "NetFlow");
        assert_eq!(components[len - 1], "recovery.json");
    }
}
