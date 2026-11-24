//! Tauri IPC commands, application state, startup recovery, and sidecar path resolution.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use netflow_core::discovery::{DiscoverySnapshot, SystemDiscovery};
use netflow_core::model::{SavedWorkflow, ValidationError, WorkflowGraph};
use netflow_core::runtime::{EngineRuntime, EngineStatus, RuntimeEvent, RuntimeState};
use netflow_core::storage::WorkflowStore;
use netflow_core::validator::validate_graph;
use tauri::{AppHandle, Manager, Runtime, State};
use tokio::sync::broadcast;

/// Tauri event name emitted whenever [`EngineStatus`] changes.
pub const EVENT_STATUS: &str = "netflow://status";
/// Tauri event name emitted with live Clash API connection snapshots.
pub const EVENT_TRAFFIC: &str = "netflow://traffic";
/// Tauri event name emitted when startup crash recovery restores or fails on stale state.
pub const EVENT_RECOVERY_NOTICE: &str = "netflow://recovery-notice";

const SINGBOX_EXE_NAME: &str = "sing-box.exe";
const SINGBOX_DEV_EXE_NAME: &str = "sing-box-x86_64-pc-windows-msvc.exe";
const WINTUN_DLL_NAME: &str = "wintun.dll";

/// Resolved filesystem paths required to launch the `sing-box` sidecar with `wintun.dll`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SidecarPaths {
    pub binary_path: PathBuf,
    pub wintun_dir: PathBuf,
}

/// Resolves `sing-box` executable and `wintun.dll` working directory from explicit base paths.
///
/// Prefers bundled release locations (`resource_dir` and `exe_dir`) before falling back to
/// development paths under `dev_manifest_dir` (`src-tauri/binaries/...` and `src-tauri/resources`).
pub fn resolve_sidecar_paths_from_bases(
    resource_dir: Option<&Path>,
    exe_dir: Option<&Path>,
    dev_manifest_dir: Option<&Path>,
) -> SidecarPaths {
    let mut binary_candidates = Vec::new();
    let mut wintun_dir_candidates = Vec::new();

    for base in [resource_dir, exe_dir].into_iter().flatten() {
        binary_candidates.push(base.join(SINGBOX_EXE_NAME));
        binary_candidates.push(base.join("sing-box"));
        binary_candidates.push(base.join("binaries").join(SINGBOX_DEV_EXE_NAME));

        wintun_dir_candidates.push(base.join("resources"));
        wintun_dir_candidates.push(base.to_path_buf());
    }

    if let Some(dev_dir) = dev_manifest_dir {
        binary_candidates.push(dev_dir.join("binaries").join(SINGBOX_DEV_EXE_NAME));
        wintun_dir_candidates.push(dev_dir.join("resources"));
    }

    let binary_path = binary_candidates
        .iter()
        .find(|candidate| candidate.is_file())
        .cloned()
        .or_else(|| {
            exe_dir
                .map(|dir| dir.join(SINGBOX_EXE_NAME))
                .or_else(|| resource_dir.map(|dir| dir.join(SINGBOX_EXE_NAME)))
                .or_else(|| {
                    dev_manifest_dir.map(|dir| dir.join("binaries").join(SINGBOX_DEV_EXE_NAME))
                })
        })
        .unwrap_or_else(|| PathBuf::from(SINGBOX_EXE_NAME));

    let wintun_dir = wintun_dir_candidates
        .iter()
        .find(|dir| dir.join(WINTUN_DLL_NAME).is_file())
        .cloned()
        .or_else(|| {
            wintun_dir_candidates
                .iter()
                .find(|dir| dir.is_dir())
                .cloned()
        })
        .or_else(|| wintun_dir_candidates.into_iter().next())
        .unwrap_or_else(|| PathBuf::from("resources"));

    SidecarPaths {
        binary_path,
        wintun_dir,
    }
}

/// Resolves `sing-box` executable and `wintun.dll` working directory for the running Tauri app.
pub fn resolve_sidecar_paths<R: Runtime>(app: &AppHandle<R>) -> SidecarPaths {
    let resource_dir = app.path().resource_dir().ok();
    let exe_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let dev_manifest_dir = cfg!(debug_assertions).then(|| Path::new(env!("CARGO_MANIFEST_DIR")));

    resolve_sidecar_paths_from_bases(
        resource_dir.as_deref(),
        exe_dir.as_deref(),
        dev_manifest_dir,
    )
}

/// Returns `true` when closing the main window should hide to the system tray instead of exiting.
pub fn should_hide_on_close_state(state: RuntimeState) -> bool {
    matches!(
        state,
        RuntimeState::Active | RuntimeState::Warning | RuntimeState::Applying
    )
}

/// Shared managed application state backing Tauri IPC commands and lifecycle hooks.
pub struct AppState {
    runtime: Arc<EngineRuntime>,
    workflow_store: WorkflowStore,
    discovery: Arc<dyn SystemDiscovery>,
    recovery_notice: Mutex<Option<String>>,
    exit_started: AtomicBool,
    exit_ready: AtomicBool,
}

impl AppState {
    /// Creates a new [`AppState`] wrapping the core runtime, workflow store, and discovery provider.
    pub fn new(
        runtime: Arc<EngineRuntime>,
        workflow_store: WorkflowStore,
        discovery: Arc<dyn SystemDiscovery>,
    ) -> Self {
        Self {
            runtime,
            workflow_store,
            discovery,
            recovery_notice: Mutex::new(None),
            exit_started: AtomicBool::new(false),
            exit_ready: AtomicBool::new(false),
        }
    }

    /// Returns a reference to the managed [`EngineRuntime`].
    pub fn runtime(&self) -> &Arc<EngineRuntime> {
        &self.runtime
    }

    /// Returns a reference to the managed [`WorkflowStore`].
    pub fn workflow_store(&self) -> &WorkflowStore {
        &self.workflow_store
    }

    /// Returns a reference to the managed [`SystemDiscovery`] implementation.
    pub fn discovery(&self) -> &Arc<dyn SystemDiscovery> {
        &self.discovery
    }

    /// Stores a startup crash-recovery notice so the frontend can retrieve it after mount.
    pub fn set_recovery_notice(&self, notice: String) {
        let mut guard = self
            .recovery_notice
            .lock()
            .expect("recovery_notice mutex poisoned");
        *guard = Some(notice);
    }

    /// Returns and clears any pending startup crash-recovery notice.
    pub fn take_recovery_notice_value(&self) -> Option<String> {
        self.recovery_notice
            .lock()
            .expect("recovery_notice mutex poisoned")
            .take()
    }

    /// Returns `true` when closing the main window should hide it to the tray instead of exiting.
    pub fn should_hide_on_close(&self) -> bool {
        should_hide_on_close_state(self.runtime.status().state)
    }

    /// Marks the start of clean shutdown, returning `true` only for the first caller.
    pub fn try_begin_exit(&self) -> bool {
        self.exit_started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Marks clean shutdown (`runtime.stop()`) as finished so `ExitRequested` can proceed.
    pub fn mark_exit_ready(&self) {
        self.exit_ready.store(true, Ordering::SeqCst);
    }

    /// Returns `true` once clean shutdown has completed and the process may exit.
    pub fn is_exit_ready(&self) -> bool {
        self.exit_ready.load(Ordering::SeqCst)
    }

    /// Queries a read-only [`DiscoverySnapshot`] on a blocking worker thread.
    pub async fn fetch_discovery_snapshot(&self) -> Result<DiscoverySnapshot, String> {
        let discovery = Arc::clone(&self.discovery);
        run_blocking_cmd(move || discovery.snapshot()).await
    }

    /// Lists all saved workflows from disk on a blocking worker thread.
    pub async fn list_saved_workflows(&self) -> Result<Vec<SavedWorkflow>, String> {
        let store = self.workflow_store.clone();
        run_blocking_cmd(move || store.list()).await
    }

    /// Atomically persists a [`SavedWorkflow`] on a blocking worker thread.
    pub async fn save_saved_workflow(
        &self,
        workflow: SavedWorkflow,
    ) -> Result<SavedWorkflow, String> {
        let store = self.workflow_store.clone();
        run_blocking_cmd(move || store.save(&workflow)).await
    }

    /// Renames a saved workflow on a blocking worker thread.
    pub async fn rename_saved_workflow(
        &self,
        id: String,
        new_name: String,
    ) -> Result<SavedWorkflow, String> {
        let store = self.workflow_store.clone();
        run_blocking_cmd(move || store.rename(&id, &new_name)).await
    }

    /// Duplicates a saved workflow under a new UUID and name on a blocking worker thread.
    pub async fn duplicate_saved_workflow(
        &self,
        id: String,
        new_name: String,
    ) -> Result<SavedWorkflow, String> {
        let store = self.workflow_store.clone();
        run_blocking_cmd(move || store.duplicate(&id, &new_name)).await
    }

    /// Deletes a saved workflow by ID on a blocking worker thread.
    pub async fn delete_saved_workflow(&self, id: String) -> Result<(), String> {
        let store = self.workflow_store.clone();
        run_blocking_cmd(move || store.delete(&id)).await
    }

    /// Applies (or hot-switches to) the given workflow graph.
    pub async fn apply_workflow(
        &self,
        workflow_id: Option<String>,
        graph: WorkflowGraph,
    ) -> Result<EngineStatus, String> {
        self.runtime
            .apply(workflow_id, &graph)
            .await
            .map_err(|err| err.to_string())
    }

    /// Stops routing and restores all neutralized VPNs and Windows System Proxy.
    pub async fn stop_routing(&self) -> Result<EngineStatus, String> {
        self.runtime.stop().await.map_err(|err| err.to_string())
    }

    /// Returns a snapshot of the current [`EngineStatus`].
    pub fn engine_status(&self) -> EngineStatus {
        self.runtime.status()
    }
}

/// Runs startup stale crash recovery, drains the matching `RecoveryNotice` from `event_rx`
/// so it is not emitted twice by the async forwarder, and stores it in `state`.
pub fn run_startup_recovery(
    state: &AppState,
    event_rx: &mut broadcast::Receiver<RuntimeEvent>,
) -> Option<String> {
    match state.runtime().recover_if_stale() {
        Ok(false) => None,
        Ok(true) => {
            let mut captured = None;
            while let Ok(event) = event_rx.try_recv() {
                if let RuntimeEvent::RecoveryNotice(notice) = event {
                    captured = Some(notice);
                }
            }
            let notice = captured.unwrap_or_else(|| {
                "Recovered stale NetFlow network state from previous unexpected exit.".to_string()
            });
            state.set_recovery_notice(notice.clone());
            Some(notice)
        }
        Err(err) => {
            let notice = format!("Startup crash recovery failed: {err}");
            state.set_recovery_notice(notice.clone());
            Some(notice)
        }
    }
}

async fn run_blocking_cmd<F, T, E>(f: F) -> Result<T, String>
where
    F: FnOnce() -> Result<T, E> + Send + 'static,
    T: Send + 'static,
    E: std::fmt::Display + Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| format!("background worker task failed: {err}"))?
        .map_err(|err| err.to_string())
}

/// Queries live Windows interfaces, VPN providers, and running processes.
#[tauri::command]
pub async fn get_discovery_snapshot(state: State<'_, AppState>) -> Result<DiscoverySnapshot, String> {
    state.fetch_discovery_snapshot().await
}

/// Validates a workflow graph structurally and semantically without modifying OS state.
#[tauri::command]
pub fn validate_workflow_graph(graph: WorkflowGraph) -> Result<(), Vec<ValidationError>> {
    validate_graph(&graph).map(|_| ())
}

/// Lists all saved workflows sorted by `updatedAt` descending.
#[tauri::command]
pub async fn list_workflows(state: State<'_, AppState>) -> Result<Vec<SavedWorkflow>, String> {
    state.list_saved_workflows().await
}

/// Saves a workflow atomically under `%APPDATA%\NetFlow\workflows\<id>.json`.
#[tauri::command]
pub async fn save_workflow(
    state: State<'_, AppState>,
    workflow: SavedWorkflow,
) -> Result<SavedWorkflow, String> {
    state.save_saved_workflow(workflow).await
}

/// Renames an existing saved workflow without changing its ID.
#[tauri::command]
pub async fn rename_workflow(
    state: State<'_, AppState>,
    id: String,
    new_name: String,
) -> Result<SavedWorkflow, String> {
    state.rename_saved_workflow(id, new_name).await
}

/// Duplicates an existing saved workflow under a fresh UUID and new name.
#[tauri::command]
pub async fn duplicate_workflow(
    state: State<'_, AppState>,
    id: String,
    new_name: String,
) -> Result<SavedWorkflow, String> {
    state.duplicate_saved_workflow(id, new_name).await
}

/// Deletes a saved workflow by ID.
#[tauri::command]
pub async fn delete_workflow(state: State<'_, AppState>, id: String) -> Result<(), String> {
    state.delete_saved_workflow(id).await
}

/// Validates, pre-flights, compiles, and applies (or hot-switches to) a workflow graph.
#[tauri::command]
pub async fn apply_workflow(
    state: State<'_, AppState>,
    workflow_id: Option<String>,
    graph: WorkflowGraph,
) -> Result<EngineStatus, String> {
    state.apply_workflow(workflow_id, graph).await
}

/// Stops `sing-box`, restores neutralized VPNs and Windows System Proxy, and clears recovery state.
#[tauri::command]
pub async fn stop_routing(state: State<'_, AppState>) -> Result<EngineStatus, String> {
    state.stop_routing().await
}

/// Returns the current engine status snapshot.
#[tauri::command]
pub fn get_engine_status(state: State<'_, AppState>) -> EngineStatus {
    state.engine_status()
}

/// Returns and clears any startup crash-recovery notice captured before WebView listeners attached.
#[tauri::command]
pub fn take_recovery_notice(state: State<'_, AppState>) -> Option<String> {
    state.take_recovery_notice_value()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Duration;

    use netflow_core::discovery::{
        DetectedVpnInfo, DiscoveryError, DiscoverySnapshot, PhysicalInterfaceInfo,
        RunningProcessInfo, SystemDiscovery,
    };
    use netflow_core::model::{
        NodeKind, SavedWorkflow, ValidationErrorCode, VpnNodeSettings, VpnProvider, WorkflowEdge,
        WorkflowGraph, WorkflowNode,
    };
    use netflow_core::recovery::{
        InterfaceMetricSnapshot, RecoverySnapshot, RecoveryStore, RouteRecord, SystemProxySnapshot,
    };
    use netflow_core::runtime::{
        EngineRuntime, EngineRuntimeConfig, RuntimeState, SidecarError, SidecarRunner,
    };
    use netflow_core::storage::WorkflowStore;
    use netflow_core::win_net::{NetOpsError, WindowsNetworkOps};

    use super::*;

    static TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

    struct TempDirGuard(PathBuf);

    impl TempDirGuard {
        fn new(prefix: &str) -> Self {
            let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "{prefix}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp test dir");
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

    struct MockDiscovery {
        snapshot: DiscoverySnapshot,
    }

    impl MockDiscovery {
        fn healthy_wifi() -> Self {
            Self {
                snapshot: DiscoverySnapshot {
                    interfaces: vec![PhysicalInterfaceInfo {
                        alias: "Wi-Fi".to_string(),
                        description: "Intel Wi-Fi 6".to_string(),
                        if_index: 12,
                        ipv4: Some("192.168.1.50".to_string()),
                        gateway_ipv4: Some("192.168.1.1".to_string()),
                        is_up: true,
                        link_speed_mbps: 866,
                        is_default_gateway: true,
                    }],
                    vpns: vec![DetectedVpnInfo {
                        provider: VpnProvider::Karing,
                        is_running: false,
                        detected_port: None,
                        adapter_alias: None,
                        adapter_if_index: None,
                        adapter_gateway: None,
                        remote_server_ip: None,
                        warp_current_mode: None,
                    }],
                    processes: vec![RunningProcessInfo {
                        exe_name: "chrome.exe".to_string(),
                        path: Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe".into()),
                    }],
                },
            }
        }
    }

    impl SystemDiscovery for MockDiscovery {
        fn snapshot(&self) -> Result<DiscoverySnapshot, DiscoveryError> {
            Ok(self.snapshot.clone())
        }
    }

    struct MockNetOps {
        system_proxy: Mutex<SystemProxySnapshot>,
    }

    impl Default for MockNetOps {
        fn default() -> Self {
            Self::with_proxy(0, None)
        }
    }

    impl MockNetOps {
        fn with_proxy(proxy_enable: u32, server: Option<&str>) -> Self {
            Self {
                system_proxy: Mutex::new(SystemProxySnapshot {
                    proxy_enable,
                    proxy_server: server.map(str::to_string),
                    proxy_override: None,
                }),
            }
        }

        fn current_proxy(&self) -> SystemProxySnapshot {
            self.system_proxy.lock().unwrap().clone()
        }
    }

    impl WindowsNetworkOps for MockNetOps {
        fn list_routes(
            &self,
            _interface_index: Option<u32>,
            _is_ipv6: bool,
        ) -> Result<Vec<RouteRecord>, NetOpsError> {
            Ok(Vec::new())
        }

        fn add_route(&self, _route: &RouteRecord) -> Result<(), NetOpsError> {
            Ok(())
        }

        fn remove_route(&self, _route: &RouteRecord) -> Result<(), NetOpsError> {
            Ok(())
        }

        fn get_interface_metric(
            &self,
            interface_index: u32,
            is_ipv6: bool,
        ) -> Result<InterfaceMetricSnapshot, NetOpsError> {
            Ok(InterfaceMetricSnapshot {
                interface_index,
                is_ipv6,
                original_metric: 25,
                automatic_metric: true,
            })
        }

        fn set_interface_metric(
            &self,
            _interface_index: u32,
            _is_ipv6: bool,
            _metric: u32,
            _automatic_metric: bool,
        ) -> Result<(), NetOpsError> {
            Ok(())
        }

        fn find_best_route_interface(
            &self,
            _dest_ipv4: &str,
        ) -> Result<Option<String>, NetOpsError> {
            Ok(Some("NetFlow-TUN".to_string()))
        }

        fn find_interface_index_by_alias(&self, alias: &str) -> Result<Option<u32>, NetOpsError> {
            if alias.eq_ignore_ascii_case("NetFlow-TUN") {
                Ok(Some(99))
            } else {
                Ok(None)
            }
        }

        fn get_system_proxy(&self) -> Result<SystemProxySnapshot, NetOpsError> {
            Ok(self.system_proxy.lock().unwrap().clone())
        }

        fn set_system_proxy(&self, snapshot: &SystemProxySnapshot) -> Result<(), NetOpsError> {
            *self.system_proxy.lock().unwrap() = snapshot.clone();
            Ok(())
        }

        fn disable_system_proxy(&self) -> Result<(), NetOpsError> {
            let mut guard = self.system_proxy.lock().unwrap();
            guard.proxy_enable = 0;
            Ok(())
        }

        fn warp_cli_get_mode(&self) -> Result<Option<String>, NetOpsError> {
            Ok(None)
        }

        fn warp_cli_set_mode(&self, _mode: &str) -> Result<(), NetOpsError> {
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockSidecar {
        alive: AtomicBool,
    }

    impl SidecarRunner for MockSidecar {
        fn spawn(&self, _config_path: &Path) -> Result<(), SidecarError> {
            self.alive.store(true, Ordering::SeqCst);
            Ok(())
        }

        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }

        fn kill(&self) -> Result<(), SidecarError> {
            self.alive.store(false, Ordering::SeqCst);
            Ok(())
        }
    }

    fn build_test_app_state(temp: &Path, net_ops: Arc<MockNetOps>) -> AppState {
        let discovery: Arc<dyn SystemDiscovery> = Arc::new(MockDiscovery::healthy_wifi());
        let sidecar: Arc<dyn SidecarRunner> = Arc::new(MockSidecar::default());
        let recovery_store = RecoveryStore::new(temp.join("recovery.json"));
        let runtime_config = EngineRuntimeConfig {
            runtime_dir: temp.join("runtime"),
            clash_api_port: 19090,
            health_poll_interval: Duration::from_secs(60),
            tun_ready_attempts: 2,
            tun_ready_retry_delay: Duration::from_millis(1),
        };
        let runtime = Arc::new(EngineRuntime::new(
            Arc::clone(&discovery),
            net_ops,
            sidecar,
            recovery_store,
            runtime_config,
        ));
        let workflow_store = WorkflowStore::new(temp.join("workflows"));
        AppState::new(runtime, workflow_store, discovery)
    }

    fn sample_valid_graph() -> WorkflowGraph {
        WorkflowGraph {
            nodes: vec![
                WorkflowNode {
                    id: "iface-wifi".to_string(),
                    x: 100.0,
                    y: 100.0,
                    kind: NodeKind::Interface {
                        interface_alias: "Wi-Fi".to_string(),
                        is_default: true,
                    },
                },
                WorkflowNode {
                    id: "apps-1".to_string(),
                    x: 360.0,
                    y: 100.0,
                    kind: NodeKind::Apps {
                        apps: vec!["chrome.exe".to_string()],
                    },
                },
            ],
            edges: vec![WorkflowEdge {
                id: "edge-1".to_string(),
                source: "iface-wifi".to_string(),
                target: "apps-1".to_string(),
            }],
        }
    }

    #[test]
    fn test_validate_workflow_graph_accepts_valid_and_rejects_invalid() {
        assert_eq!(validate_workflow_graph(sample_valid_graph()), Ok(()));

        let invalid_graph = WorkflowGraph {
            nodes: vec![
                WorkflowNode {
                    id: "vpn-karing".to_string(),
                    x: 0.0,
                    y: 0.0,
                    kind: NodeKind::Vpn {
                        provider: VpnProvider::Karing,
                        is_default: false,
                        settings: VpnNodeSettings::default(),
                    },
                },
                WorkflowNode {
                    id: "apps-a".to_string(),
                    x: 200.0,
                    y: 0.0,
                    kind: NodeKind::Apps {
                        apps: vec!["chrome.exe".to_string()],
                    },
                },
                WorkflowNode {
                    id: "apps-b".to_string(),
                    x: 200.0,
                    y: 120.0,
                    kind: NodeKind::Apps {
                        apps: vec![" CHROME.EXE ".to_string()],
                    },
                },
            ],
            edges: vec![
                WorkflowEdge {
                    id: "e1".to_string(),
                    source: "vpn-karing".to_string(),
                    target: "apps-a".to_string(),
                },
                WorkflowEdge {
                    id: "e2".to_string(),
                    source: "vpn-karing".to_string(),
                    target: "apps-b".to_string(),
                },
            ],
        };

        let errors = validate_workflow_graph(invalid_graph).expect_err("expected validation errors");
        let codes: Vec<_> = errors.iter().map(|e| e.code).collect();
        assert!(codes.contains(&ValidationErrorCode::MissingUpstreamInterface));
        assert!(codes.contains(&ValidationErrorCode::DuplicateAppAssignment));
    }

    #[test]
    fn test_resolve_sidecar_paths_prefers_bundle_dirs_over_dev_fallback() {
        let temp = TempDirGuard::new("netflow-sidecar-bundle");
        let resource_dir = temp.path().join("bundle");
        let exe_dir = temp.path().join("exe");
        let dev_dir = temp.path().join("dev");

        fs::create_dir_all(resource_dir.join("resources")).unwrap();
        fs::create_dir_all(&exe_dir).unwrap();
        fs::create_dir_all(dev_dir.join("binaries")).unwrap();
        fs::create_dir_all(dev_dir.join("resources")).unwrap();

        let bundled_bin = resource_dir.join("sing-box.exe");
        let bundled_wintun = resource_dir.join("resources").join("wintun.dll");
        fs::write(&bundled_bin, b"stub").unwrap();
        fs::write(&bundled_wintun, b"stub").unwrap();
        fs::write(
            dev_dir
                .join("binaries")
                .join("sing-box-x86_64-pc-windows-msvc.exe"),
            b"dev",
        )
        .unwrap();
        fs::write(dev_dir.join("resources").join("wintun.dll"), b"dev").unwrap();

        let resolved = resolve_sidecar_paths_from_bases(
            Some(&resource_dir),
            Some(&exe_dir),
            Some(&dev_dir),
        );
        assert_eq!(resolved.binary_path, bundled_bin);
        assert_eq!(resolved.wintun_dir, resource_dir.join("resources"));

        // Also support wintun.dll placed directly at resource_dir root
        fs::remove_file(&bundled_wintun).unwrap();
        fs::remove_dir(resource_dir.join("resources")).unwrap();
        fs::write(resource_dir.join("wintun.dll"), b"stub").unwrap();
        let resolved_flat = resolve_sidecar_paths_from_bases(
            Some(&resource_dir),
            Some(&exe_dir),
            Some(&dev_dir),
        );
        assert_eq!(resolved_flat.wintun_dir, resource_dir);
    }

    #[test]
    fn test_resolve_sidecar_paths_falls_back_to_dev_manifest_dir() {
        let temp = TempDirGuard::new("netflow-sidecar-dev");
        let empty_resource_dir = temp.path().join("empty-resource");
        let empty_exe_dir = temp.path().join("empty-exe");
        let dev_dir = temp.path().join("src-tauri");

        fs::create_dir_all(&empty_resource_dir).unwrap();
        fs::create_dir_all(&empty_exe_dir).unwrap();
        fs::create_dir_all(dev_dir.join("binaries")).unwrap();
        fs::create_dir_all(dev_dir.join("resources")).unwrap();

        let dev_bin = dev_dir
            .join("binaries")
            .join("sing-box-x86_64-pc-windows-msvc.exe");
        let dev_wintun = dev_dir.join("resources").join("wintun.dll");
        fs::write(&dev_bin, b"dev-bin").unwrap();
        fs::write(&dev_wintun, b"dev-dll").unwrap();

        let resolved = resolve_sidecar_paths_from_bases(
            Some(&empty_resource_dir),
            Some(&empty_exe_dir),
            Some(&dev_dir),
        );
        assert_eq!(resolved.binary_path, dev_bin);
        assert_eq!(resolved.wintun_dir, dev_dir.join("resources"));
    }

    #[test]
    fn test_app_state_recovery_notice_and_lifecycle_helpers() {
        let temp = TempDirGuard::new("netflow-appstate-helpers");
        let net_ops = Arc::new(MockNetOps::default());
        let state = build_test_app_state(temp.path(), net_ops);

        assert_eq!(state.take_recovery_notice_value(), None);
        state.set_recovery_notice("Recovered stale state".to_string());
        assert_eq!(
            state.take_recovery_notice_value(),
            Some("Recovered stale state".to_string())
        );
        assert_eq!(state.take_recovery_notice_value(), None);

        assert!(!should_hide_on_close_state(RuntimeState::Stopped));
        assert!(!should_hide_on_close_state(RuntimeState::Error));
        assert!(should_hide_on_close_state(RuntimeState::Active));
        assert!(should_hide_on_close_state(RuntimeState::Warning));
        assert!(should_hide_on_close_state(RuntimeState::Applying));

        assert!(!state.should_hide_on_close());
        assert!(state.try_begin_exit());
        assert!(!state.try_begin_exit());
        assert!(!state.is_exit_ready());
        state.mark_exit_ready();
        assert!(state.is_exit_ready());
    }

    #[tokio::test]
    async fn test_app_state_commands_discovery_crud_and_apply_stop() {
        let temp = TempDirGuard::new("netflow-appstate-cmds");
        let net_ops = Arc::new(MockNetOps::with_proxy(1, Some("127.0.0.1:3067")));
        let state = build_test_app_state(temp.path(), Arc::clone(&net_ops));

        let discovery = state
            .fetch_discovery_snapshot()
            .await
            .expect("fetch discovery");
        assert_eq!(discovery.interfaces.len(), 1);
        assert_eq!(discovery.interfaces[0].alias, "Wi-Fi");

        let workflow = SavedWorkflow {
            id: "wf-main".to_string(),
            name: "Main Split".to_string(),
            updated_at: String::new(),
            graph: sample_valid_graph(),
        };
        let saved = state.save_saved_workflow(workflow).await.expect("save");
        assert!(!saved.updated_at.is_empty());

        let listed = state.list_saved_workflows().await.expect("list");
        assert_eq!(listed.len(), 1);

        let renamed = state
            .rename_saved_workflow("wf-main".to_string(), "Work Split".to_string())
            .await
            .expect("rename");
        assert_eq!(renamed.name, "Work Split");

        let dup = state
            .duplicate_saved_workflow("wf-main".to_string(), "Work Copy".to_string())
            .await
            .expect("duplicate");
        assert_ne!(dup.id, "wf-main");
        assert_eq!(state.list_saved_workflows().await.unwrap().len(), 2);

        let active_status = state
            .apply_workflow(Some("wf-main".to_string()), sample_valid_graph())
            .await
            .expect("apply workflow");
        assert_eq!(active_status.state, RuntimeState::Active);
        assert_eq!(
            active_status.active_workflow_id.as_deref(),
            Some("wf-main")
        );
        assert!(state.should_hide_on_close());
        assert_eq!(net_ops.current_proxy().proxy_enable, 0);

        let stopped_status = state.stop_routing().await.expect("stop routing");
        assert_eq!(stopped_status.state, RuntimeState::Stopped);
        assert!(!state.should_hide_on_close());
        assert_eq!(net_ops.current_proxy().proxy_enable, 1);

        state
            .delete_saved_workflow(dup.id)
            .await
            .expect("delete duplicate");
        assert_eq!(state.list_saved_workflows().await.unwrap().len(), 1);
    }

    #[test]
    fn test_run_startup_recovery_captures_and_drains_notice() {
        let temp = TempDirGuard::new("netflow-startup-recovery");
        let net_ops = Arc::new(MockNetOps::with_proxy(0, None));
        let recovery_path = temp.path().join("recovery.json");
        let stale = RecoverySnapshot {
            created_at: "2026-11-24T04:00:00Z".to_string(),
            system_proxy: Some(SystemProxySnapshot {
                proxy_enable: 1,
                proxy_server: Some("127.0.0.1:3067".to_string()),
                proxy_override: None,
            }),
            vpn_entries: HashMap::new(),
            pinned_host_routes: Vec::new(),
        };
        RecoveryStore::new(recovery_path.clone())
            .save_atomic(&stale)
            .unwrap();

        let state = build_test_app_state(temp.path(), Arc::clone(&net_ops));
        let mut rx = state.runtime().subscribe_events();

        let notice = run_startup_recovery(&state, &mut rx).expect("expected recovery notice");
        assert!(notice.contains("2026-11-24T04:00:00Z"));
        assert!(!recovery_path.exists());
        assert_eq!(net_ops.current_proxy().proxy_enable, 1);
        assert_eq!(state.take_recovery_notice_value(), Some(notice));
        assert!(
            rx.try_recv().is_err(),
            "startup RecoveryNotice should be drained so it is not emitted twice"
        );
    }

    #[test]
    fn test_run_startup_recovery_records_error_notice_on_corrupted_snapshot() {
        let temp = TempDirGuard::new("netflow-startup-recovery-corrupt");
        let net_ops = Arc::new(MockNetOps::default());
        let recovery_path = temp.path().join("recovery.json");
        fs::write(&recovery_path, b"{not valid json").unwrap();

        let state = build_test_app_state(temp.path(), net_ops);
        let mut rx = state.runtime().subscribe_events();

        let notice =
            run_startup_recovery(&state, &mut rx).expect("expected error recovery notice");
        assert!(notice.starts_with("Startup crash recovery failed:"));
        assert_eq!(state.take_recovery_notice_value(), Some(notice));
        assert_eq!(state.take_recovery_notice_value(), None);
    }
}
