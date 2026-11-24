use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::{broadcast, watch, Mutex as AsyncMutex};
use tokio::task::JoinHandle;

use crate::compiler::{compile_singbox_config, CompileError, CompileInput, ResolvedVpnRuntimeInfo};
use crate::discovery::{
    DetectedVpnInfo, DiscoveryError, DiscoverySnapshot, PhysicalInterfaceInfo, SystemDiscovery,
};
use crate::model::{
    NodeKind, ValidatedGraph, ValidationError, VpnProvider, WarpMode, WorkflowGraph,
};
use crate::recovery::{
    RecoveryError, RecoverySnapshot, RecoveryStore, RouteRecord, VpnRecoveryEntry,
};
use crate::storage::{default_netflow_dir, write_atomic};
use crate::traffic::{LiveConnection, TrafficMonitor};
use crate::validator::validate_graph;
use crate::vpn_adapters::{
    neutralize_vpn, pin_openvpn_dco_host_route, preflight_and_resolve_vpn, restore_vpn,
    VpnAdapterError,
};
use crate::win_net::{NetOpsError, WindowsNetworkOps};

const TUN_INTERFACE_ALIAS: &str = "NetFlow-TUN";
const TUN_GATEWAY_IPV4: &str = "172.19.0.2";
const DEFAULT_CLASH_API_PORT: u16 = 9090;
const ERROR_NOT_FOUND_CODE: u32 = 1168;
const ERROR_OBJECT_ALREADY_EXISTS_CODE: u32 = 5010;
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Lifecycle state of the NetFlow routing engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RuntimeState {
    Stopped,
    Applying,
    Active,
    Warning,
    Error,
}

/// Live health state of a wired physical interface or VPN node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NodeHealth {
    Healthy,
    Dropped,
}

/// Complete engine status snapshot exposed to the Tauri shell and frontend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EngineStatus {
    pub state: RuntimeState,
    pub active_workflow_id: Option<String>,
    pub node_health: HashMap<String, NodeHealth>,
    pub warning_banner: Option<String>,
    pub last_error: Option<String>,
}

impl Default for EngineStatus {
    fn default() -> Self {
        Self {
            state: RuntimeState::Stopped,
            active_workflow_id: None,
            node_health: HashMap::new(),
            warning_banner: None,
            last_error: None,
        }
    }
}

/// Events emitted by [`EngineRuntime`] and [`TrafficMonitor`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload", rename_all = "camelCase")]
pub enum RuntimeEvent {
    StatusChanged(EngineStatus),
    TrafficUpdated(Vec<LiveConnection>),
    RecoveryNotice(String),
}

/// Errors produced by [`SidecarRunner`] implementations.
#[derive(Debug, Error)]
pub enum SidecarError {
    #[error("sing-box binary not found at '{0}'")]
    BinaryNotFound(PathBuf),
    #[error("wintun directory not found at '{0}'")]
    WintunDirNotFound(PathBuf),
    #[error("failed to spawn sing-box process: {0}")]
    SpawnFailed(#[source] std::io::Error),
    #[error("sing-box exited immediately after launch (status: {0})")]
    ExitedImmediately(String),
    #[error("failed to inspect or terminate sing-box process: {0}")]
    ProcessControlFailed(#[source] std::io::Error),
}

/// Abstraction over managing the `sing-box` child process.
pub trait SidecarRunner: Send + Sync {
    /// Launches `sing-box` with the compiled configuration file at `config_path`.
    fn spawn(&self, config_path: &Path) -> Result<(), SidecarError>;
    /// Returns `true` if the managed `sing-box` process is currently running.
    fn is_alive(&self) -> bool;
    /// Terminates the managed `sing-box` process if it is running.
    fn kill(&self) -> Result<(), SidecarError>;
}

/// Real OS process runner for `sing-box.exe`.
pub struct SingBoxSidecar {
    binary_path: PathBuf,
    wintun_dir: PathBuf,
    child: Mutex<Option<Child>>,
}

impl SingBoxSidecar {
    /// Creates a new [`SingBoxSidecar`] targeting `binary_path` with `wintun_dir` as working directory.
    pub fn new(binary_path: PathBuf, wintun_dir: PathBuf) -> Self {
        Self {
            binary_path,
            wintun_dir,
            child: Mutex::new(None),
        }
    }

    /// Returns the configured `sing-box` executable path.
    pub fn binary_path(&self) -> &Path {
        &self.binary_path
    }

    /// Returns the directory containing `wintun.dll` used as the process working directory.
    pub fn wintun_dir(&self) -> &Path {
        &self.wintun_dir
    }
}

impl SidecarRunner for SingBoxSidecar {
    fn spawn(&self, config_path: &Path) -> Result<(), SidecarError> {
        if !self.binary_path.is_file() {
            return Err(SidecarError::BinaryNotFound(self.binary_path.clone()));
        }
        if !self.wintun_dir.is_dir() {
            return Err(SidecarError::WintunDirNotFound(self.wintun_dir.clone()));
        }

        let mut guard = self.child.lock().expect("sidecar child mutex poisoned");
        if let Some(mut existing) = guard.take() {
            terminate_child(&mut existing)?;
        }

        let mut cmd = Command::new(&self.binary_path);
        cmd.args(["run", "-c"])
            .arg(config_path)
            .current_dir(&self.wintun_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }

        let mut child = cmd.spawn().map_err(SidecarError::SpawnFailed)?;
        if let Some(status) = child
            .try_wait()
            .map_err(SidecarError::ProcessControlFailed)?
        {
            return Err(SidecarError::ExitedImmediately(status.to_string()));
        }

        *guard = Some(child);
        Ok(())
    }

    fn is_alive(&self) -> bool {
        let mut guard = self.child.lock().expect("sidecar child mutex poisoned");
        let Some(child) = guard.as_mut() else {
            return false;
        };
        match child.try_wait() {
            Ok(None) => true,
            _ => {
                *guard = None;
                false
            }
        }
    }

    fn kill(&self) -> Result<(), SidecarError> {
        let mut guard = self.child.lock().expect("sidecar child mutex poisoned");
        let Some(mut child) = guard.take() else {
            return Ok(());
        };
        terminate_child(&mut child)
    }
}

fn terminate_child(child: &mut Child) -> Result<(), SidecarError> {
    match child.try_wait() {
        Ok(Some(_)) => Ok(()),
        Ok(None) => {
            if let Err(err) = child.kill() {
                if matches!(child.try_wait(), Ok(Some(_))) {
                    return Ok(());
                }
                return Err(SidecarError::ProcessControlFailed(err));
            }
            let _ = child.wait();
            Ok(())
        }
        Err(err) => Err(SidecarError::ProcessControlFailed(err)),
    }
}

impl Drop for SingBoxSidecar {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.child.lock() {
            if let Some(mut child) = guard.take() {
                let _ = terminate_child(&mut child);
            }
        }
    }
}

/// Typed errors returned by [`EngineRuntime`] lifecycle operations.
#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("workflow validation failed: {}", format_validation_errors(.0))]
    Validation(Vec<ValidationError>),
    #[error("physical interface '{0}' is down or unavailable")]
    InterfaceDown(String),
    #[error("no active default physical interface is available")]
    NoDefaultPhysicalInterface,
    #[error("VPN adapter error: {0}")]
    VpnAdapter(#[from] VpnAdapterError),
    #[error("config compilation failed: {0}")]
    Compile(#[from] CompileError),
    #[error("system discovery failed: {0}")]
    Discovery(#[from] DiscoveryError),
    #[error("network operation failed: {0}")]
    NetOps(#[from] NetOpsError),
    #[error("recovery store error: {0}")]
    Recovery(#[from] RecoveryError),
    #[error("sidecar process error: {0}")]
    Sidecar(#[from] SidecarError),
    #[error("NetFlow-TUN interface did not become ready in time")]
    TunInterfaceNotReady,
    #[error("engine is busy with an active lifecycle transition")]
    EngineBusy,
    #[error("failed to restore network state: {0}")]
    RestoreFailed(String),
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("blocking runtime worker failed: {0}")]
    BlockingTask(String),
}

fn format_validation_errors(errors: &[ValidationError]) -> String {
    errors
        .iter()
        .map(|e| e.message.as_str())
        .collect::<Vec<_>>()
        .join("; ")
}

/// Runtime paths, ports, and polling intervals for [`EngineRuntime`].
#[derive(Debug, Clone)]
pub struct EngineRuntimeConfig {
    pub runtime_dir: PathBuf,
    pub clash_api_port: u16,
    pub health_poll_interval: Duration,
    pub tun_ready_attempts: usize,
    pub tun_ready_retry_delay: Duration,
}

impl Default for EngineRuntimeConfig {
    fn default() -> Self {
        Self {
            runtime_dir: default_netflow_dir().join("runtime"),
            clash_api_port: DEFAULT_CLASH_API_PORT,
            health_poll_interval: Duration::from_secs(2),
            tun_ready_attempts: 15,
            tun_ready_retry_delay: Duration::from_millis(200),
        }
    }
}

struct HealthWatcherHandle {
    cancel: watch::Sender<bool>,
    handle: Option<JoinHandle<()>>,
}

impl HealthWatcherHandle {
    async fn stop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for HealthWatcherHandle {
    fn drop(&mut self) {
        let _ = self.cancel.send(true);
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

struct ActiveSession {
    generation: u64,
    recovery: RecoverySnapshot,
    warp_mode: Option<WarpMode>,
    pre_netflow_warp_mode: Option<String>,
    health_watcher: HealthWatcherHandle,
    traffic_monitor: Option<TrafficMonitor>,
}

struct InnerState {
    status: EngineStatus,
    next_generation: u64,
    active_session: Option<ActiveSession>,
}

#[derive(Clone)]
struct PreparedApply {
    validated: ValidatedGraph,
    default_physical_interface: String,
    discovery_snap: DiscoverySnapshot,
    vpn_runtime: HashMap<VpnProvider, ResolvedVpnRuntimeInfo>,
    pre_netflow_warp_mode: Option<String>,
    outbound_to_node_id: HashMap<String, String>,
    compiled_config_bytes: Vec<u8>,
}

/// Core NetFlow runtime orchestrating pre-flight checks, atomic recovery, VPN neutralization,
/// `sing-box` lifecycle, hot-switching, fail-closed health watching, and live traffic streaming.
pub struct EngineRuntime {
    discovery: Arc<dyn SystemDiscovery>,
    net_ops: Arc<dyn WindowsNetworkOps>,
    sidecar: Arc<dyn SidecarRunner>,
    recovery_store: RecoveryStore,
    config: EngineRuntimeConfig,
    op_lock: Arc<AsyncMutex<()>>,
    inner: Arc<Mutex<InnerState>>,
    event_tx: broadcast::Sender<RuntimeEvent>,
}

impl EngineRuntime {
    /// Creates a new [`EngineRuntime`] with injected discovery, network ops, sidecar, and recovery store.
    pub fn new(
        discovery: Arc<dyn SystemDiscovery>,
        net_ops: Arc<dyn WindowsNetworkOps>,
        sidecar: Arc<dyn SidecarRunner>,
        recovery_store: RecoveryStore,
        config: EngineRuntimeConfig,
    ) -> Self {
        let (event_tx, _) = broadcast::channel(128);
        Self {
            discovery,
            net_ops,
            sidecar,
            recovery_store,
            config,
            op_lock: Arc::new(AsyncMutex::new(())),
            inner: Arc::new(Mutex::new(InnerState {
                status: EngineStatus::default(),
                next_generation: 1,
                active_session: None,
            })),
            event_tx,
        }
    }

    /// Restores any stale `recovery.json` persisted from an unexpected crash/exit and deletes the file.
    pub fn recover_if_stale(&self) -> Result<bool, RuntimeError> {
        let _op_guard = self
            .op_lock
            .try_lock()
            .map_err(|_| RuntimeError::EngineBusy)?;

        {
            let inner = self.inner.lock().expect("engine status mutex poisoned");
            if inner.active_session.is_some()
                || matches!(
                    inner.status.state,
                    RuntimeState::Active | RuntimeState::Warning | RuntimeState::Applying
                )
            {
                return Err(RuntimeError::EngineBusy);
            }
        }

        let Some(snapshot) = self.recovery_store.load()? else {
            return Ok(false);
        };

        let _ = self.sidecar.kill();
        restore_snapshot_state(&*self.net_ops, &snapshot)?;
        self.recovery_store.clear()?;

        let notice = format!(
            "Recovered stale NetFlow network state from {}",
            snapshot.created_at
        );
        let _ = self.event_tx.send(RuntimeEvent::RecoveryNotice(notice));
        Ok(true)
    }

    /// Validates, pre-flights, compiles, and applies a workflow (supports both cold start and hot-switch).
    pub async fn apply(
        &self,
        workflow_id: Option<String>,
        graph: &WorkflowGraph,
    ) -> Result<EngineStatus, RuntimeError> {
        let _op_guard = self.op_lock.lock().await;

        let prior_warp_state = {
            let guard = self.inner.lock().expect("engine status mutex poisoned");
            guard
                .active_session
                .as_ref()
                .map(|s| (s.warp_mode, s.pre_netflow_warp_mode.clone()))
        };

        let mut prepared = {
            let discovery = Arc::clone(&self.discovery);
            let net_ops = Arc::clone(&self.net_ops);
            let config = self.config.clone();
            let graph = graph.clone();
            let prior = prior_warp_state.clone();
            match run_blocking(move || {
                prepare_apply_blocking(&*discovery, &*net_ops, &config, &graph, prior.as_ref())
            })
            .await
            {
                Ok(plan) => plan,
                Err(err) => {
                    let is_active = {
                        let mut inner = self.inner.lock().expect("engine status mutex poisoned");
                        if inner.active_session.is_none() {
                            inner.status.last_error = Some(err.to_string());
                            false
                        } else {
                            true
                        }
                    };
                    if !is_active {
                        self.emit_status();
                    }
                    return Err(err);
                }
            }
        };

        let existing_session = self.stop_active_session_tasks().await;

        {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            inner.status.state = RuntimeState::Applying;
            inner.status.last_error = None;
        }
        self.emit_status();

        let snapshot = if let Some(old_session) = existing_session {
            let sidecar = Arc::clone(&self.sidecar);
            if let Err(err) = run_blocking(move || sidecar.kill().map_err(RuntimeError::from)).await
            {
                return Err(self
                    .rollback_on_apply_failure(&old_session.recovery, err)
                    .await);
            }
            let mut snap = old_session.recovery;
            if let Err(err) = self
                .reconcile_hot_switch(
                    &mut prepared,
                    &mut snap,
                    old_session.warp_mode,
                    old_session.pre_netflow_warp_mode,
                )
                .await
            {
                return Err(self.rollback_on_apply_failure(&snap, err).await);
            }
            snap
        } else {
            let net_ops = Arc::clone(&self.net_ops);
            let system_proxy = match run_blocking(move || {
                net_ops.get_system_proxy().map_err(RuntimeError::from)
            })
            .await
            {
                Ok(proxy) => proxy,
                Err(err) => {
                    self.record_cold_preflight_error(&err);
                    return Err(err);
                }
            };
            let mut snap = RecoverySnapshot {
                created_at: now_rfc3339(),
                system_proxy: Some(system_proxy),
                vpn_entries: HashMap::new(),
                pinned_host_routes: Vec::new(),
            };
            let store = self.recovery_store.clone();
            let snap_for_save = snap.clone();
            if let Err(err) = run_blocking(move || {
                store
                    .save_atomic(&snap_for_save)
                    .map_err(RuntimeError::from)
            })
            .await
            {
                self.record_cold_preflight_error(&err);
                return Err(err);
            }
            let net_ops = Arc::clone(&self.net_ops);
            let store = self.recovery_store.clone();
            let prepared_ref = prepared.clone();
            if let Err(err) = run_snapshot_blocking(&mut snap, move |local_snap| {
                apply_cold_start_mutations_blocking(&*net_ops, &store, &prepared_ref, local_snap)
            })
            .await
            {
                return Err(self.rollback_on_apply_failure(&snap, err).await);
            }
            snap
        };

        let config_path = self.config.runtime_dir.join("sing-box.json");
        {
            let runtime_dir = self.config.runtime_dir.clone();
            let config_path_write = config_path.clone();
            let bytes = prepared.compiled_config_bytes.clone();
            if let Err(err) = run_blocking(move || {
                fs::create_dir_all(&runtime_dir)
                    .and_then(|()| write_atomic(&config_path_write, &bytes))
                    .map_err(RuntimeError::from)
            })
            .await
            {
                return Err(self.rollback_on_apply_failure(&snapshot, err).await);
            }
        }

        {
            let sidecar = Arc::clone(&self.sidecar);
            let config_path_spawn = config_path.clone();
            if let Err(err) =
                run_blocking(move || sidecar.spawn(&config_path_spawn).map_err(RuntimeError::from))
                    .await
            {
                return Err(self.rollback_on_apply_failure(&snapshot, err).await);
            }
        }

        if let Err(err) = self.ensure_tun_route_priority().await {
            return Err(self.rollback_on_apply_failure(&snapshot, err).await);
        }

        // Persist finalized snapshot (noop if already flushed, ensures consistency).
        {
            let store = self.recovery_store.clone();
            let snap_for_save = snapshot.clone();
            if let Err(err) = run_blocking(move || {
                store
                    .save_atomic(&snap_for_save)
                    .map_err(RuntimeError::from)
            })
            .await
            {
                return Err(self.rollback_on_apply_failure(&snapshot, err).await);
            }
        }

        let node_health = initial_node_health(&prepared.validated);
        let new_status = EngineStatus {
            state: RuntimeState::Active,
            active_workflow_id: workflow_id,
            node_health,
            warning_banner: None,
            last_error: None,
        };

        let warp_mode = prepared
            .vpn_runtime
            .get(&VpnProvider::CloudflareWarp)
            .map(|rt| rt.warp_mode);
        let pre_netflow_warp_mode = if warp_mode.is_some() {
            prepared.pre_netflow_warp_mode
        } else {
            None
        };

        let generation = {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            let gen = inner.next_generation;
            inner.next_generation += 1;
            inner.status = new_status.clone();
            gen
        };

        let traffic_monitor = TrafficMonitor::spawn(
            self.config.clash_api_port,
            prepared.outbound_to_node_id,
            self.event_tx.clone(),
        );
        let health_watcher = self.spawn_health_watcher(generation, prepared.validated);

        {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            inner.active_session = Some(ActiveSession {
                generation,
                recovery: snapshot,
                warp_mode,
                pre_netflow_warp_mode,
                health_watcher,
                traffic_monitor: Some(traffic_monitor),
            });
        }

        let _ = self
            .event_tx
            .send(RuntimeEvent::StatusChanged(new_status.clone()));
        Ok(new_status)
    }

    /// Stops `sing-box`, restores all neutralized VPNs and Windows System Proxy, and clears `recovery.json`.
    pub async fn stop(&self) -> Result<EngineStatus, RuntimeError> {
        let _op_guard = self.op_lock.lock().await;

        let active_session = self.stop_active_session_tasks().await;
        let active_recovery = active_session.map(|s| s.recovery);

        let sidecar = Arc::clone(&self.sidecar);
        let net_ops = Arc::clone(&self.net_ops);
        let store = self.recovery_store.clone();
        let errors = run_blocking(move || {
            let kill_result = sidecar.kill();
            let recovery_snapshot = match active_recovery {
                Some(snap) => Some(snap),
                None => store.load()?,
            };
            let restore_result = match recovery_snapshot {
                Some(ref snapshot) => restore_snapshot_state(&*net_ops, snapshot),
                None => Ok(()),
            };
            let clear_result = if restore_result.is_ok() {
                store.clear().map_err(RuntimeError::from)
            } else {
                Ok(())
            };

            let mut errs = Vec::new();
            if let Err(err) = kill_result {
                errs.push(err.to_string());
            }
            if let Err(err) = restore_result {
                errs.push(err.to_string());
            }
            if let Err(err) = clear_result {
                errs.push(err.to_string());
            }
            Ok(errs)
        })
        .await?;

        let new_status = if errors.is_empty() {
            EngineStatus {
                state: RuntimeState::Stopped,
                active_workflow_id: None,
                node_health: HashMap::new(),
                warning_banner: None,
                last_error: None,
            }
        } else {
            EngineStatus {
                state: RuntimeState::Error,
                active_workflow_id: None,
                node_health: HashMap::new(),
                warning_banner: None,
                last_error: Some(errors.join("; ")),
            }
        };

        {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            inner.status = new_status.clone();
        }
        let _ = self
            .event_tx
            .send(RuntimeEvent::StatusChanged(new_status.clone()));

        if errors.is_empty() {
            Ok(new_status)
        } else {
            Err(RuntimeError::RestoreFailed(errors.join("; ")))
        }
    }

    /// Returns a snapshot of the current [`EngineStatus`].
    pub fn status(&self) -> EngineStatus {
        self.inner
            .lock()
            .expect("engine status mutex poisoned")
            .status
            .clone()
    }

    /// Subscribes to [`RuntimeEvent`] status and live traffic updates.
    pub fn subscribe_events(&self) -> broadcast::Receiver<RuntimeEvent> {
        self.event_tx.subscribe()
    }

    async fn reconcile_hot_switch(
        &self,
        prepared: &mut PreparedApply,
        snapshot: &mut RecoverySnapshot,
        old_warp_mode: Option<WarpMode>,
        old_pre_netflow_warp_mode: Option<String>,
    ) -> Result<(), RuntimeError> {
        // 1. Remove old pinned routes and VPNs no longer present in the new workflow.
        {
            let net_ops = Arc::clone(&self.net_ops);
            let store = self.recovery_store.clone();
            let new_providers: HashSet<VpnProvider> = prepared
                .validated
                .vpn_chains
                .iter()
                .map(|c| c.provider)
                .collect();
            run_snapshot_blocking(snapshot, move |local_snap| {
                reconcile_hot_switch_removals_blocking(&*net_ops, &store, &new_providers, local_snap)
            })
            .await?;
        }

        // 2. If WARP is switching between Proxy and Tun modes, restore/switch mode first,
        //    persist transitional baseline, re-query fresh discovery, and recompile sing-box config.
        if let Some(warp_chain) = prepared
            .validated
            .vpn_chains
            .iter()
            .find(|c| c.provider == VpnProvider::CloudflareWarp)
            .cloned()
        {
            let target_mode = warp_chain.settings.warp_mode;
            let warp_mode_changed = old_warp_mode.is_some() && old_warp_mode != Some(target_mode);
            if warp_mode_changed {
                let baseline_mode = snapshot
                    .vpn_entries
                    .get(&VpnProvider::CloudflareWarp)
                    .and_then(|e| e.warp_previous_mode.clone())
                    .or_else(|| old_pre_netflow_warp_mode.clone())
                    .or_else(|| {
                        if old_warp_mode == Some(WarpMode::Proxy) {
                            Some("proxy".to_string())
                        } else {
                            None
                        }
                    });
                prepared.pre_netflow_warp_mode = baseline_mode.clone();

                // Switch/restore WARP out of the previous mode before re-discovering.
                {
                    let net_ops = Arc::clone(&self.net_ops);
                    let store = self.recovery_store.clone();
                    let baseline_for_save = baseline_mode.clone();
                    run_snapshot_blocking(snapshot, move |local_snap| {
                        switch_warp_mode_before_rediscovery_blocking(
                            &*net_ops,
                            &store,
                            local_snap,
                            target_mode,
                            baseline_for_save,
                        )
                    })
                    .await?;
                }

                // Re-query discovery after warp-cli mode transition so TUN adapter/routes or
                // proxy port reflect the live state.
                let fresh_snap = self.discover_after_warp_mode_switch(target_mode).await?;
                prepared.discovery_snap = fresh_snap;

                let fresh_detected = find_detected_vpn(
                    &prepared.discovery_snap.vpns,
                    VpnProvider::CloudflareWarp,
                )?;
                let fresh_resolved = preflight_and_resolve_vpn(
                    VpnProvider::CloudflareWarp,
                    &warp_chain.settings,
                    fresh_detected,
                )?;
                prepared
                    .vpn_runtime
                    .insert(VpnProvider::CloudflareWarp, fresh_resolved.clone());

                // Neutralize freshly discovered WARP state and preserve pre-NetFlow baseline.
                {
                    let net_ops = Arc::clone(&self.net_ops);
                    let store = self.recovery_store.clone();
                    let fresh_detected = fresh_detected.clone();
                    let fresh_resolved = fresh_resolved.clone();
                    let baseline_mode = baseline_mode.clone();
                    run_snapshot_blocking(snapshot, move |local_snap| {
                        neutralize_switched_warp_blocking(
                            &*net_ops,
                            &store,
                            local_snap,
                            target_mode,
                            &fresh_resolved,
                            &fresh_detected,
                            baseline_mode.as_deref(),
                        )
                    })
                    .await?;
                }

                // Re-compile sing-box config using the freshly resolved WARP runtime info.
                let compiled = compile_singbox_config(&CompileInput {
                    validated: prepared.validated.clone(),
                    default_physical_interface: prepared.default_physical_interface.clone(),
                    vpn_runtime: prepared.vpn_runtime.clone(),
                    clash_api_port: self.config.clash_api_port,
                    log_path: self.config.runtime_dir.join("sing-box.log"),
                })?;
                prepared.outbound_to_node_id = compiled.outbound_to_node_id;
                prepared.compiled_config_bytes = serde_json::to_vec_pretty(&compiled.json)?;
            }
        }

        // 3. Neutralize any remaining newly added VPNs and re-pin OpenVPN DCO /32 routes,
        //    preserving existing baseline entries via insert_vpn_if_absent.
        {
            let net_ops = Arc::clone(&self.net_ops);
            let store = self.recovery_store.clone();
            let prepared_ref = prepared.clone();
            run_snapshot_blocking(snapshot, move |local_snap| {
                apply_remaining_hot_switch_vpns_blocking(&*net_ops, &store, &prepared_ref, local_snap)
            })
            .await?;
        }

        Ok(())
    }

    async fn discover_after_warp_mode_switch(
        &self,
        target_mode: WarpMode,
    ) -> Result<DiscoverySnapshot, RuntimeError> {
        let attempts = match target_mode {
            WarpMode::Tun => self.config.tun_ready_attempts.max(1),
            WarpMode::Proxy => 1,
        };

        for attempt in 0..attempts {
            let discovery = Arc::clone(&self.discovery);
            let snap = run_blocking(move || discovery.snapshot().map_err(RuntimeError::from)).await?;
            let detected = snap
                .vpns
                .iter()
                .find(|v| v.provider == VpnProvider::CloudflareWarp);

            match detected {
                Some(v) if !v.is_running => {
                    return Err(RuntimeError::VpnAdapter(VpnAdapterError::NotRunning(
                        VpnProvider::CloudflareWarp,
                    )));
                }
                Some(v)
                    if target_mode == WarpMode::Proxy
                        || v.adapter_if_index.is_some()
                        || v.adapter_alias
                            .as_deref()
                            .is_some_and(|a| !a.trim().is_empty()) =>
                {
                    return Ok(snap);
                }
                _ if attempt + 1 < attempts && !self.config.tun_ready_retry_delay.is_zero() => {
                    tokio::time::sleep(self.config.tun_ready_retry_delay).await;
                }
                _ => return Ok(snap),
            }
        }

        let discovery = Arc::clone(&self.discovery);
        run_blocking(move || discovery.snapshot().map_err(RuntimeError::from)).await
    }

    async fn ensure_tun_route_priority(&self) -> Result<(), RuntimeError> {
        let attempts = self.config.tun_ready_attempts.max(1);
        for attempt in 0..attempts {
            let sidecar = Arc::clone(&self.sidecar);
            let net_ops = Arc::clone(&self.net_ops);
            let ready = run_blocking(move || {
                if !sidecar.is_alive() {
                    return Err(RuntimeError::Sidecar(SidecarError::ExitedImmediately(
                        "terminated before NetFlow-TUN became ready".to_string(),
                    )));
                }

                if let Some(best_alias) = net_ops.find_best_route_interface("1.1.1.1")? {
                    if best_alias.eq_ignore_ascii_case(TUN_INTERFACE_ALIAS) {
                        return Ok(true);
                    }
                }

                if let Some(nf_idx) = net_ops.find_interface_index_by_alias(TUN_INTERFACE_ALIAS)? {
                    net_ops.set_interface_metric(nf_idx, false, 1, false)?;
                    for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
                        let route = RouteRecord {
                            interface_index: nf_idx,
                            destination_prefix: prefix.to_string(),
                            next_hop: TUN_GATEWAY_IPV4.to_string(),
                            route_metric: 0,
                            is_ipv6: false,
                        };
                        add_or_replace_route(&*net_ops, &route)?;
                    }
                    return Ok(true);
                }

                Ok(false)
            })
            .await?;

            if ready {
                return Ok(());
            }

            if attempt + 1 < attempts && !self.config.tun_ready_retry_delay.is_zero() {
                tokio::time::sleep(self.config.tun_ready_retry_delay).await;
            }
        }

        Err(RuntimeError::TunInterfaceNotReady)
    }

    async fn rollback_on_apply_failure(
        &self,
        snapshot: &RecoverySnapshot,
        err: RuntimeError,
    ) -> RuntimeError {
        let sidecar = Arc::clone(&self.sidecar);
        let net_ops = Arc::clone(&self.net_ops);
        let store = self.recovery_store.clone();
        let snap = snapshot.clone();
        let restore_res = run_blocking(move || {
            let _ = sidecar.kill();
            let res = restore_snapshot_state(&*net_ops, &snap);
            if res.is_ok() {
                let _ = store.clear();
            }
            res
        })
        .await;

        let err_msg = match restore_res {
            Ok(()) => err.to_string(),
            Err(restore_err) => format!("{err}; rollback also failed: {restore_err}"),
        };

        let status = EngineStatus {
            state: RuntimeState::Error,
            active_workflow_id: None,
            node_health: HashMap::new(),
            warning_banner: None,
            last_error: Some(err_msg),
        };
        {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            inner.status = status.clone();
            inner.active_session = None;
        }
        let _ = self.event_tx.send(RuntimeEvent::StatusChanged(status));
        err
    }

    fn record_cold_preflight_error(&self, err: &RuntimeError) {
        let mut inner = self.inner.lock().expect("engine status mutex poisoned");
        inner.status.last_error = Some(err.to_string());
        let status = inner.status.clone();
        drop(inner);
        let _ = self.event_tx.send(RuntimeEvent::StatusChanged(status));
    }

    fn emit_status(&self) {
        let status = self.status();
        let _ = self.event_tx.send(RuntimeEvent::StatusChanged(status));
    }

    async fn stop_active_session_tasks(&self) -> Option<ActiveSession> {
        let mut session = {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            inner.active_session.take()
        }?;

        session.health_watcher.stop().await;
        if let Some(mut tm) = session.traffic_monitor.take() {
            tm.stop().await;
        }
        Some(session)
    }

    fn spawn_health_watcher(
        &self,
        generation: u64,
        validated: ValidatedGraph,
    ) -> HealthWatcherHandle {
        let (cancel_tx, mut cancel_rx) = watch::channel(false);
        let poll_interval = self.config.health_poll_interval.max(Duration::from_millis(5));
        let discovery = Arc::clone(&self.discovery);
        let net_ops = Arc::clone(&self.net_ops);
        let sidecar = Arc::clone(&self.sidecar);
        let recovery_store = self.recovery_store.clone();
        let op_lock = Arc::clone(&self.op_lock);
        let inner = Arc::clone(&self.inner);
        let event_tx = self.event_tx.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => {
                        if *cancel_rx.borrow() {
                            break;
                        }
                    }
                    _ = tokio::time::sleep(poll_interval) => {}
                }

                if *cancel_rx.borrow() {
                    break;
                }

                let _op_guard = tokio::select! {
                    biased;
                    _ = cancel_rx.changed() => break,
                    guard = op_lock.lock() => guard,
                };

                if *cancel_rx.borrow() {
                    break;
                }

                let current_gen = {
                    let guard = inner.lock().expect("engine status mutex poisoned");
                    guard.active_session.as_ref().map(|s| s.generation)
                };
                if current_gen != Some(generation) {
                    break;
                }

                let poll_res = {
                    let sidecar = Arc::clone(&sidecar);
                    let discovery = Arc::clone(&discovery);
                    tokio::task::spawn_blocking(move || {
                        if !sidecar.is_alive() {
                            return Ok(None);
                        }
                        Ok::<_, DiscoveryError>(Some(discovery.snapshot()?))
                    })
                    .await
                };

                let snapshot = match poll_res {
                    Ok(Ok(Some(snap))) => snap,
                    Ok(Ok(None)) => {
                        let crashed_session = {
                            let mut guard = inner.lock().expect("engine status mutex poisoned");
                            guard.active_session.take()
                        };

                        if let Some(mut session) = crashed_session {
                            if let Some(mut tm) = session.traffic_monitor.take() {
                                tm.stop().await;
                            }
                            let net_ops = Arc::clone(&net_ops);
                            let store = recovery_store.clone();
                            let recovery = session.recovery;
                            let restore_res = run_blocking(move || {
                                let res = restore_snapshot_state(&*net_ops, &recovery);
                                if res.is_ok() {
                                    let _ = store.clear();
                                }
                                res
                            })
                            .await;
                            let last_error = match restore_res {
                                Ok(()) => {
                                    "sing-box exited unexpectedly; restored original network state"
                                        .to_string()
                                }
                                Err(err) => {
                                    format!("sing-box exited unexpectedly; restore failed: {err}")
                                }
                            };
                            let err_status = EngineStatus {
                                state: RuntimeState::Error,
                                active_workflow_id: None,
                                node_health: HashMap::new(),
                                warning_banner: None,
                                last_error: Some(last_error),
                            };
                            {
                                let mut guard = inner.lock().expect("engine status mutex poisoned");
                                guard.status = err_status.clone();
                            }
                            let _ = event_tx.send(RuntimeEvent::StatusChanged(err_status));
                        }
                        break;
                    }
                    Ok(Err(_)) | Err(_) => continue,
                };

                let (new_health, dropped_labels) = evaluate_node_health(&validated, &snapshot);
                let (new_state, new_banner) = if dropped_labels.is_empty() {
                    (RuntimeState::Active, None)
                } else {
                    (
                        RuntimeState::Warning,
                        Some(format!(
                            "{} dropped — traffic blocked fail-closed. Reconnect & Re-Apply.",
                            dropped_labels.join(", ")
                        )),
                    )
                };

                let maybe_changed = {
                    let mut guard = inner.lock().expect("engine status mutex poisoned");
                    if guard.active_session.as_ref().map(|s| s.generation) != Some(generation) {
                        None
                    } else if guard.status.state != new_state
                        || guard.status.node_health != new_health
                        || guard.status.warning_banner != new_banner
                    {
                        guard.status.state = new_state;
                        guard.status.node_health = new_health;
                        guard.status.warning_banner = new_banner;
                        Some(guard.status.clone())
                    } else {
                        None
                    }
                };

                if let Some(updated_status) = maybe_changed {
                    let _ = event_tx.send(RuntimeEvent::StatusChanged(updated_status));
                }
            }
        });

        HealthWatcherHandle {
            cancel: cancel_tx,
            handle: Some(handle),
        }
    }
}

async fn run_blocking<F, T>(f: F) -> Result<T, RuntimeError>
where
    F: FnOnce() -> Result<T, RuntimeError> + Send + 'static,
    T: Send + 'static,
{
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|err| RuntimeError::BlockingTask(err.to_string()))?
}

async fn run_snapshot_blocking<F>(
    snapshot: &mut RecoverySnapshot,
    f: F,
) -> Result<(), RuntimeError>
where
    F: FnOnce(&mut RecoverySnapshot) -> Result<(), RuntimeError> + Send + 'static,
{
    let mut local_snap = snapshot.clone();
    let join_res = tokio::task::spawn_blocking(move || {
        let res = f(&mut local_snap);
        (local_snap, res)
    })
    .await;
    match join_res {
        Ok((updated_snap, res)) => {
            *snapshot = updated_snap;
            res
        }
        Err(join_err) => Err(RuntimeError::BlockingTask(join_err.to_string())),
    }
}

fn prepare_apply_blocking(
    discovery: &dyn SystemDiscovery,
    net_ops: &dyn WindowsNetworkOps,
    config: &EngineRuntimeConfig,
    graph: &WorkflowGraph,
    prior_warp_state: Option<&(Option<WarpMode>, Option<String>)>,
) -> Result<PreparedApply, RuntimeError> {
    let validated = validate_graph(graph).map_err(RuntimeError::Validation)?;
    let discovery_snap = discovery.snapshot()?;

    for iface_node_id in &validated.interface_node_ids {
        let Some(node) = validated.nodes_by_id.get(iface_node_id) else {
            return Err(RuntimeError::Compile(CompileError::UnknownNodeReference {
                node_id: iface_node_id.clone(),
            }));
        };
        if let NodeKind::Interface {
            interface_alias, ..
        } = &node.kind
        {
            let is_up = find_physical_interface(&discovery_snap.interfaces, interface_alias)
                .is_some_and(|iface| iface.is_up);
            if !is_up {
                return Err(RuntimeError::InterfaceDown(interface_alias.clone()));
            }
        }
    }

    let default_physical_interface = discovery_snap
        .interfaces
        .iter()
        .find(|i| i.is_up && i.is_default_gateway)
        .or_else(|| discovery_snap.interfaces.iter().find(|i| i.is_up))
        .map(|i| i.alias.clone())
        .ok_or(RuntimeError::NoDefaultPhysicalInterface)?;

    let mut vpn_runtime = HashMap::new();
    let mut pre_netflow_warp_mode = prior_warp_state.and_then(|(_, m)| m.clone());

    for chain in &validated.vpn_chains {
        let detected = discovery_snap
            .vpns
            .iter()
            .find(|v| v.provider == chain.provider)
            .ok_or(RuntimeError::VpnAdapter(VpnAdapterError::NotRunning(
                chain.provider,
            )))?;

        if chain.provider == VpnProvider::CloudflareWarp && pre_netflow_warp_mode.is_none() {
            pre_netflow_warp_mode = net_ops
                .warp_cli_get_mode()
                .ok()
                .flatten()
                .or_else(|| detected.warp_current_mode.clone())
                .or_else(|| {
                    if chain.settings.warp_mode == WarpMode::Proxy {
                        Some("proxy".to_string())
                    } else {
                        None
                    }
                });
        }

        let is_warp_proxy_to_tun = chain.provider == VpnProvider::CloudflareWarp
            && chain.settings.warp_mode == WarpMode::Tun
            && matches!(prior_warp_state, Some((Some(WarpMode::Proxy), _)));

        let resolved = if is_warp_proxy_to_tun {
            if !detected.is_running {
                return Err(RuntimeError::VpnAdapter(VpnAdapterError::NotRunning(
                    VpnProvider::CloudflareWarp,
                )));
            }
            ResolvedVpnRuntimeInfo {
                provider: VpnProvider::CloudflareWarp,
                karing_socks_port: None,
                warp_mode: WarpMode::Tun,
                warp_socks_port: None,
                warp_adapter_alias: Some(
                    detected
                        .adapter_alias
                        .as_deref()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .unwrap_or("CloudflareWARP")
                        .to_string(),
                ),
                openvpn_adapter_alias: None,
                openvpn_server_ip: None,
            }
        } else {
            preflight_and_resolve_vpn(chain.provider, &chain.settings, detected)?
        };
        vpn_runtime.insert(chain.provider, resolved);
    }

    let compiled = compile_singbox_config(&CompileInput {
        validated: validated.clone(),
        default_physical_interface: default_physical_interface.clone(),
        vpn_runtime: vpn_runtime.clone(),
        clash_api_port: config.clash_api_port,
        log_path: config.runtime_dir.join("sing-box.log"),
    })?;
    let compiled_config_bytes = serde_json::to_vec_pretty(&compiled.json)?;

    Ok(PreparedApply {
        validated,
        default_physical_interface,
        discovery_snap,
        vpn_runtime,
        pre_netflow_warp_mode,
        outbound_to_node_id: compiled.outbound_to_node_id,
        compiled_config_bytes,
    })
}

fn apply_cold_start_mutations_blocking(
    net_ops: &dyn WindowsNetworkOps,
    recovery_store: &RecoveryStore,
    prepared: &PreparedApply,
    snapshot: &mut RecoverySnapshot,
) -> Result<(), RuntimeError> {
    net_ops.disable_system_proxy()?;

    for chain in &prepared.validated.vpn_chains {
        let detected = find_detected_vpn(&prepared.discovery_snap.vpns, chain.provider)?;
        let resolved = prepared
            .vpn_runtime
            .get(&chain.provider)
            .ok_or(RuntimeError::Compile(CompileError::MissingVpnRuntime {
                provider: chain.provider,
            }))?;

        let entry = neutralize_vpn(net_ops, chain.provider, resolved, detected)?;
        snapshot.insert_vpn_if_absent(entry);
        recovery_store.save_atomic(snapshot)?;

        maybe_pin_openvpn_route_blocking(net_ops, recovery_store, prepared, chain, resolved, snapshot)?;
    }

    Ok(())
}

fn reconcile_hot_switch_removals_blocking(
    net_ops: &dyn WindowsNetworkOps,
    recovery_store: &RecoveryStore,
    new_providers: &HashSet<VpnProvider>,
    snapshot: &mut RecoverySnapshot,
) -> Result<(), RuntimeError> {
    if !snapshot.pinned_host_routes.is_empty() {
        while let Some(route) = snapshot.pinned_host_routes.last().cloned() {
            remove_route_ignore_missing(net_ops, &route)?;
            snapshot.pinned_host_routes.pop();
        }
        recovery_store.save_atomic(snapshot)?;
    }

    let removed_providers: Vec<VpnProvider> = snapshot
        .vpn_entries
        .keys()
        .copied()
        .filter(|provider| !new_providers.contains(provider))
        .collect();

    for provider in removed_providers {
        if let Some(entry) = snapshot.vpn_entries.get(&provider) {
            restore_vpn(net_ops, entry)?;
        }
        snapshot.vpn_entries.remove(&provider);
        recovery_store.save_atomic(snapshot)?;
    }

    Ok(())
}

fn switch_warp_mode_before_rediscovery_blocking(
    net_ops: &dyn WindowsNetworkOps,
    recovery_store: &RecoveryStore,
    snapshot: &mut RecoverySnapshot,
    target_mode: WarpMode,
    baseline_mode: Option<String>,
) -> Result<(), RuntimeError> {
    let mut switched_via_restore = false;
    if let Some(old_entry) = snapshot.vpn_entries.get(&VpnProvider::CloudflareWarp) {
        switched_via_restore = old_entry.warp_previous_mode.is_some();
        restore_vpn(net_ops, old_entry)?;
    }

    if target_mode == WarpMode::Tun && !switched_via_restore {
        // WARP was originally in "proxy" mode so restore_vpn did not switch warp-cli out of proxy.
        net_ops.warp_cli_set_mode("warp")?;
        let transitional = VpnRecoveryEntry {
            provider: VpnProvider::CloudflareWarp,
            removed_routes: Vec::new(),
            added_routes: Vec::new(),
            metric_snapshots: Vec::new(),
            warp_previous_mode: baseline_mode.or_else(|| Some("proxy".to_string())),
        };
        snapshot
            .vpn_entries
            .insert(VpnProvider::CloudflareWarp, transitional);
    } else {
        snapshot.vpn_entries.remove(&VpnProvider::CloudflareWarp);
    }

    recovery_store.save_atomic(snapshot)?;
    Ok(())
}

fn neutralize_switched_warp_blocking(
    net_ops: &dyn WindowsNetworkOps,
    recovery_store: &RecoveryStore,
    snapshot: &mut RecoverySnapshot,
    target_mode: WarpMode,
    resolved: &ResolvedVpnRuntimeInfo,
    detected: &DetectedVpnInfo,
    baseline_mode: Option<&str>,
) -> Result<(), RuntimeError> {
    let mut entry = neutralize_vpn(net_ops, VpnProvider::CloudflareWarp, resolved, detected)?;
    if entry.warp_previous_mode.is_none() {
        if let Some(orig) = baseline_mode {
            match target_mode {
                WarpMode::Tun if orig.eq_ignore_ascii_case("proxy") => {
                    entry.warp_previous_mode = Some(orig.to_string());
                }
                WarpMode::Proxy if !orig.eq_ignore_ascii_case("proxy") => {
                    entry.warp_previous_mode = Some(orig.to_string());
                }
                _ => {}
            }
        }
    }
    snapshot
        .vpn_entries
        .insert(VpnProvider::CloudflareWarp, entry);
    recovery_store.save_atomic(snapshot)?;
    Ok(())
}

fn apply_remaining_hot_switch_vpns_blocking(
    net_ops: &dyn WindowsNetworkOps,
    recovery_store: &RecoveryStore,
    prepared: &PreparedApply,
    snapshot: &mut RecoverySnapshot,
) -> Result<(), RuntimeError> {
    for chain in &prepared.validated.vpn_chains {
        let detected = find_detected_vpn(&prepared.discovery_snap.vpns, chain.provider)?;
        let resolved = prepared
            .vpn_runtime
            .get(&chain.provider)
            .ok_or(RuntimeError::Compile(CompileError::MissingVpnRuntime {
                provider: chain.provider,
            }))?;

        if !snapshot.vpn_entries.contains_key(&chain.provider) {
            let entry = neutralize_vpn(net_ops, chain.provider, resolved, detected)?;
            snapshot.insert_vpn_if_absent(entry);
            recovery_store.save_atomic(snapshot)?;
        }

        maybe_pin_openvpn_route_blocking(
            net_ops,
            recovery_store,
            prepared,
            chain,
            resolved,
            snapshot,
        )?;
    }
    Ok(())
}

fn maybe_pin_openvpn_route_blocking(
    net_ops: &dyn WindowsNetworkOps,
    recovery_store: &RecoveryStore,
    prepared: &PreparedApply,
    chain: &crate::model::ValidatedVpnChain,
    resolved: &ResolvedVpnRuntimeInfo,
    snapshot: &mut RecoverySnapshot,
) -> Result<(), RuntimeError> {
    if chain.provider != VpnProvider::OpenVpn {
        return Ok(());
    }
    let Some(ref server_ip) = resolved.openvpn_server_ip else {
        return Ok(());
    };
    let Some(upstream_node) = prepared.validated.nodes_by_id.get(&chain.upstream_node_id) else {
        return Ok(());
    };
    let NodeKind::Interface {
        interface_alias, ..
    } = &upstream_node.kind
    else {
        // Chained downstream of another VPN: compiler emits <server_ip>/32 sing-box rule instead.
        return Ok(());
    };
    let upstream_if = find_physical_interface(&prepared.discovery_snap.interfaces, interface_alias)
        .ok_or_else(|| RuntimeError::InterfaceDown(interface_alias.clone()))?;

    let pinned_route = pin_openvpn_dco_host_route(net_ops, server_ip, upstream_if)?;
    snapshot.pinned_host_routes.push(pinned_route);
    recovery_store.save_atomic(snapshot)?;
    Ok(())
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn find_physical_interface<'a>(
    interfaces: &'a [PhysicalInterfaceInfo],
    alias: &str,
) -> Option<&'a PhysicalInterfaceInfo> {
    let trimmed = alias.trim();
    interfaces
        .iter()
        .find(|i| i.alias.eq_ignore_ascii_case(trimmed))
}

fn find_detected_vpn(
    vpns: &[DetectedVpnInfo],
    provider: VpnProvider,
) -> Result<&DetectedVpnInfo, RuntimeError> {
    vpns.iter()
        .find(|v| v.provider == provider)
        .ok_or(RuntimeError::VpnAdapter(VpnAdapterError::NotRunning(provider)))
}

fn initial_node_health(validated: &ValidatedGraph) -> HashMap<String, NodeHealth> {
    let mut health = HashMap::new();
    for id in &validated.interface_node_ids {
        health.insert(id.clone(), NodeHealth::Healthy);
    }
    for chain in &validated.vpn_chains {
        health.insert(chain.node_id.clone(), NodeHealth::Healthy);
    }
    health
}

fn evaluate_node_health(
    validated: &ValidatedGraph,
    snapshot: &DiscoverySnapshot,
) -> (HashMap<String, NodeHealth>, Vec<String>) {
    let mut health = HashMap::new();
    let mut dropped = Vec::new();

    for iface_node_id in &validated.interface_node_ids {
        let Some(node) = validated.nodes_by_id.get(iface_node_id) else {
            continue;
        };
        if let NodeKind::Interface {
            interface_alias, ..
        } = &node.kind
        {
            let up = find_physical_interface(&snapshot.interfaces, interface_alias)
                .is_some_and(|iface| iface.is_up);
            if up {
                health.insert(iface_node_id.clone(), NodeHealth::Healthy);
            } else {
                health.insert(iface_node_id.clone(), NodeHealth::Dropped);
                dropped.push(interface_alias.clone());
            }
        }
    }

    for chain in &validated.vpn_chains {
        let running = snapshot
            .vpns
            .iter()
            .find(|v| v.provider == chain.provider)
            .is_some_and(|v| v.is_running);
        if running {
            health.insert(chain.node_id.clone(), NodeHealth::Healthy);
        } else {
            health.insert(chain.node_id.clone(), NodeHealth::Dropped);
            dropped.push(provider_display_name(chain.provider).to_string());
        }
    }

    (health, dropped)
}

fn provider_display_name(provider: VpnProvider) -> &'static str {
    match provider {
        VpnProvider::Karing => "Karing",
        VpnProvider::CloudflareWarp => "Cloudflare WARP",
        VpnProvider::OpenVpn => "OpenVPN",
    }
}

fn remove_route_ignore_missing(
    ops: &dyn WindowsNetworkOps,
    route: &RouteRecord,
) -> Result<(), NetOpsError> {
    match ops.remove_route(route) {
        Ok(()) => Ok(()),
        Err(NetOpsError::RouteNotFound { .. }) => Ok(()),
        Err(NetOpsError::Win32 { code, .. }) if code == ERROR_NOT_FOUND_CODE => Ok(()),
        Err(err) => Err(err),
    }
}

fn add_or_replace_route(
    ops: &dyn WindowsNetworkOps,
    route: &RouteRecord,
) -> Result<(), NetOpsError> {
    match ops.add_route(route) {
        Ok(()) => Ok(()),
        Err(NetOpsError::Win32 { code, .. }) if code == ERROR_OBJECT_ALREADY_EXISTS_CODE => {
            let _ = ops.remove_route(route);
            ops.add_route(route)
        }
        Err(err) => Err(err),
    }
}

fn restore_snapshot_state(
    ops: &dyn WindowsNetworkOps,
    snapshot: &RecoverySnapshot,
) -> Result<(), RuntimeError> {
    let mut errors = Vec::new();

    for route in &snapshot.pinned_host_routes {
        if let Err(err) = remove_route_ignore_missing(ops, route) {
            errors.push(format!(
                "remove pinned host route {}: {err}",
                route.destination_prefix
            ));
        }
    }

    for entry in snapshot.vpn_entries.values() {
        if let Err(err) = restore_vpn(ops, entry) {
            errors.push(format!("restore {:?}: {err}", entry.provider));
        }
    }

    if let Some(ref proxy) = snapshot.system_proxy {
        if let Err(err) = ops.set_system_proxy(proxy) {
            errors.push(format!("restore system proxy: {err}"));
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(RuntimeError::RestoreFailed(errors.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use serde_json::Value;
    use uuid::Uuid;

    use super::*;
    use crate::discovery::{
        DetectedVpnInfo, DiscoveryError, DiscoverySnapshot, PhysicalInterfaceInfo, SystemDiscovery,
    };
    use crate::model::{
        NodeKind, VpnNodeSettings, VpnProvider, WarpMode, WorkflowEdge, WorkflowGraph,
        WorkflowNode,
    };
    use crate::recovery::{
        InterfaceMetricSnapshot, RecoverySnapshot, RecoveryStore, RouteRecord, SystemProxySnapshot,
        VpnRecoveryEntry,
    };
    use crate::win_net::{NetOpsError, WindowsNetworkOps};

    fn temp_test_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("netflow-t8-{label}-{}", Uuid::new_v4()));
        fs::create_dir_all(&dir).expect("create test temp dir");
        dir
    }

    fn iface_node(id: &str, alias: &str, is_default: bool) -> WorkflowNode {
        WorkflowNode {
            id: id.to_string(),
            x: 0.0,
            y: 0.0,
            kind: NodeKind::Interface {
                interface_alias: alias.to_string(),
                is_default,
            },
        }
    }

    fn vpn_node(
        id: &str,
        provider: VpnProvider,
        is_default: bool,
        settings: VpnNodeSettings,
    ) -> WorkflowNode {
        WorkflowNode {
            id: id.to_string(),
            x: 0.0,
            y: 0.0,
            kind: NodeKind::Vpn {
                provider,
                is_default,
                settings,
            },
        }
    }

    fn apps_node(id: &str, apps: &[&str]) -> WorkflowNode {
        WorkflowNode {
            id: id.to_string(),
            x: 0.0,
            y: 0.0,
            kind: NodeKind::Apps {
                apps: apps.iter().map(|s| (*s).to_string()).collect(),
            },
        }
    }

    fn edge(id: &str, source: &str, target: &str) -> WorkflowEdge {
        WorkflowEdge {
            id: id.to_string(),
            source: source.to_string(),
            target: target.to_string(),
        }
    }

    fn route(if_index: u32, prefix: &str, next_hop: &str, metric: u32, is_ipv6: bool) -> RouteRecord {
        RouteRecord {
            interface_index: if_index,
            destination_prefix: prefix.to_string(),
            next_hop: next_hop.to_string(),
            route_metric: metric,
            is_ipv6,
        }
    }

    struct MockDiscovery {
        snapshot: Mutex<DiscoverySnapshot>,
    }

    impl MockDiscovery {
        fn new(snapshot: DiscoverySnapshot) -> Self {
            Self {
                snapshot: Mutex::new(snapshot),
            }
        }

        fn set_vpn_running(&self, provider: VpnProvider, running: bool) {
            let mut guard = self.snapshot.lock().unwrap();
            if let Some(vpn) = guard.vpns.iter_mut().find(|v| v.provider == provider) {
                vpn.is_running = running;
            }
        }

        fn set_interface_up(&self, alias: &str, is_up: bool) {
            let mut guard = self.snapshot.lock().unwrap();
            if let Some(iface) = guard
                .interfaces
                .iter_mut()
                .find(|i| i.alias.eq_ignore_ascii_case(alias))
            {
                iface.is_up = is_up;
            }
        }
    }

    impl SystemDiscovery for MockDiscovery {
        fn snapshot(&self) -> Result<DiscoverySnapshot, DiscoveryError> {
            Ok(self.snapshot.lock().unwrap().clone())
        }
    }

    #[derive(Default)]
    struct MockNetState {
        routes: HashMap<u32, Vec<RouteRecord>>,
        metrics: HashMap<(u32, bool), InterfaceMetricSnapshot>,
        system_proxy: Option<SystemProxySnapshot>,
        warp_mode: Option<String>,
        best_route_interface: Option<String>,
        aliases: HashMap<String, u32>,
        ops_log: Vec<String>,
        recovery_path_to_probe: Option<PathBuf>,
        recovery_existed_before_first_mutation: Option<bool>,
        warp_sync_discovery: Option<Arc<MockDiscovery>>,
    }

    struct MockNetworkOps {
        state: Mutex<MockNetState>,
    }

    impl MockNetworkOps {
        fn new(initial_proxy: SystemProxySnapshot) -> Self {
            let state = MockNetState {
                system_proxy: Some(initial_proxy),
                best_route_interface: Some(TUN_INTERFACE_ALIAS.to_string()),
                ..Default::default()
            };
            Self {
                state: Mutex::new(state),
            }
        }

        fn probe_recovery_path(&self, path: PathBuf) {
            self.state.lock().unwrap().recovery_path_to_probe = Some(path);
        }

        fn set_best_route_interface(&self, alias: Option<&str>) {
            self.state.lock().unwrap().best_route_interface = alias.map(ToString::to_string);
        }

        fn register_alias(&self, alias: &str, if_index: u32) {
            self.state
                .lock()
                .unwrap()
                .aliases
                .insert(alias.to_string(), if_index);
        }

        fn seed_interface(&self, if_index: u32, metric: u32, auto: bool, routes: Vec<RouteRecord>) {
            let mut state = self.state.lock().unwrap();
            state.metrics.insert(
                (if_index, false),
                InterfaceMetricSnapshot {
                    interface_index: if_index,
                    is_ipv6: false,
                    original_metric: metric,
                    automatic_metric: auto,
                },
            );
            state.routes.insert(if_index, routes);
        }

        #[allow(clippy::type_complexity)]
        fn snapshot_state(
            &self,
        ) -> (
            Vec<String>,
            SystemProxySnapshot,
            HashMap<u32, Vec<RouteRecord>>,
            HashMap<(u32, bool), InterfaceMetricSnapshot>,
            Option<bool>,
        ) {
            let s = self.state.lock().unwrap();
            (
                s.ops_log.clone(),
                s.system_proxy.clone().unwrap(),
                s.routes.clone(),
                s.metrics.clone(),
                s.recovery_existed_before_first_mutation,
            )
        }

        fn clear_ops_log(&self) {
            self.state.lock().unwrap().ops_log.clear();
        }

        fn set_warp_mode(&self, mode: Option<&str>) {
            self.state.lock().unwrap().warp_mode = mode.map(ToString::to_string);
        }

        fn attach_warp_discovery_sync(&self, discovery: Arc<MockDiscovery>) {
            self.state.lock().unwrap().warp_sync_discovery = Some(discovery);
        }
    }

    fn record_mutation_probe(state: &mut MockNetState, op: String) {
        if state.recovery_existed_before_first_mutation.is_none() {
            if let Some(ref path) = state.recovery_path_to_probe {
                state.recovery_existed_before_first_mutation = Some(path.exists());
            }
        }
        state.ops_log.push(op);
    }

    impl WindowsNetworkOps for MockNetworkOps {
        fn list_routes(
            &self,
            interface_index: Option<u32>,
            is_ipv6: bool,
        ) -> Result<Vec<RouteRecord>, NetOpsError> {
            let state = self.state.lock().unwrap();
            let mut out = Vec::new();
            match interface_index {
                Some(idx) => {
                    if let Some(list) = state.routes.get(&idx) {
                        out.extend(list.iter().filter(|r| r.is_ipv6 == is_ipv6).cloned());
                    }
                }
                None => {
                    for list in state.routes.values() {
                        out.extend(list.iter().filter(|r| r.is_ipv6 == is_ipv6).cloned());
                    }
                }
            }
            Ok(out)
        }

        fn add_route(&self, route: &RouteRecord) -> Result<(), NetOpsError> {
            let mut state = self.state.lock().unwrap();
            record_mutation_probe(
                &mut state,
                format!(
                    "add_route:{}:{}:{}:{}",
                    route.interface_index,
                    route.destination_prefix,
                    route.next_hop,
                    route.route_metric
                ),
            );
            state
                .routes
                .entry(route.interface_index)
                .or_default()
                .push(route.clone());
            Ok(())
        }

        fn remove_route(&self, route: &RouteRecord) -> Result<(), NetOpsError> {
            let mut state = self.state.lock().unwrap();
            record_mutation_probe(
                &mut state,
                format!(
                    "remove_route:{}:{}:{}",
                    route.interface_index, route.destination_prefix, route.next_hop
                ),
            );
            let list = state.routes.entry(route.interface_index).or_default();
            if let Some(pos) = list.iter().position(|r| {
                r.destination_prefix == route.destination_prefix
                    && r.next_hop == route.next_hop
                    && r.is_ipv6 == route.is_ipv6
            }) {
                list.remove(pos);
                Ok(())
            } else {
                Err(NetOpsError::RouteNotFound {
                    interface_index: route.interface_index,
                    prefix: route.destination_prefix.clone(),
                    next_hop: route.next_hop.clone(),
                })
            }
        }

        fn get_interface_metric(
            &self,
            interface_index: u32,
            is_ipv6: bool,
        ) -> Result<InterfaceMetricSnapshot, NetOpsError> {
            let state = self.state.lock().unwrap();
            state
                .metrics
                .get(&(interface_index, is_ipv6))
                .cloned()
                .ok_or(NetOpsError::Win32 {
                    operation: "GetIpInterfaceEntry",
                    code: ERROR_NOT_FOUND_CODE,
                    message: "not found".to_string(),
                })
        }

        fn set_interface_metric(
            &self,
            interface_index: u32,
            is_ipv6: bool,
            metric: u32,
            automatic_metric: bool,
        ) -> Result<(), NetOpsError> {
            let mut state = self.state.lock().unwrap();
            record_mutation_probe(
                &mut state,
                format!(
                    "set_interface_metric:{interface_index}:{is_ipv6}:{metric}:{automatic_metric}"
                ),
            );
            state.metrics.insert(
                (interface_index, is_ipv6),
                InterfaceMetricSnapshot {
                    interface_index,
                    is_ipv6,
                    original_metric: metric,
                    automatic_metric,
                },
            );
            Ok(())
        }

        fn find_best_route_interface(&self, dest_ipv4: &str) -> Result<Option<String>, NetOpsError> {
            let mut state = self.state.lock().unwrap();
            state
                .ops_log
                .push(format!("find_best_route_interface:{dest_ipv4}"));
            Ok(state.best_route_interface.clone())
        }

        fn find_interface_index_by_alias(&self, alias: &str) -> Result<Option<u32>, NetOpsError> {
            let mut state = self.state.lock().unwrap();
            state
                .ops_log
                .push(format!("find_interface_index_by_alias:{alias}"));
            Ok(state
                .aliases
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(alias))
                .map(|(_, v)| *v))
        }

        fn get_system_proxy(&self) -> Result<SystemProxySnapshot, NetOpsError> {
            let mut state = self.state.lock().unwrap();
            state.ops_log.push("get_system_proxy".to_string());
            Ok(state.system_proxy.clone().unwrap())
        }

        fn set_system_proxy(&self, snapshot: &SystemProxySnapshot) -> Result<(), NetOpsError> {
            let mut state = self.state.lock().unwrap();
            record_mutation_probe(&mut state, "set_system_proxy".to_string());
            state.system_proxy = Some(snapshot.clone());
            Ok(())
        }

        fn disable_system_proxy(&self) -> Result<(), NetOpsError> {
            let mut state = self.state.lock().unwrap();
            record_mutation_probe(&mut state, "disable_system_proxy".to_string());
            if let Some(proxy) = state.system_proxy.as_mut() {
                proxy.proxy_enable = 0;
            }
            Ok(())
        }

        fn warp_cli_get_mode(&self) -> Result<Option<String>, NetOpsError> {
            Ok(self.state.lock().unwrap().warp_mode.clone())
        }

        fn warp_cli_set_mode(&self, mode: &str) -> Result<(), NetOpsError> {
            let sync_discovery = {
                let mut state = self.state.lock().unwrap();
                record_mutation_probe(&mut state, format!("warp_cli_set_mode:{mode}"));
                state.warp_mode = Some(mode.to_string());
                if mode.eq_ignore_ascii_case("proxy") {
                    state.routes.remove(&40);
                    state.metrics.remove(&(40, false));
                } else {
                    state.metrics.insert(
                        (40, false),
                        InterfaceMetricSnapshot {
                            interface_index: 40,
                            is_ipv6: false,
                            original_metric: 15,
                            automatic_metric: true,
                        },
                    );
                    state.routes.insert(
                        40,
                        vec![
                            route(40, "0.0.0.0/0", "172.16.0.1", 0, false),
                            route(40, "0.0.0.0/1", "172.16.0.1", 0, false),
                        ],
                    );
                }
                state.warp_sync_discovery.clone()
            };

            if let Some(discovery) = sync_discovery {
                let mut guard = discovery.snapshot.lock().unwrap();
                if let Some(warp) = guard
                    .vpns
                    .iter_mut()
                    .find(|v| v.provider == VpnProvider::CloudflareWarp)
                {
                    warp.warp_current_mode = Some(mode.to_string());
                    if mode.eq_ignore_ascii_case("proxy") {
                        warp.detected_port = Some(40000);
                        warp.adapter_alias = None;
                        warp.adapter_if_index = None;
                        warp.adapter_gateway = None;
                    } else {
                        warp.detected_port = None;
                        warp.adapter_alias = Some("CloudflareWARP".to_string());
                        warp.adapter_if_index = Some(40);
                        warp.adapter_gateway = Some("172.16.0.1".to_string());
                    }
                }
            }
            Ok(())
        }
    }

    #[derive(Default)]
    struct MockSidecarState {
        spawn_calls: Vec<PathBuf>,
        last_spawned_json: Option<Value>,
        kill_count: usize,
        alive: bool,
        fail_spawn: bool,
    }

    struct MockSidecarRunner {
        state: Mutex<MockSidecarState>,
        ops_log_sink: Option<Arc<MockNetworkOps>>,
    }

    impl MockSidecarRunner {
        fn new(ops_log_sink: Option<Arc<MockNetworkOps>>) -> Self {
            Self {
                state: Mutex::new(MockSidecarState::default()),
                ops_log_sink,
            }
        }

        fn set_fail_spawn(&self, fail: bool) {
            self.state.lock().unwrap().fail_spawn = fail;
        }

        fn set_alive(&self, alive: bool) {
            self.state.lock().unwrap().alive = alive;
        }

        fn stats(&self) -> (Vec<PathBuf>, usize, bool, Option<Value>) {
            let s = self.state.lock().unwrap();
            (
                s.spawn_calls.clone(),
                s.kill_count,
                s.alive,
                s.last_spawned_json.clone(),
            )
        }
    }

    impl SidecarRunner for MockSidecarRunner {
        fn spawn(&self, config_path: &Path) -> Result<(), SidecarError> {
            if let Some(ref ops) = self.ops_log_sink {
                ops.state
                    .lock()
                    .unwrap()
                    .ops_log
                    .push(format!("sidecar.spawn:{}", config_path.display()));
            }
            let mut state = self.state.lock().unwrap();
            if state.fail_spawn {
                return Err(SidecarError::ExitedImmediately("exit code 1".to_string()));
            }
            let raw = fs::read_to_string(config_path).expect("compiled sing-box.json exists");
            let json: Value = serde_json::from_str(&raw).expect("valid sing-box JSON");
            state.last_spawned_json = Some(json);
            state.spawn_calls.push(config_path.to_path_buf());
            state.alive = true;
            Ok(())
        }

        fn is_alive(&self) -> bool {
            self.state.lock().unwrap().alive
        }

        fn kill(&self) -> Result<(), SidecarError> {
            if let Some(ref ops) = self.ops_log_sink {
                ops.state.lock().unwrap().ops_log.push("sidecar.kill".to_string());
            }
            let mut state = self.state.lock().unwrap();
            state.kill_count += 1;
            state.alive = false;
            Ok(())
        }
    }

    fn base_discovery_snapshot() -> DiscoverySnapshot {
        DiscoverySnapshot {
            interfaces: vec![
                PhysicalInterfaceInfo {
                    alias: "Wi-Fi".to_string(),
                    description: "Intel Wi-Fi 6".to_string(),
                    if_index: 12,
                    ipv4: Some("192.168.1.50".to_string()),
                    gateway_ipv4: Some("192.168.1.1".to_string()),
                    is_up: true,
                    link_speed_mbps: 866,
                    is_default_gateway: true,
                },
                PhysicalInterfaceInfo {
                    alias: "Ethernet".to_string(),
                    description: "Realtek PCIe".to_string(),
                    if_index: 15,
                    ipv4: None,
                    gateway_ipv4: None,
                    is_up: false,
                    link_speed_mbps: 0,
                    is_default_gateway: false,
                },
            ],
            vpns: vec![
                DetectedVpnInfo {
                    provider: VpnProvider::Karing,
                    is_running: true,
                    detected_port: Some(3067),
                    adapter_alias: Some("karing-tun".to_string()),
                    adapter_if_index: Some(20),
                    adapter_gateway: Some("172.16.0.2".to_string()),
                    remote_server_ip: None,
                    warp_current_mode: None,
                },
                DetectedVpnInfo {
                    provider: VpnProvider::OpenVpn,
                    is_running: true,
                    detected_port: None,
                    adapter_alias: Some("OpenVPN Data Channel Offload".to_string()),
                    adapter_if_index: Some(30),
                    adapter_gateway: None,
                    remote_server_ip: Some("203.0.113.10".to_string()),
                    warp_current_mode: None,
                },
                DetectedVpnInfo {
                    provider: VpnProvider::CloudflareWarp,
                    is_running: true,
                    detected_port: None,
                    adapter_alias: Some("CloudflareWARP".to_string()),
                    adapter_if_index: Some(40),
                    adapter_gateway: Some("172.16.0.1".to_string()),
                    remote_server_ip: None,
                    warp_current_mode: Some("warp".to_string()),
                },
            ],
            processes: vec![],
        }
    }

    fn seed_vpn_routes(ops: &MockNetworkOps) {
        ops.seed_interface(
            20,
            5,
            true,
            vec![
                route(20, "0.0.0.0/1", "172.16.0.2", 0, false),
                route(20, "128.0.0.0/1", "172.16.0.2", 0, false),
            ],
        );
        ops.seed_interface(
            30,
            10,
            true,
            vec![
                route(30, "0.0.0.0/1", "0.0.0.0", 0, false),
                route(30, "128.0.0.0/1", "0.0.0.0", 0, false),
            ],
        );
        ops.seed_interface(
            40,
            15,
            true,
            vec![
                route(40, "0.0.0.0/0", "172.16.0.1", 0, false),
                route(40, "0.0.0.0/1", "172.16.0.1", 0, false),
            ],
        );
        ops.register_alias(TUN_INTERFACE_ALIAS, 99);
    }

    fn karing_workflow() -> WorkflowGraph {
        WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, VpnNodeSettings::default()),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "apps-1"),
            ],
        }
    }

    fn make_runtime(
        dir: &Path,
        discovery: Arc<MockDiscovery>,
        ops: Arc<MockNetworkOps>,
        sidecar: Arc<MockSidecarRunner>,
    ) -> EngineRuntime {
        let recovery_path = dir.join("recovery.json");
        ops.probe_recovery_path(recovery_path.clone());
        EngineRuntime::new(
            discovery,
            ops,
            sidecar,
            RecoveryStore::new(recovery_path),
            EngineRuntimeConfig {
                runtime_dir: dir.join("runtime"),
                clash_api_port: 19090,
                health_poll_interval: Duration::from_millis(20),
                tun_ready_attempts: 2,
                tun_ready_retry_delay: Duration::from_millis(5),
            },
        )
    }

    #[tokio::test]
    async fn test_apply_writes_recovery_before_mutations_disables_proxy_and_enforces_tun_priority() {
        let dir = temp_test_dir("cold-apply");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: Some("localhost".to_string()),
        }));
        seed_vpn_routes(&ops);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), Arc::clone(&sidecar));

        let status = runtime
            .apply(Some("wf-1".to_string()), &karing_workflow())
            .await
            .expect("apply succeeds");
        assert_eq!(status.state, RuntimeState::Active);
        assert_eq!(status.active_workflow_id.as_deref(), Some("wf-1"));

        let (ops_log, proxy, _, metrics, recovery_before_mutation) = ops.snapshot_state();
        assert_eq!(
            recovery_before_mutation,
            Some(true),
            "recovery.json must be written BEFORE any OS route/proxy mutation"
        );
        assert_eq!(proxy.proxy_enable, 0);

        let pos_disable_proxy = ops_log
            .iter()
            .position(|e| e == "disable_system_proxy")
            .expect("disable_system_proxy called");
        let pos_remove_route = ops_log
            .iter()
            .position(|e| e.starts_with("remove_route:20:"))
            .expect("karing split route removed");
        let pos_spawn = ops_log
            .iter()
            .position(|e| e.starts_with("sidecar.spawn:"))
            .expect("sidecar spawned");
        let pos_best_route = ops_log
            .iter()
            .position(|e| e == "find_best_route_interface:1.1.1.1")
            .expect("checked best route interface");
        assert!(pos_disable_proxy < pos_remove_route);
        assert!(pos_remove_route < pos_spawn);
        assert!(pos_spawn < pos_best_route);
        assert!(!metrics.contains_key(&(99, false)));

        runtime.stop().await.expect("clean stop");

        // Second verification: if NetFlow-TUN is NOT the best route initially, enforce metric=1 and /1 routes.
        let dir2 = temp_test_dir("tun-enforce");
        let discovery2 = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops2 = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops2);
        ops2.set_best_route_interface(Some("Wi-Fi"));
        let sidecar2 = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops2))));
        let runtime2 = make_runtime(&dir2, discovery2, Arc::clone(&ops2), sidecar2);

        runtime2
            .apply(None, &karing_workflow())
            .await
            .expect("apply enforces tun priority");

        let (_, _, routes2, metrics2, _) = ops2.snapshot_state();
        assert_eq!(
            metrics2.get(&(99, false)),
            Some(&InterfaceMetricSnapshot {
                interface_index: 99,
                is_ipv6: false,
                original_metric: 1,
                automatic_metric: false,
            })
        );
        let tun_routes = routes2.get(&99).expect("NetFlow-TUN routes added");
        assert!(tun_routes.contains(&route(99, "0.0.0.0/1", TUN_GATEWAY_IPV4, 0, false)));
        assert!(tun_routes.contains(&route(99, "128.0.0.0/1", TUN_GATEWAY_IPV4, 0, false)));

        runtime2.stop().await.expect("clean stop");
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::remove_dir_all(&dir2);
    }

    #[tokio::test]
    async fn test_partial_apply_failure_rolls_back_all_mutations() {
        let dir = temp_test_dir("rollback");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let initial_proxy = SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: Some("localhost".to_string()),
        };
        let ops = Arc::new(MockNetworkOps::new(initial_proxy.clone()));
        seed_vpn_routes(&ops);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        sidecar.set_fail_spawn(true);

        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), sidecar);
        let err = runtime
            .apply(Some("wf-fail".to_string()), &karing_workflow())
            .await
            .expect_err("sidecar spawn failure must trigger rollback error");
        assert!(matches!(err, RuntimeError::Sidecar(_)));

        let (_, proxy, routes, metrics, _) = ops.snapshot_state();
        assert_eq!(proxy, initial_proxy, "system proxy must be restored");
        let karing_routes = routes.get(&20).expect("karing routes present");
        assert_eq!(karing_routes.len(), 2);
        assert!(karing_routes.contains(&route(20, "0.0.0.0/1", "172.16.0.2", 0, false)));
        assert!(karing_routes.contains(&route(20, "128.0.0.0/1", "172.16.0.2", 0, false)));
        assert_eq!(
            metrics.get(&(20, false)),
            Some(&InterfaceMetricSnapshot {
                interface_index: 20,
                is_ipv6: false,
                original_metric: 5,
                automatic_metric: true,
            })
        );
        assert!(
            !dir.join("recovery.json").exists(),
            "recovery.json must be cleared after successful rollback"
        );
        assert_eq!(runtime.status().state, RuntimeState::Error);
        assert!(runtime.status().last_error.is_some());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_stale_recovery_on_startup_restores_routes_and_proxy() {
        let dir = temp_test_dir("stale-recovery");
        let recovery_path = dir.join("recovery.json");
        let store = RecoveryStore::new(recovery_path.clone());

        let original_proxy = SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: Some("localhost".to_string()),
        };
        let mut vpn_entries = HashMap::new();
        vpn_entries.insert(
            VpnProvider::Karing,
            VpnRecoveryEntry {
                provider: VpnProvider::Karing,
                removed_routes: vec![
                    route(20, "0.0.0.0/1", "172.16.0.2", 0, false),
                    route(20, "128.0.0.0/1", "172.16.0.2", 0, false),
                ],
                added_routes: vec![route(20, "0.0.0.0/0", "172.16.0.2", 500, false)],
                metric_snapshots: vec![InterfaceMetricSnapshot {
                    interface_index: 20,
                    is_ipv6: false,
                    original_metric: 5,
                    automatic_metric: true,
                }],
                warp_previous_mode: None,
            },
        );
        let pinned = route(12, "203.0.113.10/32", "192.168.1.1", 0, false);

        store
            .save_atomic(&RecoverySnapshot {
                created_at: "2026-11-24T00:00:00Z".to_string(),
                system_proxy: Some(original_proxy.clone()),
                vpn_entries,
                pinned_host_routes: vec![pinned.clone()],
            })
            .expect("seed stale recovery.json");

        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: Some("localhost".to_string()),
        }));
        ops.seed_interface(12, 25, true, vec![pinned]);
        ops.seed_interface(
            20,
            500,
            false,
            vec![route(20, "0.0.0.0/0", "172.16.0.2", 500, false)],
        );
        let sidecar = Arc::new(MockSidecarRunner::new(None));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), sidecar);

        assert!(runtime.recover_if_stale().expect("recover stale snapshot"));
        assert!(!recovery_path.exists(), "recovery.json must be deleted");

        let (_, proxy, routes, metrics, _) = ops.snapshot_state();
        assert_eq!(proxy, original_proxy);
        assert!(routes.get(&12).unwrap().is_empty(), "pinned route removed");
        assert_eq!(
            routes.get(&20).unwrap(),
            &vec![
                route(20, "0.0.0.0/1", "172.16.0.2", 0, false),
                route(20, "128.0.0.0/1", "172.16.0.2", 0, false),
            ]
        );
        assert_eq!(
            metrics.get(&(20, false)),
            Some(&InterfaceMetricSnapshot {
                interface_index: 20,
                is_ipv6: false,
                original_metric: 5,
                automatic_metric: true,
            })
        );

        assert!(
            !runtime.recover_if_stale().expect("idempotent second call"),
            "second call returns false"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_apply_rejects_disconnected_interface_before_touching_routes() {
        let dir = temp_test_dir("iface-down");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), Arc::clone(&sidecar));

        let down_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-eth", "Ethernet", false),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![edge("e1", "if-eth", "apps-1")],
        };

        let err = runtime
            .apply(None, &down_graph)
            .await
            .expect_err("down interface must be rejected");
        assert!(
            matches!(err, RuntimeError::InterfaceDown(ref alias) if alias == "Ethernet"),
            "unexpected error: {err:?}"
        );

        let (ops_log, proxy, _, _, _) = ops.snapshot_state();
        assert!(ops_log.is_empty(), "expected zero OS mutation calls, got {ops_log:?}");
        assert_eq!(proxy.proxy_enable, 1);
        assert!(!dir.join("recovery.json").exists());
        assert!(sidecar.stats().0.is_empty());

        // Hot-switch pre-flight failure must also leave existing Active workflow untouched.
        runtime
            .apply(Some("wf-ok".to_string()), &karing_workflow())
            .await
            .expect("initial apply succeeds");
        ops.clear_ops_log();

        let err2 = runtime
            .apply(Some("wf-bad".to_string()), &down_graph)
            .await
            .expect_err("hot-switch to down interface rejected");
        assert!(matches!(err2, RuntimeError::InterfaceDown(ref alias) if alias == "Ethernet"));

        let (ops_log_after, _, _, _, _) = ops.snapshot_state();
        assert!(ops_log_after.is_empty(), "hot-switch rejection must not touch OS");
        let (spawns, kills, alive, _) = sidecar.stats();
        assert_eq!(spawns.len(), 1);
        assert_eq!(kills, 0);
        assert!(alive);
        assert_eq!(runtime.status().state, RuntimeState::Active);
        assert_eq!(runtime.status().active_workflow_id.as_deref(), Some("wf-ok"));

        runtime.stop().await.expect("clean stop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_hot_switch_workflow_preserves_karing_baseline_restores_openvpn_and_neutralizes_warp() {
        let dir = temp_test_dir("hot-switch");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        ops.seed_interface(12, 25, true, vec![]);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), Arc::clone(&sidecar));

        let wf_a = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, VpnNodeSettings::default()),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false, VpnNodeSettings::default()),
                apps_node("apps-1", &["chrome.exe"]),
                apps_node("apps-2", &["firefox.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "apps-1"),
                edge("e3", "if-wifi", "vpn-ovpn"),
                edge("e4", "vpn-ovpn", "apps-2"),
            ],
        };

        let status_a = runtime
            .apply(Some("wf-a".to_string()), &wf_a)
            .await
            .expect("apply workflow A");
        assert_eq!(status_a.state, RuntimeState::Active);

        let store = RecoveryStore::new(dir.join("recovery.json"));
        let snap_a = store.load().unwrap().expect("recovery snapshot after wf-a");
        let karing_baseline = snap_a
            .vpn_entries
            .get(&VpnProvider::Karing)
            .expect("karing baseline")
            .clone();
        assert!(snap_a.vpn_entries.contains_key(&VpnProvider::OpenVpn));
        assert_eq!(snap_a.pinned_host_routes.len(), 1);

        ops.clear_ops_log();

        let wf_b = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, VpnNodeSettings::default()),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    VpnNodeSettings {
                        warp_mode: WarpMode::Tun,
                        ..Default::default()
                    },
                ),
                apps_node("apps-1", &["chrome.exe"]),
                apps_node("apps-2", &["steam.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "apps-1"),
                edge("e3", "if-wifi", "vpn-warp"),
                edge("e4", "vpn-warp", "apps-2"),
            ],
        };

        let status_b = runtime
            .apply(Some("wf-b".to_string()), &wf_b)
            .await
            .expect("hot-switch to workflow B");
        assert_eq!(status_b.state, RuntimeState::Active);
        assert_eq!(status_b.active_workflow_id.as_deref(), Some("wf-b"));

        let snap_b = store.load().unwrap().expect("recovery snapshot after wf-b");
        assert_eq!(
            snap_b.vpn_entries.get(&VpnProvider::Karing),
            Some(&karing_baseline),
            "Karing baseline in recovery.json must remain untouched across hot-switch"
        );
        assert!(
            !snap_b.vpn_entries.contains_key(&VpnProvider::OpenVpn),
            "OpenVPN entry must be removed from recovery.json after restore"
        );
        assert!(
            snap_b.vpn_entries.contains_key(&VpnProvider::CloudflareWarp),
            "WARP entry must be recorded in recovery.json"
        );
        assert!(
            snap_b.pinned_host_routes.is_empty(),
            "old OpenVPN /32 pinned host route must be removed"
        );

        let (ops_log, proxy, routes, metrics, _) = ops.snapshot_state();
        assert_eq!(proxy.proxy_enable, 0);
        assert!(
            !ops_log.iter().any(|e| e.contains(":20:")),
            "Karing adapter (if_index 20) must not be touched during hot-switch: {ops_log:?}"
        );
        assert!(routes.get(&12).unwrap().is_empty(), "pinned /32 route removed");
        assert_eq!(
            routes.get(&30).unwrap(),
            &vec![
                route(30, "0.0.0.0/1", "0.0.0.0", 0, false),
                route(30, "128.0.0.0/1", "0.0.0.0", 0, false),
            ],
            "OpenVPN routes restored"
        );
        assert_eq!(metrics.get(&(30, false)).unwrap().original_metric, 10);
        assert_eq!(
            routes.get(&40).unwrap(),
            &vec![route(40, "0.0.0.0/0", "172.16.0.1", 500, false)],
            "WARP routes neutralized"
        );
        assert_eq!(metrics.get(&(40, false)).unwrap().original_metric, 500);
        assert!(!metrics.get(&(40, false)).unwrap().automatic_metric);
        assert_eq!(
            snap_b
                .vpn_entries
                .get(&VpnProvider::CloudflareWarp)
                .unwrap()
                .metric_snapshots[0]
                .original_metric,
            15
        );

        let (spawns, kills, alive, last_json) = sidecar.stats();
        assert_eq!(kills, 1);
        assert_eq!(spawns.len(), 2);
        assert!(alive);
        let outbounds = last_json.unwrap()["outbounds"].as_array().unwrap().clone();
        assert!(outbounds.iter().any(|o| o["tag"] == "vpn-warp"));
        assert!(!outbounds.iter().any(|o| o["tag"] == "vpn-openvpn"));

        runtime.stop().await.expect("clean stop");
        assert!(!dir.join("recovery.json").exists());
        let (_, proxy_after_stop, routes_after_stop, metrics_after_stop, _) = ops.snapshot_state();
        assert_eq!(proxy_after_stop.proxy_enable, 1);
        assert_eq!(routes_after_stop.get(&20).unwrap().len(), 2);
        assert_eq!(routes_after_stop.get(&40).unwrap().len(), 2);
        assert_eq!(metrics_after_stop.get(&(40, false)).unwrap().original_metric, 15);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_hot_switch_spawn_failure_rolls_back_all_state() {
        let dir = temp_test_dir("hot-switch-rollback");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let initial_proxy = SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: None,
        };
        let ops = Arc::new(MockNetworkOps::new(initial_proxy.clone()));
        seed_vpn_routes(&ops);
        ops.seed_interface(12, 25, true, vec![]);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), Arc::clone(&sidecar));

        runtime
            .apply(Some("wf-a".to_string()), &karing_workflow())
            .await
            .expect("initial apply succeeds");

        sidecar.set_fail_spawn(true);

        let wf_b = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, VpnNodeSettings::default()),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    VpnNodeSettings {
                        warp_mode: WarpMode::Tun,
                        ..Default::default()
                    },
                ),
                apps_node("apps-1", &["chrome.exe"]),
                apps_node("apps-2", &["steam.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "apps-1"),
                edge("e3", "if-wifi", "vpn-warp"),
                edge("e4", "vpn-warp", "apps-2"),
            ],
        };

        let err = runtime
            .apply(Some("wf-b".to_string()), &wf_b)
            .await
            .expect_err("hot-switch spawn failure rolls back");
        assert!(matches!(err, RuntimeError::Sidecar(_)));
        assert_eq!(runtime.status().state, RuntimeState::Error);
        assert!(!dir.join("recovery.json").exists());

        let (_, proxy, routes, metrics, _) = ops.snapshot_state();
        assert_eq!(proxy, initial_proxy);
        assert_eq!(routes.get(&20).unwrap().len(), 2);
        assert_eq!(routes.get(&40).unwrap().len(), 2);
        assert_eq!(metrics.get(&(20, false)).unwrap().original_metric, 5);
        assert_eq!(metrics.get(&(40, false)).unwrap().original_metric, 15);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_health_watcher_flags_dropped_vpn_or_interface_without_fallback() {
        let dir = temp_test_dir("health-watcher");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, Arc::clone(&discovery), Arc::clone(&ops), sidecar);
        let mut events = runtime.subscribe_events();

        runtime
            .apply(Some("wf-watch".to_string()), &karing_workflow())
            .await
            .expect("apply succeeds");
        ops.clear_ops_log();

        discovery.set_vpn_running(VpnProvider::Karing, false);

        let dropped_status = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(RuntimeEvent::StatusChanged(status)) = events.recv().await {
                    if status.state == RuntimeState::Warning {
                        return status;
                    }
                }
            }
        })
        .await
        .expect("health watcher emitted warning status");

        assert_eq!(
            dropped_status.node_health.get("vpn-karing"),
            Some(&NodeHealth::Dropped)
        );
        assert_eq!(
            dropped_status.node_health.get("if-wifi"),
            Some(&NodeHealth::Healthy)
        );
        assert!(dropped_status.warning_banner.is_some());
        assert!(
            ops.snapshot_state().0.is_empty(),
            "fail-closed health watcher must NEVER mutate routes or proxy"
        );

        // Also verify dropping a physical interface flags it without route fallback.
        discovery.set_vpn_running(VpnProvider::Karing, true);
        discovery.set_interface_up("Wi-Fi", false);

        let iface_dropped = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(RuntimeEvent::StatusChanged(status)) = events.recv().await {
                    if status.node_health.get("if-wifi") == Some(&NodeHealth::Dropped) {
                        return status;
                    }
                }
            }
        })
        .await
        .expect("health watcher flagged dropped Wi-Fi");

        assert_eq!(iface_dropped.state, RuntimeState::Warning);
        assert!(iface_dropped.warning_banner.is_some());
        assert!(ops.snapshot_state().0.is_empty());

        runtime.stop().await.expect("clean stop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_health_watcher_restores_and_errors_when_sidecar_dies() {
        let dir = temp_test_dir("sidecar-crash");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let initial_proxy = SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: None,
        };
        let ops = Arc::new(MockNetworkOps::new(initial_proxy.clone()));
        seed_vpn_routes(&ops);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), Arc::clone(&sidecar));
        let mut events = runtime.subscribe_events();

        runtime
            .apply(Some("wf-crash".to_string()), &karing_workflow())
            .await
            .expect("apply succeeds");

        sidecar.set_alive(false);

        let err_status = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Ok(RuntimeEvent::StatusChanged(status)) = events.recv().await {
                    if status.state == RuntimeState::Error {
                        return status;
                    }
                }
            }
        })
        .await
        .expect("health watcher transitioned to Error on unexpected sidecar exit");

        assert!(err_status.last_error.is_some());
        assert!(!dir.join("recovery.json").exists());
        let (_, proxy, routes, _, _) = ops.snapshot_state();
        assert_eq!(proxy, initial_proxy);
        assert_eq!(routes.get(&20).unwrap().len(), 2);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_runtime_types_serialize_camel_case() {
        let status = EngineStatus {
            state: RuntimeState::Warning,
            active_workflow_id: Some("wf-1".to_string()),
            node_health: HashMap::from([("vpn-1".to_string(), NodeHealth::Dropped)]),
            warning_banner: Some("Karing dropped".to_string()),
            last_error: None,
        };
        let event = RuntimeEvent::StatusChanged(status);
        let json: Value = serde_json::to_value(&event).expect("serialize RuntimeEvent");
        assert_eq!(json["type"], "statusChanged");
        assert_eq!(json["payload"]["state"], "warning");
        assert_eq!(json["payload"]["activeWorkflowId"], "wf-1");
        assert_eq!(json["payload"]["nodeHealth"]["vpn-1"], "dropped");
        assert_eq!(json["payload"]["warningBanner"], "Karing dropped");
    }

    #[test]
    fn test_singbox_sidecar_validates_paths_and_is_alive() {
        let dir = temp_test_dir("sidecar-paths");
        let missing_bin = dir.join("missing-sing-box.exe");
        let sidecar = SingBoxSidecar::new(missing_bin.clone(), dir.clone());
        assert_eq!(sidecar.binary_path(), missing_bin.as_path());
        assert_eq!(sidecar.wintun_dir(), dir.as_path());
        assert!(!sidecar.is_alive());
        assert!(matches!(
            sidecar.spawn(&dir.join("sing-box.json")),
            Err(SidecarError::BinaryNotFound(_))
        ));

        let fake_bin = dir.join("fake-sing-box.exe");
        fs::write(&fake_bin, b"not-an-exe").expect("write dummy bin");
        let sidecar2 = SingBoxSidecar::new(fake_bin, dir.join("missing-wintun-dir"));
        assert!(matches!(
            sidecar2.spawn(&dir.join("sing-box.json")),
            Err(SidecarError::WintunDirNotFound(_))
        ));
        sidecar2.kill().expect("kill on non-running sidecar is ok");

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_hot_switch_warp_proxy_to_tun_requeries_discovery_and_preserves_baseline() {
        // Part A: WARP was ALREADY in "proxy" mode prior to NetFlow starting.
        // Applying Proxy -> hot-switching to Tun must switch warp-cli to "warp", re-query
        // fresh discovery to discover CloudflareWARP + TUN routes, neutralize them, compile a
        // TUN direct outbound, preserve pre-NetFlow "proxy" in recovery.json, and restore
        // "proxy" on stop().
        let dir_a = temp_test_dir("warp-proxy-to-tun-orig-proxy");
        let mut snap_a = base_discovery_snapshot();
        if let Some(warp) = snap_a
            .vpns
            .iter_mut()
            .find(|v| v.provider == VpnProvider::CloudflareWarp)
        {
            warp.detected_port = Some(40000);
            warp.adapter_alias = None;
            warp.adapter_if_index = None;
            warp.adapter_gateway = None;
            warp.warp_current_mode = Some("proxy".to_string());
        }
        let discovery_a = Arc::new(MockDiscovery::new(snap_a));
        let ops_a = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        ops_a.register_alias(TUN_INTERFACE_ALIAS, 99);
        ops_a.set_warp_mode(Some("proxy"));
        ops_a.attach_warp_discovery_sync(Arc::clone(&discovery_a));
        let sidecar_a = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops_a))));
        let runtime_a = make_runtime(
            &dir_a,
            Arc::clone(&discovery_a),
            Arc::clone(&ops_a),
            Arc::clone(&sidecar_a),
        );

        let wf_proxy = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    VpnNodeSettings {
                        warp_mode: WarpMode::Proxy,
                        ..Default::default()
                    },
                ),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-warp"),
                edge("e2", "vpn-warp", "apps-1"),
            ],
        };
        let wf_tun = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    VpnNodeSettings {
                        warp_mode: WarpMode::Tun,
                        ..Default::default()
                    },
                ),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-warp"),
                edge("e2", "vpn-warp", "apps-1"),
            ],
        };

        runtime_a
            .apply(Some("wf-proxy".to_string()), &wf_proxy)
            .await
            .expect("apply WARP proxy workflow");
        let store_a = RecoveryStore::new(dir_a.join("recovery.json"));
        let rec_proxy = store_a.load().unwrap().expect("recovery after proxy");
        assert_eq!(
            rec_proxy
                .vpn_entries
                .get(&VpnProvider::CloudflareWarp)
                .unwrap()
                .warp_previous_mode,
            None
        );

        ops_a.clear_ops_log();

        runtime_a
            .apply(Some("wf-tun".to_string()), &wf_tun)
            .await
            .expect("hot-switch WARP Proxy -> Tun succeeds");

        let (ops_log_a, _, routes_a, metrics_a, _) = ops_a.snapshot_state();
        let pos_warp_mode = ops_log_a
            .iter()
            .position(|e| e == "warp_cli_set_mode:warp")
            .expect("warp-cli switched to warp mode");
        let pos_warp_remove = ops_log_a
            .iter()
            .position(|e| e.starts_with("remove_route:40:"))
            .expect("fresh TUN routes neutralized");
        assert!(
            pos_warp_mode < pos_warp_remove,
            "must switch warp-cli before neutralizing freshly created TUN routes"
        );
        assert_eq!(
            routes_a.get(&40).unwrap(),
            &vec![route(40, "0.0.0.0/0", "172.16.0.1", 500, false)]
        );
        assert_eq!(metrics_a.get(&(40, false)).unwrap().original_metric, 500);

        let rec_tun = store_a.load().unwrap().expect("recovery after Proxy -> Tun");
        let warp_entry = rec_tun
            .vpn_entries
            .get(&VpnProvider::CloudflareWarp)
            .expect("warp recovery entry");
        assert_eq!(
            warp_entry.warp_previous_mode.as_deref(),
            Some("proxy"),
            "pre-NetFlow 'proxy' baseline must be preserved in recovery.json"
        );
        assert_eq!(warp_entry.removed_routes.len(), 2);

        let (_, _, _, last_json_a) = sidecar_a.stats();
        let warp_outbound = last_json_a.unwrap()["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "vpn-warp")
            .cloned()
            .expect("vpn-warp outbound present");
        assert_eq!(warp_outbound["type"], "direct");
        assert_eq!(warp_outbound["bind_interface"], "CloudflareWARP");

        ops_a.clear_ops_log();
        runtime_a.stop().await.expect("clean stop");
        let (stop_ops_a, _, _, _, _) = ops_a.snapshot_state();
        assert!(
            stop_ops_a.iter().any(|e| e == "warp_cli_set_mode:proxy"),
            "stop() must restore pre-NetFlow 'proxy' mode: {stop_ops_a:?}"
        );
        assert_eq!(
            ops_a.warp_cli_get_mode().unwrap().as_deref(),
            Some("proxy")
        );

        // Part B: WARP was originally in "warp+doh" TUN mode -> Proxy -> Tun hot-switch.
        let dir_b = temp_test_dir("warp-proxy-to-tun-orig-doh");
        let mut snap_b = base_discovery_snapshot();
        if let Some(warp) = snap_b
            .vpns
            .iter_mut()
            .find(|v| v.provider == VpnProvider::CloudflareWarp)
        {
            warp.warp_current_mode = Some("warp+doh".to_string());
        }
        let discovery_b = Arc::new(MockDiscovery::new(snap_b));
        let ops_b = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops_b);
        ops_b.set_warp_mode(Some("warp+doh"));
        ops_b.attach_warp_discovery_sync(Arc::clone(&discovery_b));
        let sidecar_b = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops_b))));
        let runtime_b = make_runtime(
            &dir_b,
            Arc::clone(&discovery_b),
            Arc::clone(&ops_b),
            Arc::clone(&sidecar_b),
        );

        runtime_b
            .apply(Some("wf-proxy".to_string()), &wf_proxy)
            .await
            .expect("apply WARP proxy");
        assert_eq!(
            ops_b.warp_cli_get_mode().unwrap().as_deref(),
            Some("proxy")
        );

        runtime_b
            .apply(Some("wf-tun".to_string()), &wf_tun)
            .await
            .expect("hot-switch Proxy -> Tun restores warp+doh then neutralizes TUN");
        assert_eq!(
            ops_b.warp_cli_get_mode().unwrap().as_deref(),
            Some("warp+doh")
        );
        let (_, _, routes_b, _, _) = ops_b.snapshot_state();
        assert_eq!(
            routes_b.get(&40).unwrap(),
            &vec![route(40, "0.0.0.0/0", "172.16.0.1", 500, false)]
        );

        let store_b = RecoveryStore::new(dir_b.join("recovery.json"));
        let rec_b = store_b.load().unwrap().expect("recovery after B");
        assert_eq!(
            rec_b
                .vpn_entries
                .get(&VpnProvider::CloudflareWarp)
                .unwrap()
                .warp_previous_mode,
            None
        );

        runtime_b.stop().await.expect("clean stop B");
        assert_eq!(
            ops_b.warp_cli_get_mode().unwrap().as_deref(),
            Some("warp+doh")
        );
        let (_, _, routes_b_after, metrics_b_after, _) = ops_b.snapshot_state();
        assert_eq!(routes_b_after.get(&40).unwrap().len(), 2);
        assert_eq!(metrics_b_after.get(&(40, false)).unwrap().original_metric, 15);

        let _ = fs::remove_dir_all(&dir_a);
        let _ = fs::remove_dir_all(&dir_b);
    }
}
