use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, TcpListener};
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
    NodeKind, ValidatedGraph, ValidatedVpnChain, ValidationError, VpnProvider, WorkflowGraph,
};
use crate::recovery::{
    InterfaceMetricSnapshot, RecoveryError, RecoverySnapshot, RecoveryStore, RouteRecord,
};
use crate::storage::{default_netflow_dir, write_atomic};
use crate::traffic::{LiveConnection, TrafficMonitor};
use crate::validator::validate_graph;
use crate::vpn_adapters::{
    neutralize_vpn, pin_openvpn_dco_host_route, preflight_and_resolve_vpn, restore_vpn,
    VpnAdapterError,
};
use crate::win_net::{
    is_benign_remove_route_error, is_benign_restore_add_route_error, NetOpsError,
    WindowsNetworkOps, ERROR_OBJECT_ALREADY_EXISTS_CODE,
};

const TUN_INTERFACE_ALIAS: &str = "NetFlow-TUN";
const TUN_GATEWAY_IPV4: &str = "172.19.0.2";
const DEFAULT_CLASH_API_PORT: u16 = 0;
const FALLBACK_CLASH_API_PORT: u16 = 19090;
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
    /// Returns the OS process ID of the currently running managed `sing-box` child, if any.
    fn pid(&self) -> Option<u32>;
    /// Terminates the managed `sing-box` process if it is running.
    fn kill(&self) -> Result<(), SidecarError>;
    /// Terminates an orphaned `sing-box` process by PID after verifying its executable image name.
    fn kill_pid(&self, pid: u32) -> Result<(), RuntimeError>;
}

#[cfg(windows)]
struct JobHandle(windows::Win32::Foundation::HANDLE);

#[cfg(windows)]
unsafe impl Send for JobHandle {}

#[cfg(windows)]
impl Drop for JobHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

struct ManagedChild {
    child: Child,
    #[cfg(windows)]
    _job: Option<JobHandle>,
}

/// Real OS process runner for `sing-box.exe`.
pub struct SingBoxSidecar {
    binary_path: PathBuf,
    wintun_dir: PathBuf,
    child: Mutex<Option<ManagedChild>>,
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
            terminate_child(&mut existing.child)?;
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

        #[cfg(windows)]
        let job = match attach_kill_on_close_job(&child) {
            Ok(job) => Some(job),
            Err(err) => {
                let _ = terminate_child(&mut child);
                return Err(err);
            }
        };

        *guard = Some(ManagedChild {
            child,
            #[cfg(windows)]
            _job: job,
        });
        Ok(())
    }

    fn is_alive(&self) -> bool {
        let mut guard = self.child.lock().expect("sidecar child mutex poisoned");
        let Some(managed) = guard.as_mut() else {
            return false;
        };
        match managed.child.try_wait() {
            Ok(None) => true,
            _ => {
                *guard = None;
                false
            }
        }
    }

    fn pid(&self) -> Option<u32> {
        let mut guard = self.child.lock().expect("sidecar child mutex poisoned");
        let managed = guard.as_mut()?;
        match managed.child.try_wait() {
            Ok(None) => Some(managed.child.id()),
            _ => {
                *guard = None;
                None
            }
        }
    }

    fn kill(&self) -> Result<(), SidecarError> {
        let mut guard = self.child.lock().expect("sidecar child mutex poisoned");
        let Some(mut managed) = guard.take() else {
            return Ok(());
        };
        terminate_child(&mut managed.child)
    }

    fn kill_pid(&self, pid: u32) -> Result<(), RuntimeError> {
        if pid == 0 {
            return Ok(());
        }
        if self.pid() == Some(pid) {
            return self.kill().map_err(RuntimeError::from);
        }
        #[cfg(windows)]
        {
            kill_orphaned_singbox_pid(pid)
        }
        #[cfg(not(windows))]
        {
            Ok(())
        }
    }
}

fn is_singbox_image_path(path: &str) -> bool {
    let Some(filename) = path.trim().rsplit(['\\', '/']).next() else {
        return false;
    };
    let lower = filename.to_ascii_lowercase();
    lower.starts_with("sing-box") && lower.ends_with(".exe")
}

#[cfg(windows)]
fn win32_err_to_io(err: &windows::core::Error) -> std::io::Error {
    let code = (err.code().0 as u32) & 0xFFFF;
    if code != 0 {
        std::io::Error::from_raw_os_error(code as i32)
    } else {
        std::io::Error::other(err.message())
    }
}

#[cfg(windows)]
fn attach_kill_on_close_job(child: &Child) -> Result<JobHandle, SidecarError> {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;

    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    };

    let raw_job = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|e| SidecarError::ProcessControlFailed(win32_err_to_io(&e)))?;
    let job = JobHandle(raw_job);

    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    unsafe {
        SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            (&raw const info).cast::<c_void>(),
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|e| SidecarError::ProcessControlFailed(win32_err_to_io(&e)))?;

    let child_handle = HANDLE(child.as_raw_handle());
    unsafe { AssignProcessToJobObject(job.0, child_handle) }
        .map_err(|e| SidecarError::ProcessControlFailed(win32_err_to_io(&e)))?;

    Ok(job)
}

#[cfg(windows)]
fn kill_orphaned_singbox_pid(pid: u32) -> Result<(), RuntimeError> {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, ERROR_NOT_FOUND, HANDLE,
        STILL_ACTIVE,
    };
    use windows::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, QueryFullProcessImageNameW, TerminateProcess,
        WaitForSingleObject, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        PROCESS_TERMINATE,
    };

    struct ProcessHandleGuard(HANDLE);
    impl Drop for ProcessHandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn query_image_path(handle: HANDLE) -> Option<String> {
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let res = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(buf.as_mut_ptr()),
                &mut len,
            )
        };
        if res.is_ok() && (len as usize) <= buf.len() {
            Some(String::from_utf16_lossy(&buf[..len as usize]))
        } else {
            None
        }
    }

    let handle = match unsafe {
        OpenProcess(
            PROCESS_TERMINATE | PROCESS_QUERY_LIMITED_INFORMATION,
            false,
            pid,
        )
    } {
        Ok(h) => ProcessHandleGuard(h),
        Err(err) => {
            let code = (err.code().0 as u32) & 0xFFFF;
            if code == ERROR_INVALID_PARAMETER.0 || code == ERROR_NOT_FOUND.0 {
                return Ok(());
            }
            if code == ERROR_ACCESS_DENIED.0 {
                if let Ok(q_handle) =
                    unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }
                {
                    let q_guard = ProcessHandleGuard(q_handle);
                    if let Some(path) = query_image_path(q_guard.0) {
                        if !is_singbox_image_path(&path) {
                            // PID was recycled by another application; never terminate it.
                            return Ok(());
                        }
                    }
                    return Err(RuntimeError::Sidecar(SidecarError::ProcessControlFailed(
                        win32_err_to_io(&err),
                    )));
                }
                // Protected system process (PPL) cannot be sing-box.exe.
                return Ok(());
            }
            return Err(RuntimeError::Sidecar(SidecarError::ProcessControlFailed(
                win32_err_to_io(&err),
            )));
        }
    };

    let Some(image_path) = query_image_path(handle.0) else {
        return Ok(());
    };
    if !is_singbox_image_path(&image_path) {
        return Ok(());
    }

    let mut exit_code: u32 = 0;
    if unsafe { GetExitCodeProcess(handle.0, &mut exit_code) }.is_ok()
        && exit_code != STILL_ACTIVE.0 as u32
    {
        return Ok(());
    }

    if let Err(err) = unsafe { TerminateProcess(handle.0, 1) } {
        let mut after_code: u32 = 0;
        if unsafe { GetExitCodeProcess(handle.0, &mut after_code) }.is_ok()
            && after_code != STILL_ACTIVE.0 as u32
        {
            return Ok(());
        }
        return Err(RuntimeError::Sidecar(SidecarError::ProcessControlFailed(
            win32_err_to_io(&err),
        )));
    }

    unsafe {
        let _ = WaitForSingleObject(handle.0, 3_000);
    }
    Ok(())
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
            if let Some(mut managed) = guard.take() {
                let _ = terminate_child(&mut managed.child);
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
    clash_api_port: u16,
    discovery_snap: DiscoverySnapshot,
    vpn_runtime: HashMap<VpnProvider, ResolvedVpnRuntimeInfo>,
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
        if let Some(pid) = snapshot.singbox_pid {
            self.sidecar.kill_pid(pid)?;
        }
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

        let prior_metric_snapshots = {
            let inner = self.inner.lock().expect("engine status mutex poisoned");
            inner
                .active_session
                .as_ref()
                .map(|s| s.recovery.physical_metric_snapshots.clone())
                .unwrap_or_default()
        };

        let prepared = {
            let discovery = Arc::clone(&self.discovery);
            let config = self.config.clone();
            let graph = graph.clone();
            match run_blocking(move || {
                prepare_apply_blocking(&*discovery, &config, &graph, &prior_metric_snapshots)
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

        let mut snapshot = if let Some(old_session) = existing_session {
            let sidecar = Arc::clone(&self.sidecar);
            if let Err(err) = run_blocking(move || sidecar.kill().map_err(RuntimeError::from)).await
            {
                return Err(self
                    .rollback_on_apply_failure(&old_session.recovery, err)
                    .await);
            }
            let mut snap = old_session.recovery;
            snap.singbox_pid = None;
            if let Err(err) = self.reconcile_hot_switch(&prepared, &mut snap).await {
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
                removed_bypass_routes: Vec::new(),
                physical_metric_snapshots: Vec::new(),
                singbox_pid: None,
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

        snapshot.singbox_pid = self.sidecar.pid();
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

        if let Err(err) = self.ensure_tun_route_priority().await {
            return Err(self.rollback_on_apply_failure(&snapshot, err).await);
        }

        let node_health = initial_node_health(&prepared.validated);
        let new_status = EngineStatus {
            state: RuntimeState::Active,
            active_workflow_id: workflow_id,
            node_health,
            warning_banner: None,
            last_error: None,
        };

        let generation = {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            let gen = inner.next_generation;
            inner.next_generation += 1;
            inner.status = new_status.clone();
            gen
        };

        let traffic_monitor = TrafficMonitor::spawn(
            prepared.clash_api_port,
            prepared.outbound_to_node_id,
            self.event_tx.clone(),
        );
        let health_watcher = self.spawn_health_watcher(generation, prepared.validated);

        {
            let mut inner = self.inner.lock().expect("engine status mutex poisoned");
            inner.active_session = Some(ActiveSession {
                generation,
                recovery: snapshot,
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
        prepared: &PreparedApply,
        snapshot: &mut RecoverySnapshot,
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

        // 2. Neutralize any newly added VPNs and re-pin OpenVPN DCO /32 routes,
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

fn pick_default_physical_interface(
    interfaces: &[PhysicalInterfaceInfo],
    prior_metric_snapshots: &[InterfaceMetricSnapshot],
) -> Option<String> {
    if !prior_metric_snapshots.is_empty() {
        let orig_by_if: HashMap<u32, u32> = prior_metric_snapshots
            .iter()
            .filter(|s| !s.is_ipv6)
            .map(|s| (s.interface_index, s.original_metric))
            .collect();

        if let Some(best_prior) = interfaces
            .iter()
            .filter(|i| i.is_up && i.gateway_ipv4.is_some())
            .filter_map(|i| orig_by_if.get(&i.if_index).map(|m| (*m, i.if_index, &i.alias)))
            .min_by_key(|(m, idx, _)| (*m, *idx))
            .map(|(_, _, alias)| alias.clone())
        {
            return Some(best_prior);
        }
    }

    interfaces
        .iter()
        .find(|i| i.is_up && i.is_default_gateway)
        .or_else(|| interfaces.iter().find(|i| i.is_up))
        .map(|i| i.alias.clone())
}

fn prepare_apply_blocking(
    discovery: &dyn SystemDiscovery,
    config: &EngineRuntimeConfig,
    graph: &WorkflowGraph,
    prior_metric_snapshots: &[InterfaceMetricSnapshot],
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

    let default_physical_interface =
        pick_default_physical_interface(&discovery_snap.interfaces, prior_metric_snapshots)
            .ok_or(RuntimeError::NoDefaultPhysicalInterface)?;

    let interface_ipv4s: HashMap<String, String> = discovery_snap
        .interfaces
        .iter()
        .filter_map(|i| i.ipv4.as_ref().map(|ip| (i.alias.clone(), ip.clone())))
        .collect();

    let mut vpn_runtime = HashMap::new();

    for chain in &validated.vpn_chains {
        let detected = discovery_snap
            .vpns
            .iter()
            .find(|v| v.provider == chain.provider)
            .ok_or(RuntimeError::VpnAdapter(VpnAdapterError::NotRunning(
                chain.provider,
            )))?;

        let resolved = preflight_and_resolve_vpn(chain.provider, &chain.settings, detected)?;
        vpn_runtime.insert(chain.provider, resolved);
    }

    let clash_api_port = resolve_clash_api_port(config.clash_api_port);
    let compiled = compile_singbox_config(&CompileInput {
        validated: validated.clone(),
        default_physical_interface: default_physical_interface.clone(),
        interface_ipv4s,
        vpn_runtime: vpn_runtime.clone(),
        clash_api_port,
        log_path: config.runtime_dir.join("sing-box.log"),
    })?;
    let compiled_config_bytes = serde_json::to_vec_pretty(&compiled.json)?;

    Ok(PreparedApply {
        validated,
        clash_api_port,
        discovery_snap,
        vpn_runtime,
        outbound_to_node_id: compiled.outbound_to_node_id,
        compiled_config_bytes,
    })
}

fn resolve_clash_api_port(configured_port: u16) -> u16 {
    if configured_port != 0 {
        return configured_port;
    }
    for _ in 0..3 {
        if let Ok(listener) = TcpListener::bind("127.0.0.1:0") {
            if let Ok(addr) = listener.local_addr() {
                let port = addr.port();
                if port != 0 && port != 9090 {
                    return port;
                }
            }
        }
    }
    FALLBACK_CLASH_API_PORT
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

        maybe_prioritize_karing_upstream_interface_blocking(
            net_ops,
            recovery_store,
            prepared,
            chain,
            snapshot,
        )?;
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
    net_ops.disable_system_proxy()?;

    if !snapshot.pinned_host_routes.is_empty() {
        while let Some(route) = snapshot.pinned_host_routes.last().cloned() {
            remove_route_ignore_missing(net_ops, &route)?;
            snapshot.pinned_host_routes.pop();
        }
        recovery_store.save_atomic(snapshot)?;
    }

    if !snapshot.removed_bypass_routes.is_empty() {
        while let Some(route) = snapshot.removed_bypass_routes.last().cloned() {
            add_route_ignore_benign(net_ops, &route)?;
            snapshot.removed_bypass_routes.pop();
        }
        recovery_store.save_atomic(snapshot)?;
    }

    if !new_providers.contains(&VpnProvider::Karing) && !snapshot.physical_metric_snapshots.is_empty() {
        while let Some(metric_snap) = snapshot.physical_metric_snapshots.last().cloned() {
            restore_metric_ignore_missing(net_ops, &metric_snap)?;
            snapshot.physical_metric_snapshots.pop();
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

        maybe_prioritize_karing_upstream_interface_blocking(
            net_ops,
            recovery_store,
            prepared,
            chain,
            snapshot,
        )?;
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

const KARING_PREFERRED_PHYSICAL_METRIC: u32 = 10;
const KARING_DEPRIORITIZED_PHYSICAL_METRIC: u32 = 50;

/// Karing (`karingService.exe`) runs its own embedded `sing-box` with
/// `auto_detect_interface: true`, which binds outbound sockets via `IP_UNICAST_IF`
/// to whichever physical Windows adapter has the lowest IPv4 `InterfaceMetric`
/// (bypassing `NetFlow-TUN`). When 2+ physical interfaces are up and Karing is
/// wired directly to a specific physical interface, we set that interface's
/// metric to `10` and other up physical interfaces to `50` (snapshotting
/// original metrics in `recovery.json` first) so Karing's `default_interface_monitor`
/// switches its outbound tunnel to the chosen interface immediately.
fn maybe_prioritize_karing_upstream_interface_blocking(
    net_ops: &dyn WindowsNetworkOps,
    recovery_store: &RecoveryStore,
    prepared: &PreparedApply,
    chain: &crate::model::ValidatedVpnChain,
    snapshot: &mut RecoverySnapshot,
) -> Result<(), RuntimeError> {
    if chain.provider != VpnProvider::Karing {
        return Ok(());
    }

    let Some(upstream_node) = prepared.validated.nodes_by_id.get(&chain.upstream_node_id) else {
        return Ok(());
    };
    let NodeKind::Interface {
        interface_alias, ..
    } = &upstream_node.kind
    else {
        return Ok(());
    };

    let up_physical: Vec<&PhysicalInterfaceInfo> = prepared
        .discovery_snap
        .interfaces
        .iter()
        .filter(|i| i.is_up)
        .collect();
    if up_physical.len() < 2 {
        return Ok(());
    }

    let Some(target_iface) = up_physical
        .iter()
        .find(|i| i.alias.eq_ignore_ascii_case(interface_alias))
    else {
        return Ok(());
    };

    let mut recorded_new = false;
    for iface in &up_physical {
        let already_saved = snapshot
            .physical_metric_snapshots
            .iter()
            .any(|s| s.interface_index == iface.if_index && !s.is_ipv6);
        if !already_saved {
            if let Ok(metric_snap) = net_ops.get_interface_metric(iface.if_index, false) {
                snapshot.physical_metric_snapshots.push(metric_snap);
                recorded_new = true;
            }
        }
    }
    if recorded_new {
        recovery_store.save_atomic(snapshot)?;
    }

    for iface in &up_physical {
        let desired_metric = if iface.if_index == target_iface.if_index {
            KARING_PREFERRED_PHYSICAL_METRIC
        } else {
            KARING_DEPRIORITIZED_PHYSICAL_METRIC
        };
        net_ops.set_interface_metric(iface.if_index, false, desired_metric, false)?;
    }

    Ok(())
}

fn canonical_ipv4_prefix(route: &RouteRecord) -> Option<String> {
    if route.is_ipv6 {
        return None;
    }
    let (ip_str, len_str) = route.destination_prefix.trim().split_once('/')?;
    let ip: Ipv4Addr = ip_str.parse().ok()?;
    let len: u8 = len_str.parse().ok()?;
    Some(format!("{ip}/{len}"))
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
    match &upstream_node.kind {
        NodeKind::Interface {
            interface_alias, ..
        } => {
            let upstream_if =
                find_physical_interface(&prepared.discovery_snap.interfaces, interface_alias)
                    .ok_or_else(|| RuntimeError::InterfaceDown(interface_alias.clone()))?;

            if let Some(pinned_route) =
                pin_openvpn_dco_host_route(net_ops, server_ip, upstream_if)?
            {
                snapshot.pinned_host_routes.push(pinned_route);
                recovery_store.save_atomic(snapshot)?;
            }
        }
        NodeKind::Vpn { .. } => {
            // Chained downstream of another VPN: remove any physical /32 route to the OpenVPN
            // server so packets hit NetFlow-TUN and match compiler.rs's ip_cidr -> upstream VPN rule.
            let Ok(parsed_ip) = server_ip.trim().parse::<Ipv4Addr>() else {
                return Ok(());
            };
            let target_prefix = format!("{parsed_ip}/32");
            let mut changed = false;
            for phys in &prepared.discovery_snap.interfaces {
                let routes = net_ops.list_routes(Some(phys.if_index), false)?;
                for route in routes {
                    if canonical_ipv4_prefix(&route).as_deref() == Some(target_prefix.as_str()) {
                        match net_ops.remove_route(&route) {
                            Ok(()) => {
                                snapshot.removed_bypass_routes.push(route);
                                changed = true;
                            }
                            Err(err)
                                if is_benign_remove_route_error(
                                    net_ops,
                                    route.interface_index,
                                    &err,
                                ) => {}
                            Err(err) => return Err(err.into()),
                        }
                    }
                }
            }
            if changed {
                recovery_store.save_atomic(snapshot)?;
            }
        }
        NodeKind::Apps { .. } => {}
    }
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
        let healthy = snapshot
            .vpns
            .iter()
            .find(|v| v.provider == chain.provider)
            .is_some_and(|v| is_vpn_node_healthy(chain, v));
        if healthy {
            health.insert(chain.node_id.clone(), NodeHealth::Healthy);
        } else {
            health.insert(chain.node_id.clone(), NodeHealth::Dropped);
            dropped.push(provider_display_name(chain.provider).to_string());
        }
    }

    (health, dropped)
}

fn is_vpn_node_healthy(chain: &ValidatedVpnChain, info: &DetectedVpnInfo) -> bool {
    if !info.is_running {
        return false;
    }
    match chain.provider {
        VpnProvider::Karing => {
            info.detected_port.is_some()
                || chain.settings.karing_port_override.is_some_and(|p| p != 0)
        }
        VpnProvider::OpenVpn => info.adapter_is_up,
    }
}

fn provider_display_name(provider: VpnProvider) -> &'static str {
    match provider {
        VpnProvider::Karing => "Karing",
        VpnProvider::OpenVpn => "OpenVPN",
    }
}

fn remove_route_ignore_missing(
    ops: &dyn WindowsNetworkOps,
    route: &RouteRecord,
) -> Result<(), NetOpsError> {
    match ops.remove_route(route) {
        Ok(()) => Ok(()),
        Err(err) if is_benign_remove_route_error(ops, route.interface_index, &err) => Ok(()),
        Err(err) => Err(err),
    }
}

fn add_route_ignore_benign(
    ops: &dyn WindowsNetworkOps,
    route: &RouteRecord,
) -> Result<(), NetOpsError> {
    match ops.add_route(route) {
        Ok(()) => Ok(()),
        Err(err) if is_benign_restore_add_route_error(ops, route.interface_index, &err) => Ok(()),
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

fn restore_metric_ignore_missing(
    ops: &dyn WindowsNetworkOps,
    metric_snap: &InterfaceMetricSnapshot,
) -> Result<(), NetOpsError> {
    match ops.restore_interface_metric(metric_snap) {
        Ok(()) => Ok(()),
        Err(err)
            if crate::win_net::is_benign_restore_metric_error(
                ops,
                metric_snap.interface_index,
                &err,
            ) =>
        {
            Ok(())
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

    for route in &snapshot.removed_bypass_routes {
        if let Err(err) = add_route_ignore_benign(ops, route) {
            errors.push(format!(
                "restore removed bypass route {}: {err}",
                route.destination_prefix
            ));
        }
    }

    for metric_snap in &snapshot.physical_metric_snapshots {
        if let Err(err) = restore_metric_ignore_missing(ops, metric_snap) {
            errors.push(format!(
                "restore physical metric ifIndex={}: {err}",
                metric_snap.interface_index
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
        NodeKind, VpnNodeSettings, VpnProvider, WorkflowEdge, WorkflowGraph, WorkflowNode,
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
                label: None,
                icon_data_url: None,
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

        fn set_vpn_adapter_up(&self, provider: VpnProvider, adapter_is_up: bool) {
            let mut guard = self.snapshot.lock().unwrap();
            if let Some(vpn) = guard.vpns.iter_mut().find(|v| v.provider == provider) {
                vpn.adapter_is_up = adapter_is_up;
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
        best_route_interface: Option<String>,
        aliases: HashMap<String, u32>,
        ops_log: Vec<String>,
        recovery_path_to_probe: Option<PathBuf>,
        recovery_existed_before_first_mutation: Option<bool>,
        vanished_interfaces: HashSet<u32>,
        vanished_error_code: Option<u32>,
        fail_remove_prefix: Option<String>,
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

        fn mark_interface_vanished(&self, if_index: u32, error_code: u32) {
            let mut state = self.state.lock().unwrap();
            state.vanished_interfaces.insert(if_index);
            state.vanished_error_code = Some(error_code);
            state.routes.remove(&if_index);
            state.metrics.remove(&(if_index, false));
            state.metrics.remove(&(if_index, true));
        }

        fn set_fail_remove_prefix(&self, prefix: Option<&str>) {
            self.state.lock().unwrap().fail_remove_prefix = prefix.map(ToString::to_string);
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
            if state.vanished_interfaces.contains(&route.interface_index) {
                let code = state.vanished_error_code.unwrap_or(1168);
                return Err(NetOpsError::Win32 {
                    operation: "CreateIpForwardEntry2",
                    code,
                    message: "Vanished interface.".to_string(),
                });
            }
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
            if state.fail_remove_prefix.as_deref() == Some(route.destination_prefix.as_str()) {
                return Err(NetOpsError::Win32 {
                    operation: "DeleteIpForwardEntry2",
                    code: 5,
                    message: "Access is denied.".to_string(),
                });
            }
            if state.vanished_interfaces.contains(&route.interface_index) {
                let code = state.vanished_error_code.unwrap_or(1168);
                return Err(NetOpsError::Win32 {
                    operation: "DeleteIpForwardEntry2",
                    code,
                    message: "Vanished interface.".to_string(),
                });
            }
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
                    code: 1168,
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
            if state.vanished_interfaces.contains(&interface_index) {
                let code = state.vanished_error_code.unwrap_or(1168);
                return Err(NetOpsError::Win32 {
                    operation: "SetIpInterfaceEntry",
                    code,
                    message: "Vanished interface.".to_string(),
                });
            }
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

        fn interface_exists(&self, interface_index: u32) -> Result<bool, NetOpsError> {
            let state = self.state.lock().unwrap();
            Ok(!state.vanished_interfaces.contains(&interface_index))
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
    }

    #[derive(Default)]
    struct MockSidecarState {
        spawn_calls: Vec<PathBuf>,
        last_spawned_json: Option<Value>,
        kill_count: usize,
        kill_pid_calls: Vec<u32>,
        pid: Option<u32>,
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

        fn kill_pid_calls(&self) -> Vec<u32> {
            self.state.lock().unwrap().kill_pid_calls.clone()
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
            state.pid = Some(9000 + state.spawn_calls.len() as u32);
            Ok(())
        }

        fn is_alive(&self) -> bool {
            self.state.lock().unwrap().alive
        }

        fn pid(&self) -> Option<u32> {
            let state = self.state.lock().unwrap();
            if state.alive {
                state.pid
            } else {
                None
            }
        }

        fn kill(&self) -> Result<(), SidecarError> {
            if let Some(ref ops) = self.ops_log_sink {
                ops.state.lock().unwrap().ops_log.push("sidecar.kill".to_string());
            }
            let mut state = self.state.lock().unwrap();
            state.kill_count += 1;
            state.alive = false;
            state.pid = None;
            Ok(())
        }

        fn kill_pid(&self, pid: u32) -> Result<(), RuntimeError> {
            if let Some(ref ops) = self.ops_log_sink {
                ops.state
                    .lock()
                    .unwrap()
                    .ops_log
                    .push(format!("sidecar.kill_pid:{pid}"));
            }
            let mut state = self.state.lock().unwrap();
            state.kill_pid_calls.push(pid);
            if state.pid == Some(pid) {
                state.alive = false;
                state.pid = None;
            }
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
                    adapter_is_up: true,
                    adapter_gateway: Some("172.16.0.2".to_string()),
                    remote_server_ip: None,
                },
                DetectedVpnInfo {
                    provider: VpnProvider::OpenVpn,
                    is_running: true,
                    detected_port: None,
                    adapter_alias: Some("OpenVPN Data Channel Offload".to_string()),
                    adapter_if_index: Some(30),
                    adapter_is_up: true,
                    adapter_gateway: None,
                    remote_server_ip: Some("203.0.113.10".to_string()),
                },
            ],
            processes: vec![],
            open_apps: vec![],
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
            },
        );
        let pinned = route(12, "203.0.113.10/32", "192.168.1.1", 0, false);

        store
            .save_atomic(&RecoverySnapshot {
                created_at: "2026-11-24T00:00:00Z".to_string(),
                system_proxy: Some(original_proxy.clone()),
                vpn_entries,
                pinned_host_routes: vec![pinned.clone()],
                removed_bypass_routes: Vec::new(),
                physical_metric_snapshots: Vec::new(),
                singbox_pid: None,
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
    async fn test_hot_switch_workflow_preserves_karing_baseline_and_restores_or_adds_openvpn() {
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

        // Hot-switch to Karing-only workflow (removes OpenVPN and its pinned /32 route).
        let wf_b = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, VpnNodeSettings::default()),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "apps-1"),
            ],
        };

        let status_b = runtime
            .apply(Some("wf-b".to_string()), &wf_b)
            .await
            .expect("hot-switch to Karing-only workflow B");
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

        let (spawns, kills, alive, last_json) = sidecar.stats();
        assert_eq!(kills, 1);
        assert_eq!(spawns.len(), 2);
        assert!(alive);
        let outbounds = last_json.unwrap()["outbounds"].as_array().unwrap().clone();
        assert!(outbounds.iter().any(|o| o["tag"] == "vpn-karing"));
        assert!(!outbounds.iter().any(|o| o["tag"] == "vpn-openvpn"));

        // Hot-switch back to Karing + OpenVPN -> OpenVPN is neutralized and pinned again while Karing stays intact.
        ops.clear_ops_log();
        let status_c = runtime
            .apply(Some("wf-c".to_string()), &wf_a)
            .await
            .expect("hot-switch back to Karing+OpenVPN");
        assert_eq!(status_c.state, RuntimeState::Active);
        let snap_c = store.load().unwrap().expect("recovery snapshot after wf-c");
        assert_eq!(snap_c.vpn_entries.get(&VpnProvider::Karing), Some(&karing_baseline));
        assert!(snap_c.vpn_entries.contains_key(&VpnProvider::OpenVpn));
        assert_eq!(snap_c.pinned_host_routes.len(), 1);
        assert_eq!(
            ops.snapshot_state().2.get(&30).unwrap(),
            &vec![route(30, "0.0.0.0/0", "0.0.0.0", 500, false)],
            "OpenVPN routes neutralized on re-add"
        );

        runtime.stop().await.expect("clean stop");
        assert!(!dir.join("recovery.json").exists());
        let (_, proxy_after_stop, routes_after_stop, metrics_after_stop, _) = ops.snapshot_state();
        assert_eq!(proxy_after_stop.proxy_enable, 1);
        assert_eq!(routes_after_stop.get(&20).unwrap().len(), 2);
        assert_eq!(routes_after_stop.get(&30).unwrap().len(), 2);
        assert_eq!(metrics_after_stop.get(&(30, false)).unwrap().original_metric, 10);
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
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false, VpnNodeSettings::default()),
                apps_node("apps-1", &["chrome.exe"]),
                apps_node("apps-2", &["steam.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "apps-1"),
                edge("e3", "if-wifi", "vpn-ovpn"),
                edge("e4", "vpn-ovpn", "apps-2"),
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
        assert_eq!(routes.get(&30).unwrap().len(), 2);
        assert_eq!(metrics.get(&(20, false)).unwrap().original_metric, 5);
        assert_eq!(metrics.get(&(30, false)).unwrap().original_metric, 10);

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
    async fn test_recover_if_stale_kills_saved_singbox_pid_before_restoring_routes() {
        // Part A: apply() records singbox_pid in recovery.json.
        let dir = temp_test_dir("recover-pid");
        let recovery_path = dir.join("recovery.json");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), Arc::clone(&sidecar));

        runtime
            .apply(Some("wf-pid".to_string()), &karing_workflow())
            .await
            .expect("apply succeeds");
        let store = RecoveryStore::new(recovery_path.clone());
        let saved = store.load().unwrap().expect("recovery snapshot exists");
        assert_eq!(saved.singbox_pid, Some(9001));
        runtime.stop().await.expect("stop");

        // Part B: Simulate orphaned sing-box.exe PID left in recovery.json on crash restart.
        let mut crashed = saved.clone();
        crashed.singbox_pid = Some(43210);
        store.save_atomic(&crashed).expect("seed crashed snapshot");
        ops.clear_ops_log();

        let discovery2 = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let sidecar2 = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime2 = make_runtime(&dir, discovery2, Arc::clone(&ops), Arc::clone(&sidecar2));

        assert!(runtime2.recover_if_stale().expect("recover succeeds"));
        assert!(!recovery_path.exists());
        assert_eq!(sidecar2.kill_pid_calls(), vec![43210]);

        let ops_log = ops.snapshot_state().0;
        let pos_kill_pid = ops_log
            .iter()
            .position(|e| e == "sidecar.kill_pid:43210")
            .expect("kill_pid called");
        let pos_restore_route = ops_log
            .iter()
            .position(|e| e.starts_with("remove_route:") || e.starts_with("add_route:") || e == "set_system_proxy")
            .expect("route/proxy restoration occurred");
        assert!(
            pos_kill_pid < pos_restore_route,
            "kill_pid must run BEFORE restoring routes/proxy: {ops_log:?}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_singbox_image_name_filter_and_kill_pid_safety() {
        assert!(is_singbox_image_path(r"C:\Program Files\NetFlow\sing-box.exe"));
        assert!(is_singbox_image_path(
            r"D:\Study\src-tauri\binaries\sing-box-x86_64-pc-windows-msvc.exe"
        ));
        assert!(!is_singbox_image_path(r"C:\Windows\System32\notepad.exe"));
        assert!(!is_singbox_image_path(r"C:\Program Files\Google\chrome.exe"));
        assert!(!is_singbox_image_path(""));

        let dir = temp_test_dir("kill-pid-safety");
        let sidecar = SingBoxSidecar::new(dir.join("sing-box.exe"), dir.clone());
        // PID 0 and current test runner PID (not sing-box*.exe) must be safely ignored.
        sidecar.kill_pid(0).expect("pid 0 ignored");
        sidecar
            .kill_pid(std::process::id())
            .expect("non-sing-box pid must never be terminated");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_apply_and_stop_preserve_preexisting_openvpn_dco_host_route() {
        let dir = temp_test_dir("ovpn-preexisting-dco");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        let preexisting_dco = route(12, "203.0.113.10/32", "192.168.1.1", 5, false);
        ops.seed_interface(12, 25, true, vec![preexisting_dco.clone()]);

        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), sidecar);

        let ovpn_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false, VpnNodeSettings::default()),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-ovpn"),
                edge("e2", "vpn-ovpn", "apps-1"),
            ],
        };

        runtime
            .apply(Some("wf-ovpn".to_string()), &ovpn_graph)
            .await
            .expect("apply succeeds when /32 route already exists");

        let store = RecoveryStore::new(dir.join("recovery.json"));
        let saved = store.load().unwrap().expect("recovery snapshot exists");
        assert!(
            saved.pinned_host_routes.is_empty(),
            "pre-existing /32 route must NOT be recorded in pinned_host_routes"
        );
        let ops_log = ops.snapshot_state().0;
        assert!(
            !ops_log.iter().any(|e| e.starts_with("add_route:12:203.0.113.10/32")),
            "add_route must NOT be called for pre-existing /32 route: {ops_log:?}"
        );

        runtime.stop().await.expect("clean stop");
        let routes_after = ops.snapshot_state().2;
        assert!(
            routes_after
                .get(&12)
                .unwrap()
                .contains(&preexisting_dco),
            "stop() must NOT remove OpenVPN's pre-existing /32 host route"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_recover_if_stale_after_reboot_tolerates_vanished_tun_adapter_and_clears_recovery() {
        let dir = temp_test_dir("recover-vanished-tun");
        let recovery_path = dir.join("recovery.json");
        let store = RecoveryStore::new(recovery_path.clone());

        let original_proxy = SystemProxySnapshot {
            proxy_enable: 1,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: Some("localhost".to_string()),
        };
        let vanished_if = 30;
        let mut vpn_entries = HashMap::new();
        vpn_entries.insert(
            VpnProvider::OpenVpn,
            VpnRecoveryEntry {
                provider: VpnProvider::OpenVpn,
                removed_routes: vec![route(vanished_if, "0.0.0.0/1", "10.8.0.1", 0, false)],
                added_routes: vec![route(vanished_if, "0.0.0.0/0", "10.8.0.1", 500, false)],
                metric_snapshots: vec![InterfaceMetricSnapshot {
                    interface_index: vanished_if,
                    is_ipv6: false,
                    original_metric: 10,
                    automatic_metric: false,
                }],
            },
        );
        // Pinned host route also missing after reboot
        let vanished_pinned = route(12, "203.0.113.10/32", "192.168.1.1", 0, false);
        store
            .save_atomic(&RecoverySnapshot {
                created_at: "2026-11-24T00:00:00Z".to_string(),
                system_proxy: Some(original_proxy.clone()),
                vpn_entries,
                pinned_host_routes: vec![vanished_pinned],
                removed_bypass_routes: Vec::new(),
                physical_metric_snapshots: Vec::new(),
                singbox_pid: Some(999999),
            })
            .expect("seed recovery snapshot");

        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: Some("127.0.0.1:3067".to_string()),
            proxy_override: Some("localhost".to_string()),
        }));
        ops.mark_interface_vanished(vanished_if, 1168);
        let sidecar = Arc::new(MockSidecarRunner::new(None));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), sidecar);

        assert!(runtime.recover_if_stale().expect("recover succeeds despite vanished TUN"));
        assert!(!recovery_path.exists(), "recovery.json must be deleted");
        assert_eq!(ops.snapshot_state().1, original_proxy);

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_stop_after_vpn_closed_tolerates_vanished_tun_clears_recovery_and_transitions_to_stopped() {
        let dir = temp_test_dir("stop-vanished-tun");
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
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), sidecar);

        let ovpn_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false, VpnNodeSettings::default()),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-ovpn"),
                edge("e2", "vpn-ovpn", "apps-1"),
            ],
        };
        runtime.apply(Some("wf-ovpn".to_string()), &ovpn_graph).await.expect("apply");

        // User closes OpenVPN while NetFlow is active -> ephemeral adapter 30 vanishes.
        ops.mark_interface_vanished(30, 87);

        let status = runtime.stop().await.expect("stop succeeds cleanly");
        assert_eq!(status.state, RuntimeState::Stopped);
        assert!(
            !dir.join("recovery.json").exists(),
            "recovery.json must be cleared on clean stop after VPN closed"
        );
        assert_eq!(ops.snapshot_state().1, initial_proxy);

        // Real Access Denied (5) error during stop must NOT be swallowed and must preserve recovery.json.
        let ops_denied = Arc::new(MockNetworkOps::new(initial_proxy.clone()));
        seed_vpn_routes(&ops_denied);
        ops_denied.seed_interface(12, 25, true, vec![]);
        let sidecar_denied = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops_denied))));
        let dir_denied = temp_test_dir("stop-access-denied");
        let runtime_denied = make_runtime(
            &dir_denied,
            Arc::new(MockDiscovery::new(base_discovery_snapshot())),
            Arc::clone(&ops_denied),
            sidecar_denied,
        );
        runtime_denied
            .apply(Some("wf-denied".to_string()), &ovpn_graph)
            .await
            .expect("apply succeeds");
        ops_denied.set_fail_remove_prefix(Some("0.0.0.0/0"));
        let err = runtime_denied
            .stop()
            .await
            .expect_err("Access Denied error must not be swallowed");
        assert!(matches!(err, RuntimeError::RestoreFailed(_)));
        assert_eq!(runtime_denied.status().state, RuntimeState::Error);
        assert!(
            dir_denied.join("recovery.json").exists(),
            "recovery.json must remain when real restore error occurs"
        );

        let _ = fs::remove_dir_all(&dir_denied);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_disconnected_always_on_openvpn_with_adapter_down_fails_preflight_and_triggers_dropped_health() {
        let dir = temp_test_dir("ovpn-down-health");
        let mut snap = base_discovery_snapshot();
        if let Some(ovpn) = snap
            .vpns
            .iter_mut()
            .find(|v| v.provider == VpnProvider::OpenVpn)
        {
            // Simulate always-on ovpnconnector.exe running while OpenVPN adapter is down
            ovpn.is_running = true;
            ovpn.adapter_is_up = false;
        }
        let discovery = Arc::new(MockDiscovery::new(snap));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        ops.seed_interface(12, 25, true, vec![]);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, Arc::clone(&discovery), Arc::clone(&ops), sidecar);

        let ovpn_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node(
                    "vpn-ovpn",
                    VpnProvider::OpenVpn,
                    false,
                    VpnNodeSettings::default(),
                ),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-ovpn"),
                edge("e2", "vpn-ovpn", "apps-1"),
            ],
        };

        let err = runtime
            .apply(Some("wf-ovpn-down".to_string()), &ovpn_graph)
            .await
            .expect_err("running ovpnconnector with adapter_is_up=false must fail preflight");
        assert!(matches!(
            err,
            RuntimeError::VpnAdapter(VpnAdapterError::NotRunning(VpnProvider::OpenVpn))
        ));

        // Now bring adapter up, apply, then drop adapter mid-session while is_running stays true.
        discovery.set_vpn_adapter_up(VpnProvider::OpenVpn, true);
        let mut events = runtime.subscribe_events();
        runtime
            .apply(Some("wf-ovpn-up".to_string()), &ovpn_graph)
            .await
            .expect("apply succeeds when OpenVPN adapter is up");

        discovery.set_vpn_adapter_up(VpnProvider::OpenVpn, false);
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
        .expect("health watcher emitted Warning when OpenVPN adapter dropped");
        assert_eq!(
            dropped_status.node_health.get("vpn-ovpn"),
            Some(&NodeHealth::Dropped)
        );

        runtime.stop().await.expect("clean stop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_clash_api_port_zero_dynamically_selects_non_zero_non_9090_port() {
        assert_eq!(EngineRuntimeConfig::default().clash_api_port, 0);

        let dir = temp_test_dir("dynamic-clash-port");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = EngineRuntime::new(
            discovery,
            ops,
            Arc::clone(&sidecar) as Arc<dyn SidecarRunner>,
            RecoveryStore::new(dir.join("recovery.json")),
            EngineRuntimeConfig {
                runtime_dir: dir.join("runtime"),
                clash_api_port: 0,
                health_poll_interval: Duration::from_secs(60),
                tun_ready_attempts: 2,
                tun_ready_retry_delay: Duration::from_millis(5),
            },
        );

        runtime
            .apply(Some("wf-dyn-port".to_string()), &karing_workflow())
            .await
            .expect("apply succeeds with clash_api_port: 0");

        let (_, _, _, last_json) = sidecar.stats();
        let json = last_json.expect("compiled config written");
        let controller = json["experimental"]["clash_api"]["external_controller"]
            .as_str()
            .expect("external_controller string");
        let port: u16 = controller
            .strip_prefix("127.0.0.1:")
            .expect("loopback host")
            .parse()
            .expect("valid port");
        assert_ne!(port, 0);
        assert_ne!(port, 9090);

        runtime.stop().await.expect("clean stop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_chained_openvpn_temporarily_removes_physical_bypass_route_and_restores_on_stop() {
        let dir = temp_test_dir("chained-ovpn-bypass");
        let discovery = Arc::new(MockDiscovery::new(base_discovery_snapshot()));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        let wifi_bypass_route = route(12, "203.0.113.10/32", "192.168.1.1", 5, false);
        let wifi_default_route = route(12, "0.0.0.0/0", "192.168.1.1", 40, false);
        ops.seed_interface(
            12,
            25,
            true,
            vec![wifi_default_route.clone(), wifi_bypass_route.clone()],
        );
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), sidecar);

        let chained_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, VpnNodeSettings::default()),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false, VpnNodeSettings::default()),
                apps_node("apps-1", &["firefox.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-ovpn"),
                edge("e3", "vpn-ovpn", "apps-1"),
            ],
        };

        runtime
            .apply(Some("wf-chained-ovpn".to_string()), &chained_graph)
            .await
            .expect("apply chained OpenVPN succeeds");

        // Wi-Fi's /32 bypass route must be removed while active and recorded in recovery.json
        let wifi_routes_active = ops.snapshot_state().2.get(&12).cloned().unwrap_or_default();
        assert!(!wifi_routes_active.contains(&wifi_bypass_route));
        assert!(wifi_routes_active.contains(&wifi_default_route));

        let store = RecoveryStore::new(dir.join("recovery.json"));
        let saved = store.load().unwrap().expect("recovery snapshot exists");
        assert_eq!(saved.removed_bypass_routes, vec![wifi_bypass_route.clone()]);
        assert!(saved.pinned_host_routes.is_empty());

        // Stop must restore Wi-Fi's /32 bypass route and delete recovery.json
        runtime.stop().await.expect("clean stop");
        assert!(!dir.join("recovery.json").exists());
        let wifi_routes_after = ops.snapshot_state().2.get(&12).cloned().unwrap_or_default();
        assert!(
            wifi_routes_after.contains(&wifi_bypass_route),
            "stop() must restore Wi-Fi's /32 bypass route"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_hot_switch_default_interface_updates_compiled_final_and_bind_address() {
        let dir = temp_test_dir("hot-switch-default-iface");
        let mut snap = base_discovery_snapshot();
        if let Some(eth) = snap.interfaces.iter_mut().find(|i| i.alias == "Ethernet") {
            eth.ipv4 = Some("192.168.42.50".to_string());
            eth.gateway_ipv4 = Some("192.168.42.1".to_string());
            eth.is_up = true;
            eth.link_speed_mbps = 1000;
        }
        let discovery = Arc::new(MockDiscovery::new(snap));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        ops.seed_interface(12, 25, true, vec![]);
        ops.seed_interface(15, 35, true, vec![]);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, discovery, Arc::clone(&ops), Arc::clone(&sidecar));

        let wf_wifi_default = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", true),
                iface_node("if-eth", "Ethernet", false),
            ],
            edges: vec![],
        };
        runtime
            .apply(Some("wf-1".to_string()), &wf_wifi_default)
            .await
            .expect("initial apply succeeds");

        let wf_eth_default = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                iface_node("if-eth", "Ethernet", true),
            ],
            edges: vec![],
        };
        runtime
            .apply(Some("wf-1".to_string()), &wf_eth_default)
            .await
            .expect("hot-switch default to Ethernet succeeds");

        let (spawns, kills, alive, last_json) = sidecar.stats();
        assert_eq!(spawns.len(), 2);
        assert_eq!(kills, 1);
        assert!(alive);

        let json = last_json.expect("second compiled config exists");
        assert_eq!(json["route"]["final"], "iface-ethernet");
        assert_eq!(json["dns"]["final"], "dns-iface-ethernet");
        assert_eq!(json["route"]["default_domain_resolver"], "dns-iface-ethernet");

        let outbounds = json["outbounds"].as_array().unwrap();
        let eth_out = outbounds
            .iter()
            .find(|o| o["tag"] == "iface-ethernet")
            .expect("iface-ethernet outbound");
        assert_eq!(eth_out["bind_interface"], "Ethernet");
        assert_eq!(eth_out["inet4_bind_address"], "192.168.42.50");

        let dns_servers = json["dns"]["servers"].as_array().unwrap();
        let eth_dns = dns_servers
            .iter()
            .find(|s| s["tag"] == "dns-iface-ethernet")
            .expect("dns-iface-ethernet server");
        assert_eq!(eth_dns["bind_interface"], "Ethernet");
        assert_eq!(eth_dns["inet4_bind_address"], "192.168.42.50");

        runtime.stop().await.expect("clean stop");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn test_hot_switch_from_karing_to_no_default_uses_original_lowest_metric_interface() {
        let dir = temp_test_dir("hot-switch-karing-metric-default");
        let mut snap = base_discovery_snapshot();
        // Originally Ethernet (if_index=15) has lower metric (20) than Wi-Fi (if_index=12, metric=40),
        // so Ethernet is Windows' original default gateway before Karing prioritization.
        if let Some(wifi) = snap.interfaces.iter_mut().find(|i| i.alias == "Wi-Fi") {
            wifi.is_default_gateway = false;
        }
        if let Some(eth) = snap.interfaces.iter_mut().find(|i| i.alias == "Ethernet") {
            eth.ipv4 = Some("192.168.42.50".to_string());
            eth.gateway_ipv4 = Some("192.168.42.1".to_string());
            eth.is_up = true;
            eth.link_speed_mbps = 1000;
            eth.is_default_gateway = true;
        }
        let discovery = Arc::new(MockDiscovery::new(snap));
        let ops = Arc::new(MockNetworkOps::new(SystemProxySnapshot {
            proxy_enable: 0,
            proxy_server: None,
            proxy_override: None,
        }));
        seed_vpn_routes(&ops);
        ops.seed_interface(12, 40, true, vec![]);
        ops.seed_interface(15, 20, true, vec![]);
        let sidecar = Arc::new(MockSidecarRunner::new(Some(Arc::clone(&ops))));
        let runtime = make_runtime(&dir, Arc::clone(&discovery), Arc::clone(&ops), Arc::clone(&sidecar));

        // 1. Apply Karing wired to Wi-Fi: NetFlow sets Wi-Fi metric=10 and Ethernet metric=50.
        runtime
            .apply(Some("wf-karing".to_string()), &karing_workflow())
            .await
            .expect("apply karing on Wi-Fi");

        // Simulate discovery now reporting Wi-Fi as Windows default gateway due to NetFlow's metric=10.
        {
            let mut d = discovery.snapshot.lock().unwrap();
            for iface in &mut d.interfaces {
                iface.is_default_gateway = iface.alias == "Wi-Fi";
            }
        }

        // 2. Hot-switch to a workflow with no Karing and no explicit default node.
        let wf_no_default = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                iface_node("if-eth", "Ethernet", false),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![edge("e1", "if-wifi", "apps-1")],
        };
        runtime
            .apply(Some("wf-no-default".to_string()), &wf_no_default)
            .await
            .expect("hot-switch to no-default workflow");

        let (_, _, _, last_json) = sidecar.stats();
        let json = last_json.expect("second compiled config exists");
        let default_direct = json["outbounds"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["tag"] == "default-direct")
            .expect("default-direct outbound");
        assert_eq!(
            default_direct["bind_interface"], "Ethernet",
            "fallback default must use pre-NetFlow lowest-metric interface (Ethernet), not mutated Karing upstream (Wi-Fi)"
        );
        assert_eq!(default_direct["inet4_bind_address"], "192.168.42.50");

        runtime.stop().await.expect("clean stop");
        let _ = fs::remove_dir_all(&dir);
    }
}
