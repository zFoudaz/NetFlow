//! Core domain model, graph validation, sing-box config compilation, and Win32
//! network orchestration for NetFlow.
//!
//! Intentionally free of any `tauri` dependency so it can be tested headlessly and
//! reused across targets.

pub mod app_groups;
pub mod autostart;
pub mod compiler;
pub mod discovery;
pub mod model;
pub mod recovery;
pub mod runtime;
pub mod settings;
pub mod storage;
pub mod traffic;
pub mod validator;
pub mod vpn_adapters;
pub mod win_net;

/// Returns the semantic version of `netflow-core`.
pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
