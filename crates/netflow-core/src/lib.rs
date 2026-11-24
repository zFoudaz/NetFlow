//! Core domain model, graph validation, sing-box config compilation, and Win32
//! network orchestration for NetFlow.
//!
//! Intentionally free of any `tauri` dependency so it can be tested headlessly and
//! reused across targets.

pub mod model;
pub mod validator;

/// Returns the semantic version of `netflow-core`.
pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
