//! NetFlow Tauri v2 desktop shell.

/// Launches the Tauri desktop application runtime.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let _core_ver = netflow_core::core_version();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .run(tauri::generate_context!())
        .expect("error while running NetFlow Tauri application");
}
