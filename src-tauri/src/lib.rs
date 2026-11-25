//! NetFlow Tauri v2 desktop shell: IPC command wiring, system tray, and lifecycle management.

pub mod commands;

use std::path::PathBuf;
use std::sync::Arc;

use netflow_core::app_groups::{default_app_groups_path, AppGroupStore};
use netflow_core::autostart::{AutoStartManager, WindowsTaskSchedulerAutoStart};
use netflow_core::discovery::{SystemDiscovery, Win32Discovery};
use netflow_core::recovery::{default_recovery_path, RecoveryStore};
use netflow_core::runtime::{
    EngineRuntime, EngineRuntimeConfig, RuntimeEvent, RuntimeState, SidecarRunner, SingBoxSidecar,
};
use netflow_core::settings::{default_settings_path, SettingsStore};
use netflow_core::storage::{default_workflows_dir, WorkflowStore};
use netflow_core::win_net::{Win32NetworkOps, WindowsNetworkOps};
use tauri::menu::{MenuBuilder, MenuItemBuilder};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, RunEvent, WindowEvent};
use tokio::sync::broadcast;
use tokio::sync::broadcast::error::RecvError;

use crate::commands::{
    is_autostart_launch, resolve_sidecar_paths, run_startup_recovery, AppState,
    EVENT_RECOVERY_NOTICE, EVENT_STATUS, EVENT_TRAFFIC,
};

const TRAY_ID: &str = "netflow-tray";
const TRAY_SHOW_ID: &str = "show_netflow";
const TRAY_STOP_ID: &str = "stop_routing";
const TRAY_EXIT_ID: &str = "exit";

fn show_main_window<R: tauri::Runtime>(app: &AppHandle<R>) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn initiate_clean_exit(app_handle: AppHandle) {
    let Some(state) = app_handle.try_state::<AppState>() else {
        app_handle.exit(0);
        return;
    };

    if state.is_exit_ready() {
        app_handle.exit(0);
        return;
    }

    if !state.try_begin_exit() {
        return;
    }

    let runtime = Arc::clone(state.runtime());
    tauri::async_runtime::spawn(async move {
        let _ = runtime.stop().await;
        if let Some(state) = app_handle.try_state::<AppState>() {
            state.mark_exit_ready();
        }
        app_handle.exit(0);
    });
}

fn is_connected_state(state: RuntimeState) -> bool {
    matches!(state, RuntimeState::Active | RuntimeState::Warning)
}

fn to_grayscale_icon(icon: &tauri::image::Image<'_>) -> tauri::image::Image<'static> {
    let src = icon.rgba();
    let mut dst = Vec::with_capacity(src.len());
    for px in src.chunks_exact(4) {
        let luma = ((u32::from(px[0]) * 299 + u32::from(px[1]) * 587 + u32::from(px[2]) * 114)
            / 1000) as u8;
        dst.extend_from_slice(&[luma, luma, luma, px[3]]);
    }
    tauri::image::Image::new_owned(dst, icon.width(), icon.height())
}

fn update_app_icons(app_handle: &AppHandle, state: RuntimeState) {
    let Some(default_icon) = app_handle.default_window_icon() else {
        return;
    };
    let connected = is_connected_state(state);
    let icon = if connected {
        default_icon.to_owned()
    } else {
        to_grayscale_icon(default_icon)
    };

    if let Some(tray) = app_handle.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(icon.clone()));
        let tooltip = if connected {
            "NetFlow — Connected"
        } else {
            "NetFlow — Disconnected"
        };
        let _ = tray.set_tooltip(Some(tooltip));
    }

    if let Some(window) = app_handle.get_webview_window("main") {
        let _ = window.set_icon(icon);
    }
}

fn spawn_event_forwarder(
    app_handle: AppHandle,
    runtime: Arc<EngineRuntime>,
    mut event_rx: broadcast::Receiver<RuntimeEvent>,
) {
    tauri::async_runtime::spawn(async move {
        loop {
            match event_rx.recv().await {
                Ok(RuntimeEvent::StatusChanged(status)) => {
                    update_app_icons(&app_handle, status.state);
                    let _ = app_handle.emit(EVENT_STATUS, status);
                }
                Ok(RuntimeEvent::TrafficUpdated(connections)) => {
                    let _ = app_handle.emit(EVENT_TRAFFIC, connections);
                }
                Ok(RuntimeEvent::RecoveryNotice(notice)) => {
                    if let Some(state) = app_handle.try_state::<AppState>() {
                        state.set_recovery_notice(notice.clone());
                    }
                    let _ = app_handle.emit(EVENT_RECOVERY_NOTICE, notice);
                }
                Err(RecvError::Lagged(_)) => {
                    let status = runtime.status();
                    update_app_icons(&app_handle, status.state);
                    let _ = app_handle.emit(EVENT_STATUS, status);
                }
                Err(RecvError::Closed) => break,
            }
        }
    });
}

fn build_system_tray(app: &tauri::App) -> tauri::Result<()> {
    let show_item = MenuItemBuilder::with_id(TRAY_SHOW_ID, "Show NetFlow").build(app)?;
    let stop_item = MenuItemBuilder::with_id(TRAY_STOP_ID, "Stop Routing").build(app)?;
    let exit_item = MenuItemBuilder::with_id(TRAY_EXIT_ID, "Exit").build(app)?;

    let menu = MenuBuilder::new(app)
        .item(&show_item)
        .item(&stop_item)
        .separator()
        .item(&exit_item)
        .build()?;

    let mut builder = TrayIconBuilder::with_id(TRAY_ID)
        .menu(&menu)
        .tooltip("NetFlow — Disconnected")
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            TRAY_SHOW_ID => show_main_window(app),
            TRAY_STOP_ID => {
                let app_handle = app.clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(state) = app_handle.try_state::<AppState>() {
                        let _ = state.stop_routing().await;
                    }
                });
            }
            TRAY_EXIT_ID => initiate_clean_exit(app.clone()),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| match event {
            TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            }
            | TrayIconEvent::DoubleClick {
                button: MouseButton::Left,
                ..
            } => {
                show_main_window(tray.app_handle());
            }
            _ => {}
        });

    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(to_grayscale_icon(icon));
    }

    builder.build(app)?;
    Ok(())
}

/// Launches the Tauri desktop application runtime.
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let sidecar_paths = resolve_sidecar_paths(app.handle());
            let discovery: Arc<dyn SystemDiscovery> = Arc::new(Win32Discovery);
            let net_ops: Arc<dyn WindowsNetworkOps> = Arc::new(Win32NetworkOps);
            let sidecar: Arc<dyn SidecarRunner> = Arc::new(SingBoxSidecar::new(
                sidecar_paths.binary_path,
                sidecar_paths.wintun_dir,
            ));
            let recovery_store = RecoveryStore::new(default_recovery_path());
            let runtime = Arc::new(EngineRuntime::new(
                Arc::clone(&discovery),
                net_ops,
                sidecar,
                recovery_store,
                EngineRuntimeConfig::default(),
            ));
            let workflow_store = WorkflowStore::new(default_workflows_dir());
            let settings_store = SettingsStore::new(default_settings_path());
            let app_group_store = AppGroupStore::new(default_app_groups_path());
            let auto_start: Arc<dyn AutoStartManager> =
                Arc::new(WindowsTaskSchedulerAutoStart::default());
            let exe_path =
                std::env::current_exe().unwrap_or_else(|_| PathBuf::from("NetFlow.exe"));
            let app_state = AppState::new(
                Arc::clone(&runtime),
                workflow_store,
                settings_store,
                app_group_store,
                auto_start,
                exe_path,
                discovery,
            );

            let mut event_rx = runtime.subscribe_events();
            if let Some(notice) = run_startup_recovery(&app_state, &mut event_rx) {
                let _ = app.emit(EVENT_RECOVERY_NOTICE, notice);
            }

            let autostart_launch = is_autostart_launch(std::env::args());

            app.manage(app_state);
            spawn_event_forwarder(app.handle().clone(), runtime, event_rx);
            build_system_tray(app)?;
            update_app_icons(app.handle(), RuntimeState::Stopped);

            if autostart_launch {
                let app_handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Some(state) = app_handle.try_state::<AppState>() {
                        let _ = state.run_autostart_workflow_if_enabled().await;
                    }
                });
            } else {
                show_main_window(app.handle());
            }

            Ok(())
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if let Some(state) = window.try_state::<AppState>() {
                    if state.should_hide_on_close() {
                        api.prevent_close();
                        let _ = window.hide();
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_discovery_snapshot,
            commands::validate_workflow_graph,
            commands::list_workflows,
            commands::save_workflow,
            commands::rename_workflow,
            commands::duplicate_workflow,
            commands::delete_workflow,
            commands::apply_workflow,
            commands::stop_routing,
            commands::get_engine_status,
            commands::take_recovery_notice,
            commands::get_app_settings,
            commands::update_app_settings,
            commands::list_app_groups,
            commands::save_app_group,
            commands::delete_app_group,
        ])
        .build(tauri::generate_context!())
        .expect("error while building NetFlow Tauri application");

    app.run(|app_handle, event| match event {
        RunEvent::ExitRequested { code, api, .. } => {
            if code == Some(tauri::RESTART_EXIT_CODE) {
                return;
            }
            if let Some(state) = app_handle.try_state::<AppState>() {
                if !state.is_exit_ready() {
                    api.prevent_exit();
                    initiate_clean_exit(app_handle.clone());
                }
            }
        }
        RunEvent::Exit => {
            if let Some(state) = app_handle.try_state::<AppState>() {
                if !state.is_exit_ready() && state.try_begin_exit() {
                    let runtime = Arc::clone(state.runtime());
                    let _ = tauri::async_runtime::block_on(runtime.stop());
                    state.mark_exit_ready();
                }
            }
        }
        _ => {}
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_connected_state() {
        assert!(!is_connected_state(RuntimeState::Stopped));
        assert!(!is_connected_state(RuntimeState::Applying));
        assert!(!is_connected_state(RuntimeState::Error));
        assert!(is_connected_state(RuntimeState::Active));
        assert!(is_connected_state(RuntimeState::Warning));
    }

    #[test]
    fn test_to_grayscale_icon_preserves_alpha_and_dimensions() {
        // 2x1 RGBA image: green/teal pixel + transparent pixel
        let rgba = vec![62, 207, 142, 255, 20, 184, 166, 0];
        let icon = tauri::image::Image::new(&rgba, 2, 1);
        let gray = to_grayscale_icon(&icon);

        assert_eq!(gray.width(), 2);
        assert_eq!(gray.height(), 1);
        let out = gray.rgba();
        assert_eq!(out[0], out[1]);
        assert_eq!(out[1], out[2]);
        assert_eq!(out[3], 255);
        assert_eq!(out[4], out[5]);
        assert_eq!(out[5], out[6]);
        assert_eq!(out[7], 0);
    }
}
