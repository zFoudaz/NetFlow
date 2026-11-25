//! Windows system discovery for physical and virtual third-party network adapters,
//! running processes, and active VPN providers (`Karing`, `OpenVPN`).

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::Ipv4Addr;
use std::sync::{Mutex, OnceLock};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::VpnProvider;
use crate::recovery::RouteRecord;
use crate::validator::canonicalize_exe_name;
use crate::win_net::{NetOpsError, Win32NetworkOps, WindowsNetworkOps};

const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;

/// Physical network interface discovered on the Windows host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PhysicalInterfaceInfo {
    pub alias: String,
    pub description: String,
    pub if_index: u32,
    pub ipv4: Option<String>,
    pub gateway_ipv4: Option<String>,
    pub is_up: bool,
    pub link_speed_mbps: u64,
    pub is_default_gateway: bool,
}

/// Running Windows process metadata returned in a discovery snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningProcessInfo {
    pub exe_name: String,
    pub path: Option<String>,
}

/// Live detection state for one supported VPN provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedVpnInfo {
    pub provider: VpnProvider,
    pub is_running: bool,
    pub detected_port: Option<u16>,
    pub adapter_alias: Option<String>,
    pub adapter_if_index: Option<u32>,
    #[serde(default)]
    pub adapter_is_up: bool,
    pub adapter_gateway: Option<String>,
    pub remote_server_ip: Option<String>,
}

/// User-facing running Windows application discovered from visible windows,
/// grouping its primary executable with related helper/child executables.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedAppInfo {
    pub id: String,
    pub name: String,
    pub primary_exe: String,
    pub primary_path: Option<String>,
    pub executables: Vec<String>,
    pub icon_data_url: Option<String>,
}

/// Live detection state for Windows Mobile Hotspot sharing adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DetectedHotspotInfo {
    pub is_active: bool,
    pub adapter_alias: Option<String>,
    pub ipv4: Option<String>,
}

/// Complete read-only snapshot of Windows interfaces, VPN providers, and running processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySnapshot {
    pub interfaces: Vec<PhysicalInterfaceInfo>,
    pub vpns: Vec<DetectedVpnInfo>,
    pub processes: Vec<RunningProcessInfo>,
    #[serde(default)]
    pub open_apps: Vec<DetectedAppInfo>,
    #[serde(default)]
    pub hotspot: Option<DetectedHotspotInfo>,
}

/// Typed errors returned by [`SystemDiscovery`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DiscoveryError {
    #[error("Win32 discovery call '{operation}' failed with error code {code}: {message}")]
    Win32 {
        operation: &'static str,
        code: u32,
        message: String,
    },
    #[error("network discovery query failed: {0}")]
    NetOps(#[from] NetOpsError),
    #[error("Windows system discovery is only supported on Windows")]
    UnsupportedPlatform,
}

/// Abstraction for querying host physical interfaces, running processes, and VPN state.
pub trait SystemDiscovery: Send + Sync {
    /// Captures a read-only [`DiscoverySnapshot`] of the current system state.
    fn snapshot(&self) -> Result<DiscoverySnapshot, DiscoveryError>;
}

/// Real Win32 implementation of [`SystemDiscovery`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Win32Discovery;

impl SystemDiscovery for Win32Discovery {
    fn snapshot(&self) -> Result<DiscoverySnapshot, DiscoveryError> {
        let net_ops = Win32NetworkOps;
        let raw_adapters = crate::win_net::platform::enumerate_adapters()?;
        let ipv4_routes = net_ops.list_routes(None, false)?;
        let (processes, pid_to_exe, raw_processes) = platform::enumerate_processes()?;
        let listening_ports_by_pid = platform::enumerate_listening_tcp_ports()?;
        let visible_pids = platform::enumerate_visible_window_pids(&pid_to_exe);

        let mut ports_by_exe: HashMap<String, Vec<u16>> = HashMap::new();
        for (pid, ports) in listening_ports_by_pid {
            if let Some(exe_lower) = pid_to_exe.get(&pid) {
                let entry = ports_by_exe.entry(exe_lower.clone()).or_default();
                for port in ports {
                    if !entry.contains(&port) {
                        entry.push(port);
                    }
                }
            }
        }

        let interfaces = classify_physical_interfaces(&raw_adapters, &ipv4_routes);
        let running_exe_set: HashSet<String> = processes
            .iter()
            .map(|p| p.exe_name.to_ascii_lowercase())
            .collect();

        let karing = detect_karing(&raw_adapters, &ipv4_routes, &running_exe_set, &ports_by_exe);
        let openvpn = detect_openvpn(
            &raw_adapters,
            &ipv4_routes,
            &running_exe_set,
            &interfaces,
        );
        let nekoray = detect_nekoray(&raw_adapters, &ipv4_routes, &running_exe_set, &ports_by_exe);
        let hotspot = detect_hotspot(&raw_adapters);
        let open_apps = group_open_apps(
            &raw_processes,
            &visible_pids,
            std::process::id(),
            |_exe, path| cached_exe_metadata(path),
        );

        Ok(DiscoverySnapshot {
            interfaces,
            vpns: vec![karing, openvpn, nekoray],
            processes,
            open_apps,
            hotspot: Some(hotspot),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawProcessEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub exe_name: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RawAdapterInfo {
    pub alias: String,
    pub description: String,
    pub if_index: u32,
    pub if_type: u32,
    pub is_up: bool,
    pub ipv4: Option<String>,
    pub gateway_ipv4: Option<String>,
    pub link_speed_bps: u64,
    pub ipv4_metric: u32,
}

fn contains_any_ci(haystack_a: &str, haystack_b: &str, needles: &[&str]) -> bool {
    let a = haystack_a.to_ascii_lowercase();
    let b = haystack_b.to_ascii_lowercase();
    needles
        .iter()
        .any(|needle| a.contains(needle) || b.contains(needle))
}

fn is_karing_adapter(alias: &str, description: &str) -> bool {
    contains_any_ci(alias, description, &["karing"])
}

fn is_openvpn_adapter(alias: &str, description: &str) -> bool {
    contains_any_ci(alias, description, &["openvpn", "tap-windows"])
}

fn is_nekoray_adapter(alias: &str, description: &str) -> bool {
    contains_any_ci(alias, description, &["nekoray", "nekobox"])
}

pub(crate) fn is_virtual_or_excluded_adapter(
    alias: &str,
    description: &str,
    if_type: u32,
) -> bool {
    if if_type == IF_TYPE_SOFTWARE_LOOPBACK {
        return true;
    }

    contains_any_ci(
        alias,
        description,
        &[
            "loopback",
            "netflow-tun",
            "netflow-hotspot-tun",
            "karing",
            "nekoray",
            "nekobox",
            "openvpn",
            "tap-windows",
            "vethernet",
            "hyper-v virtual",
            "teredo",
            "6to4",
            "isatap",
            "ip-https",
            "wan miniport",
            "kernel debug network adapter",
            "wi-fi direct virtual",
            "virtualbox host-only",
            "vmware virtual ethernet",
        ],
    )
}

pub(crate) fn classify_physical_interfaces(
    adapters: &[RawAdapterInfo],
    ipv4_routes: &[RouteRecord],
) -> Vec<PhysicalInterfaceInfo> {
    let mut candidates: Vec<(u32, PhysicalInterfaceInfo)> = adapters
        .iter()
        .filter(|a| !is_virtual_or_excluded_adapter(&a.alias, &a.description, a.if_type))
        .map(|a| {
            let link_speed_mbps = if !a.is_up || a.link_speed_bps == u64::MAX {
                0
            } else {
                a.link_speed_bps / 1_000_000
            };

            let gateway_ipv4 = a.gateway_ipv4.clone().or_else(|| {
                ipv4_routes
                    .iter()
                    .find(|r| {
                        !r.is_ipv6
                            && r.interface_index == a.if_index
                            && r.destination_prefix == "0.0.0.0/0"
                            && is_usable_gateway(&r.next_hop)
                    })
                    .map(|r| r.next_hop.clone())
            });

            (
                a.ipv4_metric,
                PhysicalInterfaceInfo {
                    alias: a.alias.clone(),
                    description: a.description.clone(),
                    if_index: a.if_index,
                    ipv4: a.ipv4.clone(),
                    gateway_ipv4,
                    is_up: a.is_up,
                    link_speed_mbps,
                    is_default_gateway: false,
                },
            )
        })
        .collect();

    let default_if_index = pick_default_gateway_if_index(&candidates, ipv4_routes);
    if let Some(winner) = default_if_index {
        for (_, iface) in &mut candidates {
            if iface.if_index == winner {
                iface.is_default_gateway = true;
                break;
            }
        }
    }

    candidates.sort_by(|(metric_a, a), (metric_b, b)| {
        b.is_default_gateway
            .cmp(&a.is_default_gateway)
            .then_with(|| b.is_up.cmp(&a.is_up))
            .then_with(|| metric_a.cmp(metric_b))
            .then_with(|| a.alias.to_ascii_lowercase().cmp(&b.alias.to_ascii_lowercase()))
    });

    candidates.into_iter().map(|(_, iface)| iface).collect()
}

fn pick_default_gateway_if_index(
    candidates: &[(u32, PhysicalInterfaceInfo)],
    ipv4_routes: &[RouteRecord],
) -> Option<u32> {
    let mut best_by_route: Option<(u32, u32)> = None;
    for (if_metric, iface) in candidates {
        if !iface.is_up || iface.gateway_ipv4.is_none() {
            continue;
        }
        for route in ipv4_routes {
            if !route.is_ipv6
                && route.interface_index == iface.if_index
                && route.destination_prefix == "0.0.0.0/0"
                && is_usable_gateway(&route.next_hop)
            {
                let effective = route.route_metric.saturating_add(*if_metric);
                let replace = match best_by_route {
                    None => true,
                    Some((best_eff, best_idx)) => {
                        (effective, iface.if_index) < (best_eff, best_idx)
                    }
                };
                if replace {
                    best_by_route = Some((effective, iface.if_index));
                }
            }
        }
    }
    if let Some((_, if_index)) = best_by_route {
        return Some(if_index);
    }

    candidates
        .iter()
        .filter(|(_, iface)| iface.is_up && iface.gateway_ipv4.is_some())
        .min_by_key(|(if_metric, iface)| (*if_metric, iface.if_index))
        .map(|(_, iface)| iface.if_index)
}

fn is_usable_gateway(next_hop: &str) -> bool {
    next_hop != "0.0.0.0" && next_hop != "127.0.0.1" && !next_hop.is_empty()
}

/// Picks Karing's Mixed/SOCKS5 listening port, preferring `3067` and skipping control ports.
pub(crate) fn pick_karing_mixed_port(ports: &[u16]) -> Option<u16> {
    const CONTROL_PORTS: [u16; 4] = [5848, 9519, 9090, 3057];
    if ports.contains(&3067) {
        return Some(3067);
    }
    ports
        .iter()
        .copied()
        .find(|&p| p != 0 && !CONTROL_PORTS.contains(&p))
}

/// Picks NekoRay / NekoBox's SOCKS5 listening port, preferring `2080` and skipping HTTP/control ports.
pub(crate) fn pick_nekoray_socks_port(ports: &[u16]) -> Option<u16> {
    const SKIP_PORTS: [u16; 2] = [2081, 9090];
    if ports.contains(&2080) {
        return Some(2080);
    }
    ports
        .iter()
        .copied()
        .find(|&p| p != 0 && !SKIP_PORTS.contains(&p))
}

/// Extracts OpenVPN's remote server IPv4 from a `/32` host route routed via a physical gateway.
pub(crate) fn extract_openvpn_remote_server_ip(
    routes: &[RouteRecord],
    openvpn_if_index: Option<u32>,
    physical_interfaces: &[PhysicalInterfaceInfo],
) -> Option<String> {
    let physical_by_index: HashMap<u32, &PhysicalInterfaceInfo> = physical_interfaces
        .iter()
        .map(|iface| (iface.if_index, iface))
        .collect();

    let mut best: Option<(bool, u32, String)> = None;

    for route in routes {
        if route.is_ipv6 {
            continue;
        }
        if openvpn_if_index == Some(route.interface_index) {
            continue;
        }
        let Some(host_str) = route.destination_prefix.strip_suffix("/32") else {
            continue;
        };
        let Ok(host_ip) = host_str.parse::<Ipv4Addr>() else {
            continue;
        };
        if host_ip.is_unspecified()
            || host_ip.is_loopback()
            || host_ip.is_link_local()
            || host_ip.is_multicast()
            || host_ip.is_broadcast()
        {
            continue;
        }
        if !is_usable_gateway(&route.next_hop) {
            continue;
        }

        let Some(phys) = physical_by_index.get(&route.interface_index) else {
            continue;
        };
        if phys.gateway_ipv4.as_deref() != Some(route.next_hop.as_str()) {
            continue;
        }
        if phys.ipv4.as_deref() == Some(host_str) || phys.gateway_ipv4.as_deref() == Some(host_str)
        {
            continue;
        }

        let candidate = (phys.is_default_gateway, route.route_metric, host_str.to_string());
        let replace = match &best {
            None => true,
            Some((best_default, best_metric, _)) => {
                (!*best_default && candidate.0)
                    || (*best_default == candidate.0 && candidate.1 < *best_metric)
            }
        };
        if replace {
            best = Some(candidate);
        }
    }

    best.map(|(_, _, ip)| ip)
}

fn find_matching_adapter(
    adapters: &[RawAdapterInfo],
    predicate: fn(&str, &str) -> bool,
) -> Option<&RawAdapterInfo> {
    adapters
        .iter()
        .filter(|a| predicate(&a.alias, &a.description))
        .max_by_key(|a| (a.is_up, a.gateway_ipv4.is_some(), a.ipv4.is_some()))
}

fn resolve_adapter_gateway(
    adapter: Option<&RawAdapterInfo>,
    ipv4_routes: &[RouteRecord],
) -> Option<String> {
    let adapter = adapter?;
    if let Some(gw) = &adapter.gateway_ipv4 {
        if is_usable_gateway(gw) {
            return Some(gw.clone());
        }
    }

    ipv4_routes
        .iter()
        .filter(|r| {
            !r.is_ipv6
                && r.interface_index == adapter.if_index
                && is_usable_gateway(&r.next_hop)
                && !r.destination_prefix.starts_with("224.")
                && !r.destination_prefix.starts_with("255.")
        })
        .min_by_key(|r| {
            let priority = match r.destination_prefix.as_str() {
                "0.0.0.0/0" => 0u8,
                "0.0.0.0/1" | "128.0.0.0/1" => 1u8,
                _ => 2u8,
            };
            (priority, r.route_metric)
        })
        .map(|r| r.next_hop.clone())
}

fn has_any_process(running_exe_set: &HashSet<String>, names: &[&str]) -> bool {
    names.iter().any(|name| running_exe_set.contains(*name))
}

fn detect_karing(
    adapters: &[RawAdapterInfo],
    ipv4_routes: &[RouteRecord],
    running_exe_set: &HashSet<String>,
    ports_by_exe: &HashMap<String, Vec<u16>>,
) -> DetectedVpnInfo {
    let process_running = has_any_process(running_exe_set, &["karingservice.exe", "karing.exe"]);
    let adapter = find_matching_adapter(adapters, is_karing_adapter);
    let adapter_is_up = adapter.is_some_and(|a| a.is_up);
    let detected_port = ports_by_exe
        .get("karingservice.exe")
        .and_then(|ports| pick_karing_mixed_port(ports))
        .or_else(|| {
            ports_by_exe
                .get("karing.exe")
                .and_then(|ports| pick_karing_mixed_port(ports))
        });
    let is_running = process_running && detected_port.is_some();

    DetectedVpnInfo {
        provider: VpnProvider::Karing,
        is_running,
        detected_port,
        adapter_alias: adapter.map(|a| a.alias.clone()),
        adapter_if_index: adapter.map(|a| a.if_index),
        adapter_is_up,
        adapter_gateway: resolve_adapter_gateway(adapter, ipv4_routes),
        remote_server_ip: None,
    }
}

fn detect_nekoray(
    adapters: &[RawAdapterInfo],
    ipv4_routes: &[RouteRecord],
    running_exe_set: &HashSet<String>,
    ports_by_exe: &HashMap<String, Vec<u16>>,
) -> DetectedVpnInfo {
    let process_running = has_any_process(
        running_exe_set,
        &["nekobox_core.exe", "nekoray_core.exe", "nekoray.exe"],
    );
    let adapter = find_matching_adapter(adapters, is_nekoray_adapter);
    let adapter_is_up = adapter.is_some_and(|a| a.is_up);
    let detected_port = ports_by_exe
        .get("nekobox_core.exe")
        .and_then(|ports| pick_nekoray_socks_port(ports))
        .or_else(|| {
            ports_by_exe
                .get("nekoray_core.exe")
                .and_then(|ports| pick_nekoray_socks_port(ports))
        })
        .or_else(|| {
            ports_by_exe
                .get("nekoray.exe")
                .and_then(|ports| pick_nekoray_socks_port(ports))
        });
    let is_running = process_running && detected_port.is_some();

    DetectedVpnInfo {
        provider: VpnProvider::NekoRay,
        is_running,
        detected_port,
        adapter_alias: adapter.map(|a| a.alias.clone()),
        adapter_if_index: adapter.map(|a| a.if_index),
        adapter_is_up,
        adapter_gateway: resolve_adapter_gateway(adapter, ipv4_routes),
        remote_server_ip: None,
    }
}

pub(crate) fn detect_hotspot(adapters: &[RawAdapterInfo]) -> DetectedHotspotInfo {
    let adapter = adapters
        .iter()
        .filter(|a| {
            a.ipv4.as_deref() == Some("192.168.137.1")
                || a.description
                    .to_ascii_lowercase()
                    .contains("wi-fi direct virtual")
        })
        .max_by_key(|a| (a.is_up, a.ipv4.as_deref() == Some("192.168.137.1")));

    DetectedHotspotInfo {
        is_active: adapter.is_some_and(|a| a.is_up),
        adapter_alias: adapter.map(|a| a.alias.clone()),
        ipv4: adapter.and_then(|a| a.ipv4.clone()),
    }
}

fn detect_openvpn(
    adapters: &[RawAdapterInfo],
    ipv4_routes: &[RouteRecord],
    running_exe_set: &HashSet<String>,
    physical_interfaces: &[PhysicalInterfaceInfo],
) -> DetectedVpnInfo {
    let process_running = has_any_process(
        running_exe_set,
        &[
            "openvpn.exe",
            "ovpnconnector.exe",
            "agent_ovpnconnect.exe",
            "ovpnhelper_service.exe",
            "openvpnconnect.exe",
        ],
    );
    let adapter = find_matching_adapter(adapters, is_openvpn_adapter);
    let adapter_is_up = adapter.is_some_and(|a| a.is_up);
    let is_running = process_running && adapter_is_up;
    let remote_server_ip = if is_running {
        extract_openvpn_remote_server_ip(
            ipv4_routes,
            adapter.map(|a| a.if_index),
            physical_interfaces,
        )
    } else {
        None
    };

    DetectedVpnInfo {
        provider: VpnProvider::OpenVpn,
        is_running,
        detected_port: None,
        adapter_alias: adapter.map(|a| a.alias.clone()),
        adapter_if_index: adapter.map(|a| a.if_index),
        adapter_is_up,
        adapter_gateway: resolve_adapter_gateway(adapter, ipv4_routes),
        remote_server_ip,
    }
}

pub(crate) fn is_excluded_shell_or_self_exe(exe_lower: &str) -> bool {
    matches!(
        exe_lower,
        "netflow.exe"
            | "netflow-tauri.exe"
            | "sing-box.exe"
            | "sing-box-x86_64-pc-windows-msvc.exe"
            | "explorer.exe"
            | "applicationframehost.exe"
            | "shellexperiencehost.exe"
            | "startmenuexperiencehost.exe"
            | "searchhost.exe"
            | "searchapp.exe"
            | "textinputhost.exe"
            | "lockapp.exe"
            | "dwm.exe"
            | "csrss.exe"
            | "svchost.exe"
            | "conhost.exe"
            | "runtimebroker.exe"
            | "dllhost.exe"
            | "sihost.exe"
            | "ctfmon.exe"
            | "systemsettings.exe"
            | "winlogon.exe"
            | "fontdrvhost.exe"
            | "searchindexer.exe"
    )
}

pub(crate) fn is_ignored_child_exe(exe_lower: &str) -> bool {
    matches!(
        exe_lower,
        "conhost.exe"
            | "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "svchost.exe"
            | "werfault.exe"
            | "msiexec.exe"
            | "rundll32.exe"
            | "dllhost.exe"
            | "runtimebroker.exe"
            | "backgroundtaskhost.exe"
            | "taskhostw.exe"
            | "openconsole.exe"
    )
}

fn is_generic_install_dir(dir_lower: &str) -> bool {
    let bytes = dir_lower.as_bytes();
    if bytes.len() <= 3 && bytes.get(1) == Some(&b':') {
        return true;
    }

    if dir_lower == r"c:\windows"
        || dir_lower == r"c:\windows\system32"
        || dir_lower == r"c:\windows\syswow64"
        || dir_lower.ends_with(r"\windows")
        || dir_lower.ends_with(r"\windows\system32")
        || dir_lower.ends_with(r"\windows\syswow64")
        || dir_lower.ends_with(r"\program files")
        || dir_lower.ends_with(r"\program files (x86)")
        || dir_lower.ends_with(r"\appdata\local")
        || dir_lower.ends_with(r"\appdata\roaming")
        || dir_lower.ends_with(r"\appdata\locallow")
        || dir_lower.ends_with(r"\desktop")
        || dir_lower.ends_with(r"\downloads")
        || dir_lower.ends_with(r"\temp")
        || dir_lower.ends_with(r"\programdata")
        || dir_lower.ends_with(r"\windowsapps")
    {
        return true;
    }

    false
}

fn is_version_or_bin_subdir(segment_lower: &str) -> bool {
    if segment_lower.starts_with("app-") && segment_lower.len() > 4 {
        return true;
    }
    matches!(
        segment_lower,
        "application" | "bin" | "win64" | "win32" | "x64" | "binaries" | "client" | "launcher"
    )
}

pub(crate) fn extract_app_install_root(path: &str) -> Option<String> {
    let normalized = path.trim().replace('/', "\\");
    if normalized.is_empty() {
        return None;
    }
    let (parent_raw, _) = normalized.rsplit_once('\\')?;
    let parent = parent_raw.trim_end_matches('\\');
    if parent.is_empty() {
        return None;
    }
    let parent_lower = parent.to_ascii_lowercase();
    if is_generic_install_dir(&parent_lower) {
        return None;
    }

    if let Some((grandparent_raw, last_seg)) = parent_lower.rsplit_once('\\') {
        let grandparent = grandparent_raw.trim_end_matches('\\');
        if is_version_or_bin_subdir(last_seg)
            && !grandparent.is_empty()
            && !is_generic_install_dir(grandparent)
        {
            return Some(grandparent.to_string());
        }
    }

    Some(parent_lower)
}

pub(crate) fn fallback_display_name(exe_name: &str) -> String {
    let trimmed = exe_name.trim();
    let stem = trimmed
        .strip_suffix(".exe")
        .or_else(|| trimmed.strip_suffix(".EXE"))
        .unwrap_or(trimmed);
    let words: Vec<String> = stem
        .split(['_', '-', '.'])
        .filter(|w| !w.is_empty())
        .map(|word| {
            let mut chars = word.chars();
            match chars.next() {
                Some(first) => {
                    let mut s = first.to_uppercase().to_string();
                    s.push_str(chars.as_str());
                    s
                }
                None => String::new(),
            }
        })
        .collect();
    if words.is_empty() {
        trimmed.to_string()
    } else {
        words.join(" ")
    }
}

fn is_secondary_helper_exe(exe_lower: &str) -> bool {
    exe_lower.contains("helper")
        || exe_lower.contains("crashpad")
        || exe_lower.contains("updater")
        || exe_lower.contains("update")
        || exe_lower.contains("webhelper")
        || exe_lower.contains("service")
        || exe_lower.starts_with("unins")
}

fn slugify_app_id(exe_lower: &str) -> String {
    let stem = exe_lower.strip_suffix(".exe").unwrap_or(exe_lower);
    let mut slug = String::with_capacity(stem.len());
    let mut prev_dash = false;
    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !slug.is_empty() {
            slug.push('-');
            prev_dash = true;
        }
    }
    while slug.ends_with('-') {
        slug.pop();
    }
    if slug.is_empty() {
        slug.push_str("app");
    }
    format!("app-{slug}")
}

pub(crate) fn group_open_apps<F>(
    raw_processes: &[RawProcessEntry],
    visible_pids: &HashSet<u32>,
    current_pid: u32,
    mut resolve_meta: F,
) -> Vec<DetectedAppInfo>
where
    F: FnMut(&str, Option<&str>) -> (Option<String>, Option<String>),
{
    let mut by_pid: HashMap<u32, &RawProcessEntry> = HashMap::new();
    let mut children_by_parent: HashMap<u32, Vec<u32>> = HashMap::new();

    for proc_entry in raw_processes {
        by_pid.insert(proc_entry.pid, proc_entry);
        if proc_entry.parent_pid != 0 && proc_entry.parent_pid != proc_entry.pid {
            children_by_parent
                .entry(proc_entry.parent_pid)
                .or_default()
                .push(proc_entry.pid);
        }
    }

    let mut groups: BTreeMap<String, Vec<&RawProcessEntry>> = BTreeMap::new();

    for proc_entry in raw_processes {
        if proc_entry.pid == current_pid || !visible_pids.contains(&proc_entry.pid) {
            continue;
        }
        let Some(canonical) = canonicalize_exe_name(&proc_entry.exe_name) else {
            continue;
        };
        if is_excluded_shell_or_self_exe(&canonical) {
            continue;
        }

        let key = proc_entry
            .path
            .as_deref()
            .and_then(extract_app_install_root)
            .map(|root| format!("root:{root}"))
            .unwrap_or_else(|| format!("exe:{canonical}"));

        groups.entry(key).or_default().push(proc_entry);
    }

    let mut apps = Vec::with_capacity(groups.len());

    for (key, seeds) in groups {
        let Some(&primary_entry) = seeds.iter().min_by_key(|entry| {
            let exe_lower = canonicalize_exe_name(&entry.exe_name)
                .unwrap_or_else(|| entry.exe_name.to_ascii_lowercase());
            (
                is_secondary_helper_exe(&exe_lower),
                exe_lower.len(),
                entry.pid,
            )
        }) else {
            continue;
        };

        let Some(primary_exe) = canonicalize_exe_name(&primary_entry.exe_name) else {
            continue;
        };

        let mut collected_exes: HashSet<String> = HashSet::new();
        collected_exes.insert(primary_exe.clone());

        let mut visited_pids: HashSet<u32> = HashSet::new();
        let mut queue: VecDeque<(u32, usize)> = VecDeque::new();
        for seed in &seeds {
            if visited_pids.insert(seed.pid) {
                queue.push_back((seed.pid, 0));
            }
            if let Some(canon) = canonicalize_exe_name(&seed.exe_name) {
                if !is_excluded_shell_or_self_exe(&canon) {
                    collected_exes.insert(canon);
                }
            }
        }

        while let Some((pid, depth)) = queue.pop_front() {
            if depth >= 8 {
                continue;
            }
            if let Some(child_pids) = children_by_parent.get(&pid) {
                for &child_pid in child_pids {
                    if !visited_pids.insert(child_pid) {
                        continue;
                    }
                    let Some(child) = by_pid.get(&child_pid) else {
                        continue;
                    };
                    let Some(child_exe) = canonicalize_exe_name(&child.exe_name) else {
                        continue;
                    };
                    if is_excluded_shell_or_self_exe(&child_exe) || is_ignored_child_exe(&child_exe)
                    {
                        continue;
                    }
                    collected_exes.insert(child_exe);
                    queue.push_back((child_pid, depth + 1));
                }
            }
        }

        if let Some(root) = key.strip_prefix("root:") {
            let root_prefix = format!("{root}\\");
            for proc_entry in raw_processes {
                let Some(path) = proc_entry.path.as_deref() else {
                    continue;
                };
                let norm_path = path.trim().replace('/', "\\").to_ascii_lowercase();
                if !norm_path.starts_with(&root_prefix) {
                    continue;
                }
                let Some(canon) = canonicalize_exe_name(&proc_entry.exe_name) else {
                    continue;
                };
                if is_excluded_shell_or_self_exe(&canon)
                    || is_ignored_child_exe(&canon)
                    || canon.starts_with("unins")
                {
                    continue;
                }
                collected_exes.insert(canon);
            }
        }

        let mut executables: Vec<String> = collected_exes
            .into_iter()
            .filter(|exe| exe != &primary_exe)
            .collect();
        executables.sort();
        executables.insert(0, primary_exe.clone());

        let (resolved_name, icon_data_url) =
            resolve_meta(&primary_exe, primary_entry.path.as_deref());
        let name = resolved_name
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| fallback_display_name(&primary_exe));

        apps.push(DetectedAppInfo {
            id: slugify_app_id(&primary_exe),
            name,
            primary_exe,
            primary_path: primary_entry.path.clone(),
            executables,
            icon_data_url,
        });
    }

    apps.sort_by(|a, b| {
        a.name
            .to_ascii_lowercase()
            .cmp(&b.name.to_ascii_lowercase())
            .then_with(|| a.primary_exe.cmp(&b.primary_exe))
    });

    let mut used_ids: HashSet<String> = HashSet::new();
    for app in &mut apps {
        let base = app.id.clone();
        if !used_ids.insert(base.clone()) {
            let mut suffix = 2usize;
            loop {
                let candidate = format!("{base}-{suffix}");
                if used_ids.insert(candidate.clone()) {
                    app.id = candidate;
                    break;
                }
                suffix += 1;
            }
        }
    }

    apps
}

pub(crate) fn encode_rgba_png_data_url(width: u32, height: u32, rgba: &[u8]) -> Option<String> {
    if width == 0 || height == 0 || rgba.len() != (width as usize) * (height as usize) * 4 {
        return None;
    }
    let mut png_bytes = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut png_bytes, width, height);
        encoder.set_color(png::ColorType::Rgba);
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(rgba).ok()?;
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&png_bytes);
    Some(format!("data:image/png;base64,{b64}"))
}

type ExeMetadataCache = Mutex<HashMap<String, (Option<String>, Option<String>)>>;
type EnumeratedProcesses = (
    Vec<RunningProcessInfo>,
    HashMap<u32, String>,
    Vec<RawProcessEntry>,
);

fn cached_exe_metadata(path: Option<&str>) -> (Option<String>, Option<String>) {
    let Some(raw_path) = path.map(str::trim).filter(|p| !p.is_empty()) else {
        return (None, None);
    };
    static CACHE: OnceLock<ExeMetadataCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let key = raw_path.to_ascii_lowercase();
    if let Ok(guard) = cache.lock() {
        if let Some(entry) = guard.get(&key) {
            return entry.clone();
        }
    }

    let resolved = (
        platform::read_exe_display_name(raw_path),
        platform::extract_exe_icon_data_url(raw_path),
    );
    if let Ok(mut guard) = cache.lock() {
        guard.insert(key, resolved.clone());
    }
    resolved
}

#[cfg(windows)]
mod platform {
    use std::collections::{BTreeMap, HashMap, HashSet};
    use std::ffi::c_void;

    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::{
        CloseHandle, BOOL, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, HANDLE, HWND, LPARAM,
        NO_ERROR,
    };
    use windows::Win32::Graphics::Gdi::{
        DeleteDC, DeleteObject, GetDC, GetDIBits, GetObjectW, ReleaseDC, BITMAP, BITMAPINFO,
        BITMAPINFOHEADER, BI_RGB, DIB_RGB_COLORS, HBITMAP, HDC, HGDIOBJ,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows::Win32::Storage::FileSystem::{
        GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW, FILE_FLAGS_AND_ATTRIBUTES,
    };
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    use windows::Win32::UI::Shell::{
        ExtractIconExW, SHGetFileInfoW, SHFILEINFOW, SHGFI_ICON, SHGFI_LARGEICON,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        DestroyIcon, EnumChildWindows, EnumWindows, GetIconInfo, GetWindow, GetWindowLongW,
        GetWindowTextLengthW, GetWindowThreadProcessId, IsWindowVisible, GWL_EXSTYLE, GW_OWNER,
        HICON, ICONINFO, WS_EX_APPWINDOW, WS_EX_TOOLWINDOW,
    };

    use super::{
        encode_rgba_png_data_url, DiscoveryError, EnumeratedProcesses, RawProcessEntry,
        RunningProcessInfo,
    };
    use crate::win_net::platform::{to_wide_null, win32_error_message};

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    fn utf16_array_to_string(buf: &[u16]) -> String {
        let end = buf.iter().position(|&ch| ch == 0).unwrap_or(buf.len());
        String::from_utf16_lossy(&buf[..end])
    }

    fn query_process_image_path(pid: u32) -> Option<String> {
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) }.ok()?;
        let guard = HandleGuard(handle);
        let mut buf = vec![0u16; 1024];
        let mut len = buf.len() as u32;
        let res = unsafe {
            QueryFullProcessImageNameW(
                guard.0,
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

    pub(crate) fn enumerate_processes() -> Result<EnumeratedProcesses, DiscoveryError> {
        let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.map_err(|e| {
            DiscoveryError::Win32 {
                operation: "CreateToolhelp32Snapshot",
                code: e.code().0 as u32,
                message: e.message(),
            }
        })?;
        let snap_guard = HandleGuard(snap);

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if let Err(err) = unsafe { Process32FirstW(snap_guard.0, &mut entry) } {
            let code = (err.code().0 as u32) & 0xFFFF;
            if code == ERROR_NO_MORE_FILES.0 {
                return Ok((Vec::new(), HashMap::new(), Vec::new()));
            }
            return Err(DiscoveryError::Win32 {
                operation: "Process32FirstW",
                code: err.code().0 as u32,
                message: err.message(),
            });
        }

        let mut pid_to_exe: HashMap<u32, String> = HashMap::new();
        let mut by_exe_lower: BTreeMap<String, RunningProcessInfo> = BTreeMap::new();
        let mut raw_entries: Vec<RawProcessEntry> = Vec::new();

        loop {
            let pid = entry.th32ProcessID;
            if pid != 0 {
                let exe_name = utf16_array_to_string(&entry.szExeFile);
                if !exe_name.is_empty() {
                    let exe_lower = exe_name.to_ascii_lowercase();
                    pid_to_exe.insert(pid, exe_lower.clone());
                    let path = query_process_image_path(pid);
                    raw_entries.push(RawProcessEntry {
                        pid,
                        parent_pid: entry.th32ParentProcessID,
                        exe_name: exe_name.clone(),
                        path: path.clone(),
                    });

                    match by_exe_lower.get_mut(&exe_lower) {
                        None => {
                            by_exe_lower.insert(exe_lower, RunningProcessInfo { exe_name, path });
                        }
                        Some(existing) if existing.path.is_none() && path.is_some() => {
                            existing.path = path;
                        }
                        Some(_) => {}
                    }
                }
            }

            if let Err(err) = unsafe { Process32NextW(snap_guard.0, &mut entry) } {
                let code = (err.code().0 as u32) & 0xFFFF;
                if code == ERROR_NO_MORE_FILES.0 {
                    break;
                }
                return Err(DiscoveryError::Win32 {
                    operation: "Process32NextW",
                    code: err.code().0 as u32,
                    message: err.message(),
                });
            }
        }

        let mut processes: Vec<RunningProcessInfo> = by_exe_lower.into_values().collect();
        processes.sort_by(|a, b| {
            a.exe_name
                .to_ascii_lowercase()
                .cmp(&b.exe_name.to_ascii_lowercase())
        });

        Ok((processes, pid_to_exe, raw_entries))
    }

    unsafe fn collect_tcp_listener_rows<Row: Copy>(
        table_first_row: *const Row,
        num_entries: u32,
        effective_bytes: usize,
        row_fields: fn(&Row) -> (u32, u32),
        out: &mut HashMap<u32, Vec<u16>>,
    ) {
        let header = std::mem::size_of::<u32>();
        if effective_bytes < header {
            return;
        }
        let max_rows = (effective_bytes - header) / std::mem::size_of::<Row>();
        let safe_count = (num_entries as usize).min(max_rows);
        let rows = std::slice::from_raw_parts(table_first_row, safe_count);
        for row in rows {
            let (raw_port, pid) = row_fields(row);
            let port = u16::from_be(raw_port as u16);
            if port != 0 {
                let entry = out.entry(pid).or_default();
                if !entry.contains(&port) {
                    entry.push(port);
                }
            }
        }
    }

    fn fetch_tcp_table_for_family(
        family: u32,
        out: &mut HashMap<u32, Vec<u16>>,
    ) -> Result<(), DiscoveryError> {
        let mut size: u32 = 8 * 1024;
        // 8-byte aligned storage for MIB_TCPTABLE_OWNER_PID / MIB_TCP6TABLE_OWNER_PID.
        let mut aligned_buf: Vec<u64> = vec![0; (size as usize).div_ceil(8)];
        let mut succeeded = false;

        for _attempt in 0..6 {
            let status = unsafe {
                GetExtendedTcpTable(
                    Some(aligned_buf.as_mut_ptr().cast::<c_void>()),
                    &mut size,
                    false,
                    family,
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if status == NO_ERROR.0 {
                succeeded = true;
                break;
            }
            if status == ERROR_INSUFFICIENT_BUFFER.0 {
                aligned_buf.resize((size as usize).div_ceil(8), 0);
                continue;
            }
            return Err(DiscoveryError::Win32 {
                operation: "GetExtendedTcpTable",
                code: status,
                message: win32_error_message(status),
            });
        }

        if !succeeded {
            return Err(DiscoveryError::Win32 {
                operation: "GetExtendedTcpTable",
                code: ERROR_INSUFFICIENT_BUFFER.0,
                message: win32_error_message(ERROR_INSUFFICIENT_BUFFER.0),
            });
        }

        let effective_bytes = (size as usize).min(aligned_buf.len() * std::mem::size_of::<u64>());
        if effective_bytes < std::mem::size_of::<u32>() {
            return Ok(());
        }

        if family == AF_INET.0 as u32 {
            let table_ptr = aligned_buf.as_ptr().cast::<MIB_TCPTABLE_OWNER_PID>();
            unsafe {
                collect_tcp_listener_rows::<MIB_TCPROW_OWNER_PID>(
                    (*table_ptr).table.as_ptr(),
                    (*table_ptr).dwNumEntries,
                    effective_bytes,
                    |r| (r.dwLocalPort, r.dwOwningPid),
                    out,
                );
            }
        } else if family == AF_INET6.0 as u32 {
            let table_ptr = aligned_buf.as_ptr().cast::<MIB_TCP6TABLE_OWNER_PID>();
            unsafe {
                collect_tcp_listener_rows::<MIB_TCP6ROW_OWNER_PID>(
                    (*table_ptr).table.as_ptr(),
                    (*table_ptr).dwNumEntries,
                    effective_bytes,
                    |r| (r.dwLocalPort, r.dwOwningPid),
                    out,
                );
            }
        }

        Ok(())
    }

    pub(crate) fn enumerate_listening_tcp_ports(
    ) -> Result<HashMap<u32, Vec<u16>>, DiscoveryError> {
        let mut by_pid: HashMap<u32, Vec<u16>> = HashMap::new();
        fetch_tcp_table_for_family(AF_INET.0 as u32, &mut by_pid)?;
        fetch_tcp_table_for_family(AF_INET6.0 as u32, &mut by_pid)?;
        Ok(by_pid)
    }

    struct EnumVisibleState<'a> {
        pid_to_exe: &'a HashMap<u32, String>,
        visible_pids: HashSet<u32>,
    }

    struct UwpChildState {
        host_pid: u32,
        real_pid: Option<u32>,
    }

    unsafe extern "system" fn enum_uwp_child_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        let state = &mut *(lparam.0 as *mut UwpChildState);
        let mut child_pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut child_pid));
        if child_pid != 0 && child_pid != state.host_pid {
            state.real_pid = Some(child_pid);
            return BOOL(0);
        }
        BOOL(1)
    }

    unsafe extern "system" fn enum_visible_windows_proc(hwnd: HWND, lparam: LPARAM) -> BOOL {
        if !IsWindowVisible(hwnd).as_bool() {
            return BOOL(1);
        }
        if GetWindowTextLengthW(hwnd) <= 0 {
            return BOOL(1);
        }
        let has_owner = GetWindow(hwnd, GW_OWNER)
            .ok()
            .is_some_and(|owner| !owner.is_invalid());
        if has_owner {
            return BOOL(1);
        }
        let ex_style = GetWindowLongW(hwnd, GWL_EXSTYLE);
        let is_tool = (ex_style & (WS_EX_TOOLWINDOW.0 as i32)) != 0;
        let is_app = (ex_style & (WS_EX_APPWINDOW.0 as i32)) != 0;
        if is_tool && !is_app {
            return BOOL(1);
        }

        let state = &mut *(lparam.0 as *mut EnumVisibleState<'_>);
        let mut pid = 0u32;
        GetWindowThreadProcessId(hwnd, Some(&mut pid));
        if pid == 0 {
            return BOOL(1);
        }

        if state
            .pid_to_exe
            .get(&pid)
            .is_some_and(|exe| exe == "applicationframehost.exe")
        {
            let mut child_state = UwpChildState {
                host_pid: pid,
                real_pid: None,
            };
            let _ = EnumChildWindows(
                hwnd,
                Some(enum_uwp_child_proc),
                LPARAM((&raw mut child_state) as isize),
            );
            if let Some(real_pid) = child_state.real_pid {
                state.visible_pids.insert(real_pid);
            }
        } else {
            state.visible_pids.insert(pid);
        }

        BOOL(1)
    }

    pub(crate) fn enumerate_visible_window_pids(
        pid_to_exe: &HashMap<u32, String>,
    ) -> HashSet<u32> {
        let mut state = EnumVisibleState {
            pid_to_exe,
            visible_pids: HashSet::new(),
        };
        let _ = unsafe {
            EnumWindows(
                Some(enum_visible_windows_proc),
                LPARAM((&raw mut state) as isize),
            )
        };
        state.visible_pids
    }

    unsafe fn read_version_string(
        version_buf: &[u8],
        lang: u16,
        codepage: u16,
        field: &str,
    ) -> Option<String> {
        let query = format!(r"\StringFileInfo\{lang:04x}{codepage:04x}\{field}");
        let wide_query = to_wide_null(&query);
        let mut ptr: *mut c_void = std::ptr::null_mut();
        let mut len: u32 = 0;
        if VerQueryValueW(
            version_buf.as_ptr().cast::<c_void>(),
            PCWSTR(wide_query.as_ptr()),
            &mut ptr,
            &mut len,
        )
        .as_bool()
            && !ptr.is_null()
            && len > 0
        {
            let slice = std::slice::from_raw_parts(ptr.cast::<u16>(), len as usize);
            let s = utf16_array_to_string(slice).trim().to_string();
            if !s.is_empty() {
                return Some(s);
            }
        }
        None
    }

    fn is_generic_version_string(value: &str) -> bool {
        let lower = value.trim().to_ascii_lowercase();
        lower.is_empty()
            || matches!(
                lower.as_str(),
                "electron" | "chromium" | "application" | "bootstrapper" | "windows"
            )
    }

    pub(crate) fn read_exe_display_name(path: &str) -> Option<String> {
        let wide_path = to_wide_null(path);
        let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(wide_path.as_ptr()), None) };
        if size == 0 {
            return None;
        }
        let mut buf = vec![0u8; size as usize];
        unsafe {
            GetFileVersionInfoW(
                PCWSTR(wide_path.as_ptr()),
                0,
                size,
                buf.as_mut_ptr().cast::<c_void>(),
            )
        }
        .ok()?;

        let mut locales: Vec<(u16, u16)> = Vec::new();
        let trans_query = to_wide_null(r"\VarFileInfo\Translation");
        let mut trans_ptr: *mut c_void = std::ptr::null_mut();
        let mut trans_len: u32 = 0;
        if unsafe {
            VerQueryValueW(
                buf.as_ptr().cast::<c_void>(),
                PCWSTR(trans_query.as_ptr()),
                &mut trans_ptr,
                &mut trans_len,
            )
        }
        .as_bool()
            && !trans_ptr.is_null()
            && trans_len >= 4
        {
            let count = (trans_len as usize) / 4;
            let pairs = unsafe { std::slice::from_raw_parts(trans_ptr.cast::<[u16; 2]>(), count) };
            for pair in pairs {
                locales.push((pair[0], pair[1]));
            }
        }
        locales.push((0x0409, 0x04B0));
        locales.push((0x0409, 0x04E4));

        let mut fallback_product: Option<String> = None;
        for (lang, cp) in locales {
            if let Some(desc) = unsafe { read_version_string(&buf, lang, cp, "FileDescription") } {
                if !is_generic_version_string(&desc) {
                    return Some(desc);
                }
            }
            if fallback_product.is_none() {
                if let Some(prod) = unsafe { read_version_string(&buf, lang, cp, "ProductName") } {
                    if !is_generic_version_string(&prod) {
                        fallback_product = Some(prod);
                    }
                }
            }
        }

        fallback_product
    }

    struct IconGuard(HICON);
    impl Drop for IconGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = DestroyIcon(self.0);
                }
            }
        }
    }

    struct BitmapGuard(HBITMAP);
    impl Drop for BitmapGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = DeleteObject(HGDIOBJ(self.0 .0));
                }
            }
        }
    }

    struct ScreenDcGuard(HDC);
    impl Drop for ScreenDcGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = ReleaseDC(HWND::default(), self.0);
                }
            }
        }
    }

    struct MemDcGuard(HDC);
    impl Drop for MemDcGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = DeleteDC(self.0);
                }
            }
        }
    }

    pub(crate) fn extract_exe_icon_data_url(path: &str) -> Option<String> {
        let wide_path = to_wide_null(path);
        let mut large_icon = HICON::default();
        let count = unsafe {
            ExtractIconExW(
                PCWSTR(wide_path.as_ptr()),
                0,
                Some(&mut large_icon),
                None,
                1,
            )
        };
        let raw_icon = if count > 0 && count != u32::MAX && !large_icon.is_invalid() {
            large_icon
        } else {
            let mut shfi = SHFILEINFOW::default();
            let res = unsafe {
                SHGetFileInfoW(
                    PCWSTR(wide_path.as_ptr()),
                    FILE_FLAGS_AND_ATTRIBUTES(0),
                    Some(&mut shfi),
                    std::mem::size_of::<SHFILEINFOW>() as u32,
                    SHGFI_ICON | SHGFI_LARGEICON,
                )
            };
            if res == 0 || shfi.hIcon.is_invalid() {
                return None;
            }
            shfi.hIcon
        };
        let icon_guard = IconGuard(raw_icon);

        let mut icon_info = ICONINFO::default();
        unsafe { GetIconInfo(icon_guard.0, &mut icon_info) }.ok()?;
        let color_guard = BitmapGuard(icon_info.hbmColor);
        let mask_guard = BitmapGuard(icon_info.hbmMask);

        let target_bmp = if !color_guard.0.is_invalid() {
            color_guard.0
        } else if !mask_guard.0.is_invalid() {
            mask_guard.0
        } else {
            return None;
        };

        let mut bmp_meta = BITMAP::default();
        let meta_size = unsafe {
            GetObjectW(
                HGDIOBJ(target_bmp.0),
                std::mem::size_of::<BITMAP>() as i32,
                Some((&raw mut bmp_meta).cast::<c_void>()),
            )
        };
        if meta_size == 0 || bmp_meta.bmWidth <= 0 || bmp_meta.bmHeight <= 0 {
            return None;
        }

        let width = (bmp_meta.bmWidth as u32).min(256);
        let raw_height = bmp_meta.bmHeight.unsigned_abs();
        let height = if color_guard.0.is_invalid() && raw_height >= width * 2 {
            (raw_height / 2).min(256)
        } else {
            raw_height.min(256)
        };
        if width == 0 || height == 0 {
            return None;
        }

        let screen_dc = ScreenDcGuard(unsafe { GetDC(HWND::default()) });
        if screen_dc.0.is_invalid() {
            return None;
        }
        let _mem_dc = MemDcGuard(HDC::default());

        let mut bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: width as i32,
                biHeight: -(height as i32),
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB.0,
                ..Default::default()
            },
            ..Default::default()
        };

        let pixel_bytes = (width as usize) * (height as usize) * 4;
        let mut bgra = vec![0u8; pixel_bytes];
        let lines = unsafe {
            GetDIBits(
                screen_dc.0,
                target_bmp,
                0,
                height,
                Some(bgra.as_mut_ptr().cast::<c_void>()),
                &mut bmi,
                DIB_RGB_COLORS,
            )
        };
        if lines == 0 {
            return None;
        }

        let has_alpha = bgra.as_chunks::<4>().0.iter().any(|px| px[3] != 0);
        if !has_alpha {
            if !mask_guard.0.is_invalid() && !color_guard.0.is_invalid() {
                let mut mask_bgra = vec![0u8; pixel_bytes];
                let mask_lines = unsafe {
                    GetDIBits(
                        screen_dc.0,
                        mask_guard.0,
                        0,
                        height,
                        Some(mask_bgra.as_mut_ptr().cast::<c_void>()),
                        &mut bmi,
                        DIB_RGB_COLORS,
                    )
                };
                if mask_lines != 0 {
                    for (px, m) in bgra
                        .as_chunks_mut::<4>()
                        .0
                        .iter_mut()
                        .zip(mask_bgra.as_chunks::<4>().0.iter())
                    {
                        let is_transparent = m[0] != 0 || m[1] != 0 || m[2] != 0;
                        px[3] = if is_transparent { 0 } else { 255 };
                    }
                } else {
                    for px in bgra.as_chunks_mut::<4>().0 {
                        px[3] = 255;
                    }
                }
            } else {
                for px in bgra.as_chunks_mut::<4>().0 {
                    px[3] = 255;
                }
            }
        }

        let mut rgba = vec![0u8; pixel_bytes];
        for (dst, src) in rgba
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(bgra.as_chunks::<4>().0.iter())
        {
            dst[0] = src[2];
            dst[1] = src[1];
            dst[2] = src[0];
            dst[3] = src[3];
        }

        encode_rgba_png_data_url(width, height, &rgba)
    }
}

#[cfg(not(windows))]
mod platform {
    use std::collections::{HashMap, HashSet};

    use super::{DiscoveryError, EnumeratedProcesses};

    pub(crate) fn enumerate_processes() -> Result<EnumeratedProcesses, DiscoveryError> {
        Err(DiscoveryError::UnsupportedPlatform)
    }

    pub(crate) fn enumerate_listening_tcp_ports(
    ) -> Result<HashMap<u32, Vec<u16>>, DiscoveryError> {
        Err(DiscoveryError::UnsupportedPlatform)
    }

    pub(crate) fn enumerate_visible_window_pids(
        _pid_to_exe: &HashMap<u32, String>,
    ) -> HashSet<u32> {
        HashSet::new()
    }

    pub(crate) fn read_exe_display_name(_path: &str) -> Option<String> {
        None
    }

    pub(crate) fn extract_exe_icon_data_url(_path: &str) -> Option<String> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::VpnProvider;
    use crate::recovery::RouteRecord;

    struct AdapterSpec<'a> {
        alias: &'a str,
        description: &'a str,
        if_index: u32,
        if_type: u32,
        is_up: bool,
        ipv4: Option<&'a str>,
        gateway_ipv4: Option<&'a str>,
        link_speed_bps: u64,
        ipv4_metric: u32,
    }

    impl<'a> AdapterSpec<'a> {
        fn build(self) -> RawAdapterInfo {
            RawAdapterInfo {
                alias: self.alias.to_string(),
                description: self.description.to_string(),
                if_index: self.if_index,
                if_type: self.if_type,
                is_up: self.is_up,
                ipv4: self.ipv4.map(str::to_string),
                gateway_ipv4: self.gateway_ipv4.map(str::to_string),
                link_speed_bps: self.link_speed_bps,
                ipv4_metric: self.ipv4_metric,
            }
        }
    }

    #[test]
    fn test_classifies_physical_vs_virtual_adapters() {
        let adapters = vec![
            AdapterSpec {
                alias: "Loopback Pseudo-Interface 1",
                description: "Software Loopback Interface 1",
                if_index: 1,
                if_type: 24,
                is_up: true,
                ipv4: Some("127.0.0.1"),
                gateway_ipv4: None,
                link_speed_bps: 1_073_741_824,
                ipv4_metric: 75,
            }
            .build(),
            AdapterSpec {
                alias: "NetFlow-TUN",
                description: "Wintun Userspace Tunnel",
                if_index: 55,
                if_type: 53,
                is_up: true,
                ipv4: Some("172.19.0.1"),
                gateway_ipv4: None,
                link_speed_bps: 100_000_000_000,
                ipv4_metric: 1,
            }
            .build(),
            AdapterSpec {
                alias: "Karing TUN Network Adapter",
                description: "Karing TUN Network Adapter Tunnel",
                if_index: 41,
                if_type: 53,
                is_up: true,
                ipv4: Some("10.20.0.1"),
                gateway_ipv4: None,
                link_speed_bps: 100_000_000_000,
                ipv4_metric: 5,
            }
            .build(),
            AdapterSpec {
                alias: "CloudflareWARP",
                description: "Cloudflare WARP WireGuard Tunnel",
                if_index: 44,
                if_type: 131,
                is_up: true,
                ipv4: Some("172.16.0.2"),
                gateway_ipv4: None,
                link_speed_bps: 100_000_000_000,
                ipv4_metric: 5,
            }
            .build(),
            AdapterSpec {
                alias: "WireGuard Tunnel",
                description: "WireGuard Tunnel Wintun",
                if_index: 45,
                if_type: 131,
                is_up: true,
                ipv4: Some("10.66.66.2"),
                gateway_ipv4: None,
                link_speed_bps: 100_000_000_000,
                ipv4_metric: 10,
            }
            .build(),
            AdapterSpec {
                alias: "OpenVPN Wintun",
                description: "OpenVPN Wintun",
                if_index: 22,
                if_type: 53,
                is_up: true,
                ipv4: Some("10.8.0.2"),
                gateway_ipv4: Some("10.8.0.1"),
                link_speed_bps: 1_000_000_000,
                ipv4_metric: 5,
            }
            .build(),
            AdapterSpec {
                alias: "Local Area Connection",
                description: "TAP-Windows Adapter V9",
                if_index: 23,
                if_type: 6,
                is_up: false,
                ipv4: None,
                gateway_ipv4: None,
                link_speed_bps: 0,
                ipv4_metric: 25,
            }
            .build(),
            AdapterSpec {
                alias: "vEthernet (WSL (Hyper-V firewall))",
                description: "Hyper-V Virtual Ethernet Adapter",
                if_index: 42,
                if_type: 6,
                is_up: true,
                ipv4: Some("172.24.160.1"),
                gateway_ipv4: None,
                link_speed_bps: 10_000_000_000,
                ipv4_metric: 5000,
            }
            .build(),
            AdapterSpec {
                alias: "Wi-Fi",
                description: "Qualcomm Atheros QCA61x4A Wireless Network Adapter",
                if_index: 8,
                if_type: 71,
                is_up: true,
                ipv4: Some("192.168.1.50"),
                gateway_ipv4: Some("192.168.1.1"),
                link_speed_bps: 300_000_000,
                ipv4_metric: 40,
            }
            .build(),
            AdapterSpec {
                alias: "Ethernet",
                description: "Realtek PCIe GbE Family Controller",
                if_index: 10,
                if_type: 6,
                is_up: false,
                ipv4: None,
                gateway_ipv4: None,
                link_speed_bps: u64::MAX,
                ipv4_metric: 25,
            }
            .build(),
        ];

        let routes = vec![RouteRecord {
            interface_index: 8,
            destination_prefix: "0.0.0.0/0".to_string(),
            next_hop: "192.168.1.1".to_string(),
            route_metric: 0,
            is_ipv6: false,
        }];

        let physical = classify_physical_interfaces(&adapters, &routes);
        let aliases: Vec<&str> = physical.iter().map(|i| i.alias.as_str()).collect();
        assert_eq!(
            aliases,
            vec!["Wi-Fi", "CloudflareWARP", "WireGuard Tunnel", "Ethernet"]
        );

        let wifi = &physical[0];
        assert_eq!(wifi.if_index, 8);
        assert!(wifi.is_up);
        assert_eq!(wifi.link_speed_mbps, 300);
        assert!(wifi.is_default_gateway);
        assert_eq!(wifi.ipv4.as_deref(), Some("192.168.1.50"));
        assert_eq!(wifi.gateway_ipv4.as_deref(), Some("192.168.1.1"));

        let warp = &physical[1];
        assert_eq!(warp.if_index, 44);
        assert!(warp.is_up);

        let wg = &physical[2];
        assert_eq!(wg.if_index, 45);
        assert!(wg.is_up);

        let eth = &physical[3];
        assert_eq!(eth.if_index, 10);
        assert!(!eth.is_up);
        assert_eq!(eth.link_speed_mbps, 0);
        assert!(!eth.is_default_gateway);
    }

    #[test]
    fn test_picks_karing_mixed_port_preferring_3067() {
        assert_eq!(
            pick_karing_mixed_port(&[5848, 3067, 3066, 3065, 3057]),
            Some(3067)
        );
        assert_eq!(pick_karing_mixed_port(&[5848, 7890, 7891]), Some(7890));
        assert_eq!(
            pick_karing_mixed_port(&[9519, 3057, 9090, 10808]),
            Some(10808)
        );
        assert_eq!(pick_karing_mixed_port(&[5848, 3057]), None);
        assert_eq!(pick_karing_mixed_port(&[]), None);
    }

    #[test]
    fn test_extracts_openvpn_remote_server_ip_from_host_route() {
        let physical = vec![PhysicalInterfaceInfo {
            alias: "Wi-Fi".to_string(),
            description: "Qualcomm Atheros QCA61x4A".to_string(),
            if_index: 8,
            ipv4: Some("192.168.1.50".to_string()),
            gateway_ipv4: Some("192.168.1.1".to_string()),
            is_up: true,
            link_speed_mbps: 300,
            is_default_gateway: true,
        }];

        let routes = vec![
            RouteRecord {
                interface_index: 8,
                destination_prefix: "0.0.0.0/0".to_string(),
                next_hop: "192.168.1.1".to_string(),
                route_metric: 40,
                is_ipv6: false,
            },
            RouteRecord {
                interface_index: 8,
                destination_prefix: "192.168.1.50/32".to_string(),
                next_hop: "0.0.0.0".to_string(),
                route_metric: 256,
                is_ipv6: false,
            },
            RouteRecord {
                interface_index: 8,
                destination_prefix: "255.255.255.255/32".to_string(),
                next_hop: "0.0.0.0".to_string(),
                route_metric: 256,
                is_ipv6: false,
            },
            RouteRecord {
                interface_index: 22,
                destination_prefix: "0.0.0.0/1".to_string(),
                next_hop: "10.8.0.1".to_string(),
                route_metric: 5,
                is_ipv6: false,
            },
            RouteRecord {
                interface_index: 22,
                destination_prefix: "128.0.0.0/1".to_string(),
                next_hop: "10.8.0.1".to_string(),
                route_metric: 5,
                is_ipv6: false,
            },
            RouteRecord {
                interface_index: 8,
                destination_prefix: "198.51.100.42/32".to_string(),
                next_hop: "192.168.1.1".to_string(),
                route_metric: 5,
                is_ipv6: false,
            },
        ];

        assert_eq!(
            extract_openvpn_remote_server_ip(&routes, Some(22), &physical).as_deref(),
            Some("198.51.100.42")
        );

        let routes_without_host_route: Vec<RouteRecord> = routes
            .into_iter()
            .filter(|r| r.destination_prefix != "198.51.100.42/32")
            .collect();
        assert_eq!(
            extract_openvpn_remote_server_ip(&routes_without_host_route, Some(22), &physical),
            None
        );
    }

    #[test]
    fn test_detects_vpn_providers_and_route_fallback_gateways() {
        let adapters = vec![
            AdapterSpec {
                alias: "Karing TUN Network Adapter",
                description: "Karing TUN Network Adapter Tunnel",
                if_index: 41,
                if_type: 53,
                is_up: true,
                ipv4: Some("10.20.0.1"),
                gateway_ipv4: None,
                link_speed_bps: 100_000_000_000,
                ipv4_metric: 5,
            }
            .build(),
            AdapterSpec {
                alias: "OpenVPN Wintun",
                description: "OpenVPN Wintun",
                if_index: 22,
                if_type: 53,
                is_up: true,
                ipv4: Some("10.8.0.2"),
                gateway_ipv4: Some("10.8.0.1"),
                link_speed_bps: 1_000_000_000,
                ipv4_metric: 5,
            }
            .build(),
        ];

        let routes = vec![
            RouteRecord {
                interface_index: 41,
                destination_prefix: "128.0.0.0/1".to_string(),
                next_hop: "10.20.0.2".to_string(),
                route_metric: 0,
                is_ipv6: false,
            },
            RouteRecord {
                interface_index: 8,
                destination_prefix: "198.51.100.42/32".to_string(),
                next_hop: "192.168.1.1".to_string(),
                route_metric: 5,
                is_ipv6: false,
            },
        ];

        let physical = vec![PhysicalInterfaceInfo {
            alias: "Wi-Fi".to_string(),
            description: "Qualcomm".to_string(),
            if_index: 8,
            ipv4: Some("192.168.1.50".to_string()),
            gateway_ipv4: Some("192.168.1.1".to_string()),
            is_up: true,
            link_speed_mbps: 300,
            is_default_gateway: true,
        }];

        let running: HashSet<String> = ["karingservice.exe", "ovpnconnector.exe"]
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut ports = HashMap::new();
        ports.insert("karingservice.exe".to_string(), vec![5848, 3067, 3066]);

        let karing = detect_karing(&adapters, &routes, &running, &ports);
        assert!(karing.is_running);
        assert!(karing.adapter_is_up);
        assert_eq!(karing.detected_port, Some(3067));
        assert_eq!(karing.adapter_if_index, Some(41));
        assert_eq!(karing.adapter_gateway.as_deref(), Some("10.20.0.2"));

        let openvpn = detect_openvpn(&adapters, &routes, &running, &physical);
        assert!(openvpn.is_running);
        assert!(openvpn.adapter_is_up);
        assert_eq!(openvpn.adapter_if_index, Some(22));
        assert_eq!(openvpn.adapter_gateway.as_deref(), Some("10.8.0.1"));
        assert_eq!(openvpn.remote_server_ip.as_deref(), Some("198.51.100.42"));
    }

    #[test]
    fn test_always_on_services_without_live_tunnel_are_reported_disconnected() {
        let down_adapters = vec![
            AdapterSpec {
                alias: "OpenVPN Data Channel Offload",
                description: "OpenVPN Data Channel Offload",
                if_index: 22,
                if_type: 53,
                is_up: false,
                ipv4: None,
                gateway_ipv4: None,
                link_speed_bps: 0,
                ipv4_metric: 5,
            }
            .build(),
            AdapterSpec {
                alias: "OpenVPN Wintun",
                description: "OpenVPN Wintun",
                if_index: 25,
                if_type: 53,
                is_up: true,
                ipv4: Some("10.8.0.2"),
                gateway_ipv4: Some("10.8.0.1"),
                link_speed_bps: 1_000_000_000,
                ipv4_metric: 5,
            }
            .build(),
        ];

        let running: HashSet<String> = ["karingservice.exe", "ovpnconnector.exe"]
            .into_iter()
            .map(str::to_string)
            .collect();

        // Karing service running with only control ports (no SOCKS/Mixed port) -> not running
        let mut control_only_ports = HashMap::new();
        control_only_ports.insert("karingservice.exe".to_string(), vec![5848, 3057]);
        let karing = detect_karing(&down_adapters, &[], &running, &control_only_ports);
        assert!(!karing.is_running);
        assert_eq!(karing.detected_port, None);

        // OpenVPN prefers the is_up == true adapter over the down DCO adapter
        let openvpn_up = detect_openvpn(&down_adapters, &[], &running, &[]);
        assert!(openvpn_up.is_running);
        assert!(openvpn_up.adapter_is_up);
        assert_eq!(openvpn_up.adapter_if_index, Some(25));

        // OpenVPN with only down adapter -> not running even when ovpnconnector.exe is running
        let down_only_ovpn = vec![down_adapters[0].clone()];
        let openvpn_down = detect_openvpn(&down_only_ovpn, &[], &running, &[]);
        assert!(!openvpn_down.is_running);
        assert!(!openvpn_down.adapter_is_up);
    }

    #[cfg(windows)]
    #[test]
    fn test_win32_discovery_snapshot_smoke_on_windows() {
        let discovery = Win32Discovery;
        let snapshot = discovery.snapshot().expect("Win32Discovery snapshot");

        assert!(
            !snapshot.interfaces.is_empty(),
            "expected at least 1 physical interface on Windows"
        );
        assert!(
            !snapshot.processes.is_empty(),
            "expected non-empty running process list on Windows"
        );
        assert_eq!(snapshot.vpns.len(), 3);
        assert!(snapshot.vpns.iter().any(|v| v.provider == VpnProvider::Karing));
        assert!(snapshot.vpns.iter().any(|v| v.provider == VpnProvider::OpenVpn));
        assert!(snapshot.vpns.iter().any(|v| v.provider == VpnProvider::NekoRay));

        for iface in &snapshot.interfaces {
            let lower = iface.alias.to_ascii_lowercase();
            assert!(!lower.contains("loopback"));
            assert!(!lower.contains("netflow-tun"));
            assert!(!lower.contains("karing"));
            assert!(!lower.contains("nekoray"));
            assert!(!lower.contains("openvpn"));
            assert!(!lower.contains("vethernet"));
        }

        if snapshot
            .processes
            .iter()
            .any(|p| p.exe_name.eq_ignore_ascii_case("karingService.exe"))
        {
            let karing = snapshot
                .vpns
                .iter()
                .find(|v| v.provider == VpnProvider::Karing)
                .expect("karing entry");
            assert_eq!(karing.is_running, karing.detected_port.is_some());
        }

        for app in &snapshot.open_apps {
            assert!(!app.id.is_empty());
            assert!(!app.name.trim().is_empty());
            assert!(!app.executables.is_empty());
            assert_eq!(app.executables[0], app.primary_exe);
        }
    }

    #[test]
    fn test_extract_app_install_root_handles_generic_vs_app_folders() {
        assert_eq!(
            extract_app_install_root(r"C:\Windows\System32\notepad.exe"),
            None
        );
        assert_eq!(
            extract_app_install_root(r"C:\Program Files\SomeTool.exe"),
            None
        );
        assert_eq!(
            extract_app_install_root(
                r"C:\Users\alice\AppData\Local\Discord\app-1.0.9269\Discord.exe"
            ),
            Some(r"c:\users\alice\appdata\local\discord".to_string())
        );
        assert_eq!(
            extract_app_install_root(
                r"C:\Program Files\Google\Chrome\Application\chrome.exe"
            ),
            Some(r"c:\program files\google\chrome".to_string())
        );
    }

    #[test]
    fn test_groups_open_apps_by_install_root_and_process_tree() {
        let raw_processes = vec![
            RawProcessEntry {
                pid: 100,
                parent_pid: 1,
                exe_name: "explorer.exe".to_string(),
                path: Some(r"C:\Windows\explorer.exe".to_string()),
            },
            RawProcessEntry {
                pid: 101,
                parent_pid: 1,
                exe_name: "netflow.exe".to_string(),
                path: Some(r"C:\Program Files\NetFlow\netflow.exe".to_string()),
            },
            RawProcessEntry {
                pid: 200,
                parent_pid: 100,
                exe_name: "Discord.exe".to_string(),
                path: Some(r"C:\Users\u\AppData\Local\Discord\app-1.0.9269\Discord.exe".to_string()),
            },
            RawProcessEntry {
                pid: 201,
                parent_pid: 200,
                exe_name: "DiscordSystemHelper.exe".to_string(),
                path: Some(
                    r"C:\Users\u\AppData\Local\Discord\app-1.0.9269\DiscordSystemHelper.exe"
                        .to_string(),
                ),
            },
            RawProcessEntry {
                pid: 202,
                parent_pid: 200,
                exe_name: "conhost.exe".to_string(),
                path: Some(r"C:\Windows\System32\conhost.exe".to_string()),
            },
            RawProcessEntry {
                pid: 300,
                parent_pid: 100,
                exe_name: "chrome.exe".to_string(),
                path: Some(r"C:\Program Files\Google\Chrome\Application\chrome.exe".to_string()),
            },
            RawProcessEntry {
                pid: 301,
                parent_pid: 300,
                exe_name: "chrome_helper.exe".to_string(),
                path: Some(r"C:\Program Files\Google\Chrome\Application\chrome_helper.exe".to_string()),
            },
            RawProcessEntry {
                pid: 400,
                parent_pid: 100,
                exe_name: "steam.exe".to_string(),
                path: Some(r"C:\Program Files (x86)\Steam\steam.exe".to_string()),
            },
            RawProcessEntry {
                pid: 401,
                parent_pid: 400,
                exe_name: "steamwebhelper.exe".to_string(),
                path: Some(r"C:\Program Files (x86)\Steam\bin\cef\steamwebhelper.exe".to_string()),
            },
            RawProcessEntry {
                pid: 500,
                parent_pid: 1,
                exe_name: "svchost.exe".to_string(),
                path: Some(r"C:\Windows\System32\svchost.exe".to_string()),
            },
        ];

        let visible_pids: HashSet<u32> = [100, 101, 200, 300, 400].into_iter().collect();
        let apps = group_open_apps(&raw_processes, &visible_pids, 9999, |exe, _| match exe {
            "discord.exe" => (
                Some("Discord".to_string()),
                Some("data:image/png;base64,ZGlzY29yZA==".to_string()),
            ),
            "chrome.exe" => (Some("Google Chrome".to_string()), None),
            _ => (None, None),
        });

        assert_eq!(apps.len(), 3);
        assert_eq!(apps[0].name, "Discord");
        assert_eq!(apps[0].primary_exe, "discord.exe");
        assert_eq!(
            apps[0].executables,
            vec!["discord.exe", "discordsystemhelper.exe"]
        );
        assert_eq!(
            apps[0].icon_data_url.as_deref(),
            Some("data:image/png;base64,ZGlzY29yZA==")
        );

        assert_eq!(apps[1].name, "Google Chrome");
        assert_eq!(apps[1].primary_exe, "chrome.exe");
        assert_eq!(apps[1].executables, vec!["chrome.exe", "chrome_helper.exe"]);

        assert_eq!(apps[2].name, "Steam");
        assert_eq!(apps[2].primary_exe, "steam.exe");
        assert_eq!(apps[2].executables, vec!["steam.exe", "steamwebhelper.exe"]);
    }

    #[test]
    fn test_encode_rgba_png_data_url() {
        let rgba = [
            255, 0, 0, 255, // red
            0, 255, 0, 255, // green
            0, 0, 255, 255, // blue
            255, 255, 255, 0, // transparent
        ];
        let url = encode_rgba_png_data_url(2, 2, &rgba).expect("valid PNG data URL");
        let b64 = url
            .strip_prefix("data:image/png;base64,")
            .expect("png data URL prefix");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .expect("valid base64");
        assert!(decoded.starts_with(b"\x89PNG\r\n\x1a\n"));
        assert_eq!(encode_rgba_png_data_url(0, 2, &[]), None);
    }
}
