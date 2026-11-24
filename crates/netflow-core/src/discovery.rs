//! Windows system discovery for physical and virtual third-party network adapters,
//! running processes, and active VPN providers (`Karing`, `OpenVPN`).

use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::model::VpnProvider;
use crate::recovery::RouteRecord;
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

/// Complete read-only snapshot of Windows interfaces, VPN providers, and running processes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoverySnapshot {
    pub interfaces: Vec<PhysicalInterfaceInfo>,
    pub vpns: Vec<DetectedVpnInfo>,
    pub processes: Vec<RunningProcessInfo>,
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
        let (processes, pid_to_exe) = platform::enumerate_processes()?;
        let listening_ports_by_pid = platform::enumerate_listening_tcp_ports()?;

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

        Ok(DiscoverySnapshot {
            interfaces,
            vpns: vec![karing, openvpn],
            processes,
        })
    }
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
            "karing",
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

fn detect_openvpn(
    adapters: &[RawAdapterInfo],
    ipv4_routes: &[RouteRecord],
    running_exe_set: &HashSet<String>,
    physical_interfaces: &[PhysicalInterfaceInfo],
) -> DetectedVpnInfo {
    let process_running = has_any_process(running_exe_set, &["openvpn.exe", "ovpnconnector.exe"]);
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

#[cfg(windows)]
mod platform {
    use std::collections::{BTreeMap, HashMap};
    use std::ffi::c_void;

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_MORE_FILES, HANDLE, NO_ERROR,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_WIN32,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };

    use super::{DiscoveryError, RunningProcessInfo};
    use crate::win_net::platform::win32_error_message;

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

    pub(crate) fn enumerate_processes(
    ) -> Result<(Vec<RunningProcessInfo>, HashMap<u32, String>), DiscoveryError> {
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
                return Ok((Vec::new(), HashMap::new()));
            }
            return Err(DiscoveryError::Win32 {
                operation: "Process32FirstW",
                code: err.code().0 as u32,
                message: err.message(),
            });
        }

        let mut pid_to_exe: HashMap<u32, String> = HashMap::new();
        let mut by_exe_lower: BTreeMap<String, RunningProcessInfo> = BTreeMap::new();

        loop {
            let pid = entry.th32ProcessID;
            if pid != 0 {
                let exe_name = utf16_array_to_string(&entry.szExeFile);
                if !exe_name.is_empty() {
                    let exe_lower = exe_name.to_ascii_lowercase();
                    pid_to_exe.insert(pid, exe_lower.clone());
                    let path = query_process_image_path(pid);

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

        Ok((processes, pid_to_exe))
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
}

#[cfg(not(windows))]
mod platform {
    use std::collections::HashMap;

    use super::{DiscoveryError, RunningProcessInfo};

    pub(crate) fn enumerate_processes(
    ) -> Result<(Vec<RunningProcessInfo>, HashMap<u32, String>), DiscoveryError> {
        Err(DiscoveryError::UnsupportedPlatform)
    }

    pub(crate) fn enumerate_listening_tcp_ports(
    ) -> Result<HashMap<u32, Vec<u16>>, DiscoveryError> {
        Err(DiscoveryError::UnsupportedPlatform)
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
        assert_eq!(snapshot.vpns.len(), 2);
        assert!(snapshot.vpns.iter().any(|v| v.provider == VpnProvider::Karing));
        assert!(snapshot.vpns.iter().any(|v| v.provider == VpnProvider::OpenVpn));

        for iface in &snapshot.interfaces {
            let lower = iface.alias.to_ascii_lowercase();
            assert!(!lower.contains("loopback"));
            assert!(!lower.contains("netflow-tun"));
            assert!(!lower.contains("karing"));
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
    }
}
