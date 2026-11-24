//! Win32 routing table, interface metric, Windows System Proxy, and Cloudflare WARP CLI
//! operations for NetFlow.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use thiserror::Error;

use crate::recovery::{InterfaceMetricSnapshot, RouteRecord, SystemProxySnapshot};

/// Typed errors returned by [`WindowsNetworkOps`] implementations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum NetOpsError {
    #[error("Win32 API call '{operation}' failed with error code {code}: {message}")]
    Win32 {
        operation: &'static str,
        code: u32,
        message: String,
    },
    #[error("invalid IP address '{value}'")]
    InvalidAddress { value: String },
    #[error("invalid CIDR prefix '{value}'")]
    InvalidPrefix { value: String },
    #[error("route not found ({prefix} via {next_hop} on ifIndex {interface_index})")]
    RouteNotFound {
        interface_index: u32,
        prefix: String,
        next_hop: String,
    },
    #[error("warp-cli.exe not found in PATH or standard installation directory")]
    WarpCliNotFound,
    #[error("warp-cli command failed: {message}")]
    WarpCliFailed { message: String },
    #[error("invalid warp-cli mode '{mode}'")]
    InvalidWarpMode { mode: String },
    #[error("I/O error: {0}")]
    Io(String),
    #[error("Windows network operations are only supported on Windows")]
    UnsupportedPlatform,
}

/// Abstraction over OS-level routing table, interface metric, System Proxy, and WARP CLI actions.
pub trait WindowsNetworkOps: Send + Sync {
    /// Lists routing table entries, optionally filtered to a specific interface index.
    fn list_routes(
        &self,
        interface_index: Option<u32>,
        is_ipv6: bool,
    ) -> Result<Vec<RouteRecord>, NetOpsError>;

    /// Adds a route entry to the Windows IP routing table.
    fn add_route(&self, route: &RouteRecord) -> Result<(), NetOpsError>;

    /// Removes a route entry from the Windows IP routing table.
    fn remove_route(&self, route: &RouteRecord) -> Result<(), NetOpsError>;

    /// Reads the current metric and AutomaticMetric flag for an IPv4 or IPv6 interface.
    fn get_interface_metric(
        &self,
        interface_index: u32,
        is_ipv6: bool,
    ) -> Result<InterfaceMetricSnapshot, NetOpsError>;

    /// Sets an interface's manual metric or re-enables AutomaticMetric.
    fn set_interface_metric(
        &self,
        interface_index: u32,
        is_ipv6: bool,
        metric: u32,
        automatic_metric: bool,
    ) -> Result<(), NetOpsError>;

    /// Restores a previously captured [`InterfaceMetricSnapshot`].
    fn restore_interface_metric(
        &self,
        snapshot: &InterfaceMetricSnapshot,
    ) -> Result<(), NetOpsError> {
        self.set_interface_metric(
            snapshot.interface_index,
            snapshot.is_ipv6,
            snapshot.original_metric,
            snapshot.automatic_metric,
        )
    }

    /// Resolves the interface alias (e.g. `"NetFlow-TUN"` or `"Wi-Fi"`) owning the best route to `dest_ipv4`.
    fn find_best_route_interface(&self, dest_ipv4: &str) -> Result<Option<String>, NetOpsError>;

    /// Looks up a network interface's `IfIndex` by its alias (`FriendlyName`), case-insensitively.
    fn find_interface_index_by_alias(&self, alias: &str) -> Result<Option<u32>, NetOpsError>;

    /// Reads the current per-user Windows Internet Settings system proxy configuration.
    fn get_system_proxy(&self) -> Result<SystemProxySnapshot, NetOpsError>;

    /// Applies and broadcasts a [`SystemProxySnapshot`] to Windows Internet Settings.
    fn set_system_proxy(&self, snapshot: &SystemProxySnapshot) -> Result<(), NetOpsError>;

    /// Disables Windows System Proxy (`ProxyEnable = 0`) and broadcasts WinINet refresh.
    fn disable_system_proxy(&self) -> Result<(), NetOpsError>;

    /// Queries the current Cloudflare WARP mode via `warp-cli settings`, returning `Ok(None)` if not installed.
    fn warp_cli_get_mode(&self) -> Result<Option<String>, NetOpsError>;

    /// Switches Cloudflare WARP mode via `warp-cli mode <mode>`.
    fn warp_cli_set_mode(&self, mode: &str) -> Result<(), NetOpsError>;
}

/// Real Win32 implementation of [`WindowsNetworkOps`].
#[derive(Debug, Default, Clone, Copy)]
pub struct Win32NetworkOps;

impl WindowsNetworkOps for Win32NetworkOps {
    fn list_routes(
        &self,
        interface_index: Option<u32>,
        is_ipv6: bool,
    ) -> Result<Vec<RouteRecord>, NetOpsError> {
        platform::list_routes(interface_index, is_ipv6)
    }

    fn add_route(&self, route: &RouteRecord) -> Result<(), NetOpsError> {
        platform::add_route(route)
    }

    fn remove_route(&self, route: &RouteRecord) -> Result<(), NetOpsError> {
        platform::remove_route(route)
    }

    fn get_interface_metric(
        &self,
        interface_index: u32,
        is_ipv6: bool,
    ) -> Result<InterfaceMetricSnapshot, NetOpsError> {
        platform::get_interface_metric(interface_index, is_ipv6)
    }

    fn set_interface_metric(
        &self,
        interface_index: u32,
        is_ipv6: bool,
        metric: u32,
        automatic_metric: bool,
    ) -> Result<(), NetOpsError> {
        platform::set_interface_metric(interface_index, is_ipv6, metric, automatic_metric)
    }

    fn find_best_route_interface(&self, dest_ipv4: &str) -> Result<Option<String>, NetOpsError> {
        platform::find_best_route_interface(dest_ipv4)
    }

    fn find_interface_index_by_alias(&self, alias: &str) -> Result<Option<u32>, NetOpsError> {
        let trimmed = alias.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }
        let adapters = platform::enumerate_adapters()?;
        Ok(adapters
            .into_iter()
            .find(|a| a.alias.eq_ignore_ascii_case(trimmed))
            .map(|a| a.if_index))
    }

    fn get_system_proxy(&self) -> Result<SystemProxySnapshot, NetOpsError> {
        platform::get_system_proxy()
    }

    fn set_system_proxy(&self, snapshot: &SystemProxySnapshot) -> Result<(), NetOpsError> {
        platform::set_system_proxy(snapshot)
    }

    fn disable_system_proxy(&self) -> Result<(), NetOpsError> {
        platform::disable_system_proxy()
    }

    fn warp_cli_get_mode(&self) -> Result<Option<String>, NetOpsError> {
        warp_cli_get_mode_impl()
    }

    fn warp_cli_set_mode(&self, mode: &str) -> Result<(), NetOpsError> {
        warp_cli_set_mode_impl(mode)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpKind {
    V4([u8; 4]),
    V6([u8; 16]),
}

pub(crate) fn parse_cidr_prefix(prefix: &str, is_ipv6: bool) -> Result<(IpKind, u8), NetOpsError> {
    let trimmed = prefix.trim();
    let Some((ip_str, len_str)) = trimmed.split_once('/') else {
        return Err(NetOpsError::InvalidPrefix {
            value: prefix.to_string(),
        });
    };
    if len_str.contains('/') {
        return Err(NetOpsError::InvalidPrefix {
            value: prefix.to_string(),
        });
    }

    let prefix_len: u8 = len_str.parse().map_err(|_| NetOpsError::InvalidPrefix {
        value: prefix.to_string(),
    })?;
    let max_len = if is_ipv6 { 128 } else { 32 };
    if prefix_len > max_len {
        return Err(NetOpsError::InvalidPrefix {
            value: prefix.to_string(),
        });
    }

    let ip = parse_ip_addr(ip_str, is_ipv6).map_err(|_| NetOpsError::InvalidPrefix {
        value: prefix.to_string(),
    })?;
    Ok((ip, prefix_len))
}

pub(crate) fn parse_ip_addr(addr: &str, is_ipv6: bool) -> Result<IpKind, NetOpsError> {
    let trimmed = addr.trim();
    if is_ipv6 {
        let parsed: Ipv6Addr = trimmed.parse().map_err(|_| NetOpsError::InvalidAddress {
            value: addr.to_string(),
        })?;
        Ok(IpKind::V6(parsed.octets()))
    } else {
        let parsed: Ipv4Addr = trimmed.parse().map_err(|_| NetOpsError::InvalidAddress {
            value: addr.to_string(),
        })?;
        Ok(IpKind::V4(parsed.octets()))
    }
}

/// Parses `warp-cli settings` output into a CLI-compatible `warp-cli mode <arg>` token.
pub(crate) fn parse_warp_cli_mode(output: &str) -> Option<String> {
    for line in output.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        let value = if lower.starts_with("mode:") {
            trimmed.split_once(':').map(|(_, rhs)| rhs)
        } else if lower.starts_with("operation mode:") {
            trimmed.split_once(':').map(|(_, rhs)| rhs)
        } else {
            None
        };

        if let Some(raw_val) = value {
            let token = raw_val.split_whitespace().next().unwrap_or("").trim();
            if token.is_empty() {
                continue;
            }
            let normalized = match token.to_ascii_lowercase().as_str() {
                "warp" => "warp".to_string(),
                "warpwithdnsoverhttps" | "warp+doh" => "warp+doh".to_string(),
                "warpwithdnsovertls" | "warp+dot" => "warp+dot".to_string(),
                "dnsoverhttps" | "doh" => "doh".to_string(),
                "dnsovertls" | "dot" => "dot".to_string(),
                "proxy" => "proxy".to_string(),
                "tunnelonly" | "tunnel_only" => "tunnel_only".to_string(),
                other => other.to_string(),
            };
            return Some(normalized);
        }
    }
    None
}

pub(crate) fn find_warp_cli_path() -> Option<PathBuf> {
    if let Some(path_var) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_var) {
            let candidate = dir.join("warp-cli.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }

    for fallback in [
        r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe",
        r"C:\Program Files (x86)\Cloudflare\Cloudflare WARP\warp-cli.exe",
    ] {
        let candidate = PathBuf::from(fallback);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn run_warp_cli(args: &[&str]) -> Result<String, NetOpsError> {
    let exe = find_warp_cli_path().ok_or(NetOpsError::WarpCliNotFound)?;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let output = cmd
        .output()
        .map_err(|err| NetOpsError::Io(format!("failed to execute warp-cli: {err}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = if !stderr.is_empty() { stderr } else { stdout };
        return Err(NetOpsError::WarpCliFailed {
            message: if detail.is_empty() {
                format!("exit status {}", output.status)
            } else {
                detail
            },
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn warp_cli_get_mode_impl() -> Result<Option<String>, NetOpsError> {
    if find_warp_cli_path().is_none() {
        return Ok(None);
    }
    let stdout = run_warp_cli(&["settings"])?;
    Ok(parse_warp_cli_mode(&stdout))
}

fn warp_cli_set_mode_impl(mode: &str) -> Result<(), NetOpsError> {
    let trimmed = mode.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err(NetOpsError::InvalidWarpMode {
            mode: mode.to_string(),
        });
    }
    let _ = run_warp_cli(&["mode", trimmed])?;
    Ok(())
}

#[cfg(windows)]
pub(crate) mod platform {
    use std::ffi::c_void;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ptr;

    use windows::core::{HRESULT, PCWSTR};
    use windows::Win32::Foundation::{
        BOOLEAN, ERROR_BUFFER_OVERFLOW, ERROR_FILE_NOT_FOUND, ERROR_NETWORK_UNREACHABLE,
        ERROR_NOT_FOUND, NO_ERROR, WIN32_ERROR,
    };
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias, CreateIpForwardEntry2,
        DeleteIpForwardEntry2, FreeMibTable, GetAdaptersAddresses, GetBestRoute2,
        GetIpForwardTable2, GetIpInterfaceEntry, InitializeIpForwardEntry,
        InitializeIpInterfaceEntry, SetIpInterfaceEntry, GAA_FLAG_INCLUDE_GATEWAYS,
        IP_ADAPTER_ADDRESSES_LH, MIB_IPFORWARD_ROW2, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
    use windows::Win32::Networking::WinInet::{
        InternetSetOptionW, INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED,
    };
    use windows::Win32::Networking::WinSock::{
        ADDRESS_FAMILY, AF_INET, AF_INET6, AF_UNSPEC, IN6_ADDR, IN6_ADDR_0, IN_ADDR, IN_ADDR_0,
        IN_ADDR_0_0, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6, SOCKADDR_INET,
    };
    use windows::Win32::System::Registry::{
        RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW, HKEY,
        HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_DWORD, REG_SZ, REG_VALUE_TYPE,
    };

    use super::{parse_cidr_prefix, parse_ip_addr, IpKind, NetOpsError};
    use crate::discovery::RawAdapterInfo;
    use crate::recovery::{InterfaceMetricSnapshot, RouteRecord, SystemProxySnapshot};

    const INTERNET_SETTINGS_SUBKEY: &str =
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings";

    struct MibTableGuard(*const c_void);

    impl Drop for MibTableGuard {
        fn drop(&mut self) {
            if !self.0.is_null() {
                unsafe { FreeMibTable(self.0) };
            }
        }
    }

    struct RegKeyGuard(HKEY);

    impl Drop for RegKeyGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() {
                unsafe {
                    let _ = RegCloseKey(self.0);
                }
            }
        }
    }

    pub(crate) fn win32_error_message(code: u32) -> String {
        HRESULT::from_win32(code).message()
    }

    fn err_from_win32(operation: &'static str, code: WIN32_ERROR) -> NetOpsError {
        NetOpsError::Win32 {
            operation,
            code: code.0,
            message: win32_error_message(code.0),
        }
    }

    pub(crate) fn to_wide_null(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Reads a null-terminated UTF-16 string pointer safely with an upper scan bound.
    pub(crate) unsafe fn pwstr_to_string(ptr: windows::core::PWSTR) -> String {
        if ptr.is_null() {
            return String::new();
        }
        const MAX_WSTR_LEN: usize = 4096;
        let mut len = 0usize;
        while len < MAX_WSTR_LEN && *ptr.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr.0, len);
        String::from_utf16_lossy(slice)
    }

    fn sockaddr_inet_from_ip(ip: IpKind) -> SOCKADDR_INET {
        match ip {
            IpKind::V4(octets) => {
                let mut addr = SOCKADDR_INET::default();
                addr.Ipv4 = SOCKADDR_IN {
                    sin_family: AF_INET,
                    sin_port: 0,
                    sin_addr: IN_ADDR {
                        S_un: IN_ADDR_0 {
                            S_un_b: IN_ADDR_0_0 {
                                s_b1: octets[0],
                                s_b2: octets[1],
                                s_b3: octets[2],
                                s_b4: octets[3],
                            },
                        },
                    },
                    sin_zero: [0; 8],
                };
                addr
            }
            IpKind::V6(octets) => {
                let mut addr = SOCKADDR_INET::default();
                addr.Ipv6 = SOCKADDR_IN6 {
                    sin6_family: AF_INET6,
                    sin6_port: 0,
                    sin6_flowinfo: 0,
                    sin6_addr: IN6_ADDR {
                        u: IN6_ADDR_0 { Byte: octets },
                    },
                    ..Default::default()
                };
                addr
            }
        }
    }

    fn ipv4_from_in_addr(in_addr: IN_ADDR) -> Ipv4Addr {
        let b = unsafe { in_addr.S_un.S_un_b };
        Ipv4Addr::new(b.s_b1, b.s_b2, b.s_b3, b.s_b4)
    }

    fn format_sockaddr_inet(addr: &SOCKADDR_INET, is_ipv6: bool) -> String {
        let family = unsafe { addr.si_family };
        if family == AF_INET {
            let v4 = unsafe { ipv4_from_in_addr(addr.Ipv4.sin_addr) };
            v4.to_string()
        } else if family == AF_INET6 {
            let v6 = unsafe { Ipv6Addr::from(addr.Ipv6.sin6_addr.u.Byte) };
            v6.to_string()
        } else if is_ipv6 {
            "::".to_string()
        } else {
            "0.0.0.0".to_string()
        }
    }

    fn row_to_route_record(row: &MIB_IPFORWARD_ROW2, is_ipv6: bool) -> RouteRecord {
        let prefix_addr = format_sockaddr_inet(&row.DestinationPrefix.Prefix, is_ipv6);
        let destination_prefix = format!("{prefix_addr}/{}", row.DestinationPrefix.PrefixLength);
        let next_hop = format_sockaddr_inet(&row.NextHop, is_ipv6);
        RouteRecord {
            interface_index: row.InterfaceIndex,
            destination_prefix,
            next_hop,
            route_metric: row.Metric,
            is_ipv6,
        }
    }

    fn build_forward_row(route: &RouteRecord) -> Result<MIB_IPFORWARD_ROW2, NetOpsError> {
        let (dest_ip, prefix_len) =
            parse_cidr_prefix(&route.destination_prefix, route.is_ipv6)?;
        let next_hop_ip = parse_ip_addr(&route.next_hop, route.is_ipv6)?;

        let mut row = MIB_IPFORWARD_ROW2::default();
        unsafe { InitializeIpForwardEntry(&mut row) };

        row.InterfaceIndex = route.interface_index;
        let mut luid = NET_LUID_LH::default();
        let luid_status = unsafe { ConvertInterfaceIndexToLuid(route.interface_index, &mut luid) };
        if luid_status == NO_ERROR {
            row.InterfaceLuid = luid;
        }

        row.DestinationPrefix.Prefix = sockaddr_inet_from_ip(dest_ip);
        row.DestinationPrefix.PrefixLength = prefix_len;
        row.NextHop = sockaddr_inet_from_ip(next_hop_ip);
        row.Metric = route.route_metric;
        Ok(row)
    }

    fn get_forward_table(
        family: ADDRESS_FAMILY,
    ) -> Result<(MibTableGuard, *const MIB_IPFORWARD_TABLE2), NetOpsError> {
        let mut table_ptr: *mut MIB_IPFORWARD_TABLE2 = ptr::null_mut();
        let status = unsafe { GetIpForwardTable2(family, &mut table_ptr) };
        if status != NO_ERROR {
            return Err(err_from_win32("GetIpForwardTable2", status));
        }
        if table_ptr.is_null() {
            return Err(NetOpsError::Win32 {
                operation: "GetIpForwardTable2",
                code: 0,
                message: "returned null route table pointer".to_string(),
            });
        }
        Ok((
            MibTableGuard(table_ptr.cast::<c_void>()),
            table_ptr.cast_const(),
        ))
    }

    pub(crate) fn list_routes(
        interface_index: Option<u32>,
        is_ipv6: bool,
    ) -> Result<Vec<RouteRecord>, NetOpsError> {
        let family = if is_ipv6 { AF_INET6 } else { AF_INET };
        let (_guard, table_ptr) = get_forward_table(family)?;
        let count = unsafe { (*table_ptr).NumEntries as usize };
        let rows = unsafe { std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), count) };

        let mut out = Vec::new();
        for row in rows {
            if let Some(target_idx) = interface_index {
                if row.InterfaceIndex != target_idx {
                    continue;
                }
            }
            out.push(row_to_route_record(row, is_ipv6));
        }
        Ok(out)
    }

    pub(crate) fn add_route(route: &RouteRecord) -> Result<(), NetOpsError> {
        let row = build_forward_row(route)?;
        let status = unsafe { CreateIpForwardEntry2(&row) };
        if status != NO_ERROR {
            return Err(err_from_win32("CreateIpForwardEntry2", status));
        }
        Ok(())
    }

    pub(crate) fn remove_route(route: &RouteRecord) -> Result<(), NetOpsError> {
        let family = if route.is_ipv6 { AF_INET6 } else { AF_INET };
        let (dest_ip, prefix_len) =
            parse_cidr_prefix(&route.destination_prefix, route.is_ipv6)?;
        let next_hop_ip = parse_ip_addr(&route.next_hop, route.is_ipv6)?;
        let canonical_prefix = format!(
            "{}/{}",
            match dest_ip {
                IpKind::V4(o) => Ipv4Addr::from(o).to_string(),
                IpKind::V6(o) => Ipv6Addr::from(o).to_string(),
            },
            prefix_len
        );
        let canonical_next_hop = match next_hop_ip {
            IpKind::V4(o) => Ipv4Addr::from(o).to_string(),
            IpKind::V6(o) => Ipv6Addr::from(o).to_string(),
        };

        let matched_row = {
            let (_guard, table_ptr) = get_forward_table(family)?;
            let count = unsafe { (*table_ptr).NumEntries as usize };
            let rows = unsafe { std::slice::from_raw_parts((*table_ptr).Table.as_ptr(), count) };
            rows.iter()
                .find(|row| {
                    if row.InterfaceIndex != route.interface_index {
                        return false;
                    }
                    let rec = row_to_route_record(row, route.is_ipv6);
                    rec.destination_prefix == canonical_prefix && rec.next_hop == canonical_next_hop
                })
                .copied()
        };

        let target_row = match matched_row {
            Some(row) => row,
            None => build_forward_row(route)?,
        };

        let status = unsafe { DeleteIpForwardEntry2(&target_row) };
        if status == ERROR_NOT_FOUND {
            return Err(NetOpsError::RouteNotFound {
                interface_index: route.interface_index,
                prefix: route.destination_prefix.clone(),
                next_hop: route.next_hop.clone(),
            });
        }
        if status != NO_ERROR {
            return Err(err_from_win32("DeleteIpForwardEntry2", status));
        }
        Ok(())
    }

    pub(crate) fn get_interface_metric(
        interface_index: u32,
        is_ipv6: bool,
    ) -> Result<InterfaceMetricSnapshot, NetOpsError> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = if is_ipv6 { AF_INET6 } else { AF_INET };
        row.InterfaceIndex = interface_index;

        let status = unsafe { GetIpInterfaceEntry(&mut row) };
        if status != NO_ERROR {
            return Err(err_from_win32("GetIpInterfaceEntry", status));
        }
        Ok(InterfaceMetricSnapshot {
            interface_index,
            is_ipv6,
            original_metric: row.Metric,
            automatic_metric: row.UseAutomaticMetric.as_bool(),
        })
    }

    pub(crate) fn set_interface_metric(
        interface_index: u32,
        is_ipv6: bool,
        metric: u32,
        automatic_metric: bool,
    ) -> Result<(), NetOpsError> {
        let mut row = MIB_IPINTERFACE_ROW::default();
        unsafe { InitializeIpInterfaceEntry(&mut row) };
        row.Family = if is_ipv6 { AF_INET6 } else { AF_INET };
        row.InterfaceIndex = interface_index;

        let get_status = unsafe { GetIpInterfaceEntry(&mut row) };
        if get_status != NO_ERROR {
            return Err(err_from_win32("GetIpInterfaceEntry", get_status));
        }

        // Win32 SetIpInterfaceEntry rejects non-zero SitePrefixLength for IPv4.
        if !is_ipv6 {
            row.SitePrefixLength = 0;
        }
        row.UseAutomaticMetric = BOOLEAN::from(automatic_metric);
        row.Metric = if automatic_metric { 0 } else { metric };

        let set_status = unsafe { SetIpInterfaceEntry(&mut row) };
        if set_status != NO_ERROR {
            return Err(err_from_win32("SetIpInterfaceEntry", set_status));
        }
        Ok(())
    }

    pub(crate) fn find_best_route_interface(
        dest_ipv4: &str,
    ) -> Result<Option<String>, NetOpsError> {
        let ip = parse_ip_addr(dest_ipv4, false)?;
        let dest_sockaddr = sockaddr_inet_from_ip(ip);
        let mut best_route = MIB_IPFORWARD_ROW2::default();
        let mut best_source = SOCKADDR_INET::default();

        let status = unsafe {
            GetBestRoute2(
                None,
                0,
                None,
                &dest_sockaddr,
                0,
                &mut best_route,
                &mut best_source,
            )
        };
        if status == ERROR_NOT_FOUND || status == ERROR_NETWORK_UNREACHABLE {
            return Ok(None);
        }
        if status != NO_ERROR {
            return Err(err_from_win32("GetBestRoute2", status));
        }

        let mut alias_buf = [0u16; 257];
        let alias_status =
            unsafe { ConvertInterfaceLuidToAlias(&best_route.InterfaceLuid, &mut alias_buf) };
        if alias_status != NO_ERROR {
            return Err(err_from_win32("ConvertInterfaceLuidToAlias", alias_status));
        }

        let end = alias_buf
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(alias_buf.len());
        let alias = String::from_utf16_lossy(&alias_buf[..end]);
        Ok(Some(alias))
    }

    unsafe fn extract_ipv4_from_socket_address(lp_sockaddr: *const SOCKADDR) -> Option<Ipv4Addr> {
        if lp_sockaddr.is_null() {
            return None;
        }
        if (*lp_sockaddr).sa_family != AF_INET {
            return None;
        }
        let sockaddr_in = &*(lp_sockaddr.cast::<SOCKADDR_IN>());
        Some(ipv4_from_in_addr(sockaddr_in.sin_addr))
    }

    pub(crate) fn enumerate_adapters() -> Result<Vec<RawAdapterInfo>, NetOpsError> {
        const ERROR_NO_DATA_CODE: u32 = 232;
        let mut buf_len: u32 = 16 * 1024;
        // Use u64 backing storage so the buffer satisfies 8-byte alignment for IP_ADAPTER_ADDRESSES_LH.
        let mut aligned_buf: Vec<u64> = vec![0; (buf_len as usize).div_ceil(8)];
        let mut succeeded = false;

        for _attempt in 0..6 {
            let status = unsafe {
                GetAdaptersAddresses(
                    AF_UNSPEC.0 as u32,
                    GAA_FLAG_INCLUDE_GATEWAYS,
                    None,
                    Some(aligned_buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>()),
                    &mut buf_len,
                )
            };

            if status == NO_ERROR.0 {
                succeeded = true;
                break;
            }
            if status == ERROR_NO_DATA_CODE {
                return Ok(Vec::new());
            }
            if status == ERROR_BUFFER_OVERFLOW.0 {
                aligned_buf.resize((buf_len as usize).div_ceil(8), 0);
                continue;
            }
            return Err(err_from_win32("GetAdaptersAddresses", WIN32_ERROR(status)));
        }

        if !succeeded {
            return Err(err_from_win32("GetAdaptersAddresses", ERROR_BUFFER_OVERFLOW));
        }
        if (buf_len as usize) < std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>() {
            return Ok(Vec::new());
        }

        let mut adapters = Vec::new();
        let mut cur: *const IP_ADAPTER_ADDRESSES_LH =
            aligned_buf.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();

        while !cur.is_null() {
            let adapter = unsafe { &*cur };
            let if_index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
            let alias = unsafe { pwstr_to_string(adapter.FriendlyName) };
            let description = unsafe { pwstr_to_string(adapter.Description) };
            let is_up = adapter.OperStatus == IfOperStatusUp;

            let mut primary_ipv4: Option<String> = None;
            let mut fallback_ipv4: Option<String> = None;
            let mut ua = adapter.FirstUnicastAddress.cast_const();
            while !ua.is_null() {
                let ua_ref = unsafe { &*ua };
                if let Some(ip) =
                    unsafe { extract_ipv4_from_socket_address(ua_ref.Address.lpSockaddr) }
                {
                    if !ip.is_loopback() && !ip.is_unspecified() {
                        if !ip.is_link_local() && primary_ipv4.is_none() {
                            primary_ipv4 = Some(ip.to_string());
                        } else if fallback_ipv4.is_none() {
                            fallback_ipv4 = Some(ip.to_string());
                        }
                    }
                }
                ua = ua_ref.Next.cast_const();
            }

            let mut gateway_ipv4: Option<String> = None;
            let mut gw = adapter.FirstGatewayAddress.cast_const();
            while !gw.is_null() {
                let gw_ref = unsafe { &*gw };
                if let Some(ip) =
                    unsafe { extract_ipv4_from_socket_address(gw_ref.Address.lpSockaddr) }
                {
                    if !ip.is_unspecified() {
                        gateway_ipv4 = Some(ip.to_string());
                        break;
                    }
                }
                gw = gw_ref.Next.cast_const();
            }

            let link_speed_bps = if adapter.TransmitLinkSpeed != 0
                && adapter.TransmitLinkSpeed != u64::MAX
            {
                adapter.TransmitLinkSpeed
            } else {
                adapter.ReceiveLinkSpeed
            };

            adapters.push(RawAdapterInfo {
                alias,
                description,
                if_index,
                if_type: adapter.IfType,
                is_up,
                ipv4: primary_ipv4.or(fallback_ipv4),
                gateway_ipv4,
                link_speed_bps,
                ipv4_metric: adapter.Ipv4Metric,
            });

            cur = adapter.Next.cast_const();
        }

        Ok(adapters)
    }

    fn open_internet_settings_key(access: windows::Win32::System::Registry::REG_SAM_FLAGS) -> Result<RegKeyGuard, NetOpsError> {
        let subkey = to_wide_null(INTERNET_SETTINGS_SUBKEY);
        let mut hkey = HKEY::default();
        let status = unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                PCWSTR(subkey.as_ptr()),
                0,
                access,
                &mut hkey,
            )
        };
        if status != NO_ERROR {
            return Err(err_from_win32("RegOpenKeyExW", status));
        }
        Ok(RegKeyGuard(hkey))
    }

    fn reg_read_dword(hkey: HKEY, name: &str) -> Result<Option<u32>, NetOpsError> {
        let wide_name = to_wide_null(name);
        let mut val_type = REG_VALUE_TYPE::default();
        let mut data = [0u8; 4];
        let mut data_len = data.len() as u32;
        let status = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut val_type),
                Some(data.as_mut_ptr()),
                Some(&mut data_len),
            )
        };
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != NO_ERROR {
            return Err(err_from_win32("RegQueryValueExW", status));
        }
        if val_type != REG_DWORD || data_len != 4 {
            return Ok(None);
        }
        Ok(Some(u32::from_le_bytes(data)))
    }

    fn reg_read_string(hkey: HKEY, name: &str) -> Result<Option<String>, NetOpsError> {
        let wide_name = to_wide_null(name);
        let mut val_type = REG_VALUE_TYPE::default();
        let mut byte_len: u32 = 0;

        let probe_status = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut val_type),
                None,
                Some(&mut byte_len),
            )
        };
        if probe_status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if probe_status != NO_ERROR {
            return Err(err_from_win32("RegQueryValueExW", probe_status));
        }
        if byte_len == 0 || val_type != REG_SZ {
            return Ok(None);
        }

        let mut buf: Vec<u16> = vec![0; (byte_len as usize).div_ceil(2)];
        let mut read_len = (buf.len() * 2) as u32;
        let read_status = unsafe {
            RegQueryValueExW(
                hkey,
                PCWSTR(wide_name.as_ptr()),
                None,
                Some(&mut val_type),
                Some(buf.as_mut_ptr().cast::<u8>()),
                Some(&mut read_len),
            )
        };
        if read_status != NO_ERROR {
            return Err(err_from_win32("RegQueryValueExW", read_status));
        }

        let u16_count = (read_len as usize / 2).min(buf.len());
        let trimmed = &buf[..u16_count];
        let end = trimmed
            .iter()
            .position(|&ch| ch == 0)
            .unwrap_or(trimmed.len());
        Ok(Some(String::from_utf16_lossy(&trimmed[..end])))
    }

    fn reg_write_dword(hkey: HKEY, name: &str, value: u32) -> Result<(), NetOpsError> {
        let wide_name = to_wide_null(name);
        let bytes = value.to_le_bytes();
        let status = unsafe {
            RegSetValueExW(
                hkey,
                PCWSTR(wide_name.as_ptr()),
                0,
                REG_DWORD,
                Some(&bytes),
            )
        };
        if status != NO_ERROR {
            return Err(err_from_win32("RegSetValueExW", status));
        }
        Ok(())
    }

    fn reg_write_or_delete_string(
        hkey: HKEY,
        name: &str,
        value: Option<&str>,
    ) -> Result<(), NetOpsError> {
        let wide_name = to_wide_null(name);
        match value {
            Some(s) => {
                let wide_val = to_wide_null(s);
                let byte_slice = unsafe {
                    std::slice::from_raw_parts(
                        wide_val.as_ptr().cast::<u8>(),
                        wide_val.len() * std::mem::size_of::<u16>(),
                    )
                };
                let status = unsafe {
                    RegSetValueExW(
                        hkey,
                        PCWSTR(wide_name.as_ptr()),
                        0,
                        REG_SZ,
                        Some(byte_slice),
                    )
                };
                if status != NO_ERROR {
                    return Err(err_from_win32("RegSetValueExW", status));
                }
            }
            None => {
                let status = unsafe { RegDeleteValueW(hkey, PCWSTR(wide_name.as_ptr())) };
                if status != NO_ERROR && status != ERROR_FILE_NOT_FOUND {
                    return Err(err_from_win32("RegDeleteValueW", status));
                }
            }
        }
        Ok(())
    }

    fn broadcast_wininet_proxy_refresh() -> Result<(), NetOpsError> {
        unsafe {
            InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0).map_err(|e| {
                NetOpsError::Win32 {
                    operation: "InternetSetOptionW(SETTINGS_CHANGED)",
                    code: e.code().0 as u32,
                    message: e.message(),
                }
            })?;
            InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0).map_err(|e| {
                NetOpsError::Win32 {
                    operation: "InternetSetOptionW(REFRESH)",
                    code: e.code().0 as u32,
                    message: e.message(),
                }
            })?;
        }
        Ok(())
    }

    pub(crate) fn get_system_proxy() -> Result<SystemProxySnapshot, NetOpsError> {
        let key = open_internet_settings_key(KEY_READ)?;
        let proxy_enable = reg_read_dword(key.0, "ProxyEnable")?.unwrap_or(0);
        let proxy_server = reg_read_string(key.0, "ProxyServer")?;
        let proxy_override = reg_read_string(key.0, "ProxyOverride")?;
        Ok(SystemProxySnapshot {
            proxy_enable,
            proxy_server,
            proxy_override,
        })
    }

    pub(crate) fn set_system_proxy(snapshot: &SystemProxySnapshot) -> Result<(), NetOpsError> {
        let key = open_internet_settings_key(KEY_WRITE)?;
        reg_write_dword(key.0, "ProxyEnable", snapshot.proxy_enable)?;
        reg_write_or_delete_string(key.0, "ProxyServer", snapshot.proxy_server.as_deref())?;
        reg_write_or_delete_string(key.0, "ProxyOverride", snapshot.proxy_override.as_deref())?;
        broadcast_wininet_proxy_refresh()
    }

    pub(crate) fn disable_system_proxy() -> Result<(), NetOpsError> {
        let key = open_internet_settings_key(KEY_WRITE)?;
        reg_write_dword(key.0, "ProxyEnable", 0)?;
        broadcast_wininet_proxy_refresh()
    }
}

#[cfg(not(windows))]
pub(crate) mod platform {
    use super::NetOpsError;
    use crate::discovery::RawAdapterInfo;
    use crate::recovery::{InterfaceMetricSnapshot, RouteRecord, SystemProxySnapshot};

    pub(crate) fn list_routes(_: Option<u32>, _: bool) -> Result<Vec<RouteRecord>, NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn add_route(_: &RouteRecord) -> Result<(), NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn remove_route(_: &RouteRecord) -> Result<(), NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn get_interface_metric(
        _: u32,
        _: bool,
    ) -> Result<InterfaceMetricSnapshot, NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn set_interface_metric(
        _: u32,
        _: bool,
        _: u32,
        _: bool,
    ) -> Result<(), NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn find_best_route_interface(_: &str) -> Result<Option<String>, NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn enumerate_adapters() -> Result<Vec<RawAdapterInfo>, NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn get_system_proxy() -> Result<SystemProxySnapshot, NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn set_system_proxy(_: &SystemProxySnapshot) -> Result<(), NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }

    pub(crate) fn disable_system_proxy() -> Result<(), NetOpsError> {
        Err(NetOpsError::UnsupportedPlatform)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parses_ipv4_and_ipv6_cidr_prefixes_and_rejects_invalid() {
        assert_eq!(
            parse_cidr_prefix("0.0.0.0/1", false).expect("valid ipv4 /1"),
            (IpKind::V4([0, 0, 0, 0]), 1)
        );
        assert_eq!(
            parse_cidr_prefix("198.51.100.10/32", false).expect("valid ipv4 /32"),
            (IpKind::V4([198, 51, 100, 10]), 32)
        );
        assert_eq!(
            parse_cidr_prefix("8000::/1", true).expect("valid ipv6 /1"),
            (
                IpKind::V6([0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                1
            )
        );
        assert!(parse_cidr_prefix("0.0.0.0/33", false).is_err());
        assert!(parse_cidr_prefix("::/129", true).is_err());
        assert!(parse_cidr_prefix("10.0.0.0/8", true).is_err());
        assert!(parse_cidr_prefix("::/0", false).is_err());
        assert!(parse_cidr_prefix("invalid-prefix", false).is_err());
    }

    #[test]
    fn test_parses_warp_cli_settings_modes() {
        assert_eq!(
            parse_warp_cli_mode("Always On: true\nMode: Warp\n").as_deref(),
            Some("warp")
        );
        assert_eq!(
            parse_warp_cli_mode("Mode: WarpWithDnsOverHttps\n").as_deref(),
            Some("warp+doh")
        );
        assert_eq!(
            parse_warp_cli_mode("Operation Mode: Proxy\n").as_deref(),
            Some("proxy")
        );
        assert_eq!(
            parse_warp_cli_mode("Mode: DnsOverHttps\n").as_deref(),
            Some("doh")
        );
        assert_eq!(
            parse_warp_cli_mode("Mode: TunnelOnly\n").as_deref(),
            Some("tunnel_only")
        );
        assert_eq!(parse_warp_cli_mode("unrelated output\n"), None);
    }

    #[cfg(windows)]
    #[test]
    fn test_win32_network_ops_read_only_smoke() {
        let ops = Win32NetworkOps;
        let ipv4_routes = ops.list_routes(None, false).expect("list IPv4 routes");
        assert!(
            !ipv4_routes.is_empty(),
            "expected at least one IPv4 route on Windows"
        );
        let _ipv6_routes = ops.list_routes(None, true).expect("list IPv6 routes");

        let _proxy = ops.get_system_proxy().expect("read HKCU Internet Settings");

        let missing = ops
            .find_interface_index_by_alias("NetFlow-NonExistent-Adapter-99999")
            .expect("lookup missing alias");
        assert_eq!(missing, None);

        if let Some(best_alias) = ops
            .find_best_route_interface("1.1.1.1")
            .expect("find best route interface")
        {
            let best_idx = ops
                .find_interface_index_by_alias(&best_alias)
                .expect("lookup best route alias")
                .expect("best route alias should resolve to interface index");
            let metric = ops
                .get_interface_metric(best_idx, false)
                .expect("read best route interface metric");
            assert_eq!(metric.interface_index, best_idx);
            assert!(!metric.is_ipv6);
        }

        if let Some(first_route) = ipv4_routes.first() {
            let metric = ops
                .get_interface_metric(first_route.interface_index, false)
                .expect("read interface metric");
            assert_eq!(metric.interface_index, first_route.interface_index);
            assert!(!metric.is_ipv6);
        }
    }

    #[test]
    fn test_restore_interface_metric_delegates_both_metric_and_automatic_flag() {
        use std::sync::Mutex;

        struct RecordingOps(Mutex<Vec<(u32, bool, u32, bool)>>);

        impl WindowsNetworkOps for RecordingOps {
            fn list_routes(&self, _: Option<u32>, _: bool) -> Result<Vec<RouteRecord>, NetOpsError> {
                Ok(Vec::new())
            }
            fn add_route(&self, _: &RouteRecord) -> Result<(), NetOpsError> {
                Ok(())
            }
            fn remove_route(&self, _: &RouteRecord) -> Result<(), NetOpsError> {
                Ok(())
            }
            fn get_interface_metric(&self, _: u32, _: bool) -> Result<InterfaceMetricSnapshot, NetOpsError> {
                Err(NetOpsError::UnsupportedPlatform)
            }
            fn set_interface_metric(
                &self,
                interface_index: u32,
                is_ipv6: bool,
                metric: u32,
                automatic_metric: bool,
            ) -> Result<(), NetOpsError> {
                self.0
                    .lock()
                    .unwrap()
                    .push((interface_index, is_ipv6, metric, automatic_metric));
                Ok(())
            }
            fn find_best_route_interface(&self, _: &str) -> Result<Option<String>, NetOpsError> {
                Ok(None)
            }
            fn find_interface_index_by_alias(&self, _: &str) -> Result<Option<u32>, NetOpsError> {
                Ok(None)
            }
            fn get_system_proxy(&self) -> Result<SystemProxySnapshot, NetOpsError> {
                Err(NetOpsError::UnsupportedPlatform)
            }
            fn set_system_proxy(&self, _: &SystemProxySnapshot) -> Result<(), NetOpsError> {
                Ok(())
            }
            fn disable_system_proxy(&self) -> Result<(), NetOpsError> {
                Ok(())
            }
            fn warp_cli_get_mode(&self) -> Result<Option<String>, NetOpsError> {
                Ok(None)
            }
            fn warp_cli_set_mode(&self, _: &str) -> Result<(), NetOpsError> {
                Ok(())
            }
        }

        let ops = RecordingOps(Mutex::new(Vec::new()));
        let snap = InterfaceMetricSnapshot {
            interface_index: 8,
            is_ipv6: false,
            original_metric: 40,
            automatic_metric: true,
        };
        ops.restore_interface_metric(&snap).expect("restore");
        assert_eq!(ops.0.lock().unwrap().as_slice(), &[(8, false, 40, true)]);
    }
}
