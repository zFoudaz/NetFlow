//! VPN provider adapters for pre-flight validation, route/metric neutralization,
//! OpenVPN DCO host-route pinning, and exact restoration.

use std::net::{Ipv4Addr, Ipv6Addr};

use thiserror::Error;

use crate::compiler::ResolvedVpnRuntimeInfo;
use crate::discovery::{DetectedVpnInfo, PhysicalInterfaceInfo};
use crate::model::{VpnNodeSettings, VpnProvider};
use crate::recovery::{RouteRecord, VpnRecoveryEntry};
use crate::win_net::{
    is_benign_remove_route_error, is_benign_restore_add_route_error,
    is_benign_restore_metric_error, NetOpsError, WindowsNetworkOps, ERROR_NOT_FOUND_CODE,
};

const NEUTRALIZED_METRIC: u32 = 500;

/// Typed errors returned by VPN adapter pre-flight, neutralization, pinning, and restoration.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VpnAdapterError {
    #[error("{0:?} is not running")]
    NotRunning(VpnProvider),
    #[error("provider mismatch: expected {expected:?}, got {actual:?}")]
    ProviderMismatch {
        expected: VpnProvider,
        actual: VpnProvider,
    },
    #[error("missing SOCKS5 port for Karing; enable Karing or configure a port override")]
    MissingKaringPort,
    #[error("missing SOCKS5 port for NekoRay; enable NekoRay or configure a port override")]
    MissingNekoRayPort,
    #[error("missing network interface index for {provider:?}")]
    MissingAdapterIfIndex { provider: VpnProvider },
    #[error("missing virtual adapter alias for OpenVPN")]
    MissingOpenVpnAdapterAlias,
    #[error("invalid OpenVPN server IPv4 address '{value}'")]
    InvalidOpenVpnServerIp { value: String },
    #[error("upstream physical interface '{alias}' (ifIndex {if_index}) has no IPv4 gateway")]
    MissingUpstreamGateway { alias: String, if_index: u32 },
    #[error("network operation failed: {0}")]
    NetOps(#[from] NetOpsError),
    #[error("multiple errors occurred while restoring VPN state: {summary}")]
    PartialRestore {
        summary: String,
        errors: Vec<NetOpsError>,
    },
}

/// Validates that a VPN provider is running and resolves its runtime parameters.
pub fn preflight_and_resolve_vpn(
    provider: VpnProvider,
    settings: &VpnNodeSettings,
    detected: &DetectedVpnInfo,
) -> Result<ResolvedVpnRuntimeInfo, VpnAdapterError> {
    if detected.provider != provider {
        return Err(VpnAdapterError::ProviderMismatch {
            expected: provider,
            actual: detected.provider,
        });
    }
    if !detected.is_running {
        return Err(VpnAdapterError::NotRunning(provider));
    }

    match provider {
        VpnProvider::Karing => {
            let port = settings
                .karing_port_override
                .filter(|&p| p != 0)
                .or_else(|| detected.detected_port.filter(|&p| p != 0))
                .ok_or(VpnAdapterError::MissingKaringPort)?;
            Ok(ResolvedVpnRuntimeInfo {
                provider: VpnProvider::Karing,
                karing_socks_port: Some(port),
                nekoray_socks_port: None,
                openvpn_adapter_alias: None,
                openvpn_server_ip: None,
            })
        }
        VpnProvider::NekoRay => {
            let port = settings
                .nekoray_port_override
                .filter(|&p| p != 0)
                .or_else(|| detected.detected_port.filter(|&p| p != 0))
                .ok_or(VpnAdapterError::MissingNekoRayPort)?;
            Ok(ResolvedVpnRuntimeInfo {
                provider: VpnProvider::NekoRay,
                karing_socks_port: None,
                nekoray_socks_port: Some(port),
                openvpn_adapter_alias: None,
                openvpn_server_ip: None,
            })
        }
        VpnProvider::OpenVpn => {
            if !detected.adapter_is_up {
                return Err(VpnAdapterError::NotRunning(VpnProvider::OpenVpn));
            }
            let alias = non_empty_trimmed(settings.openvpn_adapter_override.as_deref())
                .or_else(|| non_empty_trimmed(detected.adapter_alias.as_deref()))
                .ok_or(VpnAdapterError::MissingOpenVpnAdapterAlias)?;
            let server_ip = non_empty_trimmed(settings.openvpn_server_ip_override.as_deref())
                .or_else(|| non_empty_trimmed(detected.remote_server_ip.as_deref()))
                .map(|raw| validate_routable_ipv4(&raw).map(|ip| ip.to_string()))
                .transpose()?;
            Ok(ResolvedVpnRuntimeInfo {
                provider: VpnProvider::OpenVpn,
                karing_socks_port: None,
                nekoray_socks_port: None,
                openvpn_adapter_alias: Some(alias),
                openvpn_server_ip: server_ip,
            })
        }
    }
}

/// Neutralizes an active VPN provider's default/split routing hijack and captures a recovery entry.
pub fn neutralize_vpn(
    ops: &dyn WindowsNetworkOps,
    provider: VpnProvider,
    resolved: &ResolvedVpnRuntimeInfo,
    detected: &DetectedVpnInfo,
) -> Result<VpnRecoveryEntry, VpnAdapterError> {
    if resolved.provider != provider {
        return Err(VpnAdapterError::ProviderMismatch {
            expected: provider,
            actual: resolved.provider,
        });
    }
    if detected.provider != provider {
        return Err(VpnAdapterError::ProviderMismatch {
            expected: provider,
            actual: detected.provider,
        });
    }

    match provider {
        VpnProvider::Karing | VpnProvider::NekoRay => {
            let Some(if_index) = detected.adapter_if_index else {
                return Ok(empty_recovery_entry(provider));
            };
            neutralize_tun_adapter(
                ops,
                provider,
                if_index,
                detected.adapter_gateway.as_deref(),
                should_neutralize_split_or_default_route,
            )
        }
        VpnProvider::OpenVpn => {
            let if_index = resolve_adapter_if_index(
                ops,
                VpnProvider::OpenVpn,
                detected.adapter_if_index,
                resolved.openvpn_adapter_alias.as_deref(),
            )?;
            neutralize_tun_adapter(
                ops,
                VpnProvider::OpenVpn,
                if_index,
                detected.adapter_gateway.as_deref(),
                is_hijack_default_or_split_route,
            )
        }
    }
}

/// Restores a VPN provider's routes and interface metrics from a recovery entry.
///
/// Continues attempting all remaining restoration steps even if an individual step fails,
/// so partial failures do not skip restoring routes or metrics.
pub fn restore_vpn(
    ops: &dyn WindowsNetworkOps,
    entry: &VpnRecoveryEntry,
) -> Result<(), VpnAdapterError> {
    let mut errors: Vec<NetOpsError> = Vec::new();

    for route in &entry.added_routes {
        if let Err(err) = ops.remove_route(route) {
            if !is_benign_remove_route_error(ops, route.interface_index, &err) {
                errors.push(err);
            }
        }
    }

    for snapshot in &entry.metric_snapshots {
        if let Err(err) = ops.restore_interface_metric(snapshot) {
            if !is_benign_restore_metric_error(ops, snapshot.interface_index, &err) {
                errors.push(err);
            }
        }
    }

    for route in &entry.removed_routes {
        if let Err(err) = ops.add_route(route) {
            if !is_benign_restore_add_route_error(ops, route.interface_index, &err) {
                errors.push(err);
            }
        }
    }

    match errors.len() {
        0 => Ok(()),
        1 => Err(VpnAdapterError::NetOps(errors.remove(0))),
        _ => {
            let summary = errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ");
            Err(VpnAdapterError::PartialRestore { summary, errors })
        }
    }
}

/// Pins `<server_ip>/32` via the upstream physical interface gateway so OpenVPN DCO avoids loops.
///
/// Returns `Ok(None)` when a matching `<server_ip>/32` route via `upstream_if`'s gateway already
/// exists on `upstream_if.if_index`, so NetFlow never duplicates or later deletes OpenVPN's route.
pub fn pin_openvpn_dco_host_route(
    ops: &dyn WindowsNetworkOps,
    server_ip: &str,
    upstream_if: &PhysicalInterfaceInfo,
) -> Result<Option<RouteRecord>, VpnAdapterError> {
    let ip = validate_routable_ipv4(server_ip)?;
    let gateway = non_empty_trimmed(upstream_if.gateway_ipv4.as_deref())
        .and_then(|gw| parse_usable_ipv4_gateway(&gw))
        .ok_or_else(|| VpnAdapterError::MissingUpstreamGateway {
            alias: upstream_if.alias.clone(),
            if_index: upstream_if.if_index,
        })?;

    let target_prefix = format!("{ip}/32");
    let existing = ops.list_routes(Some(upstream_if.if_index), false)?;
    if existing.iter().any(|r| {
        !r.is_ipv6
            && r.interface_index == upstream_if.if_index
            && canonical_prefix(r).as_deref() == Some(target_prefix.as_str())
            && r.next_hop.trim().parse::<Ipv4Addr>().ok() == Some(gateway)
    }) {
        return Ok(None);
    }

    let route = RouteRecord {
        interface_index: upstream_if.if_index,
        destination_prefix: target_prefix,
        next_hop: gateway.to_string(),
        route_metric: 0,
        is_ipv6: false,
    };
    ops.add_route(&route)?;
    Ok(Some(route))
}

fn empty_recovery_entry(provider: VpnProvider) -> VpnRecoveryEntry {
    VpnRecoveryEntry {
        provider,
        removed_routes: Vec::new(),
        added_routes: Vec::new(),
        metric_snapshots: Vec::new(),
    }
}

fn non_empty_trimmed(value: Option<&str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
}

fn validate_routable_ipv4(raw: &str) -> Result<Ipv4Addr, VpnAdapterError> {
    let trimmed = raw.trim();
    let ip: Ipv4Addr = trimmed
        .parse()
        .map_err(|_| VpnAdapterError::InvalidOpenVpnServerIp {
            value: raw.to_string(),
        })?;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
        return Err(VpnAdapterError::InvalidOpenVpnServerIp {
            value: raw.to_string(),
        });
    }
    Ok(ip)
}

fn parse_usable_ipv4_gateway(raw: &str) -> Option<Ipv4Addr> {
    let ip: Ipv4Addr = raw.trim().parse().ok()?;
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() || ip.is_broadcast() {
        return None;
    }
    Some(ip)
}

fn resolve_adapter_if_index(
    ops: &dyn WindowsNetworkOps,
    provider: VpnProvider,
    detected_if_index: Option<u32>,
    alias: Option<&str>,
) -> Result<u32, VpnAdapterError> {
    if let Some(if_index) = detected_if_index {
        return Ok(if_index);
    }
    if let Some(alias) = alias.map(str::trim).filter(|a| !a.is_empty()) {
        if let Some(if_index) = ops.find_interface_index_by_alias(alias)? {
            return Ok(if_index);
        }
    }
    Err(VpnAdapterError::MissingAdapterIfIndex { provider })
}

fn neutralize_tun_adapter(
    ops: &dyn WindowsNetworkOps,
    provider: VpnProvider,
    if_index: u32,
    detected_gateway: Option<&str>,
    route_predicate: fn(&RouteRecord) -> bool,
) -> Result<VpnRecoveryEntry, VpnAdapterError> {
    let mut entry = empty_recovery_entry(provider);
    if let Err(err) = apply_tun_neutralization(
        ops,
        if_index,
        detected_gateway,
        route_predicate,
        &mut entry,
    ) {
        // Best-effort rollback of any partial mutations made before the failure.
        let _ = restore_vpn(ops, &entry);
        return Err(err);
    }
    Ok(entry)
}

fn apply_tun_neutralization(
    ops: &dyn WindowsNetworkOps,
    if_index: u32,
    detected_gateway: Option<&str>,
    route_predicate: fn(&RouteRecord) -> bool,
    entry: &mut VpnRecoveryEntry,
) -> Result<(), VpnAdapterError> {
    let v4_routes = ops.list_routes(Some(if_index), false)?;
    let v6_routes = ops.list_routes(Some(if_index), true)?;

    let routes_to_remove: Vec<RouteRecord> = v4_routes
        .into_iter()
        .chain(v6_routes)
        .filter(route_predicate)
        .collect();

    let v4_metric = ops.get_interface_metric(if_index, false)?;
    entry.metric_snapshots.push(v4_metric);

    match ops.get_interface_metric(if_index, true) {
        Ok(v6_metric) => entry.metric_snapshots.push(v6_metric),
        Err(NetOpsError::Win32 {
            code: ERROR_NOT_FOUND_CODE,
            ..
        }) => {}
        Err(err) => return Err(err.into()),
    }

    for route in routes_to_remove {
        ops.remove_route(&route)?;
        entry.removed_routes.push(route);
    }

    for snap in &entry.metric_snapshots {
        ops.set_interface_metric(
            snap.interface_index,
            snap.is_ipv6,
            NEUTRALIZED_METRIC,
            false,
        )?;
    }

    let fallback_gateway = select_fallback_gateway(detected_gateway, &entry.removed_routes);
    let fallback_route = RouteRecord {
        interface_index: if_index,
        destination_prefix: "0.0.0.0/0".to_string(),
        next_hop: fallback_gateway,
        route_metric: NEUTRALIZED_METRIC,
        is_ipv6: false,
    };
    ops.add_route(&fallback_route)?;
    entry.added_routes.push(fallback_route);

    Ok(())
}

fn select_fallback_gateway(detected_gateway: Option<&str>, removed_routes: &[RouteRecord]) -> String {
    if let Some(gw) = detected_gateway.and_then(parse_usable_ipv4_gateway) {
        return gw.to_string();
    }

    let mut best: Option<(u8, u32, String)> = None;
    for route in removed_routes {
        if route.is_ipv6 {
            continue;
        }
        let Some(gw) = parse_usable_ipv4_gateway(&route.next_hop) else {
            continue;
        };
        let priority = match canonical_prefix(route).as_deref() {
            Some("0.0.0.0/0") => 0u8,
            Some("0.0.0.0/1") | Some("128.0.0.0/1") => 1u8,
            _ => 2u8,
        };
        let candidate = (priority, route.route_metric, gw.to_string());
        let replace = match &best {
            None => true,
            Some(cur) => (candidate.0, candidate.1) < (cur.0, cur.1),
        };
        if replace {
            best = Some(candidate);
        }
    }

    best.map(|(_, _, gw)| gw)
        .unwrap_or_else(|| "0.0.0.0".to_string())
}

fn is_ipv6_link_local(ip: Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

fn canonical_prefix(route: &RouteRecord) -> Option<String> {
    let (ip_str, len_str) = route.destination_prefix.trim().split_once('/')?;
    let len: u8 = len_str.parse().ok()?;
    if route.is_ipv6 {
        let ip: Ipv6Addr = ip_str.parse().ok()?;
        Some(format!("{ip}/{len}"))
    } else {
        let ip: Ipv4Addr = ip_str.parse().ok()?;
        Some(format!("{ip}/{len}"))
    }
}

fn is_hijack_default_or_split_route(route: &RouteRecord) -> bool {
    let Some(prefix) = canonical_prefix(route) else {
        return false;
    };
    if route.is_ipv6 {
        matches!(prefix.as_str(), "::/0" | "::/1" | "8000::/1")
    } else {
        matches!(prefix.as_str(), "0.0.0.0/0" | "0.0.0.0/1" | "128.0.0.0/1")
    }
}

fn should_neutralize_split_or_default_route(route: &RouteRecord) -> bool {
    if is_hijack_default_or_split_route(route) {
        return true;
    }

    let Some((ip_str, _)) = route.destination_prefix.trim().split_once('/') else {
        return false;
    };

    if route.is_ipv6 {
        let Ok(dest_ip) = ip_str.parse::<Ipv6Addr>() else {
            return false;
        };
        if dest_ip.is_multicast()
            || dest_ip.is_loopback()
            || is_ipv6_link_local(dest_ip)
            || dest_ip.is_unspecified()
        {
            return false;
        }
        let Ok(next_hop) = route.next_hop.trim().parse::<Ipv6Addr>() else {
            return false;
        };
        !next_hop.is_unspecified() && !next_hop.is_loopback()
    } else {
        let Ok(dest_ip) = ip_str.parse::<Ipv4Addr>() else {
            return false;
        };
        if dest_ip.is_broadcast()
            || dest_ip.is_multicast()
            || dest_ip.is_loopback()
            || dest_ip.is_link_local()
            || dest_ip.is_unspecified()
        {
            return false;
        }
        parse_usable_ipv4_gateway(&route.next_hop).is_some()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;

    use super::*;
    use crate::recovery::{InterfaceMetricSnapshot, SystemProxySnapshot};

    #[derive(Debug, Default)]
    struct MockState {
        routes: Vec<RouteRecord>,
        metrics: HashMap<(u32, bool), InterfaceMetricSnapshot>,
        alias_to_if_index: HashMap<String, u32>,
        fail_remove_prefix: Option<String>,
        vanished_interfaces: HashSet<u32>,
        vanished_error_code: Option<u32>,
        add_route_calls: Vec<RouteRecord>,
    }

    #[derive(Debug, Default)]
    struct MockNetworkOps {
        state: Mutex<MockState>,
    }

    impl MockNetworkOps {
        fn new() -> Self {
            Self::default()
        }

        fn with_routes(routes: Vec<RouteRecord>) -> Self {
            let ops = Self::new();
            ops.state.lock().unwrap().routes = routes;
            ops
        }

        fn set_metric(&self, if_index: u32, is_ipv6: bool, metric: u32, automatic_metric: bool) {
            self.state.lock().unwrap().metrics.insert(
                (if_index, is_ipv6),
                InterfaceMetricSnapshot {
                    interface_index: if_index,
                    is_ipv6,
                    original_metric: metric,
                    automatic_metric,
                },
            );
        }

        fn set_alias(&self, alias: &str, if_index: u32) {
            self.state
                .lock()
                .unwrap()
                .alias_to_if_index
                .insert(alias.to_ascii_lowercase(), if_index);
        }

        fn set_fail_remove_prefix(&self, prefix: Option<&str>) {
            self.state.lock().unwrap().fail_remove_prefix = prefix.map(ToString::to_string);
        }

        fn mark_interface_vanished(&self, if_index: u32, error_code: u32) {
            let mut guard = self.state.lock().unwrap();
            guard.vanished_interfaces.insert(if_index);
            guard.vanished_error_code = Some(error_code);
            guard.routes.retain(|r| r.interface_index != if_index);
            guard.metrics.remove(&(if_index, false));
            guard.metrics.remove(&(if_index, true));
        }

        fn add_route_calls(&self) -> Vec<RouteRecord> {
            self.state.lock().unwrap().add_route_calls.clone()
        }

        fn routes_for(&self, if_index: u32, is_ipv6: bool) -> Vec<RouteRecord> {
            self.state
                .lock()
                .unwrap()
                .routes
                .iter()
                .filter(|r| r.interface_index == if_index && r.is_ipv6 == is_ipv6)
                .cloned()
                .collect()
        }

        fn all_routes(&self) -> Vec<RouteRecord> {
            self.state.lock().unwrap().routes.clone()
        }

        fn metric_for(&self, if_index: u32, is_ipv6: bool) -> InterfaceMetricSnapshot {
            self.state
                .lock()
                .unwrap()
                .metrics
                .get(&(if_index, is_ipv6))
                .cloned()
                .expect("metric exists")
        }
    }

    impl WindowsNetworkOps for MockNetworkOps {
        fn list_routes(
            &self,
            interface_index: Option<u32>,
            is_ipv6: bool,
        ) -> Result<Vec<RouteRecord>, NetOpsError> {
            let guard = self.state.lock().unwrap();
            Ok(guard
                .routes
                .iter()
                .filter(|r| {
                    r.is_ipv6 == is_ipv6
                        && interface_index.is_none_or(|idx| r.interface_index == idx)
                })
                .cloned()
                .collect())
        }

        fn add_route(&self, route: &RouteRecord) -> Result<(), NetOpsError> {
            let mut guard = self.state.lock().unwrap();
            guard.add_route_calls.push(route.clone());
            if guard.vanished_interfaces.contains(&route.interface_index) {
                let code = guard.vanished_error_code.unwrap_or(1168);
                return Err(NetOpsError::Win32 {
                    operation: "CreateIpForwardEntry2",
                    code,
                    message: "Vanished interface.".to_string(),
                });
            }
            if guard.routes.iter().any(|r| {
                r.interface_index == route.interface_index
                    && r.destination_prefix == route.destination_prefix
                    && r.next_hop == route.next_hop
                    && r.is_ipv6 == route.is_ipv6
            }) {
                return Err(NetOpsError::Win32 {
                    operation: "CreateIpForwardEntry2",
                    code: 5010,
                    message: "The object already exists.".to_string(),
                });
            }
            guard.routes.push(route.clone());
            Ok(())
        }

        fn remove_route(&self, route: &RouteRecord) -> Result<(), NetOpsError> {
            let mut guard = self.state.lock().unwrap();
            if guard.fail_remove_prefix.as_deref() == Some(route.destination_prefix.as_str()) {
                return Err(NetOpsError::Win32 {
                    operation: "DeleteIpForwardEntry2",
                    code: 5,
                    message: "Access is denied.".to_string(),
                });
            }
            if guard.vanished_interfaces.contains(&route.interface_index) {
                let code = guard.vanished_error_code.unwrap_or(1168);
                return Err(NetOpsError::Win32 {
                    operation: "DeleteIpForwardEntry2",
                    code,
                    message: "Vanished interface.".to_string(),
                });
            }
            let pos = guard.routes.iter().position(|r| {
                r.interface_index == route.interface_index
                    && r.destination_prefix == route.destination_prefix
                    && r.next_hop == route.next_hop
                    && r.is_ipv6 == route.is_ipv6
            });
            match pos {
                Some(idx) => {
                    guard.routes.remove(idx);
                    Ok(())
                }
                None => Err(NetOpsError::RouteNotFound {
                    interface_index: route.interface_index,
                    prefix: route.destination_prefix.clone(),
                    next_hop: route.next_hop.clone(),
                }),
            }
        }

        fn get_interface_metric(
            &self,
            interface_index: u32,
            is_ipv6: bool,
        ) -> Result<InterfaceMetricSnapshot, NetOpsError> {
            let guard = self.state.lock().unwrap();
            guard
                .metrics
                .get(&(interface_index, is_ipv6))
                .cloned()
                .ok_or_else(|| NetOpsError::Win32 {
                    operation: "GetIpInterfaceEntry",
                    code: 1168,
                    message: "Element not found.".to_string(),
                })
        }

        fn set_interface_metric(
            &self,
            interface_index: u32,
            is_ipv6: bool,
            metric: u32,
            automatic_metric: bool,
        ) -> Result<(), NetOpsError> {
            let mut guard = self.state.lock().unwrap();
            if guard.vanished_interfaces.contains(&interface_index) {
                let code = guard.vanished_error_code.unwrap_or(1168);
                return Err(NetOpsError::Win32 {
                    operation: "SetIpInterfaceEntry",
                    code,
                    message: "Vanished interface.".to_string(),
                });
            }
            guard.metrics.insert(
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
            let guard = self.state.lock().unwrap();
            Ok(!guard.vanished_interfaces.contains(&interface_index))
        }

        fn find_best_route_interface(&self, _dest_ipv4: &str) -> Result<Option<String>, NetOpsError> {
            Ok(None)
        }

        fn find_interface_index_by_alias(&self, alias: &str) -> Result<Option<u32>, NetOpsError> {
            let guard = self.state.lock().unwrap();
            Ok(guard
                .alias_to_if_index
                .get(&alias.trim().to_ascii_lowercase())
                .copied())
        }

        fn get_system_proxy(&self) -> Result<SystemProxySnapshot, NetOpsError> {
            Ok(SystemProxySnapshot {
                proxy_enable: 0,
                proxy_server: None,
                proxy_override: None,
            })
        }

        fn set_system_proxy(&self, _snapshot: &SystemProxySnapshot) -> Result<(), NetOpsError> {
            Ok(())
        }

        fn disable_system_proxy(&self) -> Result<(), NetOpsError> {
            Ok(())
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

    #[test]
    fn test_karing_neutralize_and_restore_replaces_split_routes_with_metric_500() {
        let karing_if = 21;
        let mut initial_routes = Vec::new();

        // 24 IPv4 split routes + 6 IPv6 split routes = 30 split routes
        for i in 1..=24u8 {
            initial_routes.push(route(
                karing_if,
                &format!("{}.0.0.0/8", i * 4),
                "10.20.0.2",
                5,
                false,
            ));
        }
        for i in 1..=6u16 {
            initial_routes.push(route(
                karing_if,
                &format!("200{:x}::/16", i),
                "fdfe:dcba:9876::2",
                5,
                true,
            ));
        }

        // Local / on-link / broadcast / multicast routes on Karing TUN that MUST be preserved
        let preserved_routes = vec![
            route(karing_if, "10.20.0.0/30", "0.0.0.0", 256, false),
            route(karing_if, "10.20.0.1/32", "0.0.0.0", 256, false),
            route(karing_if, "224.0.0.0/4", "0.0.0.0", 256, false),
            route(karing_if, "255.255.255.255/32", "0.0.0.0", 256, false),
            route(karing_if, "fe80::/64", "::", 256, true),
            route(karing_if, "ff00::/8", "::", 256, true),
        ];
        initial_routes.extend(preserved_routes);

        let ops = MockNetworkOps::with_routes(initial_routes.clone());
        ops.set_metric(karing_if, false, 5, false);
        ops.set_metric(karing_if, true, 10, true);

        let detected = DetectedVpnInfo {
            provider: VpnProvider::Karing,
            is_running: true,
            detected_port: Some(3067),
            adapter_alias: Some("Karing TUN".to_string()),
            adapter_if_index: Some(karing_if),
            adapter_is_up: true,
            adapter_gateway: Some("10.20.0.2".to_string()),
            remote_server_ip: None,
        };
        let settings = VpnNodeSettings::default();
        let resolved = preflight_and_resolve_vpn(VpnProvider::Karing, &settings, &detected)
            .expect("preflight karing");
        assert_eq!(resolved.karing_socks_port, Some(3067));

        let recovery = neutralize_vpn(&ops, VpnProvider::Karing, &resolved, &detected)
            .expect("neutralize karing");

        assert_eq!(recovery.provider, VpnProvider::Karing);
        assert_eq!(recovery.removed_routes.len(), 30);
        assert_eq!(
            recovery.added_routes,
            vec![route(karing_if, "0.0.0.0/0", "10.20.0.2", 500, false)]
        );
        assert_eq!(recovery.metric_snapshots.len(), 2);

        // Metric set to 500 manual for both IPv4 and IPv6
        let v4_metric = ops.metric_for(karing_if, false);
        assert_eq!(v4_metric.original_metric, 500);
        assert!(!v4_metric.automatic_metric);
        let v6_metric = ops.metric_for(karing_if, true);
        assert_eq!(v6_metric.original_metric, 500);
        assert!(!v6_metric.automatic_metric);

        // Only preserved routes + single 0.0.0.0/0 metric-500 fallback remain
        let remaining_v4 = ops.routes_for(karing_if, false);
        assert_eq!(remaining_v4.len(), 5);
        assert!(remaining_v4.contains(&route(karing_if, "0.0.0.0/0", "10.20.0.2", 500, false)));
        let remaining_v6 = ops.routes_for(karing_if, true);
        assert_eq!(remaining_v6.len(), 2);

        // Restore must remove fallback route, restore original metrics, and re-add all 30 routes
        restore_vpn(&ops, &recovery).expect("restore karing");

        assert_eq!(ops.metric_for(karing_if, false).original_metric, 5);
        assert!(!ops.metric_for(karing_if, false).automatic_metric);
        assert_eq!(ops.metric_for(karing_if, true).original_metric, 10);
        assert!(ops.metric_for(karing_if, true).automatic_metric);

        let restored_all = ops.all_routes();
        assert_eq!(restored_all.len(), initial_routes.len());
        for expected in &initial_routes {
            assert!(
                restored_all.contains(expected),
                "missing restored route: {expected:?}"
            );
        }
    }

    #[test]
    fn test_openvpn_neutralizes_hijack_routes_and_pins_dco_host_route() {
        let ovpn_if = 44;
        let phys_if = 7;
        let initial_routes = vec![
            route(ovpn_if, "0.0.0.0/0", "0.0.0.0", 5, false),
            route(ovpn_if, "0.0.0.0/1", "10.8.0.1", 5, false),
            route(ovpn_if, "128.0.0.0/1", "10.8.0.1", 5, false),
            route(ovpn_if, "::/0", "::", 5, true),
            route(ovpn_if, "::/1", "fe80::1", 5, true),
            route(ovpn_if, "8000::/1", "fe80::1", 5, true),
            // Local subnet route on OpenVPN adapter must remain intact
            route(ovpn_if, "10.8.0.0/24", "0.0.0.0", 256, false),
        ];

        let ops = MockNetworkOps::with_routes(initial_routes.clone());
        ops.set_metric(ovpn_if, false, 3, false);
        ops.set_metric(ovpn_if, true, 3, false);
        ops.set_alias("OpenVPN Data Channel Offload", ovpn_if);

        let detected = DetectedVpnInfo {
            provider: VpnProvider::OpenVpn,
            is_running: true,
            detected_port: None,
            adapter_alias: Some("OpenVPN Data Channel Offload".to_string()),
            adapter_if_index: Some(ovpn_if),
            adapter_is_up: true,
            adapter_gateway: None,
            remote_server_ip: Some("203.0.113.45".to_string()),
        };
        let settings = VpnNodeSettings::default();
        let resolved = preflight_and_resolve_vpn(VpnProvider::OpenVpn, &settings, &detected)
            .expect("preflight openvpn");
        assert_eq!(
            resolved.openvpn_adapter_alias.as_deref(),
            Some("OpenVPN Data Channel Offload")
        );
        assert_eq!(resolved.openvpn_server_ip.as_deref(), Some("203.0.113.45"));

        let entry = neutralize_vpn(&ops, VpnProvider::OpenVpn, &resolved, &detected)
            .expect("neutralize openvpn");
        assert_eq!(entry.removed_routes.len(), 6);
        assert_eq!(
            entry.added_routes,
            vec![route(ovpn_if, "0.0.0.0/0", "10.8.0.1", 500, false)]
        );
        assert_eq!(ops.metric_for(ovpn_if, false).original_metric, 500);
        assert_eq!(ops.metric_for(ovpn_if, true).original_metric, 500);

        let remaining_v4 = ops.routes_for(ovpn_if, false);
        assert_eq!(remaining_v4.len(), 2);
        assert!(remaining_v4.contains(&route(ovpn_if, "10.8.0.0/24", "0.0.0.0", 256, false)));
        assert!(remaining_v4.contains(&route(ovpn_if, "0.0.0.0/0", "10.8.0.1", 500, false)));
        assert!(ops.routes_for(ovpn_if, true).is_empty());

        // Pin DCO host route via upstream physical interface
        let upstream_if = PhysicalInterfaceInfo {
            alias: "Ethernet".to_string(),
            description: "Intel Gigabit".to_string(),
            if_index: phys_if,
            ipv4: Some("192.168.1.50".to_string()),
            gateway_ipv4: Some("192.168.1.1".to_string()),
            is_up: true,
            link_speed_mbps: 1000,
            is_default_gateway: true,
        };
        let pinned = pin_openvpn_dco_host_route(
            &ops,
            resolved.openvpn_server_ip.as_deref().unwrap(),
            &upstream_if,
        )
        .expect("pin DCO /32 host route")
        .expect("new pinned route returned");
        assert_eq!(
            pinned,
            RouteRecord {
                interface_index: phys_if,
                destination_prefix: "203.0.113.45/32".to_string(),
                next_hop: "192.168.1.1".to_string(),
                route_metric: 0,
                is_ipv6: false,
            }
        );
        assert!(ops.routes_for(phys_if, false).contains(&pinned));

        restore_vpn(&ops, &entry).expect("restore openvpn");
        assert_eq!(ops.metric_for(ovpn_if, false).original_metric, 3);
        let restored_ovpn: Vec<_> = ops
            .all_routes()
            .into_iter()
            .filter(|r| r.interface_index == ovpn_if)
            .collect();
        assert_eq!(restored_ovpn.len(), initial_routes.len());
    }

    #[test]
    fn test_preflight_fails_with_clear_error_when_vpn_stopped() {
        let detected = DetectedVpnInfo {
            provider: VpnProvider::Karing,
            is_running: false,
            detected_port: None,
            adapter_alias: None,
            adapter_if_index: None,
            adapter_is_up: false,
            adapter_gateway: None,
            remote_server_ip: None,
        };
        let err = preflight_and_resolve_vpn(
            VpnProvider::Karing,
            &VpnNodeSettings::default(),
            &detected,
        )
        .expect_err("stopped VPN should fail preflight");
        assert_eq!(err, VpnAdapterError::NotRunning(VpnProvider::Karing));
        assert!(err.to_string().contains("not running"));
    }

    #[test]
    fn test_preflight_respects_overrides_and_validates_inputs() {
        let karing_detected = DetectedVpnInfo {
            provider: VpnProvider::Karing,
            is_running: true,
            detected_port: Some(3067),
            adapter_alias: None,
            adapter_if_index: None,
            adapter_is_up: false,
            adapter_gateway: None,
            remote_server_ip: None,
        };
        let karing_settings = VpnNodeSettings {
            karing_port_override: Some(7890),
            ..Default::default()
        };
        let resolved_karing =
            preflight_and_resolve_vpn(VpnProvider::Karing, &karing_settings, &karing_detected)
                .expect("karing override");
        assert_eq!(resolved_karing.karing_socks_port, Some(7890));

        // Karing without TUN adapter neutralizes cleanly to empty entry
        let ops = MockNetworkOps::new();
        let entry = neutralize_vpn(&ops, VpnProvider::Karing, &resolved_karing, &karing_detected)
            .expect("karing socks-only neutralize");
        assert!(entry.removed_routes.is_empty());
        assert!(entry.added_routes.is_empty());

        // NekoRay with TUN adapter neutralizes hijack routes and restores them cleanly
        let neko_if = 31;
        let neko_ops = MockNetworkOps::with_routes(vec![
            route(neko_if, "0.0.0.0/0", "172.19.0.2", 0, false),
            route(neko_if, "172.19.0.0/28", "0.0.0.0", 256, false),
        ]);
        neko_ops.set_metric(neko_if, false, 5, false);
        let neko_detected = DetectedVpnInfo {
            provider: VpnProvider::NekoRay,
            is_running: true,
            detected_port: Some(2080),
            adapter_alias: Some("nekoray-tun".to_string()),
            adapter_if_index: Some(neko_if),
            adapter_is_up: true,
            adapter_gateway: Some("172.19.0.2".to_string()),
            remote_server_ip: None,
        };
        let neko_settings = VpnNodeSettings {
            nekoray_port_override: Some(2090),
            ..Default::default()
        };
        let resolved_neko =
            preflight_and_resolve_vpn(VpnProvider::NekoRay, &neko_settings, &neko_detected)
                .expect("nekoray override");
        assert_eq!(resolved_neko.nekoray_socks_port, Some(2090));
        let neko_recovery = neutralize_vpn(&neko_ops, VpnProvider::NekoRay, &resolved_neko, &neko_detected)
            .expect("nekoray tun neutralize");
        assert_eq!(neko_recovery.provider, VpnProvider::NekoRay);
        assert_eq!(neko_recovery.removed_routes.len(), 1);
        assert_eq!(neko_ops.metric_for(neko_if, false).original_metric, 500);
        restore_vpn(&neko_ops, &neko_recovery).expect("nekoray restore");
        assert_eq!(neko_ops.metric_for(neko_if, false).original_metric, 5);

        // OpenVPN overrides
        let ovpn_detected = DetectedVpnInfo {
            provider: VpnProvider::OpenVpn,
            is_running: true,
            detected_port: None,
            adapter_alias: Some("Detected OVPN".to_string()),
            adapter_if_index: None,
            adapter_is_up: true,
            adapter_gateway: None,
            remote_server_ip: Some("198.51.100.10".to_string()),
        };
        let ovpn_settings = VpnNodeSettings {
            openvpn_adapter_override: Some("Custom OVPN".to_string()),
            openvpn_server_ip_override: Some("203.0.113.99".to_string()),
            ..Default::default()
        };
        let resolved_ovpn =
            preflight_and_resolve_vpn(VpnProvider::OpenVpn, &ovpn_settings, &ovpn_detected)
                .expect("openvpn overrides");
        assert_eq!(
            resolved_ovpn.openvpn_adapter_alias.as_deref(),
            Some("Custom OVPN")
        );
        assert_eq!(
            resolved_ovpn.openvpn_server_ip.as_deref(),
            Some("203.0.113.99")
        );

        // Invalid OpenVPN server IP fails preflight & pinning
        let bad_ovpn = VpnNodeSettings {
            openvpn_server_ip_override: Some("not-an-ip".to_string()),
            ..Default::default()
        };
        assert!(matches!(
            preflight_and_resolve_vpn(VpnProvider::OpenVpn, &bad_ovpn, &ovpn_detected),
            Err(VpnAdapterError::InvalidOpenVpnServerIp { .. })
        ));
    }

    #[test]
    fn test_restore_vpn_continues_remaining_steps_when_one_step_fails() {
        let if_idx = 55;
        let ops = MockNetworkOps::with_routes(vec![route(if_idx, "0.0.0.0/0", "10.9.0.1", 500, false)]);
        ops.set_metric(if_idx, false, 500, false);
        ops.set_fail_remove_prefix(Some("0.0.0.0/0"));

        let entry = VpnRecoveryEntry {
            provider: VpnProvider::OpenVpn,
            removed_routes: vec![route(if_idx, "0.0.0.0/1", "10.9.0.1", 5, false)],
            added_routes: vec![route(if_idx, "0.0.0.0/0", "10.9.0.1", 500, false)],
            metric_snapshots: vec![InterfaceMetricSnapshot {
                interface_index: if_idx,
                is_ipv6: false,
                original_metric: 12,
                automatic_metric: false,
            }],
        };

        let err = restore_vpn(&ops, &entry).expect_err("remove_route failure is reported");
        assert!(matches!(err, VpnAdapterError::NetOps(_)));

        // Even though removing the added route failed, metric and removed_routes were restored!
        assert_eq!(ops.metric_for(if_idx, false).original_metric, 12);
        assert!(ops
            .routes_for(if_idx, false)
            .contains(&route(if_idx, "0.0.0.0/1", "10.9.0.1", 5, false)));
    }

    #[test]
    fn test_pin_openvpn_dco_host_route_validates_gateway_and_server_ip() {
        let ops = MockNetworkOps::new();
        let no_gw = PhysicalInterfaceInfo {
            alias: "Wi-Fi".to_string(),
            description: "Wi-Fi".to_string(),
            if_index: 9,
            ipv4: Some("192.168.1.20".to_string()),
            gateway_ipv4: None,
            is_up: true,
            link_speed_mbps: 866,
            is_default_gateway: true,
        };

        assert!(matches!(
            pin_openvpn_dco_host_route(&ops, "198.51.100.1", &no_gw),
            Err(VpnAdapterError::MissingUpstreamGateway { if_index: 9, .. })
        ));
        assert!(matches!(
            pin_openvpn_dco_host_route(&ops, "127.0.0.1", &no_gw),
            Err(VpnAdapterError::InvalidOpenVpnServerIp { .. })
        ));
    }

    #[test]
    fn test_openvpn_on_link_wintun_falls_back_to_unspecified_next_hop() {
        let ovpn_if = 48;
        let ops = MockNetworkOps::with_routes(vec![
            route(ovpn_if, "0.0.0.0/1", "0.0.0.0", 5, false),
            route(ovpn_if, "128.0.0.0/1", "0.0.0.0", 5, false),
        ]);
        ops.set_metric(ovpn_if, false, 1, false);

        let detected = DetectedVpnInfo {
            provider: VpnProvider::OpenVpn,
            is_running: true,
            detected_port: None,
            adapter_alias: Some("OpenVPN Wintun".to_string()),
            adapter_if_index: Some(ovpn_if),
            adapter_is_up: true,
            adapter_gateway: None,
            remote_server_ip: None,
        };
        let resolved = preflight_and_resolve_vpn(
            VpnProvider::OpenVpn,
            &VpnNodeSettings::default(),
            &detected,
        )
        .expect("preflight");
        let entry = neutralize_vpn(&ops, VpnProvider::OpenVpn, &resolved, &detected)
            .expect("neutralize on-link wintun");
        assert_eq!(
            entry.added_routes,
            vec![route(ovpn_if, "0.0.0.0/0", "0.0.0.0", 500, false)]
        );
    }

    #[test]
    fn test_pin_openvpn_dco_host_route_skips_preexisting_host_route() {
        let phys_if = 7;
        let existing_route = route(phys_if, "203.0.113.45/32", "192.168.1.1", 5, false);
        let ops = MockNetworkOps::with_routes(vec![existing_route.clone()]);
        let upstream_if = PhysicalInterfaceInfo {
            alias: "Wi-Fi".to_string(),
            description: "Wi-Fi".to_string(),
            if_index: phys_if,
            ipv4: Some("192.168.1.50".to_string()),
            gateway_ipv4: Some("192.168.1.1".to_string()),
            is_up: true,
            link_speed_mbps: 866,
            is_default_gateway: true,
        };

        let result = pin_openvpn_dco_host_route(&ops, "203.0.113.45", &upstream_if)
            .expect("preexisting route should succeed");
        assert_eq!(result, None);
        assert!(
            ops.add_route_calls().is_empty(),
            "add_route must NOT be called when matching /32 route already exists"
        );
        assert_eq!(ops.routes_for(phys_if, false), vec![existing_route]);
    }

    #[test]
    fn test_restore_vpn_tolerates_vanished_adapter_and_already_exists_but_reports_access_denied() {
        // Vanished TUN adapter with ERROR_NOT_FOUND (1168) or ERROR_INVALID_PARAMETER (87)
        for code in [1168u32, 2u32, 87u32] {
            let vanished_if = 77;
            let ops = MockNetworkOps::new();
            ops.mark_interface_vanished(vanished_if, code);
            let entry = VpnRecoveryEntry {
                provider: VpnProvider::OpenVpn,
                removed_routes: vec![route(vanished_if, "0.0.0.0/1", "10.8.0.1", 5, false)],
                added_routes: vec![route(vanished_if, "0.0.0.0/0", "10.8.0.1", 500, false)],
                metric_snapshots: vec![InterfaceMetricSnapshot {
                    interface_index: vanished_if,
                    is_ipv6: false,
                    original_metric: 10,
                    automatic_metric: false,
                }],
            };
            restore_vpn(&ops, &entry).expect("vanished ephemeral TUN adapter must restore cleanly");
        }

        // Pre-existing removed_routes on live interface (ERROR_OBJECT_ALREADY_EXISTS = 5010)
        let live_if = 33;
        let existing_route = route(live_if, "0.0.0.0/1", "10.8.0.1", 5, false);
        let ops_existing = MockNetworkOps::with_routes(vec![existing_route.clone()]);
        ops_existing.set_metric(live_if, false, 500, false);
        let entry_existing = VpnRecoveryEntry {
            provider: VpnProvider::OpenVpn,
            removed_routes: vec![existing_route],
            added_routes: Vec::new(),
            metric_snapshots: vec![InterfaceMetricSnapshot {
                interface_index: live_if,
                is_ipv6: false,
                original_metric: 5,
                automatic_metric: false,
            }],
        };
        restore_vpn(&ops_existing, &entry_existing).expect("5010 already exists is tolerated");
        assert_eq!(ops_existing.metric_for(live_if, false).original_metric, 5);

        // Real error (Access Denied / 5) on an existing interface is NEVER swallowed
        let ops_denied = MockNetworkOps::with_routes(vec![route(live_if, "0.0.0.0/0", "10.8.0.1", 500, false)]);
        ops_denied.set_fail_remove_prefix(Some("0.0.0.0/0"));
        let entry_denied = VpnRecoveryEntry {
            provider: VpnProvider::OpenVpn,
            removed_routes: Vec::new(),
            added_routes: vec![route(live_if, "0.0.0.0/0", "10.8.0.1", 500, false)],
            metric_snapshots: Vec::new(),
        };
        let err = restore_vpn(&ops_denied, &entry_denied).expect_err("Access Denied must be reported");
        assert!(matches!(
            err,
            VpnAdapterError::NetOps(NetOpsError::Win32 { code: 5, .. })
        ));
    }

    #[test]
    fn test_preflight_rejects_disconnected_always_on_openvpn_when_adapter_down() {
        let ovpn_down = DetectedVpnInfo {
            provider: VpnProvider::OpenVpn,
            is_running: true, // simulates always-on ovpnconnector.exe running
            detected_port: None,
            adapter_alias: Some("OpenVPN Data Channel Offload".to_string()),
            adapter_if_index: Some(30),
            adapter_is_up: false,
            adapter_gateway: None,
            remote_server_ip: None,
        };
        assert_eq!(
            preflight_and_resolve_vpn(VpnProvider::OpenVpn, &VpnNodeSettings::default(), &ovpn_down),
            Err(VpnAdapterError::NotRunning(VpnProvider::OpenVpn))
        );
    }
}
