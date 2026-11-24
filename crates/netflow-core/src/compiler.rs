use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::net::Ipv4Addr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use thiserror::Error;

use crate::model::{NodeKind, ValidatedGraph, ValidatedVpnChain, VpnProvider};
use crate::validator::canonicalize_exe_name as canonicalize_validator_exe_name;

const TUN_TAG: &str = "NetFlow-TUN";
const TUN_INET4_ADDR: &str = "172.19.0.1/30";
const TUN_INET6_ADDR: &str = "fdfe:dcba:9876::1/126";
const FAKEIP_INET4_RANGE: &str = "198.18.0.0/15";
const DNS_BOOTSTRAP_SERVER: &str = "1.1.1.1";
const DNS_DEFAULT_TAG: &str = "dns-default";
const DNS_FAKEIP_TAG: &str = "dns-fakeip";
const LOCAL_DIRECT_TAG: &str = "direct";
const DEFAULT_DIRECT_TAG: &str = "default-direct";

const PRIVATE_LAN_CIDRS: [&str; 7] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
];

/// Resolved runtime parameters for an active VPN node, obtained from discovery/settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResolvedVpnRuntimeInfo {
    pub provider: VpnProvider,
    pub karing_socks_port: Option<u16>,
    pub openvpn_adapter_alias: Option<String>,
    pub openvpn_server_ip: Option<String>,
}

/// Complete input required to compile a validated NetFlow graph into a `sing-box` v1.14+ config.
#[derive(Debug, Clone, PartialEq)]
pub struct CompileInput {
    pub validated: ValidatedGraph,
    pub default_physical_interface: String,
    pub vpn_runtime: HashMap<VpnProvider, ResolvedVpnRuntimeInfo>,
    pub clash_api_port: u16,
    pub log_path: PathBuf,
}

/// Compiled `sing-box` JSON configuration paired with outbound-to-node ID metadata for Live Traffic.
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledConfig {
    pub json: Value,
    pub outbound_to_node_id: HashMap<String, String>,
}

/// Typed errors returned when a validated graph or runtime snapshot cannot produce a safe `sing-box` config.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CompileError {
    #[error("default physical interface alias cannot be empty")]
    MissingDefaultPhysicalInterface,
    #[error("clash API port must be non-zero")]
    InvalidClashApiPort,
    #[error("missing runtime info for active VPN provider {provider:?}")]
    MissingVpnRuntime { provider: VpnProvider },
    #[error("missing SOCKS5 port for Karing")]
    MissingKaringPort,
    #[error("missing virtual adapter alias for OpenVPN")]
    MissingOpenVpnAdapterAlias,
    #[error("invalid OpenVPN server IPv4 address '{value}'")]
    InvalidOpenVpnServerIp { value: String },
    #[error("validated graph references unknown or non-routable node '{node_id}'")]
    UnknownNodeReference { node_id: String },
    #[error("invalid executable name '{raw}'")]
    InvalidAppName { raw: String },
}

struct InterfaceOutbound {
    alias: String,
    outbound_tag: String,
    dns_tag: String,
}

enum VpnOutboundKind {
    Socks {
        port: u16,
    },
    TunDirect {
        adapter_alias: String,
        dns_tag: String,
    },
}

struct ResolvedVpnOutbound {
    chain: ValidatedVpnChain,
    outbound_tag: String,
    kind: VpnOutboundKind,
    chained_dco_cidr: Option<String>,
}

/// Compiles a `ValidatedGraph` and resolved VPN runtime details into a `sing-box` v1.14+ JSON config.
pub fn compile_singbox_config(input: &CompileInput) -> Result<CompiledConfig, CompileError> {
    let default_iface = input.default_physical_interface.trim();
    if default_iface.is_empty() {
        return Err(CompileError::MissingDefaultPhysicalInterface);
    }
    if input.clash_api_port == 0 {
        return Err(CompileError::InvalidClashApiPort);
    }

    let mut used_tags: HashSet<String> = [
        LOCAL_DIRECT_TAG.to_string(),
        DEFAULT_DIRECT_TAG.to_string(),
        TUN_TAG.to_string(),
    ]
    .into_iter()
    .collect();

    let mut node_to_outbound: HashMap<String, String> = HashMap::new();
    let mut outbound_to_node_id: HashMap<String, String> = HashMap::new();

    let interface_outbounds = build_interface_outbounds(
        &input.validated,
        &mut used_tags,
        &mut node_to_outbound,
        &mut outbound_to_node_id,
    )?;

    let vpn_outbounds = build_vpn_outbounds(
        &input.validated,
        &input.vpn_runtime,
        &mut used_tags,
        &mut node_to_outbound,
        &mut outbound_to_node_id,
    )?;

    let (final_outbound_tag, use_default_direct) = match &input.validated.default_node_id {
        Some(default_id) => {
            let tag = node_to_outbound.get(default_id).ok_or_else(|| {
                CompileError::UnknownNodeReference {
                    node_id: default_id.clone(),
                }
            })?;
            (tag.clone(), false)
        }
        None => (DEFAULT_DIRECT_TAG.to_string(), true),
    };

    let dns_final_tag =
        resolve_dns_final_tag(&final_outbound_tag, &interface_outbounds, &vpn_outbounds);

    let log_section = build_log_section(&input.log_path);
    let dns_section = build_dns_section(
        &input.validated,
        default_iface,
        &interface_outbounds,
        &vpn_outbounds,
        dns_final_tag,
    );
    let inbounds_section = build_inbounds_section();
    let outbounds_section = build_outbounds_section(
        default_iface,
        use_default_direct,
        &interface_outbounds,
        &vpn_outbounds,
    );
    let route_section = build_route_section(
        &input.validated,
        &node_to_outbound,
        &vpn_outbounds,
        &final_outbound_tag,
    )?;

    let cache_path = input.log_path.with_file_name("cache.db");
    let json = json!({
        "log": log_section,
        "dns": dns_section,
        "inbounds": inbounds_section,
        "outbounds": outbounds_section,
        "route": route_section,
        "experimental": {
            "clash_api": {
                "external_controller": format!("127.0.0.1:{}", input.clash_api_port)
            },
            "cache_file": {
                "enabled": true,
                "path": cache_path.to_string_lossy(),
                "store_fakeip": true
            }
        }
    });

    Ok(CompiledConfig {
        json,
        outbound_to_node_id,
    })
}

fn build_interface_outbounds(
    validated: &ValidatedGraph,
    used_tags: &mut HashSet<String>,
    node_to_outbound: &mut HashMap<String, String>,
    outbound_to_node_id: &mut HashMap<String, String>,
) -> Result<Vec<InterfaceOutbound>, CompileError> {
    let mut outbounds = Vec::with_capacity(validated.interface_node_ids.len());

    for node_id in &validated.interface_node_ids {
        let node = validated.nodes_by_id.get(node_id).ok_or_else(|| {
            CompileError::UnknownNodeReference {
                node_id: node_id.clone(),
            }
        })?;

        let NodeKind::Interface {
            interface_alias, ..
        } = &node.kind
        else {
            return Err(CompileError::UnknownNodeReference {
                node_id: node_id.clone(),
            });
        };

        let alias = interface_alias.trim();
        if alias.is_empty() {
            return Err(CompileError::UnknownNodeReference {
                node_id: node_id.clone(),
            });
        }

        let outbound_tag = unique_interface_tag(alias, used_tags);
        let dns_tag = format!("dns-{outbound_tag}");

        node_to_outbound.insert(node_id.clone(), outbound_tag.clone());
        outbound_to_node_id.insert(outbound_tag.clone(), node_id.clone());

        outbounds.push(InterfaceOutbound {
            alias: alias.to_string(),
            outbound_tag,
            dns_tag,
        });
    }

    Ok(outbounds)
}

fn build_vpn_outbounds(
    validated: &ValidatedGraph,
    vpn_runtime: &HashMap<VpnProvider, ResolvedVpnRuntimeInfo>,
    used_tags: &mut HashSet<String>,
    node_to_outbound: &mut HashMap<String, String>,
    outbound_to_node_id: &mut HashMap<String, String>,
) -> Result<Vec<ResolvedVpnOutbound>, CompileError> {
    let mut resolved = Vec::with_capacity(validated.vpn_chains.len());

    for chain in &validated.vpn_chains {
        let runtime = vpn_runtime
            .get(&chain.provider)
            .ok_or(CompileError::MissingVpnRuntime {
                provider: chain.provider,
            })?;

        let outbound_tag = vpn_outbound_tag(chain.provider).to_string();
        used_tags.insert(outbound_tag.clone());

        let (kind, chained_dco_cidr) = match chain.provider {
            VpnProvider::Karing => {
                let port = chain
                    .settings
                    .karing_port_override
                    .or(runtime.karing_socks_port)
                    .filter(|p| *p != 0)
                    .ok_or(CompileError::MissingKaringPort)?;
                (VpnOutboundKind::Socks { port }, None)
            }
            VpnProvider::OpenVpn => {
                let alias = non_empty_trimmed(chain.settings.openvpn_adapter_override.as_deref())
                    .or_else(|| non_empty_trimmed(runtime.openvpn_adapter_alias.as_deref()))
                    .ok_or(CompileError::MissingOpenVpnAdapterAlias)?;

                let upstream_is_vpn = validated.vpn_by_id.contains_key(&chain.upstream_node_id);
                let chained_dco_cidr = if upstream_is_vpn {
                    let server_ip =
                        non_empty_trimmed(chain.settings.openvpn_server_ip_override.as_deref())
                            .or_else(|| non_empty_trimmed(runtime.openvpn_server_ip.as_deref()));
                    server_ip
                        .map(|raw| normalize_ipv4_host_cidr(&raw))
                        .transpose()?
                } else {
                    None
                };

                (
                    VpnOutboundKind::TunDirect {
                        adapter_alias: alias,
                        dns_tag: format!("dns-{outbound_tag}"),
                    },
                    chained_dco_cidr,
                )
            }
        };

        node_to_outbound.insert(chain.node_id.clone(), outbound_tag.clone());
        outbound_to_node_id.insert(outbound_tag.clone(), chain.node_id.clone());

        resolved.push(ResolvedVpnOutbound {
            chain: chain.clone(),
            outbound_tag,
            kind,
            chained_dco_cidr,
        });
    }

    Ok(resolved)
}

fn build_log_section(log_path: &std::path::Path) -> Value {
    let mut map = Map::new();
    map.insert("level".to_string(), json!("info"));
    let path_str = log_path.to_string_lossy();
    if !path_str.trim().is_empty() {
        map.insert("output".to_string(), json!(path_str.as_ref()));
    }
    map.insert("timestamp".to_string(), json!(true));
    Value::Object(map)
}

fn resolve_dns_final_tag<'a>(
    final_outbound_tag: &str,
    interface_outbounds: &'a [InterfaceOutbound],
    vpn_outbounds: &'a [ResolvedVpnOutbound],
) -> &'a str {
    if let Some(iface) = interface_outbounds
        .iter()
        .find(|i| i.outbound_tag == final_outbound_tag)
    {
        return &iface.dns_tag;
    }
    if let Some(vpn) = vpn_outbounds
        .iter()
        .find(|v| v.outbound_tag == final_outbound_tag)
    {
        if let VpnOutboundKind::TunDirect { dns_tag, .. } = &vpn.kind {
            return dns_tag;
        }
    }
    DNS_DEFAULT_TAG
}

fn build_dns_section(
    validated: &ValidatedGraph,
    default_iface: &str,
    interface_outbounds: &[InterfaceOutbound],
    vpn_outbounds: &[ResolvedVpnOutbound],
    dns_final_tag: &str,
) -> Value {
    let mut servers = vec![json!({
        "type": "udp",
        "tag": DNS_DEFAULT_TAG,
        "server": DNS_BOOTSTRAP_SERVER,
        "bind_interface": default_iface
    })];

    for iface in interface_outbounds {
        servers.push(json!({
            "type": "udp",
            "tag": iface.dns_tag,
            "server": DNS_BOOTSTRAP_SERVER,
            "bind_interface": iface.alias
        }));
    }

    for vpn in vpn_outbounds {
        if let VpnOutboundKind::TunDirect {
            adapter_alias,
            dns_tag,
        } = &vpn.kind
        {
            servers.push(json!({
                "type": "udp",
                "tag": dns_tag,
                "server": DNS_BOOTSTRAP_SERVER,
                "bind_interface": adapter_alias
            }));
        }
    }

    servers.push(json!({
        "type": "fakeip",
        "tag": DNS_FAKEIP_TAG,
        "inet4_range": FAKEIP_INET4_RANGE
    }));

    let mut rules = vec![json!({
        "query_type": ["AAAA", "HTTPS", "SVCB"],
        "action": "predefined",
        "rcode": "NOERROR"
    })];

    // VPN daemon processes (Karing, OpenVPN) must receive real IPv4 DNS
    // answers bound to their root physical interface rather than FakeIPs,
    // otherwise their endpoint health checks and local SOCKS5 dials fail.
    for chain in &validated.vpn_chains {
        let real_dns_tag = interface_outbounds
            .iter()
            .find(|iface| iface.alias.eq_ignore_ascii_case(&chain.root_interface_alias))
            .map(|iface| iface.dns_tag.as_str())
            .unwrap_or(DNS_DEFAULT_TAG);
        rules.push(json!({
            "process_path_regex": exes_to_path_regexes(outer_tunnel_processes(chain.provider)),
            "action": "route",
            "server": real_dns_tag
        }));
    }

    rules.push(json!({
        "query_type": ["A"],
        "action": "route",
        "server": DNS_FAKEIP_TAG
    }));

    json!({
        "servers": servers,
        "rules": rules,
        "strategy": "ipv4_only",
        "final": dns_final_tag
    })
}

fn build_inbounds_section() -> Value {
    json!([
        {
            "type": "tun",
            "tag": TUN_TAG,
            "interface_name": TUN_TAG,
            "address": [TUN_INET4_ADDR, TUN_INET6_ADDR],
            "auto_route": true,
            "strict_route": true,
            "stack": "mixed"
        }
    ])
}

fn build_outbounds_section(
    default_iface: &str,
    use_default_direct: bool,
    interface_outbounds: &[InterfaceOutbound],
    vpn_outbounds: &[ResolvedVpnOutbound],
) -> Value {
    let mut outbounds = vec![json!({
        "type": "direct",
        "tag": LOCAL_DIRECT_TAG
    })];

    if use_default_direct {
        outbounds.push(json!({
            "type": "direct",
            "tag": DEFAULT_DIRECT_TAG,
            "bind_interface": default_iface,
            "domain_resolver": DNS_DEFAULT_TAG
        }));
    }

    for iface in interface_outbounds {
        outbounds.push(json!({
            "type": "direct",
            "tag": iface.outbound_tag,
            "bind_interface": iface.alias,
            "domain_resolver": iface.dns_tag
        }));
    }

    for vpn in vpn_outbounds {
        match &vpn.kind {
            VpnOutboundKind::Socks { port } => {
                outbounds.push(json!({
                    "type": "socks",
                    "tag": vpn.outbound_tag,
                    "server": "127.0.0.1",
                    "server_port": port,
                    "version": "5"
                }));
            }
            VpnOutboundKind::TunDirect {
                adapter_alias,
                dns_tag,
            } => {
                outbounds.push(json!({
                    "type": "direct",
                    "tag": vpn.outbound_tag,
                    "bind_interface": adapter_alias,
                    "domain_resolver": dns_tag
                }));
            }
        }
    }

    Value::Array(outbounds)
}

fn build_route_section(
    validated: &ValidatedGraph,
    node_to_outbound: &HashMap<String, String>,
    vpn_outbounds: &[ResolvedVpnOutbound],
    final_outbound_tag: &str,
) -> Result<Value, CompileError> {
    // 1. Sniff -> 2. DNS Hijack -> 3. IPv6 Reject -> 4. Private LAN Direct (excluding FakeIP)
    let mut rules = vec![
        json!({ "action": "sniff" }),
        json!({ "protocol": "dns", "action": "hijack-dns" }),
        json!({ "ip_version": 6, "action": "reject" }),
        json!({
            "ip_cidr": PRIVATE_LAN_CIDRS,
            "action": "route",
            "outbound": LOCAL_DIRECT_TAG
        }),
    ];

    // 5. VPN outer-tunnel rules in topological order (closest to root physical Interface first)
    for vpn in vpn_outbounds {
        let upstream_tag = node_to_outbound
            .get(&vpn.chain.upstream_node_id)
            .ok_or_else(|| CompileError::UnknownNodeReference {
                node_id: vpn.chain.upstream_node_id.clone(),
            })?;

        rules.push(json!({
            "process_path_regex": exes_to_path_regexes(outer_tunnel_processes(vpn.chain.provider)),
            "action": "route",
            "outbound": upstream_tag
        }));

        if let Some(cidr) = &vpn.chained_dco_cidr {
            rules.push(json!({
                "ip_cidr": [cidr],
                "action": "route",
                "outbound": upstream_tag
            }));
        }
    }

    // 6. Connected Apps rules grouped deterministically by target outbound tag
    let mut grouped_apps: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for assignment in validated.app_routes.values() {
        let target_tag = node_to_outbound
            .get(&assignment.target_node_id)
            .ok_or_else(|| CompileError::UnknownNodeReference {
                node_id: assignment.target_node_id.clone(),
            })?;
        let canonical_exe = canonicalize_exe_name(&assignment.exe_name)?;
        grouped_apps
            .entry(target_tag.clone())
            .or_default()
            .insert(canonical_exe);
    }

    for (target_tag, exe_set) in grouped_apps {
        let regexes: Vec<String> = exe_set
            .into_iter()
            .map(|exe| exe_to_case_insensitive_path_regex(&exe))
            .collect();
        rules.push(json!({
            "process_path_regex": regexes,
            "action": "route",
            "outbound": target_tag
        }));
    }

    Ok(json!({
        "auto_detect_interface": true,
        "default_domain_resolver": DNS_DEFAULT_TAG,
        "rules": rules,
        "final": final_outbound_tag
    }))
}

fn vpn_outbound_tag(provider: VpnProvider) -> &'static str {
    match provider {
        VpnProvider::Karing => "vpn-karing",
        VpnProvider::OpenVpn => "vpn-openvpn",
    }
}

fn outer_tunnel_processes(provider: VpnProvider) -> &'static [&'static str] {
    match provider {
        VpnProvider::Karing => &["karingservice.exe", "karing.exe"],
        VpnProvider::OpenVpn => &["openvpn.exe", "ovpnconnector.exe"],
    }
}

fn unique_interface_tag(alias: &str, used_tags: &mut HashSet<String>) -> String {
    let mut slug = String::with_capacity(alias.len());
    let mut prev_dash = false;
    for ch in alias.chars() {
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
        slug.push_str("node");
    }

    let base = format!("iface-{slug}");
    if used_tags.insert(base.clone()) {
        return base;
    }

    let mut suffix = 2usize;
    loop {
        let candidate = format!("{base}-{suffix}");
        if used_tags.insert(candidate.clone()) {
            return candidate;
        }
        suffix += 1;
    }
}

fn non_empty_trimmed(opt: Option<&str>) -> Option<String> {
    opt.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
}

fn normalize_ipv4_host_cidr(raw: &str) -> Result<String, CompileError> {
    let trimmed = raw.trim();
    let ip_part = trimmed.strip_suffix("/32").unwrap_or(trimmed);
    let ip: Ipv4Addr = ip_part
        .parse()
        .map_err(|_| CompileError::InvalidOpenVpnServerIp {
            value: raw.to_string(),
        })?;
    Ok(format!("{ip}/32"))
}

fn canonicalize_exe_name(raw: &str) -> Result<String, CompileError> {
    canonicalize_validator_exe_name(raw).ok_or_else(|| CompileError::InvalidAppName {
        raw: raw.to_string(),
    })
}

/// Converts a canonical lowercase executable name (e.g. `karingservice.exe` or `discord.exe`)
/// into a case-insensitive `sing-box` `process_path_regex` matching any Windows path ending in
/// that executable filename (`C:\Program Files\Karing\karingService.exe`, etc.).
fn exe_to_case_insensitive_path_regex(exe: &str) -> String {
    let mut escaped = String::with_capacity(exe.len() + 8);
    for ch in exe.chars() {
        match ch {
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                escaped.push('\\');
                escaped.push(ch);
            }
            _ => escaped.push(ch),
        }
    }
    format!(r"(?i)(^|[\\/]){escaped}$")
}

fn exes_to_path_regexes(exes: &[&str]) -> Vec<String> {
    exes.iter()
        .map(|exe| exe_to_case_insensitive_path_regex(exe))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AppRouteAssignment, NodeKind, VpnNodeSettings, WorkflowEdge, WorkflowGraph, WorkflowNode,
    };
    use crate::validator::validate_graph;

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

    fn vpn_node(id: &str, provider: VpnProvider, is_default: bool) -> WorkflowNode {
        WorkflowNode {
            id: id.to_string(),
            x: 0.0,
            y: 0.0,
            kind: NodeKind::Vpn {
                provider,
                is_default,
                settings: VpnNodeSettings::default(),
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

    fn karing_runtime(port: u16) -> ResolvedVpnRuntimeInfo {
        ResolvedVpnRuntimeInfo {
            provider: VpnProvider::Karing,
            karing_socks_port: Some(port),
            openvpn_adapter_alias: None,
            openvpn_server_ip: None,
        }
    }

    fn openvpn_runtime(alias: &str, server_ip: Option<&str>) -> ResolvedVpnRuntimeInfo {
        ResolvedVpnRuntimeInfo {
            provider: VpnProvider::OpenVpn,
            karing_socks_port: None,
            openvpn_adapter_alias: Some(alias.to_string()),
            openvpn_server_ip: server_ip.map(|s| s.to_string()),
        }
    }

    fn rule_has_process(rule: &serde_json::Value, exe: &str) -> bool {
        let expected_regex = exe_to_case_insensitive_path_regex(&exe.to_ascii_lowercase());
        rule.get("process_path_regex")
            .and_then(|v| v.as_array())
            .is_some_and(|arr| arr.iter().any(|item| item.as_str() == Some(expected_regex.as_str())))
    }

    #[test]
    fn test_compiles_direct_and_chained_vpn_rules_in_strict_order() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false),
                apps_node("apps-ovpn", &["chrome.exe"]),
                apps_node("apps-wifi", &["msedge.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-ovpn"),
                edge("e3", "vpn-ovpn", "apps-ovpn"),
                edge("e4", "if-wifi", "apps-wifi"),
            ],
        };

        let validated = validate_graph(&graph).expect("graph should validate");
        let mut vpn_runtime = HashMap::new();
        vpn_runtime.insert(VpnProvider::Karing, karing_runtime(3067));
        vpn_runtime.insert(
            VpnProvider::OpenVpn,
            openvpn_runtime("OpenVPN Wintun", None),
        );

        let compiled = compile_singbox_config(&CompileInput {
            validated,
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime,
            clash_api_port: 9090,
            log_path: PathBuf::from(r"C:\ProgramData\NetFlow\sing-box.log"),
        })
        .expect("compile should succeed");

        let json = &compiled.json;

        // TUN inbound check
        let inbound = &json["inbounds"][0];
        assert_eq!(inbound["type"], "tun");
        assert_eq!(inbound["tag"], "NetFlow-TUN");
        assert_eq!(inbound["interface_name"], "NetFlow-TUN");
        assert_eq!(
            inbound["address"],
            serde_json::json!(["172.19.0.1/30", "fdfe:dcba:9876::1/126"])
        );
        assert_eq!(inbound["auto_route"], true);
        assert_eq!(inbound["strict_route"], true);
        assert_eq!(inbound["stack"], "mixed");

        // DNS FakeIP + IPv4-only check
        assert_eq!(json["dns"]["strategy"], "ipv4_only");
        let dns_servers = json["dns"]["servers"]
            .as_array()
            .expect("dns servers array");
        assert!(dns_servers
            .iter()
            .any(|s| { s["type"] == "fakeip" && s["inet4_range"] == "198.18.0.0/15" }));
        assert!(dns_servers
            .iter()
            .any(|s| { s["type"] == "udp" && s["bind_interface"] == "Wi-Fi" }));
        assert!(json["route"]["default_domain_resolver"].as_str().is_some());

        // Clash API check
        assert_eq!(
            json["experimental"]["clash_api"]["external_controller"],
            "127.0.0.1:9090"
        );

        // Outbound mapping check
        let wifi_tag = compiled
            .outbound_to_node_id
            .iter()
            .find_map(|(tag, id)| (id == "if-wifi").then(|| tag.clone()))
            .expect("Wi-Fi outbound mapped");
        assert_eq!(
            compiled
                .outbound_to_node_id
                .get("vpn-karing")
                .map(String::as_str),
            Some("vpn-karing")
        );
        assert_eq!(
            compiled
                .outbound_to_node_id
                .get("vpn-openvpn")
                .map(String::as_str),
            Some("vpn-ovpn")
        );

        // Strict rule ordering
        let rules = json["route"]["rules"]
            .as_array()
            .expect("route.rules array");
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(rules[1]["protocol"], "dns");
        assert_eq!(rules[1]["action"], "hijack-dns");
        assert_eq!(rules[2]["ip_version"], 6);
        assert_eq!(rules[2]["action"], "reject");

        // Private LAN bypass rule excludes FakeIP 198.18.0.0/15
        assert_eq!(rules[3]["outbound"], "direct");
        assert!(rules[3].get("ip_is_private").is_none());
        let lan_cidrs = rules[3]["ip_cidr"].as_array().expect("lan ip_cidr");
        for expected in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "127.0.0.0/8",
            "169.254.0.0/16",
            "224.0.0.0/4",
            "255.255.255.255/32",
        ] {
            assert!(lan_cidrs.iter().any(|v| v.as_str() == Some(expected)));
        }
        assert!(!lan_cidrs
            .iter()
            .any(|v| v.as_str() == Some("198.18.0.0/15")));

        let karing_outer_idx = rules
            .iter()
            .position(|r| {
                rule_has_process(r, "karingservice.exe") && rule_has_process(r, "karing.exe")
            })
            .expect("karing outer rule");
        assert_eq!(rules[karing_outer_idx]["outbound"], wifi_tag);

        let ovpn_outer_idx = rules
            .iter()
            .position(|r| {
                rule_has_process(r, "openvpn.exe") && rule_has_process(r, "ovpnconnector.exe")
            })
            .expect("openvpn outer rule");
        assert_eq!(rules[ovpn_outer_idx]["outbound"], "vpn-karing");

        let chrome_idx = rules
            .iter()
            .position(|r| rule_has_process(r, "chrome.exe"))
            .expect("chrome app rule");
        assert_eq!(rules[chrome_idx]["outbound"], "vpn-openvpn");

        let edge_idx = rules
            .iter()
            .position(|r| rule_has_process(r, "msedge.exe"))
            .expect("msedge app rule");
        assert_eq!(rules[edge_idx]["outbound"], wifi_tag);

        assert!(3 < karing_outer_idx);
        assert!(karing_outer_idx < ovpn_outer_idx);
        assert!(ovpn_outer_idx < chrome_idx);
        assert!(ovpn_outer_idx < edge_idx);

        assert_eq!(json["route"]["final"], "default-direct");
    }

    #[test]
    fn test_compiles_openvpn_dco_server_ip_rule_when_chained_downstream() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false),
                apps_node("apps-1", &["firefox.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-ovpn"),
                edge("e3", "vpn-ovpn", "apps-1"),
            ],
        };

        let validated = validate_graph(&graph).expect("valid graph");
        let mut vpn_runtime = HashMap::new();
        vpn_runtime.insert(VpnProvider::Karing, karing_runtime(3067));
        vpn_runtime.insert(
            VpnProvider::OpenVpn,
            openvpn_runtime("OpenVPN Data Channel Offload", Some("203.0.113.10")),
        );

        let compiled = compile_singbox_config(&CompileInput {
            validated,
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .expect("compile should succeed");

        let rules = compiled.json["route"]["rules"]
            .as_array()
            .expect("route.rules");

        let ovpn_proc_idx = rules
            .iter()
            .position(|r| {
                rule_has_process(r, "openvpn.exe") && rule_has_process(r, "ovpnconnector.exe")
            })
            .expect("openvpn process outer rule");
        assert_eq!(rules[ovpn_proc_idx]["outbound"], "vpn-karing");

        let ovpn_ip_idx = rules
            .iter()
            .position(|r| {
                r.get("ip_cidr")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| arr.iter().any(|c| c.as_str() == Some("203.0.113.10/32")))
            })
            .expect("openvpn DCO /32 server IP rule");
        assert_eq!(rules[ovpn_ip_idx]["outbound"], "vpn-karing");

        let firefox_idx = rules
            .iter()
            .position(|r| rule_has_process(r, "firefox.exe"))
            .expect("firefox app rule");
        assert_eq!(rules[firefox_idx]["outbound"], "vpn-openvpn");

        assert!(ovpn_proc_idx < firefox_idx);
        assert!(ovpn_ip_idx < firefox_idx);

        // When OpenVPN connects directly to a physical Interface, do NOT emit sing-box /32 ip_cidr rule
        let direct_iface_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false),
                apps_node("apps-1", &["firefox.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-ovpn"),
                edge("e2", "vpn-ovpn", "apps-1"),
            ],
        };
        let mut vpn_runtime_2 = HashMap::new();
        vpn_runtime_2.insert(
            VpnProvider::OpenVpn,
            openvpn_runtime("OpenVPN Wintun", Some("203.0.113.10")),
        );
        let compiled_2 = compile_singbox_config(&CompileInput {
            validated: validate_graph(&direct_iface_graph).unwrap(),
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime: vpn_runtime_2,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .expect("compile should succeed");
        let has_dco_cidr = compiled_2.json["route"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| {
                r.get("ip_cidr")
                    .and_then(|v| v.as_array())
                    .is_some_and(|arr| arr.iter().any(|c| c.as_str() == Some("203.0.113.10/32")))
            });
        assert!(!has_dco_cidr);
    }

    #[test]
    fn test_compiles_user_selected_default_vpn_as_final_and_normalizes_exe_names() {
        let mut validated = validate_graph(&WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, true),
                iface_node("if-lan1", "LAN 1", false),
                apps_node("apps-lan", &[" Chrome.EXE ", r"C:\Tools\IDMan.EXE"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "if-lan1", "apps-lan"),
            ],
        })
        .expect("valid graph");

        // Also ensure canonical `.exe` normalization even if an un-suffixed name is passed in ValidatedGraph
        validated.app_routes.insert(
            "notepad".to_string(),
            AppRouteAssignment {
                exe_name: " Notepad ".to_string(),
                target_node_id: "if-lan1".to_string(),
                apps_node_id: "apps-lan".to_string(),
            },
        );

        let mut vpn_runtime = HashMap::new();
        vpn_runtime.insert(VpnProvider::Karing, karing_runtime(3067));

        let compiled = compile_singbox_config(&CompileInput {
            validated,
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .expect("compile should succeed");

        assert_eq!(compiled.json["route"]["final"], "vpn-karing");

        let rules = compiled.json["route"]["rules"].as_array().unwrap();
        let mut observed_regexes = Vec::new();
        for rule in rules {
            if let Some(arr) = rule.get("process_path_regex").and_then(|v| v.as_array()) {
                for item in arr {
                    let s = item.as_str().expect("process_path_regex item is string");
                    assert!(
                        s.starts_with(r"(?i)(^|[\\/])") && s.ends_with(r"\.exe$"),
                        "process_path_regex '{s}' must be case-insensitive canonical .exe pattern"
                    );
                    observed_regexes.push(s.to_string());
                }
            }
        }

        for expected in [
            "chrome.exe",
            "idman.exe",
            "notepad.exe",
            "karingservice.exe",
            "karing.exe",
        ] {
            let pattern = exe_to_case_insensitive_path_regex(expected);
            assert!(
                observed_regexes.contains(&pattern),
                "missing pattern {pattern} for {expected}"
            );
        }

        assert!(matches!(
            canonicalize_exe_name(".exe"),
            Err(CompileError::InvalidAppName { .. })
        ));
        assert!(matches!(
            canonicalize_exe_name("chrome."),
            Err(CompileError::InvalidAppName { .. })
        ));
    }

    fn assert_passes_real_singbox_check(config: &Value) {
        let temp_path = std::env::temp_dir().join(format!(
            "netflow-compiler-test-{}.json",
            uuid::Uuid::new_v4()
        ));
        let serialized = serde_json::to_string_pretty(config).expect("serialize json");
        std::fs::write(&temp_path, serialized).expect("write temp config");

        let singbox_bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("src-tauri")
            .join("binaries")
            .join("sing-box-x86_64-pc-windows-msvc.exe");
        assert!(
            singbox_bin.exists(),
            "sing-box binary not found at {}",
            singbox_bin.display()
        );

        let output = std::process::Command::new(&singbox_bin)
            .arg("check")
            .arg("-c")
            .arg(&temp_path)
            .output()
            .expect("execute sing-box check");

        let _ = std::fs::remove_file(&temp_path);

        assert!(
            output.status.success(),
            "sing-box check failed (status {:?}): stdout={} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn test_compiled_json_passes_real_singbox_check() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false),
                apps_node("apps-1", &["firefox.exe", "steam.exe"]),
                iface_node("if-lan1", "LAN 1", false),
                apps_node("apps-2", &["chrome.exe"]),
                iface_node("if-lan2", "LAN 2", true),
                apps_node("apps-3", &["idm.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-ovpn"),
                edge("e3", "vpn-ovpn", "apps-1"),
                edge("e4", "if-lan1", "apps-2"),
                edge("e5", "if-lan2", "apps-3"),
            ],
        };

        let validated = validate_graph(&graph).expect("valid complex graph");
        let mut vpn_runtime = HashMap::new();
        vpn_runtime.insert(VpnProvider::Karing, karing_runtime(3067));
        vpn_runtime.insert(
            VpnProvider::OpenVpn,
            openvpn_runtime("OpenVPN Data Channel Offload", Some("203.0.113.10")),
        );

        let compiled = compile_singbox_config(&CompileInput {
            validated,
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .expect("compile should succeed");

        assert_eq!(compiled.json["dns"]["final"], "dns-iface-lan-2");
        assert_passes_real_singbox_check(&compiled.json);

        // Also validate a default-direct + Karing -> OpenVPN chained configuration
        let chained_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-ovpn"),
                edge("e3", "vpn-ovpn", "apps-1"),
            ],
        };
        let mut chained_rt = HashMap::new();
        chained_rt.insert(VpnProvider::Karing, karing_runtime(3067));
        chained_rt.insert(
            VpnProvider::OpenVpn,
            openvpn_runtime("OpenVPN Wintun", None),
        );
        let chained_compiled = compile_singbox_config(&CompileInput {
            validated: validate_graph(&chained_graph).unwrap(),
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime: chained_rt,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .expect("compile should succeed");

        assert_eq!(chained_compiled.json["dns"]["final"], "dns-default");
        assert_passes_real_singbox_check(&chained_compiled.json);
    }

    #[test]
    fn test_rejects_missing_runtime_info_or_invalid_inputs() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "apps-1"),
            ],
        };
        let validated = validate_graph(&graph).unwrap();

        let err = compile_singbox_config(&CompileInput {
            validated: validated.clone(),
            default_physical_interface: "  ".to_string(),
            vpn_runtime: HashMap::new(),
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .unwrap_err();
        assert_eq!(err, CompileError::MissingDefaultPhysicalInterface);

        let err = compile_singbox_config(&CompileInput {
            validated: validated.clone(),
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime: HashMap::new(),
            clash_api_port: 0,
            log_path: PathBuf::from("sing-box.log"),
        })
        .unwrap_err();
        assert_eq!(err, CompileError::InvalidClashApiPort);

        let err = compile_singbox_config(&CompileInput {
            validated: validated.clone(),
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime: HashMap::new(),
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .unwrap_err();
        assert_eq!(
            err,
            CompileError::MissingVpnRuntime {
                provider: VpnProvider::Karing
            }
        );

        let mut missing_port = HashMap::new();
        missing_port.insert(
            VpnProvider::Karing,
            ResolvedVpnRuntimeInfo {
                provider: VpnProvider::Karing,
                karing_socks_port: None,
                openvpn_adapter_alias: None,
                openvpn_server_ip: None,
            },
        );
        let err = compile_singbox_config(&CompileInput {
            validated,
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime: missing_port,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .unwrap_err();
        assert_eq!(err, CompileError::MissingKaringPort);

        // Chained OpenVPN with malformed server IP
        let ovpn_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-ovpn"),
            ],
        };
        let mut ovpn_rt = HashMap::new();
        ovpn_rt.insert(VpnProvider::Karing, karing_runtime(3067));
        ovpn_rt.insert(
            VpnProvider::OpenVpn,
            openvpn_runtime("OpenVPN Data Channel Offload", Some("bad-ip")),
        );
        let err = compile_singbox_config(&CompileInput {
            validated: validate_graph(&ovpn_graph).unwrap(),
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime: ovpn_rt,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .unwrap_err();
        assert_eq!(
            err,
            CompileError::InvalidOpenVpnServerIp {
                value: "bad-ip".to_string()
            }
        );
    }

    #[test]
    fn test_deduplicates_interface_tags_with_default_vpn() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi-1", "Wi-Fi", false),
                iface_node("if-wifi-2", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, true),
            ],
            edges: vec![edge("e1", "if-wifi-1", "vpn-karing")],
        };

        let mut vpn_runtime = HashMap::new();
        vpn_runtime.insert(VpnProvider::Karing, karing_runtime(3067));

        let compiled = compile_singbox_config(&CompileInput {
            validated: validate_graph(&graph).unwrap(),
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime,
            clash_api_port: 9090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .expect("compile should succeed");

        assert_eq!(compiled.json["route"]["final"], "vpn-karing");
        assert_eq!(compiled.outbound_to_node_id.len(), 3);
        let tags: HashSet<&String> = compiled.outbound_to_node_id.keys().collect();
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn test_vpn_daemon_processes_bypass_fakeip_for_real_dns() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, true),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-ovpn"),
            ],
        };

        let validated = validate_graph(&graph).expect("graph should validate");
        let mut vpn_runtime = HashMap::new();
        vpn_runtime.insert(VpnProvider::Karing, karing_runtime(3067));
        vpn_runtime.insert(
            VpnProvider::OpenVpn,
            openvpn_runtime("OpenVPN Wintun", None),
        );

        let compiled = compile_singbox_config(&CompileInput {
            validated,
            default_physical_interface: "Wi-Fi".to_string(),
            vpn_runtime,
            clash_api_port: 19090,
            log_path: PathBuf::from("sing-box.log"),
        })
        .expect("compilation should succeed");

        let dns_rules = compiled.json["dns"]["rules"]
            .as_array()
            .expect("dns.rules array");

        let karing_dns_idx = dns_rules
            .iter()
            .position(|r| {
                rule_has_process(r, "karingservice.exe") && rule_has_process(r, "karing.exe")
            })
            .expect("karingservice.exe/karing.exe must have a real DNS rule");
        let ovpn_dns_idx = dns_rules
            .iter()
            .position(|r| {
                rule_has_process(r, "openvpn.exe") && rule_has_process(r, "ovpnconnector.exe")
            })
            .expect("openvpn.exe/ovpnconnector.exe must have a real DNS rule");
        let fakeip_idx = dns_rules
            .iter()
            .position(|r| r["server"] == DNS_FAKEIP_TAG)
            .expect("fakeip rule must exist");

        assert!(
            karing_dns_idx < fakeip_idx,
            "Karing daemon DNS rule must precede FakeIP rule so Karing never receives 198.18.x.x FakeIPs"
        );
        assert!(
            ovpn_dns_idx < fakeip_idx,
            "OpenVPN daemon DNS rule must precede FakeIP rule so OpenVPN never receives 198.18.x.x FakeIPs"
        );
        assert_eq!(dns_rules[karing_dns_idx]["server"], "dns-iface-wi-fi");
        assert_eq!(dns_rules[ovpn_dns_idx]["server"], "dns-iface-wi-fi");
    }
}
