use std::collections::{HashMap, HashSet, VecDeque};

use crate::model::{
    AppRouteAssignment, NodeKind, ValidatedGraph, ValidatedVpnChain, ValidationError,
    ValidationErrorCode, VpnProvider, WarpMode, WorkflowGraph, WorkflowNode,
};

/// Normalizes an executable name or path into a lowercase executable filename.
///
/// Trims surrounding whitespace, extracts the filename component if a path with `/` or `\`
/// separators is supplied, lowercases it, and rejects empty, dot-only, trailing-dot,
/// stemless `.exe`, or illegal filenames.
pub fn normalize_exe_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let filename = trimmed.rsplit(['\\', '/']).next()?.trim();
    if filename.is_empty() || filename == "." || filename == ".." {
        return None;
    }

    if filename
        .chars()
        .any(|c| c.is_control() || matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*'))
    {
        return None;
    }

    let lower = filename.to_lowercase();
    if lower.ends_with('.') {
        return None;
    }

    let stem = lower.strip_suffix(".exe").unwrap_or(&lower);
    if stem
        .trim_matches(|c: char| c == '.' || c.is_whitespace())
        .is_empty()
    {
        return None;
    }

    Some(lower)
}

/// Normalizes an executable name or path and guarantees a canonical lowercase `.exe` suffix.
pub fn canonicalize_exe_name(raw: &str) -> Option<String> {
    let normalized = normalize_exe_name(raw)?;
    if normalized.ends_with(".exe") {
        Some(normalized)
    } else {
        Some(format!("{normalized}.exe"))
    }
}

/// Validates a `WorkflowGraph`, collecting all structural and semantic errors before
/// returning a topologically ordered `ValidatedGraph`.
pub fn validate_graph(graph: &WorkflowGraph) -> Result<ValidatedGraph, Vec<ValidationError>> {
    let mut errors = Vec::new();

    let indexed = index_nodes(graph, &mut errors);
    let (incoming, outgoing) = build_adjacency(graph, &indexed.nodes_by_id, &mut errors);

    check_upstream_and_warp_constraints(
        &indexed.node_order,
        &indexed.nodes_by_id,
        &incoming,
        &outgoing,
        &mut errors,
    );
    detect_cycles(&indexed.node_order, &outgoing, &mut errors);
    check_orphan_vpns(
        &indexed.node_order,
        &indexed.nodes_by_id,
        &incoming,
        &outgoing,
        &mut errors,
    );
    let app_routes = validate_apps(
        &indexed.node_order,
        &indexed.nodes_by_id,
        &incoming,
        &mut errors,
    );

    if !errors.is_empty() {
        return Err(errors);
    }

    let (vpn_chains, vpn_by_id, vpn_by_provider) = build_vpn_chains(
        &indexed.interface_node_ids,
        &indexed.nodes_by_id,
        &indexed.node_index,
        &outgoing,
    );

    Ok(ValidatedGraph {
        nodes_by_id: indexed.nodes_by_id,
        interface_node_ids: indexed.interface_node_ids,
        vpn_chains,
        vpn_by_id,
        vpn_by_provider,
        app_routes,
        default_node_id: indexed.default_node_id,
    })
}

struct IndexedNodes {
    nodes_by_id: HashMap<String, WorkflowNode>,
    node_order: Vec<String>,
    node_index: HashMap<String, usize>,
    interface_node_ids: Vec<String>,
    default_node_id: Option<String>,
}

fn push_error(
    errors: &mut Vec<ValidationError>,
    code: ValidationErrorCode,
    node_ids: Vec<String>,
    message: impl Into<String>,
) {
    errors.push(ValidationError {
        code,
        node_ids,
        message: message.into(),
    });
}

fn index_nodes(graph: &WorkflowGraph, errors: &mut Vec<ValidationError>) -> IndexedNodes {
    let mut nodes_by_id = HashMap::new();
    let mut node_order = Vec::new();
    let mut node_index = HashMap::new();
    let mut interface_node_ids = Vec::new();
    let mut vpn_by_provider: HashMap<VpnProvider, Vec<String>> = HashMap::new();
    let mut default_node_ids = Vec::new();

    for node in &graph.nodes {
        if nodes_by_id.contains_key(&node.id) {
            push_error(
                errors,
                ValidationErrorCode::DuplicateNodeId,
                vec![node.id.clone()],
                format!("Duplicate node ID '{}'", node.id),
            );
            continue;
        }

        let idx = node_order.len();
        node_order.push(node.id.clone());
        node_index.insert(node.id.clone(), idx);
        nodes_by_id.insert(node.id.clone(), node.clone());

        match &node.kind {
            NodeKind::Interface {
                interface_alias,
                is_default,
            } => {
                if interface_alias.trim().is_empty() {
                    push_error(
                        errors,
                        ValidationErrorCode::EmptyInterfaceAlias,
                        vec![node.id.clone()],
                        format!("Interface node '{}' has an empty interface alias", node.id),
                    );
                }
                interface_node_ids.push(node.id.clone());
                if *is_default {
                    default_node_ids.push(node.id.clone());
                }
            }
            NodeKind::Vpn {
                provider,
                is_default,
                ..
            } => {
                vpn_by_provider
                    .entry(*provider)
                    .or_default()
                    .push(node.id.clone());
                if *is_default {
                    default_node_ids.push(node.id.clone());
                }
            }
            NodeKind::Apps { .. } => {}
        }
    }

    for (provider, ids) in vpn_by_provider {
        if ids.len() > 1 {
            push_error(
                errors,
                ValidationErrorCode::DuplicateVpnProvider,
                ids,
                format!("Duplicate VPN provider '{provider:?}' is not allowed"),
            );
        }
    }

    let default_node_id = if default_node_ids.len() > 1 {
        push_error(
            errors,
            ValidationErrorCode::MultipleDefaults,
            default_node_ids,
            "At most one Interface or VPN node can be marked as default",
        );
        None
    } else {
        default_node_ids.into_iter().next()
    };

    IndexedNodes {
        nodes_by_id,
        node_order,
        node_index,
        interface_node_ids,
        default_node_id,
    }
}

type AdjacencyMap = HashMap<String, Vec<String>>;

fn build_adjacency(
    graph: &WorkflowGraph,
    nodes_by_id: &HashMap<String, WorkflowNode>,
    errors: &mut Vec<ValidationError>,
) -> (AdjacencyMap, AdjacencyMap) {
    let mut incoming: AdjacencyMap = HashMap::new();
    let mut outgoing: AdjacencyMap = HashMap::new();

    for edge in &graph.edges {
        let Some(source_node) = nodes_by_id.get(&edge.source) else {
            push_error(
                errors,
                ValidationErrorCode::UnknownNodeReference,
                vec![edge.source.clone()],
                format!("Edge '{}' references unknown source node '{}'", edge.id, edge.source),
            );
            continue;
        };

        let Some(target_node) = nodes_by_id.get(&edge.target) else {
            push_error(
                errors,
                ValidationErrorCode::UnknownNodeReference,
                vec![edge.target.clone()],
                format!("Edge '{}' references unknown target node '{}'", edge.id, edge.target),
            );
            continue;
        };

        if matches!(source_node.kind, NodeKind::Apps { .. }) {
            push_error(
                errors,
                ValidationErrorCode::InvalidEdgeDirection,
                vec![edge.source.clone(), edge.target.clone()],
                format!("Apps node '{}' cannot have outgoing edges", edge.source),
            );
            continue;
        }

        if matches!(target_node.kind, NodeKind::Interface { .. }) {
            push_error(
                errors,
                ValidationErrorCode::InvalidEdgeDirection,
                vec![edge.source.clone(), edge.target.clone()],
                format!("Interface node '{}' cannot have incoming edges", edge.target),
            );
            continue;
        }

        incoming
            .entry(edge.target.clone())
            .or_default()
            .push(edge.source.clone());
        outgoing
            .entry(edge.source.clone())
            .or_default()
            .push(edge.target.clone());
    }

    (incoming, outgoing)
}

fn check_upstream_and_warp_constraints(
    node_order: &[String],
    nodes_by_id: &HashMap<String, WorkflowNode>,
    incoming: &AdjacencyMap,
    outgoing: &AdjacencyMap,
    errors: &mut Vec<ValidationError>,
) {
    for id in node_order {
        if let Some(parents) = incoming.get(id) {
            if parents.len() > 1 {
                push_error(
                    errors,
                    ValidationErrorCode::MultipleUpstreams,
                    vec![id.clone()],
                    format!("Node '{id}' has multiple upstream connections"),
                );
            }
        }

        let Some(node) = nodes_by_id.get(id) else {
            continue;
        };

        if let NodeKind::Vpn {
            provider: VpnProvider::CloudflareWarp,
            settings,
            ..
        } = &node.kind
        {
            if settings.warp_mode == WarpMode::Proxy {
                if let Some(children) = outgoing.get(id) {
                    for child_id in children {
                        if let Some(child) = nodes_by_id.get(child_id) {
                            if matches!(child.kind, NodeKind::Vpn { .. }) {
                                push_error(
                                    errors,
                                    ValidationErrorCode::WarpProxyCannotChainDownstream,
                                    vec![id.clone(), child_id.clone()],
                                    format!(
                                        "Cloudflare WARP in Proxy mode ('{id}') cannot chain downstream VPN '{child_id}'"
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum VisitState {
    Visiting,
    Visited,
}

fn detect_cycles(
    node_order: &[String],
    outgoing: &AdjacencyMap,
    errors: &mut Vec<ValidationError>,
) {
    let mut state: HashMap<String, VisitState> = HashMap::new();
    let mut stack: Vec<String> = Vec::new();

    for id in node_order {
        if !state.contains_key(id) {
            dfs_cycle(id, outgoing, &mut state, &mut stack, errors);
        }
    }
}

fn dfs_cycle(
    node_id: &str,
    outgoing: &AdjacencyMap,
    state: &mut HashMap<String, VisitState>,
    stack: &mut Vec<String>,
    errors: &mut Vec<ValidationError>,
) {
    state.insert(node_id.to_string(), VisitState::Visiting);
    stack.push(node_id.to_string());

    if let Some(children) = outgoing.get(node_id) {
        for child_id in children {
            match state.get(child_id).copied() {
                None => dfs_cycle(child_id, outgoing, state, stack, errors),
                Some(VisitState::Visiting) => {
                    let start = stack.iter().position(|id| id == child_id).unwrap_or(0);
                    let cycle_nodes = stack[start..].to_vec();
                    push_error(
                        errors,
                        ValidationErrorCode::CycleDetected,
                        cycle_nodes,
                        format!("Cycle detected involving node '{child_id}'"),
                    );
                }
                Some(VisitState::Visited) => {}
            }
        }
    }

    stack.pop();
    state.insert(node_id.to_string(), VisitState::Visited);
}

fn check_orphan_vpns(
    node_order: &[String],
    nodes_by_id: &HashMap<String, WorkflowNode>,
    incoming: &AdjacencyMap,
    outgoing: &AdjacencyMap,
    errors: &mut Vec<ValidationError>,
) {
    let mut reported_roots: HashSet<String> = HashSet::new();

    for id in node_order {
        let Some(node) = nodes_by_id.get(id) else {
            continue;
        };
        let NodeKind::Vpn { is_default, .. } = node.kind else {
            continue;
        };

        let is_active = is_default || can_reach_apps(id, nodes_by_id, outgoing);
        if !is_active {
            continue;
        }

        if let Some(orphan_root) = find_orphan_root(id, nodes_by_id, incoming) {
            if reported_roots.insert(orphan_root.clone()) {
                push_error(
                    errors,
                    ValidationErrorCode::MissingUpstreamInterface,
                    vec![orphan_root.clone()],
                    format!("VPN node '{orphan_root}' requires an upstream physical interface"),
                );
            }
        }
    }
}

fn can_reach_apps(
    start_id: &str,
    nodes_by_id: &HashMap<String, WorkflowNode>,
    outgoing: &AdjacencyMap,
) -> bool {
    let mut visited = HashSet::new();
    let mut queue = VecDeque::new();
    visited.insert(start_id.to_string());
    queue.push_back(start_id.to_string());

    while let Some(cur) = queue.pop_front() {
        if let Some(children) = outgoing.get(&cur) {
            for child in children {
                if let Some(node) = nodes_by_id.get(child) {
                    if matches!(node.kind, NodeKind::Apps { .. }) {
                        return true;
                    }
                    if visited.insert(child.clone()) {
                        queue.push_back(child.clone());
                    }
                }
            }
        }
    }

    false
}

/// Walks upstream from a VPN node. Returns `Some(root_vpn_id)` if the chain terminates at a
/// VPN node with no incoming edges, or `None` if it reaches an Interface, a cycle, or a
/// multi-upstream fork (the latter two are already reported by their own checks).
fn find_orphan_root(
    start_id: &str,
    nodes_by_id: &HashMap<String, WorkflowNode>,
    incoming: &AdjacencyMap,
) -> Option<String> {
    let mut visited = HashSet::new();
    let mut cur = start_id.to_string();

    loop {
        if !visited.insert(cur.clone()) {
            return None;
        }

        let node = nodes_by_id.get(&cur)?;

        if matches!(node.kind, NodeKind::Interface { .. }) {
            return None;
        }

        let parents = incoming.get(&cur).map(Vec::as_slice).unwrap_or(&[]);
        match parents.len() {
            0 => return Some(cur),
            1 => cur = parents[0].clone(),
            _ => return None,
        }
    }
}

fn validate_apps(
    node_order: &[String],
    nodes_by_id: &HashMap<String, WorkflowNode>,
    incoming: &AdjacencyMap,
    errors: &mut Vec<ValidationError>,
) -> HashMap<String, AppRouteAssignment> {
    let mut app_routes = HashMap::new();
    let mut seen_apps: HashMap<String, String> = HashMap::new();

    for id in node_order {
        let Some(node) = nodes_by_id.get(id) else {
            continue;
        };
        let NodeKind::Apps { apps } = &node.kind else {
            continue;
        };

        let parents = incoming.get(id).map(Vec::as_slice).unwrap_or(&[]);
        if !apps.is_empty() && parents.is_empty() {
            push_error(
                errors,
                ValidationErrorCode::MissingUpstreamInterface,
                vec![id.clone()],
                format!("Apps node '{id}' requires an upstream Interface or VPN node"),
            );
        }

        let target_node_id = if parents.len() == 1 {
            Some(parents[0].clone())
        } else {
            None
        };

        for raw_app in apps {
            let Some(exe_name) = canonicalize_exe_name(raw_app) else {
                push_error(
                    errors,
                    ValidationErrorCode::InvalidAppName,
                    vec![id.clone()],
                    format!("Invalid executable name '{raw_app}' in Apps node '{id}'"),
                );
                continue;
            };

            if let Some(first_node_id) = seen_apps.get(&exe_name) {
                let mut affected = vec![first_node_id.clone()];
                if first_node_id != id {
                    affected.push(id.clone());
                }
                push_error(
                    errors,
                    ValidationErrorCode::DuplicateAppAssignment,
                    affected,
                    format!("Executable '{exe_name}' is assigned more than once"),
                );
                continue;
            }

            seen_apps.insert(exe_name.clone(), id.clone());
            if let Some(target_id) = &target_node_id {
                app_routes.insert(
                    exe_name.clone(),
                    AppRouteAssignment {
                        exe_name,
                        target_node_id: target_id.clone(),
                        apps_node_id: id.clone(),
                    },
                );
            }
        }
    }

    app_routes
}

fn build_vpn_chains(
    interface_node_ids: &[String],
    nodes_by_id: &HashMap<String, WorkflowNode>,
    node_index: &HashMap<String, usize>,
    outgoing: &AdjacencyMap,
) -> (
    Vec<ValidatedVpnChain>,
    HashMap<String, ValidatedVpnChain>,
    HashMap<VpnProvider, ValidatedVpnChain>,
) {
    let mut builder = VpnChainBuilder {
        nodes_by_id,
        node_index,
        outgoing,
        vpn_chains: Vec::new(),
        vpn_by_id: HashMap::new(),
        vpn_by_provider: HashMap::new(),
    };

    for iface_id in interface_node_ids {
        let Some(iface_node) = nodes_by_id.get(iface_id) else {
            continue;
        };
        let NodeKind::Interface {
            interface_alias, ..
        } = &iface_node.kind
        else {
            continue;
        };

        builder.collect_subtree(iface_id, iface_id, interface_alias);
    }

    (
        builder.vpn_chains,
        builder.vpn_by_id,
        builder.vpn_by_provider,
    )
}

struct VpnChainBuilder<'a> {
    nodes_by_id: &'a HashMap<String, WorkflowNode>,
    node_index: &'a HashMap<String, usize>,
    outgoing: &'a AdjacencyMap,
    vpn_chains: Vec<ValidatedVpnChain>,
    vpn_by_id: HashMap<String, ValidatedVpnChain>,
    vpn_by_provider: HashMap<VpnProvider, ValidatedVpnChain>,
}

impl VpnChainBuilder<'_> {
    fn collect_subtree(&mut self, upstream_id: &str, root_iface_id: &str, root_iface_alias: &str) {
        let Some(children) = self.outgoing.get(upstream_id) else {
            return;
        };

        let mut vpn_children: Vec<&String> = children
            .iter()
            .filter(|child_id| {
                self.nodes_by_id
                    .get(*child_id)
                    .is_some_and(|n| matches!(n.kind, NodeKind::Vpn { .. }))
            })
            .collect();
        vpn_children.sort_by_key(|id| self.node_index.get(*id).copied().unwrap_or(usize::MAX));

        for child_id in vpn_children {
            let Some(child_node) = self.nodes_by_id.get(child_id) else {
                continue;
            };
            let NodeKind::Vpn {
                provider,
                is_default,
                settings,
            } = &child_node.kind
            else {
                continue;
            };

            let chain = ValidatedVpnChain {
                node_id: child_id.clone(),
                provider: *provider,
                upstream_node_id: upstream_id.to_string(),
                root_interface_node_id: root_iface_id.to_string(),
                root_interface_alias: root_iface_alias.to_string(),
                is_default: *is_default,
                settings: settings.clone(),
            };

            self.vpn_chains.push(chain.clone());
            self.vpn_by_id.insert(child_id.clone(), chain.clone());
            self.vpn_by_provider.insert(*provider, chain);

            self.collect_subtree(child_id, root_iface_id, root_iface_alias);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        NodeKind, ValidationErrorCode, VpnNodeSettings, VpnProvider, WarpMode, WorkflowEdge,
        WorkflowGraph, WorkflowNode,
    };

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
        warp_mode: WarpMode,
    ) -> WorkflowNode {
        WorkflowNode {
            id: id.to_string(),
            x: 0.0,
            y: 0.0,
            kind: NodeKind::Vpn {
                provider,
                is_default,
                settings: VpnNodeSettings {
                    warp_mode,
                    ..Default::default()
                },
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

    #[test]
    fn test_valid_parallel_and_chained_vpn_graph() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, WarpMode::Tun),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    WarpMode::Tun,
                ),
                apps_node("apps-1", &["chrome.exe"]),
                iface_node("if-lan1", "LAN 1", false),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false, WarpMode::Tun),
                apps_node("apps-2", &["firefox.exe"]),
                iface_node("if-lan2", "LAN 2", true),
                apps_node("apps-3", &["idm.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-karing"),
                edge("e2", "vpn-karing", "vpn-warp"),
                edge("e3", "vpn-warp", "apps-1"),
                edge("e4", "if-lan1", "vpn-ovpn"),
                edge("e5", "vpn-ovpn", "apps-2"),
                edge("e6", "if-lan2", "apps-3"),
            ],
        };

        let validated = validate_graph(&graph).expect("graph should validate cleanly");
        let providers: Vec<VpnProvider> =
            validated.vpn_chains.iter().map(|c| c.provider).collect();
        assert_eq!(
            providers,
            vec![
                VpnProvider::Karing,
                VpnProvider::CloudflareWarp,
                VpnProvider::OpenVpn
            ]
        );

        let karing_idx = validated
            .vpn_chains
            .iter()
            .position(|c| c.node_id == "vpn-karing")
            .unwrap();
        let warp_idx = validated
            .vpn_chains
            .iter()
            .position(|c| c.node_id == "vpn-warp")
            .unwrap();
        assert!(karing_idx < warp_idx);

        assert_eq!(validated.vpn_by_id["vpn-karing"].upstream_node_id, "if-wifi");
        assert_eq!(
            validated.vpn_by_id["vpn-karing"].root_interface_alias,
            "Wi-Fi"
        );
        assert_eq!(
            validated.vpn_by_id["vpn-warp"].upstream_node_id,
            "vpn-karing"
        );
        assert_eq!(
            validated.vpn_by_id["vpn-warp"].root_interface_alias,
            "Wi-Fi"
        );
        assert_eq!(validated.vpn_by_id["vpn-ovpn"].upstream_node_id, "if-lan1");
        assert_eq!(
            validated.vpn_by_id["vpn-ovpn"].root_interface_alias,
            "LAN 1"
        );

        assert_eq!(
            validated.app_routes["chrome.exe"].target_node_id,
            "vpn-warp"
        );
        assert_eq!(
            validated.app_routes["firefox.exe"].target_node_id,
            "vpn-ovpn"
        );
        assert_eq!(validated.app_routes["idm.exe"].target_node_id, "if-lan2");
        assert_eq!(validated.default_node_id.as_deref(), Some("if-lan2"));
    }

    #[test]
    fn test_rejects_vpn_cycle() {
        let graph = WorkflowGraph {
            nodes: vec![
                vpn_node("vpn-karing", VpnProvider::Karing, false, WarpMode::Tun),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    WarpMode::Tun,
                ),
            ],
            edges: vec![
                edge("e1", "vpn-karing", "vpn-warp"),
                edge("e2", "vpn-warp", "vpn-karing"),
            ],
        };

        let errors = validate_graph(&graph).expect_err("cycle should be rejected");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::CycleDetected));
    }

    #[test]
    fn test_rejects_orphan_vpn_with_apps_or_default() {
        let graph_with_apps = WorkflowGraph {
            nodes: vec![
                vpn_node("vpn-karing", VpnProvider::Karing, false, WarpMode::Tun),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![edge("e1", "vpn-karing", "apps-1")],
        };

        let errors =
            validate_graph(&graph_with_apps).expect_err("orphan vpn with apps should fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::MissingUpstreamInterface));

        let graph_with_default = WorkflowGraph {
            nodes: vec![vpn_node(
                "vpn-karing",
                VpnProvider::Karing,
                true,
                WarpMode::Tun,
            )],
            edges: vec![],
        };

        let errors =
            validate_graph(&graph_with_default).expect_err("orphan default vpn should fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::MissingUpstreamInterface));
    }

    #[test]
    fn test_rejects_duplicate_vpn_provider() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-1", "Wi-Fi", false),
                iface_node("if-2", "LAN 1", false),
                vpn_node("vpn-ovpn-1", VpnProvider::OpenVpn, false, WarpMode::Tun),
                vpn_node("vpn-ovpn-2", VpnProvider::OpenVpn, false, WarpMode::Tun),
            ],
            edges: vec![
                edge("e1", "if-1", "vpn-ovpn-1"),
                edge("e2", "if-2", "vpn-ovpn-2"),
            ],
        };

        let errors = validate_graph(&graph).expect_err("duplicate provider should fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::DuplicateVpnProvider));
    }

    #[test]
    fn test_rejects_multiple_upstreams_into_vpn_or_apps() {
        let vpn_multi = WorkflowGraph {
            nodes: vec![
                iface_node("if-1", "Wi-Fi", false),
                iface_node("if-2", "LAN 1", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, WarpMode::Tun),
            ],
            edges: vec![
                edge("e1", "if-1", "vpn-karing"),
                edge("e2", "if-2", "vpn-karing"),
            ],
        };

        let errors = validate_graph(&vpn_multi).expect_err("multiple upstreams into vpn must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::MultipleUpstreams));

        let apps_multi = WorkflowGraph {
            nodes: vec![
                iface_node("if-1", "Wi-Fi", false),
                iface_node("if-2", "LAN 1", false),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![edge("e1", "if-1", "apps-1"), edge("e2", "if-2", "apps-1")],
        };

        let errors =
            validate_graph(&apps_multi).expect_err("multiple upstreams into apps must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::MultipleUpstreams));
    }

    #[test]
    fn test_rejects_downstream_vpn_after_warp_proxy() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    WarpMode::Proxy,
                ),
                vpn_node("vpn-ovpn", VpnProvider::OpenVpn, false, WarpMode::Tun),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-warp"),
                edge("e2", "vpn-warp", "vpn-ovpn"),
                edge("e3", "vpn-ovpn", "apps-1"),
            ],
        };

        let errors = validate_graph(&graph).expect_err("warp proxy downstream vpn must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::WarpProxyCannotChainDownstream));

        // Direct Apps downstream of WARP(Proxy) must be allowed.
        let valid_proxy_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node(
                    "vpn-warp",
                    VpnProvider::CloudflareWarp,
                    false,
                    WarpMode::Proxy,
                ),
                apps_node("apps-1", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "vpn-warp"),
                edge("e2", "vpn-warp", "apps-1"),
            ],
        };
        assert!(validate_graph(&valid_proxy_graph).is_ok());
    }

    #[test]
    fn test_rejects_multiple_default_nodes() {
        let graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", true),
                vpn_node("vpn-karing", VpnProvider::Karing, true, WarpMode::Tun),
            ],
            edges: vec![edge("e1", "if-wifi", "vpn-karing")],
        };

        let errors = validate_graph(&graph).expect_err("multiple defaults must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::MultipleDefaults));
    }

    #[test]
    fn test_rejects_duplicate_apps_case_and_whitespace_insensitive() {
        let dup_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                iface_node("if-lan", "LAN 1", false),
                apps_node("apps-a", &[" Chrome.EXE "]),
                apps_node("apps-b", &["chrome.exe"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "apps-a"),
                edge("e2", "if-lan", "apps-b"),
            ],
        };

        let errors = validate_graph(&dup_graph).expect_err("duplicate apps must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::DuplicateAppAssignment));

        let blank_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                apps_node("apps-a", &["   ", "C:\\folder\\"]),
            ],
            edges: vec![edge("e1", "if-wifi", "apps-a")],
        };

        let errors = validate_graph(&blank_graph).expect_err("blank app name must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::InvalidAppName));

        assert_eq!(normalize_exe_name(" Chrome.EXE "), Some("chrome.exe".into()));
        assert_eq!(
            normalize_exe_name(r"C:\Program Files\Google\Chrome\chrome.exe"),
            Some("chrome.exe".into())
        );
        assert_eq!(
            normalize_exe_name("/usr/bin/Firefox"),
            Some("firefox".into())
        );
        assert_eq!(normalize_exe_name("   "), None);
        assert_eq!(normalize_exe_name(r"C:\folder\"), None);
        assert_eq!(normalize_exe_name("bad*name.exe"), None);
        assert_eq!(normalize_exe_name(".."), None);
        assert_eq!(normalize_exe_name(".exe"), None);
        assert_eq!(normalize_exe_name(" .EXE "), None);
        assert_eq!(normalize_exe_name(r"C:\Tools\.exe"), None);
        assert_eq!(normalize_exe_name("chrome."), None);
        assert_eq!(normalize_exe_name("..exe"), None);

        // "chrome" vs "chrome.exe" across two Apps nodes must be caught as DuplicateAppAssignment
        let canonical_dup_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                iface_node("if-lan", "LAN 1", false),
                apps_node("apps-a", &["chrome"]),
                apps_node("apps-b", &["CHROME.EXE"]),
            ],
            edges: vec![
                edge("e1", "if-wifi", "apps-a"),
                edge("e2", "if-lan", "apps-b"),
            ],
        };
        let dup_errors =
            validate_graph(&canonical_dup_graph).expect_err("chrome vs chrome.exe must collide");
        assert!(dup_errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::DuplicateAppAssignment));

        // Stemless ".exe" and trailing-dot names fail validation with InvalidAppName
        let stemless_graph = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                apps_node("apps-a", &[".exe", "firefox."]),
            ],
            edges: vec![edge("e1", "if-wifi", "apps-a")],
        };
        let invalid_errors =
            validate_graph(&stemless_graph).expect_err("stemless .exe must fail");
        assert_eq!(
            invalid_errors
                .iter()
                .filter(|e| e.code == ValidationErrorCode::InvalidAppName)
                .count(),
            2
        );

        // Un-suffixed "chrome" is stored canonically as "chrome.exe" in ValidatedGraph.app_routes
        let unsuffixed_valid = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                apps_node("apps-a", &[" Chrome "]),
            ],
            edges: vec![edge("e1", "if-wifi", "apps-a")],
        };
        let validated = validate_graph(&unsuffixed_valid).expect("unsuffixed chrome validates");
        assert!(validated.app_routes.contains_key("chrome.exe"));
        assert_eq!(validated.app_routes["chrome.exe"].exe_name, "chrome.exe");
    }

    #[test]
    fn test_rejects_outgoing_edge_from_apps_and_incoming_edge_to_interface() {
        let outgoing_from_apps = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                apps_node("apps-1", &["chrome.exe"]),
                vpn_node("vpn-karing", VpnProvider::Karing, false, WarpMode::Tun),
            ],
            edges: vec![
                edge("e1", "if-wifi", "apps-1"),
                edge("e2", "apps-1", "vpn-karing"),
            ],
        };

        let errors =
            validate_graph(&outgoing_from_apps).expect_err("outgoing edge from apps must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::InvalidEdgeDirection));

        let incoming_to_iface = WorkflowGraph {
            nodes: vec![
                iface_node("if-wifi", "Wi-Fi", false),
                vpn_node("vpn-karing", VpnProvider::Karing, false, WarpMode::Tun),
            ],
            edges: vec![edge("e1", "vpn-karing", "if-wifi")],
        };

        let errors =
            validate_graph(&incoming_to_iface).expect_err("incoming edge to interface must fail");
        assert!(errors
            .iter()
            .any(|e| e.code == ValidationErrorCode::InvalidEdgeDirection));
    }

    #[test]
    fn test_serde_camel_case_serialization() {
        let node = vpn_node(
            "vpn-1",
            VpnProvider::CloudflareWarp,
            true,
            WarpMode::Proxy,
        );
        let json = serde_json::to_value(&node).expect("serialize node");
        assert_eq!(json["kind"]["type"], "vpn");
        assert_eq!(json["kind"]["provider"], "cloudflareWarp");
        assert_eq!(json["kind"]["isDefault"], true);
        assert_eq!(json["kind"]["settings"]["warpMode"], "proxy");

        let iface = iface_node("if-1", "Wi-Fi", false);
        let iface_json = serde_json::to_value(&iface).expect("serialize interface");
        assert_eq!(iface_json["kind"]["type"], "interface");
        assert_eq!(iface_json["kind"]["interfaceAlias"], "Wi-Fi");
        assert_eq!(iface_json["kind"]["isDefault"], false);

        let roundtrip: WorkflowNode = serde_json::from_value(json).expect("deserialize node");
        assert_eq!(roundtrip, node);
    }
}
