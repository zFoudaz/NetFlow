use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Supported VPN providers that can appear as nodes in a NetFlow workflow graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VpnProvider {
    Karing,
    OpenVpn,
}

/// Provider-specific overrides configured on a VPN node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase", default)]
pub struct VpnNodeSettings {
    pub karing_port_override: Option<u16>,
    pub openvpn_adapter_override: Option<String>,
    pub openvpn_server_ip_override: Option<String>,
}

/// Discriminated union of workflow node kinds, serialized with a `type` tag.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", rename_all_fields = "camelCase")]
pub enum NodeKind {
    Interface {
        interface_alias: String,
        #[serde(default)]
        is_default: bool,
    },
    Vpn {
        provider: VpnProvider,
        #[serde(default)]
        is_default: bool,
        #[serde(default)]
        settings: VpnNodeSettings,
    },
    Apps {
        #[serde(default)]
        apps: Vec<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        icon_data_url: Option<String>,
    },
}

/// A positioned node inside the visual workflow graph.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowNode {
    pub id: String,
    pub x: f64,
    pub y: f64,
    pub kind: NodeKind,
}

/// A directed edge connecting an upstream node (`source`) to a downstream node (`target`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowEdge {
    pub id: String,
    pub source: String,
    pub target: String,
}

/// Complete workflow graph payload exchanged with the frontend and stored on disk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct WorkflowGraph {
    pub nodes: Vec<WorkflowNode>,
    pub edges: Vec<WorkflowEdge>,
}

/// Persisted workflow document with metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SavedWorkflow {
    pub id: String,
    pub name: String,
    pub updated_at: String,
    pub graph: WorkflowGraph,
}

/// Machine-readable classification of graph validation failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ValidationErrorCode {
    CycleDetected,
    MissingUpstreamInterface,
    DuplicateVpnProvider,
    MultipleUpstreams,
    MultipleDefaults,
    DuplicateAppAssignment,
    InvalidAppName,
    InvalidEdgeDirection,
    DuplicateNodeId,
    UnknownNodeReference,
    EmptyInterfaceAlias,
}

/// Structured validation error identifying all affected node IDs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidationError {
    pub code: ValidationErrorCode,
    pub node_ids: Vec<String>,
    pub message: String,
}

/// A validated VPN node with its resolved upstream node and root physical interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedVpnChain {
    pub node_id: String,
    pub provider: VpnProvider,
    pub upstream_node_id: String,
    pub root_interface_node_id: String,
    pub root_interface_alias: String,
    pub is_default: bool,
    pub settings: VpnNodeSettings,
}

/// A validated routing assignment from a normalized executable name to its upstream egress node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppRouteAssignment {
    pub exe_name: String,
    pub target_node_id: String,
    pub apps_node_id: String,
}

/// Validated, topologically ordered representation of a `WorkflowGraph` ready for compilation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatedGraph {
    pub nodes_by_id: HashMap<String, WorkflowNode>,
    pub interface_node_ids: Vec<String>,
    pub vpn_chains: Vec<ValidatedVpnChain>,
    pub vpn_by_id: HashMap<String, ValidatedVpnChain>,
    pub vpn_by_provider: HashMap<VpnProvider, ValidatedVpnChain>,
    pub app_routes: HashMap<String, AppRouteAssignment>,
    pub default_node_id: Option<String>,
}
