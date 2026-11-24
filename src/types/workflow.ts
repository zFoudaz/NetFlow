export type VpnProvider = "karing" | "cloudflareWarp" | "openVpn";

export type WarpMode = "tun" | "proxy";

export interface VpnNodeSettings {
  karingPortOverride?: number | null;
  warpMode: WarpMode;
  openvpnAdapterOverride?: string | null;
  openvpnServerIpOverride?: string | null;
}

export type NodeKind =
  | {
      type: "interface";
      interfaceAlias: string;
      isDefault: boolean;
    }
  | {
      type: "vpn";
      provider: VpnProvider;
      isDefault: boolean;
      settings: VpnNodeSettings;
    }
  | {
      type: "apps";
      apps: string[];
    };

export interface WorkflowNode {
  id: string;
  x: number;
  y: number;
  kind: NodeKind;
}

export interface WorkflowEdge {
  id: string;
  source: string;
  target: string;
}

export interface WorkflowGraph {
  nodes: WorkflowNode[];
  edges: WorkflowEdge[];
}

export interface SavedWorkflow {
  id: string;
  name: string;
  updatedAt: string;
  graph: WorkflowGraph;
}

export interface ValidationError {
  code: string;
  nodeIds: string[];
  message: string;
}

export type RuntimeState = "stopped" | "applying" | "active" | "warning" | "error";

export type NodeHealth = "healthy" | "dropped";

export interface EngineStatus {
  state: RuntimeState;
  activeWorkflowId: string | null;
  nodeHealth: Record<string, NodeHealth>;
  warningBanner: string | null;
  lastError: string | null;
}

export interface PhysicalInterfaceInfo {
  alias: string;
  description: string;
  ifIndex: number;
  ipv4: string | null;
  gatewayIpv4: string | null;
  isUp: boolean;
  linkSpeedMbps: number;
  isDefaultGateway: boolean;
}

export interface DetectedVpnInfo {
  provider: VpnProvider;
  isRunning: boolean;
  detectedPort: number | null;
  adapterAlias: string | null;
  adapterIfIndex: number | null;
  adapterGateway: string | null;
  remoteServerIp: string | null;
  warpCurrentMode: string | null;
}

export interface RunningProcessInfo {
  exeName: string;
  path: string | null;
}

export interface DiscoverySnapshot {
  interfaces: PhysicalInterfaceInfo[];
  vpns: DetectedVpnInfo[];
  processes: RunningProcessInfo[];
}

export interface LiveConnection {
  id: string;
  processName: string;
  destination: string;
  network: string;
  outboundTag: string;
  nodeId: string | null;
  uploadBytes: number;
  downloadBytes: number;
}

export interface SelectWorkflowResult {
  switched: boolean;
  needsConfirm: boolean;
}
