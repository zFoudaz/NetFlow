import { AlertCircle, Network, Star, Wifi } from "lucide-react";
import { useNetFlowStore } from "../../store/useNetFlowStore";
import type {
  ValidationError,
  VpnNodeSettings,
  VpnProvider,
  WorkflowNode,
} from "../../types/workflow";

export const NETFLOW_DND_MIME = "application/netflow-node";

export const VPN_PROVIDERS: readonly VpnProvider[] = [
  "karing",
  "nekoRay",
  "openVpn",
] as const;

export const VPN_PROVIDER_LABELS: Record<VpnProvider, string> = {
  karing: "Karing",
  nekoRay: "NekoRay",
  openVpn: "OpenVPN",
};

export function getConflictingVpnProvider(
  provider: VpnProvider,
  nodes: WorkflowNode[]
): VpnProvider | null {
  const conflictTarget: VpnProvider | null =
    provider === "karing" ? "nekoRay" : provider === "nekoRay" ? "karing" : null;
  if (!conflictTarget) return null;
  return nodes.some((n) => n.kind.type === "vpn" && n.kind.provider === conflictTarget)
    ? conflictTarget
    : null;
}

export function getInterfaceIcon(alias: string) {
  return /wi-?fi|wlan/i.test(alias) ? Wifi : Network;
}

export function createDefaultVpnSettings(): VpnNodeSettings {
  return {
    karingPortOverride: null,
    nekorayPortOverride: null,
    openvpnAdapterOverride: null,
    openvpnServerIpOverride: null,
  };
}

export type DragNodePayload =
  | { type: "interface"; interfaceAlias: string }
  | { type: "vpn"; provider: VpnProvider }
  | { type: "hotspot" }
  | {
      type: "apps";
      label?: string | null;
      apps?: string[];
      iconDataUrl?: string | null;
    };

export function parseDragNodePayload(raw: string): DragNodePayload | null {
  if (!raw) return null;
  try {
    const parsed: unknown = JSON.parse(raw);
    if (typeof parsed !== "object" || parsed === null || !("type" in parsed)) {
      return null;
    }
    const record = parsed as Record<string, unknown>;
    if (record.type === "interface" && typeof record.interfaceAlias === "string") {
      return { type: "interface", interfaceAlias: record.interfaceAlias };
    }
    if (
      record.type === "vpn" &&
      (record.provider === "karing" ||
        record.provider === "openVpn" ||
        record.provider === "nekoRay")
    ) {
      return { type: "vpn", provider: record.provider };
    }
    if (record.type === "hotspot") {
      return { type: "hotspot" };
    }
    if (record.type === "apps") {
      const result: Extract<DragNodePayload, { type: "apps" }> = { type: "apps" };
      if (typeof record.label === "string" && record.label.trim()) {
        result.label = record.label.trim();
      }
      if (Array.isArray(record.apps)) {
        const apps = record.apps
          .filter((item): item is string => typeof item === "string")
          .map((item) => item.trim())
          .filter(Boolean);
        if (apps.length > 0) {
          result.apps = apps;
        }
      }
      if (
        typeof record.iconDataUrl === "string" &&
        record.iconDataUrl.startsWith("data:image/")
      ) {
        result.iconDataUrl = record.iconDataUrl;
      }
      return result;
    }
    return null;
  } catch {
    return null;
  }
}

function generateNodeId(prefix: string): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return `${prefix}-${globalThis.crypto.randomUUID().slice(0, 8)}`;
  }
  return `${prefix}-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

export function createWorkflowNode(
  payload: DragNodePayload,
  position: { x: number; y: number }
): WorkflowNode {
  const x = Number.isFinite(position.x) ? Math.round(position.x) : 0;
  const y = Number.isFinite(position.y) ? Math.round(position.y) : 0;

  switch (payload.type) {
    case "interface":
      return {
        id: generateNodeId("iface"),
        x,
        y,
        kind: {
          type: "interface",
          interfaceAlias: payload.interfaceAlias,
          isDefault: false,
        },
      };
    case "vpn":
      return {
        id: generateNodeId(`vpn-${payload.provider}`),
        x,
        y,
        kind: {
          type: "vpn",
          provider: payload.provider,
          isDefault: false,
          settings: createDefaultVpnSettings(),
        },
      };
    case "hotspot":
      return {
        id: generateNodeId("hotspot"),
        x,
        y,
        kind: {
          type: "hotspot",
        },
      };
    case "apps": {
      const seen = new Set<string>();
      const apps: string[] = [];
      for (const rawExe of payload.apps ?? []) {
        const normalized = rawExe.trim().toLowerCase();
        if (normalized && !seen.has(normalized)) {
          seen.add(normalized);
          apps.push(normalized);
        }
      }
      const trimmedLabel = payload.label?.trim();
      const kind: Extract<WorkflowNode["kind"], { type: "apps" }> = {
        type: "apps",
        apps,
      };
      if (trimmedLabel) {
        kind.label = trimmedLabel;
      }
      if (payload.iconDataUrl) {
        kind.iconDataUrl = payload.iconDataUrl;
      }
      return {
        id: generateNodeId("apps"),
        x,
        y,
        kind,
      };
    }
  }
}

export function nextQuickAddPosition(
  nodeType: DragNodePayload["type"],
  existingNodes: WorkflowNode[]
): { x: number; y: number } {
  const sameKindCount = existingNodes.filter((n) => n.kind.type === nodeType).length;
  const xByType: Record<DragNodePayload["type"], number> = {
    interface: 60,
    vpn: 360,
    apps: 660,
    hotspot: 660,
  };
  return {
    x: xByType[nodeType] + (sameKindCount % 2) * 24,
    y: 80 + sameKindCount * 160,
  };
}

export interface NodeDiagnostics {
  nodeErrors: ValidationError[];
  isDropped: boolean;
  hasIssue: boolean;
  errorTooltip: string | undefined;
}

export function useNodeDiagnostics(nodeId: string): NodeDiagnostics {
  const validationErrors = useNetFlowStore((s) => s.validationErrors);
  const nodeHealth = useNetFlowStore((s) => s.engineStatus.nodeHealth[nodeId]);

  const nodeErrors = validationErrors.filter((err) => err.nodeIds.includes(nodeId));
  const isDropped = nodeHealth === "dropped";
  const hasIssue = nodeErrors.length > 0 || isDropped;
  const messages = nodeErrors.map((err) => err.message);
  if (isDropped) {
    messages.unshift("Node dropped or disconnected during active routing.");
  }

  return {
    nodeErrors,
    isDropped,
    hasIssue,
    errorTooltip: messages.length > 0 ? messages.join("\n") : undefined,
  };
}

export function getNodeCardBorderClass(
  hasIssue: boolean,
  selected: boolean,
  isDefault = false
): string {
  if (hasIssue) {
    return "border-rose-500 ring-1 ring-rose-500/40";
  }
  if (selected) {
    return "border-[#3ECF8E] ring-1 ring-[#3ECF8E]/30";
  }
  if (isDefault) {
    return "border-[#2E3540]";
  }
  return "border-[#232830] hover:border-[#2E3540]";
}

interface DefaultTogglePillProps {
  isDefault: boolean;
  disabled?: boolean;
  onToggle: () => void;
}

export function DefaultTogglePill({ isDefault, disabled = false, onToggle }: DefaultTogglePillProps) {
  return (
    <button
      type="button"
      disabled={disabled}
      onClick={onToggle}
      aria-pressed={isDefault}
      className={`nodrag inline-flex items-center gap-1.5 rounded border px-2 py-1 text-[11px] font-medium transition disabled:cursor-not-allowed disabled:opacity-50 ${
        isDefault
          ? "border-[#3ECF8E]/40 bg-[#3ECF8E]/10 text-[#3ECF8E]"
          : "border-[#232830] bg-[#161A20] text-[#9CA3AF] hover:border-[#2E3540] hover:text-[#F3F4F6]"
      }`}
    >
      <Star className={`h-3 w-3 ${isDefault ? "fill-[#3ECF8E] text-[#3ECF8E]" : ""}`} />
      <span>{isDefault ? "DEFAULT" : "Set as Default"}</span>
    </button>
  );
}

interface NodeErrorCalloutProps {
  errors: ValidationError[];
  tooltip?: string;
}

export function NodeErrorCallout({ errors, tooltip }: NodeErrorCalloutProps) {
  if (errors.length === 0) {
    return null;
  }

  return (
    <div
      role="alert"
      title={tooltip}
      className="mt-2 space-y-1 rounded border border-rose-500/35 bg-rose-950/50 px-2 py-1.5 text-[11px] leading-snug text-rose-200"
    >
      {errors.map((err, idx) => (
        <div key={`${err.code}-${idx}`} className="flex items-start gap-1.5">
          <AlertCircle className="mt-0.5 h-3 w-3 shrink-0 text-rose-400" />
          <span>{err.message}</span>
        </div>
      ))}
    </div>
  );
}
