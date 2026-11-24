import { AlertCircle, Star } from "lucide-react";
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
  "openVpn",
] as const;

export const VPN_PROVIDER_LABELS: Record<VpnProvider, string> = {
  karing: "Karing",
  openVpn: "OpenVPN",
};

export function createDefaultVpnSettings(): VpnNodeSettings {
  return {
    karingPortOverride: null,
    openvpnAdapterOverride: null,
    openvpnServerIpOverride: null,
  };
}

export type DragNodePayload =
  | { type: "interface"; interfaceAlias: string }
  | { type: "vpn"; provider: VpnProvider }
  | { type: "apps" };

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
      (record.provider === "karing" || record.provider === "openVpn")
    ) {
      return { type: "vpn", provider: record.provider };
    }
    if (record.type === "apps") {
      return { type: "apps" };
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
    case "apps":
      return {
        id: generateNodeId("apps"),
        x,
        y,
        kind: {
          type: "apps",
          apps: [],
        },
      };
  }
}

export function nextQuickAddPosition(
  nodeType: DragNodePayload["type"],
  existingNodes: WorkflowNode[]
): { x: number; y: number } {
  const sameKindCount = existingNodes.filter((n) => n.kind.type === nodeType).length;
  const xByType: Record<DragNodePayload["type"], number> = {
    interface: 60,
    vpn: 370,
    apps: 700,
  };
  return {
    x: xByType[nodeType] + (sameKindCount % 2) * 24,
    y: 80 + sameKindCount * 170,
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
    return "border-rose-500 ring-2 ring-rose-500/40";
  }
  if (selected) {
    return "border-sky-400 ring-2 ring-sky-500/30";
  }
  if (isDefault) {
    return "border-amber-400/70";
  }
  return "border-slate-700/90 hover:border-slate-600";
}

interface DefaultTogglePillProps {
  isDefault: boolean;
  onToggle: () => void;
}

export function DefaultTogglePill({ isDefault, onToggle }: DefaultTogglePillProps) {
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={isDefault}
      className={`nodrag inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold tracking-wide transition ${
        isDefault
          ? "border-amber-400/60 bg-amber-500/20 text-amber-300"
          : "border-slate-700 bg-slate-800/80 text-slate-400 hover:border-slate-600 hover:text-slate-200"
      }`}
    >
      <Star className={`h-3 w-3 ${isDefault ? "fill-amber-300 text-amber-300" : ""}`} />
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
      className="mt-2 space-y-1 rounded-md border border-rose-500/40 bg-rose-950/70 px-2.5 py-1.5 text-[11px] leading-snug text-rose-200"
    >
      {errors.map((err, idx) => (
        <div key={`${err.code}-${idx}`} className="flex items-start gap-1.5">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-400" />
          <span>{err.message}</span>
        </div>
      ))}
    </div>
  );
}
