import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Settings2, Shield, Star, Trash2 } from "lucide-react";
import { useNetFlowStore } from "../../store/useNetFlowStore";
import type { WorkflowNode } from "../../types/workflow";
import {
  getNodeCardBorderClass,
  NodeErrorCallout,
  useNodeDiagnostics,
  VPN_PROVIDER_LABELS,
} from "./nodeShared";

export type VpnFlowNode = Node<{ node: WorkflowNode }, "vpn">;

export function VpnNode({ data, selected }: NodeProps<VpnFlowNode>) {
  const wfNode = data.node;
  const discoveryVpns = useNetFlowStore((s) => s.discovery.vpns);
  const graph = useNetFlowStore((s) => s.graph);
  const selectedNodeId = useNetFlowStore((s) => s.selectedNodeId);
  const isApplying = useNetFlowStore((s) => s.isApplying);
  const setSelectedNodeId = useNetFlowStore((s) => s.setSelectedNodeId);
  const setDefaultNode = useNetFlowStore((s) => s.setDefaultNode);
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const { nodeErrors, isDropped, hasIssue, errorTooltip } = useNodeDiagnostics(wfNode.id);

  if (wfNode.kind.type !== "vpn") {
    return null;
  }

  const { provider, isDefault, settings } = wfNode.kind;
  const providerLabel = VPN_PROVIDER_LABELS[provider];
  const vpnInfo = discoveryVpns.find((v) => v.provider === provider);
  const isRunning = Boolean(vpnInfo?.isRunning);
  const isSelected = Boolean(selected) || selectedNodeId === wfNode.id;

  // Resolve the single associated upstream interface/node
  const incomingEdge = graph.edges.find((e) => e.target === wfNode.id);
  const upstreamNode = incomingEdge
    ? graph.nodes.find((n) => n.id === incomingEdge.source)
    : undefined;
  const upstreamLabel =
    upstreamNode?.kind.type === "interface"
      ? upstreamNode.kind.interfaceAlias
      : upstreamNode?.kind.type === "vpn"
        ? VPN_PROVIDER_LABELS[upstreamNode.kind.provider]
        : null;

  const endpointDetail =
    provider === "karing"
      ? `Port ${settings.karingPortOverride ?? vpnInfo?.detectedPort ?? "Auto"}`
      : settings.openvpnAdapterOverride || vpnInfo?.adapterAlias || "TAP / Wintun";

  return (
    <div
      data-testid={`flow-node-${wfNode.id}`}
      title={errorTooltip}
      className={`group relative w-56 rounded-lg border bg-[#161A20] p-3 text-[#F3F4F6] transition ${getNodeCardBorderClass(
        hasIssue,
        isSelected,
        isDefault
      )}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border !border-[#2E3540] !bg-[#9CA3AF]"
      />

      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <Shield
            className={`h-4 w-4 shrink-0 ${
              isRunning ? "text-[#14B8A6]" : "text-[#6B7280]"
            }`}
          />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-[13px] font-semibold text-[#F3F4F6]">
                {providerLabel}
              </span>
            </div>
            <div className="mt-0.5 flex items-center gap-1.5 text-[11px]">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  isRunning ? "bg-[#3ECF8E]" : "bg-[#6B7280]"
                }`}
              />
              <span className={isRunning ? "text-[#3ECF8E]" : "text-[#9CA3AF]"}>
                {isRunning ? "Running" : "Stopped"}
              </span>
              {isDropped && (
                <span className="ml-1 rounded bg-rose-500/20 px-1.5 py-0.2 text-[10px] font-medium text-rose-300">
                  Dropped
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="nodrag flex items-center gap-0.5 opacity-0 transition group-hover:opacity-100 focus-within:opacity-100">
          <button
            type="button"
            aria-label={`Configure ${providerLabel} settings`}
            onClick={(e) => {
              e.stopPropagation();
              setSelectedNodeId(wfNode.id);
            }}
            className="rounded p-1 text-[#6B7280] transition hover:bg-[#1D222B] hover:text-[#F3F4F6]"
          >
            <Settings2 className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            aria-label={`Delete ${providerLabel} node`}
            onClick={(e) => {
              e.stopPropagation();
              removeNode(wfNode.id);
            }}
            className="rounded p-1 text-[#6B7280] transition hover:bg-rose-500/15 hover:text-rose-300"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="mt-2.5 flex items-center justify-between gap-2 border-t border-[#232830] pt-2 text-[11px]">
        <span className="truncate text-[#9CA3AF]">
          {upstreamLabel ? `via ${upstreamLabel}` : "No interface"}
        </span>
        <span className="shrink-0 font-mono text-[10px] text-[#6B7280]">
          {endpointDetail}
        </span>
      </div>

      <div className="nodrag mt-2 flex items-center justify-between border-t border-[#232830] pt-2">
        <button
          type="button"
          disabled={isApplying}
          aria-pressed={isDefault}
          aria-label={
            isDefault
              ? `Clear default on ${providerLabel}`
              : `Set ${providerLabel} as default`
          }
          onClick={(e) => {
            e.stopPropagation();
            setSelectedNodeId(wfNode.id);
            setDefaultNode(wfNode.id);
          }}
          className={`inline-flex items-center gap-1 rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide transition disabled:cursor-not-allowed disabled:opacity-50 ${
            isDefault
              ? "border-[#3ECF8E]/40 bg-[#3ECF8E]/10 text-[#3ECF8E]"
              : "border-[#232830] bg-[#111418] text-[#9CA3AF] hover:border-[#2E3540] hover:text-[#F3F4F6]"
          }`}
        >
          <Star className={`h-2.5 w-2.5 ${isDefault ? "fill-[#3ECF8E] text-[#3ECF8E]" : ""}`} />
          <span>{isDefault ? "Default" : "Set Default"}</span>
        </button>
      </div>

      <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />

      <Handle
        type="source"
        position={Position.Right}
        className="!h-2.5 !w-2.5 !border !border-[#2E3540] !bg-[#9CA3AF]"
      />
    </div>
  );
}
