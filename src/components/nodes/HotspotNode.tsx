import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Radio, Settings2, Trash2 } from "lucide-react";
import { useNetFlowStore } from "../../store/useNetFlowStore";
import type { WorkflowNode } from "../../types/workflow";
import {
  getNodeCardBorderClass,
  NodeErrorCallout,
  useNodeDiagnostics,
  VPN_PROVIDER_LABELS,
} from "./nodeShared";

export type HotspotFlowNode = Node<{ node: WorkflowNode }, "hotspot">;

export function HotspotNode({ data, selected }: NodeProps<HotspotFlowNode>) {
  const wfNode = data.node;
  const graph = useNetFlowStore((s) => s.graph);
  const hotspot = useNetFlowStore((s) => s.discovery.hotspot);
  const selectedNodeId = useNetFlowStore((s) => s.selectedNodeId);
  const setSelectedNodeId = useNetFlowStore((s) => s.setSelectedNodeId);
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const { nodeErrors, hasIssue, errorTooltip } = useNodeDiagnostics(wfNode.id);

  if (wfNode.kind.type !== "hotspot") {
    return null;
  }

  const isSelected = Boolean(selected) || selectedNodeId === wfNode.id;
  const isActive = Boolean(hotspot?.isActive);

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

  return (
    <div
      data-testid={`flow-node-${wfNode.id}`}
      title={errorTooltip}
      className={`group relative w-56 rounded-lg border bg-[#161A20] p-3 text-[#F3F4F6] transition ${getNodeCardBorderClass(
        hasIssue,
        isSelected,
        false
      )}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border !border-[#2E3540] !bg-[#9CA3AF]"
      />

      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <Radio
            className={`h-4 w-4 shrink-0 ${
              isActive ? "text-amber-400" : "text-[#6B7280]"
            }`}
          />
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold text-[#F3F4F6]">
              Mobile Hotspot
            </div>
            <div className="mt-0.5 flex items-center gap-1.5 text-[11px]">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  isActive ? "bg-[#3ECF8E]" : "bg-[#6B7280]"
                }`}
              />
              <span className={isActive ? "text-[#3ECF8E]" : "text-[#9CA3AF]"}>
                {isActive ? "Active" : "Off"}
              </span>
            </div>
          </div>
        </div>

        <div className="nodrag flex items-center gap-0.5 opacity-0 transition group-hover:opacity-100 focus-within:opacity-100">
          <button
            type="button"
            aria-label="Configure Mobile Hotspot"
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
            aria-label="Delete Mobile Hotspot node"
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
          {upstreamLabel ? `via ${upstreamLabel}` : "Connect an interface or VPN"}
        </span>
        {hotspot?.adapterAlias && (
          <span className="max-w-20 truncate font-mono text-[10px] text-[#6B7280]">
            {hotspot.adapterAlias}
          </span>
        )}
      </div>

      <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />
    </div>
  );
}
