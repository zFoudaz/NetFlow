import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Trash2 } from "lucide-react";
import { useNetFlowStore } from "../../store/useNetFlowStore";
import type { WorkflowNode } from "../../types/workflow";
import {
  getInterfaceIcon,
  getNodeCardBorderClass,
  NodeErrorCallout,
  useNodeDiagnostics,
} from "./nodeShared";

export type InterfaceFlowNode = Node<{ node: WorkflowNode }, "interface">;

export function InterfaceNode({ data, selected }: NodeProps<InterfaceFlowNode>) {
  const wfNode = data.node;
  const discoveryInterfaces = useNetFlowStore((s) => s.discovery.interfaces);
  const selectedNodeId = useNetFlowStore((s) => s.selectedNodeId);
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const { nodeErrors, isDropped, hasIssue, errorTooltip } = useNodeDiagnostics(wfNode.id);

  if (wfNode.kind.type !== "interface") {
    return null;
  }

  const { interfaceAlias, isDefault } = wfNode.kind;
  const ifaceInfo = discoveryInterfaces.find((i) => i.alias === interfaceAlias);
  const isUp = Boolean(ifaceInfo?.isUp);
  const Icon = getInterfaceIcon(interfaceAlias);
  const isSelected = Boolean(selected) || selectedNodeId === wfNode.id;

  return (
    <div
      data-testid={`flow-node-${wfNode.id}`}
      title={errorTooltip}
      className={`group w-56 rounded-lg border bg-[#161A20] p-3 text-[#F3F4F6] transition ${getNodeCardBorderClass(
        hasIssue,
        isSelected,
        isDefault
      )}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          <Icon
            className={`h-4 w-4 shrink-0 ${
              isUp ? "text-[#3ECF8E]" : "text-[#6B7280]"
            }`}
          />
          <div className="min-w-0">
            <div className="flex items-center gap-1.5">
              <span className="truncate text-[13px] font-semibold text-[#F3F4F6]">
                {interfaceAlias}
              </span>
              {isDefault && (
                <span className="shrink-0 rounded border border-[#3ECF8E]/30 bg-[#3ECF8E]/10 px-1 py-0.2 text-[9px] font-semibold uppercase tracking-wide text-[#3ECF8E]">
                  Default
                </span>
              )}
            </div>
            <div className="mt-0.5 flex items-center gap-1.5 text-[11px]">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  isUp ? "bg-[#3ECF8E]" : "bg-amber-400"
                }`}
              />
              <span className={isUp ? "text-[#3ECF8E]" : "text-amber-300"}>
                {isUp ? "Up" : "Offline"}
              </span>
              {isDropped && (
                <span className="ml-1 rounded bg-rose-500/20 px-1.5 py-0.2 text-[10px] font-medium text-rose-300">
                  Dropped
                </span>
              )}
            </div>
          </div>
        </div>

        <button
          type="button"
          aria-label={`Delete ${interfaceAlias} node`}
          onClick={(e) => {
            e.stopPropagation();
            removeNode(wfNode.id);
          }}
          className="nodrag rounded p-1 text-[#6B7280] opacity-0 transition group-hover:opacity-100 hover:bg-rose-500/15 hover:text-rose-300 focus:opacity-100"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="mt-2.5 flex items-center justify-between border-t border-[#232830] pt-2 font-mono text-[11px] text-[#9CA3AF]">
        <span>{ifaceInfo?.ipv4 ?? "No IPv4"}</span>
        {ifaceInfo?.gatewayIpv4 && (
          <span className="text-[10px] text-[#6B7280]">GW {ifaceInfo.gatewayIpv4}</span>
        )}
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
