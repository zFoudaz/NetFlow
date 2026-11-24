import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Network, Trash2 } from "lucide-react";
import { useNetFlowStore } from "../../store/useNetFlowStore";
import type { WorkflowNode } from "../../types/workflow";
import {
  DefaultTogglePill,
  getNodeCardBorderClass,
  NodeErrorCallout,
  useNodeDiagnostics,
} from "./nodeShared";

export type InterfaceFlowNode = Node<{ node: WorkflowNode }, "interface">;

export function InterfaceNode({ data, selected }: NodeProps<InterfaceFlowNode>) {
  const wfNode = data.node;
  const discoveryInterfaces = useNetFlowStore((s) => s.discovery.interfaces);
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const setDefaultNode = useNetFlowStore((s) => s.setDefaultNode);
  const { nodeErrors, isDropped, hasIssue, errorTooltip } = useNodeDiagnostics(wfNode.id);

  if (wfNode.kind.type !== "interface") {
    return null;
  }

  const { interfaceAlias, isDefault } = wfNode.kind;
  const ifaceInfo = discoveryInterfaces.find((i) => i.alias === interfaceAlias);
  const isUp = Boolean(ifaceInfo?.isUp);

  return (
    <div
      data-testid={`flow-node-${wfNode.id}`}
      title={errorTooltip}
      className={`w-60 rounded-xl border bg-slate-900/95 p-3 text-slate-100 shadow-lg shadow-black/40 transition ${getNodeCardBorderClass(
        hasIssue,
        Boolean(selected),
        isDefault
      )}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-sky-500/30 bg-sky-500/15 text-sky-300">
            <Network className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-sky-400">
              Interface
            </div>
            <div className="truncate text-sm font-semibold text-slate-100">
              {interfaceAlias}
            </div>
          </div>
        </div>

        <button
          type="button"
          aria-label={`Delete ${interfaceAlias} node`}
          onClick={() => removeNode(wfNode.id)}
          className="nodrag rounded p-1 text-slate-500 transition hover:bg-rose-500/15 hover:text-rose-300"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-xs">
        {isUp ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-300">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Up
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300">
            <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
            Offline
          </span>
        )}

        {isDropped && (
          <span className="inline-flex items-center rounded-full border border-rose-500/40 bg-rose-500/20 px-2 py-0.5 text-[11px] font-semibold text-rose-300">
            Dropped
          </span>
        )}

        <span className="ml-auto font-mono text-[11px] text-slate-400">
          {ifaceInfo?.ipv4 ?? "No IPv4"}
        </span>
      </div>

      <div className="mt-2.5 flex items-center justify-between border-t border-slate-800/90 pt-2">
        <DefaultTogglePill
          isDefault={isDefault}
          onToggle={() => setDefaultNode(wfNode.id)}
        />
        {ifaceInfo?.gatewayIpv4 && (
          <span className="font-mono text-[10px] text-slate-500">
            GW {ifaceInfo.gatewayIpv4}
          </span>
        )}
      </div>

      <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />

      <Handle
        type="source"
        position={Position.Right}
        className="!h-3 !w-3 !border-2 !border-slate-950 !bg-sky-400"
      />
    </div>
  );
}
