import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { AppWindow, Plus, Trash2, X } from "lucide-react";
import { useState } from "react";
import { useNetFlowStore } from "../../store/useNetFlowStore";
import type { WorkflowNode } from "../../types/workflow";
import { AddAppModal, normalizeExeBasename } from "../AddAppModal";
import {
  getNodeCardBorderClass,
  NodeErrorCallout,
  useNodeDiagnostics,
} from "./nodeShared";

export type AppsFlowNode = Node<{ node: WorkflowNode }, "apps">;

export function AppsNode({ data, selected }: NodeProps<AppsFlowNode>) {
  const wfNode = data.node;
  const selectedNodeId = useNetFlowStore((s) => s.selectedNodeId);
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const updateNodeApps = useNetFlowStore((s) => s.updateNodeApps);
  const { nodeErrors, isDropped, hasIssue, errorTooltip } = useNodeDiagnostics(wfNode.id);

  const [modalOpen, setModalOpen] = useState(false);

  if (wfNode.kind.type !== "apps") {
    return null;
  }

  const { apps, label, iconDataUrl } = wfNode.kind;
  const title = label?.trim() || "Connected Apps";
  const isSelected = Boolean(selected) || selectedNodeId === wfNode.id;

  const handleAddApp = (exeName: string) => {
    const normalized = normalizeExeBasename(exeName) ?? exeName.toLowerCase();
    if (!apps.some((app) => (normalizeExeBasename(app) ?? app.toLowerCase()) === normalized)) {
      updateNodeApps(wfNode.id, [...apps, normalized]);
    }
  };

  const handleRemoveApp = (exeName: string) => {
    updateNodeApps(
      wfNode.id,
      apps.filter((app) => app !== exeName)
    );
  };

  return (
    <div
      data-testid={`flow-node-${wfNode.id}`}
      title={errorTooltip}
      className={`group w-60 rounded-lg border bg-[#161A20] p-3 text-[#F3F4F6] transition ${getNodeCardBorderClass(
        hasIssue,
        isSelected
      )}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-2.5 !w-2.5 !border !border-[#2E3540] !bg-[#9CA3AF]"
      />

      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2.5">
          {iconDataUrl ? (
            <img
              src={iconDataUrl}
              alt=""
              className="h-4 w-4 shrink-0 rounded-sm object-contain"
            />
          ) : (
            <AppWindow className="h-4 w-4 shrink-0 text-[#3ECF8E]" />
          )}
          <div className="min-w-0">
            <div className="truncate text-[13px] font-semibold text-[#F3F4F6]">
              {title}
            </div>
            <div className="mt-0.5 flex items-center gap-1.5 text-[11px] text-[#9CA3AF]">
              <span>
                {apps.length} {apps.length === 1 ? "app" : "apps"}
              </span>
              {isDropped && (
                <span className="rounded bg-rose-500/20 px-1.5 py-0.2 text-[10px] font-medium text-rose-300">
                  Dropped
                </span>
              )}
            </div>
          </div>
        </div>

        <button
          type="button"
          aria-label={`Delete ${title} node`}
          onClick={(e) => {
            e.stopPropagation();
            removeNode(wfNode.id);
          }}
          className="nodrag rounded p-1 text-[#6B7280] opacity-0 transition group-hover:opacity-100 hover:bg-rose-500/15 hover:text-rose-300 focus:opacity-100"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>

      <div className="nodrag nowheel mt-2.5 max-h-44 overflow-y-auto border-t border-[#232830]">
        {apps.length === 0 ? (
          <div className="py-3 text-center text-[11px] text-[#6B7280]">
            No executables assigned
          </div>
        ) : (
          <ul className="divide-y divide-[#232830]">
            {apps.map((exe) => (
              <li
                key={exe}
                className="flex items-center justify-between gap-2 py-1.5 text-xs hover:bg-[#1D222B]/60"
              >
                <span className="truncate font-mono text-[11px] text-[#E5E7EB]">
                  {exe}
                </span>
                <button
                  type="button"
                  aria-label={`Remove ${exe}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    handleRemoveApp(exe);
                  }}
                  className="shrink-0 rounded p-0.5 text-[#6B7280] transition hover:bg-rose-500/15 hover:text-rose-300"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div className="nodrag mt-2 border-t border-[#232830] pt-2">
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            setModalOpen(true);
          }}
          className="inline-flex w-full items-center justify-center gap-1 rounded border border-[#232830] bg-[#111418] px-2.5 py-1.5 text-xs font-medium text-[#D1D5DB] transition hover:border-[#3ECF8E]/40 hover:bg-[#1D222B] hover:text-[#3ECF8E]"
        >
          <Plus className="h-3.5 w-3.5" />
          <span>+ Add App</span>
        </button>
      </div>

      <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />

      <AddAppModal
        isOpen={modalOpen}
        existingApps={apps}
        onAddApp={handleAddApp}
        onClose={() => setModalOpen(false)}
      />
    </div>
  );
}
