import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { AppWindow, Trash2, X } from "lucide-react";
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
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const updateNodeApps = useNetFlowStore((s) => s.updateNodeApps);
  const { nodeErrors, isDropped, hasIssue, errorTooltip } = useNodeDiagnostics(wfNode.id);

  const [modalOpen, setModalOpen] = useState(false);

  if (wfNode.kind.type !== "apps") {
    return null;
  }

  const { apps } = wfNode.kind;

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
      className={`w-64 rounded-xl border bg-slate-900/95 p-3 text-slate-100 shadow-lg shadow-black/40 transition ${getNodeCardBorderClass(
        hasIssue,
        Boolean(selected)
      )}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-3 !w-3 !border-2 !border-slate-950 !bg-emerald-400"
      />

      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/15 text-emerald-300">
            <AppWindow className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-400">
              Application Group
            </div>
            <div className="flex items-center gap-1.5">
              <span className="truncate text-sm font-semibold text-slate-100">
                Connected Apps
              </span>
              <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-semibold text-slate-300">
                {apps.length}
              </span>
            </div>
          </div>
        </div>

        <button
          type="button"
          aria-label="Delete Connected Apps node"
          onClick={() => removeNode(wfNode.id)}
          className="nodrag rounded p-1 text-slate-500 transition hover:bg-rose-500/15 hover:text-rose-300"
        >
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>

      {isDropped && (
        <div className="mt-2">
          <span className="inline-flex items-center rounded-full border border-rose-500/40 bg-rose-500/20 px-2 py-0.5 text-[11px] font-semibold text-rose-300">
            Dropped
          </span>
        </div>
      )}

      <div className="nodrag nowheel mt-2.5 overflow-hidden rounded-lg border border-slate-800 bg-slate-950/80">
        {apps.length === 0 ? (
          <div className="px-3 py-3 text-center text-[11px] text-slate-500">
            No apps assigned yet. Add executables below.
          </div>
        ) : (
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[10px] uppercase tracking-wider text-slate-500">
                <th className="px-2.5 py-1.5 font-medium">Executable</th>
                <th className="w-8 px-1.5 py-1.5 text-right font-medium">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {apps.map((exe) => (
                <tr key={exe} className="hover:bg-slate-900/70">
                  <td className="max-w-[175px] truncate px-2.5 py-1.5 font-mono text-[11px] text-slate-200">
                    {exe}
                  </td>
                  <td className="px-1.5 py-1 text-right">
                    <button
                      type="button"
                      aria-label={`Remove ${exe}`}
                      onClick={() => handleRemoveApp(exe)}
                      className="rounded p-0.5 text-slate-500 transition hover:bg-rose-500/15 hover:text-rose-300"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <div className="nodrag mt-2.5">
        <button
          type="button"
          onClick={() => setModalOpen(true)}
          className="inline-flex w-full items-center justify-center rounded-md border border-slate-700 bg-slate-800/90 px-2.5 py-1.5 text-xs font-medium text-slate-200 transition hover:border-emerald-500/40 hover:bg-emerald-500/15 hover:text-emerald-200"
        >
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
