import { useState, type FormEvent } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  ChevronDown,
  CopyPlus,
  FilePlus2,
  Pencil,
  Play,
  RefreshCw,
  Save,
  ShieldAlert,
  Square,
  Trash2,
  X,
} from "lucide-react";
import { isRoutingActiveState, useNetFlowStore } from "../store/useNetFlowStore";
import type { RuntimeState } from "../types/workflow";

type PromptMode =
  | { kind: "new" }
  | { kind: "saveAs" }
  | { kind: "rename"; workflowId: string }
  | null;

type PendingDiscard =
  | { kind: "select"; workflowId: string; workflowName: string; applyAfter: boolean }
  | { kind: "new" }
  | null;

const STATUS_META: Record<
  RuntimeState,
  { label: string; pillClass: string; dotClass: string }
> = {
  stopped: {
    label: "Stopped",
    pillClass: "border-slate-700 bg-slate-800/80 text-slate-300",
    dotClass: "bg-slate-400",
  },
  applying: {
    label: "Applying",
    pillClass: "border-sky-500/40 bg-sky-500/15 text-sky-300",
    dotClass: "bg-sky-400 animate-pulse",
  },
  active: {
    label: "Active",
    pillClass: "border-emerald-500/40 bg-emerald-500/15 text-emerald-300",
    dotClass: "bg-emerald-400",
  },
  warning: {
    label: "Warning",
    pillClass: "border-amber-500/40 bg-amber-500/15 text-amber-300",
    dotClass: "bg-amber-400 animate-pulse",
  },
  error: {
    label: "Error",
    pillClass: "border-rose-500/40 bg-rose-500/15 text-rose-300",
    dotClass: "bg-rose-400",
  },
};

export function TopBar() {
  const workflows = useNetFlowStore((s) => s.workflows);
  const currentWorkflowId = useNetFlowStore((s) => s.currentWorkflowId);
  const currentWorkflowName = useNetFlowStore((s) => s.currentWorkflowName);
  const isDirty = useNetFlowStore((s) => s.isDirty);
  const engineStatus = useNetFlowStore((s) => s.engineStatus);
  const isApplying = useNetFlowStore((s) => s.isApplying);
  const recoveryNotice = useNetFlowStore((s) => s.recoveryNotice);
  const uiError = useNetFlowStore((s) => s.uiError);
  const isTrafficDrawerOpen = useNetFlowStore((s) => s.isTrafficDrawerOpen);
  const liveConnections = useNetFlowStore((s) => s.liveConnections);

  const selectWorkflow = useNetFlowStore((s) => s.selectWorkflow);
  const createWorkflow = useNetFlowStore((s) => s.createWorkflow);
  const saveCurrentWorkflow = useNetFlowStore((s) => s.saveCurrentWorkflow);
  const saveAsWorkflow = useNetFlowStore((s) => s.saveAsWorkflow);
  const renameWorkflow = useNetFlowStore((s) => s.renameWorkflow);
  const deleteWorkflow = useNetFlowStore((s) => s.deleteWorkflow);
  const applyCurrentWorkflow = useNetFlowStore((s) => s.applyCurrentWorkflow);
  const switchAndApplyWorkflow = useNetFlowStore((s) => s.switchAndApplyWorkflow);
  const stopRouting = useNetFlowStore((s) => s.stopRouting);
  const toggleTrafficDrawer = useNetFlowStore((s) => s.toggleTrafficDrawer);
  const dismissRecoveryNotice = useNetFlowStore((s) => s.dismissRecoveryNotice);
  const clearUiError = useNetFlowStore((s) => s.clearUiError);

  const [menuOpen, setMenuOpen] = useState(false);
  const [promptMode, setPromptMode] = useState<PromptMode>(null);
  const [nameInput, setNameInput] = useState("");
  const [pendingDiscard, setPendingDiscard] = useState<PendingDiscard>(null);

  const routingActive = isRoutingActiveState(engineStatus.state);
  const statusMeta = STATUS_META[engineStatus.state];
  const applyingNow = isApplying || engineStatus.state === "applying";
  const droppedCount = Object.values(engineStatus.nodeHealth).filter(
    (h) => h === "dropped"
  ).length;
  const showWarningBanner =
    engineStatus.state === "warning" ||
    Boolean(engineStatus.warningBanner) ||
    droppedCount > 0;
  const errorMessage = uiError ?? engineStatus.lastError;

  const handleSelectWorkflow = (id: string, name: string) => {
    const result = selectWorkflow(id);
    setMenuOpen(false);
    if (result.needsConfirm) {
      setPendingDiscard({ kind: "select", workflowId: id, workflowName: name, applyAfter: false });
    }
  };

  const handleSwitchAndApply = async (id: string, name: string) => {
    const result = await switchAndApplyWorkflow(id);
    setMenuOpen(false);
    if (result.needsConfirm) {
      setPendingDiscard({ kind: "select", workflowId: id, workflowName: name, applyAfter: true });
    }
  };

  const handleConfirmDiscard = async () => {
    if (!pendingDiscard) return;
    const action = pendingDiscard;
    setPendingDiscard(null);
    setMenuOpen(false);
    if (action.kind === "new") {
      openNamePrompt({ kind: "new" });
      return;
    }
    if (action.applyAfter) {
      await switchAndApplyWorkflow(action.workflowId, { force: true });
    } else {
      selectWorkflow(action.workflowId, { force: true });
    }
  };

  const handleRequestNew = () => {
    if (isDirty) {
      setPendingDiscard({ kind: "new" });
      setMenuOpen(false);
      return;
    }
    openNamePrompt({ kind: "new" });
  };

  const openNamePrompt = (mode: NonNullable<PromptMode>, initialValue = "") => {
    setPromptMode(mode);
    setNameInput(initialValue);
    setMenuOpen(false);
  };

  const handlePromptSubmit = async (e: FormEvent) => {
    e.preventDefault();
    const trimmed = nameInput.trim();
    if (!trimmed || !promptMode) return;

    if (promptMode.kind === "new") {
      await createWorkflow(trimmed);
    } else if (promptMode.kind === "saveAs") {
      await saveAsWorkflow(trimmed);
    } else if (promptMode.kind === "rename") {
      await renameWorkflow(promptMode.workflowId, trimmed);
    }
    setPromptMode(null);
    setNameInput("");
  };

  const handleDeleteCurrent = async () => {
    if (!currentWorkflowId) return;
    await deleteWorkflow(currentWorkflowId);
    setMenuOpen(false);
  };

  return (
    <header className="relative z-30 flex flex-col border-b border-slate-800 bg-slate-900/95 text-slate-100 backdrop-blur">
      <div className="flex flex-wrap items-center justify-between gap-3 px-4 py-2.5">
        {/* Left: Brand + Workflow Switcher */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 pr-2">
            <span className="inline-flex h-7 w-7 items-center justify-center rounded-md bg-sky-500/20 text-xs font-bold tracking-wider text-sky-300 ring-1 ring-sky-500/40">
              NF
            </span>
            <span className="text-sm font-semibold tracking-tight text-slate-100">
              NetFlow
            </span>
          </div>

          <div className="relative">
            <button
              type="button"
              onClick={() => setMenuOpen((prev) => !prev)}
              aria-expanded={menuOpen}
              aria-label="Workflow Switcher"
              className="inline-flex items-center gap-2 rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm font-medium text-slate-100 transition hover:border-slate-600 hover:bg-slate-700/80"
            >
              <span className="max-w-48 truncate">
                {currentWorkflowName}
                {isDirty ? " *" : ""}
              </span>
              <ChevronDown className="h-4 w-4 text-slate-400" />
            </button>

            {menuOpen && (
              <div
                role="menu"
                className="absolute left-0 mt-1.5 w-80 rounded-lg border border-slate-700 bg-slate-900 p-1.5 shadow-xl shadow-black/50"
              >
                <div className="px-2 py-1 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Saved Workflows
                </div>

                <div className="max-h-56 space-y-0.5 overflow-y-auto py-1">
                  {workflows.length === 0 ? (
                    <div className="px-2.5 py-2 text-xs text-slate-500">
                      No saved workflows yet.
                    </div>
                  ) : (
                    workflows.map((wf) => {
                      const isCurrent = wf.id === currentWorkflowId;
                      const isRunningWf =
                        routingActive && wf.id === engineStatus.activeWorkflowId;
                      return (
                        <div
                          key={wf.id}
                          className={`flex items-center justify-between gap-2 rounded-md px-2 py-1.5 text-sm ${
                            isCurrent
                              ? "bg-slate-800 text-slate-100"
                              : "text-slate-300 hover:bg-slate-800/60"
                          }`}
                        >
                          <button
                            type="button"
                            onClick={() => handleSelectWorkflow(wf.id, wf.name)}
                            className="flex min-w-0 flex-1 items-center gap-2 text-left"
                          >
                            <span className="truncate">
                              {wf.name}
                              {isCurrent && isDirty ? " *" : ""}
                            </span>
                            {isRunningWf && (
                              <span className="shrink-0 rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] font-medium text-emerald-300">
                                Running
                              </span>
                            )}
                          </button>

                          {routingActive && !isRunningWf && (
                            <button
                              type="button"
                              onClick={() => void handleSwitchAndApply(wf.id, wf.name)}
                              className="shrink-0 rounded border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 text-xs font-medium text-sky-300 transition hover:bg-sky-500/25"
                            >
                              Switch &amp; Apply
                            </button>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>

                <div className="my-1.5 border-t border-slate-800" />

                <div className="grid grid-cols-2 gap-1 p-0.5">
                  <button
                    type="button"
                    onClick={handleRequestNew}
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                  >
                    <FilePlus2 className="h-3.5 w-3.5 text-slate-400" />
                    New
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      void saveCurrentWorkflow();
                      setMenuOpen(false);
                    }}
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                  >
                    <Save className="h-3.5 w-3.5 text-slate-400" />
                    Save
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      openNamePrompt({ kind: "saveAs" }, `${currentWorkflowName} Copy`)
                    }
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800"
                  >
                    <CopyPlus className="h-3.5 w-3.5 text-slate-400" />
                    Save As
                  </button>
                  <button
                    type="button"
                    disabled={!currentWorkflowId}
                    onClick={() =>
                      currentWorkflowId &&
                      openNamePrompt(
                        { kind: "rename", workflowId: currentWorkflowId },
                        currentWorkflowName
                      )
                    }
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-slate-200 hover:bg-slate-800 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Pencil className="h-3.5 w-3.5 text-slate-400" />
                    Rename
                  </button>
                  <button
                    type="button"
                    disabled={!currentWorkflowId}
                    onClick={() => void handleDeleteCurrent()}
                    className="col-span-2 inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/15 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete Workflow
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Center/Right: Status Pill, Engine Controls, Traffic Toggle */}
        <div className="flex flex-wrap items-center gap-2.5">
          <div
            className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-medium ${statusMeta.pillClass}`}
          >
            <span className={`h-2 w-2 rounded-full ${statusMeta.dotClass}`} />
            <span>{statusMeta.label}</span>
          </div>

          <button
            type="button"
            disabled={applyingNow}
            onClick={() => void applyCurrentWorkflow()}
            className="inline-flex items-center gap-1.5 rounded-md bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            <Play className="h-3.5 w-3.5" />
            <span>{applyingNow ? "Applying..." : "Start / Apply"}</span>
          </button>

          <button
            type="button"
            disabled={engineStatus.state === "stopped"}
            onClick={() => void stopRouting()}
            className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-semibold text-slate-200 transition hover:border-rose-500/50 hover:bg-rose-500/15 hover:text-rose-200 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Square className="h-3.5 w-3.5" />
            <span>Stop</span>
          </button>

          <button
            type="button"
            onClick={toggleTrafficDrawer}
            aria-pressed={isTrafficDrawerOpen}
            className={`inline-flex items-center gap-1.5 rounded-md border px-3 py-1.5 text-xs font-medium transition ${
              isTrafficDrawerOpen
                ? "border-sky-500/50 bg-sky-500/15 text-sky-200"
                : "border-slate-700 bg-slate-800 text-slate-300 hover:bg-slate-700"
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            <span>Live Traffic</span>
            {liveConnections.length > 0 && (
              <span className="rounded bg-slate-700/90 px-1.5 py-0.5 text-[10px] font-semibold text-slate-200">
                {liveConnections.length}
              </span>
            )}
          </button>
        </div>
      </div>

      {/* Inline Workflow Name Prompt (New / Save As / Rename) */}
      {promptMode && (
        <form
          onSubmit={(e) => void handlePromptSubmit(e)}
          className="flex items-center gap-2 border-t border-slate-800 bg-slate-950/70 px-4 py-2 text-xs"
        >
          <span className="font-medium text-slate-300">
            {promptMode.kind === "new"
              ? "New workflow name:"
              : promptMode.kind === "saveAs"
                ? "Save workflow as:"
                : "Rename workflow:"}
          </span>
          <input
            type="text"
            autoFocus
            value={nameInput}
            onChange={(e) => setNameInput(e.target.value)}
            placeholder="Workflow name"
            className="w-64 rounded border border-slate-700 bg-slate-900 px-2.5 py-1 text-xs text-slate-100 outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            className="inline-flex items-center gap-1 rounded bg-sky-600 px-2.5 py-1 font-medium text-white hover:bg-sky-500"
          >
            <Check className="h-3.5 w-3.5" />
            Confirm
          </button>
          <button
            type="button"
            onClick={() => setPromptMode(null)}
            className="inline-flex items-center gap-1 rounded border border-slate-700 px-2.5 py-1 text-slate-300 hover:bg-slate-800"
          >
            Cancel
          </button>
        </form>
      )}

      {/* Unsaved Changes Guard Confirmation */}
      {pendingDiscard && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-200">
          <span>
            You have unsaved changes in <strong>{currentWorkflowName}</strong>.{" "}
            {pendingDiscard.kind === "new" ? (
              "Discard edits and create a new workflow?"
            ) : (
              <>
                Discard edits and switch to <strong>{pendingDiscard.workflowName}</strong>?
              </>
            )}
          </span>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => void handleConfirmDiscard()}
              className="rounded bg-amber-500 px-2.5 py-1 font-semibold text-slate-950 hover:bg-amber-400"
            >
              {pendingDiscard.kind === "new" ? "Discard & Continue" : "Discard & Switch"}
            </button>
            <button
              type="button"
              onClick={() => setPendingDiscard(null)}
              className="rounded border border-amber-500/40 px-2.5 py-1 text-amber-200 hover:bg-amber-500/20"
            >
              Keep Editing
            </button>
          </div>
        </div>
      )}

      {/* Warning Banner for Dropped Nodes */}
      {showWarningBanner && (
        <div className="flex flex-wrap items-center justify-between gap-2 border-t border-amber-500/30 bg-amber-500/10 px-4 py-2 text-xs text-amber-200">
          <div className="flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>
              {engineStatus.warningBanner ??
                `${droppedCount} routed node(s) dropped during active routing.`}
            </span>
          </div>
          <button
            type="button"
            onClick={() => void applyCurrentWorkflow()}
            className="inline-flex items-center gap-1 rounded bg-amber-500 px-2.5 py-1 font-semibold text-slate-950 transition hover:bg-amber-400"
          >
            <RefreshCw className="h-3 w-3" />
            Re-Apply
          </button>
        </div>
      )}

      {/* Startup Crash-Recovery Notice */}
      {recoveryNotice && (
        <div className="flex items-center justify-between gap-2 border-t border-sky-500/30 bg-sky-500/10 px-4 py-2 text-xs text-sky-200">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0 text-sky-400" />
            <span>{recoveryNotice}</span>
          </div>
          <button
            type="button"
            aria-label="Dismiss recovery notice"
            onClick={dismissRecoveryNotice}
            className="rounded p-0.5 text-sky-300 hover:bg-sky-500/20"
          >
            <X className="h-3.5 w-3.5" />
          </button>
        </div>
      )}

      {/* Actionable Error Banner */}
      {errorMessage && (
        <div className="flex items-center justify-between gap-2 border-t border-rose-500/30 bg-rose-500/10 px-4 py-2 text-xs text-rose-200">
          <span>{errorMessage}</span>
          {uiError && (
            <button
              type="button"
              aria-label="Dismiss error"
              onClick={clearUiError}
              className="rounded p-0.5 text-rose-300 hover:bg-rose-500/20"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>
      )}
    </header>
  );
}
