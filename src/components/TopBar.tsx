import { useState, type FormEvent } from "react";
import {
  Activity,
  AlertTriangle,
  Check,
  CheckCircle2,
  ChevronDown,
  CopyPlus,
  FilePlus2,
  Folder,
  Maximize2,
  Pencil,
  Play,
  RefreshCw,
  Save,
  Settings,
  ShieldAlert,
  Square,
  Trash2,
  X,
} from "lucide-react";
import {
  isRoutingActiveState,
  serializeRoutingGraph,
  useNetFlowStore,
} from "../store/useNetFlowStore";
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
    pillClass: "border-[#232830] bg-[#161A20] text-[#9CA3AF]",
    dotClass: "bg-[#6B7280]",
  },
  applying: {
    label: "Applying",
    pillClass: "border-teal-500/40 bg-teal-500/10 text-teal-300",
    dotClass: "bg-teal-400 animate-pulse",
  },
  active: {
    label: "Active",
    pillClass: "border-[#3ECF8E]/40 bg-[#3ECF8E]/10 text-[#3ECF8E]",
    dotClass: "bg-[#3ECF8E]",
  },
  warning: {
    label: "Warning",
    pillClass: "border-amber-500/40 bg-amber-500/10 text-amber-300",
    dotClass: "bg-amber-400 animate-pulse",
  },
  error: {
    label: "Error",
    pillClass: "border-rose-500/40 bg-rose-500/10 text-rose-300",
    dotClass: "bg-rose-400",
  },
};

export function TopBar() {
  const workflows = useNetFlowStore((s) => s.workflows);
  const currentWorkflowId = useNetFlowStore((s) => s.currentWorkflowId);
  const currentWorkflowName = useNetFlowStore((s) => s.currentWorkflowName);
  const graph = useNetFlowStore((s) => s.graph);
  const isDirty = useNetFlowStore((s) => s.isDirty);
  const engineStatus = useNetFlowStore((s) => s.engineStatus);
  const isApplying = useNetFlowStore((s) => s.isApplying);
  const appliedGraphSignature = useNetFlowStore((s) => s.appliedGraphSignature);
  const recoveryNotice = useNetFlowStore((s) => s.recoveryNotice);
  const uiError = useNetFlowStore((s) => s.uiError);
  const isTrafficDrawerOpen = useNetFlowStore((s) => s.isTrafficDrawerOpen);
  const liveConnections = useNetFlowStore((s) => s.liveConnections);
  const appSettings = useNetFlowStore((s) => s.appSettings);

  const selectWorkflow = useNetFlowStore((s) => s.selectWorkflow);
  const createWorkflow = useNetFlowStore((s) => s.createWorkflow);
  const saveCurrentWorkflow = useNetFlowStore((s) => s.saveCurrentWorkflow);
  const saveAsWorkflow = useNetFlowStore((s) => s.saveAsWorkflow);
  const renameWorkflow = useNetFlowStore((s) => s.renameWorkflow);
  const deleteWorkflow = useNetFlowStore((s) => s.deleteWorkflow);
  const applyCurrentWorkflow = useNetFlowStore((s) => s.applyCurrentWorkflow);
  const switchAndApplyWorkflow = useNetFlowStore((s) => s.switchAndApplyWorkflow);
  const stopRouting = useNetFlowStore((s) => s.stopRouting);
  const validateCurrentGraph = useNetFlowStore((s) => s.validateCurrentGraph);
  const requestFitView = useNetFlowStore((s) => s.requestFitView);
  const toggleTrafficDrawer = useNetFlowStore((s) => s.toggleTrafficDrawer);
  const updateAppSettings = useNetFlowStore((s) => s.updateAppSettings);
  const dismissRecoveryNotice = useNetFlowStore((s) => s.dismissRecoveryNotice);
  const clearUiError = useNetFlowStore((s) => s.clearUiError);

  const [menuOpen, setMenuOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [isUpdatingSettings, setIsUpdatingSettings] = useState(false);
  const [promptMode, setPromptMode] = useState<PromptMode>(null);
  const [nameInput, setNameInput] = useState("");
  const [pendingDiscard, setPendingDiscard] = useState<PendingDiscard>(null);
  const [validatedOk, setValidatedOk] = useState(false);

  const handleToggleSetting = async (
    key: "startWithWindows" | "autoApplyLastWorkflow",
    nextValue: boolean
  ) => {
    setIsUpdatingSettings(true);
    try {
      await updateAppSettings({ [key]: nextValue });
    } finally {
      setIsUpdatingSettings(false);
    }
  };

  const routingActive = isRoutingActiveState(engineStatus.state);
  const statusMeta = STATUS_META[engineStatus.state];
  const applyingNow = isApplying || engineStatus.state === "applying";
  const hasUnappliedChanges =
    routingActive &&
    appliedGraphSignature !== null &&
    serializeRoutingGraph(graph) !== appliedGraphSignature;
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

  const handleValidate = async () => {
    const ok = await validateCurrentGraph();
    if (ok) {
      setValidatedOk(true);
      setTimeout(() => setValidatedOk(false), 2000);
    }
  };

  return (
    <header className="relative z-30 flex flex-col border-b border-[#232830] bg-[#111418] text-[#F3F4F6]">
      <div className="flex h-12 flex-wrap items-center justify-between gap-2 px-4">
        {/* Left: Workflow Switcher + Canvas Utilities */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <button
              type="button"
              onClick={() => {
                setMenuOpen((prev) => !prev);
                setSettingsOpen(false);
              }}
              aria-expanded={menuOpen}
              aria-label="Workflow Switcher"
              className="inline-flex h-8 items-center gap-2 rounded-md border border-[#232830] bg-[#161A20] px-2.5 text-xs font-medium text-[#F3F4F6] transition hover:border-[#2E3540] hover:bg-[#1D222B]"
            >
              <Folder className="h-3.5 w-3.5 text-[#9CA3AF]" />
              <span className="max-w-44 truncate">
                {currentWorkflowName}
                {isDirty ? " *" : ""}
              </span>
              <ChevronDown className="h-3.5 w-3.5 text-[#6B7280]" />
            </button>

            {menuOpen && (
              <div
                role="menu"
                className="absolute left-0 mt-1.5 w-80 rounded-md border border-[#2E3540] bg-[#111418] p-1.5 shadow-lg shadow-black/40"
              >
                <div className="px-2 py-1 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                  Saved Workflows
                </div>

                <div className="max-h-56 space-y-0.5 overflow-y-auto py-1">
                  {workflows.length === 0 ? (
                    <div className="px-2.5 py-2 text-xs text-[#6B7280]">
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
                          className={`flex items-center justify-between gap-2 rounded px-2 py-1.5 text-xs ${
                            isCurrent
                              ? "bg-[#1D222B] text-[#F3F4F6]"
                              : "text-[#9CA3AF] hover:bg-[#161A20] hover:text-[#F3F4F6]"
                          }`}
                        >
                          <button
                            type="button"
                            onClick={() => handleSelectWorkflow(wf.id, wf.name)}
                            className="flex min-w-0 flex-1 items-center gap-2 text-left"
                          >
                            <span className="truncate font-medium">
                              {wf.name}
                              {isCurrent && isDirty ? " *" : ""}
                            </span>
                            {isRunningWf && (
                              <span className="shrink-0 rounded border border-[#3ECF8E]/30 bg-[#3ECF8E]/10 px-1.5 py-0.5 text-[10px] font-medium text-[#3ECF8E]">
                                Running
                              </span>
                            )}
                          </button>

                          {routingActive && !isRunningWf && (
                            <button
                              type="button"
                              onClick={() => void handleSwitchAndApply(wf.id, wf.name)}
                              className="shrink-0 rounded border border-[#3ECF8E]/40 bg-[#3ECF8E]/10 px-2 py-0.5 text-[11px] font-medium text-[#3ECF8E] transition hover:bg-[#3ECF8E]/20"
                            >
                              Switch &amp; Apply
                            </button>
                          )}
                        </div>
                      );
                    })
                  )}
                </div>

                <div className="my-1.5 border-t border-[#232830]" />

                <div className="grid grid-cols-2 gap-1 p-0.5">
                  <button
                    type="button"
                    onClick={handleRequestNew}
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-[#F3F4F6] hover:bg-[#1D222B]"
                  >
                    <FilePlus2 className="h-3.5 w-3.5 text-[#9CA3AF]" />
                    New
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      void saveCurrentWorkflow();
                      setMenuOpen(false);
                    }}
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-[#F3F4F6] hover:bg-[#1D222B]"
                  >
                    <Save className="h-3.5 w-3.5 text-[#9CA3AF]" />
                    Save
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      openNamePrompt({ kind: "saveAs" }, `${currentWorkflowName} Copy`)
                    }
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-[#F3F4F6] hover:bg-[#1D222B]"
                  >
                    <CopyPlus className="h-3.5 w-3.5 text-[#9CA3AF]" />
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
                    className="inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-[#F3F4F6] hover:bg-[#1D222B] disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Pencil className="h-3.5 w-3.5 text-[#9CA3AF]" />
                    Rename
                  </button>
                  <button
                    type="button"
                    disabled={!currentWorkflowId}
                    onClick={() => void handleDeleteCurrent()}
                    className="col-span-2 inline-flex items-center gap-1.5 rounded px-2.5 py-1.5 text-xs font-medium text-rose-400 hover:bg-rose-500/10 disabled:cursor-not-allowed disabled:opacity-40"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                    Delete Workflow
                  </button>
                </div>
              </div>
            )}
          </div>

          <div className="h-4 w-px bg-[#232830]" />

          <button
            type="button"
            onClick={requestFitView}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-[#232830] bg-[#161A20] px-2.5 text-xs font-medium text-[#9CA3AF] transition hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
          >
            <Maximize2 className="h-3.5 w-3.5" />
            <span>Fit View</span>
          </button>

          <button
            type="button"
            onClick={() => void handleValidate()}
            className={`inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition ${
              validatedOk
                ? "border-[#3ECF8E]/40 bg-[#3ECF8E]/10 text-[#3ECF8E]"
                : "border-[#232830] bg-[#161A20] text-[#9CA3AF] hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
            }`}
          >
            <CheckCircle2 className={`h-3.5 w-3.5 ${validatedOk ? "text-[#3ECF8E]" : "text-[#3ECF8E]"}`} />
            <span>{validatedOk ? "Valid" : "Validate"}</span>
          </button>
        </div>

        {/* Right: Status Pill, Live Traffic, Start/Apply, Stop */}
        <div className="flex flex-wrap items-center gap-2">
          <div
            className={`inline-flex h-7 items-center gap-1.5 rounded-md border px-2.5 text-[11px] font-medium ${statusMeta.pillClass}`}
          >
            <span className={`h-1.5 w-1.5 rounded-full ${statusMeta.dotClass}`} />
            <span>{statusMeta.label}</span>
          </div>

          <button
            type="button"
            onClick={toggleTrafficDrawer}
            aria-pressed={isTrafficDrawerOpen}
            className={`inline-flex h-8 items-center gap-1.5 rounded-md border px-2.5 text-xs font-medium transition ${
              isTrafficDrawerOpen
                ? "border-[#14B8A6]/50 bg-[#14B8A6]/10 text-[#2DD4BF]"
                : "border-[#232830] bg-[#161A20] text-[#9CA3AF] hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
            }`}
          >
            <Activity className="h-3.5 w-3.5" />
            <span>Live Traffic</span>
            {liveConnections.length > 0 && (
              <span className="rounded bg-[#232830] px-1.5 py-0.5 font-mono text-[10px] text-[#F3F4F6]">
                {liveConnections.length}
              </span>
            )}
          </button>

          <button
            type="button"
            disabled={engineStatus.state === "stopped"}
            onClick={() => void stopRouting()}
            className="inline-flex h-8 items-center gap-1.5 rounded-md border border-[#232830] bg-[#161A20] px-2.5 text-xs font-medium text-[#9CA3AF] transition hover:border-rose-500/40 hover:bg-rose-500/10 hover:text-rose-300 disabled:cursor-not-allowed disabled:opacity-40"
          >
            <Square className="h-3.5 w-3.5" />
            <span>Stop</span>
          </button>

          <button
            type="button"
            disabled={applyingNow}
            onClick={() => void applyCurrentWorkflow()}
            className={`inline-flex h-8 items-center gap-1.5 rounded-md px-3.5 text-xs font-semibold text-[#0B0D10] transition disabled:cursor-not-allowed disabled:opacity-50 ${
              hasUnappliedChanges && !applyingNow
                ? "bg-amber-400 hover:bg-amber-300"
                : "bg-[#3ECF8E] hover:bg-[#34B87E]"
            }`}
          >
            <Play className="h-3.5 w-3.5 fill-current" />
            <span>
              {applyingNow
                ? "Applying..."
                : hasUnappliedChanges
                  ? "Apply Changes"
                  : "Start / Apply"}
            </span>
          </button>

          <div className="relative">
            <button
              type="button"
              aria-label="Settings"
              aria-expanded={settingsOpen}
              title="Settings"
              onClick={() => {
                setSettingsOpen((prev) => !prev);
                setMenuOpen(false);
              }}
              className={`inline-flex h-8 w-8 items-center justify-center rounded-md border transition ${
                settingsOpen
                  ? "border-[#3ECF8E]/50 bg-[#1D222B] text-[#3ECF8E]"
                  : "border-[#232830] bg-[#161A20] text-[#9CA3AF] hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
              }`}
            >
              <Settings className="h-3.5 w-3.5" />
            </button>

            {settingsOpen && (
              <div
                role="dialog"
                aria-label="Application Settings"
                className="absolute right-0 mt-1.5 w-80 rounded-md border border-[#2E3540] bg-[#111418] p-3 shadow-lg shadow-black/40"
              >
                <div className="mb-2.5 flex items-center justify-between">
                  <span className="text-[11px] font-semibold uppercase tracking-wider text-[#9CA3AF]">
                    Settings
                  </span>
                  <button
                    type="button"
                    aria-label="Close settings"
                    onClick={() => setSettingsOpen(false)}
                    className="rounded p-0.5 text-[#6B7280] hover:text-[#F3F4F6]"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>

                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-xs font-medium text-[#F3F4F6]">
                        Start with Windows
                      </div>
                      <div className="text-[11px] text-[#6B7280]">
                        Launch minimized in the system tray at sign-in
                      </div>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-label="Start with Windows"
                      aria-checked={appSettings.startWithWindows}
                      disabled={isUpdatingSettings}
                      onClick={() =>
                        void handleToggleSetting(
                          "startWithWindows",
                          !appSettings.startWithWindows
                        )
                      }
                      className={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border transition disabled:cursor-not-allowed disabled:opacity-50 ${
                        appSettings.startWithWindows
                          ? "border-[#3ECF8E] bg-[#3ECF8E]/30"
                          : "border-[#2E3540] bg-[#161A20]"
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full transition ${
                          appSettings.startWithWindows
                            ? "translate-x-4 bg-[#3ECF8E]"
                            : "translate-x-0.5 bg-[#6B7280]"
                        }`}
                      />
                    </button>
                  </div>

                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-xs font-medium text-[#F3F4F6]">
                        Auto-apply last workflow
                      </div>
                      <div className="text-[11px] text-[#6B7280]">
                        Restore routing automatically when launched at startup
                      </div>
                    </div>
                    <button
                      type="button"
                      role="switch"
                      aria-label="Auto-apply last workflow"
                      aria-checked={appSettings.autoApplyLastWorkflow}
                      disabled={isUpdatingSettings}
                      onClick={() =>
                        void handleToggleSetting(
                          "autoApplyLastWorkflow",
                          !appSettings.autoApplyLastWorkflow
                        )
                      }
                      className={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border transition disabled:cursor-not-allowed disabled:opacity-50 ${
                        appSettings.autoApplyLastWorkflow
                          ? "border-[#3ECF8E] bg-[#3ECF8E]/30"
                          : "border-[#2E3540] bg-[#161A20]"
                      }`}
                    >
                      <span
                        className={`inline-block h-3.5 w-3.5 transform rounded-full transition ${
                          appSettings.autoApplyLastWorkflow
                            ? "translate-x-4 bg-[#3ECF8E]"
                            : "translate-x-0.5 bg-[#6B7280]"
                        }`}
                      />
                    </button>
                  </div>
                </div>

                <div className="mt-3 border-t border-[#232830] pt-2.5 text-[11px] leading-relaxed text-[#6B7280]">
                  Closing the window (X) minimizes NetFlow to the System Tray. Exit from the tray icon menu.
                </div>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Inline Workflow Name Prompt (New / Save As / Rename) */}
      {promptMode && (
        <form
          onSubmit={(e) => void handlePromptSubmit(e)}
          className="flex items-center gap-2 border-t border-[#232830] bg-[#0B0D10] px-4 py-2 text-xs"
        >
          <span className="font-medium text-[#9CA3AF]">
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
            className="w-64 rounded border border-[#232830] bg-[#161A20] px-2.5 py-1 text-xs text-[#F3F4F6] outline-none focus:border-[#3ECF8E]"
          />
          <button
            type="submit"
            className="inline-flex items-center gap-1 rounded bg-[#3ECF8E] px-2.5 py-1 font-semibold text-[#0B0D10] hover:bg-[#34B87E]"
          >
            <Check className="h-3.5 w-3.5" />
            Confirm
          </button>
          <button
            type="button"
            onClick={() => setPromptMode(null)}
            className="inline-flex items-center gap-1 rounded border border-[#232830] bg-[#161A20] px-2.5 py-1 text-[#9CA3AF] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
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
              className="rounded bg-amber-500 px-2.5 py-1 font-semibold text-[#0B0D10] hover:bg-amber-400"
            >
              {pendingDiscard.kind === "new" ? "Discard & Continue" : "Discard & Switch"}
            </button>
            <button
              type="button"
              onClick={() => setPendingDiscard(null)}
              className="rounded border border-amber-500/40 px-2.5 py-1 text-amber-200 hover:bg-amber-500/15"
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
            className="inline-flex items-center gap-1 rounded bg-amber-500 px-2.5 py-1 font-semibold text-[#0B0D10] transition hover:bg-amber-400"
          >
            <RefreshCw className="h-3 w-3" />
            Re-Apply
          </button>
        </div>
      )}

      {/* Startup Crash-Recovery Notice */}
      {recoveryNotice && (
        <div className="flex items-center justify-between gap-2 border-t border-teal-500/30 bg-teal-500/10 px-4 py-2 text-xs text-teal-200">
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 shrink-0 text-teal-400" />
            <span>{recoveryNotice}</span>
          </div>
          <button
            type="button"
            aria-label="Dismiss recovery notice"
            onClick={dismissRecoveryNotice}
            className="rounded p-0.5 text-teal-300 hover:bg-teal-500/20"
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
