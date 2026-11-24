import { create } from "zustand";
import * as tauri from "../lib/tauri";
import type {
  DiscoverySnapshot,
  EngineStatus,
  LiveConnection,
  SavedWorkflow,
  SelectWorkflowResult,
  ValidationError,
  VpnNodeSettings,
  WorkflowEdge,
  WorkflowGraph,
  WorkflowNode,
} from "../types/workflow";

const DEFAULT_WORKFLOW_NAME = "Untitled Workflow";

const EMPTY_DISCOVERY: DiscoverySnapshot = {
  interfaces: [],
  vpns: [],
  processes: [],
};

const EMPTY_GRAPH: WorkflowGraph = {
  nodes: [],
  edges: [],
};

const INITIAL_ENGINE_STATUS: EngineStatus = {
  state: "stopped",
  activeWorkflowId: null,
  nodeHealth: {},
  warningBanner: null,
  lastError: null,
};

function cloneGraph(graph: WorkflowGraph): WorkflowGraph {
  return {
    nodes: graph.nodes.map((node) => {
      if (node.kind.type === "vpn") {
        return {
          ...node,
          kind: {
            ...node.kind,
            settings: { ...node.kind.settings },
          },
        };
      }
      if (node.kind.type === "apps") {
        return {
          ...node,
          kind: {
            ...node.kind,
            apps: [...node.kind.apps],
          },
        };
      }
      return {
        ...node,
        kind: { ...node.kind },
      };
    }),
    edges: graph.edges.map((edge) => ({ ...edge })),
  };
}

function generateId(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  return `wf-${Date.now()}-${Math.random().toString(16).slice(2, 10)}`;
}

function upsertWorkflow(workflows: SavedWorkflow[], saved: SavedWorkflow): SavedWorkflow[] {
  const filtered = workflows.filter((w) => w.id !== saved.id);
  return [saved, ...filtered].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
}

function isValidationErrorArray(err: unknown): err is ValidationError[] {
  return (
    Array.isArray(err) &&
    err.every(
      (item) =>
        typeof item === "object" &&
        item !== null &&
        "code" in item &&
        "nodeIds" in item &&
        "message" in item
    )
  );
}

function formatError(err: unknown): string {
  if (typeof err === "string") {
    return err;
  }
  if (err instanceof Error) {
    return err.message;
  }
  if (isValidationErrorArray(err) && err.length > 0) {
    return err[0].message;
  }
  return "An unexpected error occurred.";
}

export function isRoutingActiveState(state: EngineStatus["state"]): boolean {
  return state === "active" || state === "warning" || state === "applying";
}

function clearOtherDefaults(nodes: WorkflowNode[], activeDefaultId: string): WorkflowNode[] {
  return nodes.map((node) => {
    if (node.id === activeDefaultId) {
      return node;
    }
    if (node.kind.type === "interface" || node.kind.type === "vpn") {
      return node.kind.isDefault
        ? { ...node, kind: { ...node.kind, isDefault: false } }
        : node;
    }
    return node;
  });
}

export interface NetFlowStoreState {
  discovery: DiscoverySnapshot;
  workflows: SavedWorkflow[];
  currentWorkflowId: string | null;
  currentWorkflowName: string;
  graph: WorkflowGraph;
  isDirty: boolean;
  validationErrors: ValidationError[];
  engineStatus: EngineStatus;
  liveConnections: LiveConnection[];
  isTrafficDrawerOpen: boolean;
  recoveryNotice: string | null;
  uiError: string | null;
  isApplying: boolean;
  selectedNodeId: string | null;
  fitViewRequestCount: number;

  refreshDiscovery: () => Promise<void>;
  loadWorkflows: () => Promise<void>;
  selectWorkflow: (id: string, options?: { force?: boolean }) => SelectWorkflowResult;
  resetToBlankWorkflow: (options?: { force?: boolean }) => SelectWorkflowResult;
  createWorkflow: (name: string) => Promise<SavedWorkflow | null>;
  saveCurrentWorkflow: () => Promise<SavedWorkflow | null>;
  saveAsWorkflow: (name: string) => Promise<SavedWorkflow | null>;
  renameWorkflow: (id: string, newName: string) => Promise<SavedWorkflow | null>;
  duplicateWorkflow: (id: string, newName: string) => Promise<SavedWorkflow | null>;
  deleteWorkflow: (id: string) => Promise<boolean>;
  applyCurrentWorkflow: () => Promise<boolean>;
  switchAndApplyWorkflow: (
    id: string,
    options?: { force?: boolean }
  ) => Promise<SelectWorkflowResult>;
  stopRouting: () => Promise<void>;
  validateCurrentGraph: () => Promise<boolean>;

  updateGraph: (nodes: WorkflowNode[], edges: WorkflowEdge[]) => void;
  addNode: (node: WorkflowNode) => void;
  removeNode: (nodeId: string) => void;
  updateNodeApps: (nodeId: string, apps: string[]) => void;
  updateVpnSettings: (nodeId: string, settings: Partial<VpnNodeSettings>) => void;
  setDefaultNode: (nodeId: string, isDefault?: boolean) => void;

  setLiveConnections: (connections: LiveConnection[]) => void;
  toggleTrafficDrawer: () => void;
  setSelectedNodeId: (nodeId: string | null) => void;
  requestFitView: () => void;
  dismissRecoveryNotice: () => void;
  clearUiError: () => void;
  hydrateCanvasDraft: () => void;
  initEventListeners: () => Promise<() => void>;
  resetStore: () => void;
}

const CANVAS_DRAFT_STORAGE_KEY = "netflow.canvasDraft.v1";

interface CanvasDraftPayload {
  currentWorkflowId: string | null;
  currentWorkflowName: string;
  graph: WorkflowGraph;
  isDirty: boolean;
}

function readCanvasDraft(): CanvasDraftPayload | null {
  try {
    const raw = globalThis.localStorage?.getItem(CANVAS_DRAFT_STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<CanvasDraftPayload>;
    if (
      !parsed ||
      typeof parsed.currentWorkflowName !== "string" ||
      !parsed.graph ||
      !Array.isArray(parsed.graph.nodes) ||
      !Array.isArray(parsed.graph.edges)
    ) {
      return null;
    }
    return {
      currentWorkflowId:
        typeof parsed.currentWorkflowId === "string" ? parsed.currentWorkflowId : null,
      currentWorkflowName: parsed.currentWorkflowName,
      graph: cloneGraph(parsed.graph),
      isDirty: Boolean(parsed.isDirty),
    };
  } catch {
    return null;
  }
}

function writeCanvasDraft(payload: CanvasDraftPayload): void {
  try {
    globalThis.localStorage?.setItem(CANVAS_DRAFT_STORAGE_KEY, JSON.stringify(payload));
  } catch {
    // Ignore storage quota/unavailable errors
  }
}

function clearCanvasDraft(): void {
  try {
    globalThis.localStorage?.removeItem(CANVAS_DRAFT_STORAGE_KEY);
  } catch {
    // Ignore storage unavailable errors
  }
}

export const useNetFlowStore = create<NetFlowStoreState>((set, get) => ({
  discovery: EMPTY_DISCOVERY,
  workflows: [],
  currentWorkflowId: null,
  currentWorkflowName: DEFAULT_WORKFLOW_NAME,
  graph: cloneGraph(EMPTY_GRAPH),
  isDirty: false,
  validationErrors: [],
  engineStatus: { ...INITIAL_ENGINE_STATUS },
  liveConnections: [],
  isTrafficDrawerOpen: false,
  recoveryNotice: null,
  uiError: null,
  isApplying: false,
  selectedNodeId: null,
  fitViewRequestCount: 0,

  refreshDiscovery: async () => {
    try {
      const snapshot = await tauri.getDiscoverySnapshot();
      set({ discovery: snapshot, uiError: null });
    } catch (err) {
      set({ uiError: formatError(err) });
    }
  },

  loadWorkflows: async () => {
    try {
      const workflows = await tauri.listWorkflows();
      const { currentWorkflowId, isDirty, graph, engineStatus } = get();
      const shouldAutoSelect =
        !currentWorkflowId &&
        !isDirty &&
        graph.nodes.length === 0 &&
        graph.edges.length === 0 &&
        workflows.length > 0;

      if (shouldAutoSelect) {
        const preferred =
          workflows.find((w) => w.id === engineStatus.activeWorkflowId) ?? workflows[0];
        set({
          workflows,
          currentWorkflowId: preferred.id,
          currentWorkflowName: preferred.name,
          graph: cloneGraph(preferred.graph),
          isDirty: false,
          validationErrors: [],
          uiError: null,
        });
      } else {
        set({ workflows, uiError: null });
      }
    } catch (err) {
      set({ uiError: formatError(err) });
    }
  },

  selectWorkflow: (id, options) => {
    const force = options?.force ?? false;
    const { currentWorkflowId, isDirty, workflows } = get();

    if (id === currentWorkflowId && !isDirty) {
      return { switched: true, needsConfirm: false };
    }
    if (isDirty && !force) {
      return { switched: false, needsConfirm: true };
    }

    const target = workflows.find((w) => w.id === id);
    if (!target) {
      set({ uiError: `Workflow '${id}' was not found.` });
      return { switched: false, needsConfirm: false };
    }

    set({
      currentWorkflowId: target.id,
      currentWorkflowName: target.name,
      graph: cloneGraph(target.graph),
      isDirty: false,
      validationErrors: [],
      uiError: null,
      selectedNodeId: null,
    });
    return { switched: true, needsConfirm: false };
  },

  resetToBlankWorkflow: (options) => {
    const force = options?.force ?? false;
    if (get().isDirty && !force) {
      return { switched: false, needsConfirm: true };
    }
    set({
      currentWorkflowId: null,
      currentWorkflowName: DEFAULT_WORKFLOW_NAME,
      graph: cloneGraph(EMPTY_GRAPH),
      isDirty: false,
      validationErrors: [],
      uiError: null,
      selectedNodeId: null,
    });
    return { switched: true, needsConfirm: false };
  },

  createWorkflow: async (name) => {
    const trimmed = name.trim();
    if (!trimmed) {
      set({ uiError: "Workflow name cannot be empty." });
      return null;
    }
    const draft: SavedWorkflow = {
      id: generateId(),
      name: trimmed,
      updatedAt: new Date().toISOString(),
      graph: cloneGraph(EMPTY_GRAPH),
    };
    try {
      const saved = await tauri.saveWorkflow(draft);
      set((state) => ({
        workflows: upsertWorkflow(state.workflows, saved),
        currentWorkflowId: saved.id,
        currentWorkflowName: saved.name,
        graph: cloneGraph(saved.graph),
        isDirty: false,
        validationErrors: [],
        uiError: null,
        selectedNodeId: null,
      }));
      return saved;
    } catch (err) {
      set({ uiError: formatError(err) });
      return null;
    }
  },

  saveCurrentWorkflow: async () => {
    const { currentWorkflowId, currentWorkflowName, graph, workflows } = get();
    const existing = currentWorkflowId
      ? workflows.find((w) => w.id === currentWorkflowId)
      : undefined;

    const payload: SavedWorkflow = {
      id: currentWorkflowId ?? generateId(),
      name: (existing?.name ?? currentWorkflowName).trim() || DEFAULT_WORKFLOW_NAME,
      updatedAt: new Date().toISOString(),
      graph: cloneGraph(graph),
    };

    try {
      const saved = await tauri.saveWorkflow(payload);
      set((state) => ({
        workflows: upsertWorkflow(state.workflows, saved),
        currentWorkflowId: saved.id,
        currentWorkflowName: saved.name,
        isDirty: false,
        uiError: null,
      }));
      return saved;
    } catch (err) {
      set({ uiError: formatError(err) });
      return null;
    }
  },

  saveAsWorkflow: async (name) => {
    const trimmed = name.trim();
    if (!trimmed) {
      set({ uiError: "Workflow name cannot be empty." });
      return null;
    }
    const payload: SavedWorkflow = {
      id: generateId(),
      name: trimmed,
      updatedAt: new Date().toISOString(),
      graph: cloneGraph(get().graph),
    };

    try {
      const saved = await tauri.saveWorkflow(payload);
      set((state) => ({
        workflows: upsertWorkflow(state.workflows, saved),
        currentWorkflowId: saved.id,
        currentWorkflowName: saved.name,
        isDirty: false,
        uiError: null,
      }));
      return saved;
    } catch (err) {
      set({ uiError: formatError(err) });
      return null;
    }
  },

  renameWorkflow: async (id, newName) => {
    const trimmed = newName.trim();
    if (!trimmed) {
      set({ uiError: "Workflow name cannot be empty." });
      return null;
    }
    try {
      const updated = await tauri.renameWorkflow(id, trimmed);
      set((state) => ({
        workflows: upsertWorkflow(state.workflows, updated),
        currentWorkflowName:
          state.currentWorkflowId === id ? updated.name : state.currentWorkflowName,
        uiError: null,
      }));
      return updated;
    } catch (err) {
      set({ uiError: formatError(err) });
      return null;
    }
  },

  duplicateWorkflow: async (id, newName) => {
    const trimmed = newName.trim();
    if (!trimmed) {
      set({ uiError: "Workflow name cannot be empty." });
      return null;
    }
    try {
      const duplicated = await tauri.duplicateWorkflow(id, trimmed);
      set((state) => ({
        workflows: upsertWorkflow(state.workflows, duplicated),
        uiError: null,
      }));
      return duplicated;
    } catch (err) {
      set({ uiError: formatError(err) });
      return null;
    }
  },

  deleteWorkflow: async (id) => {
    const { engineStatus, workflows, currentWorkflowId } = get();
    if (isRoutingActiveState(engineStatus.state) && id === engineStatus.activeWorkflowId) {
      set({
        uiError:
          "Cannot delete the active workflow while routing is running. Stop routing first, then delete the workflow.",
      });
      return false;
    }

    try {
      await tauri.deleteWorkflow(id);
      const remaining = workflows.filter((w) => w.id !== id);
      if (currentWorkflowId === id) {
        if (remaining.length > 0) {
          const next = remaining[0];
          set({
            workflows: remaining,
            currentWorkflowId: next.id,
            currentWorkflowName: next.name,
            graph: cloneGraph(next.graph),
            isDirty: false,
            validationErrors: [],
            uiError: null,
            selectedNodeId: null,
          });
        } else {
          set({
            workflows: [],
            currentWorkflowId: null,
            currentWorkflowName: DEFAULT_WORKFLOW_NAME,
            graph: cloneGraph(EMPTY_GRAPH),
            isDirty: false,
            validationErrors: [],
            uiError: null,
            selectedNodeId: null,
          });
        }
      } else {
        set({ workflows: remaining, uiError: null });
      }
      return true;
    } catch (err) {
      set({ uiError: formatError(err) });
      return false;
    }
  },

  validateCurrentGraph: async () => {
    try {
      await tauri.validateWorkflowGraph(get().graph);
      set({ validationErrors: [] });
      return true;
    } catch (err) {
      if (isValidationErrorArray(err)) {
        set({
          validationErrors: err,
          uiError: err[0]?.message ?? "Workflow validation failed.",
        });
      } else {
        set({ uiError: formatError(err) });
      }
      return false;
    }
  },

  applyCurrentWorkflow: async () => {
    set({ isApplying: true, uiError: null });
    const valid = await get().validateCurrentGraph();
    if (!valid) {
      set({ isApplying: false });
      return false;
    }

    const { currentWorkflowId, graph } = get();
    try {
      const status = await tauri.applyWorkflow(currentWorkflowId, graph);
      set({ engineStatus: status, isApplying: false, uiError: null });
      return true;
    } catch (err) {
      set({ isApplying: false, uiError: formatError(err) });
      return false;
    }
  },

  switchAndApplyWorkflow: async (id, options) => {
    const selection = get().selectWorkflow(id, options);
    if (!selection.switched) {
      return selection;
    }

    await get().applyCurrentWorkflow();
    return selection;
  },

  stopRouting: async () => {
    try {
      const status = await tauri.stopRouting();
      set({ engineStatus: status, uiError: null });
    } catch (err) {
      set({ uiError: formatError(err) });
    }
  },

  updateGraph: (nodes, edges) => {
    set({
      graph: { nodes, edges },
      isDirty: true,
    });
  },

  addNode: (node) => {
    set((state) => {
      const baseNodes = [...state.graph.nodes, node];
      const hasDefault =
        (node.kind.type === "interface" || node.kind.type === "vpn") && node.kind.isDefault;
      const nodes = hasDefault ? clearOtherDefaults(baseNodes, node.id) : baseNodes;
      return {
        graph: { ...state.graph, nodes },
        isDirty: true,
      };
    });
  },

  removeNode: (nodeId) => {
    set((state) => ({
      graph: {
        nodes: state.graph.nodes.filter((n) => n.id !== nodeId),
        edges: state.graph.edges.filter(
          (e) => e.source !== nodeId && e.target !== nodeId
        ),
      },
      isDirty: true,
      selectedNodeId: state.selectedNodeId === nodeId ? null : state.selectedNodeId,
    }));
  },

  updateNodeApps: (nodeId, apps) => {
    set((state) => ({
      graph: {
        ...state.graph,
        nodes: state.graph.nodes.map((node) =>
          node.id === nodeId && node.kind.type === "apps"
            ? { ...node, kind: { ...node.kind, apps: [...apps] } }
            : node
        ),
      },
      isDirty: true,
    }));
  },

  updateVpnSettings: (nodeId, settings) => {
    set((state) => ({
      graph: {
        ...state.graph,
        nodes: state.graph.nodes.map((node) =>
          node.id === nodeId && node.kind.type === "vpn"
            ? {
                ...node,
                kind: {
                  ...node.kind,
                  settings: { ...node.kind.settings, ...settings },
                },
              }
            : node
        ),
      },
      isDirty: true,
    }));
  },

  setDefaultNode: (nodeId, explicitDefault) => {
    set((state) => {
      const target = state.graph.nodes.find((n) => n.id === nodeId);
      if (!target || (target.kind.type !== "interface" && target.kind.type !== "vpn")) {
        return state;
      }
      const nextDefault = explicitDefault ?? !target.kind.isDefault;
      const updatedNodes = state.graph.nodes.map((node) => {
        if (node.kind.type !== "interface" && node.kind.type !== "vpn") {
          return node;
        }
        if (node.id === nodeId) {
          return { ...node, kind: { ...node.kind, isDefault: nextDefault } };
        }
        if (nextDefault && node.kind.isDefault) {
          return { ...node, kind: { ...node.kind, isDefault: false } };
        }
        return node;
      });
      return {
        graph: { ...state.graph, nodes: updatedNodes },
        isDirty: true,
      };
    });
  },

  setLiveConnections: (connections) => {
    set({ liveConnections: connections });
  },

  toggleTrafficDrawer: () => {
    set((state) => ({ isTrafficDrawerOpen: !state.isTrafficDrawerOpen }));
  },

  setSelectedNodeId: (nodeId) => {
    set({ selectedNodeId: nodeId });
  },

  requestFitView: () => {
    set((state) => ({ fitViewRequestCount: state.fitViewRequestCount + 1 }));
  },

  dismissRecoveryNotice: () => {
    set({ recoveryNotice: null });
  },

  clearUiError: () => {
    set({ uiError: null });
  },

  initEventListeners: async () => {
    const [unlistenStatus, unlistenTraffic, unlistenRecovery, initialStatus, notice] =
      await Promise.all([
        tauri.onStatusChanged((status) => {
          set({ engineStatus: status });
        }),
        tauri.onTrafficUpdated((connections) => {
          set({ liveConnections: connections });
        }),
        tauri.onRecoveryNotice((recoveryNotice) => {
          set({ recoveryNotice });
        }),
        tauri.getEngineStatus().catch(() => null),
        tauri.takeRecoveryNotice().catch(() => null),
      ]);

    set((state) => ({
      engineStatus: initialStatus ?? state.engineStatus,
      recoveryNotice: notice ?? state.recoveryNotice,
    }));

    return () => {
      unlistenStatus();
      unlistenTraffic();
      unlistenRecovery();
    };
  },

  hydrateCanvasDraft: () => {
    const draft = readCanvasDraft();
    if (!draft) return;
    if (draft.graph.nodes.length === 0 && draft.graph.edges.length === 0 && !draft.currentWorkflowId) {
      return;
    }
    set({
      currentWorkflowId: draft.currentWorkflowId,
      currentWorkflowName: draft.currentWorkflowName,
      graph: cloneGraph(draft.graph),
      isDirty: draft.isDirty,
    });
  },

  resetStore: () => {
    clearCanvasDraft();
    set({
      discovery: EMPTY_DISCOVERY,
      workflows: [],
      currentWorkflowId: null,
      currentWorkflowName: DEFAULT_WORKFLOW_NAME,
      graph: cloneGraph(EMPTY_GRAPH),
      isDirty: false,
      validationErrors: [],
      engineStatus: { ...INITIAL_ENGINE_STATUS },
      liveConnections: [],
      isTrafficDrawerOpen: false,
      recoveryNotice: null,
      uiError: null,
      isApplying: false,
      selectedNodeId: null,
      fitViewRequestCount: 0,
    });
  },
}));

useNetFlowStore.subscribe((state, prevState) => {
  if (
    state.graph !== prevState.graph ||
    state.currentWorkflowId !== prevState.currentWorkflowId ||
    state.currentWorkflowName !== prevState.currentWorkflowName ||
    state.isDirty !== prevState.isDirty
  ) {
    writeCanvasDraft({
      currentWorkflowId: state.currentWorkflowId,
      currentWorkflowName: state.currentWorkflowName,
      graph: state.graph,
      isDirty: state.isDirty,
    });
  }
});
