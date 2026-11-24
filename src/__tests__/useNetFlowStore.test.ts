import { beforeEach, describe, expect, it, vi } from "vitest";
import type {
  DiscoverySnapshot,
  EngineStatus,
  LiveConnection,
  SavedWorkflow,
  ValidationError,
  WorkflowGraph,
} from "../types/workflow";

const mockTauri = vi.hoisted(() => ({
  getDiscoverySnapshot: vi.fn(),
  validateWorkflowGraph: vi.fn(),
  listWorkflows: vi.fn(),
  saveWorkflow: vi.fn(),
  renameWorkflow: vi.fn(),
  duplicateWorkflow: vi.fn(),
  deleteWorkflow: vi.fn(),
  applyWorkflow: vi.fn(),
  stopRouting: vi.fn(),
  getEngineStatus: vi.fn(),
  takeRecoveryNotice: vi.fn(),
  onStatusChanged: vi.fn(),
  onTrafficUpdated: vi.fn(),
  onRecoveryNotice: vi.fn(),
}));

vi.mock("../lib/tauri", () => mockTauri);

import { useNetFlowStore } from "../store/useNetFlowStore";

const makeGraph = (overrides?: Partial<WorkflowGraph>): WorkflowGraph => ({
  nodes: [
    {
      id: "iface-wifi",
      x: 100,
      y: 100,
      kind: { type: "interface", interfaceAlias: "Wi-Fi", isDefault: true },
    },
    {
      id: "vpn-karing",
      x: 300,
      y: 100,
      kind: {
        type: "vpn",
        provider: "karing",
        isDefault: false,
        settings: {
          karingPortOverride: null,
          openvpnAdapterOverride: null,
          openvpnServerIpOverride: null,
        },
      },
    },
    {
      id: "apps-1",
      x: 520,
      y: 100,
      kind: { type: "apps", apps: ["chrome.exe"] },
    },
  ],
  edges: [
    { id: "e1", source: "iface-wifi", target: "vpn-karing" },
    { id: "e2", source: "vpn-karing", target: "apps-1" },
  ],
  ...overrides,
});

const wfA: SavedWorkflow = {
  id: "wf-a",
  name: "Work VPN",
  updatedAt: "2026-11-24T05:00:00Z",
  graph: makeGraph(),
};

const wfB: SavedWorkflow = {
  id: "wf-b",
  name: "Gaming Direct",
  updatedAt: "2026-11-24T04:00:00Z",
  graph: {
    nodes: [
      {
        id: "iface-eth",
        x: 100,
        y: 100,
        kind: { type: "interface", interfaceAlias: "Ethernet", isDefault: true },
      },
    ],
    edges: [],
  },
};

const stoppedStatus: EngineStatus = {
  state: "stopped",
  activeWorkflowId: null,
  nodeHealth: {},
  warningBanner: null,
  lastError: null,
};

const activeStatus = (workflowId: string): EngineStatus => ({
  state: "active",
  activeWorkflowId: workflowId,
  nodeHealth: { "iface-wifi": "healthy", "vpn-karing": "healthy" },
  warningBanner: null,
  lastError: null,
});

describe("useNetFlowStore", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useNetFlowStore.getState().resetStore();

    mockTauri.validateWorkflowGraph.mockResolvedValue(null);
    mockTauri.getEngineStatus.mockResolvedValue(stoppedStatus);
    mockTauri.takeRecoveryNotice.mockResolvedValue(null);
    mockTauri.onStatusChanged.mockResolvedValue(() => {});
    mockTauri.onTrafficUpdated.mockResolvedValue(() => {});
    mockTauri.onRecoveryNotice.mockResolvedValue(() => {});
  });

  it("test_marks_dirty_on_graph_edit_and_guards_unsaved_switch", async () => {
    mockTauri.listWorkflows.mockResolvedValue([wfA, wfB]);
    await useNetFlowStore.getState().loadWorkflows();

    expect(useNetFlowStore.getState().currentWorkflowId).toBe("wf-a");
    expect(useNetFlowStore.getState().isDirty).toBe(false);

    // Edit graph
    const editedNodes = useNetFlowStore.getState().graph.nodes.map((n) =>
      n.id === "apps-1" ? { ...n, x: 600 } : n
    );
    useNetFlowStore.getState().updateGraph(editedNodes, useNetFlowStore.getState().graph.edges);

    expect(useNetFlowStore.getState().isDirty).toBe(true);

    // Attempt to switch without force -> blocked with needsConfirm: true
    const guarded = useNetFlowStore.getState().selectWorkflow("wf-b");
    expect(guarded).toEqual({ switched: false, needsConfirm: true });
    expect(useNetFlowStore.getState().currentWorkflowId).toBe("wf-a");
    expect(useNetFlowStore.getState().isDirty).toBe(true);
    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "apps-1")?.x
    ).toBe(600);

    // Force switch -> discards edits and switches cleanly
    const forced = useNetFlowStore.getState().selectWorkflow("wf-b", { force: true });
    expect(forced).toEqual({ switched: true, needsConfirm: false });
    expect(useNetFlowStore.getState().currentWorkflowId).toBe("wf-b");
    expect(useNetFlowStore.getState().currentWorkflowName).toBe("Gaming Direct");
    expect(useNetFlowStore.getState().isDirty).toBe(false);
    expect(useNetFlowStore.getState().graph.nodes).toHaveLength(1);
  });

  it("test_switch_and_apply_while_active_invokes_apply_with_new_workflow", async () => {
    mockTauri.listWorkflows.mockResolvedValue([wfA, wfB]);
    mockTauri.applyWorkflow.mockResolvedValue(activeStatus("wf-b"));

    await useNetFlowStore.getState().loadWorkflows();
    useNetFlowStore.setState({ engineStatus: activeStatus("wf-a") });

    const result = await useNetFlowStore.getState().switchAndApplyWorkflow("wf-b");

    expect(result).toEqual({ switched: true, needsConfirm: false });
    expect(mockTauri.stopRouting).not.toHaveBeenCalled();
    expect(mockTauri.validateWorkflowGraph).toHaveBeenCalledTimes(1);
    expect(mockTauri.validateWorkflowGraph).toHaveBeenCalledWith(wfB.graph);
    expect(mockTauri.applyWorkflow).toHaveBeenCalledTimes(1);
    expect(mockTauri.applyWorkflow).toHaveBeenCalledWith("wf-b", wfB.graph);
    expect(useNetFlowStore.getState().currentWorkflowId).toBe("wf-b");
    expect(useNetFlowStore.getState().engineStatus.activeWorkflowId).toBe("wf-b");
    expect(useNetFlowStore.getState().engineStatus.state).toBe("active");
  });

  it("test_switch_and_apply_validates_target_workflow_before_applying", async () => {
    mockTauri.listWorkflows.mockResolvedValue([wfA, wfB]);
    await useNetFlowStore.getState().loadWorkflows();
    useNetFlowStore.setState({ engineStatus: activeStatus("wf-a") });

    const errors: ValidationError[] = [
      {
        code: "missingUpstreamInterface",
        nodeIds: ["iface-eth"],
        message: "Target workflow is invalid.",
      },
    ];
    mockTauri.validateWorkflowGraph.mockRejectedValueOnce(errors);

    const result = await useNetFlowStore.getState().switchAndApplyWorkflow("wf-b");
    expect(result).toEqual({ switched: true, needsConfirm: false });
    expect(mockTauri.validateWorkflowGraph).toHaveBeenCalledWith(wfB.graph);
    expect(mockTauri.applyWorkflow).not.toHaveBeenCalled();
    expect(useNetFlowStore.getState().validationErrors).toEqual(errors);
    expect(useNetFlowStore.getState().uiError).toBe("Target workflow is invalid.");
    expect(useNetFlowStore.getState().isApplying).toBe(false);
  });

  it("test_deleting_active_workflow_stops_or_blocks_cleanly", async () => {
    mockTauri.listWorkflows.mockResolvedValue([wfA, wfB]);
    mockTauri.deleteWorkflow.mockResolvedValue(null);

    await useNetFlowStore.getState().loadWorkflows();
    useNetFlowStore.setState({ engineStatus: activeStatus("wf-a") });

    // While routing is active on wf-a, deletion must be blocked with actionable uiError
    const blocked = await useNetFlowStore.getState().deleteWorkflow("wf-a");
    expect(blocked).toBe(false);
    expect(mockTauri.deleteWorkflow).not.toHaveBeenCalled();
    expect(useNetFlowStore.getState().uiError).toMatch(/stop/i);
    expect(useNetFlowStore.getState().workflows).toHaveLength(2);

    // Once stopped, deletion succeeds and selects next available workflow
    useNetFlowStore.setState({ engineStatus: stoppedStatus });
    const deletedFirst = await useNetFlowStore.getState().deleteWorkflow("wf-a");
    expect(deletedFirst).toBe(true);
    expect(mockTauri.deleteWorkflow).toHaveBeenCalledWith("wf-a");
    expect(useNetFlowStore.getState().workflows.map((w) => w.id)).toEqual(["wf-b"]);
    expect(useNetFlowStore.getState().currentWorkflowId).toBe("wf-b");
    expect(useNetFlowStore.getState().uiError).toBeNull();

    // Deleting the last remaining workflow resets to a clean blank canvas
    const deletedLast = await useNetFlowStore.getState().deleteWorkflow("wf-b");
    expect(deletedLast).toBe(true);
    expect(useNetFlowStore.getState().workflows).toEqual([]);
    expect(useNetFlowStore.getState().currentWorkflowId).toBeNull();
    expect(useNetFlowStore.getState().graph).toEqual({ nodes: [], edges: [] });
    expect(useNetFlowStore.getState().isDirty).toBe(false);
  });

  it("test_set_default_node_enforces_at_most_one_default", async () => {
    mockTauri.listWorkflows.mockResolvedValue([wfA]);
    await useNetFlowStore.getState().loadWorkflows();

    // Initially iface-wifi is default, vpn-karing is not
    const initialNodes = useNetFlowStore.getState().graph.nodes;
    const wifiBefore = initialNodes.find((n) => n.id === "iface-wifi");
    const vpnBefore = initialNodes.find((n) => n.id === "vpn-karing");
    expect(wifiBefore?.kind.type === "interface" && wifiBefore.kind.isDefault).toBe(true);
    expect(vpnBefore?.kind.type === "vpn" && vpnBefore.kind.isDefault).toBe(false);

    // Setting default on VPN node clears default from Interface node
    useNetFlowStore.getState().setDefaultNode("vpn-karing");

    const updatedNodes = useNetFlowStore.getState().graph.nodes;
    const wifiAfter = updatedNodes.find((n) => n.id === "iface-wifi");
    const vpnAfter = updatedNodes.find((n) => n.id === "vpn-karing");
    expect(wifiAfter?.kind.type === "interface" && wifiAfter.kind.isDefault).toBe(false);
    expect(vpnAfter?.kind.type === "vpn" && vpnAfter.kind.isDefault).toBe(true);
    expect(useNetFlowStore.getState().isDirty).toBe(true);

    // Toggling the already-default VPN node clears it (0 defaults is valid)
    useNetFlowStore.getState().setDefaultNode("vpn-karing");
    const clearedNodes = useNetFlowStore.getState().graph.nodes;
    const vpnCleared = clearedNodes.find((n) => n.id === "vpn-karing");
    expect(vpnCleared?.kind.type === "vpn" && vpnCleared.kind.isDefault).toBe(false);
  });

  it("test_init_event_listeners_loads_recovery_notice_and_subscribes_to_events", async () => {
    let statusCb: ((s: EngineStatus) => void) | undefined;
    let trafficCb: ((c: LiveConnection[]) => void) | undefined;
    let recoveryCb: ((n: string) => void) | undefined;

    mockTauri.takeRecoveryNotice.mockResolvedValue("Recovered stale proxy settings.");
    mockTauri.getEngineStatus.mockResolvedValue(stoppedStatus);
    mockTauri.onStatusChanged.mockImplementation(async (cb) => {
      statusCb = cb;
      return vi.fn();
    });
    mockTauri.onTrafficUpdated.mockImplementation(async (cb) => {
      trafficCb = cb;
      return vi.fn();
    });
    mockTauri.onRecoveryNotice.mockImplementation(async (cb) => {
      recoveryCb = cb;
      return vi.fn();
    });

    const unlisten = await useNetFlowStore.getState().initEventListeners();

    expect(useNetFlowStore.getState().recoveryNotice).toBe("Recovered stale proxy settings.");

    statusCb?.(activeStatus("wf-a"));
    expect(useNetFlowStore.getState().engineStatus.state).toBe("active");

    const conn: LiveConnection = {
      id: "conn-1",
      processName: "chrome.exe",
      destination: "1.1.1.1:443",
      network: "tcp",
      outboundTag: "vpn-karing",
      nodeId: "vpn-karing",
      uploadBytes: 120,
      downloadBytes: 540,
    };
    trafficCb?.([conn]);
    expect(useNetFlowStore.getState().liveConnections).toEqual([conn]);

    useNetFlowStore.getState().dismissRecoveryNotice();
    expect(useNetFlowStore.getState().recoveryNotice).toBeNull();

    recoveryCb?.("Late recovery notice");
    expect(useNetFlowStore.getState().recoveryNotice).toBe("Late recovery notice");

    useNetFlowStore.getState().toggleTrafficDrawer();
    expect(useNetFlowStore.getState().isTrafficDrawerOpen).toBe(true);

    unlisten();
  });

  it("test_apply_current_workflow_blocks_on_validation_errors", async () => {
    mockTauri.listWorkflows.mockResolvedValue([wfA]);
    await useNetFlowStore.getState().loadWorkflows();

    const errors: ValidationError[] = [
      {
        code: "duplicateAppAssignment",
        nodeIds: ["apps-1"],
        message: "chrome.exe is assigned to multiple paths.",
      },
    ];
    mockTauri.validateWorkflowGraph.mockRejectedValue(errors);

    const applied = await useNetFlowStore.getState().applyCurrentWorkflow();
    expect(applied).toBe(false);
    expect(mockTauri.applyWorkflow).not.toHaveBeenCalled();
    expect(useNetFlowStore.getState().validationErrors).toEqual(errors);
    expect(useNetFlowStore.getState().uiError).toContain("chrome.exe");
  });

  it("test_save_as_and_rename_and_node_helpers", async () => {
    const snapshot: DiscoverySnapshot = {
      interfaces: [
        {
          alias: "Wi-Fi",
          description: "Intel Wi-Fi",
          ifIndex: 12,
          ipv4: "192.168.1.5",
          gatewayIpv4: "192.168.1.1",
          isUp: true,
          linkSpeedMbps: 866,
          isDefaultGateway: true,
        },
      ],
      vpns: [],
      processes: [{ exeName: "chrome.exe", path: null }],
    };
    mockTauri.getDiscoverySnapshot.mockResolvedValue(snapshot);
    await useNetFlowStore.getState().refreshDiscovery();
    expect(useNetFlowStore.getState().discovery).toEqual(snapshot);

    mockTauri.listWorkflows.mockResolvedValue([wfA]);
    await useNetFlowStore.getState().loadWorkflows();

    useNetFlowStore.getState().updateNodeApps("apps-1", ["chrome.exe", "discord.exe"]);
    useNetFlowStore.getState().updateVpnSettings("vpn-karing", { karingPortOverride: 7890 });
    expect(useNetFlowStore.getState().isDirty).toBe(true);

    const savedAs: SavedWorkflow = {
      id: "wf-copy",
      name: "Work VPN Copy",
      updatedAt: "2026-11-24T06:00:00Z",
      graph: useNetFlowStore.getState().graph,
    };
    mockTauri.saveWorkflow.mockResolvedValue(savedAs);

    const result = await useNetFlowStore.getState().saveAsWorkflow("Work VPN Copy");
    expect(result?.id).toBe("wf-copy");
    expect(useNetFlowStore.getState().currentWorkflowId).toBe("wf-copy");
    expect(useNetFlowStore.getState().isDirty).toBe(false);

    mockTauri.renameWorkflow.mockResolvedValue({ ...savedAs, name: "Renamed Flow" });
    await useNetFlowStore.getState().renameWorkflow("wf-copy", "Renamed Flow");
    expect(useNetFlowStore.getState().currentWorkflowName).toBe("Renamed Flow");
  });
});
