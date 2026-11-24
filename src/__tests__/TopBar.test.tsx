import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { EngineStatus, SavedWorkflow } from "../types/workflow";

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

import { TopBar } from "../components/TopBar";
import { useNetFlowStore } from "../store/useNetFlowStore";

const wfA: SavedWorkflow = {
  id: "wf-a",
  name: "Work VPN",
  updatedAt: "2026-11-24T05:00:00Z",
  graph: {
    nodes: [
      {
        id: "iface-wifi",
        x: 100,
        y: 100,
        kind: { type: "interface", interfaceAlias: "Wi-Fi", isDefault: true },
      },
    ],
    edges: [],
  },
};

const wfB: SavedWorkflow = {
  id: "wf-b",
  name: "Direct Gaming",
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

const activeStatus: EngineStatus = {
  state: "active",
  activeWorkflowId: "wf-a",
  nodeHealth: { "iface-wifi": "healthy" },
  warningBanner: null,
  lastError: null,
};

describe("TopBar", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useNetFlowStore.getState().resetStore();
    mockTauri.validateWorkflowGraph.mockResolvedValue(null);
    mockTauri.applyWorkflow.mockResolvedValue(activeStatus);
    mockTauri.stopRouting.mockResolvedValue({
      state: "stopped",
      activeWorkflowId: null,
      nodeHealth: {},
      warningBanner: null,
      lastError: null,
    });
  });

  afterEach(() => {
    cleanup();
  });

  it("shows dirty indicator, guards unsaved switch, and allows Switch & Apply when active", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      workflows: [wfA, wfB],
      currentWorkflowId: wfA.id,
      currentWorkflowName: wfA.name,
      graph: wfA.graph,
      isDirty: true,
      engineStatus: activeStatus,
    });

    render(<TopBar />);

    const switcher = screen.getByRole("button", { name: "Workflow Switcher" });
    expect(switcher.textContent).toContain("Work VPN *");
    expect(screen.getByText("Active")).toBeTruthy();

    await user.click(switcher);

    // Switch & Apply button appears for non-active workflow while routing is active
    const switchAndApplyBtn = screen.getByRole("button", { name: /Switch & Apply/i });
    await user.click(switchAndApplyBtn);

    // Dirty guard prompt appears instead of discarding edits immediately
    expect(screen.getByText(/You have unsaved changes/i)).toBeTruthy();
    expect(mockTauri.applyWorkflow).not.toHaveBeenCalled();

    // Confirming discards and calls applyWorkflow for wf-b directly
    mockTauri.applyWorkflow.mockResolvedValue({ ...activeStatus, activeWorkflowId: "wf-b" });
    await user.click(screen.getByRole("button", { name: /Discard & Switch/i }));

    expect(mockTauri.stopRouting).not.toHaveBeenCalled();
    expect(mockTauri.applyWorkflow).toHaveBeenCalledWith("wf-b", wfB.graph);
  });

  it("renders warning banner with Re-Apply, recovery notice dismiss, and traffic toggle", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      workflows: [wfA],
      currentWorkflowId: wfA.id,
      currentWorkflowName: wfA.name,
      graph: wfA.graph,
      recoveryNotice: "Recovered stale system proxy on startup.",
      engineStatus: {
        state: "warning",
        activeWorkflowId: "wf-a",
        nodeHealth: { "iface-wifi": "dropped" },
        warningBanner: "Wi-Fi interface disconnected.",
        lastError: null,
      },
    });

    render(<TopBar />);

    expect(screen.getByText("Warning")).toBeTruthy();
    expect(screen.getByText("Wi-Fi interface disconnected.")).toBeTruthy();
    expect(screen.getByText("Recovered stale system proxy on startup.")).toBeTruthy();

    await user.click(screen.getByRole("button", { name: /Re-Apply/i }));
    expect(mockTauri.applyWorkflow).toHaveBeenCalledWith("wf-a", wfA.graph);

    await user.click(screen.getByRole("button", { name: "Dismiss recovery notice" }));
    expect(useNetFlowStore.getState().recoveryNotice).toBeNull();

    await user.click(screen.getByRole("button", { name: /Live Traffic/i }));
    expect(useNetFlowStore.getState().isTrafficDrawerOpen).toBe(true);
  });

  it("closes workflow dropdown when pendingDiscard or blocked-delete banners trigger", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      workflows: [wfA, wfB],
      currentWorkflowId: wfA.id,
      currentWorkflowName: wfA.name,
      graph: wfA.graph,
      isDirty: true,
      engineStatus: activeStatus,
    });

    render(<TopBar />);

    const switcher = screen.getByRole("button", { name: "Workflow Switcher" });

    // 1. Guarded selectWorkflow closes dropdown when showing pendingDiscard
    await user.click(switcher);
    expect(screen.getByRole("menu")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Direct Gaming" }));
    expect(screen.queryByRole("menu")).toBeNull();
    expect(screen.getByText(/Discard edits and switch to/i)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Keep Editing" }));

    // 2. Guarded switchAndApplyWorkflow closes dropdown when showing pendingDiscard
    await user.click(switcher);
    expect(screen.getByRole("menu")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /Switch & Apply/i }));
    expect(screen.queryByRole("menu")).toBeNull();
    expect(screen.getByText(/Discard edits and switch to/i)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Keep Editing" }));

    // 3. Blocked deleteWorkflow on active workflow closes dropdown when showing error banner
    await user.click(switcher);
    expect(screen.getByRole("menu")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: /Delete Workflow/i }));
    expect(screen.queryByRole("menu")).toBeNull();
    expect(
      screen.getByText(/Cannot delete the active workflow while routing is running/i)
    ).toBeTruthy();
  });
});
