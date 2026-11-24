import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

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

import App from "../App";
import { useNetFlowStore } from "../store/useNetFlowStore";

beforeAll(() => {
  if (typeof globalThis.ResizeObserver === "undefined") {
    globalThis.ResizeObserver = class ResizeObserver {
      observe() {}
      unobserve() {}
      disconnect() {}
    };
  }
  if (typeof globalThis.DOMMatrixReadOnly === "undefined") {
    globalThis.DOMMatrixReadOnly = class DOMMatrixReadOnly {
      m11 = 1;
      m22 = 1;
      m41 = 0;
      m42 = 0;
    } as unknown as typeof DOMMatrixReadOnly;
  }
});

describe("App", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useNetFlowStore.getState().resetStore();
    mockTauri.getDiscoverySnapshot.mockResolvedValue({
      interfaces: [],
      vpns: [],
      processes: [],
    });
    mockTauri.listWorkflows.mockResolvedValue([]);
    mockTauri.getEngineStatus.mockResolvedValue({
      state: "stopped",
      activeWorkflowId: null,
      nodeHealth: {},
      warningBanner: null,
      lastError: null,
    });
    mockTauri.takeRecoveryNotice.mockResolvedValue(null);
    mockTauri.onStatusChanged.mockResolvedValue(vi.fn());
    mockTauri.onTrafficUpdated.mockResolvedValue(vi.fn());
    mockTauri.onRecoveryNotice.mockResolvedValue(vi.fn());
  });

  afterEach(() => {
    cleanup();
  });

  it("mounts TopBar, Sidebar, and FlowCanvas and initializes startup listeners", async () => {
    const unlistenStatus = vi.fn();
    const unlistenTraffic = vi.fn();
    const unlistenRecovery = vi.fn();
    mockTauri.onStatusChanged.mockResolvedValue(unlistenStatus);
    mockTauri.onTrafficUpdated.mockResolvedValue(unlistenTraffic);
    mockTauri.onRecoveryNotice.mockResolvedValue(unlistenRecovery);

    const { unmount } = render(<App />);

    expect(screen.getByText("NetFlow")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Workflow Switcher" })).toBeTruthy();
    expect(screen.getByLabelText("Workflow Node Palette")).toBeTruthy();
    expect(screen.getByTestId("flow-canvas-dropzone")).toBeTruthy();

    await waitFor(() => {
      expect(mockTauri.getDiscoverySnapshot).toHaveBeenCalledTimes(1);
      expect(mockTauri.listWorkflows).toHaveBeenCalledTimes(1);
      expect(mockTauri.onStatusChanged).toHaveBeenCalledTimes(1);
      expect(mockTauri.onTrafficUpdated).toHaveBeenCalledTimes(1);
      expect(mockTauri.onRecoveryNotice).toHaveBeenCalledTimes(1);
    });

    unmount();
    expect(unlistenStatus).toHaveBeenCalledTimes(1);
    expect(unlistenTraffic).toHaveBeenCalledTimes(1);
    expect(unlistenRecovery).toHaveBeenCalledTimes(1);
  });
});
