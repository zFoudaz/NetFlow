import { cleanup, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DiscoverySnapshot, WorkflowGraph } from "../types/workflow";

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
  getAppSettings: vi.fn(),
  updateAppSettings: vi.fn(),
  listAppGroups: vi.fn(),
  saveAppGroup: vi.fn(),
  deleteAppGroup: vi.fn(),
  onStatusChanged: vi.fn(),
  onTrafficUpdated: vi.fn(),
  onRecoveryNotice: vi.fn(),
}));

const mockDialog = vi.hoisted(() => ({
  open: vi.fn(),
}));

vi.mock("../lib/tauri", () => mockTauri);
vi.mock("@tauri-apps/plugin-dialog", () => mockDialog);

import { PropertiesPanel } from "../components/PropertiesPanel";
import { useNetFlowStore } from "../store/useNetFlowStore";

const sampleDiscovery: DiscoverySnapshot = {
  interfaces: [
    {
      alias: "Wi-Fi",
      description: "Intel Wi-Fi 6E AX211",
      ifIndex: 12,
      ipv4: "192.168.1.42",
      gatewayIpv4: "192.168.1.1",
      isUp: true,
      linkSpeedMbps: 866,
      isDefaultGateway: true,
    },
    {
      alias: "Ethernet",
      description: "Realtek 2.5GbE",
      ifIndex: 8,
      ipv4: "192.168.1.88",
      gatewayIpv4: "192.168.1.1",
      isUp: true,
      linkSpeedMbps: 2500,
      isDefaultGateway: false,
    },
  ],
  vpns: [
    {
      provider: "karing",
      isRunning: true,
      detectedPort: 3080,
      adapterAlias: null,
      adapterIfIndex: null,
      adapterIsUp: false,
      adapterGateway: null,
      remoteServerIp: null,
    },
    {
      provider: "openVpn",
      isRunning: false,
      detectedPort: null,
      adapterAlias: "OpenVPN Wintun",
      adapterIfIndex: null,
      adapterIsUp: false,
      adapterGateway: null,
      remoteServerIp: "203.0.113.10",
    },
  ],
  processes: [
    { exeName: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
    { exeName: "discord.exe", path: "C:\\Users\\Test\\AppData\\Local\\Discord\\Discord.exe" },
  ],
};

const sampleGraph: WorkflowGraph = {
  nodes: [
    {
      id: "iface-wifi",
      x: 50,
      y: 80,
      kind: { type: "interface", interfaceAlias: "Wi-Fi", isDefault: true },
    },
    {
      id: "iface-eth",
      x: 50,
      y: 260,
      kind: { type: "interface", interfaceAlias: "Ethernet", isDefault: false },
    },
    {
      id: "vpn-karing",
      x: 340,
      y: 80,
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
      x: 640,
      y: 80,
      kind: { type: "apps", apps: ["chrome.exe", "discord.exe"] },
    },
  ],
  edges: [
    { id: "e-wifi-karing", source: "iface-wifi", target: "vpn-karing" },
    { id: "e-karing-apps", source: "vpn-karing", target: "apps-1" },
  ],
};

describe("PropertiesPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useNetFlowStore.getState().resetStore();
    useNetFlowStore.setState({
      discovery: sampleDiscovery,
      currentWorkflowName: "Office Routing",
      graph: sampleGraph,
      isDirty: true,
    });
    mockTauri.validateWorkflowGraph.mockResolvedValue(null);
    mockTauri.saveWorkflow.mockImplementation(async (wf) => wf);
  });

  afterEach(() => {
    cleanup();
  });

  it("shows workflow overview when no node is selected and triggers Validate/Save", async () => {
    const user = userEvent.setup();
    render(<PropertiesPanel />);

    const panel = screen.getByLabelText("Workflow Properties");
    expect(within(panel).getByText("Office Routing")).toBeTruthy();
    expect(within(panel).getByText("Unsaved changes")).toBeTruthy();
    expect(within(panel).getByText("No validation issues detected")).toBeTruthy();

    await user.click(within(panel).getByRole("button", { name: /^Validate$/i }));
    expect(mockTauri.validateWorkflowGraph).toHaveBeenCalledTimes(1);

    await user.click(within(panel).getByRole("button", { name: /^Save$/i }));
    expect(mockTauri.saveWorkflow).toHaveBeenCalledTimes(1);
  });

  it("inspects an interface node, toggles default, and removes it", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({ selectedNodeId: "iface-eth" });

    render(<PropertiesPanel />);

    const panel = screen.getByLabelText("Node Properties");
    expect(within(panel).getByText("Ethernet")).toBeTruthy();
    expect(within(panel).getByText("192.168.1.88")).toBeTruthy();
    expect(within(panel).getByText("2500 Mbps")).toBeTruthy();
    expect(within(panel).getByText("Realtek 2.5GbE")).toBeTruthy();

    await user.click(within(panel).getByRole("button", { name: /Set as Default/i }));
    const ethNode = useNetFlowStore
      .getState()
      .graph.nodes.find((n) => n.id === "iface-eth");
    expect(ethNode?.kind).toMatchObject({ isDefault: true });

    await user.click(within(panel).getByRole("button", { name: /Remove Interface/i }));
    expect(useNetFlowStore.getState().selectedNodeId).toBeNull();
    expect(
      useNetFlowStore.getState().graph.nodes.some((n) => n.id === "iface-eth")
    ).toBe(false);
  });

  it("inspects a VPN node, enforces single physical interface association, and updates overrides", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({ selectedNodeId: "vpn-karing" });

    render(<PropertiesPanel />);

    const panel = screen.getByLabelText("Node Properties");
    expect(within(panel).getAllByText("Karing").length).toBeGreaterThan(0);
    expect(within(panel).getByText("3080")).toBeTruthy();

    // Switch physical interface from Wi-Fi to Ethernet; only 1 incoming edge should exist
    const ifaceSelect = within(panel).getByLabelText("Associated Physical Interface");
    expect((ifaceSelect as HTMLSelectElement).value).toBe("iface-wifi");

    await user.selectOptions(ifaceSelect, "iface-eth");
    const incomingToVpn = useNetFlowStore
      .getState()
      .graph.edges.filter((e) => e.target === "vpn-karing");
    expect(incomingToVpn).toHaveLength(1);
    expect(incomingToVpn[0].source).toBe("iface-eth");

    // Update Karing port override
    const portInput = within(panel).getByPlaceholderText(/Detected \(3080\)/i);
    await user.type(portInput, "7890");
    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "vpn-karing")?.kind
    ).toMatchObject({
      settings: { karingPortOverride: 7890 },
    });
  });

  it("inspects a Connected Apps group, shows route, removes and adds apps", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({ selectedNodeId: "apps-1" });

    render(<PropertiesPanel />);

    const panel = screen.getByLabelText("Node Properties");
    expect(within(panel).getByText("Connected Apps")).toBeTruthy();
    expect(within(panel).getByText("2 applications")).toBeTruthy();
    expect(within(panel).getByText("Karing")).toBeTruthy();
    expect(within(panel).getByText("chrome.exe")).toBeTruthy();
    expect(within(panel).getByText("discord.exe")).toBeTruthy();

    await user.click(within(panel).getByRole("button", { name: /Remove chrome\.exe from inspector/i }));
    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "apps-1")?.kind
    ).toEqual({
      type: "apps",
      apps: ["discord.exe"],
    });

    await user.click(within(panel).getByRole("button", { name: /Add Application/i }));
    const dialog = await screen.findByRole("dialog", { name: /Add Application/i });
    await user.click(within(dialog).getByRole("button", { name: /chrome\.exe/i }));

    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "apps-1")?.kind
    ).toEqual({
      type: "apps",
      apps: ["discord.exe", "chrome.exe"],
    });
  });

  it("hot-applies immediately when toggling default route in PropertiesPanel while active", async () => {
    const user = userEvent.setup();
    mockTauri.applyWorkflow.mockResolvedValue({
      state: "active",
      activeWorkflowId: null,
      nodeHealth: {},
      warningBanner: null,
      lastError: null,
    });
    useNetFlowStore.setState({
      selectedNodeId: "iface-eth",
      engineStatus: {
        state: "active",
        activeWorkflowId: null,
        nodeHealth: {},
        warningBanner: null,
        lastError: null,
      },
    });

    render(<PropertiesPanel />);
    const panel = screen.getByLabelText("Node Properties");
    expect(
      within(panel).getByText(/Click to switch the active catch-all route immediately/i)
    ).toBeTruthy();

    await user.click(within(panel).getByRole("button", { name: /Set as Default/i }));

    await waitFor(() => {
      expect(mockTauri.applyWorkflow).toHaveBeenCalledTimes(1);
    });
    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "iface-eth")?.kind
    ).toMatchObject({ isDefault: true });
    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "iface-wifi")?.kind
    ).toMatchObject({ isDefault: false });
    expect(
      await within(panel).findByText(/Active catch-all route for unlisted apps/i)
    ).toBeTruthy();
  });

  it("renames a Connected Apps node and saves it as a reusable Saved Group in Sidebar", async () => {
    const user = userEvent.setup();
    mockTauri.saveAppGroup.mockImplementation(async (group) => ({
      ...group,
      id: "grp-work",
      updatedAt: "2026-11-24T18:00:00Z",
    }));
    useNetFlowStore.setState({ selectedNodeId: "apps-1" });

    render(<PropertiesPanel />);
    const panel = screen.getByLabelText("Node Properties");

    const saveBtn = within(panel).getByRole("button", { name: /Save to Sidebar/i });
    expect((saveBtn as HTMLButtonElement).disabled).toBe(true);

    const groupNameInput = within(panel).getByLabelText("Group Name");
    await user.type(groupNameInput, "Work Apps");

    expect(within(panel).getByText("Work Apps")).toBeTruthy();
    expect((saveBtn as HTMLButtonElement).disabled).toBe(false);

    await user.click(saveBtn);

    await waitFor(() => {
      expect(mockTauri.saveAppGroup).toHaveBeenCalledTimes(1);
    });
    expect(mockTauri.saveAppGroup).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "Work Apps",
        apps: ["chrome.exe", "discord.exe"],
      })
    );
    expect(useNetFlowStore.getState().savedAppGroups).toHaveLength(1);
    expect(useNetFlowStore.getState().savedAppGroups[0].name).toBe("Work Apps");
    expect(await within(panel).findByText("Saved to Sidebar")).toBeTruthy();
  });
});
