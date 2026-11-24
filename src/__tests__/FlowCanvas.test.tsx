import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { DiscoverySnapshot, EngineStatus, WorkflowGraph } from "../types/workflow";

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

const mockDialog = vi.hoisted(() => ({
  open: vi.fn(),
}));

vi.mock("../lib/tauri", () => mockTauri);
vi.mock("@tauri-apps/plugin-dialog", () => mockDialog);

import { normalizeExeBasename } from "../components/AddAppModal";
import { FlowCanvas, isValidWorkflowConnection } from "../components/FlowCanvas";
import { Sidebar } from "../components/Sidebar";
import { useNetFlowStore } from "../store/useNetFlowStore";

const sampleDiscovery: DiscoverySnapshot = {
  interfaces: [
    {
      alias: "Wi-Fi",
      description: "Intel Wi-Fi 6E",
      ifIndex: 12,
      ipv4: "192.168.1.42",
      gatewayIpv4: "192.168.1.1",
      isUp: true,
      linkSpeedMbps: 866,
      isDefaultGateway: true,
    },
    {
      alias: "Ethernet",
      description: "Realtek Gaming 2.5GbE",
      ifIndex: 8,
      ipv4: null,
      gatewayIpv4: null,
      isUp: false,
      linkSpeedMbps: 0,
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
      remoteServerIp: null,
    },
  ],
  processes: [
    { exeName: "chrome.exe", path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" },
    { exeName: "discord.exe", path: "C:\\Users\\Test\\AppData\\Local\\Discord\\app\\Discord.exe" },
    { exeName: "steam.exe", path: "C:\\Program Files (x86)\\Steam\\steam.exe" },
  ],
};

const stoppedStatus: EngineStatus = {
  state: "stopped",
  activeWorkflowId: null,
  nodeHealth: {},
  warningBanner: null,
  lastError: null,
};

beforeAll(() => {
  if (typeof globalThis.ResizeObserver === "undefined") {
    globalThis.ResizeObserver = class ResizeObserver {
      private callback: ResizeObserverCallback;
      constructor(callback: ResizeObserverCallback) {
        this.callback = callback;
      }
      observe(target: Element) {
        this.callback(
          [
            {
              target,
              contentRect: {
                x: 0,
                y: 0,
                width: 1000,
                height: 700,
                top: 0,
                left: 0,
                bottom: 700,
                right: 1000,
                toJSON: () => ({}),
              },
              borderBoxSize: [],
              contentBoxSize: [],
              devicePixelContentBoxSize: [],
            } as ResizeObserverEntry,
          ],
          this
        );
      }
      unobserve() {}
      disconnect() {}
    };
  }

  Object.defineProperties(HTMLElement.prototype, {
    offsetHeight: {
      configurable: true,
      get() {
        return 700;
      },
    },
    offsetWidth: {
      configurable: true,
      get() {
        return 1000;
      },
    },
  });

  HTMLElement.prototype.getBoundingClientRect = function () {
    return {
      x: 0,
      y: 0,
      top: 0,
      left: 0,
      bottom: 700,
      right: 1000,
      width: 1000,
      height: 700,
      toJSON: () => ({}),
    };
  };

  if (typeof globalThis.DOMMatrixReadOnly === "undefined") {
    globalThis.DOMMatrixReadOnly = class DOMMatrixReadOnly {
      m11 = 1;
      m22 = 1;
      m41 = 0;
      m42 = 0;
      constructor() {}
    } as unknown as typeof DOMMatrixReadOnly;
  }
});

describe("FlowCanvas, Sidebar, and Custom Nodes", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    useNetFlowStore.getState().resetStore();
    useNetFlowStore.setState({
      discovery: sampleDiscovery,
      engineStatus: stoppedStatus,
    });
    mockTauri.getDiscoverySnapshot.mockResolvedValue(sampleDiscovery);
  });

  afterEach(() => {
    cleanup();
  });

  it("test_sidebar_renders_detected_interfaces_and_two_vpns", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      graph: {
        nodes: [
          {
            id: "vpn-karing-1",
            x: 320,
            y: 120,
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
        ],
        edges: [],
      },
    });

    render(<Sidebar />);

    // Interfaces section with live Up/Down badges and IPv4
    const wifiItem = screen.getByTestId("sidebar-interface-Wi-Fi");
    expect(within(wifiItem).getByText("Wi-Fi")).toBeTruthy();
    expect(within(wifiItem).getByText("Up")).toBeTruthy();
    expect(within(wifiItem).getByText("192.168.1.42")).toBeTruthy();

    const ethItem = screen.getByTestId("sidebar-interface-Ethernet");
    expect(within(ethItem).getByText("Ethernet")).toBeTruthy();
    expect(within(ethItem).getByText("Down")).toBeTruthy();

    // Both supported VPNs render with live Running/Stopped status
    const karingItem = screen.getByTestId("sidebar-vpn-karing");
    expect(within(karingItem).getByText("Karing")).toBeTruthy();
    expect(within(karingItem).getByText("Running")).toBeTruthy();
    expect(within(karingItem).getByText("On Canvas")).toBeTruthy();
    expect(karingItem.getAttribute("draggable")).toBe("false");
    expect(within(karingItem).getByRole("button", { name: /Add Karing VPN/i })).toHaveProperty(
      "disabled",
      true
    );

    const openVpnItem = screen.getByTestId("sidebar-vpn-openVpn");
    expect(within(openVpnItem).getByText("OpenVPN")).toBeTruthy();
    expect(within(openVpnItem).getByText("Stopped")).toBeTruthy();
    expect(openVpnItem.getAttribute("draggable")).toBe("true");

    // Connected Apps template card is draggable
    const appsTemplate = screen.getByTestId("sidebar-apps-template");
    expect(within(appsTemplate).getByText("Connected Apps")).toBeTruthy();
    expect(appsTemplate.getAttribute("draggable")).toBe("true");

    // Clicking refresh calls refreshDiscovery
    await user.click(screen.getByRole("button", { name: /Refresh discovery/i }));
    expect(mockTauri.getDiscoverySnapshot).toHaveBeenCalledTimes(1);

    // Quick-add button adds OpenVPN to canvas and marks it On Canvas
    await user.click(within(openVpnItem).getByRole("button", { name: /Add OpenVPN VPN/i }));
    expect(
      useNetFlowStore
        .getState()
        .graph.nodes.some((n) => n.kind.type === "vpn" && n.kind.provider === "openVpn")
    ).toBe(true);
    expect(within(openVpnItem).getByText("On Canvas")).toBeTruthy();
    expect(openVpnItem.getAttribute("draggable")).toBe("false");
  });

  it("test_apps_node_adds_and_removes_exe_via_modal", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      graph: {
        nodes: [
          {
            id: "apps-1",
            x: 200,
            y: 120,
            kind: { type: "apps", apps: [] },
          },
        ],
        edges: [],
      },
    });

    render(<FlowCanvas />);

    const appsNode = await screen.findByTestId("flow-node-apps-1");
    expect(within(appsNode).getByText("Connected Apps")).toBeTruthy();

    // Open AddAppModal
    await user.click(within(appsNode).getByRole("button", { name: /\+ Add App/i }));
    const dialog = await screen.findByRole("dialog", { name: /Add Application/i });

    // Search running processes for chrome
    const searchInput = within(dialog).getByLabelText(/Search running processes/i);
    await user.type(searchInput, "chrome");
    expect(within(dialog).queryByText("discord.exe")).toBeNull();

    // Add chrome.exe from search results
    await user.click(within(dialog).getByRole("button", { name: /chrome\.exe/i }));

    // Modal closes and chrome.exe renders in Connected Apps table & store
    expect(screen.queryByRole("dialog", { name: /Add Application/i })).toBeNull();
    expect(within(appsNode).getByText("chrome.exe")).toBeTruthy();
    const updatedNode = useNetFlowStore.getState().graph.nodes[0];
    expect(updatedNode.kind).toEqual({ type: "apps", apps: ["chrome.exe"] });

    // Browse .exe... via Tauri dialog normalizes Windows backslash path to lowercase basename
    mockDialog.open.mockResolvedValueOnce("C:\\Program Files\\Mozilla Firefox\\Firefox.EXE");
    await user.click(within(appsNode).getByRole("button", { name: /\+ Add App/i }));
    const dialog2 = await screen.findByRole("dialog", { name: /Add Application/i });
    await user.click(within(dialog2).getByRole("button", { name: /Browse \.exe/i }));
    expect(await within(appsNode).findByText("firefox.exe")).toBeTruthy();

    // Remove chrome.exe cleanly
    await user.click(within(appsNode).getByRole("button", { name: /Remove chrome\.exe/i }));
    expect(within(appsNode).queryByText("chrome.exe")).toBeNull();
    expect(useNetFlowStore.getState().graph.nodes[0].kind).toEqual({
      type: "apps",
      apps: ["firefox.exe"],
    });
  });

  it("test_vpn_node_settings_popover_updates_karing_port_and_sets_default", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      graph: {
        nodes: [
          {
            id: "iface-wifi",
            x: 60,
            y: 120,
            kind: { type: "interface", interfaceAlias: "Wi-Fi", isDefault: true },
          },
          {
            id: "vpn-karing",
            x: 360,
            y: 120,
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
        ],
        edges: [{ id: "e1", source: "iface-wifi", target: "vpn-karing" }],
      },
    });

    render(<FlowCanvas />);

    const karingNode = await screen.findByTestId("flow-node-vpn-karing");
    expect(within(karingNode).getByText("Karing")).toBeTruthy();
    expect(within(karingNode).getByText("Running")).toBeTruthy();

    // Open VPN settings popover and configure Karing port override
    await user.click(
      within(karingNode).getByRole("button", { name: /Configure Karing settings/i })
    );
    const portInput = await within(karingNode).findByPlaceholderText(/Detected \(3080\)/i);
    await user.type(portInput, "7890");

    const storeKaringAfterPort = useNetFlowStore
      .getState()
      .graph.nodes.find((n) => n.id === "vpn-karing");
    expect(storeKaringAfterPort?.kind).toMatchObject({
      type: "vpn",
      provider: "karing",
      settings: { karingPortOverride: 7890 },
    });

    // Toggle "Set as Default" on Karing node (clears default from iface-wifi)
    await user.click(within(karingNode).getByRole("button", { name: /Set as Default/i }));

    const nodes = useNetFlowStore.getState().graph.nodes;
    const wifiAfter = nodes.find((n) => n.id === "iface-wifi");
    const karingAfter = nodes.find((n) => n.id === "vpn-karing");
    expect(karingAfter?.kind).toMatchObject({ isDefault: true });
    expect(wifiAfter?.kind).toMatchObject({ isDefault: false });
    expect(
      within(karingNode).getByRole("button", { name: /^DEFAULT$/i }).getAttribute("aria-pressed")
    ).toBe("true");
  });

  it("test_displays_offline_badge_and_validation_errors_on_nodes", async () => {
    useNetFlowStore.setState({
      graph: {
        nodes: [
          {
            id: "iface-eth",
            x: 80,
            y: 80,
            kind: { type: "interface", interfaceAlias: "Ethernet", isDefault: false },
          },
          {
            id: "vpn-ovpn",
            x: 340,
            y: 80,
            kind: {
              type: "vpn",
              provider: "openVpn",
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
            x: 620,
            y: 80,
            kind: { type: "apps", apps: ["chrome.exe"] },
          },
        ],
        edges: [],
      },
      validationErrors: [
        {
          code: "missingUpstreamInterface",
          nodeIds: ["vpn-ovpn"],
          message: "OpenVPN requires an upstream physical interface",
        },
        {
          code: "duplicateAppAssignment",
          nodeIds: ["apps-1"],
          message: "Executable 'chrome.exe' is assigned more than once",
        },
      ],
      engineStatus: {
        state: "warning",
        activeWorkflowId: "wf-1",
        nodeHealth: { "iface-eth": "dropped" },
        warningBanner: "Ethernet interface disconnected.",
        lastError: null,
      },
    });

    render(<FlowCanvas />);

    const ethNode = await screen.findByTestId("flow-node-iface-eth");
    expect(within(ethNode).getByText("Offline")).toBeTruthy();
    expect(within(ethNode).getByText("Dropped")).toBeTruthy();
    expect(ethNode.className).toContain("border-rose-500");

    const ovpnNode = await screen.findByTestId("flow-node-vpn-ovpn");
    expect(ovpnNode.className).toContain("border-rose-500");
    expect(
      within(ovpnNode).getByText("OpenVPN requires an upstream physical interface")
    ).toBeTruthy();

    const appsNode = await screen.findByTestId("flow-node-apps-1");
    expect(appsNode.className).toContain("border-rose-500");
    expect(
      within(appsNode).getByText("Executable 'chrome.exe' is assigned more than once")
    ).toBeTruthy();
  });

  it("enforces isValidWorkflowConnection rules and animates edges when active", async () => {
    const graph: WorkflowGraph = {
      nodes: [
        {
          id: "iface-1",
          x: 50,
          y: 100,
          kind: { type: "interface", interfaceAlias: "Wi-Fi", isDefault: true },
        },
        {
          id: "vpn-1",
          x: 280,
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
          id: "vpn-2",
          x: 500,
          y: 100,
          kind: {
            type: "vpn",
            provider: "openVpn",
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
          x: 720,
          y: 100,
          kind: { type: "apps", apps: ["chrome.exe"] },
        },
      ],
      edges: [
        { id: "e1", source: "iface-1", target: "vpn-1" },
        { id: "e2", source: "vpn-1", target: "apps-1" },
      ],
    };

    // Allowed: vpn-1 -> vpn-2, interface -> apps (when target has no upstream)
    expect(
      isValidWorkflowConnection(
        { source: "vpn-1", target: "vpn-2", sourceHandle: null, targetHandle: null },
        graph.nodes,
        graph.edges
      )
    ).toBe(true);

    // Disallowed: >1 incoming edge into apps-1 or vpn-1
    expect(
      isValidWorkflowConnection(
        { source: "iface-1", target: "apps-1", sourceHandle: null, targetHandle: null },
        graph.nodes,
        graph.edges
      )
    ).toBe(false);
    expect(
      isValidWorkflowConnection(
        { source: "vpn-2", target: "vpn-1", sourceHandle: null, targetHandle: null },
        graph.nodes,
        graph.edges
      )
    ).toBe(false);

    // Disallowed: apps -> anything
    expect(
      isValidWorkflowConnection(
        { source: "apps-1", target: "vpn-2", sourceHandle: null, targetHandle: null },
        graph.nodes,
        graph.edges
      )
    ).toBe(false);

    // Disallowed: anything -> interface
    expect(
      isValidWorkflowConnection(
        { source: "vpn-2", target: "iface-1", sourceHandle: null, targetHandle: null },
        graph.nodes,
        graph.edges
      )
    ).toBe(false);

    // Disallowed: self-loop
    expect(
      isValidWorkflowConnection(
        { source: "vpn-2", target: "vpn-2", sourceHandle: null, targetHandle: null },
        graph.nodes,
        graph.edges
      )
    ).toBe(false);

    // Disallowed: cycle (vpn-1 -> vpn-2 -> vpn-1)
    const chainedEdges = [
      { id: "e1", source: "iface-1", target: "vpn-1" },
      { id: "e2", source: "vpn-1", target: "vpn-2" },
    ];
    expect(
      isValidWorkflowConnection(
        { source: "vpn-2", target: "vpn-1", sourceHandle: null, targetHandle: null },
        graph.nodes,
        chainedEdges
      )
    ).toBe(false);

    // Verify active routing sets animated edges in React Flow
    useNetFlowStore.setState({
      graph,
      engineStatus: {
        state: "active",
        activeWorkflowId: "wf-1",
        nodeHealth: {},
        warningBanner: null,
        lastError: null,
      },
    });

    const { container } = render(<FlowCanvas />);
    await screen.findByTestId("flow-node-iface-1");
    expect(container.querySelectorAll(".react-flow__edge.animated").length).toBeGreaterThan(0);

    // Drag & drop onto canvas adds node with finite position and marks store dirty
    const canvasWrapper = screen.getByTestId("flow-canvas-dropzone");
    const dataTransfer = {
      getData: (mime: string) =>
        mime === "application/netflow-node" ? JSON.stringify({ type: "apps" }) : "",
    };
    fireEvent.drop(canvasWrapper, {
      clientX: 400,
      clientY: 250,
      dataTransfer,
    });
    const appsNodesAfterDrop = useNetFlowStore
      .getState()
      .graph.nodes.filter((n) => n.kind.type === "apps");
    expect(appsNodesAfterDrop.length).toBe(2);
    expect(Number.isFinite(appsNodesAfterDrop[1].x)).toBe(true);
    expect(Number.isFinite(appsNodesAfterDrop[1].y)).toBe(true);
    expect(useNetFlowStore.getState().isDirty).toBe(true);
  });

  it("supports manual exe entry, graceful dialog fallback, and Karing/OpenVPN settings overrides", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      graph: {
        nodes: [
          {
            id: "vpn-karing",
            x: 100,
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
            id: "vpn-ovpn",
            x: 380,
            y: 100,
            kind: {
              type: "vpn",
              provider: "openVpn",
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
            x: 660,
            y: 100,
            kind: { type: "apps", apps: [] },
          },
        ],
        edges: [],
      },
    });

    render(<FlowCanvas />);

    // Karing port override
    const karingNode = await screen.findByTestId("flow-node-vpn-karing");
    await user.click(within(karingNode).getByRole("button", { name: /Configure Karing settings/i }));
    const portInput = within(karingNode).getByPlaceholderText(/Detected \(3080\)/i);
    await user.type(portInput, "7890");
    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "vpn-karing")?.kind
    ).toMatchObject({
      settings: { karingPortOverride: 7890 },
    });

    // OpenVPN adapter & server IP overrides
    const ovpnNode = await screen.findByTestId("flow-node-vpn-ovpn");
    await user.click(within(ovpnNode).getByRole("button", { name: /Configure OpenVPN settings/i }));
    await user.type(within(ovpnNode).getByLabelText(/Adapter Alias Override/i), "Tun0");
    await user.type(within(ovpnNode).getByLabelText(/Remote Server IP Override/i), "1.2.3.4");
    expect(
      useNetFlowStore.getState().graph.nodes.find((n) => n.id === "vpn-ovpn")?.kind
    ).toMatchObject({
      settings: {
        openvpnAdapterOverride: "Tun0",
        openvpnServerIpOverride: "1.2.3.4",
      },
    });

    // Graceful dialog rejection fallback & manual exe entry in AddAppModal
    mockDialog.open.mockRejectedValueOnce(new Error("Dialog unavailable in browser"));
    const appsNode = await screen.findByTestId("flow-node-apps-1");
    await user.click(within(appsNode).getByRole("button", { name: /\+ Add App/i }));
    const dialog = await screen.findByRole("dialog", { name: /Add Application/i });
    await user.click(within(dialog).getByRole("button", { name: /Browse \.exe/i }));
    expect(
      await within(dialog).findByText(/File browser dialog is unavailable in this environment/i)
    ).toBeTruthy();

    const manualInput = within(dialog).getByLabelText(/Manual executable name/i);
    await user.type(manualInput, "D:/Tools/Spotify.EXE");
    await user.click(within(dialog).getByRole("button", { name: /^Add$/i }));
    expect(await within(appsNode).findByText("spotify.exe")).toBeTruthy();

    // Deleting a node removes it from store
    await user.click(within(karingNode).getByRole("button", { name: /Delete Karing node/i }));
    expect(useNetFlowStore.getState().graph.nodes.some((n) => n.id === "vpn-karing")).toBe(false);
  });

  it("rejects stemless .exe names and detects chrome vs chrome.exe duplicates in AddAppModal", async () => {
    expect(normalizeExeBasename(".exe")).toBeNull();
    expect(normalizeExeBasename(" .EXE ")).toBeNull();
    expect(normalizeExeBasename("C:\\Tools\\.exe")).toBeNull();
    expect(normalizeExeBasename("chrome.")).toBeNull();
    expect(normalizeExeBasename("chrome")).toBe("chrome.exe");

    const user = userEvent.setup();
    useNetFlowStore.setState({
      graph: {
        nodes: [
          {
            id: "apps-1",
            x: 200,
            y: 120,
            kind: { type: "apps", apps: ["chrome.exe"] },
          },
        ],
        edges: [],
      },
    });

    render(<FlowCanvas />);

    const appsNode = await screen.findByTestId("flow-node-apps-1");
    await user.click(within(appsNode).getByRole("button", { name: /\+ Add App/i }));
    const dialog = await screen.findByRole("dialog", { name: /Add Application/i });
    const manualInput = within(dialog).getByLabelText(/Manual executable name/i);
    const addBtn = within(dialog).getByRole("button", { name: /^Add$/i });

    // Stemless ".exe" is rejected with validation feedback
    await user.type(manualInput, ".exe");
    await user.click(addBtn);
    expect(
      await within(dialog).findByText(/Enter a valid executable filename/i)
    ).toBeTruthy();

    // Un-suffixed "chrome" collides with existing "chrome.exe"
    await user.clear(manualInput);
    await user.type(manualInput, "chrome");
    await user.click(addBtn);
    expect(
      await within(dialog).findByText(/'chrome\.exe' is already assigned to this node\./i)
    ).toBeTruthy();

    expect(useNetFlowStore.getState().graph.nodes[0].kind).toEqual({
      type: "apps",
      apps: ["chrome.exe"],
    });
  });
});
