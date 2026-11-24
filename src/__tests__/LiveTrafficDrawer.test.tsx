import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { LiveTrafficDrawer } from "../components/LiveTrafficDrawer";
import { useNetFlowStore } from "../store/useNetFlowStore";
import type { LiveConnection, WorkflowGraph } from "../types/workflow";

const sampleGraph: WorkflowGraph = {
  nodes: [
    {
      id: "if-wifi",
      x: 100,
      y: 100,
      kind: { type: "interface", interfaceAlias: "Wi-Fi", isDefault: true },
    },
    {
      id: "vpn-karing",
      x: 340,
      y: 100,
      kind: {
        type: "vpn",
        provider: "karing",
        isDefault: false,
        settings: { warpMode: "tun" },
      },
    },
    {
      id: "vpn-warp",
      x: 340,
      y: 220,
      kind: {
        type: "vpn",
        provider: "cloudflareWarp",
        isDefault: false,
        settings: { warpMode: "tun" },
      },
    },
  ],
  edges: [],
};

const sampleConnections: LiveConnection[] = [
  {
    id: "conn-1",
    processName: "chrome.exe",
    destination: "api.ipify.org:443",
    network: "tcp",
    outboundTag: "vpn-karing",
    nodeId: "vpn-karing",
    uploadBytes: 2048,
    downloadBytes: 1572864,
  },
  {
    id: "conn-2",
    processName: "curl-wifi.exe",
    destination: "api.ipify.org:443",
    network: "tcp",
    outboundTag: "iface-wi-fi",
    nodeId: "if-wifi",
    uploadBytes: 512,
    downloadBytes: 4096,
  },
];

describe("LiveTrafficDrawer", () => {
  beforeEach(() => {
    useNetFlowStore.getState().resetStore();
  });

  afterEach(() => {
    cleanup();
  });

  it("test_renders_and_filters_live_connections", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      isTrafficDrawerOpen: true,
      graph: sampleGraph,
      liveConnections: sampleConnections,
    });

    render(<LiveTrafficDrawer />);

    expect(screen.getByText("chrome.exe")).toBeTruthy();
    expect(screen.getByText("curl-wifi.exe")).toBeTruthy();
    expect(screen.getAllByText("api.ipify.org:443")).toHaveLength(2);
    expect(screen.getByText("Karing")).toBeTruthy();
    expect(screen.getByText("Wi-Fi")).toBeTruthy();
    expect(screen.getByText(/2\.0 KB/)).toBeTruthy();
    expect(screen.getByText(/1\.5 MB/)).toBeTruthy();

    const searchInput = screen.getByPlaceholderText(/filter/i);
    await user.type(searchInput, "chrome");

    expect(screen.getByText("chrome.exe")).toBeTruthy();
    expect(screen.queryByText("curl-wifi.exe")).toBeNull();

    await user.clear(searchInput);
    await user.type(searchInput, "Wi-Fi");

    expect(screen.queryByText("chrome.exe")).toBeNull();
    expect(screen.getByText("curl-wifi.exe")).toBeTruthy();
  });

  it("renders empty state when there are no live connections and closes on X button", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      isTrafficDrawerOpen: true,
      graph: sampleGraph,
      liveConnections: [],
    });

    render(<LiveTrafficDrawer />);

    expect(
      screen.getByText("No active connections yet — start routing to see live traffic")
    ).toBeTruthy();

    await user.click(screen.getByRole("button", { name: /close live traffic/i }));
    expect(useNetFlowStore.getState().isTrafficDrawerOpen).toBe(false);
  });

  it("renders nothing when isTrafficDrawerOpen is false", () => {
    useNetFlowStore.setState({
      isTrafficDrawerOpen: false,
      liveConnections: sampleConnections,
    });

    const { container } = render(<LiveTrafficDrawer />);
    expect(container.firstChild).toBeNull();
  });

  it("applies color-coded outbound badges for interface, VPN, block, and default-direct", () => {
    useNetFlowStore.setState({
      isTrafficDrawerOpen: true,
      graph: sampleGraph,
      liveConnections: [
        ...sampleConnections,
        {
          id: "conn-3",
          processName: "telemetry.exe",
          destination: "ads.example.com:443",
          network: "udp",
          outboundTag: "block",
          nodeId: null,
          uploadBytes: 0,
          downloadBytes: 0,
        },
        {
          id: "conn-4",
          processName: "svchost.exe",
          destination: "time.windows.com:123",
          network: "udp",
          outboundTag: "default-direct",
          nodeId: null,
          uploadBytes: 128,
          downloadBytes: 256,
        },
      ],
    });

    render(<LiveTrafficDrawer />);

    const vpnBadge = screen.getByTestId("outbound-badge-conn-1");
    const ifaceBadge = screen.getByTestId("outbound-badge-conn-2");
    const blockBadge = screen.getByTestId("outbound-badge-conn-3");
    const defaultBadge = screen.getByTestId("outbound-badge-conn-4");

    expect(vpnBadge.className).toMatch(/violet|indigo/);
    expect(ifaceBadge.className).toMatch(/emerald|teal/);
    expect(blockBadge.className).toMatch(/red|rose/);
    expect(defaultBadge.className).toMatch(/slate/);
  });

  it("shows no-match state, clears filter, and resolves WARP/OpenVPN labels with GB formatting", async () => {
    const user = userEvent.setup();
    useNetFlowStore.setState({
      isTrafficDrawerOpen: true,
      graph: {
        ...sampleGraph,
        nodes: [
          ...sampleGraph.nodes,
          {
            id: "vpn-ovpn",
            x: 340,
            y: 320,
            kind: {
              type: "vpn",
              provider: "openVpn",
              isDefault: false,
              settings: { warpMode: "tun" },
            },
          },
        ],
      },
      liveConnections: [
        {
          id: "conn-warp",
          processName: "firefox.exe",
          destination: "1.1.1.1:443",
          network: "udp",
          outboundTag: "vpn-warp",
          nodeId: "vpn-warp",
          uploadBytes: 1024 * 1024 * 1024 * 2,
          downloadBytes: 500,
        },
        {
          id: "conn-ovpn",
          processName: "ssh.exe",
          destination: "10.0.0.5:22",
          network: "tcp",
          outboundTag: "vpn-openvpn",
          nodeId: "vpn-ovpn",
          uploadBytes: 0,
          downloadBytes: 1024,
        },
      ],
    });

    render(<LiveTrafficDrawer />);

    expect(screen.getByText("Cloudflare WARP")).toBeTruthy();
    expect(screen.getByText("OpenVPN")).toBeTruthy();
    expect(screen.getByText(/2\.0 GB/)).toBeTruthy();
    expect(screen.getByText(/500 B/)).toBeTruthy();

    const searchInput = screen.getByLabelText("Filter live traffic");
    await user.type(searchInput, "nonexistent-proc");
    expect(screen.getByText(/No connections match/i)).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "Clear filter" }));
    expect(screen.getByText("firefox.exe")).toBeTruthy();
    expect(screen.getByText("ssh.exe")).toBeTruthy();
  });
});
