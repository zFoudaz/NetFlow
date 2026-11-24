import {
  AppWindow,
  Bookmark,
  Network,
  Plus,
  RefreshCw,
  Search,
  Shield,
  Trash2,
  Wifi,
} from "lucide-react";
import { useMemo, useState, type DragEvent } from "react";
import { isRoutingActiveState, useNetFlowStore } from "../store/useNetFlowStore";
import type { DetectedVpnInfo, RuntimeState, VpnProvider } from "../types/workflow";
import { NetFlowLogo } from "./NetFlowLogo";
import {
  createWorkflowNode,
  NETFLOW_DND_MIME,
  nextQuickAddPosition,
  VPN_PROVIDER_LABELS,
  VPN_PROVIDERS,
  type DragNodePayload,
} from "./nodes/nodeShared";

function getVpnHint(provider: VpnProvider, info?: DetectedVpnInfo): string {
  if (provider === "karing") {
    return info?.detectedPort ? `Port ${info.detectedPort}` : "Port 3067 (auto)";
  }
  return info?.adapterAlias ? info.adapterAlias : "TAP / Wintun";
}

function setDragPayload(event: DragEvent<HTMLElement>, payload: DragNodePayload) {
  const serialized = JSON.stringify(payload);
  event.dataTransfer.setData(NETFLOW_DND_MIME, serialized);
  event.dataTransfer.setData("text/plain", serialized);
  event.dataTransfer.effectAllowed = "move";
}

const FOOTER_STATUS_META: Record<
  RuntimeState,
  { label: string; dotClass: string; subtitle: string }
> = {
  stopped: {
    label: "Engine Stopped",
    dotClass: "bg-[#6B7280]",
    subtitle: "Ready to apply changes",
  },
  applying: {
    label: "Applying Rules",
    dotClass: "bg-[#14B8A6] animate-pulse",
    subtitle: "Configuring network routes...",
  },
  active: {
    label: "Routing Active",
    dotClass: "bg-[#3ECF8E]",
    subtitle: "All systems operational",
  },
  warning: {
    label: "Degraded Route",
    dotClass: "bg-amber-400 animate-pulse",
    subtitle: "Check dropped nodes",
  },
  error: {
    label: "Engine Error",
    dotClass: "bg-rose-400",
    subtitle: "Review configuration",
  },
};

export function Sidebar() {
  const discovery = useNetFlowStore((s) => s.discovery);
  const graphNodes = useNetFlowStore((s) => s.graph.nodes);
  const savedAppGroups = useNetFlowStore((s) => s.savedAppGroups);
  const engineStatus = useNetFlowStore((s) => s.engineStatus);
  const liveConnections = useNetFlowStore((s) => s.liveConnections);
  const refreshDiscovery = useNetFlowStore((s) => s.refreshDiscovery);
  const addNode = useNetFlowStore((s) => s.addNode);
  const deleteAppGroup = useNetFlowStore((s) => s.deleteAppGroup);
  const setSelectedNodeId = useNetFlowStore((s) => s.setSelectedNodeId);
  const toggleTrafficDrawer = useNetFlowStore((s) => s.toggleTrafficDrawer);

  const [isRefreshing, setIsRefreshing] = useState(false);
  const [openAppsQuery, setOpenAppsQuery] = useState("");

  const canvasExeSet = useMemo(() => {
    const set = new Set<string>();
    for (const node of graphNodes) {
      if (node.kind.type === "apps") {
        for (const exe of node.kind.apps) {
          const normalized = exe.trim().toLowerCase();
          if (normalized) {
            set.add(normalized);
          }
        }
      }
    }
    return set;
  }, [graphNodes]);

  const openApps = discovery.openApps ?? [];
  const filteredOpenApps = useMemo(() => {
    const query = openAppsQuery.trim().toLowerCase();
    if (!query) {
      return openApps;
    }
    return openApps.filter(
      (app) =>
        app.name.toLowerCase().includes(query) ||
        app.primaryExe.toLowerCase().includes(query) ||
        app.executables.some((exe) => exe.toLowerCase().includes(query))
    );
  }, [openApps, openAppsQuery]);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      await refreshDiscovery();
    } finally {
      setIsRefreshing(false);
    }
  };

  const handleQuickAdd = (payload: DragNodePayload) => {
    if (
      payload.type === "vpn" &&
      graphNodes.some((n) => n.kind.type === "vpn" && n.kind.provider === payload.provider)
    ) {
      return;
    }
    const pos = nextQuickAddPosition(payload.type, graphNodes);
    const created = createWorkflowNode(payload, pos);
    addNode(created);
    setSelectedNodeId(created.id);
  };

  const statusMeta = FOOTER_STATUS_META[engineStatus.state];
  const routingActive = isRoutingActiveState(engineStatus.state);

  return (
    <aside
      aria-label="Workflow Node Palette"
      className="flex w-64 shrink-0 flex-col border-r border-[#232830] bg-[#111418] text-[#F3F4F6] select-none"
    >
      {/* Brand Header */}
      <div className="flex h-12 shrink-0 items-center justify-between border-b border-[#232830] px-4">
        <NetFlowLogo size={22} />
        <button
          type="button"
          aria-label="Refresh discovery"
          title="Refresh interfaces, VPNs, and running apps"
          disabled={isRefreshing}
          onClick={() => void handleRefresh()}
          className="rounded p-1.5 text-[#9CA3AF] transition hover:bg-[#1D222B] hover:text-[#F3F4F6] disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
        </button>
      </div>

      {/* Resource Lists */}
      <div className="min-h-0 flex-1 overflow-y-auto">
        {/* 1. Network Interfaces */}
        <section className="border-b border-[#232830] py-3">
          <div className="mb-1.5 flex items-center justify-between px-4">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              Network Interfaces
            </span>
          </div>

          {discovery.interfaces.length === 0 ? (
            <div className="px-4 py-3 text-xs text-[#6B7280]">
              No interfaces detected.
            </div>
          ) : (
            <div className="divide-y divide-[#1A1F26]">
              {discovery.interfaces.map((iface) => {
                const payload: DragNodePayload = {
                  type: "interface",
                  interfaceAlias: iface.alias,
                };
                const isWifi = /wi-?fi|wlan/i.test(iface.alias);
                const Icon = isWifi ? Wifi : Network;

                return (
                  <div
                    key={iface.alias}
                    data-testid={`sidebar-interface-${iface.alias}`}
                    draggable
                    onDragStart={(e) => setDragPayload(e, payload)}
                    className="group flex cursor-grab items-center gap-2.5 px-4 py-2 transition hover:bg-[#161A20] active:cursor-grabbing"
                  >
                    <Icon
                      className={`h-4 w-4 shrink-0 ${
                        iface.isUp ? "text-[#3ECF8E]" : "text-[#6B7280]"
                      }`}
                    />
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className="truncate text-[13px] font-medium text-[#F3F4F6]">
                          {iface.alias}
                        </span>
                        <span
                          className={`ml-auto inline-flex items-center gap-1 text-[11px] ${
                            iface.isUp ? "text-[#3ECF8E]" : "text-[#6B7280]"
                          }`}
                        >
                          <span
                            className={`h-1.5 w-1.5 rounded-full ${
                              iface.isUp ? "bg-[#3ECF8E]" : "bg-[#4B5563]"
                            }`}
                          />
                          {iface.isUp ? "Up" : "Down"}
                        </span>
                      </div>
                      <div className="truncate font-mono text-[11px] text-[#6B7280]">
                        {iface.ipv4 ?? "No IPv4"}
                      </div>
                    </div>
                    <button
                      type="button"
                      aria-label={`Add ${iface.alias} interface`}
                      onClick={() => handleQuickAdd(payload)}
                      className="shrink-0 rounded border border-transparent p-1 text-[#6B7280] transition hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
                    >
                      <Plus className="h-3.5 w-3.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* 2. VPN Connections */}
        <section className="border-b border-[#232830] py-3">
          <div className="mb-1.5 px-4">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              VPN Connections
            </span>
          </div>

          <div className="divide-y divide-[#1A1F26]">
            {VPN_PROVIDERS.map((provider) => {
              const label = VPN_PROVIDER_LABELS[provider];
              const vpnInfo = discovery.vpns.find((v) => v.provider === provider);
              const isRunning = Boolean(vpnInfo?.isRunning);
              const onCanvas = graphNodes.some(
                (n) => n.kind.type === "vpn" && n.kind.provider === provider
              );
              const payload: DragNodePayload = { type: "vpn", provider };

              return (
                <div
                  key={provider}
                  data-testid={`sidebar-vpn-${provider}`}
                  draggable={!onCanvas}
                  aria-disabled={onCanvas}
                  onDragStart={(e) => {
                    if (onCanvas) {
                      e.preventDefault();
                      return;
                    }
                    setDragPayload(e, payload);
                  }}
                  className={`group flex items-center gap-2.5 px-4 py-2 transition ${
                    onCanvas
                      ? "cursor-not-allowed opacity-55"
                      : "cursor-grab hover:bg-[#161A20] active:cursor-grabbing"
                  }`}
                >
                  <Shield
                    className={`h-4 w-4 shrink-0 ${
                      isRunning ? "text-[#14B8A6]" : "text-[#6B7280]"
                    }`}
                  />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span className="truncate text-[13px] font-medium text-[#F3F4F6]">
                        {label}
                      </span>
                      <span
                        className={`ml-auto inline-flex items-center gap-1 text-[11px] ${
                          isRunning ? "text-[#3ECF8E]" : "text-[#6B7280]"
                        }`}
                      >
                        <span
                          className={`h-1.5 w-1.5 rounded-full ${
                            isRunning ? "bg-[#3ECF8E]" : "bg-[#4B5563]"
                          }`}
                        />
                        {isRunning ? "Running" : "Stopped"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between gap-2 text-[11px] text-[#6B7280]">
                      <span className="truncate">{getVpnHint(provider, vpnInfo)}</span>
                      {onCanvas && (
                        <span className="shrink-0 text-[10px] font-medium text-[#9CA3AF]">
                          On Canvas
                        </span>
                      )}
                    </div>
                  </div>
                  <button
                    type="button"
                    aria-label={`Add ${label} VPN`}
                    disabled={onCanvas}
                    onClick={() => handleQuickAdd(payload)}
                    className="shrink-0 rounded border border-transparent p-1 text-[#6B7280] transition hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6] disabled:cursor-not-allowed disabled:opacity-35"
                  >
                    <Plus className="h-3.5 w-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        </section>

        {/* 3. Connected Applications */}
        <section className="border-b border-[#232830] py-3">
          <div className="mb-1.5 px-4">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              Connected Applications
            </span>
          </div>

          <div
            data-testid="sidebar-apps-template"
            draggable
            onDragStart={(e) => setDragPayload(e, { type: "apps" })}
            className="group flex cursor-grab items-center gap-2.5 px-4 py-2 transition hover:bg-[#161A20] active:cursor-grabbing"
          >
            <AppWindow className="h-4 w-4 shrink-0 text-[#3ECF8E]" />
            <div className="min-w-0 flex-1">
              <div className="text-[13px] font-medium text-[#F3F4F6]">Connected Apps</div>
              <div className="text-[11px] text-[#6B7280]">Group Windows .exe apps</div>
            </div>
            <button
              type="button"
              aria-label="Add Connected Apps node"
              onClick={() => handleQuickAdd({ type: "apps" })}
              className="shrink-0 rounded border border-transparent p-1 text-[#6B7280] transition hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
            >
              <Plus className="h-3.5 w-3.5" />
            </button>
          </div>
        </section>

        {/* 4. Saved Connection Groups */}
        <section className="border-b border-[#232830] py-3">
          <div className="mb-1.5 flex items-center justify-between px-4">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              Saved Groups
            </span>
            <span className="rounded bg-[#161A20] px-1.5 py-0.5 font-mono text-[10px] text-[#9CA3AF]">
              {savedAppGroups.length}
            </span>
          </div>

          {savedAppGroups.length === 0 ? (
            <div className="px-4 py-2 text-[11px] leading-relaxed text-[#6B7280]">
              Name a Connected Apps node and save it from the inspector to reuse it here.
            </div>
          ) : (
            <div className="divide-y divide-[#1A1F26]">
              {savedAppGroups.map((group) => {
                const payload: DragNodePayload = {
                  type: "apps",
                  label: group.name,
                  apps: group.apps,
                  iconDataUrl: group.iconDataUrl ?? null,
                };
                return (
                  <div
                    key={group.id}
                    data-testid={`sidebar-saved-group-${group.id}`}
                    draggable
                    onDragStart={(e) => setDragPayload(e, payload)}
                    className="group flex cursor-grab items-center gap-2.5 px-4 py-2 transition hover:bg-[#161A20] active:cursor-grabbing"
                  >
                    {group.iconDataUrl ? (
                      <img
                        src={group.iconDataUrl}
                        alt=""
                        className="h-4 w-4 shrink-0 rounded-sm object-contain"
                      />
                    ) : (
                      <Bookmark className="h-4 w-4 shrink-0 text-[#14B8A6]" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px] font-medium text-[#F3F4F6]">
                        {group.name}
                      </div>
                      <div
                        title={group.apps.join(", ")}
                        className="truncate font-mono text-[11px] text-[#6B7280]"
                      >
                        {group.apps.length} {group.apps.length === 1 ? "exe" : "exes"}
                      </div>
                    </div>
                    <button
                      type="button"
                      aria-label={`Add ${group.name} group`}
                      onClick={() => handleQuickAdd(payload)}
                      className="shrink-0 rounded border border-transparent p-1 text-[#6B7280] transition hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6]"
                    >
                      <Plus className="h-3.5 w-3.5" />
                    </button>
                    <button
                      type="button"
                      aria-label={`Delete ${group.name} group`}
                      onClick={() => void deleteAppGroup(group.id)}
                      className="shrink-0 rounded border border-transparent p-1 text-[#6B7280] opacity-0 transition group-hover:opacity-100 hover:bg-rose-500/15 hover:text-rose-300 focus:opacity-100"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </section>

        {/* 5. Running Open Apps */}
        <section className="py-3">
          <div className="mb-1.5 flex items-center justify-between px-4">
            <span className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              Running Apps
            </span>
            <span className="rounded bg-[#161A20] px-1.5 py-0.5 font-mono text-[10px] text-[#9CA3AF]">
              {openApps.length}
            </span>
          </div>

          {openApps.length > 0 && (
            <div className="px-4 pb-2">
              <div className="relative flex items-center">
                <Search className="pointer-events-none absolute left-2 h-3 w-3 text-[#6B7280]" />
                <input
                  type="text"
                  value={openAppsQuery}
                  onChange={(e) => setOpenAppsQuery(e.target.value)}
                  placeholder="Filter running apps..."
                  aria-label="Filter running apps"
                  className="w-full rounded border border-[#232830] bg-[#0B0D10] py-1 pl-6 pr-2 text-[11px] text-[#F3F4F6] placeholder:text-[#6B7280] focus:border-[#3ECF8E] focus:outline-none"
                />
              </div>
            </div>
          )}

          {openApps.length === 0 ? (
            <div className="px-4 py-2 text-xs text-[#6B7280]">
              No open desktop apps detected.
            </div>
          ) : filteredOpenApps.length === 0 ? (
            <div className="px-4 py-2 text-xs text-[#6B7280]">
              No apps match &ldquo;{openAppsQuery.trim()}&rdquo;.
            </div>
          ) : (
            <div className="divide-y divide-[#1A1F26]">
              {filteredOpenApps.map((app) => {
                const onCanvas =
                  app.executables.length > 0 &&
                  app.executables.every((exe) => canvasExeSet.has(exe.toLowerCase()));
                const payload: DragNodePayload = {
                  type: "apps",
                  label: app.name,
                  apps: app.executables,
                  iconDataUrl: app.iconDataUrl,
                };
                const exeSummary =
                  app.executables.length > 1
                    ? `${app.primaryExe} +${app.executables.length - 1}`
                    : app.primaryExe;

                return (
                  <div
                    key={app.id}
                    data-testid={`sidebar-open-app-${app.id}`}
                    draggable={!onCanvas}
                    aria-disabled={onCanvas}
                    onDragStart={(e) => {
                      if (onCanvas) {
                        e.preventDefault();
                        return;
                      }
                      setDragPayload(e, payload);
                    }}
                    className={`group flex items-center gap-2.5 px-4 py-2 transition ${
                      onCanvas
                        ? "cursor-not-allowed opacity-55"
                        : "cursor-grab hover:bg-[#161A20] active:cursor-grabbing"
                    }`}
                  >
                    {app.iconDataUrl ? (
                      <img
                        src={app.iconDataUrl}
                        alt=""
                        className="h-4 w-4 shrink-0 rounded-sm object-contain"
                      />
                    ) : (
                      <AppWindow className="h-4 w-4 shrink-0 text-[#3ECF8E]" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-[13px] font-medium text-[#F3F4F6]">
                        {app.name}
                      </div>
                      <div className="flex items-center justify-between gap-2 text-[11px] text-[#6B7280]">
                        <span
                          title={app.executables.join(", ")}
                          className="truncate font-mono"
                        >
                          {exeSummary}
                        </span>
                        {onCanvas && (
                          <span className="shrink-0 text-[10px] font-medium text-[#9CA3AF]">
                            On Canvas
                          </span>
                        )}
                      </div>
                    </div>
                    <button
                      type="button"
                      aria-label={`Add ${app.name} app`}
                      disabled={onCanvas}
                      onClick={() => handleQuickAdd(payload)}
                      className="shrink-0 rounded border border-transparent p-1 text-[#6B7280] transition hover:border-[#2E3540] hover:bg-[#1D222B] hover:text-[#F3F4F6] disabled:cursor-not-allowed disabled:opacity-35"
                    >
                      <Plus className="h-3.5 w-3.5" />
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </section>
      </div>

      {/* Bottom Engine Status Footer */}
      <div className="border-t border-[#232830] p-3">
        <button
          type="button"
          onClick={toggleTrafficDrawer}
          className="flex w-full items-start gap-2.5 rounded-md border border-[#232830] bg-[#161A20] px-3 py-2 text-left transition hover:border-[#2E3540] hover:bg-[#1D222B]"
        >
          <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${statusMeta.dotClass}`} />
          <div className="min-w-0 flex-1">
            <div className="truncate text-xs font-medium text-[#F3F4F6]">
              {statusMeta.label}
            </div>
            <div className="truncate text-[11px] text-[#6B7280]">
              {routingActive && liveConnections.length > 0
                ? `${liveConnections.length} active connections`
                : statusMeta.subtitle}
            </div>
          </div>
        </button>
      </div>
    </aside>
  );
}
