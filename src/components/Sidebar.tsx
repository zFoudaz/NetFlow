import { AppWindow, GripVertical, Network, Plus, RefreshCw, Shield } from "lucide-react";
import { useState, type DragEvent } from "react";
import { useNetFlowStore } from "../store/useNetFlowStore";
import type { DetectedVpnInfo, VpnProvider } from "../types/workflow";
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
  return info?.adapterAlias ? `Adapter: ${info.adapterAlias}` : "TAP / Wintun";
}

function setDragPayload(event: DragEvent<HTMLElement>, payload: DragNodePayload) {
  const serialized = JSON.stringify(payload);
  event.dataTransfer.setData(NETFLOW_DND_MIME, serialized);
  event.dataTransfer.setData("text/plain", serialized);
  event.dataTransfer.effectAllowed = "move";
}

export function Sidebar() {
  const discovery = useNetFlowStore((s) => s.discovery);
  const graphNodes = useNetFlowStore((s) => s.graph.nodes);
  const refreshDiscovery = useNetFlowStore((s) => s.refreshDiscovery);
  const addNode = useNetFlowStore((s) => s.addNode);

  const [isRefreshing, setIsRefreshing] = useState(false);

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
    addNode(createWorkflowNode(payload, pos));
  };

  return (
    <aside
      aria-label="Workflow Node Palette"
      className="flex w-72 shrink-0 flex-col overflow-y-auto border-r border-slate-800 bg-slate-900/90 text-slate-100 select-none"
    >
      <div className="border-b border-slate-800 px-4 py-3">
        <h2 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          Components
        </h2>
        <p className="mt-0.5 text-[11px] text-slate-500">
          Drag onto the canvas or click + to add.
        </p>
      </div>

      {/* Interfaces Section */}
      <section className="border-b border-slate-800/80 px-3 py-3">
        <div className="mb-2 flex items-center justify-between px-1">
          <div className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider text-slate-300">
            <Network className="h-3.5 w-3.5 text-sky-400" />
            <span>Interfaces</span>
          </div>
          <button
            type="button"
            aria-label="Refresh discovery"
            title="Refresh interfaces, VPNs, and running apps"
            disabled={isRefreshing}
            onClick={() => void handleRefresh()}
            className="rounded p-1 text-slate-400 transition hover:bg-slate-800 hover:text-slate-100 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
          </button>
        </div>

        {discovery.interfaces.length === 0 ? (
          <div className="rounded-lg border border-dashed border-slate-800 px-3 py-3 text-center text-[11px] text-slate-500">
            No interfaces detected. Click refresh.
          </div>
        ) : (
          <div className="space-y-1.5">
            {discovery.interfaces.map((iface) => {
              const payload: DragNodePayload = {
                type: "interface",
                interfaceAlias: iface.alias,
              };
              return (
                <div
                  key={iface.alias}
                  data-testid={`sidebar-interface-${iface.alias}`}
                  draggable
                  onDragStart={(e) => setDragPayload(e, payload)}
                  className="group flex cursor-grab items-center gap-2 rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-2 transition hover:border-sky-500/40 hover:bg-slate-800/70 active:cursor-grabbing"
                >
                  <GripVertical className="h-3.5 w-3.5 shrink-0 text-slate-600 group-hover:text-slate-400" />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-1.5">
                      <span
                        className={`h-2 w-2 shrink-0 rounded-full ${
                          iface.isUp ? "bg-emerald-400" : "bg-slate-500"
                        }`}
                      />
                      <span className="truncate text-xs font-semibold text-slate-100">
                        {iface.alias}
                      </span>
                      <span
                        className={`ml-auto shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium ${
                          iface.isUp
                            ? "bg-emerald-500/15 text-emerald-300"
                            : "bg-slate-800 text-slate-400"
                        }`}
                      >
                        {iface.isUp ? "Up" : "Down"}
                      </span>
                    </div>
                    <div className="mt-0.5 truncate font-mono text-[11px] text-slate-400">
                      {iface.ipv4 ?? "No IPv4"}
                    </div>
                  </div>
                  <button
                    type="button"
                    aria-label={`Add ${iface.alias} interface`}
                    onClick={() => handleQuickAdd(payload)}
                    className="shrink-0 rounded border border-slate-700 bg-slate-900 p-1 text-slate-300 transition hover:border-sky-500/50 hover:bg-sky-500/20 hover:text-sky-200"
                  >
                    <Plus className="h-3.5 w-3.5" />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* VPNs Section */}
      <section className="border-b border-slate-800/80 px-3 py-3">
        <div className="mb-2 flex items-center gap-1.5 px-1 text-xs font-semibold uppercase tracking-wider text-slate-300">
          <Shield className="h-3.5 w-3.5 text-violet-400" />
          <span>VPNs</span>
        </div>

        <div className="space-y-1.5">
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
                className={`group flex items-center gap-2 rounded-lg border px-2.5 py-2 transition ${
                  onCanvas
                    ? "cursor-not-allowed border-slate-800/60 bg-slate-950/40 opacity-60"
                    : "cursor-grab border-slate-800 bg-slate-950/70 hover:border-violet-500/40 hover:bg-slate-800/70 active:cursor-grabbing"
                }`}
              >
                <GripVertical className="h-3.5 w-3.5 shrink-0 text-slate-600" />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-1.5">
                    <span
                      className={`h-2 w-2 shrink-0 rounded-full ${
                        isRunning ? "bg-emerald-400" : "bg-slate-500"
                      }`}
                    />
                    <span className="truncate text-xs font-semibold text-slate-100">
                      {label}
                    </span>
                    <span
                      className={`ml-auto shrink-0 rounded px-1.5 py-0.5 text-[10px] font-medium ${
                        isRunning
                          ? "bg-emerald-500/15 text-emerald-300"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      {isRunning ? "Running" : "Stopped"}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-center justify-between gap-2">
                    <span className="truncate text-[11px] text-slate-400">
                      {getVpnHint(provider, vpnInfo)}
                    </span>
                    {onCanvas && (
                      <span className="shrink-0 rounded border border-slate-700 bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-300">
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
                  className="shrink-0 rounded border border-slate-700 bg-slate-900 p-1 text-slate-300 transition hover:border-violet-500/50 hover:bg-violet-500/20 hover:text-violet-200 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Plus className="h-3.5 w-3.5" />
                </button>
              </div>
            );
          })}
        </div>
      </section>

      {/* Apps Section */}
      <section className="px-3 py-3">
        <div className="mb-2 flex items-center gap-1.5 px-1 text-xs font-semibold uppercase tracking-wider text-slate-300">
          <AppWindow className="h-3.5 w-3.5 text-emerald-400" />
          <span>Apps</span>
        </div>

        <div
          data-testid="sidebar-apps-template"
          draggable
          onDragStart={(e) => setDragPayload(e, { type: "apps" })}
          className="group flex cursor-grab items-center gap-2 rounded-lg border border-slate-800 bg-slate-950/70 px-2.5 py-2.5 transition hover:border-emerald-500/40 hover:bg-slate-800/70 active:cursor-grabbing"
        >
          <GripVertical className="h-3.5 w-3.5 shrink-0 text-slate-600 group-hover:text-slate-400" />
          <div className="min-w-0 flex-1">
            <div className="text-xs font-semibold text-slate-100">Connected Apps</div>
            <div className="text-[11px] text-slate-400">
              Assign Windows .exe processes
            </div>
          </div>
          <button
            type="button"
            aria-label="Add Connected Apps node"
            onClick={() => handleQuickAdd({ type: "apps" })}
            className="shrink-0 rounded border border-slate-700 bg-slate-900 p-1 text-slate-300 transition hover:border-emerald-500/50 hover:bg-emerald-500/20 hover:text-emerald-200"
          >
            <Plus className="h-3.5 w-3.5" />
          </button>
        </div>
      </section>
    </aside>
  );
}
