import {
  AlertCircle,
  AppWindow,
  CheckCircle2,
  Info,
  Plus,
  Save,
  Shield,
  SlidersHorizontal,
  Trash2,
  X,
} from "lucide-react";
import { useState } from "react";
import { useNetFlowStore } from "../store/useNetFlowStore";
import type { WorkflowNode } from "../types/workflow";
import { AddAppModal, normalizeExeBasename } from "./AddAppModal";
import {
  DefaultTogglePill,
  getInterfaceIcon,
  NodeErrorCallout,
  useNodeDiagnostics,
  VPN_PROVIDER_LABELS,
} from "./nodes/nodeShared";

function formatNodeName(node: WorkflowNode): string {
  if (node.kind.type === "interface") return node.kind.interfaceAlias;
  if (node.kind.type === "vpn") return VPN_PROVIDER_LABELS[node.kind.provider];
  return `Connected Apps (${node.kind.apps.length})`;
}

export function PropertiesPanel() {
  const selectedNodeId = useNetFlowStore((s) => s.selectedNodeId);
  const graph = useNetFlowStore((s) => s.graph);
  const discovery = useNetFlowStore((s) => s.discovery);
  const validationErrors = useNetFlowStore((s) => s.validationErrors);
  const currentWorkflowName = useNetFlowStore((s) => s.currentWorkflowName);
  const isDirty = useNetFlowStore((s) => s.isDirty);

  const setDefaultNode = useNetFlowStore((s) => s.setDefaultNode);
  const updateVpnSettings = useNetFlowStore((s) => s.updateVpnSettings);
  const updateNodeApps = useNetFlowStore((s) => s.updateNodeApps);
  const updateGraph = useNetFlowStore((s) => s.updateGraph);
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const validateCurrentGraph = useNetFlowStore((s) => s.validateCurrentGraph);
  const saveCurrentWorkflow = useNetFlowStore((s) => s.saveCurrentWorkflow);

  const [addModalOpen, setAddModalOpen] = useState(false);

  const selectedNode = selectedNodeId
    ? graph.nodes.find((n) => n.id === selectedNodeId)
    : undefined;

  if (!selectedNode) {
    const ifaceCount = graph.nodes.filter((n) => n.kind.type === "interface").length;
    const vpnCount = graph.nodes.filter((n) => n.kind.type === "vpn").length;
    const appsCount = graph.nodes.filter((n) => n.kind.type === "apps").length;

    return (
      <aside
        aria-label="Workflow Properties"
        className="flex w-72 shrink-0 flex-col border-l border-[#232830] bg-[#111418] text-[#F3F4F6]"
      >
        <div className="flex h-10 shrink-0 items-center gap-2 border-b border-[#232830] px-4">
          <Info className="h-3.5 w-3.5 text-[#9CA3AF]" />
          <span className="text-xs font-semibold uppercase tracking-wider text-[#9CA3AF]">
            Workflow Info
          </span>
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto">
          <section className="border-b border-[#232830] px-4 py-3.5">
            <div className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              Active Plan
            </div>
            <div className="mt-1 truncate text-sm font-semibold text-[#F3F4F6]">
              {currentWorkflowName}
            </div>
            <div className="mt-1 flex items-center gap-1.5 text-xs">
              <span
                className={`h-1.5 w-1.5 rounded-full ${
                  isDirty ? "bg-amber-400" : "bg-[#3ECF8E]"
                }`}
              />
              <span className={isDirty ? "text-amber-300" : "text-[#9CA3AF]"}>
                {isDirty ? "Unsaved changes" : "Saved"}
              </span>
            </div>
          </section>

          <section className="border-b border-[#232830] px-4 py-3.5">
            <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              Topology Summary
            </div>
            <dl className="space-y-1.5 text-xs">
              <div className="flex items-center justify-between">
                <dt className="text-[#9CA3AF]">Physical Interfaces</dt>
                <dd className="font-mono text-[#F3F4F6]">{ifaceCount}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-[#9CA3AF]">VPN Connections</dt>
                <dd className="font-mono text-[#F3F4F6]">{vpnCount}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-[#9CA3AF]">Application Groups</dt>
                <dd className="font-mono text-[#F3F4F6]">{appsCount}</dd>
              </div>
              <div className="flex items-center justify-between">
                <dt className="text-[#9CA3AF]">Routing Links</dt>
                <dd className="font-mono text-[#F3F4F6]">{graph.edges.length}</dd>
              </div>
            </dl>
          </section>

          <section className="border-b border-[#232830] px-4 py-3.5">
            <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              Validation
            </div>
            {validationErrors.length === 0 ? (
              <div className="flex items-center gap-2 text-xs text-[#9CA3AF]">
                <CheckCircle2 className="h-3.5 w-3.5 text-[#3ECF8E]" />
                <span>No validation issues detected</span>
              </div>
            ) : (
              <div className="space-y-2">
                {validationErrors.map((err, idx) => (
                  <div
                    key={`${err.code}-${idx}`}
                    className="flex items-start gap-2 rounded border border-rose-500/35 bg-rose-950/40 px-2.5 py-2 text-xs text-rose-200"
                  >
                    <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-400" />
                    <span>{err.message}</span>
                  </div>
                ))}
              </div>
            )}
          </section>

          <section className="px-4 py-3.5">
            <div className="grid grid-cols-2 gap-2">
              <button
                type="button"
                onClick={() => void validateCurrentGraph()}
                className="inline-flex items-center justify-center gap-1.5 rounded-md border border-[#232830] bg-[#161A20] px-2.5 py-1.5 text-xs font-medium text-[#F3F4F6] transition hover:border-[#2E3540] hover:bg-[#1D222B]"
              >
                <CheckCircle2 className="h-3.5 w-3.5 text-[#3ECF8E]" />
                Validate
              </button>
              <button
                type="button"
                onClick={() => void saveCurrentWorkflow()}
                className="inline-flex items-center justify-center gap-1.5 rounded-md border border-[#232830] bg-[#161A20] px-2.5 py-1.5 text-xs font-medium text-[#F3F4F6] transition hover:border-[#2E3540] hover:bg-[#1D222B]"
              >
                <Save className="h-3.5 w-3.5 text-[#9CA3AF]" />
                Save
              </button>
            </div>
            <p className="mt-3 text-[11px] leading-relaxed text-[#6B7280]">
              Select any node on the canvas to inspect or edit its properties.
            </p>
          </section>
        </div>
      </aside>
    );
  }

  return (
    <NodeInspector
      node={selectedNode}
      graph={graph}
      discovery={discovery}
      setDefaultNode={setDefaultNode}
      updateVpnSettings={updateVpnSettings}
      updateNodeApps={updateNodeApps}
      updateGraph={updateGraph}
      removeNode={removeNode}
      addModalOpen={addModalOpen}
      setAddModalOpen={setAddModalOpen}
    />
  );
}

interface NodeInspectorProps {
  node: WorkflowNode;
  graph: ReturnType<typeof useNetFlowStore.getState>["graph"];
  discovery: ReturnType<typeof useNetFlowStore.getState>["discovery"];
  setDefaultNode: (nodeId: string, isDefault?: boolean) => void;
  updateVpnSettings: (
    nodeId: string,
    settings: Partial<import("../types/workflow").VpnNodeSettings>
  ) => void;
  updateNodeApps: (nodeId: string, apps: string[]) => void;
  updateGraph: (
    nodes: WorkflowNode[],
    edges: import("../types/workflow").WorkflowEdge[]
  ) => void;
  removeNode: (nodeId: string) => void;
  addModalOpen: boolean;
  setAddModalOpen: (open: boolean) => void;
}

function NodeInspector({
  node,
  graph,
  discovery,
  setDefaultNode,
  updateVpnSettings,
  updateNodeApps,
  updateGraph,
  removeNode,
  addModalOpen,
  setAddModalOpen,
}: NodeInspectorProps) {
  const { nodeErrors, isDropped, errorTooltip } = useNodeDiagnostics(node.id);

  return (
    <aside
      aria-label="Node Properties"
      className="flex w-72 shrink-0 flex-col border-l border-[#232830] bg-[#111418] text-[#F3F4F6]"
    >
      <div className="flex h-10 shrink-0 items-center gap-2 border-b border-[#232830] px-4">
        <SlidersHorizontal className="h-3.5 w-3.5 text-[#3ECF8E]" />
        <span className="text-xs font-semibold uppercase tracking-wider text-[#9CA3AF]">
          Node Properties
        </span>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto">
        {node.kind.type === "interface" && (() => {
          const { interfaceAlias, isDefault } = node.kind;
          const ifaceInfo = discovery.interfaces.find((i) => i.alias === interfaceAlias);
          const isUp = Boolean(ifaceInfo?.isUp);
          const Icon = getInterfaceIcon(interfaceAlias);
          const downstreamNodes = graph.edges
            .filter((e) => e.source === node.id)
            .map((e) => graph.nodes.find((n) => n.id === e.target))
            .filter((n): n is WorkflowNode => Boolean(n));

          return (
            <>
              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="flex items-center gap-2.5">
                  <Icon
                    className={`h-5 w-5 shrink-0 ${
                      isUp ? "text-[#3ECF8E]" : "text-[#6B7280]"
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-[#F3F4F6]">
                      {interfaceAlias}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 text-xs">
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          isUp ? "bg-[#3ECF8E]" : "bg-amber-400"
                        }`}
                      />
                      <span className={isUp ? "text-[#3ECF8E]" : "text-amber-300"}>
                        {isUp ? "Connected" : "Offline"}
                      </span>
                      {isDropped && (
                        <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] text-rose-300">
                          Dropped
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />
              </section>

              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                  Interface Details
                </div>
                <dl className="space-y-2 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-[#9CA3AF]">IPv4 Address</dt>
                    <dd className="font-mono text-[#F3F4F6]">
                      {ifaceInfo?.ipv4 ?? "N/A"}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-[#9CA3AF]">Gateway</dt>
                    <dd className="font-mono text-[#F3F4F6]">
                      {ifaceInfo?.gatewayIpv4 ?? "N/A"}
                    </dd>
                  </div>
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-[#9CA3AF]">Link Speed</dt>
                    <dd className="font-mono text-[#F3F4F6]">
                      {ifaceInfo?.linkSpeedMbps ? `${ifaceInfo.linkSpeedMbps} Mbps` : "N/A"}
                    </dd>
                  </div>
                  {ifaceInfo?.description && (
                    <div className="pt-1">
                      <dt className="text-[#9CA3AF]">Adapter</dt>
                      <dd className="mt-0.5 text-[11px] text-[#6B7280]">
                        {ifaceInfo.description}
                      </dd>
                    </div>
                  )}
                </dl>
              </section>

              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                  Default Route
                </div>
                <DefaultTogglePill
                  isDefault={isDefault}
                  onToggle={() => setDefaultNode(node.id)}
                />
              </section>

              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                  Downstream Targets ({downstreamNodes.length})
                </div>
                {downstreamNodes.length === 0 ? (
                  <p className="text-xs text-[#6B7280]">No downstream nodes connected.</p>
                ) : (
                  <ul className="space-y-1 text-xs text-[#D1D5DB]">
                    {downstreamNodes.map((target) => (
                      <li key={target.id} className="truncate">
                        • {formatNodeName(target)}
                      </li>
                    ))}
                  </ul>
                )}
              </section>

              <div className="px-4 py-3.5">
                <button
                  type="button"
                  onClick={() => removeNode(node.id)}
                  className="inline-flex w-full items-center justify-center gap-1.5 rounded-md border border-rose-500/35 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 transition hover:bg-rose-500/20"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Remove Interface
                </button>
              </div>
            </>
          );
        })()}

        {node.kind.type === "vpn" && (() => {
          const { provider, isDefault, settings } = node.kind;
          const providerLabel = VPN_PROVIDER_LABELS[provider];
          const vpnInfo = discovery.vpns.find((v) => v.provider === provider);
          const isRunning = Boolean(vpnInfo?.isRunning);

          const interfaceNodes = graph.nodes.filter((n) => n.kind.type === "interface");
          const currentIncomingEdge = graph.edges.find((e) => e.target === node.id);
          const currentInterfaceId =
            currentIncomingEdge &&
            interfaceNodes.some((iface) => iface.id === currentIncomingEdge.source)
              ? currentIncomingEdge.source
              : "";

          const handleInterfaceChange = (nextInterfaceId: string) => {
            const withoutIncoming = graph.edges.filter((e) => e.target !== node.id);
            if (!nextInterfaceId) {
              updateGraph(graph.nodes, withoutIncoming);
              return;
            }
            const nextEdge = {
              id: `edge-${nextInterfaceId}-${node.id}-${Date.now()}`,
              source: nextInterfaceId,
              target: node.id,
            };
            updateGraph(graph.nodes, [...withoutIncoming, nextEdge]);
          };

          const handleKaringPortChange = (raw: string) => {
            const trimmed = raw.trim();
            if (!trimmed) {
              updateVpnSettings(node.id, { karingPortOverride: null });
              return;
            }
            const parsed = Number.parseInt(trimmed, 10);
            if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535) {
              updateVpnSettings(node.id, { karingPortOverride: parsed });
            }
          };

          const downstreamAppsNodes = graph.edges
            .filter((e) => e.source === node.id)
            .map((e) => graph.nodes.find((n) => n.id === e.target))
            .filter((n): n is WorkflowNode => Boolean(n && n.kind.type === "apps"));

          return (
            <>
              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="flex items-center gap-2.5">
                  <Shield
                    className={`h-5 w-5 shrink-0 ${
                      isRunning ? "text-[#14B8A6]" : "text-[#6B7280]"
                    }`}
                  />
                  <div className="min-w-0">
                    <div className="truncate text-sm font-semibold text-[#F3F4F6]">
                      {providerLabel}
                    </div>
                    <div className="mt-0.5 flex items-center gap-1.5 text-xs">
                      <span
                        className={`h-1.5 w-1.5 rounded-full ${
                          isRunning ? "bg-[#3ECF8E]" : "bg-[#6B7280]"
                        }`}
                      />
                      <span className={isRunning ? "text-[#3ECF8E]" : "text-[#9CA3AF]"}>
                        {isRunning ? "Running" : "Stopped"}
                      </span>
                      {isDropped && (
                        <span className="rounded bg-rose-500/20 px-1.5 py-0.5 text-[10px] text-rose-300">
                          Dropped
                        </span>
                      )}
                    </div>
                  </div>
                </div>
                <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />
              </section>

              <section className="border-b border-[#232830] px-4 py-3.5">
                <label className="block space-y-1.5">
                  <span className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                    Physical Interface
                  </span>
                  <select
                    aria-label="Associated Physical Interface"
                    value={currentInterfaceId}
                    onChange={(e) => handleInterfaceChange(e.target.value)}
                    className="w-full rounded-md border border-[#232830] bg-[#161A20] px-2.5 py-1.5 text-xs text-[#F3F4F6] outline-none focus:border-[#3ECF8E]"
                  >
                    <option value="">None (Unlinked)</option>
                    {interfaceNodes.map((iface) => {
                      if (iface.kind.type !== "interface") return null;
                      const alias = iface.kind.interfaceAlias;
                      const ifaceInfo = discovery.interfaces.find((i) => i.alias === alias);
                      return (
                        <option key={iface.id} value={iface.id}>
                          {alias}
                          {ifaceInfo?.ipv4 ? ` (${ifaceInfo.ipv4})` : ""}
                        </option>
                      );
                    })}
                  </select>
                </label>
                <p className="mt-1.5 text-[11px] text-[#6B7280]">
                  A VPN tunnel binds to a single upstream physical interface.
                </p>
              </section>

              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                  VPN Details
                </div>
                <dl className="space-y-1.5 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <dt className="text-[#9CA3AF]">Provider</dt>
                    <dd className="text-[#F3F4F6]">{providerLabel}</dd>
                  </div>
                  {provider === "karing" ? (
                    <div className="flex items-center justify-between gap-2">
                      <dt className="text-[#9CA3AF]">Detected Port</dt>
                      <dd className="font-mono text-[#F3F4F6]">
                        {vpnInfo?.detectedPort ?? "Auto"}
                      </dd>
                    </div>
                  ) : (
                    <>
                      <div className="flex items-center justify-between gap-2">
                        <dt className="text-[#9CA3AF]">Adapter</dt>
                        <dd className="truncate font-mono text-[#F3F4F6]">
                          {vpnInfo?.adapterAlias ?? "Auto"}
                        </dd>
                      </div>
                      <div className="flex items-center justify-between gap-2">
                        <dt className="text-[#9CA3AF]">Server</dt>
                        <dd className="truncate font-mono text-[#F3F4F6]">
                          {vpnInfo?.remoteServerIp ?? "Auto"}
                        </dd>
                      </div>
                    </>
                  )}
                </dl>
              </section>

              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                  Configuration
                </div>

                {provider === "karing" && (
                  <label className="block space-y-1">
                    <span className="text-xs text-[#9CA3AF]">SOCKS / Mixed Port Override</span>
                    <input
                      type="number"
                      min={1}
                      max={65535}
                      value={settings.karingPortOverride ?? ""}
                      onChange={(e) => handleKaringPortChange(e.target.value)}
                      placeholder={
                        vpnInfo?.detectedPort
                          ? `Detected (${vpnInfo.detectedPort})`
                          : "Auto-detect port"
                      }
                      className="w-full rounded-md border border-[#232830] bg-[#0B0D10] px-2.5 py-1.5 text-xs text-[#F3F4F6] placeholder-[#6B7280] outline-none focus:border-[#3ECF8E]"
                    />
                  </label>
                )}

                {provider === "openVpn" && (
                  <div className="space-y-2.5">
                    <label className="block space-y-1">
                      <span className="text-xs text-[#9CA3AF]">Adapter Alias Override</span>
                      <input
                        type="text"
                        value={settings.openvpnAdapterOverride ?? ""}
                        onChange={(e) =>
                          updateVpnSettings(node.id, {
                            openvpnAdapterOverride: e.target.value || null,
                          })
                        }
                        onBlur={(e) =>
                          updateVpnSettings(node.id, {
                            openvpnAdapterOverride: e.target.value.trim() || null,
                          })
                        }
                        placeholder={vpnInfo?.adapterAlias ?? "Auto-detect TAP/Wintun"}
                        className="w-full rounded-md border border-[#232830] bg-[#0B0D10] px-2.5 py-1.5 text-xs text-[#F3F4F6] placeholder-[#6B7280] outline-none focus:border-[#3ECF8E]"
                      />
                    </label>
                    <label className="block space-y-1">
                      <span className="text-xs text-[#9CA3AF]">Remote Server IP Override</span>
                      <input
                        type="text"
                        value={settings.openvpnServerIpOverride ?? ""}
                        onChange={(e) =>
                          updateVpnSettings(node.id, {
                            openvpnServerIpOverride: e.target.value || null,
                          })
                        }
                        onBlur={(e) =>
                          updateVpnSettings(node.id, {
                            openvpnServerIpOverride: e.target.value.trim() || null,
                          })
                        }
                        placeholder={vpnInfo?.remoteServerIp ?? "Auto-detect from config"}
                        className="w-full rounded-md border border-[#232830] bg-[#0B0D10] px-2.5 py-1.5 text-xs text-[#F3F4F6] placeholder-[#6B7280] outline-none focus:border-[#3ECF8E]"
                      />
                    </label>
                  </div>
                )}

                <div className="mt-3">
                  <DefaultTogglePill
                    isDefault={isDefault}
                    onToggle={() => setDefaultNode(node.id)}
                  />
                </div>
              </section>

              {downstreamAppsNodes.length > 0 && (
                <section className="border-b border-[#232830] px-4 py-3.5">
                  <div className="mb-2 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                    Routed App Groups
                  </div>
                  <ul className="space-y-1 text-xs text-[#D1D5DB]">
                    {downstreamAppsNodes.map((appsNode) => (
                      <li key={appsNode.id}>• {formatNodeName(appsNode)}</li>
                    ))}
                  </ul>
                </section>
              )}

              <div className="px-4 py-3.5">
                <button
                  type="button"
                  onClick={() => removeNode(node.id)}
                  className="inline-flex w-full items-center justify-center gap-1.5 rounded-md border border-rose-500/35 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 transition hover:bg-rose-500/20"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Remove VPN
                </button>
              </div>
            </>
          );
        })()}

        {node.kind.type === "apps" && (() => {
          const { apps } = node.kind;
          const incomingEdge = graph.edges.find((e) => e.target === node.id);
          const upstreamNode = incomingEdge
            ? graph.nodes.find((n) => n.id === incomingEdge.source)
            : undefined;
          const routeLabel = upstreamNode ? formatNodeName(upstreamNode) : "Unconnected";

          const handleAddApp = (exeName: string) => {
            const normalized = normalizeExeBasename(exeName) ?? exeName.toLowerCase();
            if (
              !apps.some(
                (app) => (normalizeExeBasename(app) ?? app.toLowerCase()) === normalized
              )
            ) {
              updateNodeApps(node.id, [...apps, normalized]);
            }
          };

          const handleRemoveApp = (exeName: string) => {
            updateNodeApps(
              node.id,
              apps.filter((app) => app !== exeName)
            );
          };

          return (
            <>
              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="flex items-center gap-2.5">
                  <AppWindow className="h-5 w-5 shrink-0 text-[#3ECF8E]" />
                  <div className="min-w-0">
                    <div className="text-sm font-semibold text-[#F3F4F6]">
                      Connected Apps
                    </div>
                    <div className="mt-0.5 text-xs text-[#9CA3AF]">
                      {apps.length} {apps.length === 1 ? "application" : "applications"}
                    </div>
                  </div>
                </div>
                <div className="mt-2.5 flex items-center justify-between text-xs">
                  <span className="text-[#6B7280]">Routed Via</span>
                  <span className="font-medium text-[#3ECF8E]">{routeLabel}</span>
                </div>
                <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />
              </section>

              <section className="border-b border-[#232830] px-4 py-3.5">
                <div className="mb-2 flex items-center justify-between">
                  <span className="text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
                    Executables
                  </span>
                </div>

                {apps.length === 0 ? (
                  <p className="py-2 text-xs text-[#6B7280]">
                    No applications assigned yet.
                  </p>
                ) : (
                  <ul className="max-h-60 divide-y divide-[#232830] overflow-y-auto">
                    {apps.map((exe) => (
                      <li
                        key={exe}
                        className="flex items-center justify-between gap-2 py-1.5 text-xs"
                      >
                        <span className="truncate font-mono text-[#E5E7EB]">{exe}</span>
                        <button
                          type="button"
                          aria-label={`Remove ${exe} from inspector`}
                          onClick={() => handleRemoveApp(exe)}
                          className="shrink-0 rounded p-0.5 text-[#6B7280] transition hover:bg-rose-500/15 hover:text-rose-300"
                        >
                          <X className="h-3.5 w-3.5" />
                        </button>
                      </li>
                    ))}
                  </ul>
                )}

                <button
                  type="button"
                  onClick={() => setAddModalOpen(true)}
                  className="mt-3 inline-flex w-full items-center justify-center gap-1.5 rounded-md border border-[#232830] bg-[#161A20] px-3 py-1.5 text-xs font-medium text-[#F3F4F6] transition hover:border-[#3ECF8E]/40 hover:bg-[#1D222B] hover:text-[#3ECF8E]"
                >
                  <Plus className="h-3.5 w-3.5" />
                  Add Application
                </button>
              </section>

              <div className="px-4 py-3.5">
                <button
                  type="button"
                  onClick={() => removeNode(node.id)}
                  className="inline-flex w-full items-center justify-center gap-1.5 rounded-md border border-rose-500/35 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 transition hover:bg-rose-500/20"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Remove Group
                </button>
              </div>

              <AddAppModal
                isOpen={addModalOpen}
                existingApps={apps}
                onAddApp={handleAddApp}
                onClose={() => setAddModalOpen(false)}
              />
            </>
          );
        })()}
      </div>
    </aside>
  );
}
