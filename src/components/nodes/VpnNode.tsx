import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { Settings2, Shield, Trash2 } from "lucide-react";
import { useState } from "react";
import { useNetFlowStore } from "../../store/useNetFlowStore";
import type { WorkflowNode } from "../../types/workflow";
import {
  DefaultTogglePill,
  getNodeCardBorderClass,
  NodeErrorCallout,
  useNodeDiagnostics,
  VPN_PROVIDER_LABELS,
} from "./nodeShared";

export type VpnFlowNode = Node<{ node: WorkflowNode }, "vpn">;

export function VpnNode({ data, selected }: NodeProps<VpnFlowNode>) {
  const wfNode = data.node;
  const discoveryVpns = useNetFlowStore((s) => s.discovery.vpns);
  const removeNode = useNetFlowStore((s) => s.removeNode);
  const setDefaultNode = useNetFlowStore((s) => s.setDefaultNode);
  const updateVpnSettings = useNetFlowStore((s) => s.updateVpnSettings);
  const { nodeErrors, isDropped, hasIssue, errorTooltip } = useNodeDiagnostics(wfNode.id);

  const [settingsOpen, setSettingsOpen] = useState(false);

  if (wfNode.kind.type !== "vpn") {
    return null;
  }

  const { provider, isDefault, settings } = wfNode.kind;
  const providerLabel = VPN_PROVIDER_LABELS[provider];
  const vpnInfo = discoveryVpns.find((v) => v.provider === provider);
  const isRunning = Boolean(vpnInfo?.isRunning);

  const summaryText =
    provider === "karing"
      ? `Port: ${settings.karingPortOverride ?? vpnInfo?.detectedPort ?? "Auto"}`
      : provider === "cloudflareWarp"
        ? `Mode: ${settings.warpMode === "proxy" ? "Proxy (TCP-only)" : "TUN (Default)"}`
        : `Adapter: ${settings.openvpnAdapterOverride || vpnInfo?.adapterAlias || "Auto"}`;

  const handleKaringPortChange = (raw: string) => {
    const trimmed = raw.trim();
    if (!trimmed) {
      updateVpnSettings(wfNode.id, { karingPortOverride: null });
      return;
    }
    const parsed = Number.parseInt(trimmed, 10);
    if (Number.isInteger(parsed) && parsed >= 1 && parsed <= 65535) {
      updateVpnSettings(wfNode.id, { karingPortOverride: parsed });
    }
  };

  return (
    <div
      data-testid={`flow-node-${wfNode.id}`}
      title={errorTooltip}
      className={`relative w-64 rounded-xl border bg-slate-900/95 p-3 text-slate-100 shadow-lg shadow-black/40 transition ${getNodeCardBorderClass(
        hasIssue,
        Boolean(selected),
        isDefault
      )}`}
    >
      <Handle
        type="target"
        position={Position.Left}
        className="!h-3 !w-3 !border-2 !border-slate-950 !bg-violet-400"
      />

      <div className="flex items-start justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border border-violet-500/30 bg-violet-500/15 text-violet-300">
            <Shield className="h-4 w-4" />
          </span>
          <div className="min-w-0">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-violet-400">
              VPN Tunnel
            </div>
            <div className="truncate text-sm font-semibold text-slate-100">
              {providerLabel}
            </div>
          </div>
        </div>

        <div className="nodrag flex items-center gap-1">
          <button
            type="button"
            aria-label={`Configure ${providerLabel} settings`}
            aria-expanded={settingsOpen}
            onClick={() => setSettingsOpen((prev) => !prev)}
            className={`rounded p-1 transition ${
              settingsOpen
                ? "bg-violet-500/20 text-violet-200"
                : "text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            }`}
          >
            <Settings2 className="h-3.5 w-3.5" />
          </button>
          <button
            type="button"
            aria-label={`Delete ${providerLabel} node`}
            onClick={() => removeNode(wfNode.id)}
            className="rounded p-1 text-slate-500 transition hover:bg-rose-500/15 hover:text-rose-300"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>

      <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-xs">
        {isRunning ? (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-300">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400" />
            Running
          </span>
        ) : (
          <span className="inline-flex items-center gap-1.5 rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-[11px] font-medium text-slate-400">
            <span className="h-1.5 w-1.5 rounded-full bg-slate-500" />
            Stopped
          </span>
        )}

        {isDropped && (
          <span className="inline-flex items-center rounded-full border border-rose-500/40 bg-rose-500/20 px-2 py-0.5 text-[11px] font-semibold text-rose-300">
            Dropped
          </span>
        )}
      </div>

      <div className="mt-2 truncate rounded bg-slate-950/70 px-2 py-1 text-[11px] text-slate-300">
        {summaryText}
      </div>

      <div className="mt-2.5 flex items-center justify-between border-t border-slate-800/90 pt-2">
        <DefaultTogglePill
          isDefault={isDefault}
          onToggle={() => setDefaultNode(wfNode.id)}
        />
      </div>

      {settingsOpen && (
        <div
          className="nodrag nopan nowheel mt-2.5 space-y-2.5 rounded-lg border border-slate-700 bg-slate-950 p-2.5 text-xs shadow-xl"
          onKeyDown={(e) => e.stopPropagation()}
        >
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              {providerLabel} Settings
            </span>
            <button
              type="button"
              onClick={() => setSettingsOpen(false)}
              className="text-[11px] font-medium text-sky-400 hover:text-sky-300"
            >
              Done
            </button>
          </div>

          {provider === "karing" && (
            <label className="block space-y-1">
              <span className="text-[11px] text-slate-400">SOCKS / Mixed Port Override</span>
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
                className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100 outline-none focus:border-violet-500"
              />
            </label>
          )}

          {provider === "cloudflareWarp" && (
            <div className="space-y-1.5">
              <span className="block text-[11px] text-slate-400">Routing Mode</span>
              <div className="grid grid-cols-1 gap-1.5">
                <button
                  type="button"
                  aria-pressed={settings.warpMode === "tun"}
                  onClick={() => updateVpnSettings(wfNode.id, { warpMode: "tun" })}
                  className={`rounded border px-2.5 py-1.5 text-left text-[11px] font-medium transition ${
                    settings.warpMode === "tun"
                      ? "border-violet-500 bg-violet-500/20 text-violet-200"
                      : "border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800"
                  }`}
                >
                  TUN (Default)
                </button>
                <button
                  type="button"
                  aria-pressed={settings.warpMode === "proxy"}
                  onClick={() => updateVpnSettings(wfNode.id, { warpMode: "proxy" })}
                  className={`rounded border px-2.5 py-1.5 text-left text-[11px] font-medium transition ${
                    settings.warpMode === "proxy"
                      ? "border-violet-500 bg-violet-500/20 text-violet-200"
                      : "border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800"
                  }`}
                >
                  Proxy (TCP-only fallback)
                </button>
              </div>
            </div>
          )}

          {provider === "openVpn" && (
            <div className="space-y-2">
              <label className="block space-y-1">
                <span className="text-[11px] text-slate-400">Adapter Alias Override</span>
                <input
                  type="text"
                  value={settings.openvpnAdapterOverride ?? ""}
                  onChange={(e) =>
                    updateVpnSettings(wfNode.id, {
                      openvpnAdapterOverride: e.target.value || null,
                    })
                  }
                  onBlur={(e) =>
                    updateVpnSettings(wfNode.id, {
                      openvpnAdapterOverride: e.target.value.trim() || null,
                    })
                  }
                  placeholder={vpnInfo?.adapterAlias ?? "Auto-detect TAP/Wintun"}
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100 outline-none focus:border-violet-500"
                />
              </label>
              <label className="block space-y-1">
                <span className="text-[11px] text-slate-400">Remote Server IP Override</span>
                <input
                  type="text"
                  value={settings.openvpnServerIpOverride ?? ""}
                  onChange={(e) =>
                    updateVpnSettings(wfNode.id, {
                      openvpnServerIpOverride: e.target.value || null,
                    })
                  }
                  onBlur={(e) =>
                    updateVpnSettings(wfNode.id, {
                      openvpnServerIpOverride: e.target.value.trim() || null,
                    })
                  }
                  placeholder={vpnInfo?.remoteServerIp ?? "Auto-detect from config"}
                  className="w-full rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-100 outline-none focus:border-violet-500"
                />
              </label>
            </div>
          )}
        </div>
      )}

      <NodeErrorCallout errors={nodeErrors} tooltip={errorTooltip} />

      <Handle
        type="source"
        position={Position.Right}
        className="!h-3 !w-3 !border-2 !border-slate-950 !bg-violet-400"
      />
    </div>
  );
}
