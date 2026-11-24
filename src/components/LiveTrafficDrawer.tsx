import { useMemo, useState } from "react";
import { Activity, ArrowDown, ArrowUp, Search, X } from "lucide-react";
import { useNetFlowStore } from "../store/useNetFlowStore";
import type { LiveConnection, WorkflowNode } from "../types/workflow";
import { VPN_PROVIDER_LABELS } from "./nodes/nodeShared";

const BYTE_UNITS = ["B", "KB", "MB", "GB", "TB"] as const;

/** Formats a byte count into a human-readable string (B, KB, MB, GB, TB). */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) {
    return "0 B";
  }
  let value = bytes;
  let unitIndex = 0;
  while (value >= 1024 && unitIndex < BYTE_UNITS.length - 1) {
    value /= 1024;
    unitIndex += 1;
  }
  if (unitIndex === 0) {
    return `${Math.round(value)} B`;
  }
  return `${value.toFixed(1)} ${BYTE_UNITS[unitIndex]}`;
}

function resolveNodeLabel(node: WorkflowNode | undefined, outboundTag: string): string {
  if (node?.kind.type === "interface") {
    return node.kind.interfaceAlias;
  }
  if (node?.kind.type === "vpn") {
    return VPN_PROVIDER_LABELS[node.kind.provider];
  }
  const normalized = outboundTag.toLowerCase();
  if (normalized === "block" || normalized === "reject") {
    return "Blocked";
  }
  if (normalized === "default-direct") {
    return "Default Direct";
  }
  return outboundTag;
}

function getOutboundBadgeClass(node: WorkflowNode | undefined, outboundTag: string): string {
  const tag = outboundTag.toLowerCase();
  if (
    tag === "block" ||
    tag === "reject" ||
    tag.startsWith("block-") ||
    tag.startsWith("reject-")
  ) {
    return "border-rose-500/40 bg-rose-500/15 text-rose-300";
  }
  if (node?.kind.type === "vpn" || tag.startsWith("vpn-")) {
    return "border-violet-500/40 bg-violet-500/15 text-violet-300";
  }
  if (
    node?.kind.type === "interface" ||
    tag.startsWith("if-") ||
    tag.startsWith("iface-")
  ) {
    return "border-emerald-500/40 bg-emerald-500/15 text-emerald-300";
  }
  return "border-slate-600 bg-slate-800 text-slate-300";
}

interface EnrichedConnection {
  conn: LiveConnection;
  nodeLabel: string;
  badgeClass: string;
}

/** Collapsible bottom drawer displaying real-time routed connections and filter controls. */
export function LiveTrafficDrawer() {
  const isTrafficDrawerOpen = useNetFlowStore((s) => s.isTrafficDrawerOpen);
  const liveConnections = useNetFlowStore((s) => s.liveConnections);
  const graph = useNetFlowStore((s) => s.graph);
  const toggleTrafficDrawer = useNetFlowStore((s) => s.toggleTrafficDrawer);

  const [filterQuery, setFilterQuery] = useState("");

  const nodesById = useMemo(() => {
    const map = new Map<string, WorkflowNode>();
    for (const node of graph.nodes) {
      map.set(node.id, node);
    }
    return map;
  }, [graph.nodes]);

  const enrichedConnections = useMemo<EnrichedConnection[]>(() => {
    return liveConnections.map((conn) => {
      const matchedNode = conn.nodeId ? nodesById.get(conn.nodeId) : undefined;
      return {
        conn,
        nodeLabel: resolveNodeLabel(matchedNode, conn.outboundTag),
        badgeClass: getOutboundBadgeClass(matchedNode, conn.outboundTag),
      };
    });
  }, [liveConnections, nodesById]);

  const filteredConnections = useMemo(() => {
    const query = filterQuery.trim().toLowerCase();
    if (!query) {
      return enrichedConnections;
    }
    return enrichedConnections.filter(({ conn, nodeLabel }) => {
      return (
        conn.processName.toLowerCase().includes(query) ||
        conn.destination.toLowerCase().includes(query) ||
        nodeLabel.toLowerCase().includes(query) ||
        conn.outboundTag.toLowerCase().includes(query) ||
        conn.network.toLowerCase().includes(query)
      );
    });
  }, [enrichedConnections, filterQuery]);

  if (!isTrafficDrawerOpen) {
    return null;
  }

  return (
    <section
      aria-label="Live Traffic Log"
      className="flex h-64 shrink-0 flex-col border-t border-slate-800 bg-slate-900/95 text-slate-100"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 px-4 py-2">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-sky-400" />
          <h2 className="text-xs font-semibold uppercase tracking-wide text-slate-200">
            Live Traffic
          </h2>
          <span className="rounded-full bg-slate-800 px-2 py-0.5 text-[11px] font-medium text-slate-300">
            {filterQuery.trim()
              ? `${filteredConnections.length} / ${liveConnections.length}`
              : liveConnections.length}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative flex items-center">
            <Search className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-slate-400" />
            <input
              type="text"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="Filter process, destination, node, outbound..."
              aria-label="Filter live traffic"
              className="w-72 rounded-md border border-slate-700 bg-slate-950 py-1 pl-8 pr-7 text-xs text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
            />
            {filterQuery && (
              <button
                type="button"
                onClick={() => setFilterQuery("")}
                aria-label="Clear filter"
                className="absolute right-2 rounded p-0.5 text-slate-400 hover:text-slate-200"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>

          <button
            type="button"
            onClick={toggleTrafficDrawer}
            aria-label="Close Live Traffic"
            className="rounded-md p-1 text-slate-400 transition hover:bg-slate-800 hover:text-slate-100"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {liveConnections.length === 0 ? (
          <div className="flex h-full items-center justify-center px-4 text-xs text-slate-400">
            No active connections yet — start routing to see live traffic
          </div>
        ) : filteredConnections.length === 0 ? (
          <div className="flex h-full items-center justify-center px-4 text-xs text-slate-400">
            No connections match &ldquo;{filterQuery.trim()}&rdquo;.
          </div>
        ) : (
          <table className="w-full border-collapse text-left text-xs">
            <thead className="sticky top-0 z-10 border-b border-slate-800 bg-slate-900 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
              <tr>
                <th className="px-4 py-2">Process</th>
                <th className="px-4 py-2">Destination</th>
                <th className="px-4 py-2">Protocol</th>
                <th className="px-4 py-2">Matched Node / Outbound</th>
                <th className="px-4 py-2 text-right">Up / Down</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredConnections.map(({ conn, nodeLabel, badgeClass }) => (
                <tr key={conn.id} className="hover:bg-slate-800/40">
                  <td className="whitespace-nowrap px-4 py-1.5 font-medium text-slate-100">
                    {conn.processName}
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5 font-mono text-slate-300">
                    {conn.destination}
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5 uppercase text-slate-400">
                    {conn.network}
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5">
                    <div className="inline-flex items-center gap-2">
                      <span
                        data-testid={`outbound-badge-${conn.id}`}
                        className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${badgeClass}`}
                      >
                        {nodeLabel}
                      </span>
                      {nodeLabel !== conn.outboundTag && (
                        <span className="font-mono text-[11px] text-slate-500">
                          {conn.outboundTag}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5 text-right font-mono text-slate-300">
                    <span className="inline-flex items-center gap-2">
                      <span className="inline-flex items-center gap-0.5 text-sky-300">
                        <ArrowUp className="h-3 w-3" />
                        {formatBytes(conn.uploadBytes)}
                      </span>
                      <span className="text-slate-600">/</span>
                      <span className="inline-flex items-center gap-0.5 text-emerald-300">
                        <ArrowDown className="h-3 w-3" />
                        {formatBytes(conn.downloadBytes)}
                      </span>
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </section>
  );
}
