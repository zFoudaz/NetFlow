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
    return "border-rose-500/40 bg-rose-500/10 text-rose-300";
  }
  if (node?.kind.type === "vpn" || tag.startsWith("vpn-")) {
    return "border-teal-500/40 bg-teal-500/10 text-teal-300";
  }
  if (
    node?.kind.type === "interface" ||
    tag.startsWith("if-") ||
    tag.startsWith("iface-")
  ) {
    return "border-emerald-500/40 bg-emerald-500/10 text-emerald-300";
  }
  return "border-[#2E3540] bg-[#161A20] text-[#9CA3AF]";
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
      className="flex h-64 shrink-0 flex-col border-t border-[#232830] bg-[#111418] text-[#F3F4F6]"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#232830] px-4 py-2">
        <div className="flex items-center gap-2">
          <Activity className="h-4 w-4 text-[#3ECF8E]" />
          <h2 className="text-xs font-semibold uppercase tracking-wide text-[#F3F4F6]">
            Live Traffic
          </h2>
          <span className="rounded bg-[#161A20] px-2 py-0.5 font-mono text-[11px] font-medium text-[#9CA3AF]">
            {filterQuery.trim()
              ? `${filteredConnections.length} / ${liveConnections.length}`
              : liveConnections.length}
          </span>
        </div>

        <div className="flex items-center gap-2">
          <div className="relative flex items-center">
            <Search className="pointer-events-none absolute left-2.5 h-3.5 w-3.5 text-[#6B7280]" />
            <input
              type="text"
              value={filterQuery}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="Filter process, destination, node, outbound..."
              aria-label="Filter live traffic"
              className="w-72 rounded-md border border-[#232830] bg-[#0B0D10] py-1 pl-8 pr-7 text-xs text-[#F3F4F6] placeholder:text-[#6B7280] focus:border-[#3ECF8E] focus:outline-none"
            />
            {filterQuery && (
              <button
                type="button"
                onClick={() => setFilterQuery("")}
                aria-label="Clear filter"
                className="absolute right-2 rounded p-0.5 text-[#6B7280] hover:text-[#F3F4F6]"
              >
                <X className="h-3 w-3" />
              </button>
            )}
          </div>

          <button
            type="button"
            onClick={toggleTrafficDrawer}
            aria-label="Close Live Traffic"
            className="rounded p-1 text-[#9CA3AF] transition hover:bg-[#1D222B] hover:text-[#F3F4F6]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-auto">
        {liveConnections.length === 0 ? (
          <div className="flex h-full items-center justify-center px-4 text-xs text-[#6B7280]">
            No active connections yet — start routing to see live traffic
          </div>
        ) : filteredConnections.length === 0 ? (
          <div className="flex h-full items-center justify-center px-4 text-xs text-[#6B7280]">
            No connections match &ldquo;{filterQuery.trim()}&rdquo;.
          </div>
        ) : (
          <table className="w-full border-collapse text-left text-xs">
            <thead className="sticky top-0 z-10 border-b border-[#232830] bg-[#111418] text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
              <tr>
                <th className="px-4 py-2">Process</th>
                <th className="px-4 py-2">Destination</th>
                <th className="px-4 py-2">Protocol</th>
                <th className="px-4 py-2">Matched Node / Outbound</th>
                <th className="px-4 py-2 text-right">Up / Down</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1A1F26]">
              {filteredConnections.map(({ conn, nodeLabel, badgeClass }) => (
                <tr key={conn.id} className="hover:bg-[#161A20]">
                  <td className="whitespace-nowrap px-4 py-1.5 font-medium text-[#F3F4F6]">
                    {conn.processName}
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5 font-mono text-[#9CA3AF]">
                    {conn.destination}
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5 uppercase text-[#6B7280]">
                    {conn.network}
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5">
                    <div className="inline-flex items-center gap-2">
                      <span
                        data-testid={`outbound-badge-${conn.id}`}
                        className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-medium ${badgeClass}`}
                      >
                        {nodeLabel}
                      </span>
                      {nodeLabel !== conn.outboundTag && (
                        <span className="font-mono text-[11px] text-[#6B7280]">
                          {conn.outboundTag}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-4 py-1.5 text-right font-mono text-[#D1D5DB]">
                    <span className="inline-flex items-center gap-2">
                      <span className="inline-flex items-center gap-0.5 text-[#14B8A6]">
                        <ArrowUp className="h-3 w-3" />
                        {formatBytes(conn.uploadBytes)}
                      </span>
                      <span className="text-[#4B5563]">/</span>
                      <span className="inline-flex items-center gap-0.5 text-[#3ECF8E]">
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
