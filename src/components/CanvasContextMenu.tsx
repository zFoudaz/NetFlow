import { AppWindow, Bookmark, Check, Radio, Search, Shield } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNetFlowStore } from "../store/useNetFlowStore";
import {
  getConflictingVpnProvider,
  getInterfaceIcon,
  VPN_PROVIDER_LABELS,
  VPN_PROVIDERS,
  type DragNodePayload,
} from "./nodes/nodeShared";

interface CanvasContextMenuProps {
  x: number;
  y: number;
  onAddNode: (payload: DragNodePayload) => void;
  onClose: () => void;
}

export function CanvasContextMenu({
  x,
  y,
  onAddNode,
  onClose,
}: CanvasContextMenuProps) {
  const discovery = useNetFlowStore((s) => s.discovery);
  const graphNodes = useNetFlowStore((s) => s.graph.nodes);
  const savedAppGroups = useNetFlowStore((s) => s.savedAppGroups);

  const [query, setQuery] = useState("");
  const menuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        onClose();
      }
    };
    const handleMouseDown = (event: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    window.addEventListener("mousedown", handleMouseDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
      window.removeEventListener("mousedown", handleMouseDown);
    };
  }, [onClose]);

  const canvasExeSet = useMemo(() => {
    const set = new Set<string>();
    for (const node of graphNodes) {
      if (node.kind.type === "apps") {
        for (const exe of node.kind.apps) {
          const normalized = exe.trim().toLowerCase();
          if (normalized) set.add(normalized);
        }
      }
    }
    return set;
  }, [graphNodes]);

  const normalizedQuery = query.trim().toLowerCase();

  const filteredInterfaces = useMemo(
    () =>
      discovery.interfaces.filter(
        (iface) =>
          !normalizedQuery || iface.alias.toLowerCase().includes(normalizedQuery)
      ),
    [discovery.interfaces, normalizedQuery]
  );

  const filteredVpns = useMemo(
    () =>
      VPN_PROVIDERS.filter((provider) => {
        if (!normalizedQuery) return true;
        return (
          VPN_PROVIDER_LABELS[provider].toLowerCase().includes(normalizedQuery) ||
          provider.toLowerCase().includes(normalizedQuery)
        );
      }),
    [normalizedQuery]
  );

  const showAppsTemplate =
    !normalizedQuery ||
    "connected apps".includes(normalizedQuery) ||
    "group".includes(normalizedQuery);

  const showHotspot =
    !normalizedQuery ||
    "mobile hotspot".includes(normalizedQuery) ||
    "share".includes(normalizedQuery);

  const hotspotOnCanvas = graphNodes.some((n) => n.kind.type === "hotspot");
  const hotspotActive = Boolean(discovery.hotspot?.isActive);

  const filteredSavedGroups = useMemo(
    () =>
      savedAppGroups.filter(
        (group) =>
          !normalizedQuery ||
          group.name.toLowerCase().includes(normalizedQuery) ||
          group.apps.some((exe) => exe.toLowerCase().includes(normalizedQuery))
      ),
    [savedAppGroups, normalizedQuery]
  );

  const filteredOpenApps = useMemo(
    () =>
      (discovery.openApps ?? []).filter(
        (app) =>
          !normalizedQuery ||
          app.name.toLowerCase().includes(normalizedQuery) ||
          app.primaryExe.toLowerCase().includes(normalizedQuery) ||
          app.executables.some((exe) => exe.toLowerCase().includes(normalizedQuery))
      ),
    [discovery.openApps, normalizedQuery]
  );

  const hasAnyMatches =
    filteredInterfaces.length > 0 ||
    filteredVpns.length > 0 ||
    showAppsTemplate ||
    showHotspot ||
    filteredSavedGroups.length > 0 ||
    filteredOpenApps.length > 0;

  const pickItem = (payload: DragNodePayload) => {
    onAddNode(payload);
    onClose();
  };

  return (
    <div
      ref={menuRef}
      role="menu"
      aria-label="Add node menu"
      style={{ left: x, top: y }}
      onContextMenu={(e) => e.preventDefault()}
      className="absolute z-40 flex max-h-80 w-60 flex-col overflow-hidden rounded-lg border border-[#2E3540] bg-[#111418] text-[#F3F4F6] shadow-xl shadow-black/50 select-none"
    >
      <div className="border-b border-[#232830] p-2">
        <div className="relative flex items-center">
          <Search className="pointer-events-none absolute left-2 h-3.5 w-3.5 text-[#6B7280]" />
          <input
            type="text"
            autoFocus
            aria-label="Search nodes to add"
            placeholder="Add node..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="w-full rounded border border-[#232830] bg-[#0B0D10] py-1 pl-7 pr-2 text-xs text-[#F3F4F6] placeholder:text-[#6B7280] focus:border-[#3ECF8E] focus:outline-none"
          />
        </div>
      </div>

      <div className="min-h-0 flex-1 overflow-y-auto py-1">
        {!hasAnyMatches && (
          <div className="px-3 py-4 text-center text-xs text-[#6B7280]">
            No matching nodes
          </div>
        )}

        {filteredInterfaces.length > 0 && (
          <div className="py-1">
            <div className="px-3 py-1 text-[10px] font-medium uppercase tracking-wider text-[#6B7280]">
              Interfaces
            </div>
            {filteredInterfaces.map((iface) => {
              const Icon = getInterfaceIcon(iface.alias);
              return (
                <button
                  key={iface.alias}
                  type="button"
                  role="menuitem"
                  onClick={() =>
                    pickItem({ type: "interface", interfaceAlias: iface.alias })
                  }
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-[#1D222B]"
                >
                  <Icon
                    className={`h-3.5 w-3.5 shrink-0 ${
                      iface.isUp ? "text-[#3ECF8E]" : "text-[#6B7280]"
                    }`}
                  />
                  <span className="min-w-0 flex-1 truncate font-medium">
                    {iface.alias}
                  </span>
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      iface.isUp ? "bg-[#3ECF8E]" : "bg-[#4B5563]"
                    }`}
                  />
                </button>
              );
            })}
          </div>
        )}

        {filteredVpns.length > 0 && (
          <div className="border-t border-[#1A1F26] py-1">
            <div className="px-3 py-1 text-[10px] font-medium uppercase tracking-wider text-[#6B7280]">
              VPNs
            </div>
            {filteredVpns.map((provider) => {
              const label = VPN_PROVIDER_LABELS[provider];
              const vpnInfo = discovery.vpns.find((v) => v.provider === provider);
              const isRunning = Boolean(vpnInfo?.isRunning);
              const onCanvas = graphNodes.some(
                (n) => n.kind.type === "vpn" && n.kind.provider === provider
              );
              const conflictingProvider = onCanvas
                ? null
                : getConflictingVpnProvider(provider, graphNodes);
              const isDisabled = onCanvas || conflictingProvider !== null;

              return (
                <button
                  key={provider}
                  type="button"
                  role="menuitem"
                  disabled={isDisabled}
                  title={
                    conflictingProvider
                      ? `Blocked by ${VPN_PROVIDER_LABELS[conflictingProvider]}`
                      : onCanvas
                        ? "Already on canvas"
                        : undefined
                  }
                  onClick={() => pickItem({ type: "vpn", provider })}
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-[#1D222B] disabled:cursor-not-allowed disabled:opacity-45"
                >
                  <Shield
                    className={`h-3.5 w-3.5 shrink-0 ${
                      isRunning ? "text-[#3ECF8E]" : "text-[#6B7280]"
                    }`}
                  />
                  <span className="min-w-0 flex-1 truncate font-medium">
                    {label}
                  </span>
                  {onCanvas ? (
                    <Check className="h-3.5 w-3.5 shrink-0 text-[#9CA3AF]" />
                  ) : conflictingProvider ? (
                    <span className="inline-flex h-3.5 w-3.5 shrink-0 items-center justify-center rounded-full bg-amber-400 text-[9px] font-bold text-[#111418]">
                      !
                    </span>
                  ) : (
                    <span
                      className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                        isRunning ? "bg-[#3ECF8E]" : "bg-[#4B5563]"
                      }`}
                    />
                  )}
                </button>
              );
            })}
          </div>
        )}

        {(showAppsTemplate ||
          showHotspot ||
          filteredSavedGroups.length > 0 ||
          filteredOpenApps.length > 0) && (
          <div className="border-t border-[#1A1F26] py-1">
            <div className="px-3 py-1 text-[10px] font-medium uppercase tracking-wider text-[#6B7280]">
              Applications
            </div>

            {showAppsTemplate && (
              <button
                type="button"
                role="menuitem"
                onClick={() => pickItem({ type: "apps" })}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-[#1D222B]"
              >
                <AppWindow className="h-3.5 w-3.5 shrink-0 text-[#3ECF8E]" />
                <span className="min-w-0 flex-1 truncate font-medium">
                  Connected Apps
                </span>
              </button>
            )}

            {showHotspot && (
              <button
                type="button"
                role="menuitem"
                disabled={hotspotOnCanvas}
                onClick={() => pickItem({ type: "hotspot" })}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-[#1D222B] disabled:cursor-not-allowed disabled:opacity-45"
              >
                <Radio
                  className={`h-3.5 w-3.5 shrink-0 ${
                    hotspotActive ? "text-amber-400" : "text-[#6B7280]"
                  }`}
                />
                <span className="min-w-0 flex-1 truncate font-medium">
                  Mobile Hotspot
                </span>
                {hotspotOnCanvas ? (
                  <Check className="h-3.5 w-3.5 shrink-0 text-[#9CA3AF]" />
                ) : (
                  <span
                    className={`h-1.5 w-1.5 shrink-0 rounded-full ${
                      hotspotActive ? "bg-[#3ECF8E]" : "bg-[#4B5563]"
                    }`}
                  />
                )}
              </button>
            )}

            {filteredSavedGroups.map((group) => (
              <button
                key={group.id}
                type="button"
                role="menuitem"
                onClick={() =>
                  pickItem({
                    type: "apps",
                    label: group.name,
                    apps: group.apps,
                    iconDataUrl: group.iconDataUrl ?? null,
                  })
                }
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-[#1D222B]"
              >
                {group.iconDataUrl ? (
                  <img
                    src={group.iconDataUrl}
                    alt=""
                    className="h-3.5 w-3.5 shrink-0 rounded-sm object-contain"
                  />
                ) : (
                  <Bookmark className="h-3.5 w-3.5 shrink-0 text-[#14B8A6]" />
                )}
                <span className="min-w-0 flex-1 truncate font-medium">
                  {group.name}
                </span>
              </button>
            ))}

            {filteredOpenApps.map((app) => {
              const onCanvas =
                app.executables.length > 0 &&
                app.executables.every((exe) => canvasExeSet.has(exe.toLowerCase()));
              return (
                <button
                  key={app.id}
                  type="button"
                  role="menuitem"
                  disabled={onCanvas}
                  onClick={() =>
                    pickItem({
                      type: "apps",
                      label: app.name,
                      apps: app.executables,
                      iconDataUrl: app.iconDataUrl,
                    })
                  }
                  className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-xs transition hover:bg-[#1D222B] disabled:cursor-not-allowed disabled:opacity-45"
                >
                  {app.iconDataUrl ? (
                    <img
                      src={app.iconDataUrl}
                      alt=""
                      className="h-3.5 w-3.5 shrink-0 rounded-sm object-contain"
                    />
                  ) : (
                    <AppWindow className="h-3.5 w-3.5 shrink-0 text-[#3ECF8E]" />
                  )}
                  <span className="min-w-0 flex-1 truncate font-medium">
                    {app.name}
                  </span>
                  {onCanvas && (
                    <Check className="h-3.5 w-3.5 shrink-0 text-[#9CA3AF]" />
                  )}
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
