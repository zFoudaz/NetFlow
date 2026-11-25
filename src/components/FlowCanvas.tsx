import {
  applyEdgeChanges,
  applyNodeChanges,
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
  type Connection,
  type Edge,
  type EdgeChange,
  type EdgeTypes,
  type IsValidConnection,
  type NodeChange,
  type NodeTypes,
  type OnSelectionChangeParams,
} from "@xyflow/react";
import { useCallback, useEffect, useRef, useState, type DragEvent, type MouseEvent } from "react";
import { useNetFlowStore } from "../store/useNetFlowStore";
import type { EngineStatus, WorkflowEdge, WorkflowNode } from "../types/workflow";
import { CanvasContextMenu } from "./CanvasContextMenu";
import { DeletableEdge } from "./edges/DeletableEdge";
import { AppsNode, type AppsFlowNode } from "./nodes/AppsNode";
import { HotspotNode, type HotspotFlowNode } from "./nodes/HotspotNode";
import { InterfaceNode, type InterfaceFlowNode } from "./nodes/InterfaceNode";
import {
  createWorkflowNode,
  getConflictingVpnProvider,
  NETFLOW_DND_MIME,
  parseDragNodePayload,
  type DragNodePayload,
} from "./nodes/nodeShared";
import { VpnNode, type VpnFlowNode } from "./nodes/VpnNode";

export type FlowNode = InterfaceFlowNode | VpnFlowNode | AppsFlowNode | HotspotFlowNode;

const nodeTypes: NodeTypes = {
  interface: InterfaceNode as NodeTypes[string],
  vpn: VpnNode as NodeTypes[string],
  apps: AppsNode as NodeTypes[string],
  hotspot: HotspotNode as NodeTypes[string],
};

const edgeTypes: EdgeTypes = {
  deletable: DeletableEdge,
};

function createsCycle(
  sourceId: string,
  targetId: string,
  edges: WorkflowEdge[]
): boolean {
  const outgoing = new Map<string, string[]>();
  for (const edge of edges) {
    const list = outgoing.get(edge.source);
    if (list) {
      list.push(edge.target);
    } else {
      outgoing.set(edge.source, [edge.target]);
    }
  }

  const visited = new Set<string>();
  const stack = [targetId];

  while (stack.length > 0) {
    const current = stack.pop()!;
    if (current === sourceId) {
      return true;
    }
    if (visited.has(current)) {
      continue;
    }
    visited.add(current);
    const children = outgoing.get(current);
    if (children) {
      for (const child of children) {
        if (!visited.has(child)) {
          stack.push(child);
        }
      }
    }
  }

  return false;
}

/**
 * Enforces workflow graph connection rules:
 * - Allowed: interface -> vpn, interface -> apps, vpn -> vpn (acyclic), vpn -> apps
 * - Disallowed: apps -> anything, anything -> interface, self-loops, cycles,
 *   duplicate edges, and >1 incoming edge into any vpn or apps node.
 */
export function isValidWorkflowConnection(
  connection: Connection | Pick<Edge, "source" | "target">,
  nodes: WorkflowNode[],
  edges: WorkflowEdge[],
  ignoreEdgeId?: string
): boolean {
  const { source, target } = connection;
  if (!source || !target || source === target) {
    return false;
  }

  const sourceNode = nodes.find((n) => n.id === source);
  const targetNode = nodes.find((n) => n.id === target);
  if (!sourceNode || !targetNode) {
    return false;
  }

  if (
    sourceNode.kind.type === "apps" ||
    sourceNode.kind.type === "hotspot" ||
    targetNode.kind.type === "interface"
  ) {
    return false;
  }

  const activeEdges = ignoreEdgeId
    ? edges.filter((e) => e.id !== ignoreEdgeId)
    : edges;

  if (activeEdges.some((e) => e.source === source && e.target === target)) {
    return false;
  }

  if (activeEdges.some((e) => e.target === target)) {
    return false;
  }

  if (createsCycle(source, target, activeEdges)) {
    return false;
  }

  return true;
}

function toFlowNodes(
  workflowNodes: WorkflowNode[],
  previousNodes: FlowNode[],
  selectedNodeId: string | null
): FlowNode[] {
  const prevById = new Map(previousNodes.map((n) => [n.id, n]));
  return workflowNodes.map((wfNode) => {
    const prev = prevById.get(wfNode.id);
    return {
      id: wfNode.id,
      type: wfNode.kind.type,
      position: { x: wfNode.x, y: wfNode.y },
      data: { node: wfNode },
      selected: selectedNodeId !== null && wfNode.id === selectedNodeId,
      measured: prev?.measured,
      dragging: prev?.dragging,
    } as FlowNode;
  });
}

function toFlowEdges(
  workflowEdges: WorkflowEdge[],
  engineStatus: EngineStatus,
  previousEdges: Edge[]
): Edge[] {
  const prevById = new Map(previousEdges.map((e) => [e.id, e]));
  const isActive = engineStatus.state === "active";

  return workflowEdges.map((wfEdge) => {
    const prev = prevById.get(wfEdge.id);
    const hasDroppedEndpoint =
      engineStatus.nodeHealth[wfEdge.source] === "dropped" ||
      engineStatus.nodeHealth[wfEdge.target] === "dropped";

    const isSelected = Boolean(prev?.selected);
    const stroke = hasDroppedEndpoint
      ? "#f43f5e"
      : isActive
        ? "#3ECF8E"
        : isSelected
          ? "#9CA3AF"
          : "#4B5563";

    return {
      id: wfEdge.id,
      source: wfEdge.source,
      target: wfEdge.target,
      type: "deletable",
      interactionWidth: 24,
      animated: isActive,
      selected: prev?.selected,
      style: {
        stroke,
        strokeWidth: isActive || isSelected ? 2 : 1.5,
      },
    };
  });
}

function FlowCanvasInner() {
  const graph = useNetFlowStore((s) => s.graph);
  const engineStatus = useNetFlowStore((s) => s.engineStatus);
  const selectedNodeId = useNetFlowStore((s) => s.selectedNodeId);
  const fitViewRequestCount = useNetFlowStore((s) => s.fitViewRequestCount);
  const addNode = useNetFlowStore((s) => s.addNode);
  const updateGraph = useNetFlowStore((s) => s.updateGraph);
  const setSelectedNodeId = useNetFlowStore((s) => s.setSelectedNodeId);

  const { screenToFlowPosition, fitView } = useReactFlow<FlowNode, Edge>();
  const dropzoneRef = useRef<HTMLDivElement | null>(null);
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    flowPosition: { x: number; y: number };
  } | null>(null);

  const rfNodesRef = useRef<FlowNode[]>(toFlowNodes(graph.nodes, [], selectedNodeId));
  const [rfNodes, setRfNodes] = useState<FlowNode[]>(rfNodesRef.current);

  const rfEdgesRef = useRef<Edge[]>(toFlowEdges(graph.edges, engineStatus, []));
  const [rfEdges, setRfEdges] = useState<Edge[]>(rfEdgesRef.current);

  useEffect(() => {
    const synced = toFlowNodes(graph.nodes, rfNodesRef.current, selectedNodeId);
    rfNodesRef.current = synced;
    setRfNodes(synced);
  }, [graph.nodes, selectedNodeId]);

  useEffect(() => {
    const synced = toFlowEdges(graph.edges, engineStatus, rfEdgesRef.current);
    rfEdgesRef.current = synced;
    setRfEdges(synced);
  }, [graph.edges, engineStatus]);

  useEffect(() => {
    if (fitViewRequestCount > 0) {
      void fitView({ padding: 0.25, duration: 200 });
    }
  }, [fitViewRequestCount, fitView]);

  const onNodesChange = useCallback(
    (changes: NodeChange<FlowNode>[]) => {
      const next = applyNodeChanges(changes, rfNodesRef.current);
      rfNodesRef.current = next;
      setRfNodes(next);

      const mutatesGraph = changes.some(
        (c) => (c.type === "position" && c.position != null) || c.type === "remove"
      );
      if (!mutatesGraph) {
        return;
      }

      const latestGraph = useNetFlowStore.getState().graph;
      const nodeById = new Map(latestGraph.nodes.map((n) => [n.id, n]));
      const nextWorkflowNodes: WorkflowNode[] = [];
      let changed = false;

      for (const rfNode of next) {
        const existing = nodeById.get(rfNode.id);
        if (existing) {
          if (existing.x !== rfNode.position.x || existing.y !== rfNode.position.y) {
            changed = true;
          }
          nextWorkflowNodes.push({
            ...existing,
            x: rfNode.position.x,
            y: rfNode.position.y,
          });
        }
      }

      if (!changed && nextWorkflowNodes.length === latestGraph.nodes.length) {
        return;
      }

      const survivingIds = new Set(nextWorkflowNodes.map((n) => n.id));
      const nextWorkflowEdges = latestGraph.edges.filter(
        (e) => survivingIds.has(e.source) && survivingIds.has(e.target)
      );
      updateGraph(nextWorkflowNodes, nextWorkflowEdges);
    },
    [updateGraph]
  );

  const onEdgesChange = useCallback(
    (changes: EdgeChange<Edge>[]) => {
      const next = applyEdgeChanges(changes, rfEdgesRef.current);
      rfEdgesRef.current = next;
      setRfEdges(next);

      if (!changes.some((c) => c.type === "remove")) {
        return;
      }

      const latestGraph = useNetFlowStore.getState().graph;
      const survivingIds = new Set(next.map((e) => e.id));
      const nextWorkflowEdges = latestGraph.edges.filter((e) => survivingIds.has(e.id));
      updateGraph(latestGraph.nodes, nextWorkflowEdges);
    },
    [updateGraph]
  );

  const onSelectionChange = useCallback(
    ({ nodes }: OnSelectionChangeParams<FlowNode, Edge>) => {
      const currentSelected = useNetFlowStore.getState().selectedNodeId;
      if (nodes.length === 0) {
        const currentRfNode = currentSelected
          ? rfNodesRef.current.find((n) => n.id === currentSelected)
          : undefined;
        if (!currentRfNode || !currentRfNode.selected) {
          if (currentSelected !== null) {
            setSelectedNodeId(null);
          }
        }
        return;
      }
      const nextId =
        nodes.length > 1 && currentSelected
          ? (nodes.find((n) => n.id !== currentSelected)?.id ?? nodes[0].id)
          : nodes[0].id;
      if (nextId !== currentSelected) {
        setSelectedNodeId(nextId);
      }
    },
    [setSelectedNodeId]
  );

  const onNodeClick = useCallback(
    (_event: MouseEvent, node: FlowNode) => {
      setContextMenu(null);
      setSelectedNodeId(node.id);
    },
    [setSelectedNodeId]
  );

  const onPaneClick = useCallback(() => {
    setContextMenu(null);
    setSelectedNodeId(null);
  }, [setSelectedNodeId]);

  const onPaneContextMenu = useCallback(
    (event: globalThis.MouseEvent | MouseEvent) => {
      event.preventDefault();
      const rect = dropzoneRef.current?.getBoundingClientRect();
      const rawX = rect ? event.clientX - rect.left : event.clientX;
      const rawY = rect ? event.clientY - rect.top : event.clientY;
      const menuWidth = 240;
      const menuHeight = 320;
      const maxX = rect ? Math.max(8, rect.width - menuWidth - 8) : rawX;
      const maxY = rect ? Math.max(8, rect.height - menuHeight - 8) : rawY;
      const x = Math.min(Math.max(8, rawX), maxX);
      const y = Math.min(Math.max(8, rawY), maxY);

      const rawFlow = screenToFlowPosition({ x: event.clientX, y: event.clientY });
      const flowPosition = {
        x: Number.isFinite(rawFlow.x) ? rawFlow.x : 160,
        y: Number.isFinite(rawFlow.y) ? rawFlow.y : 160,
      };
      setContextMenu({ x, y, flowPosition });
    },
    [screenToFlowPosition]
  );

  const handleAddNodeFromContextMenu = useCallback(
    (payload: DragNodePayload) => {
      if (!contextMenu) return;
      const latestNodes = useNetFlowStore.getState().graph.nodes;
      if (
        (payload.type === "vpn" &&
          (latestNodes.some((n) => n.kind.type === "vpn" && n.kind.provider === payload.provider) ||
            getConflictingVpnProvider(payload.provider, latestNodes) !== null)) ||
        (payload.type === "hotspot" && latestNodes.some((n) => n.kind.type === "hotspot"))
      ) {
        return;
      }
      const created = createWorkflowNode(payload, contextMenu.flowPosition);
      addNode(created);
      setSelectedNodeId(created.id);
      setContextMenu(null);
    },
    [addNode, contextMenu, setSelectedNodeId]
  );

  const isValidConnection = useCallback<IsValidConnection<Edge>>((edgeOrConnection) => {
    const latestGraph = useNetFlowStore.getState().graph;
    const ignoreId = "id" in edgeOrConnection ? edgeOrConnection.id : undefined;
    return isValidWorkflowConnection(
      edgeOrConnection,
      latestGraph.nodes,
      latestGraph.edges,
      ignoreId
    );
  }, []);

  const onConnect = useCallback(
    (connection: Connection) => {
      const latestGraph = useNetFlowStore.getState().graph;
      if (
        !isValidWorkflowConnection(connection, latestGraph.nodes, latestGraph.edges) ||
        !connection.source ||
        !connection.target
      ) {
        return;
      }

      const edgeId = `edge-${connection.source}-${connection.target}-${Date.now()}`;
      const newEdge: WorkflowEdge = {
        id: edgeId,
        source: connection.source,
        target: connection.target,
      };
      updateGraph(latestGraph.nodes, [...latestGraph.edges, newEdge]);
    },
    [updateGraph]
  );

  const onDragOver = useCallback((event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = "move";
    }
  }, []);

  const onDrop = useCallback(
    (event: DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      const raw =
        event.dataTransfer?.getData(NETFLOW_DND_MIME) ||
        event.dataTransfer?.getData("text/plain") ||
        "";
      const payload = parseDragNodePayload(raw);
      if (!payload) {
        return;
      }

      const latestNodes = useNetFlowStore.getState().graph.nodes;
      if (
        (payload.type === "vpn" &&
          (latestNodes.some((n) => n.kind.type === "vpn" && n.kind.provider === payload.provider) ||
            getConflictingVpnProvider(payload.provider, latestNodes) !== null)) ||
        (payload.type === "hotspot" && latestNodes.some((n) => n.kind.type === "hotspot"))
      ) {
        return;
      }

      const clientX = Number.isFinite(event.clientX) ? event.clientX : 0;
      const clientY = Number.isFinite(event.clientY) ? event.clientY : 0;
      const rawPosition = screenToFlowPosition({
        x: clientX,
        y: clientY,
      });
      const position = {
        x: Number.isFinite(rawPosition.x) ? rawPosition.x : 120,
        y: Number.isFinite(rawPosition.y) ? rawPosition.y : 120,
      };
      const created = createWorkflowNode(payload, position);
      addNode(created);
      setSelectedNodeId(created.id);
    },
    [addNode, screenToFlowPosition, setSelectedNodeId]
  );

  const onEdgeContextMenu = useCallback(
    (event: MouseEvent, edge: Edge) => {
      event.preventDefault();
      event.stopPropagation();
      const latestGraph = useNetFlowStore.getState().graph;
      const nextEdges = latestGraph.edges.filter((e) => e.id !== edge.id);
      if (nextEdges.length !== latestGraph.edges.length) {
        updateGraph(latestGraph.nodes, nextEdges);
      }
    },
    [updateGraph]
  );

  return (
    <div
      ref={dropzoneRef}
      data-testid="flow-canvas-dropzone"
      onDragOver={onDragOver}
      onDrop={onDrop}
      className="relative h-full w-full bg-[#0B0D10]"
    >
      <ReactFlow<FlowNode, Edge>
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        edgeTypes={edgeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onSelectionChange={onSelectionChange}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        onPaneContextMenu={onPaneContextMenu}
        onEdgeContextMenu={onEdgeContextMenu}
        onConnect={onConnect}
        isValidConnection={isValidConnection}
        deleteKeyCode={["Backspace", "Delete"]}
        colorMode="dark"
        fitView
        fitViewOptions={{ padding: 0.25 }}
        className="bg-[#0B0D10]"
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={22}
          size={1}
          color="#222730"
        />
        <Controls />
        <MiniMap
          pannable
          zoomable
          nodeColor={(node) => {
            if (node.type === "interface") return "#9CA3AF";
            if (node.type === "vpn") return "#14B8A6";
            if (node.type === "apps") return "#3ECF8E";
            if (node.type === "hotspot") return "#F59E0B";
            return "#4B5563";
          }}
          maskColor="rgba(11, 13, 16, 0.78)"
          className="!border !border-[#232830] !bg-[#111418]"
        />
      </ReactFlow>

      {graph.nodes.length === 0 && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-6">
          <div className="max-w-sm rounded-lg border border-dashed border-[#232830] bg-[#111418]/90 px-6 py-5 text-center">
            <h3 className="text-sm font-medium text-[#F3F4F6]">
              Empty Routing Canvas
            </h3>
            <p className="mt-1.5 text-xs leading-relaxed text-[#6B7280]">
              Drag or add a <span className="text-[#9CA3AF]">Network Interface</span>,{" "}
              <span className="text-[#14B8A6]">VPN Connection</span>, or{" "}
              <span className="text-[#3ECF8E]">Connected Apps</span> group from the left
              sidebar, then connect handles left to right.
            </p>
          </div>
        </div>
      )}

      {contextMenu && (
        <CanvasContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          onAddNode={handleAddNodeFromContextMenu}
          onClose={() => setContextMenu(null)}
        />
      )}
    </div>
  );
}

export function FlowCanvas() {
  return (
    <ReactFlowProvider>
      <FlowCanvasInner />
    </ReactFlowProvider>
  );
}
