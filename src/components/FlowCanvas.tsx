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
  type IsValidConnection,
  type NodeChange,
  type NodeTypes,
} from "@xyflow/react";
import { useCallback, useEffect, useRef, useState, type DragEvent } from "react";
import { useNetFlowStore } from "../store/useNetFlowStore";
import type { EngineStatus, WorkflowEdge, WorkflowNode } from "../types/workflow";
import { AppsNode, type AppsFlowNode } from "./nodes/AppsNode";
import { InterfaceNode, type InterfaceFlowNode } from "./nodes/InterfaceNode";
import {
  createWorkflowNode,
  NETFLOW_DND_MIME,
  parseDragNodePayload,
} from "./nodes/nodeShared";
import { VpnNode, type VpnFlowNode } from "./nodes/VpnNode";

export type FlowNode = InterfaceFlowNode | VpnFlowNode | AppsFlowNode;

const nodeTypes: NodeTypes = {
  interface: InterfaceNode as NodeTypes[string],
  vpn: VpnNode as NodeTypes[string],
  apps: AppsNode as NodeTypes[string],
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

  if (sourceNode.kind.type === "apps" || targetNode.kind.type === "interface") {
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
  previousNodes: FlowNode[]
): FlowNode[] {
  const prevById = new Map(previousNodes.map((n) => [n.id, n]));
  return workflowNodes.map((wfNode) => {
    const prev = prevById.get(wfNode.id);
    return {
      id: wfNode.id,
      type: wfNode.kind.type,
      position: { x: wfNode.x, y: wfNode.y },
      data: { node: wfNode },
      selected: prev?.selected,
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

    const stroke = hasDroppedEndpoint
      ? "#f43f5e"
      : isActive
        ? "#38bdf8"
        : "#64748b";

    return {
      id: wfEdge.id,
      source: wfEdge.source,
      target: wfEdge.target,
      type: "smoothstep",
      animated: isActive,
      selected: prev?.selected,
      style: {
        stroke,
        strokeWidth: isActive ? 2.25 : 1.75,
      },
    };
  });
}

function FlowCanvasInner() {
  const graph = useNetFlowStore((s) => s.graph);
  const engineStatus = useNetFlowStore((s) => s.engineStatus);
  const addNode = useNetFlowStore((s) => s.addNode);
  const updateGraph = useNetFlowStore((s) => s.updateGraph);

  const { screenToFlowPosition } = useReactFlow<FlowNode, Edge>();

  const rfNodesRef = useRef<FlowNode[]>(toFlowNodes(graph.nodes, []));
  const [rfNodes, setRfNodes] = useState<FlowNode[]>(rfNodesRef.current);

  const rfEdgesRef = useRef<Edge[]>(toFlowEdges(graph.edges, engineStatus, []));
  const [rfEdges, setRfEdges] = useState<Edge[]>(rfEdgesRef.current);

  useEffect(() => {
    const synced = toFlowNodes(graph.nodes, rfNodesRef.current);
    rfNodesRef.current = synced;
    setRfNodes(synced);
  }, [graph.nodes]);

  useEffect(() => {
    const synced = toFlowEdges(graph.edges, engineStatus, rfEdgesRef.current);
    rfEdgesRef.current = synced;
    setRfEdges(synced);
  }, [graph.edges, engineStatus]);

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
        payload.type === "vpn" &&
        latestNodes.some((n) => n.kind.type === "vpn" && n.kind.provider === payload.provider)
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
      addNode(createWorkflowNode(payload, position));
    },
    [addNode, screenToFlowPosition]
  );

  return (
    <div
      data-testid="flow-canvas-dropzone"
      onDragOver={onDragOver}
      onDrop={onDrop}
      className="relative h-full w-full bg-slate-950"
    >
      <ReactFlow<FlowNode, Edge>
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onConnect={onConnect}
        isValidConnection={isValidConnection}
        deleteKeyCode={["Backspace", "Delete"]}
        colorMode="dark"
        fitView
        fitViewOptions={{ padding: 0.25 }}
        className="bg-slate-950"
      >
        <Background
          variant={BackgroundVariant.Dots}
          gap={20}
          size={1.25}
          color="#334155"
        />
        <Controls className="!border-slate-700 !bg-slate-900 !shadow-lg" />
        <MiniMap
          pannable
          zoomable
          nodeColor={(node) => {
            if (node.type === "interface") return "#38bdf8";
            if (node.type === "vpn") return "#a78bfa";
            if (node.type === "apps") return "#34d399";
            return "#64748b";
          }}
          maskColor="rgba(2, 6, 23, 0.72)"
          className="!border !border-slate-800 !bg-slate-900/90"
        />
      </ReactFlow>

      {graph.nodes.length === 0 && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-6">
          <div className="max-w-md rounded-xl border border-dashed border-slate-800 bg-slate-900/75 px-6 py-5 text-center shadow-lg backdrop-blur">
            <h3 className="text-sm font-semibold text-slate-200">
              Build a Routing Workflow
            </h3>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
              Drag an <span className="text-sky-300">Interface</span>,{" "}
              <span className="text-violet-300">VPN</span>, or{" "}
              <span className="text-emerald-300">Connected Apps</span> card from the left
              sidebar onto the canvas, then connect handles left-to-right.
            </p>
          </div>
        </div>
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
