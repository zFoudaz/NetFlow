import {
  BaseEdge,
  EdgeLabelRenderer,
  getSmoothStepPath,
  type EdgeProps,
} from "@xyflow/react";
import { X } from "lucide-react";
import type { MouseEvent } from "react";
import { useNetFlowStore } from "../../store/useNetFlowStore";

export function DeletableEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  style,
  markerEnd,
  selected,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getSmoothStepPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  const handleDelete = (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    const { graph, updateGraph } = useNetFlowStore.getState();
    const nextEdges = graph.edges.filter((edge) => edge.id !== id);
    if (nextEdges.length !== graph.edges.length) {
      updateGraph(graph.nodes, nextEdges);
    }
  };

  return (
    <>
      <BaseEdge id={id} path={edgePath} style={style} markerEnd={markerEnd} />
      <EdgeLabelRenderer>
        <div
          style={{
            position: "absolute",
            transform: `translate(-50%, -50%) translate(${labelX}px, ${labelY}px)`,
            pointerEvents: "all",
          }}
          className="nodrag nopan"
        >
          <button
            type="button"
            onClick={handleDelete}
            aria-label={`Delete connection ${id}`}
            title="Delete connection (or right-click line)"
            className={`flex h-5 w-5 items-center justify-center rounded-full border text-xs shadow transition ${
              selected
                ? "border-rose-400 bg-rose-600 text-white opacity-100"
                : "border-slate-600 bg-slate-900/90 text-slate-300 opacity-75 hover:border-rose-400 hover:bg-rose-600 hover:text-white hover:opacity-100"
            }`}
          >
            <X className="h-3 w-3" />
          </button>
        </div>
      </EdgeLabelRenderer>
    </>
  );
}
