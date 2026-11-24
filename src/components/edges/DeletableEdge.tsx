import {
  BaseEdge,
  EdgeLabelRenderer,
  getBezierPath,
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
  const [edgePath, labelX, labelY] = getBezierPath({
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
            className={`flex h-4 w-4 items-center justify-center rounded-full border text-[10px] transition ${
              selected
                ? "border-rose-400 bg-rose-600 text-white opacity-100"
                : "border-[#2E3540] bg-[#111418] text-[#9CA3AF] opacity-40 hover:border-rose-400 hover:bg-rose-600 hover:text-white hover:opacity-100"
            }`}
          >
            <X className="h-2.5 w-2.5" />
          </button>
        </div>
      </EdgeLabelRenderer>
    </>
  );
}
