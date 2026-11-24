import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  DiscoverySnapshot,
  EngineStatus,
  LiveConnection,
  SavedWorkflow,
  WorkflowGraph,
} from "../types/workflow";

export const EVENT_STATUS = "netflow://status";
export const EVENT_TRAFFIC = "netflow://traffic";
export const EVENT_RECOVERY_NOTICE = "netflow://recovery-notice";

/** Queries live Windows network interfaces, running processes, and VPN providers. */
export function getDiscoverySnapshot(): Promise<DiscoverySnapshot> {
  return invoke<DiscoverySnapshot>("get_discovery_snapshot");
}

/** Validates a workflow graph without applying OS changes. Rejects with `ValidationError[]`. */
export function validateWorkflowGraph(graph: WorkflowGraph): Promise<null> {
  return invoke<null>("validate_workflow_graph", { graph });
}

/** Lists all saved workflows ordered by `updatedAt` descending. */
export function listWorkflows(): Promise<SavedWorkflow[]> {
  return invoke<SavedWorkflow[]>("list_workflows");
}

/** Persists a workflow document atomically on disk. */
export function saveWorkflow(workflow: SavedWorkflow): Promise<SavedWorkflow> {
  return invoke<SavedWorkflow>("save_workflow", { workflow });
}

/** Renames an existing saved workflow without changing its ID. */
export function renameWorkflow(id: string, newName: string): Promise<SavedWorkflow> {
  return invoke<SavedWorkflow>("rename_workflow", { id, newName });
}

/** Duplicates an existing saved workflow under a new UUID and name. */
export function duplicateWorkflow(id: string, newName: string): Promise<SavedWorkflow> {
  return invoke<SavedWorkflow>("duplicate_workflow", { id, newName });
}

/** Deletes a saved workflow by ID. */
export function deleteWorkflow(id: string): Promise<null> {
  return invoke<null>("delete_workflow", { id });
}

/** Validates, compiles, and applies (or hot-switches to) a workflow graph. */
export function applyWorkflow(
  workflowId: string | null,
  graph: WorkflowGraph
): Promise<EngineStatus> {
  return invoke<EngineStatus>("apply_workflow", { workflowId, graph });
}

/** Stops routing and restores neutralized VPNs and Windows System Proxy. */
export function stopRouting(): Promise<EngineStatus> {
  return invoke<EngineStatus>("stop_routing");
}

/** Fetches the current engine status snapshot. */
export function getEngineStatus(): Promise<EngineStatus> {
  return invoke<EngineStatus>("get_engine_status");
}

/** Retrieves and clears any pending startup crash-recovery notice. */
export function takeRecoveryNotice(): Promise<string | null> {
  return invoke<string | null>("take_recovery_notice");
}

/** Subscribes to live `EngineStatus` updates from the backend. */
export function onStatusChanged(
  handler: (status: EngineStatus) => void
): Promise<UnlistenFn> {
  return listen<EngineStatus>(EVENT_STATUS, (event) => handler(event.payload));
}

/** Subscribes to live Clash API connection snapshots. */
export function onTrafficUpdated(
  handler: (connections: LiveConnection[]) => void
): Promise<UnlistenFn> {
  return listen<LiveConnection[]>(EVENT_TRAFFIC, (event) => handler(event.payload));
}

/** Subscribes to startup crash-recovery notices. */
export function onRecoveryNotice(handler: (notice: string) => void): Promise<UnlistenFn> {
  return listen<string>(EVENT_RECOVERY_NOTICE, (event) => handler(event.payload));
}
