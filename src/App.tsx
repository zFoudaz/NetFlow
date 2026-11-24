import { useEffect } from "react";
import { FlowCanvas } from "./components/FlowCanvas";
import { LiveTrafficDrawer } from "./components/LiveTrafficDrawer";
import { PropertiesPanel } from "./components/PropertiesPanel";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { useNetFlowStore } from "./store/useNetFlowStore";

export function App() {
  const initEventListeners = useNetFlowStore((s) => s.initEventListeners);
  const refreshDiscovery = useNetFlowStore((s) => s.refreshDiscovery);
  const hydrateCanvasDraft = useNetFlowStore((s) => s.hydrateCanvasDraft);
  const loadWorkflows = useNetFlowStore((s) => s.loadWorkflows);
  const loadAppSettings = useNetFlowStore((s) => s.loadAppSettings);
  const loadAppGroups = useNetFlowStore((s) => s.loadAppGroups);

  useEffect(() => {
    let active = true;
    let cleanup: (() => void) | undefined;

    hydrateCanvasDraft();

    void initEventListeners()
      .then((unlisten) => {
        if (active) {
          cleanup = unlisten;
        } else {
          unlisten();
        }
      })
      .catch(() => {
        // Safe no-op outside Tauri webview runtime
      });

    void refreshDiscovery();
    void loadWorkflows();
    void loadAppSettings();
    void loadAppGroups();

    return () => {
      active = false;
      cleanup?.();
    };
  }, [
    hydrateCanvasDraft,
    initEventListeners,
    loadAppGroups,
    loadAppSettings,
    loadWorkflows,
    refreshDiscovery,
  ]);

  return (
    <div
      className="flex h-screen w-screen overflow-hidden bg-[#0B0D10] text-[#F3F4F6]"
      onContextMenu={(event) => {
        const target = event.target as HTMLElement | null;
        if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA")) {
          return;
        }
        event.preventDefault();
      }}
    >
      <Sidebar />

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <TopBar />
        <div className="flex min-h-0 flex-1 overflow-hidden">
          <main className="relative min-w-0 flex-1 overflow-hidden">
            <FlowCanvas />
          </main>
          <PropertiesPanel />
        </div>
        <LiveTrafficDrawer />
      </div>
    </div>
  );
}

export default App;
