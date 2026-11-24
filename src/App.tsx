import { useEffect } from "react";
import { FlowCanvas } from "./components/FlowCanvas";
import { LiveTrafficDrawer } from "./components/LiveTrafficDrawer";
import { Sidebar } from "./components/Sidebar";
import { TopBar } from "./components/TopBar";
import { useNetFlowStore } from "./store/useNetFlowStore";

export function App() {
  const initEventListeners = useNetFlowStore((s) => s.initEventListeners);
  const refreshDiscovery = useNetFlowStore((s) => s.refreshDiscovery);
  const loadWorkflows = useNetFlowStore((s) => s.loadWorkflows);

  useEffect(() => {
    let active = true;
    let cleanup: (() => void) | undefined;

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

    return () => {
      active = false;
      cleanup?.();
    };
  }, [initEventListeners, loadWorkflows, refreshDiscovery]);

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden bg-slate-950 text-slate-100">
      <TopBar />
      <div className="flex min-h-0 flex-1 overflow-hidden">
        <Sidebar />
        <main className="relative min-w-0 flex-1 overflow-hidden">
          <FlowCanvas />
        </main>
      </div>
      <LiveTrafficDrawer />
    </div>
  );
}

export default App;
