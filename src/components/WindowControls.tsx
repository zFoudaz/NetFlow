import { useEffect, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X } from "lucide-react";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function WindowControls() {
  const [isMaximized, setIsMaximized] = useState(false);

  useEffect(() => {
    if (!isTauriRuntime()) {
      return;
    }

    let unlisten: (() => void) | undefined;
    let active = true;

    const appWindow = getCurrentWindow();
    void appWindow
      .isMaximized()
      .then((max) => {
        if (active) setIsMaximized(max);
      })
      .catch(() => {});

    void appWindow
      .onResized(() => {
        void appWindow
          .isMaximized()
          .then((max) => {
            if (active) setIsMaximized(max);
          })
          .catch(() => {});
      })
      .then((fn) => {
        if (active) {
          unlisten = fn;
        } else {
          fn();
        }
      })
      .catch(() => {});

    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  const handleMinimize = () => {
    if (!isTauriRuntime()) return;
    void getCurrentWindow().minimize().catch(() => {});
  };

  const handleToggleMaximize = () => {
    if (!isTauriRuntime()) return;
    void getCurrentWindow()
      .toggleMaximize()
      .then(() => getCurrentWindow().isMaximized())
      .then((max) => setIsMaximized(max))
      .catch(() => {});
  };

  const handleClose = () => {
    if (!isTauriRuntime()) return;
    void getCurrentWindow().close().catch(() => {});
  };

  return (
    <div className="ml-1 flex h-12 shrink-0 items-stretch border-l border-[#232830]">
      <button
        type="button"
        aria-label="Minimize window"
        title="Minimize"
        onClick={handleMinimize}
        className="inline-flex w-11 items-center justify-center text-[#9CA3AF] transition hover:bg-[#1D222B] hover:text-[#F3F4F6]"
      >
        <Minus className="h-3.5 w-3.5" />
      </button>
      <button
        type="button"
        aria-label={isMaximized ? "Restore window" : "Maximize window"}
        title={isMaximized ? "Restore" : "Maximize"}
        onClick={handleToggleMaximize}
        className="inline-flex w-11 items-center justify-center text-[#9CA3AF] transition hover:bg-[#1D222B] hover:text-[#F3F4F6]"
      >
        {isMaximized ? (
          <svg
            aria-hidden="true"
            viewBox="0 0 12 12"
            className="h-3 w-3"
            fill="none"
            stroke="currentColor"
            strokeWidth="1.25"
          >
            <rect x="1.5" y="3.5" width="7" height="7" rx="0.5" />
            <path d="M3.5 3.5V2a.5.5 0 0 1 .5-.5h6a.5.5 0 0 1 .5.5v6a.5.5 0 0 1-.5.5H8.5" />
          </svg>
        ) : (
          <Square className="h-3 w-3" />
        )}
      </button>
      <button
        type="button"
        aria-label="Close window"
        title="Minimize to tray"
        onClick={handleClose}
        className="inline-flex w-11 items-center justify-center text-[#9CA3AF] transition hover:bg-rose-600 hover:text-white"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
