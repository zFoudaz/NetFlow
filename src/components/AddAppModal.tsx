import { open } from "@tauri-apps/plugin-dialog";
import { FolderOpen, Plus, Search, X } from "lucide-react";
import { useMemo, useState, type FormEvent } from "react";
import { createPortal } from "react-dom";
import { useNetFlowStore } from "../store/useNetFlowStore";

export function normalizeExeBasename(raw: string): string | null {
  const trimmed = raw.trim();
  if (!trimmed) return null;

  const segments = trimmed.split(/[\\/]/);
  const filename = (segments[segments.length - 1] ?? "").trim();
  if (!filename || filename === "." || filename === "..") {
    return null;
  }

  // Reject Windows-invalid filename characters and control characters
  for (let i = 0; i < filename.length; i += 1) {
    const code = filename.charCodeAt(i);
    const ch = filename[i];
    if (code < 32 || '<>:"|?*'.includes(ch)) {
      return null;
    }
  }

  const lower = filename.toLowerCase();
  if (lower.endsWith(".")) {
    return null;
  }

  const stem = lower.endsWith(".exe") ? lower.slice(0, -4) : lower;
  if (!stem.replace(/[. ]/g, "")) {
    return null;
  }

  return lower.endsWith(".exe") ? lower : `${lower}.exe`;
}

interface AddAppModalProps {
  isOpen: boolean;
  existingApps: string[];
  onAddApp: (exeName: string) => void;
  onClose: () => void;
}

export function AddAppModal({
  isOpen,
  existingApps,
  onAddApp,
  onClose,
}: AddAppModalProps) {
  const processes = useNetFlowStore((s) => s.discovery.processes);

  const [searchQuery, setSearchQuery] = useState("");
  const [manualInput, setManualInput] = useState("");
  const [feedback, setFeedback] = useState<string | null>(null);

  const existingSet = useMemo(
    () => new Set(existingApps.map((app) => normalizeExeBasename(app) ?? app.toLowerCase())),
    [existingApps]
  );

  const filteredProcesses = useMemo(() => {
    const seen = new Set<string>();
    const query = searchQuery.trim().toLowerCase();
    const list: { exeName: string; normalized: string; path: string | null }[] = [];

    for (const proc of processes) {
      const normalized = normalizeExeBasename(proc.exeName);
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);

      const matchesQuery =
        !query ||
        normalized.includes(query) ||
        (proc.path ? proc.path.toLowerCase().includes(query) : false);
      if (matchesQuery) {
        list.push({
          exeName: proc.exeName,
          normalized,
          path: proc.path,
        });
      }
    }

    return list.sort((a, b) => a.normalized.localeCompare(b.normalized));
  }, [processes, searchQuery]);

  if (!isOpen) {
    return null;
  }

  const handleClose = () => {
    setFeedback(null);
    setManualInput("");
    setSearchQuery("");
    onClose();
  };

  const commitExe = (raw: string) => {
    const normalized = normalizeExeBasename(raw);
    if (!normalized) {
      setFeedback("Enter a valid executable filename (for example, chrome.exe).");
      return;
    }
    if (existingSet.has(normalized)) {
      setFeedback(`'${normalized}' is already assigned to this node.`);
      return;
    }
    setFeedback(null);
    setManualInput("");
    setSearchQuery("");
    onAddApp(normalized);
    onClose();
  };

  const handleManualSubmit = (e: FormEvent) => {
    e.preventDefault();
    commitExe(manualInput);
  };

  const handleBrowseExe = async () => {
    setFeedback(null);
    try {
      const selected = await open({
        title: "Select Application Executable",
        multiple: false,
        filters: [{ name: "Executables", extensions: ["exe"] }],
      });

      const pickedPath = Array.isArray(selected) ? selected[0] : selected;
      if (!pickedPath) {
        return;
      }
      commitExe(pickedPath);
    } catch {
      setFeedback(
        "File browser dialog is unavailable in this environment. Enter an .exe name manually below."
      );
    }
  };

  const modalContent = (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-[#0B0D10]/80 p-4 backdrop-blur-xs"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          handleClose();
        }
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          handleClose();
        }
        e.stopPropagation();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Add Application"
        className="flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden rounded-lg border border-[#2E3540] bg-[#111418] text-[#F3F4F6] shadow-xl shadow-black/60"
      >
        <div className="flex items-center justify-between border-b border-[#232830] px-4 py-3">
          <div>
            <h2 className="text-sm font-semibold text-[#F3F4F6]">Add Application</h2>
            <p className="text-xs text-[#9CA3AF]">
              Select a running process, browse for an .exe, or type a filename.
            </p>
          </div>
          <button
            type="button"
            aria-label="Close modal"
            onClick={handleClose}
            className="rounded p-1 text-[#9CA3AF] transition hover:bg-[#1D222B] hover:text-[#F3F4F6]"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-3 border-b border-[#232830] px-4 py-3">
          <div className="flex items-center gap-2">
            <div className="relative flex-1">
              <Search className="pointer-events-none absolute left-2.5 top-2.5 h-4 w-4 text-[#6B7280]" />
              <input
                type="text"
                autoFocus
                aria-label="Search running processes"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search running processes..."
                className="w-full rounded-md border border-[#232830] bg-[#0B0D10] py-2 pl-8 pr-3 text-xs text-[#F3F4F6] placeholder-[#6B7280] outline-none focus:border-[#3ECF8E]"
              />
            </div>

            <button
              type="button"
              onClick={() => void handleBrowseExe()}
              className="inline-flex shrink-0 items-center gap-1.5 rounded-md border border-[#232830] bg-[#161A20] px-3 py-2 text-xs font-medium text-[#F3F4F6] transition hover:border-[#2E3540] hover:bg-[#1D222B]"
            >
              <FolderOpen className="h-3.5 w-3.5 text-[#3ECF8E]" />
              <span>Browse .exe...</span>
            </button>
          </div>

          <form onSubmit={handleManualSubmit} className="flex items-center gap-2">
            <input
              type="text"
              aria-label="Manual executable name"
              value={manualInput}
              onChange={(e) => setManualInput(e.target.value)}
              placeholder="Or type exe name (e.g. chrome.exe)"
              className="flex-1 rounded-md border border-[#232830] bg-[#0B0D10] px-3 py-1.5 text-xs text-[#F3F4F6] placeholder-[#6B7280] outline-none focus:border-[#3ECF8E]"
            />
            <button
              type="submit"
              className="inline-flex items-center gap-1 rounded-md bg-[#3ECF8E] px-3 py-1.5 text-xs font-semibold text-[#0B0D10] transition hover:bg-[#34B87E]"
            >
              <Plus className="h-3.5 w-3.5" />
              <span>Add</span>
            </button>
          </form>

          {feedback && (
            <p className="rounded border border-rose-500/40 bg-rose-500/10 px-2.5 py-1.5 text-xs text-rose-200">
              {feedback}
            </p>
          )}
        </div>

        <div className="min-h-0 flex-1 overflow-y-auto px-2 py-2">
          <div className="px-2 pb-1.5 text-[11px] font-medium uppercase tracking-wider text-[#6B7280]">
            Running Processes ({filteredProcesses.length})
          </div>

          {filteredProcesses.length === 0 ? (
            <div className="px-2 py-6 text-center text-xs text-[#6B7280]">
              No matching running processes found.
            </div>
          ) : (
            <div className="divide-y divide-[#1A1F26]">
              {filteredProcesses.map((proc) => {
                const alreadyAdded = existingSet.has(proc.normalized);
                return (
                  <button
                    key={proc.normalized}
                    type="button"
                    disabled={alreadyAdded}
                    onClick={() => commitExe(proc.normalized)}
                    className="flex w-full items-center justify-between gap-3 px-2.5 py-2 text-left transition hover:bg-[#161A20] disabled:cursor-not-allowed disabled:opacity-45"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="font-mono text-xs font-medium text-[#F3F4F6]">
                        {proc.normalized}
                      </div>
                      {proc.path && (
                        <div className="truncate text-[11px] text-[#6B7280]">{proc.path}</div>
                      )}
                    </div>
                    <span
                      className={`shrink-0 rounded px-2 py-0.5 text-[11px] font-medium ${
                        alreadyAdded
                          ? "bg-[#161A20] text-[#6B7280]"
                          : "bg-[#3ECF8E]/10 text-[#3ECF8E]"
                      }`}
                    >
                      {alreadyAdded ? "Added" : "Select"}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );

  return createPortal(modalContent, document.body);
}
