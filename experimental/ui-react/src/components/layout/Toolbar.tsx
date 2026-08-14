import React, { useRef } from "react";
import { useAppStore } from "../../store/appStore";
import { api } from "../../api/adapter";
import PlatypusSVG from "../svg/platypus.tsx";

const Toolbar: React.FC = () => {
  const loadedFile = useAppStore((s) => s.loadedFile);
  const isLoading = useAppStore((s) => s.isLoading);
  const loadFile = useAppStore((s) => s.loadFile);
  const loadFileObject = useAppStore((s) => s.loadFileObject);
  const showFlowGraph = useAppStore((s) => s.showFlowGraph);
  const toggleFlowGraph = useAppStore((s) => s.toggleFlowGraph);
  const toggleSettingsWindow = useAppStore((s) => s.toggleSettingsWindow);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleOpen = async () => {
    // Try native Tauri dialog first
    try {
      const path = await api.openFileDialog();
      if (path) {
        await loadFile(path);
        return;
      }
    } catch {
      // Fall through to web file input
    }
    // Web fallback: trigger hidden file input
    fileInputRef.current?.click();
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    // Pass the actual File object — the store will upload it to the REST backend.
    await loadFileObject(file);
    e.target.value = "";
  };

  const fileName = loadedFile
    ? loadedFile.split(/[/\\]/).pop() ?? loadedFile
    : null;

  return (
    <div className="flex items-center gap-2 px-3 h-9 bg-vs-toolbar border-b border-vs-border flex-shrink-0">
      {/* Logo / title */}
      <div style={{ inlineSize: '2%' }} className="inline"> <PlatypusSVG /> </div>
      <span className="text-vs-accent font-bold text-sm tracking-wide select-none">
           Project Platypus
      </span>

      <div className="w-px h-5 bg-vs-border" />

      {/* Open button */}
      <button
        className="flex items-center gap-1 px-2.5 py-1 rounded text-xs bg-vs-elevated hover:bg-vs-accent hover:text-white text-vs-text border border-vs-border transition-colors"
        onClick={handleOpen}
        disabled={isLoading}
        title="Open APK / DEX / JAR"
      >
        {isLoading ? (
          <>
            <span className="animate-spin text-xs">⟳</span>
            Loading…
          </>
        ) : (
          <>📂 Open File</>
        )}
      </button>

      {/* Flow Graph toggle */}
      {loadedFile && (
        <button
          className={[
            "flex items-center gap-1 px-2.5 py-1 rounded text-xs border transition-colors",
            showFlowGraph
              ? "bg-vs-accent text-white border-vs-accent"
              : "bg-vs-elevated hover:bg-vs-accent hover:text-white text-vs-text border-vs-border",
          ].join(" ")}
          onClick={toggleFlowGraph}
          title="Toggle Flow Graph explorer"
        >
          🔀 Flow
        </button>
      )}

      {/* Current file */}
      {fileName && (
        <span
          className="text-xs text-vs-muted truncate max-w-xs"
          title={loadedFile ?? ""}
        >
          {fileName}
        </span>
      )}

      <div className="flex-1" />

      {/* Search button — opens the standalone search window (JADX-style). */}
      <button
        className="flex items-center gap-1 px-2.5 py-1 rounded text-xs bg-vs-elevated hover:bg-vs-accent hover:text-white text-vs-text border border-vs-border transition-colors"
        onClick={() => void api.openSearchWindow()}
        title="Open search window (⌘K)"
      >
        🔍 <span className="hidden sm:inline">Search</span>
        <kbd className="ml-1 text-vs-dim text-[10px] border border-vs-border rounded px-1 hidden lg:inline">⌘K</kbd>
      </button>

      {/* Settings button */}
      <button
        className="flex items-center gap-1 px-2.5 py-1 rounded text-xs bg-vs-elevated hover:bg-vs-accent hover:text-white text-vs-text border border-vs-border transition-colors"
        onClick={toggleSettingsWindow}
        title="Settings (⌘,)"
      >
        ⚙️ <span className="hidden sm:inline">Settings</span>
        <kbd className="ml-1 text-vs-dim text-[10px] border border-vs-border rounded px-1 hidden lg:inline">⌘,</kbd>
      </button>

      <div className="w-px h-5 bg-vs-border" />

      {/* Status indicator */}
      <span
        className={[
          "text-xs font-mono",
          loadedFile ? "text-vs-success" : "text-vs-dim",
        ].join(" ")}
      >
        {loadedFile ? "● Loaded" : "○ No file"}
      </span>

      {/* Hidden file input for web mode */}
      <input
        ref={fileInputRef}
        type="file"
        accept=".apk,.dex,.jar,.aab,.aar"
        className="hidden"
        onChange={handleFileInputChange}
      />
    </div>
  );
};

export default Toolbar;
