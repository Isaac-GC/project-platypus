/**
 * Standalone platypus-viewer entrypoint.
 *
 * The shell is intentionally tiny — it loads the same `@platypus/activity-viewer`
 * component used by the Project Platypus integration, and provides a Tauri-
 * backed `ViewerApi` plus a top toolbar with File→Open, current path, and a
 * "no APK loaded" placeholder when the user hasn't picked a file yet.
 */

import React, { useCallback, useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import { invoke } from "@tauri-apps/api/core";

import {
  ViewerShell,
  type ActivitySummary,
  type ActivityView,
  type MappingInfo,
  type Theme,
  type ViewerApi,
} from "@platypus/activity-viewer";
import "@platypus/activity-viewer/styles.css";
import { checkForUpdates, type UpdateStatus } from "./updater";

// ─── Tauri-backed ViewerApi ────────────────────────────────────────────────

class StandaloneApi implements ViewerApi {
  async appLabel(): Promise<string> {
    return invoke<string>("app_label");
  }
  async listActivities(): Promise<ActivitySummary[]> {
    return invoke<ActivitySummary[]>("activity_list");
  }
  async rehydrateActivity(name: string): Promise<ActivityView> {
    return invoke<ActivityView>("activity_rehydrate", { activityName: name });
  }
  /** Active theme for the activity — lets the R1 renderer resolve
   *  `?attr/colorPrimary` etc. against the actual app theme rather than
   *  bundled defaults. */
  async theme(name: string): Promise<Theme | null> {
    try {
      return await invoke<Theme>("activity_theme", { activityName: name });
    } catch {
      return null;
    }
  }
  // Standalone shell has no main code-editor / project model to integrate
  // with, so the rest of the optional hooks are deliberately undefined.
  // The component's affordances (jump-to-source, open-layout-file links)
  // just don't show.

  // ── Dexmapper bridge ──
  // ViewerShell auto-renders a "Load mapping…" pill when these three are
  // defined. The Rust side does the actual deobfuscation inside
  // `activity_rehydrate`, so the rest of the renderer just sees real names.
  async loadMappingDialog(): Promise<MappingInfo | null> {
    return invoke<MappingInfo | null>("load_mapping_dialog");
  }
  async currentMapping(): Promise<MappingInfo | null> {
    return invoke<MappingInfo | null>("current_mapping");
  }
  async clearMapping(): Promise<void> {
    await invoke<void>("clear_mapping");
  }
}

// ─── Root component ────────────────────────────────────────────────────────

const App: React.FC = () => {
  const [apkPath, setApkPath] = useState<string | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [api] = useState(() => new StandaloneApi());
  const [updateStatus, setUpdateStatus] = useState<UpdateStatus | null>(null);

  // Check for a pre-loaded APK (from CLI arg or drag-and-drop) on mount.
  useEffect(() => {
    invoke<string | null>("current_apk_path")
      .then((p) => setApkPath(p))
      .catch(() => { /* fresh start with no APK */ });
  }, []);

  // ── Background self-update check ──
  // Runs once per launch (throttled to once per hour across launches via
  // localStorage). Skipped in dev builds — override with
  // `localStorage.PLATYPUS_FORCE_UPDATE_CHECK = "1"` to test the flow.
  useEffect(() => {
    void checkForUpdates({ silent: true, onStatus: setUpdateStatus });
  }, []);

  const handleManualUpdateCheck = useCallback(async () => {
    setUpdateStatus(null);
    const result = await checkForUpdates({
      silent: false, force: true, onStatus: setUpdateStatus,
    });
    if (result.kind === "current") {
      window.alert(`You're on the latest version (${result.current}).`);
    } else if (result.kind === "error") {
      window.alert(`Update check failed: ${result.message}`);
    }
  }, []);

  const handleOpen = useCallback(async () => {
    setError(null);
    try {
      const picked = await invoke<string | null>("open_apk");
      if (picked) {
        setApkPath(picked);
        // Bump the key so ViewerShell re-mounts and re-fetches activities.
        setRefreshKey((k) => k + 1);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  // Drag-and-drop a file onto the window.
  useEffect(() => {
    const onDragOver = (e: DragEvent) => { e.preventDefault(); };
    const onDrop = async (e: DragEvent) => {
      e.preventDefault();
      const file = e.dataTransfer?.files?.[0];
      if (!file) return;
      // In Tauri, the dropped file's path is on the file object.
      const path = (file as any).path || file.name;
      try {
        await invoke("set_apk_path", { path });
        setApkPath(path);
        setRefreshKey((k) => k + 1);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      }
    };
    window.addEventListener("dragover", onDragOver);
    window.addEventListener("drop", onDrop);
    return () => {
      window.removeEventListener("dragover", onDragOver);
      window.removeEventListener("drop", onDrop);
    };
  }, []);

  // ── No APK loaded — show a centered hero / drop zone. ──
  if (!apkPath) {
    return (
      <div style={hero}>
        <div style={{ fontSize: 48, marginBottom: 12 }}>📦</div>
        <h1 style={{ margin: 0, fontSize: 20, fontWeight: 600 }}>
          platypus-viewer
        </h1>
        <p style={{ color: "#888", marginTop: 8, marginBottom: 24, maxWidth: 360, textAlign: "center" }}>
          Drop an APK on this window or click below to open one. Supports
          <code> .apk</code>, <code>.xapk</code>, <code>.apkm</code>, <code>.apks</code>, <code>.aab</code>.
        </p>
        <button onClick={handleOpen} style={openBtn}>Open APK…</button>
        {error && (
          <div style={errorBox}>{error}</div>
        )}
        <p style={{ color: "#555", marginTop: 32, fontSize: 11 }}>
          You can also pass an APK path on the command line:
          <br />
          <code>platypus-viewer /path/to/app.apk</code>
        </p>
      </div>
    );
  }

  // ── APK loaded — render the shared shell. ──
  return (
    <div style={{ display: "flex", flexDirection: "column", height: "100%" }}>
      <div style={topBar}>
        <button onClick={handleOpen} style={topBarBtn}>📂 Open…</button>
        <span style={topBarPath} title={apkPath}>{shortenPath(apkPath)}</span>
        <div style={{ flex: 1 }} />
        <UpdatePill status={updateStatus} onCheck={handleManualUpdateCheck} />
      </div>
      <div style={{ flex: 1, minHeight: 0 }}>
        <ViewerShell key={refreshKey} api={api} />
      </div>
    </div>
  );
};

// ─── Styles ────────────────────────────────────────────────────────────────

const hero: React.CSSProperties = {
  display: "flex",
  flexDirection: "column",
  alignItems: "center",
  justifyContent: "center",
  height: "100vh",
  background: "#1e1e1e",
  color: "#cccccc",
  fontFamily: "-apple-system, BlinkMacSystemFont, sans-serif",
};

const openBtn: React.CSSProperties = {
  background: "#007acc",
  color: "white",
  border: "none",
  padding: "10px 24px",
  borderRadius: 4,
  cursor: "pointer",
  fontSize: 14,
  fontWeight: 600,
};

const errorBox: React.CSSProperties = {
  marginTop: 16,
  background: "rgba(244, 135, 113, 0.1)",
  color: "#f48771",
  border: "1px solid rgba(244, 135, 113, 0.3)",
  padding: "8px 12px",
  borderRadius: 4,
  fontSize: 12,
  maxWidth: 480,
};

const topBar: React.CSSProperties = {
  display: "flex",
  alignItems: "center",
  gap: 12,
  background: "#252526",
  borderBottom: "1px solid #3e3e42",
  padding: "6px 12px",
  flexShrink: 0,
};

const topBarBtn: React.CSSProperties = {
  background: "transparent",
  border: "1px solid #3e3e42",
  color: "#cccccc",
  padding: "4px 10px",
  borderRadius: 3,
  cursor: "pointer",
  fontSize: 11,
};

const topBarPath: React.CSSProperties = {
  color: "#888",
  fontFamily: "ui-monospace, monospace",
  fontSize: 11,
  overflow: "hidden",
  textOverflow: "ellipsis",
  whiteSpace: "nowrap",
};

function shortenPath(p: string): string {
  // "/Users/me/long/.../path/to/foo.apk" — keep first 2 and last 2 segments.
  const parts = p.split("/");
  if (parts.length <= 5) return p;
  return [parts[0], parts[1], "…", parts[parts.length - 2], parts[parts.length - 1]].join("/");
}

// ─── Self-update status pill + manual check ────────────────────────────────

/** Tiny header chip that surfaces the updater's state.
 *
 *   - idle / "current" / dev-skipped → renders a quiet "↻ Check for updates"
 *     link
 *   - "downloading" / "installing"    → renders a percentage indicator and
 *     disables the button (you don't want two checks racing each other)
 *   - "deferred" (user dismissed)     → shows a muted "v0.2.0 ready" link
 *     so the user can change their mind without restarting
 *   - "error"                         → shows the failure message in a
 *     tooltip; click to retry
 *
 * The pill never raises a modal of its own — `updater.ts`'s prompt is the
 * single confirmation surface.
 */
const UpdatePill: React.FC<{ status: UpdateStatus | null; onCheck: () => void; }> =
({ status, onCheck }) => {
  const inFlight = status?.kind === "downloading" || status?.kind === "installing";
  const label = (() => {
    if (!status || status.kind === "skipped" || status.kind === "current") {
      return "↻ Check for updates";
    }
    if (status.kind === "downloading") {
      const pct = status.total ? Math.round((status.downloaded / status.total) * 100) : null;
      return `Downloading${pct !== null ? ` ${pct}%` : "…"}`;
    }
    if (status.kind === "installing") return "Installing…";
    if (status.kind === "installed")  return `Installed ${status.available} — restarting`;
    if (status.kind === "deferred")   return `${status.available} ready`;
    if (status.kind === "error")      return "Update check failed";
    return "↻ Check for updates";
  })();
  const tip = status?.kind === "error" ? status.message : undefined;
  return (
    <button onClick={onCheck} disabled={inFlight} style={updatePill} title={tip}>
      {label}
    </button>
  );
};

const updatePill: React.CSSProperties = {
  background: "transparent",
  border: "1px solid #3e3e42",
  color: "#888",
  padding: "3px 9px",
  borderRadius: 12,
  cursor: "pointer",
  fontSize: 11,
};

// ─── Mount ─────────────────────────────────────────────────────────────────

const root = createRoot(document.getElementById("root")!);
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
