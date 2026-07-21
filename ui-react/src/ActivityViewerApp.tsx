/**
 * ActivityViewerApp — the Project Platypus integration of the
 * @platypus/activity-viewer component (phase 4).
 *
 * Loaded by `main.tsx` when `window.location.hash` starts with
 * `#/activity-viewer`. Opened by the `open_activity_viewer_window` Tauri
 * command from the main app's context menu / project panel.
 *
 * The window is its own Tauri WebviewWindow (mirrors the Search / Taint
 * window pattern), so it can run alongside the main analyser window and
 * has its own resizable real estate. It backs the ViewerApi with three
 * Tauri commands that operate on the active slot in the main app's
 * project state.
 */

import React, { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import {
  ViewerShell,
  type ViewerApi,
  type ActivitySummary,
  type ActivityView,
  type MappingInfo,
  type Theme,
} from "@platypus/activity-viewer";
import "@platypus/activity-viewer/styles.css";

// ─── Tauri-backed ViewerApi ────────────────────────────────────────────────

class TauriViewerApi implements ViewerApi {
  async appLabel(): Promise<string> {
    // Pull the active slot's display name + package via the existing
    // project_list_slots command. Cheap (just metadata).
    try {
      const snap: any = await invoke("project_list_slots");
      const active = snap.slots.find((s: any) => s.id === snap.activeSlotId);
      if (!active) return "Activity Viewer";
      const label = active.displayName ?? active.packageName ?? "(unknown)";
      const pkg = active.packageName ? `  ${active.packageName}` : "";
      return `${label}${pkg}`;
    } catch {
      return "Activity Viewer";
    }
  }

  async listActivities(): Promise<ActivitySummary[]> {
    return invoke<ActivitySummary[]>("activity_list");
  }

  async rehydrateActivity(name: string): Promise<ActivityView> {
    return invoke<ActivityView>("activity_rehydrate", { activityName: name });
  }

  /** Active theme for an activity (used by the R1 HTML renderer to resolve
   *  `?attr/colorPrimary` etc. — falls back to bundled defaults if the
   *  backend can't determine the theme). */
  async theme(name: string): Promise<Theme | null> {
    try {
      return await invoke<Theme>("activity_theme", { activityName: name });
    } catch {
      return null;
    }
  }

  // The optional hooks — wired into the main window's existing actions.

  async openActivity(name: string): Promise<void> {
    // Keep the main window in sync — load the activity's class in the
    // centre panel by emitting an event the main App listens for.
    // The main App already has `navigateToClass(name)`; we just emit
    // a custom event that App.tsx subscribes to.
    try {
      const { emit } = await import("@tauri-apps/api/event");
      await emit("activity-viewer:select-class", { className: name });
    } catch {
      // Best-effort — silent failure is fine for this convenience hook.
    }
  }

  async jumpToSource(methodRef: string): Promise<void> {
    // Same pattern — emit and let the main window handle it.
    try {
      const { emit } = await import("@tauri-apps/api/event");
      await emit("activity-viewer:jump-to-source", { methodRef });
    } catch {
      /* ignore */
    }
  }

  async openLayoutFile(path: string): Promise<void> {
    try {
      const { emit } = await import("@tauri-apps/api/event");
      await emit("activity-viewer:open-entry", { entryPath: path });
    } catch {
      /* ignore */
    }
  }

  // ── Dexmapper bridge ──
  // ViewerShell auto-renders the mapping pill when these are present. The
  // Rust side rewrites class/method refs inside `activity_rehydrate` so
  // the rest of the renderer doesn't have to know about the mapping.
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

// ─── Window component ──────────────────────────────────────────────────────

const ActivityViewerApp: React.FC = () => {
  // Read `?activity=<name>` from the hash on first mount.
  const initialActivity = useMemo<string | undefined>(() => {
    const hash = window.location.hash;
    const q = new URLSearchParams(hash.split("?")[1] ?? "");
    return q.get("activity") ?? undefined;
  }, []);

  // Allow the main app to push us to a different activity by emitting
  // `activity-viewer:navigate`. Re-render with a key bump so ViewerShell's
  // initialActivity prop takes effect.
  const [navKey, setNavKey] = useState(0);
  const [override, setOverride] = useState<string | undefined>(initialActivity);

  useEffect(() => {
    const unlisten = listen<{ activityName: string }>(
      "activity-viewer:navigate",
      (e) => {
        setOverride(e.payload?.activityName);
        setNavKey((k) => k + 1);
      },
    );
    return () => { void unlisten.then((fn) => fn()); };
  }, []);

  // One persistent api instance — hooks above are bound at construction.
  const api = useMemo(() => new TauriViewerApi(), []);

  return (
    <ViewerShell
      key={navKey}
      api={api}
      initialActivity={override}
    />
  );
};

export default ActivityViewerApp;
