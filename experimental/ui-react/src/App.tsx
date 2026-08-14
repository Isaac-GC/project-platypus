import React, { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import MainLayout from "./components/layout/MainLayout";
import SettingsWindow from "./components/windows/SettingsWindow";
import { useAppStore } from "./store/appStore";
import { api } from "./api/adapter";
import type { SearchResult } from "./api/types";
import { checkForUpdates } from "./utils/updater";

const App: React.FC = () => {
  const loadCache = useAppStore((s) => s.loadCache);
  const initProject = useAppStore((s) => s.initProject);
  const fetchScriptCompletions = useAppStore((s) => s.fetchScriptCompletions);
  const loadScripts = useAppStore((s) => s.loadScripts);
  const showSettingsWindow = useAppStore((s) => s.showSettingsWindow);
  const toggleSettingsWindow = useAppStore((s) => s.toggleSettingsWindow);
  const closeSettingsWindow = useAppStore((s) => s.closeSettingsWindow);
  const navigateToSearchResult = useAppStore((s) => s.navigateToSearchResult);
  const settings = useAppStore((s) => s.settings);

  // Restore persisted renames + deobf, then init the project (which restores
  // any persisted slots and re-loads the active one's file contents).
  // Also fetch the platypus introspection for script-pane completions so it's
  // ready when the user needs it.
  useEffect(() => {
    loadCache();
    void initProject();
    void fetchScriptCompletions();
    void loadScripts();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Background self-update check ──
  // Runs once per launch (throttled to once per hour across launches
  // via localStorage). Skipped in dev builds — override with
  // `localStorage.PLATYPUS_FORCE_UPDATE_CHECK = "1"` to test the flow.
  // The user can also force a check from Settings → "Check for updates".
  useEffect(() => {
    void checkForUpdates({ silent: true });
  }, []);

  // Apply CSS custom properties whenever settings change
  useEffect(() => {
    const root = document.documentElement;
    root.style.setProperty("--code-font-size", `${settings.fontSize}px`);
    root.style.setProperty("--code-font-family", settings.fontFamily);
  }, [settings.fontSize, settings.fontFamily]);

  // Global keyboard shortcuts.
  // ⌘K opens the standalone search window (a separate OS window — JADX-style).
  // ⌘, opens the in-app settings overlay.
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const meta = e.metaKey || e.ctrlKey;

      if (meta && e.key === "k") {
        e.preventDefault();
        if (showSettingsWindow) closeSettingsWindow();
        void api.openSearchWindow();
        return;
      }

      if (meta && e.key === ",") {
        e.preventDefault();
        toggleSettingsWindow();
        return;
      }

      if (e.key === "Escape" && showSettingsWindow) {
        closeSettingsWindow();
      }
    };

    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [showSettingsWindow, toggleSettingsWindow, closeSettingsWindow]);

  // Listen for `search:navigate` events from the standalone search window —
  // when the user picks a result there, jump to it here. The search window
  // stays open so they can keep chasing more results.
  useEffect(() => {
    const unlisten = listen<SearchResult>("search:navigate", (e) => {
      void navigateToSearchResult(e.payload);
    });
    return () => { void unlisten.then((fn) => fn()); };
  }, [navigateToSearchResult]);

  // Listen for activity-viewer window's host-callback events — when the
  // user clicks a method ref / activity / layout file in the viewer, the
  // main window navigates to it. All three are best-effort; failures are
  // silent (the viewer doesn't depend on them).
  const navigateToClass = useAppStore((s) => s.navigateToClass);
  useEffect(() => {
    const unlistens = [
      listen<{ className: string }>("activity-viewer:select-class", (e) => {
        if (e.payload?.className) void navigateToClass(e.payload.className);
      }),
      listen<{ methodRef: string }>("activity-viewer:jump-to-source", (e) => {
        // The methodRef is "Lcom/Foo;->bar(...)V" — extract the class
        // and navigate. Method-level highlighting can land in a follow-up.
        const ref = e.payload?.methodRef ?? "";
        const arrow = ref.indexOf("->");
        if (arrow > 0) {
          let cls = ref.slice(0, arrow);
          if (cls.startsWith("L") && cls.endsWith(";")) cls = cls.slice(1, -1);
          void navigateToClass(cls.replace(/\//g, "."));
        }
      }),
      // `activity-viewer:open-entry` — open a layout XML file in the entry
      // browser. For now just navigate to the parent class context;
      // a true file-opener can land later.
      listen<{ entryPath: string }>("activity-viewer:open-entry", () => {
        // Placeholder — wire up when the entry-browser exposes an "open by path".
      }),
    ];
    return () => { unlistens.forEach((p) => void p.then((fn) => fn())); };
  }, [navigateToClass]);

  return (
    <>
      <MainLayout />
      {showSettingsWindow && <SettingsWindow />}
    </>
  );
};

export default App;
