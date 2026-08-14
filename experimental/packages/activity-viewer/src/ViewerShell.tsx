/**
 * ViewerShell — the top-level component each shell embeds.
 *
 * Layout: 3 columns (picker | tree | attributes). The shell owns:
 *   - which activity is currently selected
 *   - which tree node is currently selected (path + node)
 *   - which tree paths are expanded (for collapse/expand UX)
 *   - the loading state
 *
 * Data comes from the host-supplied `ViewerApi`. The shell never imports
 * from `@tauri-apps/*`, fetch endpoints, or anything shell-specific —
 * that's all behind the api boundary.
 */

import React, { useCallback, useEffect, useMemo, useState } from "react";
import { ActivityPicker } from "./components/ActivityPicker";
import { AttributePane } from "./components/AttributePane";
import { MappingControl } from "./components/MappingControl";
import { RendererErrorBoundary } from "./components/RendererErrorBoundary";
import { TreeView, type TreePath } from "./components/TreeView";
import { HtmlRenderer } from "./renderers/html/HtmlRenderer";
import { CanvasRenderer } from "./renderers/canvas/CanvasRenderer";
import { GraphRenderer } from "./renderers/graph/GraphRenderer";
import type { MappingInfo, ViewerApi } from "./api";
import type { ActivitySummary, ActivityView, Theme, UnifiedView } from "./types";

/** Which centre-pane renderer is active. */
export type RendererKind = "tree" | "html" | "canvas" | "graph";

/** Pixel dimensions for one preset. Logical pixels (CSS px), not actual
 *  device pixels — both renderers do their own DPR scaling. */
export interface DevicePreset {
  id: string;
  label: string;
  width: number;
  height: number;
}

/** Preset device sizes the user can flip between. Pixel ratios picked so
 *  the rendered surface mirrors a typical Android device's CSS-px viewport
 *  (not the raw screen resolution). */
export const DEVICE_PRESETS: DevicePreset[] = [
  { id: "phone",          label: "Phone",          width: 360,  height: 640  },
  { id: "phone-large",    label: "Phone (large)",  width: 412,  height: 892  },
  { id: "tablet",         label: "Tablet",         width: 800,  height: 1280 },
  { id: "tablet-land",    label: "Tablet land",    width: 1280, height: 800  },
  { id: "foldable-inner", label: "Foldable inner", width: 700,  height: 760  },
];

export interface ViewerShellProps {
  /** Host-supplied API. */
  api: ViewerApi;
  /** Optional — if set, this activity is selected on first mount instead
   *  of the picker's first launcher. */
  initialActivity?: string;
  /** Optional — hide the right-side attribute pane (useful for embedded
   *  contexts where the host already shows attributes elsewhere). */
  hideAttributes?: boolean;
  /** Optional — which renderer to start in. Defaults to `"tree"` (the
   *  inspector). The user can toggle this in the header. */
  initialRenderer?: RendererKind;
  /** Optional — host-supplied controls rendered inside the header,
   *  between the title and the device/interactive/renderer toggles.
   *  Both shells use this to drop in a `<MappingControl>` that wires up
   *  the Tauri `load_mapping_dialog` / `clear_mapping` commands. The
   *  shared component stays Tauri-agnostic — only the host knows about
   *  the backing API. */
  headerExtras?: React.ReactNode;
}

export const ViewerShell: React.FC<ViewerShellProps> = ({
  api, initialActivity, hideAttributes = false, initialRenderer = "tree",
  headerExtras,
}) => {
  const [appLabel, setAppLabel] = useState<string>("");
  const [activities, setActivities] = useState<ActivitySummary[]>([]);
  const [selectedActivity, setSelectedActivity] = useState<string | null>(
    initialActivity ?? null,
  );
  const [activityView, setActivityView] = useState<ActivityView | null>(null);
  const [theme, setTheme] = useState<Theme | null>(null);
  const [renderer, setRenderer] = useState<RendererKind>(initialRenderer);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // ── Interactive mode ──
  // When enabled, clicking a view in the renderer follows its statically-
  // discovered behaviour (navigate to target activity, surface handler
  // info) instead of just selecting the view. `navHistory` tracks the
  // back-stack so the user can rewind.
  const [interactive, setInteractive] = useState(false);
  const [navHistory, setNavHistory] = useState<string[]>([]);

  // ── Device size ──
  // Picked from `DEVICE_PRESETS`; controls the CSS dimensions of the
  // phone-frame surface in HTML mode and the canvas dimensions in
  // canvas mode. Tree/Graph modes ignore this.
  const [device, setDevice] = useState<DevicePreset>(DEVICE_PRESETS[0]);

  // Tree selection
  const [selectedPath, setSelectedPath] = useState<TreePath | null>(null);
  // expandedPaths uses a string-key set: a key in the set means "explicitly
  // expanded". A `!` prefix means "explicitly collapsed" — needed because
  // the tree default-expands the first 2 levels. See TreeView.
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());

  // ── Initial load ──
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const [label, list] = await Promise.all([
          api.appLabel(),
          api.listActivities(),
        ]);
        if (cancelled) return;
        setAppLabel(label);
        setActivities(list);
        // Pick the first launcher activity, or fall back to the first one.
        const initial = initialActivity
          ?? list.find((a) => a.isLauncher)?.name
          ?? list[0]?.name
          ?? null;
        setSelectedActivity(initial);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => { cancelled = true; };
  }, [api, initialActivity]);

  // ── Load IR for selected activity ──
  useEffect(() => {
    if (!selectedActivity) {
      setActivityView(null);
      return;
    }
    let cancelled = false;
    setActivityView(null);
    setTheme(null);
    setSelectedPath(null);
    setExpandedPaths(new Set());
    (async () => {
      try {
        // Fetch the IR and (optionally) the active theme in parallel —
        // theme load failures are non-fatal; we just render without it.
        const [view, themeResult] = await Promise.all([
          api.rehydrateActivity(selectedActivity),
          api.theme
            ? api.theme(selectedActivity).catch(() => null)
            : Promise.resolve(null),
        ]);
        if (!cancelled) {
          setActivityView(view);
          setTheme(themeResult);
          // Default-select the root so the attribute pane shows something.
          if (view.root) setSelectedPath([]);
        }
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : String(e));
        }
      }
    })();
    return () => { cancelled = true; };
  }, [api, selectedActivity]);

  // ── Mapping (dexmapper) state ──
  // Auto-fetched on mount if the host's api exposes the optional methods.
  // After load/clear we re-fetch the active IR so the rendered names reflect
  // the new mapping immediately.
  const [mapping, setMapping] = useState<MappingInfo | null>(null);
  const [mappingBusy, setMappingBusy] = useState(false);
  const mappingSupported = !!(api.loadMappingDialog && api.currentMapping && api.clearMapping);

  useEffect(() => {
    if (!mappingSupported) return;
    let cancelled = false;
    api.currentMapping?.()
      .then((info) => { if (!cancelled) setMapping(info ?? null); })
      .catch(() => { /* host returned null/error — leave as no mapping */ });
    return () => { cancelled = true; };
  }, [api, mappingSupported]);

  const reloadCurrentActivity = useCallback(() => {
    if (!selectedActivity) return;
    // Bump the selectedActivity to itself to force the IR-load effect to
    // re-run. Simpler than threading a `refreshKey` through every render path.
    const name = selectedActivity;
    setSelectedActivity(null);
    queueMicrotask(() => setSelectedActivity(name));
  }, [selectedActivity]);

  const handleMappingLoad = useCallback(async () => {
    if (!api.loadMappingDialog) return;
    setMappingBusy(true);
    try {
      const info = await api.loadMappingDialog();
      if (info) {
        setMapping(info);
        reloadCurrentActivity();
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setMappingBusy(false);
    }
  }, [api, reloadCurrentActivity]);

  const handleMappingClear = useCallback(async () => {
    if (!api.clearMapping) return;
    setMappingBusy(true);
    try {
      await api.clearMapping();
      setMapping(null);
      reloadCurrentActivity();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setMappingBusy(false);
    }
  }, [api, reloadCurrentActivity]);

  // ── Resolve the selected node from the path ──
  const selectedNode = useMemo<UnifiedView | null>(() => {
    if (!activityView?.root || !selectedPath) return null;
    return navigateTo(activityView.root, selectedPath);
  }, [activityView, selectedPath]);

  // ── Handlers ──

  /** Navigate to another activity, pushing the current one onto the back-stack
   *  so interactive mode can rewind. Falls back to the host's openActivity for
   *  destinations not present in the loaded APK. */
  const navigateToActivity = useCallback((name: string) => {
    if (activities.some((a) => a.name === name)) {
      if (selectedActivity) {
        setNavHistory((prev) => [...prev, selectedActivity]);
      }
      setSelectedActivity(name);
    } else if (api.openActivity) {
      void api.openActivity(name);
    }
  }, [activities, selectedActivity, api]);

  const navigateBack = useCallback(() => {
    setNavHistory((prev) => {
      if (prev.length === 0) return prev;
      const next = prev.slice(0, -1);
      setSelectedActivity(prev[prev.length - 1]);
      return next;
    });
  }, []);

  /** Renderer click handler — branches on interactive mode:
   *   - Interactive + the view has a `startActivity*` navigation: follow it.
   *   - Interactive + the view has a click handler we can jump to: surface it
   *     via the host's jumpToSource (best-effort).
   *   - Otherwise: regular selection. */
  const handleSelect = useCallback((path: TreePath, node: UnifiedView) => {
    if (interactive) {
      const nav = node.navigation;
      if (nav && (nav.kind === "startActivity" || nav.kind === "startActivityForResult")) {
        navigateToActivity(nav.target);
        return;
      }
      // Non-navigation handlers — surface via jumpToSource if the host
      // wired one. The selection still updates so the inspector reflects it.
      const handler = node.clickHandler;
      if (handler && api.jumpToSource) {
        void api.jumpToSource(handler.target);
      }
    }
    setSelectedPath(path);
  }, [interactive, navigateToActivity, api]);

  const handleToggleExpand = useCallback((path: TreePath) => {
    const key = path.join(".");
    setExpandedPaths((prev) => {
      const next = new Set(prev);
      // Three-state cycle: default → explicitly collapsed → explicitly
      // expanded → default. We model "default" as neither key present.
      if (next.has(key)) {
        next.delete(key);
        next.add(`!${key}`);   // mark as explicitly collapsed
      } else if (next.has(`!${key}`)) {
        next.delete(`!${key}`);
        next.add(key);          // explicitly expanded
      } else {
        // No marker yet — toggle vs the default. Default-expanded for
        // depth < 2, default-collapsed otherwise. Mark the opposite.
        if (path.length < 2) {
          next.add(`!${key}`);
        } else {
          next.add(key);
        }
      }
      return next;
    });
  }, []);

  // ── Render ──
  if (loading) {
    return (
      <div className="pap-shell">
        <div className="pap-loading">Loading activities…</div>
      </div>
    );
  }
  if (error) {
    return (
      <div className="pap-shell">
        <div className="pap-error-banner">Failed to load: {error}</div>
      </div>
    );
  }

  const shellClass = ["pap-shell", hideAttributes ? "pap-shell--no-right" : ""]
    .filter(Boolean).join(" ");

  return (
    <div className={shellClass}>
      <header className="pap-header">
        {navHistory.length > 0 && (
          <button
            className="pap-header__action pap-header__back"
            onClick={navigateBack}
            title={`Back to ${navHistory[navHistory.length - 1]}`}
          >
            ← Back
          </button>
        )}
        <span className="pap-header__title">{appLabel || "Activity Viewer"}</span>
        <span className="pap-header__subtitle">
          {activities.length} activit{activities.length === 1 ? "y" : "ies"}
          {selectedActivity && ` · ${selectedActivity}`}
        </span>
        <div className="pap-header__spacer" />
        {mappingSupported && (
          <MappingControl
            info={mapping}
            onLoad={handleMappingLoad}
            onClear={handleMappingClear}
            busy={mappingBusy}
          />
        )}
        {headerExtras}
        {(renderer === "html" || renderer === "canvas") && (
          <select
            className="pap-header__device"
            value={device.id}
            onChange={(e) => {
              const found = DEVICE_PRESETS.find((d) => d.id === e.target.value);
              if (found) setDevice(found);
            }}
            title="Device size — only affects HTML/Canvas previews"
          >
            {DEVICE_PRESETS.map((d) => (
              <option key={d.id} value={d.id}>
                {d.label} · {d.width}×{d.height}
              </option>
            ))}
          </select>
        )}
        <button
          className={`pap-header__action pap-header__interactive ${
            interactive ? "pap-header__interactive--on" : ""
          }`}
          onClick={() => setInteractive((v) => !v)}
          title={
            interactive
              ? "Interactive mode ON — clicks follow navigation. Toggle off to inspect."
              : "Interactive mode OFF — clicks select views. Toggle on to click through screens."
          }
          aria-pressed={interactive}
          // Disabled in tree + graph modes. Tree has no visual buttons
          // to click through; graph already wires every node click to
          // navigateToActivity, so the toggle would be redundant.
          disabled={renderer === "tree" || renderer === "graph"}
        >
          {interactive ? "▶ Interactive" : "Interactive"}
        </button>
        <div className="pap-renderer-toggle" role="tablist" aria-label="Renderer">
          <button
            role="tab"
            aria-selected={renderer === "tree"}
            className={`pap-renderer-toggle__btn ${renderer === "tree" ? "pap-renderer-toggle__btn--active" : ""}`}
            onClick={() => setRenderer("tree")}
            title="Inspector tree"
          >Tree</button>
          <button
            role="tab"
            aria-selected={renderer === "html"}
            className={`pap-renderer-toggle__btn ${renderer === "html" ? "pap-renderer-toggle__btn--active" : ""}`}
            onClick={() => setRenderer("html")}
            title="HTML/CSS preview"
          >HTML</button>
          <button
            role="tab"
            aria-selected={renderer === "canvas"}
            className={`pap-renderer-toggle__btn ${renderer === "canvas" ? "pap-renderer-toggle__btn--active" : ""}`}
            onClick={() => setRenderer("canvas")}
            title="Canvas preview (pixel-painted, no DOM)"
          >Canvas</button>
          <button
            role="tab"
            aria-selected={renderer === "graph"}
            className={`pap-renderer-toggle__btn ${renderer === "graph" ? "pap-renderer-toggle__btn--active" : ""}`}
            onClick={() => setRenderer("graph")}
            title="Cross-activity navigation graph"
          >Graph</button>
        </div>
      </header>

      <ActivityPicker
        activities={activities}
        selectedName={selectedActivity}
        onSelect={(name) => {
          // Picker selection is a "fresh start" — clear the back-stack so
          // the user isn't returned to a screen they didn't navigate from.
          setNavHistory([]);
          setSelectedActivity(name);
          // Best-effort: tell the host so it can mirror the navigation
          // (Project Platypus might also open the activity's source).
          if (api.openActivity) void api.openActivity(name);
        }}
      />

      {activityView ? (
        renderer === "tree" ? (
          <TreeView
            activity={activityView}
            selectedPath={selectedPath}
            onSelect={handleSelect}
            expandedPaths={expandedPaths}
            onToggleExpand={handleToggleExpand}
            onOpenLayoutFile={api.openLayoutFile}
          />
        ) : renderer === "html" ? (
          <div className={`pap-tree-pane ${interactive ? "pap-tree-pane--interactive" : ""}`}>
            <RendererErrorBoundary resetKey={`html:${selectedActivity}`}>
              <HtmlRenderer
                root={activityView.root}
                theme={theme ?? undefined}
                selectedPath={selectedPath}
                onSelect={handleSelect}
                interactive={interactive}
                width={device.width}
                height={device.height}
              />
            </RendererErrorBoundary>
          </div>
        ) : renderer === "canvas" ? (
          <div className={`pap-tree-pane ${interactive ? "pap-tree-pane--interactive" : ""}`}>
            <RendererErrorBoundary resetKey={`canvas:${selectedActivity}`}>
              <CanvasRenderer
                root={activityView.root}
                theme={theme ?? undefined}
                selectedPath={selectedPath}
                onSelect={handleSelect}
                interactive={interactive}
                width={device.width}
                height={device.height}
              />
            </RendererErrorBoundary>
          </div>
        ) : (
          <div className="pap-tree-pane">
            <RendererErrorBoundary resetKey={`graph:${selectedActivity}`}>
              <GraphRenderer
                currentActivity={selectedActivity}
                activities={activities}
                currentView={activityView}
                api={api}
                onSelectActivity={navigateToActivity}
              />
            </RendererErrorBoundary>
          </div>
        )
      ) : (
        <div className="pap-tree-pane">
          <div className="pap-loading">
            {selectedActivity ? `Rehydrating ${selectedActivity}…` : "Pick an activity →"}
          </div>
        </div>
      )}

      {!hideAttributes && (
        <AttributePane
          node={selectedNode}
          onJumpToSource={api.jumpToSource}
          // Reuses the same back-stack-aware navigation as click-through
          // mode — clicking a navigation target in the inspector counts as
          // navigating, so the back button works either way.
          onOpenActivity={navigateToActivity}
        />
      )}
    </div>
  );
};

// ─── Helpers ───────────────────────────────────────────────────────────────

function navigateTo(root: UnifiedView, path: TreePath): UnifiedView | null {
  let node: UnifiedView | undefined = root;
  for (const idx of path) {
    if (!node) return null;
    node = node.children[idx];
  }
  return node ?? null;
}
