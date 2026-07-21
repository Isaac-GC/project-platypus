/**
 * Centre pane — the inspector tree (R3 renderer).
 *
 * Walks the UnifiedView tree and renders one row per node, recursively,
 * with click-to-select + expand/collapse. Each row shows:
 *   - expander chevron (▸/▾) for nodes with children
 *   - icon based on view kind
 *   - tag name (LinearLayout, TextView, …)
 *   - id when present (`@id/foo`)
 *   - inline text preview (TextView's `android:text`)
 *   - source-marker for non-direct origins (included / merged / stub-inflated)
 *
 * Selection is controlled — the parent `ViewerShell` owns selectedPath so
 * the AttributePane can read it too.
 */

import React, { useMemo } from "react";
import type { ActivityView, UnifiedView, ViewKind } from "../types";

/** Path = sequence of child indices from the root. Stable, comparable. */
export type TreePath = number[];

export interface TreeViewProps {
  activity: ActivityView;
  selectedPath: TreePath | null;
  onSelect: (path: TreePath, node: UnifiedView) => void;
  expandedPaths: Set<string>;
  onToggleExpand: (path: TreePath) => void;
  /** Optional — open the activity's source layout file in the host editor. */
  onOpenLayoutFile?: (path: string) => void;
}

export const TreeView: React.FC<TreeViewProps> = ({
  activity, selectedPath, onSelect, expandedPaths, onToggleExpand,
  onOpenLayoutFile,
}) => {
  if (!activity.root) {
    return (
      <div className="pap-tree-pane">
        <Header activity={activity} viewCount={0} onOpenLayoutFile={onOpenLayoutFile} />
        <div className="pap-empty">
          No layout could be reconstructed for this activity.
          {activity.diagnostics.length > 0 && (
            <div style={{ marginTop: 8 }}>
              See the diagnostics below for details.
            </div>
          )}
        </div>
        <DiagnosticsPanel activity={activity} />
      </div>
    );
  }

  const totalCount = useMemo(() => countViews(activity.root!), [activity.root]);

  return (
    <div className="pap-tree-pane">
      <Header
        activity={activity}
        viewCount={totalCount}
        onOpenLayoutFile={onOpenLayoutFile}
      />
      <div className="pap-tree-pane__body" role="tree">
        <TreeRow
          node={activity.root}
          path={[]}
          depth={0}
          selectedPath={selectedPath}
          expandedPaths={expandedPaths}
          onSelect={onSelect}
          onToggleExpand={onToggleExpand}
        />
      </div>
      <DiagnosticsPanel activity={activity} />
    </div>
  );
};

// ─── Sub-components ────────────────────────────────────────────────────────

const Header: React.FC<{
  activity: ActivityView;
  viewCount: number;
  onOpenLayoutFile?: (path: string) => void;
}> = ({ activity, viewCount, onOpenLayoutFile }) => {
  const navCount = activity.outgoingNavigations.length;
  const navTitle = navCount > 0
    ? "Outgoing navigations:\n  " +
      activity.outgoingNavigations.map((n) => `${n.kind}: ${n.target}`).join("\n  ")
    : "No outgoing navigations discovered";
  return (
    <div className="pap-tree-pane__header">
      <span className="pap-tree-pane__path">
        {activity.layoutPath ?? "(no layout)"}
      </span>
      {activity.layoutPath && onOpenLayoutFile && (
        <button
          className="pap-header__action"
          onClick={() => onOpenLayoutFile(activity.layoutPath!)}
          title="Open layout XML in host editor"
        >
          Open
        </button>
      )}
      <span className="pap-tree-pane__view-count">
        {viewCount} view{viewCount === 1 ? "" : "s"}
      </span>
      {navCount > 0 && (
        <span className="pap-tree-pane__nav-count" title={navTitle}>
          → {navCount} nav target{navCount === 1 ? "" : "s"}
        </span>
      )}
    </div>
  );
};

const TreeRow: React.FC<{
  node: UnifiedView;
  path: TreePath;
  depth: number;
  selectedPath: TreePath | null;
  expandedPaths: Set<string>;
  onSelect: (path: TreePath, node: UnifiedView) => void;
  onToggleExpand: (path: TreePath) => void;
}> = ({ node, path, depth, selectedPath, expandedPaths, onSelect, onToggleExpand }) => {
  const pathKey = path.join(".");
  // Default-expand the first 2 levels so the user lands on a useful view.
  const defaultExpanded = depth < 2;
  const isExpanded = expandedPaths.has(pathKey)
    ? true
    : (expandedPaths.has(`!${pathKey}`) ? false : defaultExpanded);
  const isSelected = selectedPath?.join(".") === pathKey;
  const hasChildren = node.children.length > 0;

  // Inline text preview (TextView etc.)
  const inlineText = node.attrs.find((a) => a.name === "android:text")?.value;

  return (
    <>
      <div
        className={[
          "pap-tree-row",
          isSelected ? "pap-tree-row--selected" : "",
        ].join(" ")}
        style={{ paddingLeft: depth * 16 + 4 }}
        onClick={(e) => {
          // Clicking the expander chevron toggles; clicking elsewhere selects.
          if ((e.target as HTMLElement).dataset.expander === "true") {
            onToggleExpand(path);
          } else {
            onSelect(path, node);
          }
        }}
        title={node.tag}
      >
        <span
          className="pap-tree-row__expander"
          data-expander="true"
          onClick={(e) => { e.stopPropagation(); if (hasChildren) onToggleExpand(path); }}
        >
          {hasChildren ? (isExpanded ? "▾" : "▸") : ""}
        </span>
        <span className="pap-tree-row__icon">{iconFor(node.kind)}</span>
        <span className="pap-tree-row__tag">{shortTag(node.tag)}</span>
        {node.id && (
          <span className="pap-tree-row__id">#{node.id}</span>
        )}
        {inlineText && (
          <span className="pap-tree-row__text" title={inlineText}>
            "{truncate(inlineText, 40)}"
          </span>
        )}
        {node.source.kind !== "xml" && (
          <span className="pap-tree-row__source-marker"
                title={`origin: ${describeSource(node.source)}`}>
            {sourceMarker(node.source.kind)}
          </span>
        )}
      </div>
      {hasChildren && isExpanded && node.children.map((child, idx) => (
        <TreeRow
          key={idx}
          node={child}
          path={[...path, idx]}
          depth={depth + 1}
          selectedPath={selectedPath}
          expandedPaths={expandedPaths}
          onSelect={onSelect}
          onToggleExpand={onToggleExpand}
        />
      ))}
    </>
  );
};

const DiagnosticsPanel: React.FC<{ activity: ActivityView }> = ({ activity }) => {
  if (activity.diagnostics.length === 0) return null;
  return (
    <div className="pap-diagnostics">
      <div className="pap-diagnostics__header">
        Diagnostics ({activity.diagnostics.length})
      </div>
      {activity.diagnostics.map((d, i) => (
        <div key={i} className={`pap-diagnostic pap-diagnostic--${d.severity}`}>
          <span style={{ flexShrink: 0, opacity: 0.8 }}>
            {d.severity === "error" ? "✖" : d.severity === "warning" ? "⚠" : "ℹ"}
          </span>
          <span style={{ flex: 1 }}>
            {d.message}
            {d.location && (
              <span style={{ opacity: 0.6, marginLeft: 6, fontFamily: "var(--pap-font-mono)" }}>
                @ {d.location}
              </span>
            )}
          </span>
        </div>
      ))}
    </div>
  );
};

// ─── Helpers ───────────────────────────────────────────────────────────────

function countViews(node: UnifiedView): number {
  return 1 + node.children.reduce((sum, c) => sum + countViews(c), 0);
}

/** Short class name for AndroidX / Material types — drop everything but the
 *  trailing class. Plain `LinearLayout` etc. pass through unchanged. */
function shortTag(tag: string): string {
  if (!tag.includes(".")) return tag;
  const parts = tag.split(".");
  return parts[parts.length - 1] ?? tag;
}

function truncate(s: string, max: number): string {
  return s.length <= max ? s : s.slice(0, max - 1) + "…";
}

/** Tiny ASCII/emoji icon hint per kind. Renderers can swap these for
 *  proper SVG icons later — keeping it lightweight for now. */
function iconFor(kind: ViewKind): string {
  switch (kind.kind) {
    case "linearLayout":
    case "relativeLayout":
    case "frameLayout":
    case "constraintLayout":
    case "coordinatorLayout":
    case "gridLayout":
    case "tableLayout":         return "▦";
    case "scrollView":
    case "horizontalScrollView":
    case "nestedScrollView":    return "↕";
    case "text":                return "T";
    case "editText":            return "✎";
    case "button":
    case "imageButton":         return "⏺";
    case "image":               return "🖼";
    case "switch":              return "⏻";
    case "checkBox":            return "☑";
    case "radioButton":         return "◉";
    case "seekBar":             return "↔";
    case "progressBar":         return "⏳";
    case "spinner":             return "▼";
    case "toolbar":
    case "appBar":              return "▤";
    case "bottomNav":           return "▥";
    case "tabLayout":           return "⛶";
    case "recyclerView":
    case "listView":
    case "gridView":            return "≡";
    case "viewPager":
    case "viewPager2":          return "▷";
    case "fragment":            return "▒";
    case "viewStub":            return "◌";
    case "include":             return "⊕";
    case "merge":               return "⊜";
    case "webView":             return "🌐";
    case "custom":              return "⚙";
    case "other":               return "·";
  }
}

function sourceMarker(kind: string): string {
  switch (kind) {
    case "included":     return "⊕";
    case "merged":       return "⊜";
    case "stubInflated": return "◌";
    case "compose":      return "ⓒ";
    case "synthetic":    return "ⓢ";
    default:             return "";
  }
}

function describeSource(s: UnifiedView["source"]): string {
  switch (s.kind) {
    case "xml":          return `XML: ${s.layoutPath}`;
    case "included":     return `<include> from ${s.fromLayoutPath} → ${s.includedLayoutPath}`;
    case "merged":       return `<merge> flattened from ${s.fromLayoutPath}`;
    case "stubInflated": return `<ViewStub> in ${s.stubLayoutPath} → ${s.targetLayoutPath}`;
    case "compose":      return `Compose: ${s.methodRef}`;
    case "synthetic":    return "synthetic placeholder";
  }
}
