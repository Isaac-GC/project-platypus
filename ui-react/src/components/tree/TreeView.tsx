import React, { useMemo, useState, useEffect } from "react";
import type { TreeNode, NodeKind } from "../../api/types";
import { useAppStore } from "../../store/appStore";

// ─── Method ref parsing ───────────────────────────────────────────────────────

/**
 * Parse a method-node's `fullName` into `(className, methodName)`.
 * Accepts either:
 *   `Lcom/Foo;->bar(Lx;)V`   (smali-style; the common case)
 *   `Lcom/Foo;->bar`          (no proto)
 *   `com/Foo->bar`            (already stripped)
 * The deobf-mark backend stores the L/;-stripped class form; we
 * normalise here so context-menu callers can pass node.fullName
 * verbatim.
 *
 * Returns null when the format isn't a method ref (e.g. a class node
 * whose fullName has no `->`).
 */
function parseMethodRef(fullName: string | undefined): { className: string; methodName: string } | null {
  if (!fullName) return null;
  const arrowIdx = fullName.indexOf("->");
  if (arrowIdx < 0) return null;
  const rawClass = fullName.slice(0, arrowIdx);
  const rest = fullName.slice(arrowIdx + 2);
  // Trim any proto off the method name (everything from "(" onward).
  const methodName = rest.split("(")[0];
  const className = rawClass.replace(/^L/, "").replace(/;$/, "");
  if (!className || !methodName) return null;
  return { className, methodName };
}

// ─── Icons and colors ─────────────────────────────────────────────────────────

const KIND_COLOR: Record<NodeKind, string> = {
  package: "text-tree-package",
  class: "text-tree-class",
  method: "text-tree-method",
  field: "text-tree-field",
  dexfile: "text-vs-muted",
  assets_folder: "text-vs-muted",
  asset: "text-vs-text",
  source_root: "text-vs-muted",
  resources_root: "text-syn-string",
  res_type: "text-vs-muted",
  res_entry: "text-vs-text",
  manifest: "text-syn-string",
  embedded_root: "text-vs-accent",
  embedded_apk: "text-vs-text",
  diff_section: "text-vs-muted",
  diff_added: "text-vs-success",
  diff_removed: "text-vs-error",
  diff_modified: "text-vs-warn",
};

const KIND_ICON: Record<NodeKind, string> = {
  package: "📦",
  class: "🟦",
  method: "🔧",
  field: "🔹",
  dexfile: "🗂",
  assets_folder: "📁",
  asset: "📄",
  source_root: "📂",
  resources_root: "🗃️",
  res_type: "📁",
  res_entry: "🔑",
  manifest: "📋",
  embedded_root: "📦",
  embedded_apk: "🧩",
  diff_section: "📂",
  diff_added: "➕",
  diff_removed: "➖",
  diff_modified: "✏️",
};

// ─── Filter helpers ───────────────────────────────────────────────────────────

function nodeMatchesFilter(node: TreeNode, filter: string): boolean {
  if (!filter) return true;
  const lf = filter.toLowerCase();
  if (node.name.toLowerCase().includes(lf)) return true;
  if (node.fullName?.toLowerCase().includes(lf)) return true;
  if (node.children?.some((c) => nodeMatchesFilter(c, filter))) return true;
  return false;
}

function filterTree(nodes: TreeNode[], filter: string): TreeNode[] {
  if (!filter) return nodes;
  return nodes
    .filter((n) => nodeMatchesFilter(n, filter))
    .map((n) => ({
      ...n,
      children: n.children ? filterTree(n.children, filter) : undefined,
    }));
}

// ─── Props ───────────────────────────────────────────────────────────────────

interface TreeViewProps {
  nodes: TreeNode[];
  expandedNodes: Set<string>;
  selectedNodeId?: string;
  filterQuery?: string;
  onToggleExpand: (nodeId: string) => void;
  onSelectNode: (node: TreeNode) => void;
  onOpenNode: (node: TreeNode) => void;
  depth?: number;
}

// ─── Recursive node ───────────────────────────────────────────────────────────

const TreeNodeRow: React.FC<{
  node: TreeNode;
  depth: number;
  expandedNodes: Set<string>;
  selectedNodeId?: string;
  onToggleExpand: (nodeId: string) => void;
  onSelectNode: (node: TreeNode) => void;
  onOpenNode: (node: TreeNode) => void;
}> = ({
  node,
  depth,
  expandedNodes,
  selectedNodeId,
  onToggleExpand,
  onSelectNode,
  onOpenNode,
}) => {
  const openOnSingleClick = useAppStore((s) => s.settings.openOnSingleClick);

  // Deobf-mark state (the row reads its own marked status so we can
  // render a 🔒 marker next to deobf-method names without a parent
  // selector). Re-renders on marks change because Zustand subscribes
  // per-selector.
  const isDeobfMarked    = useAppStore((s) => s.isDeobfMarked);
  const markDeobf        = useAppStore((s) => s.markDeobf);
  const unmarkDeobf      = useAppStore((s) => s.unmarkDeobf);
  const setActiveBottomTab = useAppStore((s) => s.setActiveBottomTab);

  // Re-read marked state on every render; cheap (membership check).
  const methodRef = node.kind === "method" ? parseMethodRef(node.fullName) : null;
  const isMarked = methodRef
    ? isDeobfMarked(methodRef.className, methodRef.methodName)
    : false;

  // Context-menu position; null = closed.
  const [ctxMenu, setCtxMenu] = useState<{ x: number; y: number } | null>(null);
  // Close on any outside click. We listen at document level so the menu
  // dismisses even when the user clicks another tree row.
  useEffect(() => {
    if (!ctxMenu) return;
    const close = () => setCtxMenu(null);
    document.addEventListener("click", close);
    document.addEventListener("contextmenu", close);
    return () => {
      document.removeEventListener("click", close);
      document.removeEventListener("contextmenu", close);
    };
  }, [ctxMenu]);

  const hasChildren = (node.children?.length ?? 0) > 0;
  const isExpanded = expandedNodes.has(node.id);
  const isSelected = node.id === selectedNodeId;
  const indent = depth * 12;

  const isOpenable =
    node.kind === "class" ||
    node.kind === "method" ||
    node.kind === "manifest" ||
    node.kind === "res_entry" ||
    node.kind === "asset" ||
    node.kind === "embedded_apk" ||
    node.kind === "diff_added" ||
    node.kind === "diff_removed" ||
    node.kind === "diff_modified";

  const handleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    onSelectNode(node);
    if (openOnSingleClick) {
      // Original behaviour: single click opens and expands
      if (isOpenable) {
        onOpenNode(node);
        if (node.kind === "class" && hasChildren) {
          onToggleExpand(node.id);
        }
      } else if (hasChildren) {
        onToggleExpand(node.id);
      }
    } else {
      // Select-only on single click; containers still toggle expand
      if (!isOpenable && hasChildren) {
        onToggleExpand(node.id);
      }
    }
  };

  const handleDoubleClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (!isOpenable && hasChildren) {
      // Containers always toggle expand on double-click
      onToggleExpand(node.id);
    } else {
      onOpenNode(node);
      if (node.kind === "class" && hasChildren) {
        onToggleExpand(node.id);
      }
    }
  };

  return (
    <>
      <div
        data-node-id={node.id}
        className={[
          "flex items-center gap-1 py-0.5 pr-2 cursor-pointer select-none group",
          "text-xs font-mono",
          isSelected
            ? "bg-vs-selection text-vs-text"
            : "hover:bg-vs-elevated/60 text-vs-text",
        ].join(" ")}
        style={{ paddingLeft: `${indent + 4}px` }}
        onClick={handleClick}
        onDoubleClick={handleDoubleClick}
        title={node.fullName ?? node.name}
        onContextMenu={(e) => {
          // Only methods get the deobf-mark menu — clicking other node
          // types lets the browser show its default menu (handy for
          // copying text from a class name, etc.).
          if (!methodRef) return;
          e.preventDefault();
          setCtxMenu({ x: e.clientX, y: e.clientY });
        }}
      >
        {/* Expand toggle */}
        <span className="w-4 flex-shrink-0 text-center text-vs-dim">
          {hasChildren ? (isExpanded ? "▾" : "▸") : ""}
        </span>

        {/* Icon */}
        <span className="text-xs flex-shrink-0" role="img" aria-label={node.kind}>
          {KIND_ICON[node.kind]}
        </span>

        {/* Name */}
        <span
          className={[
            "truncate flex-1",
            KIND_COLOR[node.kind],
          ].join(" ")}
        >
          {node.name}
        </span>

        {/* Deobf-mark indicator. Only shown for marked methods so the
            tree stays visually quiet for everything else. */}
        {isMarked && (
          <span
            className="text-vs-accent text-xs flex-shrink-0"
            title="Marked as a deobfuscation method — see the DEOBFUSCATION bottom-bar tab"
            aria-label="deobfuscation mark"
          >
            🔓
          </span>
        )}

        {/* Access flags badge */}
        {node.accessFlags && node.accessFlags.length > 0 && (
          <span className="text-vs-dim text-xs opacity-60 flex-shrink-0">
            {node.accessFlags
              .filter((f) => ["public", "private", "protected", "static", "abstract"].includes(f))
              .slice(0, 2)
              .map((f) => f[0].toUpperCase())
              .join("")}
          </span>
        )}
      </div>

      {/* Method context menu — Mark / Unmark as deobfuscator. Rendered
          here (not inside the row) so it floats above neighbouring rows
          rather than being clipped by overflow. */}
      {ctxMenu && methodRef && (
        <div
          className="fixed z-50 bg-vs-surface border border-vs-border rounded shadow-lg py-1 min-w-52 text-xs"
          style={{ left: ctxMenu.x, top: ctxMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-3 py-1 border-b border-vs-border mb-1 text-vs-dim font-mono truncate">
            {methodRef.className.split("/").pop()}::{methodRef.methodName}
          </div>
          {isMarked ? (
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated"
              onClick={() => {
                void unmarkDeobf(methodRef.className, methodRef.methodName);
                setCtxMenu(null);
              }}
            >
              🔒  Unmark as deobfuscator
            </button>
          ) : (
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated"
              onClick={() => {
                void markDeobf(methodRef.className, methodRef.methodName);
                setCtxMenu(null);
              }}
            >
              🔓  Mark as deobfuscator
            </button>
          )}
          <button
            className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated text-vs-dim"
            onClick={() => {
              setActiveBottomTab("DEOBFUSCATION");
              setCtxMenu(null);
            }}
          >
            🧰  Open Deobfuscation panel
          </button>
        </div>
      )}

      {/* Children */}
      {hasChildren && isExpanded && (
        <div>
          {node.children!.map((child) => (
            <TreeNodeRow
              key={child.id}
              node={child}
              depth={depth + 1}
              expandedNodes={expandedNodes}
              selectedNodeId={selectedNodeId}
              onToggleExpand={onToggleExpand}
              onSelectNode={onSelectNode}
              onOpenNode={onOpenNode}
            />
          ))}
        </div>
      )}
    </>
  );
};

// ─── TreeView ─────────────────────────────────────────────────────────────────

const TreeView: React.FC<TreeViewProps> = ({
  nodes,
  expandedNodes,
  selectedNodeId,
  filterQuery = "",
  onToggleExpand,
  onSelectNode,
  onOpenNode,
  depth = 0,
}) => {
  const filteredNodes = useMemo(
    () => filterTree(nodes, filterQuery),
    [nodes, filterQuery]
  );

  if (filteredNodes.length === 0 && filterQuery) {
    return (
      <div className="px-4 py-3 text-xs text-vs-dim italic">
        No results for "{filterQuery}"
      </div>
    );
  }

  if (filteredNodes.length === 0) {
    return (
      <div className="px-4 py-3 text-xs text-vs-dim italic">
        No items
      </div>
    );
  }

  return (
    <div>
      {filteredNodes.map((node) => (
        <TreeNodeRow
          key={node.id}
          node={node}
          depth={depth}
          expandedNodes={expandedNodes}
          selectedNodeId={selectedNodeId}
          onToggleExpand={onToggleExpand}
          onSelectNode={onSelectNode}
          onOpenNode={onOpenNode}
        />
      ))}
    </div>
  );
};

export default TreeView;
