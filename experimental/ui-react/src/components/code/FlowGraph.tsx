// Binary-Ninja-style call-graph viewer.
//
// Replaces the older force-directed simulation with a Sugiyama-style
// hierarchical layout courtesy of `dagre`. Each node is a function
// (className::methodName); edges go from caller to callee.
//
// ## Layout
//
// We default to a left-to-right (LR) ranking — that's what Binja's
// call graph uses and it reads naturally for English-LTR users
// (caller flows left → callee on the right). Nodes are rounded
// rectangles styled to match the rest of the platypus UI; edges
// are SVG polylines with arrowheads at the callee end.
//
// ## Interaction
//
// - Pan: drag empty space
// - Zoom: mouse wheel
// - Click node: select it (highlighted with accent border) + reveal
//   it in the centre-panel code view
// - Double-click node: expand its callers + callees into the graph
// - Right-click node: context menu with Expand / Remove / Open source
// - The graph re-lays out (synchronously) whenever the node set
//   changes; dagre is fast enough at <500 nodes that animation isn't
//   needed.
//
// ## Why dagre
//
// Native Sugiyama (hand-rolled rank assignment + crossing minimisation
// + coordinate assignment) is ~800 lines of careful code. `dagre` is
// ~50KB, mature, and produces edge waypoints we can render directly
// as orthogonal polylines. The cost (one new dependency) is well
// below the cost of maintaining a hand-rolled layout.

import React, { useEffect, useMemo, useRef, useState, useCallback } from "react";
import dagre from "dagre";
import { api } from "../../api/adapter";
import { useAppStore } from "../../store/appStore";

// ─── Sizing constants ────────────────────────────────────────────────────────

const NODE_W = 200;
const NODE_H = 56;
/** Visual padding inside the SVG viewBox so edges don't clip at the borders. */
const VIEW_PAD = 60;

// ─── Internal types ──────────────────────────────────────────────────────────

type NodeRole = "start" | "target" | "normal";

interface FGNode {
  id: string;
  className: string;
  methodName: string;
  role: NodeRole;
  loading: boolean;
  /** Layout-assigned center coordinates. Reset on every dagre run. */
  x: number;
  y: number;
}

interface FGEdge {
  sourceId: string;
  targetId: string;
  /** Polyline waypoints from dagre (in graph coordinates). The first
   *  and last point are the node-edge intersection; intermediate
   *  points form the orthogonal kinks. */
  points: Array<{ x: number; y: number }>;
}

interface Transform {
  tx: number;
  ty: number;
  scale: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function nodeId(className: string, methodName: string): string {
  return `${className}->${methodName}`;
}

function shortClass(className: string): string {
  let n = className;
  if (n.startsWith("L") && n.endsWith(";")) n = n.slice(1, -1);
  const parts = n.split("/");
  return parts[parts.length - 1] ?? n;
}

/** Role-based colour scheme. Binja's palette: dark slate node with
 *  a single-pixel accent border. Selected nodes get a brighter
 *  border + glow. */
function nodeColors(role: NodeRole, selected: boolean): {
  bg: string; border: string; titleColor: string; subColor: string;
} {
  // Selected always wins for the border so it's visually obvious.
  const sel = selected;
  switch (role) {
    case "start":
      return {
        bg: "#1a2a4a",
        border: sel ? "#60a5fa" : "#3b82f6",
        titleColor: "#dbeafe",
        subColor: "#93c5fd",
      };
    case "target":
      return {
        bg: "#3a1a1a",
        border: sel ? "#fca5a5" : "#ef4444",
        titleColor: "#fee2e2",
        subColor: "#fecaca",
      };
    default:
      return {
        bg: "#1e1e2e",
        border: sel ? "#a78bfa" : "#4b5563",
        titleColor: "#e2e8f0",
        subColor: "#94a3b8",
      };
  }
}

// ─── Component ───────────────────────────────────────────────────────────────

interface FlowGraphProps {
  onClose: () => void;
}

const FlowGraph: React.FC<FlowGraphProps> = ({ onClose }) => {
  const selectedNode    = useAppStore((s) => s.selectedNode);
  const navigateToMember = useAppStore((s) => s.navigateToMember);

  // Graph data. We keep nodes/edges in refs to avoid re-rendering
  // mid-mutation; the explicit `tick` after each mutation is what
  // triggers a re-render and a dagre relayout.
  const nodesRef = useRef<Map<string, FGNode>>(new Map());
  const edgesRef = useRef<FGEdge[]>([]);
  const [tick, setTick] = useState(0);
  const bump = useCallback(() => setTick((t) => t + 1), []);

  // Pan/zoom. The SVG renders nodes in graph coordinates; the
  // <g transform> applies (tx, ty, scale) on top.
  const transformRef = useRef<Transform>({ tx: 0, ty: 0, scale: 1 });
  const [, forceTransformRender] = useState(0);
  const repaintTransform = useCallback(() => forceTransformRender((t) => t + 1), []);

  // Interaction state
  const [selectedId, setSelectedId]   = useState<string | null>(null);
  const [ctxMenu, setCtxMenu]         = useState<{ x: number; y: number; nodeId: string } | null>(null);
  const [layoutDir, setLayoutDir]     = useState<"LR" | "TB">("LR");
  const isDraggingBgRef = useRef(false);
  const dragStartRef    = useRef({ mx: 0, my: 0, tx: 0, ty: 0 });
  const svgRef          = useRef<SVGSVGElement>(null);

  // ── Dagre layout ────────────────────────────────────────────────────────
  //
  // Re-runs every time `tick` changes (i.e. after any mutation). The
  // graph is built fresh each time — dagre is fast enough at our
  // expected scale (<500 nodes) and statefulness across runs isn't
  // worth the bookkeeping cost.

  useEffect(() => {
    const g = new dagre.graphlib.Graph();
    g.setGraph({
      rankdir: layoutDir,
      nodesep: 30,     // gap between nodes in the same rank
      ranksep: 80,     // gap between ranks
      edgesep: 12,
      marginx: VIEW_PAD,
      marginy: VIEW_PAD,
    });
    g.setDefaultEdgeLabel(() => ({}));

    for (const n of nodesRef.current.values()) {
      g.setNode(n.id, { width: NODE_W, height: NODE_H });
    }
    for (const e of edgesRef.current) {
      // dagre silently ignores edges to/from unknown nodes, which is
      // exactly what we want when a target was just removed.
      g.setEdge(e.sourceId, e.targetId);
    }

    dagre.layout(g);

    // Pull positions back into our node/edge refs. dagre uses
    // top-left for node origin... no wait, it returns the *centre*
    // of the node already, so we can copy x/y verbatim.
    for (const n of nodesRef.current.values()) {
      const pos = g.node(n.id);
      if (pos) {
        n.x = pos.x;
        n.y = pos.y;
      }
    }
    for (const e of edgesRef.current) {
      const ge = g.edge(e.sourceId, e.targetId);
      e.points = ge?.points ?? [];
    }
  }, [tick, layoutDir]);

  // ── Mutators ──────────────────────────────────────────────────────────

  function addNode(className: string, methodName: string, role: NodeRole): boolean {
    const id = nodeId(className, methodName);
    if (nodesRef.current.has(id)) return false;
    nodesRef.current.set(id, {
      id, className, methodName, role,
      loading: false,
      x: 0, y: 0,
    });
    return true;
  }

  function addEdge(sourceId: string, targetId: string) {
    if (sourceId === targetId) return;
    if (!nodesRef.current.has(sourceId) || !nodesRef.current.has(targetId)) return;
    const exists = edgesRef.current.some((e) => e.sourceId === sourceId && e.targetId === targetId);
    if (exists) return;
    edgesRef.current.push({ sourceId, targetId, points: [] });
  }

  function removeNode(id: string) {
    nodesRef.current.delete(id);
    edgesRef.current = edgesRef.current.filter((e) => e.sourceId !== id && e.targetId !== id);
    if (selectedId === id) setSelectedId(null);
    setCtxMenu(null);
    bump();
  }

  async function expandNode(id: string) {
    const node = nodesRef.current.get(id);
    if (!node || node.loading) return;
    node.loading = true;
    bump();

    try {
      const result = await api.getCallGraph(node.className, node.methodName);
      for (const callee of result.callees) {
        addNode(callee.className, callee.methodName, "normal");
        addEdge(id, nodeId(callee.className, callee.methodName));
      }
      for (const caller of result.callers) {
        addNode(caller.className, caller.methodName, "normal");
        addEdge(nodeId(caller.className, caller.methodName), id);
      }
    } catch (err) {
      console.error("FlowGraph: expand failed", err);
    } finally {
      const n = nodesRef.current.get(id);
      if (n) n.loading = false;
      bump();
    }
  }

  // ── Seed from selected method ─────────────────────────────────────────

  useEffect(() => {
    if (!selectedNode || selectedNode.kind !== "method") return;
    const fullName = selectedNode.fullName ?? "";
    const arrowIdx = fullName.indexOf("->");
    if (arrowIdx < 0) return;
    const className = fullName.slice(0, arrowIdx);
    const methodName = fullName.slice(arrowIdx + 2).split("(")[0];
    if (!className || !methodName) return;

    // Reset whenever the active method changes — a stale graph from
    // a previous method is worse than no graph.
    nodesRef.current.clear();
    edgesRef.current = [];
    transformRef.current = { tx: 0, ty: 0, scale: 1 };

    addNode(className, methodName, "start");
    setSelectedId(nodeId(className, methodName));
    // Auto-expand the seed node so the user sees something immediately.
    void expandNode(nodeId(className, methodName));
    bump();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedNode?.id, selectedNode?.fullName]);

  // ── Auto-fit on first layout ──────────────────────────────────────────
  //
  // After every layout, compute the bounding box of the current nodes
  // and recenter (no scale change unless graph is bigger than viewport).
  // This makes the "click Flow → see your function" interaction land
  // with the graph already centered.

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;
    if (nodesRef.current.size === 0) return;
    const nodes = Array.from(nodesRef.current.values());
    const minX = Math.min(...nodes.map((n) => n.x - NODE_W / 2));
    const minY = Math.min(...nodes.map((n) => n.y - NODE_H / 2));
    const maxX = Math.max(...nodes.map((n) => n.x + NODE_W / 2));
    const maxY = Math.max(...nodes.map((n) => n.y + NODE_H / 2));
    const graphW = maxX - minX + VIEW_PAD * 2;
    const graphH = maxY - minY + VIEW_PAD * 2;
    const viewW = svg.clientWidth || 800;
    const viewH = svg.clientHeight || 500;
    // Don't auto-zoom out aggressively — clamp at 1x so a small graph
    // stays readable. Zoom in further to 1x if the graph is tiny.
    const scale = Math.min(1, viewW / graphW, viewH / graphH);
    const tx = (viewW - (graphW - VIEW_PAD * 2) * scale) / 2 - minX * scale;
    const ty = (viewH - (graphH - VIEW_PAD * 2) * scale) / 2 - minY * scale;
    transformRef.current = { tx, ty, scale };
    repaintTransform();
    // We deliberately re-fit on every layout so newly-expanded nodes
    // never end up off-screen. If this feels jumpy in practice we can
    // gate it behind a "Reset view" button instead.
  }, [tick, repaintTransform]);

  // ── Pan + zoom ────────────────────────────────────────────────────────

  function onMouseDown(e: React.MouseEvent<SVGSVGElement>) {
    if ((e.target as SVGElement).closest("[data-node-id]")) return;
    isDraggingBgRef.current = true;
    dragStartRef.current = {
      mx: e.clientX,
      my: e.clientY,
      tx: transformRef.current.tx,
      ty: transformRef.current.ty,
    };
  }
  function onMouseMove(e: React.MouseEvent<SVGSVGElement>) {
    if (!isDraggingBgRef.current) return;
    const dx = e.clientX - dragStartRef.current.mx;
    const dy = e.clientY - dragStartRef.current.my;
    transformRef.current.tx = dragStartRef.current.tx + dx;
    transformRef.current.ty = dragStartRef.current.ty + dy;
    repaintTransform();
  }
  function onMouseUp() { isDraggingBgRef.current = false; }
  function onWheel(e: React.WheelEvent<SVGSVGElement>) {
    e.preventDefault();
    const svg = svgRef.current;
    if (!svg) return;
    const rect = svg.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    const oldScale = transformRef.current.scale;
    const factor = e.deltaY < 0 ? 1.15 : 1 / 1.15;
    const newScale = Math.max(0.1, Math.min(4, oldScale * factor));
    // Zoom toward cursor: shift the translation so the point under
    // the cursor stays under the cursor.
    transformRef.current.tx = mx - (mx - transformRef.current.tx) * (newScale / oldScale);
    transformRef.current.ty = my - (my - transformRef.current.ty) * (newScale / oldScale);
    transformRef.current.scale = newScale;
    repaintTransform();
  }

  // ── Node click handlers ──────────────────────────────────────────────

  function onNodeClick(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    setSelectedId(id);
    setCtxMenu(null);
  }
  function onNodeDoubleClick(id: string, e: React.MouseEvent) {
    e.stopPropagation();
    void expandNode(id);
  }
  function onNodeContextMenu(id: string, e: React.MouseEvent) {
    e.preventDefault();
    e.stopPropagation();
    setCtxMenu({ x: e.clientX, y: e.clientY, nodeId: id });
  }
  function navigateToNode(id: string) {
    const n = nodesRef.current.get(id);
    if (!n) return;
    // Ensure class ref is L…;-wrapped for navigateToMember.
    let classRef = n.className;
    if (!classRef.startsWith("L") || !classRef.endsWith(";")) {
      classRef = `L${classRef.replace(/^L/, "").replace(/;$/, "")};`;
    }
    void navigateToMember(classRef, n.methodName);
  }

  // ── Dismiss context menu on outside click ─────────────────────────────

  useEffect(() => {
    if (!ctxMenu) return;
    const close = () => setCtxMenu(null);
    document.addEventListener("click", close);
    return () => document.removeEventListener("click", close);
  }, [ctxMenu]);

  // ── Edge rendering ────────────────────────────────────────────────────

  // Pre-compute edge path strings. dagre returns waypoints; we string
  // them together as polylines (orthogonal kinks already baked in).
  const edgePaths = useMemo(() => {
    return edgesRef.current.map((e) => {
      if (e.points.length === 0) return { id: `${e.sourceId}→${e.targetId}`, d: "" };
      const d = e.points
        .map((p, i) => `${i === 0 ? "M" : "L"} ${p.x} ${p.y}`)
        .join(" ");
      return { id: `${e.sourceId}→${e.targetId}`, d };
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tick]);

  // ── Render ──────────────────────────────────────────────────────────────

  const t = transformRef.current;
  const nodes = Array.from(nodesRef.current.values());

  return (
    <div className="absolute inset-0 z-30 bg-vs-bg flex flex-col">
      {/* Top toolbar */}
      <div className="flex items-center gap-2 px-2 py-1 border-b border-vs-border bg-vs-elevated/40 flex-shrink-0">
        <span className="text-xs text-vs-muted font-semibold uppercase tracking-wider">
          Call Graph
        </span>
        <span className="text-[10px] text-vs-dim">
          {nodes.length} node{nodes.length === 1 ? "" : "s"} ·
          {" "}{edgesRef.current.length} edge{edgesRef.current.length === 1 ? "" : "s"}
        </span>

        {/* Layout direction toggle */}
        <div className="ml-3 flex items-center gap-0.5">
          <button
            className={[
              "px-1.5 py-0.5 text-[10px] rounded border",
              layoutDir === "LR"
                ? "border-vs-accent text-vs-accent bg-vs-accent/10"
                : "border-vs-border text-vs-dim hover:text-vs-text",
            ].join(" ")}
            onClick={() => setLayoutDir("LR")}
            title="Left → Right layout"
          >
            ⇢ LR
          </button>
          <button
            className={[
              "px-1.5 py-0.5 text-[10px] rounded border",
              layoutDir === "TB"
                ? "border-vs-accent text-vs-accent bg-vs-accent/10"
                : "border-vs-border text-vs-dim hover:text-vs-text",
            ].join(" ")}
            onClick={() => setLayoutDir("TB")}
            title="Top → Bottom layout"
          >
            ⇣ TB
          </button>
        </div>

        <div className="ml-auto flex items-center gap-1">
          <span className="text-[10px] text-vs-dim italic">
            drag · scroll · double-click to expand · right-click for menu
          </span>
          <button
            className="px-2 py-0.5 text-xs text-vs-muted hover:text-vs-text"
            onClick={onClose}
            title="Close call graph"
          >
            ✕
          </button>
        </div>
      </div>

      {/* SVG canvas */}
      <div className="flex-1 overflow-hidden relative">
        <svg
          ref={svgRef}
          className="w-full h-full bg-vs-bg cursor-grab"
          style={{ cursor: isDraggingBgRef.current ? "grabbing" : "grab" }}
          onMouseDown={onMouseDown}
          onMouseMove={onMouseMove}
          onMouseUp={onMouseUp}
          onMouseLeave={onMouseUp}
          onWheel={onWheel}
        >
          <defs>
            {/* Arrowhead marker. Pointing right; rotated automatically
                by the renderer per-edge orientation. */}
            <marker
              id="fg-arrow"
              viewBox="0 0 10 10"
              refX="9"
              refY="5"
              markerUnits="strokeWidth"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#6b7280" />
            </marker>
          </defs>

          <g transform={`translate(${t.tx}, ${t.ty}) scale(${t.scale})`}>
            {/* Edges drawn first so nodes sit on top */}
            {edgePaths.map((p) => (
              <path
                key={p.id}
                d={p.d}
                fill="none"
                stroke="#6b7280"
                strokeWidth={1.5}
                markerEnd="url(#fg-arrow)"
              />
            ))}

            {/* Nodes */}
            {nodes.map((n) => {
              const selected = selectedId === n.id;
              const c = nodeColors(n.role, selected);
              const x = n.x - NODE_W / 2;
              const y = n.y - NODE_H / 2;
              return (
                <g
                  key={n.id}
                  data-node-id={n.id}
                  transform={`translate(${x}, ${y})`}
                  onClick={(e) => onNodeClick(n.id, e)}
                  onDoubleClick={(e) => onNodeDoubleClick(n.id, e)}
                  onContextMenu={(e) => onNodeContextMenu(n.id, e)}
                  className="cursor-pointer"
                  style={{ userSelect: "none" }}
                >
                  <rect
                    width={NODE_W}
                    height={NODE_H}
                    rx={8}
                    ry={8}
                    fill={c.bg}
                    stroke={c.border}
                    strokeWidth={selected ? 2 : 1}
                  />
                  <text
                    x={10}
                    y={20}
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    fontSize={12}
                    fill={c.titleColor}
                    fontWeight={600}
                  >
                    {shortClass(n.className).slice(0, 28)}
                  </text>
                  <text
                    x={10}
                    y={38}
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    fontSize={11}
                    fill={c.subColor}
                  >
                    {n.methodName.slice(0, 30)}
                  </text>
                  {n.loading && (
                    <circle
                      cx={NODE_W - 12}
                      cy={NODE_H / 2}
                      r={4}
                      fill={c.subColor}
                    >
                      <animate attributeName="opacity" values="0.2;1;0.2" dur="1s" repeatCount="indefinite" />
                    </circle>
                  )}
                </g>
              );
            })}
          </g>
        </svg>

        {/* Empty state */}
        {nodes.length === 0 && (
          <div className="absolute inset-0 flex items-center justify-center text-vs-dim text-sm pointer-events-none">
            Select a method in the tree (or click Flow from the Info pane) to populate the graph.
          </div>
        )}

        {/* Context menu */}
        {ctxMenu && (
          <div
            className="fixed z-50 bg-vs-surface border border-vs-border rounded shadow-lg py-1 min-w-44 text-xs"
            style={{ left: ctxMenu.x, top: ctxMenu.y }}
            onClick={(e) => e.stopPropagation()}
          >
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated"
              onClick={() => { void expandNode(ctxMenu.nodeId); setCtxMenu(null); }}
            >
              ⇡⇣  Expand callers + callees
            </button>
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated"
              onClick={() => { navigateToNode(ctxMenu.nodeId); setCtxMenu(null); }}
            >
              📄  Open source
            </button>
            <button
              className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated text-vs-error"
              onClick={() => removeNode(ctxMenu.nodeId)}
            >
              ✕  Remove from graph
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default FlowGraph;
