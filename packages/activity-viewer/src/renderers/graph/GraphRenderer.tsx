/**
 * Cross-activity navigation graph view.
 *
 * Renders activities as nodes and their statically-discovered navigation
 * transitions (Phase 8's `ActivityView.outgoingNavigations`) as directed
 * edges. The current activity sits at the centre; outgoing destinations
 * fan out around it; clicking any node navigates the viewer to that
 * activity (using the same back-stack-aware navigation as click-through
 * mode).
 *
 * The graph is populated incrementally — we only have `outgoingNavigations`
 * for activities we've already rehydrated, so as the user drills into the
 * graph we lazy-fetch each new neighbour. A simple in-component cache
 * keeps the work bounded across navigations.
 *
 * Layout: a deliberately-simple radial pass. Current activity centred;
 * direct outgoing destinations arranged in a circle around it; reverse
 * edges (other activities that navigate *to* the current one) appear as
 * an inner ring with thinner connectors. Force-directed layout would be
 * prettier on big graphs but adds animation complexity and per-node DOM
 * cost we don't need at v1 scope.
 */

import React, { useEffect, useMemo, useState } from "react";
import type { ActivitySummary, ActivityView, NavTarget } from "../../types";
import type { ViewerApi } from "../../api";

export interface GraphRendererProps {
  /** Currently-selected activity name (centre node). */
  currentActivity: string | null;
  /** Lightweight activity directory — we use it both to render display
   *  labels and to know which destinations resolve to in-APK activities
   *  vs external (framework / not loaded). */
  activities: ActivitySummary[];
  /** The IR for the current activity — gives us its `outgoingNavigations`
   *  without an extra fetch. */
  currentView: ActivityView | null;
  /** Host API — we use `rehydrateActivity` to lazy-fetch neighbours'
   *  outgoing edges when they enter the visible graph. */
  api: ViewerApi;
  /** Click-to-navigate. */
  onSelectActivity(name: string): void;
}

/** Cached `outgoingNavigations` keyed by activity name. Module-scope so
 *  the cache survives renderer-toggle (when the user flips Tree/HTML/
 *  Canvas/Graph the cache stays warm). The IR doesn't change between
 *  renders unless the APK reloads, so cache invalidation isn't a concern
 *  in this session. */
const navCache: Map<string, NavTarget[]> = new Map();

export const GraphRenderer: React.FC<GraphRendererProps> = ({
  currentActivity, activities, currentView, api, onSelectActivity,
}) => {
  // ── Maintain the cache as new IR comes in ──
  useEffect(() => {
    if (currentView) {
      navCache.set(currentView.activityName, currentView.outgoingNavigations);
    }
  }, [currentView]);

  // ── Lazy-fetch outgoing edges for visible neighbours ──
  // When a new neighbour appears in the graph we fetch its edges so the
  // user can see where IT goes too, one hop at a time. Bounded by the
  // visible neighbour count (typically 3-8).
  const [, setBumpRender] = useState(0);
  useEffect(() => {
    if (!currentActivity || !currentView) return;
    const targets = currentView.outgoingNavigations
      .filter(isJumpableActivityNav)
      .map((n) => n.target)
      .filter((name) => activities.some((a) => a.name === name))
      .filter((name) => !navCache.has(name));

    let cancelled = false;
    Promise.all(targets.map((name) => api.rehydrateActivity(name).catch(() => null)))
      .then((results) => {
        if (cancelled) return;
        let changed = false;
        for (const r of results) {
          if (r && !navCache.has(r.activityName)) {
            navCache.set(r.activityName, r.outgoingNavigations);
            changed = true;
          }
        }
        if (changed) setBumpRender((n) => n + 1);
      });
    return () => { cancelled = true; };
  }, [currentActivity, currentView, activities, api]);

  // ── Build the visible graph ──
  const graph = useMemo(() => {
    if (!currentActivity) return null;
    return buildVisibleGraph(currentActivity, activities);
  }, [currentActivity, activities]);

  if (!currentActivity || !graph) {
    return (
      <div className="pap-renderer pap-renderer--empty">
        Pick an activity to see its navigation graph.
      </div>
    );
  }

  // ── Render ──
  const W = 720;
  const H = 540;
  return (
    <div className="pap-renderer pap-renderer--graph">
      <svg className="pap-graph" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
        {/* Arrowhead markers, shared across all edges. The `refX` is a few
         *  px shy of the marker box so the tip lands exactly at the line
         *  endpoint (which we already trimmed to the node border). */}
        <defs>
          <marker id="pap-arrow-out" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--pap-accent)" />
          </marker>
          <marker id="pap-arrow-in" viewBox="0 0 10 10" refX="9" refY="5"
                  markerWidth="6" markerHeight="6" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--pap-muted)" />
          </marker>
        </defs>

        {/* Edges first so node rectangles paint over the line endpoints. */}
        {graph.edges.map((e, i) => (
          <Edge key={i} edge={e} />
        ))}
        {graph.nodes.map((n) => (
          <Node
            key={n.name}
            node={n}
            isCurrent={n.name === currentActivity}
            onClick={() => onSelectActivity(n.name)}
          />
        ))}
      </svg>
      <div className="pap-graph__legend">
        <span><span className="pap-graph__sw pap-graph__sw--current" /> current</span>
        <span><span className="pap-graph__sw pap-graph__sw--out" /> destination</span>
        <span><span className="pap-graph__sw pap-graph__sw--in" /> caller</span>
        <span><span className="pap-graph__sw pap-graph__sw--external" /> external</span>
      </div>
    </div>
  );
};

// ── SVG primitives ───────────────────────────────────────────────────────

const Node: React.FC<{
  node: GraphNode;
  isCurrent: boolean;
  onClick: () => void;
}> = ({ node, isCurrent, onClick }) => {
  const cls = [
    "pap-graph__node",
    isCurrent ? "pap-graph__node--current" : "",
    !node.isInApk ? "pap-graph__node--external" : "",
    node.role === "in" ? "pap-graph__node--in" : "",
    node.role === "out" ? "pap-graph__node--out" : "",
  ].filter(Boolean).join(" ");
  return (
    <g className={cls} onClick={onClick} style={{ cursor: node.isInApk ? "pointer" : "not-allowed" }}>
      <rect
        x={node.x - node.w / 2}
        y={node.y - node.h / 2}
        width={node.w}
        height={node.h}
        rx={node.h / 2}
      />
      <text x={node.x} y={node.y} textAnchor="middle" dominantBaseline="middle">
        {shortName(node.name)}
      </text>
      <title>{node.name}</title>
    </g>
  );
};

const Edge: React.FC<{ edge: GraphEdge }> = ({ edge }) => {
  // Trim line endpoints so they meet the node ovals' borders, not centres.
  const dx = edge.x2 - edge.x1;
  const dy = edge.y2 - edge.y1;
  const len = Math.hypot(dx, dy) || 1;
  const ux = dx / len, uy = dy / len;
  // Approximate the rounded-rect with an outward offset roughly equal to
  // half its short axis — close enough not to overlap visibly.
  const trim1 = 28;
  const trim2 = 32;
  const x1 = edge.x1 + ux * trim1;
  const y1 = edge.y1 + uy * trim1;
  const x2 = edge.x2 - ux * trim2;
  const y2 = edge.y2 - uy * trim2;

  // Marker-based arrowhead.
  const markerId = edge.kind === "in" ? "pap-arrow-in" : "pap-arrow-out";
  return (
    <>
      <line
        className={`pap-graph__edge pap-graph__edge--${edge.kind}`}
        x1={x1} y1={y1} x2={x2} y2={y2}
        markerEnd={`url(#${markerId})`}
      />
      <title>{edge.label}</title>
      {/* Markers are SVG-scoped; we stamp them once per render at the end
       *  of the parent SVG via a defs block. Done in the parent. */}
    </>
  );
};

// ── Graph layout ─────────────────────────────────────────────────────────

interface GraphNode {
  name: string;
  /** "current" / "out" (destination) / "in" (caller). */
  role: "current" | "out" | "in";
  isInApk: boolean;
  x: number; y: number;
  w: number; h: number;
}

interface GraphEdge {
  x1: number; y1: number;
  x2: number; y2: number;
  kind: "out" | "in";
  label: string;
}

interface VisibleGraph {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

function buildVisibleGraph(
  currentActivity: string,
  activities: ActivitySummary[],
): VisibleGraph {
  const W = 720, H = 540;
  const cx = W / 2, cy = H / 2;
  const nodeW = 180, nodeH = 36;

  // Direct outgoing destinations from current.
  const outgoing = (navCache.get(currentActivity) ?? [])
    .filter(isJumpableActivityNav)
    .map((n) => n.target);
  const outgoingDeduped = Array.from(new Set(outgoing));

  // Reverse edges: any cached activity whose outgoingNavigations include
  // currentActivity as a startActivity target. This is best-effort —
  // limited to activities the user has already drilled into.
  const incoming: string[] = [];
  for (const [from, navs] of navCache.entries()) {
    if (from === currentActivity) continue;
    if (navs.some((n) => isJumpableActivityNav(n) && n.target === currentActivity)) {
      incoming.push(from);
    }
  }

  // Position outgoing in a half-fan to the right; incoming in a half-fan
  // to the left. Keeps the visual flow "left = where I came from, right =
  // where I'm going" which matches reading direction.
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  nodes.push({
    name: currentActivity,
    role: "current",
    isInApk: activities.some((a) => a.name === currentActivity),
    x: cx, y: cy, w: nodeW, h: nodeH,
  });

  const placeFan = (
    items: string[], side: "right" | "left", role: "out" | "in",
  ) => {
    if (items.length === 0) return;
    // Vertical fan: spread evenly across the available height. For a
    // small number of items they'll all sit on the same horizontal line
    // but offset; for many items they'll stack.
    const radius = 240;
    const angleSpan = Math.min(160, 30 * items.length); // degrees
    const startAngle = -angleSpan / 2;
    for (let i = 0; i < items.length; i++) {
      const t = items.length === 1 ? 0.5 : i / (items.length - 1);
      const angleDeg = startAngle + angleSpan * t;
      const angleRad = (angleDeg * Math.PI) / 180;
      const dx = radius * Math.cos(angleRad);
      const dy = radius * Math.sin(angleRad);
      const x = side === "right" ? cx + dx : cx - dx;
      const y = cy + dy;
      const name = items[i];
      const isInApk = activities.some((a) => a.name === name);
      nodes.push({
        name, role,
        isInApk,
        x, y, w: nodeW, h: nodeH,
      });
      // Edge always points from caller → callee (out: current→neighbour;
      // in: neighbour→current).
      if (role === "out") {
        edges.push({
          x1: cx, y1: cy, x2: x, y2: y,
          kind: "out",
          label: `${currentActivity} → ${name}`,
        });
      } else {
        edges.push({
          x1: x, y1: y, x2: cx, y2: cy,
          kind: "in",
          label: `${name} → ${currentActivity}`,
        });
      }
    }
  };

  placeFan(outgoingDeduped, "right", "out");
  placeFan(incoming, "left", "in");

  return { nodes, edges };
}

// ── Helpers ──────────────────────────────────────────────────────────────

/** True for nav targets that resolve to an activity FQN — the only kinds
 *  worth drawing (fragment swaps and nav-graph ids point at things we
 *  can't necessarily resolve to a node). */
function isJumpableActivityNav(n: NavTarget): boolean {
  return n.kind === "startActivity" || n.kind === "startActivityForResult";
}

function shortName(fq: string): string {
  const dot = fq.lastIndexOf(".");
  return dot >= 0 ? fq.slice(dot + 1) : fq;
}
