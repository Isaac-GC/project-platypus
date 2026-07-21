/**
 * ConstraintLayout solver — emits CSS placements (in container-pixel
 * coordinates) for every child of a `<ConstraintLayout>` node.
 *
 * Why hand-rolled, not Cassowary? Cassowary's strength (incremental
 * solving over a complex constraint graph) is overkill for our needs:
 * we only need a one-shot static layout, and the realistic feature
 * subset that appears in production layouts is small enough to solve
 * with a couple of passes:
 *
 *   1. **Topological pass.** Order children so each child is laid out
 *      after the siblings its anchors depend on. Children that only
 *      reference `parent` go first; cycles produce a diagnostic and
 *      we fall back to flex-column rendering.
 *   2. **Geometry pass.** For each child in topo order, resolve each
 *      anchored edge (top/bottom/start/end + left/right aliases) to a
 *      concrete pixel offset inside the container. The supported
 *      cases:
 *        - Parent anchor (`"0"` / `"parent"`)        → 0 or container size
 *        - Sibling anchor (`"@id/foo"`)              → previously-placed sibling's edge
 *        - Bidirectional anchor + horizontal/vertical_bias → bias-weighted placement
 *        - `layout_width="0dp"` (a.k.a. MATCH_CONSTRAINT) when the
 *          opposite edge is anchored → stretch to fill
 *        - Margins (per-side + the `layout_margin` shorthand)
 *        - Wrap-content sizes derived from a small heuristic table
 *          (button → 48dp, image → 40dp, text → ~24dp tall) — refined
 *          if you have actual measurements from a second pass
 *
 * What we don't implement:
 *   - Chains (`layout_constraintHorizontal_chainStyle="spread"` etc.) —
 *     they need a group solver; out of scope for v1.
 *   - Guidelines (`<Guideline app:layout_constraintGuide_percent="0.5"/>`)
 *     — virtual elements that need their own placement pre-pass.
 *   - Barriers, circular constraints, dimension ratios.
 *
 * For the unsupported cases the solver still emits absolute positions
 * for the children it could resolve and leaves the rest in flow.
 */

import type { Attribute, UnifiedView } from "../../types";

// ── Public API ─────────────────────────────────────────────────────────────

/** Container-relative pixel rectangle. All edges in CSS-px. */
export interface SolvedRect {
  /** Distance from the container's left edge. */
  left: number;
  /** Distance from the container's top edge. */
  top: number;
  /** Computed width. `null` when we couldn't determine one (renderer falls back to `auto`). */
  width: number | null;
  /** Computed height. `null` when we couldn't determine one. */
  height: number | null;
}

export interface SolveResult {
  /** Indexed by `parent.children` position. `null` when a child couldn't be solved
   *  (cycle, missing reference) — caller renders it in normal flow. */
  rects: (SolvedRect | null)[];
  /** True when at least one child has constraints (and the solver did real work). */
  anyConstrained: boolean;
  /** Human-readable diagnostics — surfaced into the renderer's `data-` attrs. */
  diagnostics: string[];
}

/** Run the solver against a ConstraintLayout-like container. */
export function solveConstraints(
  container: UnifiedView,
  containerWidthPx: number,
  containerHeightPx: number,
): SolveResult {
  const children = container.children;
  const constraints = children.map(extractConstraints);
  const anyConstrained = constraints.some(hasAnyAnchor);

  if (!anyConstrained) {
    return { rects: children.map(() => null), anyConstrained: false, diagnostics: [] };
  }

  // ── Topological order: children placed before the siblings that
  // reference them. Cycles are reported and the cycle's children fall
  // through to normal flow.
  const idToIndex = new Map<string, number>();
  children.forEach((c, i) => { if (c.id) idToIndex.set(c.id, i); });

  const order: number[] = [];
  const visiting = new Set<number>();
  const visited  = new Set<number>();
  const diagnostics: string[] = [];

  const visit = (i: number, stack: number[]): boolean => {
    if (visited.has(i)) return true;
    if (visiting.has(i)) {
      diagnostics.push(`cycle: ${stack.concat(i).map((x) => children[x].id ?? `#${x}`).join(" → ")}`);
      return false;
    }
    visiting.add(i);
    const deps = constraints[i].dependsOn;
    for (const dep of deps) {
      const j = idToIndex.get(dep);
      if (j === undefined) continue;            // forward ref outside the layout — skip
      if (!visit(j, [...stack, i])) {
        visiting.delete(i);
        return false;
      }
    }
    visiting.delete(i);
    visited.add(i);
    order.push(i);
    return true;
  };

  const placeable = new Set<number>();
  children.forEach((_, i) => {
    if (visit(i, [])) placeable.add(i);
  });

  // ── Geometry pass: resolve every placeable child's bbox using the
  // siblings already in `solved`.
  const solved = new Map<number, SolvedRect>();
  for (const i of order) {
    if (!placeable.has(i)) continue;
    const child = children[i];
    const c = constraints[i];
    const rect = solveOne(child, c, solved, idToIndex, containerWidthPx, containerHeightPx);
    if (rect) solved.set(i, rect);
  }

  const rects: (SolvedRect | null)[] = children.map((_, i) => solved.get(i) ?? null);
  return { rects, anyConstrained, diagnostics };
}

// ── Constraint extraction ──────────────────────────────────────────────────

interface Constraints {
  // Each edge — undefined when no anchor for that side.
  top:    EdgeAnchor | undefined;
  bottom: EdgeAnchor | undefined;
  left:   EdgeAnchor | undefined;
  right:  EdgeAnchor | undefined;
  // Sizes. -1 = match_parent (only meaningful at the container level),
  // -2 = wrap_content, 0 = MATCH_CONSTRAINT (stretch between anchors),
  // positive = explicit dp/px.
  widthDp:  number;
  heightDp: number;
  // Margins (per-side + shorthand). Resolved to px below.
  marginTop:    number;
  marginBottom: number;
  marginLeft:   number;
  marginRight:  number;
  // Biases when both sides of an axis are anchored. 0..1.
  hBias: number;
  vBias: number;
  // Sibling ids this child depends on — drives topo order.
  dependsOn: string[];
}

interface EdgeAnchor {
  /** What we anchor to. `"parent"` (parent-anchored) or a sibling id. */
  target: "parent" | { kind: "sibling"; id: string };
  /** Which edge of the target. `"start"` / `"end"` = same-axis edge of the target. */
  targetEdge: "start" | "end";
}

function extractConstraints(child: UnifiedView): Constraints {
  const find = (suffix: string): string | undefined =>
    child.attrs.find((a: Attribute) => a.name.endsWith(suffix))?.value;

  const anchor = (sideAttrs: string[][]): EdgeAnchor | undefined => {
    for (const [suffix, edge] of sideAttrs) {
      const v = find(suffix);
      if (v === undefined) continue;
      // "0" / "parent" / "@id/0" → parent anchor
      if (v === "0" || v === "parent" || v === "@id/0") {
        return { target: "parent", targetEdge: edge as "start" | "end" };
      }
      // "@id/foo" / "@+id/foo" → sibling anchor
      const m = v.match(/^@\+?id\/(.+)$/);
      if (m) return { target: { kind: "sibling", id: m[1] }, targetEdge: edge as "start" | "end" };
    }
    return undefined;
  };

  const top = anchor([
    [":layout_constraintTop_toTopOf",    "start"],
    [":layout_constraintTop_toBottomOf", "end"],
  ]);
  const bottom = anchor([
    [":layout_constraintBottom_toBottomOf", "end"],
    [":layout_constraintBottom_toTopOf",    "start"],
  ]);
  const left = anchor([
    [":layout_constraintStart_toStartOf", "start"],
    [":layout_constraintStart_toEndOf",   "end"],
    [":layout_constraintLeft_toLeftOf",   "start"],
    [":layout_constraintLeft_toRightOf",  "end"],
  ]);
  const right = anchor([
    [":layout_constraintEnd_toEndOf",     "end"],
    [":layout_constraintEnd_toStartOf",   "start"],
    [":layout_constraintRight_toRightOf", "end"],
    [":layout_constraintRight_toLeftOf",  "start"],
  ]);

  const dependsOn: string[] = [];
  for (const e of [top, bottom, left, right]) {
    if (e && typeof e.target !== "string" && "id" in e.target) {
      dependsOn.push(e.target.id);
    }
  }

  return {
    top, bottom, left, right,
    widthDp:  dpToNumber(find(":layout_width")) ?? -2,
    heightDp: dpToNumber(find(":layout_height")) ?? -2,
    marginTop:    px(find(":layout_marginTop") ?? find(":layout_margin")),
    marginBottom: px(find(":layout_marginBottom") ?? find(":layout_margin")),
    marginLeft:   px(find(":layout_marginStart") ?? find(":layout_marginLeft") ?? find(":layout_margin")),
    marginRight:  px(find(":layout_marginEnd") ?? find(":layout_marginRight") ?? find(":layout_margin")),
    hBias: parseFloat(find(":layout_constraintHorizontal_bias") ?? "0.5"),
    vBias: parseFloat(find(":layout_constraintVertical_bias")   ?? "0.5"),
    dependsOn,
  };
}

function hasAnyAnchor(c: Constraints): boolean {
  return !!(c.top || c.bottom || c.left || c.right);
}

// ── Single-child geometry ─────────────────────────────────────────────────

function solveOne(
  child: UnifiedView,
  c: Constraints,
  solved: Map<number, SolvedRect>,
  idToIndex: Map<string, number>,
  cw: number, ch: number,
): SolvedRect | null {
  // Resolve each axis independently.
  const horiz = solveAxis(
    c.left, c.right, c.widthDp, c.marginLeft, c.marginRight,
    c.hBias, solved, idToIndex, cw, "h", child,
  );
  const vert = solveAxis(
    c.top, c.bottom, c.heightDp, c.marginTop, c.marginBottom,
    c.vBias, solved, idToIndex, ch, "v", child,
  );

  if (!horiz && !vert) return null;
  return {
    left:   horiz?.start ?? 0,
    top:    vert?.start  ?? 0,
    width:  horiz?.length ?? null,
    height: vert?.length  ?? null,
  };
}

interface AxisResult {
  start: number;     // left or top, in container px
  length: number | null;
}

function solveAxis(
  startAnchor: EdgeAnchor | undefined,
  endAnchor:   EdgeAnchor | undefined,
  sizeDp: number,
  marginStart: number,
  marginEnd: number,
  bias: number,
  solved: Map<number, SolvedRect>,
  idToIndex: Map<string, number>,
  containerExtent: number,
  axis: "h" | "v",
  child: UnifiedView,
): AxisResult | null {
  if (!startAnchor && !endAnchor) return null;

  const edge = (anchor: EdgeAnchor | undefined): number | null => {
    if (!anchor) return null;
    if (anchor.target === "parent") {
      // start-edge of parent is 0; end-edge is containerExtent.
      return anchor.targetEdge === "start" ? 0 : containerExtent;
    }
    const i = idToIndex.get(anchor.target.id);
    if (i === undefined) return null;
    const sib = solved.get(i);
    if (!sib) return null;
    if (axis === "h") {
      const w = sib.width ?? 0;
      return anchor.targetEdge === "start" ? sib.left : sib.left + w;
    } else {
      const h = sib.height ?? 0;
      return anchor.targetEdge === "start" ? sib.top : sib.top + h;
    }
  };

  const startEdge = edge(startAnchor);
  const endEdge   = edge(endAnchor);

  // Resolve the size first. wrap_content (-2) and the default get a
  // sensible per-kind preview width/height. MATCH_CONSTRAINT (0) requires
  // both sides anchored so we can stretch.
  let length: number | null;
  if (sizeDp > 0) {
    length = sizeDp;
  } else if (sizeDp === 0 && startEdge !== null && endEdge !== null) {
    length = Math.max(0, endEdge - startEdge - marginStart - marginEnd);
  } else if (sizeDp === -1) {
    // match_parent only inside a CL is unusual but we treat it as 0dp.
    if (startEdge !== null && endEdge !== null) {
      length = Math.max(0, endEdge - startEdge - marginStart - marginEnd);
    } else {
      length = containerExtent;
    }
  } else {
    // wrap_content — approximate.
    length = approxWrapSize(child, axis);
  }

  let start: number;
  if (startEdge !== null && endEdge !== null) {
    // Bidirectional: bias-weighted placement within the slack space.
    const span    = endEdge - startEdge;
    const used    = (length ?? 0) + marginStart + marginEnd;
    const slack   = span - used;
    start = startEdge + marginStart + Math.max(0, slack) * (axis === "h" ? bias : bias);
  } else if (startEdge !== null) {
    start = startEdge + marginStart;
  } else if (endEdge !== null) {
    start = endEdge - marginEnd - (length ?? 0);
  } else {
    return null;
  }

  return { start, length };
}

// ── Approximations ─────────────────────────────────────────────────────────

/** Pick a sensible default size for a `wrap_content` child by view kind.
 *  These are real-world averages from Material 3 spec defaults — they
 *  make the preview look proportional without needing actual measurement. */
function approxWrapSize(child: UnifiedView, axis: "h" | "v"): number {
  const kind = child.kind?.kind ?? "other";
  switch (kind) {
    case "button":            return axis === "h" ? 96 : 48;
    case "imageButton":       return 48;
    case "image":             return 40;
    case "text":              return axis === "h" ? 80 : 22;
    case "editText":          return axis === "h" ? 160 : 48;
    case "switch":            return axis === "h" ? 52  : 32;
    case "checkBox":
    case "radioButton":       return axis === "h" ? 24 : 24;
    case "seekBar":
    case "progressBar":       return axis === "h" ? 200 : 32;
    case "toolbar":
    case "appBar":            return axis === "h" ? 360 : 56;
    case "bottomNav":         return axis === "h" ? 360 : 56;
    case "tabLayout":         return axis === "h" ? 360 : 48;
    case "recyclerView":
    case "listView":
    case "gridView":          return axis === "h" ? 360 : 200;
    case "custom":            return axis === "h" ? 56 : 56;     // FAB-ish default
    default:                  return axis === "h" ? 100 : 32;
  }
}

// ── Parsing helpers ────────────────────────────────────────────────────────

/** Parse an Android dimension into a plain number (px). Returns 0 for empty
 *  / unrecognised inputs. `"-1"` / `"-2"` / `"0"` pass through unchanged
 *  so the caller can detect MATCH_PARENT / WRAP_CONTENT / MATCH_CONSTRAINT. */
function dpToNumber(raw: string | undefined): number | undefined {
  if (raw === undefined) return undefined;
  if (raw === "-1") return -1;
  if (raw === "-2") return -2;
  const m = raw.match(/^(-?\d+(?:\.\d+)?)(dp|sp|px|dip)?$/);
  if (!m) return undefined;
  return parseFloat(m[1]);
}

function px(raw: string | undefined): number {
  if (raw === undefined) return 0;
  const m = raw.match(/^(-?\d+(?:\.\d+)?)(dp|sp|px|dip)?$/);
  if (!m) return 0;
  const n = parseFloat(m[1]);
  return n < 0 ? 0 : n;
}
