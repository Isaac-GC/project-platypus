/**
 * Two-pass measure+layout for the canvas renderer.
 *
 * This is a deliberately minimal port of Android's measure/layout pipeline
 * — enough to produce something that looks plausible for the typical view
 * trees the rehydrate IR produces, not a faithful rebuild. Where Android
 * has dozens of layout-policy classes (`LinearLayout.LayoutParams`,
 * `RelativeLayout.LayoutParams`, …) we collapse to a small handful of
 * strategies dispatched on `ViewKind`.
 *
 * The output is a flat positional tree the paint pass walks in order. Each
 * `LaidOutView` carries:
 *   - the original UnifiedView (so paint can read attrs / handlers)
 *   - the absolute pixel rect inside the canvas
 *   - the `TreePath` (so hit-test can emit selection events)
 *
 * We don't attempt to position floating menus, popups, or absolute
 * `layout_x`/`layout_y` coordinates — those are rare in the static layout
 * XML the IR comes from, and out of scope for v1.
 */

import type { UnifiedView, Theme } from "../../types";
import type { TreePath } from "../../components/TreeView";
import {
  attr, dpToPx, dpToNumber, gravityToFlexParent, layoutGravityToFlexChild,
  spacingFromAttrs, resolveThemeRef, androidColorToCss,
} from "../html/attrs";

/** A view with its computed pixel rectangle (relative to the canvas origin). */
export interface LaidOutView {
  node: UnifiedView;
  path: TreePath;
  /** X/Y/W/H in canvas-space pixels. */
  x: number; y: number; w: number; h: number;
  /** Flat list of children's positioned rects, depth-first by `path`. */
  children: LaidOutView[];
  /** The "intrinsic" size used during measure — paint can compare against
   *  the final box to know if a content view was clipped. */
  intrinsic: { w: number; h: number };
  /** When this view is being laid out as a repeat of a list-host's
   *  `itemTemplate`, the row index. Lets paint substitute `{field} #N`
   *  for non-literal text bindings so each row reads as distinct.
   *  `undefined` outside of list contexts. */
  rowIndex?: number;
}

/** Layout the entire tree into a fixed-width "screen" of `screenW × screenH`.
 *  Returns the root LaidOutView; consumers walk `.children` recursively. */
export function layoutTree(
  root: UnifiedView,
  screenW: number,
  screenH: number,
  theme: Theme | undefined,
): LaidOutView {
  const ctx: LayoutCtx = { theme, screenW, screenH };
  return layoutNode(root, [], 0, 0, screenW, screenH, ctx);
}

interface LayoutCtx {
  theme: Theme | undefined;
  screenW: number;
  screenH: number;
}

// ── Per-node dispatch ────────────────────────────────────────────────────

function layoutNode(
  node: UnifiedView,
  path: TreePath,
  x: number, y: number,
  parentW: number, parentH: number,
  ctx: LayoutCtx,
): LaidOutView {
  // Resolve this view's outer dimensions against the parent box.
  const ownW = resolveDimension(attr(node, "layout_width"),  parentW, intrinsicWidth(node));
  const ownH = resolveDimension(attr(node, "layout_height"), parentH, intrinsicHeight(node));

  const intrinsic = { w: intrinsicWidth(node), h: intrinsicHeight(node) };

  // Recurse into children using the kind-specific child layout.
  const innerPad = spacingFromAttrs(node);
  const padL = parsePx(innerPad.paddingLeft);
  const padT = parsePx(innerPad.paddingTop);
  const padR = parsePx(innerPad.paddingRight);
  const padB = parsePx(innerPad.paddingBottom);
  const innerX = x + padL;
  const innerY = y + padT;
  const innerW = Math.max(0, ownW - padL - padR);
  const innerH = Math.max(0, ownH - padT - padB);

  // For list-host views with a recovered template, lay out repeated copies
  // *before* dispatching by kind — saves duplicating that branch in every
  // list-related case.
  const childrenForLayout = listChildrenWithTemplate(node);

  let kids: LaidOutView[];
  switch (node.kind.kind) {
    case "linearLayout":
      kids = layoutLinear(node, childrenForLayout, path,
        innerX, innerY, innerW, innerH, ctx);
      break;
    case "frameLayout":
    case "relativeLayout":
    case "constraintLayout":
    case "coordinatorLayout":
      kids = layoutFrame(node, childrenForLayout, path,
        innerX, innerY, innerW, innerH, ctx);
      break;
    case "scrollView":
    case "nestedScrollView":
      kids = layoutLinearVertical(node, childrenForLayout, path,
        innerX, innerY, innerW, Number.POSITIVE_INFINITY, ctx);
      break;
    case "horizontalScrollView":
      kids = layoutLinearHorizontal(node, childrenForLayout, path,
        innerX, innerY, Number.POSITIVE_INFINITY, innerH, ctx);
      break;
    case "gridLayout":
      kids = layoutGrid(node, childrenForLayout, path,
        innerX, innerY, innerW, innerH, ctx);
      break;
    case "recyclerView":
    case "listView":
      kids = layoutListRepeats(node, path, innerX, innerY, innerW, innerH, ctx, "vertical");
      break;
    case "gridView":
      kids = layoutListRepeats(node, path, innerX, innerY, innerW, innerH, ctx, "grid");
      break;
    default:
      kids = layoutLinear(node, childrenForLayout, path,
        innerX, innerY, innerW, innerH, ctx);
      break;
  }

  return { node, path, x, y, w: ownW, h: ownH, children: kids, intrinsic };
}

// ── Layout strategies ────────────────────────────────────────────────────

function layoutLinear(
  node: UnifiedView, children: UnifiedView[], path: TreePath,
  x: number, y: number, w: number, h: number, ctx: LayoutCtx,
): LaidOutView[] {
  const orientation = (attr(node, "orientation") ?? "horizontal").toLowerCase();
  return orientation === "vertical"
    ? layoutLinearVertical(node, children, path, x, y, w, h, ctx)
    : layoutLinearHorizontal(node, children, path, x, y, w, h, ctx);
}

function layoutLinearVertical(
  _node: UnifiedView, children: UnifiedView[], path: TreePath,
  x: number, y: number, w: number, h: number, ctx: LayoutCtx,
): LaidOutView[] {
  // First measure-pass: figure out total fixed height + sum of weights so
  // we can distribute the slack to weighted children.
  let fixedH = 0;
  let totalWeight = 0;
  const measured: { req: number; weight: number; ch: UnifiedView }[] = [];
  for (const ch of children) {
    const weight = parseFloat(attr(ch, "layout_weight") ?? "0") || 0;
    const heightAttr = attr(ch, "layout_height");
    const req = (heightAttr === "match_parent" || heightAttr === "fill_parent" || heightAttr === "0dp")
      ? 0  // weight-driven; no fixed contribution
      : resolveDimension(heightAttr, h, intrinsicHeight(ch));
    measured.push({ req, weight, ch });
    fixedH  += req;
    totalWeight += weight;
  }
  const slack = Math.max(0, h - fixedH);

  // Layout pass: place top-to-bottom.
  const out: LaidOutView[] = [];
  let cursor = y;
  for (let i = 0; i < measured.length; i++) {
    const { req, weight, ch } = measured[i];
    const allotH = totalWeight > 0 && weight > 0
      ? req + slack * (weight / totalWeight)
      : req;
    // Apply layout_gravity for horizontal alignment within the row.
    const childW = resolveDimension(attr(ch, "layout_width"), w, intrinsicWidth(ch));
    const childX = horizontalGravityOffset(ch, w, childW) + x;
    out.push(
      layoutNodeWithSize(ch, [...path, i], childX, cursor, childW, allotH, ctx),
    );
    cursor += allotH;
  }
  return out;
}

function layoutLinearHorizontal(
  _node: UnifiedView, children: UnifiedView[], path: TreePath,
  x: number, y: number, w: number, h: number, ctx: LayoutCtx,
): LaidOutView[] {
  let fixedW = 0;
  let totalWeight = 0;
  const measured: { req: number; weight: number; ch: UnifiedView }[] = [];
  for (const ch of children) {
    const weight = parseFloat(attr(ch, "layout_weight") ?? "0") || 0;
    const widthAttr = attr(ch, "layout_width");
    const req = (widthAttr === "match_parent" || widthAttr === "fill_parent" || widthAttr === "0dp")
      ? 0
      : resolveDimension(widthAttr, w, intrinsicWidth(ch));
    measured.push({ req, weight, ch });
    fixedW  += req;
    totalWeight += weight;
  }
  const slack = Math.max(0, w - fixedW);

  const out: LaidOutView[] = [];
  let cursor = x;
  for (let i = 0; i < measured.length; i++) {
    const { req, weight, ch } = measured[i];
    const allotW = totalWeight > 0 && weight > 0
      ? req + slack * (weight / totalWeight)
      : req;
    const childH = resolveDimension(attr(ch, "layout_height"), h, intrinsicHeight(ch));
    const childY = verticalGravityOffset(ch, h, childH) + y;
    out.push(
      layoutNodeWithSize(ch, [...path, i], cursor, childY, allotW, childH, ctx),
    );
    cursor += allotW;
  }
  return out;
}

function layoutFrame(
  node: UnifiedView, children: UnifiedView[], path: TreePath,
  x: number, y: number, w: number, h: number, ctx: LayoutCtx,
): LaidOutView[] {
  // FrameLayout stacks children at the parent's gravity-resolved corner.
  const align = gravityToFlexParent(attr(node, "gravity"));
  const out: LaidOutView[] = [];
  for (let i = 0; i < children.length; i++) {
    const ch = children[i];
    const childW = resolveDimension(attr(ch, "layout_width"),  w, intrinsicWidth(ch));
    const childH = resolveDimension(attr(ch, "layout_height"), h, intrinsicHeight(ch));
    // Per-child layout_gravity overrides parent gravity.
    const cga = layoutGravityToFlexChild(attr(ch, "layout_gravity"));
    const halign = cga.alignSelf ?? align.alignItems;
    const valign = cga.alignSelf ?? align.alignItems;
    const childX = positionForAlign(halign === "flex-end" ? "end" : halign === "center" ? "center" : "start",
      x, w, childW);
    const childY = positionForAlign(valign === "flex-end" ? "end" : valign === "center" ? "center" : "start",
      y, h, childH);
    out.push(layoutNodeWithSize(ch, [...path, i], childX, childY, childW, childH, ctx));
  }
  return out;
}

function layoutGrid(
  node: UnifiedView, children: UnifiedView[], path: TreePath,
  x: number, y: number, w: number, h: number, ctx: LayoutCtx,
): LaidOutView[] {
  const cols = Math.max(1, parseInt(attr(node, "columnCount") ?? "2", 10) || 2);
  const cellW = w / cols;
  const out: LaidOutView[] = [];
  for (let i = 0; i < children.length; i++) {
    const row = Math.floor(i / cols);
    const col = i % cols;
    // Cell height: each child's intrinsic. We don't try to align rows
    // (Android's GridLayout does row-baseline alignment; we don't).
    const ch = children[i];
    const childH = resolveDimension(attr(ch, "layout_height"), h, intrinsicHeight(ch));
    out.push(layoutNodeWithSize(ch, [...path, i],
      x + col * cellW, y + row * (childH + 4),
      cellW, childH, ctx,
    ));
  }
  return out;
}

function layoutListRepeats(
  node: UnifiedView, path: TreePath,
  x: number, y: number, w: number, h: number,
  ctx: LayoutCtx, mode: "vertical" | "grid",
): LaidOutView[] {
  const template = node.itemTemplate;
  const cols = mode === "grid" ? 2 : 1;
  const itemCount = mode === "grid" ? 6 : 3;

  // No template — synthesize plain stub rows with reasonable heights.
  if (!template) {
    const rowH = 48;
    const out: LaidOutView[] = [];
    for (let i = 0; i < itemCount; i++) {
      const row = Math.floor(i / cols);
      const col = i % cols;
      const cellW = w / cols;
      // Synthesize a minimal placeholder UnifiedView so paint can branch
      // on a known stub-tag — we use the host's path + i so selection
      // round-trips back to the host.
      const stub: UnifiedView = {
        source: { kind: "synthetic" },
        kind: { kind: "other", tag: "_pap_list_stub" },
        tag: "_pap_list_stub",
        id: null,
        attrs: [{ name: "_label", value: `Item ${i + 1}`, origin: { kind: "static" } }],
        children: [],
        clickHandler: null, navigation: null, dynamicModifications: [],
        itemTemplate: null, drawables: {},
      };
      out.push({
        node: stub,
        path: [...path, i],
        x: x + col * cellW,
        y: y + row * rowH,
        w: cellW,
        h: rowH,
        children: [],
        intrinsic: { w: cellW, h: rowH },
      });
    }
    return out;
  }

  // Template present — measure once at full available width, then repeat.
  const cellW = w / cols;
  const probe = layoutNodeWithSize(template, [...path, 0], 0, 0, cellW, h, ctx);
  const rowH = Math.max(probe.h, 32);
  const out: LaidOutView[] = [];
  for (let i = 0; i < itemCount; i++) {
    const row = Math.floor(i / cols);
    const col = i % cols;
    const placed = layoutNodeWithSize(
      template, [...path, i],
      x + col * cellW, y + row * rowH,
      cellW, rowH, ctx,
    );
    // Tag the rooted laid-out view (and recursively its descendants) with
    // the row index so paint can substitute per-row text.
    tagWithRowIndex(placed, i);
    out.push(placed);
  }
  return out;
}

/** Recursively annotate a laid-out subtree with `rowIndex`. Mutates in
 *  place — cheap (no extra allocation) and avoids piping the index
 *  through every layoutNode call. */
function tagWithRowIndex(v: LaidOutView, idx: number): void {
  v.rowIndex = idx;
  for (const c of v.children) tagWithRowIndex(c, idx);
}

// ── Helpers ──────────────────────────────────────────────────────────────

function layoutNodeWithSize(
  node: UnifiedView, path: TreePath,
  x: number, y: number, w: number, h: number, ctx: LayoutCtx,
): LaidOutView {
  // Re-enter layoutNode but with parent extents fixed to the box we just
  // chose for this child. Keeps the recursive logic in one place.
  return layoutNode(node, path, x, y, w, h, ctx);
}

/** Resolve a `layout_*` dimension string against the parent's available
 *  space and the view's intrinsic size. Returns pixels. */
function resolveDimension(
  v: string | undefined,
  parentExtent: number,
  intrinsic: number,
): number {
  if (v === undefined) return intrinsic;
  const t = v.trim();
  if (t === "match_parent" || t === "fill_parent" || t === "-1") {
    return Number.isFinite(parentExtent) ? parentExtent : intrinsic;
  }
  if (t === "wrap_content" || t === "-2") return intrinsic;
  const n = dpToNumber(t);
  return n !== undefined ? n : intrinsic;
}

/** Heuristic intrinsic widths per view kind. Designed to look plausible at
 *  a 360×640 phone preview; not Android's actual measure logic. */
function intrinsicWidth(node: UnifiedView): number {
  switch (node.kind.kind) {
    case "text":          return Math.min(280, 8 * (attr(node, "text")?.length ?? 6) + 16);
    case "editText":      return 200;
    case "button":        return Math.max(96, 10 * (attr(node, "text")?.length ?? 6) + 32);
    case "imageButton":
    case "image":         return 48;
    case "switch":
    case "checkBox":
    case "radioButton":   return Math.max(56, 12 + 8 * (attr(node, "text")?.length ?? 0));
    case "seekBar":
    case "progressBar":   return 200;
    case "spinner":       return 160;
    case "toolbar":
    case "appBar":        return 360;
    default:              return 360;
  }
}

function intrinsicHeight(node: UnifiedView): number {
  switch (node.kind.kind) {
    case "text":          return 20;
    case "editText":      return 36;
    case "button":        return 40;
    case "imageButton":   return 48;
    case "image":         return 48;
    case "switch":
    case "checkBox":
    case "radioButton":   return 28;
    case "seekBar":       return 24;
    case "progressBar":   return 8;
    case "spinner":       return 36;
    case "toolbar":
    case "appBar":        return 56;
    case "bottomNav":     return 56;
    case "tabLayout":     return 48;
    default:              return 0;
  }
}

function horizontalGravityOffset(child: UnifiedView, parentW: number, childW: number): number {
  const grav = attr(child, "layout_gravity") ?? "";
  const tokens = grav.toLowerCase().split("|").map((s) => s.trim());
  if (tokens.includes("center_horizontal") || tokens.includes("center")) {
    return (parentW - childW) / 2;
  }
  if (tokens.includes("right") || tokens.includes("end")) {
    return parentW - childW;
  }
  return 0;
}

function verticalGravityOffset(child: UnifiedView, parentH: number, childH: number): number {
  const grav = attr(child, "layout_gravity") ?? "";
  const tokens = grav.toLowerCase().split("|").map((s) => s.trim());
  if (tokens.includes("center_vertical") || tokens.includes("center")) {
    return (parentH - childH) / 2;
  }
  if (tokens.includes("bottom")) {
    return parentH - childH;
  }
  return 0;
}

function positionForAlign(
  align: "start" | "center" | "end",
  origin: number, extent: number, childExtent: number,
): number {
  switch (align) {
    case "center": return origin + (extent - childExtent) / 2;
    case "end":    return origin + extent - childExtent;
    default:       return origin;
  }
}

function parsePx(v: string | undefined): number {
  if (!v) return 0;
  const n = parseFloat(v);
  return isNaN(n) ? 0 : n;
}

/** When a list-host view has a template, callers want to render the template
 *  rather than the (usually empty) static children. For non-list views this
 *  passes through unchanged. */
function listChildrenWithTemplate(node: UnifiedView): UnifiedView[] {
  // Layout only uses children, so nothing to override here — the list-host
  // dispatch (`layoutListRepeats`) consults `node.itemTemplate` directly.
  return node.children;
}

// Re-export the theme helper so paint.ts can resolve `?attr/...` against
// the same theme without duplicating the import.
export { resolveThemeRef, androidColorToCss };

// Suppress "imported but never used" — these are part of attrs.ts's
// public surface and used by paint.ts.
void dpToPx;
