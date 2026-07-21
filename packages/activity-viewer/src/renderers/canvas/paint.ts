/**
 * Canvas paint pass — walks the laid-out tree depth-first and draws every
 * view with the closest 2D-context primitive that approximates its
 * appearance.
 *
 * Where R1 (HTML/CSS) leans on the browser's box model, R2 owns every
 * pixel. The trade-off: more code per view kind, but no surprises from
 * CSS quirks, exact control of text metrics and the ability to layer
 * "click target" overlays without disturbing layout.
 *
 * For text rendering we use the canvas's default measureText — close
 * enough for a preview. For drawables and inline colors we go through the
 * same `androidColorToCss` helper R1 uses, so the color palette stays
 * consistent across renderers.
 */

import type { Theme } from "../../types";
import {
  attr, attrResolved, androidColorToCss, resolveThemeRef,
} from "../html/attrs";
import type { LaidOutView } from "./layout";
import { paintDrawableBackground } from "./drawables";

export interface PaintOptions {
  theme?: Theme;
  selectedPath?: number[] | null;
  /** Devicepixelratio adjustment for crisp rendering on hi-dpi screens. */
  dpr: number;
  /** Click-through mode — handler/nav overlays paint solid (instead of
   *  dashed) so live views read as "tappable". */
  interactive?: boolean;
}

/** Clear and paint the entire screen rect. */
export function paintScreen(
  ctx: CanvasRenderingContext2D,
  root: LaidOutView,
  width: number,
  height: number,
  opts: PaintOptions,
): void {
  // Surface background defaults to the theme's windowBackground.
  const surfaceBg = opts.theme
    ? androidColorToCss(resolveThemeRef("?attr/windowBackground", opts.theme)) ?? "#ffffff"
    : "#ffffff";
  ctx.fillStyle = surfaceBg;
  ctx.fillRect(0, 0, width, height);

  paintNode(ctx, root, opts);

  // Selection highlight goes on top of everything so it's never occluded.
  if (opts.selectedPath) {
    const sel = findByPath(root, opts.selectedPath);
    if (sel) {
      ctx.save();
      ctx.strokeStyle = "#007acc";
      ctx.lineWidth = 2;
      ctx.strokeRect(sel.x + 1, sel.y + 1, sel.w - 2, sel.h - 2);
      ctx.restore();
    }
  }
}

// ── Per-node dispatch ────────────────────────────────────────────────────

function paintNode(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  opts: PaintOptions,
): void {
  // Background first — every view (or container) can have one. This also
  // doubles as the "you can see the box" baseline for empty containers.
  paintBackground(ctx, v, opts);

  switch (v.node.kind.kind) {
    case "text":          paintText(ctx, v, opts); break;
    case "editText":      paintEditText(ctx, v, opts); break;
    case "button":        paintButton(ctx, v, opts); break;
    case "imageButton":   paintImageButton(ctx, v); break;
    case "image":         paintImage(ctx, v); break;
    case "switch":
    case "checkBox":
    case "radioButton":   paintToggle(ctx, v, v.node.kind.kind); break;
    case "seekBar":       paintSeekBar(ctx, v); break;
    case "progressBar":   paintProgress(ctx, v, opts); break;
    case "spinner":       paintSpinner(ctx, v); break;
    case "toolbar":
    case "appBar":        paintToolbar(ctx, v, opts); break;
    case "bottomNav":     paintBottomNav(ctx, v); break;
    case "tabLayout":     paintTabLayout(ctx, v); break;
    case "webView":       paintWebViewStub(ctx, v); break;
    case "fragment":      paintFragmentStub(ctx, v, safeClassName(v.node.kind, v.node.tag)); break;
    case "viewStub":      paintGenericStub(ctx, v, "ViewStub"); break;
    case "custom":
      // Custom views with children are typically just LinearLayouts in
      // disguise — let the children paint themselves.
      if (v.children.length === 0) {
        paintCustomStub(ctx, v, safeClassName(v.node.kind, v.node.tag));
      }
      break;
    case "recyclerView":
    case "listView":
    case "gridView":
      // List items get rendered through their template repeats (each
      // becomes a child); nothing to do at the host level beyond the
      // background.
      break;
    default:
      // Containers (Linear/Frame/Relative/Constraint/Grid/Scroll/Other) — paint
      // happens through children.
      break;
  }

  // Synthetic list stub (no template recovered) — special-cased here so
  // both list kinds share the rendering.
  if (v.node.tag === "_pap_list_stub") {
    paintListStubRow(ctx, v);
  }

  // Recurse before drawing handler/navigation overlays so overlays sit on
  // top of children.
  for (const child of v.children) {
    paintNode(ctx, child, opts);
  }

  paintHandlerOverlay(ctx, v, opts.interactive ?? false);
}

// ── Background + text helpers ────────────────────────────────────────────

function paintBackground(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  opts: PaintOptions,
): void {
  // Prefer the structured drawable when the resolver produced one.
  const drawable = v.node.drawables?.["android:background"];
  if (drawable) {
    paintDrawableBackground(ctx, drawable, v.x, v.y, v.w, v.h);
    return;
  }
  const raw = attr(v.node, "background");
  if (!raw) return;
  const resolved = resolveThemeRef(raw, opts.theme);
  if (resolved.startsWith("#")) {
    ctx.fillStyle = androidColorToCss(resolved) ?? resolved;
    ctx.fillRect(v.x, v.y, v.w, v.h);
  } else if (resolved.startsWith("@") || resolved.startsWith("res/")) {
    paintHatch(ctx, v.x, v.y, v.w, v.h);
  }
}

function paintText(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  opts: PaintOptions,
): void {
  let text = attr(v.node, "text") ?? attr(v.node, "hint") ?? "";

  // Per-row substitution for list-template repeats (mirrors HtmlRenderer):
  // when this TextView has a non-literal `setText` binding, show
  // `{field} #N` so each row reads distinctly instead of identical
  // placeholder text.
  if (v.rowIndex !== undefined) {
    // Defensive: an old IR may not carry `dynamicModifications`.
    const mods = v.node.dynamicModifications ?? [];
    const dyn = mods.find(
      (m) => m.setter === "setText" && !m.literal,
    );
    if (dyn) {
      const field = dyn.value.startsWith("from ") ? dyn.value.slice(5) : "value";
      text = `${field} #${v.rowIndex + 1}`;
    }
  }

  if (!text) return;

  const colorRaw = attrResolved(v.node, "textColor", opts.theme);
  const color = androidColorToCss(colorRaw) ?? "#222";
  const sizeStr = attrResolved(v.node, "textSize", opts.theme);
  const px = parsePxLike(sizeStr) ?? 14;
  const style = (attr(v.node, "textStyle") ?? "").toLowerCase();
  const weight = style.includes("bold") ? "bold" : "normal";
  const italic = style.includes("italic") ? "italic" : "normal";

  ctx.fillStyle = color;
  ctx.font = `${italic} ${weight} ${px}px -apple-system, "Segoe UI", Roboto, sans-serif`;
  ctx.textBaseline = "middle";

  const { fillText } = clipped(ctx, v);
  fillText(text, v.x + 4, v.y + v.h / 2);
}

function paintEditText(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  _opts: PaintOptions,
): void {
  // Field background.
  ctx.fillStyle = "#fff";
  ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "#999";
  ctx.lineWidth = 1;
  ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);

  const text = attr(v.node, "text") ?? "";
  const hint = attr(v.node, "hint") ?? "";
  ctx.font = "14px -apple-system, sans-serif";
  ctx.textBaseline = "middle";
  if (text) {
    ctx.fillStyle = "#222";
    const { fillText } = clipped(ctx, v);
    fillText(text, v.x + 8, v.y + v.h / 2);
  } else if (hint) {
    ctx.fillStyle = "#888";
    const { fillText } = clipped(ctx, v);
    fillText(hint, v.x + 8, v.y + v.h / 2);
  }
}

function paintButton(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  opts: PaintOptions,
): void {
  const themePrimary = androidColorToCss(resolveThemeRef("?attr/colorPrimary", opts.theme)) ?? "#6750a4";
  const onPrimary    = androidColorToCss(resolveThemeRef("?attr/colorOnPrimary", opts.theme)) ?? "#fff";

  // Use background attr if it's a color, otherwise theme primary.
  let fill = themePrimary;
  const bg = attr(v.node, "background");
  if (bg && bg.startsWith("#")) {
    fill = androidColorToCss(bg) ?? themePrimary;
  }

  ctx.fillStyle = fill;
  fillRoundedRect(ctx, v.x, v.y, v.w, v.h, 20);

  const text = attr(v.node, "text") ?? "Button";
  ctx.fillStyle = onPrimary;
  ctx.font = "500 14px -apple-system, sans-serif";
  ctx.textBaseline = "middle";
  ctx.textAlign = "center";
  const { fillText } = clipped(ctx, v);
  fillText(text, v.x + v.w / 2, v.y + v.h / 2);
  ctx.textAlign = "start";
}

function paintImageButton(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  ctx.strokeStyle = "#999";
  ctx.lineWidth = 1;
  ctx.setLineDash([3, 3]);
  ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
  ctx.setLineDash([]);
  ctx.fillStyle = "#888";
  ctx.font = "10px monospace";
  ctx.textAlign = "center"; ctx.textBaseline = "middle";
  ctx.fillText("img", v.x + v.w / 2, v.y + v.h / 2);
  ctx.textAlign = "start";
}

function paintImage(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  // Prefer the structured drawable from `android:src` / `srcCompat` /
  // `app:srcCompat`. Vectors paint as SVG, shapes as gradients/borders.
  const drawable =
    v.node.drawables?.["android:src"]
    ?? v.node.drawables?.["android:srcCompat"]
    ?? v.node.drawables?.["app:srcCompat"];
  if (drawable) {
    paintDrawableBackground(ctx, drawable, v.x, v.y, v.w, v.h);
    return;
  }

  // Hatched placeholder + filename caption for unresolved sources.
  paintHatch(ctx, v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "#bbb";
  ctx.lineWidth = 1;
  ctx.setLineDash([2, 2]);
  ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
  ctx.setLineDash([]);
  const src = attr(v.node, "src") ?? attr(v.node, "srcCompat") ?? "";
  const label = src.split("/").pop()?.split(".")[0] || "img";
  ctx.fillStyle = "#666";
  ctx.font = "9px monospace";
  ctx.textAlign = "center"; ctx.textBaseline = "middle";
  const { fillText } = clipped(ctx, v);
  fillText(label, v.x + v.w / 2, v.y + v.h / 2);
  ctx.textAlign = "start";
}

function paintToggle(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  type: "switch" | "checkBox" | "radioButton",
): void {
  const checked = (attr(v.node, "checked") ?? "false").toLowerCase() === "true";
  const text = attr(v.node, "text") ?? "";

  // Indicator on the left.
  const cx = v.x + 8;
  const cy = v.y + v.h / 2;
  if (type === "checkBox") {
    ctx.strokeStyle = "#666"; ctx.lineWidth = 1.5;
    ctx.strokeRect(cx - 6, cy - 6, 12, 12);
    if (checked) {
      ctx.beginPath();
      ctx.moveTo(cx - 4, cy);
      ctx.lineTo(cx - 1, cy + 3);
      ctx.lineTo(cx + 4, cy - 3);
      ctx.stroke();
    }
  } else if (type === "radioButton") {
    ctx.strokeStyle = "#666"; ctx.lineWidth = 1.5;
    ctx.beginPath(); ctx.arc(cx, cy, 7, 0, Math.PI * 2); ctx.stroke();
    if (checked) {
      ctx.fillStyle = "#666";
      ctx.beginPath(); ctx.arc(cx, cy, 3.5, 0, Math.PI * 2); ctx.fill();
    }
  } else {
    // Switch — pill track with thumb.
    ctx.fillStyle = checked ? "#6750a4" : "#bbb";
    fillRoundedRect(ctx, cx - 10, cy - 6, 24, 12, 6);
    ctx.fillStyle = "#fff";
    const thumbX = checked ? cx + 8 : cx - 6;
    ctx.beginPath(); ctx.arc(thumbX, cy, 5, 0, Math.PI * 2); ctx.fill();
  }

  if (text) {
    ctx.fillStyle = "#222";
    ctx.font = "14px -apple-system, sans-serif";
    ctx.textBaseline = "middle";
    const { fillText } = clipped(ctx, v);
    fillText(text, v.x + (type === "switch" ? 28 : 24), cy);
  }
}

function paintSeekBar(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  const max = parseInt(attr(v.node, "max") ?? "100", 10) || 100;
  const progress = parseInt(attr(v.node, "progress") ?? "0", 10) || 0;
  const ratio = Math.max(0, Math.min(1, progress / max));
  const trackY = v.y + v.h / 2;
  ctx.strokeStyle = "#ccc"; ctx.lineWidth = 2;
  ctx.beginPath(); ctx.moveTo(v.x + 6, trackY); ctx.lineTo(v.x + v.w - 6, trackY); ctx.stroke();
  ctx.strokeStyle = "#6750a4";
  ctx.beginPath();
  ctx.moveTo(v.x + 6, trackY);
  ctx.lineTo(v.x + 6 + (v.w - 12) * ratio, trackY);
  ctx.stroke();
  // Thumb.
  ctx.fillStyle = "#6750a4";
  ctx.beginPath(); ctx.arc(v.x + 6 + (v.w - 12) * ratio, trackY, 6, 0, Math.PI * 2); ctx.fill();
}

function paintProgress(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  opts: PaintOptions,
): void {
  const indeterminate = (attr(v.node, "indeterminate") ?? "false").toLowerCase() === "true";
  const accent = androidColorToCss(resolveThemeRef("?attr/colorAccent", opts.theme)) ?? "#6750a4";
  ctx.fillStyle = "#ccc";
  ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.fillStyle = accent;
  if (indeterminate) {
    ctx.fillRect(v.x, v.y, v.w * 0.3, v.h);
  } else {
    const max = parseInt(attr(v.node, "max") ?? "100", 10) || 100;
    const value = parseInt(attr(v.node, "progress") ?? "0", 10) || 0;
    ctx.fillRect(v.x, v.y, v.w * (value / max), v.h);
  }
}

function paintSpinner(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  ctx.fillStyle = "#fff"; ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "#999"; ctx.lineWidth = 1;
  ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
  ctx.fillStyle = "#222"; ctx.font = "14px -apple-system, sans-serif";
  ctx.textBaseline = "middle";
  const { fillText } = clipped(ctx, v);
  fillText("(spinner)", v.x + 8, v.y + v.h / 2);
  // Caret.
  ctx.beginPath();
  ctx.moveTo(v.x + v.w - 14, v.y + v.h / 2 - 3);
  ctx.lineTo(v.x + v.w - 8, v.y + v.h / 2 - 3);
  ctx.lineTo(v.x + v.w - 11, v.y + v.h / 2 + 2);
  ctx.closePath(); ctx.fillStyle = "#666"; ctx.fill();
}

function paintToolbar(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  opts: PaintOptions,
): void {
  const themePrimary = androidColorToCss(resolveThemeRef("?attr/colorPrimary", opts.theme)) ?? "#6750a4";
  const onPrimary    = androidColorToCss(resolveThemeRef("?attr/colorOnPrimary", opts.theme)) ?? "#fff";
  ctx.fillStyle = themePrimary;
  ctx.fillRect(v.x, v.y, v.w, v.h);
  const title = attr(v.node, "title") ?? "";
  if (title) {
    ctx.fillStyle = onPrimary;
    ctx.font = "500 18px -apple-system, sans-serif";
    ctx.textBaseline = "middle";
    const { fillText } = clipped(ctx, v);
    fillText(title, v.x + 16, v.y + v.h / 2);
  }
}

function paintBottomNav(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  ctx.fillStyle = "#fff"; ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "#ddd"; ctx.lineWidth = 1;
  ctx.beginPath(); ctx.moveTo(v.x, v.y + 0.5); ctx.lineTo(v.x + v.w, v.y + 0.5); ctx.stroke();
  if (v.children.length === 0) {
    const labels = ["Home", "Items", "Profile"];
    const itemW = v.w / labels.length;
    for (let i = 0; i < labels.length; i++) {
      const cx = v.x + itemW * (i + 0.5);
      // Icon dot.
      ctx.fillStyle = "#999";
      fillRoundedRect(ctx, cx - 10, v.y + 12, 20, 20, 4);
      ctx.fillStyle = "#222";
      ctx.font = "12px -apple-system, sans-serif";
      ctx.textBaseline = "alphabetic"; ctx.textAlign = "center";
      ctx.fillText(labels[i], cx, v.y + v.h - 8);
    }
    ctx.textAlign = "start";
  }
}

function paintTabLayout(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  const labels = v.children.length > 0
    ? null  // children paint themselves
    : ["Tab 1", "Tab 2", "Tab 3"];
  if (!labels) {
    // Underline indicator on bottom.
    ctx.strokeStyle = "#6750a4"; ctx.lineWidth = 2;
    ctx.beginPath();
    ctx.moveTo(v.x, v.y + v.h - 1); ctx.lineTo(v.x + v.w, v.y + v.h - 1);
    ctx.stroke();
    return;
  }
  const itemW = v.w / labels.length;
  for (let i = 0; i < labels.length; i++) {
    const cx = v.x + itemW * (i + 0.5);
    ctx.fillStyle = "#222";
    ctx.font = i === 0 ? "600 14px -apple-system, sans-serif" : "14px -apple-system, sans-serif";
    ctx.textBaseline = "middle"; ctx.textAlign = "center";
    ctx.fillText(labels[i], cx, v.y + v.h / 2);
    if (i === 0) {
      ctx.strokeStyle = "#6750a4"; ctx.lineWidth = 2;
      ctx.beginPath();
      ctx.moveTo(v.x + i * itemW + 16, v.y + v.h - 1);
      ctx.lineTo(v.x + (i + 1) * itemW - 16, v.y + v.h - 1);
      ctx.stroke();
    }
  }
  ctx.textAlign = "start";
}

function paintWebViewStub(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  ctx.fillStyle = "#222"; ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.fillStyle = "#0f0"; ctx.font = "12px monospace";
  ctx.textBaseline = "middle"; ctx.textAlign = "center";
  ctx.fillText("<WebView>", v.x + v.w / 2, v.y + v.h / 2);
  ctx.textAlign = "start";
}

/** Pull a usable class-name string out of a `kind` discriminant that
 *  expects one. Mirrors the same helper in the HTML renderer — a stale
 *  IR or partial fixture might leave the field undefined; falling back
 *  to the node's tag is friendlier than a runtime crash. */
function safeClassName(kind: { className?: unknown }, fallbackTag: string): string {
  const cn = kind.className;
  if (typeof cn === "string" && cn.length > 0) return cn;
  return fallbackTag || "(unknown)";
}

/** Last dotted segment of a FQN, with a non-string guard so we never
 *  blow up with `undefined.split` when something upstream went wrong. */
function shortClass(fqn: string): string {
  if (typeof fqn !== "string") return "(unknown)";
  const dot = fqn.lastIndexOf(".");
  return dot >= 0 ? fqn.slice(dot + 1) : fqn;
}

function paintFragmentStub(ctx: CanvasRenderingContext2D, v: LaidOutView, className: string): void {
  ctx.fillStyle = "rgba(150,90,200,0.05)";
  ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "rgba(150,90,200,0.5)"; ctx.lineWidth = 1;
  ctx.setLineDash([3, 3]);
  ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
  ctx.setLineDash([]);
  ctx.fillStyle = "#666"; ctx.font = "12px -apple-system, sans-serif";
  ctx.textBaseline = "top";
  const short = shortClass(className);
  const { fillText } = clipped(ctx, v);
  fillText(`Fragment: ${short}`, v.x + 12, v.y + 12);
}

function paintGenericStub(ctx: CanvasRenderingContext2D, v: LaidOutView, label: string): void {
  ctx.fillStyle = "rgba(0,0,0,0.03)"; ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "#999"; ctx.lineWidth = 1;
  ctx.setLineDash([3, 3]);
  ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
  ctx.setLineDash([]);
  ctx.fillStyle = "#666"; ctx.font = "12px -apple-system, sans-serif";
  ctx.textBaseline = "top";
  const { fillText } = clipped(ctx, v);
  fillText(label, v.x + 8, v.y + 8);
}

function paintCustomStub(ctx: CanvasRenderingContext2D, v: LaidOutView, className: string): void {
  ctx.fillStyle = "rgba(255,140,0,0.05)";
  ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "rgba(255,140,0,0.5)"; ctx.lineWidth = 1;
  ctx.setLineDash([3, 3]);
  ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
  ctx.setLineDash([]);
  const short = shortClass(className);
  ctx.fillStyle = "#666"; ctx.font = "11px -apple-system, sans-serif";
  ctx.textBaseline = "top";
  const { fillText } = clipped(ctx, v);
  fillText(short, v.x + 8, v.y + 8);
}

function paintListStubRow(ctx: CanvasRenderingContext2D, v: LaidOutView): void {
  ctx.fillStyle = "rgba(0,122,204,0.04)";
  ctx.fillRect(v.x, v.y, v.w, v.h);
  ctx.strokeStyle = "rgba(0,0,0,0.05)"; ctx.lineWidth = 1;
  ctx.beginPath();
  ctx.moveTo(v.x, v.y + 0.5); ctx.lineTo(v.x + v.w, v.y + 0.5);
  ctx.stroke();
  const label = attr(v.node, "_label") ?? "Item";
  ctx.fillStyle = "#222"; ctx.font = "14px -apple-system, sans-serif";
  ctx.textBaseline = "middle";
  ctx.fillText(label, v.x + 16, v.y + v.h / 2);
}

// ── Handler / nav overlays ────────────────────────────────────────────────

function paintHandlerOverlay(
  ctx: CanvasRenderingContext2D,
  v: LaidOutView,
  interactive: boolean,
): void {
  if (v.node.navigation) {
    ctx.save();
    ctx.strokeStyle = "rgba(0, 122, 204, 0.95)";
    if (interactive) {
      ctx.lineWidth = 2;
    } else {
      ctx.setLineDash([4, 3]);
      ctx.lineWidth = 1.5;
    }
    ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
    ctx.restore();
  } else if (v.node.clickHandler) {
    ctx.save();
    ctx.strokeStyle = "rgba(255, 167, 38, 0.85)";
    if (interactive) {
      ctx.lineWidth = 1.5;
    } else {
      ctx.setLineDash([3, 3]);
      ctx.lineWidth = 1;
    }
    ctx.strokeRect(v.x + 0.5, v.y + 0.5, v.w - 1, v.h - 1);
    ctx.restore();
  }
}

// ── Drawing primitives ────────────────────────────────────────────────────

function fillRoundedRect(
  ctx: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number, r: number,
): void {
  const radius = Math.min(r, w / 2, h / 2);
  ctx.beginPath();
  ctx.moveTo(x + radius, y);
  ctx.arcTo(x + w, y,     x + w, y + h, radius);
  ctx.arcTo(x + w, y + h, x,     y + h, radius);
  ctx.arcTo(x,     y + h, x,     y,     radius);
  ctx.arcTo(x,     y,     x + w, y,     radius);
  ctx.closePath();
  ctx.fill();
}

function paintHatch(
  ctx: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number,
): void {
  ctx.save();
  ctx.beginPath();
  ctx.rect(x, y, w, h);
  ctx.clip();
  ctx.fillStyle = "#f8f8f8";
  ctx.fillRect(x, y, w, h);
  ctx.strokeStyle = "#eee";
  ctx.lineWidth = 1;
  // 45-degree stripes.
  for (let i = -h; i < w; i += 8) {
    ctx.beginPath();
    ctx.moveTo(x + i,     y);
    ctx.lineTo(x + i + h, y + h);
    ctx.stroke();
  }
  ctx.restore();
}

/** Wrap a fillText so it clips to the view's rectangle — saves writing
 *  `ctx.save / clip / restore` around every text call. */
function clipped(ctx: CanvasRenderingContext2D, v: LaidOutView): {
  fillText: (s: string, x: number, y: number) => void;
} {
  return {
    fillText: (s, x, y) => {
      ctx.save();
      ctx.beginPath();
      ctx.rect(v.x, v.y, v.w, v.h);
      ctx.clip();
      ctx.fillText(s, x, y);
      ctx.restore();
    },
  };
}

function parsePxLike(v: string | undefined): number | undefined {
  if (!v) return undefined;
  const m = v.match(/^(-?\d+(?:\.\d+)?)/);
  return m ? parseFloat(m[1]) : undefined;
}

/** Walk a laid-out tree to find the node whose `path` matches `target`. */
function findByPath(root: LaidOutView, target: number[]): LaidOutView | null {
  if (root.path.length === target.length
      && root.path.every((v, i) => v === target[i])) {
    return root;
  }
  for (const c of root.children) {
    const found = findByPath(c, target);
    if (found) return found;
  }
  return null;
}
