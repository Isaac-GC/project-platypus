/**
 * Canvas drawing for structured Drawables. Used by paint.ts to render
 * `android:background` / `android:src` etc. when the IR carries a
 * pre-resolved Drawable.
 *
 * For vector drawables we hold a tiny in-module cache of `<svg>` strings
 * → `HTMLImageElement`s so re-paints don't re-parse the SVG. Cache keyed
 * by SVG content (assumed deduplicated by the Rust side).
 */

import type { Drawable, ShapeDrawable, Gradient } from "../../types";

/** AARRGGBB → CSS rgba string. */
function argb32ToCss(argb: number): string {
  const u = argb >>> 0;
  const a = ((u >> 24) & 0xff) / 255;
  const r = (u >> 16) & 0xff;
  const g = (u >> 8)  & 0xff;
  const b = u         & 0xff;
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

/** SVG-to-image cache. Keys are the SVG payload string itself; values are
 *  pre-decoded `Image` elements ready for `drawImage`. */
const svgImageCache: Map<string, HTMLImageElement> = new Map();

function getSvgImage(svg: string): HTMLImageElement {
  let img = svgImageCache.get(svg);
  if (img) return img;
  img = new Image();
  // Note: data URIs decode synchronously enough for a re-paint cycle to
  // pick them up; the first paint may show empty until decode completes.
  img.src = `data:image/svg+xml;utf8,${encodeURIComponent(svg)
    .replace(/'/g, "%27").replace(/"/g, "%22")}`;
  svgImageCache.set(svg, img);
  return img;
}

/** Paint a Drawable as the background of a rectangle. */
export function paintDrawableBackground(
  ctx: CanvasRenderingContext2D,
  d: Drawable,
  x: number, y: number, w: number, h: number,
): void {
  switch (d.kind) {
    case "color":
      ctx.fillStyle = argb32ToCss(d.rgba);
      ctx.fillRect(x, y, w, h);
      return;

    case "vector": {
      const img = getSvgImage(d.svg);
      // If the image hasn't decoded yet, re-paint when it's ready.
      if (img.complete && img.naturalWidth > 0) {
        ctx.drawImage(img, x, y, w, h);
      } else {
        // Soft "loading" placeholder.
        ctx.fillStyle = "#f8f8f8";
        ctx.fillRect(x, y, w, h);
        img.addEventListener("load", () => {
          // The component re-renders on selection/layout change; we
          // don't have a way to invalidate from here without coupling.
          // The cached image will be ready on the next render.
        }, { once: true });
      }
      return;
    }

    case "shape":
      paintShape(ctx, d, x, y, w, h);
      return;

    case "selector": {
      const def = d.items.find((i) => i.state === "default") ?? d.items[0];
      if (def) paintDrawableBackground(ctx, def.drawable, x, y, w, h);
      return;
    }

    case "layerList": {
      // Paint back-to-front (Android stacks earlier items underneath).
      for (const layer of d.items) {
        const lx = x + layer.insetLeft;
        const ly = y + layer.insetTop;
        const lw = Math.max(0, w - layer.insetLeft - layer.insetRight);
        const lh = Math.max(0, h - layer.insetTop - layer.insetBottom);
        paintDrawableBackground(ctx, layer.drawable, lx, ly, lw, lh);
      }
      return;
    }

    case "ripple":
      if (d.content) paintDrawableBackground(ctx, d.content, x, y, w, h);
      return;

    case "inset": {
      const ix = x + d.insetLeft;
      const iy = y + d.insetTop;
      const iw = Math.max(0, w - d.insetLeft - d.insetRight);
      const ih = Math.max(0, h - d.insetTop - d.insetBottom);
      paintDrawableBackground(ctx, d.drawable, ix, iy, iw, ih);
      return;
    }

    case "bitmap":
    case "ninePatch":
    case "reference":
    case "unknown":
      paintHatchedPlaceholder(ctx, x, y, w, h);
      return;
  }
}

function paintShape(
  ctx: CanvasRenderingContext2D,
  s: ShapeDrawable,
  x: number, y: number, w: number, h: number,
): void {
  // Build the path first — re-used for both fill and stroke so corner
  // radius / oval shape are consistent.
  ctx.save();
  pathForShape(ctx, s, x, y, w, h);

  // Fill: gradient takes priority over solid color (matches Android).
  if (s.gradient) {
    ctx.fillStyle = makeGradient(ctx, s.gradient, x, y, w, h);
    ctx.fill();
  } else if (s.solidColor !== null) {
    ctx.fillStyle = argb32ToCss(s.solidColor);
    ctx.fill();
  } else if (s.shapeKind === "ring") {
    // Ring with no explicit fill — leave hollow.
  }

  // Stroke. Re-build the path because fill consumed it.
  if (s.stroke && s.stroke.width > 0) {
    pathForShape(ctx, s, x, y, w, h);
    ctx.strokeStyle = argb32ToCss(s.stroke.color);
    ctx.lineWidth = s.stroke.width;
    if (s.stroke.dashWidth > 0) {
      ctx.setLineDash([s.stroke.dashWidth, s.stroke.dashGap]);
    }
    ctx.stroke();
  }

  ctx.restore();
}

function pathForShape(
  ctx: CanvasRenderingContext2D,
  s: ShapeDrawable,
  x: number, y: number, w: number, h: number,
): void {
  ctx.beginPath();
  switch (s.shapeKind) {
    case "oval":
      ctx.ellipse(x + w / 2, y + h / 2, w / 2, h / 2, 0, 0, Math.PI * 2);
      break;
    case "ring":
      // Outer + reverse inner — even-odd fill rule would help but we
      // approximate with a stroked circle (explicit width controls
      // inner hole size).
      ctx.ellipse(x + w / 2, y + h / 2, w / 2, h / 2, 0, 0, Math.PI * 2);
      break;
    case "line":
      ctx.moveTo(x, y + h / 2);
      ctx.lineTo(x + w, y + h / 2);
      break;
    case "rectangle": {
      const c = s.corners ?? null;
      if (c && (c.topLeft || c.topRight || c.bottomLeft || c.bottomRight)) {
        roundedRectPath(ctx, x, y, w, h, c.topLeft, c.topRight, c.bottomRight, c.bottomLeft);
      } else {
        ctx.rect(x, y, w, h);
      }
      break;
    }
  }
}

function roundedRectPath(
  ctx: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number,
  tl: number, tr: number, br: number, bl: number,
): void {
  // Clamp radii to the box.
  const cap = Math.min(w, h) / 2;
  tl = Math.min(tl, cap); tr = Math.min(tr, cap);
  br = Math.min(br, cap); bl = Math.min(bl, cap);
  ctx.moveTo(x + tl, y);
  ctx.lineTo(x + w - tr, y);
  ctx.arcTo(x + w, y, x + w, y + tr, tr);
  ctx.lineTo(x + w, y + h - br);
  ctx.arcTo(x + w, y + h, x + w - br, y + h, br);
  ctx.lineTo(x + bl, y + h);
  ctx.arcTo(x, y + h, x, y + h - bl, bl);
  ctx.lineTo(x, y + tl);
  ctx.arcTo(x, y, x + tl, y, tl);
}

function makeGradient(
  ctx: CanvasRenderingContext2D,
  g: Gradient,
  x: number, y: number, w: number, h: number,
): CanvasGradient {
  let grad: CanvasGradient;
  switch (g.gradientKind.kind) {
    case "linear": {
      // Android angle: 0 = left→right, 90 = bottom→top.
      const rad = (g.gradientKind.angleDeg * Math.PI) / 180;
      const cx = x + w / 2, cy = y + h / 2;
      const r = Math.max(w, h);
      grad = ctx.createLinearGradient(
        cx - Math.cos(rad) * r / 2,
        cy + Math.sin(rad) * r / 2,
        cx + Math.cos(rad) * r / 2,
        cy - Math.sin(rad) * r / 2,
      );
      break;
    }
    case "radial": {
      const cx = x + g.gradientKind.centerX * w;
      const cy = y + g.gradientKind.centerY * h;
      grad = ctx.createRadialGradient(cx, cy, 0, cx, cy, g.gradientKind.radius || Math.max(w, h) / 2);
      break;
    }
    case "sweep":
      // Canvas doesn't have native sweep gradients before recent specs;
      // approximate with a conic via radial fallback.
      grad = ctx.createRadialGradient(x + w / 2, y + h / 2, 0, x + w / 2, y + h / 2, Math.max(w, h));
      break;
  }
  grad.addColorStop(0, argb32ToCss(g.startColor));
  if (g.centerColor !== null) {
    grad.addColorStop(0.5, argb32ToCss(g.centerColor));
  }
  grad.addColorStop(1, argb32ToCss(g.endColor));
  return grad;
}

function paintHatchedPlaceholder(
  ctx: CanvasRenderingContext2D,
  x: number, y: number, w: number, h: number,
): void {
  ctx.save();
  ctx.beginPath();
  ctx.rect(x, y, w, h);
  ctx.clip();
  ctx.fillStyle = "#f8f8f8";
  ctx.fillRect(x, y, w, h);
  ctx.strokeStyle = "rgba(0,0,0,0.05)";
  ctx.lineWidth = 1;
  for (let i = -h; i < w; i += 8) {
    ctx.beginPath();
    ctx.moveTo(x + i,     y);
    ctx.lineTo(x + i + h, y + h);
    ctx.stroke();
  }
  ctx.restore();
}
