/**
 * Render structured Drawables to CSS. Used by HtmlRenderer to display
 * `android:background` etc. when the IR carries a pre-resolved Drawable.
 *
 * Coverage mirrors the Rust resolver's variant set:
 *   - color   → `backgroundColor`
 *   - vector  → SVG-data-URL background-image
 *   - shape   → CSS gradients + border + border-radius (rectangle / oval)
 *   - selector → renders its `default` item (other states need runtime input)
 *   - layerList → uses the topmost item (CSS doesn't easily stack drawable layers)
 *   - ripple → renders the ripple's content layer (the ripple itself needs animation)
 *   - inset → renders the wrapped drawable, padded
 *   - bitmap / 9-patch / reference / unknown → diagonal-stripe placeholder
 */

import type { Drawable, Gradient } from "../../types";

/** Convert a 32-bit packed AARRGGBB color to a CSS `#rrggbbaa` literal. */
function argb32ToCss(argb: number): string {
  // JS bitwise ops are 32-bit signed; we want unsigned for hex formatting.
  const u = argb >>> 0;
  const a = (u >> 24) & 0xff;
  const r = (u >> 16) & 0xff;
  const g = (u >> 8)  & 0xff;
  const b = u         & 0xff;
  const hh = (n: number) => n.toString(16).padStart(2, "0");
  return `#${hh(r)}${hh(g)}${hh(b)}${hh(a)}`;
}

const HATCH_BG =
  "repeating-linear-gradient(45deg, rgba(0,0,0,0.05) 0 4px, transparent 4px 8px)";

/** Translate a Drawable to a `React.CSSProperties` fragment that paints
 *  it as an element's background. Returns `{}` if we can't render it
 *  (caller should fall back to its default treatment). */
export function drawableToBackgroundStyle(d: Drawable): React.CSSProperties {
  switch (d.kind) {
    case "color":
      return { backgroundColor: argb32ToCss(d.rgba) };

    case "vector": {
      // Embed the SVG as a data URL — works in any browser, no extra
      // fetch. The renderer doesn't size based on `intrinsicWidthDp`
      // because the surrounding view's CSS already controls width/height.
      const encoded = encodeURIComponent(d.svg)
        .replace(/'/g, "%27")
        .replace(/"/g, "%22");
      return {
        backgroundImage: `url("data:image/svg+xml;utf8,${encoded}")`,
        backgroundRepeat: "no-repeat",
        backgroundPosition: "center",
        backgroundSize: "contain",
      };
    }

    case "shape":
      return shapeToCss(d);

    case "selector": {
      const def = d.items.find((i) => i.state === "default")
        ?? d.items[0];
      return def ? drawableToBackgroundStyle(def.drawable) : {};
    }

    case "layerList": {
      // Stack the layers via comma-separated background images. Earlier
      // layers paint on top so we reverse the order (CSS background paints
      // first-listed on top of last-listed).
      // For simplicity we only layer the top item — multi-layer requires
      // multiple background-images stacked in one declaration which only
      // works cleanly when they're all images, not solid colors.
      const top = d.items[d.items.length - 1];
      return top ? drawableToBackgroundStyle(top.drawable) : {};
    }

    case "ripple":
      // Render the ripple's content layer (most ripples wrap a shape or
      // color). The ripple effect itself needs runtime touch input —
      // we surface a faint pulse via box-shadow elsewhere if needed.
      return d.content ? drawableToBackgroundStyle(d.content) : {};

    case "inset":
      return drawableToBackgroundStyle(d.drawable);

    case "bitmap":
    case "ninePatch":
    case "reference":
    case "unknown":
      // Hatched placeholder so the box is visibly "has a background" but
      // we don't try to fake bitmap rendering. (A future pass could
      // expose APK bytes via the API.)
      return { background: HATCH_BG };
  }
}

/** Render a Drawable as standalone visual content (e.g. for an ImageView's
 *  `src`). Returns CSS `background-*` properties suitable for the renderer
 *  to spread onto the image element. */
export function drawableToImageStyle(d: Drawable): React.CSSProperties {
  // For images, vector + bitmap variants want `contain`; everything else
  // falls through to background-style behaviour.
  const base = drawableToBackgroundStyle(d);
  if (d.kind === "vector") return base;
  if (d.kind === "bitmap" || d.kind === "ninePatch") {
    // We don't have bitmap bytes available client-side yet — placeholder.
    return { background: HATCH_BG };
  }
  return base;
}

/** Translate a `<shape>` drawable to CSS. Handles solid + gradient fills,
 *  stroke, corner radii. Oval shapes use `border-radius: 50%`. */
function shapeToCss(s: Extract<Drawable, { kind: "shape" }>): React.CSSProperties {
  const out: React.CSSProperties = {};

  // Fill: gradient takes priority over solid color (matches Android).
  if (s.gradient) {
    out.backgroundImage = gradientToCss(s.gradient);
  } else if (s.solidColor !== null) {
    out.backgroundColor = argb32ToCss(s.solidColor);
  }

  // Stroke → border. Dashed if dashWidth > 0.
  if (s.stroke && s.stroke.width > 0) {
    const styleKw = s.stroke.dashWidth > 0 ? "dashed" : "solid";
    out.border = `${s.stroke.width}px ${styleKw} ${argb32ToCss(s.stroke.color)}`;
  }

  // Corner radii.
  if (s.shapeKind === "oval") {
    out.borderRadius = "50%";
  } else if (s.corners) {
    const c = s.corners;
    out.borderRadius =
      `${c.topLeft}px ${c.topRight}px ${c.bottomRight}px ${c.bottomLeft}px`;
  }

  // Ring uses an inner border: not perfectly representable in plain CSS,
  // approximate with a thick border + transparent fill.
  if (s.shapeKind === "ring") {
    out.borderRadius = "50%";
    if (!out.border) {
      out.border = `2px solid currentColor`;
    }
    out.background = "transparent";
  }

  // Lines render as a horizontal rule — collapse height to the stroke width.
  if (s.shapeKind === "line" && s.stroke) {
    out.height = s.stroke.width;
    out.background = argb32ToCss(s.stroke.color);
    out.border = "none";
  }

  return out;
}

/** Build a CSS gradient string from a parsed Gradient. */
function gradientToCss(g: Gradient): string {
  const start  = argb32ToCss(g.startColor);
  const end    = argb32ToCss(g.endColor);
  const middle = g.centerColor !== null ? argb32ToCss(g.centerColor) : null;
  const stops  = middle ? `${start}, ${middle}, ${end}` : `${start}, ${end}`;

  switch (g.gradientKind.kind) {
    case "linear": {
      // Android angle: 0 = left→right, 90 = bottom→top. CSS angle: 0 =
      // bottom→top, 90 = left→right. So Android = CSS - 90 (mod 360).
      const cssAngle = ((g.gradientKind.angleDeg + 90) % 360 + 360) % 360;
      return `linear-gradient(${cssAngle}deg, ${stops})`;
    }
    case "radial": {
      const cx = `${g.gradientKind.centerX * 100}%`;
      const cy = `${g.gradientKind.centerY * 100}%`;
      return `radial-gradient(circle at ${cx} ${cy}, ${stops})`;
    }
    case "sweep":
      return `conic-gradient(${stops})`;
  }
}

/** Quick check — does this drawable have any visible content at all? */
export function drawableHasContent(d: Drawable): boolean {
  switch (d.kind) {
    case "color":     return ((d.rgba >>> 24) & 0xff) > 0;  // non-zero alpha
    case "vector":    return d.svg.length > 0;
    case "shape":     return d.solidColor !== null
                          || d.gradient !== null
                          || (d.stroke !== null && d.stroke.width > 0);
    case "selector":
    case "layerList":
    case "ripple":
    case "inset":     return true;
    default:          return false;
  }
}
