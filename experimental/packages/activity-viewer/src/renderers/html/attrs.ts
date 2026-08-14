/**
 * Pure-function helpers for translating Android attribute values into the
 * CSS / inline-style shape the HTML renderer needs.
 *
 * Everything here works on the raw attribute *strings* the IR produces
 * (already reference-resolved by the Rust side). Theme attrs (`?attr/...`)
 * fall back to the supplied `Theme` when present.
 *
 * Layout vs paint:
 *   - layout_* attributes affect how the *parent* sizes/positions this
 *     view, so they're applied in the parent's layout helper.
 *   - paint attributes (background, padding, text*) apply directly to the
 *     view's own style and live in `paintStyle()`.
 */

import type { Attribute, Theme, UnifiedView } from "../../types";
import { findThemeAttr } from "../../types";
import { drawableToBackgroundStyle } from "./drawables";

// ── Attribute lookup ──────────────────────────────────────────────────────

/** Look up an attribute by name on a view. Strips namespace prefix when
 *  matching so callers can ask for `"text"` or `"android:text"`
 *  interchangeably.
 *
 *  Defensive against partial IRs (legacy fixtures) where `attrs` may be
 *  missing or non-array — returns `undefined` rather than throwing. */
export function attr(view: UnifiedView, name: string): string | undefined {
  const attrs = view.attrs;
  if (!Array.isArray(attrs)) return undefined;
  const target = stripNs(name);
  for (const a of attrs) {
    if (a && stripNs(a.name) === target) return a.value;
  }
  return undefined;
}

/** Like {@link attr} but returns the resolved value through theme attr
 *  references (`?attr/...` / `?...`). */
export function attrResolved(
  view: UnifiedView, name: string, theme?: Theme,
): string | undefined {
  const v = attr(view, name);
  if (v === undefined) return undefined;
  return resolveThemeRef(v, theme);
}

function stripNs(name: string): string {
  const colon = name.indexOf(":");
  return colon >= 0 ? name.slice(colon + 1) : name;
}

// ── Theme reference resolution ────────────────────────────────────────────

/** If `value` is a theme reference (`?attr/foo`, `?android:colorPrimary`,
 *  `?foo`) return the underlying value from `theme`. Otherwise return the
 *  input unchanged. */
export function resolveThemeRef(value: string, theme?: Theme): string {
  if (!theme || value.length === 0 || value[0] !== "?") return value;
  const body = value.slice(1);
  // strip optional package + "attr/" prefix
  const afterPkg = body.includes(":") ? body.slice(body.indexOf(":") + 1) : body;
  const name = afterPkg.startsWith("attr/") ? afterPkg.slice(5) : afterPkg;
  const found = findThemeAttr(theme, name);
  return found ? found.value : value;
}

// ── Dimensions ─────────────────────────────────────────────────────────────

/**
 * Convert an Android dimension string (`16dp`, `12sp`, `100px`, `8dip`,
 * `match_parent`, `wrap_content`, `0`, `12.5dp`) to a CSS length / keyword.
 *
 * - `match_parent` / `fill_parent` → `"100%"`
 * - `wrap_content`                 → `"auto"`
 * - `dp` / `dip`                   → `Npx` (1dp = 1px in our preview;
 *                                   close enough for static reconstruction)
 * - `sp`                           → `Npx`
 * - `px`                           → `Npx`
 * - bare number / unitless         → `Npx`
 *
 * Returns the input unchanged if it looks like something else (theme
 * reference, drawable ref, etc.) — caller decides what to do.
 */
export function dpToPx(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const v = value.trim();
  if (v === "match_parent" || v === "fill_parent" || v === "-1") return "100%";
  if (v === "wrap_content" || v === "-2") return "auto";
  const m = v.match(/^(-?\d+(?:\.\d+)?)\s*(dp|dip|sp|px|pt|in|mm)?$/i);
  if (!m) return v; // not a dimension — let caller deal with it
  const n = parseFloat(m[1]);
  // For preview purposes treat all units as logical px. dp/sp ≈ px on a
  // baseline-density device.
  return `${n}px`;
}

/** Numeric variant — useful when you need to do arithmetic. Returns
 *  `undefined` for non-numeric / keyword values. */
export function dpToNumber(value: string | undefined): number | undefined {
  if (value === undefined) return undefined;
  const m = value.trim().match(/^(-?\d+(?:\.\d+)?)\s*(dp|dip|sp|px|pt)?$/i);
  if (!m) return undefined;
  return parseFloat(m[1]);
}

// ── Colors ─────────────────────────────────────────────────────────────────

/**
 * Parse an Android color string into a CSS color.
 *
 * Accepts `#RGB`, `#ARGB`, `#RRGGBB`, `#AARRGGBB`. Android's hex order is
 * AARRGGBB (alpha first); CSS expects RRGGBBAA. We re-order accordingly.
 * Returns the input unchanged if it doesn't look like a hex color.
 */
export function androidColorToCss(value: string | undefined): string | undefined {
  if (value === undefined) return undefined;
  const v = value.trim();
  if (!v.startsWith("#")) return v;
  const hex = v.slice(1);
  switch (hex.length) {
    case 3: { // #RGB → #RRGGBB
      const [r, g, b] = hex;
      return `#${r}${r}${g}${g}${b}${b}`;
    }
    case 4: { // #ARGB → #RRGGBBAA
      const [a, r, g, b] = hex;
      return `#${r}${r}${g}${g}${b}${b}${a}${a}`;
    }
    case 6: // #RRGGBB — already CSS-friendly
      return v;
    case 8: { // #AARRGGBB → #RRGGBBAA
      const a = hex.slice(0, 2);
      const r = hex.slice(2, 4);
      const g = hex.slice(4, 6);
      const b = hex.slice(6, 8);
      return `#${r}${g}${b}${a}`;
    }
    default:
      return v;
  }
}

// ── Gravity / alignment ───────────────────────────────────────────────────

/**
 * Translate an Android `gravity` value to flexbox alignment.
 *
 * Returns CSS properties to spread onto the *parent* (when the parent is a
 * flex container). The mapping is approximate — `gravity` and `layout_gravity`
 * pre-date flexbox by a decade, and not every combination has a clean
 * flexbox equivalent.
 *
 * Returns a `React.CSSProperties` so it composes cleanly with other style
 * fragments without TypeScript widening the literal `textAlign` value to
 * a plain `string`.
 */
export function gravityToFlexParent(value: string | undefined): React.CSSProperties {
  if (!value) return {};
  const tokens = value.split("|").map((s) => s.trim().toLowerCase());
  const out: React.CSSProperties = {};

  // horizontal
  if (tokens.includes("center_horizontal") || tokens.includes("center")) {
    out.justifyContent = "center";
    out.textAlign = "center";
  } else if (tokens.includes("right") || tokens.includes("end")) {
    out.justifyContent = "flex-end";
    out.textAlign = "right";
  } else if (tokens.includes("left") || tokens.includes("start")) {
    out.justifyContent = "flex-start";
    out.textAlign = "left";
  }

  // vertical
  if (tokens.includes("center_vertical") || tokens.includes("center")) {
    out.alignItems = "center";
  } else if (tokens.includes("bottom")) {
    out.alignItems = "flex-end";
  } else if (tokens.includes("top")) {
    out.alignItems = "flex-start";
  }

  return out;
}

/** Same idea but for self-alignment (a child's `layout_gravity`). */
export function layoutGravityToFlexChild(value: string | undefined): {
  alignSelf?: string;
  marginLeft?: string;
  marginRight?: string;
} {
  if (!value) return {};
  const tokens = value.split("|").map((s) => s.trim().toLowerCase());

  let alignSelf: string | undefined;
  if (tokens.includes("center_vertical") || tokens.includes("center")) alignSelf = "center";
  else if (tokens.includes("bottom")) alignSelf = "flex-end";
  else if (tokens.includes("top")) alignSelf = "flex-start";

  // horizontal centering inside a vertical LinearLayout typically means
  // auto margins on both sides.
  let marginLeft: string | undefined;
  let marginRight: string | undefined;
  if (tokens.includes("center_horizontal") || tokens.includes("center")) {
    marginLeft = "auto"; marginRight = "auto";
  } else if (tokens.includes("right") || tokens.includes("end")) {
    marginLeft = "auto";
  } else if (tokens.includes("left") || tokens.includes("start")) {
    marginRight = "auto";
  }

  return {
    ...(alignSelf !== undefined ? { alignSelf } : {}),
    ...(marginLeft !== undefined ? { marginLeft } : {}),
    ...(marginRight !== undefined ? { marginRight } : {}),
  };
}

// ── Padding / margins ──────────────────────────────────────────────────────

interface BoxSpacing {
  paddingLeft?: string; paddingTop?: string; paddingRight?: string; paddingBottom?: string;
  marginLeft?: string; marginTop?: string; marginRight?: string; marginBottom?: string;
}

/** Read the various `padding*` / `margin*` attrs and produce a CSS
 *  fragment. Handles the "padding sets all four" shorthand. */
export function spacingFromAttrs(view: UnifiedView): BoxSpacing {
  const out: BoxSpacing = {};

  const all = dpToPx(attr(view, "padding"));
  if (all) {
    out.paddingLeft = all; out.paddingRight = all;
    out.paddingTop = all; out.paddingBottom = all;
  }
  const horiz = dpToPx(attr(view, "paddingHorizontal"));
  if (horiz) { out.paddingLeft = horiz; out.paddingRight = horiz; }
  const vert = dpToPx(attr(view, "paddingVertical"));
  if (vert) { out.paddingTop = vert; out.paddingBottom = vert; }

  for (const side of ["Left", "Top", "Right", "Bottom"] as const) {
    const v = dpToPx(attr(view, `padding${side}`))
           ?? dpToPx(attr(view, `padding${sideToStartEnd(side)}`));
    if (v) (out as Record<string, string>)[`padding${side}`] = v;
  }

  const allM = dpToPx(attr(view, "layout_margin"));
  if (allM) {
    out.marginLeft = allM; out.marginRight = allM;
    out.marginTop = allM; out.marginBottom = allM;
  }
  for (const side of ["Left", "Top", "Right", "Bottom"] as const) {
    const v = dpToPx(attr(view, `layout_margin${side}`))
           ?? dpToPx(attr(view, `layout_margin${sideToStartEnd(side)}`));
    if (v) (out as Record<string, string>)[`margin${side}`] = v;
  }

  return out;
}

function sideToStartEnd(side: "Left" | "Top" | "Right" | "Bottom"): string {
  // RTL-aware Android attrs use "Start"/"End" for left/right.
  if (side === "Left") return "Start";
  if (side === "Right") return "End";
  return side;
}

// ── Visibility ─────────────────────────────────────────────────────────────

/** Translate `android:visibility` to CSS `display` / `visibility`. */
export function visibilityToCss(value: string | undefined): {
  display?: string; visibility?: string;
} {
  if (!value) return {};
  switch (value.toLowerCase()) {
    case "gone":      return { display: "none" };
    case "invisible": return { visibility: "hidden" };
    default:          return {};
  }
}

// ── Text ───────────────────────────────────────────────────────────────────

/** Translate `android:textStyle` to CSS font-weight/font-style. */
export function textStyleToCss(value: string | undefined): {
  fontWeight?: string; fontStyle?: string;
} {
  if (!value) return {};
  const tokens = value.split("|").map((s) => s.trim().toLowerCase());
  const out: { fontWeight?: string; fontStyle?: string } = {};
  if (tokens.includes("bold")) out.fontWeight = "bold";
  if (tokens.includes("italic")) out.fontStyle = "italic";
  return out;
}

// ── Background ─────────────────────────────────────────────────────────────

/** Translate `android:background` (literal color or drawable reference)
 *  to a CSS fragment.
 *
 *  Two-pass strategy:
 *    1. If the view has a pre-resolved Drawable for this attr (via the
 *       Rust builder's `resolve_drawables_for`), render it structurally —
 *       vector drawables become SVG data URLs, shapes become gradient +
 *       border + radius, etc.
 *    2. Otherwise fall back to string parsing: color literals → CSS,
 *       theme refs → resolve via theme, anything else → faint hatch.
 */
export function backgroundToCss(
  value: string | undefined,
  theme?: Theme,
  drawable?: import("../../types").Drawable,
): React.CSSProperties {
  // Structured drawable wins — it's already been classified by the Rust
  // resolver, no string-parsing heuristics needed.
  if (drawable) {
    return drawableToBackgroundStyle(drawable);
  }

  if (!value) return {};
  const resolved = resolveThemeRef(value, theme);

  // Color literal — most common case once the resolver has run.
  if (resolved.startsWith("#")) {
    return { backgroundColor: androidColorToCss(resolved) };
  }
  // Drawable reference / file path that didn't get resolved (probably
  // means the entry wasn't found in resources.arsc) — stub with placeholder.
  if (resolved.startsWith("@") || resolved.startsWith("res/")) {
    return {
      background:
        "repeating-linear-gradient(45deg, rgba(0,0,0,0.04) 0 4px, transparent 4px 8px)",
    };
  }
  return {};
}

// ── Misc convenience ──────────────────────────────────────────────────────

/** All paint-only style — what most leaf renderers spread onto their root. */
export function paintStyle(view: UnifiedView, theme?: Theme): React.CSSProperties {
  const out: React.CSSProperties = {};

  const wRaw = attr(view, "layout_width");
  const hRaw = attr(view, "layout_height");
  const w = dpToPx(wRaw);
  const h = dpToPx(hRaw);
  if (w) out.width = w;
  if (h) out.height = h;

  // ConstraintLayout convention: `0dp` (a.k.a. MATCH_CONSTRAINT) means
  // "stretch to fill the constrained extent". The ConstraintLayout
  // engine derives the actual size from the surrounding constraints,
  // which we don't run — so we emit `flex: 1` along the matching axis
  // so the surrounding flex container at least gives this view the
  // remaining space. Without this, the view collapses to 0px and the
  // typical "AppBar / Content / BottomNav" pattern looks broken.
  if (hRaw === "0dp" && hasVerticalConstraints(view)) {
    out.height = "auto";
    out.flex = "1 1 0";
  }
  if (wRaw === "0dp" && hasHorizontalConstraints(view)) {
    out.width = "auto";
    out.flexGrow = 1;
  }

  const minW = dpToPx(attr(view, "minWidth"));
  if (minW) out.minWidth = minW;
  const minH = dpToPx(attr(view, "minHeight"));
  if (minH) out.minHeight = minH;

  Object.assign(out, spacingFromAttrs(view));
  Object.assign(out, visibilityToCss(attr(view, "visibility")));
  Object.assign(out, backgroundToCss(
    attr(view, "background"), theme, view.drawables?.["android:background"],
  ));
  Object.assign(out, layoutGravityToFlexChild(attr(view, "layout_gravity")));

  // A weight of 1 in a LinearLayout child means "expand to fill remainder"
  // — flexbox flex-grow is the natural mapping.
  const weight = attr(view, "layout_weight");
  if (weight) {
    const n = parseFloat(weight);
    if (!isNaN(n)) out.flexGrow = n;
  }

  return out;
}

/** Coerce Attribute lookup result for the rare case a caller needs the
 *  full record (origin, etc.). */
export function rawAttr(view: UnifiedView, name: string): Attribute | undefined {
  const attrs = view.attrs;
  if (!Array.isArray(attrs)) return undefined;
  const target = stripNs(name);
  return attrs.find((a) => a && stripNs(a.name) === target);
}

/** True if the view has at least one constraint anchoring its top OR
 *  bottom — used by `paintStyle` to know when `layout_height="0dp"`
 *  should stretch to fill via flexbox. */
function hasVerticalConstraints(view: UnifiedView): boolean {
  return view.attrs.some((a) =>
       a.name.endsWith(":layout_constraintTop_toTopOf")
    || a.name.endsWith(":layout_constraintTop_toBottomOf")
    || a.name.endsWith(":layout_constraintBottom_toBottomOf")
    || a.name.endsWith(":layout_constraintBottom_toTopOf"),
  );
}

/** True if the view has at least one constraint anchoring its start OR
 *  end (or left/right) — companion to {@link hasVerticalConstraints}. */
function hasHorizontalConstraints(view: UnifiedView): boolean {
  return view.attrs.some((a) =>
       a.name.endsWith(":layout_constraintStart_toStartOf")
    || a.name.endsWith(":layout_constraintStart_toEndOf")
    || a.name.endsWith(":layout_constraintEnd_toStartOf")
    || a.name.endsWith(":layout_constraintEnd_toEndOf")
    || a.name.endsWith(":layout_constraintLeft_toLeftOf")
    || a.name.endsWith(":layout_constraintLeft_toRightOf")
    || a.name.endsWith(":layout_constraintRight_toLeftOf")
    || a.name.endsWith(":layout_constraintRight_toRightOf"),
  );
}
