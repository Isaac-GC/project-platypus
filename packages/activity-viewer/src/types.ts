/**
 * UnifiedView IR — TypeScript mirror of the Rust types in
 * `platypus-rehydrate/src/ir.rs`. The shapes match what the Tauri
 * commands return AND what `platypus.rehydrate_activity(apk, name)`
 * returns from Python (both go through the same serde camelCase
 * derives).
 *
 * Field names are camelCase. When updating either side, update both —
 * there's no automated codegen between Rust and TS.
 */

/** Result of rehydrating one activity. */
export interface ActivityView {
  /** Fully-qualified activity class name. */
  activityName: string;
  /** Resource id of the root layout if discovered. */
  layoutId: number | null;
  /** Layout file path if resolved, e.g. `"res/layout/activity_main.xml"`. */
  layoutPath: string | null;
  /** Resolved + expanded view tree. `null` when discovery failed. */
  root: UnifiedView | null;
  /** Per-activity warnings — always present (often empty). */
  diagnostics: Diagnostic[];
  /** Every distinct navigation transition reachable from this activity —
   *  union of all view-level handlers AND non-click navigations
   *  (e.g. lifecycle methods that call `startActivity` directly). Feeds
   *  the cross-activity navigation graph. */
  outgoingNavigations: NavTarget[];
}

export interface Diagnostic {
  severity: "info" | "warning" | "error";
  message: string;
  /** Optional location hint — view id, file path, method ref. */
  location: string | null;
}

/** One node in the view tree. */
export interface UnifiedView {
  /** Where this node came from in source. */
  source: ViewSource;
  /** Coarse classification. Renderers branch on this for layout/paint. */
  kind: ViewKind;
  /** Original XML tag (or Compose function name). */
  tag: string;
  /** `android:id` value with `@id/` / `@+id/` prefixes stripped. */
  id: string | null;
  /** All resolved attributes in source order. References already resolved. */
  attrs: Attribute[];
  /** Children in source order. Empty for leaf views. */
  children: UnifiedView[];
  /** Click handler — XML `android:onClick` or DEX `setOnClickListener`. */
  clickHandler: Handler | null;
  /** Where this view navigates if clicked (phase 8+). */
  navigation: NavTarget | null;
  /** Post-inflation modifications discovered via DEX analysis (phase 9+). */
  dynamicModifications: DynMod[];
  /** For list-host views (RecyclerView/ListView/GridView/ViewPager): the
   *  recovered item-row template, expanded from the adapter's
   *  `onCreateViewHolder` (phase 10). Renderers repeat this a few times
   *  instead of showing a generic placeholder. `null` for non-list views
   *  and for list views where adapter recovery failed. */
  itemTemplate: UnifiedView | null;
  /** Pre-resolved drawables, keyed by attribute name (`"android:background"`,
   *  `"android:src"`, …). Each value is a discriminated `Drawable` —
   *  vector drawables arrive as ready-to-paint SVG strings, shapes as
   *  typed colour/corner records, etc. Empty if no drawable refs. */
  drawables: Record<string, Drawable>;
}

// ─── Drawables (mirrors platypus-resources::drawable::Drawable) ────────────

/** A resolved Android drawable. Mirrors the Rust `Drawable` enum — every
 *  variant has a `kind` discriminator (serde's `tag = "kind"` convention). */
export type Drawable =
  | { kind: "bitmap"; path: string; format: BitmapFormat }
  | { kind: "ninePatch"; path: string }
  | { kind: "vector"; svg: string; intrinsicWidthDp: number; intrinsicHeightDp: number }
  | ShapeDrawable
  | { kind: "selector"; items: SelectorItem[] }
  | { kind: "layerList"; items: LayerItem[] }
  | { kind: "ripple"; color: number; content: Drawable | null; mask: Drawable | null }
  | { kind: "inset"; drawable: Drawable; insetLeft: number; insetTop: number; insetRight: number; insetBottom: number }
  | { kind: "color"; rgba: number }
  | { kind: "reference"; typeName: string; name: string }
  | { kind: "unknown"; entryPath: string; reason: string };

export type BitmapFormat = "png" | "webp" | "jpg" | "gif" | "unknown";

export interface ShapeDrawable {
  kind: "shape";
  shapeKind: "rectangle" | "oval" | "line" | "ring";
  solidColor: number | null;
  stroke: { width: number; color: number; dashGap: number; dashWidth: number } | null;
  corners: { topLeft: number; topRight: number; bottomLeft: number; bottomRight: number } | null;
  paddingLeft: number; paddingTop: number; paddingRight: number; paddingBottom: number;
  gradient: Gradient | null;
  intrinsicWidth: number;
  intrinsicHeight: number;
}

export interface Gradient {
  startColor: number;
  centerColor: number | null;
  endColor: number;
  gradientKind: { kind: "linear"; angleDeg: number }
    | { kind: "radial"; centerX: number; centerY: number; radius: number }
    | { kind: "sweep" };
}

export interface SelectorItem {
  state: "pressed" | "focused" | "selected" | "activated" | "hovered" | "checked" | "disabled" | "default";
  drawable: Drawable;
}

export interface LayerItem {
  drawable: Drawable;
  id: string | null;
  insetLeft: number; insetTop: number; insetRight: number; insetBottom: number;
}

/** Where a view was reconstructed from. */
export type ViewSource =
  | { kind: "xml"; layoutPath: string }
  | { kind: "included"; fromLayoutPath: string; includedLayoutPath: string }
  | { kind: "merged"; fromLayoutPath: string }
  | { kind: "stubInflated"; stubLayoutPath: string; targetLayoutPath: string }
  | { kind: "compose"; methodRef: string }
  | { kind: "synthetic" };

/** View-kind discriminator. Layout containers, content views, and lists
 *  get their own variants; `custom` and `other` carry the raw class/tag. */
export type ViewKind =
  // Layout containers
  | { kind: "linearLayout" }
  | { kind: "relativeLayout" }
  | { kind: "frameLayout" }
  | { kind: "constraintLayout" }
  | { kind: "coordinatorLayout" }
  | { kind: "gridLayout" }
  | { kind: "tableLayout" }
  | { kind: "scrollView" }
  | { kind: "horizontalScrollView" }
  | { kind: "nestedScrollView" }
  // Content
  | { kind: "text" }
  | { kind: "editText" }
  | { kind: "button" }
  | { kind: "imageButton" }
  | { kind: "image" }
  | { kind: "switch" }
  | { kind: "checkBox" }
  | { kind: "radioButton" }
  | { kind: "seekBar" }
  | { kind: "progressBar" }
  | { kind: "spinner" }
  | { kind: "toolbar" }
  | { kind: "appBar" }
  | { kind: "bottomNav" }
  | { kind: "tabLayout" }
  // Lists / paging
  | { kind: "recyclerView" }
  | { kind: "listView" }
  | { kind: "gridView" }
  | { kind: "viewPager" }
  | { kind: "viewPager2" }
  // Containers we partially handle
  | { kind: "fragment"; className: string }
  | { kind: "viewStub"; stubLayoutPath: string }
  | { kind: "include"; includedLayoutPath: string }
  | { kind: "merge" }
  // Web
  | { kind: "webView" }
  // Custom view (FQN)
  | { kind: "custom"; className: string }
  // Anything else — preserves the tag
  | { kind: "other"; tag: string };

export interface Attribute {
  /** Attribute name as declared in XML (`"android:text"`, `"layout_width"`). */
  name: string;
  /** Resolved value — strings, dimensions, colors all as strings. */
  value: string;
  /** Where this attribute value came from. */
  origin: AttrOrigin;
}

export type AttrOrigin =
  | { kind: "static" }
  | { kind: "dynamic"; fromMethod: string }
  | { kind: "style"; styleName: string };

export interface Handler {
  kind: "xmlOnClick" | "codeOnClickListener" | "codeOnLongClickListener";
  /** Method ref or method name. For XML this is the named method on the
   *  activity (`"onLoginClicked"`); for DEX this is a class+method ref
   *  (`"Lcom/example/MainActivity$1;->onClick(Landroid/view/View;)V"`). */
  target: string;
}

export interface NavTarget {
  kind: "startActivity" | "startActivityForResult" | "replaceFragment" | "navController";
  /** Activity FQN, fragment class name, or nav-graph destination id. */
  target: string;
}

export interface DynMod {
  /** Setter method e.g. `"setText"`, `"setVisibility"`. */
  setter: string;
  /** Argument as a string — literal when known, otherwise source method ref. */
  value: string;
  /** Where the modification was discovered. */
  fromMethod: string;
  /** True iff the value is a literal. */
  literal: boolean;
}

// ─── Theme + style (mirrors platypus-resources) ────────────────────────────

/** Effective theme — the flattened result of walking a theme's parent chain
 *  and layering bundled Material 3 defaults underneath. Mirrors the Rust
 *  `platypus_resources::theme::Theme`. */
export interface Theme {
  /** Resource id of the theme as declared on the manifest. `0` if no
   *  `android:theme` was set and we're showing only bundled defaults. */
  id: number;
  /** Theme display name (`Theme.MyApp`, `<material3-defaults>`, …). */
  name: string;
  /** Flattened attributes, keyed by attribute id (rendered as a string in
   *  JSON because JSON object keys must be strings — parse with `Number(k)`
   *  if you need the numeric form). Most consumers should look up by name
   *  via {@link findThemeAttr} since attribute names are friendlier. */
  attrs: Record<string, StyleAttribute>;
}

/** One key/value pair inside a theme or style. */
export interface StyleAttribute {
  attrId: number;
  /** Best-effort attribute name. `attr_<hex>` when unknown. */
  name: string;
  /** `"android"` for framework attrs, `null` for app attrs. */
  package: string | null;
  /** Raw `data_type` from the binary `Res_value` (0x01 = ref, 0x03 = string,
   *  0x10 = int, 0x12 = bool, 0x1c-0x1f = colors, …). */
  dataType: number;
  /** Raw `data` field — interpretation depends on `dataType`. */
  data: number;
  /** Pre-formatted string view (e.g. `"#ff6750a4"`, `"14.0sp"`). */
  value: string;
  /** True when this attribute came from a parent style rather than the
   *  named style itself — useful for inheritance debugging. */
  inherited: boolean;
}

/** Find a theme attribute by friendly name. Returns `undefined` if the
 *  theme doesn't define it. */
export function findThemeAttr(theme: Theme, name: string): StyleAttribute | undefined {
  for (const k in theme.attrs) {
    const a = theme.attrs[k];
    if (a.name === name) return a;
  }
  return undefined;
}

// ─── Activity directory entry — what the picker shows ──────────────────────

/** Lightweight summary used by the activity picker. Doesn't include the
 *  full IR — that's loaded on demand when the activity is selected. */
export interface ActivitySummary {
  /** Fully-qualified class name. */
  name: string;
  /** Display label from the manifest (resolved if possible). */
  label: string | null;
  /** True iff this activity is on the launcher (MAIN + LAUNCHER intent-filter). */
  isLauncher: boolean;
  /** True iff this activity is exported. */
  exported: boolean;
}
