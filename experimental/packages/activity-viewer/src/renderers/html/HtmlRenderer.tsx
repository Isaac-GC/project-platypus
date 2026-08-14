/**
 * R1 — HTML/CSS renderer.
 *
 * Walks the UnifiedView tree and emits an approximate HTML/CSS preview of
 * what the activity would look like at runtime. This is *not* pixel-perfect
 * (Android's measure/layout pipeline doesn't have a 1:1 CSS analogue) — it
 * targets "good enough that you can spot an unfamiliar screen at a glance".
 *
 * Layout strategy per container kind:
 *   LinearLayout      → flexbox (orientation → flex-direction)
 *   FrameLayout       → CSS grid with all children stacked into 1×1 area
 *   RelativeLayout    → flexbox column (sibling-relative attrs are dropped;
 *                        we don't try to interpret layout_toRightOf etc.)
 *   ConstraintLayout  → flexbox column (similar simplification)
 *   ScrollView        → block + overflow:auto
 *   GridLayout        → CSS grid (rowCount/columnCount)
 *
 * Selection highlighting and click-to-select are wired through the same
 * (selectedPath / onSelect) contract as the inspector tree, so both views
 * stay in sync.
 */

import React from "react";
import type { UnifiedView, ViewKind, Theme } from "../../types";
import type { TreePath } from "../../components/TreeView";
import {
  attr, attrResolved, paintStyle, dpToPx, androidColorToCss,
  gravityToFlexParent, textStyleToCss, resolveThemeRef,
} from "./attrs";
import { drawableToImageStyle } from "./drawables";
import { solveConstraints } from "./constraint-solver";

export interface HtmlRendererProps {
  root: UnifiedView | null;
  theme?: Theme;
  selectedPath?: TreePath | null;
  onSelect?(path: TreePath, node: UnifiedView): void;
  /** When true, give views with handlers/navigation a stronger hover cue
   *  so the user knows what's "clickable" in click-through mode. The
   *  click semantics themselves are decided by the host's `onSelect`. */
  interactive?: boolean;
  /** Logical CSS width of the device-frame surface. Defaults to 360
   *  (typical phone). Pass 800/1280 for tablet sizes. */
  width?: number;
  /** Logical CSS height of the device-frame surface. Defaults to 640. */
  height?: number;
}

export const HtmlRenderer: React.FC<HtmlRendererProps> = ({
  root, theme, selectedPath, onSelect, interactive = false,
  width = 360, height = 640,
}) => {
  if (!root) {
    return (
      <div className="pap-renderer pap-renderer--empty">
        No layout to render.
      </div>
    );
  }

  // Surface background = theme's windowBackground, falling back to white.
  const surfaceBg = theme
    ? androidColorToCss(resolveThemeRef("?attr/windowBackground", theme)) ?? "#ffffff"
    : "#ffffff";

  // Inline width/height on the phone-frame override the CSS defaults so
  // the same component can render anything from a phone to a 1280×800
  // tablet without per-size CSS classes.
  return (
    <div className={`pap-renderer ${interactive ? "pap-renderer--interactive" : ""}`}
         style={{ background: surfaceBg }}>
      <div className="pap-renderer__phone"
           style={{ width: `${width}px`, height: `${height}px`, minHeight: `${height}px` }}>
        <RenderNode
          node={root}
          path={[]}
          theme={theme}
          selectedPath={selectedPath ?? null}
          onSelect={onSelect}
          interactive={interactive}
          deviceWidth={width}
          deviceHeight={height}
        />
      </div>
    </div>
  );
};

// ── Per-node dispatch ──────────────────────────────────────────────────────

interface NodeProps {
  node: UnifiedView;
  path: TreePath;
  theme?: Theme;
  selectedPath: TreePath | null;
  onSelect?(path: TreePath, node: UnifiedView): void;
  /** Threaded down so leaf renderers can opt in to a stronger
   *  pointer-cursor + hover treatment when the view is "live". */
  interactive: boolean;
  /** Set when this view is being painted as a repeat of a list-host's
   *  `itemTemplate`. Lets text leaves with a non-literal `setText`
   *  binding show distinct per-row hints (`{field} #N`) instead of
   *  identical placeholder text. `undefined` for non-list contexts. */
  rowIndex?: number;
  /** Logical CSS extent of the device-frame surface. Threaded down so
   *  the ConstraintLayout solver knows how big a `match_parent`
   *  ancestor actually is when resolving "parent" anchors. */
  deviceWidth: number;
  deviceHeight: number;
}

const RenderNode: React.FC<NodeProps> = (rawProps) => {
  // Defensive: normalise the node so the rest of the renderer can rely on
  // `attrs` / `children` / `dynamicModifications` being arrays (a partial
  // IR — e.g. a stale fixture from before some field was added — would
  // otherwise crash at first read).
  const node: UnifiedView = {
    ...rawProps.node,
    attrs:                 Array.isArray(rawProps.node.attrs)                 ? rawProps.node.attrs                 : [],
    children:              Array.isArray(rawProps.node.children)              ? rawProps.node.children              : [],
    dynamicModifications:  Array.isArray(rawProps.node.dynamicModifications)  ? rawProps.node.dynamicModifications  : [],
    drawables:             rawProps.node.drawables ?? {},
  };
  const props: NodeProps = { ...rawProps, node };

  // Selection highlight is applied as an outline on the rendered element so
  // it doesn't shift layout. The wrapper handler short-circuits propagation
  // so clicking a child selects only that child, not its ancestors.
  const isSelected = pathsEqual(props.path, props.selectedPath);
  const handleClick = props.onSelect
    ? (e: React.MouseEvent) => {
        e.stopPropagation();
        props.onSelect!(props.path, node);
      }
    : undefined;

  // Click-handler indicator: faint dashed outline so analysts can see at a
  // glance which views have static handlers (XML or DEX-discovered).
  // Navigation handlers get a stronger blue outline so the eye lands on
  // "this button takes you somewhere" first.
  // In interactive mode the outline gets bumped to solid + the cursor flips
  // to pointer-only on actually-clickable views, so the play UX makes the
  // affordance obvious.
  // Selection outline takes priority — same property, last write wins.
  const hasHandler = !!node.clickHandler;
  const hasNav     = !!node.navigation;
  const isLive     = props.interactive && (hasNav || hasHandler);

  let handlerStyle: React.CSSProperties = {};
  if (hasNav) {
    handlerStyle = props.interactive
      ? { outline: "2px solid var(--pap-accent)", outlineOffset: -2 }
      : { outline: "1.5px dashed var(--pap-accent)", outlineOffset: -1 };
  } else if (hasHandler) {
    handlerStyle = props.interactive
      ? { outline: "1.5px solid rgba(255, 167, 38, 0.85)", outlineOffset: -1 }
      : { outline: "1px dashed rgba(255, 167, 38, 0.7)", outlineOffset: -1 };
  }

  const baseStyle: React.CSSProperties = {
    ...paintStyle(node, props.theme),
    ...handlerStyle,
    ...(isSelected ? { outline: "2px solid var(--pap-accent)", outlineOffset: -2 } : {}),
    // Interactive mode: only "live" views get the hand cursor — non-live
    // views look unclickable, matching the click-through metaphor.
    // Inspect mode: any view is selectable, so any view shows the pointer.
    ...(props.onSelect
      ? { cursor: props.interactive ? (isLive ? "pointer" : "default") : "pointer" }
      : {}),
  };

  return renderForKind(node.kind, node, props, baseStyle, handleClick);
};

function renderForKind(
  kind: ViewKind,
  node: UnifiedView,
  props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  switch (kind.kind) {
    case "linearLayout":           return renderLinear(node, props, baseStyle, onClick);
    case "frameLayout":            return renderFrame(node, props, baseStyle, onClick);
    case "relativeLayout":
    case "constraintLayout":
    case "coordinatorLayout":      return renderRelative(node, props, baseStyle, onClick);
    case "gridLayout":             return renderGrid(node, props, baseStyle, onClick);
    case "scrollView":
    case "nestedScrollView":       return renderScroll(node, props, baseStyle, onClick, "vertical");
    case "horizontalScrollView":   return renderScroll(node, props, baseStyle, onClick, "horizontal");

    case "text":                   return renderText(node, props, baseStyle, onClick);
    case "editText":               return renderEditText(node, props, baseStyle, onClick);
    case "button":                 return renderButton(node, props, baseStyle, onClick);
    case "imageButton":            return renderImageButton(node, props, baseStyle, onClick);
    case "image":                  return renderImage(node, props, baseStyle, onClick);

    case "switch":                 return renderToggle(node, props, baseStyle, onClick, "switch");
    case "checkBox":               return renderToggle(node, props, baseStyle, onClick, "checkbox");
    case "radioButton":            return renderToggle(node, props, baseStyle, onClick, "radio");
    case "seekBar":                return renderSeekBar(node, props, baseStyle, onClick);
    case "progressBar":            return renderProgressBar(node, props, baseStyle, onClick);
    case "spinner":                return renderSpinner(node, props, baseStyle, onClick);

    case "toolbar":
    case "appBar":                 return renderToolbar(node, props, baseStyle, onClick);
    case "bottomNav":              return renderBottomNav(node, props, baseStyle, onClick);
    case "tabLayout":              return renderTabLayout(node, props, baseStyle, onClick);

    case "recyclerView":
    case "listView":
    case "gridView":               return renderListStub(node, props, baseStyle, onClick, kind.kind);

    case "viewPager":
    case "viewPager2":             return renderPagerStub(node, props, baseStyle, onClick);

    // For variants that carry a `className`, coerce it to a string. A
    // stale backend (or partial IR shape) might leave the field
    // undefined and crash downstream `.split`/`.lastIndexOf` calls. Fall
    // back to the node's raw tag when the kind didn't carry one.
    case "fragment":               return renderFragmentStub(node, props, baseStyle, onClick, safeClassName(kind, node.tag));
    case "viewStub":               return renderStubBox(node, props, baseStyle, onClick, "ViewStub");
    case "include":                return renderLinear(node, props, baseStyle, onClick); // expanded already
    case "merge":                  return renderLinear(node, props, baseStyle, onClick);

    case "webView":                return renderWebViewStub(node, props, baseStyle, onClick);

    case "custom":                 return renderCustomStub(node, props, baseStyle, onClick, safeClassName(kind, node.tag));
    case "tableLayout":
    case "other":                  return renderLinear(node, props, baseStyle, onClick);
  }
}

// ── Layout containers ─────────────────────────────────────────────────────

function renderLinear(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const orientation = (attr(node, "orientation") ?? "horizontal").toLowerCase();
  const direction = orientation === "vertical" ? "column" : "row";
  const style: React.CSSProperties = {
    ...baseStyle,
    display: "flex",
    flexDirection: direction,
    ...gravityToFlexParent(attr(node, "gravity")),
  };
  return (
    <div className="pap-r1-linear" style={style} onClick={onClick}
         data-tag={node.tag} data-id={node.id ?? undefined}>
      {renderChildren(node, props)}
    </div>
  );
}

function renderFrame(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  // FrameLayout stacks children — easiest is a CSS grid where every child
  // occupies the same 1×1 cell, so they overlap. Inner gravity is honoured
  // via grid alignment.
  const align = gravityToFlexParent(attr(node, "gravity"));
  const style: React.CSSProperties = {
    ...baseStyle,
    display: "grid",
    gridTemplateColumns: "1fr",
    gridTemplateRows: "1fr",
    justifyItems: align.justifyContent === "flex-end" ? "end"
                : align.justifyContent === "center"   ? "center"
                : "start",
    alignItems:   align.alignItems     === "flex-end" ? "end"
                : align.alignItems     === "center"   ? "center"
                : "start",
  };
  return (
    <div className="pap-r1-frame" style={style} onClick={onClick}
         data-tag={node.tag} data-id={node.id ?? undefined}>
      {node.children.map((child, i) => (
        <div key={i} style={{ gridColumn: 1, gridRow: 1 }}>
          <RenderNode {...props} node={child} path={[...props.path, i]} />
        </div>
      ))}
    </div>
  );
}

function renderRelative(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  // Run the constraint solver. It returns a per-child `SolvedRect` for
  // every child whose constraints we could resolve (parent-anchored,
  // sibling-anchored after topo sort, bidirectional with bias, 0dp
  // MATCH_CONSTRAINT stretch). Children without constraint attrs at all
  // are left in normal flow inside a flex column so plain
  // LinearLayout-shaped trees still render the same.
  //
  // Container size used by the solver: the explicit numeric width /
  // height on the container's baseStyle if any, otherwise the device
  // frame extent (passed down via props.deviceWidth / deviceHeight).
  const containerW = pickPx(baseStyle.width,  props.deviceWidth);
  const containerH = pickPx(baseStyle.height, props.deviceHeight);
  const solved = solveConstraints(node, containerW, containerH);

  const style: React.CSSProperties = {
    ...baseStyle,
    position: "relative",
  };

  if (!solved.anyConstrained) {
    // Pure LinearLayout-style relative — keep the simple stack so trees
    // that *look* like ConstraintLayout but never anchor anything still
    // render naturally.
    return (
      <div className="pap-r1-relative" style={{
        ...style, display: "flex", flexDirection: "column",
      }} onClick={onClick}
           data-tag={node.tag} data-id={node.id ?? undefined}>
        {renderChildren(node, props)}
      </div>
    );
  }

  return (
    <div className="pap-r1-constraint" style={style} onClick={onClick}
         data-tag={node.tag} data-id={node.id ?? undefined}
         data-solver-diagnostics={solved.diagnostics.length > 0
           ? solved.diagnostics.join(" | ") : undefined}>
      {node.children.map((child, i) => {
        const rect = solved.rects[i];
        if (rect === null) {
          // Solver couldn't place this child (cycle, missing ref, or
          // it has no anchors at all). Fall back to normal flow so it
          // remains visible.
          return <RenderNode key={i} {...props} node={child} path={[...props.path, i]} />;
        }
        const placement: React.CSSProperties = {
          position: "absolute",
          left: `${rect.left}px`,
          top:  `${rect.top}px`,
        };
        if (rect.width  !== null) placement.width  = `${rect.width}px`;
        if (rect.height !== null) placement.height = `${rect.height}px`;
        return (
          <div key={i} style={placement}>
            <RenderNode {...props} node={child} path={[...props.path, i]} />
          </div>
        );
      })}
    </div>
  );
}

/// Resolve a CSS dimension value to a plain number-of-pixels. Falls back
/// to `fallback` when the input isn't a numeric px value (e.g. `"100%"`,
/// `"auto"`, undefined). Used to pick the container size the constraint
/// solver should treat the `parent` edges as anchoring to.
function pickPx(v: string | number | undefined, fallback: number): number {
  if (typeof v === "number") return v;
  if (typeof v === "string") {
    const m = v.match(/^(\d+(?:\.\d+)?)px$/);
    if (m) return parseFloat(m[1]);
  }
  return fallback;
}

function renderGrid(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const cols = parseInt(attr(node, "columnCount") ?? "2", 10) || 2;
  const style: React.CSSProperties = {
    ...baseStyle,
    display: "grid",
    gridTemplateColumns: `repeat(${cols}, 1fr)`,
    gap: 4,
  };
  return (
    <div className="pap-r1-grid" style={style} onClick={onClick}
         data-tag={node.tag} data-id={node.id ?? undefined}>
      {renderChildren(node, props)}
    </div>
  );
}

function renderScroll(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick: ((e: React.MouseEvent) => void) | undefined,
  axis: "vertical" | "horizontal",
): JSX.Element {
  const style: React.CSSProperties = {
    ...baseStyle,
    display: "flex",
    flexDirection: axis === "vertical" ? "column" : "row",
    overflow: axis === "vertical" ? "auto hidden" : "hidden auto",
  };
  return (
    <div className="pap-r1-scroll" style={style} onClick={onClick}
         data-tag={node.tag} data-id={node.id ?? undefined}>
      {renderChildren(node, props)}
    </div>
  );
}

// ── Content ───────────────────────────────────────────────────────────────

function renderText(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  // Per-row substitution for list templates: when this TextView has a
  // non-literal `setText` binding (e.g. `holder.title.text = item.name`),
  // we know the runtime value comes from a data field. Showing identical
  // placeholder text in every row would waste the binding info. Instead
  // we substitute `{field} #N` so each row reads as distinct.
  let text = attr(node, "text") ?? attr(node, "hint") ?? "";
  if (props.rowIndex !== undefined) {
    // Defensive: an old IR (pre-phase 9) may not carry
    // `dynamicModifications`. Treat missing as empty.
    const mods = node.dynamicModifications ?? [];
    const dyn = mods.find(
      (m) => m.setter === "setText" && !m.literal,
    );
    if (dyn) {
      // `value` is shaped "from <fieldname>" or "(derived)" — strip the
      // prefix so we just show the field name.
      const field = dyn.value.startsWith("from ") ? dyn.value.slice(5) : "value";
      text = `${field} #${props.rowIndex + 1}`;
    }
  }

  const color = androidColorToCss(attrResolved(node, "textColor", props.theme));
  const size  = dpToPx(attrResolved(node, "textSize", props.theme));
  const style: React.CSSProperties = {
    ...baseStyle,
    ...(color ? { color } : {}),
    ...(size  ? { fontSize: size } : {}),
    ...textStyleToCss(attr(node, "textStyle")),
    minHeight: baseStyle.height ?? "1em",
    minWidth:  baseStyle.width  ?? "auto",
  };
  return (
    <span className="pap-r1-text" style={style} onClick={onClick}
          data-tag={node.tag} data-id={node.id ?? undefined}>
      {text || <em style={{ opacity: 0.4 }}>(empty)</em>}
    </span>
  );
}

function renderEditText(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const text = attr(node, "text") ?? "";
  const hint = attr(node, "hint") ?? "";
  const style: React.CSSProperties = {
    ...baseStyle,
    border: "1px solid #999",
    borderRadius: 4,
    padding: "4px 8px",
    background: "#fff",
    color: "#222",
    minHeight: 28,
  };
  return (
    <input
      className="pap-r1-edittext"
      style={style}
      placeholder={hint}
      defaultValue={text}
      readOnly
      onClick={onClick as React.MouseEventHandler<HTMLInputElement>}
      data-tag={node.tag} data-id={node.id ?? undefined}
    />
  );
}

function renderButton(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const text = attr(node, "text") ?? "";
  const themePrimary = androidColorToCss(resolveThemeRef("?attr/colorPrimary", props.theme)) ?? "#6750a4";
  const onPrimary    = androidColorToCss(resolveThemeRef("?attr/colorOnPrimary", props.theme)) ?? "#ffffff";
  const style: React.CSSProperties = {
    ...baseStyle,
    background: baseStyle.backgroundColor ?? themePrimary,
    color: onPrimary,
    border: "none",
    borderRadius: 20,
    padding: "8px 16px",
    fontWeight: 500,
    cursor: "pointer",
  };
  return (
    <button
      className="pap-r1-button"
      style={style}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {text || "Button"}
    </button>
  );
}

function renderImageButton(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  // Same drawable-aware rendering as ImageView — most ImageButtons carry
  // their icon in `android:src` and a hint in `android:background`.
  const drawable =
    node.drawables?.["android:src"]
    ?? node.drawables?.["android:srcCompat"]
    ?? node.drawables?.["app:srcCompat"];
  const drawableStyle = drawable ? drawableToImageStyle(drawable) : null;
  const hasDrawableContent = !!drawableStyle && (
    !!drawableStyle.backgroundImage || !!drawableStyle.backgroundColor || !!drawableStyle.background
  );

  return (
    <button
      className="pap-r1-imagebutton"
      style={{
        ...baseStyle,
        ...(hasDrawableContent ? drawableStyle : {
          background: baseStyle.backgroundColor ?? "transparent",
          border: "1px dashed #999",
        }),
        minWidth: 32, minHeight: 32,
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {hasDrawableContent ? null : <span style={{ fontSize: 10, opacity: 0.5 }}>img</span>}
    </button>
  );
}

function renderImage(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  // Prefer a structured drawable when the resolver gave us one — vector
  // drawables paint as SVG, shapes as gradients/borders, colors fill.
  // Falls back to the hatched placeholder + source-name caption only
  // when we have no Drawable to work with (raster bitmaps without
  // backend bytes, unresolved refs).
  const src = attr(node, "src") ?? attr(node, "srcCompat") ?? "";
  const drawable =
    node.drawables?.["android:src"]
    ?? node.drawables?.["android:srcCompat"]
    ?? node.drawables?.["app:srcCompat"];
  const drawableStyle = drawable ? drawableToImageStyle(drawable) : null;
  const hasDrawableContent = !!drawableStyle && (
    !!drawableStyle.backgroundImage || !!drawableStyle.backgroundColor || !!drawableStyle.background
  );

  return (
    <div
      className="pap-r1-image"
      style={{
        ...baseStyle,
        minWidth: 24, minHeight: 24,
        ...(hasDrawableContent ? drawableStyle : {
          background: baseStyle.background ??
            "repeating-linear-gradient(45deg, #eee 0 4px, #f8f8f8 4px 8px)",
          border: "1px dashed #bbb",
        }),
        display: "flex", alignItems: "center", justifyContent: "center",
        color: "#666", fontSize: 9,
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
      title={src}
    >
      {hasDrawableContent ? null : (src.split("/").pop()?.split(".")[0] || "img")}
    </div>
  );
}

// ── Form controls ─────────────────────────────────────────────────────────

function renderToggle(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick: ((e: React.MouseEvent) => void) | undefined,
  type: "switch" | "checkbox" | "radio",
): JSX.Element {
  const text = attr(node, "text") ?? "";
  const checked = (attr(node, "checked") ?? "false").toLowerCase() === "true";
  const inputType = type === "switch" ? "checkbox" : type;
  return (
    <label
      className={`pap-r1-toggle pap-r1-toggle--${type}`}
      style={{ ...baseStyle, display: "inline-flex", alignItems: "center", gap: 6 }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      <input type={inputType} defaultChecked={checked} readOnly />
      {text && <span>{text}</span>}
    </label>
  );
}

function renderSeekBar(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const max = parseInt(attr(node, "max") ?? "100", 10);
  const progress = parseInt(attr(node, "progress") ?? "0", 10);
  return (
    <input
      className="pap-r1-seekbar"
      type="range"
      style={{ ...baseStyle, minWidth: 100 }}
      min={0} max={max} defaultValue={progress} readOnly
      onClick={onClick as React.MouseEventHandler<HTMLInputElement>}
      data-tag={node.tag} data-id={node.id ?? undefined}
    />
  );
}

function renderProgressBar(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const indeterminate = (attr(node, "indeterminate") ?? "false").toLowerCase() === "true";
  const max = parseInt(attr(node, "max") ?? "100", 10);
  const value = parseInt(attr(node, "progress") ?? "0", 10);
  const accent = androidColorToCss(resolveThemeRef("?attr/colorAccent", props.theme)) ?? "#6750a4";
  if (indeterminate) {
    return (
      <div
        className="pap-r1-progress pap-r1-progress--indeterminate"
        style={{ ...baseStyle, height: baseStyle.height ?? 4, background: "#ccc",
                 minWidth: 80, position: "relative", overflow: "hidden" }}
        onClick={onClick}
        data-tag={node.tag} data-id={node.id ?? undefined}
      >
        <div style={{
          position: "absolute", top: 0, bottom: 0, width: "30%",
          background: accent,
          animation: "pap-r1-progress-sweep 1.4s linear infinite",
        }} />
      </div>
    );
  }
  return (
    <progress
      className="pap-r1-progress"
      style={{ ...baseStyle, minWidth: 80 }}
      max={max} value={value}
      onClick={onClick as React.MouseEventHandler<HTMLProgressElement>}
      data-tag={node.tag} data-id={node.id ?? undefined}
    />
  );
}

function renderSpinner(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  return (
    <select
      className="pap-r1-spinner"
      style={{ ...baseStyle, minWidth: 100 }}
      onClick={onClick as React.MouseEventHandler<HTMLSelectElement>}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      <option>(spinner)</option>
    </select>
  );
}

// ── Bars ──────────────────────────────────────────────────────────────────

function renderToolbar(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const title = attr(node, "title") ?? "";
  const themePrimary = androidColorToCss(resolveThemeRef("?attr/colorPrimary", props.theme)) ?? "#6750a4";
  const onPrimary    = androidColorToCss(resolveThemeRef("?attr/colorOnPrimary", props.theme)) ?? "#ffffff";
  const style: React.CSSProperties = {
    ...baseStyle,
    background: baseStyle.backgroundColor ?? themePrimary,
    color: onPrimary,
    minHeight: baseStyle.height ?? 56,
    padding: "0 16px",
    display: "flex", alignItems: "center",
    fontWeight: 500, fontSize: 18,
  };
  return (
    <div className="pap-r1-toolbar" style={style} onClick={onClick}
         data-tag={node.tag} data-id={node.id ?? undefined}>
      {title || node.children.length === 0 ? title : renderChildren(node, props)}
    </div>
  );
}

function renderBottomNav(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const style: React.CSSProperties = {
    ...baseStyle,
    background: baseStyle.backgroundColor ?? "#fff",
    borderTop: "1px solid #ddd",
    minHeight: baseStyle.height ?? 56,
    display: "flex", alignItems: "stretch", justifyContent: "space-around",
  };
  return (
    <div className="pap-r1-bottomnav" style={style} onClick={onClick}
         data-tag={node.tag} data-id={node.id ?? undefined}>
      {node.children.length > 0
        ? renderChildren(node, props)
        : ["Home", "Items", "Profile"].map((label) => (
            <div key={label} style={{
              flex: 1, display: "flex", flexDirection: "column",
              alignItems: "center", justifyContent: "center", fontSize: 12,
            }}>
              <div style={{ width: 20, height: 20, background: "#999", borderRadius: 4 }} />
              {label}
            </div>
          ))}
    </div>
  );
}

function renderTabLayout(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  return (
    <div
      className="pap-r1-tablayout"
      style={{
        ...baseStyle,
        display: "flex",
        borderBottom: "2px solid var(--pap-accent, #6750a4)",
        minHeight: baseStyle.height ?? 48,
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {node.children.length > 0
        ? renderChildren(node, props)
        : ["Tab 1", "Tab 2", "Tab 3"].map((label, i) => (
            <div key={label} style={{
              flex: 1, padding: "12px 16px", textAlign: "center",
              fontWeight: i === 0 ? 600 : 400,
              borderBottom: i === 0 ? "2px solid #6750a4" : "none",
              marginBottom: -2,
            }}>{label}</div>
          ))}
    </div>
  );
}

// ── List / pager / fragment / web stubs ───────────────────────────────────

function renderListStub(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick: ((e: React.MouseEvent) => void) | undefined,
  kind: string,
): JSX.Element {
  const template = node.itemTemplate;
  const isGrid   = kind === "gridView";
  const itemCount = isGrid ? 6 : 3;

  // Container layout — vertical stack for List/Recycler, 2-column grid for
  // GridView. The host view's own padding/background still apply via baseStyle.
  const containerStyle: React.CSSProperties = isGrid
    ? {
        ...baseStyle,
        minHeight: baseStyle.height ?? 160,
        display: "grid",
        gridTemplateColumns: "repeat(2, 1fr)",
        gap: 4,
      }
    : {
        ...baseStyle,
        minHeight: baseStyle.height ?? 120,
        display: "flex",
        flexDirection: "column",
      };

  // No template recovered — fall back to the original generic stub but
  // keep the (analyst-friendly) "not resolved" hint visible.
  if (!template) {
    return (
      <div
        className="pap-r1-list-stub"
        style={{
          ...containerStyle,
          background: "rgba(0,122,204,0.04)",
          border: "1px dashed rgba(0,122,204,0.4)",
        }}
        onClick={onClick}
        data-tag={node.tag} data-id={node.id ?? undefined}
      >
        <div style={{ padding: 6, fontSize: 10, opacity: 0.6, gridColumn: "1 / -1" }}>
          {kind} (item template not resolved)
        </div>
        {Array.from({ length: itemCount }).map((_, i) => (
          <div key={i} style={{
            padding: "12px 16px",
            borderTop: !isGrid && i > 0 ? "1px solid rgba(0,0,0,0.05)" : "none",
          }}>
            Item {i + 1}
          </div>
        ))}
      </div>
    );
  }

  // Render the template a few times. Each instance reuses the same path
  // prefix so selecting a row selects the template node — there's only
  // one `itemTemplate` in the IR even though we draw it N times.
  // `rowIndex` flows down so text leaves with non-literal bindings can
  // show a per-row hint instead of identical placeholder text.
  return (
    <div
      className="pap-r1-list"
      style={containerStyle}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {Array.from({ length: itemCount }).map((_, i) => (
        <div key={i} style={{
          borderTop: !isGrid && i > 0 ? "1px solid rgba(0,0,0,0.05)" : "none",
        }}>
          <RenderNode
            {...props}
            node={template}
            // Index past `node.children.length` to avoid clashing with any
            // (legitimate but rare) static children on the list view.
            path={[...props.path, node.children.length + i]}
            rowIndex={i}
          />
        </div>
      ))}
    </div>
  );
}

function renderPagerStub(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  return (
    <div
      className="pap-r1-pager-stub"
      style={{
        ...baseStyle,
        background: "rgba(255,200,80,0.05)",
        border: "1px dashed rgba(255,200,80,0.5)",
        minHeight: baseStyle.height ?? 200,
        display: "flex", alignItems: "center", justifyContent: "center",
        color: "#888", fontSize: 12,
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      ViewPager (page content not resolved)
    </div>
  );
}

function renderFragmentStub(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick: ((e: React.MouseEvent) => void) | undefined,
  className: string,
): JSX.Element {
  return (
    <div
      className="pap-r1-fragment-stub"
      style={{
        ...baseStyle,
        background: "rgba(150,90,200,0.05)",
        border: "1px dashed rgba(150,90,200,0.5)",
        minHeight: baseStyle.height ?? 80,
        padding: 12, fontSize: 12, color: "#666",
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      <strong>Fragment:</strong> {shortClass(className)}
    </div>
  );
}

function renderStubBox(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick: ((e: React.MouseEvent) => void) | undefined,
  label: string,
): JSX.Element {
  return (
    <div
      className="pap-r1-stub"
      style={{
        ...baseStyle,
        background: "rgba(0,0,0,0.03)",
        border: "1px dashed #999",
        minHeight: 40, padding: 8, fontSize: 12, color: "#666",
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {label}
    </div>
  );
}

function renderWebViewStub(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  return (
    <div
      className="pap-r1-webview-stub"
      style={{
        ...baseStyle,
        background: "#222", color: "#0f0",
        minHeight: baseStyle.height ?? 120,
        display: "flex", alignItems: "center", justifyContent: "center",
        fontFamily: "ui-monospace, monospace", fontSize: 12,
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      &lt;WebView&gt;
    </div>
  );
}

function renderCustomStub(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick: ((e: React.MouseEvent) => void) | undefined,
  className: string,
): JSX.Element {
  // Material widgets that look distinctive but aren't classified yet in the
  // Rust IR (see ViewKind::from_tag). Recognise them by class name so the
  // user sees a recognisable shape instead of a dashed "Custom" box.
  if (className.endsWith(".FloatingActionButton")
   || className.endsWith(".ExtendedFloatingActionButton")) {
    return renderFloatingActionButton(node, props, baseStyle, onClick);
  }
  if (className.endsWith(".MaterialCardView") || className.endsWith(".CardView")) {
    return renderCardStub(node, props, baseStyle, onClick);
  }

  // If the custom view has children we attempt to render them — many custom
  // ViewGroups are just LinearLayouts in disguise. If it doesn't, we fall
  // back to a labelled stub.
  if (node.children.length > 0) {
    return renderLinear(node, props, baseStyle, onClick);
  }
  return (
    <div
      className="pap-r1-custom"
      style={{
        ...baseStyle,
        background: "rgba(255,140,0,0.05)",
        border: "1px dashed rgba(255,140,0,0.5)",
        padding: 8, fontSize: 11, color: "#666",
        minHeight: baseStyle.height ?? 24,
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {shortClass(className)}
    </div>
  );
}

/// Render a FAB approximation — a circular tinted surface that picks up
/// the `android:src` drawable when one's been resolved. Material 3 FABs
/// are 56dp square (60dp for extended) by default and render their icon
/// centered. We honour explicit `layout_width`/`layout_height` if they
/// were set; otherwise the default size kicks in so a `wrap_content` FAB
/// doesn't collapse to 0px.
function renderFloatingActionButton(
  node: UnifiedView, _props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  const drawable = node.drawables?.["android:src"];
  const svg = (drawable && typeof drawable === "object" && "svg" in drawable)
    ? (drawable as { svg: string }).svg : null;
  const w = (typeof baseStyle.width === "string" && baseStyle.width === "auto") || !baseStyle.width
    ? 56 : baseStyle.width;
  const h = (typeof baseStyle.height === "string" && baseStyle.height === "auto") || !baseStyle.height
    ? 56 : baseStyle.height;
  return (
    <div
      className="pap-r1-fab"
      style={{
        ...baseStyle,
        width: w, height: h, borderRadius: "50%",
        background: "var(--pap-accent, #6750a4)",
        color: "#fff",
        display: "inline-flex", alignItems: "center", justifyContent: "center",
        boxShadow: "0 4px 10px rgba(0,0,0,0.25)",
        cursor: onClick ? "pointer" : "default",
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {svg
        ? <span style={{ width: 24, height: 24, display: "inline-block" }}
                dangerouslySetInnerHTML={{ __html: svg.replace(/fill="#[0-9a-fA-F]+"/g, 'fill="#fff"') }} />
        : <span style={{ fontSize: 22, lineHeight: 1 }}>+</span>}
    </div>
  );
}

function renderCardStub(
  node: UnifiedView, props: NodeProps,
  baseStyle: React.CSSProperties,
  onClick?: (e: React.MouseEvent) => void,
): JSX.Element {
  return (
    <div
      className="pap-r1-card"
      style={{
        ...baseStyle,
        background: "var(--pap-surface, #1e1e1e)",
        borderRadius: 12,
        boxShadow: "0 1px 3px rgba(0,0,0,0.2)",
        padding: 12,
        minHeight: baseStyle.height ?? 80,
      }}
      onClick={onClick}
      data-tag={node.tag} data-id={node.id ?? undefined}
    >
      {node.children.length > 0
        ? renderChildren(node, props)
        : <div style={{ opacity: 0.5, fontSize: 11 }}>MaterialCardView</div>}
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────

function renderChildren(node: UnifiedView, props: NodeProps): JSX.Element[] {
  return node.children.map((child, i) => (
    <RenderNode key={i} {...props} node={child} path={[...props.path, i]} />
  ));
}

function pathsEqual(a: TreePath, b: TreePath | null): boolean {
  if (b === null) return false;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function shortClass(fqn: string): string {
  // Defensive: callers might have lost the type info via JSON round-trip
  // and pass a non-string. Treat anything else as opaque.
  if (typeof fqn !== "string") return "(unknown)";
  const dot = fqn.lastIndexOf(".");
  return dot >= 0 ? fqn.slice(dot + 1) : fqn;
}

/** Pull a usable class-name string out of a `kind` discriminant that
 *  expects one. If the IR is missing the field (older Rust build, partial
 *  fixture, type mismatch) we fall back to the node's raw tag — better
 *  than crashing on `undefined.split` downstream. */
function safeClassName(kind: { className?: unknown }, fallbackTag: string): string {
  const cn = kind.className;
  if (typeof cn === "string" && cn.length > 0) return cn;
  return fallbackTag || "(unknown)";
}
