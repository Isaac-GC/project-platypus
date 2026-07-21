/**
 * R2 — Canvas renderer.
 *
 * Top-level React component that wraps the layout/paint/hit-test pipeline
 * in a single `<canvas>` element. Re-renders when the IR root, theme, or
 * selection changes; the actual drawing happens in an effect that runs
 * `paintScreen` against the cached layout tree.
 *
 * Sized to 360×640 by default — the same logical pixel grid R1 uses for
 * its phone preview, so the two renderers are visually comparable.
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { Theme, UnifiedView } from "../../types";
import type { TreePath } from "../../components/TreeView";
import { layoutTree } from "./layout";
import { paintScreen } from "./paint";
import { hitTest } from "./hitTest";

export interface CanvasRendererProps {
  root: UnifiedView | null;
  theme?: Theme;
  selectedPath?: TreePath | null;
  onSelect?(path: TreePath, node: UnifiedView): void;
  /** Logical screen width in CSS pixels. Defaults to 360. */
  width?: number;
  /** Logical screen height in CSS pixels. Defaults to 640. */
  height?: number;
  /** Click-through mode — paint pass uses bolder outlines on live views and
   *  the cursor only flips to pointer when over one. The click semantics
   *  themselves are decided by the host's `onSelect`. */
  interactive?: boolean;
}

export const CanvasRenderer: React.FC<CanvasRendererProps> = ({
  root, theme, selectedPath, onSelect,
  width = 360, height = 640, interactive = false,
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const dpr = typeof window !== "undefined" ? (window.devicePixelRatio || 1) : 1;

  // Re-layout whenever the IR or theme changes — cheap (one tree walk),
  // and we hold onto it for both painting and hit-testing.
  const laidOut = useMemo(() => {
    if (!root) return null;
    return layoutTree(root, width, height, theme);
  }, [root, theme, width, height]);

  // Paint pass — fires on layout change OR selection change.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // Hi-dpi: scale the canvas's backing store by DPR but keep the CSS
    // pixel dimensions unchanged. paintScreen draws in CSS pixels.
    const targetW = Math.round(width * dpr);
    const targetH = Math.round(height * dpr);
    if (canvas.width !== targetW || canvas.height !== targetH) {
      canvas.width = targetW;
      canvas.height = targetH;
    }
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    if (!laidOut) {
      ctx.fillStyle = "#fff";
      ctx.fillRect(0, 0, width, height);
      ctx.fillStyle = "#888";
      ctx.font = "14px -apple-system, sans-serif";
      ctx.textBaseline = "middle"; ctx.textAlign = "center";
      ctx.fillText("No layout to render.", width / 2, height / 2);
      return;
    }
    paintScreen(ctx, laidOut, width, height, {
      theme,
      selectedPath: selectedPath ?? null,
      dpr,
      interactive,
    });
  }, [laidOut, theme, selectedPath, width, height, dpr, interactive]);

  /** Translate a mouse event's viewport coords back to canvas-logical
   *  coords. The canvas may be CSS-scaled to fit its container so a raw
   *  `clientX/Y` doesn't map 1:1 to the layout grid. */
  const eventToCanvasCoords = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    return {
      x: (e.clientX - rect.left) * (width / rect.width),
      y: (e.clientY - rect.top)  * (height / rect.height),
    };
  }, [width, height]);

  const handleClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!onSelect || !laidOut) return;
    const { x, y } = eventToCanvasCoords(e);
    const path = hitTest(laidOut, x, y);
    if (path) {
      const node = findByPath(laidOut, path);
      if (node) onSelect(path, node);
    }
  }, [onSelect, laidOut, eventToCanvasCoords]);

  // Cursor feedback: in inspect mode every view is selectable so the
  // pointer is always on. In interactive mode only "live" views (those
  // with a clickHandler/navigation) get the pointer — matches the HTML
  // renderer's behaviour and tells the user "this isn't a real form
  // control, but it's mapped to a known click target".
  const [hoverCursor, setHoverCursor] = useState<"pointer" | "default">("default");
  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!onSelect || !laidOut) return;
    if (!interactive) {
      // Inspect mode — pointer everywhere we can be clicked.
      if (hoverCursor !== "pointer") setHoverCursor("pointer");
      return;
    }
    const { x, y } = eventToCanvasCoords(e);
    const path = hitTest(laidOut, x, y);
    const node = path ? findByPath(laidOut, path) : null;
    const live = !!(node && (node.navigation || node.clickHandler));
    const next = live ? "pointer" : "default";
    if (next !== hoverCursor) setHoverCursor(next);
  }, [onSelect, laidOut, interactive, eventToCanvasCoords, hoverCursor]);

  return (
    <div className="pap-renderer" style={{ background: "#1a1a1a" }}>
      <div className="pap-renderer__phone" style={{ padding: 0 }}>
        <canvas
          ref={canvasRef}
          onClick={handleClick}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setHoverCursor("default")}
          style={{
            display: "block",
            width: `${width}px`,
            height: `${height}px`,
            cursor: onSelect ? hoverCursor : "default",
          }}
        />
      </div>
    </div>
  );
};

/** Resolve a path into the original UnifiedView via the laid-out tree.
 *  Mirrors the search hitTest does — kept here so the canvas event
 *  handler doesn't have to import paint internals. */
function findByPath(root: LaidOutViewLike, target: TreePath): UnifiedView | null {
  if (root.path.length === target.length
      && root.path.every((n, i) => n === target[i])) {
    return root.node;
  }
  for (const c of root.children) {
    const found = findByPath(c, target);
    if (found) return found;
  }
  return null;
}

// Local structural type — avoids importing the layout module's full type
// just for the click handler's traversal.
interface LaidOutViewLike {
  node: UnifiedView;
  path: TreePath;
  children: LaidOutViewLike[];
}
