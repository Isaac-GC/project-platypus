/**
 * Pixel → view path resolver for the canvas renderer.
 *
 * Canvas doesn't carry click affordances per-element like the DOM does —
 * we get a single (x, y) on the canvas and have to find which laid-out
 * view contains the click. We walk the tree depth-first and return the
 * deepest match, which mirrors how DOM event bubbling resolves to the
 * innermost child first.
 */

import type { LaidOutView } from "./layout";
import type { TreePath } from "../../components/TreeView";

/** Find the deepest LaidOutView whose rect contains (x, y). Returns the
 *  root's path when the click misses every child. */
export function hitTest(root: LaidOutView, x: number, y: number): TreePath | null {
  if (!contains(root, x, y)) {
    // Click outside the root entirely — no selection to make.
    return null;
  }

  // Walk children in reverse order so later-painted siblings (drawn on
  // top in FrameLayout) win. Recurse first so we end at the deepest match.
  for (let i = root.children.length - 1; i >= 0; i--) {
    const child = root.children[i];
    if (contains(child, x, y)) {
      const deeper = hitTest(child, x, y);
      if (deeper) return deeper;
    }
  }
  return root.path;
}

function contains(v: LaidOutView, x: number, y: number): boolean {
  return x >= v.x && x < v.x + v.w && y >= v.y && y < v.y + v.h;
}
