import type { TreeNode } from "../api/types";

/**
 * Flatten the class tree by dropping the `dexfile` layer and merging
 * packages from every DEX into one tree per `source_root`.
 *
 * The backend always returns:
 * ```
 * source_root  ("Source Code")
 *   ├── dexfile  ("classes.dex")
 *   │     ├── package  ("com")
 *   │     │     └── package  ("foo")
 *   │     │           └── class  ("Bar")
 *   │     └── …
 *   └── dexfile  ("classes2.dex")
 *         └── package  ("com")
 *               └── package  ("foo")
 *                     └── class  ("Baz")
 * ```
 *
 * After flattening:
 * ```
 * source_root  ("Source Code")
 *   └── package  ("com")
 *         └── package  ("foo")
 *               ├── class  ("Bar")    ← from classes.dex
 *               └── class  ("Baz")    ← from classes2.dex
 * ```
 *
 * Packages are merged by name at every depth; their non-package children
 * (classes, fields, methods) are concatenated. Each merged package's
 * `id` is rewritten to be deterministic + collision-free
 * (`merged:com/foo`) so React's keying stays stable across re-renders.
 *
 * Non-`source_root` siblings (`manifest`, `resources_root`) pass through
 * untouched.
 *
 * **What's preserved per class node**: `dexName`, `fullName`, and all
 * other metadata. Downstream `openNode` already routes via these fields,
 * so opening a class still finds the right backend entry regardless of
 * which DEX it lived in. Two classes with the same simple name from
 * different DEXs appear side-by-side (their `id`s differ because the
 * backend prefixed them with the DEX file name).
 */
export function flattenTreeByPackage(
  roots: TreeNode[],
  // Prefix for the synthetic merged-package ids. Override per embedded APK
  // (e.g. `merged:embedded:assets/x.apk:`) so its package nodes don't collide
  // with the main tree's `merged:com/foo` ids in `expandedNodes`.
  idPrefix: string = "merged:",
): TreeNode[] {
  return roots.map((root) => {
    if (root.kind !== "source_root" || !root.children || root.children.length === 0) {
      return root;
    }
    // Collect every dexfile's package-children into one merged map.
    // We walk dexfile children only; if a class somehow shows up
    // directly under source_root (shouldn't happen but be defensive),
    // it passes through unchanged.
    const mergedTop = new Map<string, TreeNode>();
    const passThrough: TreeNode[] = [];
    for (const child of root.children) {
      if (child.kind === "dexfile" && child.children) {
        mergeInto(mergedTop, child.children, idPrefix);
      } else if (child.kind !== "dexfile") {
        passThrough.push(child);
      }
    }
    return {
      ...root,
      children: [...passThrough, ...sortedNodes(mergedTop)],
    };
  });
}

/**
 * Merge `incoming` nodes into `acc`, keyed by node name. Packages
 * recurse; everything else (classes, methods, fields) is appended to
 * a per-name bucket so duplicates from different DEXs coexist.
 *
 * `idPrefix` is threaded down to keep merged-node IDs stable and
 * distinct from the original per-DEX IDs (so React doesn't think a
 * merged node is the "same" node as one of its constituents and skip
 * a re-render).
 */
function mergeInto(
  acc: Map<string, TreeNode>,
  incoming: TreeNode[],
  idPrefix: string,
) {
  for (const node of incoming) {
    if (node.kind === "package") {
      const existing = acc.get(node.name);
      if (existing) {
        // Merge children into the existing bucket. We keep the existing
        // node's id so React doesn't churn the row.
        const childMap = new Map<string, TreeNode>();
        // First: re-index the existing children so nested merging
        // picks them up cleanly.
        for (const c of existing.children ?? []) {
          // Only packages get name-keyed merging; everything else is
          // appended as-is via the "extras" bucket below.
          if (c.kind === "package") childMap.set(c.name, c);
        }
        const extras: TreeNode[] = (existing.children ?? []).filter(
          (c) => c.kind !== "package",
        );
        // Now merge the new node's children.
        for (const c of node.children ?? []) {
          if (c.kind === "package") {
            const subPrefix = `${idPrefix}${node.name}/`;
            mergeInto(childMap, [c], subPrefix);
          } else {
            extras.push(c);
          }
        }
        acc.set(node.name, {
          ...existing,
          children: [...extras, ...sortedNodes(childMap)],
        });
      } else {
        // First time seeing this package at this level — clone with
        // a merged id so React doesn't conflate with the source DEX's
        // package node.
        const subPrefix = `${idPrefix}${node.name}/`;
        const childMap = new Map<string, TreeNode>();
        const extras: TreeNode[] = [];
        for (const c of node.children ?? []) {
          if (c.kind === "package") {
            mergeInto(childMap, [c], subPrefix);
          } else {
            extras.push(c);
          }
        }
        acc.set(node.name, {
          ...node,
          id: `${idPrefix}${node.name}`,
          children: [...extras, ...sortedNodes(childMap)],
        });
      }
    } else {
      // Class / field / method at the top of a DEX (rare — usually a
      // class sits inside a package). Bucket by name; collisions
      // accumulate as siblings.
      const key = `${node.kind}:${node.name}`;
      const existing = acc.get(key);
      if (existing) {
        // Append (siblings); the merged node holds them in `children`
        // — but for non-package types we want them flat at this level.
        // Use a synthetic key so we just dedupe by (kind,name).
        // Practically this branch almost never fires for real APKs.
        acc.set(`${key}::${node.id}`, node);
      } else {
        acc.set(key, node);
      }
    }
  }
}

/** Stable alphabetical ordering for the visible tree (case-insensitive). */
function sortedNodes(map: Map<string, TreeNode>): TreeNode[] {
  return Array.from(map.values()).sort((a, b) =>
    a.name.toLowerCase().localeCompare(b.name.toLowerCase()),
  );
}
