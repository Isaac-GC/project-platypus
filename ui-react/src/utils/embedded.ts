import type { TreeNode, EmbeddedCandidate } from "../api/types";
import { flattenTreeByPackage } from "./tree";

/** Show the full resource path when it's a reasonable length, otherwise
 *  ellipsize to `…/<filename>` (packers bury payloads under long random paths). */
export function embeddedDisplayName(path: string): string {
  if (path.length <= 56) return path;
  return `…/${path.split("/").pop() ?? path}`;
}

/** Build the "Embedded code" group node (`embedded_root`) with one bare
 *  `embedded_apk` child per candidate. The children are filled in lazily +
 *  recursively at render time by [`resolveEmbedded`]. */
export function embeddedGroupNode(candidates: EmbeddedCandidate[]): TreeNode {
  return {
    id: "embedded-apks-root",
    name: `Embedded code (${candidates.length})`,
    kind: "embedded_root",
    children: candidates.map((c) => ({
      id: `embedded:${c.entryPath}`,
      name: embeddedDisplayName(c.entryPath),
      kind: "embedded_apk",
      fullName: c.entryPath,
    })),
  };
}

/** Walk `nodes` and fill in every `embedded_apk` node's children from the
 *  lazily-loaded `embeddedTrees` (keyed by node id), recursing so nested
 *  payloads (a DEX/JAR inside an embedded APK inside another) all resolve.
 *  Applies the global "Group classes by" shape per embedded subtree. */
export function resolveEmbedded(
  nodes: TreeNode[],
  embeddedTrees: Record<string, TreeNode[]>,
  loading: Set<string>,
  groupBy: "dexfile" | "merged",
): TreeNode[] {
  return nodes.map((n) => {
    if (n.kind === "embedded_apk") {
      const loaded = embeddedTrees[n.id];
      if (!loaded) {
        // Inert placeholder so the node shows a chevron (expand → lazy parse).
        return {
          ...n,
          children: [{
            id: `${n.id}::ph`,
            name: loading.has(n.id) ? "Loading…" : "Expand to browse",
            kind: "embedded_root" as const,
          }],
        };
      }
      const shaped = groupBy === "merged"
        ? flattenTreeByPackage(loaded, `merged:${n.id}:`)
        : loaded;
      return { ...n, children: resolveEmbedded(shaped, embeddedTrees, loading, groupBy) };
    }
    if (n.children && n.children.length > 0) {
      return { ...n, children: resolveEmbedded(n.children, embeddedTrees, loading, groupBy) };
    }
    return n;
  });
}

/** Decode an embedded-apk tree-node id back to the slot whose ZIP contains it
 *  and the entry path within. Top-level ids are `embedded:<entryPath>` (parent
 *  = active slot); nested ids are `s:<parentSlotId>:embedded:<entryPath>`. */
export function parseEmbeddedNodeId(
  id: string,
  activeSlotId: string | null,
): { parentSlotId: string; entryPath: string } | null {
  if (id.startsWith("embedded:")) {
    if (!activeSlotId) return null;
    return { parentSlotId: activeSlotId, entryPath: id.slice("embedded:".length) };
  }
  const m = id.match(/^s:([^:]+):embedded:([\s\S]*)$/);
  if (m) return { parentSlotId: m[1], entryPath: m[2] };
  return null;
}

/** The chain of node ids that must be expanded for an embedded node at any
 *  nesting depth to be visible: every enclosing "Embedded code" group and
 *  embedded-apk node, up to the top-level group. */
export function embeddedAncestorIds(
  nodeId: string,
  slotToNode: Record<string, string>,
): string[] {
  const ids = new Set<string>(["embedded-apks-root", nodeId]);
  let cur = nodeId;
  // Each nested id `s:<parentSlot>:embedded:<entry>` sits inside that parent
  // slot's nested group + that parent slot's embedded-apk node.
  for (let guard = 0; guard < 32; guard++) {
    const m = cur.match(/^s:([^:]+):embedded:/);
    if (!m) break;
    const parentSlot = m[1];
    ids.add(`s:${parentSlot}:embedded-apks-root`);
    const parentNodeId = slotToNode[parentSlot];
    if (!parentNodeId || ids.has(parentNodeId)) break;
    ids.add(parentNodeId);
    cur = parentNodeId;
  }
  return [...ids];
}
