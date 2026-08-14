import React, { useState, useEffect, useMemo, useRef } from "react";
import { useAppStore } from "../../store/appStore";
import TreeView from "../tree/TreeView";
import { api } from "../../api/adapter";
import type { TreeNode, SlotSummary, DexLoaderSite } from "../../api/types";
import { flattenTreeByPackage } from "../../utils/tree";
import { embeddedGroupNode, resolveEmbedded } from "../../utils/embedded";

// ─── Project tab — one row per detected dex-loader site ────────────────────

interface DexLoaderRowProps {
  site: DexLoaderSite;
  /** Open the loader's containing class+method in the centre panel. */
  onOpenCaller: () => void;
  /** Pre-fill the find-exec panel with the most likely byte-source target
   *  and run it so the user can recover the loaded bytes. */
  onTraceChain: () => void;
}

const DexLoaderRow: React.FC<DexLoaderRowProps> = ({ site, onOpenCaller, onTraceChain }) => {
  const fmtClass = (s: string) => s.replace(/^L/, "").replace(/;$/, "").replace(/\//g, ".");
  const callerShort = `${fmtClass(site.callerClass).split(".").pop()}::${site.callerMethod.split("(")[0]}`;
  return (
    <div className="flex flex-col gap-0.5 px-2 py-1.5 border-b border-vs-border/40 hover:bg-vs-elevated/40">
      <div className="flex items-center gap-1.5">
        <span className="text-[10px] px-1 py-0.5 rounded bg-vs-warning/15 text-vs-warning font-mono">
          {site.loaderClass}
        </span>
        <span className="flex-1 min-w-0 text-xs font-mono text-vs-text truncate" title={`${site.callerClass}.${site.callerMethod}`}>
          {callerShort}
        </span>
        {site.lineNumber !== undefined && (
          <span className="text-[10px] text-vs-dim">:{site.lineNumber}</span>
        )}
      </div>

      {/* Candidate assets — strings statically resolvable from the same method */}
      {site.candidateAssets.length > 0 && (
        <div className="flex flex-wrap gap-1 mt-0.5">
          {site.candidateAssets.map((a) => (
            <span
              key={a}
              className="text-[10px] px-1 py-0.5 rounded bg-vs-accent/10 text-vs-accent font-mono"
              title="Candidate asset/file passed to a byte-source method in the same scope"
            >
              {a}
            </span>
          ))}
        </div>
      )}

      {/* Byte-source kinds (deduplicated) */}
      {site.byteSources.length > 0 && (
        <div className="text-[10px] text-vs-muted mt-0.5">
          via {Array.from(new Set(site.byteSources.map((bs) => bs.kind))).join(", ")}
        </div>
      )}

      <div className="flex items-center gap-1 mt-0.5">
        <button
          className="px-1.5 py-0.5 rounded text-[10px] border border-vs-border text-vs-muted hover:text-vs-text hover:border-vs-accent"
          onClick={onOpenCaller}
          title="Open the containing class in the centre panel"
        >
          Open
        </button>
        <button
          className="px-1.5 py-0.5 rounded text-[10px] border border-vs-border text-vs-muted hover:text-vs-accent hover:border-vs-accent"
          onClick={onTraceChain}
          title="Pre-fill find-exec with the byte-source method and run it (recovered APK bytes show a 📦 Load APK button)"
        >
          Trace chain
        </button>
      </div>
    </div>
  );
};

// ─── Project tab — one row per slot ──────────────────────────────────────────

interface SlotRowProps {
  slot: SlotSummary;
  depth: number;                          // 0 = top-level, 1 = nested under parent
  isActive: boolean;
  isCompare: boolean;
  onSetActive: () => void;
  onSetCompare: () => void;
  onForceReload: () => void;
  onRemove: () => void;
  onAddSplit: () => void;
}

const SlotRow: React.FC<SlotRowProps> = ({
  slot, depth, isActive, isCompare,
  onSetActive, onSetCompare, onForceReload, onRemove, onAddSplit,
}) => {
  const missingCount = slot.declaredSplits.filter(
    (n) => !slot.loadedSplits.some((l) => l.includes(n))
  ).length;
  return (
    <div
      className={[
        "flex flex-col gap-0.5 px-2 py-1.5 border-b border-vs-border/40 cursor-pointer hover:bg-vs-elevated/50",
        isActive ? "bg-vs-accent/10 border-l-2 border-l-vs-accent" : "border-l-2 border-l-transparent",
      ].join(" ")}
      style={{ paddingLeft: `${0.5 + depth * 0.75}rem` }}
      onClick={onSetActive}
    >
      {/* Header row: name + status badges */}
      <div className="flex items-center gap-1.5">
        {depth > 0 && <span className="text-vs-dim text-xs">↳</span>}
        <span className={[
          "flex-1 min-w-0 text-xs font-mono truncate",
          isActive ? "text-vs-text font-semibold" : "text-vs-text",
        ].join(" ")} title={slot.basePath}>
          {slot.displayName}
        </span>
        {isActive && (
          <span className="text-[9px] px-1 py-0.5 rounded bg-vs-accent text-white">A</span>
        )}
        {isCompare && (
          <span className="text-[9px] px-1 py-0.5 rounded bg-vs-warning text-vs-bg">B</span>
        )}
        {slot.isCached && (
          <span className="text-[9px] px-1 py-0.5 rounded bg-vs-elevated text-vs-muted" title="Extracted into cache">cached</span>
        )}
      </div>

      {/* Metadata row */}
      <div className="flex items-center gap-2 text-[10px] text-vs-muted">
        {slot.versionName && <span>v{slot.versionName}</span>}
        {slot.versionCode && <span>({slot.versionCode})</span>}
        <span>{slot.dexCount} dex</span>
        {slot.loadedSplits.length > 0 && (
          <span>{slot.loadedSplits.length} split{slot.loadedSplits.length === 1 ? "" : "s"}</span>
        )}
        {missingCount > 0 && (
          <span className="text-vs-warning" title={`Missing: ${slot.declaredSplits.filter((n) => !slot.loadedSplits.some((l) => l.includes(n))).join(", ")}`}>
            ⚠ {missingCount} missing
          </span>
        )}
        {slot.embeddedCandidates.length > 0 && (
          <span className="text-vs-accent" title="Embedded APKs detected">
            📦 {slot.embeddedCandidates.length}
          </span>
        )}
      </div>

      {/* Action row */}
      <div className="flex items-center gap-1 mt-0.5" onClick={(e) => e.stopPropagation()}>
        <button
          className={[
            "px-1.5 py-0.5 rounded text-[10px] border transition-colors",
            isCompare
              ? "border-vs-warning text-vs-warning bg-vs-warning/10"
              : "border-vs-border text-vs-muted hover:text-vs-warning hover:border-vs-warning",
          ].join(" ")}
          onClick={onSetCompare}
          title={isCompare ? "Unset as compare slot" : "Use as diff/compare slot"}
        >
          {isCompare ? "✓ Compare" : "Compare"}
        </button>
        <button
          className="px-1.5 py-0.5 rounded text-[10px] border border-vs-border text-vs-muted hover:text-vs-text hover:border-vs-accent"
          onClick={onAddSplit}
          title="Attach a split APK to this slot's bundle"
        >
          + Split
        </button>
        <button
          className="px-1.5 py-0.5 rounded text-[10px] border border-vs-border text-vs-muted hover:text-vs-text hover:border-vs-accent"
          onClick={onForceReload}
          title="Re-read from disk (force reload)"
        >
          ⟳
        </button>
        <button
          className="px-1.5 py-0.5 rounded text-[10px] border border-vs-border text-vs-muted hover:text-vs-error hover:border-vs-error"
          onClick={onRemove}
          title="Remove from project"
        >
          ✕
        </button>
      </div>
    </div>
  );
};

const LeftPanel: React.FC = () => {
  const tree = useAppStore((s) => s.tree);
  const treeGroupBy = useAppStore((s) => s.settings.treeGroupBy);
  // Apply the Settings → "Group classes by" toggle. The store always
  // holds the per-DEX shape (that's what the backend returns), and we
  // transform-on-render so toggling the setting is instant — no APK
  // reload, no cache invalidation. The merged form is purely visual;
  // node.dexName + node.fullName are preserved on every class node so
  // openNode still routes correctly downstream.
  const displayTree = useMemo(
    () => (treeGroupBy === "merged" ? flattenTreeByPackage(tree) : tree),
    [tree, treeGroupBy],
  );
  const expandedNodes = useAppStore((s) => s.expandedNodes);
  const selectedNode = useAppStore((s) => s.selectedNode);
  const revealRequest = useAppStore((s) => s.revealRequest);
  const filterQuery = useAppStore((s) => s.filterQuery);
  const loadedFile = useAppStore((s) => s.loadedFile);
  const loadedFileB = useAppStore((s) => s.loadedFileB);
  const diffTree = useAppStore((s) => s.diffTree);
  const buildDiffTree = useAppStore((s) => s.buildDiffTree);
  const toggleExpand = useAppStore((s) => s.toggleExpand);
  const selectNode = useAppStore((s) => s.selectNode);
  const openNode = useAppStore((s) => s.openNode);
  const setFilterQuery = useAppStore((s) => s.setFilterQuery);
  // Multi-APK project state
  const slots = useAppStore((s) => s.slots);
  const activeSlotId = useAppStore((s) => s.activeSlotId);
  const compareSlotId = useAppStore((s) => s.compareSlotId);
  const cacheDir = useAppStore((s) => s.cacheDir);
  const setActiveSlot = useAppStore((s) => s.setActiveSlot);
  const setCompareSlot = useAppStore((s) => s.setCompareSlot);
  const removeSlot = useAppStore((s) => s.removeSlot);
  const forceReloadActiveSlot = useAppStore((s) => s.forceReloadActiveSlot);
  const forceReloadSlot = useAppStore((s) => s.forceReloadSlot);
  const loadEmbeddedAsSlot = useAppStore((s) => s.loadEmbeddedAsSlot);
  const addApkToProject = useAppStore((s) => s.addApkToProject);
  const addSplitToSlot = useAppStore((s) => s.addSplitToSlot);
  const clearExtractedCache = useAppStore((s) => s.clearExtractedCache);
  const dexLoaderSites = useAppStore((s) => s.dexLoaderSites);
  const isAnalyzingDexLoaders = useAppStore((s) => s.isAnalyzingDexLoaders);
  const analyzeDexLoaders = useAppStore((s) => s.analyzeDexLoaders);
  const navigateToMember = useAppStore((s) => s.navigateToMember);
  const findAndExec = useAppStore((s) => s.findAndExec);
  const setExecSignature = useAppStore((s) => s.setExecSignature);
  const setActiveBottomTab = useAppStore((s) => s.setActiveBottomTab);
  const activeSlot = slots.find((s) => s.id === activeSlotId) ?? null;
  const missingSplitsCount = activeSlot
    ? activeSlot.declaredSplits.filter(
        (n) => !activeSlot.loadedSplits.some((l) => l.includes(n))
      ).length
    : 0;
  const embeddedCandidates = activeSlot?.embeddedCandidates ?? [];
  const embeddedTrees = useAppStore((s) => s.embeddedTrees);
  const embeddedLoading = useAppStore((s) => s.embeddedLoading);
  // Append a dedicated "Embedded APKs" group to the tree so packed payloads are
  // discoverable and browsable inline (expand to parse into a child slot).
  const treeWithEmbedded = useMemo(() => {
    if (embeddedCandidates.length === 0) return displayTree;
    // Build the top-level group, then recursively resolve every embedded node's
    // children from the lazily-loaded subtrees (handles arbitrary nesting).
    const group = embeddedGroupNode(embeddedCandidates);
    const resolved = resolveEmbedded([group], embeddedTrees, embeddedLoading, treeGroupBy)[0];
    return [...displayTree, resolved];
  }, [displayTree, embeddedCandidates, embeddedTrees, embeddedLoading, treeGroupBy]);
  const treeScrollRef = useRef<HTMLDivElement>(null);

  const [activeTab, setActiveTab] = useState<"explorer" | "project" | "diff">("explorer");
  const [diffFilter, setDiffFilter] = useState("");
  const [showEmbeddedPopover, setShowEmbeddedPopover] = useState(false);

  // Auto-switch to diff tab when B is loaded; rebuild diff tree
  useEffect(() => {
    if (loadedFileB) {
      buildDiffTree();
      setActiveTab("diff");
    }
  }, [loadedFileB]); // eslint-disable-line

  // ── Reveal-in-tree scroll ──────────────────────────────────────────────
  // When navigation (XREF click, search result, deobf jump) asks to reveal a
  // class, the store expands its ancestors + selects it; here we switch to
  // the Explorer tab (where the class tree lives) and scroll the now-visible
  // row into view. Two animation frames give React time to commit the tab
  // switch + expanded rows before we query for the target element.
  useEffect(() => {
    if (!revealRequest) return;
    setActiveTab("explorer");
    let inner = 0;
    const outer = requestAnimationFrame(() => {
      inner = requestAnimationFrame(() => {
        const container = treeScrollRef.current;
        if (!container) return;
        const row = container.querySelector(
          `[data-node-id="${CSS.escape(revealRequest.nodeId)}"]`
        );
        row?.scrollIntoView({ block: "center", behavior: "smooth" });
      });
    });
    return () => { cancelAnimationFrame(outer); cancelAnimationFrame(inner); };
  }, [revealRequest]);

  // Handle click on diff tree nodes
  const handleDiffNodeOpen = (node: TreeNode) => {
    if (
      (node.kind === "diff_added" || node.kind === "diff_removed" || node.kind === "diff_modified") &&
      node.fullName
    ) {
      // Navigate to the class (from slot A)
      openNode({ ...node, kind: "class" });
    }
  };

  return (
    <div className="flex flex-col h-full bg-vs-surface border-r border-vs-border overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center bg-vs-elevated border-b border-vs-border flex-shrink-0">
        <button
          className={[
            "px-3 h-8 text-xs font-semibold border-b-2 transition-colors",
            activeTab === "explorer"
              ? "border-vs-accent text-vs-accent"
              : "border-transparent text-vs-muted hover:text-vs-text",
          ].join(" ")}
          onClick={() => setActiveTab("explorer")}
        >
          Explorer
        </button>
        <button
          className={[
            "px-3 h-8 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1",
            activeTab === "project"
              ? "border-vs-accent text-vs-accent"
              : "border-transparent text-vs-muted hover:text-vs-text",
          ].join(" ")}
          onClick={() => setActiveTab("project")}
          title="Manage all loaded APKs"
        >
          Project
          {slots.length > 0 && (
            <span className="text-[10px] text-vs-muted">({slots.length})</span>
          )}
        </button>
        <button
          className={[
            "px-3 h-8 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1",
            activeTab === "diff"
              ? "border-vs-accent text-vs-accent"
              : "border-transparent text-vs-muted hover:text-vs-text",
            !loadedFileB ? "opacity-40" : "",
          ].join(" ")}
          onClick={() => { if (loadedFileB) { buildDiffTree(); setActiveTab("diff"); } }}
          title={!loadedFileB ? "Load APK B in the DIFF tab first" : "Diff view"}
        >
          Diff
          {loadedFileB && (
            <span className="w-1.5 h-1.5 rounded-full bg-vs-accent inline-block" />
          )}
        </button>
      </div>

      {/* ── Explorer tab ── */}
      {activeTab === "explorer" && (
        <>
          {/* Slot picker — only when multiple APKs are loaded.
             For a single-slot project we just show the file name in the existing
             tree, no chrome change. */}
          {slots.length > 1 && (
            <div className="px-2 py-1.5 border-b border-vs-border flex-shrink-0 flex items-center gap-1">
              <select
                value={activeSlotId ?? ""}
                onChange={(e) => void setActiveSlot(e.target.value)}
                className="flex-1 min-w-0 bg-vs-bg border border-vs-border rounded px-2 py-1 text-xs text-vs-text focus:outline-none focus:border-vs-accent"
                title="Switch active APK"
              >
                {slots.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.displayName}
                    {s.versionName ? ` (v${s.versionName})` : ""}
                    {s.parentId ? "  ↳ extracted" : ""}
                  </option>
                ))}
              </select>
              <button
                className="px-2 py-1 rounded text-xs border border-vs-border text-vs-muted hover:text-vs-text hover:border-vs-accent"
                onClick={() => void forceReloadActiveSlot()}
                title="Re-read this APK from disk (force reload)"
              >
                ⟳
              </button>
              <button
                className="px-2 py-1 rounded text-xs border border-vs-border text-vs-muted hover:text-vs-error hover:border-vs-error"
                onClick={() => {
                  if (activeSlotId && confirm("Remove this APK from the project?")) {
                    void removeSlot(activeSlotId);
                  }
                }}
                title="Remove this APK from the project"
              >
                ✕
              </button>
            </div>
          )}

          {/* Missing-splits banner — only when the base manifest declared splits we don't have */}
          {missingSplitsCount > 0 && activeSlot && (
            <div className="px-2 py-1 bg-vs-warning/10 text-vs-warning text-xs flex-shrink-0 border-b border-vs-border"
                 title={`Missing splits: ${activeSlot.declaredSplits
                   .filter((n) => !activeSlot.loadedSplits.some((l) => l.includes(n)))
                   .join(", ")}`}>
              ⚠ {missingSplitsCount} declared split{missingSplitsCount === 1 ? "" : "s"} not loaded
            </div>
          )}

          {/* Embedded-APKs banner — visible when the auto-scan found ZIP-with-classes.dex
              in any asset/resource entry. Clicking opens a popover listing the candidates
              with one-click "Load as APK" buttons. */}
          {embeddedCandidates.length > 0 && activeSlot && (
            <div className="relative flex-shrink-0 border-b border-vs-border">
              <button
                className="w-full px-2 py-1 bg-vs-accent/10 text-vs-accent text-xs flex items-center justify-between hover:bg-vs-accent/20 transition-colors"
                onClick={() => setShowEmbeddedPopover((s) => !s)}
                title="Click to view embedded APK / JAR / DEX payloads detected in assets/resources"
              >
                <span>📦 {embeddedCandidates.length} embedded payload{embeddedCandidates.length === 1 ? "" : "s"} detected</span>
                <span className="text-vs-muted">{showEmbeddedPopover ? "▴" : "▾"}</span>
              </button>
              {showEmbeddedPopover && (
                <div className="absolute z-30 left-0 right-0 top-full bg-vs-elevated border-b border-vs-border shadow-lg max-h-72 overflow-y-auto">
                  {embeddedCandidates.map((c) => (
                    <div
                      key={`${c.splitName}/${c.entryPath}`}
                      className="flex items-center gap-2 px-2 py-1.5 border-b border-vs-border/40 last:border-b-0 hover:bg-vs-bg/40"
                    >
                      <div className="flex-1 min-w-0">
                        <div className="text-xs text-vs-text font-mono truncate" title={c.entryPath}>
                          {c.splitName ? `[${c.splitName}] ` : ""}{c.entryPath}
                        </div>
                        <div className="text-[10px] text-vs-muted flex gap-2">
                          <span>{(c.size / 1024).toFixed(1)} KB</span>
                          <span>{c.dexCount} dex</span>
                          {c.hasManifest && <span className="text-vs-success">manifest</span>}
                          {!c.hasManifest && <span className="italic">no manifest</span>}
                        </div>
                      </div>
                      <button
                        className="px-2 py-0.5 rounded text-[10px] bg-vs-accent text-white hover:bg-vs-accent/80 flex-shrink-0"
                        onClick={() => {
                          setShowEmbeddedPopover(false);
                          void loadEmbeddedAsSlot(activeSlot.id, c.entryPath);
                        }}
                      >
                        Load
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Filter */}
          <div className="px-2 py-1.5 border-b border-vs-border flex-shrink-0">
            <input
              type="text"
              value={filterQuery}
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              onChange={(e) => setFilterQuery(e.target.value)}
              placeholder="Filter…"
              className="w-full bg-vs-bg border border-vs-border rounded px-2 py-1 text-xs text-vs-text placeholder:text-vs-dim focus:outline-none focus:border-vs-accent"
            />
          </div>
          <div ref={treeScrollRef} className="flex-1 overflow-y-auto overflow-x-hidden">
            {!loadedFile ? (
              <div className="flex flex-col items-center justify-center h-full gap-2 text-vs-dim">
                <span className="text-3xl">📂</span>
                <span className="text-xs text-center px-4">
                  Open an APK, DEX, or JAR file to explore its structure
                </span>
              </div>
            ) : tree.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <span className="text-xs text-vs-dim italic">Loading tree…</span>
              </div>
            ) : (
              <TreeView
                nodes={treeWithEmbedded}
                expandedNodes={expandedNodes}
                selectedNodeId={selectedNode?.id}
                filterQuery={filterQuery}
                onToggleExpand={toggleExpand}
                onSelectNode={selectNode}
                onOpenNode={openNode}
              />
            )}
          </div>
        </>
      )}

      {/* ── Project tab ── manage all loaded APKs */}
      {activeTab === "project" && (
        <>
          {/* Top action bar */}
          <div className="px-2 py-1.5 border-b border-vs-border flex-shrink-0 flex items-center gap-1">
            <button
              className="px-2 py-1 rounded text-xs bg-vs-accent text-white hover:bg-vs-accent/80 flex-1"
              onClick={async () => {
                const path = await api.openFileDialog();
                if (path) await addApkToProject(path);
              }}
              title="Open another APK and add it to the project"
            >
              + Add APK
            </button>
            <button
              className="px-2 py-1 rounded text-xs border border-vs-border text-vs-muted hover:text-vs-error hover:border-vs-error"
              onClick={() => {
                const cachedCount = slots.filter((s) => s.isCached).length;
                if (cachedCount === 0) return;
                if (confirm(`Remove ${cachedCount} extracted APK${cachedCount === 1 ? "" : "s"} from cache?`)) {
                  void clearExtractedCache();
                }
              }}
              title="Remove all extracted/decrypted APKs from the cache"
              disabled={!slots.some((s) => s.isCached)}
            >
              Clear cache
            </button>
          </div>

          {/* Slot list — top-level slots first, extracted children indented under them */}
          <div className="flex-1 overflow-y-auto">
            {slots.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-full gap-2 text-vs-dim p-4">
                <span className="text-3xl">📦</span>
                <span className="text-xs text-center">
                  No APKs loaded. Use <strong>+ Add APK</strong> above or open one
                  from the file menu.
                </span>
              </div>
            ) : (
              <div className="flex flex-col">
                {slots.filter((s) => !s.parentId).map((slot) => {
                  const children = slots.filter((c) => c.parentId === slot.id);
                  return (
                    <React.Fragment key={slot.id}>
                      <SlotRow
                        slot={slot}
                        depth={0}
                        isActive={activeSlotId === slot.id}
                        isCompare={compareSlotId === slot.id}
                        onSetActive={() => void setActiveSlot(slot.id)}
                        onSetCompare={() =>
                          void setCompareSlot(compareSlotId === slot.id ? null : slot.id)
                        }
                        onForceReload={() => void forceReloadSlot(slot.id)}
                        onRemove={() => {
                          if (confirm(`Remove "${slot.displayName}" from the project?`)) {
                            void removeSlot(slot.id);
                          }
                        }}
                        onAddSplit={async () => {
                          const path = await api.openFileDialog();
                          if (path) await addSplitToSlot(slot.id, path);
                        }}
                      />
                      {children.map((child) => (
                        <SlotRow
                          key={child.id}
                          slot={child}
                          depth={1}
                          isActive={activeSlotId === child.id}
                          isCompare={compareSlotId === child.id}
                          onSetActive={() => void setActiveSlot(child.id)}
                          onSetCompare={() =>
                            void setCompareSlot(compareSlotId === child.id ? null : child.id)
                          }
                          onForceReload={() => void forceReloadSlot(child.id)}
                          onRemove={() => {
                            if (confirm(`Remove "${child.displayName}" from the project?`)) {
                              void removeSlot(child.id);
                            }
                          }}
                          onAddSplit={async () => {
                            const path = await api.openFileDialog();
                            if (path) await addSplitToSlot(child.id, path);
                          }}
                        />
                      ))}
                    </React.Fragment>
                  );
                })}
              </div>
            )}
          </div>

          {/* Dynamic loaders section — collapsible. Static scan, on-demand. */}
          {activeSlotId && (
            <div className="border-t border-vs-border flex-shrink-0 max-h-72 overflow-y-auto">
              <div className="flex items-center justify-between px-2 py-1.5 bg-vs-elevated/40">
                <span className="text-xs font-semibold text-vs-muted uppercase tracking-wider">
                  Dynamic Loaders
                  {dexLoaderSites.length > 0 && (
                    <span className="ml-1 text-vs-accent">({dexLoaderSites.length})</span>
                  )}
                </span>
                <button
                  className="px-2 py-0.5 rounded text-[10px] border border-vs-border text-vs-muted hover:text-vs-accent hover:border-vs-accent disabled:opacity-50 disabled:cursor-not-allowed"
                  onClick={() => void analyzeDexLoaders()}
                  disabled={isAnalyzingDexLoaders}
                  title="Static scan for DexClassLoader / InMemoryDexClassLoader / PathClassLoader sites"
                >
                  {isAnalyzingDexLoaders ? "Scanning…" : "Scan"}
                </button>
              </div>

              {dexLoaderSites.length > 0 ? (
                <div className="flex flex-col">
                  {dexLoaderSites.map((site, i) => (
                    <DexLoaderRow
                      key={`${site.callerClass}:${site.codepoint}:${i}`}
                      site={site}
                      onOpenCaller={() => {
                        navigateToMember(site.callerClass, site.callerMethod.split("(")[0]);
                      }}
                      onTraceChain={() => {
                        // Pre-fill the find-exec panel with the byte-source method
                        // and switch to the EXECUTION tab so the user can run it.
                        const firstWithArg = site.byteSources.find((bs) => bs.argument);
                        const target = firstWithArg
                          ? firstWithArg.methodRef.split("(")[0]
                          : `${site.callerClass}->${site.callerMethod.split("(")[0]}`;
                        setExecSignature(target);
                        setActiveBottomTab("EXECUTION");
                        void findAndExec();
                      }}
                    />
                  ))}
                </div>
              ) : (
                <div className="px-2 py-2 text-[11px] text-vs-dim italic">
                  {isAnalyzingDexLoaders
                    ? "Analysing…"
                    : 'Click "Scan" to find DexClassLoader sites in the active slot.'}
                </div>
              )}
            </div>
          )}

          {/* Cache dir footer */}
          {cacheDir && (
            <div className="px-2 py-1 border-t border-vs-border text-[10px] text-vs-dim font-mono truncate"
                 title={cacheDir}>
              📁 {cacheDir}
            </div>
          )}
        </>
      )}

      {/* ── Diff tab ── */}
      {activeTab === "diff" && (
        <>
          {/* Header with APK info */}
          <div className="px-2 py-1.5 border-b border-vs-border flex-shrink-0 flex flex-col gap-1">
            <div className="flex items-center gap-1 text-xs text-vs-muted">
              <span className="text-vs-success font-semibold">A:</span>
              <span className="truncate">{loadedFile?.split(/[\\/]/).pop() ?? "—"}</span>
            </div>
            <div className="flex items-center gap-1 text-xs text-vs-muted">
              <span className="text-vs-error font-semibold">B:</span>
              <span className="truncate">{loadedFileB?.split(/[\\/]/).pop() ?? "—"}</span>
            </div>
          </div>
          {/* Diff filter */}
          <div className="px-2 py-1.5 border-b border-vs-border flex-shrink-0">
            <input
              type="text"
              value={diffFilter}
              autoCorrect="off"
              autoCapitalize="none"
              spellCheck={false}
              onChange={(e) => setDiffFilter(e.target.value)}
              placeholder="Filter diff…"
              className="w-full bg-vs-bg border border-vs-border rounded px-2 py-1 text-xs text-vs-text placeholder:text-vs-dim focus:outline-none focus:border-vs-accent"
            />
          </div>
          <div className="flex-1 overflow-y-auto overflow-x-hidden">
            {!loadedFileB ? (
              <div className="flex flex-col items-center justify-center h-full gap-2 text-vs-dim px-4">
                <span className="text-3xl">⚖️</span>
                <span className="text-xs text-center">
                  Load a comparison APK via the <strong className="text-vs-text">DIFF</strong> tab in the bottom panel
                </span>
              </div>
            ) : diffTree.length === 0 ? (
              <div className="flex items-center justify-center h-full">
                <span className="text-xs text-vs-dim italic">Computing diff…</span>
              </div>
            ) : (
              <TreeView
                nodes={diffTree}
                expandedNodes={expandedNodes}
                selectedNodeId={selectedNode?.id}
                filterQuery={diffFilter}
                onToggleExpand={toggleExpand}
                onSelectNode={selectNode}
                onOpenNode={handleDiffNodeOpen}
              />
            )}
          </div>
        </>
      )}
    </div>
  );
};

export default LeftPanel;
