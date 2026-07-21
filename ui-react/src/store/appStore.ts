import { create } from "zustand";
import { api, isTauri } from "../api/adapter";
import type {
  TreeNode,
  CodeTab,
  LogEntry,
  LogLevel,
  Language,
  XRef,
  SearchResult,
  RunResult,
  ExecResult,
  DeobfReplacement,
  MethodRename,
  CallGraphResult,
  MethodCfgResult,
  ResourceEntry,
  NodeKind,
  ScriptRunResult,
  ScriptRunEntry,
  AppSettings,
  SlotSummary,
  DexLoaderSite,
  ScriptIntrospection,
  ScriptInfo,
  DeobfMark,
  DeobfSite,
  DeobfBulkResult,
} from "../api/types";
import { DEFAULT_SETTINGS } from "../api/types";
import { persistGet, persistGetSync, persistSet } from "../utils/persistentStore";
import { flattenTreeByPackage } from "../utils/tree";
import { embeddedGroupNode, parseEmbeddedNodeId, embeddedAncestorIds } from "../utils/embedded";

/** One element of the `deobf_run_specific_sites` request — a single call
 *  site to execute the deobfuscator at. Derived from the API binding so it
 *  never drifts. */
type DeobfSiteRequest = Parameters<typeof api.deobfRunSpecificSites>[0][number];

// ─── Per-slot snapshot ───────────────────────────────────────────────────────

/** Frontend-only per-slot state. Snapshotted into the store's `slotFrontendStates`
 *  map when the user switches active slots, restored on switch-back. Persisted
 *  to localStorage as part of the cache so it survives app restarts. */
export interface SlotFrontendState {
  openTabs: CodeTab[];
  activeTabId: string | null;
  activeLanguage: Language;
  /** Set serialised as array. */
  expandedNodes: string[];
  selectedNode: TreeNode | null;
  selectedLine: number | null;
  /** Set serialised as array. */
  appliedDeobf: string[];
  deobfReplacements: Record<string, DeobfReplacement>;
  /** Cached static call-site listing per marked method (key:
   *  `deobfMarkKey`). Persisted so the DEOBFUSCATION tab can show each
   *  method's sites and "x / y deobfuscated" status on reload without
   *  re-scanning. Optional for back-compat with snapshots written before
   *  this field existed. */
  deobfSitesByMark?: Record<string, DeobfSite[]>;
  /** Cached per-call-site deobfuscation results (key: `deobfSiteKey`).
   *  Only sites that were ACTUALLY deobfuscated (no error) are persisted,
   *  so reopening the APK shows the resolved values without re-running the
   *  VM. Optional for back-compat. */
  deobfSiteResults?: Record<string, ExecResult>;
  renames: MethodRename[];
  /** @deprecated retained for back-compat with old per-slot snapshots; the
   *  active script is now global (see store.scriptContent / scripts list). */
  scriptCode?: string;
  scriptOutput: ScriptRunResult | null;
  execSignature: string;
  execArgs: string;
  /** Per-call instruction budget passed to `run_method` / `find_exec`.
   *  Default 5,000,000 — bump for slow deobfuscators (multi-MB string tables,
   *  AES-CBC chains, PBKDF2). The bottom-panel Execution row exposes this. */
  execInstrLimit: number;
  execResult: RunResult | null;
  findExecResults: ExecResult[];
  filterQuery: string;
}

// ─── State shape ─────────────────────────────────────────────────────────────

interface StoreState {
  // File
  loadedFile: string | null;
  isLoading: boolean;

  // Tree
  tree: TreeNode[];
  /** Lazily-loaded children for each expanded embedded APK, keyed by the
   *  embedded-apk tree-node id. Tagged with the child slot id. */
  embeddedTrees: Record<string, TreeNode[]>;
  /** Embedded-apk node ids currently being parsed (for a loading indicator). */
  embeddedLoading: Set<string>;
  /** child slot id → embedded-apk tree-node id, so navigation can re-expand a
   *  subtree on demand (survives slot switches; cleared on a fresh file load). */
  embeddedSlotMap: Record<string, string>;
  expandedNodes: Set<string>;
  filterQuery: string;
  /** A pending "scroll this tree node into view" request. Bumped (new
   *  object identity) by `revealInTree`; the LeftPanel watches it and
   *  scrolls the matching row into view after the ancestors expand. */
  revealRequest: { nodeId: string; nonce: number } | null;

  // Tabs
  openTabs: CodeTab[];
  activeTabId: string | null;

  // Selection
  selectedNode: TreeNode | null;
  activeLanguage: Language;

  // Right panel
  xrefs: XRef[];
  /** True while `loadXrefsForMethod` is in flight. */
  isXrefsLoading: boolean;
  /** Method whose xrefs are currently displayed (or being loaded). Set by
   *  `loadXrefsForMethod`, used by the XRefs panel header so an empty result
   *  is clearly attributed instead of looking like nothing happened. */
  xrefsTarget: { className: string; methodName: string } | null;
  callGraph: CallGraphResult | null;
  isCallGraphLoading: boolean;
  cfgResult: MethodCfgResult | null;
  isCfgLoading: boolean;
  activeRightTab: "INFO" | "XREFS" | "CFG" | "RUN" | "SCRIPT";
  showFlowGraph: boolean;
  toggleFlowGraph: () => void;

  // Script pane — multi-script library backed by .py files in <cache>/scripts/.
  /** Live editor buffer for the active script. Mirrors the on-disk file with
   *  a debounced write. */
  scriptContent: string;
  /** All saved scripts in the on-disk library. */
  scripts: ScriptInfo[];
  /** Filename of the currently-active script (key into `scripts`). */
  activeScriptName: string | null;
  scriptOutput: ScriptRunResult | null;
  /** Rolling history of past script runs (newest first). Capped at
   *  `SCRIPT_HISTORY_MAX` to bound memory + render cost; older entries
   *  fall off silently. Lives alongside `scriptOutput` (which always
   *  points at history[0]) so existing consumers keep working. */
  scriptOutputHistory: ScriptRunEntry[];
  /** Clear every entry in `scriptOutputHistory` (and `scriptOutput`). */
  clearScriptHistory: () => void;
  /** Remove a single entry from `scriptOutputHistory` by its `id`. If the
   *  removed entry was the latest, `scriptOutput` snaps to the new head. */
  removeScriptHistoryEntry: (id: string) => void;
  isScriptRunning: boolean;
  killScript: () => Promise<void>;
  isLoadingScripts: boolean;

  // Script library actions
  loadScripts:        () => Promise<void>;
  setActiveScript:    (name: string) => Promise<void>;
  setScriptContent:   (content: string) => void;     // updates buffer + debounced save
  saveActiveScript:   () => Promise<void>;
  createScript:       (name: string, initialContent?: string) => Promise<void>;
  deleteScript:       (name: string) => Promise<void>;
  renameScript:       (oldName: string, newName: string) => Promise<void>;
  duplicateScript:    (name: string) => Promise<void>;
  runScript:          () => Promise<void>;

  // Popout windows
  // Settings is still an in-app overlay; the search window is now a separate
  // OS window opened via `api.openSearchWindow()` — no store state needed for it.
  showSettingsWindow: boolean;
  openSettingsWindow: () => void;
  closeSettingsWindow: () => void;
  toggleSettingsWindow: () => void;

  // App settings
  settings: AppSettings;
  updateSetting: <K extends keyof AppSettings>(key: K, value: AppSettings[K]) => void;
  /** Re-fetch every open Java tab using the current settings. Called by
   *  `updateSetting` when a decompile-affecting setting changes. */
  refreshOpenJavaTabs: () => Promise<void>;
  resetSettings: () => void;
  clearDeobf: () => void;

  // Code navigation
  selectedLine: number | null;
  setSelectedLine: (line: number | null) => void;

  // Bottom panel
  activeBottomTab: "LOGS" | "EXECUTION" | "DEOBFUSCATION" | "DIFF";
  logs: LogEntry[];
  searchQuery: string;
  searchResults: SearchResult[];
  /** Slot the current results were searched in (an embedded child slot, or
   *  undefined for the active slot). Used to navigate hits to the right slot. */
  searchSlotId?: string;
  isSearching: boolean;
  execSignature: string;
  execArgs: string;
  /** Per-call instruction budget passed to `run_method` / `find_exec`.
   *  Default 5,000,000 — bump for slow deobfuscators (multi-MB string tables,
   *  AES-CBC chains, PBKDF2). The bottom-panel Execution row exposes this. */
  execInstrLimit: number;
  execResult: RunResult | null;
  isRunning: boolean;
  findExecResults: ExecResult[];
  isFindRunning: boolean;

  // ── Deobfuscation marks (DEOBFUSCATION bottom-bar tab) ────────────
  //
  // Persisted server-side per APK (see Slot.deobf_marks). The fields
  // below are a cached projection: `deobfMarks` mirrors the backend
  // set, and the two maps cache lazy data we only fetch on expand /
  // run actions. Both maps are keyed by `${className}#${methodName}`
  // (the same form `deobfMarkKey` constructs).
  deobfMarks: DeobfMark[];
  /** Per-mark static call-site listing. Loaded on row expand and
   *  refreshed on demand; never auto-recomputed. */
  deobfSitesByMark: Record<string, DeobfSite[]>;
  /** Per-mark execution results (one ExecResult per call site).
   *  Loaded by "Run all sites for this method" or "Deobfuscate All". */
  deobfResultsByMark: Record<string, ExecResult[]>;
  /** Set of method-keys currently expanded in the tab UI. Persisted in
   *  the store so collapse/re-expand is sticky during a session. */
  deobfExpandedMarks: Set<string>;
  /** Methods whose sites are currently being scanned (debounce flag). */
  deobfLoadingSites: Set<string>;
  /** Methods whose call sites are currently being executed. */
  deobfRunningMarks: Set<string>;
  /** True while `deobfRunAll` is in flight. */
  deobfRunningAll: boolean;
  /** Worker count passed to the backend's rayon-driven parallel
   *  deobf path. `0` = "let the backend pick" (rayon's default
   *  thread pool = `num_cpus`). `1` = sequential. Higher values
   *  give the chunker more shards but the actual parallelism is
   *  capped by rayon's global pool. Persisted via saveCache. */
  deobfNumThreads: number;
  setDeobfNumThreads: (n: number) => void;
  /** Substring filter applied to each call site's caller class
   *  in the DEOBFUSCATION tab. Empty = show everything. Match is
   *  case-insensitive and uses `/` as the package separator, so
   *  `com/foo`, `foo`, and `Foo` all match `com/example/FooBar`. */
  deobfFilter: string;
  setDeobfFilter: (q: string) => void;
  /** Per-call-site result map. Keyed by
   *  `${markKey}|${callerClass}|${offset}` so single-site runs (the
   *  ▶ button on a row) and bulk runs (Deobfuscate Shown/All) all
   *  populate the SAME cache. The mark-level `deobfResultsByMark`
   *  is still kept up to date by the bulk paths for backwards
   *  compatibility, but per-site lookups should prefer this map. */
  deobfSiteResults: Record<string, ExecResult>;
  /** Set of site-result keys currently in-flight (for spinner state
   *  on per-row ▶). Distinct from deobfRunningMarks because one
   *  ▶ click is much finer-grained than per-method runs. */
  deobfRunningSites: Set<string>;
  /** True while the toolbar's "Deobfuscate Shown" is in flight. */
  deobfRunningShown: boolean;
  /** Set by `stopDeobf` to request cancellation of an in-flight deobf
   *  run. The batched run loops check it between batches and stop at the
   *  next boundary (already-completed sites stay cached). Cleared when a
   *  run starts and when it finishes. */
  deobfStopRequested: boolean;

  // Resources
  resources: ResourceEntry[];

  // Entry names (raw ZIP paths)
  entryNames: string[];
  entryNamesB: string[];

  // Diff tree
  diffTree: TreeNode[];

  // Deobfuscation
  deobfReplacements: Record<string, DeobfReplacement>;
  appliedDeobf: Set<string>;

  // Method renames (persisted to localStorage)
  renames: MethodRename[];

  // ── Multi-APK project ───────────────────────────────────────────────────────
  /** All loaded APKs (slots). One can be active and one can be the diff target. */
  slots: SlotSummary[];
  /** Id of the slot whose contents back the centre/sidebar/etc views. */
  activeSlotId: string | null;
  /** Id of the slot used as the diff "B" side (formerly the slot-B blob). */
  compareSlotId: string | null;
  /** Resolved cache directory (`<os cache>/project_platypus`). */
  cacheDir: string;
  /** True once `initProject()` has resolved at least once. */
  isProjectInitialized: boolean;
  /** Per-slot snapshot of frontend-only state (open tabs, applied deobf,
   *  renames, script code, etc.). The flat fields above mirror whichever entry
   *  here corresponds to `activeSlotId`. On `setActiveSlot`, the current flat
   *  fields are written back to the old slot's entry, then the new slot's
   *  entry is hydrated into the flat fields. */
  slotFrontendStates: Record<string, SlotFrontendState>;

  // ── Slot B (comparison APK) + Diff ──────────────────────────────────────────
  loadedFileB: string | null;
  treeB: TreeNode[];
  isLoadingB: boolean;
  /** "deobf" = deobfuscation diff; "apk" = side-by-side APK diff */
  diffMode: "deobf" | "apk";
  diffClassA: string | null;
  diffClassB: string | null;
  diffCodeA: string | null;
  diffCodeB: string | null;
  isDiffLoading: boolean;

  // ── Project actions ─────────────────────────────────────────────────────────
  initProject: () => Promise<void>;
  refreshProject: () => Promise<void>;
  addApkToProject: (path: string, parentId?: string) => Promise<void>;
  addSplitToSlot: (slotId: string, splitPath: string) => Promise<void>;
  removeSlot: (slotId: string) => Promise<void>;
  setActiveSlot: (slotId: string) => Promise<void>;
  setCompareSlot: (slotId: string | null) => Promise<void>;
  forceReloadActiveSlot: () => Promise<void>;
  forceReloadSlot: (slotId: string) => Promise<void>;
  clearExtractedCache: () => Promise<void>;
  loadEmbeddedAsSlot: (parentSlotId: string, entryPath: string) => Promise<void>;
  // Dex-loader trace assist
  dexLoaderSites: DexLoaderSite[];
  isAnalyzingDexLoaders: boolean;
  analyzeDexLoaders: () => Promise<void>;

  // Script-pane completions (introspection of the platypus Python module)
  scriptIntrospection: ScriptIntrospection | null;
  /** Set when the introspection script ran but couldn't import platypus. */
  scriptIntrospectionUnavailable: boolean;
  isFetchingScriptCompletions: boolean;
  fetchScriptCompletions: () => Promise<void>;

  // Actions
  loadFile: (path: string) => Promise<void>;
  buildDiffTree: () => void;
  loadFileObject: (file: File) => Promise<void>;
  loadFileB: (path: string) => Promise<void>;
  loadFileBObject: (file: File) => Promise<void>;
  setDiffMode: (mode: "deobf" | "apk") => void;
  setDiffClassA: (className: string | null) => void;
  setDiffClassB: (className: string | null) => void;
  loadDiff: () => Promise<void>;
  openNode: (node: TreeNode) => Promise<void>;
  selectNode: (node: TreeNode) => void;
  toggleExpand: (nodeId: string) => void;
  /** Parse an embedded APK/JAR/DEX (inside `parentSlotId`'s ZIP) into a
   *  non-active child slot and expand it inline. `nodeId` is its tree node. */
  expandEmbedded: (nodeId: string, entryPath: string, parentSlotId?: string) => Promise<void>;
  /** Ensure the inline subtree for a child slot is loaded (parse on demand),
   *  so navigation/reveal into a not-yet-expanded embedded APK still works. */
  ensureEmbeddedLoaded: (slotId?: string) => Promise<void>;
  /** Reveal a class in the left treeview: expand its ancestor folders,
   *  select it, and scroll it into view. Used by navigation (XREF clicks,
   *  search results, deobf jumps) so following a reference also surfaces
   *  the target in the tree. No-op when the class isn't in the tree. */
  revealInTree: (className: string, slotId?: string) => void;
  setFilterQuery: (q: string) => void;
  setActiveTab: (tabId: string) => void;
  reorderTabs: (fromIndex: number, toIndex: number) => void;
  closeTab: (tabId: string) => void;
  closeOtherTabs: (tabId: string) => void;
  closeAllTabs: () => void;
  setActiveLanguage: (lang: Language) => void;
  setActiveRightTab: (tab: "INFO" | "XREFS" | "CFG" | "RUN" | "SCRIPT") => void;
  loadCallGraph: (className: string, methodName: string, slotId?: string) => Promise<void>;
  loadCfg: (className: string, methodName: string, slotId?: string) => Promise<void>;
  loadXrefsForMethod: (className: string, methodName: string, slotId?: string) => void;
  setActiveBottomTab: (tab: "LOGS" | "EXECUTION" | "DEOBFUSCATION" | "DIFF") => void;
  addLog: (level: LogLevel, message: string, tag?: string) => void;
  clearLogs: () => void;
  setSearchQuery: (q: string) => void;
  runSearch: () => Promise<void>;
  navigateToSearchResult: (result: SearchResult) => Promise<void>;
  setExecSignature: (sig: string) => void;
  setExecArgs: (args: string) => void;
  setExecInstrLimit: (n: number) => void;
  runMethod: () => Promise<void>;
  findAndExec: () => Promise<void>;
  applyDeobf: (resultIdx: number) => void;
  applyAllDeobf: () => void;
  markAsDeobfuscator: (signature: string) => Promise<void>;

  // ── DEOBFUSCATION tab actions ─────────────────────────────────────
  /** Initial load: pulled from the backend on slot activation and on
   *  startup. Idempotent — callable at any time to re-sync. */
  loadDeobfMarks: () => Promise<void>;
  /** Add a (className, methodName) to the active slot's marks. Both
   *  the L/;-wrapped and stripped forms are accepted for className —
   *  the backend normalises. */
  markDeobf: (className: string, methodName: string) => Promise<void>;
  /** Remove a mark. */
  unmarkDeobf: (className: string, methodName: string) => Promise<void>;
  /** Convenience: true if (className, methodName) is currently marked.
   *  Accepts either L/;-wrapped or stripped className. */
  isDeobfMarked: (className: string, methodName: string) => boolean;
  /** Expand/collapse the per-method site listing in the DEOBFUSCATION
   *  tab. Triggers a lazy `loadDeobfSites` on first expand if the
   *  sites haven't been scanned yet. */
  toggleDeobfExpanded: (className: string, methodName: string) => void;
  /** Scan one mark's call sites. Results are cached per method and
   *  reused until the method is unmarked (see [`unmarkDeobf`]); pass
   *  `force` to bypass the cache and re-scan (the ↻ refresh button),
   *  e.g. after script-driven rewrites change the underlying code. */
  loadDeobfSites: (className: string, methodName: string, force?: boolean) => Promise<void>;
  /** Execute every call site for one marked method. */
  runDeobfForMark: (className: string, methodName: string) => Promise<void>;
  /** Execute every call site for every marked method. */
  runAllDeobfMarks: () => Promise<void>;
  /** Execute ONE specific call site of a marked method (the ▶
   *  button on each site row). Reuses the per-call-site result
   *  cache (`deobfSiteResults`). */
  runDeobfSite: (mark: DeobfMark, site: DeobfSite) => Promise<void>;
  /** Execute every currently-visible call site (after the filter is
   *  applied), in cancellable batches. */
  runDeobfShown: () => Promise<void>;
  /** Request cancellation of any in-flight deobf run. The run stops at
   *  the next batch boundary; results computed so far are kept. */
  stopDeobf: () => void;
  /** @internal Run a list of call-site requests in cancellable batches,
   *  merging each batch's results into `deobfSiteResults` + inline
   *  annotations live. Shared by every run path so they all get live
   *  progress and stop support. */
  runDeobfBatches: (requests: DeobfSiteRequest[]) => Promise<{ stopped: boolean; collected: ExecResult[] }>;
  /** Pure selector — read by the UI to render filtered call sites.
   *  Returns `Map<markKey, DeobfSite[]>` with only the marks/sites
   *  that match the current `deobfFilter`. When the filter is empty
   *  the full `deobfSitesByMark` is returned. */
  filteredDeobfSites: () => Map<string, DeobfSite[]>;
  addRename: (rename: MethodRename) => void;
  removeRename: (className: string, methodName: string) => void;
  clearRenames: () => void;
  saveCache: () => void;
  loadCache: () => Promise<void>;
  navigateToClass: (className: string) => Promise<void>;
  navigateToMember: (classRef: string, memberName: string) => Promise<void>;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Build the cache key used by `deobfSitesByMark` / `deobfResultsByMark` /
 *  `deobfExpandedMarks`. We normalise the className to the same form
 *  the backend stores (no `L`/`;` wrapper) so calls from either the
 *  tree (L-wrapped) or the code-view (stripped) produce equal keys. */
export function deobfMarkKey(className: string, methodName: string): string {
  const norm = className.replace(/^L/, "").replace(/;$/, "");
  return `${norm}#${methodName}`;
}

/** Build a stable replacement key for a deobf result, used as the dictionary
 *  key in `deobfReplacements` and the membership token in `appliedDeobf`.
 *
 *  Same form as the legacy `applyDeobf` path (`{callerClass}:{offset}:{idx}`)
 *  so a result that lands here via the DEOBFUSCATION pane is identical to
 *  one that came via the older `markAsDeobfuscator` flow — the code view
 *  filtering in `buildDeobfList` keys off `(className, key)` and doesn't
 *  care which path produced the entry. */
function deobfReplacementKey(callerClass: string, offset: number, idx: number): string {
  return `${callerClass}:${offset}:${idx}`;
}

/** Normalise a class name to the stripped form used by tab.className
 *  and `node.fullName` in the tree (`com/foo/Bar`, no `L`/`;`). The
 *  backend returns `Lcom/foo/Bar;` (raw dex type_name) but the frontend
 *  stores tabs against the stripped form — without this normalisation,
 *  `buildDeobfList`'s strict-equality filter never matches a
 *  backend-supplied replacement to its caller-class tab, so the inline
 *  annotations never render.
 *
 *  Pure function; idempotent; safe to call on either form.
 */
function normaliseClassName(raw: string): string {
  return raw.replace(/^L/, "").replace(/;$/, "");
}

/** Take a batch of ExecResults from any of the DEOBFUSCATION pane run paths
 *  and merge them into `deobfReplacements` + `appliedDeobf` so the caller
 *  class code views render the inline `/* DEOBF: "..." *\/` annotations.
 *
 *  Without this step, the deobf pane was running the VM, populating
 *  `deobfSiteResults` for its own list display, and stopping there — none
 *  of the resolved values ever reached the centre-panel renderer. The fix
 *  is to call this from every run path (run-mark, run-all, run-site,
 *  run-shown) right after results land.
 *
 *  Returns the updated maps so the caller can fold them into a single
 *  `set(...)` call that also writes its own state, avoiding a double-render.
 */
function applyResultsToReplacements(
  results: ExecResult[],
  currentReplacements: Record<string, DeobfReplacement>,
  currentApplied: Set<string>,
): {
  replacements: Record<string, DeobfReplacement>;
  applied: Set<string>;
  count: number;
} {
  const replacements = { ...currentReplacements };
  const applied = new Set(currentApplied);
  let count = 0;
  results.forEach((r, idx) => {
    if (r.error || !r.resolvedValue) return;
    // Normalise the caller class to the stripped form — see
    // `normaliseClassName` for why. The replacement key MUST use the
    // normalised form too, otherwise idempotency breaks when the same
    // result lands via two different run paths (one with the L; form,
    // one without).
    const normalisedClass = normaliseClassName(r.callerClass);
    const key = deobfReplacementKey(normalisedClass, r.offset, idx);
    if (applied.has(key)) return;
    replacements[key] = {
      original: r.callSite,
      resolved: r.resolvedValue,
      lineIndex: r.offset,
      className: normalisedClass,
    };
    applied.add(key);
    count++;
  });
  return { replacements, applied, count };
}

/** Per-call-site cache key for `deobfSiteResults` / `deobfRunningSites`.
 *  Combines the mark key with the originating callsite's
 *  (callerClass, offset). callerClass collisions across offsets are
 *  impossible (each invoke instruction has a unique codepoint within
 *  its method), so this is a stable identity. */
export function deobfSiteKey(
  className: string,
  methodName: string,
  callerClass: string,
  offset: number,
): string {
  return `${deobfMarkKey(className, methodName)}|${callerClass}|${offset}`;
}

let logIdCounter = 0;

/** Welcome text used as the body of the default `scratch.py` on a fresh
 *  install. Also used to migrate the legacy single-script `cache.scriptCode`
 *  if the on-disk library is empty. */
const DEFAULT_SCRATCH = `# Platypus scripting environment
# Available globals:
#   LOADED_APK  – path to the currently loaded APK (str | None)
#
# Import the project modules normally, e.g.:
#   from vm.vm import VM
#   from dex.dexfile import DexFile
#
# Use print() — output appears below.

print("Hello from Platypus!")
`;

/** Debounce timer for the active-script disk write. Module-level so the
 *  next setScriptContent call coalesces with the previous pending save. */
let scriptSaveTimer: ReturnType<typeof setTimeout> | null = null;
const SCRIPT_SAVE_DEBOUNCE_MS = 750;

/** Cap on the script-output timeline. Each entry holds the full
 *  stdout/stderr plus metadata, so this is the dominant memory cost of
 *  the script pane. 30 is a sweet spot for a typical session — enough
 *  to compare a handful of recent iterations, small enough that the
 *  timeline renders fast even when every entry is expanded. */
const SCRIPT_HISTORY_MAX = 30;

function makeLogId(): string {
  return `log-${Date.now()}-${++logIdCounter}`;
}

function makeTabId(className: string, language: Language, slotId?: string): string {
  return `tab-${slotId ? slotId + ":" : ""}${className}-${language}`;
}

function findNodeById(nodes: TreeNode[], id: string): TreeNode | null {
  for (const node of nodes) {
    if (node.id === id) return node;
    if (node.children) {
      const found = findNodeById(node.children, id);
      if (found) return found;
    }
  }
  return null;
}

// ─── Per-slot state helpers ──────────────────────────────────────────────────

/** Pull the per-slot fields out of the live store state into a snapshot. */
function snapshotFromState(s: StoreState): SlotFrontendState {
  return {
    openTabs:           s.openTabs,
    activeTabId:        s.activeTabId,
    activeLanguage:     s.activeLanguage,
    expandedNodes:      [...s.expandedNodes],
    selectedNode:       s.selectedNode,
    selectedLine:       s.selectedLine,
    appliedDeobf:       [...s.appliedDeobf],
    deobfReplacements:  s.deobfReplacements,
    deobfSitesByMark:   s.deobfSitesByMark,
    // Persist only sites that actually resolved — errored/never-run sites
    // carry no value worth caching and are cheap to re-run on demand.
    deobfSiteResults:   Object.fromEntries(
      Object.entries(s.deobfSiteResults).filter(([, r]) => !r.error),
    ),
    renames:            s.renames,
    // scriptCode dropped — scripts are global now (see `scripts` / `activeScriptName`)
    scriptOutput:       s.scriptOutput,
    execSignature:      s.execSignature,
    execArgs:           s.execArgs,
    execInstrLimit:     s.execInstrLimit,
    execResult:         s.execResult,
    findExecResults:    s.findExecResults,
    filterQuery:        s.filterQuery,
  };
}

/** Defaults for a slot we've never visited before (or after loadFile reset). */
function freshSlotState(activeLanguage: Language): SlotFrontendState {
  return {
    openTabs:           [],
    activeTabId:        null,
    activeLanguage,
    expandedNodes:      [],
    selectedNode:       null,
    selectedLine:       null,
    appliedDeobf:       [],
    deobfReplacements:  {},
    deobfSitesByMark:   {},
    deobfSiteResults:   {},
    renames:            [],
    // scriptCode dropped — scripts are global now (see store.scripts / activeScriptName)
    scriptOutput:       null,
    execSignature:      "",
    execArgs:           "",
    execInstrLimit:     5_000_000,
    execResult:         null,
    findExecResults:    [],
    filterQuery:        "",
  };
}

/** Build a `set()` partial that hydrates the flat fields from a snapshot.
 *  Used on app launch to restore the last session — including the open
 *  tabs the user left behind. For mid-session slot switches use
 *  [`applySnapshotPreserveTabs`] instead, which drops the tab fields
 *  so the centre panel resets cleanly on each switch (users expect
 *  the tab strip to follow the active slot, not silently reopen tabs
 *  from a previous visit to that slot). */
function applySnapshot(snap: SlotFrontendState): Partial<StoreState> {
  return {
    openTabs:           snap.openTabs,
    activeTabId:        snap.activeTabId,
    activeLanguage:     snap.activeLanguage,
    expandedNodes:      new Set(snap.expandedNodes),
    selectedNode:       snap.selectedNode,
    selectedLine:       snap.selectedLine,
    appliedDeobf:       new Set(snap.appliedDeobf),
    deobfReplacements:  snap.deobfReplacements,
    deobfSitesByMark:   snap.deobfSitesByMark ?? {},
    deobfSiteResults:   snap.deobfSiteResults ?? {},
    renames:            snap.renames,
    // snap.scriptCode is intentionally ignored — scripts are global now.
    scriptOutput:       snap.scriptOutput,
    execSignature:      snap.execSignature,
    execArgs:           snap.execArgs,
    execInstrLimit:     snap.execInstrLimit,
    execResult:         snap.execResult,
    findExecResults:    snap.findExecResults,
    filterQuery:        snap.filterQuery,
  };
}

/** Like [`applySnapshot`] but DROPS the tab-related fields. Used by
 *  mid-session slot/APK switches.
 *
 *  The user-visible contract: tabs follow the *active* slot but never
 *  silently come back when you switch to a slot you've visited before.
 *  Persisting deobf replacements / renames / script state across slot
 *  switches is desirable (these are analysis artefacts); persisting the
 *  exact tab strip is not (it surprises users with stale-looking files
 *  from a previous session and obscures the fact that they just switched
 *  contexts).
 *
 *  Also leaves `selectedNode`, `selectedLine`, and `expandedNodes`
 *  alone — these are intrinsically tied to whichever class the user has
 *  open in the centre panel, so they only make sense when tabs are
 *  restored too. */
function applySnapshotPreserveTabs(snap: SlotFrontendState): Partial<StoreState> {
  return {
    activeLanguage:     snap.activeLanguage,
    appliedDeobf:       new Set(snap.appliedDeobf),
    deobfReplacements:  snap.deobfReplacements,
    deobfSitesByMark:   snap.deobfSitesByMark ?? {},
    deobfSiteResults:   snap.deobfSiteResults ?? {},
    renames:            snap.renames,
    scriptOutput:       snap.scriptOutput,
    execSignature:      snap.execSignature,
    execArgs:           snap.execArgs,
    execInstrLimit:     snap.execInstrLimit,
    execResult:         snap.execResult,
    findExecResults:    snap.findExecResults,
    filterQuery:        snap.filterQuery,
  };
}

// ─── Code line finder ────────────────────────────────────────────────────────

function findCodeLine(
  code: string,
  language: Language,
  memberName: string,
  kind: "method" | "field"
): number | null {
  const lines = code.split("\n");

  if (language === "smali") {
    const prefix = kind === "field" ? ".field" : ".method";
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes(prefix) && line.includes(memberName)) {
        return i;
      }
    }
  } else {
    // Java: find the definition line (not a call site)
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const trimmed = line.trim();
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;

      const needle = kind === "method" ? memberName + "(" : memberName;
      const idx = line.indexOf(needle);
      if (idx === -1) continue;

      // Make sure the char immediately before is not '.' (call site: obj.method)
      const charBefore = idx > 0 ? line[idx - 1] : "";
      if (charBefore === ".") continue;

      return i;
    }
  }
  return null;
}

/** Resolve the *rendered* line a search hit lives on.
 *
 *  Instruction-level hits (strings / references) carry the matched smali
 *  instruction verbatim in `snippet`, and smali renders those instructions
 *  literally — so we find the first rendered line that contains the
 *  instruction text. That gives the exact call-site / string line.
 *
 *  For method/field definition hits (or Java, where the smali snippet won't
 *  appear) we fall back to locating the member's definition line. Class hits
 *  return null (jump to the top of the file). */
function findSearchResultLine(
  code: string,
  language: Language,
  result: SearchResult,
): number | null {
  // Try the verbatim-instruction match first (smali string/reference hits).
  if (
    (result.kind === "string" || result.kind === "reference") &&
    result.snippet &&
    language === "smali"
  ) {
    const needle = result.snippet.trim();
    const lines = code.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes(needle)) return i;
    }
  }
  // Fall back to the member definition line.
  if (result.memberName) {
    const kind = result.kind === "field" ? "field" : "method";
    return findCodeLine(code, language, result.memberName, kind);
  }
  return null;
}

// ─── Module-level helpers for resource tree and diff ─────────────────────────

function buildRawEntryTree(entryNames: string[]): TreeNode {
  type Dir = { files: string[]; dirs: Map<string, Dir> };
  const root: Dir = { files: [], dirs: new Map() };

  for (const path of entryNames) {
    if (path.endsWith('/')) continue;
    const parts = path.split('/');
    let cur = root;
    for (let i = 0; i < parts.length - 1; i++) {
      const p = parts[i];
      if (!cur.dirs.has(p)) cur.dirs.set(p, { files: [], dirs: new Map() });
      cur = cur.dirs.get(p)!;
    }
    cur.files.push(parts[parts.length - 1]);
  }

  function toNodes(dir: Dir, prefix: string): TreeNode[] {
    const nodes: TreeNode[] = [];
    for (const [name, sub] of [...dir.dirs.entries()].sort(([a], [b]) => a.localeCompare(b))) {
      nodes.push({
        id: `entry:${prefix}${name}`,
        name,
        kind: 'assets_folder' as NodeKind,
        children: toNodes(sub, `${prefix}${name}/`),
      });
    }
    for (const file of [...dir.files].sort()) {
      nodes.push({
        id: `entry:${prefix}${file}`,
        name: file,
        kind: 'asset' as NodeKind,
        fullName: `${prefix}${file}`,
      });
    }
    return nodes;
  }

  const totalFiles = entryNames.filter(n => !n.endsWith('/')).length;
  return {
    id: 'resources-root',
    name: `Resources (${totalFiles})`,
    kind: 'resources_root' as NodeKind,
    children: toNodes(root, ''),
  };
}

/** Tag every node in `nodes` with `slotId` and namespace its `id` so an
 *  embedded APK's nodes never collide with the active slot's (which share class
 *  names and `entry:`/`resources-root` ids). `fullName` is left intact — it's
 *  the class/entry path used for the slot-scoped read. */
function tagSubtree(nodes: TreeNode[], slotId: string): TreeNode[] {
  return nodes.map((n) => ({
    ...n,
    id: `s:${slotId}:${n.id}`,
    slotId,
    children: n.children ? tagSubtree(n.children, slotId) : undefined,
  }));
}

/** The inline-expanded subtree roots belonging to a child (embedded) slot, or
 *  null if that slot isn't currently expanded in the tree. */
function embeddedRootsForSlot(
  embeddedTrees: Record<string, TreeNode[]>,
  slotId: string,
): TreeNode[] | null {
  for (const kids of Object.values(embeddedTrees)) {
    if (kids.some((k) => k.slotId === slotId)) return kids;
  }
  return null;
}

function flattenClassNames(nodes: TreeNode[]): string[] {
  const out: string[] = [];
  function walk(n: TreeNode) {
    if (n.kind === 'class' && n.fullName) {
      out.push(n.fullName.startsWith('L') && n.fullName.endsWith(';')
        ? n.fullName.slice(1, -1) : n.fullName);
    }
    n.children?.forEach(walk);
  }
  nodes.forEach(walk);
  return out;
}

function computeDiffTree(
  tree: TreeNode[], treeB: TreeNode[],
  entryNames: string[], entryNamesB: string[]
): TreeNode[] {
  const classesA = new Set(flattenClassNames(tree));
  const classesB = new Set(flattenClassNames(treeB));

  const addedClasses   = [...classesB].filter(c => !classesA.has(c)).sort();
  const removedClasses = [...classesA].filter(c => !classesB.has(c)).sort();
  const commonClasses  = [...classesA].filter(c => classesB.has(c)).sort();

  const skipFile = (n: string) => n.endsWith('/') || n === 'resources.arsc' || n.endsWith('.dex');
  const resA = new Set(entryNames.filter(n => !skipFile(n)));
  const resB = new Set(entryNamesB.filter(n => !skipFile(n)));

  const addedRes   = [...resB].filter(r => !resA.has(r)).sort();
  const removedRes = [...resA].filter(r => !resB.has(r)).sort();
  const commonRes  = [...resA].filter(r => resB.has(r)).sort();

  const mkSection = (id: string, label: string, items: string[], kind: NodeKind): TreeNode => ({
    id,
    name: `${label} (${items.length})`,
    kind: 'diff_section' as NodeKind,
    children: items.map(item => ({
      id: `${id}:${item}`,
      name: item.split('/').pop() ?? item,
      kind,
      fullName: item,
    })),
  });

  return [
    mkSection('diff:code:added',    'Code Added (A→B)',         addedClasses,   'diff_added'    as NodeKind),
    mkSection('diff:code:removed',  'Code Removed (A→B)',       removedClasses, 'diff_removed'  as NodeKind),
    mkSection('diff:code:modified', 'Code Modified (A→B)',      commonClasses,  'diff_modified' as NodeKind),
    mkSection('diff:res:added',     'Resources Added (A→B)',    addedRes,       'diff_added'    as NodeKind),
    mkSection('diff:res:removed',   'Resources Removed (A→B)',  removedRes,     'diff_removed'  as NodeKind),
    mkSection('diff:res:modified',  'Resources Modified (A→B)', commonRes,      'diff_modified' as NodeKind),
  ];
}

// ─── Store ───────────────────────────────────────────────────────────────────

export const useAppStore = create<StoreState>((set, get) => ({
  // ── Initial state ──
  loadedFile: null,
  isLoading: false,
  tree: [],
  embeddedTrees: {},
  embeddedLoading: new Set(),
  embeddedSlotMap: {},
  expandedNodes: new Set(),
  filterQuery: "",
  revealRequest: null,
  openTabs: [],
  activeTabId: null,
  selectedNode: null,
  activeLanguage: "java",
  xrefs: [],
  isXrefsLoading: false,
  xrefsTarget: null,
  callGraph: null,
  isCallGraphLoading: false,
  cfgResult: null,
  isCfgLoading: false,
  activeRightTab: "INFO",
  showFlowGraph: false,
  selectedLine: null,
  showSettingsWindow: false,
  settings: DEFAULT_SETTINGS,

  scriptContent: "",
  scripts: [],
  activeScriptName: null,
  scriptOutput: null,
  scriptOutputHistory: [],
  isScriptRunning: false,
  isLoadingScripts: false,
  activeBottomTab: "LOGS",
  logs: [],
  searchQuery: "",
  searchResults: [],
  isSearching: false,
  execSignature: "",
  execArgs: "",
  execInstrLimit: 5_000_000,
  execResult: null,
  isRunning: false,
  findExecResults: [],
  isFindRunning: false,
  // Deobfuscation marks state — all empty until `loadDeobfMarks()`
  // runs (kicked off after `initProject` completes and on slot
  // switches).
  deobfMarks: [],
  deobfSitesByMark: {},
  deobfResultsByMark: {},
  deobfExpandedMarks: new Set(),
  deobfLoadingSites: new Set(),
  deobfRunningMarks: new Set(),
  deobfRunningAll: false,
  // 0 = use rayon's default thread pool (typically num_cpus). The
  // user can override from the DEOBFUSCATION tab toolbar.
  deobfNumThreads: 0,
  // Filter applied to call-site rows in the DEOBFUSCATION tab.
  // Empty = show all.
  deobfFilter: "",
  deobfSiteResults: {},
  deobfRunningSites: new Set(),
  deobfRunningShown: false,
  deobfStopRequested: false,
  deobfReplacements: {},
  appliedDeobf: new Set(),
  renames: [],
  resources: [],
  entryNames: [],
  entryNamesB: [],
  diffTree: [],

  // Multi-APK project
  slots: [],
  activeSlotId: null,
  compareSlotId: null,
  cacheDir: "",
  isProjectInitialized: false,
  slotFrontendStates: {},
  dexLoaderSites: [],
  isAnalyzingDexLoaders: false,
  scriptIntrospection: null,
  scriptIntrospectionUnavailable: false,
  isFetchingScriptCompletions: false,

  // Slot B / Diff
  loadedFileB: null,
  treeB: [],
  isLoadingB: false,
  diffMode: "apk",
  diffClassA: null,
  diffClassB: null,
  diffCodeA: null,
  diffCodeB: null,
  isDiffLoading: false,

  // ── Project / multi-APK actions ─────────────────────────────────────────
  // The backend persists slot metadata to `<cache>/project.json` and rehydrates
  // it on every app start. The store mirrors the backend's project snapshot
  // and triggers `loadFile()` for the active slot to populate the existing
  // single-slot view state (tree, manifest, etc.).

  initProject: async () => {
    try {
      const snap = await api.projectInit();
      set({
        slots: snap.slots,
        activeSlotId: snap.activeSlotId,
        compareSlotId: snap.compareSlotId,
        cacheDir: snap.cacheDir,
        isProjectInitialized: true,
      });
      // If a slot was restored, re-populate the existing single-slot view…
      const active = snap.slots.find((s) => s.id === snap.activeSlotId);
      if (active) {
        await get().loadFile(active.basePath);
        // …then restore any per-slot frontend state that was saved with the
        // last session (open tabs, applied deobf, renames, script code, etc).
        const saved = get().slotFrontendStates[active.id];
        if (saved) set(applySnapshot(saved));
        // Pull the persisted deobf marks for this slot (Slot.deobf_marks
        // in project.json). Fire-and-forget; UI just shows empty until
        // the marks arrive.
        void get().loadDeobfMarks();
      }
    } catch (e) {
      get().addLog("ERROR", `Failed to initialise project: ${(e as Error).message}`, "Project");
      set({ isProjectInitialized: true });   // unblock UI even on failure
    }
  },

  refreshProject: async () => {
    const snap = await api.projectListSlots();
    set({
      slots: snap.slots,
      activeSlotId: snap.activeSlotId,
      compareSlotId: snap.compareSlotId,
      cacheDir: snap.cacheDir,
    });
  },

  addApkToProject: async (path: string, parentId?: string) => {
    // Snapshot the currently-active slot's frontend state before we navigate away.
    const oldId = get().activeSlotId;
    if (oldId) {
      const snap = snapshotFromState(get());
      set((s) => ({ slotFrontendStates: { ...s.slotFrontendStates, [oldId]: snap } }));
    }
    const snap = await api.projectAddApk(path, parentId);
    set({
      slots: snap.slots,
      activeSlotId: snap.activeSlotId,
      compareSlotId: snap.compareSlotId,
      cacheDir: snap.cacheDir,
    });
    // Defensive reset — same reasoning as setActiveSlot step 3. Per-slot
    // analysis state (deobfReplacements / renames / appliedDeobf) is
    // cleared too so it doesn't leak into the new slot if there's no
    // prior snapshot to apply below.
    set({
      openTabs: [],
      activeTabId: null,
      selectedNode: null,
      selectedLine: null,
      expandedNodes: new Set(),
      // Drop any inline-expanded embedded-APK subtrees from the previous slot.
      embeddedTrees: {},
      embeddedLoading: new Set(),
      deobfReplacements: {},
      appliedDeobf: new Set(),
      // Reset per-slot deobf caches so a slot with no saved snapshot
      // doesn't inherit the previous slot's call sites / resolved values.
      deobfSitesByMark: {},
      deobfResultsByMark: {},
      deobfSiteResults: {},
      deobfExpandedMarks: new Set(),
      renames: [],
    });
    // Backend already set the new slot active — refresh the centre view…
    const active = snap.slots.find((s) => s.id === snap.activeSlotId);
    if (active) await get().loadFile(active.basePath);
    // …and restore prior analysis state (deobf / renames / script) if
    // we've seen this slot before (e.g. the same APK was added and
    // removed in this session). Tabs are NOT restored — see setActiveSlot
    // step 4 for the rationale.
    if (active) {
      const saved = get().slotFrontendStates[active.id];
      if (saved) set(applySnapshotPreserveTabs(saved));
    }
  },

  addSplitToSlot: async (slotId: string, splitPath: string) => {
    const snap = await api.projectAddSplit(slotId, splitPath);
    set({
      slots: snap.slots,
      activeSlotId: snap.activeSlotId,
      compareSlotId: snap.compareSlotId,
    });
    // If the split was added to the active slot, refresh the view.
    if (slotId === snap.activeSlotId) {
      const active = snap.slots.find((s) => s.id === slotId);
      if (active) await get().loadFile(active.basePath);
    }
  },

  removeSlot: async (slotId: string) => {
    const wasActive = get().activeSlotId === slotId;
    // If we're removing the active slot, no point snapshotting its state.
    // For a non-active removal, snapshot the active slot's state first so any
    // pending edits aren't lost across the slot-list mutation.
    if (!wasActive) {
      const oldId = get().activeSlotId;
      if (oldId) {
        const snap = snapshotFromState(get());
        set((s) => ({ slotFrontendStates: { ...s.slotFrontendStates, [oldId]: snap } }));
      }
    }
    const snap = await api.projectRemoveSlot(slotId);
    // Drop the removed slot's frontend state.
    set((s) => {
      const rest = { ...s.slotFrontendStates };
      delete rest[slotId];
      return {
        slots: snap.slots,
        activeSlotId: snap.activeSlotId,
        compareSlotId: snap.compareSlotId,
        slotFrontendStates: rest,
      };
    });
    if (wasActive) {
      // Same defensive tab + analysis-state reset as
      // setActiveSlot/addApkToProject — when the active slot is
      // removed and the UI auto-switches to a sibling, the user
      // expects a clean slate (no leftover tabs, deobf, renames)
      // unless the sibling has its own saved snapshot.
      set({
        openTabs: [],
        activeTabId: null,
        selectedNode: null,
        selectedLine: null,
        expandedNodes: new Set(),
        deobfReplacements: {},
        appliedDeobf: new Set(),
        // Reset per-slot deobf caches so a slot with no saved snapshot
        // doesn't inherit the previous slot's call sites / resolved values.
        deobfSitesByMark: {},
        deobfResultsByMark: {},
        deobfSiteResults: {},
        deobfExpandedMarks: new Set(),
        renames: [],
      });
      const active = snap.slots.find((s) => s.id === snap.activeSlotId);
      if (active) {
        await get().loadFile(active.basePath);
        // Restore the new active slot's analysis state but NOT its
        // tabs — see setActiveSlot for the rationale.
        const saved = get().slotFrontendStates[active.id];
        if (saved) set(applySnapshotPreserveTabs(saved));
      } else {
        // Project is empty now — clear the centre view.
        set({
          loadedFile: null, tree: [], entryNames: [], openTabs: [],
          activeTabId: null, selectedNode: null, xrefs: [], expandedNodes: new Set(),
        });
      }
    }
  },

  setActiveSlot: async (slotId: string) => {
    const oldId = get().activeSlotId;
    if (oldId === slotId) return;

    // 1. Snapshot the OLD slot's frontend state so analysis artefacts
    //    (deobf, renames, script state) survive a round trip. Tabs are
    //    snapshotted too but NEVER restored on switch — see step 4.
    if (oldId) {
      const snap = snapshotFromState(get());
      set((s) => ({ slotFrontendStates: { ...s.slotFrontendStates, [oldId]: snap } }));
    }

    // 2. Backend switch + project metadata refresh.
    //    Clear scan-derived state — it belonged to the previous active slot.
    const snap = await api.projectSetActiveSlot(slotId);
    set({
      slots: snap.slots,
      activeSlotId: snap.activeSlotId,
      compareSlotId: snap.compareSlotId,
      dexLoaderSites: [],
    });

    // 3. Repopulate the centre view (loadFile resets tabs, expandedNodes, …).
    //    Belt-and-braces: also reset the tab strip + tree-selection +
    //    per-slot analysis state explicitly. The reset matters even
    //    when loadFile DOES run, because deobfReplacements / renames
    //    are NOT touched by loadFile — if we don't reset them here,
    //    they leak into the new slot when there's no prior snapshot
    //    to apply in step 4. (When the new slot HAS a snapshot,
    //    step 4 overwrites these fields with the saved values; the
    //    reset is harmless in that case.)
    set({
      openTabs: [],
      activeTabId: null,
      selectedNode: null,
      selectedLine: null,
      expandedNodes: new Set(),
      // Drop any inline-expanded embedded-APK subtrees from the previous slot.
      embeddedTrees: {},
      embeddedLoading: new Set(),
      deobfReplacements: {},
      appliedDeobf: new Set(),
      // Reset per-slot deobf caches so a slot with no saved snapshot
      // doesn't inherit the previous slot's call sites / resolved values.
      deobfSitesByMark: {},
      deobfResultsByMark: {},
      deobfSiteResults: {},
      deobfExpandedMarks: new Set(),
      renames: [],
    });
    const active = snap.slots.find((s) => s.id === snap.activeSlotId);
    if (active) await get().loadFile(active.basePath);

    // 4. Restore the NEW slot's saved analysis state if we've seen it
    //    before — but NOT its tab strip. Users expect tabs to follow
    //    whichever APK is active; silently re-opening tabs from a
    //    previous visit looks like the switch failed (especially for
    //    classes whose names overlap across APKs). Deobf replacements,
    //    renames, and script state ARE restored — those are analyst
    //    work that should survive context switching.
    const saved = get().slotFrontendStates[slotId];
    if (saved) set(applySnapshotPreserveTabs(saved));

    // 5. Pull this slot's persisted deobf marks. The previous slot's
    //    marks were dropped by `loadDeobfMarks` (which also clears the
    //    per-mark caches), so no leak.
    void get().loadDeobfMarks();
  },

  setCompareSlot: async (slotId: string | null) => {
    const snap = await api.projectSetCompareSlot(slotId);
    set({
      slots: snap.slots,
      activeSlotId: snap.activeSlotId,
      compareSlotId: snap.compareSlotId,
    });
  },

  forceReloadActiveSlot: async () => {
    const id = get().activeSlotId;
    if (!id) return;
    await get().forceReloadSlot(id);
  },

  forceReloadSlot: async (slotId: string) => {
    const snap = await api.projectForceReloadSlot(slotId);
    set({
      slots: snap.slots,
      activeSlotId: snap.activeSlotId,
      compareSlotId: snap.compareSlotId,
    });
    if (get().activeSlotId === slotId) {
      const active = snap.slots.find((s) => s.id === slotId);
      if (active) await get().loadFile(active.basePath);
    }
  },

  clearExtractedCache: async () => {
    const snap = await api.projectClearExtracted();
    const wasActive = get().activeSlotId;
    set({
      slots: snap.slots,
      activeSlotId: snap.activeSlotId,
      compareSlotId: snap.compareSlotId,
    });
    // If the active slot was extracted (and just got removed), repopulate.
    if (wasActive && !snap.slots.some((s) => s.id === wasActive)) {
      const active = snap.slots.find((s) => s.id === snap.activeSlotId);
      if (active) await get().loadFile(active.basePath);
    }
  },

  analyzeDexLoaders: async () => {
    set({ isAnalyzingDexLoaders: true });
    try {
      const sites = await api.analyzeDexLoaders();
      set({ dexLoaderSites: sites });
      get().addLog(
        "INFO",
        `Found ${sites.length} dynamic-loader site${sites.length === 1 ? "" : "s"} in active slot`,
        "DexLoader"
      );
    } catch (e) {
      get().addLog("ERROR", `Dex-loader analysis failed: ${(e as Error).message}`, "DexLoader");
    } finally {
      set({ isAnalyzingDexLoaders: false });
    }
  },

  fetchScriptCompletions: async () => {
    if (get().isFetchingScriptCompletions) return;
    set({ isFetchingScriptCompletions: true });
    try {
      const result = await api.getScriptCompletions();
      set({
        scriptIntrospection: result.introspection,
        scriptIntrospectionUnavailable: result.platypusUnavailable,
      });
      if (result.platypusUnavailable) {
        get().addLog(
          "WARN",
          `Script completions: ${result.error ?? "platypus module not importable"}. ` +
          "Build it via `cd rust && maturin develop --features python` to enable.",
          "ScriptPanel",
        );
      } else {
        const cn = Object.keys(result.introspection.classes ?? {}).length;
        get().addLog("INFO", `Script completions: introspected ${cn} classes`, "ScriptPanel");
      }
    } catch (e) {
      get().addLog(
        "ERROR",
        `Script-completions fetch failed: ${(e as Error).message}`,
        "ScriptPanel",
      );
    } finally {
      set({ isFetchingScriptCompletions: false });
    }
  },

  loadEmbeddedAsSlot: async (parentSlotId: string, entryPath: string) => {
    get().addLog("INFO", `Extracting embedded APK: ${entryPath}`, "Project");
    try {
      const snap = await api.projectLoadEmbedded(parentSlotId, entryPath);
      set({
        slots: snap.slots,
        activeSlotId: snap.activeSlotId,
        compareSlotId: snap.compareSlotId,
      });
      const active = snap.slots.find((s) => s.id === snap.activeSlotId);
      if (active) {
        await get().loadFile(active.basePath);
        get().addLog("INFO", `Loaded embedded APK as slot: ${active.displayName}`, "Project");
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      get().addLog("ERROR", `Failed to load embedded APK: ${msg}`, "Project");
    }
  },

  // ── Expand an embedded payload inline (under the "Embedded code" group) ──
  expandEmbedded: async (nodeId: string, entryPath: string, parentSlotId?: string) => {
    const parentId = parentSlotId ?? get().activeSlotId;
    if (!parentId) {
      get().addLog("ERROR", "No parent slot to load the embedded payload from", "Project");
      return;
    }
    // Already loaded → just toggle its expansion.
    if (get().embeddedTrees[nodeId]) { get().toggleExpand(nodeId); return; }
    if (get().embeddedLoading.has(nodeId)) return; // in flight

    // Expand immediately (so the "Loading…" placeholder is visible) and mark
    // the node as loading.
    set((s) => ({
      embeddedLoading: new Set(s.embeddedLoading).add(nodeId),
      expandedNodes: new Set(s.expandedNodes).add(nodeId),
    }));
    get().addLog("INFO", `Expanding embedded payload: ${entryPath}`, "Project");
    try {
      const res = await api.projectLoadEmbeddedNested(parentId, entryPath);
      // Children = the payload's class tree + a Resources subtree + (if it
      // contains its own payloads) a nested "Embedded code" group. All tagged
      // with the child slot id so reads route there and parse on demand.
      const resourcesNode = res.entryNames.length > 0 ? buildRawEntryTree(res.entryNames) : null;
      const nestedGroup = res.embedded.length > 0 ? embeddedGroupNode(res.embedded) : null;
      const kids = tagSubtree(
        [
          ...res.tree,
          ...(resourcesNode ? [resourcesNode] : []),
          ...(nestedGroup ? [nestedGroup] : []),
        ],
        res.slotId,
      );
      set((s) => {
        const loading = new Set(s.embeddedLoading); loading.delete(nodeId);
        const expanded = new Set(s.expandedNodes); expanded.add(nodeId);
        return {
          embeddedTrees: { ...s.embeddedTrees, [nodeId]: kids },
          embeddedLoading: loading,
          expandedNodes: expanded,
          embeddedSlotMap: { ...s.embeddedSlotMap, [res.slotId]: nodeId },
        };
      });
      get().addLog("INFO", `Expanded ${entryPath} (slot ${res.slotId.slice(0, 8)})`, "Project");
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      set((s) => { const l = new Set(s.embeddedLoading); l.delete(nodeId); return { embeddedLoading: l }; });
      get().addLog("ERROR", `Failed to expand embedded APK ${entryPath}: ${msg}`, "Project");
    }
  },

  // ── Ensure an embedded APK's inline subtree is parsed (on-demand) ──
  ensureEmbeddedLoaded: async (slotId?: string) => {
    if (!slotId) return;
    if (embeddedRootsForSlot(get().embeddedTrees, slotId)) return; // already loaded
    const nodeId = get().embeddedSlotMap[slotId];
    if (!nodeId) return; // unknown source — can't re-parse
    const meta = parseEmbeddedNodeId(nodeId, get().activeSlotId);
    if (!meta) return;
    await get().expandEmbedded(nodeId, meta.entryPath, meta.parentSlotId);
  },

  // ── Load a file (APK / DEX / JAR) ──
  loadFile: async (path: string) => {
    set({ isLoading: true });
    get().addLog("INFO", `Loading file: ${path}`, "Loader");
    try {
      const result = await api.loadFile(path);
      const entryNames = result.entryNames ?? [];
      const resourcesTree = entryNames.length > 0 ? buildRawEntryTree(entryNames) : null;
      const fullTree = resourcesTree ? [...result.tree, resourcesTree] : result.tree;
      set({
        loadedFile: result.path,
        tree: fullTree,
        embeddedTrees: {},
        embeddedLoading: new Set(),
        embeddedSlotMap: {},
        entryNames,
        resources: [],
        openTabs: [],
        activeTabId: null,
        selectedNode: null,
        xrefs: [],
        expandedNodes: new Set(),
        isLoading: false,
      });
      get().addLog(
        "INFO",
        `Loaded ${result.classCount} classes in ${result.packageCount} packages across ${result.dexFiles.length} DEX file(s).`,
        "Loader"
      );
      // Refresh the project slot list — `load_file` may have added a new slot
      // or refocused an existing one. Ignore failures (e.g. web mode).
      try {
        const snap = await api.projectListSlots();
        set({
          slots: snap.slots,
          activeSlotId: snap.activeSlotId,
          compareSlotId: snap.compareSlotId,
          cacheDir: snap.cacheDir || get().cacheDir,
        });
      } catch { /* web mode or backend without project support */ }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      set({ isLoading: false });
      get().addLog("ERROR", `Failed to load file: ${msg}`, "Loader");
    }
  },

  // ── Load a File object (web mode upload, or Tauri path fallback) ──
  loadFileObject: async (file: File) => {
    set({ isLoading: true });
    get().addLog("INFO", `Loading file: ${file.name}`, "Loader");
    try {
      // In Tauri mode we have no real path for a File object, so we can't use
      // the native loader.  Show a clear error instead of silently failing.
      if (isTauri()) {
        throw new Error(
          "Drag-and-drop / file-picker upload is not supported in Tauri mode. " +
          "Use the Open File button which opens a native file dialog."
        );
      }
      const result = await api.uploadFile(file);
      const entryNames = result.entryNames ?? [];
      const resourcesTree = entryNames.length > 0 ? buildRawEntryTree(entryNames) : null;
      const fullTree = resourcesTree ? [...result.tree, resourcesTree] : result.tree;
      set({
        loadedFile: result.path,
        tree: fullTree,
        embeddedTrees: {},
        embeddedLoading: new Set(),
        embeddedSlotMap: {},
        entryNames,
        resources: [],
        openTabs: [],
        activeTabId: null,
        selectedNode: null,
        xrefs: [],
        expandedNodes: new Set(),
        isLoading: false,
      });
      get().addLog(
        "INFO",
        `Loaded ${result.classCount} classes in ${result.packageCount} packages across ${result.dexFiles.length} DEX file(s).`,
        "Loader"
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      set({ isLoading: false });
      get().addLog("ERROR", `Failed to load file: ${msg}`, "Loader");
    }
  },

  // ── Build diff tree from treeA vs treeB and entryNames ──
  buildDiffTree: () => {
    const { tree, treeB, entryNames, entryNamesB } = get();
    if (treeB.length === 0) return;
    const diffTree = computeDiffTree(tree, treeB, entryNames, entryNamesB);
    set({ diffTree });
  },

  // ── Load comparison APK into slot B ──
  loadFileB: async (path: string) => {
    set({ isLoadingB: true });
    get().addLog("INFO", `Loading comparison file: ${path}`, "Diff");
    try {
      const result = await api.loadFileB(path);
      set({
        loadedFileB: result.path,
        treeB: result.tree,
        entryNamesB: result.entryNames ?? [],
        isLoadingB: false,
        diffClassB: null,
        diffCodeA: null,
        diffCodeB: null,
      });
      get().addLog(
        "INFO",
        `Comparison APK loaded: ${result.classCount} classes in ${result.packageCount} packages.`,
        "Diff"
      );
    } catch (err) {
      set({ isLoadingB: false });
      get().addLog("ERROR", `Failed to load comparison file: ${err}`, "Diff");
    }
  },

  loadFileBObject: async (file: File) => {
    set({ isLoadingB: true });
    get().addLog("INFO", `Loading comparison file: ${file.name}`, "Diff");
    try {
      if (isTauri()) throw new Error("Use loadFileB(path) in Tauri mode.");
      const result = await api.uploadFileB(file);
      set({
        loadedFileB: result.path,
        treeB: result.tree,
        entryNamesB: result.entryNames ?? [],
        isLoadingB: false,
        diffClassB: null,
        diffCodeA: null,
        diffCodeB: null,
      });
      get().addLog(
        "INFO",
        `Comparison APK loaded: ${result.classCount} classes.`,
        "Diff"
      );
    } catch (err) {
      set({ isLoadingB: false });
      get().addLog("ERROR", `Failed to load comparison file: ${err}`, "Diff");
    }
  },

  setDiffMode: (mode) => set({ diffMode: mode }),
  setDiffClassA: (className) => set({ diffClassA: className, diffCodeA: null, diffCodeB: null }),
  setDiffClassB: (className) => set({ diffClassB: className, diffCodeA: null, diffCodeB: null }),

  loadDiff: async () => {
    const { diffClassA, diffClassB, activeLanguage } = get();
    if (!diffClassA || !diffClassB) return;
    set({ isDiffLoading: true, diffCodeA: null, diffCodeB: null });
    try {
      const [codeA, codeB] = await Promise.all([
        activeLanguage === "java"
          ? api.getClassJava(diffClassA, get().settings.keepKotlinIntrinsics)
          : api.getClassSmali(diffClassA),
        activeLanguage === "java"
          ? api.getClassJavaB(diffClassB, get().settings.keepKotlinIntrinsics)
          : api.getClassSmaliB(diffClassB),
      ]);
      set({ diffCodeA: codeA, diffCodeB: codeB, isDiffLoading: false });
    } catch (err) {
      set({ isDiffLoading: false });
      get().addLog("ERROR", `Diff failed: ${err}`, "Diff");
    }
  },

  // ── Open a tree node in the editor ──
  openNode: async (node: TreeNode) => {
    const { activeLanguage, openTabs } = get();

    // If it's the manifest node, load manifest XML
    if (node.kind === "manifest") {
      const tabId = "tab-manifest-xml";
      const existing = openTabs.find((t) => t.id === tabId);
      if (!existing) {
        try {
          const code = await api.getManifest();
          const tab: CodeTab = {
            id: tabId,
            title: "AndroidManifest.xml",
            className: "__manifest__",
            language: "xml",
            code,
            isDirty: false,
          };
          set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId }));
        } catch (err) {
          get().addLog("ERROR", `Failed to load manifest: ${err}`, "Editor");
        }
      } else {
        set({ activeTabId: tabId });
      }
      return;
    }

    // Embedded payload (from an "Embedded code" group) — expand it inline.
    // `node.slotId` (set for nested payloads) is the slot whose ZIP contains it.
    if (node.kind === "embedded_apk") {
      await get().expandEmbedded(node.id, node.fullName ?? node.name, node.slotId);
      return;
    }

    // Raw ZIP entry (asset / resource file from the APK's directory tree).
    // `node.slotId` is set for entries inside an inline-expanded embedded APK.
    if (node.kind === "asset") {
      const entryPath = node.fullName ?? node.name;
      const tabId = `tab-entry-${node.slotId ? node.slotId + ":" : ""}${entryPath}`;
      const existing = openTabs.find((t) => t.id === tabId);
      if (existing) { set({ activeTabId: tabId }); return; }

      get().addLog("INFO", `Loading entry: ${entryPath}`, "Editor");
      try {
        const content = await api.getEntry(entryPath, node.slotId);
        // Pick display language based on file extension.
        const ext = entryPath.split(".").pop()?.toLowerCase() ?? "";
        const language: Language =
          ext === "xml"  ? "xml"  :
          ext === "json" ? "text" :
          "text";

        const tab: CodeTab = {
          id: tabId,
          title: entryPath.split("/").pop() ?? entryPath,
          className: `__entry__/${entryPath}`,
          language,
          code: content,
          isDirty: false,
        };
        set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId }));
      } catch (err) {
        get().addLog("ERROR", `Failed to load entry ${entryPath}: ${err}`, "Editor");
      }
      return;
    }

    // Resource entry — open a plain-text viewer tab
    if (node.kind === "res_entry") {
      const tabId = `tab-res-${node.fullName}`;
      const existing = openTabs.find((t) => t.id === tabId);
      if (existing) { set({ activeTabId: tabId }); return; }

      const entry = get().resources.find((r) => r.id === node.fullName);
      if (!entry) return;

      const lines = [
        `Resource:  ${entry.name}`,
        `Type:      ${entry.type}`,
        `ID:        ${entry.id}`,
        ``,
        entry.content != null && entry.content !== ""
          ? `Value:     ${entry.content}`
          : `(No resolved value)`,
      ];
      const tab: CodeTab = {
        id: tabId,
        title: `${entry.type}/${entry.name}`,
        className: `__res__/${entry.id}`,
        language: "text",
        code: lines.join("\n"),
        isDirty: false,
      };
      set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId }));
      return;
    }

    if (node.kind !== "class" && node.kind !== "method" && node.kind !== "field") {
      return;
    }

    // For method/field nodes, the className is the part before "->"
    let className: string;
    let memberName: string | null = null;

    if ((node.kind === "method" || node.kind === "field") && node.fullName?.includes("->")) {
      const arrowIdx = node.fullName.indexOf("->");
      className = node.fullName.slice(0, arrowIdx);
      memberName = node.name; // bare member name (no signature)
    } else {
      className = node.fullName ?? node.name;
    }

    // `node.slotId` is set for classes inside an inline-expanded embedded APK;
    // reads route to that child slot and the tab id is scoped to it.
    const slotId = node.slotId;
    const tabId = makeTabId(className, activeLanguage, slotId);
    const existing = openTabs.find((t) => t.id === tabId);

    if (existing) {
      const line = memberName
        ? findCodeLine(existing.code, existing.language, memberName, node.kind as "method" | "field")
        : null;
      set({ activeTabId: tabId, selectedLine: line });
      return;
    }

    try {
      const code =
        activeLanguage === "java"
          ? await api.getClassJava(className, get().settings.keepKotlinIntrinsics, slotId)
          : await api.getClassSmali(className, slotId);

      const tab: CodeTab = {
        id: tabId,
        title: className.split("/").pop()?.replace(";", "") ?? className,
        className,
        language: activeLanguage,
        code,
        isDirty: false,
        slotId,
      };

      const line = memberName
        ? findCodeLine(code, activeLanguage, memberName, node.kind as "method" | "field")
        : null;

      set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId, selectedLine: line }));
      get().addLog("DEBUG", `Opened ${className} (${activeLanguage})`, "Editor");
    } catch (err) {
      get().addLog("ERROR", `Failed to open ${className}: ${err}`, "Editor");
    }
  },

  // ── Select a node (updates right panel) ──
  selectNode: (node: TreeNode) => {
    set({ selectedNode: node });

    if (node.kind === "method" && node.fullName) {
      const parts = node.fullName.split("->");
      const className = parts[0] ?? "";
      const methodSig = parts[1] ?? node.name;
      // For methods inside an inline-expanded embedded APK, route xref /
      // call-graph / CFG to that child slot.
      const slotId = node.slotId;
      get().addLog("DEBUG", `Selected method: ${node.fullName}`, "Selection");

      // Auto-fill exec signature
      set({ execSignature: node.fullName ?? "" });

      // Load xrefs
      api
        .getXrefs(className, methodSig, slotId)
        .then((xrefs) => set({ xrefs }))
        .catch((err) =>
          get().addLog("WARN", `Could not load xrefs: ${err}`, "XRefs")
        );

      // Load call graph
      get().loadCallGraph(className, methodSig, slotId);
      // Load CFG
      get().loadCfg(className, methodSig, slotId);
    } else {
      set({ xrefs: [], callGraph: null, cfgResult: null });
    }
  },

  // ── Tree expand/collapse ──
  toggleExpand: (nodeId: string) => {
    // Expanding an embedded payload node for the first time lazily parses it
    // (works at any nesting depth via the encoded parent slot id).
    if (!get().embeddedTrees[nodeId]) {
      const meta = parseEmbeddedNodeId(nodeId, get().activeSlotId);
      if (meta) {
        void get().expandEmbedded(nodeId, meta.entryPath, meta.parentSlotId);
        return;
      }
    }
    set((s) => {
      const expanded = new Set(s.expandedNodes);
      if (expanded.has(nodeId)) {
        expanded.delete(nodeId);
      } else {
        expanded.add(nodeId);
      }
      return { expandedNodes: expanded };
    });
  },

  revealInTree: (className: string, slotId?: string) => {
    // For an embedded class, search the matching embedded subtree and also
    // expand the "Embedded APKs" group + the embedded-apk node so the path
    // is visible; otherwise search the active slot's tree.
    let roots = get().tree;
    let extraExpand: string[] = [];
    if (slotId) {
      const hit = Object.entries(get().embeddedTrees).find(
        ([, kids]) => kids.some((k) => k.slotId === slotId),
      );
      if (!hit) return;
      const [nodeId, rawKids] = hit;
      // Match the displayed shape so ancestor ids line up with what the
      // treeview renders (which follows the global "Group classes by").
      roots = get().settings.treeGroupBy === "merged"
        ? flattenTreeByPackage(rawKids, `merged:${nodeId}:`)
        : rawKids;
      // Expand every enclosing embedded group/node up the nesting chain so a
      // deeply-nested class is actually visible.
      extraExpand = embeddedAncestorIds(nodeId, get().embeddedSlotMap);
    }
    const path = findNodePath(roots, className);
    if (!path || path.length === 0) return; // not in the tree (framework class, etc.)

    const target = path[path.length - 1];
    set((s) => {
      // Expand every ancestor (everything except the leaf) so the row is
      // visible. The leaf's own expansion state is left untouched — we're
      // revealing the class, not forcing its members open.
      const expanded = new Set(s.expandedNodes);
      for (const id of extraExpand) expanded.add(id);
      for (let i = 0; i < path.length - 1; i++) expanded.add(path[i].id);
      return {
        expandedNodes: expanded,
        selectedNode: target,
        // New object identity each call so the LeftPanel effect re-fires
        // even when revealing the same node twice in a row.
        revealRequest: { nodeId: target.id, nonce: (s.revealRequest?.nonce ?? 0) + 1 },
      };
    });
  },

  setFilterQuery: (q: string) => set({ filterQuery: q }),

  // ── Tab management ──
  setActiveTab: (tabId: string) => set({ activeTabId: tabId, selectedLine: null }),

  reorderTabs: (fromIndex: number, toIndex: number) => {
    set((s) => {
      const tabs = [...s.openTabs];
      const [moved] = tabs.splice(fromIndex, 1);
      tabs.splice(toIndex, 0, moved);
      return { openTabs: tabs };
    });
  },

  closeTab: (tabId: string) => {
    set((s) => {
      const tabs = s.openTabs.filter((t) => t.id !== tabId);
      let activeTabId = s.activeTabId;
      if (activeTabId === tabId) {
        const idx = s.openTabs.findIndex((t) => t.id === tabId);
        activeTabId = tabs[idx]?.id ?? tabs[idx - 1]?.id ?? null;
      }
      return { openTabs: tabs, activeTabId };
    });
  },

  closeOtherTabs: (tabId: string) => {
    set((s) => ({
      openTabs: s.openTabs.filter((t) => t.id === tabId),
      activeTabId: tabId,
    }));
  },

  closeAllTabs: () => set({ openTabs: [], activeTabId: null }),

  // ── Language toggle ──
  setActiveLanguage: async (lang: Language) => {
    const { activeTabId, openTabs } = get();
    set({ activeLanguage: lang });

    if (!activeTabId) return;
    const activeTab = openTabs.find((t) => t.id === activeTabId);
    if (!activeTab || activeTab.language === "xml") return;

    const { className } = activeTab;
    const tabId = makeTabId(className, lang);
    const existing = openTabs.find((t) => t.id === tabId);
    if (existing) {
      set({ activeTabId: tabId });
      return;
    }

    try {
      const code =
        lang === "java"
          ? await api.getClassJava(className, get().settings.keepKotlinIntrinsics)
          : await api.getClassSmali(className);

      const tab: CodeTab = {
        id: tabId,
        title: activeTab.title,
        className,
        language: lang,
        code,
        isDirty: false,
      };
      set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId }));
    } catch (err) {
      get().addLog("ERROR", `Failed to switch to ${lang}: ${err}`, "Editor");
    }
  },

  // ── Code navigation ──
  setSelectedLine: (line) => set({ selectedLine: line }),

  // ── Panel tabs ──
  setActiveRightTab: (tab) => set({ activeRightTab: tab }),
  setActiveBottomTab: (tab) => set({ activeBottomTab: tab }),
  toggleFlowGraph: () => set((s) => ({ showFlowGraph: !s.showFlowGraph })),

  // ── Script library ──────────────────────────────────────────────────────

  /** Initial fetch of the on-disk script library. Runs once on app start.
   *  Migrates legacy single-script `cache.scriptCode` to a `scratch.py` file
   *  if the library is empty on first run. */
  loadScripts: async () => {
    set({ isLoadingScripts: true });
    try {
      let list = await api.scriptList();

      // First-run / migration path: empty library + maybe legacy scriptCode in
      // localStorage → seed scratch.py so users don't lose their work.
      if (list.length === 0) {
        let seed = DEFAULT_SCRATCH;
        try {
          // Legacy one-time migration; backend mirror covers Linux fresh launch.
          const raw = await persistGet("platypus_cache");
          if (raw) {
            const parsed = JSON.parse(raw) as { scriptCode?: string };
            if (typeof parsed.scriptCode === "string" && parsed.scriptCode.trim().length > 0) {
              seed = parsed.scriptCode;
            }
          }
        } catch { /* ignore corrupt cache */ }
        try {
          await api.scriptCreate("scratch.py", seed);
          list = await api.scriptList();
        } catch (e) {
          get().addLog("ERROR", `Could not seed scratch.py: ${(e as Error).message}`, "Scripts");
        }
      }

      // Restore last-active script preference if it still exists on disk.
      let activeName: string | null = null;
      try {
        const stored = await persistGet("platypus_active_script");
        if (stored && list.some((s) => s.name === stored)) {
          activeName = stored;
        }
      } catch { /* ignore */ }
      if (!activeName && list.length > 0) activeName = list[0].name;

      let content = "";
      if (activeName) {
        try { content = await api.scriptLoad(activeName); }
        catch (e) {
          get().addLog("ERROR", `Could not load ${activeName}: ${(e as Error).message}`, "Scripts");
        }
      }

      set({ scripts: list, activeScriptName: activeName, scriptContent: content });
    } finally {
      set({ isLoadingScripts: false });
    }
  },

  setActiveScript: async (name: string) => {
    if (get().activeScriptName === name) return;
    // Flush any pending edits to the OUTGOING script before we swap.
    if (scriptSaveTimer) { clearTimeout(scriptSaveTimer); scriptSaveTimer = null; }
    await get().saveActiveScript();
    try {
      const content = await api.scriptLoad(name);
      set({ activeScriptName: name, scriptContent: content });
      try { persistSet("platypus_active_script", name); } catch { /* ignore */ }
    } catch (e) {
      get().addLog("ERROR", `Could not switch to ${name}: ${(e as Error).message}`, "Scripts");
    }
  },

  setScriptContent: (content: string) => {
    set({ scriptContent: content });
    if (scriptSaveTimer) clearTimeout(scriptSaveTimer);
    scriptSaveTimer = setTimeout(() => {
      void get().saveActiveScript();
    }, SCRIPT_SAVE_DEBOUNCE_MS);
  },

  saveActiveScript: async () => {
    const { activeScriptName, scriptContent } = get();
    if (!activeScriptName) return;
    try {
      await api.scriptSave(activeScriptName, scriptContent);
      // Refresh metadata so the tab badge / mtime stays accurate.
      const list = await api.scriptList();
      set({ scripts: list });
    } catch (e) {
      get().addLog("ERROR", `Could not save ${activeScriptName}: ${(e as Error).message}`, "Scripts");
    }
  },

  createScript: async (name: string, initialContent?: string) => {
    // Make sure pending edits to the current script are flushed first.
    if (scriptSaveTimer) { clearTimeout(scriptSaveTimer); scriptSaveTimer = null; }
    await get().saveActiveScript();
    try {
      const info = await api.scriptCreate(name, initialContent ?? "");
      const list = await api.scriptList();
      set({
        scripts: list,
        activeScriptName: info.name,
        scriptContent: initialContent ?? "",
      });
      try { persistSet("platypus_active_script", info.name); } catch { /* ignore */ }
      get().addLog("INFO", `Created script ${info.name}`, "Scripts");
    } catch (e) {
      get().addLog("ERROR", `Could not create script: ${(e as Error).message}`, "Scripts");
      throw e;
    }
  },

  deleteScript: async (name: string) => {
    // Confirmation is handled by the in-app dialog before this is called —
    // we no longer depend on `window.confirm`, which is silently dropped by
    // some Tauri webviews.
    try {
      await api.scriptDelete(name);
      const list = await api.scriptList();
      const wasActive = get().activeScriptName === name;
      let nextActive: string | null = get().activeScriptName;
      let nextContent: string = get().scriptContent;
      if (wasActive) {
        nextActive = list[0]?.name ?? null;
        nextContent = nextActive ? await api.scriptLoad(nextActive) : "";
        if (nextActive) {
          try { persistSet("platypus_active_script", nextActive); } catch { /* ignore */ }
        }
      }
      set({ scripts: list, activeScriptName: nextActive, scriptContent: nextContent });
      get().addLog("INFO", `Deleted script ${name}`, "Scripts");
    } catch (e) {
      get().addLog("ERROR", `Could not delete ${name}: ${(e as Error).message}`, "Scripts");
    }
  },

  renameScript: async (oldName: string, newName: string) => {
    if (oldName === newName) return;
    // Flush any pending edits before the file is moved out from under us.
    if (scriptSaveTimer) { clearTimeout(scriptSaveTimer); scriptSaveTimer = null; }
    await get().saveActiveScript();
    try {
      const finalName = await api.scriptRename(oldName, newName);
      const list = await api.scriptList();
      const updateActive = get().activeScriptName === oldName;
      set({
        scripts: list,
        ...(updateActive ? { activeScriptName: finalName } : {}),
      });
      if (updateActive) {
        try { persistSet("platypus_active_script", finalName); } catch { /* ignore */ }
      }
    } catch (e) {
      get().addLog("ERROR", `Could not rename: ${(e as Error).message}`, "Scripts");
      throw e;
    }
  },

  duplicateScript: async (name: string) => {
    try {
      const content = await api.scriptLoad(name);
      const base = name.replace(/\.py$/i, "");
      let candidate = `${base}-copy.py`;
      let n = 2;
      while (get().scripts.some((s) => s.name === candidate)) {
        candidate = `${base}-copy-${n}.py`;
        n++;
      }
      await get().createScript(candidate, content);
    } catch (e) {
      get().addLog("ERROR", `Could not duplicate: ${(e as Error).message}`, "Scripts");
    }
  },

  runScript: async () => {
    const { scriptContent, activeScriptName, loadedFile } = get();
    // Don't clear scriptOutput on start — the user can keep reading the
    // last run's output while the new one is in flight. The button state
    // (isScriptRunning) already signals "in progress".
    set({ isScriptRunning: true });
    get().addLog("INFO",
      `Running ${activeScriptName ?? "(unsaved)"}…`,
      "Script");
    // Always flush before running so the on-disk file matches what we execute.
    if (scriptSaveTimer) { clearTimeout(scriptSaveTimer); scriptSaveTimer = null; }
    await get().saveActiveScript();
    try {
      const result = await api.runScript(scriptContent);
      const entry: ScriptRunEntry = {
        ...result,
        id: `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 7)}`,
        finishedAt: Date.now(),
        scriptName: activeScriptName,
      };
      set((s) => {
        // Newest first, cap at SCRIPT_HISTORY_MAX. The cap is generous —
        // each entry is a few KB of text at most, and the timeline UI
        // only renders headers eagerly; bodies are gated on expand.
        const next = [entry, ...s.scriptOutputHistory].slice(0, SCRIPT_HISTORY_MAX);
        return {
          scriptOutput: result,
          scriptOutputHistory: next,
          isScriptRunning: false,
        };
      });
      if (result.exitCode === 0) {
        get().addLog("INFO", `Script completed in ${result.durationMs}ms`, "Script");
      } else {
        get().addLog("WARN", `Script exited with code ${result.exitCode}`, "Script");
      }
    } catch (err) {
      get().addLog("ERROR", `Script execution failed: ${err}`, "Script");
      set({ isScriptRunning: false });
    }
    void loadedFile;
  },

  clearScriptHistory: () => {
    set({ scriptOutput: null, scriptOutputHistory: [] });
  },

  removeScriptHistoryEntry: (id: string) => {
    set((s) => {
      const next = s.scriptOutputHistory.filter((e) => e.id !== id);
      // If we removed the head, scriptOutput should point at the new
      // head (or null when the list is empty).
      const newOutput = s.scriptOutput && next[0]
        ? (next[0].id === s.scriptOutputHistory[0]?.id
            ? s.scriptOutput            // unchanged head
            : { ...next[0] })            // new head — copy excluding ScriptRunEntry-only fields
        : (next[0] ? { ...next[0] } : null);
      return { scriptOutput: newOutput, scriptOutputHistory: next };
    });
  },

  killScript: async () => {
    if (!get().isScriptRunning) return;
    try {
      const killed = await api.killScript();
      if (killed) {
        get().addLog("WARN", "Script terminated by user (SIGTERM)", "Script");
      } else {
        get().addLog("INFO", "No running script to kill", "Script");
      }
    } catch (err) {
      get().addLog("ERROR", `Could not kill script: ${err}`, "Script");
    }
    // Don't flip isScriptRunning here — `runScript`'s catch/finally will do it
    // when the subprocess actually dies and `wait_with_output` returns.
  },

  // ── Popout windows ──
  openSettingsWindow:  () => set({ showSettingsWindow: true }),
  closeSettingsWindow: () => set({ showSettingsWindow: false }),
  toggleSettingsWindow: () => set((s) => ({ showSettingsWindow: !s.showSettingsWindow })),

  // ── App settings ──
  updateSetting: (key, value) => {
    set((s) => ({ settings: { ...s.settings, [key]: value } }));
    get().saveCache();

    // Settings that affect decompiled output need a refresh of any open Java
    // tabs so the change is immediately visible. Smali tabs are unaffected.
    if (key === "keepKotlinIntrinsics") {
      void get().refreshOpenJavaTabs();
    }
  },

  /** Re-fetch the Java source for every open Java tab, using the *current*
   *  `settings.keepKotlinIntrinsics` value. Called when settings that affect
   *  decompiled output change. */
  refreshOpenJavaTabs: async () => {
    const tabs = get().openTabs.filter((t) => t.language === "java");
    if (tabs.length === 0) return;
    const keep = get().settings.keepKotlinIntrinsics;
    const refreshed = await Promise.all(
      tabs.map(async (t) => {
        try {
          const code = await api.getClassJava(t.className, keep);
          return { id: t.id, code };
        } catch {
          return null;
        }
      }),
    );
    set((s) => ({
      openTabs: s.openTabs.map((t) => {
        const upd = refreshed.find((r) => r && r.id === t.id);
        return upd ? { ...t, code: upd.code } : t;
      }),
    }));
  },

  resetSettings: () => {
    set({ settings: DEFAULT_SETTINGS });
    get().saveCache();
  },

  clearDeobf: () => {
    set({ deobfReplacements: {}, appliedDeobf: new Set() });
    get().saveCache();
  },

  // ── Call graph ──
  loadCallGraph: async (className: string, methodName: string, slotId?: string) => {
    set({ isCallGraphLoading: true, callGraph: null });
    try {
      const result = await api.getCallGraph(className, methodName, slotId);
      set({ callGraph: result, isCallGraphLoading: false });
    } catch (err) {
      get().addLog("WARN", `Could not load call graph: ${err}`, "CallGraph");
      set({ isCallGraphLoading: false });
    }
  },

  // ── XRefs for a specific method (used by xref entry click) ──
  loadXrefsForMethod: (className: string, methodName: string, slotId?: string) => {
    // Default to the focused tab's slot so xref-panel clicks while viewing an
    // embedded class stay within that embedded APK.
    const sid = slotId ?? get().openTabs.find((t) => t.id === get().activeTabId)?.slotId;
    set({
      xrefs: [],
      isXrefsLoading: true,
      xrefsTarget: { className, methodName },
    });
    api
      .getXrefs(className, methodName, sid)
      .then((xrefs) => set({ xrefs, isXrefsLoading: false }))
      .catch((err) => {
        get().addLog("WARN", `Could not load xrefs: ${err}`, "XRefs");
        set({ isXrefsLoading: false });
      });
  },

  // ── CFG ──
  loadCfg: async (className: string, methodName: string, slotId?: string) => {
    set({ isCfgLoading: true, cfgResult: null });
    try {
      const result = await api.getMethodCfg(className, methodName, slotId);
      set({ cfgResult: result, isCfgLoading: false });
    } catch (err) {
      get().addLog("WARN", `Could not load CFG: ${err}`, "CFG");
      set({ isCfgLoading: false });
    }
  },

  // ── Logging ──
  addLog: (level: LogLevel, message: string, tag?: string) => {
    const entry: LogEntry = {
      id: makeLogId(),
      timestamp: Date.now(),
      level,
      message,
      tag,
    };
    set((s) => ({ logs: [...s.logs.slice(-4999), entry] }));
  },

  clearLogs: () => set({ logs: [] }),

  // ── Search ──
  setSearchQuery: (q: string) => set({ searchQuery: q }),

  runSearch: async () => {
    const { searchQuery } = get();
    if (!searchQuery.trim()) return;
    set({ isSearching: true, searchResults: [] });
    try {
      // Scope to the slot of the tab currently in focus, so searching while
      // viewing an embedded APK's class searches that embedded APK.
      const focusedSlot = get().openTabs.find((t) => t.id === get().activeTabId)?.slotId;
      const results = await api.searchCode(searchQuery, undefined, focusedSlot);
      set({ searchResults: results, searchSlotId: focusedSlot, isSearching: false });
    } catch (err) {
      get().addLog("ERROR", `Search failed: ${err}`, "Search");
      set({ isSearching: false });
    }
  },

  navigateToSearchResult: async (result: SearchResult) => {
    // ── Resource hit → open a resource-entry viewer tab ──
    // Mirrors the `res_entry` tab format produced by openNode, so the
    // resources view shows the matched entry (name / type / id / value).
    if (result.kind === "resource" && result.resId != null) {
      const tabId = `tab-res-${result.resId}`;
      const existing = get().openTabs.find((t) => t.id === tabId);
      if (existing) { set({ activeTabId: tabId }); return; }

      const type = result.className;
      const name = result.memberName ?? String(result.resId);
      const value = result.snippet;
      const lines = [
        `Resource:  ${name}`,
        `Type:      ${type}`,
        `ID:        ${result.resId}`,
        ``,
        value !== "" ? `Value:     ${value}` : `(No resolved value)`,
      ];
      const tab: CodeTab = {
        id: tabId,
        title: `${type}/${name}`,
        className: `__res__/${result.resId}`,
        language: "text",
        code: lines.join("\n"),
        isDirty: false,
      };
      set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId, selectedLine: null }));
      return;
    }

    // ── Code hit → open the class, then jump to the matched line ──
    // Results carry the slot they were searched in (an embedded child slot).
    const slotId = get().searchSlotId;
    await get().ensureEmbeddedLoaded(slotId);
    const roots = slotId
      ? (embeddedRootsForSlot(get().embeddedTrees, slotId) ?? get().tree)
      : get().tree;
    const node = findNodeInTree(roots, result.className);
    if (node) {
      await get().openNode(node);
      get().selectNode(node);
    } else {
      // Directly open the class without a tree node
      const lang = get().activeLanguage;
      const tabId = makeTabId(result.className, lang, slotId);
      const existing = get().openTabs.find((t) => t.id === tabId);
      if (!existing) {
        try {
          const code =
            lang === "java"
              ? await api.getClassJava(result.className, get().settings.keepKotlinIntrinsics, slotId)
              : await api.getClassSmali(result.className, slotId);
          const tab: CodeTab = {
            id: tabId,
            title: result.className.split("/").pop() ?? result.className,
            className: result.className,
            language: lang,
            code,
            isDirty: false,
            slotId,
          };
          set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId }));
        } catch (err) {
          get().addLog("ERROR", `Navigation failed: ${err}`, "Search");
        }
      } else {
        set({ activeTabId: tabId });
      }
    }

    // Resolve + select the exact line the hit lives on. The active tab now
    // holds the opened class; use its rendered code so the line matches what
    // the user sees (codepoints from the backend don't map 1:1 to rendered
    // lines, so we locate via the snippet/member instead).
    const { openTabs, activeTabId } = get();
    const activeTab = openTabs.find((t) => t.id === activeTabId);
    if (activeTab) {
      const line = findSearchResultLine(activeTab.code, activeTab.language, result);
      set({ selectedLine: line });
    }
  },

  // ── Execution ──
  setExecSignature: (sig: string) => set({ execSignature: sig }),
  setExecArgs: (args: string) => set({ execArgs: args }),
  setExecInstrLimit: (n: number) => {
    // Clamp to a sensible range so a stray keystroke doesn't lock the UI for
    // an hour. 1k is the floor (anything less is useless); 1B is a hard
    // ceiling — at our ~14k–500k ips that's ~30min–20h wall-clock per call.
    const clamped = Math.max(1_000, Math.min(1_000_000_000, Math.floor(n) || 0));
    set({ execInstrLimit: clamped });
  },

  setDeobfNumThreads: (n: number) => {
    // 0 = "let backend pick" (rayon's default = num_cpus). Anything
    // beyond 64 is almost certainly a typo (chunking too thinly hurts
    // throughput) so we cap there.
    const clamped = Math.max(0, Math.min(64, Math.floor(n) || 0));
    set({ deobfNumThreads: clamped });
  },

  setDeobfFilter: (q: string) => set({ deobfFilter: q }),

  runMethod: async () => {
    const { execSignature, execArgs } = get();
    if (!execSignature.trim()) return;

    // Parse "Lcom/example/Foo;->methodName(...)V" style
    const arrowIdx = execSignature.indexOf("->");
    let className = execSignature;
    let methodName = "";
    if (arrowIdx !== -1) {
      className = execSignature.slice(0, arrowIdx);
      methodName = execSignature.slice(arrowIdx + 2);
    }

    const args = execArgs
      .split(",")
      .map((a) => a.trim())
      .filter(Boolean);

    set({ isRunning: true, execResult: null });
    get().addLog("INFO", `Running ${execSignature} with args [${args.join(", ")}]`, "VM");

    try {
      const focusedSlot = get().openTabs.find((t) => t.id === get().activeTabId)?.slotId;
      const result = await api.runMethod(className, methodName, args, get().execInstrLimit, focusedSlot);
      set({ execResult: result, isRunning: false });
      get().addLog("INFO", `Result: ${result.returnValue} (${result.returnType})`, "VM");
      result.logs.forEach((l) => get().addLog("DEBUG", l, "VM"));
      if (result.error) {
        get().addLog("ERROR", `VM error: ${result.error}`, "VM");
      }
    } catch (err) {
      get().addLog("ERROR", `Execution failed: ${err}`, "VM");
      set({ isRunning: false });
    }
  },

  findAndExec: async () => {
    const { execSignature } = get();
    if (!execSignature.trim()) return;
    set({ isFindRunning: true, findExecResults: [] });
    get().addLog("INFO", `Finding & executing all call sites of: ${execSignature}`, "VM");
    try {
      const focusedSlot = get().openTabs.find((t) => t.id === get().activeTabId)?.slotId;
      const results = await api.findExec(execSignature, get().execInstrLimit, undefined, focusedSlot);
      set({ findExecResults: results, isFindRunning: false });
      get().addLog("INFO", `Found ${results.length} call site(s).`, "VM");
    } catch (err) {
      get().addLog("ERROR", `find_exec failed: ${err}`, "VM");
      set({ isFindRunning: false });
    }
  },

  // ── Deobfuscation ──
  applyDeobf: (resultIdx: number) => {
    const { findExecResults } = get();
    const result = findExecResults[resultIdx];
    if (!result) return;

    // Use the result's OWN callerClass — NOT the currently-active tab —
    // as the replacement key. The earlier behaviour keyed by tab.className,
    // which silently attached the resolved string to whatever was open at
    // the moment of clicking Apply (often the deobfuscator class itself,
    // since that's what users have open while running a deobf). The
    // replacement then showed up in the wrong file.
    //
    // ALSO normalise the className — the backend returns `Lcom/foo/Bar;`
    // (raw dex form) but the tab + tree store the stripped form. Without
    // this, the buildDeobfList filter never matches, so nothing renders.
    const className = normaliseClassName(result.callerClass);
    const key = `${className}:${result.offset}:${resultIdx}`;
    if (get().appliedDeobf.has(key)) return;

    const replacement: DeobfReplacement = {
      original: result.callSite,
      resolved: result.resolvedValue,
      lineIndex: result.offset,
      className,
    };

    set((s) => ({
      deobfReplacements: { ...s.deobfReplacements, [key]: replacement },
      appliedDeobf: new Set([...s.appliedDeobf, key]),
    }));

    get().addLog(
      "INFO",
      `Applied deobfuscation: "${result.resolvedValue}" at offset ${result.offset} in ${className}`,
      "Deobf"
    );
  },

  applyAllDeobf: () => {
    const { findExecResults } = get();
    findExecResults.forEach((_, idx) => get().applyDeobf(idx));
    get().saveCache();
  },

  markAsDeobfuscator: async (signature: string) => {
    set({ isFindRunning: true, findExecResults: [], execSignature: signature });
    get().addLog("INFO", `Running deobfuscator: ${signature}`, "Deobf");
    try {
      const focusedSlot = get().openTabs.find((t) => t.id === get().activeTabId)?.slotId;
      const results = await api.findExec(signature, undefined, undefined, focusedSlot);
      set({ findExecResults: results, isFindRunning: false });

      // Auto-apply all results keyed by callerClass:lineOffset so they persist
      // across tabs — when a caller class tab is opened it will show the replacement.
      const newReplacements: Record<string, DeobfReplacement> = {};
      const newApplied = new Set(get().appliedDeobf);
      let count = 0;

      results.forEach((r, idx) => {
        if (r.error || !r.resolvedValue) return;
        // Normalise to the stripped form so the centre-panel filter
        // matches against `tab.className` (which is the tree's
        // stripped `fullName`). See `normaliseClassName` for the
        // L;-wrapping vs stripped-form mismatch this guards against.
        const normalisedClass = normaliseClassName(r.callerClass);
        const key = `${normalisedClass}:${r.offset}:${idx}`;
        if (newApplied.has(key)) return;
        newReplacements[key] = {
          original: r.callSite,
          resolved: r.resolvedValue,
          lineIndex: r.offset,
          className: normalisedClass,
        };
        newApplied.add(key);
        count++;
      });

      set((s) => ({
        deobfReplacements: { ...s.deobfReplacements, ...newReplacements },
        appliedDeobf: newApplied,
        activeBottomTab: "EXECUTION",
      }));
      get().saveCache();
      get().addLog(
        "INFO",
        `Applied ${count} deobfuscation replacement(s) across ${new Set(results.map(r => r.callerClass)).size} class(es).`,
        "Deobf"
      );
    } catch (err) {
      get().addLog("ERROR", `Deobfuscator failed: ${err}`, "Deobf");
      set({ isFindRunning: false });
    }
  },

  // ── DEOBFUSCATION tab actions ────────────────────────────────────
  //
  // The persistent "marked methods" list lives in the active slot on
  // the backend (see Slot.deobf_marks). The store mirrors that list
  // and caches the lazily-loaded site listings + execution results
  // so the UI doesn't re-fetch on every render. Marks survive across
  // APK reloads (they're in project.json) but the in-memory site/
  // result caches do NOT — they're refetched on slot activation since
  // bytecode can drift between sessions.

  loadDeobfMarks: async () => {
    if (!isTauri()) return;
    try {
      const marks = await api.deobfListMarks();
      // Prune (don't wipe) the per-mark caches: keep entries for marks
      // that still exist so a snapshot restored just before this call
      // survives, and drop only entries for marks that are gone. This is
      // what lets scanned sites + deobfuscated values persist across
      // reloads "until the method is unmarked". Cross-APK staleness is
      // already handled by the per-slot reset on slot/APK switch.
      const keep = new Set(marks.map((m) => deobfMarkKey(m.className, m.methodName)));
      set((s) => ({
        deobfMarks: marks,
        deobfSitesByMark: Object.fromEntries(
          Object.entries(s.deobfSitesByMark).filter(([k]) => keep.has(k)),
        ),
        deobfResultsByMark: Object.fromEntries(
          Object.entries(s.deobfResultsByMark).filter(([k]) => keep.has(k)),
        ),
        deobfSiteResults: Object.fromEntries(
          Object.entries(s.deobfSiteResults).filter(([k]) => keep.has(k.split("|")[0])),
        ),
        deobfExpandedMarks: new Set(
          [...s.deobfExpandedMarks].filter((k) => keep.has(k)),
        ),
      }));
    } catch (err) {
      get().addLog("ERROR", `Failed to load deobf marks: ${err}`, "Deobf");
    }
  },

  markDeobf: async (className: string, methodName: string) => {
    if (!isTauri()) return;
    try {
      const marks = await api.deobfMarkMethod(className, methodName);
      set({ deobfMarks: marks });
      get().addLog("INFO", `Marked ${className}->${methodName} as deobfuscator`, "Deobf");
    } catch (err) {
      get().addLog("ERROR", `markDeobf failed: ${err}`, "Deobf");
    }
  },

  unmarkDeobf: async (className: string, methodName: string) => {
    if (!isTauri()) return;
    try {
      const marks = await api.deobfUnmarkMethod(className, methodName);
      // Unmarking is the cache's invalidation point: drop every cached
      // entry for this method so a future re-mark re-scans from scratch
      // and we don't leak memory. This covers the per-mark site listing
      // and results, the per-call-site result map (keyed `${key}|…`), the
      // expanded/loading/running flags, and in-flight per-site runs.
      const key = deobfMarkKey(className, methodName);
      const sitePrefix = `${key}|`;
      set((s) => {
        const { [key]: _sites, ...sitesRest } = s.deobfSitesByMark;
        const { [key]: _results, ...resultsRest } = s.deobfResultsByMark;
        const expanded = new Set(s.deobfExpandedMarks); expanded.delete(key);
        const loading = new Set(s.deobfLoadingSites); loading.delete(key);
        const runningMarks = new Set(s.deobfRunningMarks); runningMarks.delete(key);
        const siteResults = Object.fromEntries(
          Object.entries(s.deobfSiteResults).filter(([k]) => !k.startsWith(sitePrefix)),
        );
        const runningSites = new Set(
          [...s.deobfRunningSites].filter((k) => !k.startsWith(sitePrefix)),
        );
        return {
          deobfMarks: marks,
          deobfSitesByMark: sitesRest,
          deobfResultsByMark: resultsRest,
          deobfExpandedMarks: expanded,
          deobfLoadingSites: loading,
          deobfRunningMarks: runningMarks,
          deobfSiteResults: siteResults,
          deobfRunningSites: runningSites,
        };
      });
      get().addLog("INFO", `Unmarked ${className}->${methodName}`, "Deobf");
    } catch (err) {
      get().addLog("ERROR", `unmarkDeobf failed: ${err}`, "Deobf");
    }
  },

  isDeobfMarked: (className: string, methodName: string) => {
    const norm = className.replace(/^L/, "").replace(/;$/, "");
    return get().deobfMarks.some(
      (m) => m.className === norm && m.methodName === methodName
    );
  },

  toggleDeobfExpanded: (className: string, methodName: string) => {
    const key = deobfMarkKey(className, methodName);
    const willExpand = !get().deobfExpandedMarks.has(key);
    set((s) => {
      const expanded = new Set(s.deobfExpandedMarks);
      if (willExpand) { expanded.add(key); } else { expanded.delete(key); }
      return { deobfExpandedMarks: expanded };
    });
    // Lazy fetch the sites on expand. `loadDeobfSites` self-guards on the
    // per-method cache, so this is a no-op when the sites are already
    // scanned (re-expand after collapse, or after a marks reload that
    // kept this method's cache).
    if (willExpand) {
      void get().loadDeobfSites(className, methodName);
    }
  },

  loadDeobfSites: async (className: string, methodName: string, force = false) => {
    if (!isTauri()) return;
    const key = deobfMarkKey(className, methodName);
    // Call sites are scanned once per marked method and cached in
    // `deobfSitesByMark`. The cache lives until the method is unmarked
    // (`unmarkDeobf` clears it), so re-expanding a row never triggers a
    // redundant backend scan. The ↻ refresh button passes `force` to
    // re-scan when the underlying code may have changed.
    if (!force && get().deobfSitesByMark[key]) return;
    set((s) => {
      const loading = new Set(s.deobfLoadingSites); loading.add(key);
      return { deobfLoadingSites: loading };
    });
    try {
      const sites = await api.deobfScanSites(className, methodName);
      set((s) => ({
        deobfSitesByMark: { ...s.deobfSitesByMark, [key]: sites },
      }));
    } catch (err) {
      get().addLog("ERROR", `Site scan failed for ${className}->${methodName}: ${err}`, "Deobf");
    } finally {
      set((s) => {
        const loading = new Set(s.deobfLoadingSites); loading.delete(key);
        return { deobfLoadingSites: loading };
      });
    }
  },

  stopDeobf: () => {
    // Only meaningful while something is running, but harmless otherwise —
    // the flag is reset when the next run starts.
    if (
      get().deobfRunningAll ||
      get().deobfRunningShown ||
      get().deobfRunningMarks.size > 0
    ) {
      set({ deobfStopRequested: true });
      get().addLog("INFO", "Stopping deobfuscation after the current batch…", "Deobf");
    }
  },

  runDeobfBatches: async (requests: DeobfSiteRequest[]) => {
    const limit = get().execInstrLimit;
    const threads = get().deobfNumThreads;
    // Batch so state merges (and the "x / y" status redraws) several times
    // during a long run, and so we have cancellation checkpoints. Each
    // batch still runs in parallel on the backend, so batch >= worker
    // count keeps throughput up.
    const batchSize = Math.max(8, threads);
    const collected: ExecResult[] = [];
    let stopped = false;
    for (let i = 0; i < requests.length; i += batchSize) {
      if (get().deobfStopRequested) { stopped = true; break; }
      const batch = requests.slice(i, i + batchSize);
      const results = await api.deobfRunSpecificSites(batch, limit, threads);
      collected.push(...results);
      // Merge this batch live: the per-site cache (status counter + per-row
      // result lines) and the inline centre-panel annotations. Results are
      // paired to requests by index (the backend preserves input order).
      set((s) => {
        const bySite = { ...s.deobfSiteResults };
        results.forEach((res, idx) => {
          const req = batch[idx];
          if (req && res) {
            bySite[deobfSiteKey(req.className, req.methodName, req.callerClass, req.offset)] = res;
          }
        });
        const { replacements, applied } = applyResultsToReplacements(
          results,
          s.deobfReplacements,
          s.appliedDeobf,
        );
        return {
          deobfSiteResults: bySite,
          deobfReplacements: replacements,
          appliedDeobf: applied,
        };
      });
    }
    return { stopped, collected };
  },

  runDeobfForMark: async (className: string, methodName: string) => {
    if (!isTauri()) return;
    const key = deobfMarkKey(className, methodName);
    const norm = className.replace(/^L/, "").replace(/;$/, "");
    set((s) => {
      const running = new Set(s.deobfRunningMarks); running.add(key);
      // Clear any stale stop request from a previous run.
      return { deobfRunningMarks: running, deobfStopRequested: false };
    });
    try {
      // Make sure we have the (cached) call-site listing — we drive the
      // run site-by-site so the per-row "x / y deobfuscated" status ticks
      // live and the user can see it isn't stuck.
      await get().loadDeobfSites(className, methodName);
      const sites = get().deobfSitesByMark[key] ?? [];
      if (sites.length === 0) {
        get().addLog("INFO", `No call sites to run for ${norm}->${methodName}`, "Deobf");
        return;
      }
      const requests: DeobfSiteRequest[] = sites.map((s) => ({
        className,
        methodName,
        args: s.staticArgs,
        callerClass: s.callerClass,
        callerMethod: s.callerMethod,
        offset: s.offset,
        callSite: s.callSite,
      }));
      const { stopped, collected } = await get().runDeobfBatches(requests);
      // Keep the per-mark list cache in sync for backwards-compat views.
      set((s) => ({
        deobfResultsByMark: { ...s.deobfResultsByMark, [key]: collected },
      }));
      get().saveCache();
      const okCount = collected.filter((r) => !r.error).length;
      get().addLog(
        "INFO",
        `${stopped ? "Stopped" : "Ran"} deobfuscator ${norm}->${methodName}: ${okCount}/${collected.length} site(s) resolved${stopped ? ` (of ${sites.length})` : ""}`,
        "Deobf"
      );
    } catch (err) {
      get().addLog("ERROR", `runDeobfForMark failed: ${err}`, "Deobf");
    } finally {
      set((s) => {
        const running = new Set(s.deobfRunningMarks); running.delete(key);
        return { deobfRunningMarks: running };
      });
    }
  },

  runAllDeobfMarks: async () => {
    if (!isTauri()) return;
    set({ deobfRunningAll: true, deobfStopRequested: false });
    try {
      // Drive the run from the frontend so it's cancellable and shows
      // live per-method progress. Scan each mark's sites (cached after the
      // first time) and flatten into one request list.
      const marks = get().deobfMarks;
      const requests: DeobfSiteRequest[] = [];
      for (const m of marks) {
        if (get().deobfStopRequested) break;
        await get().loadDeobfSites(m.className, m.methodName);
        const key = deobfMarkKey(m.className, m.methodName);
        for (const s of get().deobfSitesByMark[key] ?? []) {
          requests.push({
            className: m.className,
            methodName: m.methodName,
            args: s.staticArgs,
            callerClass: s.callerClass,
            callerMethod: s.callerMethod,
            offset: s.offset,
            callSite: s.callSite,
          });
        }
      }
      const { stopped, collected } = await get().runDeobfBatches(requests);
      get().saveCache();
      const okCount = collected.filter((r) => !r.error).length;
      get().addLog(
        "INFO",
        `Deobfuscate-all ${stopped ? "stopped" : "completed"}: ${marks.length} method(s), ${okCount}/${collected.length} site(s) resolved${stopped ? ` (of ${requests.length})` : ""}`,
        "Deobf"
      );
    } catch (err) {
      get().addLog("ERROR", `runAllDeobfMarks failed: ${err}`, "Deobf");
    } finally {
      set({ deobfRunningAll: false });
    }
  },

  runDeobfSite: async (mark, site) => {
    if (!isTauri()) return;
    const key = deobfSiteKey(mark.className, mark.methodName, site.callerClass, site.offset);
    set((s) => {
      const running = new Set(s.deobfRunningSites); running.add(key);
      return { deobfRunningSites: running };
    });
    try {
      // One IPC call for one site. The backend's parallel path is
      // overkill for n=1 but the code path is identical so we get
      // free correctness — exec just lands on a single rayon worker.
      const results = await api.deobfRunSpecificSites(
        [{
          className: mark.className,
          methodName: mark.methodName,
          args: site.staticArgs,
          callerClass: site.callerClass,
          callerMethod: site.callerMethod,
          offset: site.offset,
          callSite: site.callSite,
        }],
        get().execInstrLimit,
        get().deobfNumThreads,
      );
      const result = results[0];
      if (result) {
        // Apply to inline annotations too — see runDeobfForMark
        // for the rationale. A single-site run needs the same
        // centre-panel update so the caller class shows the string.
        const { replacements, applied } = applyResultsToReplacements(
          [result],
          get().deobfReplacements,
          get().appliedDeobf,
        );
        set((s) => ({
          deobfSiteResults: { ...s.deobfSiteResults, [key]: result },
          deobfReplacements: replacements,
          appliedDeobf: applied,
        }));
        get().saveCache();
      }
    } catch (err) {
      get().addLog("ERROR", `runDeobfSite failed: ${err}`, "Deobf");
    } finally {
      set((s) => {
        const running = new Set(s.deobfRunningSites); running.delete(key);
        return { deobfRunningSites: running };
      });
    }
  },

  runDeobfShown: async () => {
    if (!isTauri()) return;
    // Snapshot the currently-visible sites via the same selector the
    // UI uses. Doing this here (rather than reading from the UI)
    // keeps the "shown" semantics consistent — whatever the user
    // sees is exactly what gets executed.
    const filtered = get().filteredDeobfSites();
    const marksByKey = new Map(get().deobfMarks.map((m) => [deobfMarkKey(m.className, m.methodName), m]));
    const sites: Array<Parameters<typeof api.deobfRunSpecificSites>[0][number]> = [];
    for (const [markKey, ss] of filtered) {
      const mark = marksByKey.get(markKey);
      if (!mark) continue;
      for (const s of ss) {
        sites.push({
          className: mark.className,
          methodName: mark.methodName,
          args: s.staticArgs,
          callerClass: s.callerClass,
          callerMethod: s.callerMethod,
          offset: s.offset,
          callSite: s.callSite,
        });
      }
    }
    if (sites.length === 0) {
      get().addLog("INFO", "Deobfuscate-shown: nothing matches the current filter", "Deobf");
      return;
    }
    set({ deobfRunningShown: true, deobfStopRequested: false });
    try {
      const { stopped, collected } = await get().runDeobfBatches(sites);
      get().saveCache();
      const okCount = collected.filter((r) => !r.error).length;
      get().addLog(
        "INFO",
        `Deobfuscate-shown ${stopped ? "stopped" : "completed"}: ${okCount}/${collected.length} site(s) resolved${stopped ? ` (of ${sites.length})` : ""}`,
        "Deobf"
      );
    } catch (err) {
      get().addLog("ERROR", `runDeobfShown failed: ${err}`, "Deobf");
    } finally {
      set({ deobfRunningShown: false });
    }
  },

  filteredDeobfSites: () => {
    const { deobfMarks, deobfSitesByMark, deobfFilter } = get();
    const out = new Map<string, DeobfSite[]>();
    // Normalise the filter once: lowercase + slashes (matches how
    // callerClass is stored — internal Dalvik form).
    const filter = deobfFilter.trim().toLowerCase().replace(/\./g, "/");
    for (const m of deobfMarks) {
      const markKey = deobfMarkKey(m.className, m.methodName);
      const sites = deobfSitesByMark[markKey];
      if (!sites) continue;
      if (!filter) {
        out.set(markKey, sites);
        continue;
      }
      const matching = sites.filter((s) => s.callerClass.toLowerCase().includes(filter));
      if (matching.length > 0) {
        out.set(markKey, matching);
      }
    }
    return out;
  },

  // ── Method renames ──
  addRename: (rename: MethodRename) => {
    set((s) => {
      // Replace existing rename for same class+method, or append.
      const filtered = s.renames.filter(
        (r) => !(r.className === rename.className && r.methodName === rename.methodName)
      );
      const next = [...filtered, rename];
      return { renames: next };
    });
    get().saveCache();
    get().addLog(
      "INFO",
      `Renamed ${rename.methodName} → ${rename.newName} in ${rename.className}`,
      "Rename"
    );
  },

  removeRename: (className: string, methodName: string) => {
    set((s) => ({
      renames: s.renames.filter(
        (r) => !(r.className === className && r.methodName === methodName)
      ),
    }));
    get().saveCache();
  },

  clearRenames: () => {
    set({ renames: [] });
    get().saveCache();
  },

  // ── Cache persistence (localStorage) ──
  // Schema: in addition to the legacy flat fields (kept for backwards-compat
  // with single-slot caches), `slotFrontendStates` carries per-slot snapshots
  // for every slot we've touched this session. Before writing we also fold the
  // current flat fields into the active slot's entry so the most recent edits
  // are captured even if the user never switched away.
  saveCache: () => {
    try {
      const state = get();
      // Per-slot snapshots are now the SOLE source of truth for
      // deobfReplacements / appliedDeobf / renames / scriptOutput etc.
      // The legacy global blob (deobfReplacements at the top level of
      // the cache) was leaking across APK boundaries — see #76 — and
      // is no longer written. `loadCache` still reads it once as a
      // one-time migration into slotFrontendStates[activeSlotId].
      const slotStates = { ...state.slotFrontendStates };
      if (state.activeSlotId) {
        slotStates[state.activeSlotId] = snapshotFromState(state);
      }
      const cache = {
        settings: state.settings,
        slotFrontendStates: slotStates,
      };
      // persistSet writes localStorage (fast, same-session) AND mirrors to
      // the durable backend store so the cache survives restarts on Linux,
      // where WebKitGTK drops localStorage for the tauri:// origin.
      persistSet("platypus_cache", JSON.stringify(cache));
    } catch {
      // localStorage unavailable (Tauri webview sandboxing, etc.) — ignore.
    }
  },

  loadCache: async () => {
    try {
      // Read localStorage first; on a fresh Linux launch it's empty, so
      // persistGet falls back to the durable backend store.
      const raw = await persistGet("platypus_cache");
      if (!raw) return;
      const cache = JSON.parse(raw) as {
        // Legacy fields — read only for one-time migration. saveCache
        // no longer writes these; once a session writes its first cache
        // entry, the legacy keys will be absent forever.
        deobfReplacements?: Record<string, DeobfReplacement>;
        appliedDeobf?: string[];
        renames?: MethodRename[];
        /** @deprecated migrated to <cache>/scripts/scratch.py on first run */
        scriptCode?: string;
        settings?: Partial<AppSettings>;
        slotFrontendStates?: Record<string, SlotFrontendState>;
      };
      const updates: Partial<StoreState> = {};
      // Note: cache.scriptCode is no longer consumed here. The migration
      // path (legacy single-script → on-disk scratch.py) lives in `loadScripts`,
      // which reads localStorage directly when the library is empty.
      if (cache.settings) {
        // Merge persisted settings with defaults (safe against new keys added later)
        updates.settings = { ...DEFAULT_SETTINGS, ...cache.settings };
      }
      if (cache.slotFrontendStates) {
        updates.slotFrontendStates = cache.slotFrontendStates;
      }
      // ── One-time migration of pre-#76 caches ──
      // Old caches stored deobf state at the top level (shared across
      // every APK ever opened). If the user has a legacy blob AND no
      // per-slot snapshots exist yet, fold the blob into the active
      // slot's snapshot on next save. We can't do better than that
      // without knowing which APK the replacements originally belonged
      // to — they were genuinely unscoped on disk.
      //
      // After this hydration runs, the FIRST `saveCache` call will
      // re-serialise without the legacy keys, so the migration is
      // one-and-done.
      const hasLegacy =
        cache.deobfReplacements ||
        (cache.appliedDeobf && cache.appliedDeobf.length > 0) ||
        (cache.renames && cache.renames.length > 0);
      if (hasLegacy && (!cache.slotFrontendStates || Object.keys(cache.slotFrontendStates).length === 0)) {
        updates.deobfReplacements = cache.deobfReplacements ?? {};
        updates.appliedDeobf = new Set(cache.appliedDeobf ?? []);
        updates.renames = cache.renames ?? [];
      }
      set(updates);
    } catch {
      // Corrupt cache — ignore.
    }
  },

  // ── Navigate to class by name ──
  navigateToClass: async (className: string) => {
    const { tree, openTabs, activeLanguage } = get();
    // Keep navigation within the embedded APK when one is in focus.
    const slotId = openTabs.find((t) => t.id === get().activeTabId)?.slotId;
    // Parse the embedded subtree on demand so the reveal can find the class.
    await get().ensureEmbeddedLoaded(slotId);
    // Also surface the class in the left treeview (expand + select + scroll).
    get().revealInTree(className, slotId);
    const roots = slotId
      ? (embeddedRootsForSlot(get().embeddedTrees, slotId) ?? tree)
      : tree;
    const node = findNodeInTree(roots, className);
    if (node) {
      await get().openNode(node);
      return;
    }

    // Fallback: load directly (slot-scoped when navigating inside an embedded APK).
    const tabId = makeTabId(className, activeLanguage, slotId);
    if (openTabs.find((t) => t.id === tabId)) {
      set({ activeTabId: tabId });
      return;
    }
    try {
      const code =
        activeLanguage === "java"
          ? await api.getClassJava(className, get().settings.keepKotlinIntrinsics, slotId)
          : await api.getClassSmali(className, slotId);
      const tab: CodeTab = {
        id: tabId,
        title: className.split("/").pop()?.replace(";", "") ?? className,
        className,
        language: activeLanguage,
        code,
        isDirty: false,
        slotId,
      };
      set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId }));
    } catch (err) {
      get().addLog("ERROR", `Navigation to ${className} failed: ${err}`, "Editor");
    }
  },

  // ── Navigate to a specific member definition (go-to-definition) ──
  navigateToMember: async (classRef: string, memberName: string) => {
    const { activeLanguage, openTabs, tree } = get();
    // Stay within the embedded APK when one is in focus.
    const slotId = openTabs.find((t) => t.id === get().activeTabId)?.slotId;
    await get().ensureEmbeddedLoaded(slotId);
    const roots = slotId
      ? (embeddedRootsForSlot(get().embeddedTrees, slotId) ?? tree)
      : tree;

    // Normalise "Lcom/example/Foo;" → "com/example/Foo"
    let className = classRef.startsWith("L") && classRef.endsWith(";")
      ? classRef.slice(1, -1)
      : classRef;

    // Guard: malformed class name (contains method signature chars) — silently bail
    if (className.includes("(") || (className.includes("->") && !className.startsWith("L"))) {
      get().addLog("WARN", `Skipping malformed class ref: ${classRef}`, "Editor");
      return;
    }

    // Resolve short class names (e.g. "wfg" → "hivhi/wfg") via tree fuzzy match
    if (!className.includes("/")) {
      const treeNode = findNodeInTree(roots, className);
      if (treeNode?.fullName) {
        const resolved = treeNode.fullName.startsWith("L") && treeNode.fullName.endsWith(";")
          ? treeNode.fullName.slice(1, -1)
          : treeNode.fullName;
        className = resolved;
      }
    }

    // Surface the (now-resolved) class in the left treeview.
    get().revealInTree(className, slotId);

    const tabId = makeTabId(className, activeLanguage, slotId);
    const existing = openTabs.find((t) => t.id === tabId);

    if (existing) {
      const line = findCodeLine(existing.code, existing.language, memberName, "method");
      set({ activeTabId: tabId, selectedLine: line });
      return;
    }

    try {
      const code =
        activeLanguage === "java"
          ? await api.getClassJava(className, get().settings.keepKotlinIntrinsics, slotId)
          : await api.getClassSmali(className, slotId);

      const tab: CodeTab = {
        id: tabId,
        title: className.split("/").pop()?.replace(";", "") ?? className,
        className,
        language: activeLanguage,
        code,
        isDirty: false,
        slotId,
      };

      const line = findCodeLine(code, activeLanguage, memberName, "method");
      set((s) => ({ openTabs: [...s.openTabs, tab], activeTabId: tabId, selectedLine: line }));
      get().addLog("DEBUG", `Navigated to ${className}.${memberName}`, "Editor");
    } catch (err) {
      get().addLog("ERROR", `Could not navigate to ${className}.${memberName}: ${err}`, "Editor");
    }
  },
}));

// ─── Helper: find node in tree ────────────────────────────────────────────────

function findNodeInTree(nodes: TreeNode[], className: string): TreeNode | null {
  for (const node of nodes) {
    if (node.fullName === className || node.name === className) return node;
    // Short-name match: "HmApplication$bdogw" against "Lcom/example/HmApplication$bdogw;"
    if (node.kind === "class" && !className.includes("/") && node.fullName) {
      const shortName = node.fullName.replace(/^L/, "").replace(/;$/, "").split("/").pop();
      if (shortName === className) return node;
    }
    if (node.children) {
      const found = findNodeInTree(node.children, className);
      if (found) return found;
    }
  }
  return null;
}

/** Strip a Dalvik `L…;` wrapper so `Lcom/Foo;` and `com/Foo` compare equal. */
function stripClassWrapper(s: string): string {
  return s.startsWith("L") && s.endsWith(";") ? s.slice(1, -1) : s;
}

/** Find the *path* (root → matching class node) for `className`, so callers
 *  can expand every ancestor folder to reveal the node. Matches the
 *  L/;-normalised full name, then falls back to a short-name match the way
 *  {@link findNodeInTree} does. Returns `null` when not found. */
function findNodePath(nodes: TreeNode[], className: string): TreeNode[] | null {
  const target = stripClassWrapper(className);
  const targetShort = target.split("/").pop();

  function walk(list: TreeNode[], trail: TreeNode[]): TreeNode[] | null {
    for (const node of list) {
      const here = [...trail, node];
      if (node.fullName) {
        const full = stripClassWrapper(node.fullName);
        if (full === target) return here;
      }
      if (node.name === className) return here;
      // Short-name match only when the query is unqualified.
      if (
        node.kind === "class" &&
        !className.includes("/") &&
        node.fullName &&
        stripClassWrapper(node.fullName).split("/").pop() === targetShort
      ) {
        return here;
      }
      if (node.children) {
        const found = walk(node.children, here);
        if (found) return found;
      }
    }
    return null;
  }
  return walk(nodes, []);
}
