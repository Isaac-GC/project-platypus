// ─── Tree ────────────────────────────────────────────────────────────────────

export type NodeKind =
  | "package"
  | "class"
  | "method"
  | "field"
  | "dexfile"
  | "assets_folder"
  | "asset"
  | "source_root"
  | "resources_root"
  | "res_type"
  | "res_entry"
  | "manifest"
  | "embedded_root"
  | "embedded_apk"
  | "diff_section"
  | "diff_added"
  | "diff_removed"
  | "diff_modified";

export interface TreeNode {
  id: string;
  name: string;
  kind: NodeKind;
  fullName?: string;
  accessFlags?: string[];
  returnType?: string;
  params?: string[];
  signature?: string;
  registerCount?: number;
  instructionCount?: number;
  dexName?: string;
  children?: TreeNode[];
  isExpanded?: boolean;
  /** When set, this node belongs to a non-active slot (an embedded APK browsed
   *  inline). Reads route to that slot via the `slotId` command argument. */
  slotId?: string;
}

/** Result of loading an embedded APK for inline browsing (non-active child slot). */
export interface EmbeddedLoadResult {
  slotId: string;
  tree: TreeNode[];
  entryNames: string[];
  /** Payloads nested inside this embedded APK (recursive drill-down). */
  embedded: EmbeddedCandidate[];
}

// ─── Load result ─────────────────────────────────────────────────────────────

export interface LoadResult {
  path: string;
  tree: TreeNode[];
  dexFiles: string[];
  packageCount: number;
  classCount: number;
  methodCount: number;
  entryNames: string[];
}

// ─── Cross-references ────────────────────────────────────────────────────────

export interface XRef {
  callerClass: string;
  callerMethod: string;
  callerSignature: string;
  offset: number;
  instruction: string;
}

// ─── Call graph ──────────────────────────────────────────────────────────────

export interface CallGraphNode {
  className: string;
  methodName: string;
  signature: string;
  offset?: number;
}

export interface CallGraphResult {
  callers: CallGraphNode[];
  callees: CallGraphNode[];
}

// ─── VM Execution ────────────────────────────────────────────────────────────

export interface RunResult {
  returnValue: string;
  returnType: string;
  logs: string[];
  error?: string;
  executionTimeMs: number;
  /** When the result was a `byte[]` that parsed as a ZIP containing
   *  classes.dex, the path to the cached file. Frontend offers a one-click
   *  "Load as APK" button when set. */
  apkCachePath?: string;
}

export interface ExecResult {
  callSite: string;
  callerClass: string;
  callerMethod: string;
  offset: number;
  resolvedValue: string;
  resolvedType: string;
  error?: string;
  /** When the result was a `byte[]` that parsed as a ZIP containing
   *  classes.dex, the path to the cached file. */
  apkCachePath?: string;
}

// ─── Deobfuscation marks ─────────────────────────────────────────────────────
//
// The DEOBFUSCATION bottom-bar tab is built around three primitives:
//
// 1. `DeobfMark` — the user's "this method is a deobfuscation helper"
//    flag, persisted per-APK on the backend (see `Slot.deobf_marks`).
// 2. `DeobfSite` — one statically-discovered call site of a marked
//    method, with literal argument values baked in but NO VM execution.
//    These populate the per-method expanded view.
// 3. `DeobfBulkResult` — one marked method's batch-execution results,
//    returned by `deobf_run_all_marks`. Each entry holds an `ExecResult`
//    per site (same shape as the `find_exec` flow).

export interface DeobfMark {
  /** Normalised class (no `L`/`;`), e.g. `com/dualtext/compare/SystemSingleton`. */
  className: string;
  /** Bare method name (no proto), e.g. `KotlinClass`. */
  methodName: string;
}

export interface DeobfSite {
  callerClass: string;
  callerMethod: string;
  offset: number;
  /** Full invoke instruction text — stable display key when the
   *  call site listing collapses identical encodings. */
  callSite: string;
  /** Statically-resolved literal arg values, encoded with the same
   *  format `resolve_arg_encoding` understands (quoted strings, bare
   *  ints/hex, `@sget:…`, `@invoke!…`). Order = positional args. */
  staticArgs: string[];
}

export interface DeobfBulkResult {
  className: string;
  methodName: string;
  sites: ExecResult[];
}

// ─── Resources ───────────────────────────────────────────────────────────────

export interface ResourceEntry {
  id: string;
  name: string;
  type: string;
  path: string;
  content?: string;
}

// ─── Code tabs ───────────────────────────────────────────────────────────────

export type Language = "smali" | "java" | "xml" | "text";

export interface CodeTab {
  id: string;
  title: string;
  className: string;
  language: Language;
  code: string;
  isDirty: boolean;
  /** Set when the tab's class lives in a non-active slot (embedded APK), so
   *  re-decompiles (e.g. on a settings change) route to the right slot. */
  slotId?: string;
}

// ─── Logs ────────────────────────────────────────────────────────────────────

export type LogLevel = "DEBUG" | "INFO" | "WARN" | "ERROR";

export interface LogEntry {
  id: string;
  timestamp: number;
  level: LogLevel;
  message: string;
  tag?: string;
}

// ─── Search ──────────────────────────────────────────────────────────────────

export interface SearchResult {
  kind: "class" | "method" | "string" | "field" | "reference" | "resource";
  /** Code hits: dex class (slash form). Resource hits: the resource type. */
  className: string;
  /** Code hits: the member (caller method for refs/strings). Resource hits: name. */
  memberName?: string;
  snippet: string;
  /** Instruction codepoint for instruction-level hits (display + tie-break). */
  line?: number;
  /** Resource id for `kind === "resource"` — used to open its entry view. */
  resId?: number;
}

// ─── Deobfuscation ───────────────────────────────────────────────────────────

export interface DeobfReplacement {
  original: string;
  resolved: string;
  lineIndex: number;
  /** The Dalvik class name owning this replacement (e.g. "com/example/Foo") */
  className: string;
}

// ─── Method renames ───────────────────────────────────────────────────────────

export interface MethodRename {
  /** Dalvik class name, e.g. "hivhi/wfg" */
  className: string;
  /** Original (obfuscated) method name, e.g. "bihvbhi" */
  methodName: string;
  /** Human-readable replacement name, e.g. "decrypt" */
  newName: string;
  /** Optional Dalvik signature used to disambiguate overloads, e.g. "(Ljava/lang/String;)Ljava/lang/String;" */
  signature?: string;
}

// ─── App state ───────────────────────────────────────────────────────────────

export interface AppState {
  loadedFile: string | null;
  tree: TreeNode[];
  openTabs: CodeTab[];
  activeTabId: string | null;
  selectedNode: TreeNode | null;
  activeLanguage: Language;
  xrefs: XRef[];
  logs: LogEntry[];
  searchResults: SearchResult[];
  execResult: RunResult | null;
  findExecResults: ExecResult[];
  deobfReplacements: Record<string, DeobfReplacement>;
  appliedDeobf: string[];
}

// ─── CFG ─────────────────────────────────────────────────────────────────────

export interface CfgBlock {
  id: number;
  blockType: string;
  instructions: string[];
  firstCodepoint: number;
  isEntry: boolean;
}

export interface CfgEdge {
  sourceId: number;
  targetId: number;
  kind: string;
}

export interface MethodCfgResult {
  blocks: CfgBlock[];
  edges: CfgEdge[];
  entryId: number;
}

// ─── Method info ─────────────────────────────────────────────────────────────

export interface MethodInfo {
  name: string;
  className: string;
  returnType: string;
  params: string[];
  accessFlags: string[];
  registerCount: number;
  instructionCount: number;
  signature: string;
}

// ─── Multi-APK Project Model ──────────────────────────────────────────────────

// ─── Script library ──────────────────────────────────────────────────────

/** Metadata for one saved script in the on-disk library. */
export interface ScriptInfo {
  /** Filename (always ends in `.py`) — also acts as the script's id. */
  name: string;
  /** File size in bytes. */
  sizeBytes: number;
  /** Last-modified time, milliseconds since the Unix epoch. */
  lastModifiedMs: number;
}

// ─── Script-pane code completions ────────────────────────────────────────

/** One member of a class returned by Python introspection. */
export interface ScriptCompletionMember {
  name: string;
  /** "method" | "static_method" | "class_method" | "property" | "attribute" */
  kind: string;
  /** `inspect.signature(member)` result, or empty if unavailable. */
  signature: string;
  /** Truncated docstring. */
  doc: string;
}

/** One class returned by Python introspection. */
export interface ScriptCompletionClass {
  name: string;
  doc: string;
  members: ScriptCompletionMember[];
}

/** Snapshot of the platypus module's API surface. */
export interface ScriptIntrospection {
  classes?: Record<string, ScriptCompletionClass>;
  globals?: ScriptCompletionMember[];
  /** Set when the platypus module wasn't importable. */
  error?: string;
}

/** What the `script_get_completions` Tauri command returns. */
export interface ScriptCompletionsResult {
  introspection: ScriptIntrospection;
  platypusUnavailable: boolean;
  error?: string;
}

/** A byte-source method call observed near a dex-loader construction site. */
export interface ByteSource {
  /** Short kind, e.g. `"AssetManager.open"`, `"Context.openFileInput"`. */
  kind: string;
  /** Full Dalvik method ref of the call. */
  methodRef: string;
  /** First static-string argument if statically resolvable
   *  (e.g. `"payload.dex"`). */
  argument?: string;
  /** Codepoint of the invoke instruction. */
  codepoint: number;
}

/** One detected `DexClassLoader` / `InMemoryDexClassLoader` / `PathClassLoader`
 *  construction site, plus byte-source observations from its containing method
 *  to help the user trace the loader chain. */
export interface DexLoaderSite {
  /** Short loader name: `"DexClassLoader"`, `"InMemoryDexClassLoader"`, etc. */
  loaderClass: string;
  /** Class containing the construction. */
  callerClass: string;
  /** Containing method (with proto, e.g. `"loadStuff()V"`). */
  callerMethod: string;
  /** Codepoint of the `<init>` invoke. */
  codepoint: number;
  /** Source line if debug info is present. */
  lineNumber?: number;
  /** Full Smali invoke string. */
  instruction: string;
  /** Byte-source method calls observed in the same method. */
  byteSources: ByteSource[];
  /** Distinct static string arguments seen on byte-source calls — most
   *  likely "what asset/file does this loader read" candidates. */
  candidateAssets: string[];
}

/** Auto-detected embedded APK or ZIP-with-classes.dex inside a slot's
 *  assets/resources. Surfaced for one-click "Load as APK". */
export interface EmbeddedCandidate {
  /** Path inside the parent ZIP, e.g. `assets/payload.apk`. */
  entryPath: string;
  /** Which split it came from (`""` = base APK). */
  splitName: string;
  /** Size of the embedded blob in bytes. */
  size: number;
  /** SHA-256 of the embedded blob. */
  sha256: string;
  /** True if `AndroidManifest.xml` was found inside. */
  hasManifest: boolean;
  /** Number of `classes*.dex` members found inside. */
  dexCount: number;
  /** Best-guess display name extracted from the entry path. */
  suggestedName: string;
}

/** One logical APK in the project — either a standalone APK, a base + its
 *  splits (collapsed into a single slot), or an APK extracted from another. */
export interface SlotSummary {
  /** Stable id (sha256 of the base APK). */
  id: string;
  /** Human-readable name (package name, falls back to filename). */
  displayName: string;
  /** Filesystem path to the base APK. */
  basePath: string;
  /** Paths to additional split APKs the user has loaded. */
  splitPaths: string[];
  /** Hex SHA-256 of the base APK. */
  sha256: string;
  packageName: string | null;
  versionName: string | null;
  versionCode: number | null;
  /** `<uses-split>` declarations parsed from the base manifest — the splits
   *  this base *expects*. Compare against `loadedSplits` to spot what's missing. */
  declaredSplits: string[];
  /** Filenames of splits the user has actually loaded. */
  loadedSplits: string[];
  /** When this slot was extracted from another (e.g. an embedded APK), the
   *  parent slot's id. Null for top-level slots. */
  parentId: string | null;
  /** True when `basePath` lives inside the platypus cache dir. */
  isCached: boolean;
  /** Number of DEX files across base + loaded splits. */
  dexCount: number;
  /** Auto-detected embedded APKs/ZIPs containing classes.dex. */
  embeddedCandidates: EmbeddedCandidate[];
}

/** Snapshot of the entire project. Returned by every project-mutating command. */
export interface ProjectSnapshot {
  slots: SlotSummary[];
  activeSlotId: string | null;
  /** The slot used as the diff "B" side (formerly "slot B"). */
  compareSlotId: string | null;
  /** Resolved cache directory (e.g. `~/Library/Application Support/project_platypus`). */
  cacheDir: string;
}

// ─── App Settings ─────────────────────────────────────────────────────────────

export interface AppSettings {
  /** Language used when opening a class for the first time. */
  defaultLanguage: "smali" | "java";
  /** Code-editor font size in px (11–16). */
  fontSize: number;
  /** CSS font-family value for the code editor. */
  fontFamily: string;
  /** When true, single-clicking a tree node opens it in the editor.
   *  When false, only a double-click opens it (single-click just selects). */
  openOnSingleClick: boolean;
  /** Show line-number gutter in the code viewer. */
  showLineNumbers: boolean;
  /** How applied deobfuscations are rendered in the centre panel.
   *  - "annotated": original code with `# DEOBF: …` overlay comments (default)
   *  - "substituted": original deobf-call lines commented out, replaced with literals */
  deobfViewMode: "annotated" | "substituted";
  /** Show Kotlin runtime null-check / boilerplate calls
   *  (`Intrinsics.checkNotNullParameter`, `DefaultConstructorMarker`, etc.)
   *  in decompiled Java output. Defaults to `false` (filter them out for
   *  cleaner output, matching JADX-GUI's default). */
  keepKotlinIntrinsics: boolean;
  /** How the centre-panel class tree groups its classes.
   *
   *  - `"dexfile"` (default): preserve the backend's per-DEX grouping —
   *    `Source Code > classes.dex > com.foo > Bar`. Honest about which
   *    DEX a class came from; useful when triaging multi-DEX APKs where
   *    classes2.dex / classes3.dex hold meaningfully different code.
   *  - `"merged"`: flatten the DEX layer so packages from every DEX
   *    collapse into one tree — `Source Code > com.foo > [Bar, Baz]`.
   *    Useful for class-name-first navigation when you don't care
   *    which DEX a class came from. Duplicate-named classes from
   *    different DEXs still appear separately; the dex_name field
   *    on each class node is preserved so the tooltip / file open
   *    routes to the correct backend entry.
   *
   *  Toggled client-side via `flattenTreeByPackage()`; no APK reload
   *  needed. */
  treeGroupBy: "dexfile" | "merged";
}

export const DEFAULT_SETTINGS: AppSettings = {
  defaultLanguage: "java",
  fontSize: 13,
  fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
  openOnSingleClick: true,
  showLineNumbers: true,
  deobfViewMode: "annotated",
  keepKotlinIntrinsics: false,
  treeGroupBy: "dexfile",
};

// ─── Script execution ─────────────────────────────────────────────────────────

export interface ScriptRunResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  durationMs: number;
  /** Number of lines the backend wrapper prepended before the user's code.
   *  The script-panel uses this to remap `File "/tmp/wrapper.py", line N`
   *  traceback frames back to the user-code line numbers shown in the
   *  CodeMirror editor. Backend supplies this; defaults to 0 for backward
   *  compatibility with older servers (web mode) that don't return it. */
  prologueLines?: number;
  /** Absolute path of the wrapper temp file. Traceback frames pointing at
   *  this path are treated as "jump to editor line" rather than "copy
   *  path to clipboard". Empty when the backend doesn't expose it. */
  wrapperPath?: string;
}

/** One entry in the script-pane's recent-runs timeline. Wraps a
 *  [`ScriptRunResult`] with the script name + a finished-at timestamp so
 *  the UI can show "scratch.py · 2s ago" headers without re-deriving
 *  the metadata. */
export interface ScriptRunEntry extends ScriptRunResult {
  /** Stable ID per run — used as the React key + for "delete this entry"
   *  actions. We use Date.now() + a tiny random suffix to avoid collisions
   *  within the same millisecond. */
  id: string;
  /** Unix-ms timestamp the run completed at. Renders as "2s ago" in the
   *  header; persisted across reloads via the cache. */
  finishedAt: number;
  /** Name of the script tab that produced this run, or `null` if the
   *  user hit Run without a saved script. Shown in the entry header so
   *  multi-script users can tell their outputs apart. */
  scriptName: string | null;
}

export interface LintDiagnostic {
  /** 0-based line */
  line: number;
  /** 0-based column */
  col: number;
  endLine?: number;
  endCol?: number;
  code: string;
  message: string;
  severity: "error" | "warning" | "info";
}

// ─── Taint analysis ───────────────────────────────────────────────────────────

export interface TaintSource {
  /** "param" | "api_return" | "field_read" */
  kind: string;
  /** Dalvik register index */
  register: number;
  /** Human-readable label: "p0 (this)", "getIntent()", … */
  label: string;
  /** Codepoint of the API call (undefined for params) */
  codepoint?: number;
  instruction?: string;
}

export interface TaintSink {
  /** "logging" | "network" | "storage" | "database" | "crypto" |
   *  "file_write" | "reflection" | "command_exec" | "webview" | "ipc" | "SMS" */
  category: string;
  methodRef: string;
  codepoint: number;
  instruction: string;
  /** 0-based argument positions that carry tainted values */
  taintedArgIndices: number[];
  /** Labels of sources flowing into this sink */
  sourcesReached: string[];
}

export interface TaintedField {
  fieldRef: string;
  codepoint: number;
  instruction: string;
  sourcesReaching: string[];
}

export interface RegisterTaintEntry {
  register: number;
  /** "vN" or "pN" shorthand */
  name: string;
  sources: string[];
}

export interface TaintAnalysisResult {
  methodRef: string;
  sources: TaintSource[];
  sinks: TaintSink[];
  taintedReturn: boolean;
  /** Source labels flowing to return value */
  returnSources: string[];
  taintedFields: TaintedField[];
  registerSummary: RegisterTaintEntry[];
}

// ── Inter-procedural taint graph ────────────────────────────────────────────

/** Per-method override applied to the taint analysis. Tagged by `kind` to
 *  match the Rust `#[serde(tag = "kind")]` convention. */
export type TaintOverride =
  | { kind: "ReturnTainted"; sources: string[] }
  | { kind: "ReturnClean" }
  | { kind: "ParamTainted"; index: number; sources: string[] }
  | { kind: "ParamClean"; index: number }
  | { kind: "ConstantValue"; value: string; typeName: string };

/** Map from method ref → list of overrides. */
export interface OverrideMap {
  overrides: Record<string, TaintOverride[]>;
}

/** One node in the call graph: a method with its analysis. */
export interface TaintNode {
  /** Same as `methodRef`. */
  id: string;
  methodRef: string;
  className: string;
  methodName: string;
  protoDesc: string;
  /** 0 = root, +n = forward (callee), -n = backward (caller). */
  depth: number;
  /** Per-method analysis. `null` when body unavailable. */
  analysis: TaintAnalysisResult | null;
  expandedForward: boolean;
  expandedBackward: boolean;
  /** True when the body could not be located (external API / abstract). */
  bodyUnavailable: boolean;
}

/** Directed edge: caller → callee at a specific call site. */
export interface TaintEdge {
  from: string;
  to: string;
  codepoint: number;
  instruction: string;
  lineNumber?: number;
}

/** The full graph: a root node plus everything discovered through expansion. */
export interface TaintGraph {
  /** Root node id. */
  root: string;
  nodes: TaintNode[];
  edges: TaintEdge[];
}