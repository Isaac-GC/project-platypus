import React, { useRef, useEffect, useState, useMemo, useCallback } from "react";
import { useAppStore, deobfMarkKey, deobfSiteKey } from "../../store/appStore";
import { api, isTauri } from "../../api/adapter";
import type { LogEntry, SearchResult, ExecResult, LogLevel, TreeNode, DeobfMark, DeobfSite } from "../../api/types";
import DiffViewer from "../code/DiffViewer";
import { buildDeobfList, applyDeobfAnnotations, buildSmaliDeobfCode } from "../../utils/deobf";

// ─── Tab button ───────────────────────────────────────────────────────────────

interface TabButtonProps {
  label: string;
  active: boolean;
  onClick: () => void;
  badge?: number;
}

const TabButton: React.FC<TabButtonProps> = ({ label, active, onClick, badge }) => (
  <button
    className={[
      "px-3 py-1.5 text-xs font-semibold border-b-2 transition-colors flex items-center gap-1",
      active
        ? "border-vs-accent text-vs-accent"
        : "border-transparent text-vs-muted hover:text-vs-text",
    ].join(" ")}
    onClick={onClick}
  >
    {label}
    {badge != null && badge > 0 && (
      <span className="bg-vs-accent text-white text-xs rounded-full px-1 min-w-4 text-center leading-none py-0.5">
        {badge > 99 ? "99+" : badge}
      </span>
    )}
  </button>
);

// ─── Log level colors ─────────────────────────────────────────────────────────

const LOG_COLOR: Record<LogLevel, string> = {
  DEBUG: "text-vs-muted",
  INFO: "text-vs-accent",
  WARN: "text-vs-warn",
  ERROR: "text-vs-error",
};

// ─── LOGS tab ─────────────────────────────────────────────────────────────────

const LogsTab: React.FC = () => {
  const logs = useAppStore((s) => s.logs);
  const clearLogs = useAppStore((s) => s.clearLogs);
  const bottomRef = useRef<HTMLDivElement>(null);
  const [autoScroll, setAutoScroll] = useState(true);

  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [logs, autoScroll]);

  if (logs.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-vs-dim text-xs italic">
        No log entries yet
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      <div className="flex items-center gap-2 px-2 py-0.5 border-b border-vs-border flex-shrink-0">
        <label className="flex items-center gap-1 text-xs text-vs-muted cursor-pointer">
          <input
            type="checkbox"
            checked={autoScroll}
            onChange={(e) => setAutoScroll(e.target.checked)}
            className="w-3 h-3"
          />
          Auto-scroll
        </label>
        <button
          className="text-xs text-vs-muted hover:text-vs-error ml-auto"
          onClick={clearLogs}
        >
          Clear
        </button>
      </div>
      <div className="flex-1 overflow-y-auto font-mono text-xs">
        {logs.map((entry) => (
          <div
            key={entry.id}
            className="flex gap-2 px-2 py-0.5 hover:bg-vs-elevated/30 border-b border-vs-border/20"
          >
            <span className="text-vs-dim flex-shrink-0 tabular-nums">
              {new Date(entry.timestamp).toLocaleTimeString("en", {
                hour12: false,
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit",
              })}
            </span>
            {entry.tag && (
              <span className="text-vs-muted flex-shrink-0 w-16 truncate">
                [{entry.tag}]
              </span>
            )}
            <span className={`${LOG_COLOR[entry.level]} flex-shrink-0 w-10`}>
              {entry.level}
            </span>
            <span className="text-vs-text break-all">{entry.message}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
};

// ─── EXECUTION tab ────────────────────────────────────────────────────────────

const ExecutionTab: React.FC = () => {
  const execSignature = useAppStore((s) => s.execSignature);
  const execArgs = useAppStore((s) => s.execArgs);
  const execResult = useAppStore((s) => s.execResult);
  const isRunning = useAppStore((s) => s.isRunning);
  const findExecResults = useAppStore((s) => s.findExecResults);
  const isFindRunning = useAppStore((s) => s.isFindRunning);
  const appliedDeobf = useAppStore((s) => s.appliedDeobf);
  const setExecSignature = useAppStore((s) => s.setExecSignature);
  const setExecArgs = useAppStore((s) => s.setExecArgs);
  const execInstrLimit = useAppStore((s) => s.execInstrLimit);
  const setExecInstrLimit = useAppStore((s) => s.setExecInstrLimit);
  const runMethod = useAppStore((s) => s.runMethod);
  const findAndExec = useAppStore((s) => s.findAndExec);
  const applyDeobf = useAppStore((s) => s.applyDeobf);
  const applyAllDeobf = useAppStore((s) => s.applyAllDeobf);
  const activeTabId = useAppStore((s) => s.activeTabId);

  return (
    <div className="flex flex-col h-full overflow-y-auto px-3 py-2 gap-3">
      {/* Method input */}
      <div className="flex flex-col gap-1">
        <label className="text-xs text-vs-muted font-semibold uppercase tracking-wider">
          Method Signature
        </label>
        <input
          type="text"
          value={execSignature}
          onChange={(e) => setExecSignature(e.target.value)}
          placeholder="Lcom/example/Foo;->bar(Ljava/lang/String;)V"
          className="bg-vs-bg border border-vs-border rounded px-2 py-1.5 text-xs font-mono text-vs-text placeholder:text-vs-dim focus:outline-none focus:border-vs-accent"
        />
      </div>

      {/* Args input */}
      <div className="flex flex-col gap-1">
        <label className="text-xs text-vs-muted font-semibold uppercase tracking-wider">
          Arguments (comma-separated)
        </label>
        <input
          type="text"
          value={execArgs}
          onChange={(e) => setExecArgs(e.target.value)}
          placeholder="arg1, arg2, arg3"
          className="bg-vs-bg border border-vs-border rounded px-2 py-1.5 text-xs font-mono text-vs-text placeholder:text-vs-dim focus:outline-none focus:border-vs-accent"
        />
      </div>

      {/* Run button + per-call instruction-budget input.
          The budget applies to both Run (single call) and Find & Run All
          (each call site). 5M default unblocks most non-trivial deobfuscators;
          dial up for AES-CBC / large string-table builders. */}
      <div className="flex items-center gap-2 self-start">
        <button
          className="flex items-center gap-1.5 px-3 py-1.5 bg-vs-accent hover:bg-vs-accent-dark text-white text-xs font-semibold rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          onClick={runMethod}
          disabled={isRunning || !execSignature.trim()}
        >
          {isRunning ? (
            <>
              <span className="animate-spin">⟳</span> Running…
            </>
          ) : (
            <>▶ Run</>
          )}
        </button>

        <label className="flex items-center gap-1.5 text-xs text-vs-muted">
          <span title="Per-call instruction budget. The VM bails out and returns null when this is exhausted.">
            ⏱ Budget:
          </span>
          <input
            type="number"
            min={1000}
            step={100_000}
            value={execInstrLimit}
            onChange={(e) => setExecInstrLimit(Number(e.target.value))}
            className="w-28 bg-vs-bg border border-vs-border rounded px-2 py-1 text-xs font-mono text-vs-text focus:outline-none focus:border-vs-accent tabular-nums"
            title="Per-call instruction budget"
          />
          <span className="text-[10px] text-vs-dim">instr</span>
          {/* Quick presets */}
          <span className="ml-1 flex items-center gap-0.5">
            {[
              { label: "1M",   value: 1_000_000 },
              { label: "5M",   value: 5_000_000 },
              { label: "20M",  value: 20_000_000 },
              { label: "100M", value: 100_000_000 },
            ].map((p) => (
              <button
                key={p.value}
                onClick={() => setExecInstrLimit(p.value)}
                className={[
                  "px-1.5 py-0.5 rounded text-[10px] font-mono border",
                  execInstrLimit === p.value
                    ? "border-vs-accent text-vs-accent bg-vs-accent/10"
                    : "border-vs-border text-vs-dim hover:text-vs-text hover:border-vs-text",
                ].join(" ")}
                title={`Set budget to ${p.value.toLocaleString()} instructions`}
              >
                {p.label}
              </button>
            ))}
          </span>
        </label>
      </div>

      {/* Result */}
      {execResult && (
        <div className="bg-vs-bg border border-vs-border rounded p-2 text-xs font-mono">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-vs-muted">Return:</span>
            <span
              className={execResult.error ? "text-vs-error" : "text-vs-success"}
            >
              {execResult.error ? `ERROR: ${execResult.error}` : execResult.returnValue}
            </span>
            <span className="text-vs-dim">({execResult.returnType})</span>
            <span className="text-vs-dim ml-auto">{execResult.executionTimeMs}ms</span>
            {/* Result was a byte[] that parses as an APK — offer one-click load. */}
            {execResult.apkCachePath && (
              <button
                className="px-1.5 py-0.5 bg-vs-accent/20 hover:bg-vs-accent/40 text-vs-accent rounded text-xs"
                title={`Cached at ${execResult.apkCachePath} — click to load as a child slot`}
                onClick={() => {
                  const parentId = useAppStore.getState().activeSlotId;
                  if (parentId && execResult.apkCachePath) {
                    void useAppStore.getState().addApkToProject(execResult.apkCachePath, parentId);
                  }
                }}
              >
                📦 Load APK
              </button>
            )}
          </div>
        </div>
      )}

      {/* Divider */}
      <div className="border-t border-vs-border" />

      {/* Deobfuscation section */}
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between">
          <span className="text-xs text-vs-muted font-semibold uppercase tracking-wider">
            Deobfuscation
          </span>
          {findExecResults.length > 0 && (
            <button
              className="text-xs text-vs-success hover:underline"
              onClick={applyAllDeobf}
            >
              Apply All
            </button>
          )}
        </div>

        <button
          className="self-start flex items-center gap-1.5 px-3 py-1.5 bg-vs-elevated hover:bg-vs-elevated/80 border border-vs-border text-vs-text text-xs font-semibold rounded transition-colors disabled:opacity-50"
          onClick={findAndExec}
          disabled={isFindRunning || !execSignature.trim()}
        >
          {isFindRunning ? (
            <>
              <span className="animate-spin">⟳</span> Scanning…
            </>
          ) : (
            <>🔍 Find & Run All Call Sites</>
          )}
        </button>

        {/* Results list */}
        {findExecResults.length > 0 && (
          <div className="flex flex-col gap-1 max-h-40 overflow-y-auto">
            {findExecResults.map((result, idx) => {
              const key = `${activeTabId ?? ""}:${result.callSite}:${idx}`;
              const applied = appliedDeobf.has(key);
              return (
                <div
                  key={idx}
                  className={[
                    "flex items-start gap-2 p-1.5 rounded border text-xs font-mono",
                    applied
                      ? "bg-vs-success/10 border-vs-success/30"
                      : "bg-vs-bg border-vs-border",
                  ].join(" ")}
                >
                  <div className="flex-1 min-w-0">
                    <div className="text-vs-muted truncate">
                      {result.callerClass.split("/").pop()}::{result.callerMethod}
                    </div>
                    <div className="text-vs-muted">@{result.offset}</div>
                    <div className={result.error ? "text-vs-error" : "text-vs-success"}>
                      → {result.error ?? `"${result.resolvedValue}"`}
                    </div>
                  </div>
                  {!applied && !result.error && (
                    <button
                      className="flex-shrink-0 px-1.5 py-0.5 bg-vs-success/20 hover:bg-vs-success/40 text-vs-success rounded text-xs"
                      onClick={() => applyDeobf(idx)}
                    >
                      Apply
                    </button>
                  )}
                  {/* Result was a byte[] that parses as an APK — offer one-click load. */}
                  {result.apkCachePath && (
                    <button
                      className="flex-shrink-0 px-1.5 py-0.5 bg-vs-accent/20 hover:bg-vs-accent/40 text-vs-accent rounded text-xs"
                      title={`Cached at ${result.apkCachePath} — click to load as a child slot`}
                      onClick={() => {
                        const parentId = useAppStore.getState().activeSlotId;
                        if (parentId && result.apkCachePath) {
                          void useAppStore.getState().addApkToProject(result.apkCachePath, parentId);
                        }
                      }}
                    >
                      📦 Load APK
                    </button>
                  )}
                  {applied && (
                    <span className="flex-shrink-0 text-vs-success text-xs">✓</span>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {findExecResults.length === 0 && !isFindRunning && (
          <span className="text-xs text-vs-dim italic">
            No results yet. Enter a method signature and click "Find & Run All Call Sites".
          </span>
        )}
      </div>
    </div>
  );
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Flatten a tree into a sorted list of class fullNames */
function flattenClasses(nodes: TreeNode[]): string[] {
  const out: string[] = [];
  function walk(n: TreeNode) {
    if (n.kind === "class" && n.fullName) {
      // Strip Dalvik L/; wrapper for display
      out.push(n.fullName.startsWith("L") && n.fullName.endsWith(";")
        ? n.fullName.slice(1, -1)
        : n.fullName);
    }
    n.children?.forEach(walk);
  }
  nodes.forEach(walk);
  return out.sort();
}

// ─── DIFF tab ─────────────────────────────────────────────────────────────────

const DiffTab: React.FC = () => {
  // ── Store ──
  const openTabs        = useAppStore((s) => s.openTabs);
  const activeTabId     = useAppStore((s) => s.activeTabId);
  const deobfReplacements = useAppStore((s) => s.deobfReplacements);
  const appliedDeobf    = useAppStore((s) => s.appliedDeobf);
  const activeLanguage  = useAppStore((s) => s.activeLanguage);

  const loadedFileB     = useAppStore((s) => s.loadedFileB);
  const treeB           = useAppStore((s) => s.treeB);
  const isLoadingB      = useAppStore((s) => s.isLoadingB);
  const diffMode        = useAppStore((s) => s.diffMode);
  const diffClassA      = useAppStore((s) => s.diffClassA);
  const diffClassB      = useAppStore((s) => s.diffClassB);
  const diffCodeA       = useAppStore((s) => s.diffCodeA);
  const diffCodeB       = useAppStore((s) => s.diffCodeB);
  const isDiffLoading   = useAppStore((s) => s.isDiffLoading);
  const loadFileB       = useAppStore((s) => s.loadFileB);
  const loadFileBObject = useAppStore((s) => s.loadFileBObject);
  const setDiffMode     = useAppStore((s) => s.setDiffMode);
  const setDiffClassA   = useAppStore((s) => s.setDiffClassA);
  const setDiffClassB   = useAppStore((s) => s.setDiffClassB);
  const loadDiff        = useAppStore((s) => s.loadDiff);

  const activeTab = openTabs.find((t) => t.id === activeTabId) ?? null;

  // ── Deobf diff (original mode) ──
  const deobfCode = useMemo(() => {
    if (!activeTab) return undefined;
    if (activeTab.language === "smali") {
      // For smali, codepoints ≈ line indices — use inline substitution.
      return buildSmaliDeobfCode(activeTab.code, deobfReplacements, appliedDeobf, activeTab.className);
    }
    // For Java (and any other language), use offset-aware per-instance
    // annotation (each call site gets its own value, no collapsing).
    const deobfList = buildDeobfList(deobfReplacements, appliedDeobf, activeTab.className);
    return applyDeobfAnnotations(activeTab.code, activeTab.language, deobfList);
  }, [activeTab, deobfReplacements, appliedDeobf]);

  // ── APK diff — class lists ──
  const classesA = useMemo(
    () => openTabs
      .filter((t) => t.language === activeLanguage && t.className !== "__manifest__" && !t.className.startsWith("__res__"))
      .map((t) => t.className)
      .sort(),
    [openTabs, activeLanguage]
  );
  const classesB = useMemo(() => flattenClasses(treeB), [treeB]);

  // When the active tab changes, auto-select it as class A
  useEffect(() => {
    if (diffMode === "apk" && activeTab && activeTab.className !== "__manifest__") {
      setDiffClassA(activeTab.className);
    }
  }, [activeTabId, diffMode]); // eslint-disable-line react-hooks/exhaustive-deps

  // When classA changes, try to auto-match in B
  useEffect(() => {
    if (diffMode === "apk" && diffClassA && classesB.length > 0) {
      const shortName = diffClassA.split("/").pop() ?? "";
      const match = classesB.find((c) => c === diffClassA)
        ?? classesB.find((c) => c.split("/").pop() === shortName);
      if (match) setDiffClassB(match);
    }
  }, [diffClassA, classesB.length, diffMode]); // eslint-disable-line react-hooks/exhaustive-deps

  // ── Load B APK via file picker or drop ──
  const handleLoadB = useCallback(async () => {
    if (isTauri()) {
      const path = await api.openFileDialog();
      if (path) loadFileB(path);
    } else {
      const input = document.createElement("input");
      input.type = "file";
      input.accept = ".apk,.dex,.xapk,.jar,.aab";
      input.onchange = () => {
        const file = input.files?.[0];
        if (file) loadFileBObject(file);
      };
      input.click();
    }
  }, [loadFileB, loadFileBObject]);

  // ── Render ──
  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Mode toggle */}
      <div className="flex items-center gap-1 px-2 py-1 border-b border-vs-border flex-shrink-0 bg-vs-elevated">
        <button
          className={["px-2 py-0.5 rounded text-xs font-semibold transition-colors",
            diffMode === "apk"
              ? "bg-vs-accent text-white"
              : "text-vs-muted hover:text-vs-text",
          ].join(" ")}
          onClick={() => setDiffMode("apk")}
        >
          APK Compare
        </button>
        <button
          className={["px-2 py-0.5 rounded text-xs font-semibold transition-colors",
            diffMode === "deobf"
              ? "bg-vs-accent text-white"
              : "text-vs-muted hover:text-vs-text",
          ].join(" ")}
          onClick={() => setDiffMode("deobf")}
        >
          Deobfuscation
        </button>
      </div>

      {/* ── APK Compare mode ── */}
      {diffMode === "apk" && (
        <>
          {/* Controls bar */}
          <div className="flex items-center gap-2 px-2 py-1.5 border-b border-vs-border flex-shrink-0 flex-wrap">
            {/* Class A selector */}
            <div className="flex flex-col gap-0.5 flex-1 min-w-0">
              <span className="text-xs text-vs-muted font-semibold">APK A (left)</span>
              <select
                value={diffClassA ?? ""}
                onChange={(e) => setDiffClassA(e.target.value || null)}
                className="bg-vs-bg border border-vs-border rounded px-1.5 py-0.5 text-xs text-vs-text focus:outline-none focus:border-vs-accent w-full"
              >
                <option value="">— select class —</option>
                {classesA.map((c) => (
                  <option key={c} value={c}>{c.split("/").pop()}</option>
                ))}
              </select>
            </div>

            {/* vs */}
            <span className="text-vs-dim text-sm font-bold flex-shrink-0">↔</span>

            {/* Class B selector + load B */}
            <div className="flex flex-col gap-0.5 flex-1 min-w-0">
              <div className="flex items-center justify-between">
                <span className="text-xs text-vs-muted font-semibold">
                  APK B (right){loadedFileB && <span className="ml-1 text-vs-dim font-normal">— {loadedFileB.split(/[\\/]/).pop()}</span>}
                </span>
                <button
                  className="text-xs text-vs-accent hover:underline flex-shrink-0"
                  onClick={handleLoadB}
                  disabled={isLoadingB}
                >
                  {isLoadingB ? "Loading…" : loadedFileB ? "Change…" : "Load APK B"}
                </button>
              </div>
              <select
                value={diffClassB ?? ""}
                onChange={(e) => setDiffClassB(e.target.value || null)}
                disabled={classesB.length === 0}
                className="bg-vs-bg border border-vs-border rounded px-1.5 py-0.5 text-xs text-vs-text focus:outline-none focus:border-vs-accent w-full disabled:opacity-40"
              >
                <option value="">— select class —</option>
                {classesB.map((c) => (
                  <option key={c} value={c}>{c.split("/").pop()}</option>
                ))}
              </select>
            </div>

            {/* Compare button */}
            <button
              className="flex-shrink-0 self-end px-3 py-1 bg-vs-accent hover:bg-vs-accent-dark text-white text-xs font-semibold rounded disabled:opacity-40 transition-colors"
              disabled={!diffClassA || !diffClassB || isDiffLoading}
              onClick={loadDiff}
            >
              {isDiffLoading ? "…" : "Compare"}
            </button>
          </div>

          {/* Diff viewer */}
          <div className="flex-1 overflow-hidden">
            {!loadedFileB ? (
              <div className="flex flex-col items-center justify-center h-full gap-3 text-vs-dim">
                <span className="text-3xl">⚖️</span>
                <p className="text-xs text-center">
                  Click <strong className="text-vs-text">Load APK B</strong> to load a second APK for comparison
                </p>
              </div>
            ) : !diffCodeA && !diffCodeB ? (
              <div className="flex items-center justify-center h-full text-vs-dim text-xs italic">
                {diffClassA && diffClassB
                  ? `Click Compare to diff "${diffClassA.split("/").pop()}" between the two APKs`
                  : "Select a class from each APK, then click Compare"}
              </div>
            ) : (
              <DiffViewer
                leftCode={diffCodeA ?? ""}
                rightCode={diffCodeB ?? ""}
                leftLabel={`A: ${diffClassA?.split("/").pop() ?? ""}`}
                rightLabel={`B: ${diffClassB?.split("/").pop() ?? ""}`}
              />
            )}
          </div>
        </>
      )}

      {/* ── Deobfuscation mode ── */}
      {diffMode === "deobf" && (
        <div className="flex-1 overflow-hidden">
          <DiffViewer
            leftCode={activeTab?.code}
            rightCode={deobfCode}
            leftLabel="Original"
            rightLabel="Deobfuscated"
          />
        </div>
      )}
    </div>
  );
};

// ─── DEOBFUSCATION tab ────────────────────────────────────────────────────────
//
// The persistent companion to the EXECUTION tab's one-shot
// "Find & Run All Call Sites". This tab is built around a curated
// list of methods the user has flagged as deobfuscation helpers
// (right-click → Mark as deobfuscator from either the tree or the
// code view). Each mark expands to show its statically-discovered
// call sites with literal arg values; per-row ▶ runs one site, per-
// method "Run all sites" runs that method's sites, and the top-level
// "Deobfuscate All" runs every mark's every site in one batch.
//
// Marks persist per-APK (backend Slot.deobf_marks; UI hydrates via
// loadDeobfMarks on slot activation). Per-mark site listings and
// execution results are cached in-store and dropped on slot switch.

/** Format one DeobfSite's literal args for display. We deliberately
 *  show the raw encoded form (quoted strings, bare ints, `@sget:…`,
 *  `@invoke!…`) because that's the exact form the executor will use
 *  — surprises are less likely. Empty arg lists show as `(no args)`. */
function formatStaticArgs(args: string[]): string {
  if (!args.length) return "(no args)";
  return args.join(", ");
}

interface DeobfMarkRowProps {
  mark: DeobfMark;
  /** Pre-filtered sites passed in by the parent so the row doesn't
   *  need to know about the filter or re-derive it on every render.
   *  `undefined` here means "sites haven't been loaded yet" — distinct
   *  from `[]` ("loaded, zero matches"). */
  filteredSites: DeobfSite[] | undefined;
  /** True when the filter is active AND no sites matched — used to
   *  show a friendlier empty-state inside the expanded body. */
  filterActive: boolean;
}

const DeobfMarkRow: React.FC<DeobfMarkRowProps> = ({ mark, filteredSites, filterActive }) => {
  const markKey  = deobfMarkKey(mark.className, mark.methodName);
  const expanded = useAppStore((s) => s.deobfExpandedMarks.has(markKey));
  const allSites = useAppStore((s) => s.deobfSitesByMark[markKey]);
  const loadingSites = useAppStore((s) => s.deobfLoadingSites.has(markKey));
  const running  = useAppStore((s) => s.deobfRunningMarks.has(markKey));
  const toggleExpanded = useAppStore((s) => s.toggleDeobfExpanded);
  const loadSites      = useAppStore((s) => s.loadDeobfSites);
  const runForMark     = useAppStore((s) => s.runDeobfForMark);
  const stopDeobf      = useAppStore((s) => s.stopDeobf);
  const stopRequested  = useAppStore((s) => s.deobfStopRequested);
  const runDeobfSite   = useAppStore((s) => s.runDeobfSite);
  const unmark         = useAppStore((s) => s.unmarkDeobf);
  const addApkToProject = useAppStore((s) => s.addApkToProject);
  const activeSlotId   = useAppStore((s) => s.activeSlotId);
  const navigateToMember = useAppStore((s) => s.navigateToMember);
  // The site-result cache is the source of truth for resolved values
  // now — bulk runs AND per-site ▶ runs both populate it.
  const siteResults    = useAppStore((s) => s.deobfSiteResults);
  const runningSites   = useAppStore((s) => s.deobfRunningSites);

  const shortClass = mark.className.split("/").pop() ?? mark.className;

  // Live deobfuscation progress for this method: how many of its call
  // sites have a result so far (success or error), out of the total. Reads
  // from the per-site result cache, so it ticks up in real time as a run
  // (per-site ▶, "Run all sites", or "Deobfuscate Shown/All") merges each
  // batch — giving the user a "not stuck" signal. `okCount` is the subset
  // that resolved without error.
  const { doneCount, okCount } = useMemo(() => {
    if (!allSites) return { doneCount: 0, okCount: 0 };
    let done = 0;
    let ok = 0;
    for (const s of allSites) {
      const r = siteResults[deobfSiteKey(mark.className, mark.methodName, s.callerClass, s.offset)];
      if (r) {
        done++;
        if (!r.error) ok++;
      }
    }
    return { doneCount: done, okCount: ok };
  }, [allSites, siteResults, mark.className, mark.methodName]);

  /** Jump to the caller method in the centre panel.
   *
   *  Each call site row in the deobf pane carries `(callerClass,
   *  callerMethod, offset)` — clicking it should open the caller
   *  class and scroll to the relevant method. `navigateToMember`
   *  handles open-or-focus tab semantics and resolves the line via
   *  `findCodeLine`. We strip the proto descriptor from
   *  `callerMethod` (e.g. `toString()Ljava/lang/String;` → `toString`)
   *  because the line search keys off the bare member name. The
   *  exact codepoint offset is shown in the row, so even when the
   *  jump lands on the method's first line the user can still find
   *  the precise call site by eye. */
  const handleSiteClick = (callerClass: string, callerMethod: string) => {
    const bareMethod = callerMethod.split("(")[0] ?? callerMethod;
    void navigateToMember(callerClass, bareMethod);
  };

  return (
    <div className="border border-vs-border rounded mb-1 bg-vs-bg">
      {/* Header row: expand toggle, class::method, run controls, unmark */}
      <div className="flex items-center gap-2 px-2 py-1.5 hover:bg-vs-elevated/30 cursor-pointer"
           onClick={() => toggleExpanded(mark.className, mark.methodName)}>
        <span className="text-vs-dim w-3 text-center text-xs">
          {expanded ? "▾" : "▸"}
        </span>
        <span className="text-vs-accent text-sm">🔓</span>
        <div className="flex-1 min-w-0 font-mono text-xs">
          <span className="text-vs-text font-semibold">{shortClass}</span>
          <span className="text-vs-dim">::</span>
          <span className="text-tree-method">{mark.methodName}</span>
          <span className="text-vs-dim text-[10px] ml-2 truncate" title={mark.className}>
            ({mark.className})
          </span>
        </div>

        {/* Site count once loaded. When filter is active we show
            `matching / total` so the user knows the filter is doing
            something even when most sites are hidden. */}
        {allSites && (
          <span className="text-vs-dim text-[10px] tabular-nums">
            {filterActive
              ? `${filteredSites?.length ?? 0} / ${allSites.length} site${allSites.length === 1 ? "" : "s"}`
              : `${allSites.length} site${allSites.length === 1 ? "" : "s"}`}
          </span>
        )}

        {/* Live deobfuscation progress: ticks up as each call site is
            resolved. Highlighted while a run is in flight so the user can
            confirm forward progress (vs. a stuck run). Shows the failed
            count only when something errored. */}
        {allSites && allSites.length > 0 && (
          <span
            className={[
              "text-[10px] tabular-nums px-1 rounded",
              running ? "text-vs-accent bg-vs-accent/10" : "text-vs-dim",
              doneCount === allSites.length && okCount === allSites.length ? "text-vs-success" : "",
            ].join(" ")}
            title={`${doneCount} of ${allSites.length} call site(s) deobfuscated${
              doneCount - okCount > 0 ? ` (${doneCount - okCount} failed)` : ""
            }`}
          >
            {running ? "⟳ " : ""}{okCount}/{allSites.length} deobfuscated
            {doneCount - okCount > 0 ? ` · ${doneCount - okCount} failed` : ""}
          </span>
        )}

        {/* Per-method run-all → becomes a Stop control while running so a
            slow run can be cancelled (it halts at the next batch boundary;
            already-resolved sites stay cached). */}
        {running ? (
          <button
            className={[
              "px-2 py-0.5 text-[10px] rounded border",
              stopRequested
                ? "border-vs-border text-vs-dim cursor-not-allowed"
                : "border-vs-error text-vs-error hover:bg-vs-error/20 cursor-pointer",
            ].join(" ")}
            disabled={stopRequested}
            onClick={(e) => {
              e.stopPropagation();
              stopDeobf();
            }}
            title="Stop after the current batch — already-resolved sites are kept"
          >
            {stopRequested ? "Stopping…" : "■ Stop"}
          </button>
        ) : (
          <button
            className="px-2 py-0.5 text-[10px] rounded border border-vs-accent text-vs-accent hover:bg-vs-accent/20 cursor-pointer"
            onClick={(e) => {
              e.stopPropagation();
              void runForMark(mark.className, mark.methodName);
            }}
            title="Execute the deobfuscator at every call site (ignores the filter)"
          >
            ▶ Run all sites
          </button>
        )}

        {/* Refresh static scan — useful when the underlying code might
            have changed (script-driven rewrites, dexmapper, etc.). */}
        <button
          className="px-1 py-0.5 text-[10px] text-vs-dim hover:text-vs-text"
          disabled={loadingSites}
          onClick={(e) => {
            e.stopPropagation();
            // Force past the per-method cache — this is the explicit
            // "the code may have changed, re-scan now" affordance.
            void loadSites(mark.className, mark.methodName, true);
          }}
          title="Re-scan call sites"
        >
          {loadingSites ? "…" : "↻"}
        </button>

        <button
          className="px-1 py-0.5 text-[10px] text-vs-dim hover:text-vs-error"
          onClick={(e) => {
            e.stopPropagation();
            void unmark(mark.className, mark.methodName);
          }}
          title="Remove this deobf mark"
        >
          ✕
        </button>
      </div>

      {/* Expanded body: per-site list */}
      {expanded && (
        <div className="border-t border-vs-border/40 px-2 py-1.5">
          {loadingSites && !allSites && (
            <div className="text-xs text-vs-dim italic py-1">Scanning call sites…</div>
          )}
          {allSites && allSites.length === 0 && (
            <div className="text-xs text-vs-dim italic py-1">No call sites found.</div>
          )}
          {allSites && allSites.length > 0 && filteredSites && filteredSites.length === 0 && (
            <div className="text-xs text-vs-dim italic py-1">
              No sites match the current filter.
            </div>
          )}
          {filteredSites && filteredSites.length > 0 && (
            <div className="flex flex-col gap-1">
              {filteredSites.map((site, idx) => {
                const siteKey = deobfSiteKey(mark.className, mark.methodName, site.callerClass, site.offset);
                const result = siteResults[siteKey];
                const isRunning = runningSites.has(siteKey);
                return (
                  <div
                    key={`${site.callerClass}:${site.offset}:${idx}`}
                    className="flex items-start gap-2 p-1 rounded bg-vs-elevated/30 text-xs font-mono"
                  >
                    <div className="flex-1 min-w-0">
                      {/* Caller class::method — clickable. Routes through
                          navigateToMember, which opens (or focuses) the
                          caller's class tab and scrolls to the method
                          definition. The cursor + accent colour signal
                          interactivity; the title attribute carries the
                          full class path for users who need it. */}
                      <button
                        type="button"
                        className="text-left text-vs-muted truncate w-full hover:text-vs-accent hover:underline cursor-pointer"
                        title={`Jump to ${site.callerClass}->${site.callerMethod} (@${site.offset})`}
                        onClick={() => handleSiteClick(site.callerClass, site.callerMethod)}
                      >
                        {site.callerClass.split("/").pop()}::{site.callerMethod}
                      </button>
                      <div className="text-vs-dim">
                        @{site.offset} · args: <span className="text-vs-text">{formatStaticArgs(site.staticArgs)}</span>
                      </div>
                      {/* Result line (only after the site has been executed
                          via per-site ▶ / per-method / all-marks). */}
                      {result && (
                        <div className={result.error ? "text-vs-error" : "text-vs-success"}>
                          → {result.error ?? `"${result.resolvedValue}"`}
                        </div>
                      )}
                    </div>

                    {/* Per-site ▶ — runs ONLY this call site. The new
                        deobf_run_specific_sites endpoint takes a list
                        of one; the parallel path collapses to a single
                        worker, but reusing the same code keeps the
                        cache merge semantics consistent. */}
                    <button
                      className={[
                        "flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] border",
                        isRunning
                          ? "border-vs-border text-vs-dim cursor-not-allowed"
                          : "border-vs-accent text-vs-accent hover:bg-vs-accent/20 cursor-pointer",
                      ].join(" ")}
                      disabled={isRunning}
                      onClick={() => void runDeobfSite(mark, site)}
                      title="Deobfuscate this single call site"
                    >
                      {isRunning ? "⟳" : "▶"}
                    </button>

                    {/* APK-cached result — same affordance the EXECUTION
                        tab offers. */}
                    {result?.apkCachePath && activeSlotId && (
                      <button
                        className="flex-shrink-0 px-1.5 py-0.5 bg-vs-accent/20 hover:bg-vs-accent/40 text-vs-accent rounded text-[10px]"
                        onClick={() => {
                          if (result.apkCachePath) {
                            void addApkToProject(result.apkCachePath, activeSlotId);
                          }
                        }}
                        title={`Cached at ${result.apkCachePath} — click to load as a child slot`}
                      >
                        📦
                      </button>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const DeobfuscationTab: React.FC = () => {
  const marks         = useAppStore((s) => s.deobfMarks);
  const runningAll    = useAppStore((s) => s.deobfRunningAll);
  const runAllMarks   = useAppStore((s) => s.runAllDeobfMarks);
  const loadMarks     = useAppStore((s) => s.loadDeobfMarks);
  const isProjectInitialized = useAppStore((s) => s.isProjectInitialized);
  const numThreads    = useAppStore((s) => s.deobfNumThreads);
  const setNumThreads = useAppStore((s) => s.setDeobfNumThreads);
  const filter        = useAppStore((s) => s.deobfFilter);
  const setFilter     = useAppStore((s) => s.setDeobfFilter);
  const runningShown  = useAppStore((s) => s.deobfRunningShown);
  const runShown      = useAppStore((s) => s.runDeobfShown);
  const stopDeobf     = useAppStore((s) => s.stopDeobf);
  const stopRequested = useAppStore((s) => s.deobfStopRequested);
  // We watch sitesByMark for changes so the filter selector re-runs
  // when sites are (lazy-)loaded. The selector itself reads from the
  // store snapshot so we don't pay subscriptions per filter field.
  const sitesByMark   = useAppStore((s) => s.deobfSitesByMark);
  const filteredSites = useAppStore((s) => s.filteredDeobfSites)();

  // Show the host's logical CPU count as a hint next to the input.
  // navigator.hardwareConcurrency may be unavailable in headless test
  // environments — fall back to 0 (= "auto") when missing.
  const hostCpus = typeof navigator !== "undefined" && navigator.hardwareConcurrency
    ? navigator.hardwareConcurrency
    : 0;

  const filterActive = filter.trim().length > 0;

  // When the filter is active, hide marks that have no matching sites.
  // When it's empty, show every mark — even ones whose sites haven't
  // been loaded yet (the row will display a "Scanning…" state on expand).
  const visibleMarks = useMemo(() => {
    if (!filterActive) return marks;
    return marks.filter((m) => {
      const key = deobfMarkKey(m.className, m.methodName);
      const sites = filteredSites.get(key);
      return sites && sites.length > 0;
    });
  }, [marks, filterActive, filteredSites]);

  // Total shown count for the "Deobfuscate Shown (N)" button label.
  const shownCount = useMemo(() => {
    let n = 0;
    for (const [, ss] of filteredSites) n += ss.length;
    // sitesByMark is referenced so this memo re-runs on its change too.
    void sitesByMark;
    return n;
  }, [filteredSites, sitesByMark]);

  // Re-pull marks on mount in case the user switched APKs while this
  // tab was hidden. Cheap (one Tauri command, no exec).
  useEffect(() => {
    if (isProjectInitialized && isTauri()) {
      void loadMarks();
    }
  }, [isProjectInitialized, loadMarks]);

  if (!marks.length) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-2 text-vs-dim text-xs">
        <span className="text-2xl">🔓</span>
        <p className="text-center max-w-xs">
          No methods marked yet. Right-click a method in the tree or code view
          and choose <strong className="text-vs-text">Mark as deobfuscator</strong>.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Toolbar — row 1: metadata + thread control + refresh/run-all */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-vs-border bg-vs-elevated/40 flex-wrap">
        <span className="text-xs text-vs-muted font-semibold uppercase tracking-wider">
          {marks.length} marked method{marks.length === 1 ? "" : "s"}
        </span>

        {/* Thread-count control. 0 = "auto" (rayon's default = host
            CPU count). The backend chunks across `n` shards then
            rayon's global pool runs them concurrently. */}
        <label className="flex items-center gap-1 text-[10px] text-vs-muted ml-3">
          <span title="Worker threads used to execute deobfuscator call sites in parallel. 0 = auto (one per CPU core).">
            🧵 Threads:
          </span>
          <input
            type="number"
            min={0}
            max={64}
            step={1}
            value={numThreads}
            onChange={(e) => setNumThreads(Number(e.target.value))}
            className="w-12 bg-vs-bg border border-vs-border rounded px-1 py-0.5 text-[10px] font-mono text-vs-text focus:outline-none focus:border-vs-accent tabular-nums"
            title="0 = auto · 1 = sequential · n = chunk into n shards"
          />
          {numThreads === 0 && hostCpus > 0 && (
            <span className="text-[10px] text-vs-dim tabular-nums" title={`Host has ${hostCpus} logical CPUs`}>
              (auto: {hostCpus})
            </span>
          )}
          {numThreads === 1 && (
            <span className="text-[10px] text-vs-warn" title="Sequential — falls back to the in-batch memo cache">
              seq
            </span>
          )}
        </label>

        <div className="ml-auto flex items-center gap-1">
          <button
            className="px-2 py-0.5 text-[10px] text-vs-dim hover:text-vs-text"
            onClick={() => void loadMarks()}
            title="Refresh marks from disk"
          >
            ↻ Refresh
          </button>
          {runningAll ? (
            <button
              className={[
                "px-2.5 py-1 text-xs font-semibold rounded transition-colors",
                stopRequested
                  ? "bg-vs-elevated text-vs-dim cursor-not-allowed"
                  : "bg-vs-error/80 hover:bg-vs-error text-white cursor-pointer",
              ].join(" ")}
              disabled={stopRequested}
              onClick={() => stopDeobf()}
              title="Stop after the current batch finishes — already-resolved sites are kept"
            >
              {stopRequested ? (
                <><span className="animate-spin inline-block">⟳</span> Stopping…</>
              ) : (
                <>■ Stop</>
              )}
            </button>
          ) : (
            <button
              className="px-2.5 py-1 text-xs font-semibold rounded transition-colors bg-vs-accent hover:bg-vs-accent-dark text-white cursor-pointer"
              onClick={() => void runAllMarks()}
              title="Execute every marked method at every call site (ignores filter)"
            >
              ⚡ Deobfuscate All
            </button>
          )}
        </div>
      </div>

      {/* Toolbar — row 2: filter input + Deobfuscate Shown.
          The filter matches against the **caller class** (where the
          deobfuscator is invoked from) — that's the most useful
          coordinate when you're narrowing down a particular
          package/feature. `.` and `/` are treated equivalently so
          users can paste Java-style fq-names. */}
      <div className="flex items-center gap-2 px-2 py-1 border-b border-vs-border bg-vs-elevated/20 flex-shrink-0">
        <span className="text-[10px] text-vs-dim" title="Filter call sites by the package/class that calls the deobfuscator.">
          🔍
        </span>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter call sites by package/class (e.g. com.example.auth)"
          className="flex-1 bg-vs-bg border border-vs-border rounded px-2 py-0.5 text-[11px] font-mono text-vs-text placeholder:text-vs-dim focus:outline-none focus:border-vs-accent"
        />
        {filterActive && (
          <button
            className="px-1 py-0.5 text-[10px] text-vs-dim hover:text-vs-text"
            onClick={() => setFilter("")}
            title="Clear filter"
          >
            ✕
          </button>
        )}
        {runningShown ? (
          <button
            className={[
              "px-2 py-0.5 text-[10px] font-semibold rounded transition-colors",
              stopRequested
                ? "bg-vs-elevated text-vs-dim cursor-not-allowed"
                : "bg-vs-error/80 hover:bg-vs-error text-white cursor-pointer",
            ].join(" ")}
            disabled={stopRequested}
            onClick={() => stopDeobf()}
            title="Stop after the current batch finishes — already-resolved sites are kept"
          >
            {stopRequested ? (
              <><span className="animate-spin inline-block">⟳</span> Stopping…</>
            ) : (
              <>■ Stop</>
            )}
          </button>
        ) : (
          <button
            className={[
              "px-2 py-0.5 text-[10px] font-semibold rounded transition-colors",
              shownCount === 0
                ? "bg-vs-elevated text-vs-dim cursor-not-allowed"
                : "bg-vs-success/30 hover:bg-vs-success/50 text-vs-success cursor-pointer",
            ].join(" ")}
            disabled={shownCount === 0}
            onClick={() => void runShown()}
            title={
              filterActive
                ? `Execute the ${shownCount} call site(s) currently matching the filter`
                : "Execute every visible call site (same as Deobfuscate All when filter is empty)"
            }
          >
            ▶ Deobfuscate Shown ({shownCount})
          </button>
        )}
      </div>

      {/* Marks list */}
      <div className="flex-1 overflow-y-auto p-2">
        {visibleMarks.length === 0 && filterActive && (
          <div className="text-xs text-vs-dim italic text-center py-4">
            No call sites match "{filter}". Try widening the filter or
            ↻ Refresh to re-scan.
          </div>
        )}
        {visibleMarks.map((m) => {
          const key = deobfMarkKey(m.className, m.methodName);
          return (
            <DeobfMarkRow
              key={key}
              mark={m}
              filteredSites={filteredSites.get(key)}
              filterActive={filterActive}
            />
          );
        })}
      </div>
    </div>
  );
};

// ─── BottomPanel ─────────────────────────────────────────────────────────────

const BottomPanel: React.FC = () => {
  const activeBottomTab = useAppStore((s) => s.activeBottomTab);
  const setActiveBottomTab = useAppStore((s) => s.setActiveBottomTab);
  const logs = useAppStore((s) => s.logs);
  const findExecResults = useAppStore((s) => s.findExecResults);
  const deobfMarks = useAppStore((s) => s.deobfMarks);

  return (
    <div className="flex flex-col h-full bg-vs-surface border-t border-vs-border overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center bg-vs-elevated border-b border-vs-border flex-shrink-0 px-1">
        <TabButton
          label="LOGS"
          active={activeBottomTab === "LOGS"}
          onClick={() => setActiveBottomTab("LOGS")}
          badge={logs.filter((l) => l.level === "ERROR").length || undefined}
        />
        <TabButton
          label="EXECUTION"
          active={activeBottomTab === "EXECUTION"}
          onClick={() => setActiveBottomTab("EXECUTION")}
          badge={findExecResults.length || undefined}
        />
        <TabButton
          label="DEOBFUSCATION"
          active={activeBottomTab === "DEOBFUSCATION"}
          onClick={() => setActiveBottomTab("DEOBFUSCATION")}
          badge={deobfMarks.length || undefined}
        />
        {/* SEARCH moved entirely to the dedicated search window (toolbar 🔍 /
            Ctrl-Shift-F). The old in-panel SEARCH tab duplicated it and was
            much slower, so it's been removed. */}
        <TabButton
          label="DIFF"
          active={activeBottomTab === "DIFF"}
          onClick={() => setActiveBottomTab("DIFF")}
        />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeBottomTab === "LOGS" && <LogsTab />}
        {activeBottomTab === "EXECUTION" && <ExecutionTab />}
        {activeBottomTab === "DEOBFUSCATION" && <DeobfuscationTab />}
        {activeBottomTab === "DIFF" && <DiffTab />}
      </div>
    </div>
  );
};

export default BottomPanel;
