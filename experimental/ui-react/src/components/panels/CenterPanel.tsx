import React, { useMemo, useState, useEffect, useCallback, useRef } from "react";
import { useAppStore } from "../../store/appStore";
import TabBar from "../common/TabBar";
import CodeViewer from "../code/CodeViewer";
import FlowGraph from "../code/FlowGraph";
import { javaRefToPath, buildClassIndex, buildImportMap, type ClassIndex, type ImportMap } from "../code/tokenizer";
import type { TreeNode } from "../../api/types";
import type { Language, DeobfReplacement, MethodRename } from "../../api/types";
import { applyDeobfAnnotations, buildDeobfList, buildSubstitutedCode } from "../../utils/deobf";
import PlatypusSVG from "../svg/platypus.tsx";
import {api} from "../../api/adapter.ts";

// ─── Context menu target extraction ──────────────────────────────────────────

/**
 * Given a raw code line and the current class name, try to extract a Dalvik
 * method reference suitable for `findExec` / rename.
 *
 * Handles:
 *  - Smali invoke-* call sites  → full ref from the line
 *  - Smali .method definitions  → prepend current class
 *  - Java method definition lines → best-effort (class + method name)
 */
function extractDeobfTarget(
  line: string,
  language: Language,
  currentClassName: string
): string | null {
  const trimmed = line.trim();

  if (language === "smali") {
    const invokeMatch = trimmed.match(
      /invoke-\w+(?:\/range)?\s+\{[^}]*\},\s*(L[^;]+;->[\w$<>]+\([^)]*\)\S+)/
    );
    if (invokeMatch) return invokeMatch[1];

    const methodMatch = trimmed.match(
      /\.method\s+(?:(?:public|private|protected|static|final|abstract|synthetic|bridge|varargs|native|strictfp|constructor)\s+)*([\w$<>]+\([^)]*\)\S+)/
    );
    if (methodMatch) return `L${currentClassName};->${methodMatch[1]}`;
  } else if (language === "java") {
    const methodMatch = trimmed.match(
      /^(?:(?:public|private|protected|static|final|abstract|native|synchronized|default)\s+)*(?:[\w<>\[\]]+\s+)+([\w$]+)\s*\(/
    );
    if (methodMatch) return `L${currentClassName};->${methodMatch[1]}`;
  }

  return null;
}

/**
 * Parse a Dalvik method reference (e.g. "Lcom/Foo;->bar(...)V") into its
 * component className and methodName parts.
 */
function parseMethodRef(
  target: string
): { className: string; methodName: string; signature: string } | null {
  const arrowIdx = target.indexOf("->");
  if (arrowIdx === -1) return null;
  let className = target.slice(0, arrowIdx);
  if (className.startsWith("L") && className.endsWith(";")) {
    className = className.slice(1, -1);
  }
  const rest = target.slice(arrowIdx + 2);
  const parenIdx = rest.indexOf("(");
  const methodName = parenIdx !== -1 ? rest.slice(0, parenIdx) : rest;
  const signature = parenIdx !== -1 ? rest.slice(parenIdx) : "";
  return { className, methodName, signature };
}

// ─── Rename application helper ────────────────────────────────────────────────

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Apply method renames to a code string for display purposes.
 * Does NOT mutate the stored code — this is purely a view-layer substitution.
 */
function applyMethodRenames(
  code: string,
  language: Language,
  renames: MethodRename[]
): string {
  if (renames.length === 0) return code;
  let result = code;
  for (const { methodName, newName } of renames) {
    const esc = escapeRe(methodName);
    if (language === "smali") {
      // Call sites:       ;->methodName(
      // Definitions:      .method ... methodName(
      result = result.replace(
        new RegExp(`(;->|\\.method\\s+(?:[\\w]+\\s+)*)${esc}(?=\\()`, "g"),
        (_, prefix) => `${prefix}${newName}`
      );
    } else {
      // Java: word-boundary before name, followed by optional whitespace then (
      // The \b prevents matching inside longer identifiers.
      result = result.replace(
        new RegExp(`\\b${esc}(?=\\s*\\()`, "g"),
        newName
      );
    }
  }
  return result;
}

// ─── Language toggle ──────────────────────────────────────────────────────────

interface LangToggleProps {
  value: Language;
  onChange: (lang: Language) => void;
  disabled?: boolean;
}

const LangToggle: React.FC<LangToggleProps> = ({ value, onChange, disabled }) => (
  <div className="flex items-center gap-0.5 bg-vs-elevated rounded border border-vs-border p-0.5">
    {(["smali", "java"] as Language[]).map((lang) => (
      <button
        key={lang}
        className={[
          "px-2 py-0.5 rounded text-xs font-mono transition-colors",
          value === lang
            ? "bg-vs-accent text-white"
            : "text-vs-muted hover:text-vs-text",
          disabled ? "opacity-40 cursor-not-allowed" : "cursor-pointer",
        ].join(" ")}
        onClick={() => !disabled && onChange(lang)}
        disabled={disabled}
      >
        {lang === "smali" ? "Smali" : "Java"}
      </button>
    ))}
  </div>
);

// ─── CenterPanel ──────────────────────────────────────────────────────────────

interface ContextMenuState {
  x: number;
  y: number;
  target: string;
  /** When non-null the menu has switched to "rename" input mode */
  renaming: boolean;
  renameValue: string;
}

const CenterPanel: React.FC = () => {
  const openTabs          = useAppStore((s) => s.openTabs);
  const activeTabId       = useAppStore((s) => s.activeTabId);
  const activeLanguage    = useAppStore((s) => s.activeLanguage);
  const tree              = useAppStore((s) => s.tree);
  const deobfReplacements = useAppStore((s) => s.deobfReplacements);
  const appliedDeobf      = useAppStore((s) => s.appliedDeobf);
  const renames           = useAppStore((s) => s.renames);
  const setActiveTab      = useAppStore((s) => s.setActiveTab);
  const closeTab          = useAppStore((s) => s.closeTab);
  const closeOtherTabs    = useAppStore((s) => s.closeOtherTabs);
  const closeAllTabs      = useAppStore((s) => s.closeAllTabs);
  const setActiveLanguage = useAppStore((s) => s.setActiveLanguage);
  const navigateToClass   = useAppStore((s) => s.navigateToClass);
  const loadedFile        = useAppStore((s) => s.loadedFile);
  const showFlowGraph     = useAppStore((s) => s.showFlowGraph);
  const toggleFlowGraph   = useAppStore((s) => s.toggleFlowGraph);
  const loadXrefsForMethod = useAppStore((s) => s.loadXrefsForMethod);
  const setActiveRightTab = useAppStore((s) => s.setActiveRightTab);
  const navigateToMember  = useAppStore((s) => s.navigateToMember);
  const selectedLine      = useAppStore((s) => s.selectedLine);
  const setSelectedLine   = useAppStore((s) => s.setSelectedLine);
  const markAsDeobfuscator = useAppStore((s) => s.markAsDeobfuscator);
  const addRename         = useAppStore((s) => s.addRename);
  const removeRename      = useAppStore((s) => s.removeRename);
  const isFindRunning     = useAppStore((s) => s.isFindRunning);
  // DEOBFUSCATION-tab integration: marking the method here adds it to
  // the persistent per-APK list surfaced in the new bottom-bar tab.
  // Distinct from "Run as Deobfuscator" above, which is a one-shot.
  const markDeobf         = useAppStore((s) => s.markDeobf);
  const unmarkDeobf       = useAppStore((s) => s.unmarkDeobf);
  const isDeobfMarked     = useAppStore((s) => s.isDeobfMarked);
  const setActiveBottomTab = useAppStore((s) => s.setActiveBottomTab);

  const activeTab = openTabs.find((t) => t.id === activeTabId) ?? null;

  // ── Context menu ─────────────────────────────────────────────────────────────
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const renameInputRef = useRef<HTMLInputElement>(null);

  // Focus rename input when switching to rename mode.
  useEffect(() => {
    if (contextMenu?.renaming) {
      setTimeout(() => renameInputRef.current?.select(), 20);
    }
  }, [contextMenu?.renaming]);

  // Close on outside click or Escape.
  useEffect(() => {
    if (!contextMenu) return;
    const close = (e: MouseEvent) => {
      // Don't close if the click is inside the menu (stopPropagation handles it).
      setContextMenu(null);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setContextMenu(null);
    };
    window.addEventListener("click", close);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("keydown", onKey);
    };
  }, [contextMenu]);

  const handleLineRightClick = useCallback(
    (lineIndex: number, x: number, y: number) => {
      if (!activeTab) return;
      const lines = activeTab.code.split("\n");
      const line = lines[lineIndex] ?? "";
      const target = extractDeobfTarget(line, activeTab.language, activeTab.className);
      if (!target) return;
      const parsed = parseMethodRef(target);
      const currentName = parsed?.methodName ?? "";
      // Pre-fill rename input with any existing rename for this method.
      const existingRename = parsed
        ? renames.find(
            (r) => r.className === parsed.className && r.methodName === parsed.methodName
          )
        : undefined;
      setContextMenu({
        x,
        y,
        target,
        renaming: false,
        renameValue: existingRename?.newName ?? currentName,
      });
    },
    [activeTab, renames]
  );

  const commitRename = useCallback(() => {
    if (!contextMenu) return;
    const parsed = parseMethodRef(contextMenu.target);
    if (!parsed) { setContextMenu(null); return; }
    const trimmed = contextMenu.renameValue.trim();
    if (trimmed && trimmed !== parsed.methodName) {
      addRename({
        className: parsed.className,
        methodName: parsed.methodName,
        newName: trimmed,
        signature: parsed.signature || undefined,
      });
    } else if (!trimmed || trimmed === parsed.methodName) {
      // Remove any existing rename for this method (i.e. "reset to original").
      removeRename(parsed.className, parsed.methodName);
    }
    setContextMenu(null);
  }, [contextMenu, addRename, removeRename]);

  // ── Deobf list (per-call-site, no collapsing) ─────────────────────────────
  const deobfList = useMemo(() => {
    if (!activeTab) return [];
    return buildDeobfList(deobfReplacements, appliedDeobf, activeTab.className);
  }, [activeTab, deobfReplacements, appliedDeobf]);

  // ── Project class index for varName.method() xref promotion ────────────────
  // Flatten the tree to a list of class fullNames and feed them into
  // `buildClassIndex`. Recomputed only when the tree itself changes —
  // not per keystroke or per tab switch.
  const allClassPaths: string[] = useMemo(() => {
    const out: string[] = [];
    const collect = (nodes: TreeNode[]) => {
      for (const n of nodes) {
        if (n.kind === "class" && n.fullName) {
          out.push(n.fullName);
        }
        if (n.children && n.children.length > 0) collect(n.children);
      }
    };
    collect(tree);
    return out;
  }, [tree]);

  const classIndex: ClassIndex = useMemo(
    () => buildClassIndex(allClassPaths),
    [allClassPaths],
  );

  // Set of every known class path (slash form), used by the tokenizer to
  // recognise all-lowercase fully-qualified calls (`hivhi.wfg.bihvbhi(...)`)
  // that the decompiler emits for classes with an ambiguous simple name.
  const classPaths: Set<string> = useMemo(
    () => new Set(allClassPaths),
    [allClassPaths],
  );

  // ── View mode comes from global settings (Settings window → Editor → Deobf view) ──
  const viewMode = useAppStore((s) => s.settings.deobfViewMode);

  // ── Rename-substituted + deobf display code ───────────────────────────────
  // Both transforms are applied at view time; the stored code is never mutated.
  const displayCode = useMemo(() => {
    if (!activeTab) return "";
    // Apply renames first so the renamed symbol names also match deobf entries.
    const renamed = applyMethodRenames(activeTab.code, activeTab.language, renames);
    if (viewMode === "substituted" && deobfList.length > 0) {
      return buildSubstitutedCode(
        renamed,
        activeTab.language,
        deobfReplacements,
        appliedDeobf,
        activeTab.className,
      );
    }
    // Default: offset-aware annotation overlay.
    return applyDeobfAnnotations(renamed, activeTab.language, deobfList);
  }, [activeTab, renames, deobfList, viewMode, deobfReplacements, appliedDeobf]);

  // ── Per-tab import map (authoritative for varName.method() xrefs) ────────────
  // Built from the rendered Java text — picks up `import com.x.Foo;` lines
  // and indexes Foo (and lowercased / camelCase aliases) under their full
  // slash-paths. Used by the tokenizer to disambiguate variable
  // receivers BEFORE falling back to the project-wide classIndex.
  // Smali tabs don't use it; we still compute (cheap) for uniformity.
  const importMap: ImportMap = useMemo(
    () => buildImportMap(displayCode),
    [displayCode],
  );

  // ── XRef navigation ──────────────────────────────────────────────────────────
  const handleXrefClick = (target: string) => {
    if (target.includes("->")) {
      const arrowIdx = target.indexOf("->");
      let classRef = target.slice(0, arrowIdx);
      let methodName = target.slice(arrowIdx + 2);
      const sigIdx = methodName.indexOf("(");
      if (sigIdx !== -1) methodName = methodName.slice(0, sigIdx);
      if (!classRef.startsWith("L") || !classRef.endsWith(";")) {
        classRef = `L${javaRefToPath(classRef)};`;
      }
      navigateToMember(classRef, methodName);
      loadXrefsForMethod(classRef, methodName);
      return;
    }
    const normalized = target.startsWith("L")
      ? target.slice(1).replace(";", "")
      : target;
    navigateToClass(normalized);
  };

  const isXmlTab  = activeTab?.language === "xml";
  const isTextTab = activeTab?.language === "text";

  // Derive label for context menu header (strip class prefix).
  const menuLabel = contextMenu
    ? (contextMenu.target.split("->")[1] ?? contextMenu.target).split("(")[0]
    : "";

  // Check if a rename already exists for the context menu target.
  const parsedTarget = contextMenu ? parseMethodRef(contextMenu.target) : null;
  const existingRenameForTarget = parsedTarget
    ? renames.find(
        (r) =>
          r.className === parsedTarget.className &&
          r.methodName === parsedTarget.methodName
      )
    : undefined;

  return (
    <div className="flex flex-col h-full bg-vs-bg overflow-hidden">
      {/* Tab bar */}
      <TabBar
        tabs={openTabs}
        activeTabId={activeTabId}
        onSelectTab={setActiveTab}
        onCloseTab={closeTab}
        onCloseOthers={closeOtherTabs}
        onCloseAll={closeAllTabs}
      />

      {/* Toolbar row */}
      {activeTab && (
        <div className="flex items-center justify-between px-3 py-1 bg-vs-surface border-b border-vs-border flex-shrink-0">
          <span className="text-xs text-vs-muted font-mono truncate max-w-sm">
            {activeTab.className}
          </span>
          <div className="flex items-center gap-2">
            {!isXmlTab && !isTextTab && (
              <LangToggle value={activeLanguage} onChange={setActiveLanguage} />
            )}
          </div>
        </div>
      )}

      {/* Code area */}
      <div className="flex-1 overflow-hidden relative">
        {!loadedFile ? (
          <div className="flex flex-col items-center justify-center h-full gap-3 text-vs-dim">
            <span className="text-5xl opacity-30" style={{ inlineSize: '10%' }}> <PlatypusSVG /> </span>
            <div className="text-center">
              <p className="text-sm font-semibold text-vs-muted">Project Platypus</p>
              <p className="text-xs mt-1">Open an APK, DEX, or JAR file to begin</p>
            </div>
          </div>
        ) : !activeTab ? (
          <div className="flex flex-col items-center justify-center h-full gap-2 text-vs-dim">
            <span className="text-3xl opacity-40">📄</span>
            <span className="text-xs">
              Select a class from the navigator to view its code
            </span>
          </div>
        ) : (
          <CodeViewer
            code={displayCode}
            language={activeTab.language}
            onXrefClick={handleXrefClick}
            selectedLine={selectedLine ?? undefined}
            onLineClick={(line) => setSelectedLine(line)}
            onLineRightClick={handleLineRightClick}
            // Threading the tab's class through lets the tokenizer
            // promote `this.method(` calls into clickable xrefs that
            // jump back to definitions in the same class. Smali tabs
            // ignore this (their xref tokens carry full L…; refs).
            currentClass={activeTab.className.replace(/^L/, "").replace(/;$/, "")}
            // The class index makes `varName.method(` calls clickable
            // when `varName` resolves to a project class via the
            // lookup heuristics (`wfg` → `Lhivhi/wfg;`,
            // `mainActivity` → `MainActivity`). Built once per tree
            // change, cheap to recompute.
            classIndex={classIndex}
            // Per-tab import map — takes precedence over classIndex
            // when an `import com.x.Wfg;` line in THIS file
            // unambiguously resolves a receiver. Fixes the
            // "wrong-class on wfg.bihvbhi(...)" bug when multiple
            // classes share a simple name across obfuscated packages.
            importMap={importMap}
            // Known class paths — lets the tokenizer resolve all-lowercase
            // fully-qualified calls (`hivhi.wfg.bihvbhi(...)`) emitted for
            // ambiguous simple names.
            classPaths={classPaths}
          />
        )}

        {showFlowGraph && (
          <div className="absolute inset-0 z-10 bg-[#0f0f1a]">
            <FlowGraph onClose={toggleFlowGraph} />
          </div>
        )}

        {/* Context menu */}
        {contextMenu && (
          <div
            className="fixed z-50 bg-vs-surface border border-vs-border rounded shadow-lg py-1 min-w-52 text-xs font-mono"
            style={{ left: contextMenu.x, top: contextMenu.y }}
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header: method name (with existing rename badge if any) */}
            <div className="px-3 py-1 border-b border-vs-border mb-1 flex items-center gap-2 min-w-0">
              <span className="text-vs-dim truncate flex-1">{menuLabel}</span>
              {existingRenameForTarget && (
                <span className="text-vs-accent shrink-0">
                  → {existingRenameForTarget.newName}
                </span>
              )}
            </div>

            {/* ── Rename mode ── */}
            {contextMenu.renaming ? (
              <div className="px-3 py-2 flex flex-col gap-2">
                <label className="text-vs-muted text-[10px] uppercase tracking-wide">
                  New name
                </label>
                <input
                  ref={renameInputRef}
                  className="bg-vs-elevated border border-vs-border rounded px-2 py-1 text-xs font-mono text-vs-text outline-none focus:border-vs-accent w-full"
                  value={contextMenu.renameValue}
                  onChange={(e) =>
                    setContextMenu((m) => m ? { ...m, renameValue: e.target.value } : m)
                  }
                  onKeyDown={(e) => {
                    if (e.key === "Enter") commitRename();
                    if (e.key === "Escape") setContextMenu(null);
                    e.stopPropagation();
                  }}
                  spellCheck={false}
                  autoComplete="off"
                />
                <div className="flex gap-2">
                  <button
                    className="flex-1 py-1 rounded bg-vs-accent text-white hover:opacity-90 cursor-pointer text-[11px]"
                    onClick={commitRename}
                  >
                    Apply
                  </button>
                  {existingRenameForTarget && (
                    <button
                      className="flex-1 py-1 rounded bg-vs-elevated text-vs-error hover:opacity-90 cursor-pointer text-[11px]"
                      onClick={() => {
                        if (parsedTarget) {
                          removeRename(parsedTarget.className, parsedTarget.methodName);
                        }
                        setContextMenu(null);
                      }}
                    >
                      Reset
                    </button>
                  )}
                  <button
                    className="flex-1 py-1 rounded bg-vs-elevated text-vs-muted hover:opacity-90 cursor-pointer text-[11px]"
                    onClick={() => setContextMenu((m) => m ? { ...m, renaming: false } : m)}
                  >
                    Cancel
                  </button>
                </div>
              </div>
            ) : (
              /* ── Normal menu items ── */
              <>
                <button
                  className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated cursor-pointer flex items-center gap-2"
                  onClick={() =>
                    setContextMenu((m) => m ? { ...m, renaming: true } : m)
                  }
                >
                  <span className="text-vs-accent">✏️</span>
                  {existingRenameForTarget ? "Edit rename…" : "Rename method…"}
                </button>

                <button
                  className={[
                    "w-full text-left px-3 py-1.5 hover:bg-vs-elevated flex items-center gap-2",
                    isFindRunning ? "opacity-50 cursor-not-allowed" : "cursor-pointer",
                  ].join(" ")}
                  disabled={isFindRunning}
                  onClick={() => {
                    setContextMenu(null);
                    markAsDeobfuscator(contextMenu.target);
                  }}
                >
                  <span className="text-vs-warn">⚡</span>
                  {isFindRunning ? "Running…" : "Run as Deobfuscator"}
                </button>

                {/* Persistent deobf-mark toggle. Adds the method to the
                    per-APK list driven by the DEOBFUSCATION bottom-bar
                    tab. Separate from "Run as Deobfuscator" above —
                    that one is a one-shot scan-and-apply; this one
                    just records the intent. */}
                {(() => {
                  const parsed = parseMethodRef(contextMenu.target);
                  if (!parsed) return null;
                  const marked = isDeobfMarked(parsed.className, parsed.methodName);
                  return (
                    <button
                      className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated cursor-pointer flex items-center gap-2"
                      onClick={() => {
                        if (marked) {
                          void unmarkDeobf(parsed.className, parsed.methodName);
                        } else {
                          void markDeobf(parsed.className, parsed.methodName);
                          // Jump straight to the new tab the first time
                          // they mark — fewer "where did that go?" moments.
                          setActiveBottomTab("DEOBFUSCATION");
                        }
                        setContextMenu(null);
                      }}
                    >
                      <span className={marked ? "text-vs-success" : "text-vs-accent"}>
                        {marked ? "🔒" : "🔓"}
                      </span>
                      {marked ? "Unmark as deobfuscator" : "Mark as deobfuscator"}
                    </button>
                  );
                })()}

                <button
                  className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated cursor-pointer flex items-center gap-2"
                  onClick={() => {
                    const parsed = parseMethodRef(contextMenu.target);
                    if (parsed) {
                      api.openTaintWindow(parsed.className, parsed.methodName);
                    }
                    setContextMenu(null);
                  }}
                >
                  <span>🔬</span>
                  Taint analysis
                </button>

                {/* Open in Activity Viewer — the new window from phase 4.
                    Best-effort: the target may not be an activity, but the
                    viewer's activity-picker will still let the user pick
                    something else once it opens. */}
                <button
                  className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated cursor-pointer flex items-center gap-2"
                  onClick={() => {
                    const parsed = parseMethodRef(contextMenu.target);
                    // Convert "com/example/Foo" → "com.example.Foo" for the
                    // viewer's FQ-name-based activity index.
                    const fq = parsed?.className.replace(/\//g, ".");
                    api.openActivityViewerWindow(fq);
                    setContextMenu(null);
                  }}
                >
                  <span>🪟</span>
                  Open in Activity Viewer
                </button>

                {/* Find XRefs — populates the right-panel XREFS tab with every
                    call site that invokes this method, then switches to it. */}
                <button
                  className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated cursor-pointer flex items-center gap-2"
                  onClick={() => {
                    const parsed = parseMethodRef(contextMenu.target);
                    if (parsed) {
                      loadXrefsForMethod(parsed.className, parsed.methodName);
                      setActiveRightTab("XREFS");
                    }
                    setContextMenu(null);
                  }}
                >
                  <span className="text-vs-accent">🔎</span>
                  Find XRefs to method
                </button>

                {/* Call graph — opens the centre-panel FlowGraph view
                    (Binary-Ninja-style hierarchical layout). The
                    FlowGraph seeds itself from the currently-selected
                    method, so we don't need to pre-load callers/callees
                    here. The old right-panel CALL_GRAPH tab was removed. */}
                <button
                  className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated cursor-pointer flex items-center gap-2"
                  onClick={() => {
                    if (!showFlowGraph) toggleFlowGraph();
                    setContextMenu(null);
                  }}
                >
                  <span className="text-vs-accent">🕸️</span>
                  Open call graph
                </button>

                <button
                  className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated cursor-pointer flex items-center gap-2"
                  onClick={() => {
                    navigator.clipboard.writeText(contextMenu.target).catch(() => {});
                    setContextMenu(null);
                  }}
                >
                  <span className="text-vs-muted">📋</span>
                  Copy method reference
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default CenterPanel;
