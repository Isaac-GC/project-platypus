import React, { useEffect, useRef, useCallback, useState } from "react";
import { useAppStore } from "../../store/appStore";
import { api } from "../../api/adapter";

// ─── CodeMirror 6 imports ────────────────────────────────────────────────────

import { EditorState } from "@codemirror/state";
import {
  EditorView,
  keymap,
  lineNumbers,
  highlightActiveLine,
  highlightActiveLineGutter,
} from "@codemirror/view";
import { defaultKeymap, indentWithTab, history, historyKeymap } from "@codemirror/commands";
import { python } from "@codemirror/lang-python";
import {
  linter,
  lintGutter,
  lintKeymap,
  setDiagnostics,
  type Diagnostic,
  forceLinting,
} from "@codemirror/lint";
import {
  autocompletion,
  completionKeymap,
  startCompletion,
  acceptCompletion,
  completionStatus,
  type CompletionContext,
  type CompletionResult,
} from "@codemirror/autocomplete";
import {
  syntaxHighlighting,
  defaultHighlightStyle,
  indentOnInput,
  bracketMatching,
} from "@codemirror/language";
import type { LintDiagnostic } from "../../api/types";
import { ScriptOutputTimeline, type FrameClickPayload } from "./ScriptOutput";

// ─── Platypus API completions ─────────────────────────────────────────────────
//
// The completion data is *dynamically* introspected from the platypus Python
// module on app startup (see `appStore.fetchScriptCompletions`). The store
// holds the result in `scriptIntrospection`; we read it synchronously here
// each time CodeMirror asks for completions. If introspection failed (e.g.
// platypus not built), the pool is empty and the user just sees no
// completions — the hardcoded fallback is gone on purpose to avoid drift.

import type { ScriptIntrospection, ScriptCompletionMember } from "../../api/types";

interface PC {
  label: string;
  type: string;
  detail?: string;
  apply?: string;
  /** Long form info shown in the completion popup body (docstring). */
  info?: string;
}

interface CompletionPools {
  /** Top-level members of `platypus.<X>`. */
  module: PC[];
  /** Class-level members keyed by class name (`Apk.<X>`). */
  staticByClass: Record<string, PC[]>;
  /** Instance members keyed by class name (`apk.<X>`). */
  instanceByClass: Record<string, PC[]>;
  /** All discovered class names — used for top-level completions and type inference. */
  classNames: string[];
}

const EMPTY_POOLS: CompletionPools = {
  module: [], staticByClass: {}, instanceByClass: {}, classNames: [],
};

/** Convert one introspection member into a CodeMirror completion item. */
function memberToPC(m: ScriptCompletionMember): PC {
  const isCallable = m.kind === "method" || m.kind === "static_method" || m.kind === "class_method";
  // Trailing `(` for callables so CodeMirror leaves the cursor inside the parens.
  // No-arg sentinel `()` would be nicer but we don't know parity reliably from
  // PyO3 signatures, so just open the call.
  const apply = isCallable ? `${m.name}(` : undefined;
  // First line of the signature is most useful in the small detail strip.
  const detail = m.signature ? m.signature : (m.kind === "property" ? "property" : m.kind);
  return {
    label: m.name,
    type: m.kind === "property" || m.kind === "attribute" ? "property" : "method",
    detail,
    apply,
    info: m.doc || undefined,
  };
}

/** Build the lookup pools from a fresh introspection snapshot.
 *  Memoise via a module-level cache keyed on the snapshot identity so we
 *  don't rebuild on every keystroke. */
let _poolCacheKey: ScriptIntrospection | null = null;
let _poolCache: CompletionPools = EMPTY_POOLS;

function buildPools(intro: ScriptIntrospection | null): CompletionPools {
  if (intro === _poolCacheKey) return _poolCache;
  if (!intro || !intro.classes) {
    _poolCacheKey = intro;
    _poolCache = EMPTY_POOLS;
    return _poolCache;
  }

  const module: PC[] = [];
  const staticByClass: Record<string, PC[]> = {};
  const instanceByClass: Record<string, PC[]> = {};
  const classNames: string[] = [];

  for (const [className, cls] of Object.entries(intro.classes)) {
    classNames.push(className);
    // Module-level entry — the class itself
    const firstDocLine = cls.doc ? cls.doc.split("\n")[0] : `platypus.${className}`;
    module.push({
      label: className,
      type: "class",
      detail: firstDocLine,
      info: cls.doc || undefined,
    });
    // Split members by kind
    const stat: PC[] = [];
    const inst: PC[] = [];
    for (const m of cls.members) {
      const pc = memberToPC(m);
      if (m.kind === "static_method" || m.kind === "class_method") {
        stat.push(pc);
      } else {
        inst.push(pc);
      }
    }
    staticByClass[className] = stat;
    instanceByClass[className] = inst;
  }

  // Also include module-level globals (functions, callables) introspected at top level.
  for (const g of intro.globals ?? []) {
    module.push(memberToPC(g));
  }

  _poolCacheKey = intro;
  _poolCache = { module, staticByClass, instanceByClass, classNames };
  return _poolCache;
}

/** Best-effort type inference for a variable. Looks for assignment patterns
 *  using any of the dynamically-discovered class names, then falls back to
 *  variable-name heuristics. */
function inferType(doc: string, varName: string, classNames: string[]): string | null {
  const escVar = varName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

  // Pattern 1: `var = platypus.Class(...)` or `var = Class(...)`
  for (const cls of classNames) {
    const escCls = cls.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pat = new RegExp(`\\b${escVar}\\s*=\\s*(?:platypus\\.)?${escCls}\\(`);
    if (pat.test(doc)) return cls;
  }
  // Pattern 2: `var = Class.factory(...)` — assume the static method returns Class
  for (const cls of classNames) {
    const escCls = cls.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const pat = new RegExp(`\\b${escVar}\\s*=\\s*(?:platypus\\.)?${escCls}\\.\\w+\\(`);
    if (pat.test(doc)) return cls;
  }
  // Pattern 3: known method-name → class mapping
  // (e.g. anything calling `.manifest()` returns a ManifestNode, `.resources()`
  // returns a ResourceTable). Only applies when those classes are present.
  const methodReturnHints: Record<string, string> = {
    manifest: "ManifestNode",
    manifest_resolved: "ManifestNode",
    resources: "ResourceTable",
  };
  for (const [method, cls] of Object.entries(methodReturnHints)) {
    if (!classNames.includes(cls)) continue;
    const pat = new RegExp(`\\b${escVar}\\s*=.*\\.${method}\\(`);
    if (pat.test(doc)) return cls;
  }

  // Pattern 4: name heuristics — try to map the variable name to a class name
  // by case-insensitive substring matching plus a few common short forms.
  const n = varName.toLowerCase();
  for (const cls of classNames) {
    const cn = cls.toLowerCase();
    if (n === cn) return cls;
  }
  // Common shorthand variable names → likely class
  const shorthandMap: Array<[(n: string) => boolean, string]> = [
    [(n) => n === "apk" || n === "app",                    "Apk"],
    [(n) => n === "apk_set" || n.startsWith("split"),       "ApkSet"],
    [(n) => n === "dex" || n.startsWith("dex"),             "Dex"],
    [(n) => n === "vm",                                      "Vm"],
    [(n) => n.startsWith("manifest") || n === "root",        "ManifestNode"],
    [(n) => n.startsWith("res") || n.includes("table"),      "ResourceTable"],
    [(n) => n.includes("site"),                              "CallSite"],
    [(n) => n.includes("result") || n.includes("exec"),     "ExecResult"],
  ];
  for (const [pred, cls] of shorthandMap) {
    if (pred(n) && classNames.includes(cls)) return cls;
  }
  return null;
}

function platypusCompletions(context: CompletionContext): CompletionResult | null {
  // Pull the live introspection snapshot from the store. This is synchronous
  // and reads through Zustand's getState — safe to call from a CodeMirror hook.
  const intro = useAppStore.getState().scriptIntrospection;
  const pools = buildPools(intro);

  // ── Member access: `obj.prefix` ─────────────────────────────────────────────
  const memberMatch = context.matchBefore(/[\w.]+\.\w*/);
  if (memberMatch) {
    const full     = memberMatch.text;
    const dotIdx   = full.lastIndexOf(".");
    const objPath  = full.substring(0, dotIdx);
    const pfx      = full.substring(dotIdx + 1).toLowerCase();
    const from     = memberMatch.from + dotIdx + 1;

    let pool: PC[] | undefined;
    if (objPath === "platypus") {
      pool = pools.module;
    } else if (pools.staticByClass[objPath]) {
      pool = pools.staticByClass[objPath];
    } else {
      const type = inferType(context.state.doc.toString(), objPath, pools.classNames);
      if (type) pool = pools.instanceByClass[type];
    }

    if (pool) {
      const options = pool.filter((c) => c.label.toLowerCase().startsWith(pfx));
      if (options.length > 0) return { from, options };
    }
    return null;
  }

  // ── Top-level word completions ───────────────────────────────────────────────
  const word = context.matchBefore(/\w+/);
  if (!word || (word.from === word.to && !context.explicit)) return null;

  const pfx = word.text.toLowerCase();
  const topLevel: PC[] = [
    { label: "LOADED_APK", type: "variable", detail: "str | None – path to the loaded APK" },
    { label: "platypus",   type: "module",   detail: "platypus – Android analysis library" },
    ...pools.classNames.map((name): PC => ({
      label: name, type: "class", detail: `platypus.${name}`,
    })),
  ];

  const options = topLevel.filter((c) => c.label.toLowerCase().startsWith(pfx));
  return options.length > 0 ? { from: word.from, options } : null;
}

// ─── Smart Tab — context-aware indent vs autocomplete ────────────────────────
//
// Default CodeMirror behaviour binds Tab to `indentWithTab`, which always
// inserts an indent regardless of what's on the line. That's frustrating
// in a Python editor where Tab is the natural way to accept the suggestion
// you can see in the completion popup — VSCode, IntelliJ, PyCharm, Jupyter
// all behave the way this handler does:
//
//   * Completion popup is already showing → accept the highlighted entry.
//   * Cursor is preceded by non-whitespace on this line → trigger completion
//     (or accept it on the second Tab if it pops up synchronously).
//   * Otherwise (cursor at start of line, or only whitespace before it) →
//     fall through to indent.
//
// The "return false" path tells CodeMirror's keymap to try the NEXT
// matching binding — which is `indentWithTab`, kept later in the same
// keymap chain. That's how we get both behaviours from one key.
function smartTab(view: EditorView): boolean {
  // 1) An active completion popup → accept it. `completionStatus`
  // returns "active" when the popup is showing and has at least one
  // option selectable; "pending" while we're waiting for completions
  // to resolve; null otherwise.
  if (completionStatus(view.state) === "active") {
    return acceptCompletion(view);
  }

  // 2) Look at the text BEFORE the cursor on the current line. We want
  // to know if there's any non-whitespace token the user might be
  // mid-typing — `pl<Tab>` should pop completions, `    <Tab>` at the
  // start of a new line should just indent.
  const { state } = view;
  const head = state.selection.main.head;
  const line = state.doc.lineAt(head);
  const before = state.sliceDoc(line.from, head);
  if (/\S/.test(before)) {
    // Non-whitespace exists → kick off completion. Returning true
    // consumes the Tab so we don't double-act (start completion AND
    // indent). The popup that opens accepts a second Tab via
    // `completionStatus("active")` above.
    return startCompletion(view);
  }

  // 3) Cursor is at the start-of-line or only whitespace precedes —
  // fall through to the next handler (`indentWithTab`).
  return false;
}

// ─── Ruff linter (debounced, calls backend) ───────────────────────────────────

let lintDebounceTimer: ReturnType<typeof setTimeout> | null = null;

function ruffLinter(view: EditorView): Promise<Diagnostic[]> {
  return new Promise((resolve) => {
    if (lintDebounceTimer) clearTimeout(lintDebounceTimer);
    lintDebounceTimer = setTimeout(async () => {
      const code = view.state.doc.toString();
      if (!code.trim()) {
        resolve([]);
        return;
      }
      try {
        const diags: LintDiagnostic[] = await api.lintScript(code);
        const cmDiags: Diagnostic[] = diags.map((d) => {
          // Convert 0-based line/col to document offset
          const line = view.state.doc.line(Math.min(d.line + 1, view.state.doc.lines));
          const from = line.from + Math.min(d.col, line.length);
          let to = from + 1;
          if (d.endLine !== undefined && d.endCol !== undefined) {
            const endLine = view.state.doc.line(Math.min(d.endLine + 1, view.state.doc.lines));
            to = endLine.from + Math.min(d.endCol, endLine.length);
          }
          return {
            from,
            to: Math.max(from + 1, to),
            severity: d.severity,
            message: `${d.code}: ${d.message}`,
          };
        });
        resolve(cmDiags);
      } catch {
        resolve([]);
      }
    }, 800);
  });
}

// ─── VS Code-like dark theme ──────────────────────────────────────────────────

const vsCodeDarkTheme = EditorView.theme(
  {
    "&": {
      color: "#d4d4d4",
      backgroundColor: "#1e1e1e",
      fontSize: "12px",
      fontFamily: "'JetBrains Mono', 'Cascadia Code', 'Fira Code', 'Consolas', monospace",
      height: "100%",
    },
    ".cm-content": {
      caretColor: "#aeafad",
      padding: "4px 0",
    },
    ".cm-cursor, .cm-dropCursor": { borderLeftColor: "#aeafad" },
    "&.cm-focused .cm-cursor": { borderLeftColor: "#aeafad" },
    ".cm-activeLine": { backgroundColor: "#2a2d2e" },
    ".cm-gutters": {
      backgroundColor: "#1e1e1e",
      color: "#858585",
      border: "none",
      borderRight: "1px solid #333",
    },
    ".cm-activeLineGutter": { backgroundColor: "#2a2d2e" },
    ".cm-lineNumbers .cm-gutterElement": { minWidth: "3em" },
    ".cm-selectionBackground, ::selection": {
      backgroundColor: "#264f78 !important",
    },
    "&.cm-focused .cm-selectionBackground": { backgroundColor: "#264f78" },
    ".cm-matchingBracket": { color: "#ffd700", outline: "1px solid #ffd700" },
    ".cm-tooltip": {
      backgroundColor: "#252526",
      border: "1px solid #454545",
      color: "#d4d4d4",
    },
    ".cm-tooltip.cm-tooltip-autocomplete > ul > li[aria-selected]": {
      backgroundColor: "#094771",
      color: "#d4d4d4",
    },
    // Lint gutter
    ".cm-lint-marker-error": { color: "#f48771" },
    ".cm-lint-marker-warning": { color: "#cca700" },
    ".cm-diagnosticSource": { fontSize: "0.8em", opacity: 0.7 },
  },
  { dark: true }
);

// ─── Completions status indicator ─────────────────────────────────────────────

interface CompletionsStatusProps {
  intro: ScriptIntrospection | null;
  unavailable: boolean;
  loading: boolean;
  onRefresh: () => void;
}

const CompletionsStatus: React.FC<CompletionsStatusProps> = ({
  intro, unavailable, loading, onRefresh,
}) => {
  let label: string;
  let cls: string;
  let title: string;

  if (loading) {
    label = "⟳ introspecting…";
    cls = "text-vs-dim";
    title = "Running Python introspection on the platypus module";
  } else if (unavailable) {
    label = "⚠ no completions";
    cls = "text-vs-warning";
    title = (intro?.error ?? "platypus module not importable") +
      "\n\nBuild it with: cd rust && maturin develop --features python";
  } else if (intro && intro.classes) {
    const n = Object.keys(intro.classes).length;
    label = `✓ ${n} class${n === 1 ? "" : "es"}`;
    cls = "text-vs-success";
    title = `Live introspection of platypus loaded: ${Object.keys(intro.classes).join(", ")}.\nClick to re-introspect.`;
  } else {
    label = "no completions";
    cls = "text-vs-dim";
    title = "Click to introspect the platypus module";
  }

  return (
    <button
      onClick={onRefresh}
      disabled={loading}
      className={`text-[10px] font-mono px-1.5 py-0.5 rounded border border-vs-border hover:border-vs-accent ${cls}`}
      title={title}
    >
      {label}
    </button>
  );
};

// ─── Script tab bar ───────────────────────────────────────────────────────────

import type { ScriptInfo } from "../../api/types";

// ─── Lightweight in-app modal ─────────────────────────────────────────────────
//
// We can't use `window.prompt` / `window.confirm` here — Tauri's WKWebView
// (macOS) and WebView2 (Windows) silently drop them on some platforms, which
// is why the create / rename / delete buttons used to appear to do nothing.
// This component is a small overlay that handles every dialog the script tab
// bar needs without depending on the runtime's modal-dialog support.

type ScriptDialog =
  | { kind: "create" }
  | { kind: "rename"; targetName: string }
  | { kind: "delete"; targetName: string };

interface ScriptDialogProps {
  dialog: ScriptDialog;
  onClose: () => void;
  onSubmit: (value?: string) => Promise<void> | void;
}

const ScriptDialogModal: React.FC<ScriptDialogProps> = ({ dialog, onClose, onSubmit }) => {
  const [value, setValue] = useState(
    dialog.kind === "rename" ? dialog.targetName :
    dialog.kind === "create" ? "untitled.py" : "",
  );
  const [busy, setBusy] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-focus + select on mount so the user can just type.
  useEffect(() => {
    inputRef.current?.focus();
    inputRef.current?.select();
  }, []);

  const handleSubmit = async () => {
    if (busy) return;
    setBusy(true);
    try {
      if (dialog.kind === "delete") {
        await onSubmit();
      } else {
        const trimmed = value.trim();
        if (!trimmed) { setBusy(false); return; }
        await onSubmit(trimmed);
      }
      onClose();
    } catch {
      // Errors are logged by the store; just keep the dialog open so the
      // user can correct the input.
      setBusy(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") { e.preventDefault(); void handleSubmit(); }
    if (e.key === "Escape") { e.preventDefault(); onClose(); }
  };

  const titleText =
    dialog.kind === "create" ? "New script"
    : dialog.kind === "rename" ? `Rename ${dialog.targetName}`
    : `Delete ${dialog.targetName}?`;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-vs-surface border border-vs-border rounded-lg shadow-2xl w-96 p-4 flex flex-col gap-3"
           onKeyDown={handleKey}>
        <div className="text-sm font-semibold text-vs-text">{titleText}</div>

        {dialog.kind !== "delete" && (
          <input
            ref={inputRef}
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={handleKey}
            placeholder="myscript.py"
            className="bg-vs-bg border border-vs-border rounded px-2 py-1.5 text-sm font-mono text-vs-text outline-none focus:border-vs-accent"
            spellCheck={false}
            autoComplete="off"
          />
        )}

        {dialog.kind === "delete" && (
          <div className="text-xs text-vs-muted">
            This will permanently remove <span className="font-mono">{dialog.targetName}</span> from
            the cache. This can&apos;t be undone.
          </div>
        )}

        <div className="flex justify-end gap-2 pt-1">
          <button
            onClick={onClose}
            disabled={busy}
            className="px-3 py-1 text-xs rounded border border-vs-border text-vs-muted hover:text-vs-text hover:border-vs-text disabled:opacity-50"
          >
            Cancel
          </button>
          <button
            onClick={() => void handleSubmit()}
            disabled={busy || (dialog.kind !== "delete" && !value.trim())}
            className={[
              "px-3 py-1 text-xs rounded text-white font-semibold disabled:opacity-50",
              dialog.kind === "delete"
                ? "bg-vs-error hover:bg-vs-error/80"
                : "bg-vs-accent hover:bg-vs-accent/80",
            ].join(" ")}
          >
            {busy
              ? <><span className="animate-spin inline-block">⟳</span> …</>
              : dialog.kind === "create" ? "Create"
              : dialog.kind === "rename" ? "Rename"
              : "Delete"}
          </button>
        </div>
      </div>
    </div>
  );
};

interface ScriptTabBarProps {
  scripts: ScriptInfo[];
  activeName: string | null;
  onSwitch:    (name: string) => void;
  onCreate:    () => void;
  onDelete:    (name: string) => void;
  onRename:    (name: string) => void;
  onDuplicate: (name: string) => void;
}

interface TabContextMenuState { x: number; y: number; targetName: string }

const ScriptTabBar: React.FC<ScriptTabBarProps> = ({
  scripts, activeName, onSwitch, onCreate, onDelete, onRename, onDuplicate,
}) => {
  const [ctxMenu, setCtxMenu] = useState<TabContextMenuState | null>(null);

  // Dismiss context menu on outside click / Escape.
  useEffect(() => {
    if (!ctxMenu) return;
    const dismiss = () => setCtxMenu(null);
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setCtxMenu(null); };
    window.addEventListener("click", dismiss);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", dismiss);
      window.removeEventListener("keydown", onKey);
    };
  }, [ctxMenu]);

  return (
    <div className="flex items-center gap-0 px-1 py-0.5 bg-vs-bg border-b border-vs-border flex-shrink-0 overflow-x-auto">
      {scripts.length === 0 && (
        <span className="text-[10px] text-vs-dim italic px-2 py-1">No scripts yet</span>
      )}
      {scripts.map((s) => {
        const isActive = s.name === activeName;
        return (
          <div key={s.name} className="relative flex-shrink-0">
            <button
              className={[
                "px-2.5 py-1 text-xs font-mono border-b-2 transition-colors whitespace-nowrap",
                isActive
                  ? "border-vs-accent text-vs-accent bg-vs-elevated/40"
                  : "border-transparent text-vs-muted hover:text-vs-text hover:bg-vs-elevated/30",
              ].join(" ")}
              onClick={() => onSwitch(s.name)}
              onContextMenu={(e) => {
                e.preventDefault();
                setCtxMenu({ x: e.clientX, y: e.clientY, targetName: s.name });
              }}
              title={`${s.name} — ${s.sizeBytes} bytes\nRight-click for options`}
            >
              {s.name}
            </button>
          </div>
        );
      })}
      {/* New-script button */}
      <button
        className="px-2 py-1 text-xs text-vs-muted hover:text-vs-accent hover:bg-vs-elevated/40 flex-shrink-0"
        onClick={onCreate}
        title="Create new script"
      >
        +
      </button>

      {/* Right-click context menu */}
      {ctxMenu && (
        <div
          className="fixed z-50 bg-vs-surface border border-vs-border rounded shadow-lg py-1 min-w-40 text-xs"
          style={{ left: ctxMenu.x, top: ctxMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <div className="px-3 py-1 border-b border-vs-border mb-1 text-vs-dim font-mono truncate">
            {ctxMenu.targetName}
          </div>
          <button
            className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated"
            onClick={() => { onRename(ctxMenu.targetName); setCtxMenu(null); }}
          >
            ✏️  Rename…
          </button>
          <button
            className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated"
            onClick={() => { onDuplicate(ctxMenu.targetName); setCtxMenu(null); }}
          >
            📑  Duplicate
          </button>
          <button
            className="w-full text-left px-3 py-1.5 hover:bg-vs-elevated text-vs-error"
            onClick={() => { onDelete(ctxMenu.targetName); setCtxMenu(null); }}
          >
            🗑  Delete
          </button>
        </div>
      )}
    </div>
  );
};

// ─── Component ────────────────────────────────────────────────────────────────

const ScriptPanel: React.FC = () => {
  const scriptContent = useAppStore((s) => s.scriptContent);
  const scriptOutput = useAppStore((s) => s.scriptOutput);
  const scriptOutputHistory = useAppStore((s) => s.scriptOutputHistory);
  const clearScriptHistory = useAppStore((s) => s.clearScriptHistory);
  const removeScriptHistoryEntry = useAppStore((s) => s.removeScriptHistoryEntry);
  const isScriptRunning = useAppStore((s) => s.isScriptRunning);
  const setScriptContent = useAppStore((s) => s.setScriptContent);
  const runScript = useAppStore((s) => s.runScript);
  const killScript = useAppStore((s) => s.killScript);
  const scriptIntrospection = useAppStore((s) => s.scriptIntrospection);
  const scriptIntrospectionUnavailable = useAppStore((s) => s.scriptIntrospectionUnavailable);
  const isFetchingScriptCompletions = useAppStore((s) => s.isFetchingScriptCompletions);
  const fetchScriptCompletions = useAppStore((s) => s.fetchScriptCompletions);
  // Multi-script library
  const scripts = useAppStore((s) => s.scripts);
  const activeScriptName = useAppStore((s) => s.activeScriptName);
  const setActiveScript = useAppStore((s) => s.setActiveScript);
  const createScript = useAppStore((s) => s.createScript);
  const deleteScript = useAppStore((s) => s.deleteScript);
  const renameScript = useAppStore((s) => s.renameScript);
  const duplicateScript = useAppStore((s) => s.duplicateScript);

  // Active create/rename/delete dialog (replaces window.prompt/confirm which
  // don't render reliably inside Tauri's webview).
  const [scriptDialog, setScriptDialog] = useState<ScriptDialog | null>(null);

  const editorRef = useRef<HTMLDivElement>(null);
  const viewRef = useRef<EditorView | null>(null);
  // Track whether external scriptContent update needs to be pushed to CM
  const internalChangeRef = useRef(false);

  // ── Initialize CodeMirror once ──────────────────────────────────────────────

  const onEditorChange = useCallback(
    (code: string) => {
      internalChangeRef.current = true;
      setScriptContent(code);
      internalChangeRef.current = false;
    },
    [setScriptContent]
  );

  useEffect(() => {
    if (!editorRef.current) return;

    const state = EditorState.create({
      doc: scriptContent,
      extensions: [
        // Core
        history(),
        keymap.of([
          // Smart Tab MUST come before indentWithTab so it gets first
          // dibs. When smartTab returns false (cursor at start-of-line
          // or only whitespace before it), CodeMirror falls through to
          // the next matching binding — which is indentWithTab below.
          { key: "Tab", run: smartTab },
          ...defaultKeymap,
          ...historyKeymap,
          ...completionKeymap,
          ...lintKeymap,
          indentWithTab,
        ]),
        lineNumbers(),
        highlightActiveLine(),
        highlightActiveLineGutter(),
        indentOnInput(),
        bracketMatching(),
        // Language
        python(),
        syntaxHighlighting(defaultHighlightStyle),
        // Completions
        autocompletion({
          override: [platypusCompletions],
          activateOnTyping: true,
        }),
        // Linting
        linter(ruffLinter, { delay: 800 }),
        lintGutter(),
        // Theme
        vsCodeDarkTheme,
        // On-change listener
        EditorView.updateListener.of((update) => {
          if (update.docChanged) {
            onEditorChange(update.state.doc.toString());
          }
        }),
      ],
    });

    const view = new EditorView({ state, parent: editorRef.current });
    viewRef.current = view;

    return () => {
      view.destroy();
      viewRef.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Sync external scriptContent changes into CM (e.g. switching scripts) ───

  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    if (internalChangeRef.current) return;
    const current = view.state.doc.toString();
    if (current === scriptContent) return;
    view.dispatch({
      changes: { from: 0, to: current.length, insert: scriptContent },
    });
  }, [scriptContent]);

  // ── Run keyboard shortcut (Ctrl/Cmd+Enter) ──────────────────────────────────

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
        e.preventDefault();
        runScript();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [runScript]);

  // ── Force re-lint when editor mounts ───────────────────────────────────────

  useEffect(() => {
    const view = viewRef.current;
    if (view && scriptContent.trim()) {
      // Trigger first lint pass after a small delay
      const t = setTimeout(() => forceLinting(view), 1200);
      return () => clearTimeout(t);
    }
  }, [scriptContent]);

  // ── Runtime error → editor diagnostic ──────────────────────────────────────
  //
  // When the latest run fails with a traceback that points at our wrapper
  // file, find the deepest frame whose file matches `wrapperPath` and
  // pin a CodeMirror diagnostic at the remapped user line. This way the
  // editor gutter shows a red dot at the offending line on the next render
  // — same flow as a static lint error, just sourced from the runtime.
  useEffect(() => {
    const view = viewRef.current;
    if (!view) return;
    if (!scriptOutput || scriptOutput.exitCode === 0 || !scriptOutput.wrapperPath) {
      // No runtime error (or no wrapper info) — push an empty diagnostic
      // set so any previous runtime marker is cleared. Ruff diagnostics
      // come through a separate linter() instance and aren't affected.
      view.dispatch(setDiagnostics(view.state, []));
      return;
    }
    // Walk the traceback from bottom to top and grab the deepest frame
    // that lives in our wrapper. That's the user-code line that actually
    // raised the exception. Stdlib frames (e.g. inside json.loads) are
    // skipped because we don't have their source open.
    const wrapper = scriptOutput.wrapperPath;
    const prologue = scriptOutput.prologueLines ?? 0;
    const frameRe = /^ *File "([^"]+)", line (\d+)(?:, in (.+))?$/gm;
    let userLine: number | null = null;
    let m: RegExpExecArray | null;
    while ((m = frameRe.exec(scriptOutput.stderr)) !== null) {
      if (m[1] === wrapper) {
        userLine = Math.max(1, parseInt(m[2], 10) - prologue);
        // Don't break — the LAST match in the wrapper is the innermost frame.
      }
    }
    if (userLine === null) {
      view.dispatch(setDiagnostics(view.state, []));
      return;
    }
    // The final non-empty line of stderr is conventionally the
    // exception type + message ("TypeError: …"). Surface that as the
    // diagnostic body so hovering the gutter tells you what blew up.
    const lastErrLine = scriptOutput.stderr
      .split("\n")
      .reverse()
      .find((l) => l.trim().length > 0) ?? "(runtime error)";
    const lineInfo = view.state.doc.line(Math.min(userLine, view.state.doc.lines));
    const diag: Diagnostic = {
      from: lineInfo.from,
      to: lineInfo.to,
      severity: "error",
      message: lastErrLine,
      source: "runtime",
    };
    view.dispatch(setDiagnostics(view.state, [diag]));
  }, [scriptOutput]);

  // ── Clickable traceback frame → jump editor cursor ────────────────────────
  //
  // The output panel surfaces `File "...", line N` traceback frames as
  // clickable buttons. When the frame's file matches our wrapper temp,
  // we jump the editor cursor to the corresponding user-code line so the
  // analyst can see the source of the error without leaving the panel.
  // External frames (stdlib, third-party) we don't have open — fall back
  // to copying the file path so the user can open it in their OS editor.
  const handleFrameClick = useCallback((payload: FrameClickPayload) => {
    if (payload.isWrapper) {
      const view = viewRef.current;
      if (!view) return;
      const line = view.state.doc.line(
        Math.min(payload.userLine, view.state.doc.lines),
      );
      view.dispatch({
        selection: { anchor: line.from, head: line.from },
        scrollIntoView: true,
      });
      view.focus();
      return;
    }
    // External frame — best-effort clipboard copy with no UI toast (we
    // don't want to add a notification system just for this).
    void navigator.clipboard.writeText(`${payload.file}:${payload.line}`).catch(() => {
      // Silent fall-through. The frame button itself shows the path in
      // its tooltip, so the user can still read it.
    });
  }, []);

  const hasOutput = scriptOutput !== null;
  const hasError = hasOutput && scriptOutput.exitCode !== 0;
  void hasError; // hasError is referenced by the old single-output block we removed;
                 // keep the variable for any future banner reuse without warnings.

  return (
    <div className="flex flex-col h-full overflow-hidden bg-vs-surface">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-2 py-1.5 border-b border-vs-border bg-vs-elevated flex-shrink-0">
        <span className="text-xs font-semibold text-vs-muted flex-1">
          🐍 Python Script
        </span>

        {/* Completion status — clickable to refresh introspection. */}
        <CompletionsStatus
          intro={scriptIntrospection}
          unavailable={scriptIntrospectionUnavailable}
          loading={isFetchingScriptCompletions}
          onRefresh={() => void fetchScriptCompletions()}
        />

        <span className="text-xs text-vs-dim opacity-60">⌘↩ to run</span>
        {/* While a script is running, the Run button becomes Stop — clicking
            sends SIGTERM to the python3 subprocess. The button stays in the
            "Stopping…" state until `runScript`'s wait_with_output returns. */}
        {isScriptRunning ? (
          <button
            className="flex items-center gap-1 px-2.5 py-1 bg-vs-error hover:bg-vs-error/80 text-white text-xs font-semibold rounded transition-colors"
            onClick={() => void killScript()}
            title="Send SIGTERM to the running python3 subprocess"
          >
            <span className="animate-spin inline-block">⟳</span> Stop
          </button>
        ) : (
          <button
            className="flex items-center gap-1 px-2.5 py-1 bg-vs-accent hover:bg-vs-accent/80 text-white text-xs font-semibold rounded transition-colors"
            onClick={runScript}
          >
            ▶ Run
          </button>
        )}
      </div>

      {/* Script tab bar — one tab per saved .py in <cache>/scripts/. */}
      <ScriptTabBar
        scripts={scripts}
        activeName={activeScriptName}
        onSwitch={(name) => void setActiveScript(name)}
        onCreate={() => setScriptDialog({ kind: "create" })}
        onDelete={(name) => setScriptDialog({ kind: "delete", targetName: name })}
        onRename={(oldName) => setScriptDialog({ kind: "rename", targetName: oldName })}
        onDuplicate={(name) => void duplicateScript(name)}
      />

      {/* In-app modal — renders only while a dialog is active. */}
      {scriptDialog && (
        <ScriptDialogModal
          dialog={scriptDialog}
          onClose={() => setScriptDialog(null)}
          onSubmit={async (value) => {
            if (scriptDialog.kind === "create" && value) {
              await createScript(value);
            } else if (scriptDialog.kind === "rename" && value) {
              if (value !== scriptDialog.targetName) {
                await renameScript(scriptDialog.targetName, value);
              }
            } else if (scriptDialog.kind === "delete") {
              await deleteScript(scriptDialog.targetName);
            }
          }}
        />
      )}

      {/* Editor area — takes remaining space minus output */}
      <div
        className="flex-1 overflow-hidden"
        style={{ minHeight: 0 }}
      >
        <div ref={editorRef} className="h-full overflow-hidden" />
      </div>

      {/* Output timeline — replaces the old single-output pane. Renders
          recent runs as a scrollable stack with status, duration,
          relative timestamp, and clickable traceback frames that jump
          back into the editor. */}
      <ScriptOutputTimeline
        history={scriptOutputHistory}
        onClearAll={clearScriptHistory}
        onRemove={removeScriptHistoryEntry}
        onFrameClick={handleFrameClick}
      />
    </div>
  );
};

export default ScriptPanel;
