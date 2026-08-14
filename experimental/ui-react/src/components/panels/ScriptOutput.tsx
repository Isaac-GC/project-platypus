import React, { useMemo, useState, useCallback } from "react";
import type { ScriptRunEntry } from "../../api/types";

// ─── Traceback parsing ────────────────────────────────────────────────────────
//
// Standard Python traceback shape we care about:
//
//   Traceback (most recent call last):
//     File "/tmp/xyz.py", line 42, in <module>
//       foo(bar)
//     File "/usr/lib/python3.11/foo.py", line 17, in foo
//       raise TypeError("...")
//   TypeError: bad operand
//
// We tokenize stderr into a sequence of `Segment`s — either `plain` text
// or a `frame` (clickable file:line:fnName). Render in order, preserving
// whitespace + newlines.
//
// Why parse it here instead of a third-party library? The format is
// stable across CPython 3.x and we only need *one* shape; pulling in
// `stack-trace-parser` for a 6-line regex isn't worth the bundle weight.

interface PlainSegment {
  type: "plain";
  text: string;
}

interface FrameSegment {
  type: "frame";
  /** Full text of the matched `File "...", line N, in <fn>` line so the
   *  visible rendering matches the source byte-for-byte. */
  text: string;
  file: string;
  line: number;
  /** Function name (between `in ` and end-of-line). May be `<module>`. */
  fn: string;
}

type Segment = PlainSegment | FrameSegment;

/** Matches one traceback frame line. Anchored to start-of-line and a
 *  trailing line break (so multi-line code samples below the `File ...`
 *  line are NOT swallowed into the frame text). The two capture groups
 *  are file path and line number; the function name is parsed after. */
const FRAME_RE = /^( *File "([^"]+)", line (\d+)(?:, in (.+))?)$/gm;

export function parseTraceback(stderr: string): Segment[] {
  const segments: Segment[] = [];
  let lastEnd = 0;
  // Reset lastIndex since the regex is global + mutable.
  FRAME_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = FRAME_RE.exec(stderr)) !== null) {
    if (m.index > lastEnd) {
      segments.push({ type: "plain", text: stderr.slice(lastEnd, m.index) });
    }
    segments.push({
      type: "frame",
      text: m[1],
      file: m[2],
      line: parseInt(m[3], 10),
      fn: m[4] ?? "<module>",
    });
    lastEnd = m.index + m[1].length;
  }
  if (lastEnd < stderr.length) {
    segments.push({ type: "plain", text: stderr.slice(lastEnd) });
  }
  // No frames found → one plain segment with the original text. Saves
  // the caller a special case.
  if (segments.length === 0 && stderr.length > 0) {
    segments.push({ type: "plain", text: stderr });
  }
  return segments;
}

// ─── Frame click resolution ───────────────────────────────────────────────────

export interface FrameClickPayload {
  /** Frame's literal file path as it appeared in the traceback. */
  file: string;
  /** Source-file line number (1-based). For the wrapper case, callers
   *  remap this to the user-code line via `wrapperPath`/`prologueLines`. */
  line: number;
  fn: string;
  /** True when `file` matches the script-runner's wrapper path. The
   *  caller (ScriptPanel) should jump to the editor at the remapped line
   *  instead of trying to open a separate tab. */
  isWrapper: boolean;
  /** Line number to highlight in the editor for the wrapper case
   *  (`line - prologueLines`). For non-wrapper files this equals `line`
   *  (callers should treat the file as external and just copy the path
   *  to clipboard or open in OS editor). */
  userLine: number;
}

function resolveFrame(
  file: string,
  line: number,
  fn: string,
  wrapperPath: string | undefined,
  prologueLines: number,
): FrameClickPayload {
  const isWrapper = !!wrapperPath && file === wrapperPath;
  const userLine = isWrapper ? Math.max(1, line - prologueLines) : line;
  return { file, line, fn, isWrapper, userLine };
}

// ─── Output toolbar ────────────────────────────────────────────────────────────

interface ToolbarProps {
  entry: ScriptRunEntry;
  expanded: boolean;
  onToggleExpand: () => void;
  onCopyStdout: () => void;
  onCopyStderr: () => void;
  onRemove: () => void;
}

const EntryToolbar: React.FC<ToolbarProps> = ({
  entry, expanded, onToggleExpand, onCopyStdout, onCopyStderr, onRemove,
}) => {
  const ok = entry.exitCode === 0;
  return (
    <div
      className={[
        "flex items-center gap-2 px-2 py-1 text-xs font-semibold border-b border-vs-border sticky top-0 z-10",
        ok ? "bg-vs-success/10 text-vs-success" : "bg-vs-error/10 text-vs-error",
      ].join(" ")}
    >
      <button
        onClick={onToggleExpand}
        className="hover:bg-vs-elevated/40 px-1 rounded"
        title={expanded ? "Collapse" : "Expand"}
      >
        {expanded ? "▾" : "▸"}
      </button>
      <span className="font-mono">
        {ok ? "✓" : "✗"} {ok ? "Success" : `Exit ${entry.exitCode}`}
      </span>
      {entry.scriptName && (
        <span className="text-vs-dim font-normal">· {entry.scriptName}</span>
      )}
      <span className="text-vs-dim font-normal opacity-70">
        {entry.durationMs}ms
      </span>
      <span className="text-vs-dim font-normal opacity-50" title={new Date(entry.finishedAt).toLocaleString()}>
        {formatRelative(entry.finishedAt)}
      </span>
      <span className="flex-1" />
      {entry.stdout && (
        <button
          onClick={onCopyStdout}
          className="text-vs-dim hover:text-vs-text px-1 rounded"
          title="Copy stdout"
        >
          ⧉ out
        </button>
      )}
      {entry.stderr && (
        <button
          onClick={onCopyStderr}
          className="text-vs-dim hover:text-vs-text px-1 rounded"
          title="Copy stderr"
        >
          ⧉ err
        </button>
      )}
      <button
        onClick={onRemove}
        className="text-vs-dim hover:text-vs-error px-1 rounded"
        title="Remove this run"
      >
        ✕
      </button>
    </div>
  );
};

/** Format an epoch-ms timestamp as a short relative string ("12s ago",
 *  "5m ago"). Stops being precise after an hour — the absolute time is
 *  in the title tooltip for that case. */
function formatRelative(ms: number): string {
  const d = Date.now() - ms;
  if (d < 5_000) return "just now";
  if (d < 60_000) return `${Math.round(d / 1000)}s ago`;
  if (d < 3_600_000) return `${Math.round(d / 60_000)}m ago`;
  if (d < 86_400_000) return `${Math.round(d / 3_600_000)}h ago`;
  return new Date(ms).toLocaleDateString();
}

// ─── Frame button (renders one clickable traceback line) ───────────────────────

interface FrameLinkProps {
  segment: FrameSegment;
  payload: FrameClickPayload;
  onClick: (p: FrameClickPayload) => void;
}

const FrameLink: React.FC<FrameLinkProps> = ({ segment, payload, onClick }) => {
  const title = payload.isWrapper
    ? `Jump to script line ${payload.userLine} (${segment.fn})`
    : `External frame — click to copy path\n${segment.file}:${segment.line}`;
  return (
    <button
      onClick={() => onClick(payload)}
      className={[
        "inline text-left px-0 underline decoration-dotted hover:decoration-solid cursor-pointer",
        payload.isWrapper ? "text-vs-accent" : "text-vs-muted",
      ].join(" ")}
      title={title}
    >
      {segment.text}
    </button>
  );
};

// ─── Output body ──────────────────────────────────────────────────────────────

interface EntryBodyProps {
  entry: ScriptRunEntry;
  onFrameClick: (p: FrameClickPayload) => void;
  /** Optional filter from the search box — when non-empty, lines that
   *  don't contain it are dimmed. Matches the VSCode terminal "find"
   *  behaviour of softly demoting non-matches instead of hiding them. */
  searchQuery: string;
}

const EntryBody: React.FC<EntryBodyProps> = ({ entry, onFrameClick, searchQuery }) => {
  const segments = useMemo(() => parseTraceback(entry.stderr), [entry.stderr]);
  const q = searchQuery.toLowerCase();
  const matchClass = (text: string) =>
    q && !text.toLowerCase().includes(q) ? "opacity-30" : "";

  return (
    <>
      {entry.stdout && (
        <pre className={[
          "px-2 py-1.5 text-xs font-mono text-vs-text whitespace-pre-wrap break-all",
          matchClass(entry.stdout),
        ].join(" ")}>
          {entry.stdout}
        </pre>
      )}
      {entry.stderr && (
        <pre className={[
          "px-2 py-1.5 text-xs font-mono text-vs-error whitespace-pre-wrap break-all border-t border-vs-border/40",
          matchClass(entry.stderr),
        ].join(" ")}>
          {segments.map((seg, i) => {
            if (seg.type === "plain") {
              return <span key={i}>{seg.text}</span>;
            }
            const payload = resolveFrame(
              seg.file, seg.line, seg.fn,
              entry.wrapperPath, entry.prologueLines ?? 0,
            );
            return (
              <FrameLink
                key={i}
                segment={seg}
                payload={payload}
                onClick={onFrameClick}
              />
            );
          })}
        </pre>
      )}
      {!entry.stdout && !entry.stderr && (
        <div className="px-2 py-1.5 text-xs text-vs-dim italic">
          (no output)
        </div>
      )}
    </>
  );
};

// ─── Top-level timeline component ─────────────────────────────────────────────

interface ScriptOutputTimelineProps {
  history: ScriptRunEntry[];
  onClearAll: () => void;
  onRemove: (id: string) => void;
  onFrameClick: (p: FrameClickPayload) => void;
}

export const ScriptOutputTimeline: React.FC<ScriptOutputTimelineProps> = ({
  history, onClearAll, onRemove, onFrameClick,
}) => {
  // Each run defaults to expanded if it's the head (newest) AND there's
  // either an error to triage or non-trivial stdout. Older runs collapse
  // by default so the timeline header is scannable. State key = run id.
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});
  const [searchQuery, setSearchQuery] = useState("");

  const isExpanded = (id: string, idx: number, entry: ScriptRunEntry) => {
    if (id in expanded) return expanded[id];
    // Auto-expand the newest run, and any run with an error.
    return idx === 0 || entry.exitCode !== 0;
  };

  const copyToClipboard = useCallback(async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Tauri webview occasionally blocks the clipboard API — fall back
      // to a textarea+execCommand dance so the button always does
      // SOMETHING. Silent on failure; the user can re-try.
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); } catch { /* give up */ }
      document.body.removeChild(ta);
    }
  }, []);

  if (history.length === 0) {
    return (
      <div className="flex-shrink-0 border-t border-vs-border bg-vs-bg p-3 text-xs text-vs-dim italic text-center">
        Output history is empty. Hit Run (⌘↩) to execute the current script.
      </div>
    );
  }

  return (
    <div
      className="flex-shrink-0 border-t border-vs-border bg-vs-bg flex flex-col"
      style={{ maxHeight: "45%" }}
    >
      {/* Timeline toolbar */}
      <div className="flex items-center gap-2 px-2 py-1 border-b border-vs-border bg-vs-elevated/40 sticky top-0 z-20">
        <span className="text-xs font-semibold text-vs-muted">
          Output history
        </span>
        <span className="text-[10px] text-vs-dim">
          {history.length} run{history.length === 1 ? "" : "s"}
        </span>
        <input
          type="text"
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Filter…"
          className="ml-2 bg-vs-bg border border-vs-border rounded px-1.5 py-0.5 text-[10px] font-mono text-vs-text outline-none focus:border-vs-accent w-32"
          spellCheck={false}
        />
        <span className="flex-1" />
        <button
          onClick={() => setExpanded(Object.fromEntries(history.map(e => [e.id, true])))}
          className="text-[10px] text-vs-dim hover:text-vs-text px-1"
          title="Expand all"
        >
          ▾ all
        </button>
        <button
          onClick={() => setExpanded(Object.fromEntries(history.map(e => [e.id, false])))}
          className="text-[10px] text-vs-dim hover:text-vs-text px-1"
          title="Collapse all"
        >
          ▸ all
        </button>
        <button
          onClick={onClearAll}
          className="text-[10px] text-vs-dim hover:text-vs-error px-1"
          title="Clear all history"
        >
          🗑 clear
        </button>
      </div>

      {/* Scrollable run list */}
      <div className="flex-1 overflow-auto">
        {history.map((entry, idx) => {
          const exp = isExpanded(entry.id, idx, entry);
          return (
            <div key={entry.id} className="border-b border-vs-border/40">
              <EntryToolbar
                entry={entry}
                expanded={exp}
                onToggleExpand={() => setExpanded((s) => ({ ...s, [entry.id]: !exp }))}
                onCopyStdout={() => copyToClipboard(entry.stdout)}
                onCopyStderr={() => copyToClipboard(entry.stderr)}
                onRemove={() => onRemove(entry.id)}
              />
              {exp && (
                <EntryBody
                  entry={entry}
                  onFrameClick={onFrameClick}
                  searchQuery={searchQuery}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};
