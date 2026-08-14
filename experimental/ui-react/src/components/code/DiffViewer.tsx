import React, { useMemo } from "react";

interface DiffViewerProps {
  leftCode?: string;
  rightCode?: string;
  leftLabel?: string;
  rightLabel?: string;
}

// ─── Diff types ───────────────────────────────────────────────────────────────

type LineType = "equal" | "remove" | "add" | "empty";

interface SideLine {
  text: string;
  type: LineType;
  lineNum: number | null;
}

// ─── LCS-based diff ───────────────────────────────────────────────────────────

const MAX_DIFF_LINES = 3000;

function computeSideBySide(
  left: string[],
  right: string[]
): { leftLines: SideLine[]; rightLines: SideLine[] } {
  const m = left.length;
  const n = right.length;

  // Fall back to plain side-by-side for very large files
  if (m > MAX_DIFF_LINES || n > MAX_DIFF_LINES) {
    const maxLen = Math.max(m, n);
    const leftLines: SideLine[] = [];
    const rightLines: SideLine[] = [];
    for (let i = 0; i < maxLen; i++) {
      leftLines.push({ text: left[i] ?? "", type: "equal", lineNum: i < m ? i + 1 : null });
      rightLines.push({ text: right[i] ?? "", type: "equal", lineNum: i < n ? i + 1 : null });
    }
    return { leftLines, rightLines };
  }

  // Build LCS DP table
  const dp: number[][] = Array.from({ length: m + 1 }, () => new Array(n + 1).fill(0));
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (left[i - 1] === right[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1] + 1;
      } else {
        dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
      }
    }
  }

  // Backtrack to build ops
  type Op = { type: "eq" | "del" | "ins"; text: string };
  const ops: Op[] = [];
  let i = m, j = n;
  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && left[i - 1] === right[j - 1]) {
      ops.unshift({ type: "eq", text: left[i - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || dp[i][j - 1] >= dp[i - 1][j])) {
      ops.unshift({ type: "ins", text: right[j - 1] });
      j--;
    } else {
      ops.unshift({ type: "del", text: left[i - 1] });
      i--;
    }
  }

  // Build aligned side-by-side lines
  const leftLines: SideLine[] = [];
  const rightLines: SideLine[] = [];
  let leftNum = 1;
  let rightNum = 1;
  let k = 0;

  while (k < ops.length) {
    const op = ops[k];
    if (op.type === "eq") {
      leftLines.push({ text: op.text, type: "equal", lineNum: leftNum++ });
      rightLines.push({ text: op.text, type: "equal", lineNum: rightNum++ });
      k++;
    } else {
      // Collect consecutive deletions and insertions
      const dels: string[] = [];
      const ins: string[] = [];
      while (k < ops.length && (ops[k].type === "del" || ops[k].type === "ins")) {
        if (ops[k].type === "del") dels.push(ops[k].text);
        else ins.push(ops[k].text);
        k++;
      }
      const maxLen = Math.max(dels.length, ins.length);
      for (let p = 0; p < maxLen; p++) {
        if (p < dels.length) {
          leftLines.push({ text: dels[p], type: "remove", lineNum: leftNum++ });
        } else {
          leftLines.push({ text: "", type: "empty", lineNum: null });
        }
        if (p < ins.length) {
          rightLines.push({ text: ins[p], type: "add", lineNum: rightNum++ });
        } else {
          rightLines.push({ text: "", type: "empty", lineNum: null });
        }
      }
    }
  }

  return { leftLines, rightLines };
}

// ─── Line rendering ───────────────────────────────────────────────────────────

const LINE_BG: Record<LineType, string> = {
  equal: "",
  remove: "bg-red-900/30",
  add: "bg-green-900/30",
  empty: "bg-vs-elevated/20",
};

const LINE_GUTTER: Record<LineType, string> = {
  equal: "text-vs-dim",
  remove: "text-red-400",
  add: "text-green-400",
  empty: "text-vs-dim",
};

const LINE_MARKER: Record<LineType, string> = {
  equal: " ",
  remove: "-",
  add: "+",
  empty: " ",
};

// ─── DiffViewer ───────────────────────────────────────────────────────────────

const DiffViewer: React.FC<DiffViewerProps> = ({
  leftCode,
  rightCode,
  leftLabel = "Original",
  rightLabel = "Deobfuscated",
}) => {
  const leftRaw = leftCode ?? "";
  const rightRaw = rightCode ?? "";

  const { leftLines, rightLines } = useMemo(
    () => computeSideBySide(leftRaw.split("\n"), rightRaw.split("\n")),
    [leftRaw, rightRaw]
  );

  if (!leftCode && !rightCode) {
    return (
      <div className="flex items-center justify-center h-full text-vs-muted font-mono text-sm">
        No diff content. Run deobfuscation first.
      </div>
    );
  }

  const renderPane = (lines: SideLine[], label: string, side: "left" | "right") => (
    <div
      className={`flex-1 flex flex-col overflow-hidden ${
        side === "left" ? "border-r border-vs-border" : ""
      }`}
    >
      <div className="flex-shrink-0 px-3 py-1 bg-vs-surface border-b border-vs-border text-vs-muted text-xs">
        {label}
      </div>
      <div className="flex-1 overflow-auto">
        {lines.map((line, idx) => (
          <div
            key={idx}
            className={`flex hover:brightness-125 ${LINE_BG[line.type]}`}
          >
            <span
              className={`select-none w-6 text-center flex-shrink-0 text-xs font-mono ${LINE_GUTTER[line.type]}`}
            >
              {LINE_MARKER[line.type]}
            </span>
            <span
              className={`select-none w-9 text-right pr-2 text-vs-dim flex-shrink-0 text-xs font-mono`}
            >
              {line.lineNum ?? ""}
            </span>
            <span className="flex-1 whitespace-pre text-vs-text text-xs font-mono">
              {line.text}
            </span>
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <div className="flex h-full font-mono text-code-base overflow-hidden">
      {renderPane(leftLines, leftLabel, "left")}
      {renderPane(rightLines, rightLabel, "right")}
    </div>
  );
};

export default DiffViewer;
