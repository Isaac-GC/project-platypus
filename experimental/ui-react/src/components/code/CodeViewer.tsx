import React, { useMemo, useRef, useEffect, useCallback } from "react";
import { tokenizeCode, type ClassIndex, type ImportMap } from "./tokenizer";
import type { TokenType, TokenizedLine } from "./tokenizer";
import type { Language, DeobfReplacement } from "../../api/types";
import { useAppStore } from "../../store/appStore";

// ─── Token color map ─────────────────────────────────────────────────────────

const TOKEN_CLASS: Record<TokenType, string> = {
  keyword: "text-syn-keyword",
  directive: "text-syn-directive",
  opcode: "text-syn-opcode",
  string: "text-syn-string",
  comment: "text-syn-comment italic",
  type: "text-syn-type",
  number: "text-syn-number",
  register: "text-syn-register",
  label: "text-syn-label",
  annotation: "text-syn-opcode",
  xref: "cursor-pointer hover:underline",
  plain: "text-vs-text",
};

// ─── Props ───────────────────────────────────────────────────────────────────

interface DeobfInfo {
  original: string;
  resolved: string;
}

interface CodeViewerProps {
  code: string;
  language: Language;
  onXrefClick?: (target: string) => void;
  deobfReplacements?: Map<number, DeobfInfo>;
  selectedLine?: number;
  onLineClick?: (lineIndex: number) => void;
  onLineRightClick?: (lineIndex: number, x: number, y: number) => void;
  /** Normalised current class path (`com/foo/Bar` — no `L`/`;` wrapper).
   *  Used by the Java tokenizer to promote `this.method(` patterns into
   *  clickable xrefs targeting this class. Pass `undefined` when not
   *  rendering a specific class (e.g. snippet views). */
  currentClass?: string;
  /** Lookup table for resolving `varName.method(...)` calls back to a
   *  project class. Built once by the centre panel from the loaded tree
   *  and threaded through. See [`buildClassIndex`]. */
  classIndex?: ClassIndex;
  /** Per-doc import map. Authoritative for variable-receiver xref
   *  resolution in the current file — disambiguates simple-name
   *  collisions across the project. Built per-tab via
   *  [`buildImportMap`]. */
  importMap?: ImportMap;
  /** Set of all known fully-qualified class paths (slash form). Lets the
   *  Java tokenizer resolve all-lowercase fully-qualified method calls
   *  (`hivhi.wfg.bihvbhi(...)`) the decompiler emits for ambiguous class
   *  names. */
  classPaths?: Set<string>;
}

// ─── Component ───────────────────────────────────────────────────────────────

const CodeViewer: React.FC<CodeViewerProps> = ({
  code,
  language,
  onXrefClick,
  deobfReplacements,
  selectedLine,
  onLineClick,
  onLineRightClick,
  currentClass,
  classIndex,
  importMap,
  classPaths,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const settings = useAppStore((s) => s.settings);

  const tokenizedLines = useMemo(
    () => tokenizeCode(code, language, currentClass, classIndex, importMap, classPaths),
    [code, language, currentClass, classIndex, importMap, classPaths]
  );

  // Scroll selected line into view
  useEffect(() => {
    if (selectedLine == null) return;
    const el = containerRef.current?.querySelector(
      `[data-line="${selectedLine}"]`
    );
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [selectedLine]);

  const renderLine = useCallback(
    (tokens: TokenizedLine, lineIdx: number) => {
      const deobf = deobfReplacements?.get(lineIdx);
      const isSelected = selectedLine === lineIdx;

      const lineContent = (
        <span className="flex-1">
          {tokens.map((tok, tokIdx) => {
            if (tok.type === "xref" && onXrefClick) {
              return (
                <span
                  key={tokIdx}
                  className={`preserve-whitespace ${TOKEN_CLASS.xref}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    onXrefClick(tok.target ?? tok.text);
                  }}
                >
                  {tok.text}
                </span>
              );
            }
            return (
              <span key={tokIdx} className={TOKEN_CLASS[tok.type]}>
                {tok.text}
              </span>
            );
          })}
        </span>
      );

      return (
        <React.Fragment key={lineIdx}>
          {deobf && (
            <div className="flex hover:bg-vs-elevated/30">
              {/* Line gutter (ghost for the comment line) */}
              {settings.showLineNumbers && (
                <span
                  className="select-none text-right text-vs-dim pr-3 pl-2 w-12 flex-shrink-0"
                  style={{ minWidth: "3rem" }}
                >
                  {""}
                </span>
              )}
              {/* Original line as comment */}
              <span className="text-syn-comment italic flex-1">
                {"// " + deobf.original}
              </span>
            </div>
          )}
          <div
            data-line={lineIdx}
            className={[
              "preserve-whitespace flex group cursor-pointer",
              isSelected ? "bg-vs-selection/60" : "hover:bg-vs-elevated/40",
              deobf ? "border-l-2 border-vs-success" : "",
            ]
              .filter(Boolean)
              .join(" ")}
            onClick={() => onLineClick?.(lineIdx)}
            onContextMenu={(e) => {
              if (onLineRightClick) {
                e.preventDefault();
                onLineRightClick(lineIdx, e.clientX, e.clientY);
              }
            }}
          >
            {/* Gutter — only rendered when showLineNumbers is true */}
            {settings.showLineNumbers && (
              <span
                className={[
                  "select-none text-right pr-3 pl-2 flex-shrink-0",
                  isSelected ? "text-vs-muted" : "text-vs-dim",
                ].join(" ")}
                style={{ minWidth: "3rem", width: "3rem" }}
              >
                {lineIdx + 1}
              </span>
            )}
            {/* Code content */}
            {lineContent}
          </div>
        </React.Fragment>
      );
    },
    [tokenizedLines, deobfReplacements, selectedLine, onXrefClick, onLineClick, onLineRightClick]
  );

  if (!code) {
    return (
      <div className="flex items-center justify-center h-full text-vs-muted font-mono text-sm">
        No content
      </div>
    );
  }

  return (
    <div
      ref={containerRef}
      className="h-full overflow-auto bg-vs-bg leading-relaxed"
      style={{
        fontFamily: "var(--code-font-family, ui-monospace, SFMono-Regular, Menlo, monospace)",
        fontSize: "var(--code-font-size, 13px)",
      }}
    >
      <div className="min-w-max pb-4">
        {tokenizedLines.map((line, idx) => renderLine(line, idx))}
      </div>
    </div>
  );
};

export default CodeViewer;
