import React, { useMemo } from "react";
import type { MethodCfgResult, CfgBlock } from "../../api/types";

// ─── Layout constants ─────────────────────────────────────────────────────────

const BLOCK_W = 220;
const INSTR_H = 13;
const BLOCK_HEADER_H = 22;
const BLOCK_VPAD = 6;
const H_GAP = 32;
const V_GAP = 56;
const FONT_SIZE = 11;
const SVG_PAD = 30;

// ─── Types ────────────────────────────────────────────────────────────────────

interface BlockRect {
  id: number;
  x: number;
  y: number;
  w: number;
  h: number;
  blockType: string;
  instructions: string[];
  isEntry: boolean;
}

// ─── Colors ───────────────────────────────────────────────────────────────────

function blockColors(type: string, isEntry: boolean): { bg: string; header: string; border: string } {
  if (isEntry) return { bg: "#192030", header: "#1e2a3f", border: "#5b8af0" };
  switch (type) {
    case "return":
      return { bg: "#192419", header: "#1e2e1e", border: "#4db86e" };
    case "throw":
      return { bg: "#28191a", header: "#341e1e", border: "#e05c5c" };
    case "exception_handler":
      return { bg: "#2a2018", header: "#352818", border: "#e09b40" };
    default:
      return { bg: "#1e1e2a", header: "#252534", border: "#44445a" };
  }
}

function edgeColor(kind: string): string {
  if (kind === "unconditional") return "#7898c8";
  if (kind.includes("true")) return "#5ab877";
  if (kind.includes("false")) return "#c05050";
  if (kind.includes("exception")) return "#d4943a";
  return "#7a7a9a";
}

// ─── Layout algorithm ─────────────────────────────────────────────────────────

function blockH(b: CfgBlock): number {
  return BLOCK_HEADER_H + Math.max(b.instructions.length, 1) * INSTR_H + BLOCK_VPAD * 2;
}

function layoutBlocks(result: MethodCfgResult): {
  rects: BlockRect[];
  svgW: number;
  svgH: number;
} {
  const { blocks, edges, entryId } = result;
  if (blocks.length === 0) return { rects: [], svgW: 0, svgH: 0 };

  // Build successors
  const succs = new Map<number, number[]>();
  for (const b of blocks) succs.set(b.id, []);
  for (const e of edges) {
    const s = succs.get(e.sourceId);
    if (s) s.push(e.targetId);
  }

  // BFS levels from entry
  const level = new Map<number, number>();
  const queue: number[] = [entryId];
  level.set(entryId, 0);
  while (queue.length > 0) {
    const id = queue.shift()!;
    const lvl = level.get(id)!;
    for (const s of (succs.get(id) ?? [])) {
      if (!level.has(s)) {
        level.set(s, lvl + 1);
        queue.push(s);
      }
    }
  }
  // Unreachable blocks go after the last level
  const maxLvl = Math.max(...Array.from(level.values()), 0);
  for (const b of blocks) {
    if (!level.has(b.id)) level.set(b.id, maxLvl + 1);
  }

  // Group by level, sorted by id
  const byLevel = new Map<number, CfgBlock[]>();
  for (const b of blocks) {
    const l = level.get(b.id)!;
    if (!byLevel.has(l)) byLevel.set(l, []);
    byLevel.get(l)!.push(b);
  }
  for (const arr of byLevel.values()) arr.sort((a, b) => a.id - b.id);

  const allLevels = [...byLevel.keys()].sort((a, b) => a - b);

  // Compute max level width for centering
  let maxLevelW = 0;
  for (const l of allLevels) {
    const arr = byLevel.get(l)!;
    const w = arr.length * BLOCK_W + (arr.length - 1) * H_GAP;
    if (w > maxLevelW) maxLevelW = w;
  }
  const svgW = maxLevelW + SVG_PAD * 2;

  // Place blocks
  const rects: BlockRect[] = [];
  let y = SVG_PAD;
  for (const l of allLevels) {
    const arr = byLevel.get(l)!;
    const levelW = arr.length * BLOCK_W + (arr.length - 1) * H_GAP;
    const startX = (svgW - levelW) / 2;
    const levelMaxH = Math.max(...arr.map(blockH));
    for (let i = 0; i < arr.length; i++) {
      const b = arr[i];
      rects.push({
        id: b.id,
        x: startX + i * (BLOCK_W + H_GAP),
        y,
        w: BLOCK_W,
        h: blockH(b),
        blockType: b.blockType,
        instructions: b.instructions,
        isEntry: b.isEntry,
      });
    }
    y += levelMaxH + V_GAP;
  }

  return { rects, svgW, svgH: y + SVG_PAD };
}

// ─── Edge path ────────────────────────────────────────────────────────────────

function edgePath(src: BlockRect, tgt: BlockRect): string {
  const x1 = src.x + src.w / 2;
  const y1 = src.y + src.h;
  const x2 = tgt.x + tgt.w / 2;
  const y2 = tgt.y;

  // Back edge (loop): route around the side
  if (y2 <= y1) {
    const rightEdge = Math.max(src.x + src.w, tgt.x + tgt.w) + 24;
    return `M ${x1} ${y1} C ${x1} ${y1 + 20} ${rightEdge} ${y1 + 20} ${rightEdge} ${(y1 + y2) / 2} C ${rightEdge} ${y2 - 20} ${x2} ${y2 - 20} ${x2} ${y2}`;
  }

  const dy = y2 - y1;
  const cp = Math.min(dy * 0.5, 40);
  return `M ${x1} ${y1} C ${x1} ${y1 + cp} ${x2} ${y2 - cp} ${x2} ${y2}`;
}

// ─── CfgViewer ────────────────────────────────────────────────────────────────

const CfgViewer: React.FC<{ cfg: MethodCfgResult }> = ({ cfg }) => {
  const { rects, svgW, svgH } = useMemo(() => layoutBlocks(cfg), [cfg]);

  const rectMap = useMemo(() => {
    const m = new Map<number, BlockRect>();
    for (const r of rects) m.set(r.id, r);
    return m;
  }, [rects]);

  if (rects.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-vs-dim text-xs italic">
        No blocks to display
      </div>
    );
  }

  // Arrow marker per color would require defs — use inline triangles instead
  return (
    <div className="w-full h-full overflow-auto bg-[#13131f]">
      <svg
        width={svgW}
        height={svgH}
        style={{ display: "block", minWidth: "100%", fontFamily: "monospace" }}
      >
        {/* Edges */}
        {cfg.edges.map((e, idx) => {
          const src = rectMap.get(e.sourceId);
          const tgt = rectMap.get(e.targetId);
          if (!src || !tgt) return null;
          const color = edgeColor(e.kind);
          const d = edgePath(src, tgt);
          // Arrowhead at end
          const x2 = tgt.x + tgt.w / 2;
          const y2 = tgt.y;
          return (
            <g key={idx}>
              <path d={d} fill="none" stroke={color} strokeWidth="1.5" opacity="0.85" />
              <polygon
                points={`${x2},${y2} ${x2 - 4},${y2 - 8} ${x2 + 4},${y2 - 8}`}
                fill={color}
                opacity="0.85"
              />
            </g>
          );
        })}

        {/* Blocks */}
        {rects.map((rect) => {
          const { bg, header, border } = blockColors(rect.blockType, rect.isEntry);
          const maxChars = Math.floor((rect.w - 14) / (FONT_SIZE * 0.6));
          return (
            <g key={rect.id}>
              {/* Body */}
              <rect
                x={rect.x}
                y={rect.y}
                width={rect.w}
                height={rect.h}
                rx={4}
                fill={bg}
                stroke={border}
                strokeWidth={rect.isEntry ? 2 : 1}
              />
              {/* Header background */}
              <rect
                x={rect.x + 1}
                y={rect.y + 1}
                width={rect.w - 2}
                height={BLOCK_HEADER_H - 1}
                rx={3}
                fill={header}
              />
              {/* Header label */}
              <text
                x={rect.x + rect.w / 2}
                y={rect.y + 14}
                textAnchor="middle"
                fontSize={10}
                fill="#8899bb"
              >
                {`[${rect.id}] ${rect.blockType}`}
              </text>
              {/* Instructions */}
              {rect.instructions.map((instr, i) => {
                const text =
                  instr.length > maxChars ? instr.slice(0, maxChars - 1) + "\u2026" : instr;
                return (
                  <text
                    key={i}
                    x={rect.x + 7}
                    y={rect.y + BLOCK_HEADER_H + BLOCK_VPAD + i * INSTR_H + 10}
                    fontSize={FONT_SIZE}
                    fill="#aab2c8"
                  >
                    {text}
                  </text>
                );
              })}
              {rect.instructions.length === 0 && (
                <text
                  x={rect.x + rect.w / 2}
                  y={rect.y + BLOCK_HEADER_H + BLOCK_VPAD + 10}
                  textAnchor="middle"
                  fontSize={FONT_SIZE}
                  fill="#555570"
                  fontStyle="italic"
                >
                  (empty)
                </text>
              )}
            </g>
          );
        })}
      </svg>
    </div>
  );
};

export default CfgViewer;
