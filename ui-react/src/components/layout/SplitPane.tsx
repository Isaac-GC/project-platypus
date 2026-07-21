import React, { useState, useCallback, useRef } from "react";
import ResizeHandle from "../common/ResizeHandle";

// ─── Horizontal split (left | center | right) ────────────────────────────────

interface HorizontalSplitProps {
  left: React.ReactNode;
  center: React.ReactNode;
  right: React.ReactNode;
  initialLeftPct?: number;
  initialRightPct?: number;
  minLeftPx?: number;
  minRightPx?: number;
  minCenterPx?: number;
}

export const HorizontalSplit: React.FC<HorizontalSplitProps> = ({
  left,
  center,
  right,
  initialLeftPct = 22,
  initialRightPct = 22,
  minLeftPx = 120,
  minRightPx = 120,
  minCenterPx = 200,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [leftPct, setLeftPct] = useState(initialLeftPct);
  const [rightPct, setRightPct] = useState(initialRightPct);

  const handleLeftResize = useCallback(
    (delta: number) => {
      const containerWidth = containerRef.current?.offsetWidth ?? window.innerWidth;
      const deltaPct = (delta / containerWidth) * 100;
      setLeftPct((prev) => {
        const next = prev + deltaPct;
        const minPct = (minLeftPx / containerWidth) * 100;
        const maxPct = 100 - rightPct - (minCenterPx / containerWidth) * 100;
        return Math.max(minPct, Math.min(maxPct, next));
      });
    },
    [rightPct, minLeftPx, minCenterPx]
  );

  const handleRightResize = useCallback(
    (delta: number) => {
      const containerWidth = containerRef.current?.offsetWidth ?? window.innerWidth;
      const deltaPct = (delta / containerWidth) * 100;
      setRightPct((prev) => {
        const next = prev - deltaPct;
        const minPct = (minRightPx / containerWidth) * 100;
        const maxPct = 100 - leftPct - (minCenterPx / containerWidth) * 100;
        return Math.max(minPct, Math.min(maxPct, next));
      });
    },
    [leftPct, minRightPx, minCenterPx]
  );

  const centerPct = 100 - leftPct - rightPct;

  return (
    <div ref={containerRef} className="flex flex-row h-full overflow-hidden">
      {/* Left panel */}
      <div
        className="flex flex-col overflow-hidden"
        style={{ width: `${leftPct}%`, flexShrink: 0 }}
      >
        {left}
      </div>

      <ResizeHandle direction="horizontal" onResize={handleLeftResize} />

      {/* Center panel */}
      <div
        className="flex flex-col overflow-hidden flex-1"
        style={{ width: `${centerPct}%` }}
      >
        {center}
      </div>

      <ResizeHandle direction="horizontal" onResize={handleRightResize} />

      {/* Right panel */}
      <div
        className="flex flex-col overflow-hidden"
        style={{ width: `${rightPct}%`, flexShrink: 0 }}
      >
        {right}
      </div>
    </div>
  );
};

// ─── Vertical split (top | bottom) ───────────────────────────────────────────

interface VerticalSplitProps {
  top: React.ReactNode;
  bottom: React.ReactNode;
  initialTopPct?: number;
  minTopPx?: number;
  minBottomPx?: number;
}

export const VerticalSplit: React.FC<VerticalSplitProps> = ({
  top,
  bottom,
  initialTopPct = 72,
  minTopPx = 100,
  minBottomPx = 80,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [topPct, setTopPct] = useState(initialTopPct);

  const handleResize = useCallback(
    (delta: number) => {
      const containerHeight = containerRef.current?.offsetHeight ?? window.innerHeight;
      const deltaPct = (delta / containerHeight) * 100;
      setTopPct((prev) => {
        const next = prev + deltaPct;
        const minTopPct = (minTopPx / containerHeight) * 100;
        const maxTopPct = 100 - (minBottomPx / containerHeight) * 100;
        return Math.max(minTopPct, Math.min(maxTopPct, next));
      });
    },
    [minTopPx, minBottomPx]
  );

  return (
    <div ref={containerRef} className="flex flex-col h-full overflow-hidden">
      {/* Top */}
      <div
        className="overflow-hidden"
        style={{ height: `${topPct}%`, flexShrink: 0 }}
      >
        {top}
      </div>

      <ResizeHandle direction="vertical" onResize={handleResize} />

      {/* Bottom */}
      <div className="flex-1 overflow-hidden">{bottom}</div>
    </div>
  );
};
