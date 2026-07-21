import React, { useCallback, useRef } from "react";

interface ResizeHandleProps {
  direction: "horizontal" | "vertical";
  onResize: (delta: number) => void;
  className?: string;
}

const ResizeHandle: React.FC<ResizeHandleProps> = ({
  direction,
  onResize,
  className,
}) => {
  const isDragging = useRef(false);
  const lastPos = useRef(0);

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      isDragging.current = true;
      lastPos.current = direction === "horizontal" ? e.clientX : e.clientY;

      const handleMouseMove = (ev: MouseEvent) => {
        if (!isDragging.current) return;
        const pos = direction === "horizontal" ? ev.clientX : ev.clientY;
        const delta = pos - lastPos.current;
        lastPos.current = pos;
        onResize(delta);
      };

      const handleMouseUp = () => {
        isDragging.current = false;
        document.removeEventListener("mousemove", handleMouseMove);
        document.removeEventListener("mouseup", handleMouseUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      };

      document.body.style.cursor =
        direction === "horizontal" ? "col-resize" : "row-resize";
      document.body.style.userSelect = "none";
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
    },
    [direction, onResize]
  );

  return (
    <div
      className={[
        "flex-shrink-0 bg-vs-border hover:bg-vs-accent transition-colors duration-150",
        direction === "horizontal"
          ? "w-1 cursor-col-resize"
          : "h-1 cursor-row-resize",
        className ?? "",
      ].join(" ")}
      onMouseDown={handleMouseDown}
    />
  );
};

export default ResizeHandle;
