import React, { useEffect, useRef } from "react";

interface MenuItem {
  label: string;
  onClick: () => void;
  disabled?: boolean;
  separator?: boolean;
}

interface ContextMenuProps {
  x: number;
  y: number;
  onClose: () => void;
  items: MenuItem[];
}

const ContextMenu: React.FC<ContextMenuProps> = ({ x, y, onClose, items }) => {
  const menuRef = useRef<HTMLDivElement>(null);

  // Clamp to viewport
  const adjustedX = Math.min(x, window.innerWidth - 180);
  const adjustedY = Math.min(y, window.innerHeight - items.length * 32 - 8);

  useEffect(() => {
    const handleClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        onClose();
      }
    };
    const handleKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKey);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKey);
    };
  }, [onClose]);

  return (
    <div
      ref={menuRef}
      className="fixed z-50 bg-vs-elevated border border-vs-border shadow-xl rounded py-1 min-w-40"
      style={{ left: adjustedX, top: adjustedY }}
    >
      {items.map((item, idx) => {
        if (item.separator) {
          return (
            <div key={idx} className="my-1 border-t border-vs-border" />
          );
        }
        return (
          <button
            key={idx}
            className={[
              "w-full text-left px-3 py-1.5 text-xs",
              item.disabled
                ? "text-vs-dim cursor-not-allowed"
                : "text-vs-text hover:bg-vs-accent hover:text-white cursor-pointer",
            ].join(" ")}
            onClick={item.disabled ? undefined : item.onClick}
            disabled={item.disabled}
          >
            {item.label}
          </button>
        );
      })}
    </div>
  );
};

export default ContextMenu;
