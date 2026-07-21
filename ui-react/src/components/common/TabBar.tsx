import React, { useState, useRef, useEffect } from "react";
import type { CodeTab } from "../../api/types";
import ContextMenu from "./ContextMenu";

interface TabBarProps {
  tabs: CodeTab[];
  activeTabId: string | null;
  onSelectTab: (tabId: string) => void;
  onCloseTab: (tabId: string) => void;
  onCloseOthers: (tabId: string) => void;
  onCloseAll: () => void;
}

interface ContextMenuState {
  tabId: string;
  x: number;
  y: number;
}

const TabBar: React.FC<TabBarProps> = ({
  tabs,
  activeTabId,
  onSelectTab,
  onCloseTab,
  onCloseOthers,
  onCloseAll,
}) => {
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);

  const handleContextMenu = (
    e: React.MouseEvent,
    tabId: string
  ) => {
    e.preventDefault();
    setContextMenu({ tabId, x: e.clientX, y: e.clientY });
  };

  const closeContextMenu = () => setContextMenu(null);

  const languageIcon = (tab: CodeTab) => {
    if (tab.language === "xml") return "📄";
    if (tab.language === "java") return "☕";
    return "🔮";
  };

  return (
    <>
      <div className="flex flex-row overflow-x-auto bg-vs-surface border-b border-vs-border flex-shrink-0 scrollbar-thin">
        {tabs.map((tab) => {
          const isActive = tab.id === activeTabId;
          return (
            <div
              key={tab.id}
              className={[
                "flex items-center gap-1 px-3 py-1.5 cursor-pointer border-r border-vs-border flex-shrink-0 group select-none min-w-0",
                "text-xs font-mono",
                isActive
                  ? "bg-vs-bg text-vs-text border-t-2 border-t-vs-accent"
                  : "bg-vs-surface text-vs-muted hover:bg-vs-elevated hover:text-vs-text",
              ].join(" ")}
              onClick={() => onSelectTab(tab.id)}
              onContextMenu={(e) => handleContextMenu(e, tab.id)}
              title={tab.className}
            >
              <span className="text-xs opacity-70">{languageIcon(tab)}</span>
              <span className="truncate max-w-32">{tab.title}</span>
              {tab.isDirty && (
                <span className="text-vs-warn text-xs ml-0.5">●</span>
              )}
              <button
                className={[
                  "ml-1 w-4 h-4 flex items-center justify-center rounded text-vs-muted hover:text-vs-text hover:bg-vs-elevated",
                  isActive
                    ? "opacity-100"
                    : "opacity-0 group-hover:opacity-100",
                ].join(" ")}
                onClick={(e) => {
                  e.stopPropagation();
                  onCloseTab(tab.id);
                }}
                title="Close"
              >
                ×
              </button>
            </div>
          );
        })}
        {tabs.length === 0 && (
          <div className="px-3 py-1.5 text-xs text-vs-dim italic">
            No files open
          </div>
        )}
      </div>

      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          onClose={closeContextMenu}
          items={[
            {
              label: "Close",
              onClick: () => {
                onCloseTab(contextMenu.tabId);
                closeContextMenu();
              },
            },
            {
              label: "Close Others",
              onClick: () => {
                onCloseOthers(contextMenu.tabId);
                closeContextMenu();
              },
            },
            {
              label: "Close All",
              onClick: () => {
                onCloseAll();
                closeContextMenu();
              },
            },
          ]}
        />
      )}
    </>
  );
};

export default TabBar;
