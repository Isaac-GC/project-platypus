import React, { useState, useMemo } from "react";
import { useAppStore } from "../../store/appStore";
import type { TreeNode, XRef } from "../../api/types";
import CfgViewer from "../code/CfgViewer";
import ScriptPanel from "./ScriptPanel";

// ─── Tab button ───────────────────────────────────────────────────────────────

const TabButton: React.FC<{
  label: string;
  active: boolean;
  onClick: () => void;
}> = ({ label, active, onClick }) => (
  <button
    className={[
      "px-2.5 py-1.5 text-xs font-semibold border-b-2 transition-colors whitespace-nowrap",
      active
        ? "border-vs-accent text-vs-accent"
        : "border-transparent text-vs-muted hover:text-vs-text",
    ].join(" ")}
    onClick={onClick}
  >
    {label}
  </button>
);

// ─── INFO tab ─────────────────────────────────────────────────────────────────

const InfoTab: React.FC<{
  node: TreeNode | null;
  onRunClick: () => void;
  onFlowClick: () => void;
}> = ({ node, onRunClick, onFlowClick }) => {
  if (!node) {
    return (
      <div className="flex items-center justify-center h-full text-vs-dim text-xs italic">
        Select a method or class
      </div>
    );
  }

  const rows: Array<[string, string | number | undefined]> = [
    ["Name", node.name],
    ["Kind", node.kind],
    ["Full Name", node.fullName],
    ["Return Type", node.returnType],
    ["Params", node.params?.join(", ")],
    ["Access Flags", node.accessFlags?.join(", ")],
    ["Registers", node.registerCount],
    ["Instructions", node.instructionCount],
    ["Signature", node.signature],
    ["DEX File", node.dexName],
  ];

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Run button for methods */}
      {node.kind === "method" && (
        <div className="px-2 py-1.5 border-b border-vs-border flex-shrink-0 flex gap-1.5">
          <button
            className="flex-1 flex items-center justify-center gap-1.5 px-2 py-1 bg-vs-accent hover:bg-vs-accent/80 text-white text-xs font-semibold rounded transition-colors"
            onClick={onRunClick}
          >
            ▶ Run in VM
          </button>
          <button
            className="flex items-center justify-center gap-1 px-2 py-1 bg-vs-elevated hover:bg-vs-surface text-vs-text text-xs font-semibold rounded border border-vs-border transition-colors"
            onClick={onFlowClick}
            title="Open in Flow Graph"
          >
            🔀 Flow
          </button>
        </div>
      )}
      <div className="flex-1 overflow-y-auto">
        <table className="w-full text-xs font-mono">
          <tbody>
            {rows.map(([label, value]) => {
              if (value == null || value === "") return null;
              return (
                <tr key={label} className="border-b border-vs-border/40 hover:bg-vs-elevated/30">
                  <td className="px-2 py-1.5 text-vs-muted whitespace-nowrap align-top w-24">
                    {label}
                  </td>
                  <td className="px-2 py-1.5 text-vs-text break-all">{String(value)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

// ─── XREFS tab ────────────────────────────────────────────────────────────────

const XRefsTab: React.FC<{
  xrefs: XRef[];
  onNavigate: (className: string) => void;
  onLoadXrefs: (className: string, methodName: string) => void;
}> = ({ xrefs, onNavigate, onLoadXrefs }) => {
  const isLoading   = useAppStore((s) => s.isXrefsLoading);
  const xrefsTarget = useAppStore((s) => s.xrefsTarget);

  // Filter state is local to the tab — XRefs are short-lived (one
  // method at a time) so it'd be odd for the filter to persist across
  // method switches. Resets implicitly when the parent re-mounts the
  // tab for a different target.
  const [filter, setFilter] = useState("");

  // Format the header so empty results aren't ambiguous — the user always
  // sees what method we *tried* to find xrefs for.
  const targetHeader = xrefsTarget
    ? `${xrefsTarget.className.split("/").pop()}.${xrefsTarget.methodName}`
    : null;

  // Apply the filter: substring match against callerClass + callerMethod,
  // dot→slash normalisation so users can paste Java-style fq-names.
  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase().replace(/\./g, "/");
    if (!q) return xrefs;
    return xrefs.filter((x) =>
      x.callerClass.toLowerCase().includes(q) ||
      x.callerMethod.toLowerCase().includes(q)
    );
  }, [xrefs, filter]);

  // Group filtered xrefs by callerClass so the list has visible
  // structure when one class hosts many call sites. Within each
  // group we keep the original order (which is invoke-codepoint
  // order — i.e. lexically through the caller's body).
  const groupedByClass = useMemo(() => {
    const map = new Map<string, XRef[]>();
    for (const x of filtered) {
      const arr = map.get(x.callerClass) ?? [];
      arr.push(x);
      map.set(x.callerClass, arr);
    }
    return Array.from(map.entries());
  }, [filtered]);

  if (isLoading) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        {targetHeader && (
          <div className="text-xs text-vs-muted px-2 py-1 border-b border-vs-border flex-shrink-0 font-mono truncate">
            ↳ {targetHeader}
          </div>
        )}
        <div className="flex items-center justify-center h-full text-vs-dim text-xs">
          <span className="animate-spin mr-2">⟳</span> Searching call sites…
        </div>
      </div>
    );
  }

  if (xrefs.length === 0) {
    return (
      <div className="flex flex-col h-full overflow-hidden">
        {targetHeader && (
          <div className="text-xs text-vs-muted px-2 py-1 border-b border-vs-border flex-shrink-0 font-mono truncate">
            ↳ {targetHeader}
          </div>
        )}
        <div className="flex items-center justify-center flex-1 text-vs-dim text-xs italic">
          {targetHeader
            ? `No callers found for ${targetHeader}`
            : "No cross-references found"}
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header: target + summary count */}
      <div className="text-xs text-vs-muted px-2 py-1 border-b border-vs-border flex-shrink-0 flex items-baseline gap-2">
        {targetHeader && (
          <span className="font-mono truncate flex-1">↳ {targetHeader}</span>
        )}
        <span className="text-vs-dim flex-shrink-0">
          {filter
            ? `${filtered.length} / ${xrefs.length} caller${xrefs.length !== 1 ? "s" : ""}`
            : `${xrefs.length} caller${xrefs.length !== 1 ? "s" : ""}`}
        </span>
      </div>

      {/* Filter input — mirrors the DEOBFUSCATION-tab pattern so dots
          and slashes are interchangeable. */}
      <div className="flex items-center gap-1 px-2 py-1 border-b border-vs-border bg-vs-elevated/20 flex-shrink-0">
        <span className="text-[10px] text-vs-dim">🔍</span>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter callers (e.g. com.example.auth)"
          className="flex-1 bg-vs-bg border border-vs-border rounded px-2 py-0.5 text-[11px] font-mono text-vs-text placeholder:text-vs-dim focus:outline-none focus:border-vs-accent"
        />
        {filter && (
          <button
            className="px-1 py-0.5 text-[10px] text-vs-dim hover:text-vs-text"
            onClick={() => setFilter("")}
            title="Clear filter"
          >
            ✕
          </button>
        )}
      </div>

      {/* Grouped list — class header + indented call sites under it */}
      <div className="flex-1 overflow-y-auto">
        {groupedByClass.length === 0 ? (
          <div className="flex items-center justify-center h-full text-vs-dim text-xs italic">
            No callers match "{filter}"
          </div>
        ) : (
          groupedByClass.map(([callerClass, sites], gIdx) => (
            <div key={gIdx}>
              {/* Class header — clickable to navigate to the class. */}
              <div
                className="sticky top-0 z-[1] px-2 py-1 bg-vs-elevated/80 backdrop-blur-sm border-b border-vs-border flex items-center justify-between hover:bg-vs-elevated cursor-pointer group"
                onClick={() => onNavigate(callerClass)}
                title={callerClass}
              >
                <span className="text-xs font-mono font-semibold text-tree-class truncate group-hover:underline">
                  {callerClass.split("/").pop()}
                </span>
                <span className="text-[10px] text-vs-dim flex-shrink-0 ml-2">
                  {sites.length}×
                </span>
              </div>
              {/* Sites in this class — each row jumps to its line */}
              {sites.map((xref, idx) => (
                <div
                  key={idx}
                  className="px-3 py-1 border-b border-vs-border/20 hover:bg-vs-elevated/40 cursor-pointer"
                  onClick={() => onLoadXrefs(xref.callerClass, xref.callerMethod)}
                  title={`${xref.callerClass}->${xref.callerMethod} @${xref.offset}`}
                >
                  <div className="flex items-baseline gap-2">
                    <span className="text-xs text-tree-method font-mono truncate flex-1">
                      {xref.callerMethod}
                    </span>
                    <span className="text-[10px] text-vs-dim font-mono flex-shrink-0 tabular-nums">
                      @{xref.offset}
                    </span>
                  </div>
                  <div className="text-[10px] text-vs-muted font-mono mt-0.5 truncate pl-2">
                    {xref.instruction}
                  </div>
                </div>
              ))}
            </div>
          ))
        )}
      </div>
    </div>
  );
};

// The right-panel CALL_GRAPH tab and its CallGraphTab/CallGraphNodeRow
// components used to live here. They were removed: the same data is
// now visualised by the centre-panel FlowGraph (Binary-Ninja-style
// hierarchical call graph). The Flow view is launched from the INFO
// tab's Flow button or the code-view right-click menu's
// "Open call graph" entry. `callGraph` / `isCallGraphLoading` /
// `loadCallGraph` in the store remain because FlowGraph hits the
// same `get_call_graph` backend command on every node expansion.

// ─── RUN tab ──────────────────────────────────────────────────────────────────

const RunTab: React.FC = () => {
  const selectedNode = useAppStore((s) => s.selectedNode);
  const execSignature = useAppStore((s) => s.execSignature);
  const execArgs = useAppStore((s) => s.execArgs);
  const execResult = useAppStore((s) => s.execResult);
  const isRunning = useAppStore((s) => s.isRunning);
  const setExecArgs = useAppStore((s) => s.setExecArgs);
  const runMethod = useAppStore((s) => s.runMethod);

  const displaySig = selectedNode?.kind === "method"
    ? (selectedNode.fullName ?? execSignature)
    : execSignature;

  const params = selectedNode?.params ?? [];

  return (
    <div className="flex flex-col h-full overflow-y-auto px-2 py-2 gap-2">
      {/* Method signature (read-only display) */}
      <div>
        <div className="text-xs text-vs-muted mb-0.5 font-semibold">Method</div>
        <div className="bg-vs-bg border border-vs-border rounded px-2 py-1.5 text-xs font-mono text-vs-text break-all">
          {displaySig || <span className="text-vs-dim italic">No method selected</span>}
        </div>
      </div>

      {/* Args */}
      <div>
        <div className="text-xs text-vs-muted mb-0.5 font-semibold">
          Arguments {params.length > 0 && `(${params.join(", ")})`}
        </div>
        <input
          type="text"
          value={execArgs}
          onChange={(e) => setExecArgs(e.target.value)}
          placeholder={params.length ? params.map(() => "…").join(", ") : "comma-separated values"}
          className="w-full bg-vs-bg border border-vs-border rounded px-2 py-1.5 text-xs font-mono text-vs-text placeholder:text-vs-dim focus:outline-none focus:border-vs-accent"
        />
      </div>

      {/* Run button */}
      <button
        className="flex items-center justify-center gap-1.5 px-3 py-1.5 bg-vs-accent hover:bg-vs-accent/80 text-white text-xs font-semibold rounded transition-colors disabled:opacity-50"
        onClick={runMethod}
        disabled={isRunning || !displaySig.trim()}
      >
        {isRunning ? <><span className="animate-spin">⟳</span> Running…</> : <>▶ Run</>}
      </button>

      {/* Result */}
      {execResult && (
        <div className="bg-vs-bg border border-vs-border rounded p-2 text-xs font-mono">
          <div className="flex items-center gap-2">
            <span className="text-vs-muted">Return:</span>
            <span className={execResult.error ? "text-vs-error" : "text-vs-success"}>
              {execResult.error ? `ERROR: ${execResult.error}` : execResult.returnValue}
            </span>
          </div>
          <div className="text-vs-dim mt-0.5">
            type: {execResult.returnType} · {execResult.executionTimeMs}ms
          </div>
        </div>
      )}
    </div>
  );
};

// ─── CFG tab ──────────────────────────────────────────────────────────────────

const CfgTab: React.FC = () => {
  const cfgResult = useAppStore((s) => s.cfgResult);
  const isCfgLoading = useAppStore((s) => s.isCfgLoading);
  const selectedNode = useAppStore((s) => s.selectedNode);

  // Same ordering as CallGraphTab — load/data state wins over the
  // "select a method" hint so the centre-panel context menu can drive this
  // tab without the tree's `selectedNode` ever pointing at a method node.
  if (isCfgLoading) {
    return (
      <div className="flex items-center justify-center h-full text-vs-dim text-xs">
        <span className="animate-spin mr-2">⟳</span> Building CFG…
      </div>
    );
  }

  if (!cfgResult) {
    if (!selectedNode || selectedNode.kind !== "method") {
      return (
        <div className="flex items-center justify-center h-full text-vs-dim text-xs italic">
          Select a method to view its CFG
        </div>
      );
    }
    return (
      <div className="flex items-center justify-center h-full text-vs-dim text-xs italic">
        No CFG available (abstract or native method)
      </div>
    );
  }

  return <CfgViewer cfg={cfgResult} />;
};

// ─── RightPanel ───────────────────────────────────────────────────────────────

const RightPanel: React.FC = () => {
  const selectedNode = useAppStore((s) => s.selectedNode);
  const xrefs = useAppStore((s) => s.xrefs);
  const activeRightTab = useAppStore((s) => s.activeRightTab);
  const setActiveRightTab = useAppStore((s) => s.setActiveRightTab);
  const navigateToClass = useAppStore((s) => s.navigateToClass);
  const loadXrefsForMethod = useAppStore((s) => s.loadXrefsForMethod);
  const toggleFlowGraph = useAppStore((s) => s.toggleFlowGraph);

  const handleRunClick = () => {
    setActiveRightTab("RUN");
  };

  return (
    <div className="flex flex-col h-full bg-vs-surface border-l border-vs-border overflow-hidden">
      {/* Tab bar. CALL_GRAPH was removed — its functionality moved to
          the centre-panel Flow view (rendered by FlowGraph.tsx as a
          Binary-Ninja-style hierarchical call graph). The Flow view is
          launched from the INFO tab's Flow button or from the code-view
          right-click menu's "Open call graph" entry. */}
      <div className="flex items-center bg-vs-elevated border-b border-vs-border flex-shrink-0 px-1 overflow-x-auto">
        {(["INFO", "XREFS", "CFG", "RUN", "SCRIPT"] as const).map((tab) => (
          <TabButton
            key={tab}
            label={tab.replace("_", " ")}
            active={activeRightTab === tab}
            onClick={() => setActiveRightTab(tab)}
          />
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden">
        {activeRightTab === "INFO" && (
          <InfoTab node={selectedNode} onRunClick={handleRunClick} onFlowClick={toggleFlowGraph} />
        )}
        {activeRightTab === "XREFS" && (
          <XRefsTab xrefs={xrefs} onNavigate={navigateToClass} onLoadXrefs={loadXrefsForMethod} />
        )}
        {activeRightTab === "CFG" && <CfgTab />}
        {activeRightTab === "RUN" && <RunTab />}
        {activeRightTab === "SCRIPT" && <ScriptPanel />}
      </div>
    </div>
  );
};

export default RightPanel;
