import React, { useEffect, useState, useCallback, useMemo } from "react";
import { listen } from "@tauri-apps/api/event";
import { api, isTauri } from "./api/adapter";
import type {
  TaintAnalysisResult,
  TaintSink,
  TaintSource,
  TaintedField,
  RegisterTaintEntry,
  TaintGraph,
  TaintNode,
  TaintOverride,
  OverrideMap,
} from "./api/types";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function parseHash(): { className: string; methodName: string } {
  const search = window.location.hash.split("?")[1] ?? "";
  const p = new URLSearchParams(search);
  return {
    className: decodeURIComponent(p.get("class") ?? ""),
    methodName: decodeURIComponent(p.get("method") ?? ""),
  };
}

const SINK_COLOR: Record<string, string> = {
  logging:      "bg-sky-900/60 text-sky-300",
  network:      "bg-blue-900/60 text-blue-300",
  SMS:          "bg-purple-900/60 text-purple-300",
  storage:      "bg-amber-900/60 text-amber-300",
  database:     "bg-orange-900/60 text-orange-300",
  file_write:   "bg-yellow-900/60 text-yellow-200",
  crypto:       "bg-green-900/60 text-green-300",
  reflection:   "bg-pink-900/60 text-pink-300",
  command_exec: "bg-red-900/60 text-red-300",
  webview:      "bg-indigo-900/60 text-indigo-300",
  ipc:          "bg-teal-900/60 text-teal-300",
};

function SinkBadge({ category }: { category: string }) {
  const cls = SINK_COLOR[category] ?? "bg-vs-elevated text-vs-muted";
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide shrink-0 ${cls}`}>
      {category.replace("_", " ")}
    </span>
  );
}

function SourceBadge({ kind }: { kind: string }) {
  const cls =
    kind === "param"
      ? "bg-vs-elevated text-vs-accent"
      : kind === "api_return"
      ? "bg-vs-elevated text-vs-success"
      : "bg-vs-elevated text-vs-warn";
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold shrink-0 ${cls}`}>
      {kind === "param" ? "param" : kind === "api_return" ? "api" : "field"}
    </span>
  );
}

function Section({
  title,
  count,
  danger,
  children,
}: {
  title: string;
  count?: number;
  danger?: boolean;
  children: React.ReactNode;
}) {
  return (
    <section className="mb-6">
      <h2 className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-vs-muted mb-2 pb-1 border-b border-vs-border">
        {title}
        {count != null && (
          <span
            className={`px-1.5 py-0.5 rounded-full text-[10px] font-bold ${
              danger && count > 0 ? "bg-vs-error/20 text-vs-error" : "bg-vs-elevated text-vs-muted"
            }`}
          >
            {count}
          </span>
        )}
      </h2>
      {children}
    </section>
  );
}

// ─── Sub-panels (unchanged from previous version) ─────────────────────────────

function SourcesPanel({ sources }: { sources: TaintSource[] }) {
  if (sources.length === 0) {
    return <p className="text-vs-dim text-xs italic">No taint sources found.</p>;
  }
  return (
    <div className="space-y-1">
      {sources.map((src, i) => (
        <div key={i} className="flex items-start gap-2 py-1 px-2 rounded hover:bg-vs-elevated/40">
          <SourceBadge kind={src.kind} />
          <div className="min-w-0 flex-1">
            <span className="text-vs-text font-mono text-xs">{src.label}</span>
            {src.instruction && (
              <div className="text-vs-dim text-[10px] font-mono mt-0.5 truncate">
                {src.instruction}
              </div>
            )}
          </div>
          {src.register < 0xffff_ffff && (
            <span className="text-vs-dim text-[10px] font-mono shrink-0">
              r{src.register}
            </span>
          )}
        </div>
      ))}
    </div>
  );
}

function SinksPanel({ sinks }: { sinks: TaintSink[] }) {
  if (sinks.length === 0) {
    return (
      <p className="text-vs-dim text-xs italic">
        No dangerous sinks reached by tainted data.
      </p>
    );
  }
  return (
    <div className="space-y-2">
      {sinks.map((sink, i) => (
        <div
          key={i}
          className="border border-vs-border rounded p-2 hover:border-vs-accent/40 transition-colors"
        >
          <div className="flex items-start gap-2 mb-1">
            <SinkBadge category={sink.category} />
            <span className="text-vs-text font-mono text-xs truncate flex-1">
              {sink.methodRef.split("->")[1] ?? sink.methodRef}
            </span>
            <span className="text-vs-dim text-[10px] font-mono shrink-0">
              @{sink.codepoint}
            </span>
          </div>
          {sink.taintedArgIndices.length > 0 && (
            <div className="text-[10px] text-vs-dim mt-1">
              <span className="text-vs-warn">Tainted args:</span>{" "}
              {sink.taintedArgIndices.map((a) => `arg[${a}]`).join(", ")}
            </div>
          )}
          <div className="flex flex-wrap gap-1 mt-1">
            {sink.sourcesReached.map((lbl, j) => (
              <span
                key={j}
                className="px-1 py-0.5 bg-vs-elevated rounded text-[9px] text-vs-accent font-mono"
              >
                {lbl}
              </span>
            ))}
          </div>
          <div className="mt-1 text-[10px] font-mono text-vs-dim truncate">
            {sink.instruction}
          </div>
        </div>
      ))}
    </div>
  );
}

function FieldsPanel({ fields }: { fields: TaintedField[] }) {
  if (fields.length === 0) {
    return <p className="text-vs-dim text-xs italic">No tainted field writes.</p>;
  }
  return (
    <div className="space-y-1">
      {fields.map((f, i) => (
        <div key={i} className="py-1 px-2 rounded hover:bg-vs-elevated/40">
          <div className="flex items-center gap-2">
            <span className="text-vs-warn text-[10px] font-mono truncate flex-1">
              {f.fieldRef}
            </span>
            <span className="text-vs-dim text-[10px] font-mono shrink-0">@{f.codepoint}</span>
          </div>
          <div className="flex flex-wrap gap-1 mt-0.5">
            {f.sourcesReaching.map((lbl, j) => (
              <span
                key={j}
                className="px-1 py-0.5 bg-vs-elevated rounded text-[9px] text-vs-accent font-mono"
              >
                {lbl}
              </span>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function RegisterPanel({ registers }: { registers: RegisterTaintEntry[] }) {
  const [open, setOpen] = useState(false);
  if (registers.length === 0) return null;
  return (
    <section className="mb-4">
      <button
        className="flex items-center gap-2 text-xs font-semibold uppercase tracking-widest text-vs-dim mb-1 hover:text-vs-text"
        onClick={() => setOpen((o) => !o)}
      >
        <span>{open ? "▾" : "▸"}</span>
        Register Taint at Exit ({registers.length})
      </button>
      {open && (
        <div className="grid grid-cols-2 gap-1 pl-4">
          {registers.map((r) => (
            <div
              key={r.register}
              className="flex items-center gap-2 py-0.5 text-xs font-mono"
            >
              <span className="text-vs-accent w-8 shrink-0">{r.name}</span>
              <span className="text-vs-dim truncate">{r.sources.join(", ")}</span>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

// ─── Graph helpers ────────────────────────────────────────────────────────────

function shortenClass(cn: string): string {
  if (!cn) return "";
  const trimmed = cn.replace(/^L/, "").replace(/;$/, "");
  return trimmed.split("/").pop() ?? trimmed;
}

function shortenMethodRef(ref: string): string {
  // Format like "Lcom/foo/Bar;->method(...)X"
  const arrow = ref.indexOf("->");
  if (arrow === -1) return ref;
  const cls = shortenClass(ref.slice(0, arrow));
  const tail = ref.slice(arrow + 2);
  const paren = tail.indexOf("(");
  const name = paren === -1 ? tail : tail.slice(0, paren);
  return `${cls}.${name}`;
}

function describeOverride(o: TaintOverride): string {
  switch (o.kind) {
    case "ReturnTainted":
      return `Return tainted: [${o.sources.join(", ")}]`;
    case "ReturnClean":
      return "Return clean";
    case "ParamTainted":
      return `Param[${o.index}] tainted: [${o.sources.join(", ")}]`;
    case "ParamClean":
      return `Param[${o.index}] clean`;
    case "ConstantValue":
      return `Constant = ${o.value} (${o.typeName})`;
  }
}

// ─── Graph view (left column) ─────────────────────────────────────────────────

interface NodeCardProps {
  node: TaintNode;
  selected: boolean;
  busy: boolean;
  onSelect: () => void;
  onExpandForward: () => void;
  onExpandBackward: () => void;
  expandError?: string | null;
}

function NodeCard({
  node,
  selected,
  busy,
  onSelect,
  onExpandForward,
  onExpandBackward,
  expandError,
}: NodeCardProps) {
  const a = node.analysis;
  const sCount = a?.sources.length ?? 0;
  const kCount = a?.sinks.length ?? 0;
  const fCount = a?.taintedFields.length ?? 0;

  const depthLabel =
    node.depth === 0 ? "root" : node.depth > 0 ? `+${node.depth}` : `${node.depth}`;

  const indent = Math.abs(node.depth) * 12;
  const faded = node.bodyUnavailable ? "opacity-60" : "";
  const selBorder = selected
    ? "border-l-4 border-l-vs-accent bg-vs-elevated"
    : "border-l-4 border-l-transparent hover:bg-vs-elevated/40";

  return (
    <div
      className={`mb-1 cursor-pointer rounded border border-vs-border ${selBorder} ${faded}`}
      style={{ marginLeft: indent }}
      onClick={onSelect}
    >
      <div className="px-2 py-1.5">
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-vs-text font-bold text-xs truncate flex-1">
            {node.methodName}
          </span>
          <span
            className={`text-[10px] font-mono shrink-0 ${
              node.depth === 0
                ? "text-vs-accent"
                : node.depth > 0
                ? "text-vs-success"
                : "text-vs-warn"
            }`}
          >
            {depthLabel}
          </span>
        </div>
        <div className="flex items-center gap-1 mt-0.5">
          <span className="text-vs-dim text-[10px] font-mono truncate flex-1">
            {shortenClass(node.className)}
          </span>
          {node.bodyUnavailable && (
            <span className="text-[9px] text-vs-dim italic shrink-0">(external)</span>
          )}
        </div>
        {(sCount > 0 || kCount > 0 || fCount > 0) && (
          <div className="flex gap-1 mt-1">
            {sCount > 0 && (
              <span className="px-1 py-0.5 bg-vs-elevated rounded text-[9px] text-vs-accent font-mono">
                S:{sCount}
              </span>
            )}
            {kCount > 0 && (
              <span className="px-1 py-0.5 bg-vs-error/20 rounded text-[9px] text-vs-error font-mono">
                K:{kCount}
              </span>
            )}
            {fCount > 0 && (
              <span className="px-1 py-0.5 bg-vs-warn/20 rounded text-[9px] text-vs-warn font-mono">
                F:{fCount}
              </span>
            )}
          </div>
        )}
        <div className="flex gap-1 mt-1.5">
          <button
            className="px-1.5 py-0.5 text-[10px] rounded border border-vs-border bg-vs-surface text-vs-muted hover:text-vs-text hover:border-vs-accent disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:border-vs-border disabled:hover:text-vs-muted"
            disabled={node.expandedBackward || node.bodyUnavailable || busy}
            onClick={(e) => {
              e.stopPropagation();
              onExpandBackward();
            }}
          >
            ← Callers
          </button>
          <button
            className="px-1.5 py-0.5 text-[10px] rounded border border-vs-border bg-vs-surface text-vs-muted hover:text-vs-text hover:border-vs-accent disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:border-vs-border disabled:hover:text-vs-muted"
            disabled={node.expandedForward || node.bodyUnavailable || busy}
            onClick={(e) => {
              e.stopPropagation();
              onExpandForward();
            }}
          >
            Callees →
          </button>
        </div>
        {expandError && (
          <div className="mt-1 text-[10px] text-vs-error font-mono truncate" title={expandError}>
            {expandError}
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Overrides panel (right) ──────────────────────────────────────────────────

interface OverridesPanelProps {
  selectedNodeId: string | null;
  overrideMap: OverrideMap;
  onAdd: (nodeId: string, override: TaintOverride) => void;
  onRemove: (nodeId: string, index: number) => void;
  onApply: () => void;
  applying: boolean;
}

function OverridesPanel({
  selectedNodeId,
  overrideMap,
  onAdd,
  onRemove,
  onApply,
  applying,
}: OverridesPanelProps) {
  const [kind, setKind] = useState<TaintOverride["kind"]>("ReturnTainted");
  const [sourcesText, setSourcesText] = useState("");
  const [paramIndex, setParamIndex] = useState(0);
  const [constValue, setConstValue] = useState("");
  const [constType, setConstType] = useState("Ljava/lang/String;");

  const list = selectedNodeId
    ? overrideMap.overrides[selectedNodeId] ?? []
    : [];

  const handleAdd = () => {
    if (!selectedNodeId) return;
    let o: TaintOverride;
    switch (kind) {
      case "ReturnTainted":
        o = {
          kind,
          sources: sourcesText
            .split(",")
            .map((s) => s.trim())
            .filter((s) => s.length > 0),
        };
        break;
      case "ReturnClean":
        o = { kind };
        break;
      case "ParamTainted":
        o = {
          kind,
          index: paramIndex,
          sources: sourcesText
            .split(",")
            .map((s) => s.trim())
            .filter((s) => s.length > 0),
        };
        break;
      case "ParamClean":
        o = { kind, index: paramIndex };
        break;
      case "ConstantValue":
        o = { kind, value: constValue, typeName: constType };
        break;
    }
    onAdd(selectedNodeId, o);
    setSourcesText("");
    setConstValue("");
  };

  return (
    <div className="h-full flex flex-col p-3 overflow-auto">
      <h2 className="text-xs font-semibold uppercase tracking-widest text-vs-muted mb-2 pb-1 border-b border-vs-border">
        Overrides
      </h2>

      {!selectedNodeId ? (
        <p className="text-vs-dim text-xs italic">No node selected.</p>
      ) : (
        <>
          <div className="mb-3">
            <div className="text-[10px] text-vs-dim mb-1 uppercase tracking-wide">
              Active ({list.length})
            </div>
            {list.length === 0 ? (
              <p className="text-vs-dim text-xs italic">None set.</p>
            ) : (
              <div className="space-y-1">
                {list.map((o, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 py-1 px-2 rounded bg-vs-elevated/40 border border-vs-border"
                  >
                    <div className="min-w-0 flex-1">
                      <div className="text-[10px] text-vs-accent font-semibold uppercase">
                        {o.kind}
                      </div>
                      <div className="text-[11px] text-vs-text font-mono break-all">
                        {describeOverride(o)}
                      </div>
                    </div>
                    <button
                      className="text-vs-dim hover:text-vs-error text-xs shrink-0"
                      onClick={() => onRemove(selectedNodeId, i)}
                      title="Remove override"
                    >
                      ×
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="border-t border-vs-border pt-3 mb-3">
            <div className="text-[10px] text-vs-dim mb-1 uppercase tracking-wide">
              Add override
            </div>
            <select
              className="w-full bg-vs-surface border border-vs-border rounded px-2 py-1 text-xs text-vs-text mb-2"
              value={kind}
              onChange={(e) => setKind(e.target.value as TaintOverride["kind"])}
            >
              <option value="ReturnTainted">ReturnTainted</option>
              <option value="ReturnClean">ReturnClean</option>
              <option value="ParamTainted">ParamTainted</option>
              <option value="ParamClean">ParamClean</option>
              <option value="ConstantValue">ConstantValue</option>
            </select>

            {(kind === "ParamTainted" || kind === "ParamClean") && (
              <input
                type="number"
                min={0}
                value={paramIndex}
                onChange={(e) => setParamIndex(parseInt(e.target.value, 10) || 0)}
                placeholder="Param index"
                className="w-full bg-vs-surface border border-vs-border rounded px-2 py-1 text-xs text-vs-text mb-2"
              />
            )}

            {(kind === "ReturnTainted" || kind === "ParamTainted") && (
              <input
                type="text"
                value={sourcesText}
                onChange={(e) => setSourcesText(e.target.value)}
                placeholder="Sources (comma-separated)"
                className="w-full bg-vs-surface border border-vs-border rounded px-2 py-1 text-xs text-vs-text font-mono mb-2"
              />
            )}

            {kind === "ConstantValue" && (
              <>
                <input
                  type="text"
                  value={constValue}
                  onChange={(e) => setConstValue(e.target.value)}
                  placeholder="Value"
                  className="w-full bg-vs-surface border border-vs-border rounded px-2 py-1 text-xs text-vs-text font-mono mb-2"
                />
                <input
                  type="text"
                  value={constType}
                  onChange={(e) => setConstType(e.target.value)}
                  placeholder="Type (e.g. Ljava/lang/String;)"
                  className="w-full bg-vs-surface border border-vs-border rounded px-2 py-1 text-xs text-vs-text font-mono mb-2"
                />
              </>
            )}

            <button
              className="w-full px-2 py-1 text-xs rounded border border-vs-border bg-vs-surface text-vs-muted hover:text-vs-text hover:border-vs-accent"
              onClick={handleAdd}
            >
              + Add
            </button>
          </div>

          <button
            className="w-full px-2 py-1.5 text-xs rounded border border-vs-accent bg-vs-accent/20 text-vs-text hover:bg-vs-accent/30 disabled:opacity-50"
            disabled={applying}
            onClick={onApply}
          >
            {applying ? "Re-analysing…" : "Apply & re-analyse"}
          </button>
        </>
      )}
    </div>
  );
}

// ─── Main TaintApp ────────────────────────────────────────────────────────────

const TaintApp: React.FC = () => {
  const [{ className, methodName }, setTarget] = useState(parseHash);
  const [graph, setGraph] = useState<TaintGraph | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [overrideMap, setOverrideMap] = useState<OverrideMap>({ overrides: {} });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [busyNodeId, setBusyNodeId] = useState<string | null>(null);
  const [showOverrides, setShowOverrides] = useState(true);
  const [applyingOverrides, setApplyingOverrides] = useState(false);
  const [actionError, setActionError] = useState<string | null>(null);
  const [nodeError, setNodeError] = useState<{ id: string; msg: string } | null>(null);
  const [showHelp, setShowHelp] = useState(false);

  const buildRoot = useCallback(
    (cn: string, mn: string, overrides: OverrideMap) => {
      if (!cn || !mn) {
        setLoading(false);
        return;
      }
      setLoading(true);
      setError(null);
      setActionError(null);
      setNodeError(null);
      api
        .taintBuildRoot(cn, mn, overrides)
        .then((g) => {
          setGraph(g);
          setSelectedNodeId(g.root);
        })
        .catch((e: unknown) => setError(String(e)))
        .finally(() => setLoading(false));
    },
    []
  );

  // Initial build
  useEffect(() => {
    buildRoot(className, methodName, overrideMap);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Listen for navigation events from the main window
  useEffect(() => {
    if (!isTauri()) return;
    const unlisten = listen<{ className: string; methodName: string }>(
      "taint:navigate",
      ({ payload }) => {
        setTarget({ className: payload.className, methodName: payload.methodName });
        setOverrideMap({ overrides: {} });
        buildRoot(payload.className, payload.methodName, { overrides: {} });
      }
    );
    return () => {
      unlisten.then((fn) => fn());
    };
  }, [buildRoot]);

  // Sorted nodes (by depth ascending), stable on methodRef
  const sortedNodes = useMemo(() => {
    if (!graph) return [] as TaintNode[];
    return [...graph.nodes].sort((a, b) => {
      if (a.depth !== b.depth) return a.depth - b.depth;
      return a.methodRef.localeCompare(b.methodRef);
    });
  }, [graph]);

  const selectedNode = useMemo(
    () => graph?.nodes.find((n) => n.id === selectedNodeId) ?? null,
    [graph, selectedNodeId]
  );

  // ── Expansion / re-analysis handlers ─────────────────────────────────────
  const expandForward = (nodeId: string) => {
    if (!graph) return;
    setBusyNodeId(nodeId);
    setNodeError(null);
    api
      .taintExpandForward(graph, nodeId, overrideMap)
      .then(setGraph)
      .catch((e: unknown) => setNodeError({ id: nodeId, msg: String(e) }))
      .finally(() => setBusyNodeId(null));
  };

  const expandBackward = (nodeId: string) => {
    if (!graph) return;
    setBusyNodeId(nodeId);
    setNodeError(null);
    api
      .taintExpandBackward(graph, nodeId, overrideMap)
      .then(setGraph)
      .catch((e: unknown) => setNodeError({ id: nodeId, msg: String(e) }))
      .finally(() => setBusyNodeId(null));
  };

  const reanalyze = () => {
    if (!graph) return;
    setApplyingOverrides(true);
    setActionError(null);
    api
      .taintReanalyze(graph, overrideMap)
      .then(setGraph)
      .catch((e: unknown) => setActionError(String(e)))
      .finally(() => setApplyingOverrides(false));
  };

  const resetGraph = () => {
    buildRoot(className, methodName, overrideMap);
  };

  // ── Override edits ───────────────────────────────────────────────────────
  const addOverride = (nodeId: string, override: TaintOverride) => {
    setOverrideMap((prev) => {
      const list = prev.overrides[nodeId] ?? [];
      return {
        overrides: { ...prev.overrides, [nodeId]: [...list, override] },
      };
    });
  };

  const removeOverride = (nodeId: string, index: number) => {
    setOverrideMap((prev) => {
      const list = prev.overrides[nodeId] ?? [];
      const next = list.filter((_, i) => i !== index);
      const copy = { ...prev.overrides };
      if (next.length === 0) {
        delete copy[nodeId];
      } else {
        copy[nodeId] = next;
      }
      return { overrides: copy };
    });
  };

  const rootShort = graph ? shortenMethodRef(graph.root) : shortenMethodRef(`${className}->${methodName}`);

  return (
    <div
      className="h-screen flex flex-col bg-vs-bg text-vs-text overflow-hidden"
      style={{
        fontFamily: "ui-monospace, SFMono-Regular, Menlo, monospace",
        fontSize: "13px",
      }}
    >
      {/* ── Header ── */}
      <header className="flex items-center gap-3 px-4 py-2 bg-vs-elevated border-b border-vs-border shrink-0">
        <span className="text-lg">🔬</span>
        <div className="min-w-0 flex-1">
          <div className="text-xs text-vs-muted">Taint Analysis</div>
          <div className="text-sm font-semibold truncate">
            <span className="text-tree-class">{rootShort}</span>
          </div>
          {graph && (
            <div className="text-[10px] text-vs-dim">
              {graph.nodes.length} nodes / {graph.edges.length} edges
            </div>
          )}
        </div>
        <label className="flex items-center gap-1 text-[11px] text-vs-muted cursor-pointer">
          <input
            type="checkbox"
            checked={showOverrides}
            onChange={(e) => setShowOverrides(e.target.checked)}
          />
          Overrides
        </label>
        <button
          className="px-3 py-1 rounded bg-vs-elevated border border-vs-border text-xs text-vs-muted hover:text-vs-text hover:border-vs-accent transition-colors disabled:opacity-50"
          onClick={resetGraph}
          disabled={loading}
        >
          {loading ? "…" : "↺ Reset graph"}
        </button>
        <div className="relative">
          <button
            className="px-2 py-1 rounded bg-vs-elevated border border-vs-border text-xs text-vs-muted hover:text-vs-text hover:border-vs-accent"
            onClick={() => setShowHelp((h) => !h)}
            title="Help"
          >
            ?
          </button>
          {showHelp && (
            <div className="absolute right-0 top-full mt-1 w-72 z-10 bg-vs-surface border border-vs-border rounded p-3 text-[11px] text-vs-text shadow-lg">
              <div className="font-semibold mb-1">Tips</div>
              <ul className="list-disc pl-4 space-y-1 text-vs-muted">
                <li>Click a node to view its analysis.</li>
                <li>"Callees →" expands forward (called methods).</li>
                <li>"← Callers" expands backward (callers).</li>
                <li>Add overrides to model external return values, then re-analyse.</li>
                <li>Reset graph rebuilds everything from the root.</li>
              </ul>
            </div>
          )}
        </div>
      </header>

      {/* ── Body ── */}
      {loading && !graph && (
        <main className="flex-1 flex items-center justify-center">
          <div className="flex items-center gap-3 text-vs-muted text-sm">
            <span className="animate-spin">⟳</span>
            Analysing…
          </div>
        </main>
      )}

      {error && !graph && (
        <main className="flex-1 p-5">
          <div className="bg-vs-error/10 border border-vs-error/30 rounded p-4 text-vs-error text-sm font-mono">
            <div className="mb-2">{error}</div>
            <button
              className="px-2 py-1 rounded border border-vs-error/50 text-vs-error hover:bg-vs-error/20 text-xs"
              onClick={resetGraph}
            >
              Retry
            </button>
          </div>
        </main>
      )}

      {graph && (
        <div className="flex-1 flex min-h-0">
          {/* ── Left: graph view ── */}
          <div
            className="border-r border-vs-border bg-vs-surface overflow-auto p-2"
            style={{ width: "40%", minWidth: 280 }}
          >
            <div className="text-[10px] text-vs-dim uppercase tracking-wide mb-2 px-1">
              Call graph
            </div>
            {sortedNodes.map((node) => (
              <NodeCard
                key={node.id}
                node={node}
                selected={node.id === selectedNodeId}
                busy={busyNodeId === node.id}
                onSelect={() => setSelectedNodeId(node.id)}
                onExpandForward={() => expandForward(node.id)}
                onExpandBackward={() => expandBackward(node.id)}
                expandError={
                  nodeError && nodeError.id === node.id ? nodeError.msg : null
                }
              />
            ))}
          </div>

          {/* ── Middle: selected node details ── */}
          <div className="flex-1 overflow-auto p-5 min-w-0">
            {selectedNode ? (
              <>
                <div className="flex items-start gap-3 mb-4 pb-3 border-b border-vs-border">
                  <div className="min-w-0 flex-1">
                    <div className="text-[10px] text-vs-muted uppercase tracking-wide">
                      Selected
                    </div>
                    <div className="text-sm font-mono text-vs-text break-all">
                      {selectedNode.methodRef}
                    </div>
                    <div className="text-[10px] text-vs-dim mt-0.5">
                      depth = {selectedNode.depth}
                      {selectedNode.bodyUnavailable && " · external"}
                    </div>
                  </div>
                  <button
                    className="px-3 py-1 rounded bg-vs-elevated border border-vs-border text-xs text-vs-muted hover:text-vs-text hover:border-vs-accent shrink-0 disabled:opacity-50"
                    onClick={reanalyze}
                    disabled={applyingOverrides}
                  >
                    {applyingOverrides ? "…" : "↺ Re-run analysis"}
                  </button>
                </div>

                {actionError && (
                  <div className="mb-3 bg-vs-error/10 border border-vs-error/30 rounded p-2 text-vs-error text-xs font-mono">
                    {actionError}
                  </div>
                )}

                {selectedNode.analysis ? (
                  <>
                    {/* Summary banner */}
                    <div className="flex flex-wrap gap-3 mb-6">
                      <div className="px-3 py-2 rounded border border-vs-border bg-vs-elevated text-center min-w-20">
                        <div className="text-lg font-bold text-vs-accent">
                          {selectedNode.analysis.sources.length}
                        </div>
                        <div className="text-[10px] text-vs-muted uppercase tracking-wide">
                          Sources
                        </div>
                      </div>
                      <div
                        className={`px-3 py-2 rounded border text-center min-w-20 ${
                          selectedNode.analysis.sinks.length > 0
                            ? "border-vs-error/50 bg-vs-error/10"
                            : "border-vs-border bg-vs-elevated"
                        }`}
                      >
                        <div
                          className={`text-lg font-bold ${
                            selectedNode.analysis.sinks.length > 0
                              ? "text-vs-error"
                              : "text-vs-success"
                          }`}
                        >
                          {selectedNode.analysis.sinks.length}
                        </div>
                        <div className="text-[10px] text-vs-muted uppercase tracking-wide">
                          Sinks
                        </div>
                      </div>
                      <div
                        className={`px-3 py-2 rounded border text-center min-w-20 ${
                          selectedNode.analysis.taintedFields.length > 0
                            ? "border-vs-warn/50 bg-vs-warn/10"
                            : "border-vs-border bg-vs-elevated"
                        }`}
                      >
                        <div
                          className={`text-lg font-bold ${
                            selectedNode.analysis.taintedFields.length > 0
                              ? "text-vs-warn"
                              : "text-vs-muted"
                          }`}
                        >
                          {selectedNode.analysis.taintedFields.length}
                        </div>
                        <div className="text-[10px] text-vs-muted uppercase tracking-wide">
                          Field Writes
                        </div>
                      </div>
                      {selectedNode.analysis.taintedReturn && (
                        <div className="px-3 py-2 rounded border border-vs-warn/50 bg-vs-warn/10 text-center min-w-20">
                          <div className="text-lg">↩</div>
                          <div className="text-[10px] text-vs-warn uppercase tracking-wide">
                            Tainted Return
                          </div>
                        </div>
                      )}
                    </div>

                    {selectedNode.analysis.taintedReturn &&
                      selectedNode.analysis.returnSources.length > 0 && (
                        <div className="mb-4 px-3 py-2 bg-vs-warn/10 border border-vs-warn/30 rounded text-xs">
                          <span className="text-vs-warn font-semibold">
                            Return value tainted by:{" "}
                          </span>
                          {selectedNode.analysis.returnSources.join(", ")}
                        </div>
                      )}

                    <Section
                      title="Sinks Reached"
                      count={selectedNode.analysis.sinks.length}
                      danger
                    >
                      <SinksPanel sinks={selectedNode.analysis.sinks} />
                    </Section>

                    <Section
                      title="Taint Sources"
                      count={selectedNode.analysis.sources.length}
                    >
                      <SourcesPanel sources={selectedNode.analysis.sources} />
                    </Section>

                    {selectedNode.analysis.taintedFields.length > 0 && (
                      <Section
                        title="Tainted Field Writes"
                        count={selectedNode.analysis.taintedFields.length}
                      >
                        <FieldsPanel fields={selectedNode.analysis.taintedFields} />
                      </Section>
                    )}

                    <RegisterPanel registers={selectedNode.analysis.registerSummary} />
                  </>
                ) : (
                  <div className="text-vs-dim italic text-sm py-6 text-center">
                    No analysis (external method or no body found).
                  </div>
                )}
              </>
            ) : (
              <div className="text-vs-dim italic text-sm py-6 text-center">
                Select a node from the graph.
              </div>
            )}
          </div>

          {/* ── Right: overrides panel ── */}
          {showOverrides && (
            <div
              className="border-l border-vs-border bg-vs-surface overflow-hidden"
              style={{ width: "25%", minWidth: 240 }}
            >
              <OverridesPanel
                selectedNodeId={selectedNodeId}
                overrideMap={overrideMap}
                onAdd={addOverride}
                onRemove={removeOverride}
                onApply={reanalyze}
                applying={applyingOverrides}
              />
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default TaintApp;
