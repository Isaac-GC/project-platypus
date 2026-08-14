/**
 * SearchApp — JADX-style standalone search window.
 *
 * Loaded by `main.tsx` when `window.location.hash` starts with `#/search`.
 * Opened by the `open_search_window` Tauri command (or via `api.openSearchWindow`).
 * Stays open as the user works in the main window — calls navigate the main
 * window via the Tauri event bus rather than closing themselves.
 *
 * Compared to the old in-app modal this window has:
 *  - Bigger, persistent UI (resizable OS window)
 *  - **Package filter** (the new optional secondary filter)
 *  - In-window history (last 20 queries)
 *  - Live result count + per-kind tab counts
 *  - Double-click / Enter to navigate the main window
 */

import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen, emit } from "@tauri-apps/api/event";
import type { SearchResult } from "./api/types";
import { persistGet, persistGetSync, persistSet } from "./utils/persistentStore";

// ─── Types ──────────────────────────────────────────────────────────────────

type FilterKind = "all" | "class" | "method" | "field" | "string" | "reference" | "resource";

const FILTER_TABS: { id: FilterKind; label: string }[] = [
  { id: "all",       label: "All"        },
  { id: "class",     label: "Classes"    },
  { id: "method",    label: "Methods"    },
  { id: "field",     label: "Fields"     },
  { id: "string",    label: "Strings"    },
  { id: "reference", label: "References"  },
  { id: "resource",  label: "Resources"  },
];

const KIND_ICON: Record<SearchResult["kind"], string> = {
  class: "🟦", method: "🔧", field: "🔹", string: "💬",
  reference: "↗", resource: "🗂",
};

const KIND_COLOR: Record<SearchResult["kind"], string> = {
  class: "text-tree-class", method: "text-tree-method",
  field: "text-tree-field", string: "text-syn-string",
  reference: "text-vs-accent", resource: "text-syn-string",
};

const HISTORY_KEY = "platypus_search_history";
const MAX_HISTORY = 20;

function loadHistory(): string[] {
  // Synchronous seed from localStorage for the initial render. On a fresh
  // Linux launch this is empty; the mount-time async hydrate below pulls
  // the durable copy from the backend store.
  try {
    const raw = persistGetSync(HISTORY_KEY);
    return raw ? (JSON.parse(raw) as string[]).slice(0, MAX_HISTORY) : [];
  } catch { return []; }
}

function saveHistory(history: string[]) {
  // Mirrors to the durable backend store so history survives restarts on
  // Linux (WebKitGTK doesn't persist localStorage for the tauri:// origin).
  persistSet(HISTORY_KEY, JSON.stringify(history.slice(0, MAX_HISTORY)));
}

// ─── Result row ─────────────────────────────────────────────────────────────

interface ResultRowProps {
  result: SearchResult;
  isActive: boolean;
  onClick: () => void;
  onDoubleClick: () => void;
}

const ResultRow: React.FC<ResultRowProps> = ({ result, isActive, onClick, onDoubleClick }) => {
  // Strip leading "L" and trailing ";" so users see com.example.Foo not Lcom/example/Foo;
  const cls = result.className.replace(/\//g, ".");
  const lastDot = cls.lastIndexOf(".");
  const pkg = lastDot > 0 ? cls.slice(0, lastDot) : "";
  const shortClass = lastDot > 0 ? cls.slice(lastDot + 1) : cls;

  return (
    <div
      className={[
        "flex items-start gap-2.5 px-3 py-2 cursor-pointer text-xs select-none border-b border-vs-border/30",
        isActive ? "bg-vs-selection text-vs-text" : "hover:bg-vs-elevated/60 text-vs-text",
      ].join(" ")}
      onClick={onClick}
      onDoubleClick={onDoubleClick}
    >
      <span className="flex-shrink-0 mt-0.5">{KIND_ICON[result.kind]}</span>
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-1.5 flex-wrap">
          <span className={`font-mono font-semibold ${KIND_COLOR[result.kind]}`}>
            {result.memberName ?? shortClass}
          </span>
          {result.memberName && (
            <span className="text-vs-dim font-mono">in {shortClass}</span>
          )}
          {pkg && (
            <span className="text-vs-dim font-mono text-[10px]">{pkg}</span>
          )}
        </div>
        {result.snippet && result.snippet !== `${result.className.replace(/\//g, ".")}` && (
          <div className="text-vs-muted font-mono truncate mt-0.5 opacity-75">
            {result.snippet}
          </div>
        )}
      </div>
      {result.line != null && (
        <span className="text-vs-dim flex-shrink-0 tabular-nums">:{result.line + 1}</span>
      )}
    </div>
  );
};

// ─── SearchApp ──────────────────────────────────────────────────────────────

const SearchApp: React.FC = () => {
  // Initial query / pkg can be supplied via hash params: #/search?q=foo&pkg=com.example
  const initial = useMemo(() => {
    const q = new URLSearchParams(window.location.hash.split("?")[1] ?? "");
    return {
      query: q.get("q") ?? "",
      pkg:   q.get("pkg") ?? "",
    };
  }, []);

  const [query, setQuery]   = useState(initial.query);
  const [pkg, setPkg]       = useState(initial.pkg);
  const [results, setResults] = useState<SearchResult[]>([]);
  const [filter, setFilter] = useState<FilterKind>("all");
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError]   = useState<string | null>(null);
  const [activeIdx, setActiveIdx] = useState(0);
  const [history, setHistory] = useState<string[]>(loadHistory);
  const [showHistory, setShowHistory] = useState(false);

  const inputRef = useRef<HTMLInputElement>(null);
  const listRef  = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Initial focus
  useEffect(() => { inputRef.current?.focus(); inputRef.current?.select(); }, []);

  // ── Hydrate search history from the durable backend store on mount.
  // On Linux the synchronous localStorage seed (loadHistory) is empty on a
  // fresh launch; pull the persisted copy so recent searches survive
  // restarts. Only applied when the in-memory list is still empty so we
  // never clobber edits made this session.
  useEffect(() => {
    let cancelled = false;
    void persistGet(HISTORY_KEY).then((raw) => {
      if (cancelled || !raw) return;
      setHistory((prev) => {
        if (prev.length > 0) return prev;
        try { return (JSON.parse(raw) as string[]).slice(0, MAX_HISTORY); }
        catch { return prev; }
      });
    });
    return () => { cancelled = true; };
  }, []);

  // ── Listen for refocus / re-query events from the main window
  useEffect(() => {
    const unlisten = listen<{ query?: string; pkg?: string }>("search:focus", (e) => {
      if (e.payload?.query !== undefined) setQuery(e.payload.query);
      if (e.payload?.pkg !== undefined)   setPkg(e.payload.pkg);
      inputRef.current?.focus();
      inputRef.current?.select();
    });
    return () => { void unlisten.then((fn) => fn()); };
  }, []);

  // ── Debounced search
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    if (!query.trim()) {
      setResults([]); setIsSearching(false); setError(null);
      return;
    }
    setIsSearching(true);
    debounceRef.current = setTimeout(async () => {
      try {
        const res = await invoke<SearchResult[]>("search_code", {
          query,
          packageFilter: pkg.trim() || null,
        });
        setResults(res);
        setError(null);
      } catch (e) {
        setResults([]);
        setError(e instanceof Error ? e.message : String(e));
      } finally {
        setIsSearching(false);
        setActiveIdx(0);
      }
    }, 200);
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current); };
  }, [query, pkg]);

  // ── Reset active row when filter or results change
  useEffect(() => { setActiveIdx(0); }, [filter, results]);

  // ── Apply per-kind filter
  const filtered = useMemo(
    () => filter === "all" ? results : results.filter((r) => r.kind === filter),
    [filter, results],
  );

  // ── Keep active row in view
  useEffect(() => {
    if (!listRef.current) return;
    const el = listRef.current.children[activeIdx] as HTMLElement | undefined;
    el?.scrollIntoView({ block: "nearest" });
  }, [activeIdx]);

  // ── Push current query into history on Enter / open
  const recordHistory = useCallback((q: string) => {
    if (!q.trim()) return;
    setHistory((prev) => {
      const next = [q, ...prev.filter((h) => h !== q)].slice(0, MAX_HISTORY);
      saveHistory(next);
      return next;
    });
  }, []);

  // ── Navigate the *main* window to the picked result
  const navigateToResult = useCallback(async (r: SearchResult) => {
    recordHistory(query);
    // The main window has a `navigateToSearchResult` action — emit an event
    // that App.tsx listens for. The window stays open so the user can keep
    // chasing more results.
    await emit("search:navigate", r);
  }, [recordHistory, query]);

  // ── Keyboard shortcuts
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Escape") {
      if (showHistory) { setShowHistory(false); return; }
      // Keep the window open on Esc — JADX-style. Just blur the input.
      inputRef.current?.blur();
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIdx((i) => Math.min(i + 1, filtered.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      const r = filtered[activeIdx];
      if (r) void navigateToResult(r);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-vs-bg text-vs-text">

      {/* ── Header — query + package filter ─────────────────────────────────── */}
      <div className="flex flex-col gap-1.5 px-3 py-2 border-b border-vs-border bg-vs-elevated flex-shrink-0">

        {/* Query row */}
        <div className="flex items-center gap-2">
          <span className="text-vs-dim flex-shrink-0">🔍</span>
          <div className="relative flex-1">
            <input
              ref={inputRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              onFocus={() => history.length > 0 && setShowHistory(true)}
              onBlur={() => setTimeout(() => setShowHistory(false), 150)}
              onKeyDown={handleKeyDown}
              placeholder="Search classes, methods, fields, strings…"
              className="w-full bg-vs-bg border border-vs-border rounded px-2 py-1 text-sm text-vs-text placeholder-vs-dim outline-none focus:border-vs-accent"
              spellCheck={false}
              autoComplete="off"
            />
            {/* History dropdown */}
            {showHistory && history.length > 0 && (
              <div className="absolute z-20 left-0 right-0 top-full mt-1 bg-vs-elevated border border-vs-border rounded shadow-lg max-h-48 overflow-y-auto">
                <div className="px-2 py-1 text-[10px] uppercase tracking-wider text-vs-dim border-b border-vs-border">
                  Recent searches
                </div>
                {history.map((h) => (
                  <button
                    key={h}
                    onMouseDown={(e) => { e.preventDefault(); setQuery(h); setShowHistory(false); }}
                    className="block w-full text-left px-2 py-1 text-xs font-mono text-vs-text hover:bg-vs-bg/60"
                  >
                    {h}
                  </button>
                ))}
              </div>
            )}
          </div>
          {isSearching && (
            <span className="text-vs-dim text-xs animate-pulse flex-shrink-0">searching…</span>
          )}
          {!isSearching && results.length > 0 && (
            <span className="text-vs-dim text-xs tabular-nums flex-shrink-0">
              {filtered.length} / {results.length}
            </span>
          )}
        </div>

        {/* Package filter row — secondary optional filter */}
        <div className="flex items-center gap-2">
          <span className="text-vs-dim text-xs flex-shrink-0 w-5 text-center" title="Filter by source classpath / package">📦</span>
          <input
            type="text"
            value={pkg}
            onChange={(e) => setPkg(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="In package… (e.g. com.example.auth or com/example) — optional"
            className="flex-1 bg-vs-bg border border-vs-border rounded px-2 py-1 text-xs font-mono text-vs-text placeholder-vs-dim outline-none focus:border-vs-accent"
            spellCheck={false}
            autoComplete="off"
            title="Substring match against the class's package path. Dots are normalised to slashes."
          />
          {pkg && (
            <button
              onClick={() => setPkg("")}
              className="text-vs-dim hover:text-vs-text text-xs flex-shrink-0"
              title="Clear package filter"
            >
              ✕
            </button>
          )}
        </div>
      </div>

      {/* ── Filter tabs ─────────────────────────────────────────────────────── */}
      <div className="flex items-center px-2 border-b border-vs-border flex-shrink-0 bg-vs-bg">
        {FILTER_TABS.map((tab) => {
          const count = tab.id === "all"
            ? results.length
            : results.filter((r) => r.kind === tab.id).length;
          return (
            <button
              key={tab.id}
              onClick={() => setFilter(tab.id)}
              className={[
                "px-3 py-1.5 text-xs transition-colors border-b-2",
                filter === tab.id
                  ? "text-vs-accent border-vs-accent"
                  : "text-vs-dim border-transparent hover:text-vs-text",
              ].join(" ")}
            >
              {tab.label}
              {count > 0 && (
                <span className="ml-1.5 text-vs-dim tabular-nums">({count})</span>
              )}
            </button>
          );
        })}
      </div>

      {/* ── Results ─────────────────────────────────────────────────────────── */}
      <div ref={listRef} className="flex-1 overflow-y-auto">
        {error && (
          <div className="px-4 py-3 text-xs text-vs-error border-b border-vs-error/30 bg-vs-error/5">
            {error}
          </div>
        )}
        {!query.trim() && !error && (
          <div className="px-4 py-8 text-center text-xs text-vs-dim italic">
            Type to search.
            <br />
            Use the package filter to narrow by source classpath.
          </div>
        )}
        {query.trim() && !isSearching && filtered.length === 0 && !error && (
          <div className="px-4 py-8 text-center text-xs text-vs-dim italic">
            No results for &quot;{query}&quot;
            {pkg.trim() && <> in <span className="font-mono">{pkg}</span></>}
          </div>
        )}
        {filtered.map((result, idx) => (
          <ResultRow
            key={`${result.kind}-${result.className}-${result.memberName ?? ""}-${idx}`}
            result={result}
            isActive={idx === activeIdx}
            onClick={() => setActiveIdx(idx)}
            onDoubleClick={() => void navigateToResult(result)}
          />
        ))}
      </div>

      {/* ── Footer ──────────────────────────────────────────────────────────── */}
      <div className="flex items-center gap-3 px-3 py-1 border-t border-vs-border bg-vs-elevated flex-shrink-0 text-vs-dim text-[10px]">
        <span><kbd className="border border-vs-border rounded px-1">↑↓</kbd> navigate</span>
        <span><kbd className="border border-vs-border rounded px-1">↵</kbd> open in main window</span>
        <span><kbd className="border border-vs-border rounded px-1">Esc</kbd> blur input</span>
        <span className="ml-auto opacity-60">Window stays open while you work.</span>
      </div>
    </div>
  );
};

export default SearchApp;
