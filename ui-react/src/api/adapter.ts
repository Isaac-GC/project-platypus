// @tauri-apps/api/core is always bundled (it's in package.json dependencies).
// The functions are no-ops / throw gracefully when called outside a Tauri webview,
// but isTauri() guards every call so that never happens.
import { invoke as tauriInvoke } from "@tauri-apps/api/core";

import {
  LoadResult,
  XRef,
  RunResult,
  ExecResult,
  ResourceEntry,
  SearchResult,
  CallGraphResult,
  MethodCfgResult,
  ScriptRunResult,
  LintDiagnostic, TaintAnalysisResult, TaintGraph, OverrideMap, ProjectSnapshot,
  DexLoaderSite, ScriptCompletionsResult, ScriptInfo,
  DeobfMark, DeobfSite, DeobfBulkResult,
  EmbeddedLoadResult,
} from "./types";


export const isTauri = (): boolean => {
  if (typeof window === "undefined") return false;
  return "__TAURI_INTERNALS__" in window || "__TAURI__" in window;
};

// ─── Invoke wrapper ───────────────────────────────────────────────────────────

function invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  return tauriInvoke<T>(cmd, args);
}

// ─── Web REST fallback ────────────────────────────────────────────────────────

const BASE_URL = "http://localhost:8080";

async function fetchAPI<T>(path: string, options?: RequestInit): Promise<T> {
  const headers =
    options?.body instanceof FormData
      ? undefined
      : { "Content-Type": "application/json" };

  const res = await fetch(`${BASE_URL}${path}`, { headers, ...options });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API error ${res.status}: ${text}`);
  }
  // Use text() first so we can handle both JSON and plain-text responses.
  const text = await res.text();
  try {
    return JSON.parse(text) as T;
  } catch {
    return text as unknown as T;
  }
}

// ─── Unified API adapter ──────────────────────────────────────────────────────

export const api = {
  async loadFile(path: string): Promise<LoadResult> {
    if (isTauri()) return invoke<LoadResult>("load_file", { path });
    return fetchAPI<LoadResult>("/api/load", {
      method: "POST",
      body: JSON.stringify({ path }),
    });
  },

  async uploadFile(file: File): Promise<LoadResult> {
    if (isTauri()) throw new Error("uploadFile() not available in Tauri — use loadFile(path).");
    const form = new FormData();
    form.append("file", file, file.name);
    return fetchAPI<LoadResult>("/api/upload", { method: "POST", body: form });
  },

  async getClassSmali(className: string, slotId?: string): Promise<string> {
    if (isTauri()) return invoke<string>("get_class_smali", { className, slotId: slotId ?? null });
    return fetchAPI<string>(`/api/smali/${encodeURIComponent(className)}`);
  },

  async getClassJava(className: string, keepKotlinIntrinsics?: boolean, slotId?: string): Promise<string> {
    if (isTauri()) {
      return invoke<string>("get_class_java", {
        className,
        keepKotlinIntrinsics: keepKotlinIntrinsics ?? null,
        slotId: slotId ?? null,
      });
    }
    const qs = keepKotlinIntrinsics ? "?keep_kotlin_intrinsics=1" : "";
    return fetchAPI<string>(`/api/java/${encodeURIComponent(className)}${qs}`);
  },

  async getManifest(): Promise<string> {
    if (isTauri()) return invoke<string>("get_manifest");
    return fetchAPI<string>("/api/manifest");
  },

  async getXrefs(className: string, methodName: string, slotId?: string): Promise<XRef[]> {
    if (isTauri()) return invoke<XRef[]>("get_xrefs", { className, methodName, slotId: slotId ?? null });
    return fetchAPI<XRef[]>(
      `/api/xrefs?class=${encodeURIComponent(className)}&method=${encodeURIComponent(methodName)}`
    );
  },

  async getCallGraph(className: string, methodName: string, slotId?: string): Promise<CallGraphResult> {
    if (isTauri()) return invoke<CallGraphResult>("get_call_graph", { className, methodName, slotId: slotId ?? null });
    return fetchAPI<CallGraphResult>(
      `/api/call_graph?class=${encodeURIComponent(className)}&method=${encodeURIComponent(methodName)}`
    );
  },

  async runMethod(
    className: string,
    methodName: string,
    args: string[],
    instrLimit?: number,
    slotId?: string,
  ): Promise<RunResult> {
    if (isTauri()) {
      return invoke<RunResult>("run_method", {
        className, methodName, args,
        instrLimit: instrLimit ?? null,
        slotId: slotId ?? null,
      });
    }
    return fetchAPI<RunResult>("/api/run", {
      method: "POST",
      body: JSON.stringify({ className, methodName, args, instrLimit }),
    });
  },

  async findExec(target: string, instrLimit?: number, numThreads?: number, slotId?: string): Promise<ExecResult[]> {
    if (isTauri()) {
      return invoke<ExecResult[]>("find_exec", {
        target,
        instrLimit: instrLimit ?? null,
        numThreads: numThreads ?? null,
        slotId: slotId ?? null,
      });
    }
    return fetchAPI<ExecResult[]>("/api/find_exec", {
      method: "POST",
      body: JSON.stringify({ target, instrLimit, numThreads }),
    });
  },

  // ── Deobfuscation marks ────────────────────────────────────────────────
  //
  // Backed by the per-slot `deobf_marks` set on the Rust side. The
  // web REST fallback below is a no-op for now (the web build has
  // no project store), so the DEOBFUSCATION tab gracefully degrades
  // to an empty list outside Tauri.

  async deobfListMarks(): Promise<DeobfMark[]> {
    if (isTauri()) return invoke<DeobfMark[]>("deobf_list_marks");
    return [];
  },

  async deobfMarkMethod(className: string, methodName: string): Promise<DeobfMark[]> {
    if (isTauri()) {
      return invoke<DeobfMark[]>("deobf_mark_method", { className, methodName });
    }
    return [];
  },

  async deobfUnmarkMethod(className: string, methodName: string): Promise<DeobfMark[]> {
    if (isTauri()) {
      return invoke<DeobfMark[]>("deobf_unmark_method", { className, methodName });
    }
    return [];
  },

  async deobfScanSites(className: string, methodName: string): Promise<DeobfSite[]> {
    if (isTauri()) {
      return invoke<DeobfSite[]>("deobf_scan_sites", { className, methodName });
    }
    return [];
  },

  async deobfRunAllMarks(instrLimit?: number, numThreads?: number): Promise<DeobfBulkResult[]> {
    if (isTauri()) {
      return invoke<DeobfBulkResult[]>("deobf_run_all_marks", {
        instrLimit: instrLimit ?? null,
        numThreads: numThreads ?? null,
      });
    }
    return [];
  },

  /** Run a specific list of call sites — used by the DEOBFUSCATION
   *  tab's per-row ▶ and "Deobfuscate Shown" buttons. Results come
   *  back in the same order as `sites` so the caller can pair them
   *  back to the originating UI rows by index. */
  async deobfRunSpecificSites(
    sites: Array<{
      className: string;
      methodName: string;
      args: string[];
      callerClass: string;
      callerMethod: string;
      offset: number;
      callSite: string;
    }>,
    instrLimit?: number,
    numThreads?: number,
  ): Promise<ExecResult[]> {
    if (isTauri()) {
      return invoke<ExecResult[]>("deobf_run_specific_sites", {
        sites,
        instrLimit: instrLimit ?? null,
        numThreads: numThreads ?? null,
      });
    }
    return [];
  },

  async getResources(): Promise<ResourceEntry[]> {
    if (isTauri()) return invoke<ResourceEntry[]>("get_resources");
    return fetchAPI<ResourceEntry[]>("/api/resources");
  },

  async openFileDialog(): Promise<string | null> {
    if (isTauri()) return invoke<string | null>("open_file_dialog");
    return null;
  },

  async searchCode(query: string, packageFilter?: string, slotId?: string): Promise<SearchResult[]> {
    if (isTauri()) {
      return invoke<SearchResult[]>("search_code", {
        query,
        packageFilter: packageFilter ?? null,
        slotId: slotId ?? null,
      });
    }
    const qs = new URLSearchParams({ q: query });
    if (packageFilter) qs.set("pkg", packageFilter);
    return fetchAPI<SearchResult[]>(`/api/search?${qs.toString()}`);
  },

  async getMethodCfg(className: string, methodName: string, slotId?: string): Promise<MethodCfgResult> {
    if (isTauri()) return invoke<MethodCfgResult>("get_method_cfg", { className, methodName, slotId: slotId ?? null });
    return fetchAPI<MethodCfgResult>(
      `/api/cfg?class=${encodeURIComponent(className)}&method=${encodeURIComponent(methodName)}`
    );
  },

  // ── Slot B: comparison APK for diffing ──────────────────────────────────────

  async loadFileB(path: string): Promise<LoadResult> {
    if (isTauri()) return invoke<LoadResult>("load_file_b", { path });
    return fetchAPI<LoadResult>("/api/load_b", {
      method: "POST",
      body: JSON.stringify({ path }),
    });
  },

  async uploadFileB(file: File): Promise<LoadResult> {
    if (isTauri()) throw new Error("uploadFileB() not available in Tauri — use loadFileB(path).");
    const form = new FormData();
    form.append("file", file, file.name);
    return fetchAPI<LoadResult>("/api/upload_b", { method: "POST", body: form });
  },

  async getEntry(entryPath: string, slotId?: string): Promise<string> {
    if (isTauri()) return invoke<string>("get_entry", { entryPath, slotId: slotId ?? null });
    return fetchAPI<string>(`/api/entry/${encodeURIComponent(entryPath)}`);
  },

  async getClassSmaliB(className: string): Promise<string> {
    if (isTauri()) return invoke<string>("get_class_smali_b", { className });
    return fetchAPI<string>(`/api/smali_b/${encodeURIComponent(className)}`);
  },

  async getClassJavaB(className: string, keepKotlinIntrinsics?: boolean): Promise<string> {
    if (isTauri()) {
      return invoke<string>("get_class_java_b", {
        className,
        keepKotlinIntrinsics: keepKotlinIntrinsics ?? null,
      });
    }
    const qs = keepKotlinIntrinsics ? "?keep_kotlin_intrinsics=1" : "";
    return fetchAPI<string>(`/api/java_b/${encodeURIComponent(className)}${qs}`);
  },

  // ── Python scripting ────────────────────────────────────────────────────────

  /** Send SIGTERM to the currently-running script subprocess.
   *  Returns true if a process was killed, false if no script was running. */
  async killScript(): Promise<boolean> {
    if (isTauri()) return invoke<boolean>("kill_script");
    // Web mode: no subprocess to kill (the web-server runs scripts in its
    // own process model — separate concern).
    return false;
  },

  async runScript(code: string): Promise<ScriptRunResult> {
    if (isTauri()) return invoke<ScriptRunResult>("run_script", { code });
    return fetchAPI<ScriptRunResult>("/api/run_script", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  },

  async lintScript(code: string): Promise<LintDiagnostic[]> {
    if (isTauri()) return invoke<LintDiagnostic[]>("lint_script", { code });
    return fetchAPI<LintDiagnostic[]>("/api/lint_script", {
      method: "POST",
      body: JSON.stringify({ code }),
    });
  },
  async openTaintWindow(className: string, methodName: string): Promise<void> {
    if (isTauri()) return invoke("open_taint_window", { className, methodName });
    // Web fallback: open in a new browser tab
    window.open(`/#/taint?class=${encodeURIComponent(className)}&method=${encodeURIComponent(methodName)}`, "_blank");
  },

  /** Open the JADX-style global search window — separate OS window in Tauri,
   *  new tab in web mode. If already open, focuses it. */
  async openSearchWindow(): Promise<void> {
    if (isTauri()) return invoke("open_search_window");
    window.open(`/#/search`, "_blank");
  },

  /** Open the activity-viewer window. Optional `initialActivity` (FQ class
   *  name) preselects an activity. If the window is already open, focuses
   *  it and emits a navigate event so it switches to the new activity. */
  async openActivityViewerWindow(initialActivity?: string): Promise<void> {
    if (isTauri()) {
      return invoke("open_activity_viewer_window", {
        initialActivity: initialActivity ?? null,
      });
    }
    const qs = initialActivity ? `?activity=${encodeURIComponent(initialActivity)}` : "";
    window.open(`/#/activity-viewer${qs}`, "_blank");
  },

  async runTaintAnalysis(className: string, methodName: string): Promise<TaintAnalysisResult> {
    if (isTauri()) return invoke("run_taint_analysis", { className, methodName });
    return fetchAPI<TaintAnalysisResult>(`/api/taint?class=${encodeURIComponent(className)}&method=${encodeURIComponent(methodName)}`);
  },

  // ── Inter-procedural graph commands ──────────────────────────────────────

  async taintBuildRoot(
    className: string,
    methodName: string,
    overrides?: OverrideMap,
  ): Promise<TaintGraph> {
    if (isTauri()) return invoke("taint_build_root", { className, methodName, overrides });
    return fetchAPI<TaintGraph>("/api/taint/build_root", {
      method: "POST",
      body: JSON.stringify({ className, methodName, overrides }),
    });
  },

  async taintExpandForward(
    graph: TaintGraph,
    nodeId: string,
    overrides?: OverrideMap,
  ): Promise<TaintGraph> {
    if (isTauri()) return invoke("taint_expand_forward", { graph, nodeId, overrides });
    return fetchAPI<TaintGraph>("/api/taint/expand_forward", {
      method: "POST",
      body: JSON.stringify({ graph, nodeId, overrides }),
    });
  },

  async taintExpandBackward(
    graph: TaintGraph,
    nodeId: string,
    overrides?: OverrideMap,
  ): Promise<TaintGraph> {
    if (isTauri()) return invoke("taint_expand_backward", { graph, nodeId, overrides });
    return fetchAPI<TaintGraph>("/api/taint/expand_backward", {
      method: "POST",
      body: JSON.stringify({ graph, nodeId, overrides }),
    });
  },

  async taintReanalyze(graph: TaintGraph, overrides: OverrideMap): Promise<TaintGraph> {
    if (isTauri()) return invoke("taint_reanalyze", { graph, overrides });
    return fetchAPI<TaintGraph>("/api/taint/reanalyze", {
      method: "POST",
      body: JSON.stringify({ graph, overrides }),
    });
  },

  // ── Multi-APK project commands ──────────────────────────────────────────
  // Tauri-only for now; web-server backend doesn't manage projects.

  async projectInit(): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_init");
    // Stub: web mode runs single-file
    return { slots: [], activeSlotId: null, compareSlotId: null, cacheDir: "" };
  },

  async projectListSlots(): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_list_slots");
    return { slots: [], activeSlotId: null, compareSlotId: null, cacheDir: "" };
  },

  async projectAddApk(path: string, parentId?: string): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_add_apk", { path, parentId: parentId ?? null });
    throw new Error("projectAddApk not supported in web mode");
  },

  async projectAddSplit(slotId: string, splitPath: string): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_add_split", { slotId, splitPath });
    throw new Error("projectAddSplit not supported in web mode");
  },

  async projectRemoveSlot(slotId: string): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_remove_slot", { slotId });
    throw new Error("projectRemoveSlot not supported in web mode");
  },

  async projectSetActiveSlot(slotId: string): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_set_active_slot", { slotId });
    throw new Error("projectSetActiveSlot not supported in web mode");
  },

  async projectSetCompareSlot(slotId: string | null): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_set_compare_slot", { slotId });
    throw new Error("projectSetCompareSlot not supported in web mode");
  },

  async projectForceReloadSlot(slotId: string): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_force_reload_slot", { slotId });
    throw new Error("projectForceReloadSlot not supported in web mode");
  },

  async projectClearExtracted(): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_clear_extracted");
    throw new Error("projectClearExtracted not supported in web mode");
  },

  async projectCacheDir(): Promise<string> {
    if (isTauri()) return invoke("project_cache_dir");
    return "";
  },

  /** Extract `entryPath` from `parentSlotId`'s assets, write it to the cache,
   *  and load it as a new child slot. The new slot becomes active. */
  async projectLoadEmbedded(parentSlotId: string, entryPath: string): Promise<ProjectSnapshot> {
    if (isTauri()) return invoke("project_load_embedded", { parentSlotId, entryPath });
    throw new Error("projectLoadEmbedded not supported in web mode");
  },

  /** Parse an embedded APK into a non-active child slot and return its tree for
   *  inline expansion under the "Embedded APKs" group. */
  async projectLoadEmbeddedNested(parentSlotId: string, entryPath: string): Promise<EmbeddedLoadResult> {
    if (isTauri()) return invoke("project_load_embedded_nested", { parentSlotId, entryPath });
    throw new Error("projectLoadEmbeddedNested not supported in web mode");
  },

  /** Static scan of the active slot's DEX files for DexClassLoader-family
   *  construction sites, with byte-source observations from each containing
   *  method. */
  async analyzeDexLoaders(): Promise<DexLoaderSite[]> {
    if (isTauri()) return invoke("analyze_dex_loaders");
    return fetchAPI<DexLoaderSite[]>("/api/dex_loaders");
  },

  /** Introspect the platypus Python module to drive the script-pane
   *  autocomplete. Runs in a subprocess; returns class/method metadata
   *  pulled from `inspect.getmembers`. Cached on the frontend after first
   *  call; refresh with `forceRefresh = true` (currently unused — backend
   *  doesn't cache, every call re-runs). */
  async getScriptCompletions(): Promise<ScriptCompletionsResult> {
    if (isTauri()) return invoke("script_get_completions");
    throw new Error("getScriptCompletions not supported in web mode");
  },

  // ── Script library (named .py files in cache dir) ─────────────────────────

  async scriptList(): Promise<ScriptInfo[]> {
    if (isTauri()) return invoke("script_list");
    throw new Error("scriptList not supported in web mode");
  },
  async scriptLoad(name: string): Promise<string> {
    if (isTauri()) return invoke("script_load", { name });
    throw new Error("scriptLoad not supported in web mode");
  },
  /** Save a script (creates if absent). Returns the (possibly normalised) name actually used. */
  async scriptSave(name: string, content: string): Promise<string> {
    if (isTauri()) return invoke("script_save", { name, content });
    throw new Error("scriptSave not supported in web mode");
  },
  async scriptCreate(name: string, initialContent?: string): Promise<ScriptInfo> {
    if (isTauri()) return invoke("script_create", { name, initialContent: initialContent ?? null });
    throw new Error("scriptCreate not supported in web mode");
  },
  async scriptDelete(name: string): Promise<void> {
    if (isTauri()) return invoke("script_delete", { name });
    throw new Error("scriptDelete not supported in web mode");
  },
  async scriptRename(oldName: string, newName: string): Promise<string> {
    if (isTauri()) return invoke("script_rename", { oldName, newName });
    throw new Error("scriptRename not supported in web mode");
  },
  async scriptDir(): Promise<string> {
    if (isTauri()) return invoke("script_dir");
    throw new Error("scriptDir not supported in web mode");
  },
};
