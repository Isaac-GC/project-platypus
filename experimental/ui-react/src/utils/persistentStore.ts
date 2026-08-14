/**
 * Durable, cross-platform key→value persistence for UI state.
 *
 * The app persists its UI state (settings, per-slot deobf/rename
 * snapshots, the active script name, search history) to `localStorage`.
 * That works on macOS (WKWebView) and Windows (WebView2) — but **not on
 * Linux**, where the Tauri webview is WebKitGTK and does not persist
 * `localStorage` across restarts for the custom `tauri://` origin. On
 * Ubuntu the state silently vanishes on every relaunch.
 *
 * This module mirrors writes to a backend file store (`ui_state_set`),
 * keeping `localStorage` as a fast *same-session* cache. On a fresh
 * launch, reads fall back to the backend when `localStorage` is empty —
 * so state survives restarts on every platform.
 *
 * Values are opaque strings (callers store JSON). The backend never
 * parses them.
 */

import { invoke } from "@tauri-apps/api/core";
import { isTauri } from "../api/adapter";

/** Write `value` for `key`. Synchronously updates `localStorage` (so
 *  same-session synchronous readers keep working) and, in Tauri, mirrors
 *  to the durable backend store fire-and-forget. */
export function persistSet(key: string, value: string): void {
  try { localStorage.setItem(key, value); } catch { /* webview sandboxing */ }
  if (isTauri()) {
    void invoke("ui_state_set", { key, value }).catch(() => { /* best-effort */ });
  }
}

/** Read `value` for `key`. Prefers `localStorage` (fast + authoritative
 *  within a session); on a fresh launch where `localStorage` is empty,
 *  falls back to the durable backend store and re-seeds `localStorage`
 *  so later synchronous readers this session see it. */
export async function persistGet(key: string): Promise<string | null> {
  try {
    const ls = localStorage.getItem(key);
    if (ls != null) return ls;
  } catch { /* webview sandboxing */ }

  if (isTauri()) {
    try {
      const v = await invoke<string | null>("ui_state_get", { key });
      if (v != null) {
        try { localStorage.setItem(key, v); } catch { /* ignore */ }
        return v;
      }
    } catch { /* best-effort */ }
  }
  return null;
}

/** Synchronous best-effort read — `localStorage` only. Use where an async
 *  read isn't possible (e.g. a `useState` initialiser). Pair it with a
 *  one-shot async `persistGet` hydrate on mount for the Linux fresh-launch
 *  case. */
export function persistGetSync(key: string): string | null {
  try { return localStorage.getItem(key); } catch { return null; }
}

/** Remove `key` from both `localStorage` and the backend store. */
export function persistRemove(key: string): void {
  try { localStorage.removeItem(key); } catch { /* ignore */ }
  if (isTauri()) {
    void invoke("ui_state_remove", { key }).catch(() => { /* best-effort */ });
  }
}
