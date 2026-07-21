/**
 * Self-update flow for the standalone-viewer Tauri app.
 *
 * Three callable entry points:
 *
 *   - `checkForUpdates({ silent: true })`  → call on app launch. Runs
 *     in the background; reports nothing on the happy path; surfaces a
 *     consent prompt only when an update is actually available.
 *   - `checkForUpdates({ silent: false })` → wire to a "Check for
 *     updates" menu item. Always reports the outcome via the supplied
 *     `onStatus` callback so the user gets feedback even when they're
 *     already current.
 *   - `dismissUpdate()` → call after the user picks "Later" on a prompt
 *     so the same check doesn't fire on the next mount.
 *
 * Design notes:
 *   - Dev builds short-circuit on `import.meta.env.DEV` to avoid hitting
 *     the GitHub release endpoint every time you `npm run tauri dev`.
 *     Override with `localStorage.PLATYPUS_FORCE_UPDATE_CHECK = "1"`.
 *   - We never auto-install without consent — `downloadAndInstall()`
 *     fires only after the user confirms in the prompt.
 *   - All errors are caught and logged; failures NEVER crash the app
 *     (the worst outcome is "no update prompt today", which is what
 *     you want when there's a flaky network).
 */

import { check } from "@tauri-apps/plugin-updater";
import { relaunch } from "@tauri-apps/plugin-process";

// ── Public API ─────────────────────────────────────────────────────────────

export type UpdateStatus =
  | { kind: "current"; current: string }
  | { kind: "deferred"; available: string }
  | { kind: "downloading"; available: string; downloaded: number; total: number | null }
  | { kind: "installing"; available: string }
  | { kind: "installed"; available: string }
  | { kind: "skipped"; reason: "dev" | "recently-checked" | "user-dismissed" }
  | { kind: "error";  message: string };

export interface CheckOptions {
  /** When true: only prompt the user if an update is actually
   *  available. Use for the background launch check. */
  silent: boolean;
  /** Callback for every status transition. The host can render a toast
   *  / status pill. Optional — defaults to `console.log`. */
  onStatus?(s: UpdateStatus): void;
  /** When true: ignore the dev-mode short-circuit and the
   *  recently-checked throttle. Use for the manual "Check for updates"
   *  menu action so the user can always force a check. */
  force?: boolean;
}

/** Throttle for the background check — at most once per hour by default
 *  so we don't pester GitHub on every launch in a tight dev loop. The
 *  manual `force: true` path ignores this. */
const THROTTLE_MS = 60 * 60 * 1000;
const LAST_CHECK_KEY = "platypus.updater.lastCheckAt";
const DISMISSED_KEY  = "platypus.updater.dismissedVersion";

export async function checkForUpdates(opts: CheckOptions): Promise<UpdateStatus> {
  const report = (s: UpdateStatus): UpdateStatus => {
    (opts.onStatus ?? defaultOnStatus)(s);
    return s;
  };

  // Dev / throttle gates — only for silent (background) checks.
  if (opts.silent && !opts.force) {
    if (isDevBuild() && !devOverride()) {
      return report({ kind: "skipped", reason: "dev" });
    }
    if (recentlyChecked()) {
      return report({ kind: "skipped", reason: "recently-checked" });
    }
  }

  try {
    markChecked();
    const upd = await check();
    if (!upd?.available) {
      return report({ kind: "current", current: upd?.currentVersion ?? "unknown" });
    }
    if (wasDismissed(upd.version)) {
      return report({ kind: "skipped", reason: "user-dismissed" });
    }

    // Confirm in non-silent mode OR when silent + user hasn't dismissed
    // this version yet (the launch check should surface the prompt).
    const consent = await confirmUpdate(upd.version, upd.body ?? "");
    if (!consent) {
      rememberDismissed(upd.version);
      return report({ kind: "deferred", available: upd.version });
    }

    // Download with progress reporting.
    let downloaded = 0;
    let total: number | null = null;
    await upd.downloadAndInstall((event) => {
      switch (event.event) {
        case "Started":
          total = event.data.contentLength ?? null;
          report({ kind: "downloading", available: upd.version, downloaded: 0, total });
          break;
        case "Progress":
          downloaded += event.data.chunkLength;
          report({ kind: "downloading", available: upd.version, downloaded, total });
          break;
        case "Finished":
          report({ kind: "installing", available: upd.version });
          break;
      }
    });
    report({ kind: "installed", available: upd.version });
    // Brief delay so the host can flash the "installed" toast before relaunch.
    await new Promise((r) => setTimeout(r, 500));
    await relaunch();
    return { kind: "installed", available: upd.version };
  } catch (e) {
    return report({ kind: "error", message: e instanceof Error ? e.message : String(e) });
  }
}

/** Reset the throttle + clear any dismissed-version pin. Mostly useful
 *  from devtools when debugging the update flow. */
export function resetUpdateState(): void {
  try {
    localStorage.removeItem(LAST_CHECK_KEY);
    localStorage.removeItem(DISMISSED_KEY);
  } catch { /* localStorage unavailable in some headless contexts */ }
}

// ── Internals ──────────────────────────────────────────────────────────────

function defaultOnStatus(s: UpdateStatus): void {
  // eslint-disable-next-line no-console
  console.log("[updater]", s);
}

function isDevBuild(): boolean {
  // Vite injects `import.meta.env.DEV` as a literal `true` in dev builds.
  try { return !!(import.meta as any).env?.DEV; } catch { return false; }
}

function devOverride(): boolean {
  try { return localStorage.getItem("PLATYPUS_FORCE_UPDATE_CHECK") === "1"; }
  catch { return false; }
}

function recentlyChecked(): boolean {
  try {
    const raw = localStorage.getItem(LAST_CHECK_KEY);
    if (!raw) return false;
    const ts = parseInt(raw, 10);
    if (isNaN(ts)) return false;
    return Date.now() - ts < THROTTLE_MS;
  } catch { return false; }
}

function markChecked(): void {
  try { localStorage.setItem(LAST_CHECK_KEY, String(Date.now())); } catch {}
}

function wasDismissed(version: string): boolean {
  try { return localStorage.getItem(DISMISSED_KEY) === version; } catch { return false; }
}

function rememberDismissed(version: string): void {
  try { localStorage.setItem(DISMISSED_KEY, version); } catch {}
}

async function confirmUpdate(version: string, notes: string): Promise<boolean> {
  // Default to the built-in `window.confirm` so this module has no
  // hard dependency on the host's prompt component. Hosts that want a
  // custom Material 3-style dialog can override by NOT using the
  // built-in path and calling `downloadAndInstall` directly from their
  // own prompt — see README for an example.
  const trimmed = notes.length > 400 ? notes.slice(0, 400) + "…" : notes;
  const msg = `A new version (${version}) is available.\n\n` +
              (trimmed ? `${trimmed}\n\n` : "") +
              `Download and install now? The app will restart automatically.`;
  try { return window.confirm(msg); } catch { return false; }
}
