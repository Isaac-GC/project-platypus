/**
 * The host-injected API surface. Each shell (standalone Tauri viewer,
 * Project Platypus integration, dev fixture) implements this interface
 * with its own backing — the component itself is shell-agnostic.
 *
 * Methods marked optional are convenience hooks that the host can wire up
 * for richer integration (e.g. "jump to source" lands you in the Platypus
 * code editor when running embedded; just no-ops in the standalone viewer).
 */

import type { ActivitySummary, ActivityView, Theme } from "./types";

export interface ViewerApi {
  /** Display label for the loaded APK (package name, file name, etc.).
   *  Shown in the viewer header. */
  appLabel(): Promise<string>;

  /** List every activity discoverable in the loaded APK. The picker uses
   *  this to render the activity list. */
  listActivities(): Promise<ActivitySummary[]>;

  /** Get the rehydrated UnifiedView for one activity. Called when the
   *  user picks an activity in the picker, or on initial mount when the
   *  shell selects a default. */
  rehydrateActivity(name: string): Promise<ActivityView>;

  /** Optional — host-defined navigation. Called when the user clicks an
   *  activity link in the navigation graph (phase 8). The standalone
   *  viewer might just `selectActivity` internally; the Project Platypus
   *  integration might also open the activity's source in the code editor. */
  openActivity?(name: string): Promise<void>;

  /** Optional — jump to source of a specific method ref. Wired when the
   *  host provides a code editor (Project Platypus integration). The
   *  inspector uses this for click-handler / dynamic-modification jumps. */
  jumpToSource?(methodRef: string): Promise<void>;

  /** Optional — open a layout file in the host's code/resource viewer.
   *  Used by the "open source XML" action on the inspector header. */
  openLayoutFile?(path: string): Promise<void>;

  /** Optional — fetch the effective theme for an activity. Used by the
   *  HTML/CSS renderer ("R1") to resolve `?attr/colorPrimary` etc.
   *  Hosts that don't implement this fall back to bundled Material 3
   *  defaults inside the renderer. */
  theme?(activityName: string): Promise<Theme | null>;

  /** Optional — show an OS file dialog and load a dexmapper mapping.
   *  When wired, the shell renders a "Mapping" pill in the header that
   *  lets the user load / clear a deobfuscation mapping. While a mapping
   *  is loaded, host implementations of `rehydrateActivity()` should
   *  return IR with class and method names rewritten to their library
   *  originals. Returns the loaded mapping info, or `null` if the user
   *  cancelled the dialog. */
  loadMappingDialog?(): Promise<MappingInfo | null>;

  /** Optional — info about the currently-loaded mapping (or `null`). */
  currentMapping?(): Promise<MappingInfo | null>;

  /** Optional — drop the currently-loaded mapping. After this call,
   *  `rehydrateActivity()` should return raw (obfuscated) names. */
  clearMapping?(): Promise<void>;
}

/** Summary of a loaded dexmapper mapping. Shown in the header pill so the
 *  analyst can confirm what's loaded and how many entries it covers. */
export interface MappingInfo {
  /** Absolute path of the mapping file, or `null` if not loaded from disk. */
  path: string | null;
  /** Detected format — `"json"` or `"proguard"`. `null` when unknown. */
  format: string | null;
  classCount: number;
  methodCount: number;
  fieldCount: number;
}
