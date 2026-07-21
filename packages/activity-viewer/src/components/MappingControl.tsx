/**
 * MappingControl — host-agnostic UI for loading/clearing a dexmapper
 * deobfuscation mapping.
 *
 * The component is purely presentational: the host wires up the actual
 * Tauri (or other) calls and feeds back the current `MappingInfo`. Both
 * shells (standalone-viewer, ui-react) use this so the badge looks
 * identical in either context.
 *
 * Renders one of two states:
 *
 *   [Load mapping…]                   when `info == null`
 *   [ 🧬 15 cls · 149 m ] [Clear]     when `info != null`
 */

import React from "react";

import type { MappingInfo } from "../api";

export interface MappingControlProps {
  /** Currently-loaded mapping summary; `null`/`undefined` when none. */
  info: MappingInfo | null | undefined;
  /** Called when the user clicks "Load mapping…". Should open a file
   *  dialog and (if confirmed) call the host's `load_mapping_dialog`
   *  Tauri command, then refresh `info`. */
  onLoad: () => void;
  /** Called when the user clicks "Clear". */
  onClear: () => void;
  /** Optional — busy state to disable buttons while a load is in flight. */
  busy?: boolean;
}

export const MappingControl: React.FC<MappingControlProps> = ({
  info, onLoad, onClear, busy = false,
}) => {
  if (!info) {
    return (
      <button
        className="pap-header__action"
        onClick={onLoad}
        disabled={busy}
        title="Load a dexmapper mapping file (JSON or ProGuard) to deobfuscate class and method names in this view."
      >
        {busy ? "Loading…" : "Load mapping…"}
      </button>
    );
  }
  const tip = [
    info.path ? `path: ${info.path}` : null,
    info.format ? `format: ${info.format}` : null,
    `${info.classCount} classes · ${info.methodCount} methods · ${info.fieldCount} fields`,
    "Class and method names below are deobfuscated through this mapping.",
  ].filter(Boolean).join("\n");
  return (
    <span className="pap-header__mapping" title={tip}>
      <span
        className="pap-header__mapping-pill"
        aria-label="Mapping loaded"
      >
        🧬 {info.classCount}c · {info.methodCount}m
      </span>
      <button
        className="pap-header__action pap-header__mapping-clear"
        onClick={onClear}
        disabled={busy}
        title="Drop the mapping and show raw obfuscated names again."
      >
        Clear
      </button>
    </span>
  );
};
