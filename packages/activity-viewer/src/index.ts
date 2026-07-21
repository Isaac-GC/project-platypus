/**
 * Public surface of @platypus/activity-viewer.
 *
 * Consumers (standalone shell, Project Platypus integration, dev harness)
 * import from here:
 *
 * ```tsx
 * import { ViewerShell, type ViewerApi } from "@platypus/activity-viewer";
 * import "@platypus/activity-viewer/styles.css";
 * ```
 */

export { ViewerShell, DEVICE_PRESETS } from "./ViewerShell";
export type { ViewerShellProps, RendererKind, DevicePreset } from "./ViewerShell";

export type { ViewerApi, MappingInfo } from "./api";

// Re-export every IR type so consumers don't have to dig into ./types.
export type {
  ActivityView,
  ActivitySummary,
  Diagnostic,
  UnifiedView,
  ViewSource,
  ViewKind,
  Attribute,
  Handler,
  NavTarget,
  DynMod,
  Theme,
  StyleAttribute,
} from "./types";
export { findThemeAttr } from "./types";

// R1 — HTML/CSS renderer. Available standalone for hosts that want to
// embed the preview without the rest of the shell.
export { HtmlRenderer } from "./renderers/html/HtmlRenderer";
export type { HtmlRendererProps } from "./renderers/html/HtmlRenderer";

// R2 — Canvas renderer. Pixel-painted; no DOM elements per view.
export { CanvasRenderer } from "./renderers/canvas/CanvasRenderer";
export type { CanvasRendererProps } from "./renderers/canvas/CanvasRenderer";

// Cross-activity navigation graph (visualises Phase 8's outgoingNavigations).
export { GraphRenderer } from "./renderers/graph/GraphRenderer";
export type { GraphRendererProps } from "./renderers/graph/GraphRenderer";

// The individual sub-components — exported so embedders can compose
// custom layouts (e.g. the Project Platypus integration may choose to
// embed only the TreeView in an existing panel).
export { ActivityPicker } from "./components/ActivityPicker";
export type { ActivityPickerProps } from "./components/ActivityPicker";
export { TreeView } from "./components/TreeView";
export type { TreeViewProps, TreePath } from "./components/TreeView";
export { AttributePane } from "./components/AttributePane";
export type { AttributePaneProps } from "./components/AttributePane";

// Dexmapper mapping toolbar control — host-agnostic; wired by each shell
// to its own Tauri `load_mapping_dialog` / `clear_mapping` commands.
export { MappingControl } from "./components/MappingControl";
export type { MappingControlProps } from "./components/MappingControl";
