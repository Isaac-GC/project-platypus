/**
 * Right pane — attribute inspector for the selected node.
 *
 * Three sections:
 *   1. Identity   — tag, kind, id, source
 *   2. Attributes — every (name, value) with origin badge for non-static
 *   3. Behaviour  — click handler, navigation, dynamic modifications
 *                   (populated by phase 7-9)
 */

import React from "react";
import type { UnifiedView, Attribute } from "../types";

export interface AttributePaneProps {
  node: UnifiedView | null;
  /** Optional — host hook for "jump to source" on method refs. */
  onJumpToSource?: (methodRef: string) => void;
  /** Optional — host hook for navigating to a target activity. Wired to
   *  the navigation target row so analysts can hop across the graph. */
  onOpenActivity?: (activityName: string) => void;
}

export const AttributePane: React.FC<AttributePaneProps> = ({
  node, onJumpToSource, onOpenActivity,
}) => {
  if (!node) {
    return (
      <div className="pap-attrs">
        <div className="pap-attrs__header">
          <div className="pap-attrs__title">No view selected</div>
          <div className="pap-attrs__subtitle">
            Click a node in the tree to inspect its attributes.
          </div>
        </div>
      </div>
    );
  }

  // Group attributes by namespace for readability.
  const grouped = groupAttributes(node.attrs);

  return (
    <div className="pap-attrs">
      <div className="pap-attrs__header">
        <div className="pap-attrs__title">
          {node.tag}{node.id ? ` #${node.id}` : ""}
        </div>
        <div className="pap-attrs__subtitle">
          {node.kind.kind}
          {"className" in node.kind && node.kind.className
            ? ` · ${node.kind.className}`
            : ""}
        </div>
      </div>

      <div className="pap-attrs__body">
        {/* ── Source ── */}
        <div className="pap-attrs__section">Source</div>
        <div className="pap-attrs__row">
          <span className="pap-attrs__row-name">origin</span>
          <span className="pap-attrs__row-value" title={describeSource(node.source)}>
            {node.source.kind}
          </span>
        </div>
        {sourceDetails(node).map(([k, v]) => (
          <div className="pap-attrs__row" key={k}>
            <span className="pap-attrs__row-name">{k}</span>
            <span className="pap-attrs__row-value" title={v}>{v}</span>
          </div>
        ))}

        {/* ── Attributes (grouped by namespace) ── */}
        {Object.entries(grouped).map(([ns, attrs]) => (
          <React.Fragment key={ns}>
            <div className="pap-attrs__section">
              {ns === "" ? "Attributes (no namespace)" : `${ns}:`}
              {" "}
              <span style={{ opacity: 0.5, fontWeight: 400 }}>({attrs.length})</span>
            </div>
            {attrs.map((a, i) => (
              <div className="pap-attrs__row" key={i}>
                <span className="pap-attrs__row-name" title={a.name}>
                  {stripNamespace(a.name)}
                </span>
                <span className="pap-attrs__row-value" title={a.value}>
                  {a.value || <em style={{ opacity: 0.4 }}>empty</em>}
                  {a.origin.kind !== "static" && (
                    <span
                      className={`pap-attrs__origin-badge pap-attrs__origin-badge--${a.origin.kind}`}
                      title={`Set ${a.origin.kind}ally`}
                    >
                      {a.origin.kind}
                    </span>
                  )}
                </span>
              </div>
            ))}
          </React.Fragment>
        ))}

        {/* ── Behaviour (phases 7-9) ── */}
        {(node.clickHandler || node.navigation
          || node.dynamicModifications.length > 0) && (
          <>
            <div className="pap-attrs__section">Behaviour</div>
            {node.clickHandler && (
              <div className="pap-attrs__row">
                <span className="pap-attrs__row-name">
                  {clickHandlerLabel(node.clickHandler.kind)}
                </span>
                <span
                  className="pap-attrs__row-value"
                  style={onJumpToSource ? { cursor: "pointer", textDecoration: "underline" } : {}}
                  onClick={() => onJumpToSource?.(node.clickHandler!.target)}
                  title={`${node.clickHandler.kind}: ${node.clickHandler.target}`}
                >
                  {node.clickHandler.target}
                  <span className={`pap-attrs__origin-badge pap-attrs__origin-badge--${
                    node.clickHandler.kind === "xmlOnClick" ? "style" : "dynamic"
                  }`}>
                    {node.clickHandler.kind === "xmlOnClick" ? "XML" : "DEX"}
                  </span>
                </span>
              </div>
            )}
            {node.navigation && (
              <div className="pap-attrs__row">
                <span className="pap-attrs__row-name">→ navigates</span>
                <span
                  className="pap-attrs__row-value"
                  style={onOpenActivity && isJumpableNav(node.navigation)
                    ? { cursor: "pointer", textDecoration: "underline" }
                    : {}}
                  onClick={() => {
                    if (onOpenActivity && isJumpableNav(node.navigation!)) {
                      onOpenActivity(node.navigation!.target);
                    }
                  }}
                  title={`${node.navigation.kind}: ${node.navigation.target}`}
                >
                  {node.navigation.target}
                  <span className="pap-attrs__origin-badge"
                        style={{ background: "var(--pap-accent)", color: "#fff" }}>
                    {node.navigation.kind}
                  </span>
                </span>
              </div>
            )}
            {node.dynamicModifications.map((m, i) => (
              <div className="pap-attrs__row" key={i}>
                <span className="pap-attrs__row-name">{m.setter}</span>
                <span
                  className="pap-attrs__row-value"
                  style={onJumpToSource && !m.literal ? { cursor: "pointer", textDecoration: "underline" } : {}}
                  onClick={() => !m.literal && onJumpToSource?.(m.fromMethod)}
                  title={m.literal
                    ? `${m.fromMethod}: literal`
                    : `from ${m.fromMethod}`}
                >
                  {m.literal ? `"${m.value}"` : m.value}
                  {!m.literal && (
                    <span className="pap-attrs__origin-badge pap-attrs__origin-badge--dynamic">
                      derived
                    </span>
                  )}
                </span>
              </div>
            ))}
          </>
        )}
      </div>
    </div>
  );
};

// ─── Helpers ───────────────────────────────────────────────────────────────

function groupAttributes(attrs: Attribute[]): Record<string, Attribute[]> {
  const out: Record<string, Attribute[]> = {};
  for (const a of attrs) {
    const colon = a.name.indexOf(":");
    const ns = colon > 0 ? a.name.slice(0, colon) : "";
    if (!out[ns]) out[ns] = [];
    out[ns].push(a);
  }
  // Re-order: android first, then app, then others
  const keys = Object.keys(out).sort((a, b) => {
    const order = (n: string) =>
      n === "android" ? 0 : n === "app" ? 1 : n === "" ? 3 : 2;
    return order(a) - order(b);
  });
  const reordered: Record<string, Attribute[]> = {};
  for (const k of keys) reordered[k] = out[k];
  return reordered;
}

function stripNamespace(name: string): string {
  const colon = name.indexOf(":");
  return colon > 0 ? name.slice(colon + 1) : name;
}

function sourceDetails(node: UnifiedView): Array<[string, string]> {
  const s = node.source;
  switch (s.kind) {
    case "xml":          return [["layoutPath", s.layoutPath]];
    case "included":     return [
      ["from", s.fromLayoutPath],
      ["included", s.includedLayoutPath],
    ];
    case "merged":       return [["from", s.fromLayoutPath]];
    case "stubInflated": return [
      ["stub", s.stubLayoutPath],
      ["target", s.targetLayoutPath],
    ];
    case "compose":      return [["method", s.methodRef]];
    case "synthetic":    return [];
  }
}

function describeSource(s: UnifiedView["source"]): string {
  switch (s.kind) {
    case "xml":          return `XML: ${s.layoutPath}`;
    case "included":     return `<include> from ${s.fromLayoutPath} → ${s.includedLayoutPath}`;
    case "merged":       return `<merge> flattened from ${s.fromLayoutPath}`;
    case "stubInflated": return `<ViewStub> in ${s.stubLayoutPath} → ${s.targetLayoutPath}`;
    case "compose":      return `Compose: ${s.methodRef}`;
    case "synthetic":    return "synthetic placeholder";
  }
}

function clickHandlerLabel(kind: "xmlOnClick" | "codeOnClickListener" | "codeOnLongClickListener"): string {
  switch (kind) {
    case "xmlOnClick":               return "click (xml)";
    case "codeOnClickListener":      return "click";
    case "codeOnLongClickListener":  return "long click";
  }
}

/** Only `startActivity` / `startActivityForResult` give us a clean
 *  activity FQN to jump to. Fragment swaps and NavController destinations
 *  point at things the host shell can't necessarily resolve. */
function isJumpableNav(nav: { kind: string }): boolean {
  return nav.kind === "startActivity" || nav.kind === "startActivityForResult";
}
