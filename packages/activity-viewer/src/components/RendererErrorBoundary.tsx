/**
 * Wraps a renderer (HTML / Canvas / Graph) in a React error boundary.
 *
 * Renderers walk DEX-derived IR — occasional malformed nodes or missing
 * fields shouldn't take the whole shell down. The boundary catches errors,
 * logs them, and shows a banner with the message so the user can switch
 * renderers / pick another activity instead of seeing a blank crash page.
 */

import React from "react";

interface State {
  err: Error | null;
}

export interface RendererErrorBoundaryProps {
  /** Reset the boundary when this key changes — re-mount the inner tree
   *  so a fresh activity selection escapes a previous render's failure. */
  resetKey?: string | number | null;
  children: React.ReactNode;
}

export class RendererErrorBoundary
  extends React.Component<RendererErrorBoundaryProps, State> {
  state: State = { err: null };

  static getDerivedStateFromError(err: Error): State {
    return { err };
  }

  componentDidCatch(err: Error, info: React.ErrorInfo): void {
    // Eslint-style noise — visible in the dev console but not user-facing.
    // The banner below is the user-facing surface.
    console.error("[ActivityViewer] renderer crashed:", err, info.componentStack);
  }

  componentDidUpdate(prev: RendererErrorBoundaryProps): void {
    if (this.state.err !== null && prev.resetKey !== this.props.resetKey) {
      this.setState({ err: null });
    }
  }

  render(): React.ReactNode {
    if (this.state.err) {
      return (
        <div className="pap-renderer pap-renderer--empty">
          <div style={{
            maxWidth: 480,
            padding: 16,
            background: "rgba(244, 135, 113, 0.08)",
            border: "1px solid var(--pap-error)",
            borderRadius: 4,
            color: "var(--pap-text)",
          }}>
            <div style={{
              color: "var(--pap-error)",
              fontWeight: 600,
              marginBottom: 8,
              fontSize: 13,
            }}>
              Renderer crashed
            </div>
            <div style={{
              fontFamily: "var(--pap-font-mono)",
              fontSize: 11,
              color: "var(--pap-muted)",
              wordBreak: "break-word",
              whiteSpace: "pre-wrap",
            }}>
              {this.state.err.message || String(this.state.err)}
            </div>
            <div style={{
              marginTop: 12,
              fontSize: 11,
              color: "var(--pap-muted)",
            }}>
              Try switching to a different renderer (Tree mode always works),
              or pick another activity. Full stack trace is in the dev console.
            </div>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
