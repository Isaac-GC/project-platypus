import React, { useEffect, useRef, useState } from "react";
import { useAppStore } from "../../store/appStore";
import { DEFAULT_SETTINGS } from "../../api/types";
import LicenseSection from "./LicenseSection";
import { checkForUpdates, type UpdateStatus } from "../../utils/updater";

// ─── Section heading ──────────────────────────────────────────────────────────

const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="mb-5">
    <div className="text-xs font-semibold text-vs-accent uppercase tracking-wider mb-2 pb-1 border-b border-vs-border">
      {title}
    </div>
    <div className="space-y-3">{children}</div>
  </div>
);

// ─── Row ──────────────────────────────────────────────────────────────────────

const Row: React.FC<{ label: string; hint?: string; children: React.ReactNode }> = ({
  label,
  hint,
  children,
}) => (
  <div className="flex items-center justify-between gap-4">
    <div className="flex-1 min-w-0">
      <div className="text-xs text-vs-text">{label}</div>
      {hint && <div className="text-xs text-vs-dim mt-0.5">{hint}</div>}
    </div>
    <div className="flex-shrink-0">{children}</div>
  </div>
);

// ─── Toggle ───────────────────────────────────────────────────────────────────

const Toggle: React.FC<{ value: boolean; onChange: (v: boolean) => void }> = ({
  value,
  onChange,
}) => (
  <button
    role="switch"
    aria-checked={value}
    onClick={() => onChange(!value)}
    className={[
      "relative inline-flex h-5 w-9 items-center rounded-full transition-colors",
      value ? "bg-vs-accent" : "bg-vs-border",
    ].join(" ")}
  >
    <span
      className={[
        "inline-block h-3.5 w-3.5 rounded-full bg-white shadow transition-transform",
        value ? "translate-x-[18px]" : "translate-x-[2px]",
      ].join(" ")}
    />
  </button>
);

// ─── SettingsWindow ───────────────────────────────────────────────────────────

const SettingsWindow: React.FC = () => {
  const closeSettingsWindow = useAppStore((s) => s.closeSettingsWindow);
  const settings = useAppStore((s) => s.settings);
  const updateSetting = useAppStore((s) => s.updateSetting);
  const resetSettings = useAppStore((s) => s.resetSettings);
  const clearDeobf = useAppStore((s) => s.clearDeobf);
  const clearRenames = useAppStore((s) => s.clearRenames);
  const renames = useAppStore((s) => s.renames);
  const deobfReplacements = useAppStore((s) => s.deobfReplacements);

  const overlayRef = useRef<HTMLDivElement>(null);

  // Close on Escape
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") closeSettingsWindow();
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [closeSettingsWindow]);

  const deobfCount = Object.keys(deobfReplacements).length;
  const renameCount = renames.length;

  return (
    /* Backdrop */
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={(e) => {
        if (e.target === overlayRef.current) closeSettingsWindow();
      }}
    >
      {/* Panel */}
      <div className="w-[480px] max-h-[80vh] flex flex-col bg-vs-elevated border border-vs-border rounded-lg shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-vs-border flex-shrink-0">
          <span className="text-sm font-semibold text-vs-text">⚙️ Settings</span>
          <button
            onClick={closeSettingsWindow}
            className="text-vs-dim hover:text-vs-text text-lg leading-none"
            title="Close"
          >
            ×
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 overflow-y-auto px-4 py-4 text-sm">

          {/* ── Editor ────────────────────────────────────────────── */}
          <Section title="Editor">
            <Row label="Default language" hint="Language used when first opening a class">
              <select
                value={settings.defaultLanguage}
                onChange={(e) =>
                  updateSetting("defaultLanguage", e.target.value as "smali" | "java")
                }
                className="bg-vs-bg border border-vs-border rounded px-2 py-1 text-xs text-vs-text focus:outline-none focus:border-vs-accent"
              >
                <option value="java">Java</option>
                <option value="smali">Smali</option>
              </select>
            </Row>

            <Row label="Font size" hint={`${settings.fontSize}px`}>
              <div className="flex items-center gap-2">
                <input
                  type="range"
                  min={11}
                  max={18}
                  step={1}
                  value={settings.fontSize}
                  onChange={(e) => updateSetting("fontSize", Number(e.target.value))}
                  className="w-28 accent-vs-accent"
                />
                <span className="text-xs text-vs-muted w-8 text-right">{settings.fontSize}px</span>
              </div>
            </Row>

            <Row label="Font family">
              <select
                value={settings.fontFamily}
                onChange={(e) => updateSetting("fontFamily", e.target.value)}
                className="bg-vs-bg border border-vs-border rounded px-2 py-1 text-xs text-vs-text focus:outline-none focus:border-vs-accent max-w-[220px] truncate"
              >
                <option value="ui-monospace, SFMono-Regular, Menlo, monospace">
                  System Mono (default)
                </option>
                <option value="'JetBrains Mono', monospace">JetBrains Mono</option>
                <option value="'Fira Code', monospace">Fira Code</option>
                <option value="'Cascadia Code', monospace">Cascadia Code</option>
                <option value="'Source Code Pro', monospace">Source Code Pro</option>
                <option value="'Courier New', monospace">Courier New</option>
                <option value="monospace">Generic Monospace</option>
              </select>
            </Row>

            <Row label="Show line numbers">
              <Toggle
                value={settings.showLineNumbers}
                onChange={(v) => updateSetting("showLineNumbers", v)}
              />
            </Row>

            <Row
              label="Deobfuscation view"
              hint={
                settings.deobfViewMode === "annotated"
                  ? "Original code with `# DEOBF: …` overlay comments"
                  : "Inline-substitute deobf calls with literal values, original commented above"
              }
            >
              <select
                value={settings.deobfViewMode}
                onChange={(e) =>
                  updateSetting(
                    "deobfViewMode",
                    e.target.value as "annotated" | "substituted",
                  )
                }
                className="bg-vs-elevated border border-vs-border rounded px-2 py-1 text-xs text-vs-text"
              >
                <option value="annotated">Annotated</option>
                <option value="substituted">Substituted</option>
              </select>
            </Row>

            <Row
              label="Keep Kotlin intrinsics"
              hint={
                settings.keepKotlinIntrinsics
                  ? "Showing Kotlin runtime null-checks (Intrinsics.checkNotNullParameter, etc) in decompiled Java"
                  : "Filtered out — JADX-style clean output. Toggle on to surface them for review."
              }
            >
              <Toggle
                value={settings.keepKotlinIntrinsics}
                onChange={(v) => updateSetting("keepKotlinIntrinsics", v)}
              />
            </Row>
          </Section>

          {/* ── Navigation ────────────────────────────────────────── */}
          <Section title="Navigation">
            <Row
              label="Open on single click"
              hint="If off, single-click only selects; double-click opens"
            >
              <Toggle
                value={settings.openOnSingleClick}
                onChange={(v) => updateSetting("openOnSingleClick", v)}
              />
            </Row>

            <Row
              label="Group classes by"
              hint={
                settings.treeGroupBy === "dexfile"
                  ? "Tree mirrors the APK layout — one branch per classesN.dex"
                  : "All packages collapsed into one tree; classes from every DEX shown side-by-side"
              }
            >
              <select
                value={settings.treeGroupBy}
                onChange={(e) =>
                  updateSetting(
                    "treeGroupBy",
                    e.target.value as "dexfile" | "merged",
                  )
                }
                className="bg-vs-elevated border border-vs-border rounded px-2 py-1 text-xs text-vs-text"
              >
                <option value="dexfile">Source file (per DEX)</option>
                <option value="merged">All classes (merged)</option>
              </select>
            </Row>
          </Section>

          {/* ── Cache ─────────────────────────────────────────────── */}
          <Section title="Cache & Data">
            <Row
              label="Deobfuscation replacements"
              hint={`${deobfCount} active replacement${deobfCount !== 1 ? "s" : ""}`}
            >
              <button
                onClick={clearDeobf}
                disabled={deobfCount === 0}
                className="px-2.5 py-1 rounded text-xs border border-vs-border text-vs-text hover:border-vs-error hover:text-vs-error disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Clear
              </button>
            </Row>

            <Row
              label="Method renames"
              hint={`${renameCount} rename${renameCount !== 1 ? "s" : ""} stored`}
            >
              <button
                onClick={clearRenames}
                disabled={renameCount === 0}
                className="px-2.5 py-1 rounded text-xs border border-vs-border text-vs-text hover:border-vs-error hover:text-vs-error disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
              >
                Clear
              </button>
            </Row>
          </Section>

          {/* ── License ───────────────────────────────────────────── */}
          <LicenseSection />

          {/* ── Updates ───────────────────────────────────────────── */}
          <UpdateSection />

        </div>

        {/* Footer */}
        <div className="flex items-center justify-between px-4 py-3 border-t border-vs-border flex-shrink-0">
          <button
            onClick={resetSettings}
            className="text-xs text-vs-dim hover:text-vs-text transition-colors"
            title="Restore all settings to their default values"
          >
            Reset to defaults
          </button>
          <button
            onClick={closeSettingsWindow}
            className="px-3 py-1.5 rounded text-xs bg-vs-accent text-white hover:opacity-90 transition-opacity"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

export default SettingsWindow;

// ─── Update section ───────────────────────────────────────────────────────────

/** Settings card surfacing the self-update flow. The background launch
 *  check happens in `App.tsx`; this section is the manual escape hatch
 *  + a place to read the most recent check's status. */
const UpdateSection: React.FC = () => {
  const [status, setStatus] = useState<UpdateStatus | null>(null);
  const [busy, setBusy] = useState(false);

  const onCheck = async () => {
    setBusy(true);
    setStatus(null);
    const result = await checkForUpdates({
      silent: false, force: true, onStatus: setStatus,
    });
    setBusy(false);
    if (result.kind === "current") {
      setStatus({ kind: "current", current: result.current });
    }
  };

  const label = busy
    ? "Checking…"
    : (!status || status.kind === "skipped" ? "Check for updates" : statusLabel(status));

  return (
    <Section title="Updates">
      <Row
        label="Current version"
        hint={status?.kind === "current"
          ? `Latest available: ${status.current}`
          : "Click to check for a newer release"}
      >
        <button
          onClick={onCheck}
          disabled={busy}
          className="px-2.5 py-1 rounded text-xs border border-vs-border text-vs-text hover:border-vs-accent hover:text-vs-accent disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          title={status?.kind === "error" ? status.message : undefined}
        >
          {label}
        </button>
      </Row>
    </Section>
  );
};

function statusLabel(s: UpdateStatus): string {
  switch (s.kind) {
    case "current":     return "Up to date";
    case "deferred":    return `${s.available} ready`;
    case "downloading": return s.total
      ? `Downloading ${Math.round((s.downloaded / s.total) * 100)}%`
      : "Downloading…";
    case "installing":  return "Installing…";
    case "installed":   return `Installed ${s.available} — restarting`;
    case "error":       return "Failed";
    case "skipped":     return "Check for updates";
  }
}
