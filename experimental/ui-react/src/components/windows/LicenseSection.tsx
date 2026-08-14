import React, { useEffect, useState } from "react";
import {
  licenseApi,
  useLicense,
  type LicenseInfo,
  type LicenseStatus,
} from "../../api/license";

// Mirrors the local Section heading in SettingsWindow so the License block
// looks native to the settings panel.
const Section: React.FC<{ title: string; children: React.ReactNode }> = ({ title, children }) => (
  <div className="mb-5">
    <div className="text-xs font-semibold text-vs-accent uppercase tracking-wider mb-2 pb-1 border-b border-vs-border">
      {title}
    </div>
    <div className="space-y-3">{children}</div>
  </div>
);

const STATUS_LABEL: Record<LicenseStatus, string> = {
  valid: "Active",
  expired: "Expired",
  not_yet_valid: "Not yet valid",
  machine_mismatch: "Wrong machine",
  bad_signature: "Invalid signature",
  malformed: "Malformed key",
  missing: "Unlicensed",
};

// emerald = good, amber = authentic-but-unusable, red = junk/none.
function statusColor(s: LicenseStatus): string {
  if (s === "valid") return "text-emerald-400 border-emerald-400/40 bg-emerald-400/10";
  if (s === "expired" || s === "machine_mismatch" || s === "not_yet_valid")
    return "text-amber-400 border-amber-400/40 bg-amber-400/10";
  return "text-vs-error border-vs-error/40 bg-vs-error/10";
}

const Badge: React.FC<{ status: LicenseStatus }> = ({ status }) => (
  <span className={`px-2 py-0.5 rounded-full text-[11px] border ${statusColor(status)}`}>
    {STATUS_LABEL[status]}
  </span>
);

function fmtExpiry(info: LicenseInfo): string {
  if (info.expires == null) return "Perpetual";
  const d = new Date(info.expires * 1000);
  return d.toLocaleDateString();
}

const LicenseSection: React.FC = () => {
  const { info, refresh } = useLicense();
  const [fingerprint, setFingerprint] = useState<string | null>(null);
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    void licenseApi.machineFingerprint().then(setFingerprint);
  }, []);

  const activate = async () => {
    setBusy(true);
    setError(null);
    try {
      await licenseApi.activate(token.trim());
      setToken("");
      await refresh();
    } catch (e) {
      // Tauri rejects with the backend's human-readable reason string.
      setError(typeof e === "string" ? e : String(e));
    } finally {
      setBusy(false);
    }
  };

  const deactivate = async () => {
    setBusy(true);
    setError(null);
    try {
      await licenseApi.deactivate();
      await refresh();
    } finally {
      setBusy(false);
    }
  };

  const copyFingerprint = async () => {
    if (!fingerprint) return;
    await navigator.clipboard.writeText(fingerprint);
    setCopied(true);
    setTimeout(() => setCopied(false), 1200);
  };

  const licensed = info?.valid ?? false;
  // A token is on disk (active or not) whenever we got authentic claims back.
  const hasToken = !!info && info.status !== "missing" && info.id != null;

  return (
    <Section title="License">
      {/* Current status */}
      <div className="flex items-center justify-between gap-4">
        <div className="flex-1 min-w-0">
          <div className="text-xs text-vs-text flex items-center gap-2">
            Status {info && <Badge status={info.status} />}
          </div>
          {licensed && info && (
            <div className="text-xs text-vs-dim mt-0.5 truncate">
              {info.name} · {info.tier} · {info.plan} · expires {fmtExpiry(info)}
            </div>
          )}
          {licensed && info && info.features.length > 0 && (
            <div className="text-[11px] text-vs-dim mt-0.5 truncate">
              Features: {info.features.join(", ")}
            </div>
          )}
        </div>
        {hasToken && (
          <button
            onClick={deactivate}
            disabled={busy}
            className="px-2.5 py-1 rounded text-xs border border-vs-border text-vs-text hover:border-vs-error hover:text-vs-error disabled:opacity-40 disabled:cursor-not-allowed transition-colors flex-shrink-0"
          >
            Remove
          </button>
        )}
      </div>

      {/* Activation — hidden once a valid license is active */}
      {!licensed && (
        <div className="space-y-2">
          <div className="text-xs text-vs-text">Activate a license key</div>
          <textarea
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder="PLT1.…"
            spellCheck={false}
            rows={3}
            className="w-full resize-none bg-vs-bg border border-vs-border rounded px-2 py-1.5 text-[11px] font-mono text-vs-text focus:outline-none focus:border-vs-accent break-all"
          />
          {error && <div className="text-[11px] text-vs-error">{error}</div>}
          <div className="flex justify-end">
            <button
              onClick={activate}
              disabled={busy || token.trim().length === 0}
              className="px-3 py-1.5 rounded text-xs bg-vs-accent text-white hover:opacity-90 disabled:opacity-40 disabled:cursor-not-allowed transition-opacity"
            >
              {busy ? "Verifying…" : "Activate"}
            </button>
          </div>
        </div>
      )}

      {/* Machine fingerprint — needed to request a node-locked key */}
      {fingerprint && (
        <div className="flex items-center justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="text-xs text-vs-text">Machine ID</div>
            <div className="text-[11px] text-vs-dim mt-0.5 font-mono truncate">{fingerprint}</div>
          </div>
          <button
            onClick={copyFingerprint}
            className="px-2.5 py-1 rounded text-xs border border-vs-border text-vs-text hover:border-vs-accent hover:text-vs-accent transition-colors flex-shrink-0"
          >
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
      )}
    </Section>
  );
};

export default LicenseSection;
