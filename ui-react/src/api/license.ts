// Offline license API — thin typed wrappers over the Tauri `license_*` commands,
// which delegate to the shared `platypus-license` Ed25519 verifier. Mirrors the
// `LicenseInfo` shape the Rust command emits (serde camelCase).
import { invoke } from "@tauri-apps/api/core";
import { useCallback, useEffect, useState } from "react";

export type LicenseStatus =
  | "valid"
  | "expired"
  | "not_yet_valid"
  | "machine_mismatch"
  | "bad_signature"
  | "malformed"
  | "missing";

export interface LicenseInfo {
  status: LicenseStatus;
  valid: boolean;
  id: string | null;
  name: string | null;
  email: string | null;
  plan: string | null;
  tier: string | null;
  seats: number | null;
  features: string[];
  /** Expiry, unix seconds; null = perpetual. */
  expires: number | null;
  /** Bound machine fingerprint; null = floating. */
  machine: string | null;
}

const isTauri = (): boolean =>
  typeof window !== "undefined" &&
  ("__TAURI_INTERNALS__" in window || "__TAURI__" in window);

/** What the UI shows before/without a Tauri backend (e.g. the web build). */
export const UNLICENSED: LicenseInfo = {
  status: "missing",
  valid: false,
  id: null,
  name: null,
  email: null,
  plan: null,
  tier: null,
  seats: null,
  features: [],
  expires: null,
  machine: null,
};

export const licenseApi = {
  /** Current status from disk. Never throws; returns `missing` off-Tauri. */
  async status(): Promise<LicenseInfo> {
    if (!isTauri()) return UNLICENSED;
    return invoke<LicenseInfo>("license_status");
  },
  /** Verify + persist a token. Rejects (throws the reason) when not valid. */
  async activate(token: string): Promise<LicenseInfo> {
    return invoke<LicenseInfo>("license_activate", { token });
  },
  /** Remove the stored license. */
  async deactivate(): Promise<void> {
    if (!isTauri()) return;
    await invoke("license_deactivate");
  },
  /** This machine's node-lock fingerprint, to include in a license request. */
  async machineFingerprint(): Promise<string | null> {
    if (!isTauri()) return null;
    return invoke<string | null>("machine_fingerprint");
  },
};

/** Client-side entitlement check (the backend re-checks for paid commands). */
export function hasFeature(info: LicenseInfo | null, feature: string): boolean {
  if (!info || !info.valid) return false;
  return info.features.includes("*") || info.features.includes(feature);
}

/** Subscribe a component to the current license status. */
export function useLicense() {
  const [info, setInfo] = useState<LicenseInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      setInfo(await licenseApi.status());
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  return { info, loading, refresh };
}
