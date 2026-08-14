# Licensing

Project Platypus uses **offline, node-locked** licensing: one Ed25519-signed
token verifies in every client with no network call. It's built for the way the
tool is actually used — on air-gapped analysis VMs — so there is deliberately no
phone-home check.

One license, three verifiers:

| Surface | Code | Library |
|---|---|---|
| Tauri desktop app (`ui-react`) | `rust/platypus-license` + `ui-react/src-tauri/src/license.rs` (`license_*` commands) | `ed25519-dalek` (verify), `machine-uid` (node-lock) |
| `platypus` Python native module | `platypus.license` (PyO3, re-uses the crate) | `ed25519-dalek` via PyO3 |
| Pure-Python tooling | `licensing/` package | PyNaCl (`nacl.signing`) |

All three implement the same `PLT1` token format and embed the same public key,
so a token issued once works everywhere. Cross-library interop is covered by
`cargo test -p platypus-license` and `pytest tests/test_licensing.py`.

For the package-level quick reference see
[`licensing/README.md`](../licensing/README.md); this is the operator + developer
runbook.

---

## 1. How it works

The vendor holds an Ed25519 **private** key offline and signs a token per
customer. Every client embeds only the matching **public** key
(`VENDOR_PUBLIC_KEY_HEX`) and verifies tokens locally. A token can be bound to
one machine (node-lock), carry an expiry, a tier, and a set of **feature**
entitlements that gate individual tools.

```text
vendor (offline)                          client (offline)
────────────────                          ────────────────
private seed ──sign(claims)──▶  PLT1 token ──▶  embedded public key
  licensing.keygen                               verify signature
                                                 check expiry + clock skew
                                                 check machine fingerprint
                                                 ──▶ Valid / Expired / …
```

### Token format — `PLT1`

```text
PLT1.<base64url(payload_json)>.<base64url(ed25519_sig)>
```

* `PLT1` pins both the version **and** the algorithm (Ed25519). There is no
  JWT-style `alg` field, so algorithm-substitution attacks are impossible.
* The signature covers the ASCII bytes `"PLT1." + base64url(payload)` — the
  prefix is part of the signed message, so it can't be stripped or downgraded.
* Verification runs over the *encoded* payload segment, not re-serialized JSON,
  so the Rust and Python verifiers never have to agree on JSON canonicalization.

### Claims

The payload (`Claims` in `platypus-license/src/lib.rs`):

| Field | Meaning |
|---|---|
| `id` | Unique license id, e.g. `PLAT-0001`. |
| `name` / `email` | Licensee. |
| `plan` | `perpetual` \| `subscription` \| `trial`. |
| `tier` | `community` \| `pro` \| `enterprise`. |
| `seats` | Max concurrent activations (informational on the client). |
| `features` | Entitlement keys gating tools, e.g. `["unpacker","taint"]`. `"*"` grants all. |
| `issued` | Issued-at, unix seconds. |
| `expires` | Expiry, unix seconds. `null` = perpetual. |
| `machine` | Bound machine fingerprint. `null` = floating (any machine). |

### Verification outcomes (`Status`)

Signature/structural failures take precedence over policy failures — claims are
only trusted once the signature verifies, so `expired` is only ever returned for
an *authentic* token.

| Status | Meaning |
|---|---|
| `valid` | Authentic, in-date, and (if node-locked) on the right machine. **Only this unlocks paid functionality.** |
| `expired` | Authentic, but `expires` is in the past. |
| `not_yet_valid` | Authentic, but `issued` is in the future beyond the 300s clock-skew allowance. |
| `machine_mismatch` | Authentic, but bound to a different machine. |
| `bad_signature` | Signature did not verify against the vendor key. |
| `malformed` | Bad prefix / base64 / JSON. |
| `missing` | No token supplied. |

Even for `expired` / `machine_mismatch`, the decoded claims are returned so the
UI can show *whose* license it is.

---

## 2. Issuing licenses (vendor side)

The signing path is in the `licensing/` Python package (PyNaCl). In the Rust
crate it's gated behind the `sign` feature, which is **off by default** so the
shipped client only ever carries the verifier and the public key — never code
that touches a private key.

### One-time: generate the signing keypair

```bash
python -m licensing.keygen gen-keypair
# -> SEED_HEX=...        (the private seed — keep OFFLINE)
# -> PUBLIC_KEY_HEX=...  (the public half)
```

Put `PUBLIC_KEY_HEX` in **two** places so every client trusts it:

- `licensing/_pubkey.py` → `VENDOR_PUBLIC_KEY_HEX`
- `rust/platypus-license/src/lib.rs` → `VENDOR_PUBLIC_KEY_HEX`

Keep `SEED_HEX` offline (a password manager or HSM). The repo ships a demo seed
at `licensing/keys/vendor_seed.hex` (git-ignored) — **replace it for
production**; anyone with the seed can mint licenses your clients will accept.

### Issue a token

```bash
SEED=$(cat licensing/keys/vendor_seed.hex)

# Perpetual Pro license, locked to one machine
python -m licensing.keygen sign --seed "$SEED" \
    --id PLAT-0001 --name "Acme RE" --email re@acme.io \
    --tier pro --features unpacker,taint,codegen,deobf \
    --machine <FINGERPRINT>

# 1-year floating subscription with all features
python -m licensing.keygen sign --seed "$SEED" \
    --id PLAT-0002 --name "Acme RE" --email re@acme.io \
    --plan subscription --expires-days 365 --features '*'

# Inspect / debug
python -m licensing.keygen verify <TOKEN>
python -m licensing.keygen fingerprint     # this machine's node-lock id
```

`sign` flags: `--plan` (`perpetual`|`subscription`|`trial`), `--tier`
(`community`|`pro`|`enterprise`), `--seats`, `--features` (comma list or `*`),
`--expires-days` (omit = perpetual), `--machine` (a fingerprint, or `-` to lock
to the issuing machine). The `<FINGERPRINT>` comes from the customer — see §3.

### Rotating the key

Replace `VENDOR_PUBLIC_KEY_HEX` in both clients and re-issue tokens. Clients
built against the old key reject the new tokens (and vice-versa), so roll out the
new client build *before* issuing new-key tokens. Because the two Tauri apps and
the Python module share one key, rotation is a coordinated release.

---

## 3. Activating (customer side)

### Desktop app

Settings → **License** → paste the key → **Activate**. The token is verified and,
on a `valid` outcome, written verbatim to `<os-cache>/project_platypus/license.plt`.
It's a signed, tamper-evident blob, so plain-text-on-disk is fine — editing it
just makes verification fail.

The same panel shows the **Machine ID** (node-lock fingerprint) to send when
requesting a node-locked key.

Backing commands (`ui-react/src-tauri/src/license.rs`), wrapped by
`ui-react/src/api/license.ts`:

| Command | Purpose |
|---|---|
| `license_status` | Current status from disk (never errors; `missing` if absent). |
| `license_activate(token)` | Verify + persist; rejects with a human reason if not `valid`. |
| `license_deactivate` | Remove the stored license (idempotent). |
| `machine_fingerprint` | This machine's node-lock id. |

### Python

```python
from licensing import verify_license

lic = verify_license(open("license.plt").read())
if lic.valid and lic.has_feature("unpacker"):
    ...
```

The compiled native module exposes the same surface at `platypus.license`
(`platypus.license.verify(token)`, `platypus.license.machine_fingerprint()`).

### Machine fingerprint

`sha256(normalise(os_machine_id))[:16]` as lowercase hex (32 chars). The raw id
comes from `machine-uid` (IOPlatformUUID on macOS, `/etc/machine-id` on Linux,
`MachineGuid` on Windows). Normalisation — trim, strip `{}`, lowercase — makes
every platform hash the same shape. It's hashed (not stored raw) so the token
never embeds a value that correlates back to the host, and the Rust and Python
sides compute it identically, so a token locked on one verifies on the other.

---

## 4. Enforcement

Defense in depth — a UI gate plus a backend re-check:

- **Frontend.** `hasFeature(info, "taint")` (`ui-react/src/api/license.ts`) hides
  or disables paid affordances. This is UX, not security — it runs in the
  renderer.
- **Backend.** Call `require_feature(&state, "taint")?` at the top of any
  paywalled Tauri command (`ui-react/src-tauri/src/license.rs`). It re-reads the
  token from disk and checks both `valid` and the specific entitlement.

```rust
#[tauri::command]
fn run_taint(state: State<'_, AppState>, /* … */) -> Result<_, String> {
    crate::license::require_feature(&state, "taint")?;
    // … paid work …
}
```

`require_feature` is **release-only**: debug builds (`cargo run` / `tauri dev`)
skip the check so day-to-day development isn't gated, while
`cargo build --release` enforces it.

---

## 5. License-gated auto-updates (optional)

The licensing token can double as the auth key for the update proxy in
[`auto-update.md`](auto-update.md), so only licensed installs receive updates:

1. Set the Worker's `APP_KEY` secret to a shared value (or extend the Worker to
   verify a `PLT1` token directly).
2. Have the frontend forward the activated token when it checks for updates:

   ```ts
   const upd = await check({ headers: { "x-app-key": licenseToken } });
   ```

This is access-throttling on top of the existing minisign signature check, not a
replacement for it.

---

## 6. Security model

- **What a license proves:** the holder was issued an authentic token; if
  node-locked, that it's running on the bound machine; if dated, that it's
  in-date. All verified offline against the embedded public key.
- **What it does not stop:** a determined user can patch the client binary to
  bypass the gate. Offline node-locking raises the cost (no shared key to leak,
  tokens don't move between machines) but a fully offline tool can't be made
  uncrackable. The model targets honest-majority licensing + air-gapped use, not
  DRM against a motivated reverser.
- **Tamper-evidence:** any edit to `license.plt` breaks the signature
  (`bad_signature` / `malformed`).
- **Key hygiene:** the private seed never ships and never enters the repo for
  production. The `sign` feature is compiled out of every client.

---

## 7. Checklist

Vendor, before shipping:

- [ ] `gen-keypair` run; `PUBLIC_KEY_HEX` set in `licensing/_pubkey.py` **and**
      `rust/platypus-license/src/lib.rs`
- [ ] Production seed stored offline (not the committed demo seed)
- [ ] `cargo test -p platypus-license` and `pytest tests/test_licensing.py` green
- [ ] Paid commands guarded with `require_feature(&state, "<feature>")`
- [ ] Release build verified to enforce (debug skips by design)

Per customer:

- [ ] Collect their **Machine ID** (for node-locked keys)
- [ ] `licensing.keygen sign …` with the right `--tier` / `--features` / expiry
- [ ] `licensing.keygen verify <TOKEN>` before sending
