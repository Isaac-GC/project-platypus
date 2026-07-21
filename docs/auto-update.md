# Auto self-update for the Tauri apps

This repo ships two Tauri apps that both support self-update:

- **`standalone-viewer/`** — `platypus-viewer`, the focused activity-layout
  preview shell.
- **`ui-react/`** — `Project Platypus`, the full reverse-engineering UI.

This document walks through everything you need to enable the update
flow end-to-end, including the parts of the puzzle that don't live in
the repo (signing keys, CI secrets, code-signing certificates).

The code-side wiring is already in place — see the change set that
introduced this document. What follows is the operator's runbook.

---

## 1. Generate the signing keypairs (one time, locally)

Tauri 2 uses [minisign](https://jedisct1.github.io/minisign/) to verify
that updates were built by you and not by an attacker who slipped a
binary onto your release host. You generate a keypair, embed the public
half in `tauri.conf.json`, and keep the private half in CI secrets.

```sh
# One-time install
cargo install tauri-cli@2

# Per-app keypair. Use a strong passphrase — anyone with the key + pass
# can ship a "signed update" that your installed clients accept.
tauri signer generate -w ~/.tauri/platypus-viewer.key
tauri signer generate -w ~/.tauri/project-platypus-ui.key
```

Each command emits two files:

- `<name>.key` — private. Never commit. Copy into GitHub Secrets (see step 4).
- `<name>.key.pub` — public. Copy into the matching `tauri.conf.json`.

```sh
cat ~/.tauri/platypus-viewer.key.pub
# → "untrusted comment: minisign public key A1B2C3D4..."
# → "RWQAB...."     ← the actual key
```

Paste **only the second line** (the base64 blob) into:

```json
// standalone-viewer/src-tauri/tauri.conf.json
"plugins": {
  "updater": {
    "pubkey": "RWQAB...."           // ← replace REPLACE_WITH_OUTPUT_OF_tauri_signer_generate
  }
}
```

Repeat for `ui-react/src-tauri/tauri.conf.json` with the second key's
public half. The two apps **must** use different keys — if you ever
rotate one, you don't want existing clients of the other to suddenly
refuse updates.

## 2. Decide on the release host + endpoint

The placeholder endpoint in both configs points at GitHub Releases:

```json
"endpoints": [
  "https://github.com/REPLACE_OWNER/project_platypus/releases/latest/download/platypus-viewer-latest.json"
]
```

The simplest deployment is to keep using GitHub Releases:

1. Replace `REPLACE_OWNER` with your GitHub org / user.
2. The CI workflow in `.github/workflows/release.yml` uploads
   `<app>-latest.json` (plus the platform bundles + `.sig` files) to
   the draft release it creates.
3. After you publish the draft, GitHub serves the JSON at
   `…/releases/latest/download/<app>-latest.json` — exactly what the
   updater plugin hits.

### Private repo (free): a Cloudflare Worker auth proxy

If the repo is **private**, the `releases/latest/download/…` URL 404s — private
release assets require authentication, and you must *not* embed a GitHub token
in the app (anyone who extracts it gets read access to the whole repo). The fix
is a tiny auth proxy that holds a read-only token server-side; the app points at
the proxy instead of `github.com`.

A ready-to-deploy Cloudflare Worker lives in
[`infra/updater-worker/`](../infra/updater-worker/). The signing layer is
unchanged — the proxy only solves *access* to private assets, not trust:

```text
publish (CI, unchanged)        runtime (the new path)
─────────────────────────      ───────────────────────────────────────────
release.yml                    desktop app ──①──▶ Worker ──②──▶ private repo
  build + sign (minisign)        (updater)   ◀──④──         ◀──③── (GitHub API
  upload bundle + .sig +                     verify .sig            + read PAT)
  <app>-latest.json   ───────▶  against embedded pubkey ──⑤──▶ install
  to the private release
```

1. App requests `…workers.dev/ui/latest.json` (optionally with its `x-app-key`).
2. Worker calls the GitHub API with its **read-only PAT**, fetches the manifest,
   and repoints each bundle `url` back at itself.
3. App requests the bundle; the Worker **302-redirects** to GitHub's short-lived
   signed blob URL, so the binary downloads directly and never streams through
   the Worker (this is what keeps it inside the free tier).
4. (Response leg of ①–③.)
5. App verifies the inlined `.sig` against its embedded `pubkey`, then installs.

The whole setup — create a fine-grained PAT (`Contents: Read` on this repo only),
`wrangler secret put GH_TOKEN`, `wrangler deploy`, then swap the two `endpoints`
to the Worker routes — is in
[`infra/updater-worker/README.md`](../infra/updater-worker/README.md).

> Why a proxy and not an `Authorization` header? Tauri's updater *can* send
> custom headers, but a baked-in PAT ships inside the binary and grants repo
> read to anyone who extracts it. The Worker keeps the token server-side and
> lets you gate downloads on *your* app's auth (e.g. the license token — see
> [`licensing.md`](licensing.md)) instead.

You can also restrict updates to **licensed** users: set the Worker's `APP_KEY`
and have the frontend pass the activated license token as the `x-app-key` header
in its `check({ headers })` call.

### Other private hosts

If you prefer a different host (S3, Cloudflare R2, your own CDN), point the
endpoint at the JSON URL on your host and run an additional CI step that uploads
the artifacts there instead of (or in addition to) the GitHub Release. The R2
route (free: 10 GB + zero egress) decouples you from GitHub entirely — see the
"Alternatives" note in `infra/updater-worker/README.md`.

## 3. Enable updater-artifact emission

The Tauri config ships with:

```json
"bundle": { "createUpdaterArtifacts": false }
```

This is deliberate so that local `npm run tauri build` still works for
people who haven't set up signing keys yet. When you're ready to ship
real releases, flip it to `true` **in CI only** so a missing local key
doesn't break developer machines:

```yaml
# inside .github/workflows/release.yml, under each tauri-action step,
# pass it via the args field:
args: --target ${{ matrix.target }} --config '{"bundle":{"createUpdaterArtifacts":true}}'
```

…or commit the `true` everywhere and document that contributors must
run `tauri signer generate` locally for `tauri build` to succeed.

## 4. Add the secrets to your GitHub repo

`Settings → Secrets and variables → Actions → New repository secret`:

| Secret name | Value |
|---|---|
| `TAURI_SIGNING_PRIVATE_KEY` | Contents of `~/.tauri/<name>.key` (the whole file). If you keep one key per app, use a different secret name per workflow and adjust the env block in `release.yml`. |
| `TAURI_SIGNING_PRIVATE_KEY_PASSWORD` | The passphrase you set during `tauri signer generate`. |

…plus the optional codesigning secrets listed in step 5.

For the standalone-viewer + ui-react split where each app has its own
key, the cleanest pattern is **one secret per app**:

- `VIEWER_TAURI_SIGNING_PRIVATE_KEY` / `VIEWER_TAURI_SIGNING_KEY_PWD`
- `UI_TAURI_SIGNING_PRIVATE_KEY`     / `UI_TAURI_SIGNING_KEY_PWD`

Then update `release.yml`'s env blocks accordingly.

## 5. Set up code-signing (strongly recommended)

Without code-signing, your users see a Gatekeeper warning on every
macOS update and SmartScreen friction on every Windows update.
Eventually they stop installing the updates. This is the single
biggest non-code prerequisite for a quiet update flow.

### macOS — Developer ID Application cert + notarization

You need an active Apple Developer Program membership ($99/yr).

```sh
# In Xcode: Settings → Accounts → your team → Manage Certificates →
# "+" → "Developer ID Application". This populates your Keychain.

# Export the cert + key to a .p12:
#   Keychain Access → Login → Certificates → right-click → Export →
#   Personal Information Exchange (.p12), set a strong password.

# Base64 it for GitHub Secrets:
base64 -i developer_id.p12 | pbcopy
```

Set:

- `APPLE_CERTIFICATE` — the base64 blob
- `APPLE_CERTIFICATE_PASSWORD` — the export password
- `APPLE_SIGNING_IDENTITY` — exact CN, e.g. `Developer ID Application: Your Name (TEAMID)`

For notarization (so the app passes Gatekeeper without warnings):

- `APPLE_ID` — your Apple ID email
- `APPLE_PASSWORD` — an **app-specific password**, NOT your account
  password. Generate at https://appleid.apple.com → Sign-In and Security
  → App-Specific Passwords.
- `APPLE_TEAM_ID` — 10-character team identifier (visible in your
  Apple Developer account).

`tauri-action` autodetects these env vars and runs codesign +
notarization as part of the build.

### Windows — code-signing cert

- **Standard cert** (cheap, ~$80/yr from a CA): SmartScreen warns
  until your installer accrues "reputation" with Microsoft (typically
  a few hundred downloads).
- **EV cert** (~$400/yr): instant SmartScreen acceptance. Worth it if
  you have any nontrivial user base.

Export the cert as `.pfx`, base64-encode it the same way as the Apple
cert:

```sh
certutil -encode cert.pfx cert.b64
```

Set:

- `WINDOWS_CERTIFICATE`
- `WINDOWS_CERTIFICATE_PASSWORD`

Then add a `bundle.windows.signCommand` to each `tauri.conf.json`:

```json
"bundle": {
  "windows": {
    "signCommand": "signtool sign /td sha256 /fd sha256 /tr http://timestamp.digicert.com /f cert.pfx /p ${env.WINDOWS_CERTIFICATE_PASSWORD} %1"
  }
}
```

### Linux

`.AppImage` builds work with self-update out of the box and don't need
codesigning. `.deb` / `.rpm` packages **cannot** be self-updated by
Tauri's plugin — the OS package manager owns them. If you ship those
targets, limit Tauri's updater to AppImage:

```json
"bundle": {
  "linux": {
    "appimage": { "bundleMediaFramework": true }
  }
}
```

## 6. Ship the first signed release

```sh
# Commit the pubkey replacement + the endpoint owner.
git commit -am "chore: real updater pubkey + endpoint"
git push

# Tag the release. The workflow runs on tag push.
git tag v0.2.0
git push origin v0.2.0
```

The matrix job builds for darwin-aarch64, darwin-x86_64, linux-x86_64,
and windows-x86_64 in parallel. When it finishes, a **draft release**
shows up at `…/releases`. Verify the assets, then click "Publish
release".

That last click flips the `latest` redirect — and existing installs
see the new version the next time their background check fires.

## 7. Verify the update flow

On a test machine running the previous version:

```sh
# Force a check ignoring the throttle:
localStorage.PLATYPUS_FORCE_UPDATE_CHECK = "1"
```

…in the app's devtools console, then reload. You should see a confirm
dialog offering the new version. Accepting it downloads, installs, and
relaunches.

For automated verification, the updater module exposes
`resetUpdateState()` and emits `UpdateStatus` events through the
`onStatus` callback — you can wire a Playwright test that flips the
override, calls `checkForUpdates({ silent: false })`, and asserts the
sequence of statuses.

## 8. Rollback

There's no built-in rollback in the Tauri updater. The standard pattern
is **fix-forward**:

1. Find the bug.
2. Bump the version (e.g. `v0.2.1`).
3. Re-tag and let the matrix rebuild + publish.
4. Within an hour, every client's background check picks up the
   newer-still version.

If a release is catastrophically broken, you can manually delete the
GitHub Release. Existing clients will then see no `latest.json` and
fail their next check silently — but anyone who already downloaded
the bad version is stuck on it until they reinstall manually.

To avoid that scenario, consider:

- A **canary channel** by adding `?channel=canary` to your endpoint
  and pointing canary builds at a separate manifest URL. Users opt in
  via a setting.
- A **staged rollout** by hosting two manifests (e.g. 10% and 90%) and
  routing users via a query string that includes their install id.

## 9. Per-app version coupling

The two Tauri apps version independently in their respective
`tauri.conf.json -> version`. The workflow's tag-prefix logic builds:

| Tag | Result |
|---|---|
| `v0.2.0` | Both apps build, both get a release. |
| `viewer-v0.2.0` | Only standalone-viewer. |
| `platypus-ui-v0.2.0` | Only ui-react. |

If you want the apps to stay in lockstep, source `version` from a
shared file (e.g. the workspace `Cargo.toml`) and update both
tauri.conf.json's in the same commit.

## 10. Quick checklist before tagging your first release

- [ ] `pubkey` replaced in **both** `tauri.conf.json` files
- [ ] Endpoint `REPLACE_OWNER` replaced in **both** files
- [ ] `TAURI_SIGNING_PRIVATE_KEY` + password set in GitHub Secrets
- [ ] Apple cert + notarization secrets set (if you want macOS quiet)
- [ ] Windows cert + password set (if you want Windows quiet)
- [ ] `createUpdaterArtifacts` flipped to `true` in CI args (or
      committed as `true`)
- [ ] Bumped `version` in both `tauri.conf.json` files
- [ ] Pushed the tag

When that's all in place, every user of every previous version starts
receiving the update the next time they launch the app, throttled to
one check per hour. The whole flow is silent on the happy path:
checking takes a few hundred ms in the background, and only the
"update available" branch surfaces a prompt.
