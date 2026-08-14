#!/usr/bin/env bash
#
# bundle-python.sh — assemble a relocatable Python interpreter with the
# `platypus` extension module (and `ruff`) pre-installed, for shipping inside
# the Tauri desktop app.
#
# Output lands in ui-react/src-tauri/resources/python/ as:
#     bin/python3        (Linux / macOS)   — the interpreter
#     bin/ruff           (Linux / macOS)   — the linter
#     lib/python3.X/site-packages/platypus*.so
# tauri.conf.json's `bundle.resources` then ships that directory, and the
# backend resolves it at runtime (see resolve_python/resolve_ruff in
# ui-react/src-tauri/src/commands.rs).
#
# Run it on (or for) EACH platform you distribute — the interpreter and the
# compiled extension module are platform- and Python-ABI-specific.
#
# Usage:
#     ./scripts/bundle-python.sh
#
# Env overrides:
#     PY_VERSION   CPython version to fetch        (default: 3.12.7)
#     PBS_TAG      python-build-standalone release  (default: 20241016)
#     PBS_TRIPLE   target triple (auto-detected if unset)
#                  e.g. x86_64-unknown-linux-gnu, aarch64-apple-darwin
#
# Prerequisites: curl, tar, a Rust toolchain (cargo) for building the wheel.

set -euo pipefail

PY_VERSION="${PY_VERSION:-3.12.7}"
PBS_TAG="${PBS_TAG:-20241016}"

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/.." && pwd)"
rust_dir="$repo_root/rust"
res_dir="$repo_root/ui-react/src-tauri/resources/python"

# ── Detect target triple (python-build-standalone naming) ───────────────────
detect_triple() {
  local os arch
  os="$(uname -s)"
  arch="$(uname -m)"
  case "$os" in
    Linux)
      case "$arch" in
        x86_64)          echo "x86_64-unknown-linux-gnu" ;;
        aarch64|arm64)   echo "aarch64-unknown-linux-gnu" ;;
        *) echo "unsupported-linux-arch:$arch" ;;
      esac ;;
    Darwin)
      case "$arch" in
        arm64)           echo "aarch64-apple-darwin" ;;
        x86_64)          echo "x86_64-apple-darwin" ;;
        *) echo "unsupported-macos-arch:$arch" ;;
      esac ;;
    *) echo "unsupported-os:$os (Windows: fetch the *-pc-windows-msvc install_only build manually)" ;;
  esac
}

PBS_TRIPLE="${PBS_TRIPLE:-$(detect_triple)}"
if [[ "$PBS_TRIPLE" == unsupported-* ]]; then
  echo "ERROR: could not auto-detect a python-build-standalone target: $PBS_TRIPLE" >&2
  echo "Set PBS_TRIPLE explicitly (see https://github.com/astral-sh/python-build-standalone/releases)." >&2
  exit 1
fi

asset="cpython-${PY_VERSION}+${PBS_TAG}-${PBS_TRIPLE}-install_only.tar.gz"
url="https://github.com/astral-sh/python-build-standalone/releases/download/${PBS_TAG}/${asset}"

echo "▶ Target triple : $PBS_TRIPLE"
echo "▶ Python        : $PY_VERSION (python-build-standalone $PBS_TAG)"
echo "▶ Destination   : $res_dir"
echo

# ── 1. Fetch + extract the relocatable interpreter ──────────────────────────
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "▶ Downloading $asset …"
curl -fSL "$url" -o "$tmp/python.tar.gz" || {
  echo "ERROR: download failed. Check PY_VERSION/PBS_TAG/PBS_TRIPLE against the" >&2
  echo "       python-build-standalone releases page; the tag/version may have moved." >&2
  exit 1
}

echo "▶ Clearing old interpreter (keeping README.md/.gitignore) …"
find "$res_dir" -mindepth 1 -maxdepth 1 \
  ! -name 'README.md' ! -name '.gitignore' -exec rm -rf {} +

echo "▶ Extracting (stripping the leading python/ component) …"
# install_only archives extract to a top-level `python/` dir; strip it so the
# interpreter sits directly at $res_dir/bin/python3.
tar -xzf "$tmp/python.tar.gz" --strip-components=1 -C "$res_dir"

py="$res_dir/bin/python3"
if [[ ! -x "$py" ]]; then
  echo "ERROR: expected interpreter at $py after extraction" >&2
  exit 1
fi
echo "  interpreter: $("$py" --version)"

# ── 2. Build the platypus wheel against THIS interpreter's ABI ──────────────
echo "▶ Installing maturin into the bundled interpreter …"
"$py" -m pip install --quiet --upgrade pip maturin

# A stray path/token in any rustflags channel gets handed to rustc as a
# positional input ("error: multiple input filenames provided"). Dump every
# rustflags-bearing env var so it's obvious — this is almost always left over
# from earlier troubleshooting.
rf_env="$(env | grep -iE 'RUSTFLAGS' || true)"
if [[ -n "$rf_env" ]]; then
  echo "⚠  rustflags-related environment is set:" >&2
  echo "$rf_env" | sed 's/^/     /' >&2
  echo "   If the build fails with 'multiple input filenames provided', clear these:" >&2
  echo "     unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS" >&2
  echo "   and retry, or run:  env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS -u CARGO_BUILD_RUSTFLAGS $0" >&2
fi

echo "▶ Building the platypus wheel (maturin, release) …"
# --skip-auditwheel: don't run the manylinux/musllinux compliance scan. The
# wheel is installed straight into the bundled interpreter on this machine, so
# broad-portability tagging is unnecessary — and the audit's ELF parser can
# choke ("Goblin failed to parse the elf file: Too small") on some toolchain
# outputs. (On macOS this flag is a harmless no-op.)
( cd "$rust_dir" && "$py" -m maturin build --release --interpreter "$py" --skip-auditwheel )

wheel="$(ls -t "$rust_dir"/target/wheels/platypus-*.whl 2>/dev/null | head -1 || true)"
if [[ -z "$wheel" ]]; then
  echo "ERROR: no platypus wheel produced in $rust_dir/target/wheels/" >&2
  exit 1
fi
echo "  wheel: $wheel"

# ── 3. Install platypus + ruff into the bundled interpreter ─────────────────
echo "▶ Installing platypus + ruff into the bundled interpreter …"
"$py" -m pip install --quiet "$wheel" ruff

echo "▶ Verifying …"
"$py" -c "import platypus; print('  platypus OK')"
"$res_dir/bin/ruff" --version | sed 's/^/  ruff: /'

echo
echo "✅ Bundled Python ready at: $res_dir"
echo "   tauri.conf.json already ships it via bundle.resources."
echo "   Now run:  cd ui-react && npm run tauri build"
