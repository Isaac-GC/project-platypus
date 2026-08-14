# Bundled Python (generated)

This directory holds a **relocatable Python interpreter** with the `platypus`
extension module (and `ruff`) pre-installed, so the desktop app's scripting
panel works without the user installing anything.

It is populated by `scripts/bundle-python.sh` and is **not** committed to git
(see `.gitignore`). This `README.md` is the only tracked file; it exists so the
`bundle.resources` glob in `tauri.conf.json` always matches at least one file
and a plain `tauri build` (without a bundled Python) still succeeds.

When this directory contains only this README, the app falls back to the
system `python3` / `ruff` on `PATH` at runtime. After running
`scripts/bundle-python.sh`, it contains a full interpreter at:

  python/bin/python3        (Linux/macOS)
  python/python.exe         (Windows)

## Build it

    ./scripts/bundle-python.sh            # builds for the host platform

See that script's header for options (Python version, target triple, etc.).
