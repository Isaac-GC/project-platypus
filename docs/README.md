# `platypus` Python API docs

Sphinx + autodoc documentation for the `platypus` extension module. The API
pages are generated from the module's docstrings (which come from the Rust
source in `rust/src/python/*.rs`), so they never drift from the code.

## Build locally

```bash
# 1. Build & install the extension module so autodoc can import it.
#    Use a PyO3-supported Python (3.9–3.13) and keep the venv ACTIVATED so
#    `maturin develop` installs into it.
python3.12 -m venv .venv && source .venv/bin/activate
pip install maturin
( cd rust && maturin develop --release --features python )

# 2. Build the HTML docs
pip install -r docs/requirements.txt
sphinx-build -b html docs docs/_build/html
open docs/_build/html/index.html      # or xdg-open on Linux
```

If `platypus` isn't importable when you run `sphinx-build`, the API pages come
out empty and `conf.py` prints a warning telling you to build the module first.

## Hosting on Read the Docs

`.readthedocs.yaml` (repo root) builds the Rust extension on RTD (it provisions
a Rust toolchain and `pip install ./rust`, which uses maturin as the PEP 517
backend) and then runs Sphinx. Point a Read the Docs project at this repo and
it should build without further config.

## Files

- `conf.py` — Sphinx config (autodoc + napoleon, furo theme).
- `index.rst` — landing page + quick example.
- `usage.rst` — install / build instructions and core concepts.
- `api.rst` — the auto-generated API reference (classes listed explicitly so
  PyO3's `__module__ = "builtins"` default doesn't hide them).
