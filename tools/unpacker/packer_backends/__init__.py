"""Per-packer recovery backends for the unified Android-packer static dumper.

Each backend in this package implements the same shape:

    def run(input_path, out_dir, *, verbose=False, force=False) -> dict

where the returned dict is the per-sample manifest (also written to
`<out_dir>/manifest.json`). At minimum the manifest contains:

    {
      "packer":        "<family>",
      "backend":       "<this module>",
      "input":         "<absolute path>",
      "out_dir":       "<absolute path>",
      "options":       {... CLI args / detection flags ...},
      "stages": [
        {"name": "...", "ok": True/False, "detail": "..."},
        ...
      ],
      "recovered_dexs": [
        {"name": "classes.dex", "size": ..., "sha256": "...", "ok": True},
        ...
      ],
      "unrecovered":  [
        {"item": "classN.dex", "reason": "..."},
        ...
      ],
    }

The single top-level entry point is `findings/dump_packer.py`.
"""

from . import detector  # noqa: F401
