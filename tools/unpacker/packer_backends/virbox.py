"""Virbox Protector backend — wraps `findings/dump_virbox_dex.py`.

This is the only backend in the bundle that performs a deep, multi-stage
static decryption: F-method string slicing, SENS NEON-poly cipher,
VBPD trailer carving. The implementation is in the sibling module
`findings/dump_virbox_dex.py`; we import it and adapt its summary into
the unified manifest shape expected by `dump_packer.py`.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# Make the sibling `dump_virbox_dex.py` importable.
_FINDINGS_DIR = Path(__file__).resolve().parent.parent
if str(_FINDINGS_DIR) not in sys.path:
    sys.path.insert(0, str(_FINDINGS_DIR))

import dump_virbox_dex  # noqa: E402  (sibling script)

from . import _common


PACKER_NAME = "virbox"


def run(input_path, out_dir, *, verbose: bool = False, force: bool = False) -> dict:
    """Run the Virbox static dumper end-to-end on `input_path`.

    Returns the unified manifest dict (also persisted to manifest.json).
    """
    input_path = str(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    summary = dump_virbox_dex.dump_xapk(Path(input_path), out_dir, verbose=verbose)

    # Adapt to the unified manifest shape. We preserve the full original
    # virbox summary as `details` for forensic review.
    recovered = []
    for rd in summary.get("recovered_dexs", []):
        recovered.append({
            "name": rd.get("name") or rd.get("path") or "classes.dex",
            "size": rd.get("size", 0),
            "sha256": rd.get("sha256") or rd.get("sha1") or "",
            "ok": rd.get("size", 0) > 0,
            "details": rd,
        })

    unrecovered = []
    for ur in summary.get("unrecoverable_methods", []) or []:
        unrecovered.append({"item": str(ur), "reason": "VMP / runtime-resolved"})
    if summary.get("body_cipher_runtime_resolved"):
        unrecovered.append({
            "item": "VBPD-encrypted DEX body",
            "reason": "cipher slot at *(SO+0x30fde0) is populated by .init_array "
                      "(see by-packer/virbox.md and UNRECOVERED.md §1)",
        })

    manifest = {
        "packer": PACKER_NAME,
        "backend": __name__,
        "input": os.path.abspath(input_path),
        "out_dir": str(out_dir.resolve()),
        "options": {"verbose": verbose, "force": force},
        "build_id": summary.get("markers", {}).get("build_id_hex", ""),
        "category": summary.get("category", ""),
        "vbpd_layouts": summary.get("vbpd_layouts", []),
        "sens_record_count": summary.get("sens_record_count", 0),
        "decoded_strings_count": summary.get("decoded_strings_count", 0),
        "stages": summary.get("stages", []),
        "recovered_dexs": recovered,
        "unrecovered": unrecovered,
        "details": summary,
    }

    _common.write_manifest(out_dir, manifest)
    _common.write_unrecovered(out_dir, unrecovered, PACKER_NAME)
    return manifest
