"""DexShield (libDexHelper) backend — scaffold.

No DexShield samples were observed in this engagement's corpus. The
backend exists so `dump_packer.py --packer dexshield` works on a future
sample. It implements the structural recovery path:

  - Identify the packer via `lib/<abi>/libDexHelper.so` (or its x86
    variant `libDexHelper-x86.so`).
  - Carve all DexHelper SO(s) to `<out>/extracted/`.
  - Carve the outer stub `classes.dex` verbatim.
  - Flag the inner DEX as unrecoverable: DexShield hides DEX inside the
    native library's data sections with per-method indirection — a real
    backend would need a libDexHelper-specific lifter, which is out of
    scope for this engagement (CLAUDE.md flagged DexShield as "less
    prior art").
"""

from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path

from . import _common


PACKER_NAME = "dexshield"

_DEXHELPER_RE = re.compile(r"lib/[^/]+/libDexHelper(-x86)?\.so$")


def run(input_path, out_dir, *, verbose: bool = False, force: bool = False) -> dict:
    input_path = str(input_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    apk_path = _common.extract_base_apk_if_xapk(input_path, out_dir / "xapk")
    extracted_dir = out_dir / "extracted"
    extracted_dir.mkdir(parents=True, exist_ok=True)

    stages = []
    recovered = []
    unrecovered = []
    notes = {}

    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()
        helpers = [n for n in names if _DEXHELPER_RE.match(n)]
        stages.append({
            "name": "verify_markers",
            "ok": bool(helpers),
            "detail": f"libDexHelper={len(helpers)}",
        })
        notes["markers"] = {"libDexHelper": helpers}

        dex_recs = _common.carve_all_dexs(zf, out_dir)
        for r in dex_recs:
            r["ok"] = r.get("valid_dex_magic", False)
            r["recovery"] = "verbatim copy of outer stub DEX (DexShield Java shell)"
            recovered.append(r)
        stages.append({
            "name": "carve_outer_stub_dex",
            "ok": bool(dex_recs),
            "detail": f"{len(dex_recs)} stub DEX file(s) copied",
        })

        carved = _common.carve_entries(zf, helpers, extracted_dir)
        stages.append({
            "name": "carve_dexshield_assets",
            "ok": bool(carved),
            "detail": f"{len(carved)} file(s) carved to {extracted_dir.name}/",
        })
        notes["carved_artefacts"] = carved

        unrecovered.append({
            "item": "inner classes.dex (real app DEX)",
            "reason": (
                "DexShield hides DEX bytecode inside libDexHelper's data "
                "sections with per-method indirection. Static recovery "
                "requires a DexHelper-specific lifter and is not implemented "
                "in this engagement (no DexShield samples in scope)."
            ),
        })
        stages.append({
            "name": "inner_dex_decryption",
            "ok": False,
            "detail": "flagged unrecoverable — DEX hidden inside DexHelper data sections",
        })

    manifest = {
        "packer": PACKER_NAME,
        "backend": __name__,
        "input": os.path.abspath(input_path),
        "out_dir": str(out_dir.resolve()),
        "options": {"verbose": verbose, "force": force},
        "stages": stages,
        "recovered_dexs": recovered,
        "unrecovered": unrecovered,
        "notes": notes,
        "scaffold_note": "no DexShield samples in this engagement's corpus; scaffold only",
    }
    _common.write_manifest(out_dir, manifest)
    _common.write_unrecovered(out_dir, unrecovered, PACKER_NAME)
    return manifest
