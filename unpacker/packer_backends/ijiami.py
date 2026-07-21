"""Ijiami (爱加密) backend — scaffold.

No Ijiami samples were observed in this engagement's corpus. This
backend exists so `dump_packer.py --packer ijiami` works on a future
sample without requiring a code change. It implements the structural
recovery path that applies to Ijiami based on CLAUDE.md priors:

  - Identify the packer via stub class (`com.shell.NativeApplication`,
    `com.shell.NativeApplicationE`, `cn.securitystack.stss.NativeApplication`).
  - Carve `lib/<abi>/libsecmain.so`, `libsecexe.so`, `libexec.so`,
    `libexecmain.so`, `libsmainso.so`, and `assets/ijiami.dat` /
    `assets/ijiami.ajm` / `assets/ijm_lib/*` to `<out>/extracted/`.
  - Carve the outer stub `classes.dex` verbatim.
  - Flag the inner DEX as unrecoverable: the cipher is XOR+AES with
    runtime-derived material, like Jiagu. The implementation could be
    extended once a real Ijiami sample is in scope.
"""

from __future__ import annotations

import os
import re
import zipfile
from pathlib import Path

from . import _common


PACKER_NAME = "ijiami"

_LOADER_LIBS_RE = re.compile(
    r"lib/[^/]+/(libsecmain|libsecexe|libexec|libexecmain|libsmainso)\.so$"
)
_DAT_RE = re.compile(r"assets/(ijiami\.dat|ijiami\.ajm|ijm_lib/.+)$")


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
        manifest_strs = _common.read_manifest_strings(zf)

        loaders = [n for n in names if _LOADER_LIBS_RE.match(n)]
        dats = [n for n in names if _DAT_RE.match(n)]
        stub_present = any(
            s in ("com.shell.NativeApplication", "com.shell.NativeApplicationE",
                  "cn.securitystack.stss.NativeApplication")
            for s in manifest_strs
        )
        ok = bool(loaders or dats or stub_present)
        stages.append({
            "name": "verify_markers",
            "ok": ok,
            "detail": f"loaders={len(loaders)} dats={len(dats)} stub={stub_present}",
        })
        notes["markers"] = {"loaders": loaders, "dats": dats, "stub_present": stub_present}

        dex_recs = _common.carve_all_dexs(zf, out_dir)
        for r in dex_recs:
            r["ok"] = r.get("valid_dex_magic", False)
            r["recovery"] = "verbatim copy of outer stub DEX (Ijiami Java shell)"
            recovered.append(r)
        stages.append({
            "name": "carve_outer_stub_dex",
            "ok": bool(dex_recs),
            "detail": f"{len(dex_recs)} stub DEX file(s) copied",
        })

        carved = _common.carve_entries(zf, loaders + dats, extracted_dir)
        stages.append({
            "name": "carve_ijiami_assets",
            "ok": bool(carved),
            "detail": f"{len(carved)} file(s) carved to {extracted_dir.name}/",
        })
        notes["carved_artefacts"] = carved

        unrecovered.append({
            "item": "inner classes.dex (real app DEX)",
            "reason": (
                "Ijiami's loader (libsecmain/libsecexe/libexecmain) derives "
                "the XOR/AES key set from per-build constants and the "
                "encrypted blob ijiami.dat at runtime. Static recovery not "
                "implemented in this engagement; backend reports the artefacts "
                "carved out for analyst follow-up."
            ),
        })
        stages.append({
            "name": "inner_dex_decryption",
            "ok": False,
            "detail": "flagged unrecoverable — runtime key derivation",
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
        "scaffold_note": "no Ijiami samples in this engagement's corpus; scaffold only",
    }
    _common.write_manifest(out_dir, manifest)
    _common.write_unrecovered(out_dir, unrecovered, PACKER_NAME)
    return manifest
