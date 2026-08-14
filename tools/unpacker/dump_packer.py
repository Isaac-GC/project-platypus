#!/usr/bin/env python3
"""dump_packer.py — Unified static DEX dumper for Chinese-origin Android packers.

This is the top-level entry point required by `CLAUDE.md`'s deliverable §2.
It auto-detects the packer family (Virbox / Jiagu / FengYue / Ijiami /
DexShield) of an APK or XAPK and dispatches to the corresponding backend
under `findings/packer_backends/`. **No native code from the sample is
executed at any point** — every step is static.

Per-packer recovery capability — what each backend produces:

  - **virbox**: F-method-string decoder (vm_str), VBPD trailer carving,
    SENS NEON-poly cipher decryption of selected APK entries, full
    classification of the per-build VBPD prologue layout. The dominant
    `E:VBPD-only` configuration's runtime-resolved body cipher remains
    flagged unrecoverable (see by-packer/virbox.md). For everything else
    (235 samples in this corpus) the backend produces a valid recovered
    `classes.dex` and/or per-entry recovered files plus a complete
    manifest.

  - **jiagu**: identifies the packer, parses the `qh\\x00\\x01` trailer
    appended to (or embedded within) the outer `classes.dex` to recover
    50+ protector-metadata fields (real Application FQCN, package,
    APK MD5, protector version, packing timestamp, signing-cert serial
    — see `packer_backends/jiagu_trailer.py`). Carves the outer stub
    DEX, every `assets/libjiagu*.so` (+ variants + `_sdk_*Protected.so`),
    and the trailer's encrypted-data section. Where present, carves
    plaintext concatenated DEX `code_item` bodies from entry 0 to
    `extracted/jiagu_entry0_codeitems.bin` — this gives partial
    recovery for **27 / 27** Jiagu 1.3.9.x samples in this corpus and
    **5 / 7** of the 1.4.0.x (`v2_nibble_obfuscated`) samples. Flags
    the encrypted class/string/type tables (entries 1..n-1) as
    unrecoverable statically — Jiagu's key is derived at runtime
    inside libjiagu's JNI_OnLoad. See by-packer/jiagu.md.

  - **fengyue**: identifies the packer, resolves the real Application
    class FQCN behind the meta-data indirection, carves
    `assets/libdexload_*.so` and the outer stub DEX. Statically
    decrypts `assets/jiami.dat` (AES-128-CBC, fixed key/IV
    `"1234567812345678"` baked into `libdexload_a64.so` rodata at
    vaddr 0x2c218) and writes the recovered DEX as
    `classes_recovered.dex` with adler32 verified against the embedded
    DEX checksum. **Full DEX recovery on all 3 FengYue samples in this
    corpus.** See by-packer/fengyue.md.

  - **ijiami** / **dexshield**: scaffolded backends for packers that
    were not observed in this engagement's corpus but are listed in
    CLAUDE.md's scope. They carve the recognised artefacts, copy the
    outer stub DEX, and flag the inner DEX as out-of-scope for static
    recovery.

Usage:
  dump_packer.py <input.apk|input.xapk> [-o OUT] [--packer auto|virbox|jiagu|ijiami|dexshield|fengyue] [-v]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import traceback
from pathlib import Path

# Make packer_backends importable when run from anywhere.
_FINDINGS = Path(__file__).resolve().parent
if str(_FINDINGS) not in sys.path:
    sys.path.insert(0, str(_FINDINGS))

from packer_backends import detector
from packer_backends import virbox as virbox_backend
from packer_backends import jiagu as jiagu_backend
from packer_backends import fengyue as fengyue_backend
from packer_backends import ijiami as ijiami_backend
from packer_backends import dexshield as dexshield_backend

BACKENDS = {
    "virbox": virbox_backend,
    "jiagu": jiagu_backend,
    "fengyue": fengyue_backend,
    "ijiami": ijiami_backend,
    "dexshield": dexshield_backend,
}


def _stem(path):
    base = os.path.basename(path)
    for ext in (".xapk", ".apk", ".zip"):
        if base.lower().endswith(ext):
            return base[: -len(ext)]
    return os.path.splitext(base)[0]


def run_one(input_path, out_root, packer="auto", *, verbose=False, force=False,
            use_unicorn=False, unicorn_insns=2_000_000,
            unicorn_mock_inner_so=False):
    """Detect (or accept the override), dispatch, and return the manifest."""
    input_path = str(input_path)
    out_root = Path(out_root)
    stem = _stem(input_path)
    out_dir = out_root / stem
    out_dir.mkdir(parents=True, exist_ok=True)

    t0 = time.time()
    det = detector.detect(input_path)

    if packer == "auto":
        chosen = det.primary
    else:
        chosen = packer

    detection_manifest = {
        "detector": det.as_dict(),
        "chosen_backend": chosen,
        "override": packer != "auto",
    }

    if chosen == "unknown" or chosen not in BACKENDS:
        # Still emit a manifest so the operator can see what we saw.
        manifest = {
            "packer": chosen,
            "backend": None,
            "input": os.path.abspath(input_path),
            "out_dir": str(out_dir.resolve()),
            "options": {"verbose": verbose, "force": force, "packer": packer},
            "stages": [{"name": "detect", "ok": False,
                        "detail": "no known packer family matched"}],
            "recovered_dexs": [],
            "unrecovered": [{"item": "(everything)", "reason": "no packer match"}],
            "detection": detection_manifest,
            "elapsed_sec": round(time.time() - t0, 3),
        }
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True))
        return manifest

    backend = BACKENDS[chosen]
    try:
        # The jiagu backend takes extra optional kwargs for the Unicorn pass.
        if chosen == "jiagu":
            manifest = backend.run(
                input_path, out_dir, verbose=verbose, force=force,
                use_unicorn=use_unicorn, unicorn_insns=unicorn_insns,
                unicorn_mock_inner_so=unicorn_mock_inner_so,
            )
        else:
            manifest = backend.run(input_path, out_dir, verbose=verbose, force=force)
    except Exception as e:
        manifest = {
            "packer": chosen,
            "backend": backend.__name__,
            "input": os.path.abspath(input_path),
            "out_dir": str(out_dir.resolve()),
            "options": {"verbose": verbose, "force": force, "packer": packer},
            "stages": [{"name": "backend.run", "ok": False, "detail": f"{type(e).__name__}: {e}"}],
            "recovered_dexs": [],
            "unrecovered": [{"item": "(backend crashed)", "reason": str(e)}],
            "traceback": traceback.format_exc(),
        }
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, default=str))

    manifest.setdefault("detection", detection_manifest)
    manifest["elapsed_sec"] = round(time.time() - t0, 3)
    # Re-write so detection + elapsed are persisted.
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True, default=str))
    return manifest


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="dump_packer.py",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("input", help="APK or XAPK file (or a directory of them with --batch)")
    p.add_argument("-o", "--out", default="dump_out", type=Path,
                   help="Output root directory (default: dump_out)")
    p.add_argument(
        "--packer", default="auto",
        choices=("auto",) + tuple(BACKENDS.keys()),
        help="Force a particular backend (default: auto-detect)",
    )
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Trace every step")
    p.add_argument("--force", action="store_true",
                   help="Re-run even if manifest.json already exists")
    p.add_argument("--batch", action="store_true",
                   help="Treat `input` as a directory; process every APK/XAPK/zip inside")
    p.add_argument("--test", action="store_true",
                   help="Emit terse PASS/FAIL summaries (CI mode)")
    p.add_argument("--use-unicorn", action="store_true",
                   help="(jiagu only) enable the Unicorn-based emulator pass "
                        "after the static carve. Disabled by default because it "
                        "needs ~32 MB of mapped emulator memory and takes a few "
                        "seconds per sample. See packer_backends/jiagu_unicorn.py.")
    p.add_argument("--unicorn-insns", type=int, default=2_000_000,
                   help="Per-call instruction budget for the Unicorn pass "
                        "(default: 2,000,000).")
    p.add_argument("--unicorn-mock-inner-so", action="store_true",
                   help="(jiagu only, opt-in) bypass the custom inner-SO "
                        "loader inside __arm_a_1 by forcing it to return a "
                        "sentinel handle, then exercise the dlsym/blr chain "
                        "with a synthetic inner JNI_OnLoad. Lets the phase-2 "
                        "ART callback path flow through; does NOT recover "
                        "DEX (the real inner SO bytes still aren't available).")
    args = p.parse_args(argv)

    inputs = []
    if args.batch:
        root = Path(args.input)
        if not root.is_dir():
            p.error(f"--batch requires a directory, got {root}")
        for child in sorted(root.iterdir()):
            if child.is_file() and child.suffix.lower() in (".apk", ".xapk", ".zip"):
                inputs.append(child)
    else:
        inputs = [Path(args.input)]

    rc = 0
    summaries = []
    for inp in inputs:
        if not inp.is_file():
            print(f"FAIL  not a file: {inp}")
            rc = max(rc, 2)
            continue
        try:
            m = run_one(inp, args.out, packer=args.packer,
                        verbose=args.verbose, force=args.force,
                        use_unicorn=args.use_unicorn,
                        unicorn_insns=args.unicorn_insns,
                        unicorn_mock_inner_so=args.unicorn_mock_inner_so)
            summaries.append(m)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            if args.test:
                print(f"FAIL  {inp.name}: {type(e).__name__}: {e}")
                rc = max(rc, 2)
                continue
            raise

        if args.test:
            n_rec = sum(1 for r in m.get("recovered_dexs", []) if r.get("ok"))
            n_unr = len(m.get("unrecovered", []))
            print(f"{'PASS' if n_rec else 'FAIL'}  "
                  f"{inp.name}  packer={m.get('packer','?')}  "
                  f"recovered={n_rec}  unrecovered={n_unr}")
            if not n_rec:
                rc = max(rc, 3)
        elif not args.verbose:
            print(f"[{m.get('packer','?'):>9}] {inp.name}  "
                  f"recovered={sum(1 for r in m.get('recovered_dexs', []) if r.get('ok'))}  "
                  f"unrecovered={len(m.get('unrecovered', []))}  "
                  f"-> {m.get('out_dir')}")

    if args.batch and not args.test:
        idx = {
            "n_total": len(inputs),
            "n_processed": len(summaries),
            "by_packer": {},
        }
        for m in summaries:
            k = m.get("packer", "?")
            idx["by_packer"][k] = idx["by_packer"].get(k, 0) + 1
        out_index = args.out / "batch_index.json"
        out_index.parent.mkdir(parents=True, exist_ok=True)
        out_index.write_text(json.dumps(idx, indent=2, sort_keys=True))
        print(f"[batch] processed {len(summaries)}/{len(inputs)}; index at {out_index}")

    return rc


if __name__ == "__main__":
    sys.exit(main())
