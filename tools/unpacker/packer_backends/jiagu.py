"""Qihoo 360 Jiagu backend.

What this backend can do statically:

  - Identify the packer via `assets/.jgapp`, `assets/libjiagu*.so`,
    variant-named loaders (`libjg<tag>.so`), and the stub Application
    class (`com.stub.StubApp`, `com.qihoo.util.StubApp`).
  - Recover the original Application class FQCN from the manifest
    `<meta-data>` indirection.
  - Carve the outer stub `classes.dex` (parses cleanly, contains the
    Jiagu Java shell + the `<meta-data>` key for the real app).
  - Carve `assets/.jgapp`, every `assets/libjiagu*.so`, every variant
    loader, and every `lib/<abi>/libjiagu_sdk_*Protected.so` to
    `<out>/extracted/`.
  - **Parse the `qh\\x00\\x01` trailer appended to `classes.dex`** —
    recovers ~50 key/value metadata entries per sample, including:
      original Application class, package name, signing-cert MD5,
      APK MD5, Jiagu protector version, packing timestamp, original
      versionName / versionCode. See `jiagu_trailer.py` for the format.

What it cannot do statically:

  - Decrypt the *bulk* DEX payload (entries 1..n-1 of the trailer's
    data section). The Jiagu loader derives that key inside
    `JNI_OnLoad` from the APK signing certificate fingerprint and
    per-build constants, gated by anti-debug / anti-emulator
    interlocks (TracerPid, `/proc/self/maps`, `/proc/cpuinfo`,
    Frida port-27042 probes). All known recovery techniques
    (DexHunter, AppSpear, FUPK3, ARTist) hook the live ART process;
    none works statically. See `by-packer/jiagu.md` for details.

The backend therefore writes the carved artefacts, the recovered
trailer-metadata JSON, and a `manifest.json` documenting the
unrecovered inner DEX bodies with a precise reason.
"""

from __future__ import annotations

import json
import os
import re
import struct
import zipfile
from pathlib import Path

from . import _common
from .jiagu_trailer import parse_trailer, summarise_trailer
from .jiagu_codeitems import (
    recover_from_carved, serialize_code_items, build_synthetic_dex,
)


PACKER_NAME = "jiagu"

_VARIANT_LOADER_RE = re.compile(r"assets/libjg[a-z]{2,5}(_(a64|x64|x86))?\.so$")
_JIAGU_SDK_RE = re.compile(r"lib/[^/]+/libjiagu_sdk_.*\.so$")


def _resolve_real_application(manifest_strs):
    """Find the original Application class name behind Jiagu's stub.

    Jiagu typically writes the real class into `<meta-data
    android:name="STUB_APPLICATION_NAME" android:value="<fqcn>">` (the
    exact key has been observed as `STUB_APPLICATION_NAME`,
    `app_name`, or a build-randomised string in newer versions). We
    return the first plausible FQCN that's *not* the Jiagu stub.
    """
    stub_names = {
        "com.stub.StubApp", "com.qihoo.util.StubApp",
        "com.qihoo360.replugin.RePlugin",
    }
    candidates = []
    for s in manifest_strs:
        if not isinstance(s, str):
            continue
        if not s or "." not in s:
            continue
        if s in stub_names:
            continue
        if re.match(r"^[a-zA-Z_][\w.]*\.[A-Z]\w+$", s) and s.endswith("Application"):
            candidates.append(s)
    return candidates[0] if candidates else ""


def _carve_trailer_artefacts(trailer, out_dir: Path):
    """Write the decoded trailer summary plus carve every region the static
    parser can reach.

    Carves:
      - jiagu_trailer.json          full summary (metadata + structural)
      - jiagu_data_section.bin      entire encrypted data section
      - jiagu_entry0.bin            entry 0's raw bytes (plaintext code_items
                                     in 1.3.9.x; nibble-obfuscated in 1.4.0.x)
      - jiagu_entry0_header.bin     entry 0's first 16 bytes (always opaque)
      - jiagu_entry0_body.bin       entry 0 minus its 16-byte header (the
                                     part where Dalvik bytecode lives in
                                     1.3.9.x builds)
      - jiagu_pre_e0.bin            bytes between the entry table and
                                     entry 0 (encrypted, likely holds
                                     entries 1..n-1's first slice)
      - jiagu_post_e0.bin           bytes after entry 0 ends (encrypted,
                                     remaining entry payloads)
      - jiagu_entry_table.bin       the encrypted (size, off) pairs for
                                     entries 1..n-1 (each pair = 8 bytes)
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    artefacts = []

    # 1) Full trailer summary (metadata + structural fields)
    summary = summarise_trailer(trailer)
    summary_path = out_dir / "jiagu_trailer.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    artefacts.append({
        "name": "jiagu_trailer.json",
        "kind": "trailer_metadata",
        "size": summary_path.stat().st_size,
        "n_metadata_entries": len(summary["metadata"]),
        "n_data_entries": summary["n_entries"],
        "entry0_format": summary["entry0_format"],
        "out_path": str(summary_path),
    })

    ds = trailer.data_section

    # 2) Raw data section (encrypted bulk payload — useful for downstream
    #    runtime captures or future static work)
    data_path = out_dir / "jiagu_data_section.bin"
    with open(data_path, "wb") as f:
        f.write(ds)
    artefacts.append({
        "name": "jiagu_data_section.bin",
        "kind": "encrypted_data_section",
        "size": len(ds),
        "out_path": str(data_path),
    })

    # 3) Encrypted entry table (n_entries-1 (size, off) pairs)
    if trailer.encrypted_table:
        tbl_path = out_dir / "jiagu_entry_table.bin"
        with open(tbl_path, "wb") as f:
            f.write(trailer.encrypted_table)
        artefacts.append({
            "name": "jiagu_entry_table.bin",
            "kind": "encrypted_entry_table",
            "size": len(trailer.encrypted_table),
            "n_pairs": trailer.n_entries - 1 if trailer.n_entries else 0,
            "out_path": str(tbl_path),
        })

    # 4) Entry 0's raw bytes (often partly plaintext bytecode)
    if (trailer.entry0_off > 0
            and trailer.entry0_size > 0
            and trailer.entry0_off + trailer.entry0_size <= len(ds)):
        entry0 = ds[trailer.entry0_off:trailer.entry0_off + trailer.entry0_size]
        e0_path = out_dir / "jiagu_entry0.bin"
        with open(e0_path, "wb") as f:
            f.write(entry0)
        artefacts.append({
            "name": "jiagu_entry0.bin",
            "kind": "data_entry_0",
            "size": len(entry0),
            "entry0_format": summary["entry0_format"],
            "out_path": str(e0_path),
        })
        # Split: 16-byte opaque header + body
        e0_hdr_path = out_dir / "jiagu_entry0_header.bin"
        with open(e0_hdr_path, "wb") as f:
            f.write(entry0[:16])
        artefacts.append({
            "name": "jiagu_entry0_header.bin",
            "kind": "data_entry_0_header",
            "size": 16,
            "note": "opaque per-build header — likely IV/MAC for the encrypted entries",
            "out_path": str(e0_hdr_path),
        })
        e0_body_path = out_dir / "jiagu_entry0_body.bin"
        with open(e0_body_path, "wb") as f:
            f.write(entry0[16:])
        artefacts.append({
            "name": "jiagu_entry0_body.bin",
            "kind": "data_entry_0_body",
            "size": len(entry0) - 16,
            "note": (
                "plaintext concatenated DEX code_items in Jiagu 1.3.9.x; "
                "nibble-obfuscated in 1.4.0.x — see by-packer/jiagu.md"
            ),
            "out_path": str(e0_body_path),
        })

        # NEW (2026-05-18): plaintext code_items tail — works on BOTH v1
        # and v2 builds. For v1 the tail starts at offset 0 (whole body
        # is plaintext); for v2 the tail starts after the last sustained
        # nibble-alphabet run. Several v2 builds have multi-MB plaintext
        # tails despite the "v2_nibble_obfuscated" classification — see
        # jiagu_trailer.find_codeitems_tail_offset for the heuristic.
        pt_off = summary.get("plaintext_tail_offset", 0) or 0
        pt_size = summary.get("plaintext_tail_size", 0) or 0
        if pt_size > 0:
            tail = entry0[16 + pt_off:]
            tail_path = out_dir / "jiagu_entry0_codeitems.bin"
            with open(tail_path, "wb") as f:
                f.write(tail)
            artefacts.append({
                "name": "jiagu_entry0_codeitems.bin",
                "kind": "data_entry_0_plaintext_codeitems",
                "size": len(tail),
                "note": (
                    "plaintext concatenated DEX code_items carved from "
                    "entry-0's tail (offset {} within body). For v1 builds "
                    "this is the whole body. For v2 builds this is the "
                    "portion past the nibble-obfuscated prefix.".format(pt_off)
                ),
                "out_path": str(tail_path),
            })

        # 5) Encrypted pre-entry0 region (between header table end and e0_off)
        tbl_end = 12 + (trailer.n_entries * 8 if trailer.n_entries else 12)
        if trailer.entry0_off > tbl_end:
            pre_e0 = ds[tbl_end:trailer.entry0_off]
            pre_path = out_dir / "jiagu_pre_e0.bin"
            with open(pre_path, "wb") as f:
                f.write(pre_e0)
            artefacts.append({
                "name": "jiagu_pre_e0.bin",
                "kind": "encrypted_pre_e0",
                "size": len(pre_e0),
                "note": "encrypted bytes between the entry table and entry 0",
                "out_path": str(pre_path),
            })

        # 6) Encrypted post-entry0 region
        e0_end = trailer.entry0_off + trailer.entry0_size
        if e0_end < len(ds):
            post_e0 = ds[e0_end:]
            post_path = out_dir / "jiagu_post_e0.bin"
            with open(post_path, "wb") as f:
                f.write(post_e0)
            artefacts.append({
                "name": "jiagu_post_e0.bin",
                "kind": "encrypted_post_e0",
                "size": len(post_e0),
                "note": "encrypted bytes after entry 0 — entries 1..n-1 payloads",
                "out_path": str(post_path),
            })

    return artefacts, summary


def run(input_path, out_dir, *, verbose: bool = False, force: bool = False,
        use_unicorn: bool = False, unicorn_insns: int = 2_000_000,
        unicorn_mock_inner_so: bool = False) -> dict:
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
        name_set = set(names)
        manifest_strs = _common.read_manifest_strings(zf)

        # Stage 1 — verify packer markers
        jgapp = "assets/.jgapp" in name_set
        jiagu_so = [n for n in names if re.match(r"assets/libjiagu(_a64|_x64|_x86)?\.so$", n)]
        variant_so = [n for n in names if _VARIANT_LOADER_RE.match(n)]
        sdk_libs = [n for n in names if _JIAGU_SDK_RE.match(n)]
        stages.append({
            "name": "verify_markers",
            "ok": bool(jgapp or jiagu_so or variant_so),
            "detail": f"jgapp={jgapp} libjiagu={len(jiagu_so)} variants={len(variant_so)} sdk_libs={len(sdk_libs)}",
        })
        notes["markers"] = {
            "jgapp": jgapp,
            "libjiagu": jiagu_so,
            "variants": variant_so,
            "sdk_libs": sdk_libs,
        }

        # Stage 2 — resolve real Application class (best-effort from AXML)
        real_app_axml = _resolve_real_application(manifest_strs)

        # Stage 3 — carve the outer stub DEX(s) verbatim
        dex_recs = _common.carve_all_dexs(zf, out_dir)
        for r in dex_recs:
            r["ok"] = r.get("valid_dex_magic", False)
            r["recovery"] = "verbatim copy of outer stub DEX (Jiagu Java shell)"
            recovered.append(r)
        stages.append({
            "name": "carve_outer_stub_dex",
            "ok": bool(dex_recs),
            "detail": f"{len(dex_recs)} stub DEX file(s) copied",
        })

        # Stage 4 — parse the `qh\x00\x01` trailer (NEW)
        trailer_summary = None
        trailer_real_app = None
        if dex_recs:
            try:
                dex_bytes = zf.read(dex_recs[0]["name"])
            except Exception:
                dex_bytes = b""
            tr = parse_trailer(dex_bytes) if dex_bytes else None
            if tr is not None:
                artefacts, trailer_summary = _carve_trailer_artefacts(tr, extracted_dir)
                notes["trailer_artefacts"] = artefacts
                notes["trailer"] = {
                    "n_metadata": len(trailer_summary["metadata"]),
                    "n_entries": trailer_summary["n_entries"],
                    "original_app": trailer_summary["original_app"],
                    "package": trailer_summary["package"],
                    "version_code": trailer_summary["version_code"],
                    "version_name": trailer_summary["version_name"],
                    "jiagu_version": trailer_summary["jiagu_version"],
                    "protect_time": trailer_summary["protect_time"],
                    "stub_class": trailer_summary["stub_class"],
                    "entry0_format": trailer_summary["entry0_format"],
                    "entry0_format_by_data": trailer_summary["entry0_format_by_data"],
                    "entry0_format_by_version": trailer_summary["entry0_format_by_version"],
                }
                trailer_real_app = trailer_summary.get("original_app")
                stages.append({
                    "name": "parse_jiagu_trailer",
                    "ok": True,
                    "detail": (
                        f"{len(trailer_summary['metadata'])} metadata entries, "
                        f"{trailer_summary['n_entries']} encrypted data entries "
                        f"({trailer_summary['data_section_len']} bytes total)"
                    ),
                })
            else:
                stages.append({
                    "name": "parse_jiagu_trailer",
                    "ok": False,
                    "detail": "no qh\\x00\\x01 trailer found in outer DEX",
                })

        # Combine application name from AXML or trailer
        real_app = trailer_real_app or real_app_axml
        notes["original_application"] = real_app
        notes["original_application_source"] = (
            "trailer" if trailer_real_app else ("axml" if real_app_axml else "")
        )
        stages.append({
            "name": "resolve_real_application",
            "ok": bool(real_app),
            "detail": f"original_application={real_app!r} (source={notes['original_application_source']})",
        })

        # Stage 5 — carve Jiagu artefacts
        to_carve = []
        if jgapp:
            to_carve.append("assets/.jgapp")
        to_carve.extend(jiagu_so)
        to_carve.extend(variant_so)
        to_carve.extend(sdk_libs)
        carved = _common.carve_entries(zf, to_carve, extracted_dir)
        stages.append({
            "name": "carve_jiagu_assets",
            "ok": bool(carved),
            "detail": f"{len(carved)} file(s) carved to {extracted_dir.name}/",
        })
        notes["carved_artefacts"] = carved

        # Stage 6 — characterise what's static-recoverable and what's not
        e0_fmt = (trailer_summary or {}).get("entry0_format", "unknown")
        if e0_fmt == "v1_plaintext_codeitems":
            # Older Jiagu (≤ 1.3.9.x): entry 0's body is plaintext concatenated
            # DEX code_items. Useful for forensics, not enough to rebuild a
            # runnable DEX (string/type/method tables remain encrypted).
            unrecovered.append({
                "item": "inner DEX class/string/type/method tables",
                "reason": (
                    "Jiagu " + (trailer_summary.get("jiagu_version") or "?") +
                    " (older variant): entry 0's body is plaintext concatenated "
                    "DEX code_items (carved to extracted/jiagu_entry0_body.bin) — "
                    "useful for forensics but not sufficient to rebuild a "
                    "runnable DEX. The required class_defs, string_data, "
                    "type/method/proto/field tables live in encrypted entries "
                    "1..n-1, decrypted under a per-build runtime key derived "
                    "inside libjiagu*.so. See by-packer/jiagu.md §Recovery."
                ),
            })
            stages.append({
                "name": "inner_dex_decryption",
                "ok": False,
                "detail": (
                    "PARTIAL recovery — entry 0 plaintext code_items carved "
                    "(jiagu_entry0_body.bin); inner DEX tables remain encrypted "
                    "in entries 1..n-1"
                ),
            })
        elif e0_fmt == "v2_nibble_obfuscated":
            # 2026-05-18 update: many v2 builds have a plaintext tail past
            # the nibble-obfuscated prefix — see jiagu_trailer
            # find_codeitems_tail_offset. Adjust the reason text based on
            # whether any plaintext tail was recovered for this sample.
            pt_size = (trailer_summary or {}).get("plaintext_tail_size", 0) or 0
            if pt_size > 0:
                unrecovered.append({
                    "item": (
                        "inner DEX class/string/type/method tables + the "
                        "nibble-obfuscated prefix of entry 0"
                    ),
                    "reason": (
                        "Jiagu " + (trailer_summary.get("jiagu_version") or "?") +
                        " (newer variant): entry 0 splits into a nibble-"
                        "obfuscated prefix and a plaintext code_items tail; "
                        "the tail was carved to "
                        "extracted/jiagu_entry0_codeitems.bin "
                        f"({pt_size} bytes recovered). The class_defs, "
                        "string_data, type/method/proto/field tables remain "
                        "encrypted in entries 1..n-1 under a per-build runtime "
                        "key derived inside libjiagu*.so. See "
                        "by-packer/jiagu.md §Recovery."
                    ),
                })
                stages.append({
                    "name": "inner_dex_decryption",
                    "ok": False,
                    "detail": (
                        f"PARTIAL recovery — plaintext code_items tail "
                        f"({pt_size} bytes) carved from v2 entry 0; "
                        f"nibble-obfuscated prefix + entries 1..n-1 remain "
                        f"encrypted"
                    ),
                })
            else:
                unrecovered.append({
                    "item": "inner DEX bulk payload (entry 0 obfuscated + entries 1..n-1 encrypted)",
                    "reason": (
                        "Jiagu " + (trailer_summary.get("jiagu_version") or "?") +
                        " (newer variant): entry 0's prefix is nibble-obfuscated "
                        "(dominant bytes from {0x0f,0x1e,0x2d,0x3c}); entries "
                        "1..n-1 are AES-equivalent encrypted under a per-build "
                        "runtime key. Static carving (extracted/jiagu_entry0.bin, "
                        "jiagu_pre_e0.bin, jiagu_post_e0.bin, jiagu_entry_table.bin) "
                        "preserves the bytes for downstream runtime work. See "
                        "by-packer/jiagu.md §Recovery."
                    ),
                })
                stages.append({
                    "name": "inner_dex_decryption",
                    "ok": False,
                    "detail": (
                        "bulk payload flagged unrecoverable — newer Jiagu variant "
                        "with full encryption + obfuscation (no plaintext tail)"
                    ),
                })
        else:
            unrecovered.append({
                "item": "inner DEX bulk payload (entries 1..n-1)",
                "reason": (
                    "Jiagu variant (entry-0 format=" + e0_fmt + "): bulk DEX "
                    "bytes live in the trailer's data section, encrypted "
                    "under a per-build runtime key. Raw regions carved to "
                    "extracted/ for downstream work. See by-packer/jiagu.md."
                ),
            })
            stages.append({
                "name": "inner_dex_decryption",
                "ok": False,
                "detail": "bulk payload flagged unrecoverable — runtime-derived key + anti-debug gating",
            })

    # ------------------------------------------------------------------
    # Stage 7 — Plaintext code_item recovery (NEW 2026-05-18)
    # ------------------------------------------------------------------
    #
    # Empirical finding: Jiagu's "encrypted" data section is only
    # PARTIALLY encrypted. The class/method/string ID tables are
    # encrypted into `pre_e0` (~1 MB, full entropy ≈ 7.999), but the
    # bulk Dalvik method bodies are concatenated as plaintext
    # `code_item` structures across:
    #   - the latter ~2.6 MB of entry 0 (already carved as
    #     jiagu_entry0_body.bin)
    #   - the plaintext middle of post_e0 (~2.2 MB of low-entropy
    #     DEX data, identified by a 256-byte sliding entropy window)
    #
    # This stage walks all plaintext regions, parses every valid
    # code_item (16-byte header + ins + try_item[] +
    # encoded_catch_handler_list), and:
    #   - writes a serialised forensic blob (jiagu_recovered_code_items.bin)
    #   - builds a synthetic DEX (jiagu_recovered.dex) that wraps the
    #     recovered method bodies as `LRecovered::m00000`, `m00001`, ...
    #     so analysts can run dexdump / androguard on the bytecode.
    # The metadata (real class names, method signatures, field IDs) is
    # NOT recovered — it lives in the encrypted pre_e0 — but the
    # bytecode bodies themselves are the high-value forensic artefact.
    if trailer_summary is not None:
        try:
            entry0_body_path = extracted_dir / "jiagu_entry0_body.bin"
            post_e0_path = extracted_dir / "jiagu_post_e0.bin"
            pre_e0_path = extracted_dir / "jiagu_pre_e0.bin"
            e0_body = entry0_body_path.read_bytes() if entry0_body_path.exists() else b""
            post_e0 = post_e0_path.read_bytes() if post_e0_path.exists() else b""
            pre_e0 = pre_e0_path.read_bytes() if pre_e0_path.exists() else b""
            if e0_body or post_e0:
                items, rec = recover_from_carved(e0_body, post_e0, pre_e0)
                if items:
                    # Serialised forensic blob with per-item TLV index
                    ser_path = extracted_dir / "jiagu_recovered_code_items.bin"
                    ser = serialize_code_items(items)
                    ser_path.write_bytes(ser)
                    # Synthetic DEX
                    syn_path = extracted_dir / "jiagu_recovered.dex"
                    try:
                        syn_dex = build_synthetic_dex(items)
                        syn_path.write_bytes(syn_dex)
                        rec.synthetic_dex_bytes = len(syn_dex)
                        synthetic_ok = True
                    except Exception as e:                       # pragma: no cover
                        syn_dex = b""
                        synthetic_ok = False
                        if verbose:
                            print(f"[jiagu] synthetic DEX build failed: {e}")
                    recovered.append({
                        "name": str(syn_path.relative_to(out_dir.parent) if syn_path.exists() else syn_path.name),
                        "out_path": str(syn_path),
                        "size": rec.synthetic_dex_bytes,
                        "ok": synthetic_ok and rec.synthetic_dex_bytes > 0,
                        "valid_dex_magic": rec.synthetic_dex_bytes > 0,
                        "recovery": (
                            "synthetic DEX wrapping {} recovered plaintext "
                            "code_items (method names are synthetic; "
                            "bytecode is real)".format(rec.total_code_items)
                        ),
                    })
                    notes["plaintext_code_items"] = {
                        "total": rec.total_code_items,
                        "entry0": rec.entry0_code_items,
                        "post_e0": rec.post_e0_code_items,
                        "pre_e0": rec.pre_e0_code_items,
                        "total_bytecode_bytes": rec.total_bytes,
                        "plaintext_runs_post_e0": rec.plaintext_runs_post_e0,
                        "serialized_blob": str(ser_path.relative_to(out_dir.parent)),
                        "serialized_blob_size": len(ser),
                        "synthetic_dex": str(syn_path.relative_to(out_dir.parent)) if synthetic_ok else None,
                        "synthetic_dex_size": rec.synthetic_dex_bytes,
                    }
                    stages.append({
                        "name": "plaintext_code_item_recovery",
                        "ok": True,
                        "detail": (
                            f"recovered {rec.total_code_items} code_items "
                            f"({rec.entry0_bytes + rec.post_e0_bytes:,} bytes) — "
                            f"entry0={rec.entry0_code_items}, post_e0={rec.post_e0_code_items}, "
                            f"pre_e0={rec.pre_e0_code_items}; synthetic DEX "
                            f"={'yes' if synthetic_ok else 'failed'} ({rec.synthetic_dex_bytes} bytes)"
                        ),
                    })
                    if verbose:
                        print(
                            f"[jiagu] recovered {rec.total_code_items} plaintext code_items "
                            f"({rec.total_bytes:,} bytes) → {ser_path.name}, "
                            f"synthetic DEX → {syn_path.name} ({rec.synthetic_dex_bytes:,} bytes)"
                        )
        except Exception as e:                           # pragma: no cover
            stages.append({
                "name": "plaintext_code_item_recovery",
                "ok": False,
                "detail": f"exception: {e}",
            })

    # ------------------------------------------------------------------
    # Stage 8 (OPTIONAL) — Unicorn-based emulation of libjiagu_a64.so
    # ------------------------------------------------------------------
    #
    # Static carving above recovers the trailer metadata and entry-0
    # plaintext code-items, but the bulk DEX (entries 1..n-1) is
    # encrypted under a per-build key that lives only inside the SO at
    # runtime. To reach it we run libjiagu_a64.so under a Unicorn
    # AArch64 emulator (no device, no Frida, no ART). The harness:
    #
    #   - maps the SO's PT_LOAD segments
    #   - resolves dynamic relocations + JMPRELs (libc imports → BRK
    #     trampolines we service from Python)
    #   - runs the DT_INIT_ARRAY entries
    #   - calls JNI_OnLoad with a mocked JavaVM/JNIEnv that captures
    #     FindClass / RegisterNatives / DefineClass
    #   - scans the heap for DEX magic + checksums at exit
    #
    # The harness is OPT-IN because the JNI mock surface is large and
    # many builds short-circuit on anti-debug checks the emulator
    # doesn't honour. Even when no full DEX is captured, the harness
    # produces a trace of JNI calls + heap allocations that is
    # diagnostically useful (and a basis for future improvement). See
    # `packer_backends/jiagu_unicorn.py` for the harness design.

    # Static cipher analysis of libjiagu_a64.so — always runs (no
    # execution required, fast, useful even without --use-unicorn).
    # Records the modified-RC4 PRGA vaddr and the XOR-0xa5 loader-
    # strings region. See `packer_backends/jiagu_static_cipher.py`
    # for the algorithm.
    try:
        from . import jiagu_static_cipher as jsc
        cipher_info = {}
        primary_so = None
        for n in jiagu_so + variant_so:
            if "_a64" in n or "a64" in n.lower():
                primary_so = n
                break
        if primary_so is None and (jiagu_so or variant_so):
            primary_so = (jiagu_so + variant_so)[0]
        if primary_so:
            so_path = extracted_dir / primary_so.replace("/", "_")
            if so_path.exists():
                so_bytes = so_path.read_bytes()
                summary = jsc.summarise(so_bytes)
                cipher_info["so"] = primary_so
                cipher_info["rc4_prgas"] = [
                    {
                        "prologue_va": r.prologue_va,
                        "prga_inner_va": r.prga_inner_va,
                        "loop_end_va": r.loop_end_va,
                        "ret_vas": r.ret_vas,
                    } for r in summary.rc4_prgas
                ]
                if summary.xor_a5 is not None:
                    # Persist the decoded loader strings — useful forensics.
                    strings_path = extracted_dir / "jiagu_loader_strings_xor_a5.txt"
                    with open(strings_path, "w") as f:
                        f.write(
                            f"# Jiagu loader-strings region in {primary_so}\n"
                            f"# XOR-0xa5-decoded, starts at offset {summary.xor_a5.start_off:#x}\n"
                            f"# {len(summary.xor_a5.decoded_strings)} ASCII runs (>=6 chars)\n\n"
                        )
                        for s in summary.xor_a5.decoded_strings:
                            try:
                                f.write(s.decode("utf-8") + "\n")
                            except UnicodeDecodeError:
                                f.write(repr(s) + "\n")
                    cipher_info["xor_a5_region"] = {
                        "start_off": summary.xor_a5.start_off,
                        "n_anchor_matches": summary.xor_a5.n_anchor_matches,
                        "n_strings": len(summary.xor_a5.decoded_strings),
                        "strings_out": str(strings_path.relative_to(out_dir.parent)),
                    }
                else:
                    cipher_info["xor_a5_region"] = None
                stages.append({
                    "name": "static_cipher_analysis",
                    "ok": bool(summary.rc4_prgas),
                    "detail": (
                        f"RC4 PRGA: {len(summary.rc4_prgas)} found; "
                        f"XOR-0xa5: {'yes' if summary.xor_a5 else 'no'} "
                        f"({summary.xor_a5.n_anchor_matches if summary.xor_a5 else 0} anchors)"
                    ),
                })
                notes["jiagu_static_cipher"] = cipher_info
    except Exception as e:                            # pragma: no cover
        stages.append({
            "name": "static_cipher_analysis",
            "ok": False,
            "detail": f"static cipher analysis failed: {e!r}",
        })

    # Static inner-SO decryption — uses the hardcoded Jiagu-RC4 key
    # discovered 2026-05-19 to fully decrypt the inner-SO payload
    # without Unicorn. See packer_backends/jiagu_rc4.py.
    try:
        from . import jiagu_rc4 as jrc4
        primary_so = None
        for n in jiagu_so + variant_so:
            if "_a64" in n or "a64" in n.lower():
                primary_so = n
                break
        if primary_so:
            so_path = extracted_dir / primary_so.replace("/", "_")
            if so_path.exists():
                so_bytes = so_path.read_bytes()
                inner = jrc4.find_inner_so_payload(so_bytes)
                if inner is not None:
                    va, _, inflated = inner
                    inner_path = extracted_dir / "jiagu_inner_so_decrypted.bin"
                    inner_path.write_bytes(inflated)
                    stages.append({
                        "name": "inner_so_decrypt",
                        "ok": True,
                        "detail": (
                            f"inner-SO payload at vaddr {va:#x}, decrypted + "
                            f"inflated to {len(inflated)} bytes "
                            f"({inner_path.name})"
                        ),
                    })
                    notes["jiagu_inner_so"] = {
                        "payload_vaddr": va,
                        "inflated_size": len(inflated),
                        "key_hex": jrc4.INNER_SO_KEY.hex(),
                        "out_file": str(inner_path.relative_to(out_dir.parent)),
                    }
                else:
                    stages.append({
                        "name": "inner_so_decrypt",
                        "ok": False,
                        "detail": "no RC4+zlib payload found at any vaddr in any PT_LOAD segment (build may use different cipher/key)",
                    })
    except Exception as e:                            # pragma: no cover
        stages.append({
            "name": "inner_so_decrypt",
            "ok": False,
            "detail": f"inner-SO decryption failed: {e!r}",
        })

    if use_unicorn:
        try:
            from . import jiagu_unicorn as ju
        except Exception as e:                       # pragma: no cover
            stages.append({
                "name": "unicorn_pass",
                "ok": False,
                "detail": f"could not import jiagu_unicorn: {e}",
            })
        else:
            # The harness needs the SO and (optionally) a synthetic
            # filesystem keyed on asset path. For now we don't seed any
            # asset bytes — JNI_OnLoad almost never actually opens
            # /assets through libc, it goes through AssetManager which
            # we mock at the JNI layer.
            so_paths = []
            so_paths.extend(jiagu_so)
            so_paths.extend(variant_so)
            # Prefer the a64 loader.
            so_targets = [n for n in so_paths if "_a64" in n or "a64" in n.lower()] or so_paths
            unicorn_results = []
            for so_name in so_targets[:1]:           # one specimen is enough
                so_path = extracted_dir / so_name.replace("/", "_")
                if not so_path.exists():
                    continue
                if verbose:
                    print(f"[jiagu] unicorn: emulating {so_path.name}")
                if not ju.HAS_UNICORN:
                    stages.append({
                        "name": "unicorn_pass",
                        "ok": False,
                        "detail": "unicorn module not installed",
                    })
                    break
                # Pull build-specific seeds from the qh trailer we parsed
                # in stage 4. The Jiagu loader reads these values during its
                # JNI bring-up to derive its per-build key — feeding them
                # back unsticks the emulator at `GetStringUTFChars(pkg)`.
                pkg = (trailer_summary or {}).get("package") if trailer_summary else None
                apk_md5 = (trailer_summary or {}).get("apk_md5") if trailer_summary else None
                # Seed the encrypted-DEX asset bytes when present.
                asset_bytes = {}
                for so_asset in jiagu_so + variant_so:
                    pth = extracted_dir / so_asset.replace("/", "_")
                    if pth.exists():
                        asset_bytes[so_asset] = pth.read_bytes()
                # `.jgapp` is sometimes also referenced by the loader.
                jgapp_pth = extracted_dir / "assets_.jgapp"
                if jgapp_pth.exists():
                    asset_bytes["assets/.jgapp"] = jgapp_pth.read_bytes()
                res = ju.emulate_libjiagu(
                    str(so_path),
                    asset_paths=None,
                    package_name=pkg,
                    apk_md5=apk_md5,
                    asset_bytes=asset_bytes,
                    max_instructions=unicorn_insns,
                    mock_inner_so=unicorn_mock_inner_so,
                    verbose=verbose,
                )
                # Persist the captured DEX payloads.
                for i, dex in enumerate(res.dex_payloads):
                    out_path = extracted_dir / f"jiagu_unicorn_dex_{i}.dex"
                    with open(out_path, "wb") as f:
                        f.write(dex)
                    recovered.append({
                        "name": str(out_path.relative_to(out_dir.parent)),
                        "valid_dex_magic": dex[:4] in (b"dex\n", b"DEX\n"),
                        "size": len(dex),
                        "ok": dex[:4] in (b"dex\n", b"DEX\n"),
                        "recovery": "captured by Unicorn emulation of libjiagu_a64.so",
                    })
                # Persist captured decrypt buffers (RC4 + SIMD-XOR) and
                # the registered-natives table to disk for forensic review.
                if res.xor_captures:
                    for idx, (va, sz, buf) in enumerate(res.xor_captures[:5]):
                        p = extracted_dir / f"jiagu_unicorn_xor_capture_{idx}.bin"
                        p.write_bytes(buf)
                if res.rc4_captures:
                    for idx, (va, sz, buf) in enumerate(res.rc4_captures[:5]):
                        p = extracted_dir / f"jiagu_unicorn_rc4_capture_{idx}.bin"
                        p.write_bytes(buf)
                if res.registered_natives:
                    rn_path = extracted_dir / "jiagu_unicorn_registered_natives.txt"
                    with open(rn_path, "w") as f:
                        for cls, lst in res.registered_natives.items():
                            f.write(f"# class {cls} ({len(lst)} methods)\n")
                            for nm, sg, fv in lst:
                                f.write(f"  {nm} {sg} → {hex(fv)}\n")
                if res.inner_so_required_symbols:
                    inner_path = extracted_dir / "jiagu_unicorn_inner_so_required_symbols.txt"
                    with open(inner_path, "w") as f:
                        f.write(
                            "# Symbols the second-stage __arm_a_1 looks up\n"
                            "# via the custom dlsym (0xca38). These are the\n"
                            "# public export interface that Jiagu's inner SO\n"
                            "# must implement. Use this list to validate any\n"
                            "# inner-SO recovery attempt.\n"
                        )
                        for sym in res.inner_so_required_symbols:
                            f.write(f"  {sym}\n")
                # Persist the trace for forensics.
                trace_path = extracted_dir / f"jiagu_unicorn_trace_{so_path.stem}.txt"
                with open(trace_path, "w") as f:
                    f.write(f"# Unicorn emulation of {so_path.name}\n")
                    f.write(f"status = {res.status}\n")
                    f.write(f"insns_executed = {res.insns_executed}\n")
                    f.write(f"elapsed_sec = {res.elapsed_sec:.3f}\n")
                    f.write(f"error = {res.error}\n\n")
                    f.write("## JNI trace\n")
                    for line in res.jni_trace:
                        f.write(line + "\n")
                    f.write("\n## syscall trace (first/last 200 entries)\n")
                    if len(res.syscall_trace) <= 400:
                        for line in res.syscall_trace:
                            f.write(line + "\n")
                    else:
                        for line in res.syscall_trace[:200]:
                            f.write(line + "\n")
                        f.write(f"...\n[ {len(res.syscall_trace) - 400} lines omitted ]\n...\n")
                        for line in res.syscall_trace[-200:]:
                            f.write(line + "\n")
                unicorn_results.append({
                    "so": so_path.name,
                    "status": res.status,
                    "insns": res.insns_executed,
                    "elapsed_sec": res.elapsed_sec,
                    "dex_captured": len(res.dex_payloads),
                    "phase2_inner_so_required_symbols": res.inner_so_required_symbols,
                    "phase2_inner_jni_onload_invoked": res.inner_jni_onload_invoked,
                    "phase2_registered_natives_classes": len(res.registered_natives or {}),
                    "phase2_registered_natives_methods": sum(
                        len(v) for v in (res.registered_natives or {}).values()
                    ),
                    "jni_calls": len(res.jni_trace),
                    "syscalls": len(res.syscall_trace),
                    "trace_path": str(trace_path.relative_to(out_dir.parent)),
                })
            if unicorn_results:
                stages.append({
                    "name": "unicorn_pass",
                    "ok": any(u["dex_captured"] > 0 for u in unicorn_results),
                    "detail": ("Unicorn-emulated libjiagu_a64.so. "
                               + "; ".join(
                                   f"{u['so']}: status={u['status']} insns={u['insns']:,} "
                                   f"dex={u['dex_captured']} jni={u['jni_calls']}"
                                   for u in unicorn_results)),
                })
                notes["unicorn"] = unicorn_results

    manifest = {
        "packer": PACKER_NAME,
        "backend": __name__,
        "input": os.path.abspath(input_path),
        "out_dir": str(out_dir.resolve()),
        "options": {"verbose": verbose, "force": force,
                    "use_unicorn": use_unicorn,
                    "unicorn_insns": unicorn_insns if use_unicorn else 0},
        "stages": stages,
        "recovered_dexs": recovered,
        "unrecovered": unrecovered,
        "notes": notes,
    }
    _common.write_manifest(out_dir, manifest)
    _common.write_unrecovered(out_dir, unrecovered, PACKER_NAME)

    if verbose:
        n_meta = trailer_summary["metadata"] if trailer_summary else []
        print(f"[jiagu] markers: jgapp={jgapp} libjiagu={len(jiagu_so)} "
              f"variants={len(variant_so)} sdk_libs={len(sdk_libs)}")
        print(f"[jiagu] real Application class: {real_app or '(unresolved)'}")
        if trailer_summary:
            print(f"[jiagu] trailer: {len(n_meta)} metadata entries, "
                  f"{trailer_summary['n_entries']} encrypted data entries, "
                  f"data section {trailer_summary['data_section_len']} bytes")
            print(f"[jiagu] package={trailer_summary['package']!r} "
                  f"version={trailer_summary['version_name']!r} "
                  f"protected_at={trailer_summary['protect_time']!r}")
            print(f"[jiagu] jiagu_version={trailer_summary['jiagu_version']!r} "
                  f"entry0_format={trailer_summary['entry0_format']!r}")
        print(f"[jiagu] {len(carved)} Jiagu artefact(s) carved → {extracted_dir}")
        e0_fmt = (trailer_summary or {}).get("entry0_format", "unknown")
        if e0_fmt == "v1_plaintext_codeitems":
            print("[jiagu] PARTIAL recovery: entry 0 body is plaintext code_items")
        else:
            print("[jiagu] bulk DEX payload flagged unrecoverable (runtime-derived key)")

    return manifest
