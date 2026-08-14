#!/usr/bin/env python3
"""
dump_virbox_dex.py — Static, no-execution recovery tool for Virbox-protected APKs.

Target packer: Virbox Protector for Android, vendor Senstor (深思数盾).

What this tool does (all statically; the target's native code is never invoked):

  1. If given an XAPK (APK-Pure bundle), it picks out the *base* APK by reading
     `manifest.json`.

  2. It identifies the build's Virbox markers:
       - Application class name `v<buildId>.l<buildId>` declared in
         `AndroidManifest.xml` (§virbox-analysis.md §3).
       - `Lvirbox/StubApp;` + inner classes in the outer DEX (§3).
       - Helper class `Lm<buildId>;` declaring 10–16 `F<buildId>_NN` native
         dispatcher methods (§4.2).
       - Per-arch asset SO `assets/l<buildId>_<arch>.so` (§3).

  3. It walks every `classesN.dex` in the APK. For each DEX:
       - Checks DEX magic + recorded `file_size` + sha1 + adler32.
       - Looks for an in-DEX VBPD container (Report §6 — legacy r21e). The
         container is stored inside the DEX's `data` section, with its `VBPD`
         magic at +0x13c from the container start. If found, the whole
         container is extracted to `vbpd_<dex_name>.bin` for downstream
         forensic review. Not present in target.xapk (strings-only build).

  4. If the APK ships a SENS file (`assets/*.dat` with the `SENS` magic;
     legacy r21e layout, Report §6), the tool:
       - Validates the SENS structure.
       - XOR-0x2A-decodes the 16-byte obfuscated cipher key.
       - For `record_count > 0` builds, hashes every APK entry's filename
         with the recovered 64-bit rolling hash (§5.3) and decrypts the
         matched entries with the NEON polynomial cipher
         `keystream[j] = (x8 * (base + j)) & 0xff` (§5.4).
       - For `record_count = 0` builds, it stops at this layer — the body
         cipher is runtime-resolved (`*(SO+0x30fde0)`) and cannot be
         executed statically (Report §6 / FINDINGS_REVIEW §5b, and
         findings/UNRECOVERED.md). Not exercised for target.xapk
         (no SENS file).

  5. It harvests every call-site of `Lm<buildId>;->F<buildId>_NN(...)` in the
     plaintext DEXs and emits a JSON dispatch table (Report §5). Distinguishes:
       - **F<buildId>_11** (vm_str deobfuscator, Report §7) — statically
         reversible; a corpus of decoded strings is written to
         `decoded_strings/<dex>.txt`. On target.xapk: 191,505 strings decoded.
       - **F<buildId>_00..09** (generic VMP dispatch with `int idx,
         Object[] args` signature, Report §8) — NOT statically recoverable;
         each call-site is added to `UNRECOVERED.md`. On target.xapk:
         0 such call-sites in any of the 10 DEXs.
       - **F<buildId>_10..15** (specialised helpers — Object cast, asset/
         resource/classloader hooks, Object→String — Report §5) — listed
         but not "unrecovered" per se; behaviour depends on SO state.

  6. It writes a `summary.json` covering every step (Virbox markers found,
     SENS path, list of recovered DEXs with their internal stats, etc.).
     Every section in the report (`findings/virbox-analysis.md`) is
     cross-referenced from the relevant tool step via inline `# Report §N`
     comments.

Run me with:

    python3 dump_virbox_dex.py <APK or XAPK> -o <output_dir> [--verbose]

Returns 0 on success, non-zero if the input isn't recognisable as a Virbox
package.  The `--test` mode produces a one-line PASS/FAIL classification
suitable for CI / regression use.

References:
  - findings/virbox-analysis.md — the long-form report
  - findings/UNRECOVERED.md     — list of methods needing runtime VME
  - virbox_bundle/FINDINGS_REVIEW.md — prior-art catalogue
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zipfile
import zlib
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

# ───────────────────────────────────────────────────────────────────────────
# Section 0 — constants (Report §3)
# ───────────────────────────────────────────────────────────────────────────

VIRBOX_STUB_CLASSES = (b"Lvirbox/StubApp", b"Lvirbox/Application")
VIRBOX_VME_ERROR_STR = b"virbox error: unused ins in vm"
VIRBOX_SO_ID_STR     = b"virbox/%s"
VIRBOX_BUILDID_FMT   = re.compile(rb"v[0-9a-f]{8}\.l[0-9a-f]{8}", re.IGNORECASE)
# UTF-16-LE-encoded equivalent (Android binary AXML stores strings as UTF-16):
VIRBOX_BUILDID_FMT_UTF16LE = re.compile(
    (rb"v\x00[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00"
     rb"[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00\.\x00"
     rb"l\x00[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00"
     rb"[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00[0-9a-f]\x00"),
    re.IGNORECASE)

VBPD_MAGIC = b"VBPD"
VBPD_MAGIC_OFFSET_IN_CONTAINER = 0x13c   # Report §6 (legacy r21e VBPD layout)

SENS_MAGIC = b"SENS"
SENS_KEY_OFFSET = 8
SENS_KEY_LEN = 16
SENS_RECCOUNT_OFFSET = 0x1c
SENS_RECORDS_OFFSET = 0x20

# ───────────────────────────────────────────────────────────────────────────
# Section 1 — XAPK / APK input handling
# ───────────────────────────────────────────────────────────────────────────


def open_input(path: Path, work_dir: Path) -> Path:
    """Resolve an APK or XAPK path to a single base APK file.

    XAPK is an apkpure.com bundle: a ZIP that contains:
      - `manifest.json` (JSON describing the bundle)
      - `<package>.apk` (the base APK)
      - `config.<abi>.apk` (per-arch split APKs)

    For a plain APK we return the input untouched.  For an XAPK we extract
    the base APK named by `manifest.json.split_apks[id=base]` into
    `work_dir/base.apk` and return that path.
    """
    if not path.exists():
        raise SystemExit(f"input not found: {path}")

    # First sniff the magic to confirm it's a ZIP.
    with path.open("rb") as f:
        magic = f.read(4)
    if magic[:2] != b"PK":
        raise SystemExit(f"{path}: not a ZIP/APK/XAPK (magic={magic!r})")

    # Heuristic: an XAPK has a manifest.json describing split_apks.
    try:
        with zipfile.ZipFile(path) as zf:
            names = set(zf.namelist())
            if "manifest.json" in names and any(n.endswith(".apk") for n in names):
                manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
                splits = manifest.get("split_apks") or []
                base = next((s for s in splits if s.get("id") == "base"), None)
                if base is None:
                    # Fallback: pick the largest .apk entry
                    apks = [(zf.getinfo(n).file_size, n) for n in names
                            if n.endswith(".apk")]
                    apks.sort(reverse=True)
                    if not apks:
                        raise SystemExit(f"{path}: XAPK contains no .apk entry")
                    base_name = apks[0][1]
                else:
                    base_name = base["file"]
                work_dir.mkdir(parents=True, exist_ok=True)
                out = work_dir / "base.apk"
                with out.open("wb") as fout:
                    fout.write(zf.read(base_name))
                return out
    except zipfile.BadZipFile:
        raise SystemExit(f"{path}: corrupt ZIP")

    return path  # Plain APK — already a base.


# ───────────────────────────────────────────────────────────────────────────
# Section 2 — DEX header & string-table parsing (raw, no androguard)
# Used because the target APK ships 10×~10 MB DEXs which together OOM
# androguard. Raw parsing is fast and zero-allocation for what we need.
# ───────────────────────────────────────────────────────────────────────────

DEX_HDR_KEYS = ("string_ids_size", "string_ids_off",
                "type_ids_size", "type_ids_off",
                "proto_ids_size", "proto_ids_off",
                "field_ids_size", "field_ids_off",
                "method_ids_size", "method_ids_off",
                "class_defs_size", "class_defs_off",
                "data_size", "data_off")
DEX_HDR_OFFSETS = (56, 60, 64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108)


def parse_dex_header(d: bytes) -> dict:
    return {k: struct.unpack("<I", d[o:o+4])[0]
            for k, o in zip(DEX_HDR_KEYS, DEX_HDR_OFFSETS)}


def uleb128(d: bytes, off: int) -> tuple[int, int]:
    """Decode a ULEB128 starting at `off`; return (value, next_off)."""
    val = 0; shift = 0
    while True:
        b = d[off]; off += 1
        val |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
    return val, off


def get_string(d: bytes, hdr: dict, idx: int) -> str:
    """Read a UTF-8 (technically MUTF-8) string from string-ids table[idx]."""
    sid_off = hdr["string_ids_off"] + idx * 4
    data_off = struct.unpack("<I", d[sid_off:sid_off+4])[0]
    _length, p = uleb128(d, data_off)
    end = d.find(b"\x00", p)
    return d[p:end].decode("utf-8", errors="replace")


def get_type(d: bytes, hdr: dict, idx: int) -> str:
    sid_off = hdr["type_ids_off"] + idx * 4
    str_idx = struct.unpack("<I", d[sid_off:sid_off+4])[0]
    return get_string(d, hdr, str_idx)


def get_method(d: bytes, hdr: dict, idx: int) -> tuple[str, str, int]:
    """Return (class_descriptor, method_name, proto_id)."""
    moff = hdr["method_ids_off"] + idx * 8
    class_id, proto_id, name_id = struct.unpack("<HHI", d[moff:moff+8])
    return get_type(d, hdr, class_id), get_string(d, hdr, name_id), proto_id


def get_proto(d: bytes, hdr: dict, proto_id: int) -> tuple[str, str]:
    """Return (return_type_descriptor, joined_param_descriptors)."""
    poff = hdr["proto_ids_off"] + proto_id * 12
    _shorty_idx, return_type_idx, params_off = struct.unpack("<III", d[poff:poff+12])
    rt = get_type(d, hdr, return_type_idx)
    if params_off == 0:
        return rt, ""
    n = struct.unpack("<I", d[params_off:params_off+4])[0]
    parts = []
    for i in range(n):
        tid = struct.unpack("<H", d[params_off + 4 + i*2:params_off + 6 + i*2])[0]
        parts.append(get_type(d, hdr, tid))
    return rt, "".join(parts)


# Dalvik instruction widths (in bytes). 0 marks payloads (handled specially).
INSN_WIDTH = {
    0x00: 2, 0x01: 2, 0x02: 4, 0x03: 6, 0x04: 2, 0x05: 4, 0x06: 6, 0x07: 2,
    0x08: 4, 0x09: 6, 0x0a: 2, 0x0b: 2, 0x0c: 2, 0x0d: 2, 0x0e: 2, 0x0f: 2,
    0x10: 2, 0x11: 2, 0x12: 2, 0x13: 4, 0x14: 6, 0x15: 4, 0x16: 4, 0x17: 6,
    0x18: 10, 0x19: 4, 0x1a: 4, 0x1b: 6, 0x1c: 4, 0x1d: 2, 0x1e: 2, 0x1f: 4,
    0x20: 4, 0x21: 2, 0x22: 4, 0x23: 4, 0x24: 6, 0x25: 6, 0x26: 6, 0x27: 2,
    0x28: 2, 0x29: 4, 0x2a: 6, 0x2b: 6, 0x2c: 6, 0x2d: 4, 0x2e: 4, 0x2f: 4,
    0x30: 4, 0x31: 4, 0x32: 4, 0x33: 4, 0x34: 4, 0x35: 4, 0x36: 4, 0x37: 4,
    0x38: 4, 0x39: 4, 0x3a: 4, 0x3b: 4, 0x3c: 4, 0x3d: 4,
    0x44: 4, 0x45: 4, 0x46: 4, 0x47: 4, 0x48: 4, 0x49: 4, 0x4a: 4, 0x4b: 4,
    0x4c: 4, 0x4d: 4, 0x4e: 4, 0x4f: 4, 0x50: 4, 0x51: 4,
    0x52: 4, 0x53: 4, 0x54: 4, 0x55: 4, 0x56: 4, 0x57: 4, 0x58: 4, 0x59: 4,
    0x5a: 4, 0x5b: 4, 0x5c: 4, 0x5d: 4, 0x5e: 4, 0x5f: 4, 0x60: 4, 0x61: 4,
    0x62: 4, 0x63: 4, 0x64: 4, 0x65: 4, 0x66: 4, 0x67: 4, 0x68: 4, 0x69: 4,
    0x6a: 4, 0x6b: 4, 0x6c: 4, 0x6d: 4, 0x6e: 6, 0x6f: 6, 0x70: 6, 0x71: 6,
    0x72: 6, 0x73: 2, 0x74: 6, 0x75: 6, 0x76: 6, 0x77: 6, 0x78: 6, 0x79: 2,
    0x7a: 2, 0x7b: 2, 0x7c: 2, 0x7d: 2, 0x7e: 2, 0x7f: 2, 0x80: 2, 0x81: 2,
    0x82: 2, 0x83: 2, 0x84: 2, 0x85: 2, 0x86: 2, 0x87: 2, 0x88: 2, 0x89: 2,
    0x8a: 2, 0x8b: 2, 0x8c: 2, 0x8d: 2, 0x8e: 2, 0x8f: 2,
    0x90: 4, 0x91: 4, 0x92: 4, 0x93: 4, 0x94: 4, 0x95: 4, 0x96: 4, 0x97: 4,
    0x98: 4, 0x99: 4, 0x9a: 4, 0x9b: 4, 0x9c: 4, 0x9d: 4, 0x9e: 4, 0x9f: 4,
    0xa0: 4, 0xa1: 4, 0xa2: 4, 0xa3: 4, 0xa4: 4, 0xa5: 4, 0xa6: 4, 0xa7: 4,
    0xa8: 4, 0xa9: 4, 0xaa: 4, 0xab: 4, 0xac: 4, 0xad: 4, 0xae: 4, 0xaf: 4,
    0xb0: 2, 0xb1: 2, 0xb2: 2, 0xb3: 2, 0xb4: 2, 0xb5: 2, 0xb6: 2, 0xb7: 2,
    0xb8: 2, 0xb9: 2, 0xba: 2, 0xbb: 2, 0xbc: 2, 0xbd: 2, 0xbe: 2, 0xbf: 2,
    0xc0: 2, 0xc1: 2, 0xc2: 2, 0xc3: 2, 0xc4: 2, 0xc5: 2, 0xc6: 2, 0xc7: 2,
    0xc8: 2, 0xc9: 2, 0xca: 2, 0xcb: 2, 0xcc: 2, 0xcd: 2, 0xce: 2, 0xcf: 2,
    0xd0: 4, 0xd1: 4, 0xd2: 4, 0xd3: 4, 0xd4: 4, 0xd5: 4, 0xd6: 4, 0xd7: 4,
    0xd8: 4, 0xd9: 4, 0xda: 4, 0xdb: 4, 0xdc: 4, 0xdd: 4, 0xde: 4, 0xdf: 4,
    0xe0: 4, 0xe1: 4, 0xe2: 4,
    0xfa: 8, 0xfb: 10, 0xfc: 6, 0xfd: 6, 0xfe: 4, 0xff: 4,
}


def walk_methods(d: bytes, hdr: dict):
    """Iterate every method that has a non-zero code_off."""
    cdo = hdr["class_defs_off"]
    for ci in range(hdr["class_defs_size"]):
        off = cdo + ci * 32
        class_idx, _af, _si, _il, _sa, _sf, class_data_off, _sva = struct.unpack(
            "<8I", d[off:off+32])
        if class_data_off == 0:
            continue
        cls_name = get_type(d, hdr, class_idx)
        p = class_data_off
        sf, p = uleb128(d, p)
        idf, p = uleb128(d, p)
        dm, p = uleb128(d, p)
        vm, p = uleb128(d, p)
        for _ in range(sf):
            _, p = uleb128(d, p); _, p = uleb128(d, p)
        for _ in range(idf):
            _, p = uleb128(d, p); _, p = uleb128(d, p)
        for kind, count in (("direct", dm), ("virtual", vm)):
            last_idx = 0
            for _ in range(count):
                d_idx, p = uleb128(d, p)
                _af2, p = uleb128(d, p)
                code_off, p = uleb128(d, p)
                last_idx += d_idx
                if code_off == 0:
                    continue
                yield (cls_name, last_idx, code_off)


def parse_code_item(d: bytes, code_off: int) -> tuple[int, int]:
    """Return (insns_off, insns_size_in_bytes) for the code_item at code_off."""
    registers_size, ins_size, outs_size, tries_size, debug_off, insns_size = \
        struct.unpack("<HHHHII", d[code_off:code_off+16])
    return code_off + 16, insns_size * 2


def disasm_iter(d: bytes, insns_off: int, insns_bytes: int):
    """Stream of (pc, opcode, raw_bytes) over a single method's bytecode."""
    end = insns_off + insns_bytes
    i = insns_off
    while i + 2 <= end:
        op = d[i]
        width = INSN_WIDTH.get(op, 2)
        if op in (0x00,):
            # nop OR payload pseudo-instruction. Payloads have a second-byte tag.
            tag = d[i+1] if i+1 < end else 0
            if tag == 0x01:  # packed-switch-payload
                size = struct.unpack("<H", d[i+2:i+4])[0]
                width = 8 + size * 4
            elif tag == 0x02:  # sparse-switch-payload
                size = struct.unpack("<H", d[i+2:i+4])[0]
                width = 4 + size * 8
            elif tag == 0x03:  # fill-array-data-payload
                element_width = struct.unpack("<H", d[i+2:i+4])[0]
                size = struct.unpack("<I", d[i+4:i+8])[0]
                bsize = size * element_width
                if bsize & 1:
                    bsize += 1
                width = 8 + bsize
        if width == 0:
            width = 2
        yield (i, op, d[i:i+width])
        i += width


# ───────────────────────────────────────────────────────────────────────────
# Section 3 — Virbox-marker detection (Report §3)
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class VirboxMarkers:
    application_class: str = ""
    build_id_hex: str = ""
    has_virbox_stub_class: bool = False
    m_class_name: str = ""           # e.g. "Lm53a46fa6;"
    f_methods: dict = field(default_factory=dict)  # name → descriptor
    asset_so_files: list = field(default_factory=list)
    sens_file: str = ""
    sens_record_count: Optional[int] = None
    so_so_id_string_present: bool = False
    confirmed: bool = False
    notes: list = field(default_factory=list)


def parse_application_from_manifest(manifest_xml_bytes: bytes) -> Optional[str]:
    """Pull the `<application android:name=...>` value out of binary AXML.

    We look for the literal stub-name regex `v[0-9a-f]{8}.l[0-9a-f]{8}`
    in the AXML string table — for Virbox builds this is reliable because
    the name is unique enough that no other appearance is plausible.
    Android binary AXML stores strings as UTF-16-LE, so we also try that
    encoding before giving up.
    """
    from collections import Counter
    # Try ASCII (sometimes embedded as a normal string) and UTF-16-LE (AXML's
    # native form) and merge results.
    found = []
    for m in VIRBOX_BUILDID_FMT.findall(manifest_xml_bytes):
        found.append(m.decode("ascii", errors="replace"))
    for m in VIRBOX_BUILDID_FMT_UTF16LE.findall(manifest_xml_bytes):
        # decode UTF-16-LE manually (the match has interleaved \x00s)
        try:
            s = m.decode("utf-16-le")
            found.append(s)
        except UnicodeDecodeError:
            pass
    if not found:
        return None
    return Counter(found).most_common(1)[0][0]


def scan_dex_for_F_methods(dex_bytes: bytes, expected_class: Optional[str] = None
                            ) -> dict[str, str]:
    """Return {method_name: descriptor_string} for every F<buildId>_NN native
    method declared in the helper class `Lm<buildId>;` (if expected_class is
    None we'll auto-detect)."""
    hdr = parse_dex_header(dex_bytes)
    found: dict[str, str] = {}
    auto_class = None
    for idx in range(hdr["method_ids_size"]):
        cls, name, proto = get_method(dex_bytes, hdr, idx)
        if not name.startswith("F") or "_" not in name:
            continue
        m = re.match(r"^F([0-9a-fA-F]{8})_(\d{2})$", name)
        if not m:
            continue
        # Verify class matches the auto-detected pattern Lm<buildId>;
        if not (cls.startswith("Lm") and cls.endswith(";")):
            continue
        if expected_class and cls != expected_class:
            continue
        auto_class = cls
        rt, params = get_proto(dex_bytes, hdr, proto)
        found[name] = f"({params}){rt}"
    return found, auto_class


def detect_virbox(apk_path: Path, verbose=False) -> VirboxMarkers:
    """Run the marker-detection pipeline against a base APK."""
    m = VirboxMarkers()
    with zipfile.ZipFile(apk_path) as zf:
        names = zf.namelist()

        # 1. Manifest stub Application class. (Report §3)
        if "AndroidManifest.xml" in names:
            mf = zf.read("AndroidManifest.xml")
            app = parse_application_from_manifest(mf)
            if app:
                m.application_class = app
                m.build_id_hex = app.split(".")[0][1:]  # drop leading 'v'
                if verbose:
                    print(f"  [+] Application class = {app}  (buildId={m.build_id_hex})")

        # 2. Asset SOs `l<buildId>_<arch>.so`. (Report §3)
        for n in sorted(names):
            if not n.startswith("assets/") or not n.endswith(".so"):
                continue
            stem = Path(n).name
            # Match l<8hex>_<arch>.so
            mo = re.match(r"^l([0-9a-fA-F]{8})_(a32|a64|x86|x64)\.so$", stem)
            if mo:
                m.asset_so_files.append({
                    "name": n, "buildId": mo.group(1), "arch": mo.group(2),
                    "size": zf.getinfo(n).file_size,
                })
                # If we hadn't picked up buildId from manifest, fall back.
                if not m.build_id_hex:
                    m.build_id_hex = mo.group(1)

        if not m.build_id_hex:
            m.notes.append("no Virbox build-id derived from manifest or asset SOs")
            return m

        if verbose:
            print(f"  [+] Found {len(m.asset_so_files)} per-arch asset SO(s)")

        # 3. Stub classes + Lm<buildId> helper. (Report §3 markers, §5 F-method table)
        m_class_expected = f"Lm{m.build_id_hex};"
        outer_dex = None
        for cand in ("classes.dex",) + tuple(
                f"classes{i}.dex" for i in range(2, 20)):
            if cand in names:
                if outer_dex is None:
                    outer_dex = cand
                dx = zf.read(cand)
                # Check for Lvirbox/StubApp string marker — present iff
                # this is the outer DEX with the Application stub.
                if any(pat in dx for pat in VIRBOX_STUB_CLASSES):
                    m.has_virbox_stub_class = True
                # F-method table — only in the DEX that declares Lm<id>;
                f, c = scan_dex_for_F_methods(dx, expected_class=m_class_expected)
                if f and not m.m_class_name:
                    m.m_class_name = c
                    m.f_methods = f
                    if verbose:
                        print(f"  [+] {c} declares {len(f)} F<buildId>_NN dispatchers in {cand}")

        # 4. SENS file (legacy r21e — may be absent in newer builds). (§4.1)
        for n in names:
            if not n.startswith("assets/") or not n.endswith(".dat"):
                continue
            sz = zf.getinfo(n).file_size
            if not (32 <= sz <= 5_000_000):
                continue
            blob = zf.read(n)
            if blob[:4] == SENS_MAGIC:
                m.sens_file = n
                m.sens_record_count = struct.unpack(
                    "<I", blob[SENS_RECCOUNT_OFFSET:SENS_RECCOUNT_OFFSET+4])[0]
                if verbose:
                    print(f"  [+] SENS file at {n} (records={m.sens_record_count})")
                break

        # 5. Self-ID string present in any SO. (§3)
        for so in m.asset_so_files:
            d = zf.read(so["name"])
            if VIRBOX_SO_ID_STR in d or VIRBOX_VME_ERROR_STR in d:
                m.so_so_id_string_present = True
                break

    # Confidence: any 3 of (stub class, m-helper, asset SO, SENS file, SO id-string)
    score = sum([
        m.has_virbox_stub_class,
        bool(m.m_class_name),
        bool(m.asset_so_files),
        bool(m.sens_file),
        m.so_so_id_string_present,
    ])
    m.confirmed = score >= 3
    if not m.confirmed:
        m.notes.append(
            f"only {score}/5 Virbox markers matched; classification uncertain")
    return m


# ───────────────────────────────────────────────────────────────────────────
# Section 4 — VBPD container extraction (Report §6 — legacy DEX-body container)
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class VBPDContainer:
    dex_name: str
    container_offset: int        # in DEX bytes
    magic_offset: int            # = container_offset + 0x13c
    container_size: int          # bytes
    header_size: int             # claimed in header
    ver: int                     # claimed in header
    count: int                   # claimed sections
    has_r21e_prologue: bool      # 21-byte invariant prologue match (any layout)
    prologue_layout: str         # "r21e-classic" | "r21e-body0" | "r22-split" | ""
    prologue: str                # hex of the 21-byte invariant (canonicalised)
    blob_path: str = ""


# The 20-byte invariant that appears in every Virbox VBPD container we have
# observed (across 224 of 235 Virbox samples in this corpus).  See SUMMARY.md §6
# for the placement table.  The trailing byte 0xf0 originally documented as
# part of an r21e prologue was sample-dependent and is therefore stripped from
# the canonical signature.
#
# Placement table observed in this corpus:
#     position (from VBPD magic)  | n samples | label
#     +0x40 (body+0)              |    24     | r21e-body0
#     +0x44 (body+4)              |     4     | r21e-classic
#     +0x38 (header[14..15]+body) |   196     | r22-split
#     +0x28 (header[10..14])     |    ~5     | r22-deep-split
#
# Any of these counts as "real" VBPD-encrypted body for our purposes; the
# trailing 12 bytes after the 20-byte invariant are part of the cipher
# payload (per the VBPD section table in FINDINGS_REVIEW §6).
VBPD_R21E_REF = bytes.fromhex("027c4c55abd5407641df4c8a9d72ca02675bacdc")
# Legacy export (still imported by some older helpers): 21-byte form with the
# (sample-dependent) trailing 0xf0 byte.
VBPD_R21E_REF_LEGACY21 = VBPD_R21E_REF + b"\xf0"


def find_vbpd_container(dex_bytes: bytes, dex_name: str) -> Optional[VBPDContainer]:
    """Locate the VBPD container (§4.3). Returns None if none present.

    Accepts all three observed prologue layouts.  See VBPD_R21E_REF block.
    """
    p = dex_bytes.find(VBPD_MAGIC)
    if p < 0:
        return None
    container_start = max(0, p - VBPD_MAGIC_OFFSET_IN_CONTAINER)
    sz = struct.unpack("<I", dex_bytes[p+4:p+8])[0]
    ver = struct.unpack("<I", dex_bytes[p+8:p+12])[0]
    count = struct.unpack("<I", dex_bytes[p+12:p+16])[0]

    # Find the 20-byte invariant anywhere in the first 128 bytes after the
    # magic.  Map the offset to one of the four known layouts.  Any match
    # confirms a "real" VBPD-encrypted body (i.e. not a coincidental match
    # of the bytes "VBPD" appearing somewhere in benign DEX content).
    head = dex_bytes[p:p+0x80]
    pos = head.find(VBPD_R21E_REF)
    layout = ""
    has_prologue = pos >= 0
    if pos == 0x40:
        layout = "r21e-body0"
    elif pos == 0x44:
        layout = "r21e-classic"
    elif pos == 0x38:
        layout = "r22-split"
    elif pos == 0x28:
        layout = "r22-deep-split"
    elif pos > 0:
        layout = f"other@+0x{pos:x}"

    return VBPDContainer(
        dex_name=dex_name,
        container_offset=container_start,
        magic_offset=p,
        container_size=len(dex_bytes) - container_start,
        header_size=sz,
        ver=ver,
        count=count,
        has_r21e_prologue=has_prologue,
        prologue_layout=layout,
        prologue=(head[pos:pos+20].hex() if pos >= 0 else head[0x40:0x40+20].hex()),
    )


# ───────────────────────────────────────────────────────────────────────────
# Section 5 — SENS / NEON cipher (Report §6 — legacy r21e records>0 path)
# Legacy "records>0" path: per-APK-entry stream-XOR decryption.
# Not exercised against target.xapk (no SENS file), but retained for the
# tool to be a complete static unpacker across the Virbox r21e family.
# ───────────────────────────────────────────────────────────────────────────

MASK64 = (1 << 64) - 1


def vmp_hash(name: bytes) -> int:
    """64-bit rolling hash recovered from itachi 0x2820b8 (Report §6 + FINDINGS_REVIEW §4)."""
    if not name:
        return 0
    h = 0
    i = 0
    b = name[0]
    name_p1 = name[1:] + b"\x00"
    while True:
        if (i & 1) == 0:
            x12 = h >> 3
            x11 = b ^ ((h << 7) & MASK64)
        else:
            x11 = (b & 0x7ff) | ((h & ((1 << 53) - 1)) << 11)
            x12 = (~(h >> 5)) & MASK64
        b = name_p1[i] if i < len(name_p1) else 0
        x11 ^= x12
        h = (h ^ x11) & MASK64
        i += 1
        if b == 0:
            break
    return h


def derive_x8(key: bytes) -> int:
    """NEON polynomial mixer (Report §6 + FINDINGS_REVIEW §5a, §11)."""
    K = key
    w8 = 0
    for shift, idx in ((1, 0), (2, 1), (3, 2), (4, 3), (5, 4), (6, 5), (7, 6)):
        w8 = (w8 + (K[idx] << shift)) & 0xFFFFFFFF
    return w8


def neon_decrypt(ct: bytes, x8: int, base: int = 100) -> bytes:
    """Stream-XOR with keystream[j] = (x8 * (base + j)) & 0xff."""
    return bytes(c ^ ((x8 * (base + j)) & 0xff) for j, c in enumerate(ct))


@dataclass
class SENSRecovery:
    cipher_key_hex: str
    x8: int
    record_count: int
    recovered_entries: list = field(default_factory=list)
    unmatched_hashes: int = 0


def decrypt_sens_protected_entries(zf: zipfile.ZipFile, sens_blob: bytes,
                                   out_dir: Path, verbose: bool = False
                                   ) -> SENSRecovery:
    """Run the records>0 NEON-decrypt pipeline. Returns a recovery summary
    object describing what could be statically restored.

    Report §6 / FINDINGS_REVIEW §5a: in r21e samples like itachi this
    restores 150/150 encrypted APK entries to readable plaintext / Android
    binary XML. Not exercised on target.xapk (no SENS file).
    """
    key = bytes(b ^ 0x2A for b in sens_blob[SENS_KEY_OFFSET:SENS_KEY_OFFSET+SENS_KEY_LEN])
    record_count = struct.unpack(
        "<I", sens_blob[SENS_RECCOUNT_OFFSET:SENS_RECCOUNT_OFFSET+4])[0]
    x8 = derive_x8(key)
    rec = SENSRecovery(cipher_key_hex=key.hex(), x8=x8,
                       record_count=record_count)

    if record_count == 0:
        # Records=0 path: body cipher is runtime-resolved (UNRECOVERED.md).
        return rec

    sens_hashes = set()
    for i in range(record_count):
        ro = SENS_RECORDS_OFFSET + i * 16
        sens_hashes.add(struct.unpack("<Q", sens_blob[ro:ro+8])[0])

    out_dir.mkdir(parents=True, exist_ok=True)
    for info in zf.infolist():
        h = vmp_hash(info.filename.encode("utf-8"))
        if h not in sens_hashes:
            continue
        ct = zf.read(info.filename)
        pt = neon_decrypt(ct, x8=x8, base=100)
        # write under the same relative path
        op = out_dir / info.filename
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_bytes(pt)
        rec.recovered_entries.append({
            "name": info.filename,
            "size": len(pt),
            "magic": pt[:4].hex(),
        })
        if verbose:
            print(f"    [+] decrypted {info.filename}  size={len(pt)}  magic={pt[:4].hex()}")
        sens_hashes.discard(h)
    rec.unmatched_hashes = len(sens_hashes)
    return rec


# ───────────────────────────────────────────────────────────────────────────
# Section 6 — VME `vm_str` cipher (Report §7)
# Statically reproduces F<buildId>_11(String)String.
# ───────────────────────────────────────────────────────────────────────────


def vm_str_decode(encoded: str) -> Optional[str]:
    """Reproduce the Virbox VME `vm_str` cipher (FINDINGS_REVIEW §11a):

        input = "<deco><key_char><hex>"
        ct    = bytes.fromhex(input[2:])
        key   = ord(input[1])
        pt[i] = ((ct[i] - i) & 0xFF) ^ key

    Returns None if the input doesn't conform to the encoding (which is the
    normal flag for "this is a plain Java string, leave it alone").
    """
    if len(encoded) < 2:
        return None
    hex_part = encoded[2:]
    if len(hex_part) == 0 or len(hex_part) & 1:
        return None
    try:
        ct = bytes.fromhex(hex_part)
    except ValueError:
        return None
    key = ord(encoded[1])
    try:
        pt = bytes(((c - i) & 0xff) ^ key for i, c in enumerate(ct))
        pt.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(b < 0x09 for b in pt):  # control chars other than tab → reject
        return None
    return pt.decode("utf-8")


# ───────────────────────────────────────────────────────────────────────────
# Section 7 — DEX walking: harvest F<buildId>_NN call-sites + decode vm_str
# (Report §5 F-method table; §7 vm_str; §8 VMP body dispatch)
# ───────────────────────────────────────────────────────────────────────────


@dataclass
class DexReport:
    name: str
    size: int
    sha256: str
    classes_count: int
    methods_count: int
    vbpd_container: Optional[dict] = None  # asdict(VBPDContainer)
    f_dispatch_sites: dict = field(default_factory=dict)
    # f_dispatch_sites: {"_11": {"sites": [{"class":..., "method":..., "encoded":...},
    #                                       ...],
    #                              "count": N},
    #                    "_05": {...}}
    decoded_strings: list = field(default_factory=list)
    vmp_protected_methods: list = field(default_factory=list)


def find_const_string_for_register(insns_bytes: bytes, invoke_off: int,
                                    insns_off: int, target_reg: int,
                                    string_ids_off: int, hdr: dict,
                                    dex_bytes: bytes) -> Optional[str]:
    """Walk *backwards* from `invoke_off` looking for the most recent
    `const-string` / `const-string/jumbo` that writes into register
    `target_reg`. We do this only within the same code_item.
    """
    # build a list of (pc, op, rawbytes) in this code item
    insns = list(disasm_iter(dex_bytes, insns_off,
                              (invoke_off + 16) - insns_off + 1))
    # actually re-iterate the whole stream from insns_off up to invoke_off
    last_const = None
    for pc, op, raw in disasm_iter(dex_bytes, insns_off,
                                   invoke_off + 16 - insns_off):
        if pc >= invoke_off:
            break
        if op == 0x1a:  # const-string vAA, string@BBBB (format 21c, 4 bytes)
            vAA = raw[1]
            str_idx = struct.unpack("<H", raw[2:4])[0]
            if vAA == target_reg:
                last_const = get_string(dex_bytes, hdr, str_idx)
        elif op == 0x1b:  # const-string/jumbo vAA, string@BBBBBBBB (format 31c)
            vAA = raw[1]
            str_idx = struct.unpack("<I", raw[2:6])[0]
            if vAA == target_reg:
                last_const = get_string(dex_bytes, hdr, str_idx)
    return last_const


def analyse_dex(dex_bytes: bytes, dex_name: str, build_id_hex: str,
                f_methods: dict[str, str], verbose: bool = False) -> DexReport:
    """Walk a single DEX:
       - Validate the header.
       - Detect the VBPD container, if any.
       - For every F<buildId>_NN call-site, record (caller_class, caller_method,
         arg-string-if-const).
       - Statically decode F<buildId>_11 const-string arguments via vm_str.
    """
    hdr = parse_dex_header(dex_bytes)

    rep = DexReport(
        name=dex_name,
        size=len(dex_bytes),
        sha256=hashlib.sha256(dex_bytes).hexdigest(),
        classes_count=hdr["class_defs_size"],
        methods_count=hdr["method_ids_size"],
    )

    # VBPD container
    vc = find_vbpd_container(dex_bytes, dex_name)
    if vc:
        rep.vbpd_container = asdict(vc)

    # Locate F<buildId>_NN method ids in this DEX's method-id table
    F_PREFIX = f"F{build_id_hex}_"
    M_CLASS = f"Lm{build_id_hex};"
    targets: dict[int, str] = {}  # midx → suffix ("_11")
    for idx in range(hdr["method_ids_size"]):
        cls, name, _ = get_method(dex_bytes, hdr, idx)
        if cls == M_CLASS and name.startswith(F_PREFIX):
            targets[idx] = name[len(F_PREFIX)-1:]  # "_11"

    if not targets:
        return rep

    # Walk every method body looking for invoke-static / invoke-static/range
    # that targets one of those method-ids.
    for cls_name, m_idx, code_off in walk_methods(dex_bytes, hdr):
        insns_off, insns_bytes = parse_code_item(dex_bytes, code_off)
        for pc, op, raw in disasm_iter(dex_bytes, insns_off, insns_bytes):
            if op == 0x71:  # invoke-static (format 35c)
                if len(raw) < 6: continue
                midx = struct.unpack("<H", raw[2:4])[0]
                if midx in targets:
                    suff = targets[midx]
                    _, mname, mproto = get_method(dex_bytes, hdr, m_idx)
                    rt, params = get_proto(dex_bytes, hdr, mproto)
                    site_d = rep.f_dispatch_sites.setdefault(
                        suff, {"sites": [], "count": 0})
                    site_d["count"] += 1
                    # Argument-register info from the FE|DC byte and the
                    # high nibble of byte 1.
                    arg_count = (raw[1] >> 4) & 0xf
                    nibbles = raw[4] | (raw[5] << 8)  # DC, FE bytes
                    # Decode register list  (C,D,E,F,G) where G is high nibble of byte 1
                    regs = []
                    regs.append(raw[4] & 0xf)            # C
                    regs.append((raw[4] >> 4) & 0xf)     # D
                    regs.append(raw[5] & 0xf)            # E
                    regs.append((raw[5] >> 4) & 0xf)     # F
                    regs.append(raw[1] & 0xf)            # G
                    regs = regs[:arg_count]
                    site = {
                        "caller_class": cls_name,
                        "caller_method": mname,
                        "caller_descriptor": f"({params}){rt}",
                        "regs": regs,
                    }
                    # If this is F_11 (vm_str), try to recover the const-string arg
                    if suff == "_11" and arg_count >= 1:
                        target_reg = regs[0]
                        s = find_const_string_for_register(
                            None, pc, insns_off, target_reg,
                            hdr["string_ids_off"], hdr, dex_bytes)
                        if s is not None:
                            site["encoded"] = s
                            decoded = vm_str_decode(s)
                            if decoded is not None:
                                site["decoded"] = decoded
                                rep.decoded_strings.append(decoded)
                    elif suff in ("_00", "_01", "_02", "_03", "_04", "_05",
                                  "_06", "_07", "_08", "_09"):
                        # True VMP dispatch — note unrecoverable. The "idx"
                        # passed as the first arg may be a const literal
                        # (which we could resolve), but the BODY of the
                        # method still requires the VME interpreter.
                        rep.vmp_protected_methods.append({
                            "caller_class": cls_name,
                            "caller_method": mname,
                            "caller_descriptor": f"({params}){rt}",
                            "dispatch_variant": suff,
                            "regs": regs,
                        })
                    site_d["sites"].append(site)
            elif op == 0x76:  # invoke-static/range (format 3rc, 6 bytes)
                if len(raw) < 6: continue
                midx = struct.unpack("<H", raw[2:4])[0]
                if midx in targets:
                    suff = targets[midx]
                    _, mname, mproto = get_method(dex_bytes, hdr, m_idx)
                    rt, params = get_proto(dex_bytes, hdr, mproto)
                    site_d = rep.f_dispatch_sites.setdefault(
                        suff, {"sites": [], "count": 0})
                    site_d["count"] += 1
                    site_d["sites"].append({
                        "caller_class": cls_name,
                        "caller_method": mname,
                        "caller_descriptor": f"({params}){rt}",
                    })

    return rep


# ───────────────────────────────────────────────────────────────────────────
# Section 8 — Top-level orchestration
# ───────────────────────────────────────────────────────────────────────────


def validate_dex_header(d: bytes) -> tuple[bool, str]:
    """Run the DEX self-consistency checks: magic, file_size, checksum, sha1."""
    if d[:4] != b"dex\n":
        return False, f"bad magic {d[:4]!r}"
    if struct.unpack("<I", d[32:36])[0] != len(d):
        return False, "file_size mismatch"
    # adler32 over [12:]
    if struct.unpack("<I", d[8:12])[0] != zlib.adler32(d[12:]):
        return False, "adler32 mismatch"
    # sha1 over [32:]
    if d[12:32] != hashlib.sha1(d[32:]).digest():
        return False, "sha1 mismatch"
    return True, "ok"


def dump_xapk(input_path: Path, out_dir: Path, verbose: bool = False) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    work_dir = out_dir / "_work"

    base_apk = open_input(input_path, work_dir)
    if verbose:
        print(f"[*] Base APK: {base_apk}")

    # 1. Detect Virbox markers
    if verbose:
        print("[*] Detecting Virbox protection markers (Report §3)...")
    markers = detect_virbox(base_apk, verbose=verbose)
    if not markers.confirmed:
        print("[!] WARNING: Virbox markers did not reach quorum. "
              "Will proceed best-effort.", file=sys.stderr)
    if verbose:
        print(f"  build-id: 0x{markers.build_id_hex}")
        print(f"  m-class:  {markers.m_class_name or '(none)'}")
        print(f"  F* dispatchers: {len(markers.f_methods)}")
        print(f"  SENS file:    {markers.sens_file or '(none)'}")
        print(f"  asset SOs:    {len(markers.asset_so_files)}")

    summary: dict[str, Any] = {
        "input": str(input_path),
        "base_apk": str(base_apk),
        "base_apk_sha256": hashlib.sha256(base_apk.read_bytes()).hexdigest(),
        "markers": asdict(markers),
        "recovered_dexs": [],
        "decoded_strings_count": 0,
        "sens_recovery": None,
    }

    # 2. Optional SENS-records>0 path (legacy r21e)
    if markers.sens_file:
        if verbose:
            print(f"[*] SENS-protected mode detected (records={markers.sens_record_count})")
            if markers.sens_record_count == 0:
                print("    -> records=0: body cipher is runtime-resolved")
                print("       (UNRECOVERED.md §1). Will still attempt DEX extraction.")
        with zipfile.ZipFile(base_apk) as zf:
            sens_blob = zf.read(markers.sens_file)
            sens_dir = out_dir / "sens_recovered"
            rec = decrypt_sens_protected_entries(zf, sens_blob, sens_dir,
                                                  verbose=verbose)
        summary["sens_recovery"] = asdict(rec)
        if rec.record_count > 0 and verbose:
            print(f"  [+] {len(rec.recovered_entries)} entries decrypted "
                  f"(unmatched: {rec.unmatched_hashes})")

    # 3. Walk every DEX
    if verbose:
        print("[*] Recovering DEX files (Report §6)...")
    recovered_dir = out_dir / "recovered_dex"
    recovered_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(base_apk) as zf:
        dex_names = sorted([n for n in zf.namelist()
                            if n.startswith("classes") and n.endswith(".dex")])
        for dn in dex_names:
            d = zf.read(dn)
            ok, why = validate_dex_header(d)
            if verbose:
                vbpd = "VBPD✓" if VBPD_MAGIC in d else "      "
                print(f"  [{vbpd}] {dn}  {len(d):>10d} bytes  {ok and 'valid' or why}")
            # write out, even if checks fail (we still want forensic dump)
            (recovered_dir / dn).write_bytes(d)
            # extract VBPD container, if any
            vc = find_vbpd_container(d, dn)
            if vc:
                # carve container bytes
                container_blob = d[vc.container_offset:vc.container_offset+vc.container_size]
                vc_path = out_dir / "extracted" / f"vbpd_{dn}.bin"
                vc_path.parent.mkdir(parents=True, exist_ok=True)
                vc_path.write_bytes(container_blob)
                vc.blob_path = str(vc_path)
            # static analysis
            rep = analyse_dex(d, dn, markers.build_id_hex,
                              markers.f_methods, verbose=verbose)
            if vc:
                rep.vbpd_container = asdict(vc)
            # We don't want to store ~190k decoded strings *and* call-sites
            # in JSON (too big); cap per-suffix sites at 32 in the summary
            # and write the full corpus separately.
            decoded_corpus = rep.decoded_strings
            rep.decoded_strings = []  # cleared for JSON brevity
            rep_d = asdict(rep)
            # Cap sites per variant
            for suff, info in rep_d.get("f_dispatch_sites", {}).items():
                if len(info.get("sites", [])) > 32:
                    info["sites"] = info["sites"][:32] + [
                        {"_truncated_remainder": len(info["sites"]) - 32}]
            summary["recovered_dexs"].append(rep_d)
            summary["decoded_strings_count"] += len(decoded_corpus)
            if decoded_corpus:
                ofp = out_dir / "decoded_strings" / f"{dn}.txt"
                ofp.parent.mkdir(parents=True, exist_ok=True)
                ofp.write_text("\n".join(decoded_corpus))
            if verbose and decoded_corpus:
                print(f"        decoded {len(decoded_corpus)} vm_str strings -> "
                      f"decoded_strings/{dn}.txt")

    # 4. Build UNRECOVERED.md listing all method bodies that need VME
    unrecoverable = []
    for rd in summary["recovered_dexs"]:
        for entry in rd.get("vmp_protected_methods", []):
            unrecoverable.append({"dex": rd["name"], **entry})
    summary["unrecoverable_method_count"] = len(unrecoverable)

    unrec_path = out_dir / "UNRECOVERED.md"
    write_unrecovered_md(unrec_path, markers, unrecoverable, summary)
    if verbose:
        print(f"[*] UNRECOVERED.md → {unrec_path} ({len(unrecoverable)} entries)")

    # 5. JSON summary
    (out_dir / "summary.json").write_text(json.dumps(summary, indent=2, default=str))
    if verbose:
        print(f"[*] summary.json → {out_dir / 'summary.json'}")

    return summary


def write_unrecovered_md(path: Path, markers: VirboxMarkers,
                          methods: list[dict], summary: dict) -> None:
    """Write the UNRECOVERED.md listing in a stable, reviewable format."""
    lines = [
        "# UNRECOVERED methods", "",
        "Methods whose original Java bodies are not statically recoverable",
        "by this tool. Reasons follow the format defined in",
        "`findings/virbox-analysis.md §9` (VME interpreter required).", "",
        f"Sample build-id: `{markers.build_id_hex}`",
        f"Outer Application class: `{markers.application_class}`",
        f"VME dispatcher class: `{markers.m_class_name}`", "",
    ]

    if summary.get("sens_recovery"):
        sr = summary["sens_recovery"]
        if sr["record_count"] == 0:
            lines += [
                "## §1 — SENS records=0 body cipher",
                "",
                f"The SENS file ({markers.sens_file}) declares "
                f"`record_count = 0`. Per Report §6 / FINDINGS_REVIEW §5b, the "
                "body cipher for this mode is resolved at runtime via a function "
                "pointer at `*(SO+0x30fde0)` and is not statically determined. "
                "Methods whose recovery depends on this cipher are listed below "
                "as well.",
                "",
            ]
        else:
            lines += [
                f"## §1 — SENS records={sr['record_count']} cipher",
                "",
                f"Recovered key: `{sr['cipher_key_hex']}`",
                f"NEON multiplier x8 = `0x{sr['x8']:x}`",
                f"{len(sr['recovered_entries'])} entries restored to plaintext "
                "(see `sens_recovered/`).",
                "",
            ]

    lines += [
        "## §2 — Methods whose dispatch is via Virbox VME bytecode", "",
        "Each entry below is a *call-site* of one of "
        f"`{markers.m_class_name or 'Lm<id>;'}->F<id>_{{00..09}}` — the "
        "10 generic VMP dispatchers. The method's *original* Dalvik body has "
        "been replaced by a stub that calls into the SO's VME interpreter, "
        "which decodes a private (per-build-randomised) bytecode and executes "
        "it natively. Because the dispatch table at SO+0x3107c8 is per-build "
        "randomised (Report §8.2), and the opcode meanings depend on per-build "
        "handler addresses, static recovery of the original method body "
        "requires either (a) reconstructing the dispatch table from the SO "
        "and lifting the bytecode back to Dalvik, or (b) capturing the "
        "decrypted bytecode at runtime via Frida.", "",
    ]
    if not methods:
        lines += [
            "_No `F<id>_{00..09}` call-sites observed in this build._  "
            "The protection observed here is **string-encryption-only** "
            "(F<id>_11 only — Report §7). All other DEX content is plaintext.",
            "",
        ]
    else:
        lines.append("| DEX | Caller class | Caller method | Dispatch variant |")
        lines.append("| --- | --- | --- | --- |")
        for m in methods:
            lines.append(
                f"| `{m['dex']}` | `{m['caller_class']}` | "
                f"`{m['caller_method']}{m.get('caller_descriptor','')}` | "
                f"`F<id>{m['dispatch_variant']}` |")
        lines.append("")

    lines += [
        "## §3 — Tool steps cross-reference",
        "",
        "| Section in `dump_virbox_dex.py` | What it recovers | Status |",
        "| --- | --- | --- |",
        "| §1 XAPK/APK splitter | base APK from APK-Pure bundle | ✅ |",
        "| §3 marker detection | identifies Virbox + build-id | ✅ |",
        "| §4 VBPD extraction  | dumps container blob; doesn't translate bytecode | partial — needs `virbox_bundle/scripts/vbpd_lifter/virbox_vbpd_to_dalvik.py` |",
        "| §5 SENS records>0   | NEON-poly cipher (Report §6) | ✅ when SENS present and records>0 |",
        "| §5 SENS records=0   | runtime cipher pointer | ❌ (this §1) |",
        "| §6 vm_str (F_11)    | string deobfuscator (Report §7) | ✅ |",
        "| §7 DEX recovery     | plaintext copy of every classesN.dex | ✅ |",
        "",
    ]
    path.write_text("\n".join(lines))


# ───────────────────────────────────────────────────────────────────────────
# Section 9 — CLI
# ───────────────────────────────────────────────────────────────────────────


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("input", help="Target XAPK or APK file")
    p.add_argument("-o", "--out", default="dump_out", type=Path,
                   help="Output directory (default: dump_out)")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Trace every step")
    p.add_argument("--test", action="store_true",
                   help="Emit one-line PASS/FAIL status (CI mode)")
    args = p.parse_args(argv)

    try:
        summary = dump_xapk(Path(args.input), args.out, verbose=args.verbose)
    except SystemExit:
        raise
    except Exception as e:
        if args.test:
            print(f"FAIL  {type(e).__name__}: {e}")
            return 2
        raise

    if args.test:
        m = summary["markers"]
        ok = (m["confirmed"]
              and any(rd.get("size", 0) > 0 for rd in summary["recovered_dexs"]))
        n_dex = len([rd for rd in summary["recovered_dexs"]
                     if rd.get("size", 0) > 0])
        n_strings = summary["decoded_strings_count"]
        print(f"{'PASS' if ok else 'FAIL'}  "
              f"build={m.get('build_id_hex','?')}  "
              f"dex={n_dex}  decoded_strings={n_strings}  "
              f"vmp_unrec={summary.get('unrecoverable_method_count', 0)}")
        return 0 if ok else 3

    print(f"\n[done] base_apk_sha256 = {summary['base_apk_sha256']}")
    print(f"       recovered DEXs:    {len([rd for rd in summary['recovered_dexs'] if rd.get('size',0)>0])}")
    print(f"       decoded strings:   {summary['decoded_strings_count']}")
    print(f"       VMP-protected methods: {summary['unrecoverable_method_count']}")
    print(f"       output dir:        {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
