"""FengYue / StormStub backend (com.storm.fengyue.StubApplication).

Static capabilities (full DEX recovery achieved 2026-05-17):

  - Identify the packer by the `com.storm.fengyue` stub class and/or
    the `assets/libdexload_*.so` loaders.
  - Recover the original Application FQCN from the per-build randomised
    `<meta-data>` indirection in `AndroidManifest.xml`.
  - **Decrypt `assets/jiami.dat` to a valid DEX** using AES-128-CBC with
    key = IV = b"1234567812345678". The key/IV are pointed to by
    `AES_KEYCODE` and `AES_IV` data symbols in `libdexload_a64.so`
    (both relocations land on the same 16-byte literal at
    `.rodata + 0x28`, the ASCII string "1234567812345678"). Confirmed
    by adler32-checksum match on all 3 FengYue samples in the corpus.

Validation: the decrypted plaintext begins with `dex\\n035\\x00`, the
embedded `file_size` field is consistent (plaintext is padded up to the
next AES block), and the stored DEX adler32 matches a recomputed
adler32 over bytes 12..file_size exactly — i.e. these are real DEX
files, not crypto false-positives.

See `by-packer/fengyue.md` for the loader RE walk-through.
"""

from __future__ import annotations

import hashlib
import os
import re
import struct
import zipfile
import zlib
from pathlib import Path

from . import _common


PACKER_NAME = "fengyue"

_LOADER_RE = re.compile(r"assets/libdexload_(arm|a64|x86|x64)\.so$")

# AES-128-CBC key + IV — both literally "1234567812345678" (ASCII).
# Encoded statically in libdexload_a64.so's .rodata; AES_KEYCODE and
# AES_IV are RELATIV relocations both pointing at the same 16-byte
# string. Verified by reading the relocations + bytes at
# vaddr 0x2c218 in the shared a64 loader
# (sha256 7292d73f242c5a6b701254c32da7521175fe4bb41bfb07e7d0537c8ddd8a624e).
_FENGYUE_KEY = b"1234567812345678"
_FENGYUE_IV  = b"1234567812345678"


def _resolve_real_application(manifest_strs):
    """FengYue stores the real app class via a randomised meta-data key."""
    stub = "com.storm.fengyue.StubApplication"
    for s in manifest_strs:
        if not isinstance(s, str):
            continue
        if s == stub:
            continue
        if re.match(r"^[a-zA-Z_][\w.]*\.[A-Z]\w*Application$", s):
            return s
    return ""


def _find_metadata_key(manifest_strs):
    candidates = [
        s for s in manifest_strs
        if isinstance(s, str) and re.fullmatch(r"[A-Za-z]{8,12}", s)
    ]
    return candidates[0] if candidates else ""


def _aes128_cbc_decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    """AES-128-CBC decrypt without depending on pycryptodome.

    Falls back through a few providers so the backend is portable.
    """
    # Preferred: pycryptodome (installed).
    try:
        from Crypto.Cipher import AES  # type: ignore
        return AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
    except ImportError:
        pass
    # Fallback: cryptography.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        return cipher.update(ct) + cipher.finalize()
    except ImportError:
        pass
    raise RuntimeError("fengyue backend needs pycryptodome or cryptography")


def _recover_dex_from_jiami(data: bytes) -> tuple:
    """Decrypt jiami.dat and trim to the embedded DEX file_size.

    Returns (dex_bytes, info_dict). info_dict carries enough fields for
    the manifest to verify the recovery.
    """
    if len(data) == 0 or len(data) % 16 != 0:
        return b"", {
            "ok": False,
            "reason": f"jiami.dat length {len(data)} not AES-block-aligned",
            "ciphertext_size": len(data),
        }
    pt = _aes128_cbc_decrypt(data, _FENGYUE_KEY, _FENGYUE_IV)
    magic = pt[:8]
    if not magic.startswith(b"dex\n"):
        return b"", {
            "ok": False,
            "reason": f"decrypted magic {magic!r} is not DEX",
            "ciphertext_size": len(data),
            "decrypted_first_bytes": pt[:32].hex(),
        }
    file_size = struct.unpack_from("<I", pt, 32)[0]
    if file_size <= 0 or file_size > len(pt):
        return b"", {
            "ok": False,
            "reason": f"DEX header file_size {file_size} out of range "
                      f"(plaintext length {len(pt)})",
            "ciphertext_size": len(data),
        }
    dex = bytes(pt[:file_size])
    stored = struct.unpack_from("<I", dex, 8)[0]
    actual = zlib.adler32(dex[12:]) & 0xffffffff
    info = {
        "ok": stored == actual,
        "ciphertext_size": len(data),
        "plaintext_size": len(pt),
        "dex_file_size": file_size,
        "dex_padding_bytes": len(pt) - file_size,
        "dex_adler32_stored": f"0x{stored:08x}",
        "dex_adler32_actual": f"0x{actual:08x}",
        "dex_sha256": hashlib.sha256(dex).hexdigest(),
        "algorithm": "AES-128-CBC",
        "key_ascii": _FENGYUE_KEY.decode("ascii"),
        "iv_ascii":  _FENGYUE_IV.decode("ascii"),
    }
    if not info["ok"]:
        info["reason"] = "adler32 mismatch — wrong key/IV/algorithm or corrupted blob"
    return dex, info


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
        name_set = set(names)
        manifest_strs = _common.read_manifest_strings(zf)
        loaders = [n for n in names if _LOADER_RE.match(n)]
        stub_present = any("com.storm.fengyue" in s for s in manifest_strs)

        stages.append({
            "name": "verify_markers",
            "ok": bool(loaders or stub_present),
            "detail": f"libdexload={len(loaders)} stub={stub_present}",
        })
        notes["markers"] = {"loaders": loaders, "stub_present": stub_present}

        real_app = _resolve_real_application(manifest_strs)
        meta_key = _find_metadata_key(manifest_strs)
        stages.append({
            "name": "resolve_real_application",
            "ok": bool(real_app),
            "detail": f"original_application={real_app!r} meta_data_key={meta_key!r}",
        })
        notes["original_application"] = real_app
        notes["meta_data_key_candidate"] = meta_key

        # Stage — carve outer stub DEX(s) verbatim.
        dex_recs = _common.carve_all_dexs(zf, out_dir)
        for r in dex_recs:
            r["ok"] = r.get("valid_dex_magic", False)
            r["recovery"] = "verbatim copy of outer stub DEX (FengYue Java shell)"
            recovered.append(r)
        stages.append({
            "name": "carve_outer_stub_dex",
            "ok": bool(dex_recs),
            "detail": f"{len(dex_recs)} stub DEX file(s) copied",
        })

        # Stage — carve loader .so files (for reference / re-RE).
        carved = _common.carve_entries(zf, loaders, extracted_dir)
        stages.append({
            "name": "carve_fengyue_loaders",
            "ok": bool(carved),
            "detail": f"{len(carved)} loader(s) carved to {extracted_dir.name}/",
        })
        notes["carved_artefacts"] = carved

        # Stage — locate and decrypt assets/jiami.dat.
        jiami_path = "assets/jiami.dat"
        jiami_present = jiami_path in name_set
        if jiami_present:
            ct = zf.read(jiami_path)
            dex, info = _recover_dex_from_jiami(ct)
            stages.append({
                "name": "decrypt_jiami_dat",
                "ok": info.get("ok", False),
                "detail": (
                    f"jiami.dat={info.get('ciphertext_size')}B "
                    f"→ DEX={info.get('dex_file_size')}B "
                    f"adler32 stored={info.get('dex_adler32_stored')} "
                    f"actual={info.get('dex_adler32_actual')} "
                    f"match={info.get('ok')}"
                ),
            })
            notes["jiami_decrypt"] = info
            if info.get("ok"):
                # Pick a filename that does not collide with the stub DEX(s).
                # FengYue's recovered DEX *replaces* the stub at runtime, so
                # call it `classes.dex` if no stub was carved; otherwise
                # `classes_recovered.dex`.
                existing_names = {r["name"] for r in dex_recs}
                out_name = (
                    "classes.dex" if "classes.dex" not in existing_names
                    else "classes_recovered.dex"
                )
                out_path = out_dir / out_name
                with open(out_path, "wb") as f:
                    f.write(dex)
                recovered.append({
                    "name": out_name,
                    "size": len(dex),
                    "sha256": info["dex_sha256"],
                    "magic": dex[:8].hex(),
                    "valid_dex_magic": True,
                    "ok": True,
                    "recovery": (
                        "Decrypted from assets/jiami.dat with AES-128-CBC "
                        f"key=IV={_FENGYUE_KEY!r} (FengYue/StormStub static "
                        "key — see by-packer/fengyue.md §3)"
                    ),
                    "source": jiami_path,
                    "ciphertext_size": info["ciphertext_size"],
                    "out_path": str(out_path),
                })
            else:
                unrecovered.append({
                    "item": "inner classes.dex (decrypt failed)",
                    "reason": info.get("reason", "unknown failure decrypting jiami.dat"),
                })
        else:
            stages.append({
                "name": "decrypt_jiami_dat",
                "ok": False,
                "detail": "assets/jiami.dat not present — unusual FengYue layout?",
            })
            unrecovered.append({
                "item": "inner classes.dex",
                "reason": (
                    "assets/jiami.dat is missing; this sample fingerprints "
                    "as FengYue (libdexload_*.so / stub class) but the "
                    "encrypted-DEX asset is in an unexpected location. "
                    "Inspect manually."
                ),
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
    }
    _common.write_manifest(out_dir, manifest)
    _common.write_unrecovered(out_dir, unrecovered, PACKER_NAME)

    if verbose:
        print(f"[fengyue] markers: libdexload={len(loaders)} stub={stub_present}")
        print(f"[fengyue] real Application class: {real_app or '(unresolved)'}")
        print(f"[fengyue] meta-data key candidate: {meta_key or '(none)'}")
        print(f"[fengyue] {len(carved)} loader(s) carved → {extracted_dir}")
        if jiami_present:
            ji = notes.get("jiami_decrypt", {})
            print(f"[fengyue] jiami.dat → DEX: {ji.get('ok')} "
                  f"({ji.get('ciphertext_size')}B → {ji.get('dex_file_size')}B)")

    return manifest
