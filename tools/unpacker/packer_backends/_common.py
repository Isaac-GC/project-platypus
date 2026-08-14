"""Shared helpers used by every packer backend."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import zipfile
from pathlib import Path
from typing import Iterable


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        while True:
            chunk = fp.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def open_apk(input_path: str) -> tuple:
    """Return (zipfile-like, owned_temp_path_or_None).

    For XAPK input we extract `base.apk` to a temp path under the parent
    `out_dir` (the caller passes that path in via `extract_base_apk_to`
    when it wants persistence; otherwise we use an in-memory ZipFile).
    """
    z = zipfile.ZipFile(input_path)
    names = set(z.namelist())
    if "manifest.json" in names and "base.apk" in names:
        # XAPK — return ZipFile over base.apk bytes.
        base = z.read("base.apk")
        z.close()
        return zipfile.ZipFile(io.BytesIO(base)), None
    return z, None


def extract_base_apk_if_xapk(input_path: str, dest_dir: Path) -> Path:
    """If `input_path` is an XAPK, materialise the inner base APK to
    `dest_dir/base.apk` and return that path. Otherwise return
    `input_path` unchanged. Handles both APKMirror (`base.apk`) and
    APK-Pure (package-named) layouts by reading `manifest.json`'s
    `split_apks` array (with a largest-entry fallback).
    """
    import json
    with zipfile.ZipFile(input_path) as zf:
        names = set(zf.namelist())
        has_apk = any(n.endswith(".apk") for n in names)
        if not ("manifest.json" in names and has_apk):
            return Path(input_path)
        base_name = None
        try:
            inner_manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            splits = inner_manifest.get("split_apks") or []
            base = next((s for s in splits if s.get("id") == "base"), None)
            if base is not None:
                base_name = base["file"]
        except Exception:
            pass
        if base_name is None or base_name not in names:
            apks = sorted(
                [(zf.getinfo(n).file_size, n) for n in names if n.endswith(".apk")],
                reverse=True,
            )
            base_name = apks[0][1] if apks else None
        if base_name is None:
            raise RuntimeError(f"XAPK {input_path} contains no .apk entry")
        dest_dir.mkdir(parents=True, exist_ok=True)
        out = dest_dir / "base.apk"
        with zf.open(base_name) as fin, open(out, "wb") as fout:
            shutil.copyfileobj(fin, fout)
        return out


def carve_entries(zf: zipfile.ZipFile, entries: Iterable, out_dir: Path) -> list:
    """Copy named entries out of `zf` into `out_dir`. Returns a list of
    {name, size, sha256} dicts for the manifest.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    recs = []
    for name in entries:
        try:
            data = zf.read(name)
        except KeyError:
            continue
        rel = name.replace("/", "_")
        dest = out_dir / rel
        with open(dest, "wb") as f:
            f.write(data)
        recs.append({
            "name": name,
            "size": len(data),
            "sha256": sha256_bytes(data),
            "out_path": str(dest),
        })
    return recs


def carve_all_dexs(zf: zipfile.ZipFile, out_dir: Path) -> list:
    """Carve every `classesN.dex` entry verbatim from the APK. Useful as a
    baseline for packers that ship a tiny stub DEX outright. Returns
    manifest records.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
    recs = []
    for n in sorted(zf.namelist()):
        if n.endswith(".dex") and n.count("/") == 0:
            data = zf.read(n)
            dest = out_dir / n
            with open(dest, "wb") as f:
                f.write(data)
            # Verify DEX magic
            magic = data[:8]
            ok = magic.startswith(b"dex\n") or magic.startswith(b"dey\n")
            recs.append({
                "name": n,
                "size": len(data),
                "sha256": sha256_bytes(data),
                "magic": magic.hex(),
                "valid_dex_magic": ok,
                "out_path": str(dest),
            })
    return recs


def read_manifest_strings(zf: zipfile.ZipFile) -> list:
    """Best-effort AXML string-pool read for AndroidManifest.xml."""
    from .detector import _parse_axml_strings
    try:
        return _parse_axml_strings(zf.read("AndroidManifest.xml"))
    except (KeyError, Exception):
        return []


def write_manifest(out_dir: Path, manifest: dict) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "manifest.json"
    with open(p, "w") as f:
        json.dump(manifest, f, indent=2, sort_keys=True, default=str)
    return p


def write_unrecovered(out_dir: Path, items: list, packer: str) -> Path:
    """Write a per-sample UNRECOVERED.md (one bullet per item)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    p = out_dir / "UNRECOVERED.md"
    lines = [
        f"# Unrecovered items for this sample ({packer})\n",
        "",
        "These items could not be recovered statically. See "
        f"`../by-packer/{packer}.md` for the family's recovery capability.",
        "",
    ]
    if not items:
        lines.append("_None — full static recovery achieved._")
    else:
        for it in items:
            lines.append(f"- **{it['item']}** — {it['reason']}")
    p.write_text("\n".join(lines))
    return p
