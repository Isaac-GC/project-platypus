"""Auto-detect the Android packer family for an APK or XAPK.

Mirrors the logic of `findings/scripts/detect_packers.py` but factored
for in-process import. Reads the ZIP central directory plus
`AndroidManifest.xml`; never executes anything.

The detector returns the **primary** packer family (the one whose backend
should run) plus the full list of *all* detected markers including
add-on tooling (PangleArmor, App Cloner, embedded Ali Mobisec, …).
"""

from __future__ import annotations

import os
import re
import struct
import zipfile
from dataclasses import dataclass, field
from typing import Iterable


# Order matters: when multiple families fire, the one that owns the
# protected DEX wins. Add-ons (PangleArmor, AppCloner, Ali Mobisec) are
# never primary.
_PRIMARY_PRIORITY = (
    "virbox",
    "jiagu",
    "ijiami",
    "dexshield",
    "fengyue",
    "bangcle",
    "tencent-legu",
    "ducex",
)


@dataclass
class Detection:
    primary: str                       # "virbox", "jiagu", "fengyue", "ijiami", "dexshield", "unknown"
    confidence: str                    # "high" | "medium" | "low" | "none"
    all_families: list                 # [(name, evidence), ...] all markers, in priority order
    markers: dict = field(default_factory=dict)  # raw marker bag
    is_xapk: bool = False
    base_apk_path: str = ""            # for XAPK: the inner base.apk; for APK: same as input

    def as_dict(self):
        return {
            "primary": self.primary,
            "confidence": self.confidence,
            "all_families": [{"family": f, "evidence": e} for f, e in self.all_families],
            "is_xapk": self.is_xapk,
            "base_apk_path": self.base_apk_path,
            "markers": self.markers,
        }


# ---------------------------------------------------------------------------
# AXML string-pool parser (Android binary XML) — same as detect_packers.py
# ---------------------------------------------------------------------------
def _parse_axml_strings(data: bytes) -> list:
    if len(data) < 36 or data[0:4] != b"\x03\x00\x08\x00":
        return []
    try:
        n_strings = struct.unpack("<I", data[16:20])[0]
        flags = struct.unpack("<I", data[24:28])[0]
        str_pool_off = struct.unpack("<I", data[28:32])[0] + 8
        utf8 = (flags & 0x100) != 0
        offs = [
            struct.unpack("<I", data[36 + i * 4 : 40 + i * 4])[0]
            for i in range(n_strings)
        ]
        out = []
        for o in offs:
            base = str_pool_off + o
            if utf8:
                # utf-8: skipped-length byte, then byte-length, then bytes
                if base + 2 > len(data):
                    out.append("")
                    continue
                # skip "u16-length"
                lo = data[base]
                if lo & 0x80:
                    base += 2
                else:
                    base += 1
                ln = data[base]
                if ln & 0x80:
                    ln = ((ln & 0x7F) << 8) | data[base + 1]
                    base += 2
                else:
                    base += 1
                out.append(data[base : base + ln].decode("utf-8", "replace"))
            else:
                ln = struct.unpack("<H", data[base : base + 2])[0]
                if ln & 0x8000:
                    ln = ((ln & 0x7FFF) << 16) | struct.unpack("<H", data[base + 2 : base + 4])[0]
                    base += 4
                else:
                    base += 2
                out.append(data[base : base + ln * 2].decode("utf-16-le", "replace"))
        return out
    except Exception:
        return []


_VIRBOX_SO_RE = re.compile(r"assets/l[0-9a-f]{8}_(a32|a64|x86|x64)\.so$")
_VIRBOX_BLD_RE = re.compile(r"^l([0-9a-f]{8})_(a32|a64|x86|x64)\.so$")
_JIAGU_VARIANT_RE = re.compile(r"assets/libjg[a-z]{2,5}(_(a64|x64|x86))?\.so$")
_JIAGU_SDK_RE = re.compile(r"lib/[^/]+/libjiagu_sdk_.*\.so$")
_FENGYUE_LOADER_RE = re.compile(r"assets/libdexload_(arm|a64|x86|x64)\.so$")
_IJIAMI_LOADER_RE = re.compile(r"lib/[^/]+/(libexecmain|libexec|libsmainso|libsecmain|libsecexe)\.so$")
_DEXSHIELD_RE = re.compile(r"lib/[^/]+/libDexHelper(-x86)?\.so$")
_DUCEX_RE = re.compile(r"lib/[^/]+/libducex\.so$")
_LEGU_RE = re.compile(r"lib/[^/]+/libshell[axw]")


def _classify_zip(zf: zipfile.ZipFile) -> tuple:
    names = zf.namelist()
    name_set = set(names)
    asset_files = [n for n in names if n.startswith("assets/")]
    lib_files = [n for n in names if n.startswith("lib/")]

    manifest_strs = []
    if "AndroidManifest.xml" in name_set:
        try:
            manifest_strs = _parse_axml_strings(zf.read("AndroidManifest.xml"))
        except Exception:
            pass

    findings = []
    markers = {}

    # ---------------- Virbox ----------------
    virbox_so = [n for n in asset_files if _VIRBOX_SO_RE.match(n)]
    virbox_kqk = "assets/kqkticwjgzy.dat" in name_set
    virbox_stub = any("virbox/StubApp" in s or "Lvirbox/StubApp" in s for s in manifest_strs)
    virbox_appname = any(re.match(r"v[0-9a-f]{8}\.l[0-9a-f]{8}$", s) for s in manifest_strs)
    virbox_score = (
        (1 if virbox_so else 0)
        + (1 if virbox_kqk else 0)
        + (1 if virbox_stub else 0)
        + (1 if virbox_appname else 0)
    )
    if virbox_score >= 2 or (virbox_so and virbox_score >= 1):
        bid = ""
        if virbox_so:
            m = _VIRBOX_BLD_RE.match(os.path.basename(virbox_so[0]))
            if m:
                bid = m.group(1)
        ev = f"build={bid} so={len(virbox_so)} kqk={virbox_kqk} stub={virbox_stub}"
        findings.append(("virbox", ev))
        markers["virbox"] = {
            "build_id": bid,
            "asset_so_count": len(virbox_so),
            "has_kqk": virbox_kqk,
            "has_stub_class": virbox_stub,
            "has_app_name": virbox_appname,
            "score": virbox_score,
        }

    # ---------------- Qihoo 360 Jiagu ----------------
    jgapp = "assets/.jgapp" in name_set
    jiagu_so = [n for n in asset_files if re.match(r"assets/libjiagu(_a64|_x64|_x86)?\.so$", n)]
    jiagu_variant = [n for n in asset_files if _JIAGU_VARIANT_RE.match(n)]
    jiagu_sdk = [n for n in lib_files if _JIAGU_SDK_RE.match(n)]
    if jiagu_so or jgapp or jiagu_variant:
        evs = []
        if jgapp:
            evs.append(".jgapp")
        if jiagu_so:
            evs.append(f"libjiagu({len(jiagu_so)})")
        if jiagu_variant:
            evs.append(f"variant={os.path.basename(jiagu_variant[0])}")
        if jiagu_sdk:
            evs.append(f"jiagu_sdk({len(jiagu_sdk)})")
        findings.append(("jiagu", " ".join(evs)))
        markers["jiagu"] = {
            "jgapp": jgapp,
            "libjiagu_assets": jiagu_so,
            "variant_assets": jiagu_variant,
            "sdk_libs": jiagu_sdk,
        }

    # ---------------- FengYue / com.storm.fengyue ----------------
    dexload = [n for n in asset_files if _FENGYUE_LOADER_RE.match(n)]
    fengyue_stub = any("com.storm.fengyue" in s for s in manifest_strs)
    if dexload or fengyue_stub:
        findings.append(("fengyue", f"libdexload({len(dexload)}) stub={fengyue_stub}"))
        markers["fengyue"] = {
            "loaders": dexload,
            "stub_present": fengyue_stub,
        }

    # ---------------- Ijiami (爱加密) ----------------
    ijiami_so = [n for n in lib_files if _IJIAMI_LOADER_RE.match(n)]
    ijiami_dat = [n for n in asset_files if n in ("assets/ijiami.dat", "assets/ijiami.ajm")]
    ijiami_stub = any(
        s in ("com.shell.NativeApplication", "com.shell.NativeApplicationE",
              "cn.securitystack.stss.NativeApplication")
        for s in manifest_strs
    )
    if ijiami_so or ijiami_dat or ijiami_stub:
        findings.append(("ijiami", f"so={len(ijiami_so)} dat={len(ijiami_dat)} stub={ijiami_stub}"))
        markers["ijiami"] = {
            "loader_libs": ijiami_so,
            "dat_assets": ijiami_dat,
            "stub_present": ijiami_stub,
        }

    # ---------------- DexShield ----------------
    dexshield_so = [n for n in lib_files if _DEXSHIELD_RE.match(n)]
    if dexshield_so:
        findings.append(("dexshield", f"so={len(dexshield_so)}"))
        markers["dexshield"] = {"loader_libs": dexshield_so}

    # ---------------- Ducex / Triada ----------------
    ducex_so = [n for n in lib_files if _DUCEX_RE.match(n)]
    mxini = "assets/mx.ini" in name_set
    if ducex_so or mxini:
        findings.append(("ducex", f"so={len(ducex_so)} mxini={mxini}"))
        markers["ducex"] = {"loader_libs": ducex_so, "mxini": mxini}

    # ---------------- App Cloner (modding tool; not a Java packer) ----------------
    if "assets/app_cloner.dat" in name_set or "assets/app_cloner_branding.png" in name_set:
        findings.append(("appcloner", "app_cloner.dat present"))
        markers["appcloner"] = True

    # ---------------- PangleArmor (SDK-only) ----------------
    pangle = [n for n in lib_files if "libpanglearmor" in n.lower()]
    if pangle:
        findings.append(("panglearmor", f"so={len(pangle)}"))
        markers["panglearmor"] = pangle

    # ---------------- Ali Mobisec (sgmain) ----------------
    ali_sgmain = [n for n in lib_files if re.search(r"libsgmain(so)?(-[\d.]+)?\.so$", n)]
    if ali_sgmain:
        findings.append(("alijiagu", f"sgmain={len(ali_sgmain)}"))
        markers["alijiagu"] = ali_sgmain

    markers["manifest_strings_sample"] = [s for s in manifest_strs[:200] if len(s) < 256]
    return findings, markers


# ---------------------------------------------------------------------------
# Public interface
# ---------------------------------------------------------------------------
def detect(input_path: str) -> Detection:
    """Detect the packer family for an APK or XAPK at `input_path`.

    For an XAPK, transparently picks the inner `base.apk` for classification
    (and exposes its path on the returned Detection).
    """
    if not os.path.isfile(input_path):
        raise FileNotFoundError(input_path)

    is_xapk = False
    base_apk_path = input_path

    # Detect XAPK by manifest.json describing split_apks. The base entry may be
    # literally `base.apk` (APKMirror layout) or named after the package
    # (APK-Pure layout), so we read manifest.json and pick id="base" — falling
    # back to the largest .apk entry.
    try:
        with zipfile.ZipFile(input_path) as zf:
            names = set(zf.namelist())
            has_apk_inside = any(n.endswith(".apk") for n in names)
            if "manifest.json" in names and has_apk_inside:
                is_xapk = True
                base_name = None
                try:
                    import json as _json
                    inner_manifest = _json.loads(zf.read("manifest.json").decode("utf-8"))
                    splits = inner_manifest.get("split_apks") or []
                    base = next((s for s in splits if s.get("id") == "base"), None)
                    if base is not None:
                        base_name = base["file"]
                except Exception:
                    pass
                if base_name is None or base_name not in names:
                    # Fall back to largest .apk entry
                    apks = sorted(
                        [(zf.getinfo(n).file_size, n) for n in names if n.endswith(".apk")],
                        reverse=True,
                    )
                    base_name = apks[0][1] if apks else None
                if base_name is None:
                    findings, markers = [], {"error": "xapk has no inner .apk"}
                else:
                    import io
                    inner_bytes = zf.read(base_name)
                    with zipfile.ZipFile(io.BytesIO(inner_bytes)) as inner:
                        findings, markers = _classify_zip(inner)
                    base_apk_path = base_name  # name of the entry inside the XAPK
            else:
                findings, markers = _classify_zip(zf)
    except zipfile.BadZipFile:
        return Detection(
            primary="unknown",
            confidence="none",
            all_families=[],
            markers={"error": "not a zip"},
            is_xapk=False,
            base_apk_path=input_path,
        )

    # Choose primary by priority order.
    families_found = {f for f, _ in findings}
    primary = "unknown"
    for cand in _PRIMARY_PRIORITY:
        if cand in families_found:
            primary = cand
            break

    if primary == "unknown":
        # Strip add-on-only detections from "real findings" to gauge confidence
        non_addon = [f for f, _ in findings if f not in ("appcloner", "panglearmor", "alijiagu")]
        confidence = "none" if not non_addon else "low"
    else:
        # high if we have either virbox SOs, jiagu .jgapp+libjiagu, or fengyue loader+stub
        confidence = "high"

    return Detection(
        primary=primary,
        confidence=confidence,
        all_families=findings,
        markers=markers,
        is_xapk=is_xapk,
        base_apk_path=base_apk_path,
    )


def known_backends() -> tuple:
    return ("virbox", "jiagu", "ijiami", "dexshield", "fengyue")
