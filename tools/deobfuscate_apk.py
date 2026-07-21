#!/usr/bin/env python3
"""
Standalone deobfuscator for Android APKs, built on the `platypus` native module.

It targets the two control-flow obfuscations you asked about — **control-flow
flattening** and **opaque predicates** — plus the string obfuscation that
dominates real samples like Godfather.

What it actually does (and the honest limits of the Python API)
---------------------------------------------------------------
`platypus` exposes class enumeration, a decompiler, a smali disassembler, xref
enumeration, and a Dalvik VM with Python mocks. It does **not** expose the raw
CFG / per-instruction objects, nor a way to write modified bytecode back out.
So this tool deobfuscates at the *recovered-source* level rather than rewriting
the DEX:

  1. DEFLATTEN + FOLD OPAQUE PREDICATES — `Dex.decompile_class()` runs the
     decompiler's structure recovery (reconstructs if/while/loops from the
     flattened state-machine CFG) together with its deobfuscation engine
     (constant folding, goto-chain simplification, dead-branch elimination,
     nop stripping). Constant/tautological opaque predicates fold away and the
     flattened dispatch collapses into structured control flow in the emitted
     Java. We write that cleaned Java to an output tree.

  2. DETECT residual obfuscation — heuristics over the recovered Java + smali
     flag methods that *still* look control-flow-flattened (a `while (true)`
     loop around a big state `switch`) or that contain opaque predicates a
     simple folder can't kill (self-comparisons, constant comparisons,
     `if (true)/(false)`). This gives you a targeted manual-review list.

  3. RECOVER STRINGS — many obfuscators (Godfather included) push every string
     through a tiny decoder method (often fed by `fill-array-data` byte arrays).
     We find `String`-returning methods and concretely execute them on a single
     persistent VM (so lazy decode tables persist), dumping the plaintext.

  4. RECURSE INTO EMBEDDED PAYLOADS — droppers ship their live code as *nested*
     archives (an APK/JAR/DEX stored as an asset, often wrapped in extra zlib
     and/or a cipher, sometimes several layers deep). We peel the layers we can
     (zip + zlib), run passes 1–3 on every archive that opens, and recurse to
     any depth. Payloads that stay encrypted after static peeling (the loader
     decrypts them at runtime) are inventoried in `PAYLOADS.txt` rather than
     silently dropped.

Output
------
A directory (default `<apk_dir>/deobf_out/`) containing:
  * `src/<class>.java`          — deflattened / folded decompiled source (root)
  * `report.txt`                — flattening + opaque-predicate findings (root)
  * `strings.txt`               — strings recovered via the VM (root)
  * `embedded/<payload>/…`      — the same tree, per embedded code unit
  * `strings_all.txt`           — every recovered string, across all units
  * `report.json`               — machine-readable rollup of all units
  * `PAYLOADS.txt`              — payload tree + encrypted-blob inventory

Usage
-----
    # from the repo with the platypus venv active
    source .venv/bin/activate
    python tools/deobfuscate_apk.py \
        /Users/isaac/Documents/ReverseEngineering/Android/apps/godfather/godfather.apk

    # options
    python tools/deobfuscate_apk.py APK [-o OUTDIR] [--package com/foo] \
        [--max-classes N] [--no-strings] [--no-decompile]
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import sys
import time
import zipfile
import zlib
from pathlib import Path

try:
    import platypus
except ImportError:
    sys.exit(
        "error: the `platypus` module is not importable.\n"
        "Build/activate it first, e.g.:\n"
        "  source .venv/bin/activate   # or: maturin develop -m rust/Cargo.toml"
    )

DEFAULT_APK = "/Users/isaac/Documents/ReverseEngineering/Android/apps/godfather/godfather.apk"


# ── Detection heuristics ──────────────────────────────────────────────────────
#
# These run over recovered source, not the CFG (which the Python API doesn't
# expose), so they're deliberately conservative — for triage, not proof.

# Detection runs over smali (the decompiler renders switch tables as
# "/* see table */" without case labels, so Java alone can't spot flattening).
_SMALI_METHOD_HDR = re.compile(r"^[ \t]*\.method\b[^\n]*?\b(\w[\w$<>]*)\(", re.MULTILINE)
_SW = re.compile(r"\b(packed|sparse)-switch\s+(v\d+)")
_GOTO = re.compile(r"\bgoto\b")
_SELF_CMP = re.compile(r"\bif-(eq|ne|lt|le|gt|ge)\s+(v\d+)\s*,\s*\2\b")
# `if (true)` / `if (false)` surviving in recovered Java = a folded opaque branch.
_JAVA_CONST_COND = re.compile(r"\bif\s*\(\s*(true|false)\s*\)")


def _split_methods(smali: str):
    for part in re.split(r"(?=^[ \t]*\.method\b)", smali, flags=re.MULTILINE):
        h = _SMALI_METHOD_HDR.search(part)
        if h:
            yield h.group(1), part


def analyse(smali: str, java: str | None, class_name: str) -> list[dict]:
    """Flag control-flow-flattened methods + opaque predicates."""
    findings: list[dict] = []
    for mname, body in _split_methods(smali):
        # ── Control-flow flattening: a switch whose register is the state
        #    variable (many const writes) with a back-edge goto (the dispatcher
        #    loop). ──
        sw = _SW.search(body)
        if sw:
            reg = re.escape(sw.group(2))
            states = len(re.findall(rf"\bconst(?:/4|/16|/high16|-wide(?:/\w+)?)?\s+{reg}\s*,", body))
            gotos = len(_GOTO.findall(body))
            if states >= 4 and gotos >= 1:
                findings.append({
                    "class": class_name,
                    "kind": "control_flow_flattening",
                    "detail": f"{mname}(): {sw.group(1)}-switch on {sw.group(2)} — "
                              f"{states} state writes, {gotos} back-edges",
                })
        # ── Opaque predicate: a register compared against itself. ──
        for m in _SELF_CMP.finditer(body):
            findings.append({
                "class": class_name,
                "kind": "opaque_predicate",
                "detail": f"{mname}(): self-compare if-{m.group(1)} {m.group(2)},{m.group(2)}",
            })

    # Folded opaque branches that the decompiler surfaced as constants.
    if java:
        for m in _JAVA_CONST_COND.finditer(java):
            findings.append({
                "class": class_name,
                "kind": "opaque_predicate",
                "detail": f"constant condition: if ({m.group(1)})",
            })
    return findings


# ── Smali helpers (method enumeration the Python API doesn't surface) ─────────

# `.method <flags> name(params)ReturnType`
_SMALI_METHOD = re.compile(r"^\s*\.method\b[^\n]*?\b(\w[\w$]*)\(([^)]*)\)(\S+)", re.MULTILINE)


def string_decoder_targets(disasm: str, class_desc: str) -> list[str]:
    """`L<class>;-><method>` for every method that returns a String — likely a
    string decoder. We keep the signature off the target (find_exec matches by
    class+name, like the module's own example)."""
    out = []
    for m in _SMALI_METHOD.finditer(disasm):
        name, ret = m.group(1), m.group(3)
        if ret == "Ljava/lang/String;":
            out.append(f"{class_desc}->{name}")
    return out


def parse_int(val) -> int | None:
    if val is None:
        return None
    s = str(val).strip()
    try:
        return int(s, 16) if s.lower().startswith(("0x", "-0x")) else int(s)
    except ValueError:
        return None


def recover_strings_vm(dexes, dex_blobs, resources, decoder_targets: set[str],
                       instr_limit: int, max_per_decoder: int = 5000) -> list[dict]:
    """VM-orchestrated string decryption.

    For each `String`-returning decoder, gather the integer indices passed at
    its call sites (statically resolved), then concretely execute the decoder
    on a **single persistent VM** (so any lazily-initialized decode table built
    on the first call survives subsequent calls — `Dex.find_exec` uses a fresh
    VM per site and can't). Filters results to plausible plaintext.

    `dex_blobs` is a list of `(bytes, name)` loaded into the VM; `resources` is
    an optional resource table (enables `getString(int)` during decode)."""
    # ── Gather (decoder -> {index: caller}) from every dex's call sites. ──
    work: dict[str, dict[int, str]] = {}
    for target in decoder_targets:
        idxs: dict[int, str] = {}
        for dex in dexes:
            try:
                sites = dex.find_calls(target)
            except Exception:
                continue
            for cs in sites:
                for _reg, val in cs.static_args:
                    n = parse_int(val)
                    if n is not None:
                        idxs.setdefault(n, f"{cs.caller_class}->{cs.caller_method}")
        if idxs:
            work[target] = idxs

    if not work:
        return []

    # ── One persistent VM with every dex loaded. ──
    vm = platypus.Vm()
    for blob, name in dex_blobs:
        try:
            vm.load_dex_bytes(blob, name)
        except Exception:
            pass
    if resources is not None:
        try:
            vm.load_resources(resources)
        except Exception:
            pass
    vm.reset(instr_limit)

    out: list[dict] = []
    for target, idxs in work.items():
        for idx in sorted(idxs)[:max_per_decoder]:
            try:
                r = vm.exec_method(target, [str(idx)])
            except Exception:
                continue
            inner = r[1:-1] if r and len(r) >= 2 and r[0] == '"' and r[-1] == '"' else r
            if inner and looks_like_plaintext(inner):
                out.append({"decoder": target, "index": idx,
                            "caller": idxs[idx], "value": inner})
    return out


def looks_like_plaintext(s: str) -> bool:
    """Filter VM-decode noise: keep strings that read as real text. `find_exec`
    resolves only statically-known args, so a decoder fed a `fill-array-data`
    byte[] often returns intermediate/garbage data — drop those."""
    if len(s) < 3:
        return False
    printable = sum(1 for c in s if c.isprintable() and ord(c) < 0x7F)
    if printable / len(s) < 0.8:
        return False
    # Drop single-repeated-character runs (e.g. "\x06\x06\x06…", "AAAA…").
    if len(set(s)) <= 1:
        return False
    return True


def class_to_desc(class_name: str) -> str:
    """`com/foo/Bar` (or `Lcom/foo/Bar;`) → `Lcom/foo/Bar;`."""
    if class_name.startswith("L") and class_name.endswith(";"):
        return class_name
    return f"L{class_name};"


def safe_filename(class_name: str) -> str:
    return class_name.strip("L;").replace("/", ".").replace("$", "$") + ".java"


def _open_apk(path: Path):
    """Open via whichever constructor this `platypus` build exposes."""
    if hasattr(platypus.Apk, "open"):
        return platypus.Apk.open(str(path))
    return platypus.Apk.from_bytes(path.read_bytes())


# ── Embedded-payload discovery & recursion ────────────────────────────────────
#
# Real samples (Godfather included) ship their live code as *nested* payloads:
# an APK/JAR/DEX stored as an asset, sometimes wrapped in extra zlib and/or a
# cipher, sometimes several layers deep. We peel the layers we can (zip + zlib),
# recurse into every archive that opens, and honestly record the ones that stay
# encrypted (they need runtime decryption we can't do statically).

ZIP_MAGIC = b"PK\x03\x04"
DEX_MAGIC = b"dex\n"


def _sha(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def _magic(blob: bytes) -> str | None:
    if len(blob) < 8:
        return None
    if blob[:4] == ZIP_MAGIC:
        return "zip"
    if blob[:4] == DEX_MAGIC:
        return "dex"
    return None


def _maybe_zlib(blob: bytes) -> bytes | None:
    """Unwrap one zlib layer if this looks like a zlib stream (0x78 xx)."""
    if len(blob) >= 2 and blob[0] == 0x78 and blob[1] in (0x01, 0x9C, 0xDA):
        try:
            return zlib.decompress(blob)
        except Exception:
            return None
    return None


def resolve_payload(blob: bytes, max_layers: int = 4):
    """Peel zlib layers until we hit a zip/dex (or give up).

    Returns `(kind, resolved_blob, layers)` where `kind` is 'zip' | 'dex' | None
    and `layers` lists the transforms peeled (e.g. `['zlib']`)."""
    layers: list[str] = []
    cur = blob
    for _ in range(max_layers):
        m = _magic(cur)
        if m:
            return m, cur, layers
        un = _maybe_zlib(cur)
        if un is None:
            return None, cur, layers
        layers.append("zlib")
        cur = un
    return _magic(cur), cur, layers


def discover_embedded(apk) -> list[tuple[str, bytes]]:
    """Every entry in `apk` that resolves to a nested archive/dex, excluding the
    apk's own top-level `classes*.dex` (already processed as primary dexes)."""
    out: list[tuple[str, bytes]] = []
    try:
        files = apk.list_files()
    except Exception:
        return out
    for n in files:
        if n.endswith(".dex") and "/" not in n:
            continue
        try:
            b = apk.read_file(n)
        except Exception:
            continue
        if not b:
            continue
        kind, _resolved, _layers = resolve_payload(b)
        if kind:
            out.append((n, b))
    return out


class Target:
    """A processable unit: one or more DEX + how to feed them to the VM."""

    __slots__ = ("label", "dexes", "dex_blobs", "resources", "children")

    def __init__(self, label, dexes, dex_blobs, resources, children):
        self.label = label
        self.dexes = dexes            # list[platypus.Dex]
        self.dex_blobs = dex_blobs    # list[(bytes, name)] for the VM
        self.resources = resources    # resource table or None
        self.children = children      # list[(path, bytes)] to recurse into


def _dex_target(label: str, dex_blob: bytes, name: str) -> Target | None:
    try:
        d = platypus.Dex.from_bytes(dex_blob, name)
    except Exception:
        return None
    return Target(label, [d], [(dex_blob, name)], None, [])


def load_target(label: str, blob: bytes):
    """Turn a raw payload blob into a `Target` (+ a list of encrypted-payload
    records for anything we couldn't decrypt statically). Returns
    `(target_or_None, encrypted_records)`."""
    encrypted: list[dict] = []
    kind, resolved, layers = resolve_payload(blob)

    if kind == "dex":
        t = _dex_target(label, resolved, label.rsplit("::", 1)[-1] or "classes.dex")
        if t is None:
            encrypted.append({"path": label, "size": len(blob), "layers": layers,
                              "reason": "declared DEX magic but failed to parse"})
        return t, encrypted

    if kind == "zip":
        # Preferred path: it's a well-formed APK/JAR the native loader accepts.
        try:
            apk = platypus.Apk.from_bytes(resolved)
            dexes = apk.dex_files()
            if dexes:
                blobs = []
                for n in apk.list_files():
                    if n.endswith(".dex") and "/" not in n:
                        try:
                            blobs.append((apk.read_file(n), n))
                        except Exception:
                            pass
                try:
                    res = apk.resources()
                except Exception:
                    res = None
                return Target(label, dexes, blobs, res, discover_embedded(apk)), encrypted
        except Exception:
            pass
        # Fallback: a bare zip of (possibly encrypted) dex/zip entries — salvage
        # what parses, record what doesn't.
        return _load_zip_fallback(label, resolved, encrypted)

    # Couldn't reach a zip/dex — an encrypted/unknown payload.
    encrypted.append({"path": label, "size": len(blob), "layers": layers,
                      "reason": "not a DEX/ZIP after peeling zlib "
                                "(likely XOR/AES-encrypted, needs runtime decryption)"})
    return None, encrypted


def _load_zip_fallback(label: str, zip_blob: bytes, encrypted: list[dict]):
    """`Apk.from_bytes` rejected this zip (usually an encrypted inner dex).
    Enumerate entries directly: load any that resolve to real dex, queue nested
    zips as children, and record the rest as encrypted."""
    dexes, blobs, children = [], [], []
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_blob))
    except Exception as e:
        encrypted.append({"path": label, "size": len(zip_blob), "layers": [],
                          "reason": f"zip parse failed: {e}"})
        return None, encrypted
    for info in zf.infolist():
        try:
            data = zf.read(info.filename)
        except Exception as e:
            encrypted.append({"path": f"{label}::{info.filename}", "size": info.file_size,
                              "layers": [], "reason": f"entry unreadable: {e}"})
            continue
        kind, resolved, layers = resolve_payload(data)
        if kind == "dex":
            name = f"{Path(label).name}!{info.filename}"
            try:
                dexes.append(platypus.Dex.from_bytes(resolved, name))
                blobs.append((resolved, name))
            except Exception:
                encrypted.append({"path": f"{label}::{info.filename}",
                                  "size": len(data), "layers": layers,
                                  "reason": "DEX magic but failed to parse"})
        elif kind == "zip":
            children.append((f"{label}::{info.filename}", data))
        else:
            encrypted.append({"path": f"{label}::{info.filename}", "size": len(data),
                              "layers": layers,
                              "reason": "encrypted/opaque entry (needs runtime decryption)"})
    if not dexes and not children:
        return None, encrypted
    return Target(label, dexes, blobs, None, children), encrypted


# ── Per-target processing ─────────────────────────────────────────────────────

def process_target(target: Target, out_dir: Path, args) -> dict:
    """Run the full pipeline (deflatten + detect + VM strings) on one target,
    writing its own `src/` + reports under `out_dir`. Returns a stats dict."""
    src_dir = out_dir / "src"
    (src_dir if not args.no_decompile else out_dir).mkdir(parents=True, exist_ok=True)

    findings: list[dict] = []
    recovered: list[dict] = []
    decoder_targets: set[str] = set()
    profile = {"string_decoders": 0, "reflection_sites": 0, "fill_array_data": 0}
    n_classes = n_decompiled = n_errors = 0
    pkg = args.package.strip("L;") if args.package else None

    for dex in target.dexes:
        try:
            names = dex.class_names()
        except Exception:
            continue
        for cname in names:
            norm = cname.strip("L;")
            if pkg and not norm.startswith(pkg):
                continue
            if args.max_classes and n_classes >= args.max_classes:
                break
            n_classes += 1

            java = None
            if not args.no_decompile:
                try:
                    java = dex.decompile_class(cname)
                    (src_dir / safe_filename(cname)).write_text(java, encoding="utf-8")
                    n_decompiled += 1
                except Exception as e:  # noqa: BLE001
                    n_errors += 1
                    continue

            try:
                disasm = dex.disassemble_class(cname)
            except Exception:
                disasm = ""

            if disasm:
                findings.extend(analyse(disasm, java, norm))
                decoders = string_decoder_targets(disasm, class_to_desc(cname))
                decoder_targets.update(decoders)
                profile["string_decoders"] += len(decoders)
                profile["reflection_sites"] += (
                    disasm.count("Ljava/lang/Class;->forName")
                    + disasm.count("Ljava/lang/reflect/")
                )
                profile["fill_array_data"] += disasm.count("fill-array-data")

    if not args.no_strings and decoder_targets:
        recovered = recover_strings_vm(target.dexes, target.dex_blobs, target.resources,
                                       decoder_targets, args.instr_limit)

    _write_reports(out_dir, findings, recovered)
    return {
        "label": target.label, "out_dir": out_dir,
        "n_classes": n_classes, "n_decompiled": n_decompiled, "n_errors": n_errors,
        "findings": findings, "recovered": recovered, "profile": profile,
    }


# ── Main passes ───────────────────────────────────────────────────────────────

def _sanitize(label: str) -> str:
    return re.sub(r"[^\w.-]+", "_", label).strip("_") or "payload"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("apk", nargs="?", default=DEFAULT_APK, help="path to the APK")
    ap.add_argument("-o", "--out", help="output directory (default <apk_dir>/deobf_out)")
    ap.add_argument("--package", help="only process classes under this package prefix (e.g. com/foo)")
    ap.add_argument("--max-classes", type=int, default=0, help="stop after N classes (0 = all)")
    ap.add_argument("--no-decompile", action="store_true", help="skip writing decompiled source")
    ap.add_argument("--no-strings", action="store_true", help="skip VM string recovery")
    ap.add_argument("--no-recurse", action="store_true", help="do not descend into embedded payloads")
    ap.add_argument("--max-depth", type=int, default=8, help="max embedded-payload recursion depth")
    ap.add_argument("--instr-limit", type=int, default=2_000_000, help="VM instruction budget per decode")
    args = ap.parse_args()

    apk_path = Path(args.apk)
    if not apk_path.is_file():
        return _die(f"APK not found: {apk_path}")

    out = Path(args.out) if args.out else apk_path.parent / "deobf_out"
    out.mkdir(parents=True, exist_ok=True)

    print(f"[*] loading {apk_path}")
    t0 = time.time()

    # BFS over the payload tree. Each item: (label, blob, depth). `visited`
    # dedups by content hash so a payload referenced twice (or a self-referential
    # archive) is processed once.
    root_label = apk_path.name
    queue: list[tuple[str, bytes, int]] = [(root_label, apk_path.read_bytes(), 0)]
    visited: set[str] = set()
    sources: list[dict] = []      # per-target stats (root first)
    encrypted: list[dict] = []    # payloads we couldn't decrypt statically

    while queue:
        label, blob, depth = queue.pop(0)
        sha = _sha(blob)
        if sha in visited:
            continue
        visited.add(sha)

        target, enc = load_target(label, blob)
        encrypted.extend(enc)
        if target is None:
            if depth == 0:
                return _die(f"could not open {label} as an APK/DEX")
            continue

        is_root = depth == 0
        out_dir = out if is_root else out / "embedded" / _sanitize(label)
        indent = "" if is_root else "    " * depth + "└ "
        print(f"[*] {indent}{label}: {len(target.dexes)} dex"
              + (f", {len(target.children)} embedded" if target.children else ""))

        stats = process_target(target, out_dir, args)
        stats["depth"] = depth
        sources.append(stats)

        if not args.no_recurse and depth < args.max_depth:
            for cpath, cblob in target.children:
                queue.append((cpath, cblob, depth + 1))

    _write_aggregate(out, sources, encrypted)

    # ── Summary ──
    dt = time.time() - t0
    tot_classes = sum(s["n_classes"] for s in sources)
    tot_strings = sum(len(s["recovered"]) for s in sources)
    tot_flat = sum(1 for s in sources for f in s["findings"] if f["kind"] == "control_flow_flattening")
    tot_opaq = sum(1 for s in sources for f in s["findings"] if f["kind"] == "opaque_predicate")
    print(f"\n[+] done in {dt:.1f}s across {len(sources)} code unit(s)")
    print(f"    classes processed : {tot_classes}")
    print(f"    flattened methods : {tot_flat}")
    print(f"    opaque predicates : {tot_opaq}")
    print(f"    strings recovered : {tot_strings}")
    print(f"    encrypted payloads: {len(encrypted)} (need runtime decryption)")
    print(f"\n    per code unit:")
    for s in sources:
        pad = "  " * s["depth"]
        print(f"      {pad}{s['label']}: {s['n_classes']} cls, "
              f"{len(s['recovered'])} strings, {len(s['findings'])} findings")
    if encrypted:
        print(f"\n    encrypted payloads (see PAYLOADS.txt):")
        for e in encrypted:
            layers = "+".join(["zip"] + e["layers"]) if e["layers"] else "?"
            print(f"      {e['path']}  ({e['size']:,} B, {layers}) — {e['reason']}")
    if tot_flat == 0 and tot_opaq == 0:
        print("\n    note: no DEX-level control-flow flattening / opaque predicates found —")
        print("          obfuscation here is string encryption + reflection + nested packaging.")
    print(f"\n    output → {out}")
    print(f"      src/                    root deflattened/folded source")
    print(f"      strings.txt             root recovered strings")
    print(f"      embedded/<payload>/     same, per embedded code unit")
    print(f"      strings_all.txt         every recovered string, across all units")
    print(f"      PAYLOADS.txt            payload tree + encrypted-blob inventory")
    return 0


def _write_aggregate(out: Path, sources: list[dict], encrypted: list[dict]) -> None:
    """Cross-unit rollups: one JSON, one combined strings file, one payload map."""
    out.joinpath("report.json").write_text(json.dumps({
        "sources": [{
            "label": s["label"], "depth": s["depth"],
            "classes": s["n_classes"], "decompiled": s["n_decompiled"],
            "errors": s["n_errors"], "profile": s["profile"],
            "findings": s["findings"], "strings": s["recovered"],
        } for s in sources],
        "encrypted_payloads": encrypted,
    }, indent=2), encoding="utf-8")

    # Combined, deduped strings across every code unit.
    slines = ["# All recovered strings (across every embedded code unit)", ""]
    seen: set[tuple] = set()
    for s in sources:
        first = True
        for r in s["recovered"]:
            key = (s["label"], r["decoder"], r["value"])
            if key in seen:
                continue
            seen.add(key)
            if first:
                slines.append(f"\n## {s['label']}")
                first = False
            slines.append(f"{r['value']!r}  [{r['decoder']}({r['index']}) @ {r['caller']}]")
    out.joinpath("strings_all.txt").write_text("\n".join(slines) + "\n", encoding="utf-8")

    # Payload tree + encrypted inventory.
    plines = ["# Payload map", "",
              "## Code units processed (label: dex / classes / strings)"]
    for s in sources:
        pad = "  " * s["depth"]
        plines.append(f"  {pad}{s['label']}: {s['n_classes']} classes, "
                      f"{len(s['recovered'])} strings")
    plines += ["", f"## Encrypted / opaque payloads ({len(encrypted)})",
               "# These stay encrypted after static zip+zlib peeling — the loader",
               "# decrypts them at runtime (XOR/AES). Extract by hooking or by",
               "# recovering the key from the loader class.", ""]
    for e in encrypted:
        layers = "+".join(["zip"] + e["layers"]) if e["layers"] else "(raw)"
        plines.append(f"  {e['path']}")
        plines.append(f"      {e['size']:,} bytes | layers peeled: {layers}")
        plines.append(f"      {e['reason']}")
    out.joinpath("PAYLOADS.txt").write_text("\n".join(plines) + "\n", encoding="utf-8")


def _write_reports(out: Path, findings: list[dict], recovered: list[dict]) -> None:
    """Per-unit report.txt + strings.txt (report.json is written per-run by the
    aggregate)."""
    lines = ["# Deobfuscation findings", ""]
    flat = [f for f in findings if f["kind"] == "control_flow_flattening"]
    opaq = [f for f in findings if f["kind"] == "opaque_predicate"]
    lines.append(f"## Control-flow flattening ({len(flat)})")
    for f in flat:
        lines.append(f"  {f['class']}  {f['detail']}")
    lines.append("")
    lines.append(f"## Opaque predicates ({len(opaq)})")
    for f in opaq:
        lines.append(f"  {f['class']}  {f['detail']}")
    (out / "report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")

    if recovered:
        slines = ["# Recovered strings (decoder -> value)", ""]
        seen = set()
        for r in recovered:
            key = (r["decoder"], r["value"])
            if key in seen:
                continue
            seen.add(key)
            slines.append(f"{r['value']!r}\n    via {r['decoder']}({r['index']})  @ {r['caller']}")
        (out / "strings.txt").write_text("\n".join(slines) + "\n", encoding="utf-8")


def _progress(n: int, msg: str) -> None:
    print(f"    [{n:>5}] {msg}")


def _die(msg: str) -> int:
    print(f"error: {msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
