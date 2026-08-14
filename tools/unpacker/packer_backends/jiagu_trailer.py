"""Jiagu `qh\\x00\\x01` trailer parser.

Every Jiagu-packed sample in this corpus carries an extra trailer
appended to its tiny stub `classes.dex`. The trailer begins at the
DEX's `file_size` (so ART ignores it during loading) and has this
structure:

    +0  magic   = b'qh\\x00\\x01'        # u32 little-endian
    +4  size    = trailer total length    # u32, includes the 12-byte header
    +8  data_off                          # u32, offset within the body
                                          # where the encrypted-data section starts
    +12 body[size-12]                     # variable-length body

The body is split in two by `data_off`:

    body[0 .. data_off]      → metadata section (XOR-0xa6-encoded key/value entries)
    body[data_off .. end]    → encrypted data section (bulk DEX payload + sub-tables)

Metadata section layout
-----------------------

A sequence of variable-length chunks, each preceded by a 12-byte marker:

    d6 ed c6 c6 LL c6 c6 c6 TT c6 c6 c6
    \_________________________________/
     XOR every byte with 0xc6:
        first 4 bytes  = 0x00002b10   (fixed magic identifying a chunk header)
        next  4 bytes  = LL', a single u8 in [0..255] = the key length
        next  4 bytes  = TT', a single u8 = a type/category byte (often the ASCII
                                            first letter of the next chunk: 'p',
                                            's', 'q', 'C', etc. — used purely
                                            for sort/grouping)

Followed by `next_marker - this_marker - 12` payload bytes, each XOR-0xa6.
The decoded payload is `KEY (LL bytes) || VALUE (rest)`.

Recovered keys observed across the 71-sample corpus include:

    .jgapp-hash          (the assets/.jgapp content; chunk has a non-printable key)
    ACtIvIty_NAME        the original Activity FQCN (CamelCase wrt high bits)
    ApK\\rMD5             the original APK's MD5 fingerprint
    App_NAME             original Application FQCN (the StubApp's target)
    CHECKSuM             integer (build / DEX checksum)
    JIAGuVErsION         protector version, e.g. "1.4.0.4"
    prOtECt_tIME         packing timestamp, e.g. "2026-04-18\\x0018:09:03"
    pKG                  original package name (== the AndroidManifest's value)
    sIG / sIGN           signing-cert sequence / fingerprint
    stuB_ApP_NAME        the stub class FQCN (com/stub/StubApp etc.)
    vErsION_CODE/_NAME   the original Android versionCode and versionName
    x86                  arch flag — also marks the END of the metadata section;
                         the bulk encrypted data begins immediately after this
                         chunk's value byte

Data section layout
-------------------

    +0   n_entries   u32 little-endian
    +4   entry0_size u32 little-endian
    +8   entry0_off  u32 little-endian   # offset within the data section
    +12  encrypted   ( n_entries-1) further (size, off) pairs, encrypted
    +12+8(n-1) ... encrypted blob payloads (sized & ordered per the table)

The first entry's (size, offset) is plaintext. Entries 1..n-1 are
encrypted with a per-build key that the loader derives at runtime from
the APK's signing-certificate fingerprint and per-build constants
(matching `ApK\\rMD5` and `sIGN` in the metadata). Static recovery of
those keys is not feasible in this engagement — see
`by-packer/jiagu.md` for the limitation.

Entry 0 contains raw DEX bytecode for *some* of the original methods
(stored as code-item-shaped blobs); the rest of the DEX skeleton is
in the encrypted entries.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import Optional


JIAGU_TRAILER_MAGIC = b"qh\x00\x01"
CHUNK_MARKER_RE = re.compile(
    rb"\xd6\xed\xc6\xc6.\xc6\xc6\xc6.\xc6\xc6\xc6",
    re.DOTALL,
)


@dataclass
class JiaguMetaEntry:
    """One key/value pair from the trailer's metadata section."""
    key: bytes                 # raw key bytes (may include 0xa0..0xaf "shift" markers)
    key_str: str               # best-effort ASCII rendering
    type_byte: int             # single u8 grouping/sort hint
    value: bytes               # raw value bytes
    value_str: str             # best-effort ASCII rendering


@dataclass
class JiaguTrailer:
    """Parsed Jiagu trailer."""
    trailer_off: int           # file offset of `qh\x00\x01`
    trailer_size: int          # size field
    data_off: int              # offset within body where the data section starts
    body_len: int              # full body length
    metadata: list = field(default_factory=list)  # list[JiaguMetaEntry]
    data_section: bytes = b""

    # Convenience views
    n_entries: int = 0
    entry0_size: int = 0
    entry0_off: int = 0

    # Raw encrypted entry-table bytes for entries 1..n-1 (each is an opaque
    # 8-byte slot — (size,off) pair encrypted under the per-build key).
    # Always present (when n_entries >= 2).
    encrypted_table: bytes = b""

    def get(self, key: str) -> Optional[str]:
        """Look up a metadata value by Jiagu-normalised key.

        Jiagu rewrites strings in a CamelCase-with-internal-markers
        form: high-bit bytes (0x80..0xff post-XOR) are inline
        separators/case markers, and control bytes (0x0d, 0x0e, 0x0f,
        0x00) replace `_`, `.`, `/`, and space respectively. We
        normalise both sides to lowercase ASCII with all separators
        elided and compare.
        """
        target = _normalise_key(key.encode("ascii", "ignore"))
        for m in self.metadata:
            if _normalise_key(m.key) == target:
                return _render_value(m.value)
        return None

    def get_raw(self, key: str) -> Optional[bytes]:
        target = _normalise_key(key.encode("ascii", "ignore"))
        for m in self.metadata:
            if _normalise_key(m.key) == target:
                return m.value
        return None


def _expand_letter_markers(b: bytes) -> bytes:
    """Expand Jiagu's high-bit single-letter markers in-place.

    Jiagu's config rendering uses byte 0xa0+N (N in 1..26) as a
    one-byte stand-in for uppercase letter N — e.g. 0xa1='A',
    0xae='N', 0xba='Z'. We expand them so downstream normalisation
    sees a real ASCII letter.
    """
    out = bytearray()
    for c in b:
        if 0xa1 <= c <= 0xba:
            out.append(c - 0xa0 + 0x40)  # 'A'..'Z'
        else:
            out.append(c)
    return bytes(out)


def _normalise_key(b: bytes) -> bytes:
    """Lowercase, drop all non-alphanumeric bytes (after expanding
    Jiagu's letter markers)."""
    b = _expand_letter_markers(b)
    out = bytearray()
    for c in b:
        if 0x41 <= c <= 0x5a:        # uppercase
            out.append(c + 0x20)
        elif 0x61 <= c <= 0x7a:      # lowercase
            out.append(c)
        elif 0x30 <= c <= 0x39:      # digits
            out.append(c)
        # else: drop (separators)
    return bytes(out)


_SEP_TABLE = {
    0x0d: "_",   # underscore
    0x0e: ".",   # dot (package separator)
    0x0f: "/",   # forward slash (class path)
    0x00: " ",   # space
}


def _render_value(b: bytes) -> str:
    """Render a value byte string back to a likely-intended ASCII form.

    Maps known control-byte separators to their semantic equivalents,
    expands the letter-marker bytes (0xa1..0xba → 'A'..'Z'), and
    keeps printable ASCII as-is."""
    b = _expand_letter_markers(b)
    out = []
    for c in b:
        if c in _SEP_TABLE:
            out.append(_SEP_TABLE[c])
        elif 0x20 <= c < 0x7f:
            out.append(chr(c))
        else:
            out.append(f"\\x{c:02x}")
    return "".join(out)


def _render_ascii(b: bytes) -> str:
    """Diagnostic-friendly rendering: keep separators as escape
    sequences so the raw structure is visible in JSON dumps."""
    return b.decode("latin-1")


def parse_trailer(dex_bytes: bytes) -> Optional[JiaguTrailer]:
    """Parse a Jiagu trailer if present in a classes.dex.

    Returns None if no `qh\\x00\\x01` magic is found or the structure
    is malformed.
    """
    pos = dex_bytes.find(JIAGU_TRAILER_MAGIC)
    if pos < 0:
        return None
    if pos + 12 > len(dex_bytes):
        return None
    try:
        size = struct.unpack_from("<I", dex_bytes, pos + 4)[0]
        data_off = struct.unpack_from("<I", dex_bytes, pos + 8)[0]
    except struct.error:
        return None
    body = dex_bytes[pos + 12:]
    if data_off > len(body):
        return None

    # Scan metadata section for chunk markers
    metadata = []
    matches = [m.start() for m in CHUNK_MARKER_RE.finditer(body[:data_off])]
    for i, off in enumerate(matches):
        nxt = matches[i + 1] if i + 1 < len(matches) else data_off
        if off + 12 > len(body):
            break
        marker = body[off:off + 12]
        klen = marker[4] ^ 0xc6
        type_byte = marker[8] ^ 0xc6
        payload_enc = body[off + 12:nxt]
        payload = bytes(b ^ 0xa6 for b in payload_enc)
        if 0 < klen <= len(payload):
            key = payload[:klen]
            value = payload[klen:]
        else:
            key, value = payload, b""
        metadata.append(JiaguMetaEntry(
            key=key,
            key_str=_render_ascii(key),
            type_byte=type_byte,
            value=value,
            value_str=_render_ascii(value),
        ))

    data_section = body[data_off:]

    n_entries = entry0_size = entry0_off = 0
    encrypted_table = b""
    if len(data_section) >= 12:
        n_entries = struct.unpack_from("<I", data_section, 0)[0]
        entry0_size = struct.unpack_from("<I", data_section, 4)[0]
        entry0_off = struct.unpack_from("<I", data_section, 8)[0]
        # The (size, off) pairs for entries 1..n-1 follow as 8-byte each,
        # but encrypted under the per-build key. We keep them as opaque
        # bytes so downstream runtime work can decrypt and act on them.
        if n_entries >= 2:
            tbl_end = 12 + (n_entries - 1) * 8
            if tbl_end <= len(data_section):
                encrypted_table = data_section[12:tbl_end]

    return JiaguTrailer(
        trailer_off=pos,
        trailer_size=size,
        data_off=data_off,
        body_len=len(body),
        metadata=metadata,
        data_section=data_section,
        n_entries=n_entries,
        entry0_size=entry0_size,
        entry0_off=entry0_off,
        encrypted_table=encrypted_table,
    )


# ---------------------------------------------------------------------------
# Entry-0 content classification
# ---------------------------------------------------------------------------
#
# Empirical finding (this engagement): entry 0's structure differs by Jiagu
# protector version.
#
# **Older builds (≤ 1.3.9.x, ~16 samples in our corpus).** After a 16-byte
# encrypted/opaque header, entry 0 contains a concatenated sequence of
# *plaintext* Dalvik `code_item` structures — i.e. raw method bodies of
# (most of) the original DEX. The class/string/type/method/proto tables
# live in encrypted entries 1..n-1, so the entry-0 bytes alone are not
# sufficient to rebuild a runnable DEX, but they are very useful for
# forensics (method-body reading, call-graph extraction, opcode-pattern
# IOC matching).
#
# Indicator: byte distribution after the 16-byte header is dominated by
# 0x00, 0x01, 0x02, 0x10 — typical Dalvik bytecode.
#
# **Newer builds (1.4.0.x, ~52 samples in our corpus).** Entry 0 is
# heavily mangled: a large prefix region (often ~1.7 MB) is filled with
# the four-byte pattern multiples-of-15 (0x0f / 0x1e / 0x2d / 0x3c) and
# real bytecode only resumes later in the entry. The mangling appears to
# be a deterministic nibble-encoding step keyed by the same per-build
# constant that protects entries 1..n-1.
#
# Indicator: byte distribution has 0x0f as the single most common byte
# (typically ≥ 15%) and a strong cluster on the {0x0f, 0x1e, 0x2d, 0x3c}
# set within the prefix.
#
# `classify_entry0_format` returns one of:
#   "v1_plaintext_codeitems"  — older builds, entry 0 is recoverable
#   "v2_nibble_obfuscated"    — newer builds, entry 0 is not recoverable
#   "unknown"                 — heuristic could not decide
# ---------------------------------------------------------------------------

_NIBBLE_OBF_SET = {0x00, 0x0f, 0x1e, 0x2d, 0x3c}


def classify_entry0_format(entry0_bytes: bytes) -> str:
    """Classify entry-0 protection style heuristically.

    Skips the first 16 bytes (always opaque) and inspects ~2 KiB of the
    immediately-following region.
    """
    if len(entry0_bytes) < 32:
        return "unknown"
    sample = entry0_bytes[16:16 + 2048]
    if not sample:
        return "unknown"
    nibble_obf_count = sum(1 for b in sample if b in _NIBBLE_OBF_SET)
    zero_count = sample.count(0x00)
    # In newer builds the prefix is overwhelmingly {0x0f,0x1e,0x2d,0x3c}
    if nibble_obf_count / len(sample) > 0.70:
        return "v2_nibble_obfuscated"
    # In older builds typical Dalvik distribution: lots of 0x00 (padding,
    # high bytes of u4 indices) plus 0x01/0x02/0x10/0x20 (common opcodes
    # and small constants).
    if zero_count / len(sample) > 0.05:
        return "v1_plaintext_codeitems"
    return "unknown"


def _version_to_tuple(v):
    """'1.3.9.9' -> (1,3,9,9); robust to None."""
    if not v:
        return None
    try:
        return tuple(int(x) for x in v.split("."))
    except Exception:
        return None


def classify_by_version(jiagu_version: str) -> str:
    """Map JiaguVersion → expected entry-0 format. Falls back to "unknown"
    when the heuristic can't decide."""
    t = _version_to_tuple(jiagu_version)
    if t is None:
        return "unknown"
    # 1.3.9.x and earlier → plaintext code_items
    if t[:3] <= (1, 3, 9):
        return "v1_plaintext_codeitems"
    # 1.4.0.x → nibble-obfuscated
    if t[:2] == (1, 4):
        return "v2_nibble_obfuscated"
    return "unknown"


# ---------------------------------------------------------------------------
# Plaintext code-item tail detection (works on BOTH v1 and v2 entry0 bodies)
# ---------------------------------------------------------------------------
#
# Empirical finding (this engagement, 2026-05-18): for v2 (nibble-obfuscated)
# entry-0 bodies, the *first ~20–80%* of the body is filled with bytes from
# the multiples-of-15 alphabet (the "nibble obfuscation" prefix), and the
# *trailing* portion is plaintext concatenated DEX `code_item`s exactly like
# v1 builds. This means many v2 builds also yield partial recovery — we just
# need to locate the boundary where the long nibble run ends and write the
# tail.
#
# `find_codeitems_tail_offset` scans for the last position where a sustained
# (≥ 32-byte) run of nibble-alphabet bytes ends. Bytes after that point are
# read as the plaintext code-items tail.
#
# Two of the seven v2 samples observed have 0-byte tails (the entire body is
# nibble-encoded for them — those are the truly unrecoverable v2 builds).
# The other five v2 samples have multi-MB plaintext tails that this routine
# carves to disk.
# ---------------------------------------------------------------------------

# Full "multiples of 15" alphabet (0x0f * k mod 256 for k in 0..17). Plus the
# adjacent bytes 0x01, 0x02 that show up in the nibble prefix interspersed.
_NIBBLE_ALPHABET = {0x0f * k % 256 for k in range(17)} | {0}


def find_codeitems_tail_offset(entry0_body: bytes, min_run: int = 32) -> int:
    """Return the byte offset within `entry0_body` after which we believe
    the data is plaintext Dalvik code_items.

    For v1 builds this returns 0 (the whole body is plaintext after the
    16-byte header already stripped by the caller).

    For v2 builds this returns the end of the last sustained ≥ `min_run`
    byte run of "nibble alphabet" bytes.

    Returns `len(entry0_body)` if no plaintext tail was found.
    """
    n = len(entry0_body)
    if n == 0:
        return 0
    # Quick early-out: if the first 64 bytes are not dominated by the nibble
    # alphabet, we're already in plaintext territory (v1 case).
    first64 = entry0_body[:64]
    if first64 and sum(1 for b in first64 if b in _NIBBLE_ALPHABET) < len(first64) * 0.5:
        return 0
    last_run_end = 0
    i = 0
    while i < n:
        if entry0_body[i] in _NIBBLE_ALPHABET:
            j = i
            while j < n and entry0_body[j] in _NIBBLE_ALPHABET:
                j += 1
            if j - i >= min_run:
                last_run_end = j
            i = j
        else:
            i += 1
    return last_run_end


def summarise_trailer(tr: JiaguTrailer) -> dict:
    """Compact, JSON-serialisable summary suitable for the per-sample
    manifest. The full raw data_section is NOT included (it can be many
    MB) — only its length and the recovered metadata."""
    flat_meta = []
    for m in tr.metadata:
        flat_meta.append({
            "key_ascii": m.key_str,
            "key_hex": m.key.hex(),
            "type_byte": m.type_byte,
            "value_ascii": m.value_str,
            "value_len": len(m.value),
        })
    jiagu_version = tr.get("JiaguVersion")
    # Slice entry-0's content for heuristic classification (limited to
    # the first 2KB+16-byte-header). We only need a small view.
    e0_slice = b""
    if (tr.entry0_off >= 0
            and tr.entry0_size > 0
            and tr.entry0_off + min(tr.entry0_size, 0x1000) <= len(tr.data_section)):
        e0_slice = tr.data_section[
            tr.entry0_off:tr.entry0_off + min(tr.entry0_size, 0x1000)
        ]
    cls_by_data = classify_entry0_format(e0_slice) if e0_slice else "unknown"
    cls_by_ver = classify_by_version(jiagu_version)

    # Compute the plaintext-tail offset within entry 0's *body* (post the
    # 16-byte opaque header). The caller (jiagu.py) writes the tail to
    # `extracted/jiagu_entry0_codeitems.bin` so reviewers can scan its
    # `code_item`s directly without dealing with the nibble-obfuscated
    # prefix.
    pt_tail_offset = 0
    pt_tail_size = 0
    if (tr.entry0_off >= 0
            and tr.entry0_size > 16
            and tr.entry0_off + tr.entry0_size <= len(tr.data_section)):
        body = tr.data_section[
            tr.entry0_off + 16:tr.entry0_off + tr.entry0_size
        ]
        # Scan a bounded prefix (16 MB cap) — the alphabet-density scan is
        # O(n) but we don't want to spend many seconds on pathologically
        # large entries during batch runs.
        scan = body[: 16 * 1024 * 1024]
        # If scan is the full body, finding boundary in scan == finding it
        # in body; otherwise we report 0 (unknown) for safety.
        if len(scan) >= len(body):
            pt_tail_offset = find_codeitems_tail_offset(scan)
            pt_tail_size = len(body) - pt_tail_offset
        else:
            pt_tail_offset = 0
            pt_tail_size = 0

    return {
        "trailer_off": tr.trailer_off,
        "trailer_size": tr.trailer_size,
        "data_off": tr.data_off,
        "body_len": tr.body_len,
        "data_section_len": len(tr.data_section),
        "n_entries": tr.n_entries,
        "entry0_size": tr.entry0_size,
        "entry0_off": tr.entry0_off,
        "encrypted_table_len": len(tr.encrypted_table),
        "metadata": flat_meta,
        # Common parsed fields (Jiagu's internal key names; normalised
        # lookup means case + separators don't matter)
        "original_app": tr.get("AppName"),
        "activity_name": tr.get("ActivityName"),
        "apk_md5": tr.get("ApkMD5"),
        "apk_sign": tr.get("Sign"),
        "stub_class": tr.get("StubAppName"),
        "package": tr.get("pkg"),
        "version_code": tr.get("VersionCode"),
        "version_name": tr.get("VersionName"),
        "jiagu_version": jiagu_version,
        "protect_time": tr.get("ProtectTime"),
        "allowed_sig": tr.get("AllowedSig"),
        "checksum": tr.get("Checksum"),
        "sig_serial": tr.get("sig"),
        # Recovery-class hints (see classify_entry0_format docs above).
        "entry0_format_by_data": cls_by_data,
        "entry0_format_by_version": cls_by_ver,
        "entry0_format": cls_by_data if cls_by_data != "unknown" else cls_by_ver,
        # Plaintext code_items tail offset within entry-0's *body* (post the
        # 16-byte opaque header). 0 == whole body is plaintext (v1 builds);
        # > 0 == the prefix [0..pt_tail_offset) is nibble-obfuscated and the
        # tail [pt_tail_offset..] is plaintext code_items (v2 partial
        # recovery); == body_len == no plaintext tail (the truly opaque v2
        # subset).
        "plaintext_tail_offset": pt_tail_offset,
        "plaintext_tail_size": pt_tail_size,
    }
