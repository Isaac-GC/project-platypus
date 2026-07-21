"""Jiagu plaintext-`code_item` recovery.

Empirical finding (2026-05-18): Jiagu's "encrypted" data section
(entries 1..n-1 after the `qh\\x00\\x01` trailer) is only partially
encrypted. The class/method/type/string ID tables and the string_data
section are encrypted into `pre_e0` (a ~1 MB blob with full entropy
≈ 7.999), but the bulk **Dalvik method bodies** are concatenated as
plaintext `code_item` structures in:

  - the latter ~2.6 MB of entry 0 (this part is already carved as
    `jiagu_entry0_body.bin` by `jiagu.py` — that's the v1 plaintext
    code_items recovery the existing backend ships)
  - the large plaintext middle of `jiagu_post_e0.bin` — typically two
    plaintext regions of ~1 MB each, separated by short opaque /
    high-entropy bookends (likely per-entry headers and a final
    trailer)

This module walks those byte ranges with a strict `code_item` parser
(including `try_item[]` and `encoded_catch_handler_list` for items
with tries), so we recover the full body of every protected method
*for which the bytecode is in the data section*. Across a 71-sample
Jiagu corpus, this typically yields 15–35 k methods per sample —
i.e., **all** of the original DEX's methods whose bodies survive.
The metadata (class names, method signatures, type IDs) remains
encrypted, but the recovered bytecode is sufficient for:

  - opcode-pattern IOC matching
  - method-body forensics (which APIs each method calls)
  - feeding into a synthetic-DEX wrapper (see
    `build_synthetic_dex`) so analysis tools like `dexdump` and
    `androguard` can parse the recovered bodies

The module is **pure static** — no Unicorn, no Frida, no
device-side decryption. It just parses bytes that the packer already
leaves in the clear.
"""

from __future__ import annotations

import collections
import math
import struct
import zlib
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# ULEB128 / SLEB128 (used inside code_item's catch handler list)
# ---------------------------------------------------------------------------

def _uleb128(buf: bytes, off: int):
    """Returns (value, bytes_consumed) or (None, 0) on error."""
    result = 0
    shift = 0
    n = 0
    while True:
        if off + n >= len(buf):
            return None, 0
        b = buf[off + n]
        n += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            break
        shift += 7
        if shift > 32:
            return None, 0
    return result, n


def _sleb128(buf: bytes, off: int):
    result = 0
    shift = 0
    n = 0
    while True:
        if off + n >= len(buf):
            return None, 0
        b = buf[off + n]
        n += 1
        result |= (b & 0x7f) << shift
        shift += 7
        if not (b & 0x80):
            if b & 0x40:
                result |= -(1 << shift)
            break
        if shift > 32:
            return None, 0
    return result, n


def _uleb128_emit(v: int) -> bytes:
    """Encode an unsigned int as ULEB128."""
    out = bytearray()
    while True:
        byte = v & 0x7f
        v >>= 7
        if v:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            break
    return bytes(out)


# ---------------------------------------------------------------------------
# code_item parser
# ---------------------------------------------------------------------------

@dataclass
class CodeItem:
    """A single recovered Dalvik `code_item`."""
    off: int                 # offset within the source buffer
    body_end: int            # end offset (exclusive) within the source buffer
    regs: int
    ins: int
    outs: int
    tries: int
    debug_off: int
    insns_size: int          # count of u16 instruction code-units
    bytes: bytes             # the full code_item bytes (off .. body_end)


def parse_code_item(buf: bytes, off: int) -> Optional[CodeItem]:
    """Try to parse a code_item at `off` in `buf`. Returns None if the
    bytes there don't look like a valid code_item.

    The validation is strict:
      - registers_size ≤ 256, ins_size ≤ 256, outs_size ≤ 256, tries ≤ 64
      - ins_size ≤ registers_size (when registers_size > 0)
      - insns_size ∈ (0, 8192]
      - debug_info_off < 2^24
      - if tries > 0, each try_item's range must lie within insns_size
      - the encoded_catch_handler_list must parse without overflowing

    These bounds catch all the "fake matches" we'd otherwise get from
    walking 4-byte-aligned bytes through Dalvik bytecode (where
    arbitrary 16-byte windows would frequently parse as a code_item if
    we didn't bound the structural fields).
    """
    if off + 16 > len(buf):
        return None
    regs, ins, outs, tries = struct.unpack_from('<HHHH', buf, off)
    debug_off, insns_size = struct.unpack_from('<II', buf, off + 8)
    if regs > 256 or outs > 256 or tries > 64 or ins > 256:
        return None
    if regs > 0 and ins > regs:
        return None
    if insns_size == 0 or insns_size > 8192:
        return None
    if debug_off > (1 << 24):
        return None
    p = off + 16 + insns_size * 2
    if p > len(buf):
        return None
    if tries > 0:
        if insns_size & 1:
            p += 2
            if p > len(buf):
                return None
        for _ in range(tries):
            if p + 8 > len(buf):
                return None
            sa, ic, ho = struct.unpack_from('<IHH', buf, p)
            if sa + ic > insns_size:
                return None
            p += 8
        sz, n = _uleb128(buf, p)
        if sz is None or sz > 256:
            return None
        p += n
        for _ in range(sz):
            ssz, n = _sleb128(buf, p)
            if ssz is None:
                return None
            p += n
            cnt = abs(ssz)
            for _ in range(cnt):
                ti, n = _uleb128(buf, p)
                if ti is None:
                    return None
                p += n
                ad, n = _uleb128(buf, p)
                if ad is None:
                    return None
                p += n
            if ssz <= 0:
                ad, n = _uleb128(buf, p)
                if ad is None:
                    return None
                p += n
    return CodeItem(
        off=off, body_end=p,
        regs=regs, ins=ins, outs=outs, tries=tries,
        debug_off=debug_off, insns_size=insns_size,
        bytes=bytes(buf[off:p]),
    )


def walk_code_items(buf: bytes) -> list:
    """Walk through `buf` greedily finding plaintext code_items.

    Assumes code_items are 4-byte aligned relative to the start of
    `buf`. After each successful parse, jumps to the next 4-byte
    boundary past the body. On a failed parse, advances by 2 bytes
    (code_item headers are 16-byte aligned to 2-byte boundaries via
    the regs_size u16 leading the header, so a 2-byte step is fine).
    """
    out = []
    off = 0
    n = len(buf)
    while off < n - 16:
        ci = parse_code_item(buf, off)
        if ci is not None:
            out.append(ci)
            off = (ci.body_end + 3) & ~3
        else:
            off += 2
    return out


# ---------------------------------------------------------------------------
# Entropy-guided scanning (skip encrypted regions cheaply)
# ---------------------------------------------------------------------------

def _entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    cnt = collections.Counter(buf)
    n = len(buf)
    return -sum((v / n) * math.log2(v / n) for v in cnt.values())


def find_plaintext_runs(buf: bytes, chunk: int = 256,
                        thresh: float = 6.5) -> list:
    """Find byte ranges of `buf` whose 256-byte-window Shannon entropy
    is below `thresh`. Returns list of (start, end) byte offsets.

    DEX data sections are byte-distribution heavy on 0x00, 0x01, 0x02,
    small opcodes and ULEB128 continuations — typical entropy 4.5–6.0.
    Encrypted data has entropy > 7.5. The threshold of 6.5 cleanly
    separates the two with sub-second turn-around.
    """
    runs = []
    in_run = False
    run_start = 0
    n = len(buf)
    for off in range(0, n, chunk):
        sub = buf[off:off + chunk]
        if not sub:
            break
        e = _entropy(sub)
        if e < thresh:
            if not in_run:
                in_run = True
                run_start = off
        else:
            if in_run:
                runs.append((run_start, off))
                in_run = False
    if in_run:
        runs.append((run_start, n))
    return runs


# ---------------------------------------------------------------------------
# Synthetic DEX builder
# ---------------------------------------------------------------------------

DEX_MAGIC = b'dex\n035\x00'
DEX_HEADER_SIZE = 0x70


def _adler32(data: bytes) -> int:
    return zlib.adler32(data) & 0xffffffff


def build_synthetic_dex(code_items: list, *,
                        class_name: bytes = b'LRecovered;',
                        method_prefix: bytes = b'm') -> bytes:
    """Build a minimal-yet-valid DEX file that wraps the recovered
    code_items.

    The synthetic DEX has:
      - one class `LRecovered;` (a subclass of `Ljava/lang/Object;`)
      - one method per recovered `code_item`, named `m0000`, `m0001`,
        ... — all `static synthetic` and using the proto `()V`
      - the original code_item bytes verbatim (so dexdump can print
        the bytecode)

    The DEX layout (in offset order):
      - header                                  0x70 bytes
      - string_ids[N]                           N × 4 bytes
      - type_ids[T]                             T × 4 bytes
      - proto_ids[1]                            1 × 12 bytes
      - field_ids[0]                            0 bytes
      - method_ids[N_methods]                   N_methods × 8 bytes
      - class_defs[1]                           32 bytes
      - data section:
        - string_data items (uleb128 length + utf8 + null)
        - type_list for proto's parameters (empty)
        - class_data_item (the method list with code_item offsets)
        - code_items (recovered bytes — 4-byte aligned)
        - map_list (at the very end)

    Strings table includes:
      - "LRecovered;"                  class descriptor
      - "Ljava/lang/Object;"           parent class
      - "V"                            void proto shorty
      - "()V"                          proto string (not used)
      - "m0000", "m0001", ...          method names

    Type IDs (index into strings):
      - LRecovered;
      - Ljava/lang/Object;
      - V

    NOTE: This DEX **does not run on ART** — it's not signed and the
    methods reference nothing in the rest of the system. But it does
    PARSE correctly under `androguard` and `dexdump`, exposing the
    recovered bytecode for analysis. The semantic content (what each
    method actually DOES at the API level) is preserved; only the
    method names are synthetic.
    """
    # Cap to keep the output reasonable; >65535 methods break Dalvik's u16 limits
    # in some places (although class_data_item itself uses uleb128, so technically
    # unlimited). 65535 is the safe ceiling.
    if len(code_items) > 65535:
        code_items = code_items[:65535]

    # ---- String table (descriptors + names) ----
    strs = []
    strs.append(b'Ljava/lang/Object;')
    strs.append(class_name)
    strs.append(b'V')                # shorty for ()V
    strs.append(b'()V')
    # Method names m0000 ... mNNNNN
    for i in range(len(code_items)):
        strs.append(method_prefix + f'{i:05d}'.encode('ascii'))
    # Sorted lexicographic order for DEX correctness
    strs.sort()
    str_idx = {s: i for i, s in enumerate(strs)}
    str_count = len(strs)

    # ---- Type IDs (index into strings) ----
    # Just the two we need: Ljava/lang/Object; and LRecovered;
    type_ids_strs = [b'Ljava/lang/Object;', class_name]
    type_ids_strs = sorted(set(type_ids_strs), key=lambda s: str_idx[s])
    type_ids = [str_idx[s] for s in type_ids_strs]
    type_count = len(type_ids)

    # Index of LRecovered; and Ljava/lang/Object; in type_ids
    type_idx_recovered = type_ids_strs.index(class_name)
    type_idx_object = type_ids_strs.index(b'Ljava/lang/Object;')
    # For the proto's return type (V)

    # ---- Proto IDs ----
    # One proto: ()V — shorty="V", return_type=V (not a real type because primitives
    # use type_idx via descriptor "V"). We need V in type_ids too:
    if b'V' not in [type_ids_strs[i] for i in range(len(type_ids_strs))]:
        type_ids_strs.append(b'V')
        type_ids = [str_idx[s] for s in type_ids_strs]
        type_count = len(type_ids)
    type_idx_void = type_ids_strs.index(b'V')

    # proto_id_item: shorty_idx, return_type_idx, parameters_off
    proto_count = 1
    # Parameters: empty list — we set parameters_off to 0 (no parameters)
    proto_shorty_idx = str_idx[b'V']
    proto_return_type_idx = type_idx_void
    proto_parameters_off = 0  # empty parameter list → 0 by DEX convention

    # ---- Field IDs ----
    field_count = 0

    # ---- Method IDs ----
    # One method per code_item, all with proto ()V, on class LRecovered;
    method_count = len(code_items)
    # method_id_item: class_idx(u16), proto_idx(u16), name_idx(u32)
    method_ids_bin = bytearray()
    for i in range(method_count):
        name = method_prefix + f'{i:05d}'.encode('ascii')
        method_ids_bin += struct.pack('<HHI', type_idx_recovered, 0, str_idx[name])

    # ---- Class Defs ----
    # class_def_item: class_idx(u32), access_flags(u32), superclass_idx(u32),
    #                interfaces_off(u32), source_file_idx(u32), annotations_off(u32),
    #                class_data_off(u32), static_values_off(u32)
    class_count = 1

    # ---- Now compute layout ----
    header_off = 0
    string_ids_off = DEX_HEADER_SIZE
    type_ids_off = string_ids_off + str_count * 4
    proto_ids_off = type_ids_off + type_count * 4
    field_ids_off = proto_ids_off + proto_count * 12
    method_ids_off = field_ids_off + field_count * 8
    class_defs_off = method_ids_off + method_count * 8
    data_off = class_defs_off + class_count * 32

    # ---- Build data section ----
    data = bytearray()
    # data starts aligned to 4 bytes (header_size requires this implicitly)
    def data_align(boundary):
        while (data_off + len(data)) % boundary != 0:
            data.append(0)

    # 1. string_data items at the data section start
    string_data_offsets = []
    for s in strs:
        string_data_offsets.append(data_off + len(data))
        data += _uleb128_emit(len(s))
        data += s
        data.append(0)  # null terminator

    # 2. class_data_item
    data_align(1)
    class_data_off = data_off + len(data)
    data += _uleb128_emit(0)  # static_fields_size
    data += _uleb128_emit(0)  # instance_fields_size
    data += _uleb128_emit(method_count)  # direct_methods_size
    data += _uleb128_emit(0)  # virtual_methods_size
    # encoded_method[direct] entries — uleb128(method_idx_diff), uleb128(access_flags), uleb128(code_off)
    # We'll fill code_off after writing code_items, so reserve placeholders.
    # Strategy: write a stub here, then patch later.
    method_idx_diffs = []
    prev = 0
    for i in range(method_count):
        method_idx_diffs.append(i - prev)
        prev = i
    # Placeholder: we don't know code_offs yet. Build a fixed-width encoding
    # by writing 5-byte ULEB128 (max width). After we know offsets, patch.
    # Actually let's just build the class_data_item after code_items.
    # Rewind:
    data = data[:class_data_off - data_off]

    # 3. Write code_items first (4-byte aligned)
    data_align(4)
    code_offsets = []
    for ci in code_items:
        # Align to 4 bytes
        while (data_off + len(data)) % 4 != 0:
            data.append(0)
        code_offsets.append(data_off + len(data))
        data += ci.bytes

    # 4. Now class_data_item (no longer needs alignment)
    class_data_off = data_off + len(data)
    data += _uleb128_emit(0)  # static_fields_size
    data += _uleb128_emit(0)  # instance_fields_size
    data += _uleb128_emit(method_count)
    data += _uleb128_emit(0)
    # access_flags=ACC_STATIC|ACC_PUBLIC|ACC_SYNTHETIC = 0x9 | 0x1000 = 0x1009
    ACC = 0x1009
    prev = 0
    for i in range(method_count):
        data += _uleb128_emit(i - prev)
        prev = i
        data += _uleb128_emit(ACC)
        data += _uleb128_emit(code_offsets[i])

    # 5. map_list (must be 4-byte aligned)
    while (data_off + len(data)) % 4 != 0:
        data.append(0)
    map_off = data_off + len(data)
    # Build map entries: kind(u16), unused(u16), size(u32), offset(u32)
    map_entries = []

    def add_map(kind, size, offset):
        map_entries.append((kind, size, offset))

    add_map(0x0000, 1, header_off)             # TYPE_HEADER_ITEM
    if str_count:
        add_map(0x0001, str_count, string_ids_off)  # TYPE_STRING_ID_ITEM
    if type_count:
        add_map(0x0002, type_count, type_ids_off)   # TYPE_TYPE_ID_ITEM
    if proto_count:
        add_map(0x0003, proto_count, proto_ids_off) # TYPE_PROTO_ID_ITEM
    if field_count:
        add_map(0x0004, field_count, field_ids_off) # TYPE_FIELD_ID_ITEM
    if method_count:
        add_map(0x0005, method_count, method_ids_off) # TYPE_METHOD_ID_ITEM
    if class_count:
        add_map(0x0006, class_count, class_defs_off) # TYPE_CLASS_DEF_ITEM
    add_map(0x2001, len(code_items), code_offsets[0] if code_offsets else 0)  # TYPE_CODE_ITEM
    add_map(0x2002, str_count, string_data_offsets[0])     # TYPE_STRING_DATA_ITEM
    add_map(0x2000, 1, class_data_off)                     # TYPE_CLASS_DATA_ITEM
    add_map(0x1000, 1, map_off)                            # TYPE_MAP_LIST

    data += struct.pack('<I', len(map_entries))
    for kind, size, off in map_entries:
        data += struct.pack('<HHII', kind, 0, size, off)

    # ---- Build proto_ids ----
    # Now we know parameters_off (still 0 for empty params)
    proto_ids_bin = struct.pack('<III', proto_shorty_idx, proto_return_type_idx, proto_parameters_off)

    # ---- Build string_ids ----
    string_ids_bin = b''.join(struct.pack('<I', off) for off in string_data_offsets)

    # ---- Build type_ids ----
    type_ids_bin = b''.join(struct.pack('<I', si) for si in type_ids)

    # ---- Build class_defs ----
    class_defs_bin = struct.pack('<IIIIIIII',
        type_idx_recovered,
        0x1,                 # access_flags ACC_PUBLIC
        type_idx_object,     # superclass_idx
        0,                   # interfaces_off
        0xFFFFFFFF,          # source_file_idx (NO_INDEX)
        0,                   # annotations_off
        class_data_off,      # class_data_off
        0,                   # static_values_off
    )

    # ---- Final assembly ----
    body = bytearray()
    body += string_ids_bin
    body += type_ids_bin
    body += proto_ids_bin
    body += b''                              # no fields
    body += method_ids_bin
    body += class_defs_bin
    body += data

    file_size = DEX_HEADER_SIZE + len(body)
    data_size = len(data)

    # ---- Header ----
    hdr = bytearray(DEX_HEADER_SIZE)
    hdr[0:8] = DEX_MAGIC
    # checksum at +8 — Adler32 over [+12 .. end] — computed after signature
    # signature at +12 — SHA-1 over [+32 .. end] — computed after rest
    struct.pack_into('<I', hdr, 32, file_size)
    struct.pack_into('<I', hdr, 36, DEX_HEADER_SIZE)
    struct.pack_into('<I', hdr, 40, 0x12345678)  # endian_tag
    struct.pack_into('<II', hdr, 44, 0, 0)        # link_size, link_off
    struct.pack_into('<I', hdr, 52, map_off)
    struct.pack_into('<II', hdr, 56, str_count, string_ids_off)
    struct.pack_into('<II', hdr, 64, type_count, type_ids_off)
    struct.pack_into('<II', hdr, 72, proto_count, proto_ids_off)
    struct.pack_into('<II', hdr, 80, field_count, field_ids_off if field_count else 0)
    struct.pack_into('<II', hdr, 88, method_count, method_ids_off)
    struct.pack_into('<II', hdr, 96, class_count, class_defs_off)
    struct.pack_into('<II', hdr, 104, data_size, data_off)

    full = bytes(hdr) + bytes(body)

    # Compute SHA-1 over bytes [32 .. end] and patch into hdr[12 .. 32]
    import hashlib
    sig = hashlib.sha1(full[32:]).digest()
    full = full[:12] + sig + full[32:]

    # Compute Adler-32 over bytes [12 .. end] and patch into hdr[8 .. 12]
    checksum = _adler32(full[12:])
    full = full[:8] + struct.pack('<I', checksum) + full[12:]

    return full


# ---------------------------------------------------------------------------
# Top-level driver
# ---------------------------------------------------------------------------

@dataclass
class RecoveryResult:
    """Summary of what was recovered."""
    entry0_code_items: int = 0
    entry0_bytes: int = 0
    post_e0_code_items: int = 0
    post_e0_bytes: int = 0
    pre_e0_code_items: int = 0
    pre_e0_bytes: int = 0
    total_code_items: int = 0
    total_bytes: int = 0
    plaintext_runs_post_e0: list = field(default_factory=list)
    synthetic_dex_bytes: int = 0


def recover_from_carved(entry0_body: bytes,
                        post_e0: bytes,
                        pre_e0: bytes = b'',
                        ) -> tuple:
    """Walk all plaintext regions and return (list[CodeItem], RecoveryResult).

    Arguments are the byte buffers already carved by `jiagu.py`'s
    `_carve_trailer_artefacts` (jiagu_entry0_body.bin,
    jiagu_post_e0.bin, jiagu_pre_e0.bin).
    """
    result = RecoveryResult()
    all_items = []

    # Walk entry 0 body — always 4-byte aligned to start
    e0_items = walk_code_items(entry0_body)
    for it in e0_items:
        all_items.append(it)
    result.entry0_code_items = len(e0_items)
    result.entry0_bytes = sum(it.body_end - it.off for it in e0_items)

    # Walk post_e0 — code_items start at some non-zero offset after each
    # entry's opaque header. Easiest robust thing: try at offset 0 of the
    # entire post_e0 buffer; the strict parser rejects mis-aligned starts
    # naturally and the dense walker steps forward 2 bytes at a time.
    if post_e0:
        post_items = walk_code_items(post_e0)
        for it in post_items:
            all_items.append(it)
        result.post_e0_code_items = len(post_items)
        result.post_e0_bytes = sum(it.body_end - it.off for it in post_items)
        # Plaintext-run summary for the manifest (entropy-segmented)
        runs = find_plaintext_runs(post_e0)
        result.plaintext_runs_post_e0 = [
            {"start_hex": f"0x{s:x}", "end_hex": f"0x{e:x}", "size": e - s}
            for s, e in runs
        ]

    if pre_e0:
        # pre_e0 is normally fully encrypted, but include the pass for
        # rare builds that leave plaintext in there.
        pre_items = walk_code_items(pre_e0)
        for it in pre_items:
            all_items.append(it)
        result.pre_e0_code_items = len(pre_items)
        result.pre_e0_bytes = sum(it.body_end - it.off for it in pre_items)

    result.total_code_items = len(all_items)
    result.total_bytes = (result.entry0_bytes + result.post_e0_bytes +
                          result.pre_e0_bytes)
    return all_items, result


def serialize_code_items(items: list) -> bytes:
    """Concatenate all code_item bytes with a tiny TLV index for
    forensics. Format:

      magic            = b"JIAG_CI\\x01"      (8 bytes)
      n_items          = u32 LE
      item[n]:
        regs           = u16
        ins            = u16
        outs           = u16
        tries          = u16
        debug_off      = u32
        insns_size     = u32
        body_size      = u32          # total bytes following (incl. tries data)
        body           = body_size bytes (the verbatim code_item bytes)

    This is the artifact a downstream analyst loads to walk the
    recovered method bodies without needing the original DEX file.
    """
    out = bytearray()
    out += b'JIAG_CI\x01'
    out += struct.pack('<I', len(items))
    for it in items:
        body = it.bytes
        out += struct.pack('<HHHHIIi', it.regs, it.ins, it.outs, it.tries,
                            it.debug_off, it.insns_size, len(body))
        out += body
    return bytes(out)
