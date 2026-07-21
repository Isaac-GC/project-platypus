"""Static cipher analysis for Jiagu's `libjiagu*.so` loader.

This module identifies and applies the static ciphers used by Jiagu's
ARM64 loader (`libjiagu_a64.so`), without executing any code from the
SO. It complements the Unicorn-based emulator pass (which captures
runtime decryption outputs) by working entirely on the SO's bytes.

Identified ciphers (across the 16 distinct SHA-256s in this corpus):

  1. **Modified RC4 PRGA** at function start ~0xddfc (varies per build).
     Variant of standard RC4: `i += 2` (not 1), `j += S[i] + 1`. Used to
     decrypt one large buffer per JNI_OnLoad invocation (in our v1.4.0.4
     bantang sample: a 775,469-byte zlib-stream-bearing blob, of which
     the zlib stream itself decompresses to 1.78 MB of loader working
     data — strings, classes/methods Jiagu's stub uses, an embedded
     stub DEX).

  2. **Single-byte XOR (key in first byte of input)** in the function at
     ~0xd614. Format: `[key:1][len:u32 LE][data:len]`. Used many times
     for small chunk decryption.

  3. **Single-byte XOR with constant key 0xa5** for a static data
     section inside the SO itself (at varying offsets per-build, but
     always identifiable by a known plaintext anchor). This section
     contains the loader's package-name whitelist + anti-debug
     constants — useful for forensics.

The actual inner-DEX cipher (entries 1..n-1 of the qh trailer's data
section) is NOT recoverable statically — it's derived at runtime from
the APK signing certificate + package name + per-build constants
embedded in the SO. See `by-packer/jiagu.md` for the documented
limitation.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ---- ELF parsing (minimal AArch64 ELF support) ------------------------------

def _parse_phdrs(d: bytes) -> List[Tuple[int, int, int, int, int, int]]:
    if d[:4] != b"\x7fELF" or d[4] != 2:
        return []
    e_phoff = struct.unpack_from("<Q", d, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", d, 0x36)[0]
    e_phnum = struct.unpack_from("<H", d, 0x38)[0]
    out = []
    for i in range(e_phnum):
        ph = d[e_phoff + i*e_phentsize : e_phoff + (i+1)*e_phentsize]
        if len(ph) < 0x38:
            break
        rec = struct.unpack_from("<IIQQQQQQ", ph)
        out.append(rec)
    return out

def _off_to_va(phs, off):
    for p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align in phs:
        if p_type == 1 and p_offset <= off < p_offset + p_filesz:
            return p_vaddr + (off - p_offset)
    return None


# ---- AArch64 instruction decoders (just enough for signature scan) ----------

def _decode_add_imm32(ins):
    """ADD (immediate, 32-bit). Returns (Rd, Rn, imm12) or None."""
    if (ins >> 24) != 0b00010001: return None
    if ((ins >> 22) & 1) != 0: return None           # shift = 0 only
    return ((ins & 0x1f), (ins >> 5) & 0x1f, (ins >> 10) & 0xfff)

def _decode_strb_imm(ins):
    """STRB (immediate, unsigned offset). Returns (Rt, Rn, imm12) or None."""
    if (ins >> 22) != 0b0011100100: return None
    return ((ins & 0x1f), (ins >> 5) & 0x1f, (ins >> 10) & 0xfff)


# ---- Cipher fingerprinting --------------------------------------------------

@dataclass
class Rc4Prga:
    """Located instance of the modified-RC4 PRGA inside the SO.

    Attributes
    ----------
    prologue_va : int
        Virtual address of the function's `sub sp, sp, #imm` prologue.
    prga_inner_va : int
        Virtual address of the `add wX, wX, #2` PRGA-invariant instruction.
    loop_end_va : int
        Virtual address right after the loop's backward branch (i.e.,
        the first instruction executed once the PRGA loop completes).
    ret_vas : list
        Virtual addresses of `ret` instructions in the function body
        (1-2 typically — the canary-success path and canary-fail path).
    """
    prologue_va: int
    prga_inner_va: int
    loop_end_va: Optional[int]
    ret_vas: List[int] = field(default_factory=list)


def find_rc4_prga(so_bytes: bytes) -> List[Rc4Prga]:
    """Locate every Jiagu-style modified-RC4 PRGA in the given SO bytes.

    The PRGA's smoking gun is two adjacent instructions:

        add wX, wX, #2          (increment i by 2 — NOT 1, the RC4 mod)
        strb wX, [xN, #0x100]   (store i back to state[0x100])

    where Rd_of_add == Rt_of_strb == Rn_of_add (the i variable).

    Returns
    -------
    list[Rc4Prga]
    """
    d = so_bytes
    phs = _parse_phdrs(d)
    out: List[Rc4Prga] = []
    for off in range(0, len(d) - 8, 4):
        ins1 = struct.unpack_from("<I", d, off)[0]
        ins2 = struct.unpack_from("<I", d, off + 4)[0]
        a = _decode_add_imm32(ins1)
        s = _decode_strb_imm(ins2)
        if not a or not s:
            continue
        Rd_a, Rn_a, imm_a = a
        Rt_s, Rn_s, imm_s = s
        if not (imm_a == 2 and imm_s == 0x100 and Rd_a == Rt_s and Rd_a == Rn_a):
            continue
        # walk back for `sub sp, sp, #imm`
        prologue_off = None
        for back in range(4, 0x400, 4):
            if off - back < 0:
                break
            ins = struct.unpack_from("<I", d, off - back)[0]
            if (ins >> 22) == 0b1101000100 and (ins & 0x1f) == 31 and ((ins >> 5) & 0x1f) == 31:
                prologue_off = off - back
                break
        # find loop_end: scan forward for a backward branch within 512 bytes
        loop_end_off = None
        for o in range(off, off + 0x200, 4):
            if o + 4 > len(d):
                break
            ins = struct.unpack_from("<I", d, o)[0]
            # B.cond (0101 0100 imm19 0 cond)
            if (ins >> 24) == 0x54:
                imm19 = (ins >> 5) & 0x7ffff
                if imm19 & (1 << 18):
                    imm19 -= (1 << 19)
                target = o + imm19 * 4
                if target <= off:
                    loop_end_off = o + 4
                    break
            # CBZ/CBNZ (sf=1 or sf=0): top byte 0xB4..0xB5 or 0x34..0x35
            opc = ins >> 24
            if opc in (0xb4, 0xb5, 0x34, 0x35):
                imm19 = (ins >> 5) & 0x7ffff
                if imm19 & (1 << 18):
                    imm19 -= (1 << 19)
                target = o + imm19 * 4
                if target <= off:
                    loop_end_off = o + 4
                    break
        # find RET(s) inside the function body
        ret_vas: List[int] = []
        if loop_end_off:
            for o in range(loop_end_off, loop_end_off + 0x200, 4):
                if o + 4 > len(d):
                    break
                ins = struct.unpack_from("<I", d, o)[0]
                if ins == 0xd65f03c0:          # `ret`
                    ret_vas.append(_off_to_va(phs, o))
                    if len(ret_vas) >= 2:
                        break
        out.append(Rc4Prga(
            prologue_va=_off_to_va(phs, prologue_off) if prologue_off else 0,
            prga_inner_va=_off_to_va(phs, off),
            loop_end_va=_off_to_va(phs, loop_end_off) if loop_end_off else None,
            ret_vas=ret_vas,
        ))
    return out


# ---- SIMD-XOR (single-byte XOR with per-input key) function finder ---------

@dataclass
class SimdXor:
    """Located instance of the SIMD-XOR cipher function.

    The function takes (x0 = output struct, x1 = input struct) and reads
    `*(x1 + 0x10)` as a byte stream of format `[key:1][len:u32 LE][data:len]`.
    It mallocs a buffer, memcpys `data` into it, and SIMD-XORs each byte
    with `key`. At `simd_exit_va`, x21 = output buffer and x20 = length.
    """
    prologue_va: int
    simd_exit_va: int           # first insn after the scalar tail loop


def find_simd_xor(so_bytes: bytes) -> List[SimdXor]:
    """Locate Jiagu's SIMD single-byte XOR routine in the SO.

    The distinguishing pattern is the SIMD loop:
        ldp q1, q2, [x9, #-0x10]    -> 0xad7f8921
        subs xN, xN, #0x20           -> a `subs` immediate against 0x20
        eor v1.16b, v1.16b, v0.16b   -> 0x6e201c21
        eor v2.16b, v2.16b, v0.16b   -> 0x6e201c42
        stp q1, q2, [x9, #-0x10]    -> 0xad3f8921
    The scalar tail is:
        ldrb wN, [xN]
        subs xN, xN, #1
        eor wN, wN, w26 (XOR with key)
        strb wN, [xN], #1
        b.ne loop_top
    Followed by the function exit.

    Returns a list (usually 1) of SimdXor descriptors.
    """
    d = so_bytes
    phs = _parse_phdrs(d)
    out: List[SimdXor] = []
    # Anchor signature: `eor v1.16b, v1.16b, v0.16b` immediately followed by
    # `eor v2.16b, v2.16b, v0.16b`. Distinctive enough — these two are rarely
    # adjacent outside of a vectorised XOR loop.
    SIG = bytes.fromhex("211c206e421c206e")    # eor v1,v1,v0 ; eor v2,v2,v0
    for m in re.finditer(re.escape(SIG), d):
        off = m.start()
        # Walk backward for the function prologue.
        prologue_off = None
        for back in range(4, 0x400, 4):
            if off - back < 0:
                break
            ins = struct.unpack_from("<I", d, off - back)[0]
            if (ins >> 22) == 0b1101000100 and (ins & 0x1f) == 31 and ((ins >> 5) & 0x1f) == 31:
                prologue_off = off - back
                break
        # Walk forward for the scalar-tail loop's backward branch, then the
        # function-exit's first non-loop instruction.
        # Pattern: ... b.ne loop_top ; FALL_THROUGH ; ...
        # The fallthrough is our exit hook point.
        exit_off = None
        for o in range(off, off + 0x100, 4):
            if o + 4 > len(d):
                break
            ins = struct.unpack_from("<I", d, o)[0]
            # B.cond
            if (ins >> 24) == 0x54:
                imm19 = (ins >> 5) & 0x7ffff
                if imm19 & (1 << 18):
                    imm19 -= (1 << 19)
                target = o + imm19 * 4
                if target < o and target >= off - 0x100:    # backward branch within scalar tail
                    # Note: we want the scalar-tail's exit, not the SIMD loop's
                    # exit. The scalar tail comes AFTER the SIMD loop; look for
                    # a second backward branch.
                    pass
        # Simpler: just walk forward and find the FIRST instruction past two
        # backward branches (SIMD loop's b.ne + scalar tail's b.ne).
        branch_count = 0
        for o in range(off, off + 0x200, 4):
            if o + 4 > len(d):
                break
            ins = struct.unpack_from("<I", d, o)[0]
            if (ins >> 24) == 0x54:
                imm19 = (ins >> 5) & 0x7ffff
                if imm19 & (1 << 18):
                    imm19 -= (1 << 19)
                target = o + imm19 * 4
                if target < o:
                    branch_count += 1
                    if branch_count == 2:
                        exit_off = o + 4
                        break
        if exit_off is None:
            continue
        out.append(SimdXor(
            prologue_va=_off_to_va(phs, prologue_off) if prologue_off else 0,
            simd_exit_va=_off_to_va(phs, exit_off),
        ))
    # Deduplicate by prologue
    seen = set()
    unique = []
    for s in out:
        if s.prologue_va not in seen:
            seen.add(s.prologue_va)
            unique.append(s)
    return unique


# ---- XOR-0xa5 data section extractor ---------------------------------------

# Known plaintext anchors that appear in every libjiagu_a64.so we've seen.
# Recovering one such substring after XOR-0xa5 gives us the byte offset of
# the data section, from which we can walk to its bounds (the section
# begins at the first nonzero byte after a long zero run, and ends where
# entropy transitions back to non-XOR-encoded territory).
_XOR_A5_ANCHORS = [
    b"com.qihoo.permmgr",
    b"com.qihoo.apps",
    b"Lcom/qihoo/util/",
    b"qihoo",
    b"InMemoryDexClassLoader",
]

@dataclass
class XorA5Region:
    start_off: int
    decoded_strings: List[bytes]   # ASCII runs of >= 6 chars in the decoded data
    n_anchor_matches: int          # how many of the known anchors fired

def find_xor_a5_region(so_bytes: bytes) -> Optional[XorA5Region]:
    """Locate the XOR-0xa5-encoded data section inside libjiagu*.so.

    Returns None if no anchor strings are found (e.g., the SO uses a
    different obfuscation key for this region — observed in older
    1.3.9.x builds, see by-packer/jiagu.md).
    """
    d = so_bytes
    matches = []
    for anchor in _XOR_A5_ANCHORS:
        enc = bytes(b ^ 0xa5 for b in anchor)
        for m in re.finditer(re.escape(enc), d):
            matches.append((m.start(), anchor))
    if not matches:
        return None
    earliest = min(p for p, _ in matches)

    # Find the data-section start (a couple kilobytes before the earliest match,
    # walk back to a long run of zero bytes).
    start = max(0, earliest - 0x8000)
    # Find last zero-run of >= 16 zero bytes before earliest
    zero_run_end = None
    for o in range(earliest, start, -16):
        if all(b == 0 for b in d[o:o+16]):
            zero_run_end = o + 16
            break
    if zero_run_end is None:
        zero_run_end = max(0, earliest - 0x100)

    # Decode and extract ASCII strings
    region_end = min(len(d), earliest + 0x40000)
    decoded = bytes(b ^ 0xa5 for b in d[zero_run_end:region_end])
    runs = re.findall(rb"[\x20-\x7e]{6,}", decoded)
    return XorA5Region(
        start_off=zero_run_end,
        decoded_strings=runs,
        n_anchor_matches=len(matches),
    )


# ---- Public summary entry point --------------------------------------------

@dataclass
class JiaguStaticCipherSummary:
    rc4_prgas: List[Rc4Prga]
    simd_xors: List[SimdXor]
    xor_a5: Optional[XorA5Region]

def summarise(so_bytes: bytes) -> JiaguStaticCipherSummary:
    """Static-only cipher analysis of a libjiagu*.so payload."""
    return JiaguStaticCipherSummary(
        rc4_prgas=find_rc4_prga(so_bytes),
        simd_xors=find_simd_xor(so_bytes),
        xor_a5=find_xor_a5_region(so_bytes),
    )
