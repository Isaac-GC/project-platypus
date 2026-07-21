"""Jiagu custom-PRGA RC4 cipher and inner-SO decryption pipeline.

This module replicates Jiagu's RC4 variant statically, without needing
Unicorn or runtime emulation.

CIPHER CHARACTERIZATION
-----------------------

The Jiagu loader (libjiagu_a64.so for the 1.4.0.x cohort) uses a CUSTOM
variant of RC4 for the inner-SO decryption step. Reverse-engineered from
the loader at vaddr 0xdcd4 (KSA) and 0xddfc (PRGA) on 2026-05-19:

  - **KSA**: standard RC4 KSA with identity initial S-box. Iterates 256
    times: `j = (j + S[i] + key[i % key_len]) & 0xff` then `swap(S[i], S[j])`.
  - **PRGA — CUSTOM**: differs from textbook RC4 in three ways:
      1. Initial state is `(i=3, j=5)` NOT `(0, 0)`. (Stored at
         S[256..257] = `0x05 0x03`).
      2. `i` increments by **2** per byte (not 1).
      3. `j = (j + S[i] + 1) & 0xff` (i.e., +1 added per step).
      4. Output keystream byte = `S[(S[i] + S[j]) & 0xff]` (standard).

The hardcoded 10-byte key for the inner-SO decryption is at vaddr
0x4ecb1 in the dominant 1.4.0.4 build:

    key = bytes([0x76, 0x56, 0x57, 0x34, 0x23, 0x91, 0x23, 0x53, 0x56, 0x74])
        = b'vVW4#\\x91#SVt'

This key is preceded in the .rodata strings by the C++ class name
"10DynCryptor" — the cipher class that owns this key (alongside
EhdrCryptor, PhdrCryptor, EmptyCryptor).

INNER-SO DECRYPTION PIPELINE
----------------------------

The encrypted inner-SO payload is at vaddr 0x70250 of libjiagu_a64.so
(file offset 0x60250 for the dominant build, 780,753 bytes). The
decryption pipeline:

  1. RC4-decrypt the 780,753-byte payload IN-PLACE with the hardcoded
     key (custom-PRGA variant above). The result is a length-prefixed
     zlib stream:
        bytes[0..3]   = u32 LE: inflated length (= 1,776,361 for the
                                 dominant build)
        bytes[4..end] = zlib (deflate) stream
  2. zlib.decompress the stream. Output is the inner-SO body
     (1,776,361 bytes), in a CUSTOM container format that the loader's
     mapper at vaddr 0xc794 / 0xd068 parses.

The inner SO contains the actual DEX-decryption code. The DEX cipher
(and per-build key derivation) live in the inner SO and are NOT
recovered by this module — they remain the residual gate for static
inner-DEX recovery on this cohort.

USAGE
-----

    from packer_backends.jiagu_rc4 import (
        jiagu_rc4_ksa, jiagu_rc4_prga, jiagu_rc4_decrypt,
        decrypt_inner_so, INNER_SO_KEY,
    )

    # Generic decrypt with the hardcoded key
    plaintext = jiagu_rc4_decrypt(ciphertext)

    # Full inner-SO pipeline: extract + decrypt + inflate
    inner_so_bytes = decrypt_inner_so(libjiagu_a64_so_bytes)

VERIFICATION
------------

The cipher has been verified against the Unicorn-captured RC4 output
on:

  - cn.huangshimy.bantang.zip (1.4.0.4 build, dominant cohort)
  - /workspace/working/jiagu_dive/dominant/libjiagu_a64.so

Both produce byte-identical 780,753-byte RC4 output and 1,776,361-byte
inflated payloads.
"""
from __future__ import annotations

from typing import Optional
import struct
import zlib


# 10-byte hardcoded RC4 key for the inner-SO decryption step.
# Found in .rodata at vaddr 0x4ecb1 of libjiagu_a64.so (dominant
# 1.4.0.x cohort). Preceded by the "10DynCryptor" C++ class name.
INNER_SO_KEY = bytes([0x76, 0x56, 0x57, 0x34, 0x23, 0x91, 0x23, 0x53,
                      0x56, 0x74])


def jiagu_rc4_ksa(key: bytes, key_len: Optional[int] = None) -> list:
    """Standard RC4 KSA with identity initial S-box.

    Args:
        key: Key bytes.
        key_len: Optional explicit key length (default: len(key)).
    """
    if key_len is None:
        key_len = len(key)
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % key_len]) & 0xff
        S[i], S[j] = S[j], S[i]
    return S


def jiagu_rc4_prga(S: list, data: bytes) -> bytes:
    """Custom-PRGA RC4 variant matching Jiagu's loader behaviour:
      - initial (i, j) = (3, 5)
      - i += 2 per byte
      - j = (j + S[i] + 1) & 0xff

    Args:
        S: Initial 256-byte S-box (output of jiagu_rc4_ksa).
        data: Bytes to encrypt or decrypt (symmetric).
    """
    S = S.copy()
    i = 3
    j = 5
    out = bytearray(len(data))
    for k in range(len(data)):
        i = (i + 2) & 0xff
        j = (j + S[i] + 1) & 0xff
        S[i], S[j] = S[j], S[i]
        out[k] = data[k] ^ S[(S[i] + S[j]) & 0xff]
    return bytes(out)


def jiagu_rc4_decrypt(data: bytes, key: bytes = INNER_SO_KEY) -> bytes:
    """One-shot RC4 decrypt with the Jiagu custom-PRGA variant.

    Args:
        data: Ciphertext.
        key: Key bytes (default: the hardcoded inner-SO key).
    """
    S = jiagu_rc4_ksa(key)
    return jiagu_rc4_prga(S, data)


# Default inner-SO payload location for the dominant 1.4.0.x cohort.
# These are vaddrs into libjiagu_a64.so; the helper translates to file
# offsets via the program-header parse.
INNER_SO_PAYLOAD_VADDR = 0x70250
INNER_SO_PAYLOAD_SIZE = 780753


def _va_to_off(so_bytes: bytes, va: int) -> Optional[int]:
    """Translate a vaddr to a file offset using PT_LOAD segments."""
    if so_bytes[:4] != b"\x7fELF":
        return None
    e_phoff = struct.unpack_from("<Q", so_bytes, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", so_bytes, 0x36)[0]
    e_phnum = struct.unpack_from("<H", so_bytes, 0x38)[0]
    for i in range(e_phnum):
        p = so_bytes[e_phoff + i * e_phentsize :
                     e_phoff + (i + 1) * e_phentsize]
        p_type, _, p_off, p_vaddr, _, p_filesz, _, _ = struct.unpack(
            "<IIQQQQQQ", p
        )
        if p_type == 1 and p_vaddr <= va < p_vaddr + p_filesz:
            return p_off + (va - p_vaddr)
    return None


def decrypt_inner_so(so_bytes: bytes,
                     payload_vaddr: int = INNER_SO_PAYLOAD_VADDR,
                     payload_size: Optional[int] = None,
                     key: bytes = INNER_SO_KEY) -> bytes:
    """Run the full inner-SO decryption pipeline.

    1. Extract the encrypted payload from the outer libjiagu_a64.so
       at the given vaddr (default: 0x70250 — the 1.4.0.x cohort).
    2. RC4-decrypt with the custom-PRGA variant + hardcoded key.
    3. zlib-inflate the (length-prefixed) stream.

    Args:
        so_bytes: The outer libjiagu_a64.so file bytes.
        payload_vaddr: vaddr of the encrypted payload (default 0x70250).
        payload_size: number of bytes to RC4-decrypt (default: all
                      remaining bytes in the SO segment from payload_vaddr).
        key: RC4 key (default: hardcoded INNER_SO_KEY).

    Returns:
        The inflated inner-SO body bytes (typically ≈ 1.78 MB).

    Raises:
        ValueError: if the payload vaddr is not mapped, the RC4 output
        doesn't look like a length-prefixed zlib stream, or zlib
        decompression fails.
    """
    off = _va_to_off(so_bytes, payload_vaddr)
    if off is None:
        raise ValueError(
            f"vaddr {payload_vaddr:#x} not in any PT_LOAD segment"
        )
    # Determine effective payload size — clamp to what's actually in
    # the file. zlib will stop reading at its own end marker, so any
    # excess RC4-decrypted bytes are harmless.
    available = len(so_bytes) - off
    if payload_size is None:
        size = min(available, 1_500_000)  # 1.5 MB cap
    else:
        size = min(payload_size, available)
    if size < 256:
        raise ValueError(f"payload region too small ({size} bytes)")

    ciphertext = so_bytes[off : off + size]
    plaintext = jiagu_rc4_decrypt(ciphertext, key)

    # Length-prefixed zlib stream: u32 LE length, then deflate bytes
    if len(plaintext) < 4:
        raise ValueError("RC4 output shorter than 4 bytes")
    inflated_len = struct.unpack_from("<I", plaintext, 0)[0]
    if inflated_len < 0x100 or inflated_len > 0x40_000_000:
        raise ValueError(
            f"implausible inflated length {inflated_len}"
        )
    if plaintext[4:6] not in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
        raise ValueError(
            f"no zlib header at offset 4 (got {plaintext[4:6].hex()})"
        )
    try:
        inflated = zlib.decompress(plaintext[4:])
    except zlib.error as e:
        raise ValueError(f"zlib decompression failed: {e}") from e
    if len(inflated) != inflated_len:
        raise ValueError(
            f"inflated length mismatch: expected {inflated_len}, "
            f"got {len(inflated)}"
        )
    return inflated


# ---------------------------------------------------------------------------
# Per-build inner-SO payload discovery
# ---------------------------------------------------------------------------
#
# The default payload vaddr 0x70250 is for the 1.4.0.4 dominant cohort.
# Other 1.4.0.x builds may use slightly different vaddrs; the helper
# below scans for the largest contiguous high-entropy region in PT_LOAD#2
# (the data segment) and validates that RC4-then-inflate produces a
# valid output.
# ---------------------------------------------------------------------------


def find_inner_so_payload(so_bytes: bytes,
                          key: bytes = INNER_SO_KEY,
                          candidate_offsets: Optional[list] = None
                          ) -> Optional[tuple]:
    """Discover the inner-SO payload location in a libjiagu_a64.so.

    Tries the default location first, then walks PT_LOAD segments
    looking for a region that RC4-decrypts to a length-prefixed zlib
    stream.

    Returns:
        (payload_vaddr, payload_size_used, inflated_bytes) on success,
        or None if no valid payload is found.
    """
    candidates = candidate_offsets or []
    candidates.insert(0, INNER_SO_PAYLOAD_VADDR)
    for va in candidates:
        try:
            inflated = decrypt_inner_so(so_bytes, va, None, key)
            return (va, None, inflated)
        except ValueError:
            continue
    # Scan all PT_LOAD segments for any 4-byte aligned offset that
    # decrypts to a length-prefixed zlib stream. Fast: only checks the
    # first 8 RC4 bytes per candidate.
    if so_bytes[:4] != b"\x7fELF":
        return None
    e_phoff = struct.unpack_from("<Q", so_bytes, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", so_bytes, 0x36)[0]
    e_phnum = struct.unpack_from("<H", so_bytes, 0x38)[0]
    for i in range(e_phnum):
        p = so_bytes[e_phoff + i * e_phentsize :
                     e_phoff + (i + 1) * e_phentsize]
        p_type, p_flags, p_off, p_vaddr, _, p_filesz, _, _ = struct.unpack(
            "<IIQQQQQQ", p
        )
        if p_type != 1:
            continue
        # Walk vaddrs in this segment in 4-byte steps; check the first
        # 8 RC4-decrypted bytes per candidate (cheap).
        for off in range(0, max(0, p_filesz - 64), 4):
            head = jiagu_rc4_decrypt(
                so_bytes[p_off + off : p_off + off + 8], key
            )
            if head[4:6] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
                length = struct.unpack_from("<I", head, 0)[0]
                if 0x1000 < length < 0x10_000_000:
                    va = p_vaddr + off
                    try:
                        inflated = decrypt_inner_so(so_bytes, va, None, key)
                        return (va, None, inflated)
                    except Exception:
                        continue
    return None


__all__ = [
    "INNER_SO_KEY",
    "INNER_SO_PAYLOAD_VADDR",
    "INNER_SO_PAYLOAD_SIZE",
    "jiagu_rc4_ksa",
    "jiagu_rc4_prga",
    "jiagu_rc4_decrypt",
    "decrypt_inner_so",
    "find_inner_so_payload",
]
