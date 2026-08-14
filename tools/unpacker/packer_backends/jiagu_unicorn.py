"""Unicorn-based AArch64 emulator for libjiagu*.so.

WHY THIS EXISTS
---------------

Jiagu's outer SO (typically `libjiagu_a64.so`) implements its JNI
boundary via a **bytecode interpreter** rather than direct C++. Static
disassembly of the SO reveals:

    JNI_OnLoad @ 0x10d74:
        x0 = &program        # encoded VM bytecode at vaddr 0x4f2dc
        w1 = program_size    # 0xbac bytes (124 'instructions')
        x2 = &runtime_ctx    # vaddr 0x70140
        x3 = JavaVM*
        x4 = reserved
        bl interpreter_wrap_int64_t   # @ 0x46f30 → calls dispatcher @ 0x452f4

The program at 0x4f2dc is the encoded JNI_OnLoad logic — including
RegisterNatives, the per-method-decryption dispatch, the JNI-callable
asset loader, and ultimately the bulk DEX decryption.

Pure-static recovery of the DEX bytes is therefore bounded by what the
VM bytecode + its runtime ctx imply. Without executing the bytecode,
we can recover:

  - the outer stub DEX (verbatim, from the APK)
  - the `qh\x00\x01` trailer metadata
  - entry-0's plaintext code_items tail (where present)
  - the carved raw encrypted regions (data section, entry table)

What we CANNOT recover statically:

  - the per-build cipher key for entries 1..n-1
  - the nibble-obfuscation undecoding for v2 entry-0 prefixes
  - the original DEX strings/types/classes tables

THIS MODULE BRIDGES THAT GAP USING UNICORN. It is a pure-Python
emulator harness, no Frida / no device / no ART. It:

  1. Maps the SO's PT_LOAD segments into a fresh Unicorn AArch64 VM.
  2. Resolves all dynamic relocations (RELA + JMPREL + RELATIVE).
     a. Locally-defined symbols (libc++, libunwind, internal aliases
        such as `interpreter_wrap_int64_t`, `__arm_a_20`) are pointed
        at their in-SO definitions.
     b. External libc imports are stubbed by a Python-side dispatcher
        that emulates the syscall (open/read/mmap/malloc/etc.) over a
        synthetic in-memory file system seeded with the APK's assets.
  3. Runs each DT_INIT_ARRAY entry under instruction-trace.
  4. Calls JNI_OnLoad with a synthetic JavaVM*. A mocked JNIEnv table
     intercepts `RegisterNatives`, `FindClass`, `GetStringUTFChars`,
     `CallStaticObjectMethod` (the AssetManager.open hook), etc., to
     capture the decrypted DEX bytes when the loader writes them.
  5. Returns the captured DEX payload(s) plus a structured trace.

DESIGN NOTES
------------

- AArch64 only. The 32-bit `libjiagu.so` is not handled; samples that
  ship both load `_a64` on arm64 devices and the 32-bit variant is
  used by 32-bit-only devices that the operator's corpus doesn't
  target.
- The harness is intentionally **scoped to libjiagu_a64.so**. The
  variant loaders (`libjg<tag>.so`) are the same code with renamed
  exports — handled by the same emulator.
- No actual file system I/O: all libc syscalls are intercepted. The
  emulator's "open" returns synthetic FDs that map onto the APK
  entries the backend pre-extracted.
- The harness is **best-effort**: many Jiagu builds will exit the VM
  prematurely (anti-debug ptrace probes, /proc-walks that fail, JNI
  callbacks that try to recurse into the ART runtime). The harness
  catches each `UcError` and returns whatever it captured so far. The
  caller (jiagu.py) annotates the manifest with the emulator outcome.
- Compatible with the static-only mission scope: no code from the
  sample's libraries ever runs on the host CPU — only inside Unicorn,
  with stubbed syscalls.

PUBLIC API
----------

    emulate_libjiagu(so_path, asset_paths=None, *, max_instructions=...,
                     verbose=False) -> EmulationResult

Returns a dataclass with the captured DEX payloads, the trace of
intercepted syscalls / JNI calls, and a status enum.
"""

from __future__ import annotations

import collections
import io
import struct
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


# ---- Optional dependency ---------------------------------------------------
# Importing unicorn at module level keeps the import surface obvious; if it
# is missing we surface that to the caller rather than fail at function-call
# time inside the backend.
try:
    from unicorn import (
        Uc,
        UC_ARCH_ARM64, UC_MODE_ARM, UC_MODE_LITTLE_ENDIAN,
        UC_PROT_READ, UC_PROT_WRITE, UC_PROT_EXEC,
        UC_HOOK_CODE, UC_HOOK_MEM_INVALID,
        UC_HOOK_MEM_READ_UNMAPPED, UC_HOOK_MEM_WRITE_UNMAPPED,
        UC_HOOK_MEM_FETCH_UNMAPPED, UC_HOOK_INTR,
        UC_HOOK_MEM_WRITE,
        UcError,
    )
    from unicorn.arm64_const import (
        UC_ARM64_REG_X0, UC_ARM64_REG_X1, UC_ARM64_REG_X2, UC_ARM64_REG_X3,
        UC_ARM64_REG_X4, UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7,
        UC_ARM64_REG_X8, UC_ARM64_REG_X16, UC_ARM64_REG_X17, UC_ARM64_REG_X18,
        UC_ARM64_REG_X19, UC_ARM64_REG_X20, UC_ARM64_REG_X21, UC_ARM64_REG_X22,
        UC_ARM64_REG_X23, UC_ARM64_REG_X28, UC_ARM64_REG_X29, UC_ARM64_REG_X30,
        UC_ARM64_REG_SP, UC_ARM64_REG_PC,
        UC_ARM64_REG_TPIDR_EL0,
    )
    HAS_UNICORN = True
except ImportError as e:                                       # pragma: no cover
    HAS_UNICORN = False
    _IMPORT_ERROR = e


# ---- Memory layout ---------------------------------------------------------

# We pick fixed addresses well outside the SO's own load range. The SO's
# PT_LOAD segments are typically at vaddr 0..0x310000; we keep them at their
# linked addresses (Unicorn maps them as PROT_READ|WRITE|EXEC) and reserve
# the following ranges for emulator-managed memory.

EMU_LOAD_BASE      = 0x0000_0000              # SO mapped here (its vaddrs are unchanged)
EMU_STACK_BASE     = 0x0000_2000_0000_0000    # 0x20_0000_0000_0000 (high address)
EMU_STACK_SIZE     = 0x4_0000                 # 256 KB
EMU_HEAP_BASE      = 0x0000_4000_0000_0000    # bump allocator
EMU_HEAP_SIZE      = 0x1000_0000              # 256 MB — phase 2 ("ART
                                              # callback replication") calls
                                              # __arm_a_1, which re-does the
                                              # SIMD-XOR over 30 MB AGAIN on
                                              # the second-stage loader path.
                                              # The 40 MB cap was exhausted
                                              # half-way through phase 1; we
                                              # need headroom for the 2nd
                                              # 30 MB working buffer plus the
                                              # inner-DEX heap allocations
                                              # the inner SO will make.
EMU_TLS_BASE       = 0x0000_6000_0000_0000    # 8 KB thread-local storage block
EMU_TLS_SIZE       = 0x2000
EMU_FAKE_FS_BASE   = 0x0000_8000_0000_0000    # synthetic file-system memory pool
EMU_FAKE_FS_SIZE   = 0x40_0000                # 4 MB — mmaps' destination
                                              # (Jiagu doesn't mmap large files
                                              # via libc, all comes via JNI)
EMU_JNI_BASE       = 0x0000_a000_0000_0000    # JNIEnv/JavaVM mock tables
EMU_JNI_SIZE       = 0x10_0000                # 1 MB

# Stubs / trampolines for libc and JNI functions are arranged in a private
# region we map as RWX. Each stub is a unique 4-byte BRK instruction whose
# immediate identifies which function the emulator should service.
EMU_STUB_BASE      = 0x0000_c000_0000_0000
EMU_STUB_SIZE      = 0x4_0000                 # 256 KB (enough for ~16k stubs)
# BRK encoding: 1101_0100_001_imm16_00000
def _brk(imm16: int) -> bytes:
    return struct.pack("<I", 0xd4200000 | ((imm16 & 0xffff) << 5))


# ---- Result type -----------------------------------------------------------

@dataclass
class EmulationResult:
    """What the Unicorn run captured.

    `status` values:
      "ok"              — emulation completed normally; one or more DEX
                          payloads captured.
      "no_dex"          — emulation completed but no DEX bytes were
                          captured (the VM exited via anti-debug or
                          before reaching the decrypt path).
      "uc_error"        — Unicorn raised an error; partial trace.
      "unicorn_missing" — the unicorn package is not installed.
      "invalid_so"      — the SO is not a recognised AArch64 Jiagu loader.
    """

    status: str
    dex_payloads: List[bytes] = field(default_factory=list)
    decrypted_buffers: List[Tuple[int, int, bytes]] = field(default_factory=list)
    rc4_captures: List[Tuple[int, int, bytes]] = field(default_factory=list)
    xor_captures: List[Tuple[int, int, bytes]] = field(default_factory=list)
    syscall_trace: List[str] = field(default_factory=list)
    jni_trace: List[str] = field(default_factory=list)
    insns_executed: int = 0
    elapsed_sec: float = 0.0
    error: str = ""
    # Phase 2 / ART callback observations
    registered_natives: Dict[str, List[Tuple[str, str, int]]] = field(
        default_factory=dict
    )
    art_callbacks_invoked: bool = False
    # When mock_inner_so=True, the inner-SO loader (0xc8fc) is bypassed
    # and __arm_a_1 proceeds to call the custom dlsym (0xca38). Each
    # name passed to that dlsym is the inner SO's expected export — the
    # public interface Jiagu's inner SO must implement. This list is
    # high-value: a recovered inner SO can be validated by checking that
    # these symbols are exported.
    inner_so_required_symbols: List[str] = field(default_factory=list)
    inner_jni_onload_invoked: bool = False


# ---- SO parsing (independent of pyelftools to keep this self-contained) ----

def _parse_so_layout(data: bytes) -> Optional[Dict]:
    """Return PT_LOAD segments, dynamic table, init_array, sym/str tables.

    Returns None if the file is not a recognisable AArch64 ELF.
    """
    if len(data) < 0x40 or data[:4] != b"\x7fELF":
        return None
    if data[4] != 2 or data[5] != 1:                # 64-bit, little-endian
        return None
    e_machine = struct.unpack_from("<H", data, 0x12)[0]
    if e_machine != 0xb7:                            # EM_AARCH64
        return None
    e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
    e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
    e_phnum = struct.unpack_from("<H", data, 0x38)[0]
    e_entry = struct.unpack_from("<Q", data, 0x18)[0]

    segments = []
    dynamic_off = dynamic_size = 0
    for i in range(e_phnum):
        p = data[e_phoff + i*e_phentsize : e_phoff + (i+1)*e_phentsize]
        p_type, p_flags, p_offset, p_vaddr, _, p_filesz, p_memsz, _ = struct.unpack("<IIQQQQQQ", p)
        if p_type == 1:                              # PT_LOAD
            segments.append({
                "off": p_offset, "vaddr": p_vaddr,
                "filesz": p_filesz, "memsz": p_memsz, "flags": p_flags,
            })
        elif p_type == 2:                            # PT_DYNAMIC
            dynamic_off = p_offset
            dynamic_size = p_filesz

    # Parse DT_* tags from PT_DYNAMIC
    dyn = {}
    for i in range(0, dynamic_size, 16):
        d_tag, d_val = struct.unpack_from("<qQ", data, dynamic_off + i)
        if d_tag == 0:
            break
        dyn[d_tag] = d_val

    DT_HASH       = 4
    DT_STRTAB     = 5
    DT_SYMTAB     = 6
    DT_RELA       = 7
    DT_RELASZ     = 8
    DT_RELAENT    = 9
    DT_STRSZ      = 10
    DT_SYMENT     = 11
    DT_INIT_ARRAY = 25
    DT_INIT_ARRAYSZ = 27
    DT_PLTRELSZ   = 2
    DT_JMPREL     = 23
    DT_PLTREL     = 20

    init_array_va = dyn.get(DT_INIT_ARRAY, 0)
    init_array_sz = dyn.get(DT_INIT_ARRAYSZ, 0)
    rela_va       = dyn.get(DT_RELA, 0)
    rela_sz       = dyn.get(DT_RELASZ, 0)
    jmprel_va     = dyn.get(DT_JMPREL, 0)
    pltrelsz      = dyn.get(DT_PLTRELSZ, 0)
    symtab_va     = dyn.get(DT_SYMTAB, 0)
    strtab_va     = dyn.get(DT_STRTAB, 0)
    hash_va       = dyn.get(DT_HASH, 0)

    # Compute strtab size and symtab count from DT_HASH (nchain == number of syms).
    nbucket = nchain = 0
    if hash_va:
        # vaddr→fileoff translation (PT_LOAD 0 is usually identity, but be safe)
        ho = _va_to_off(segments, hash_va)
        if ho is not None:
            nbucket, nchain = struct.unpack_from("<II", data, ho)

    # Strtab spans from STRTAB to next dynamic-table reference (heuristic);
    # use the gap to SYMTAB if symtab follows strtab, otherwise DT_STRSZ.
    strsz = dyn.get(DT_STRSZ, 0)
    if not strsz:
        # fallback: assume strtab ends where the next loadable thing begins
        # (this is a heuristic; the SO usually has DT_STRSZ but the obfuscator
        # sometimes strips it).
        strsz = (rela_va or jmprel_va or 0) - strtab_va

    return {
        "e_entry": e_entry,
        "segments": segments,
        "dynamic": dyn,
        "init_array_va": init_array_va,
        "init_array_sz": init_array_sz,
        "rela_va": rela_va,
        "rela_sz": rela_sz,
        "jmprel_va": jmprel_va,
        "pltrelsz": pltrelsz,
        "symtab_va": symtab_va,
        "strtab_va": strtab_va,
        "strsz": strsz,
        "nchain": nchain,
    }


def _va_to_off(segments, va: int) -> Optional[int]:
    """Translate a virtual address (within the SO) to a file offset."""
    for s in segments:
        if s["vaddr"] <= va < s["vaddr"] + s["filesz"]:
            return s["off"] + (va - s["vaddr"])
    return None


# ---- The harness -----------------------------------------------------------

class _Emulator:
    """Internal Unicorn harness — see `emulate_libjiagu` for the public API."""

    # Stub function IDs (BRK imm16). We hand out IDs sequentially so each
    # libc/JNI entry has a unique BRK trampoline. The dispatch table maps
    # ID → (name, handler).
    def __init__(self, so_bytes: bytes, layout: Dict, verbose: bool):
        self.so = so_bytes
        self.layout = layout
        self.verbose = verbose
        self.heap_ptr = EMU_HEAP_BASE
        self.next_fake_fs = EMU_FAKE_FS_BASE
        self.next_stub_id = 1
        self.stub_table: Dict[int, Tuple[str, callable]] = {}
        self.stub_addr_by_name: Dict[str, int] = {}
        self.syscall_trace: List[str] = []
        self.jni_trace: List[str] = []
        self.dex_payloads: List[bytes] = []
        self.decrypted_buffers: List[Tuple[int, int, bytes]] = []
        self.insns_executed = 0
        self.uc: Optional["Uc"] = None
        self.errors: List[str] = []
        self.exited_cleanly = False
        # Per-build hooks set by emulate_libjiagu's caller — keyed by
        # vaddr, executed when the SO's PC enters that instruction.
        # `target_hook_lo`/`hi` bound the hot-path range to avoid a
        # dict-get on every instruction.
        self.target_hooks: Dict[int, callable] = {}
        self.target_hook_lo = 1 << 62
        self.target_hook_hi = 0
        # Captured decrypt outputs (buf_va, size, contents) from the
        # per-entry XOR cipher at 0xd614.
        self.xor_decrypt_captures: List[Tuple[int, int, bytes]] = []
        # File descriptor table (for synthetic open/read).
        self.fds: Dict[int, Tuple[str, bytes, int]] = {}    # fd → (name, data, pos)
        self.next_fd = 3                                    # 0/1/2 reserved
        # Asset filesystem: name → bytes (set externally via set_asset_fs).
        self.asset_fs: Dict[str, bytes] = {}

    # -- public knobs --------------------------------------------------------
    def set_asset_fs(self, fs: Dict[str, bytes]) -> None:
        """Register the synthetic file-system contents (asset name → bytes)."""
        self.asset_fs = dict(fs)

    # -- stub allocation -----------------------------------------------------
    def _alloc_stub(self, name: str, handler) -> int:
        """Allocate a BRK trampoline for `name`; return its address."""
        sid = self.next_stub_id
        self.next_stub_id += 1
        addr = EMU_STUB_BASE + sid * 4
        self.stub_table[sid] = (name, handler)
        self.stub_addr_by_name[name] = addr
        # Write the BRK instruction into the stub memory.
        self.uc.mem_write(addr, _brk(sid))
        return addr

    # -- heap allocation -----------------------------------------------------
    def _alloc_heap(self, size: int, align: int = 16) -> int:
        if align > 1 and (self.heap_ptr % align):
            self.heap_ptr += align - (self.heap_ptr % align)
        addr = self.heap_ptr
        self.heap_ptr += max(size, 1)
        return addr

    # -- syscall handlers ----------------------------------------------------
    # Each handler takes (self, uc) and returns the int64 to put in X0.
    # On return the harness writes X0 ← handler() and resumes after BRK.

    def _r(self, reg):
        return self.uc.reg_read(reg)

    def _w(self, reg, val):
        self.uc.reg_write(reg, val & 0xffffffffffffffff)

    def _read_cstr(self, addr: int, maxlen: int = 256) -> str:
        if not addr:
            return ""
        out = bytearray()
        for i in range(maxlen):
            try:
                b = bytes(self.uc.mem_read(addr + i, 1))[0]
            except UcError:
                break
            if b == 0:
                break
            out.append(b)
        return out.decode("latin-1", errors="replace")

    # libc stubs (minimal set; expand as needed) -----------------------------

    # Hard cap on a single allocation we'll honour. Calls above this
    # are treated as failure (NULL return). Without this cap a bogus
    # `n*sz` from a mocked return value can OOM the Python harness
    # before unicorn can even map the requested heap range.
    MAX_ALLOC = 0x2_000_000           # 32 MB

    def _stub_malloc(self):
        size = self._r(UC_ARM64_REG_X0)
        if size > self.MAX_ALLOC:
            if len(self.syscall_trace) < 5000:
                self.syscall_trace.append(f"malloc({size}) → 0 (over MAX_ALLOC cap)")
            return 0
        addr = self._alloc_heap(size)
        if size:
            try:
                self.uc.mem_write(addr, b"\x00" * size)
            except UcError as e:
                self.errors.append(f"malloc mem_write failed @ {hex(addr)} sz={size}: {e}")
                return 0
        if len(self.syscall_trace) < 5000:
            self.syscall_trace.append(f"malloc({size}) → {hex(addr)}")
        return addr

    def _stub_calloc(self):
        n = self._r(UC_ARM64_REG_X0)
        sz = self._r(UC_ARM64_REG_X1)
        total = n * sz
        if total > self.MAX_ALLOC:
            if len(self.syscall_trace) < 5000:
                self.syscall_trace.append(f"calloc({n}, {sz}) → 0 (over MAX_ALLOC cap)")
            return 0
        addr = self._alloc_heap(total)
        if total:
            try:
                self.uc.mem_write(addr, b"\x00" * total)
            except UcError as e:
                self.errors.append(f"calloc mem_write failed @ {hex(addr)} sz={total}: {e}")
                return 0
        if len(self.syscall_trace) < 5000:
            self.syscall_trace.append(f"calloc({n}, {sz}) → {hex(addr)}")
        return addr

    def _stub_free(self):
        self.syscall_trace.append(f"free({hex(self._r(UC_ARM64_REG_X0))})")
        return 0

    def _stub_realloc(self):
        ptr = self._r(UC_ARM64_REG_X0)
        sz = self._r(UC_ARM64_REG_X1)
        new_ptr = self._alloc_heap(sz)
        if ptr and sz:
            try:
                old = bytes(self.uc.mem_read(ptr, sz))
            except UcError:
                old = b""
            self.uc.mem_write(new_ptr, old.ljust(sz, b"\x00"))
        else:
            self.uc.mem_write(new_ptr, b"\x00" * sz)
        self.syscall_trace.append(f"realloc({hex(ptr)}, {sz}) → {hex(new_ptr)}")
        return new_ptr

    def _stub_memcpy(self):
        dst = self._r(UC_ARM64_REG_X0)
        src = self._r(UC_ARM64_REG_X1)
        n = self._r(UC_ARM64_REG_X2)
        if n > self.MAX_ALLOC:
            self.errors.append(f"memcpy(n={n}) capped — too large")
            return dst
        if n > 0:
            try:
                buf = bytes(self.uc.mem_read(src, n))
                self.uc.mem_write(dst, buf)
            except UcError as e:
                self.errors.append(f"memcpy({hex(dst)}, {hex(src)}, {n}) failed: {e}")
        return dst

    def _stub_memset(self):
        dst = self._r(UC_ARM64_REG_X0)
        c = self._r(UC_ARM64_REG_X1) & 0xff
        n = self._r(UC_ARM64_REG_X2)
        if n > self.MAX_ALLOC:
            self.errors.append(f"memset(n={n}) capped — too large")
            return dst
        if n > 0:
            try:
                self.uc.mem_write(dst, bytes([c]) * n)
            except UcError as e:
                self.errors.append(f"memset({hex(dst)}, {c}, {n}) failed: {e}")
        return dst

    def _stub_memmove(self):
        return self._stub_memcpy()                  # semantically fine for our use

    def _stub_memcmp(self):
        a = self._r(UC_ARM64_REG_X0)
        b = self._r(UC_ARM64_REG_X1)
        n = self._r(UC_ARM64_REG_X2)
        try:
            ba = bytes(self.uc.mem_read(a, n))
            bb = bytes(self.uc.mem_read(b, n))
        except UcError:
            return 0
        return 0 if ba == bb else (1 if ba > bb else -1) & 0xffffffffffffffff

    def _stub_strlen(self):
        return len(self._read_cstr(self._r(UC_ARM64_REG_X0), 0x10000))

    def _stub_strcmp(self):
        a = self._read_cstr(self._r(UC_ARM64_REG_X0))
        b = self._read_cstr(self._r(UC_ARM64_REG_X1))
        return (0 if a == b else (1 if a > b else -1)) & 0xffffffffffffffff

    def _stub_strncmp(self):
        n = self._r(UC_ARM64_REG_X2)
        a = self._read_cstr(self._r(UC_ARM64_REG_X0), n)
        b = self._read_cstr(self._r(UC_ARM64_REG_X1), n)
        return (0 if a == b else (1 if a > b else -1)) & 0xffffffffffffffff

    def _stub_strcpy(self):
        dst = self._r(UC_ARM64_REG_X0)
        s = self._read_cstr(self._r(UC_ARM64_REG_X1))
        self.uc.mem_write(dst, s.encode("latin-1") + b"\x00")
        return dst

    def _stub_strchr(self):
        s = self._read_cstr(self._r(UC_ARM64_REG_X0))
        c = chr(self._r(UC_ARM64_REG_X1) & 0xff)
        idx = s.find(c)
        if idx < 0:
            return 0
        return self._r(UC_ARM64_REG_X0) + idx

    def _stub_open(self):
        path = self._read_cstr(self._r(UC_ARM64_REG_X0))
        data = self.asset_fs.get(path)
        if data is None:
            # Try basename match
            for k, v in self.asset_fs.items():
                if k.endswith(path) or path.endswith(k):
                    data = v
                    break
        if data is None:
            self.syscall_trace.append(f"open({path!r}) → ENOENT")
            return 0xffffffffffffffff
        fd = self.next_fd; self.next_fd += 1
        self.fds[fd] = (path, data, 0)
        self.syscall_trace.append(f"open({path!r}) → fd={fd} (size={len(data)})")
        return fd

    def _stub_read(self):
        fd = self._r(UC_ARM64_REG_X0)
        buf = self._r(UC_ARM64_REG_X1)
        n = self._r(UC_ARM64_REG_X2)
        if fd not in self.fds:
            return 0xffffffffffffffff
        name, data, pos = self.fds[fd]
        chunk = data[pos:pos + n]
        self.uc.mem_write(buf, chunk)
        self.fds[fd] = (name, data, pos + len(chunk))
        return len(chunk)

    def _stub_close(self):
        fd = self._r(UC_ARM64_REG_X0)
        self.fds.pop(fd, None)
        return 0

    def _stub_lseek(self):
        fd = self._r(UC_ARM64_REG_X0)
        offset = self._r(UC_ARM64_REG_X1)
        whence = self._r(UC_ARM64_REG_X2) & 0xff
        if fd not in self.fds:
            return 0xffffffffffffffff
        name, data, pos = self.fds[fd]
        if whence == 0:    # SEEK_SET
            new = offset
        elif whence == 1:  # SEEK_CUR
            new = pos + offset
        else:              # SEEK_END
            new = len(data) + offset
        new = max(0, min(new, len(data)))
        self.fds[fd] = (name, data, new)
        return new

    def _stub_mmap(self):
        # mmap(addr, length, prot, flags, fd, offset)
        length = self._r(UC_ARM64_REG_X1)
        fd = self._r(UC_ARM64_REG_X4)
        offset = self._r(UC_ARM64_REG_X5)
        # Round up to page
        length = (length + 0xfff) & ~0xfff
        addr = self.next_fake_fs
        self.next_fake_fs += length
        # Zero-fill, then if fd is a real file, populate from data
        self.uc.mem_write(addr, b"\x00" * length)
        if fd in self.fds:
            name, data, _pos = self.fds[fd]
            chunk = data[offset:offset + length]
            self.uc.mem_write(addr, chunk + b"\x00" * (length - len(chunk)))
            self.syscall_trace.append(f"mmap(..len={length}, fd={fd}/{name}) → {hex(addr)}")
        else:
            self.syscall_trace.append(f"mmap(.. len={length}, anon) → {hex(addr)}")
        return addr

    def _stub_munmap(self):
        return 0

    def _stub_getpagesize(self):
        return 0x1000

    def _stub_getpid(self):
        return 12345

    def _stub_getuid(self):
        return 1000

    def _stub_gettid(self):
        return 12345

    def _stub_errno_loc(self):
        # __errno() returns a pointer to a per-thread int — give it a heap cell.
        if not hasattr(self, "_errno_loc"):
            self._errno_loc = self._alloc_heap(8, align=8)
            self.uc.mem_write(self._errno_loc, b"\x00" * 8)
        return self._errno_loc

    def _stub_exit(self):
        self.exited_cleanly = True
        self.syscall_trace.append(f"exit({self._r(UC_ARM64_REG_X0)})")
        self.uc.emu_stop()
        return 0

    def _stub_abort(self):
        self.exited_cleanly = False
        self.syscall_trace.append("abort()")
        self.errors.append("guest abort()")
        self.uc.emu_stop()
        return 0

    def _stub_stack_chk_fail(self):
        return self._stub_abort()

    def _stub_assert2(self):
        return self._stub_abort()

    def _stub_signal(self):                          return 0
    def _stub_sigaction(self):                       return 0
    def _stub_sigemptyset(self):                     return 0
    def _stub_sigfillset(self):                      return 0
    def _stub_sigaltstack(self):                     return 0
    def _stub_pthread_create(self):                  return 0
    def _stub_pthread_detach(self):                  return 0
    def _stub_pthread_once(self):                    return 0
    def _stub_pthread_mutex_init(self):              return 0
    def _stub_pthread_mutex_lock(self):              return 0
    def _stub_pthread_mutex_unlock(self):            return 0
    def _stub_pthread_mutex_destroy(self):           return 0
    def _stub_pthread_rwlock_init(self):             return 0
    def _stub_pthread_rwlock_rdlock(self):           return 0
    def _stub_pthread_rwlock_wrlock(self):           return 0
    def _stub_pthread_rwlock_unlock(self):           return 0
    def _stub_pthread_key_create(self):              return 0
    def _stub_pthread_key_delete(self):              return 0
    def _stub_pthread_getspecific(self):             return 0
    def _stub_pthread_setspecific(self):             return 0
    def _stub_prctl(self):                           return 0
    def _stub_kill(self):                            return 0
    def _stub_socket(self):                          return 0xffffffffffffffff
    def _stub_connect(self):                         return 0xffffffffffffffff
    def _stub_recv(self):                            return 0xffffffffffffffff
    def _stub_send(self):                            return 0xffffffffffffffff
    def _stub_select(self):                          return 0
    def _stub_gethostbyname(self):                   return 0
    def _stub_dlopen(self):                          return 0x10                  # nonzero handle
    def _stub_dlclose(self):                         return 0
    def _stub_dlsym(self):                           return 0                     # no sym found
    def _stub_dladdr(self):                          return 0
    def _stub_dlerror(self):                         return 0
    def _stub_access(self):                          return 0xffffffffffffffff    # ENOENT
    def _stub_stat_family(self):                     return 0xffffffffffffffff
    def _stub_log_print(self):
        path = self._read_cstr(self._r(UC_ARM64_REG_X1))
        msg = self._read_cstr(self._r(UC_ARM64_REG_X2), 0x800)
        self.syscall_trace.append(f"__android_log_print({path!r}, {msg!r})")
        return 0
    def _stub_atoi(self):
        s = self._read_cstr(self._r(UC_ARM64_REG_X0))
        try:
            return int(s.strip())
        except ValueError:
            return 0
    def _stub_strtol(self):
        s = self._read_cstr(self._r(UC_ARM64_REG_X0))
        try:
            return int(s.strip(), 0)
        except ValueError:
            return 0
    def _stub_strtoull(self):
        s = self._read_cstr(self._r(UC_ARM64_REG_X0))
        try:
            return int(s.strip(), 0)
        except ValueError:
            return 0
    def _stub_getenv(self):                          return 0
    def _stub_setenv(self):                          return 0
    def _stub_time(self):                            return 1700000000
    def _stub_difftime(self):                        return 0
    def _stub_localtime(self):                       return self._alloc_heap(0x40, align=8)
    def _stub_rand(self):                            return 0x12345678
    def _stub_srand(self):                           return 0
    def _stub_qsort(self):                           return 0
    # zlib stubs ------------------------------------------------------------
    # The DEX payload sometimes is zlib-compressed before encryption; we
    # provide pass-through inflate that copies input to output.
    def _stub_inflate(self):
        # int inflate(z_stream*, int flush) — z_stream layout (lib-relative):
        #   +0  next_in    (Bytef*)
        #   +8  avail_in   (uInt)
        #   +0x10 total_in (uLong)
        #   +0x18 next_out (Bytef*)
        #   +0x20 avail_out (uInt)
        #   +0x28 total_out (uLong)
        # We just do a memcpy of (avail_in or avail_out, whichever's smaller).
        z = self._r(UC_ARM64_REG_X0)
        try:
            ni  = struct.unpack("<Q", bytes(self.uc.mem_read(z + 0x00, 8)))[0]
            ai  = struct.unpack("<I", bytes(self.uc.mem_read(z + 0x08, 4)))[0]
            no  = struct.unpack("<Q", bytes(self.uc.mem_read(z + 0x18, 8)))[0]
            ao  = struct.unpack("<I", bytes(self.uc.mem_read(z + 0x20, 4)))[0]
        except UcError:
            return 0
        n = min(ai, ao)
        if n:
            buf = bytes(self.uc.mem_read(ni, n))
            self.uc.mem_write(no, buf)
        # advance pointers
        try:
            self.uc.mem_write(z + 0x00, struct.pack("<Q", ni + n))
            self.uc.mem_write(z + 0x08, struct.pack("<I", ai - n))
            self.uc.mem_write(z + 0x18, struct.pack("<Q", no + n))
            self.uc.mem_write(z + 0x20, struct.pack("<I", ao - n))
        except UcError:
            pass
        return 1                                    # Z_STREAM_END
    def _stub_inflateInit_(self):                    return 0
    def _stub_inflateInit2_(self):                   return 0
    def _stub_inflateEnd(self):                      return 0
    def _stub_deflate(self):                         return 0
    def _stub_deflateInit2_(self):                   return 0
    def _stub_deflateEnd(self):                      return 0
    def _stub_deflateBound(self):                    return self._r(UC_ARM64_REG_X1) * 2
    # printf / stream stubs -------------------------------------------------
    def _stub_snprintf(self):
        buf = self._r(UC_ARM64_REG_X0)
        size = self._r(UC_ARM64_REG_X1)
        fmt = self._read_cstr(self._r(UC_ARM64_REG_X2))
        # We do not interpret % directives. Write the fmt as-is, truncated.
        s = fmt.encode("latin-1")[:size - 1] + b"\x00"
        self.uc.mem_write(buf, s)
        return len(s) - 1
    def _stub_sprintf(self):
        buf = self._r(UC_ARM64_REG_X0)
        fmt = self._read_cstr(self._r(UC_ARM64_REG_X1))
        s = fmt.encode("latin-1") + b"\x00"
        self.uc.mem_write(buf, s)
        return len(s) - 1
    def _stub_puts(self):
        s = self._read_cstr(self._r(UC_ARM64_REG_X0))
        self.syscall_trace.append(f"puts({s!r})")
        return 0
    def _stub_fprintf(self):                         return 0
    def _stub_vsnprintf(self):                       return 0
    def _stub_fopen(self):                           return 0
    def _stub_fclose(self):                          return 0
    def _stub_fread(self):                           return 0
    def _stub_fseek(self):                           return 0
    def _stub_feof(self):                            return 1
    def _stub_fgets(self):                           return 0
    def _stub_write(self):                           return self._r(UC_ARM64_REG_X2)
    def _stub_chmod(self):                           return 0
    def _stub_mkdir(self):                           return 0
    def _stub_remove(self):                          return 0
    def _stub_opendir(self):                         return 0
    def _stub_readdir(self):                         return 0
    def _stub_closedir(self):                        return 0
    def _stub_fstat(self):                           return 0xffffffffffffffff
    def _stub_pread(self):
        # pread(fd, buf, count, offset)
        fd = self._r(UC_ARM64_REG_X0)
        buf = self._r(UC_ARM64_REG_X1)
        cnt = self._r(UC_ARM64_REG_X2)
        offset = self._r(UC_ARM64_REG_X3)
        if fd not in self.fds:
            return 0xffffffffffffffff
        name, data, pos = self.fds[fd]
        chunk = data[offset:offset + cnt]
        self.uc.mem_write(buf, chunk)
        return len(chunk)
    def _stub_read_chk(self):                        return self._stub_read()
    def _stub_strlen_chk(self):                      return self._stub_strlen()
    def _stub_snprintf_chk(self):                    return self._stub_snprintf()
    def _stub_sprintf_chk(self):                     return self._stub_sprintf()
    def _stub_fd_set_chk(self):                      return 0
    def _stub_strncpy_chk2(self):                    return self._stub_strcpy()
    def _stub_strcat(self):
        dst = self._r(UC_ARM64_REG_X0)
        cur = self._read_cstr(dst, 0x10000)
        add = self._read_cstr(self._r(UC_ARM64_REG_X1))
        self.uc.mem_write(dst, (cur + add).encode("latin-1") + b"\x00")
        return dst
    def _stub_strncpy(self):                         return self._stub_strcpy()
    def _stub_strdup(self):
        s = self._read_cstr(self._r(UC_ARM64_REG_X0))
        addr = self._alloc_heap(len(s) + 1)
        self.uc.mem_write(addr, s.encode("latin-1") + b"\x00")
        return addr
    def _stub_strstr(self):
        h = self._read_cstr(self._r(UC_ARM64_REG_X0))
        n = self._read_cstr(self._r(UC_ARM64_REG_X1))
        if not n:
            return self._r(UC_ARM64_REG_X0)
        i = h.find(n)
        if i < 0:
            return 0
        return self._r(UC_ARM64_REG_X0) + i
    def _stub_strrchr(self):
        s = self._read_cstr(self._r(UC_ARM64_REG_X0))
        c = chr(self._r(UC_ARM64_REG_X1) & 0xff)
        i = s.rfind(c)
        return self._r(UC_ARM64_REG_X0) + i if i >= 0 else 0
    def _stub_strtok(self):                          return 0
    def _stub_strcasecmp(self):                      return self._stub_strcmp()
    def _stub_isspace(self):                         return 1 if chr(self._r(UC_ARM64_REG_X0) & 0xff).isspace() else 0
    def _stub_isalpha(self):                         return 1 if chr(self._r(UC_ARM64_REG_X0) & 0xff).isalpha() else 0
    def _stub_tolower(self):                         return ord(chr(self._r(UC_ARM64_REG_X0) & 0xff).lower())
    def _stub_memchr(self):
        s = self._r(UC_ARM64_REG_X0)
        c = self._r(UC_ARM64_REG_X1) & 0xff
        n = self._r(UC_ARM64_REG_X2)
        try:
            buf = bytes(self.uc.mem_read(s, n))
        except UcError:
            return 0
        i = buf.find(bytes([c]))
        return s + i if i >= 0 else 0
    def _stub_fmod(self):                            return 0
    def _stub_fmodf(self):                           return 0
    def _stub_sysconf(self):                         return 0
    def _stub_fork(self):                            return -1 & 0xffffffffffffffff
    def _stub_wait(self):                            return 0
    def _stub_cxa_atexit(self):                      return 0
    def _stub_cxa_finalize(self):                    return 0
    def _stub_raise(self):                           return self._stub_abort()
    def _stub_mprotect(self):                        return 0
    def _stub_inotify_init(self):                    return 0xffffffffffffffff
    def _stub_inotify_add_watch(self):               return 0xffffffffffffffff
    def _stub_lseek64(self):                         return self._stub_lseek()
    def _stub_sscanf(self):                          return 0
    def _stub_fnmatch(self):                         return 1
    def _stub_stpcpy(self):
        return self._stub_strcpy() + self._stub_strlen()

    # -- stub table ----------------------------------------------------------
    LIBC_HANDLERS = {
        "malloc": "_stub_malloc",            "calloc": "_stub_calloc",
        "free":   "_stub_free",              "realloc": "_stub_realloc",
        "memcpy": "_stub_memcpy",            "memset": "_stub_memset",
        "memmove": "_stub_memmove",          "memcmp": "_stub_memcmp",
        "memchr": "_stub_memchr",            "strlen": "_stub_strlen",
        "__strlen_chk": "_stub_strlen_chk",
        "strcmp": "_stub_strcmp",            "strncmp": "_stub_strncmp",
        "strcasecmp": "_stub_strcasecmp",
        "strcpy": "_stub_strcpy",            "strncpy": "_stub_strncpy",
        "__strncpy_chk2": "_stub_strncpy_chk2",
        "stpcpy": "_stub_stpcpy",            "strcat": "_stub_strcat",
        "strchr": "_stub_strchr",            "strrchr": "_stub_strrchr",
        "strstr": "_stub_strstr",            "strtok": "_stub_strtok",
        "strdup": "_stub_strdup",
        "open":   "_stub_open",              "read": "_stub_read",
        "__read_chk": "_stub_read_chk",
        "close":  "_stub_close",             "lseek": "_stub_lseek",
        "lseek64": "_stub_lseek64",
        "pread":  "_stub_pread",
        "mmap":   "_stub_mmap",              "munmap": "_stub_munmap",
        "mprotect": "_stub_mprotect",
        "getpagesize": "_stub_getpagesize",  "getpid": "_stub_getpid",
        "getuid": "_stub_getuid",            "gettid": "_stub_gettid",
        "__errno": "_stub_errno_loc",
        "_exit":   "_stub_exit",             "abort":  "_stub_abort",
        "__stack_chk_fail": "_stub_stack_chk_fail",
        "__assert2": "_stub_assert2",
        "raise":   "_stub_raise",
        "signal":  "_stub_signal",           "sigaction": "_stub_sigaction",
        "sigemptyset": "_stub_sigemptyset",  "sigfillset": "_stub_sigfillset",
        "sigaltstack": "_stub_sigaltstack",
        "pthread_create": "_stub_pthread_create",
        "pthread_detach": "_stub_pthread_detach",
        "pthread_once":   "_stub_pthread_once",
        "pthread_mutex_init": "_stub_pthread_mutex_init",
        "pthread_mutex_lock": "_stub_pthread_mutex_lock",
        "pthread_mutex_unlock": "_stub_pthread_mutex_unlock",
        "pthread_mutex_destroy": "_stub_pthread_mutex_destroy",
        "pthread_rwlock_init": "_stub_pthread_rwlock_init",
        "pthread_rwlock_rdlock": "_stub_pthread_rwlock_rdlock",
        "pthread_rwlock_wrlock": "_stub_pthread_rwlock_wrlock",
        "pthread_rwlock_unlock": "_stub_pthread_rwlock_unlock",
        "pthread_key_create": "_stub_pthread_key_create",
        "pthread_key_delete": "_stub_pthread_key_delete",
        "pthread_getspecific": "_stub_pthread_getspecific",
        "pthread_setspecific": "_stub_pthread_setspecific",
        "prctl":  "_stub_prctl",             "kill": "_stub_kill",
        "socket": "_stub_socket",            "connect": "_stub_connect",
        "recv":   "_stub_recv",              "send":   "_stub_send",
        "select": "_stub_select",            "gethostbyname": "_stub_gethostbyname",
        "dlopen": "_stub_dlopen",            "dlclose": "_stub_dlclose",
        "dlsym":  "_stub_dlsym",             "dladdr": "_stub_dladdr",
        "dlerror": "_stub_dlerror",
        "access": "_stub_access",
        "fstat":  "_stub_fstat",
        "__android_log_print": "_stub_log_print",
        "atoi":   "_stub_atoi",              "strtol": "_stub_strtol",
        "strtoull": "_stub_strtoull",
        "getenv": "_stub_getenv",            "setenv": "_stub_setenv",
        "time":   "_stub_time",              "difftime": "_stub_difftime",
        "localtime": "_stub_localtime",
        "rand":   "_stub_rand",              "srand": "_stub_srand",
        "qsort":  "_stub_qsort",
        "inflate": "_stub_inflate",
        "inflateInit_": "_stub_inflateInit_",
        "inflateInit2_": "_stub_inflateInit2_",
        "inflateEnd": "_stub_inflateEnd",
        "deflate": "_stub_deflate",
        "deflateInit2_": "_stub_deflateInit2_",
        "deflateEnd": "_stub_deflateEnd",
        "deflateBound": "_stub_deflateBound",
        "snprintf": "_stub_snprintf",        "sprintf": "_stub_sprintf",
        "__snprintf_chk": "_stub_snprintf_chk",
        "__sprintf_chk":  "_stub_sprintf_chk",
        "puts":   "_stub_puts",
        "fprintf": "_stub_fprintf",          "vsnprintf": "_stub_vsnprintf",
        "fopen":  "_stub_fopen",             "fclose": "_stub_fclose",
        "fread":  "_stub_fread",             "fseek":  "_stub_fseek",
        "feof":   "_stub_feof",              "fgets":  "_stub_fgets",
        "write":  "_stub_write",             "chmod":  "_stub_chmod",
        "mkdir":  "_stub_mkdir",             "remove": "_stub_remove",
        "opendir": "_stub_opendir",          "readdir": "_stub_readdir",
        "closedir": "_stub_closedir",
        "isspace": "_stub_isspace",          "isalpha": "_stub_isalpha",
        "tolower": "_stub_tolower",
        "fmod":   "_stub_fmod",              "fmodf":  "_stub_fmodf",
        "sysconf": "_stub_sysconf",
        "fork":   "_stub_fork",              "wait":   "_stub_wait",
        "__cxa_atexit": "_stub_cxa_atexit",
        "__cxa_finalize": "_stub_cxa_finalize",
        "inotify_init": "_stub_inotify_init",
        "inotify_add_watch": "_stub_inotify_add_watch",
        "__FD_SET_chk": "_stub_fd_set_chk",
        "sscanf":  "_stub_sscanf",           "fnmatch": "_stub_fnmatch",
        # Catch-alls that just return 0
        "syscall": "_stub_signal",           "syscall.": "_stub_signal",
    }

    # -- bring-up sequence ---------------------------------------------------
    def boot(self) -> None:
        """Map the SO, set up emulator state, install stubs and relocations."""
        # 1) Map all PT_LOAD segments at their linked vaddrs.
        # Jiagu's obfuscator extends the writable segment past memsz (the
        # init code touches BSS slots beyond the linker's declared range).
        # We over-map each segment by 1 MB to absorb that.
        seg_ranges = []
        for s in self.layout["segments"]:
            base = s["vaddr"] & ~0xfff
            extra = 0x10_0000 if (s["flags"] & 2) else 0   # writable → extra pad
            end = (s["vaddr"] + s["memsz"] + extra + 0xfff) & ~0xfff
            seg_ranges.append((base, end))
        # Merge overlapping ranges so Unicorn doesn't complain.
        seg_ranges.sort()
        merged = []
        for b, e in seg_ranges:
            if merged and b <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], e))
            else:
                merged.append((b, e))
        for b, e in merged:
            self.uc.mem_map(b, e - b, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        for s in self.layout["segments"]:
            # Write the file contents
            self.uc.mem_write(s["vaddr"], self.so[s["off"]:s["off"] + s["filesz"]])
        # Map a generous scratch region past the SO. Some Jiagu builds
        # (especially the 1.3.9.x series) compute relative offsets that
        # extend BSS into vaddr ranges far beyond the linker-declared
        # memsz (these are usually mmap'd anonymously at runtime; we
        # pre-map them here so the loader doesn't trap).
        last_end = max(e for _, e in merged)
        scratch_start = (last_end + 0xfff) & ~0xfff
        scratch_size = 0x100_0000                     # 16 MB
        try:
            self.uc.mem_map(scratch_start, scratch_size,
                            UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        except UcError:
            pass

        # 2) Map ancillary regions.
        self.uc.mem_map(EMU_STACK_BASE,   EMU_STACK_SIZE,   UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(EMU_HEAP_BASE,    EMU_HEAP_SIZE,    UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(EMU_TLS_BASE,     EMU_TLS_SIZE,     UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(EMU_FAKE_FS_BASE, EMU_FAKE_FS_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(EMU_JNI_BASE,     EMU_JNI_SIZE,     UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(EMU_STUB_BASE,    EMU_STUB_SIZE,    UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)

        # 3) Install BRK trampolines for every libc-style stub. The address
        #    of each stub is what we'll write into the matching GOT slot.
        for name, handler_attr in self.LIBC_HANDLERS.items():
            handler = getattr(self, handler_attr, None)
            if handler is None:
                continue
            self._alloc_stub(name, handler)

        # 4) Resolve relocations.
        self._apply_relocations()

        # 5) Initialise TPIDR_EL0 (used by stack-canary checks throughout).
        self._w(UC_ARM64_REG_TPIDR_EL0, EMU_TLS_BASE)
        # Place a fixed cookie at TLS+0x28 (the SO loads from there for canary).
        self.uc.mem_write(EMU_TLS_BASE + 0x28, struct.pack("<Q", 0xdeadbeef_cafef00d))

        # 6) Set up stack.
        self._w(UC_ARM64_REG_SP, EMU_STACK_BASE + EMU_STACK_SIZE - 0x100)

    def _apply_relocations(self) -> None:
        """Walk RELA + JMPREL and patch the GOT to point at real functions
        (in-SO addresses) or BRK trampolines (libc imports).
        """
        layout = self.layout
        data = self.so
        segments = layout["segments"]
        sym_off = _va_to_off(segments, layout["symtab_va"])
        str_off = _va_to_off(segments, layout["strtab_va"])
        if sym_off is None or str_off is None:
            self.errors.append("Could not locate symtab/strtab in PT_LOAD")
            return

        def sym_at(idx: int):
            e = data[sym_off + idx*24 : sym_off + idx*24 + 24]
            name_off, info, other, shndx, value, size = struct.unpack("<IBBHQQ", e)
            nm = ""
            if name_off:
                end = data.index(b"\x00", str_off + name_off)
                nm = data[str_off + name_off:end].decode("latin-1", errors="replace")
            return nm, value, size

        def apply_block(va, sz):
            if not va or not sz:
                return
            off = _va_to_off(segments, va)
            if off is None:
                return
            for i in range(0, sz, 24):
                r_off, r_info, r_addend = struct.unpack_from("<QQq", data, off + i)
                rtype = r_info & 0xffffffff
                rsym = r_info >> 32
                # R_AARCH64_RELATIVE — write the addend (a vaddr inside the SO).
                if rtype == 0x403:
                    self.uc.mem_write(r_off, struct.pack("<Q", r_addend & 0xffffffffffffffff))
                # R_AARCH64_GLOB_DAT / R_AARCH64_ABS64 — resolve symbol.
                elif rtype in (0x401, 0x101):
                    nm, value, size = sym_at(rsym)
                    target = value if value else self.stub_addr_by_name.get(nm, 0)
                    if not target:
                        target = self._alloc_stub(f"undef:{nm}", self._stub_zero)
                    self.uc.mem_write(r_off, struct.pack("<Q", (target + r_addend) & 0xffffffffffffffff))
                # R_AARCH64_JUMP_SLOT — same lookup, no addend.
                elif rtype == 0x402:
                    nm, value, size = sym_at(rsym)
                    target = value if value else self.stub_addr_by_name.get(nm, 0)
                    if not target:
                        target = self._alloc_stub(f"undef:{nm}", self._stub_zero)
                    self.uc.mem_write(r_off, struct.pack("<Q", target & 0xffffffffffffffff))
                # Other reloc types — log and skip.
                else:
                    self.errors.append(f"unhandled reloc type {rtype:#x} at {hex(r_off)}")

        apply_block(layout["rela_va"], layout["rela_sz"])
        apply_block(layout["jmprel_va"], layout["pltrelsz"])

    def _stub_zero(self):
        return 0

    # -- hook handlers -------------------------------------------------------
    def _hook_intr(self, uc, intno, user_data):
        # BRK raises an interrupt; we identify the stub by the BRK immediate.
        pc = self._r(UC_ARM64_REG_PC)
        try:
            insn = struct.unpack("<I", bytes(self.uc.mem_read(pc, 4)))[0]
        except UcError:
            self.errors.append(f"BRK at unreadable PC {hex(pc)}")
            self.uc.emu_stop()
            return
        # BRK encoding: 1101_0100_001_imm16_00000  → mask 0xffe0001f, opc 0xd4200000
        if (insn & 0xffe0001f) == 0xd4200000:
            imm = (insn >> 5) & 0xffff
            entry = self.stub_table.get(imm)
            if entry is None:
                self.errors.append(f"unknown BRK imm {imm} at {hex(pc)}")
                self.uc.emu_stop()
                return
            name, handler = entry
            try:
                ret = handler()
            except Exception as ex:                  # noqa: BLE001
                self.errors.append(f"stub {name} raised {ex!r}")
                self.uc.emu_stop()
                return
            self._w(UC_ARM64_REG_X0, ret if ret is not None else 0)
            # Branch back to LR.
            self._w(UC_ARM64_REG_PC, self._r(UC_ARM64_REG_X30))
            return
        self.errors.append(f"unhandled INTR at {hex(pc)} insn={hex(insn)}")
        self.uc.emu_stop()

    def _hook_invalid_mem(self, uc, access, addr, size, value, user_data):
        self.errors.append(f"invalid mem access type={access} addr={hex(addr)} size={size}")
        return False                                  # stop emulation

    def _hook_code(self, uc, addr, size, user_data):
        self.insns_executed += 1
        if self.verbose and self.insns_executed % 1_000_000 == 0:
            print(f"  [insn {self.insns_executed:>12,}] @ {hex(addr)}")

        # Per-build target-function hooks. Fast-path: only do the dict
        # lookup when the address falls inside the small range we care
        # about (avoids 100ns dict-get per instruction in the inner SIMD
        # loop).
        if self.target_hook_lo <= addr <= self.target_hook_hi:
            h = self.target_hooks.get(addr)
            if h is not None:
                try:
                    h()
                except Exception as ex:              # noqa: BLE001
                    self.errors.append(f"target hook @ {hex(addr)} raised {ex!r}")

        # Dense trace for __arm_a_1's body (set by call_arm_a_1).
        lo = getattr(self, "arm_a_1_trace_lo", 0)
        hi = getattr(self, "arm_a_1_trace_hi", 0)
        if lo and lo <= addr < hi:
            seen = self.arm_a_1_seen
            if addr not in seen and len(seen) < 4096:
                seen[addr] = 1
                self.arm_a_1_trace.append((addr, self.insns_executed))
            else:
                seen[addr] = seen.get(addr, 0) + 1

    # DEX-magic write detection. The Jiagu loader doesn't always write 'dex\n035'
    # as a contiguous block — sometimes it patches the magic after building the
    # rest of the buffer. We therefore scan periodically for "dex\n" markers in
    # writes to addresses we haven't already harvested.
    def _hook_mem_write(self, uc, access, addr, size, value, user_data):
        # value is the value being written; address is the destination.
        # Track contiguous regions of writes to detect DEX-like buffers.
        # We keep a sliding window of recently-written bytes (>= 8 contiguous).
        if not hasattr(self, "_write_log"):
            self._write_log = []
        self._write_log.append((addr, size, value))
        # Don't keep the log unbounded
        if len(self._write_log) > 0x10000:
            self._write_log = self._write_log[-0x8000:]
        return True

    def _scan_memory_for_dex(self, regions: List[Tuple[int, int]]) -> List[bytes]:
        """Scan the given (addr, size) regions for DEX magic.

        Returns a list of carved DEX payloads.
        """
        out = []
        for base, size in regions:
            try:
                buf = bytes(self.uc.mem_read(base, size))
            except UcError:
                continue
            # Find every "dex\n0" occurrence; check it parses as DEX (file_size
            # within bounds, file_size >= 0x70).
            i = 0
            while True:
                pos = buf.find(b"dex\n", i)
                if pos < 0:
                    break
                # DEX header is 0x70 bytes; file_size at offset 0x20 (4 bytes LE)
                if pos + 0x70 <= len(buf):
                    file_size = struct.unpack_from("<I", buf, pos + 0x20)[0]
                    # Sanity bounds: 0x70 <= file_size <= 256 MB
                    if 0x70 <= file_size <= 0x10_000_000 and pos + file_size <= len(buf):
                        out.append(buf[pos:pos + file_size])
                i = pos + 4
        return out

    # -- JNI mock ------------------------------------------------------------
    # We install JavaVM* and JNIEnv* tables in EMU_JNI_BASE. Only a subset of
    # functions are wired to real handlers; the rest go to a "return 0" catch-
    # all. The wired calls capture what the Jiagu loader does: FindClass,
    # GetMethodID, RegisterNatives, GetStringUTFChars, plus the AssetManager
    # path (Call(Static)ObjectMethod returning a synthetic AssetInputStream).

    JAVAVM_PTR_ADDR   = EMU_JNI_BASE + 0x000
    JAVAVM_TABLE_ADDR = EMU_JNI_BASE + 0x1000
    JNIENV_PTR_ADDR   = EMU_JNI_BASE + 0x2000
    JNIENV_TABLE_ADDR = EMU_JNI_BASE + 0x3000

    # JNINativeInterface slot indices (subset used by Jiagu loaders).
    # Subset of slots we wire. Indices follow the standard libnativehelper
    # JNINativeInterface order — see <jni.h> for the canonical list. The
    # "..V" variants are the va_list forms used by C code; the "..A" variants
    # are the jvalue[] forms used by reflection. The Jiagu interpreter
    # dispatches through all three for the same Java method, so we mock all
    # three to the same handler.
    JNI_SLOT_DEFINE_CLASS = 5
    JNI_SLOT_FIND_CLASS = 6
    JNI_SLOT_GET_OBJECT_CLASS = 31
    JNI_SLOT_IS_INSTANCE_OF = 32
    JNI_SLOT_GET_METHOD_ID = 33
    JNI_SLOT_CALL_OBJECT_METHOD = 34
    JNI_SLOT_CALL_OBJECT_METHOD_V = 35
    JNI_SLOT_CALL_OBJECT_METHOD_A = 36
    JNI_SLOT_CALL_BOOLEAN_METHOD = 37
    JNI_SLOT_CALL_BOOLEAN_METHOD_V = 38
    JNI_SLOT_CALL_BOOLEAN_METHOD_A = 39
    JNI_SLOT_CALL_INT_METHOD = 49
    JNI_SLOT_CALL_INT_METHOD_V = 50
    JNI_SLOT_CALL_LONG_METHOD = 52
    JNI_SLOT_CALL_LONG_METHOD_V = 53
    JNI_SLOT_CALL_VOID_METHOD = 61
    JNI_SLOT_CALL_VOID_METHOD_V = 62
    JNI_SLOT_GET_FIELD_ID = 94
    JNI_SLOT_GET_OBJECT_FIELD = 95
    JNI_SLOT_GET_BOOLEAN_FIELD = 96
    JNI_SLOT_GET_INT_FIELD = 100
    JNI_SLOT_GET_LONG_FIELD = 101
    # Object lifecycle slots, per AOSP <jni.h>.
    # 27: AllocObject
    # 28: NewObject (varargs)
    # 29: NewObjectV (va_list)
    # 30: NewObjectA (jvalue[])
    JNI_SLOT_ALLOC_OBJECT = 27
    JNI_SLOT_NEW_OBJECT = 28
    JNI_SLOT_NEW_OBJECT_V = 29
    JNI_SLOT_NEW_OBJECT_A = 30

    # Static-field slots, per AOSP <jni.h>. Index 144 = GetStaticFieldID,
    # 145..153 = GetStatic{Object,Boolean,Byte,Char,Short,Int,Long,Float,Double}Field.
    # The SO at vaddr 0x1de98 dispatches GetStaticIntField via slot 150
    # (offset 0x4b0 = 150*8) — verified by static disassembly. Prior to
    # 2026-05-18b we had slot 149 here, which sent SDK_INT reads through
    # the catch-all (returning 0) and caused the loader's re-resolve loop.
    JNI_SLOT_GET_STATIC_FIELD_ID = 144
    JNI_SLOT_GET_STATIC_OBJECT_FIELD = 145
    JNI_SLOT_GET_STATIC_BOOLEAN_FIELD = 146
    JNI_SLOT_GET_STATIC_BYTE_FIELD = 147
    JNI_SLOT_GET_STATIC_CHAR_FIELD = 148
    JNI_SLOT_GET_STATIC_SHORT_FIELD = 149
    JNI_SLOT_GET_STATIC_INT_FIELD = 150
    JNI_SLOT_GET_STATIC_LONG_FIELD = 151
    JNI_SLOT_GET_STATIC_FLOAT_FIELD = 152
    JNI_SLOT_GET_STATIC_DOUBLE_FIELD = 153
    JNI_SLOT_GET_STATIC_METHOD_ID = 113
    JNI_SLOT_CALL_STATIC_OBJECT_METHOD = 114
    JNI_SLOT_CALL_STATIC_OBJECT_METHOD_V = 115
    JNI_SLOT_CALL_STATIC_OBJECT_METHOD_A = 116
    JNI_SLOT_CALL_STATIC_INT_METHOD = 129
    JNI_SLOT_CALL_STATIC_INT_METHOD_V = 130
    JNI_SLOT_CALL_STATIC_LONG_METHOD = 132
    JNI_SLOT_CALL_STATIC_LONG_METHOD_V = 133
    JNI_SLOT_NEW_STRING_UTF = 167
    JNI_SLOT_GET_STRING_UTF_LENGTH = 168
    JNI_SLOT_GET_STRING_UTF_CHARS = 169
    JNI_SLOT_RELEASE_STRING_UTF_CHARS = 170
    JNI_SLOT_GET_ARRAY_LENGTH = 171
    # Array constructors — slot 175..182, alphabetical-ish primitive order:
    # NewBooleanArray=175, NewByteArray=176, NewCharArray=177, NewShortArray=178,
    # NewIntArray=179, NewLongArray=180, NewFloatArray=181, NewDoubleArray=182.
    # Prior to 2026-05-18b we had 178 → NewByteArray (the NewShortArray slot),
    # which silently broke any byte-array allocation the loader did.
    JNI_SLOT_NEW_BYTE_ARRAY = 176
    JNI_SLOT_GET_BYTE_ARRAY_ELEMENTS = 184
    JNI_SLOT_RELEASE_BYTE_ARRAY_ELEMENTS = 192
    JNI_SLOT_GET_BYTE_ARRAY_REGION = 200
    JNI_SLOT_SET_BYTE_ARRAY_REGION = 208
    JNI_SLOT_REGISTER_NATIVES = 215
    JNI_SLOT_DELETE_LOCAL_REF = 23
    JNI_SLOT_NEW_GLOBAL_REF = 21
    JNI_SLOT_DELETE_GLOBAL_REF = 22
    JNI_SLOT_EXCEPTION_CLEAR = 17
    JNI_SLOT_EXCEPTION_CHECK = 228
    JNI_SLOT_EXCEPTION_OCCURRED = 15
    JNI_SLOT_EXCEPTION_DESCRIBE = 16

    def install_jni_mocks(self) -> None:
        """Plant a JavaVM/JNIEnv structure at EMU_JNI_BASE and wire stubs."""
        # JavaVM struct
        self.uc.mem_write(self.JAVAVM_PTR_ADDR,
                          struct.pack("<Q", self.JAVAVM_TABLE_ADDR))
        self.uc.mem_write(self.JNIENV_PTR_ADDR,
                          struct.pack("<Q", self.JNIENV_TABLE_ADDR))

        # JNIInvokeInterface: slots 4=Attach, 6=GetEnv
        attach = self._alloc_stub("JavaVM::AttachCurrentThread",
                                  self._jvm_get_env)
        get_env = self._alloc_stub("JavaVM::GetEnv", self._jvm_get_env)
        self.uc.mem_write(self.JAVAVM_TABLE_ADDR + 4*8, struct.pack("<Q", attach))
        self.uc.mem_write(self.JAVAVM_TABLE_ADDR + 6*8, struct.pack("<Q", get_env))

        # JNINativeInterface — wire the relevant slots.
        wires = {
            self.JNI_SLOT_DEFINE_CLASS:         ("DefineClass", self._jni_define_class),
            self.JNI_SLOT_FIND_CLASS:           ("FindClass", self._jni_find_class),
            self.JNI_SLOT_ALLOC_OBJECT:         ("AllocObject", self._jni_alloc_object),
            self.JNI_SLOT_NEW_OBJECT:           ("NewObject", self._jni_alloc_object),
            self.JNI_SLOT_NEW_OBJECT_V:         ("NewObjectV", self._jni_alloc_object),
            self.JNI_SLOT_NEW_OBJECT_A:         ("NewObjectA", self._jni_alloc_object),
            self.JNI_SLOT_GET_OBJECT_CLASS:     ("GetObjectClass", self._jni_get_object_class),
            self.JNI_SLOT_IS_INSTANCE_OF:       ("IsInstanceOf", lambda: 1),
            self.JNI_SLOT_GET_METHOD_ID:        ("GetMethodID", self._jni_get_method_id),
            self.JNI_SLOT_CALL_OBJECT_METHOD:   ("CallObjectMethod", self._jni_call_object_method),
            self.JNI_SLOT_CALL_OBJECT_METHOD_V: ("CallObjectMethodV", self._jni_call_object_method),
            self.JNI_SLOT_CALL_OBJECT_METHOD_A: ("CallObjectMethodA", self._jni_call_object_method),
            self.JNI_SLOT_CALL_BOOLEAN_METHOD:   ("CallBooleanMethod", lambda: 0),
            self.JNI_SLOT_CALL_BOOLEAN_METHOD_V: ("CallBooleanMethodV", lambda: 0),
            self.JNI_SLOT_CALL_BOOLEAN_METHOD_A: ("CallBooleanMethodA", lambda: 0),
            self.JNI_SLOT_CALL_INT_METHOD:       ("CallIntMethod", self._jni_call_int_method),
            self.JNI_SLOT_CALL_INT_METHOD_V:     ("CallIntMethodV", self._jni_call_int_method),
            self.JNI_SLOT_CALL_LONG_METHOD:      ("CallLongMethod", self._jni_call_long_method),
            self.JNI_SLOT_CALL_LONG_METHOD_V:    ("CallLongMethodV", self._jni_call_long_method),
            self.JNI_SLOT_CALL_VOID_METHOD:      ("CallVoidMethod", lambda: 0),
            self.JNI_SLOT_CALL_VOID_METHOD_V:    ("CallVoidMethodV", lambda: 0),
            self.JNI_SLOT_GET_FIELD_ID:         ("GetFieldID", self._jni_get_method_id),
            self.JNI_SLOT_GET_OBJECT_FIELD:     ("GetObjectField", self._jni_get_object_class),
            self.JNI_SLOT_GET_BOOLEAN_FIELD:    ("GetBooleanField", lambda: 0),
            self.JNI_SLOT_GET_INT_FIELD:        ("GetIntField", lambda: 0),
            self.JNI_SLOT_GET_LONG_FIELD:       ("GetLongField", lambda: 0),
            self.JNI_SLOT_GET_STATIC_FIELD_ID:  ("GetStaticFieldID", self._jni_get_method_id),
            self.JNI_SLOT_GET_STATIC_OBJECT_FIELD: ("GetStaticObjectField", self._jni_get_object_class),
            self.JNI_SLOT_GET_STATIC_BOOLEAN_FIELD: ("GetStaticBooleanField", lambda: 0),
            self.JNI_SLOT_GET_STATIC_INT_FIELD: ("GetStaticIntField", self._jni_get_static_int_field),
            self.JNI_SLOT_GET_STATIC_LONG_FIELD:("GetStaticLongField", lambda: 0),
            self.JNI_SLOT_GET_STATIC_METHOD_ID: ("GetStaticMethodID", self._jni_get_method_id),
            self.JNI_SLOT_CALL_STATIC_OBJECT_METHOD:   ("CallStaticObjectMethod", self._jni_call_static_object_method),
            self.JNI_SLOT_CALL_STATIC_OBJECT_METHOD_V: ("CallStaticObjectMethodV", self._jni_call_static_object_method),
            self.JNI_SLOT_CALL_STATIC_OBJECT_METHOD_A: ("CallStaticObjectMethodA", self._jni_call_static_object_method),
            self.JNI_SLOT_CALL_STATIC_INT_METHOD:    ("CallStaticIntMethod", self._jni_call_static_int_method),
            self.JNI_SLOT_CALL_STATIC_INT_METHOD_V:  ("CallStaticIntMethodV", self._jni_call_static_int_method),
            self.JNI_SLOT_CALL_STATIC_LONG_METHOD:   ("CallStaticLongMethod", self._jni_call_static_long_method),
            self.JNI_SLOT_CALL_STATIC_LONG_METHOD_V: ("CallStaticLongMethodV", self._jni_call_static_long_method),
            self.JNI_SLOT_NEW_STRING_UTF:       ("NewStringUTF", self._jni_new_string_utf),
            self.JNI_SLOT_GET_STRING_UTF_LENGTH:("GetStringUTFLength", self._jni_get_str_utf_length),
            self.JNI_SLOT_GET_STRING_UTF_CHARS: ("GetStringUTFChars", self._jni_get_str_utf),
            self.JNI_SLOT_RELEASE_STRING_UTF_CHARS: ("ReleaseStringUTFChars", self._jni_release_str_utf),
            self.JNI_SLOT_GET_ARRAY_LENGTH:     ("GetArrayLength", self._jni_array_length),
            self.JNI_SLOT_NEW_BYTE_ARRAY:       ("NewByteArray", self._jni_new_byte_array),
            self.JNI_SLOT_GET_BYTE_ARRAY_ELEMENTS: ("GetByteArrayElements", self._jni_get_byte_array_elements),
            self.JNI_SLOT_RELEASE_BYTE_ARRAY_ELEMENTS: ("ReleaseByteArrayElements", self._jni_release_byte_array_elements),
            self.JNI_SLOT_GET_BYTE_ARRAY_REGION:("GetByteArrayRegion", self._jni_get_byte_array_region),
            self.JNI_SLOT_SET_BYTE_ARRAY_REGION:("SetByteArrayRegion", self._jni_set_byte_array_region),
            self.JNI_SLOT_REGISTER_NATIVES:     ("RegisterNatives", self._jni_register_natives),
            self.JNI_SLOT_DELETE_LOCAL_REF:     ("DeleteLocalRef", self._stub_zero),
            self.JNI_SLOT_NEW_GLOBAL_REF:       ("NewGlobalRef", self._jni_get_object_class),
            self.JNI_SLOT_DELETE_GLOBAL_REF:    ("DeleteGlobalRef", self._stub_zero),
            self.JNI_SLOT_EXCEPTION_CLEAR:      ("ExceptionClear", self._stub_zero),
            self.JNI_SLOT_EXCEPTION_CHECK:      ("ExceptionCheck", self._stub_zero),
            self.JNI_SLOT_EXCEPTION_OCCURRED:   ("ExceptionOccurred", self._stub_zero),
            self.JNI_SLOT_EXCEPTION_DESCRIBE:   ("ExceptionDescribe", self._stub_zero),
        }
        catchall = self._alloc_stub("JNI::other", self._jni_other)
        for slot in range(232):
            handler_addr = catchall
            if slot in wires:
                name, fn = wires[slot]
                handler_addr = self._alloc_stub(name, fn)
            self.uc.mem_write(self.JNIENV_TABLE_ADDR + slot*8,
                              struct.pack("<Q", handler_addr))

        # Init internal JNI state.
        # jobject IDs are integers we hand out sequentially.
        self._next_jobject = 0x10_000
        # Map jobject → arbitrary tag (class name, method id, string).
        self.jobjects: Dict[int, dict] = {}
        # Per-jstring: hand out a UTF8 pointer in heap.
        self.jstring_buffers: Dict[int, int] = {}
        # Per-jbyteArray: heap pointer + length.
        self.jbyte_arrays: Dict[int, Tuple[int, int]] = {}
        # Synthetic asset bytes the loader will see as classes-of-interest.
        # Filled later by caller via emu.set_asset_bytes(...).
        self.asset_bytes_by_name: Dict[str, bytes] = {}

    def _new_jobject(self, kind: str, **kwargs) -> int:
        oid = self._next_jobject
        self._next_jobject += 1
        self.jobjects[oid] = {"kind": kind, **kwargs}
        return oid

    # -- JNI handlers --------------------------------------------------------
    def _jvm_get_env(self):
        env_pp = self._r(UC_ARM64_REG_X1)
        self.uc.mem_write(env_pp, struct.pack("<Q", self.JNIENV_PTR_ADDR))
        return 0

    def _jni_other(self):
        # Reverse-lookup: figure out which JNI slot the caller dispatched
        # through by reading the GOT pattern. The Jiagu interpreter loads:
        #   x8 = *(env)                       # JNINativeInterface*
        #   x9 = *(x8 + slot*8)               # function pointer
        #   blr x9
        # The LR is the instruction after blr. We don't know the slot from
        # PC alone, but we can read the caller's preceding instructions to
        # recover the immediate offset used in ldr x9, [x8, #imm].
        pc = self._r(UC_ARM64_REG_PC)
        lr = self._r(UC_ARM64_REG_X30)
        slot = -1
        try:
            # Scan 8 instructions back from LR for the ldr that loaded the
            # function pointer.
            for off in range(4, 64, 4):
                code = struct.unpack("<I", bytes(self.uc.mem_read(lr - off, 4)))[0]
                # LDR (immediate, unsigned offset, 64-bit): 11_111_001_01_imm12_Rn_Rt
                # Rt is the dest reg; we want the one whose value got branched.
                if (code >> 22) & 0x3ff == 0b1111100101:
                    imm12 = (code >> 10) & 0xfff
                    slot = imm12  # in 8-byte units
                    break
        except UcError:
            pass
        # Log only the first 200 unique slots to avoid log spam.
        if not hasattr(self, "_jni_unmocked_slots"):
            self._jni_unmocked_slots = set()
        if slot not in self._jni_unmocked_slots and len(self._jni_unmocked_slots) < 200:
            self._jni_unmocked_slots.add(slot)
            self.jni_trace.append(
                f"JNI[unmocked slot {slot}] @ lr={hex(lr)} x0={hex(self._r(UC_ARM64_REG_X0))}"
            )
        return 0

    def _jni_find_class(self):
        name = self._read_cstr(self._r(UC_ARM64_REG_X1))
        oid = self._new_jobject("class", name=name)
        # Log call-site for the first few invocations and *any* repeat
        # invocation past the first 5 — repeat-calls usually indicate a
        # state-machine loop and we want to see where it is.
        if not hasattr(self, "_findclass_calls"):
            self._findclass_calls = collections.Counter()
        self._findclass_calls[name] += 1
        lr = self._r(UC_ARM64_REG_X30)
        cnt = self._findclass_calls[name]
        if cnt <= 1 or cnt == 5 or cnt == 20 or cnt % 100 == 0:
            self.jni_trace.append(
                f"FindClass({name!r}) → {hex(oid)} [call #{cnt}, lr={hex(lr)}]"
            )
        return oid

    def _jni_get_object_class(self):
        # Pretend every object is a generic class
        oid = self._new_jobject("class", name="?")
        return oid

    def _jni_alloc_object(self):
        # AllocObject/NewObject/NewObjectV/NewObjectA — return a fresh
        # jobject of the requested class.
        klass = self._r(UC_ARM64_REG_X1)
        info = self.jobjects.get(klass, {})
        return self._new_jobject("object", from_class=info.get("name", "?"))

    def _jni_get_method_id(self):
        klass = self._r(UC_ARM64_REG_X1)
        name = self._read_cstr(self._r(UC_ARM64_REG_X2))
        sig = self._read_cstr(self._r(UC_ARM64_REG_X3))
        cls_name = self.jobjects.get(klass, {}).get("name", "?")
        oid = self._new_jobject("methodid", klass=cls_name, name=name, sig=sig)
        self.jni_trace.append(f"GetMethodID({cls_name}::{name} sig={sig}) → {hex(oid)}")
        return oid

    def _jni_new_string_utf(self):
        ptr = self._r(UC_ARM64_REG_X1)
        s = self._read_cstr(ptr)
        oid = self._new_jobject("string", value=s)
        # also stash a heap copy so GetStringUTFChars can return it
        buf = self._alloc_heap(len(s) + 1)
        self.uc.mem_write(buf, s.encode("latin-1") + b"\x00")
        self.jstring_buffers[oid] = buf
        return oid

    def _jni_get_str_utf(self):
        s = self._r(UC_ARM64_REG_X1)
        # If it's a known jstring, return its heap copy; otherwise check
        # the object's provenance and substitute build-specific data.
        if s in self.jstring_buffers:
            return self.jstring_buffers[s]
        info = self.jobjects.get(s)
        if info and info.get("kind") == "string":
            value = info["value"]
        else:
            # Synthesise a value based on where the jobject came from.
            value = self._synth_string_for(info)
        if not value:
            value = "?"                              # never return empty
        buf = self._alloc_heap(len(value) + 1)
        self.uc.mem_write(buf, value.encode("utf-8", "replace") + b"\x00")
        self.jstring_buffers[s] = buf
        return buf

    def _synth_string_for(self, info: Optional[dict]) -> str:
        """Pick a plausible string when the loader fetches an opaque
        jobject as a UTF-8 string. We pattern-match on the method-name
        that produced the object — see `_jni_call_*` callers.
        """
        if not info:
            return ""
        provenance = info.get("from_method", "") or info.get("name", "")
        provenance = provenance.lower()
        pkg = getattr(self, "injected_package_name", "") or ""
        md5 = getattr(self, "injected_apk_md5", "") or ""
        apk_path = self.injected_apk_path or f"/data/app/{pkg or 'com.example'}-1/base.apk"
        if "packagename" in provenance:
            return pkg
        if "sourcedir" in provenance:
            return apk_path
        if "publicsourcedir" in provenance:
            return apk_path
        if "nativelibrarydir" in provenance:
            return f"/data/app/{pkg or 'com.example'}-1/lib/arm64"
        if "package" in provenance and pkg:
            return pkg
        if "md5" in provenance and md5:
            return md5
        if "appname" in provenance:
            return pkg
        if "version" in provenance:
            return "1.0"
        if "model" in provenance:
            return "Pixel 6"
        if "manufacturer" in provenance:
            return "Google"
        if "brand" in provenance:
            return "google"
        if "device" in provenance:
            return "raven"
        if "release" in provenance:
            return "11"
        if "datadir" in provenance:
            return f"/data/data/{pkg or 'com.example'}"
        if "filesdir" in provenance:
            return f"/data/data/{pkg or 'com.example'}/files"
        if "applicationid" in provenance:
            return pkg
        if "externalstoragestate" in provenance:
            return "mounted"
        if "language" in provenance:
            return "en"
        if "country" in provenance:
            return "US"
        if "supported_abis" in provenance or "abi" in provenance:
            return "arm64-v8a"
        return ""

    def _jni_release_str_utf(self):
        return 0

    def _jni_get_static_int_field(self):
        # Return reasonable defaults for common static int fields the
        # Jiagu loader reads.
        fid = self._r(UC_ARM64_REG_X2)
        info = self.jobjects.get(fid, {})
        nm = info.get("name", "")
        val = 0
        if nm == "SDK_INT":
            val = 30        # Android 11
        # Trace once per (name, value) pair to avoid log spam.
        key = ("GetStaticIntField", nm, val)
        if not hasattr(self, "_static_trace_seen"):
            self._static_trace_seen = set()
        if key not in self._static_trace_seen:
            self._static_trace_seen.add(key)
            self.jni_trace.append(f"GetStaticIntField({nm!r}) → {val}")
        return val

    def _jni_get_str_utf_length(self):
        s = self._r(UC_ARM64_REG_X1)
        info = self.jobjects.get(s)
        if info and info.get("kind") == "string":
            return len(info["value"])
        return 0

    def _jni_call_object_method(self):
        # Variadic — Jiagu typically uses this for AssetManager.open or
        # similar. Inspect the methodID to decide what to return.
        mid = self._r(UC_ARM64_REG_X2)
        info = self.jobjects.get(mid, {})
        name = info.get("name", "?")
        self.jni_trace.append(f"CallObjectMethod(mid={name!r})")
        # Stock answers: return a fresh object.
        return self._new_jobject("object", from_method=name)

    def _jni_call_int_method(self):
        # Return method-name-specific int values for the metadata-collection
        # phase. Keep silent (no trace entry per call to avoid spam).
        mid = self._r(UC_ARM64_REG_X2)
        info = self.jobjects.get(mid, {})
        name = (info.get("name", "") or "").lower()
        if "versioncode" in name:
            return 1
        if "available" in name:                      # AvailableBlocks
            return 1_000_000
        if "blocksize" in name:
            return 4096
        if "blockcount" in name:
            return 5_000_000
        if "permission" in name:                     # checkPermission → PERMISSION_GRANTED
            return 0
        return 0

    def _jni_call_long_method(self):
        # Same as _jni_call_int_method but for jlong-returning getters.
        mid = self._r(UC_ARM64_REG_X2)
        info = self.jobjects.get(mid, {})
        name = (info.get("name", "") or "").lower()
        if "availableblocks" in name:
            return 1_000_000           # blocks
        if "blocksize" in name:
            return 4096                # bytes per block
        if "blockcount" in name:
            return 5_000_000
        if "totalspace" in name:
            return 5_000_000 * 4096    # ~20 GB
        if "availablespace" in name or "freespace" in name:
            return 1_000_000 * 4096    # ~4 GB
        return 0

    def _jni_call_static_int_method(self):
        mid = self._r(UC_ARM64_REG_X2)
        info = self.jobjects.get(mid, {})
        name = (info.get("name", "") or "").lower()
        if "permissiontoop" in name:
            return 0
        return 0

    def _jni_call_static_long_method(self):
        return 0

    def _jni_call_static_object_method(self):
        mid = self._r(UC_ARM64_REG_X2)
        info = self.jobjects.get(mid, {})
        name = info.get("name", "?")
        self.jni_trace.append(f"CallStaticObjectMethod({name!r})")
        return self._new_jobject("object", from_method=name)

    def _jni_array_length(self):
        arr = self._r(UC_ARM64_REG_X1)
        if arr in self.jbyte_arrays:
            return self.jbyte_arrays[arr][1]
        return 0

    def _jni_new_byte_array(self):
        n = self._r(UC_ARM64_REG_X1)
        buf = self._alloc_heap(max(n, 16))
        self.uc.mem_write(buf, b"\x00" * n)
        oid = self._new_jobject("byte_array", buf=buf, length=n)
        self.jbyte_arrays[oid] = (buf, n)
        return oid

    def _jni_get_byte_array_elements(self):
        arr = self._r(UC_ARM64_REG_X1)
        if arr in self.jbyte_arrays:
            buf, _ = self.jbyte_arrays[arr]
            return buf
        return self._alloc_heap(16)

    def _jni_release_byte_array_elements(self):
        return 0

    def _jni_get_byte_array_region(self):
        arr = self._r(UC_ARM64_REG_X1)
        start = self._r(UC_ARM64_REG_X2)
        n = self._r(UC_ARM64_REG_X3)
        dst = self._r(UC_ARM64_REG_X4)
        if arr in self.jbyte_arrays:
            buf, _ = self.jbyte_arrays[arr]
            try:
                src = bytes(self.uc.mem_read(buf + start, n))
                self.uc.mem_write(dst, src)
            except UcError:
                pass
        return 0

    def _jni_set_byte_array_region(self):
        arr = self._r(UC_ARM64_REG_X1)
        start = self._r(UC_ARM64_REG_X2)
        n = self._r(UC_ARM64_REG_X3)
        src = self._r(UC_ARM64_REG_X4)
        if arr in self.jbyte_arrays:
            buf, _ = self.jbyte_arrays[arr]
            try:
                data = bytes(self.uc.mem_read(src, n))
                self.uc.mem_write(buf + start, data)
            except UcError:
                pass
        return 0

    def _jni_define_class(self):
        # DefineClass(env, name, loader, buf, bufLen)
        name = self._read_cstr(self._r(UC_ARM64_REG_X1))
        buf = self._r(UC_ARM64_REG_X3)
        size = self._r(UC_ARM64_REG_X4)
        try:
            data = bytes(self.uc.mem_read(buf, size))
        except UcError:
            data = b""
        if size > 0:
            self.dex_payloads.append(data)
            self.jni_trace.append(f"DefineClass({name!r}, len={size}) — DEX CAPTURED")
        else:
            self.jni_trace.append(f"DefineClass({name!r}, empty)")
        return self._new_jobject("class", name=name, dex_len=size)

    def _jni_register_natives(self):
        klass = self._r(UC_ARM64_REG_X1)
        methods = self._r(UC_ARM64_REG_X2)
        n = self._r(UC_ARM64_REG_X3)
        cls_name = self.jobjects.get(klass, {}).get("name", "?")
        self.jni_trace.append(f"RegisterNatives({cls_name}, {n} methods)")
        # Persist the (name, sig, fn_p) tuples so phase 2 (ART callback
        # replication) can invoke them in the lifecycle order. The standard
        # JNINativeMethod size on aarch64 is 3 pointers = 24 bytes.
        if not hasattr(self, "registered_natives"):
            # class_name -> [(name, sig, fn_va), ...]
            self.registered_natives: Dict[str, List[Tuple[str, str, int]]] = {}
        try:
            # Cap at 8K methods/24 = 192 KB to avoid bad input.
            tbl = bytes(self.uc.mem_read(methods, min(n, 8192) * 24))
        except UcError:
            return 0
        entries: List[Tuple[str, str, int]] = []
        for i in range(min(n, 8192)):
            name_p, sig_p, fn_p = struct.unpack_from("<QQQ", tbl, i*24)
            try:
                nm = self._read_cstr(name_p, 128)
                sg = self._read_cstr(sig_p, 256)
            except Exception:
                nm = sg = "?"
            entries.append((nm, sg, fn_p))
            if i < 40:
                self.jni_trace.append(
                    f"  method[{i}] {nm!r} sig={sg!r} fn={hex(fn_p)}"
                )
        if n > 40:
            self.jni_trace.append(f"  ... ({n - 40} more methods registered)")
        self.registered_natives.setdefault(cls_name, []).extend(entries)
        return 0

    # -- driver --------------------------------------------------------------
    def run_init_array(self, max_insns: int) -> None:
        layout = self.layout
        ia_va = layout["init_array_va"]
        ia_sz = layout["init_array_sz"]
        if not ia_va or not ia_sz:
            return
        # Read init_array entries (already patched by relocations).
        ptrs = []
        for i in range(0, ia_sz, 8):
            try:
                p = struct.unpack("<Q", bytes(self.uc.mem_read(ia_va + i, 8)))[0]
                if p:
                    ptrs.append(p)
            except UcError:
                break
        # Install hooks ONCE.
        self.uc.hook_add(UC_HOOK_INTR, self._hook_intr)
        self.uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED
                         | UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_invalid_mem)
        self.uc.hook_add(UC_HOOK_CODE, self._hook_code)

        # Stash an end-of-call sentinel address; when LR == sentinel we stop.
        sentinel = EMU_STUB_BASE + EMU_STUB_SIZE - 0x10
        self.uc.mem_write(sentinel, _brk(0xfffe))    # invalid BRK → stop
        self.stub_table[0xfffe] = ("__sentinel__", self._stub_sentinel)

        for idx, entry in enumerate(ptrs):
            if self.verbose:
                print(f"  init_array[{idx}] → {hex(entry)}")
            # Set LR to sentinel so the entry's RET returns to a stop.
            self._w(UC_ARM64_REG_X30, sentinel)
            self._w(UC_ARM64_REG_SP, EMU_STACK_BASE + EMU_STACK_SIZE - 0x100)
            self._w(UC_ARM64_REG_PC, entry)
            try:
                self.uc.emu_start(entry, sentinel, timeout=0, count=max_insns)
            except UcError as e:
                self.errors.append(f"init_array[{idx}] @ {hex(entry)}: {e}")
                continue

    def _stub_sentinel(self):
        # Marker for "function returned to the harness". Stop emulation.
        self.uc.emu_stop()
        return 0

    def call_jni_onload(self, max_insns: int = 10_000_000) -> None:
        """Invoke JNI_OnLoad with the mock JavaVM.

        Caller is expected to have already run init_array and installed JNI
        mocks via `install_jni_mocks`.
        """
        # JNI_OnLoad vaddr is parsed from the symbol table.
        jni_va = self._find_export("JNI_OnLoad")
        if not jni_va:
            self.errors.append("JNI_OnLoad export not found")
            return
        sentinel = self.stub_addr_by_name.get("__sentinel__")
        if sentinel is None:
            sentinel = EMU_STUB_BASE + EMU_STUB_SIZE - 0x10
            self.uc.mem_write(sentinel, _brk(0xfffe))
            self.stub_table[0xfffe] = ("__sentinel__", self._stub_sentinel)
            self.stub_addr_by_name["__sentinel__"] = sentinel
        self._w(UC_ARM64_REG_X0, self.JAVAVM_PTR_ADDR)
        self._w(UC_ARM64_REG_X1, 0)
        self._w(UC_ARM64_REG_X30, sentinel)
        self._w(UC_ARM64_REG_SP, EMU_STACK_BASE + EMU_STACK_SIZE - 0x100)
        self._w(UC_ARM64_REG_PC, jni_va)
        try:
            self.uc.emu_start(jni_va, sentinel, timeout=60_000_000, count=max_insns)
        except UcError as e:
            self.errors.append(f"JNI_OnLoad: {e}")

    def _find_export(self, name: str) -> int:
        """Return the vaddr of an exported symbol, or 0."""
        data = self.so
        layout = self.layout
        sym_off = _va_to_off(layout["segments"], layout["symtab_va"])
        str_off = _va_to_off(layout["segments"], layout["strtab_va"])
        if sym_off is None or str_off is None:
            return 0
        for i in range(layout["nchain"]):
            e = data[sym_off + i*24 : sym_off + i*24 + 24]
            name_off, info, other, shndx, value, size = struct.unpack("<IBBHQQ", e)
            if not name_off:
                continue
            end = data.index(b"\x00", str_off + name_off)
            nm = data[str_off + name_off:end].decode("latin-1", errors="replace")
            if nm == name and value:
                return value
        return 0

    def _install_arm_a_1_dense_trace(self, fn_va: int, span: int = 0x400) -> None:
        """Add a trace hook at *every* basic-block boundary in [fn_va, fn_va+span)
        so we can reconstruct which path __arm_a_1 took.

        Records each unique address hit, up to 4096 entries, into
        `self.arm_a_1_trace`.
        """
        self.arm_a_1_trace: List[Tuple[int, int]] = []  # (addr, hit_count)
        self.arm_a_1_seen: Dict[int, int] = {}

        # We want to hook every instruction. Instead of installing per-insn
        # hooks (which would bloat target_hooks), set a temporary RANGE hook
        # via UC_HOOK_CODE — but the code-hook already exists. We piggyback
        # via the existing _hook_code by adding the address range as a flag.
        self.arm_a_1_trace_lo = fn_va
        self.arm_a_1_trace_hi = fn_va + span

    def _install_inner_loader_trace(self) -> None:
        """Add target-hooks at the key call sites inside the custom inner-SO
        loader (0x101f8) so we can see whether the BMP-integrity check passes,
        and what the actual loader (0xc8fc) returns.

        Addresses are from the dominant v1.4.0.4 build. The detection logic
        is brittle to per-build randomisation — for builds where these
        addresses are different, the hooks simply won't fire.
        """
        # 0x101f8: entry to the inner-SO loader. Log args.
        def _hook_101f8_entry():
            self.jni_trace.append(
                f"  inner_loader_entry @ 0x101f8 (sp={hex(self._r(UC_ARM64_REG_SP))})"
            )
        # 0x102dc: tbz w0, #0, #0x10300 (BMP integrity check result)
        def _hook_integrity_result():
            w0 = self._r(UC_ARM64_REG_X0) & 0xffffffff
            self.jni_trace.append(
                f"  inner_loader: BMP integrity check w0={hex(w0)} "
                f"(bit0={w0 & 1}; will {'continue' if (w0 & 1) else 'skip to early exit'})"
            )
        # 0x102e8: bl 0xc8fc (the actual SO loader)
        def _hook_actual_loader_entry():
            self.jni_trace.append(
                f"  inner_loader: calling actual SO loader 0xc8fc "
                f"(x0={hex(self._r(UC_ARM64_REG_X0))} x1={hex(self._r(UC_ARM64_REG_X1))})"
            )
        # 0x102ec: ldr x8, [sp, #0x110] — return point from bl 0xc8fc
        def _hook_actual_loader_ret():
            x0 = self._r(UC_ARM64_REG_X0)
            self.jni_trace.append(
                f"  inner_loader: 0xc8fc returned handle={hex(x0)}"
            )
        # 0x10318: mov x0, x19 — final return value setup
        def _hook_101f8_exit():
            x19 = self._r(UC_ARM64_REG_X19)
            self.jni_trace.append(
                f"  inner_loader: 0x101f8 exiting with X19={hex(x19)}"
            )

        # 0xc8fc body checkpoints (dominant v1.4.0.4):
        #   0xc934: bl 0xdf08   (set vtable[1,2])  — return val in w0
        #   0xc938: tbz w0, #0, #0xca08  (if w0==0 → fail)
        #   0xc944: ldr x8, [x8, #0x18] ; blr x8   (call vtable[0][3])
        #   0xc94c: tbz w0, #0, #0xca08  (if w0==0 → fail)
        #   0xc964: bl 0xc794    (the SECOND init; X19=ret)
        #   0xc96c: cbz x0, #0xca0c (if X0==0 → fail)
        #   0xca08: X19=NULL ("fail" branch)
        def _hook_c8fc_dl_post():
            w0 = self._r(UC_ARM64_REG_X0) & 0xffffffff
            self.jni_trace.append(
                f"  c8fc: 0xdf08 returned w0={hex(w0)} (will {'continue' if w0 & 1 else 'fail'})"
            )

        def _hook_c8fc_vt_post():
            w0 = self._r(UC_ARM64_REG_X0) & 0xffffffff
            self.jni_trace.append(
                f"  c8fc: vtable[0][3] returned w0={hex(w0)} (will {'continue' if w0 & 1 else 'fail'})"
            )

        def _hook_c8fc_c794_post():
            x0 = self._r(UC_ARM64_REG_X0)
            self.jni_trace.append(
                f"  c8fc: 0xc794 returned x0={hex(x0)}"
            )

        def _hook_c8fc_fail():
            self.jni_trace.append("  c8fc: entering fail branch (X19=NULL)")

        sites = [
            (0x101f8, _hook_101f8_entry),
            (0x102dc, _hook_integrity_result),
            (0x102e8, _hook_actual_loader_entry),
            (0x102ec, _hook_actual_loader_ret),
            (0x10318, _hook_101f8_exit),
            (0xc938,  _hook_c8fc_dl_post),
            (0xc94c,  _hook_c8fc_vt_post),
            (0xc968,  _hook_c8fc_c794_post),
            (0xca08,  _hook_c8fc_fail),
        ]
        for addr, h in sites:
            self.target_hooks[addr] = h
            self.target_hook_lo = min(self.target_hook_lo, addr)
            self.target_hook_hi = max(self.target_hook_hi, addr)

    def _install_arm_a_1_trace_hooks(self, fn_va: int) -> None:
        """Plant target-hooks at the key call sites inside __arm_a_1.

        This helps diagnose whether the inner JNI_OnLoad ever fires, what
        handle the custom dlopen returned, and what the custom dlsym
        resolved.

        We disassemble linearly from `fn_va` for ~1024 bytes and identify:
          - `bl <dlopen-candidate>`  immediately followed by
            `str x0, [x22, #imm]` and `cbz x0, ...`  (handle returner)
          - `bl <dlsym-candidate>` after `adrp x1; add x1, x1, #imm`
            where the resolved string equals "JNI_OnLoad"
          - `blr x8` (or similar) immediately preceded by
            `mov x0, x20; mov x1, x19` (inner JNI_OnLoad invocation)
        """
        try:
            code = bytes(self.uc.mem_read(fn_va, 0x400))
        except UcError:
            return
        # Helpers
        def _is_bl(word: int) -> Tuple[bool, int]:
            op = word >> 26
            if op != 0x25:
                return False, 0
            imm26 = word & 0x3ffffff
            if imm26 & (1 << 25):
                imm26 -= (1 << 26)
            return True, imm26 * 4
        words: List[int] = [
            struct.unpack_from("<I", code, i)[0] for i in range(0, len(code), 4)
        ]
        # Find a pair: blr Xn preceded by `mov x0, x20; mov x1, x19`.
        # encoding of mov x0, x20: ORR x0, xzr, x20 → 0xaa1403e0
        # encoding of mov x1, x19: ORR x1, xzr, x19 → 0xaa1303e1
        MOV_X0_X20 = 0xaa1403e0
        MOV_X1_X19 = 0xaa1303e1
        for i in range(2, len(words) - 1):
            if (words[i - 2] == MOV_X0_X20 and words[i - 1] == MOV_X1_X19
                    and (words[i] & 0xfffffc1f) == 0xd63f0000):   # blr Xn
                site = fn_va + i * 4
                rn = (words[i] >> 5) & 0x1f
                self.jni_trace.append(
                    f"  arm_a_1: inner-JNI_OnLoad invocation site @ {hex(site)} (blr x{rn})"
                )

                def _hook_inner_jni_onload(site=site, rn=rn):
                    target_reg_id = UC_ARM64_REG_X8 if rn == 8 else (
                        UC_ARM64_REG_X16 if rn == 16 else UC_ARM64_REG_X17
                    )
                    target = self._r(target_reg_id) if rn in (8, 16, 17) else 0
                    if not target:
                        # Fallback: read xN by id — we only handle 8/16/17 here.
                        pass
                    arg0 = self._r(UC_ARM64_REG_X0)
                    arg1 = self._r(UC_ARM64_REG_X1)
                    self.jni_trace.append(
                        f"  arm_a_1: INNER JNI_OnLoad called (target={hex(target)} "
                        f"x0={hex(arg0)} x1={hex(arg1)})"
                    )

                self.target_hooks[site] = _hook_inner_jni_onload
                self.target_hook_lo = min(self.target_hook_lo, site)
                self.target_hook_hi = max(self.target_hook_hi, site)
                break

        # Find a `bl <addr>` where the called function is the custom
        # dlsym (0xca38 in the dominant build). The pattern is: an
        # adrp/add for x1 + a literal "JNI_OnLoad" string + bl <fn>.
        # We'll find any bl that's preceded by adrp x1; add x1, ...
        # within the previous 3 words.
        ADRP_X1 = lambda w: (w & 0x9f00001f) == 0x90000001    # adrp x1, ...
        ADD_X1_X1 = lambda w: (w & 0xff8003ff) == 0x91000021  # add x1, x1, ...
        for i in range(2, len(words) - 1):
            ok, off = _is_bl(words[i])
            if not ok:
                continue
            # Check predecessor pattern
            if not (ADRP_X1(words[i - 2]) and ADD_X1_X1(words[i - 1])):
                continue
            # Compute the string address: adrp + (imm21 << 12), then
            # add x1, x1, #imm12.
            adrp = words[i - 2]
            add = words[i - 1]
            site = fn_va + i * 4
            # adrp imm21 (immlo:immhi)
            immlo = (adrp >> 29) & 0x3
            immhi = (adrp >> 5) & 0x7ffff
            imm21 = (immhi << 2) | immlo
            if imm21 & (1 << 20):
                imm21 -= (1 << 21)
            page = ((site - 8) & ~0xfff) + (imm21 << 12)
            imm12 = (add >> 10) & 0xfff
            str_va = page + imm12
            # Read the string from the in-emulator memory at str_va.
            try:
                s = self._read_cstr(str_va, 64)
            except UcError:
                s = ""
            if s == "JNI_OnLoad":
                dlsym_fn = fn_va + i * 4 + off
                self.jni_trace.append(
                    f"  arm_a_1: dlsym(handle, 'JNI_OnLoad') @ {hex(site)} → fn={hex(dlsym_fn)}"
                )

                def _hook_dlsym_jni_onload(dlsym_fn=dlsym_fn):
                    handle = self._r(UC_ARM64_REG_X0)
                    self.jni_trace.append(
                        f"  arm_a_1: dlsym entered with handle={hex(handle)} name='JNI_OnLoad'"
                    )

                # Hook the call site itself.
                self.target_hooks[site] = _hook_dlsym_jni_onload
                self.target_hook_lo = min(self.target_hook_lo, site)
                self.target_hook_hi = max(self.target_hook_hi, site)
                # Hook the return point too (the `mov x8, x0` immediately
                # after the dlsym call) to observe what dlsym returned.
                ret_site = site + 4
                if ret_site < fn_va + len(code):
                    def _hook_dlsym_ret(ret_site=ret_site):
                        rv = self._r(UC_ARM64_REG_X0)
                        self.jni_trace.append(
                            f"  arm_a_1: dlsym returned fn={hex(rv)} @ {hex(ret_site)}"
                        )
                    self.target_hooks[ret_site] = _hook_dlsym_ret
                    self.target_hook_lo = min(self.target_hook_lo, ret_site)
                    self.target_hook_hi = max(self.target_hook_hi, ret_site)
                break

    def _list_exports(self, prefix: str = "") -> List[Tuple[str, int]]:
        """Return [(name, vaddr), ...] for all exports starting with `prefix`."""
        data = self.so
        layout = self.layout
        sym_off = _va_to_off(layout["segments"], layout["symtab_va"])
        str_off = _va_to_off(layout["segments"], layout["strtab_va"])
        if sym_off is None or str_off is None:
            return []
        out: List[Tuple[str, int]] = []
        for i in range(layout["nchain"]):
            e = data[sym_off + i*24 : sym_off + i*24 + 24]
            name_off, info, other, shndx, value, size = struct.unpack("<IBBHQQ", e)
            if not (name_off and value):
                continue
            end = data.index(b"\x00", str_off + name_off)
            nm = data[str_off + name_off:end].decode("latin-1", errors="replace")
            if prefix and not nm.startswith(prefix):
                continue
            out.append((nm, value))
        return out

    # -- Phase 2: ART runtime callback replication ---------------------------
    # After JNI_OnLoad returns, the real Android runtime would invoke the
    # StubApp Application's `attachBaseContext` and `onCreate` methods. Both
    # call into native: interface5, interface99, interface8 (from attach),
    # then interface21, interface7 (from onCreate via ChangeTopApplication).
    #
    # The outer JNI_OnLoad in Jiagu *does not* call RegisterNatives — the
    # registration happens only when the second-stage loader is invoked.
    # That second stage is the exported `_Z9__arm_a_1P7_JavaVMP7_JNIEnvPvRi`
    # ("__arm_a_1(JavaVM*, JNIEnv*, void*, int&)") C++ entry point. It
    # internally calls a custom dlopen-equivalent and then dlsym's
    # "JNI_OnLoad" on the loaded handle — the inner JNI_OnLoad is what
    # actually performs RegisterNatives and may emit DefineClass calls
    # that capture the recovered DEX.
    #
    # This module's `call_arm_a_1` mirrors that runtime call by invoking
    # `__arm_a_1` with the JavaVM*/JNIEnv* we set up for the outer
    # JNI_OnLoad. The same JNI mock surface drives the inner SO.

    def _install_mock_inner_so(self) -> None:
        """Patch the inner-SO loader so phase-2 can flow past the
        custom-ELF-mapper.

        The dominant v1.4.0.4 SO has a multi-stage custom ELF mapper at
        `0xc8fc` whose terminal step `bl 0xc794` parses an embedded
        ~780 KB payload at vaddr 0x70250. Static-only emulation of that
        parser would require also reproducing the loader's C++ TLS guard
        machinery (which depends on per-build keys we don't have).

        This mock takes a shortcut: it installs target-hooks that
        intercept `0xc8fc`'s entry and force it to return a sentinel
        non-NULL handle. The same mock then intercepts `0xca38` ("custom
        dlsym") so that when it's called with name="JNI_OnLoad" it
        returns a stub trampoline address. The trampoline, when invoked
        via the `blr x8` at 0x11e6c, captures `(JavaVM*, void*)` and
        immediately RETs.

        Together this lets us SEE what __arm_a_1 attempts next, even
        though no inner-SO bytes are actually mapped. The mode is
        opt-in via `mock_inner_so=True`; default phase-2 runs without it.
        """
        # Sentinel handle. Any non-zero pointer-shaped value works; we
        # use a recognisable constant.
        SENTINEL_HANDLE = 0xdeadbeefdead_0010 & 0xffffffffffffffff
        self._mock_inner_so_handle = SENTINEL_HANDLE

        def _hook_c8fc_force_success():
            # Force `bl 0xc8fc` to return SENTINEL_HANDLE immediately.
            # The target-hook fires on the *first instruction* of 0xc8fc,
            # which is `sub sp, sp, #0x40`. At that point LR (X30) holds
            # the caller's return address — branching directly there
            # effectively makes the call a no-op that returns
            # SENTINEL_HANDLE.
            self._w(UC_ARM64_REG_X0, SENTINEL_HANDLE)
            lr = self._r(UC_ARM64_REG_X30)
            self._w(UC_ARM64_REG_PC, lr)
            self.jni_trace.append(
                f"  [mock_inner_so] 0xc8fc → forcing return handle={hex(SENTINEL_HANDLE)} (lr={hex(lr)})"
            )

        def _hook_ca38_force_resolve():
            # `bl 0xca38(handle, name)` is the custom dlsym. We intercept
            # before any of its body runs and forward to LR directly,
            # supplying our desired X0 return value.
            name = self._read_cstr(self._r(UC_ARM64_REG_X1))
            # Persist every name requested — this IS the inner SO's
            # required export surface, which is high-value forensic data.
            if not hasattr(self, "inner_so_required_symbols"):
                self.inner_so_required_symbols: List[str] = []
            if name and name not in self.inner_so_required_symbols:
                self.inner_so_required_symbols.append(name)
            if name == "JNI_OnLoad":
                stub_addr = self._alloc_stub(
                    "INNER_JNI_OnLoad", self._inner_jni_onload_stub
                )
                self.jni_trace.append(
                    f"  [mock_inner_so] 0xca38('JNI_OnLoad') → "
                    f"INNER_JNI_OnLoad stub @ {hex(stub_addr)}"
                )
                self._w(UC_ARM64_REG_X0, stub_addr)
            else:
                self.jni_trace.append(
                    f"  [mock_inner_so] 0xca38({name!r}) → 0 (not handled)"
                )
                self._w(UC_ARM64_REG_X0, 0)
            lr = self._r(UC_ARM64_REG_X30)
            self._w(UC_ARM64_REG_PC, lr)

        self.target_hooks[0xc8fc] = _hook_c8fc_force_success
        self.target_hooks[0xca38] = _hook_ca38_force_resolve
        self.target_hook_lo = min(self.target_hook_lo, 0xc8fc)
        self.target_hook_hi = max(self.target_hook_hi, 0xca38)

    def _inner_jni_onload_stub(self):
        """Trap-handler for the synthetic inner JNI_OnLoad stub.

        The outer SO's `__arm_a_1` calls this with `(x0=JavaVM*, x1=void*)`.
        Inside a real run this would invoke the inner SO's JNI_OnLoad which
        would call RegisterNatives + possibly DefineClass. Here we just
        record the call; downstream `call_registered_natives_lifecycle`
        will report no methods registered, which is fine — the harness's
        purpose at this stage is to expose the surface to a future
        inner-SO recoverer.
        """
        x0 = self._r(UC_ARM64_REG_X0)
        x1 = self._r(UC_ARM64_REG_X1)
        self.inner_jni_onload_invoked = True
        self.jni_trace.append(
            f"  [mock_inner_so] INNER_JNI_OnLoad invoked: jvm={hex(x0)} reserved={hex(x1)}"
        )
        # Return JNI_VERSION_1_6 = 0x00010006
        return 0x00010006

    def call_arm_a_1(self, max_insns: int = 50_000_000,
                     mock_inner_so: bool = False) -> bool:
        """Invoke `__arm_a_1(JavaVM*, JNIEnv*, void*, int&)`.

        Parameters
        ----------
        max_insns : int
            Instruction budget for the call.
        mock_inner_so : bool
            If True, install a target-hook that bypasses the inner-SO
            loader (which can't run statically without per-build keys)
            and forces it to return a sentinel handle. See
            `_install_mock_inner_so` for details.

        Returns True if the call ran and the SO returned cleanly; False
        if the export was not found or the call errored.
        """
        # The C++ mangled name in the libjiagu_a64.so exports:
        candidates = (
            "_Z9__arm_a_1P7_JavaVMP7_JNIEnvPvRi",
            "_Z9__arm_a_1P7_JavaVMP7_JNIEnvPvPi",        # int* vs int& (paranoia)
        )
        va = 0
        for nm in candidates:
            va = self._find_export(nm)
            if va:
                break
        if not va:
            # Try a prefix sweep for any __arm_a_1 mangling.
            for nm, v in self._list_exports("_Z9__arm_a_1"):
                va = v
                break
        if not va:
            self.jni_trace.append("__arm_a_1: export not found")
            return False
        self.jni_trace.append(f"__arm_a_1: invoking @ {hex(va)}")
        # Install a dense execution trace for the first 1 KB of
        # __arm_a_1's body so we can reconstruct which code path it took.
        try:
            self._install_arm_a_1_dense_trace(va, 0x400)
        except Exception as ex:                          # noqa: BLE001
            self.errors.append(f"_install_arm_a_1_dense_trace: {ex!r}")
        # Also instrument the inner SO loader (0x101f8) to see whether the
        # BMP-integrity check passes and what the SO loader returns.
        try:
            self._install_inner_loader_trace()
        except Exception as ex:                          # noqa: BLE001
            self.errors.append(f"_install_inner_loader_trace: {ex!r}")
        if mock_inner_so:
            try:
                self._install_mock_inner_so()
            except Exception as ex:                      # noqa: BLE001
                self.errors.append(f"_install_mock_inner_so: {ex!r}")
        # Discover and install tracing hooks at the key points inside
        # __arm_a_1's body so we can see whether the inner JNI_OnLoad
        # fires. The disassembly pattern from the v1.4.0.4 dominant SO is:
        #
        #   bl 0x101f8         (custom dlopen — returns handle)
        #   str x0, [x22, #0x90]
        #   cbz x0, end
        #   bl 0x10330 / 0x10474 / 0x10dc8 / 0x1116c / 0x10660  (init)
        #   ldr x0, [x22, #0x90]
        #   adrp x1, .rodata ; add x1, x1, #imm        ; x1 = "JNI_OnLoad"
        #   bl 0xca38                                   (custom dlsym)
        #   cbz x0, end
        #   mov x8, x0
        #   mov x0, x20                                 ; X0 = JavaVM*
        #   mov x1, x19                                 ; X1 = void* arg
        #   blr x8                                      ; inner JNI_OnLoad
        #
        # Scan __arm_a_1's body for the `blr x8` pattern immediately
        # preceded by `mov x0, x20; mov x1, x19` — that's the inner
        # JNI_OnLoad invocation site.
        try:
            self._install_arm_a_1_trace_hooks(va)
        except Exception as ex:                          # noqa: BLE001
            self.errors.append(f"_install_arm_a_1_trace_hooks: {ex!r}")
        sentinel = self.stub_addr_by_name.get("__sentinel__")
        if sentinel is None:
            sentinel = EMU_STUB_BASE + EMU_STUB_SIZE - 0x10
            self.uc.mem_write(sentinel, _brk(0xfffe))
            self.stub_table[0xfffe] = ("__sentinel__", self._stub_sentinel)
            self.stub_addr_by_name["__sentinel__"] = sentinel
        # Stack slot for the `int&` return parameter — handed to X3.
        ret_slot = self._alloc_heap(8, align=8)
        try:
            self.uc.mem_write(ret_slot, b"\x00" * 8)
        except UcError:
            pass
        # Args:
        #   X0 = JavaVM*
        #   X1 = JNIEnv*
        #   X2 = void* arg (use NULL — real ART passes a JNI reserved value)
        #   X3 = int& (pointer to int return slot)
        self._w(UC_ARM64_REG_X0, self.JAVAVM_PTR_ADDR)
        self._w(UC_ARM64_REG_X1, self.JNIENV_PTR_ADDR)
        self._w(UC_ARM64_REG_X2, 0)
        self._w(UC_ARM64_REG_X3, ret_slot)
        self._w(UC_ARM64_REG_X30, sentinel)
        self._w(UC_ARM64_REG_SP, EMU_STACK_BASE + EMU_STACK_SIZE - 0x200)
        self._w(UC_ARM64_REG_PC, va)
        try:
            self.uc.emu_start(va, sentinel, timeout=120_000_000, count=max_insns)
            self.jni_trace.append(
                f"__arm_a_1: returned (int_ret={int.from_bytes(bytes(self.uc.mem_read(ret_slot, 4)),'little')})"
            )
            # Dump the dense trace (unique addresses visited in __arm_a_1
            # body, in first-visit order). Useful for understanding where
            # the path divergence happened.
            trace = getattr(self, "arm_a_1_trace", [])
            if trace:
                self.jni_trace.append(f"  arm_a_1: visited {len(trace)} unique insns")
                self.jni_trace.append(
                    "  arm_a_1: first-30="
                    + ",".join(hex(a) for a, _ in trace[:30])
                )
                if len(trace) > 30:
                    self.jni_trace.append(
                        "  arm_a_1: last-30="
                        + ",".join(hex(a) for a, _ in trace[-30:])
                    )
            return True
        except UcError as e:
            self.errors.append(f"__arm_a_1: {e}")
            self.jni_trace.append(f"__arm_a_1: UC error: {e}")
            return False

    def call_arm_a_noarg(self, mangled: str, max_insns: int = 50_000_000) -> bool:
        """Invoke a no-arg `__arm_a_*v` C++ entry point by mangled name.

        These are part of Jiagu's C++ entry-point cluster and may perform
        secondary RegisterNatives / lifecycle setup. Best-effort: returns
        True on clean RET; False on missing export or UC error.
        """
        va = self._find_export(mangled)
        if not va:
            self.jni_trace.append(f"{mangled}: export not found")
            return False
        sentinel = self.stub_addr_by_name.get("__sentinel__")
        if sentinel is None:
            return False
        self._w(UC_ARM64_REG_X0, 0)
        self._w(UC_ARM64_REG_X1, 0)
        self._w(UC_ARM64_REG_X30, sentinel)
        self._w(UC_ARM64_REG_SP, EMU_STACK_BASE + EMU_STACK_SIZE - 0x200)
        self._w(UC_ARM64_REG_PC, va)
        self.jni_trace.append(f"{mangled}: invoking @ {hex(va)}")
        try:
            self.uc.emu_start(va, sentinel, timeout=120_000_000, count=max_insns)
            self.jni_trace.append(f"{mangled}: returned")
            return True
        except UcError as e:
            self.errors.append(f"{mangled}: {e}")
            self.jni_trace.append(f"{mangled}: UC error: {e}")
            return False

    def call_registered_natives_lifecycle(
        self,
        package_name: str = "",
        max_insns_per_call: int = 50_000_000,
    ) -> None:
        """Invoke the StubApp lifecycle natives in attach→create order.

        The Java lifecycle is:
          attachBaseContext(context):
            DtcLoader.init()
            interface5(this)
            -- inner Application created via reflection --
            interface99(inner_app)
            interface8(inner_app, context)

          onCreate():
            super.onCreate()
            ChangeTopApplication():
              interface7(inner_app, context)
            inner_app.onCreate()
            interface21(inner_app)

        We invoke each in order, passing dummy jobject references for
        Application and Context. RegisterNatives needs to have populated
        `self.registered_natives` first; if it didn't fire, we fall back
        to invoking the `__arm_a_*` exports directly (they're the
        underlying dispatchers).
        """
        if not hasattr(self, "registered_natives"):
            self.registered_natives = {}
        registered = self.registered_natives.get("com/stub/StubApp", [])
        if not registered:
            # Fallback: scan all classes for known interface names.
            for cls, lst in self.registered_natives.items():
                if any(nm.startswith("interface") for nm, _, _ in lst):
                    registered = lst
                    break
        # Fake jobjects we'll pass as Application + Context.
        # Reuse the existing jobject map.
        if not hasattr(self, "jobjects"):
            self.jobjects = {}
        app_obj = self._new_jobject("Application", name="StubApp")
        ctx_obj = self._new_jobject("Context", name="StubAppContext",
                                    package_name=package_name)

        sentinel = self.stub_addr_by_name.get("__sentinel__")
        if sentinel is None:
            return

        def _call_native(label: str, fn_va: int, args: List[int]) -> None:
            if not fn_va:
                self.jni_trace.append(f"{label}: no fn pointer")
                return
            # JNI calling convention on ARM64:
            #   X0 = JNIEnv*
            #   X1 = jclass (for static) / jobject (for instance)
            #   X2.. = Java args
            self._w(UC_ARM64_REG_X0, self.JNIENV_PTR_ADDR)
            # The StubApp natives are static; X1 = jclass for StubApp.
            stub_cls = 0
            for k, v in self.jobjects.items():
                if v.get("name") == "com/stub/StubApp":
                    stub_cls = k
                    break
            if not stub_cls:
                stub_cls = self._new_jobject("class", name="com/stub/StubApp")
            self._w(UC_ARM64_REG_X1, stub_cls)
            arg_regs = [UC_ARM64_REG_X2, UC_ARM64_REG_X3, UC_ARM64_REG_X4,
                        UC_ARM64_REG_X5, UC_ARM64_REG_X6, UC_ARM64_REG_X7]
            for i, a in enumerate(args[:6]):
                self._w(arg_regs[i], a)
            self._w(UC_ARM64_REG_X30, sentinel)
            self._w(UC_ARM64_REG_SP, EMU_STACK_BASE + EMU_STACK_SIZE - 0x200)
            self._w(UC_ARM64_REG_PC, fn_va)
            self.jni_trace.append(f"{label}: calling fn @ {hex(fn_va)} "
                                  f"(jenv={hex(self.JNIENV_PTR_ADDR)})")
            try:
                self.uc.emu_start(fn_va, sentinel, timeout=60_000_000,
                                  count=max_insns_per_call)
                self.jni_trace.append(f"{label}: returned")
            except UcError as e:
                self.errors.append(f"{label}: {e}")
                self.jni_trace.append(f"{label}: UC error: {e}")

        # Build a lookup by name.
        by_name = {nm: (sg, fv) for nm, sg, fv in registered}

        # attachBaseContext-order
        for nm, args in [
            ("interface5",  [app_obj]),
            ("interface99", [app_obj]),
            ("interface8",  [app_obj, ctx_obj]),
        ]:
            if nm in by_name:
                sg, fv = by_name[nm]
                _call_native(f"StubApp.{nm}({sg})", fv, args)
            else:
                self.jni_trace.append(f"StubApp.{nm}: not in RegisterNatives table")

        # onCreate-order
        for nm, args in [
            ("interface21", [app_obj]),
            ("interface7",  [app_obj, ctx_obj]),
        ]:
            if nm in by_name:
                sg, fv = by_name[nm]
                _call_native(f"StubApp.{nm}({sg})", fv, args)
            else:
                self.jni_trace.append(f"StubApp.{nm}: not in RegisterNatives table")


# ---- Public entry point ----------------------------------------------------

def emulate_libjiagu(so_path: str,
                     asset_paths: Optional[Dict[str, str]] = None,
                     *,
                     package_name: Optional[str] = None,
                     apk_md5: Optional[str] = None,
                     signing_cert: Optional[bytes] = None,
                     asset_bytes: Optional[Dict[str, bytes]] = None,
                     max_instructions: int = 50_000_000,
                     run_art_callbacks: bool = True,
                     mock_inner_so: bool = False,
                     verbose: bool = False) -> EmulationResult:
    """Run libjiagu_a64.so under Unicorn and capture decrypted payloads.

    Parameters
    ----------
    so_path : str
        Path to the SO file (typically `assets/libjiagu_a64.so`).
    asset_paths : Optional[Dict[str, str]]
        Optional mapping of synthetic-FS path → real file path. The
        emulator's `open()` will look up paths here; useful for
        seeding the SO with the encrypted DEX asset.
    package_name : Optional[str]
        The app's package name (e.g. `"com.example.app"`). Returned
        when the loader calls `GetStringUTFChars(packageName)`. Reading
        the package name is the loader's first per-build seed for the
        key derivation; without it the bring-up stalls.
    apk_md5 : Optional[str]
        The APK file's MD5 (hex), seeded into corresponding strings.
    signing_cert : Optional[bytes]
        Raw bytes of the APK signing certificate (DER), returned
        when the loader fetches its byte-array.
    asset_bytes : Optional[Dict[str, bytes]]
        Mapping of asset name → raw bytes, returned when the loader
        opens the asset via AssetManager.open + InputStream.read.
        For Jiagu this should contain the inner libjiagu*.so payload.
    max_instructions : int
        Per-call instruction budget. Defaults to 50 M (generous).
    verbose : bool
        Print per-init-entry progress to stdout.

    Returns
    -------
    EmulationResult
    """
    if not HAS_UNICORN:
        return EmulationResult(status="unicorn_missing",
                               error=f"unicorn import failed: {_IMPORT_ERROR}")
    so_bytes = Path(so_path).read_bytes()
    layout = _parse_so_layout(so_bytes)
    if layout is None:
        return EmulationResult(status="invalid_so",
                               error="not a recognised AArch64 ELF")

    emu = _Emulator(so_bytes, layout, verbose)
    if asset_paths:
        emu.set_asset_fs({k: Path(v).read_bytes() for k, v in asset_paths.items()})
    # Per-build injection points the loader reads on its way to the DEX
    # decrypt path. See JNI handler bodies for how each one feeds back.
    emu.injected_package_name = package_name or ""
    emu.injected_apk_md5 = apk_md5 or ""
    emu.injected_signing_cert = signing_cert or b""
    emu.injected_asset_bytes = dict(asset_bytes or {})
    emu.injected_apk_path = ""                       # set later if backend passes it
    if asset_paths:
        # Use the first asset_paths entry as the synthetic APK path.
        emu.injected_apk_path = next(iter(asset_paths.keys()), "")

    t0 = time.time()
    emu.uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM | UC_MODE_LITTLE_ENDIAN)

    # ---- Dynamic cipher hook setup --------------------------------------
    # Use the static-cipher module to locate this SO's specific RC4-PRGA
    # and SIMD-XOR exit points (varies per build). The PRGA exit is where
    # x0 (input/output buffer post-decryption) is valid. The SIMD-XOR exit
    # is where x21 (output buffer) and x20 (length) are valid.
    try:
        from . import jiagu_static_cipher as jsc
        rc4s = jsc.find_rc4_prga(so_bytes)
        simd_xors = jsc.find_simd_xor(so_bytes)
    except Exception:
        rc4s = []
        simd_xors = []

    # Per-capture caps to prevent OOM. Captures > IRL_CAP retained as
    # metadata only; under IRL_CAP fully preserved.
    # The SIMD-XOR cipher empirically yields a single very large output per
    # JNI bring-up (~30 MB on bantang, the bulk-DEX decrypt) so we need a
    # generous cap. RC4 outputs are mid-sized (≤ 2 MB). 100 captures is more
    # than the loader will ever emit in a single run.
    SIMD_MAX_CAP_BYTES = 0x4000_000          # 64 MB per SIMD capture (bulk DEX path)
    RC4_MAX_CAP_BYTES = 0x400_000            # 4 MB per RC4 capture
    MAX_CAPS_PER_KIND = 100

    def _capture_xor_output():
        if len(emu.xor_decrypt_captures) >= MAX_CAPS_PER_KIND:
            return
        try:
            x21 = emu.uc.reg_read(UC_ARM64_REG_X21)
            x20 = emu.uc.reg_read(UC_ARM64_REG_X20)
            if x21 and x20 and x20 < 0x4000_0000:    # sanity: < 1 GB
                buf = bytes(emu.uc.mem_read(x21, min(x20, SIMD_MAX_CAP_BYTES)))
                emu.xor_decrypt_captures.append((x21, x20, buf))
                if len(emu.xor_decrypt_captures) < 20:
                    emu.jni_trace.append(
                        f"xor_cipher_capture: buf={hex(x21)} len={x20} "
                        f"first8={buf[:8].hex()}"
                    )
        except Exception:                            # noqa: BLE001
            pass

    def _capture_rc4_output():
        if not hasattr(emu, "_rc4_call_stack"):
            emu._rc4_call_stack = []
            emu.rc4_captures: List[Tuple[int, int, bytes]] = []
        if not emu._rc4_call_stack:
            return
        buf_addr, length = emu._rc4_call_stack.pop()
        if length <= 0 or length > 0x4000_0000:
            return
        if len(emu.rc4_captures) >= MAX_CAPS_PER_KIND:
            return
        try:
            data = bytes(emu.uc.mem_read(buf_addr, min(length, RC4_MAX_CAP_BYTES)))
            emu.rc4_captures.append((buf_addr, length, data))
            if len(emu.rc4_captures) < 20:
                emu.jni_trace.append(
                    f"rc4_capture: buf={hex(buf_addr)} len={length} "
                    f"first8={data[:8].hex()}"
                )
        except Exception:                            # noqa: BLE001
            pass

    def _record_rc4_entry():
        if not hasattr(emu, "_rc4_call_stack"):
            emu._rc4_call_stack = []
            emu.rc4_captures: List[Tuple[int, int, bytes]] = []
        x0 = emu.uc.reg_read(UC_ARM64_REG_X0)
        x1 = emu.uc.reg_read(UC_ARM64_REG_X1)
        emu._rc4_call_stack.append((x0, x1))

    # Install hooks. Fall back to the prior session's hardcoded 0xd704
    # when the static finder finds nothing (paranoia).
    hook_addrs: List[int] = []
    for s in simd_xors:
        if s.simd_exit_va:
            emu.target_hooks[s.simd_exit_va] = _capture_xor_output
            hook_addrs.append(s.simd_exit_va)
    for r in rc4s:
        if r.prologue_va:
            emu.target_hooks[r.prologue_va] = _record_rc4_entry
            hook_addrs.append(r.prologue_va)
        if r.loop_end_va:
            emu.target_hooks[r.loop_end_va] = _capture_rc4_output
            hook_addrs.append(r.loop_end_va)
    if not hook_addrs:
        emu.target_hooks[0xd704] = _capture_xor_output
        hook_addrs.append(0xd704)
    emu.target_hook_lo = min(hook_addrs)
    emu.target_hook_hi = max(hook_addrs)

    try:
        emu.boot()
        emu.install_jni_mocks()
        emu.run_init_array(max_instructions)
        # Then call JNI_OnLoad. Most builds short-circuit early on anti-debug
        # checks; we let the emulator run until the sentinel or UC error.
        emu.call_jni_onload(max_instructions)
        # ---- Phase 2: ART callback replication --------------------------
        # In a real Android runtime, after System.load() returns, the JVM
        # would call back into the native through the lifecycle natives
        # registered via RegisterNatives. Jiagu defers RegisterNatives to
        # the second-stage entry point `__arm_a_1`. Invoking it manually
        # replicates the runtime ART callback path that Jiagu's outer
        # JNI_OnLoad alone does not trigger.
        if run_art_callbacks:
            emu.jni_trace.append("---- PHASE 2: ART callback replication ----")
            emu.call_arm_a_1(max_instructions, mock_inner_so=mock_inner_so)
            # Exercise the other arm_a_* exports too — these are
            # called by Java in builds that don't dispatch via
            # __arm_a_1 alone. They take no JNI args and so are
            # safe to invoke speculatively.
            emu.call_arm_a_noarg("_Z9__arm_a_0v",   max_instructions)
            emu.call_arm_a_noarg("_Z10__arm_a_20v", max_instructions)
            emu.call_arm_a_noarg("_Z10__arm_a_21v", max_instructions)
            # After __arm_a_1 runs, the inner SO's JNI_OnLoad should have
            # called RegisterNatives. We can then drive the StubApp Java
            # lifecycle natives in attach→create order.
            emu.call_registered_natives_lifecycle(
                package_name=emu.injected_package_name,
                max_insns_per_call=max_instructions,
            )
    except UcError as e:
        emu.errors.append(f"uc error: {e}")
    elapsed = time.time() - t0

    # Final pass: scan the heap and PT_LOAD regions for DEX magic written by
    # the loader (whether or not DefineClass was called).
    scan_regions = [
        (EMU_HEAP_BASE,    EMU_HEAP_SIZE),
        (EMU_FAKE_FS_BASE, EMU_FAKE_FS_SIZE),
    ]
    for s in layout["segments"]:
        scan_regions.append((s["vaddr"] & ~0xfff,
                             ((s["vaddr"] + s["memsz"] + 0xfff) & ~0xfff) - (s["vaddr"] & ~0xfff)))
    # Don't scan the giant heap if we already captured DEX via DefineClass.
    if not emu.dex_payloads:
        carved = emu._scan_memory_for_dex(scan_regions)
        emu.dex_payloads.extend(carved)
        if carved:
            emu.jni_trace.append(f"memory-scan: found {len(carved)} DEX payloads")

    # Promote XOR-decrypt captures to dex_payloads if they look like DEX
    # (or contain DEX magic somewhere). Otherwise expose via decrypted_buffers.
    for va, size, buf in emu.xor_decrypt_captures:
        emu.decrypted_buffers.append((va, size, buf))
        # Look for DEX magic inside the buffer
        if b"dex\n" in buf[:0x40]:
            emu.dex_payloads.append(buf)
        elif b"dex\n" in buf:
            # carve at the first dex\n
            pos = buf.index(b"dex\n")
            if pos + 0x70 <= len(buf):
                fsz = struct.unpack_from("<I", buf, pos + 0x20)[0]
                if 0x70 <= fsz <= len(buf) - pos:
                    emu.dex_payloads.append(buf[pos:pos + fsz])

    # Also promote RC4 captures: their payload may be a `[u32 LE length][zlib]`
    # container (observed in v1.4.0.4 builds — the zlib stream decompresses
    # to ~1.78 MB of loader working data + an embedded 284-byte stub DEX,
    # plus the loader's strings table). Auto-detect the format and capture
    # all DEX magic occurrences.
    if hasattr(emu, "rc4_captures"):
        import zlib
        for va, size, buf in emu.rc4_captures:
            emu.decrypted_buffers.append((va, size, buf))
            # Direct DEX magic in head
            if b"dex\n" in buf[:0x40]:
                emu.dex_payloads.append(buf)
                continue
            # Try as [length:u32 LE][zlib] container
            if len(buf) > 6 and buf[4] == 0x78 and buf[5] in (0x9c, 0xda, 0x01, 0x5e):
                try:
                    dec = zlib.decompress(buf[4:])
                    # Search for DEX magic in decompressed
                    for off in range(0, len(dec) - 0x70):
                        if dec[off:off+4] != b"dex\n":
                            continue
                        fsz = struct.unpack_from("<I", dec, off + 0x20)[0]
                        hsz = struct.unpack_from("<I", dec, off + 0x24)[0]
                        eend = struct.unpack_from("<I", dec, off + 0x28)[0]
                        if hsz == 0x70 and eend == 0x12345678 and 0x70 <= fsz <= len(dec) - off:
                            emu.dex_payloads.append(dec[off:off+fsz])
                except Exception:                    # noqa: BLE001
                    pass

    status = "ok" if not emu.errors else "uc_error"
    if emu.dex_payloads:
        status = "ok"
    elif status == "ok":
        status = "no_dex"
    return EmulationResult(
        status=status,
        dex_payloads=emu.dex_payloads,
        decrypted_buffers=emu.decrypted_buffers,
        rc4_captures=list(getattr(emu, "rc4_captures", [])),
        xor_captures=list(getattr(emu, "xor_decrypt_captures", [])),
        syscall_trace=emu.syscall_trace,
        jni_trace=emu.jni_trace,
        insns_executed=emu.insns_executed,
        elapsed_sec=elapsed,
        error="; ".join(emu.errors[:5]) if emu.errors else "",
        registered_natives=getattr(emu, "registered_natives", {}),
        art_callbacks_invoked=run_art_callbacks,
        inner_so_required_symbols=list(
            getattr(emu, "inner_so_required_symbols", []) or []
        ),
        inner_jni_onload_invoked=bool(
            getattr(emu, "inner_jni_onload_invoked", False)
        ),
    )
