//! Faithful Rust port of `dex/instructions_new.py`'s per-family
//! `execute()` methods.
//!
//! ## Why this exists
//!
//! The original Rust VM (`vm::execute_instruction`) was a *partial*
//! centralised dispatch — only the opcodes its initial test corpus
//! needed. Everything else fell through to a silent `Continue`,
//! which is why heavily-obfuscated APKs (Aurora, dualtext) couldn't
//! run methods that lean on long-arithmetic / type-conversion /
//! array / field ops.
//!
//! This module ports the Python reference implementation
//! family-by-family so we get parity with what the Python VM
//! produces, including its known quirks (which the Python codebase
//! has spent years matching against real APK output — divergence
//! from the reference is a regression even when "more correct" in
//! the AOSP-spec sense).
//!
//! ## Storage model
//!
//! Matches Python: **wide values occupy two consecutive register
//! slots** with the high 32 bits in `regs[N]` and the low 32 bits
//! in `regs[N+1]`. Combining is `(regs[N] << 32) | regs[N+1]`. This
//! divergence from the previous single-i64-in-lower-slot model is
//! load-bearing: the register-pane visualization, the
//! cross-implementation diff between Python and Rust, and the
//! debugger's "watch register" feature all depend on slot semantics
//! matching what the bytecode references.
//!
//! ## Per-family dispatch surface
//!
//! Each family exposes `pub fn execute(&Instruction, &mut Registers,
//! &mut Memory) -> InstrResult`. `vm::execute_instruction` calls
//! into the appropriate family fn based on opcode range and
//! propagates the returned `InstrResult` to the dispatch loop —
//! same control-flow contract as the inline implementation.

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};
use platypus_dex::instructions::Instruction;

pub mod arrayop;
pub mod binop;
pub mod binop_2addr;
pub mod binop_lit;
pub mod cmp;
pub mod control;
pub mod helpers;
pub mod iop;
pub mod misc;
pub mod unop;

// ─── Type-level shorthand ────────────────────────────────────────────────

/// `(operator_type, operand_type)` for the binary-op families. The
/// operand type drives 32-bit vs 64-bit storage; the operator type
/// drives the actual computation in `helpers::reg_ops_helper`.
pub type BinDispatch = (u8, u8);

// ─── Register read/write primitives ──────────────────────────────────────
//
// These mirror Python's untyped-register convention: every slot
// holds either Some(Value::Int(i64)) or None. We project values
// through small helpers so the per-family code stays readable.

/// Read a slot as `i64`. `None` slots and non-int values become 0
/// (matches Python `int(reg) if reg else 0`).
pub fn read_int(regs: &Registers, idx: u32) -> i64 {
    regs.get(idx as usize)
        .and_then(|v| v.as_ref())
        .and_then(|v| v.as_int())
        .unwrap_or(0)
}

/// Read a slot as `Option<Value>` — preserves Null / Str / Array /
/// Bytes when ops need to pass references through (the Move /
/// MoveResult / array-of-objects paths).
pub fn read_val(regs: &Registers, idx: u32) -> Option<Value> {
    regs.get(idx as usize).and_then(|v| v.clone())
}

/// Write an i64 into a single slot. Used by 32-bit arithmetic and
/// the high half of wide writes.
pub fn write_int(regs: &mut Registers, idx: u32, val: i64) {
    if let Some(slot) = regs.get_mut(idx as usize) {
        *slot = Some(Value::Int(val));
    }
}

/// Write any Value into a slot. Used by Move / MoveResult / array
/// loads that need to preserve non-Int types.
pub fn write_val(regs: &mut Registers, idx: u32, val: Value) {
    if let Some(slot) = regs.get_mut(idx as usize) {
        *slot = Some(val);
    }
}

// ─── Wide value pack / unpack ────────────────────────────────────────────
//
// Python convention:
//   long_value = (regs[N] << 32) | regs[N+1]
// where regs[N] is the high 32 bits and regs[N+1] is the low 32
// bits. After a wide computation:
//   regs[N]   = (result >> 32) & 0xFFFFFFFF   # high half (signed-ish)
//   regs[N+1] = result & 0xFFFFFFFF           # low half (unsigned 32-bit)
//
// Note that Python's `(high << 32) | low` reconstructs the bit
// pattern verbatim; the *interpretation* (signed vs unsigned) is
// left to the consumer. Most consumers treat the 64-bit result as
// signed i64.

/// Read a wide (long/double) value spanning `regs[idx]` and
/// `regs[idx+1]`. Returns the reconstituted i64.
///
/// Matches Python `(regs[N] << 32) | regs[N+1]` with the caveat
/// that the high half is treated as i32 to sign-extend correctly.
pub fn read_wide(regs: &Registers, idx: u32) -> i64 {
    let high = read_int(regs, idx) as i32 as i64;    // sign-extend low 32 of high slot
    let low  = (read_int(regs, idx + 1) as u32) as i64; // zero-extend low 32 of low slot
    (high << 32) | low
}

/// Read a wide value using Python's `or` semantics. Python's
/// `(reg[N] << 32) or reg[N+1]` returns the first *truthy* value —
/// if the high half is non-zero it's used as-is (low half discarded!);
/// only when the high half is zero does it fall through to the low
/// half. This is almost certainly a Python bug but it's also what
/// the reference implementation does, and several real-APK paths
/// depend on the resulting numeric output.
pub fn read_wide_python_or(regs: &Registers, idx: u32) -> i64 {
    let high = read_int(regs, idx) as i32 as i64;
    if high != 0 {
        high << 32
    } else {
        (read_int(regs, idx + 1) as u32) as i64
    }
}

/// Write a wide value to `regs[idx]` (high) and `regs[idx+1]` (low).
pub fn write_wide(regs: &mut Registers, idx: u32, val: i64) {
    let high = (val >> 32) as i32 as i64;       // sign-extended high
    let low  = ((val as u64) & 0xFFFFFFFF) as i64; // unsigned low
    write_int(regs, idx, high);
    write_int(regs, idx + 1, low);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;

    fn make(values: &[i64]) -> Registers {
        values.iter().map(|n| Some(Value::Int(*n))).collect()
    }

    #[test]
    fn read_int_extracts_value_or_zero() {
        let regs = make(&[42, -1]);
        assert_eq!(read_int(&regs, 0), 42);
        assert_eq!(read_int(&regs, 1), -1);
        // Out-of-range or None slots → 0.
        assert_eq!(read_int(&regs, 99), 0);
    }

    #[test]
    fn write_int_round_trip() {
        let mut regs: Registers = vec![None; 4];
        write_int(&mut regs, 2, 0xCAFEBABE);
        assert_eq!(read_int(&regs, 2), 0xCAFEBABE);
    }

    #[test]
    fn read_wide_combines_high_and_low_halves() {
        // High = 0x12345678, low = 0xDEADBEEF
        // Combined: 0x12345678_DEADBEEF
        let regs = make(&[0x12345678, 0xDEADBEEF]);
        assert_eq!(read_wide(&regs, 0) as u64, 0x12345678_DEADBEEFu64);
    }

    #[test]
    fn read_wide_sign_extends_high_half() {
        // High = -1 (0xFFFFFFFF as i32), low = 0
        // Combined: 0xFFFFFFFF_00000000 = -2^32 as i64
        let regs = make(&[-1, 0]);
        assert_eq!(read_wide(&regs, 0), -(1i64 << 32));
    }

    #[test]
    fn write_wide_splits_into_high_and_low() {
        let mut regs: Registers = vec![None; 4];
        write_wide(&mut regs, 1, 0x12345678_DEADBEEFu64 as i64);
        assert_eq!(read_int(&regs, 1), 0x12345678);
        assert_eq!(read_int(&regs, 2), 0xDEADBEEF);
    }

    #[test]
    fn write_wide_then_read_round_trips() {
        let mut regs: Registers = vec![None; 4];
        let values = [0i64, 1, -1, i64::MAX, i64::MIN, 0xCAFEBABE_DEADBEEFu64 as i64];
        for v in values {
            write_wide(&mut regs, 0, v);
            assert_eq!(read_wide(&regs, 0), v, "round-trip failed for {v:#x}");
        }
    }

    #[test]
    fn read_wide_python_or_uses_high_when_nonzero() {
        // High = 1, low = 0xBEEF → result = 1 << 32 (low IGNORED).
        let regs = make(&[1, 0xBEEF]);
        assert_eq!(read_wide_python_or(&regs, 0), 1i64 << 32);
    }

    #[test]
    fn read_wide_python_or_falls_back_to_low_when_high_is_zero() {
        let regs = make(&[0, 0x1234]);
        assert_eq!(read_wide_python_or(&regs, 0), 0x1234);
    }
}
