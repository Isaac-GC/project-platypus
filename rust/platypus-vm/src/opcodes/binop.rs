//! BinOp family (0x90-0xaf): 3-operand arithmetic — vA = vB op vC.
//!
//! Direct port of `BinOp.execute` from `dex/instructions_new.py`
//! (lines 1301-1334). The opcode-to-(operator,operand) mapping is:
//!
//! | range       | operand_type | operator range            |
//! |-------------|--------------|---------------------------|
//! | 0x90-0x9a   | 0 (int)      | 0..10 = add..ushr         |
//! | 0x9b-0xa5   | 1 (long)     | 0..10 = add..ushr         |
//! | 0xa6-0xaa   | 2 (float)    | 0..4  = add..rem          |
//! | 0xab-0xaf   | 3 (double)   | 0..4  = add..rem          |
//!
//! Formulas (mirroring Python):
//! ```text
//! if 0x90 <= op <= 0xa5:
//!     operand  = (op - 0x90) // 11
//!     operator = (op - 0x90) %  11
//! elif 0xa6 <= op <= 0xaf:
//!     operand  = (op - 0xa6) // 5 + 2
//!     operator = (op - 0xa6) %  5
//! ```
//!
//! The dispatch into the actual ALU is delegated to
//! [`crate::opcodes::helpers::reg_ops_helper`]; here we just decode
//! the operands, handle wide-register packing, and dispatch the
//! write side based on `operand_type`.
//!
//! ### Python quirks preserved verbatim
//!
//! 1. **`(reg[vB] << 32) or reg[vB+1]` for wide reads.** Python's
//!    `or` short-circuits on truthiness — if the high half is non-zero
//!    the low half is silently discarded. Mirrors
//!    [`crate::opcodes::read_wide_python_or`].
//!
//! 2. **`c` is read from `vB` (not `vC`) in the long branch's
//!    non-shift case.** This is almost certainly a Python bug:
//!    ```python
//!    case 0x1: # long
//!        b = (registers[self.vB] << 32) or registers[self.vB + 1]
//!        if self.operator_type in [0x8, 0x9, 0xa]:
//!            c = registers[self.vC]
//!        else:
//!            c = (registers[self.vB] << 32) or registers[self.vB + 1]   # ← vB, not vC!
//!    ```
//!    The result is that `add-long v0, v1, v2` actually computes
//!    `v0 = v1 + v1`. Real APKs presumably never trigger this branch
//!    in a way the test corpus notices; we mirror it byte-for-byte.
//!
//! 3. **Same vB-instead-of-vC bug in the float/double branch.**
//!
//! 4. **Float results are silently dropped.** The result-writing match
//!    has cases `0x0 | 0x4` (int) and `0x1 | 0x3` (long/double) — no
//!    case for operand_type 0x2 (float). Python's match falls through
//!    silently, so the computed `a` is discarded. We mirror this
//!    rather than try to fix it.
//!
//! 5. **The `0x4` case in the writer is dead code** — operand_type 0x4
//!    is never produced by the decoder. We include the case anyway to
//!    keep the structure 1:1 with Python so divergence is easy to spot.
//!
//! 6. **ZeroDivisionError fallback.** Python catches it and writes 0.
//!    `reg_ops_helper` already returns 0 on div/rem by zero, so we
//!    don't need an explicit catch.

use platypus_dex::instructions::Instruction;

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::{read_int, read_wide_python_or, write_int};
use super::helpers::reg_ops_helper;

/// Decode `(operator_type, operand_type)` from a BinOp opcode.
///
/// Returns `None` if the opcode is outside the BinOp range — callers
/// should already have dispatched only valid opcodes here, but this
/// keeps the function pure and testable.
pub fn decode_op(opcode: u8) -> Option<(u8, u8)> {
    if (0x90..=0xa5).contains(&opcode) {
        let operand  = (opcode - 0x90) / 11;
        let operator = (opcode - 0x90) % 11;
        Some((operator, operand))
    } else if (0xa6..=0xaf).contains(&opcode) {
        let operand  = (opcode - 0xa6) / 5 + 2;
        let operator = (opcode - 0xa6) % 5;
        Some((operator, operand))
    } else {
        None
    }
}

/// Execute a BinOp instruction (0x90-0xaf). Mirrors `BinOp.execute`
/// from `dex/instructions_new.py`. The instruction's `kind` carries
/// the pre-decoded `(operator_type, operand_type)` pair; we trust it.
pub fn execute(
    instr: &Instruction,
    regs: &mut Registers,
    _mem: &mut Memory,
) -> InstrResult {
    // Prefer the pre-decoded pair from InstructionKind::BinOp;
    // fall back to recomputing from the opcode for safety.
    let (operator, operand) = match instr.kind {
        platypus_dex::instructions::InstructionKind::BinOp { operator_type, operand_type } => {
            (operator_type, operand_type)
        }
        _ => match decode_op(instr.opcode) {
            Some(pair) => pair,
            None => return InstrResult::Continue,
        },
    };

    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;
    let v_c = instr.v_c.unwrap_or(0) as u32;

    // ── Read operands b and c, per operand_type ──────────────────
    let (b, c) = match operand {
        0x0 => {
            // int — single slot each.
            (read_int(regs, v_b), read_int(regs, v_c))
        }
        0x1 => {
            // long. b uses Python `or` wide read; c depends on operator.
            let b_val = read_wide_python_or(regs, v_b);
            let c_val = if matches!(operator, 0x8 | 0x9 | 0xa) {
                // shl / shr / ushr — c is a single-slot int.
                read_int(regs, v_c)
            } else {
                // Python bug: this re-reads vB instead of vC. Mirror it.
                read_wide_python_or(regs, v_b)
            };
            (b_val, c_val)
        }
        0x2 | 0x3 => {
            // float / double. Python bug: both b and c read from vB.
            // Mirror it.
            let b_val = read_wide_python_or(regs, v_b);
            let c_val = read_wide_python_or(regs, v_b);
            (b_val, c_val)
        }
        _ => (0, 0),
    };

    // ── Compute ────────────────────────────────────────────────
    let a = reg_ops_helper(operator, operand, b, c);

    // ── Write result ──────────────────────────────────────────
    // Python's writer match:
    //   0x0 | 0x4 → registers[vA] = a
    //   0x1 | 0x3 → split into vA (high) / vA+1 (low)
    //   0x2 (float) → no case! result silently dropped.
    match operand {
        0x0 | 0x4 => {
            write_int(regs, v_a, a);
        }
        0x1 | 0x3 => {
            // Same split as `write_wide`, but Python uses raw `>> 32`
            // (arithmetic shift) for the high half and `& 0xFFFFFFFF`
            // (unsigned) for the low. Mirror that exactly.
            let high = a >> 32;
            let low  = (a as u64 & 0xFFFFFFFF) as i64;
            write_int(regs, v_a,     high);
            write_int(regs, v_a + 1, low);
        }
        _ => {
            // Operand 0x2 (float) intentionally dropped — Python bug.
        }
    }

    let _ = Value::Int(0); // silence unused import warning
    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    /// Build a BinOp instruction. `23x` format: vA, vB, vC.
    fn binop(opcode: u8, v_a: i64, v_b: i64, v_c: i64) -> Instruction {
        let (operator, operand) = decode_op(opcode).unwrap_or((0, 0));
        Instruction {
            opcode,
            address: 0,
            codepoint: 0,
            fmt: "23x",
            instruction_str: String::new(),
            width: 2,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::BinOp {
                operator_type: operator,
                operand_type:  operand,
            },
            v_a: Some(v_a),
            v_b: Some(v_b),
            v_c: Some(v_c),
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None,
            v_z: None,
            operands: vec![v_a, v_b, v_c],
        }
    }

    fn make(values: &[i64]) -> Registers {
        values.iter().map(|n| Some(Value::Int(*n))).collect()
    }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── decode_op coverage ─────────────────────────────────────

    #[test]
    fn decode_op_int_range() {
        // 0x90 = add-int → (0, 0)
        assert_eq!(decode_op(0x90), Some((0, 0)));
        // 0x9a = ushr-int → (10, 0)
        assert_eq!(decode_op(0x9a), Some((10, 0)));
    }

    #[test]
    fn decode_op_long_range() {
        // 0x9b = add-long → (0, 1)
        assert_eq!(decode_op(0x9b), Some((0, 1)));
        // 0xa5 = ushr-long → (10, 1)
        assert_eq!(decode_op(0xa5), Some((10, 1)));
    }

    #[test]
    fn decode_op_float_range() {
        // 0xa6 = add-float → (0, 2)
        assert_eq!(decode_op(0xa6), Some((0, 2)));
        // 0xaa = rem-float → (4, 2)
        assert_eq!(decode_op(0xaa), Some((4, 2)));
    }

    #[test]
    fn decode_op_double_range() {
        // 0xab = add-double → (0, 3)
        assert_eq!(decode_op(0xab), Some((0, 3)));
        // 0xaf = rem-double → (4, 3)
        assert_eq!(decode_op(0xaf), Some((4, 3)));
    }

    #[test]
    fn decode_op_out_of_range() {
        assert_eq!(decode_op(0x00), None);
        assert_eq!(decode_op(0x8f), None);
        assert_eq!(decode_op(0xb0), None);
    }

    // ── int operations (operand 0x0) ──────────────────────────

    #[test]
    fn add_int_writes_sum_to_va() {
        let mut regs = make(&[0, 10, 7]);
        let mut mem  = Memory::new();
        execute(&binop(0x90, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 17);
    }

    #[test]
    fn sub_int_writes_difference() {
        let mut regs = make(&[0, 10, 7]);
        let mut mem  = Memory::new();
        execute(&binop(0x91, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 3);
    }

    #[test]
    fn mul_int_writes_product() {
        let mut regs = make(&[0, 6, 7]);
        let mut mem  = Memory::new();
        execute(&binop(0x92, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 42);
    }

    #[test]
    fn div_int_uses_python_floor_div_then_post_mask() {
        // -7 // 2 = -4 (Python floor div). Post-mask mangles
        // negatives → -2. See helpers.rs for the bug.
        let mut regs = make(&[0, -7, 2]);
        let mut mem  = Memory::new();
        execute(&binop(0x93, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -2);
    }

    #[test]
    fn div_int_by_zero_yields_zero() {
        let mut regs = make(&[42, 100, 0]);
        let mut mem  = Memory::new();
        execute(&binop(0x93, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn rem_int_uses_python_mod() {
        // -7 % 3 = 2 (Python divisor-sign mod). 2 is positive so
        // unaffected by the int post-mask.
        let mut regs = make(&[0, -7, 3]);
        let mut mem  = Memory::new();
        execute(&binop(0x94, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 2);
    }

    #[test]
    fn bitwise_and_int() {
        let mut regs = make(&[0, 0xF0, 0x0F]);
        let mut mem  = Memory::new();
        execute(&binop(0x95, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn bitwise_or_int() {
        let mut regs = make(&[0, 0xF0, 0x0F]);
        let mut mem  = Memory::new();
        execute(&binop(0x96, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xFF);
    }

    #[test]
    fn shl_int_uses_24_bit_mask_quirk() {
        // 1 << 24 = 0x1000000. Python masks to 0xFFFFFF = 0.
        let mut regs = make(&[0, 1, 24]);
        let mut mem  = Memory::new();
        execute(&binop(0x98, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn int_post_mask_sign_extends_with_python_off_by_two() {
        // 0x40000000 + 0x40000000 = 0x80000000. Python's off-by-2
        // post-mask gives -2147483646 (not -2147483648). See
        // helpers.rs for the bug description.
        let mut regs = make(&[0, 0x40000000, 0x40000000]);
        let mut mem  = Memory::new();
        execute(&binop(0x90, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -2147483646);
    }

    // ── long operations (operand 0x1) — wide pack/unpack ────

    #[test]
    fn add_long_writes_high_and_low_halves() {
        // vB = [high=0, low=10] → 10 (low half) per Python `or`.
        // vC ignored — Python uses vB for both b and c. So we add
        // vB to itself: 10 + 10 = 20. Write high/low.
        let mut regs = make(&[0, 0, 0, 10, 99, 99]);
        let mut mem  = Memory::new();
        // vA=0, vB=2 ([reg2,reg3]=[0,10]), vC=4 (ignored by Python bug)
        execute(&binop(0x9b, 0, 2, 4), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);  // high half of 20 = 0
        assert_eq!(read(&regs, 1), 20); // low half of 20 = 20
    }

    #[test]
    fn add_long_with_high_half_set_uses_python_or_quirk() {
        // vB high = 1, low = 99 → `(1 << 32) or 99` = 1 << 32 = 4294967296.
        // vC ignored, b = c = 4294967296. b + c = 8589934592 = 2 << 32.
        // High half = 2, low = 0.
        let mut regs = make(&[0, 0, 1, 99]);
        let mut mem  = Memory::new();
        execute(&binop(0x9b, 0, 2, 0), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 2);
        assert_eq!(read(&regs, 1), 0);
    }

    #[test]
    fn shl_long_reads_c_from_vc_not_vb() {
        // shift operator (0x8 family): c comes from vC, not vB.
        // vB = [high=0, low=1] → b = 1.
        // vC = 4. shl-long: 1 << 4 = 16. High = 0, low = 16.
        let mut regs = make(&[0, 0, 0, 1, 4]);
        let mut mem  = Memory::new();
        // opcode 0xa3 = shl-long: 0xa3 - 0x9b = 8, operand = 1
        execute(&binop(0xa3, 0, 2, 4), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
        assert_eq!(read(&regs, 1), 16);
    }

    #[test]
    fn long_writer_uses_arithmetic_shift_for_high_half() {
        // Negative wide result should sign-extend in the high half.
        // sub-long: vB = [high=0, low=0] - itself = 0. Boring.
        // Instead: build a negative result via wrapping_neg.
        // not-long is in UnOp, so simulate: long add with b = c = i64::MIN/2.
        // Skip — covered by helpers.rs tests for now.
        // This test just verifies the writer respects high vs low split
        // bit-for-bit.
        let mut regs = make(&[0, 0, 0xFFFFFFFF, 0]); // high = -1 → b = -1 << 32
        let mut mem  = Memory::new();
        // add-long: b = c = -1 << 32 (Python or quirk discards low).
        // Sum wraps via wrapping_add to -2 << 32.
        execute(&binop(0x9b, 0, 2, 0), &mut regs, &mut mem);
        // Expected: (-2 << 32) = high=-2 (sign-extended), low=0.
        assert_eq!(read(&regs, 0), -2);
        assert_eq!(read(&regs, 1), 0);
    }

    // ── float operations (operand 0x2) — result dropped ────

    #[test]
    fn float_result_is_silently_dropped_python_quirk() {
        // Python's writer match has no case for operand 0x2 (float).
        // vA must remain whatever it was before — NOT updated.
        let mut regs = make(&[0xDEAD, 0, 5, 0, 7, 0]);
        let mut mem  = Memory::new();
        // add-float (0xa6). vA=0 (so reg[0] should NOT change from 0xDEAD).
        execute(&binop(0xa6, 0, 2, 4), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD); // unchanged — Python quirk
    }

    // ── double operations (operand 0x3) — writes both halves ────

    #[test]
    fn add_double_writes_both_halves() {
        // vB high=0, low=5 → b = 5 (Python or). Same for c (vB bug).
        // 5 + 5 = 10. Write high=0, low=10.
        let mut regs = make(&[0, 0, 0, 5]);
        let mut mem  = Memory::new();
        execute(&binop(0xab, 0, 2, 0), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
        assert_eq!(read(&regs, 1), 10);
    }
}
