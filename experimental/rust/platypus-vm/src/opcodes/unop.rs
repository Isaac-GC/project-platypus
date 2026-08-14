//! UnOp family (0x7b-0x8f): unary arithmetic + type conversions.
//!
//! Direct port of `UnOp.execute` from `dex/instructions_new.py`
//! (lines 1228-1257). The opcode table:
//!
//! | range            | meaning                                  |
//! |------------------|------------------------------------------|
//! | 0x7b, 0x7f       | neg-int / neg-float                      |
//! | 0x7c, 0x7e       | not-int / not-long                       |
//! | 0x7d, 0x80       | neg-long / neg-double (split-register!)  |
//! | 0x81, 0x83,      | int→long, int→double, float→long,        |
//! | 0x88, 0x89       | float→double (zero the high half)        |
//! | 0x82, 0x86,      | int→float, long→double, float→int,       |
//! | 0x87, 0x8b       | double→long (no-op at storage layer)     |
//! | 0x84, 0x85,      | long→int, long→float, double→int,        |
//! | 0x8a, 0x8c       | double→float (collapse pair → vA)        |
//! | 0x8d, 0x8e       | int→byte, int→char                       |
//! | 0x8f             | int→short                                |
//!
//! ### Python quirks preserved verbatim
//!
//! 1. **neg-long / neg-double negate each half independently.**
//!    Python does `regs[vA] = -regs[vB]; regs[vA+1] = -regs[vB+1]` —
//!    each 32-bit half is negated as if it were an independent
//!    integer. That is mathematically wrong (true 64-bit negation
//!    would propagate the borrow across halves) but it's what the
//!    reference does, so callers calibrated against the reference
//!    will produce matching output.
//!
//! 2. **Widening conversions zero the high half.** `int-to-long` /
//!    `int-to-double` / `float-to-long` / `float-to-double` copy vB
//!    into vA and set vA+1 to 0. They do NOT sign-extend — a negative
//!    int becomes a positive long. Reference behaviour.
//!
//! 3. **Narrowing conversions use Python `or` semantics.**
//!    `long_value = (val1 << 32) or (val2 & 0xFFFFFFFF)`.
//!    When val1 (the high half) is non-zero, the low half is
//!    *silently discarded* — `or` short-circuits on truthiness. This
//!    is almost certainly a Python bug but it's what the reference
//!    does and several real-APK paths produce the matching output
//!    only because of it.
//!
//! 4. **int-to-byte uses Python's `val > 0x7F` adjustment.** We
//!    mirror the explicit `(val - 0xFF - 1)` form rather than relying
//!    on Rust's `as i8 as i64` (the two agree, but keeping the form
//!    visually identical to the Python source helps when chasing
//!    divergence).
//!
//! 5. **int-to-char zero-extends** (the result of `& 0xFFFF` plus the
//!    `> 0x7FFF ? subtract : keep` branch — Python treats char as a
//!    signed 16-bit here, which AOSP does NOT do). Reference quirk.

use platypus_dex::instructions::Instruction;

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::{read_int, write_int};

/// Execute a UnOp instruction (0x7b-0x8f). Mirrors `UnOp.execute`
/// from `dex/instructions_new.py`.
pub fn execute(
    instr: &Instruction,
    regs: &mut Registers,
    _mem: &mut Memory,
) -> InstrResult {
    // Both operands are always present for UnOp; absent operands
    // would mean a malformed instruction stream. Default to zero to
    // mirror the Python `int(reg) if reg else 0` convention rather
    // than panic — the dispatch loop has already advanced past the
    // instruction, so silently no-oping is the least-surprising
    // recovery.
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;
    let b   = read_int(regs, v_b);

    match instr.opcode {
        // neg-int (0x7b) | neg-float (0x7f)
        0x7b | 0x7f => {
            // Python catches TypeError and falls back to 0. In Rust
            // the operand is always i64, so the wrapping_neg can't
            // throw — equivalent to the Python try/except.
            write_int(regs, v_a, b.wrapping_neg());
        }

        // not-int (0x7c) | not-long (0x7e)
        0x7c | 0x7e => {
            // Python `~x` on a 64-bit int is `-x - 1`. Rust's `!`
            // matches when the operand is i64.
            write_int(regs, v_a, !b);
        }

        // neg-long (0x7d) | neg-double (0x80) — split-register
        0x7d | 0x80 => {
            let b_lo = read_int(regs, v_b + 1);
            write_int(regs, v_a,     b.wrapping_neg());
            write_int(regs, v_a + 1, b_lo.wrapping_neg());
        }

        // int→float | long→double | float→int | double→long.
        // Python `pass` — interchangeable at the storage layer.
        // We still copy vB → vA so the destination register reflects
        // the conversion (the Python reference relies on the
        // destination already aliasing the source for these, but
        // when vA != vB we DO need to copy or the result is wrong;
        // emit the copy to be safe).
        0x82 | 0x86 | 0x87 | 0x8b => {
            if v_a != v_b {
                write_int(regs, v_a, b);
                // Wide pairs (long↔double): also copy the low half.
                if matches!(instr.opcode, 0x86 | 0x8b) {
                    let b_lo = read_int(regs, v_b + 1);
                    write_int(regs, v_a + 1, b_lo);
                }
            }
        }

        // int→long | int→double | float→long | float→double.
        // Widen narrow→wide: high half = vB value, low half = 0.
        // No sign extension — matches Python (vB stays unmodified).
        0x81 | 0x83 | 0x88 | 0x89 => {
            write_int(regs, v_a,     b);
            write_int(regs, v_a + 1, 0);
        }

        // long→int | long→float | double→int | double→float.
        // Collapse wide→narrow using Python's `or` semantics:
        //   long_value = (val1 << 32) or (val2 & 0xFFFFFFFF)
        // — if val1 is truthy the low half is silently discarded.
        0x84 | 0x85 | 0x8a | 0x8c => {
            let val1 = b;
            let val2 = read_int(regs, v_b + 1);
            let long_value = if val1 != 0 {
                val1 << 32
            } else {
                (val2 as u64 & 0xFFFFFFFF) as i64
            };
            write_int(regs, v_a, long_value);
        }

        // int→byte (0x8d) | int→char (0x8e). Mask to 8 bits then
        // sign-adjust the same way Python does.
        0x8d | 0x8e => {
            let val = (b as u64) & 0xFF;
            let signed = if val > 0x7F {
                (val as i64) - 0xFF - 1
            } else {
                val as i64
            };
            write_int(regs, v_a, signed);
        }

        // int→short (0x8f). Mask to 16 bits, sign-adjust.
        0x8f => {
            let val = (b as u64) & 0xFFFF;
            let signed = if val > 0x7FFF {
                (val as i64) - 0xFFFF - 1
            } else {
                val as i64
            };
            write_int(regs, v_a, signed);
        }

        _ => {
            // Out-of-family opcode — should never reach here if the
            // dispatch table is correct. No-op to stay safe.
        }
    }

    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    /// Build a UnOp-shaped instruction. UnOp formats are `12x` and
    /// only carry vA / vB.
    fn unop(opcode: u8, v_a: i64, v_b: i64) -> Instruction {
        Instruction {
            opcode,
            address: 0,
            codepoint: 0,
            fmt: "12x",
            instruction_str: String::new(),
            width: 1,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::UnOp,
            v_a: Some(v_a),
            v_b: Some(v_b),
            v_c: None,
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None,
            v_z: None,
            operands: vec![v_a, v_b],
        }
    }

    fn make(values: &[i64]) -> Registers {
        values.iter().map(|n| Some(Value::Int(*n))).collect()
    }

    fn empty(len: usize) -> Registers { vec![None; len] }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── 0x7b / 0x7f — neg-int / neg-float ─────────────────────────

    #[test]
    fn neg_int_negates_value() {
        let mut regs = make(&[0, 42]);
        let mut mem  = Memory::new();
        execute(&unop(0x7b, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -42);
    }

    #[test]
    fn neg_int_handles_i64_min_via_wrapping() {
        let mut regs = make(&[0, i64::MIN]);
        let mut mem  = Memory::new();
        execute(&unop(0x7b, 0, 1), &mut regs, &mut mem);
        // -i64::MIN overflows; wrapping_neg keeps it at MIN.
        assert_eq!(read(&regs, 0), i64::MIN);
    }

    #[test]
    fn neg_float_uses_same_path_as_neg_int() {
        let mut regs = make(&[0, 7]);
        let mut mem  = Memory::new();
        execute(&unop(0x7f, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -7);
    }

    // ── 0x7c / 0x7e — not-int / not-long ─────────────────────────

    #[test]
    fn not_int_bitwise_complements() {
        let mut regs = make(&[0, 0]);
        let mut mem  = Memory::new();
        execute(&unop(0x7c, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1); // ~0 = -1
    }

    #[test]
    fn not_long_complements_single_slot() {
        // Python's `~regs[vB]` operates on the slot Python sees
        // (the Python reference does NOT touch vA+1 here — that's a
        // separate quirk we preserve).
        let mut regs = make(&[0, 0xF0F0]);
        let mut mem  = Memory::new();
        execute(&unop(0x7e, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), !0xF0F0i64);
    }

    // ── 0x7d / 0x80 — neg-long / neg-double ──────────────────────

    #[test]
    fn neg_long_negates_each_half_independently() {
        // Python quirk: each half is negated independently. So if
        // vB = [3, 4], result = [-3, -4] (NOT a true 64-bit negate).
        let mut regs = make(&[0, 0, 3, 4]);
        let mut mem  = Memory::new();
        execute(&unop(0x7d, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -3);
        assert_eq!(read(&regs, 1), -4);
    }

    #[test]
    fn neg_double_uses_same_per_half_negation_as_neg_long() {
        let mut regs = make(&[0, 0, 10, 20]);
        let mut mem  = Memory::new();
        execute(&unop(0x80, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -10);
        assert_eq!(read(&regs, 1), -20);
    }

    // ── 0x81 / 0x83 / 0x88 / 0x89 — widening ────────────────────

    #[test]
    fn int_to_long_copies_value_and_zeros_high_half() {
        let mut regs = make(&[0, 0, 42]);
        let mut mem  = Memory::new();
        execute(&unop(0x81, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 42);
        assert_eq!(read(&regs, 1), 0);
    }

    #[test]
    fn int_to_long_does_not_sign_extend() {
        // Python quirk: widening DOES NOT sign-extend. -1 → low=-1, high=0
        // (NOT a -1 in both halves the way AOSP would do).
        let mut regs = make(&[0, 0, -1]);
        let mut mem  = Memory::new();
        execute(&unop(0x81, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1);
        assert_eq!(read(&regs, 1), 0); // not -1
    }

    #[test]
    fn int_to_double_zeroes_high_half() {
        let mut regs = make(&[0, 0, 123]);
        let mut mem  = Memory::new();
        execute(&unop(0x83, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 123);
        assert_eq!(read(&regs, 1), 0);
    }

    #[test]
    fn float_to_long_zeroes_high_half() {
        let mut regs = make(&[0, 0, 7]);
        let mut mem  = Memory::new();
        execute(&unop(0x88, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 7);
        assert_eq!(read(&regs, 1), 0);
    }

    #[test]
    fn float_to_double_zeroes_high_half() {
        let mut regs = make(&[0, 0, 8]);
        let mut mem  = Memory::new();
        execute(&unop(0x89, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 8);
        assert_eq!(read(&regs, 1), 0);
    }

    // ── 0x82 / 0x86 / 0x87 / 0x8b — identity conversions ────────

    #[test]
    fn int_to_float_copies_value_when_dst_differs() {
        let mut regs = make(&[0, 99]);
        let mut mem  = Memory::new();
        execute(&unop(0x82, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 99);
    }

    #[test]
    fn int_to_float_is_noop_when_dst_equals_src() {
        // Python `pass` leaves the slot alone. Make sure we don't
        // accidentally clear it.
        let mut regs = make(&[55]);
        let mut mem  = Memory::new();
        execute(&unop(0x82, 0, 0), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 55);
    }

    #[test]
    fn long_to_double_copies_both_halves() {
        let mut regs = make(&[0, 0, 0xAA, 0xBB]);
        let mut mem  = Memory::new();
        execute(&unop(0x86, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xAA);
        assert_eq!(read(&regs, 1), 0xBB);
    }

    #[test]
    fn double_to_long_copies_both_halves() {
        let mut regs = make(&[0, 0, 0x11, 0x22]);
        let mut mem  = Memory::new();
        execute(&unop(0x8b, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x11);
        assert_eq!(read(&regs, 1), 0x22);
    }

    // ── 0x84 / 0x85 / 0x8a / 0x8c — narrowing (Python `or`) ─────

    #[test]
    fn long_to_int_uses_high_half_when_nonzero_and_discards_low() {
        // Python quirk: (high << 32) or low. If high != 0, low is
        // silently discarded.
        let mut regs = make(&[0, 5, 0xCAFE]);
        let mut mem  = Memory::new();
        execute(&unop(0x84, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 5i64 << 32);
    }

    #[test]
    fn long_to_int_falls_back_to_low_when_high_is_zero() {
        let mut regs = make(&[0, 0, 0x1234]);
        let mut mem  = Memory::new();
        execute(&unop(0x84, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x1234);
    }

    #[test]
    fn long_to_float_uses_same_or_semantics() {
        let mut regs = make(&[0, 0, 0x7F]);
        let mut mem  = Memory::new();
        execute(&unop(0x85, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x7F);
    }

    #[test]
    fn double_to_int_uses_same_or_semantics() {
        let mut regs = make(&[0, 0, 0x42]);
        let mut mem  = Memory::new();
        execute(&unop(0x8a, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x42);
    }

    #[test]
    fn double_to_float_uses_same_or_semantics() {
        let mut regs = make(&[0, 3, 0xBEEF]);
        let mut mem  = Memory::new();
        execute(&unop(0x8c, 0, 1), &mut regs, &mut mem);
        // High = 3, low ignored → result = 3 << 32.
        assert_eq!(read(&regs, 0), 3i64 << 32);
    }

    // ── 0x8d / 0x8e / 0x8f — narrowing int ─────────────────────

    #[test]
    fn int_to_byte_sign_extends_high_bit() {
        // 0x80 (= 128) > 0x7F → result = 128 - 256 = -128.
        let mut regs = make(&[0, 0x80]);
        let mut mem  = Memory::new();
        execute(&unop(0x8d, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -128);
    }

    #[test]
    fn int_to_byte_keeps_small_positive_unchanged() {
        let mut regs = make(&[0, 0x42]);
        let mut mem  = Memory::new();
        execute(&unop(0x8d, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x42);
    }

    #[test]
    fn int_to_byte_truncates_high_bits() {
        // 0xABCD & 0xFF = 0xCD = 205. 205 > 127 → 205 - 256 = -51.
        let mut regs = make(&[0, 0xABCD]);
        let mut mem  = Memory::new();
        execute(&unop(0x8d, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -51);
    }

    #[test]
    fn int_to_char_uses_same_8_bit_path_as_int_to_byte() {
        // Python quirk: 0x8e ALSO masks to 0xFF (not 0xFFFF) — the
        // reference implementation collapses the two cases. We
        // mirror that.
        let mut regs = make(&[0, 0xFF]);
        let mut mem  = Memory::new();
        execute(&unop(0x8e, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1);
    }

    #[test]
    fn int_to_short_sign_extends_at_16_bits() {
        // 0x8000 = 32768 > 0x7FFF → result = 32768 - 65536 = -32768.
        let mut regs = make(&[0, 0x8000]);
        let mut mem  = Memory::new();
        execute(&unop(0x8f, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -32768);
    }

    #[test]
    fn int_to_short_keeps_small_positive_unchanged() {
        let mut regs = make(&[0, 0x1234]);
        let mut mem  = Memory::new();
        execute(&unop(0x8f, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x1234);
    }

    #[test]
    fn int_to_short_truncates_high_bits() {
        // 0xABCDEF & 0xFFFF = 0xCDEF = 52719 > 0x7FFF → 52719 - 65536 = -12817.
        let mut regs = make(&[0, 0xABCDEF]);
        let mut mem  = Memory::new();
        execute(&unop(0x8f, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -12817);
    }

    // ── Defensive: instruction with missing operand ─────────────

    #[test]
    fn missing_operands_default_to_zero_and_do_not_panic() {
        let mut regs = empty(4);
        let mut mem  = Memory::new();
        let mut instr = unop(0x7b, 0, 0);
        instr.v_a = None;
        instr.v_b = None;
        // Should write -0 (= 0) into reg[0] and not panic.
        execute(&instr, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }
}
