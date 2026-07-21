//! Cmp family (0x2d-0x31): long / float / double comparison.
//!
//! Direct port of `Cmp.execute` from `dex/instructions_new.py`
//! (lines 872-889).
//!
//! | opcode | mnemonic     | wide? | bias on zero/falsy operand |
//! |--------|--------------|-------|-----------------------------|
//! | 0x2d   | cmpl-float   | no    | -1                          |
//! | 0x2e   | cmpg-float   | no    | +1                          |
//! | 0x2f   | cmpl-double  | yes   | -1                          |
//! | 0x30   | cmpg-double  | yes   | +1                          |
//! | 0x31   | cmp-long     | yes   | (undefined — Python bug)    |
//!
//! Reference implementation:
//! ```python
//! if self.opcode >= 0x2f:
//!     a = (registers[self.vB] << 32) + registers[self.vB + 1]
//!     b = (registers[self.vC] << 32) + registers[self.vC + 1]
//! else:
//!     a = registers[self.vB]
//!     b = registers[self.vC]
//!
//! if not a or not b:
//!     match self.opcode:
//!         case 0x2d | 0x2f: c = -1
//!         case 0x2e | 0x30: c = 1
//! else:
//!     if a > b: c = 1
//!     elif a < b: c = -1
//!     else: c = 0
//!
//! registers[self.vA] = c
//! ```
//!
//! ### Python quirks preserved
//!
//! 1. **Wide reads use `+` not `or`.** Unlike most other places where
//!    Python uses `(high << 32) or low` (the truthy quirk), here the
//!    arithmetic `+` correctly packs the two halves. We mirror with
//!    a proper `(high << 32) | low` (since Python's `+` on positive
//!    halves equals `|` on the bit-disjoint values).
//!
//! 2. **Falsy-operand bias.** If either operand is 0 (or None in
//!    Python terms) the result is biased to -1 for cmpl-* or +1 for
//!    cmpg-*. This DIFFERS from AOSP, which biases only on NaN —
//!    but we mirror Python.
//!
//! 3. **cmp-long (0x31) has no bias case.** When `a` or `b` is 0 and
//!    opcode is 0x31, the Python `match` silently exits without
//!    setting `c`, then `registers[self.vA] = c` raises
//!    UnboundLocalError. We mirror by skipping the write entirely —
//!    the destination register stays whatever it was before.

use platypus_dex::instructions::Instruction;

use crate::memory::Memory;
use crate::vm::{InstrResult, Registers};

use super::{read_int, write_int};

/// Execute a Cmp instruction (0x2d-0x31).
pub fn execute(
    instr: &Instruction,
    regs: &mut Registers,
    _mem: &mut Memory,
) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;
    let v_c = instr.v_c.unwrap_or(0) as u32;

    // ── Read operands ──────────────────────────────────────────
    let (a, b) = if instr.opcode >= 0x2f {
        // wide — pack high/low halves with the (high << 32) | low
        // arithmetic. We sign-extend the high half (Python uses
        // unbounded ints; we approximate with sign-extension to keep
        // the same numeric value for negative wides).
        let a_high = read_int(regs, v_b) as i32 as i64;
        let a_low  = (read_int(regs, v_b + 1) as u32) as i64;
        let b_high = read_int(regs, v_c) as i32 as i64;
        let b_low  = (read_int(regs, v_c + 1) as u32) as i64;
        (
            (a_high << 32) | a_low,
            (b_high << 32) | b_low,
        )
    } else {
        (read_int(regs, v_b), read_int(regs, v_c))
    };

    // ── Compute result ────────────────────────────────────────
    let c: Option<i64> = if a == 0 || b == 0 {
        // Falsy-operand bias. cmp-long (0x31) has no case → returns
        // None → skip the write.
        match instr.opcode {
            0x2d | 0x2f => Some(-1),
            0x2e | 0x30 => Some(1),
            _ => None,
        }
    } else {
        Some(match a.cmp(&b) {
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Less    => -1,
            std::cmp::Ordering::Equal   => 0,
        })
    };

    if let Some(val) = c {
        write_int(regs, v_a, val);
    }

    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;
    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    fn cmp(opcode: u8, v_a: i64, v_b: i64, v_c: i64) -> Instruction {
        Instruction {
            opcode,
            address: 0,
            codepoint: 0,
            fmt: "23x",
            instruction_str: String::new(),
            width: 2,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::Cmp,
            v_a: Some(v_a),
            v_b: Some(v_b),
            v_c: Some(v_c),
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: vec![v_a, v_b, v_c],
        }
    }

    fn make(values: &[i64]) -> Registers {
        values.iter().map(|n| Some(Value::Int(*n))).collect()
    }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── cmpl-float (0x2d) ────────────────────────────────────

    #[test]
    fn cmpl_float_returns_one_when_a_greater() {
        let mut regs = make(&[0, 10, 5]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2d, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 1);
    }

    #[test]
    fn cmpl_float_returns_minus_one_when_a_less() {
        let mut regs = make(&[0, 5, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2d, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1);
    }

    #[test]
    fn cmpl_float_returns_zero_when_equal() {
        let mut regs = make(&[0, 7, 7]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2d, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn cmpl_float_biases_to_minus_one_when_either_operand_zero() {
        let mut regs = make(&[0, 0, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2d, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1);
    }

    // ── cmpg-float (0x2e) ────────────────────────────────────

    #[test]
    fn cmpg_float_biases_to_plus_one_when_either_operand_zero() {
        let mut regs = make(&[0, 0, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2e, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 1);
    }

    #[test]
    fn cmpg_float_uses_normal_compare_when_both_nonzero() {
        let mut regs = make(&[0, 5, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2e, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1);
    }

    // ── cmpl-double (0x2f) — wide reads ──────────────────────

    #[test]
    fn cmpl_double_reads_wide_pairs() {
        // vB pair = [high=1, low=0] → 1 << 32 = 4294967296
        // vC pair = [high=0, low=10] → 10
        // a > b → 1
        let mut regs = make(&[0, 1, 0, 0, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2f, 0, 1, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 1);
    }

    #[test]
    fn cmpl_double_falsy_bias() {
        // vB pair = [0, 0] → 0; vC pair = [0, 10] → 10. a==0 → bias to -1.
        let mut regs = make(&[0, 0, 0, 0, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x2f, 0, 1, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1);
    }

    // ── cmpg-double (0x30) ───────────────────────────────────

    #[test]
    fn cmpg_double_falsy_bias_is_plus_one() {
        let mut regs = make(&[0, 0, 0, 0, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x30, 0, 1, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 1);
    }

    // ── cmp-long (0x31) — Python bug: no bias case ──────────

    #[test]
    fn cmp_long_normal_returns_compare_result() {
        // Both operands non-zero → normal compare.
        // vB = [0, 10] = 10; vC = [0, 5] = 5. 10 > 5 → 1.
        let mut regs = make(&[0, 0, 10, 0, 5]);
        let mut mem  = Memory::new();
        execute(&cmp(0x31, 0, 1, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 1);
    }

    #[test]
    fn cmp_long_with_zero_operand_skips_write_per_python_bug() {
        // vB pair = [0, 0] → 0; vC = [0, 5] = 5. a==0 → Python's
        // match has no case for 0x31 → c undefined → NameError →
        // the `registers[vA] = c` never happens. We mirror by
        // leaving vA untouched.
        let mut regs = make(&[0xDEAD, 0, 0, 0, 5]);
        let mut mem  = Memory::new();
        execute(&cmp(0x31, 0, 1, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD); // unchanged
    }

    #[test]
    fn cmp_long_returns_zero_when_equal() {
        let mut regs = make(&[0, 0, 100, 0, 100]);
        let mut mem  = Memory::new();
        execute(&cmp(0x31, 0, 1, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn cmp_long_returns_minus_one_when_a_less() {
        let mut regs = make(&[0, 0, 5, 0, 10]);
        let mut mem  = Memory::new();
        execute(&cmp(0x31, 0, 1, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -1);
    }
}
