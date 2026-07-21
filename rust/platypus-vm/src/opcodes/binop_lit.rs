//! BinOpLit family (0xd0-0xe2): vA = vB op #literal.
//!
//! Direct port of `BinOpLit.execute` from `dex/instructions_new.py`
//! (lines 1424-1433). All BinOpLit opcodes operate on int operands
//! (operand_type defaults to 0). The opcode-to-operator mapping:
//!
//! | range       | format  | operator range                          |
//! |-------------|---------|------------------------------------------|
//! | 0xd0-0xd7   | /lit16  | 0..7 = add, rsub, mul, div, rem, and, or, xor |
//! | 0xd8-0xdf   | /lit8   | 0..7 = add, rsub, mul, div, rem, and, or, xor |
//! | 0xe0-0xe2   | /lit8   | 8..10 = shl, shr, ushr                  |
//!
//! Wait — that doesn't match. The Python code is:
//! ```python
//! if 0xd0 <= self.opcode <= 0xd7:
//!     self.operator_type = self.opcode - 0xd0       # 0..7 = add..xor
//! elif 0xd8 <= self.opcode <= 0xe2:
//!     self.operator_type = self.opcode - 0xd8       # 0..10 = add..ushr
//! ```
//!
//! So lit16 covers operators 0..7, and lit8 covers 0..10. Both
//! literal forms use the same execute() path.
//!
//! ### Execution
//!
//! ```python
//! def execute(self, memory, registers):
//!     b = registers[self.vB] # passed in value
//!     c = self.vC # literal value
//!
//!     if self.operator_type != 0x1:
//!         a = reg_ops_helper(self.operator_type, self.operand_type, b, c)
//!     else: # In the case of 'rsub', switch the two values around
//!         a = reg_ops_helper(self.operator_type, self.operand_type, c, b)
//!
//!     registers[self.vA] = a
//! ```
//!
//! The rsub swap is needed because rsub-int is `dst = literal - src`
//! (rather than the usual `dst = src - literal`).
//!
//! ### Python quirks preserved
//!
//! 1. **operand_type defaults to 0 (int)** — `InstructionBase.__init__`
//!    sets it. So all BinOpLit ops go through `reg_ops_helper` with
//!    operand=0, which applies the int post-mask (and its off-by-2
//!    sign-extension bug).
//!
//! 2. **The 24-bit shift mask quirk** in `reg_ops_helper` applies to
//!    shl-int/lit8, shr-int/lit8, ushr-int/lit8 — values shifted past
//!    bit 24 silently become zero.

use platypus_dex::instructions::Instruction;

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::{read_int, write_int};
use super::helpers::reg_ops_helper;

/// Decode the operator type from a BinOpLit opcode. Returns `None`
/// for opcodes outside the BinOpLit range.
pub fn decode_op(opcode: u8) -> Option<u8> {
    if (0xd0..=0xd7).contains(&opcode) {
        Some(opcode - 0xd0)
    } else if (0xd8..=0xe2).contains(&opcode) {
        Some(opcode - 0xd8)
    } else {
        None
    }
}

/// Execute a BinOpLit instruction (0xd0-0xe2). Mirrors
/// `BinOpLit.execute` from `dex/instructions_new.py`. All ops are
/// int (operand_type = 0).
pub fn execute(
    instr: &Instruction,
    regs: &mut Registers,
    _mem: &mut Memory,
) -> InstrResult {
    let operator = match instr.kind {
        platypus_dex::instructions::InstructionKind::BinOpLit { operator_type } => operator_type,
        _ => match decode_op(instr.opcode) {
            Some(op) => op,
            None => return InstrResult::Continue,
        },
    };

    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;
    let c   = instr.v_c.unwrap_or(0); // literal value

    let b = read_int(regs, v_b);

    // Python: `if self.operator_type != 0x1: ... else: swap b and c`.
    // The swap implements rsub-int: dst = literal - src.
    let a = if operator != 0x1 {
        reg_ops_helper(operator, 0x0, b, c)
    } else {
        reg_ops_helper(operator, 0x0, c, b)
    };

    write_int(regs, v_a, a);

    let _ = Value::Int(0); // silence unused import warning
    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    /// Build a BinOpLit instruction. `22s` (lit16) or `22b` (lit8)
    /// both carry vA, vB, and the literal in vC.
    fn binoplit(opcode: u8, v_a: i64, v_b: i64, lit: i64) -> Instruction {
        let operator = decode_op(opcode).unwrap_or(0);
        Instruction {
            opcode,
            address: 0,
            codepoint: 0,
            fmt: if opcode <= 0xd7 { "22s" } else { "22b" },
            instruction_str: String::new(),
            width: 2,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::BinOpLit { operator_type: operator },
            v_a: Some(v_a),
            v_b: Some(v_b),
            v_c: Some(lit),
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: vec![v_a, v_b, lit],
        }
    }

    fn make(values: &[i64]) -> Registers {
        values.iter().map(|n| Some(Value::Int(*n))).collect()
    }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── decode_op coverage ────────────────────────────────────

    #[test]
    fn decode_op_lit16_range() {
        assert_eq!(decode_op(0xd0), Some(0));  // add-int/lit16
        assert_eq!(decode_op(0xd1), Some(1));  // rsub-int/lit16
        assert_eq!(decode_op(0xd7), Some(7));  // xor-int/lit16
    }

    #[test]
    fn decode_op_lit8_range() {
        assert_eq!(decode_op(0xd8), Some(0));  // add-int/lit8
        assert_eq!(decode_op(0xd9), Some(1));  // rsub-int/lit8
        assert_eq!(decode_op(0xe2), Some(10)); // ushr-int/lit8
    }

    #[test]
    fn decode_op_out_of_range() {
        assert_eq!(decode_op(0xcf), None);
        assert_eq!(decode_op(0xe3), None);
    }

    // ── lit16 ops ────────────────────────────────────────────

    #[test]
    fn add_int_lit16() {
        let mut regs = make(&[0, 10]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd0, 0, 1, 5), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 15);
    }

    #[test]
    fn rsub_int_lit16_swaps_operand_order() {
        // rsub: vA = literal - vB (note the swap).
        // vB = 7, literal = 10 → 10 - 7 = 3.
        let mut regs = make(&[0, 7]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd1, 0, 1, 10), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 3);
    }

    #[test]
    fn rsub_int_lit16_with_negative_result_then_post_mask() {
        // vB = 100, literal = 5 → 5 - 100 = -95. Negative results
        // get mangled by Python's off-by-two post-mask:
        // -95 & 0xFFFFFFFF = 0xFFFFFFA1, > 0x7FFFFFFF → subtract
        // 0xFFFFFFFE → -93. Reference (buggy) output is -93.
        let mut regs = make(&[0, 100]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd1, 0, 1, 5), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -93);
    }

    #[test]
    fn mul_int_lit16() {
        let mut regs = make(&[0, 6]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd2, 0, 1, 7), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 42);
    }

    #[test]
    fn div_int_lit16_uses_floor_div_then_post_mask() {
        let mut regs = make(&[0, -7]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd3, 0, 1, 2), &mut regs, &mut mem);
        // -7 // 2 = -4, then post-mask mangles → -2.
        assert_eq!(read(&regs, 0), -2);
    }

    #[test]
    fn div_int_lit16_by_zero_returns_zero() {
        let mut regs = make(&[0, 100]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd3, 0, 1, 0), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn and_int_lit16() {
        let mut regs = make(&[0, 0xFF]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd5, 0, 1, 0x0F), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x0F);
    }

    #[test]
    fn or_int_lit16() {
        let mut regs = make(&[0, 0xF0]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd6, 0, 1, 0x0F), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xFF);
    }

    #[test]
    fn xor_int_lit16() {
        let mut regs = make(&[0, 0xFF]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd7, 0, 1, 0x0F), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xF0);
    }

    // ── lit8 ops ─────────────────────────────────────────────

    #[test]
    fn add_int_lit8() {
        let mut regs = make(&[0, 10]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd8, 0, 1, 5), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 15);
    }

    #[test]
    fn rsub_int_lit8_also_swaps() {
        let mut regs = make(&[0, 7]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd9, 0, 1, 10), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 3);
    }

    #[test]
    fn shl_int_lit8_uses_24_bit_mask_quirk() {
        // 1 << 24 = 0x1000000. Python masks to 0xFFFFFF = 0.
        let mut regs = make(&[0, 1]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xe0, 0, 1, 24), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn shr_int_lit8() {
        // 0x100 >> 4 = 0x10.
        let mut regs = make(&[0, 0x100]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xe1, 0, 1, 4), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x10);
    }

    #[test]
    fn ushr_int_lit8_quirk_24_bit_mask() {
        // From the Python quirk test: b = -16, c = 4
        // shift = (-16) % (1<<32) = 0xFFFFFFF0; >> 4 = 0x0FFFFFFF
        // masked to 0xFFFFFF = 0xFFFFFF
        let mut regs = make(&[0, -16]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xe2, 0, 1, 4), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xFFFFFF);
    }

    // ── Python int post-mask off-by-two interaction ─────────

    #[test]
    fn add_int_lit_post_mask_uses_python_off_by_two() {
        // vB = 0x40000000, literal = 0x40000000 → sum = 0x80000000.
        // Python's int post-mask gives -2147483646 (not -2147483648).
        let mut regs = make(&[0, 0x40000000]);
        let mut mem  = Memory::new();
        execute(&binoplit(0xd0, 0, 1, 0x40000000), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), -2147483646);
    }

    // ── Defensive ───────────────────────────────────────────

    #[test]
    fn missing_operands_default_to_zero() {
        let mut regs: Registers = vec![None; 4];
        let mut mem  = Memory::new();
        let mut instr = binoplit(0xd0, 0, 0, 0);
        instr.v_a = None; instr.v_b = None; instr.v_c = None;
        execute(&instr, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }
}
