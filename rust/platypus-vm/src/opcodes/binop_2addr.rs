//! BinOp2Addr family (0xb0-0xcf): in-place arithmetic — vA = vA op vB.
//!
//! Direct port of `BinOp2Addr.execute` from `dex/instructions_new.py`
//! (lines 1363-1396). The opcode-to-(operator,operand) mapping is:
//!
//! | range       | operand_type | operator range            |
//! |-------------|--------------|---------------------------|
//! | 0xb0-0xba   | 0 (int)      | 0..10 = add..ushr         |
//! | 0xbb-0xc5   | 1 (long)     | 0..10 = add..ushr         |
//! | 0xc6-0xca   | 2 (float)    | 0..4  = add..rem          |
//! | 0xcb-0xcf   | 3 (double)   | 0..4  = add..rem          |
//!
//! ### Python quirks preserved verbatim
//!
//! 1. **For operand 0x0 (int):** computed correctly —
//!    `helper(operator, operand, vA, vB)`. Result writes to vA.
//!
//! 2. **For operand 0x1 (long): the local variable `a` is NEVER SET.**
//!    The Python code reads:
//!    ```python
//!    case 0x1: # long
//!        b = (registers[self.vA] << 32) or registers[self.vA + 1]
//!        if self.operator_type in [0x8, 0x9, 0xa]:
//!            c = registers[self.vB]
//!        else:
//!            c = (registers[self.vA] << 32) or registers[self.vA + 1]
//!    # ...
//!    a = reg_ops_helper(self.operator_type, self.operand_type, a, b)
//!    ```
//!    Note the helper call passes `(a, b)` — but `a` was never
//!    assigned in the long branch (it's still `None` from the
//!    initialiser), and the locally-computed `c` is *completely
//!    unused*. In Python this would raise TypeError on every
//!    long-2addr op (since `None + int` is unsupported); the
//!    Python codebase presumably either never exercises this path
//!    or relies on a silent upstream exception swallower.
//!
//!    We mirror the bug by treating the missing `a` as 0 (which is
//!    what `read_int` returns for None — the same default Python
//!    would land on if the TypeError were caught and ignored). The
//!    `c` value we read is set but never passed to the helper, just
//!    like in the Python.
//!
//! 3. **For operand 0x2 / 0x3 (float/double): same bug.** Both `b`
//!    and `c` are computed from vA (with Python `or` semantics),
//!    but the helper is called with `(a=None, b=wide_vA)`, so the
//!    locally-computed `c` is dropped.
//!
//! 4. **Result writer also has the same `0x4` dead branch and
//!    no-case-for-0x2 silent-drop quirk** as BinOp. Float results
//!    are silently discarded.
//!
//! These are mirrored byte-for-byte so divergence from the Python
//! reference is easy to spot. If a real APK needs the corrected
//! behaviour we can add a "spec-mode" override later.

use platypus_dex::instructions::Instruction;

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::{read_int, read_wide_python_or, write_int};
use super::helpers::reg_ops_helper;

/// Decode `(operator_type, operand_type)` from a BinOp2Addr opcode.
pub fn decode_op(opcode: u8) -> Option<(u8, u8)> {
    if (0xb0..=0xc5).contains(&opcode) {
        let operand  = (opcode - 0xb0) / 11;
        let operator = (opcode - 0xb0) % 11;
        Some((operator, operand))
    } else if (0xc6..=0xcf).contains(&opcode) {
        let operand  = (opcode - 0xc6) / 5 + 2;
        let operator = (opcode - 0xc6) % 5;
        Some((operator, operand))
    } else {
        None
    }
}

/// Execute a BinOp2Addr instruction (0xb0-0xcf). Mirrors
/// `BinOp2Addr.execute` from `dex/instructions_new.py`.
pub fn execute(
    instr: &Instruction,
    regs: &mut Registers,
    _mem: &mut Memory,
) -> InstrResult {
    let (operator, operand) = match instr.kind {
        platypus_dex::instructions::InstructionKind::BinOp2Addr { operator_type, operand_type } => {
            (operator_type, operand_type)
        }
        _ => match decode_op(instr.opcode) {
            Some(pair) => pair,
            None => return InstrResult::Continue,
        },
    };

    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;

    // ── Read operands. Per-branch behaviour mirrors Python ────
    let (lhs, rhs) = match operand {
        0x0 => {
            // int — straightforward. lhs = vA, rhs = vB.
            (read_int(regs, v_a), read_int(regs, v_b))
        }
        0x1 => {
            // long — Python BUG: local `a` is never set, so passed
            // as None (→ 0 in our representation). The local `c`
            // we'd compute below is DROPPED on the helper call.
            // We compute it anyway so the read-side semantics match
            // Python (in case it has side effects via `__getitem__`
            // someday).
            let _b_local = read_wide_python_or(regs, v_a);
            let _c_local = if matches!(operator, 0x8 | 0x9 | 0xa) {
                read_int(regs, v_b)
            } else {
                read_wide_python_or(regs, v_a)
            };
            // Helper is called with (a=None→0, b=wide_vA).
            (0i64, _b_local)
        }
        0x2 | 0x3 => {
            // float / double — same Python bug as long branch.
            let _b_local = read_wide_python_or(regs, v_a);
            let _c_local = read_wide_python_or(regs, v_a);
            (0i64, _b_local)
        }
        _ => (0, 0),
    };

    // ── Compute ────────────────────────────────────────────────
    let a = reg_ops_helper(operator, operand, lhs, rhs);

    // ── Write ──────────────────────────────────────────────────
    // Same writer-side quirks as BinOp: int|0x4 single-slot, long|double
    // wide split, float silently dropped.
    match operand {
        0x0 | 0x4 => {
            write_int(regs, v_a, a);
        }
        0x1 | 0x3 => {
            let high = a >> 32;
            let low  = (a as u64 & 0xFFFFFFFF) as i64;
            write_int(regs, v_a,     high);
            write_int(regs, v_a + 1, low);
        }
        _ => {
            // operand 0x2 (float) — Python writer has no case; drop.
        }
    }

    let _ = Value::Int(0); // silence unused import warning
    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    fn binop2(opcode: u8, v_a: i64, v_b: i64) -> Instruction {
        let (operator, operand) = decode_op(opcode).unwrap_or((0, 0));
        Instruction {
            opcode,
            address: 0,
            codepoint: 0,
            fmt: "12x",
            instruction_str: String::new(),
            width: 1,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::BinOp2Addr {
                operator_type: operator,
                operand_type:  operand,
            },
            v_a: Some(v_a),
            v_b: Some(v_b),
            v_c: None, v_d: None, v_e: None, v_f: None,
            v_g: None, v_h: None, v_z: None,
            operands: vec![v_a, v_b],
        }
    }

    fn make(values: &[i64]) -> Registers {
        values.iter().map(|n| Some(Value::Int(*n))).collect()
    }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── decode_op coverage ─────────────────────────────────────

    #[test]
    fn decode_op_int_range() {
        assert_eq!(decode_op(0xb0), Some((0, 0)));
        assert_eq!(decode_op(0xba), Some((10, 0)));
    }

    #[test]
    fn decode_op_long_range() {
        assert_eq!(decode_op(0xbb), Some((0, 1)));
        assert_eq!(decode_op(0xc5), Some((10, 1)));
    }

    #[test]
    fn decode_op_float_range() {
        assert_eq!(decode_op(0xc6), Some((0, 2)));
        assert_eq!(decode_op(0xca), Some((4, 2)));
    }

    #[test]
    fn decode_op_double_range() {
        assert_eq!(decode_op(0xcb), Some((0, 3)));
        assert_eq!(decode_op(0xcf), Some((4, 3)));
    }

    #[test]
    fn decode_op_out_of_range() {
        assert_eq!(decode_op(0xaf), None);
        assert_eq!(decode_op(0xd0), None);
    }

    // ── int operations (operand 0x0) — only the well-defined family ──

    #[test]
    fn add_int_2addr_computes_va_plus_vb() {
        let mut regs = make(&[10, 7]);
        let mut mem  = Memory::new();
        // 0xb0 = add-int/2addr. vA=0, vB=1.
        execute(&binop2(0xb0, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 17);
    }

    #[test]
    fn sub_int_2addr_uses_va_minus_vb() {
        let mut regs = make(&[10, 4]);
        let mut mem  = Memory::new();
        // 0xb1 = sub-int/2addr.
        execute(&binop2(0xb1, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 6);
    }

    #[test]
    fn mul_int_2addr() {
        let mut regs = make(&[6, 7]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb2, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 42);
    }

    #[test]
    fn div_int_2addr_uses_floor_div_then_post_mask() {
        let mut regs = make(&[-7, 2]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb3, 0, 1), &mut regs, &mut mem);
        // -7 // 2 = -4 → mangled by Python's off-by-two post-mask → -2.
        assert_eq!(read(&regs, 0), -2);
    }

    #[test]
    fn div_int_2addr_by_zero_returns_zero() {
        let mut regs = make(&[100, 0]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb3, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn rem_int_2addr_uses_python_mod() {
        // -7 % 3 = 2 — positive so unaffected by post-mask.
        let mut regs = make(&[-7, 3]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb4, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 2);
    }

    #[test]
    fn and_int_2addr() {
        let mut regs = make(&[0xFF, 0x0F]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb5, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x0F);
    }

    #[test]
    fn or_int_2addr() {
        let mut regs = make(&[0xF0, 0x0F]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb6, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xFF);
    }

    #[test]
    fn xor_int_2addr() {
        let mut regs = make(&[0xFF, 0x0F]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb7, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xF0);
    }

    #[test]
    fn shl_int_2addr_uses_24_bit_mask_quirk() {
        // 1 << 24 = 0x1000000, masked to 0xFFFFFF = 0.
        let mut regs = make(&[1, 24]);
        let mut mem  = Memory::new();
        execute(&binop2(0xb8, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    // ── long operations (operand 0x1) — Python bug preserved ─────

    #[test]
    fn add_long_2addr_uses_python_bug_path() {
        // Python BUG: the local `a` is never set. Helper is called
        // with (a=0, b=wide_vA). For add-long: a + b = 0 + wide_vA
        // = wide_vA. The actual vA contribution comes ONLY through
        // the wide read of vA — vB is never consulted for non-shift
        // long ops. Output writes back to vA.
        //
        // vA pair = [high=0, low=10] → b_local (passed as helper c) = 10
        // helper: 0 + 10 = 10. Write back: high=0, low=10.
        let mut regs = make(&[0, 10, 99, 99]);
        let mut mem  = Memory::new();
        // 0xbb = add-long/2addr. vA=0, vB=2.
        execute(&binop2(0xbb, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
        assert_eq!(read(&regs, 1), 10);
    }

    #[test]
    fn add_long_2addr_python_or_quirk_when_high_set() {
        // vA pair = [high=1, low=99] → wide read = (1<<32) or 99 = 1<<32.
        // helper: 0 + (1<<32) = 1<<32. Write high=1, low=0.
        let mut regs = make(&[1, 99]);
        let mut mem  = Memory::new();
        execute(&binop2(0xbb, 0, 1), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 1);
        assert_eq!(read(&regs, 1), 0);
    }

    #[test]
    fn shl_long_2addr_drops_c_per_python_bug() {
        // Even for shift ops, c_local IS computed (from vB) — but
        // the helper call still passes (a=None→0, b=wide_vA),
        // ignoring c. So 1 << 0 = 1; vB (the shift count) is unused.
        // vA pair = [0, 1] → wide read = 1.
        // helper(shl, long, 0, 1) → 0 << 1 = 0.
        let mut regs = make(&[0, 1, 5]);  // vB=2 holds 5; ignored.
        let mut mem  = Memory::new();
        execute(&binop2(0xc3, 0, 2), &mut regs, &mut mem);  // shl-long/2addr
        assert_eq!(read(&regs, 0), 0);
        assert_eq!(read(&regs, 1), 0);
    }

    // ── float operations (operand 0x2) — result dropped ────

    #[test]
    fn float_2addr_result_silently_dropped() {
        let mut regs = make(&[0xDEAD, 0, 5, 5]);
        let mut mem  = Memory::new();
        // 0xc6 = add-float/2addr.
        execute(&binop2(0xc6, 0, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD); // unchanged — float drop
    }

    // ── double operations (operand 0x3) — writes both halves ────

    #[test]
    fn add_double_2addr_writes_pair() {
        // vA pair = [0, 5] → wide read = 5. helper(add, double, 0, 5) = 5.
        // Write back: high=0, low=5.
        let mut regs = make(&[0, 5]);
        let mut mem  = Memory::new();
        execute(&binop2(0xcb, 0, 0), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
        assert_eq!(read(&regs, 1), 5);
    }
}
