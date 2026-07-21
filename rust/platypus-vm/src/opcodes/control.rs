//! Control-flow family: Goto / Switch / If / IfZ.
//!
//! Direct ports of `Goto.execute`, `Switch.execute`, `If.execute`,
//! `IfZ.execute` from `dex/instructions_new.py`.
//!
//! Opcode coverage:
//! | range       | family    | opcodes               |
//! |-------------|-----------|------------------------|
//! | 0x28-0x2a   | Goto      | goto, goto/16, goto/32 |
//! | 0x2b-0x2c   | Switch    | packed-switch, sparse-switch |
//! | 0x32-0x37   | If        | if-eq, if-ne, if-lt, if-ge, if-gt, if-le |
//! | 0x38-0x3d   | IfZ       | if-eqz, if-nez, if-ltz, if-gez, if-gtz, if-lez |
//!
//! ### Python bugs preserved verbatim
//!
//! 1. **If.execute is gated on `if registers[vA] and registers[vB]`.**
//!    The comparison only runs when BOTH operands are truthy (non-zero,
//!    non-None). If either is zero, the conditional is silently NOT
//!    taken regardless of operator. So `if-eq v0, v1` where v0=0 and
//!    v1=0 returns "not taken" (Python's `taken` defaults to False).
//!    This is wrong for if-eq (0 == 0 should be true) but matches
//!    the Python reference. Real APKs that depend on this branch
//!    will get the wrong control flow — that's a Python parity
//!    issue, not ours.
//!
//! 2. **IfZ.execute is gated on `if registers[vA]:`.** Same pattern —
//!    the comparison only runs when vA is truthy. So `if-eqz v0`
//!    with v0=0 returns "not taken" even though 0 == 0 should be
//!    true. This is catastrophic for real APKs (if-eqz is the most
//!    common conditional in Dalvik) but it's what the reference
//!    does.
//!
//! 3. **IfZ has a typo at opcode 0x3d (if-lez).** The Python source
//!    reads `case 0x3d: tkane = val <= 0` — note `tkane` instead of
//!    `taken`. So if-lez NEVER branches (taken stays False, and the
//!    typo-variable `tkane` is set but unused). Faithfully preserved
//!    in this port.
//!
//! 4. **Goto.execute returns `self.vA` (the raw offset), not the
//!    target codepoint.** The dispatch loop must add codepoint to
//!    the returned offset. In Rust we compute the target here and
//!    return InstrResult::Goto(target_cp) — same semantics, just
//!    folded together.
//!
//! 5. **Switch.execute writes `memory.last_exception = target`** when
//!    a match is found. That looks like a bug — exception state used
//!    for a normal branch target. We mirror by writing to the
//!    `last_exception` field (which exists in Memory).
//!
//! Some of these bugs are bad enough that wiring this module into
//! the live VM would catastrophically break real APKs. We keep the
//! existing inline implementations in vm.rs intact as the
//! production path; this module is for parity testing and as a
//! reference. If you want the "Python-quirks-as-features" mode,
//! point dispatch at this module.

use platypus_dex::instructions::{Instruction, InstructionKind};

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::read_int;

// ── Helpers ─────────────────────────────────────────────────────

/// Sign-extend a value `width` bits wide to i64.
fn sign_extend(v: i64, width: u32) -> i64 {
    let shift = 64 - width;
    ((v << shift) as i64) >> shift
}

// ── Goto ────────────────────────────────────────────────────────

/// Execute a Goto instruction (0x28-0x2a). Unconditional branch.
pub fn execute_goto(instr: &Instruction, _regs: &mut Registers, _mem: &mut Memory) -> InstrResult {
    let off = instr.v_a.unwrap_or(0);
    let width = match instr.opcode {
        0x28 => 8,
        0x29 => 16,
        0x2a => 32,
        _ => return InstrResult::Continue,
    };
    let extended = sign_extend(off, width);
    let target = (instr.codepoint as i64 + extended) as u32;
    InstrResult::Goto(target)
}

// ── Switch ──────────────────────────────────────────────────────

/// Execute a Switch instruction (0x2b-0x2c). Look up the value of
/// vA in the pre-decoded table; jump if found, fall through if not.
pub fn execute_switch(instr: &Instruction, regs: &mut Registers, mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let val = read_int(regs, v_a) as i32;

    let table = match &instr.kind {
        InstructionKind::Switch { table } => &table.table,
        _ => return InstrResult::Continue,
    };

    if let Some(&rel) = table.get(&val) {
        let target = (instr.codepoint as i64 + rel as i64) as u32;
        // Python writes last_exception here (looks like a bug — should
        // be last_return or similar — but we mirror by stashing the
        // target codepoint as an Int).
        mem.last_exception = Some(Value::Int(target as i64));
        InstrResult::Goto(target)
    } else {
        mem.last_return = None;
        InstrResult::Continue
    }
}

// ── If ──────────────────────────────────────────────────────────

/// Execute an If instruction (0x32-0x37). Compare vA vs vB; branch
/// on `vC` (a 16-bit signed offset) if the condition holds.
///
/// **Python quirk:** the comparison is gated on `if vA and vB:` —
/// if either is zero, taken always stays False.
pub fn execute_if(instr: &Instruction, regs: &mut Registers, _mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;
    let off = instr.v_c.unwrap_or(0);

    let av = read_int(regs, v_a);
    let bv = read_int(regs, v_b);

    let mut taken = false;
    // Python: `if registers[self.vA] and registers[self.vB]:`
    if av != 0 && bv != 0 {
        taken = match instr.opcode {
            0x32 => av == bv,
            0x33 => av != bv,
            0x34 => av <  bv,
            0x35 => av >= bv,
            0x36 => av >  bv,
            0x37 => av <= bv,
            _    => false,
        };
    }

    if taken {
        let target = (instr.codepoint as i64 + sign_extend(off, 16)) as u32;
        InstrResult::Branch(Some(target))
    } else {
        InstrResult::Branch(None)
    }
}

// ── IfZ ─────────────────────────────────────────────────────────

/// Execute an IfZ instruction (0x38-0x3d). Compare vA against zero;
/// branch on `vB` (16-bit signed offset).
///
/// **Python quirks:**
/// - Gated on `if registers[vA]:` — if vA is zero, the match never
///   runs and `taken` stays False. So `if-eqz v0` with v0=0 returns
///   "not taken" — catastrophically wrong but mirrored.
/// - opcode 0x3d (if-lez) has a typo in the source (`tkane` instead
///   of `taken`) so if-lez NEVER branches.
pub fn execute_ifz(instr: &Instruction, regs: &mut Registers, _mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let off = instr.v_b.unwrap_or(0);

    let val = read_int(regs, v_a);

    let mut taken = false;
    // Python: `if registers[self.vA]:`
    if val != 0 {
        taken = match instr.opcode {
            0x38 => val == 0,
            0x39 => val != 0,
            0x3a => val <  0,
            0x3b => val >= 0,
            0x3c => val >  0,
            0x3d => false, // Python typo: `tkane` instead of `taken`.
            _    => false,
        };
    }

    if taken {
        let target = (instr.codepoint as i64 + sign_extend(off, 16)) as u32;
        InstrResult::Branch(Some(target))
    } else {
        InstrResult::Branch(None)
    }
}

// ── Throw ───────────────────────────────────────────────────────

/// Execute a Throw instruction (0x27). Sets last_exception and
/// terminates the method.
pub fn execute_throw(instr: &Instruction, _regs: &mut Registers, mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0);
    // Python: `memory.last_exception = self.vA`. Stash the register
    // index as an Int — the host's exception handler is what decides
    // how to interpret it.
    mem.last_exception = Some(Value::Int(v_a));
    // Python's Throw has control_flow = Terminate. We return Return(None)
    // to match the dispatch loop's "method ends" semantics.
    InstrResult::Return(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value::Value;
    use platypus_dex::instructions::{ControlFlow, SwitchTable};
    use std::collections::HashMap;

    fn instr(opcode: u8, kind: InstructionKind, fmt: &'static str,
             v_a: Option<i64>, v_b: Option<i64>, v_c: Option<i64>,
             codepoint: u32) -> Instruction {
        Instruction {
            opcode, address: 0, codepoint,
            fmt, instruction_str: String::new(),
            width: 1, control_flow: ControlFlow::FallThrough,
            kind,
            v_a, v_b, v_c,
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: [v_a, v_b, v_c].iter().filter_map(|&v| v).collect(),
        }
    }

    fn make(values: &[i64]) -> Registers {
        values.iter().map(|n| Some(Value::Int(*n))).collect()
    }

    // ── Goto ───────────────────────────────────────────────

    #[test]
    fn goto_8bit_forward() {
        let i = instr(0x28, InstructionKind::Goto, "10t", Some(5), None, None, 100);
        let mut regs: Registers = vec![];
        let mut mem = Memory::new();
        match execute_goto(&i, &mut regs, &mut mem) {
            InstrResult::Goto(t) => assert_eq!(t, 105),
            other => panic!("expected Goto, got {:?}", other),
        }
    }

    #[test]
    fn goto_8bit_backward_sign_extends() {
        // -5 as 8-bit signed: 0xFB = 251. Sign-extended to -5.
        let i = instr(0x28, InstructionKind::Goto, "10t", Some(251), None, None, 100);
        let mut regs: Registers = vec![];
        let mut mem = Memory::new();
        match execute_goto(&i, &mut regs, &mut mem) {
            InstrResult::Goto(t) => assert_eq!(t, 95),
            other => panic!("expected Goto, got {:?}", other),
        }
    }

    #[test]
    fn goto_16bit_sign_extends() {
        // -100 as 16-bit signed: 0xFF9C = 65436. Sign-extended to -100.
        let i = instr(0x29, InstructionKind::Goto, "20t", Some(65436), None, None, 200);
        let mut regs: Registers = vec![];
        let mut mem = Memory::new();
        match execute_goto(&i, &mut regs, &mut mem) {
            InstrResult::Goto(t) => assert_eq!(t, 100),
            other => panic!("expected Goto, got {:?}", other),
        }
    }

    // ── Switch ────────────────────────────────────────────

    #[test]
    fn switch_hits_returns_goto_target() {
        let mut table = HashMap::new();
        table.insert(5i32, 20i32);   // key=5 → +20 offset
        let kind = InstructionKind::Switch { table: SwitchTable { table } };
        let i = instr(0x2b, kind, "31t", Some(0), None, None, 100);
        let mut regs = make(&[5]);
        let mut mem = Memory::new();
        match execute_switch(&i, &mut regs, &mut mem) {
            InstrResult::Goto(t) => assert_eq!(t, 120),
            other => panic!("expected Goto, got {:?}", other),
        }
    }

    #[test]
    fn switch_miss_continues_through() {
        let mut table = HashMap::new();
        table.insert(5i32, 20i32);
        let kind = InstructionKind::Switch { table: SwitchTable { table } };
        let i = instr(0x2b, kind, "31t", Some(0), None, None, 100);
        let mut regs = make(&[42]); // key 42 not in table
        let mut mem = Memory::new();
        match execute_switch(&i, &mut regs, &mut mem) {
            InstrResult::Continue => {},
            other => panic!("expected Continue, got {:?}", other),
        }
    }

    // ── If — Python quirks ────────────────────────────────

    #[test]
    fn if_eq_correctly_branches_when_both_nonzero_and_equal() {
        let i = instr(0x32, InstructionKind::If, "22t", Some(0), Some(1), Some(50), 100);
        let mut regs = make(&[7, 7]);
        let mut mem = Memory::new();
        match execute_if(&i, &mut regs, &mut mem) {
            InstrResult::Branch(Some(t)) => assert_eq!(t, 150),
            other => panic!("expected Branch(Some), got {:?}", other),
        }
    }

    #[test]
    fn if_eq_python_bug_when_either_is_zero() {
        // BUG: vA=0 and vB=0 should be equal, but Python's gate is
        // `if vA and vB:` so the comparison never runs and taken=False.
        let i = instr(0x32, InstructionKind::If, "22t", Some(0), Some(1), Some(50), 100);
        let mut regs = make(&[0, 0]);
        let mut mem = Memory::new();
        match execute_if(&i, &mut regs, &mut mem) {
            InstrResult::Branch(None) => {},
            other => panic!("expected Branch(None) per Python bug, got {:?}", other),
        }
    }

    #[test]
    fn if_lt_works_normally_when_both_nonzero() {
        let i = instr(0x34, InstructionKind::If, "22t", Some(0), Some(1), Some(10), 50);
        let mut regs = make(&[3, 7]); // 3 < 7 → taken
        let mut mem = Memory::new();
        match execute_if(&i, &mut regs, &mut mem) {
            InstrResult::Branch(Some(t)) => assert_eq!(t, 60),
            other => panic!("expected Branch(Some), got {:?}", other),
        }
    }

    // ── IfZ — Python quirks ───────────────────────────────

    #[test]
    fn ifz_eqz_python_bug_skips_check_when_val_is_zero() {
        // BUG: if-eqz v0 with v0=0 should branch, but Python's
        // `if registers[vA]:` gate fails when vA is 0.
        let i = instr(0x38, InstructionKind::IfZ, "21t", Some(0), Some(50), None, 100);
        let mut regs = make(&[0]);
        let mut mem = Memory::new();
        match execute_ifz(&i, &mut regs, &mut mem) {
            InstrResult::Branch(None) => {},
            other => panic!("expected Branch(None) per Python bug, got {:?}", other),
        }
    }

    #[test]
    fn ifz_nez_works_when_val_is_nonzero() {
        // if-nez v0=5: 5 != 0 → taken.
        let i = instr(0x39, InstructionKind::IfZ, "21t", Some(0), Some(10), None, 50);
        let mut regs = make(&[5]);
        let mut mem = Memory::new();
        match execute_ifz(&i, &mut regs, &mut mem) {
            InstrResult::Branch(Some(t)) => assert_eq!(t, 60),
            other => panic!("expected Branch(Some), got {:?}", other),
        }
    }

    #[test]
    fn ifz_ltz_works_when_val_is_negative_nonzero() {
        let i = instr(0x3a, InstructionKind::IfZ, "21t", Some(0), Some(10), None, 50);
        let mut regs = make(&[-1]); // truthy and negative → taken
        let mut mem = Memory::new();
        match execute_ifz(&i, &mut regs, &mut mem) {
            InstrResult::Branch(Some(t)) => assert_eq!(t, 60),
            other => panic!("expected Branch(Some), got {:?}", other),
        }
    }

    #[test]
    fn ifz_lez_python_typo_never_branches() {
        // Python typo: `tkane = val <= 0` instead of `taken`. So
        // if-lez NEVER branches even when val < 0 (the gate passes
        // for val=-5).
        let i = instr(0x3d, InstructionKind::IfZ, "21t", Some(0), Some(10), None, 50);
        let mut regs = make(&[-5]);
        let mut mem = Memory::new();
        match execute_ifz(&i, &mut regs, &mut mem) {
            InstrResult::Branch(None) => {},
            other => panic!("expected Branch(None) per Python typo, got {:?}", other),
        }
    }

    // ── Throw ───────────────────────────────────────────────

    #[test]
    fn throw_returns_none_and_sets_last_exception() {
        let i = instr(0x27, InstructionKind::Throw, "11x", Some(3), None, None, 100);
        let mut regs = make(&[]);
        let mut mem = Memory::new();
        match execute_throw(&i, &mut regs, &mut mem) {
            InstrResult::Return(None) => {},
            other => panic!("expected Return(None), got {:?}", other),
        }
        assert!(mem.last_exception.is_some());
    }
}
