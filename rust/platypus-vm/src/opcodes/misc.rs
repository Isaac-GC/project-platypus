//! Miscellaneous opcodes: Monitor / CheckCast / InstanceOf /
//! NewInstance / ArrLength / Throw / Array.
//!
//! Direct ports of the corresponding `*.execute` methods from
//! `dex/instructions_new.py`. Several of these classes don't define
//! `execute()` at all in Python (Monitor, CheckCast, InstanceOf),
//! so the Rust ports are explicit no-ops that consume the
//! instruction and return Continue.
//!
//! Opcode coverage:
//! | range / opcode | family       |
//! |----------------|--------------|
//! | 0x1d, 0x1e     | monitor-enter / monitor-exit  |
//! | 0x1f           | check-cast                    |
//! | 0x20           | instance-of                   |
//! | 0x21           | array-length                  |
//! | 0x22           | new-instance                  |
//! | 0x23-0x26      | new-array / filled-new-array / ... / fill-array-data |
//!
//! ### Python quirks preserved
//!
//! 1. **Monitor / CheckCast / InstanceOf have no execute() impl.**
//!    Python's class lacks the method entirely; the interpreter
//!    would raise AttributeError when called. We treat as no-op
//!    (Continue) since AttributeError-as-no-op is the most charitable
//!    interpretation of a missing method.
//!
//! 2. **ArrLength TypeErrors silently → 0.** If vB isn't indexable,
//!    Python catches TypeError and writes 0. We mirror.
//!
//! 3. **NewInstance writes the type name as a string.** For
//!    java.lang.String types, the string is empty. The Python
//!    behaviour treats every object as a stub-string-sentinel — not
//!    great but it's what the reference does.
//!
//! 4. **filled-new-array/range (0x25) Python impl is nonsensical**
//!    — it does a register-slice assignment to an out-of-bounds
//!    index, then assigns the slice to a local variable that's never
//!    used. We no-op for parity (anything else would diverge).
//!
//! 5. **fill-array-data (0x26)** reads from `memory.fd` which doesn't
//!    exist in our Rust Memory. For now we no-op; this needs payload
//!    decode integration which is in the Instruction's kind already
//!    (`FillArrayDataPayload`). Out of scope for the misc family —
//!    see task #16 follow-up.

use platypus_dex::instructions::{Instruction, InstructionKind};

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::{read_int, write_int, write_val};

// ── Monitor / CheckCast / InstanceOf ──────────────────────────

/// Execute a Monitor / CheckCast / InstanceOf instruction. Python
/// has no execute() impl; treat as no-op.
pub fn execute_noop(_instr: &Instruction, _regs: &mut Registers, _mem: &mut Memory) -> InstrResult {
    InstrResult::Continue
}

// ── ArrLength ────────────────────────────────────────────────

/// Execute an array-length instruction (0x21). Writes len(vB) into vA.
/// Returns 0 on type mismatch (mirrors Python's TypeError fallback).
pub fn execute_arr_length(instr: &Instruction, regs: &mut Registers, _mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;

    let len = regs.get(v_b as usize)
        .and_then(|s| s.as_ref())
        .map(|v| match v {
            Value::Array(_) => v.array_len().unwrap_or(0) as i64,
            Value::Bytes(b) => b.len() as i64,
            Value::Str(s)   => s.len() as i64,
            _               => 0, // TypeError equivalent
        })
        .unwrap_or(0);

    write_int(regs, v_a, len);
    InstrResult::Continue
}

// ── NewInstance ──────────────────────────────────────────────

/// Execute a new-instance instruction (0x22). Writes a string
/// sentinel into vA representing the new object's type. For String
/// types we write empty string; for everything else we write the
/// type name from the instruction_str.
///
/// Python implementation looks up `memory.dex.type_ids[vB].type_name`;
/// we approximate by extracting the type name from `instruction_str`
/// (which the dex decoder builds during instruction decoding).
pub fn execute_new_instance(instr: &Instruction, regs: &mut Registers, _mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;

    // Extract type name from instruction_str — last whitespace-separated token.
    let type_name = instr.instruction_str
        .split_whitespace()
        .last()
        .unwrap_or("object")
        .to_string();

    // Python: if "String" in type_name → ""; else → type_name.
    let value = if type_name.contains("String") {
        Value::Str(String::new())
    } else {
        Value::Str(type_name)
    };

    write_val(regs, v_a, value);
    InstrResult::Continue
}

// ── Array ────────────────────────────────────────────────────

/// Execute an Array-family instruction (0x23-0x26).
pub fn execute_array(instr: &Instruction, regs: &mut Registers, _mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;

    match instr.opcode {
        // new-array vA, vB, type@CCCC — vA = [0] * vB (Python).
        // We use Value::Array filled with Int(0).
        0x23 => {
            let len = read_int(regs, v_b);
            let len = if len < 0 { 0 } else { len as usize };
            // Cap at a sane maximum so a junk register value doesn't
            // OOM us. Python has no such cap but real APKs don't
            // allocate gigantic arrays inline.
            let len = len.min(1 << 20);
            let arr = vec![Value::Int(0); len];
            write_val(regs, v_a, Value::new_array(arr));
        }

        // filled-new-array — Python does [""] * regs[vB]. We mirror.
        0x24 => {
            let len = read_int(regs, v_b);
            let len = if len < 0 { 0 } else { len as usize };
            let len = len.min(1 << 20);
            let arr = vec![Value::Str(String::new()); len];
            write_val(regs, v_a, Value::new_array(arr));
        }

        // filled-new-array/range — Python impl is nonsensical (see
        // module-level doc). No-op for parity.
        0x25 => {}

        // fill-array-data — the payload lives at a different instruction in
        // the stream, which we can't see from here. It's handled in
        // `vm::execute_block` (which has the instruction list) via
        // `fill_array_data_inplace`, *before* this no-op runs.
        0x26 => {
            let _ = InstructionKind::Nop; // touch the import
        }

        _ => {}
    }

    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::ControlFlow;

    fn instr(opcode: u8, kind: InstructionKind, instruction_str: &str,
             v_a: Option<i64>, v_b: Option<i64>, v_c: Option<i64>) -> Instruction {
        Instruction {
            opcode, address: 0, codepoint: 0, fmt: "21c",
            instruction_str: instruction_str.to_string(), width: 1,
            control_flow: ControlFlow::FallThrough,
            kind,
            v_a, v_b, v_c,
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: [v_a, v_b, v_c].iter().filter_map(|&v| v).collect(),
        }
    }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── Monitor / CheckCast / InstanceOf — no-op ───────────────

    #[test]
    fn monitor_enter_is_noop() {
        let i = instr(0x1d, InstructionKind::Monitor, "monitor-enter v0", Some(0), None, None);
        let mut regs: Registers = vec![Some(Value::Int(42))];
        let mut mem = Memory::new();
        execute_noop(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 42);  // unchanged
    }

    #[test]
    fn check_cast_is_noop() {
        let i = instr(0x1f, InstructionKind::CheckCast, "check-cast v0, Ljava/lang/Object;", Some(0), Some(1), None);
        let mut regs: Registers = vec![Some(Value::Int(99))];
        let mut mem = Memory::new();
        execute_noop(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 99);
    }

    #[test]
    fn instance_of_is_noop() {
        let i = instr(0x20, InstructionKind::InstanceOf, "instance-of v0 v1, Ljava/lang/String;", Some(0), Some(1), Some(2));
        let mut regs: Registers = vec![Some(Value::Int(0))];
        let mut mem = Memory::new();
        execute_noop(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    // ── ArrLength ────────────────────────────────────────────

    #[test]
    fn arr_length_returns_array_length() {
        let i = instr(0x21, InstructionKind::ArrLength, "", Some(0), Some(1), None);
        let mut regs: Registers = vec![None, Some(Value::new_array(vec![Value::Int(1); 5]))];
        let mut mem = Memory::new();
        execute_arr_length(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 5);
    }

    #[test]
    fn arr_length_returns_bytes_length() {
        let i = instr(0x21, InstructionKind::ArrLength, "", Some(0), Some(1), None);
        let mut regs: Registers = vec![None, Some(Value::Bytes(vec![0u8; 10]))];
        let mut mem = Memory::new();
        execute_arr_length(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 10);
    }

    #[test]
    fn arr_length_returns_string_length() {
        let i = instr(0x21, InstructionKind::ArrLength, "", Some(0), Some(1), None);
        let mut regs: Registers = vec![None, Some(Value::Str("hello".to_string()))];
        let mut mem = Memory::new();
        execute_arr_length(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 5);
    }

    #[test]
    fn arr_length_type_error_returns_zero() {
        let i = instr(0x21, InstructionKind::ArrLength, "", Some(0), Some(1), None);
        let mut regs: Registers = vec![None, Some(Value::Int(42))]; // not indexable
        let mut mem = Memory::new();
        execute_arr_length(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
    }

    // ── NewInstance ──────────────────────────────────────────

    #[test]
    fn new_instance_string_type_writes_empty_string() {
        let i = instr(0x22, InstructionKind::NewInstance,
                      "new-instance v0, Ljava/lang/String;",
                      Some(0), Some(1), None);
        let mut regs: Registers = vec![None];
        let mut mem = Memory::new();
        execute_new_instance(&i, &mut regs, &mut mem);
        match regs[0].as_ref().unwrap() {
            Value::Str(s) => assert_eq!(s, ""),
            other => panic!("expected empty string, got {:?}", other),
        }
    }

    #[test]
    fn new_instance_non_string_writes_type_name() {
        let i = instr(0x22, InstructionKind::NewInstance,
                      "new-instance v0, Ljava/util/HashMap;",
                      Some(0), Some(1), None);
        let mut regs: Registers = vec![None];
        let mut mem = Memory::new();
        execute_new_instance(&i, &mut regs, &mut mem);
        match regs[0].as_ref().unwrap() {
            Value::Str(s) => assert_eq!(s, "Ljava/util/HashMap;"),
            other => panic!("expected Str, got {:?}", other),
        }
    }

    // ── Array ────────────────────────────────────────────────

    #[test]
    fn new_array_creates_zero_filled_array() {
        let i = instr(0x23, InstructionKind::Array, "", Some(0), Some(1), Some(2));
        let mut regs: Registers = vec![None, Some(Value::Int(3))];
        let mut mem = Memory::new();
        execute_array(&i, &mut regs, &mut mem);
        let v = regs[0].as_ref().unwrap();
        let items = v.array_snapshot()
            .unwrap_or_else(|| panic!("expected Array, got {:?}", v));
        assert_eq!(items.len(), 3);
        assert!(items.iter().all(|v| v.as_int() == Some(0)));
    }

    #[test]
    fn new_array_zero_length() {
        let i = instr(0x23, InstructionKind::Array, "", Some(0), Some(1), Some(2));
        let mut regs: Registers = vec![None, Some(Value::Int(0))];
        let mut mem = Memory::new();
        execute_array(&i, &mut regs, &mut mem);
        let v = regs[0].as_ref().unwrap();
        assert_eq!(
            v.array_len().unwrap_or_else(|| panic!("expected Array, got {:?}", v)),
            0,
        );
    }

    #[test]
    fn new_array_negative_length_treated_as_zero() {
        let i = instr(0x23, InstructionKind::Array, "", Some(0), Some(1), Some(2));
        let mut regs: Registers = vec![None, Some(Value::Int(-5))];
        let mut mem = Memory::new();
        execute_array(&i, &mut regs, &mut mem);
        let v = regs[0].as_ref().unwrap();
        assert_eq!(
            v.array_len().unwrap_or_else(|| panic!("expected Array, got {:?}", v)),
            0,
        );
    }

    #[test]
    fn filled_new_array_creates_empty_string_array() {
        let i = instr(0x24, InstructionKind::Array, "", Some(0), Some(1), Some(2));
        let mut regs: Registers = vec![None, Some(Value::Int(2))];
        let mut mem = Memory::new();
        execute_array(&i, &mut regs, &mut mem);
        let v = regs[0].as_ref().unwrap();
        let items = v.array_snapshot()
            .unwrap_or_else(|| panic!("expected Array, got {:?}", v));
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|v| matches!(v, Value::Str(s) if s.is_empty())));
    }

    #[test]
    fn filled_new_array_range_is_noop() {
        // Python impl is nonsensical; we no-op.
        let i = instr(0x25, InstructionKind::Array, "", Some(0), Some(1), Some(2));
        let mut regs: Registers = vec![Some(Value::Int(0xDEAD))];
        let mut mem = Memory::new();
        execute_array(&i, &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD); // unchanged
    }
}
