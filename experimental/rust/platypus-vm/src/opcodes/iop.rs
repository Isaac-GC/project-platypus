//! IOp family (0x52-0x6d): iget / iput / sget / sput.
//!
//! Direct port of `IGet.execute`, `IPut.execute`, `SGet.execute`,
//! `SPut.execute` from `dex/instructions_new.py` (lines 1021-1115).
//!
//! Opcode coverage:
//! | range       | family       |
//! |-------------|--------------|
//! | 0x52-0x58   | iget / iget-wide / iget-object / ...  |
//! | 0x59-0x5f   | iput / iput-wide / iput-object / ...  |
//! | 0x60-0x66   | sget / sget-wide / sget-object / ...  |
//! | 0x67-0x6d   | sput / sput-wide / sput-object / ...  |
//!
//! Field key:
//! - IGet/IPut: vC holds the field reference index (format `22c`)
//! - SGet/SPut: vB holds the field reference index (format `21c`)
//!
//! ### Python quirks preserved verbatim
//!
//! 1. **No object identity.** Python uses `memory.instance_fields[field_idx]`
//!    — keyed only by field index, NOT by `(instance_id, field_idx)`.
//!    So two different objects of the same class share the same
//!    instance-field storage. Writing `obj1.foo = 5` then reading
//!    `obj2.foo` returns 5. This is wrong but mirrored.
//!
//! 2. **IGet default for missing field is 0** (`memory.instance_fields.get(vC, 0)`).
//!    SGet's default is None (`memory.static_fields.get(vB, None)`).
//!    Asymmetric — we mirror.
//!
//! 3. **Wide IGet (0x53) splits the loaded value across vA / vA+1.**
//!    After loading the value, swap so vA gets high half and vA+1
//!    gets low half. Matches the "high in vA, low in vA+1" layout.
//!
//! 4. **Wide IPut (0x5a) has a clear bug:**
//!    ```python
//!    memory.instance_fields[self.vC] = registers[self.vA]
//!    if self.opcode == 0x5a:
//!        memory.instance_fields[self.vC] <<= 32
//!        memory.instance_fields[self.vA] += registers[self.vA + 1]  # vA, not vC!
//!    ```
//!    The low half is added to a field keyed by the *register* index
//!    `vA` (almost certainly a typo for `vC`). We mirror.
//!
//! 5. **Wide SGet (0x61) catches TypeError on the bit-extraction**
//!    and falls back to setting both halves to 0. Mirrored.
//!
//! 6. **Wide SPut (0x68) packs vA (high) and vA+1 (low) into the
//!    field correctly** — no register-index bug here. But also
//!    catches TypeError and zeroes the field on error.

use platypus_dex::instructions::Instruction;

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::{read_int, write_int};

// ── IGet (0x52-0x58) ────────────────────────────────────────────

/// Execute an IGet instruction (0x52-0x58). Loads
/// `memory.instance_fields[vC]` into `registers[vA]`. For wide
/// (opcode 0x53), splits the loaded value into vA (high) and
/// vA+1 (low).
pub fn execute_iget(instr: &Instruction, regs: &mut Registers, mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_c = instr.v_c.unwrap_or(0) as usize;

    // Default to 0 (Python: `memory.instance_fields.get(vC, 0)`).
    let val = mem.instance_fields.get(&v_c)
        .and_then(|v| v.as_int())
        .unwrap_or(0);
    write_int(regs, v_a, val);

    if instr.opcode == 0x53 {
        // Wide: swap layout. high → vA, low → vA+1.
        let low  = (val as u64 & 0xFFFFFFFF) as i64;
        let high = val >> 32;
        write_int(regs, v_a + 1, low);
        write_int(regs, v_a,     high);
    }

    InstrResult::Continue
}

// ── IPut (0x59-0x5f) ────────────────────────────────────────────

/// Execute an IPut instruction (0x59-0x5f). Writes
/// `registers[vA]` into `memory.instance_fields[vC]`. For wide
/// (opcode 0x5a), the Python code has a bug: it adds the low half
/// to `instance_fields[vA]` (register index!) instead of
/// `instance_fields[vC]`. We mirror.
pub fn execute_iput(instr: &Instruction, regs: &mut Registers, mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_c = instr.v_c.unwrap_or(0) as usize;

    let high = read_int(regs, v_a);
    mem.instance_fields.insert(v_c, Value::Int(high));

    if instr.opcode == 0x5a {
        // Wide: shift the just-written value left 32 (becomes high half).
        mem.instance_fields.insert(v_c, Value::Int(high << 32));

        // Python BUG: add the low half to instance_fields[vA] (register
        // index), not [vC]. Mirror.
        let low = read_int(regs, v_a + 1);
        let key = v_a as usize;
        let existing = mem.instance_fields.get(&key)
            .and_then(|v| v.as_int())
            .unwrap_or(0);
        mem.instance_fields.insert(key, Value::Int(existing + low));
    }

    InstrResult::Continue
}

// ── SGet (0x60-0x66) ────────────────────────────────────────────

/// Execute an SGet instruction (0x60-0x66). Loads
/// `memory.static_fields[vB]` into `registers[vA]`. For wide
/// (opcode 0x61), splits across vA / vA+1 with TypeError fallback
/// to (0, 0).
pub fn execute_sget(instr: &Instruction, regs: &mut Registers, mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as usize;

    // Python: `memory.static_fields.get(vB, None)`. We can't store
    // None directly into a register slot via write_int — we use
    // write_val instead so the slot becomes None if the field isn't set.
    let val_opt = mem.static_fields.get(&v_b).cloned();

    match val_opt {
        Some(v) => {
            // Try to extract as int for the wide path.
            let int_val = v.as_int();
            // Always write what we have into vA.
            if let Some(n) = int_val {
                write_int(regs, v_a, n);
            } else {
                // Non-int value (Str, Bytes, etc.) — preserve verbatim.
                if let Some(slot) = regs.get_mut(v_a as usize) {
                    *slot = Some(v.clone());
                }
            }

            if instr.opcode == 0x61 {
                match int_val {
                    Some(n) => {
                        let low  = (n as u64 & 0xFFFFFFFF) as i64;
                        let high = n >> 32;
                        write_int(regs, v_a + 1, low);
                        write_int(regs, v_a,     high);
                    }
                    None => {
                        // Python catches TypeError → zero both halves.
                        write_int(regs, v_a,     0);
                        write_int(regs, v_a + 1, 0);
                    }
                }
            }
        }
        None => {
            // Field missing — Python writes None. We clear vA.
            if let Some(slot) = regs.get_mut(v_a as usize) {
                *slot = None;
            }
            if instr.opcode == 0x61 {
                // Wide path with None → both halves cleared.
                if let Some(slot) = regs.get_mut(v_a as usize + 1) {
                    *slot = None;
                }
            }
        }
    }

    InstrResult::Continue
}

// ── SPut (0x67-0x6d) ────────────────────────────────────────────

/// Execute an SPut instruction (0x67-0x6d). Writes
/// `registers[vA]` into `memory.static_fields[vB]`. For wide
/// (opcode 0x68), packs vA (high) << 32 + vA+1 (low) into the
/// field, with TypeError fallback that zeroes the field.
pub fn execute_sput(instr: &Instruction, regs: &mut Registers, mem: &mut Memory) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as usize;

    // Preserve full Value type so non-int values (Str, Bytes, Null,
    // Array) round-trip through the field. Most real APKs sput a
    // String or array reference here.
    let val = match regs.get(v_a as usize).and_then(|s| s.clone()) {
        Some(v) => v,
        None => Value::Null,
    };
    mem.static_fields.insert(v_b, val.clone());

    if instr.opcode == 0x68 {
        // Wide. Python: `field <<= 32; field += regs[vA+1]`.
        match val.as_int() {
            Some(high) => {
                let low = read_int(regs, v_a + 1);
                let packed = (high << 32).wrapping_add(low);
                mem.static_fields.insert(v_b, Value::Int(packed));
            }
            None => {
                // TypeError fallback: reset field to 0.
                mem.static_fields.insert(v_b, Value::Int(0));
            }
        }
    }

    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    fn iget(opcode: u8, v_a: i64, v_b: i64, v_c: i64) -> Instruction {
        Instruction {
            opcode, address: 0, codepoint: 0, fmt: "22c",
            instruction_str: String::new(), width: 2,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::IGet,
            v_a: Some(v_a), v_b: Some(v_b), v_c: Some(v_c),
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: vec![v_a, v_b, v_c],
        }
    }

    fn iput(opcode: u8, v_a: i64, v_b: i64, v_c: i64) -> Instruction {
        let mut i = iget(opcode, v_a, v_b, v_c);
        i.kind = InstructionKind::IPut;
        i
    }

    fn sget(opcode: u8, v_a: i64, v_b: i64) -> Instruction {
        Instruction {
            opcode, address: 0, codepoint: 0, fmt: "21c",
            instruction_str: String::new(), width: 2,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::SGet,
            v_a: Some(v_a), v_b: Some(v_b),
            v_c: None, v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: vec![v_a, v_b],
        }
    }

    fn sput(opcode: u8, v_a: i64, v_b: i64) -> Instruction {
        let mut i = sget(opcode, v_a, v_b);
        i.kind = InstructionKind::SPut;
        i
    }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── IGet ────────────────────────────────────────────────

    #[test]
    fn iget_default_zero_when_field_unset() {
        let mut regs: Registers = vec![Some(Value::Int(0xDEAD))];
        let mut mem = Memory::new();
        execute_iget(&iget(0x52, 0, 0, 7), &mut regs, &mut mem);
        // Field 7 not set → default 0 → write_int(0, 0).
        assert_eq!(read(&regs, 0), 0);
    }

    #[test]
    fn iget_returns_stored_value() {
        let mut regs: Registers = vec![None];
        let mut mem = Memory::new();
        mem.instance_fields.insert(5, Value::Int(42));
        execute_iget(&iget(0x52, 0, 0, 5), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 42);
    }

    #[test]
    fn iget_wide_splits_value_high_to_va_low_to_va_plus_one() {
        let mut regs: Registers = vec![None, None];
        let mut mem = Memory::new();
        // Field value = 0x12345678_DEADBEEF.
        mem.instance_fields.insert(3, Value::Int(0x12345678_DEADBEEFu64 as i64));
        execute_iget(&iget(0x53, 0, 0, 3), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x12345678);  // high in vA
        assert_eq!(read(&regs, 1), 0xDEADBEEF);  // low in vA+1
    }

    // ── IPut ────────────────────────────────────────────────

    #[test]
    fn iput_writes_register_into_field() {
        let mut regs = vec![Some(Value::Int(123))];
        let mut mem = Memory::new();
        execute_iput(&iput(0x59, 0, 0, 7), &mut regs, &mut mem);
        assert_eq!(mem.instance_fields.get(&7).and_then(|v| v.as_int()), Some(123));
    }

    #[test]
    fn iput_wide_python_bug_writes_low_to_register_indexed_field() {
        // vA=2, vC=7. After Python's wide IPut:
        //   field[7] = regs[2] << 32 = high << 32
        //   field[2] += regs[3]      = low
        // We mirror the bug: field[2] gets the low half, NOT field[7].
        let mut regs: Registers = vec![None, None, Some(Value::Int(3)), Some(Value::Int(99))];
        let mut mem = Memory::new();
        execute_iput(&iput(0x5a, 2, 0, 7), &mut regs, &mut mem);
        assert_eq!(mem.instance_fields.get(&7).and_then(|v| v.as_int()), Some(3i64 << 32));
        assert_eq!(mem.instance_fields.get(&2).and_then(|v| v.as_int()), Some(99));
    }

    // ── SGet ────────────────────────────────────────────────

    #[test]
    fn sget_returns_stored_int() {
        let mut regs: Registers = vec![None];
        let mut mem = Memory::new();
        mem.static_fields.insert(10, Value::Int(0xCAFE));
        execute_sget(&sget(0x60, 0, 10), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xCAFE);
    }

    #[test]
    fn sget_preserves_string_value() {
        let mut regs: Registers = vec![None];
        let mut mem = Memory::new();
        mem.static_fields.insert(8, Value::Str("hello".to_string()));
        execute_sget(&sget(0x60, 0, 8), &mut regs, &mut mem);
        match regs.get(0).and_then(|s| s.clone()) {
            Some(Value::Str(s)) => assert_eq!(s, "hello"),
            other => panic!("expected Str, got {:?}", other),
        }
    }

    #[test]
    fn sget_missing_field_clears_register_to_none() {
        let mut regs: Registers = vec![Some(Value::Int(0xDEAD))];
        let mut mem = Memory::new();
        execute_sget(&sget(0x60, 0, 99), &mut regs, &mut mem);
        assert!(regs[0].is_none());
    }

    #[test]
    fn sget_wide_splits_int_field() {
        let mut regs: Registers = vec![None, None];
        let mut mem = Memory::new();
        mem.static_fields.insert(4, Value::Int(0x12345678_DEADBEEFu64 as i64));
        execute_sget(&sget(0x61, 0, 4), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x12345678);
        assert_eq!(read(&regs, 1), 0xDEADBEEF);
    }

    #[test]
    fn sget_wide_typeerror_fallback_zeros_both_halves() {
        let mut regs: Registers = vec![None, None];
        let mut mem = Memory::new();
        // Field holds a String — can't do bitwise on it. Python catches
        // TypeError → both halves zero.
        mem.static_fields.insert(4, Value::Str("not an int".to_string()));
        execute_sget(&sget(0x61, 0, 4), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0);
        assert_eq!(read(&regs, 1), 0);
    }

    // ── SPut ────────────────────────────────────────────────

    #[test]
    fn sput_writes_register_into_field() {
        let mut regs = vec![Some(Value::Int(77))];
        let mut mem = Memory::new();
        execute_sput(&sput(0x67, 0, 10), &mut regs, &mut mem);
        assert_eq!(mem.static_fields.get(&10).and_then(|v| v.as_int()), Some(77));
    }

    #[test]
    fn sput_preserves_string_value() {
        let mut regs = vec![Some(Value::Str("hi".to_string()))];
        let mut mem = Memory::new();
        execute_sput(&sput(0x67, 0, 10), &mut regs, &mut mem);
        match mem.static_fields.get(&10) {
            Some(Value::Str(s)) => assert_eq!(s, "hi"),
            other => panic!("expected Str, got {:?}", other),
        }
    }

    #[test]
    fn sput_wide_packs_high_and_low() {
        let mut regs = vec![Some(Value::Int(0x12345678)), Some(Value::Int(0xDEADBEEF))];
        let mut mem = Memory::new();
        execute_sput(&sput(0x68, 0, 5), &mut regs, &mut mem);
        assert_eq!(
            mem.static_fields.get(&5).and_then(|v| v.as_int()),
            Some(0x12345678_DEADBEEFu64 as i64)
        );
    }

    #[test]
    fn sput_wide_typeerror_fallback_zeros_field() {
        // vA holds a String — can't shift it. Python catches and resets.
        let mut regs = vec![Some(Value::Str("nope".to_string())), Some(Value::Int(99))];
        let mut mem = Memory::new();
        execute_sput(&sput(0x68, 0, 5), &mut regs, &mut mem);
        assert_eq!(mem.static_fields.get(&5).and_then(|v| v.as_int()), Some(0));
    }
}
