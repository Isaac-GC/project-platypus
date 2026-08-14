//! ArrayOp family (0x44-0x51): aget / aput.
//!
//! Direct port of `ArrayOp.execute` from `dex/instructions_new.py`
//! (lines 993-1001).
//!
//! | range       | family                                                |
//! |-------------|-------------------------------------------------------|
//! | 0x44-0x4a   | aget / aget-wide / aget-object / aget-boolean / ...   |
//! | 0x4b-0x51   | aput / aput-wide / aput-object / aput-boolean / ...   |
//!
//! Python implementation is extremely terse:
//! ```python
//! if 0x44 <= self.opcode <= 0x4a: # get
//!     try:
//!         registers[self.vA] = registers[self.vB][registers[self.vC]]
//!     except TypeError as te:
//!         log.error(...)
//! elif 0x4b <= self.opcode <= 0x51: # put
//!     registers[self.vB][registers[self.vC]] = registers[self.vA]
//! ```
//!
//! ### Python quirks preserved
//!
//! 1. **No type/width specialisation.** Even the `-wide` variants
//!    (aget-wide, aput-wide, which AOSP says span two registers)
//!    use the same single-slot path. Python ignores the type
//!    suffix entirely. Faithful port: we do the same.
//!
//! 2. **TypeError caught and logged, no assignment.** If `vB` is not
//!    indexable (Null, int, etc.) the destination register is NOT
//!    written. The Python `try/except` catches the error and
//!    proceeds. We mirror by silently no-oping on type mismatch.
//!
//! 3. **No bounds check.** If the index is out of range, Python
//!    raises IndexError — NOT caught. We mirror by also leaving the
//!    destination unwritten in that case (and not panicking).
//!
//! 4. **No null check.** If the array slot holds Value::Null we
//!    silently no-op (Python would raise TypeError on indexing None).
//!
//! 5. **`Bytes` arrays read as i64.** Python's `bytes[i]` returns an
//!    integer 0-255 — we follow suit so aget on a byte array yields
//!    a Value::Int.

use platypus_dex::instructions::Instruction;

use crate::memory::Memory;
use crate::value::Value;
use crate::vm::{InstrResult, Registers};

use super::{read_int, read_val, write_val};

/// Execute an ArrayOp instruction (0x44-0x51).
pub fn execute(
    instr: &Instruction,
    regs: &mut Registers,
    _mem: &mut Memory,
) -> InstrResult {
    let v_a = instr.v_a.unwrap_or(0) as u32;
    let v_b = instr.v_b.unwrap_or(0) as u32;
    let v_c = instr.v_c.unwrap_or(0) as u32;

    let index = read_int(regs, v_c);

    match instr.opcode {
        // aget family (0x44-0x4a)
        0x44..=0x4a => {
            let array = match read_val(regs, v_b) {
                Some(v) => v,
                None => return InstrResult::Continue, // TypeError equivalent
            };

            let element = match &array {
                Value::Array(_) => {
                    array.array_get(index as usize)
                }
                Value::Bytes(bytes) => {
                    // bytes[i] returns an int 0-255 in Python.
                    bytes.get(index as usize).map(|b| Value::Int(*b as i64))
                }
                Value::Str(s) => {
                    // Python `str[i]` returns a 1-char string. Some
                    // codepaths in obfuscated apks index into strings
                    // expecting char codes — return Int of the
                    // codepoint for those.
                    s.chars().nth(index as usize)
                     .map(|c| Value::Int(c as i64))
                }
                _ => {
                    // TypeError in Python → silently log + no-op.
                    None
                }
            };

            if let Some(val) = element {
                write_val(regs, v_a, val);
            }
            // else: out-of-bounds or type mismatch — leave dst alone.
        }

        // aput family (0x4b-0x51)
        0x4b..=0x51 => {
            let value = match read_val(regs, v_a) {
                Some(v) => v,
                None => Value::Null,
            };

            // For Value::Array, the storage is shared (Arc<Mutex<...>>),
            // so we mutate through the cloned handle rather than through
            // the slot's &mut borrow — this preserves the shared
            // reference semantics (an aput here is visible to any
            // other Value::Array clone that shares the same Arc).
            // For Value::Bytes we still need a mutable borrow of the
            // slot since bytes don't share storage.
            let slot = match regs.get_mut(v_b as usize) {
                Some(s) => s,
                None => return InstrResult::Continue,
            };

            match slot.as_mut() {
                Some(Value::Bytes(bytes)) => {
                    // aput into a byte array — coerce value to u8.
                    let byte = value.as_int().unwrap_or(0) as u8;
                    let i = index as usize;
                    if i < bytes.len() {
                        bytes[i] = byte;
                    }
                }
                Some(v @ Value::Array(_)) => {
                    // Mutate through the shared Arc handle. array_set
                    // silently no-ops on out-of-bounds (matching the
                    // Python "IndexError swallowed" behaviour).
                    v.array_set(index as usize, value);
                }
                _ => {
                    // None or not an array/bytes — Python would
                    // TypeError; no-op.
                }
            }
        }

        _ => {
            // Outside the ArrayOp range — no-op.
        }
    }

    InstrResult::Continue
}

#[cfg(test)]
mod tests {
    use super::*;
    use platypus_dex::instructions::{ControlFlow, InstructionKind};

    fn arrayop(opcode: u8, v_a: i64, v_b: i64, v_c: i64) -> Instruction {
        Instruction {
            opcode,
            address: 0,
            codepoint: 0,
            fmt: "23x",
            instruction_str: String::new(),
            width: 2,
            control_flow: ControlFlow::FallThrough,
            kind: InstructionKind::ArrayOp,
            v_a: Some(v_a),
            v_b: Some(v_b),
            v_c: Some(v_c),
            v_d: None, v_e: None, v_f: None, v_g: None, v_h: None, v_z: None,
            operands: vec![v_a, v_b, v_c],
        }
    }

    fn read(regs: &Registers, idx: u32) -> i64 { read_int(regs, idx) }

    // ── aget ────────────────────────────────────────────────────

    #[test]
    fn aget_reads_int_from_array() {
        let mut regs: Registers = vec![
            None,                                                       // 0: dst
            Some(Value::new_array(vec![Value::Int(10), Value::Int(20), Value::Int(30)])), // 1: array
            Some(Value::Int(1)),                                        // 2: index
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x44, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 20);
    }

    #[test]
    fn aget_reads_byte_from_bytes() {
        // aget-byte (0x48). bytes[2] should be 0x42.
        let mut regs: Registers = vec![
            None,
            Some(Value::Bytes(vec![0x11, 0x22, 0x42, 0x55])),
            Some(Value::Int(2)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x48, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0x42);
    }

    #[test]
    fn aget_reads_char_from_string() {
        // aget-char (0x49). str[1] should be 'B' = 66.
        let mut regs: Registers = vec![
            None,
            Some(Value::Str("ABC".to_string())),
            Some(Value::Int(1)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x49, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 'B' as i64);
    }

    #[test]
    fn aget_out_of_bounds_silently_noops() {
        let mut regs: Registers = vec![
            Some(Value::Int(0xDEAD)),  // dst — should NOT change
            Some(Value::new_array(vec![Value::Int(10)])),
            Some(Value::Int(99)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x44, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD); // unchanged
    }

    #[test]
    fn aget_on_non_array_silently_noops() {
        let mut regs: Registers = vec![
            Some(Value::Int(0xDEAD)),
            Some(Value::Int(42)),       // not an array
            Some(Value::Int(0)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x44, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD); // unchanged
    }

    #[test]
    fn aget_on_null_silently_noops() {
        let mut regs: Registers = vec![
            Some(Value::Int(0xDEAD)),
            Some(Value::Null),
            Some(Value::Int(0)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x44, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD);
    }

    #[test]
    fn aget_on_missing_slot_silently_noops() {
        let mut regs: Registers = vec![Some(Value::Int(0xDEAD)), None, None];
        let mut mem = Memory::new();
        execute(&arrayop(0x44, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 0), 0xDEAD);
    }

    // ── aput ────────────────────────────────────────────────────

    #[test]
    fn aput_writes_int_into_array() {
        // aput vA=2 into vB[vC] where vC=1.
        let mut regs: Registers = vec![
            Some(Value::Int(99)),  // source value
            Some(Value::new_array(vec![Value::Int(10), Value::Int(20), Value::Int(30)])),
            Some(Value::Int(1)),   // index
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x4b, 0, 1, 2), &mut regs, &mut mem);
        let array = regs[1].as_ref().unwrap();
        let items = array.array_snapshot().expect("expected array");
        assert_eq!(items[0].as_int(), Some(10));
        assert_eq!(items[1].as_int(), Some(99));  // was 20, now 99
        assert_eq!(items[2].as_int(), Some(30));
    }

    #[test]
    fn aput_writes_byte_into_bytes() {
        // aput-byte (0x4f). bytes[1] should become 0xAB.
        let mut regs: Registers = vec![
            Some(Value::Int(0xAB)),
            Some(Value::Bytes(vec![0x00, 0x00, 0x00])),
            Some(Value::Int(1)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x4f, 0, 1, 2), &mut regs, &mut mem);
        match regs[1].as_ref().unwrap() {
            Value::Bytes(b) => assert_eq!(b, &vec![0x00, 0xAB, 0x00]),
            _ => panic!("expected bytes"),
        }
    }

    #[test]
    fn aput_out_of_bounds_silently_noops() {
        let mut regs: Registers = vec![
            Some(Value::Int(99)),
            Some(Value::new_array(vec![Value::Int(1)])),
            Some(Value::Int(50)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x4b, 0, 1, 2), &mut regs, &mut mem);
        let v = regs[1].as_ref().unwrap();
        assert_eq!(v.array_len().expect("expected array"), 1);
    }

    #[test]
    fn aput_on_non_array_silently_noops() {
        let mut regs: Registers = vec![
            Some(Value::Int(99)),
            Some(Value::Int(42)),
            Some(Value::Int(0)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x4b, 0, 1, 2), &mut regs, &mut mem);
        assert_eq!(read(&regs, 1), 42); // unchanged
    }

    #[test]
    fn aput_on_missing_value_writes_null() {
        // vA slot is None → coerce to Value::Null and write.
        let mut regs: Registers = vec![
            None,  // source — None
            Some(Value::new_array(vec![Value::Int(1), Value::Int(2)])),
            Some(Value::Int(0)),
        ];
        let mut mem = Memory::new();
        execute(&arrayop(0x4b, 0, 1, 2), &mut regs, &mut mem);
        let v = regs[1].as_ref().unwrap();
        let items = v.array_snapshot().expect("expected array");
        assert!(matches!(items[0], Value::Null));
    }
}
