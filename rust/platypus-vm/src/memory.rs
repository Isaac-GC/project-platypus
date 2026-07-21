/// VM execution context (memory/registers) — translates vm/memory.py

use std::collections::HashMap;

use super::value::Value;

/// Execution-context state, shared across instructions in one thread.
#[derive(Debug)]
pub struct Memory {
    /// Return value of the most recently executed instruction/call.
    pub last_return:   Option<Value>,
    /// Last exception raised during execution.
    pub last_exception: Option<Value>,

    /// Per-instruction result values (keyed by codepoint).
    pub method_instr_values: HashMap<u32, Value>,
    /// Static field values: field_idx → value.
    pub static_fields: HashMap<usize, Value>,
    /// Instance field values: field_idx → value.
    pub instance_fields: HashMap<usize, Value>,
}

impl Memory {
    pub fn new() -> Self {
        Memory {
            last_return:         None,
            last_exception:      None,
            method_instr_values: HashMap::new(),
            static_fields:       HashMap::new(),
            instance_fields:     HashMap::new(),
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}
