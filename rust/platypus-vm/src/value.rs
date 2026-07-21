/// Dynamic value type for the Dalvik interpreter.
///
/// Dalvik registers are untyped 32/64-bit slots; we model values with an enum
/// so mocked Java API functions can pass strings, byte arrays, etc.
///
/// ## Array storage model
///
/// `Value::Array` wraps the inner `Vec<Value>` in `Arc<Mutex<...>>` so the
/// storage is shared by reference (matching Java's array semantics). Cloning
/// a `Value::Array` clones the `Arc` (cheap, O(1)) — both clones see each
/// other's mutations. This is load-bearing for any APK that does:
/// ```text
/// new-array v0          # v0 = empty array
/// sput-object v0, F     # F = v0 (shared reference, NOT a copy)
/// aput-object v2, v0, idx   # mutate v0[idx] — F sees the change
/// ```
/// without it, the static field holds an empty snapshot and never picks up
/// the later mutations.

use std::sync::{Arc, Mutex};

/// Shared, mutable backing storage for `Value::Array`. The `Mutex` is for
/// soundness with our cooperative threading model — contention is rare
/// because threads typically only share via static fields.
pub type ArrayData = Arc<Mutex<Vec<Value>>>;

#[derive(Debug, Clone)]
pub enum Value {
    Null,
    Int(i64),
    Float(f64),
    Bytes(Vec<u8>),
    Str(String),
    Array(ArrayData),
    Bool(bool),
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n)  => Some(*n),
            Value::Bool(b) => Some(*b as i64),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn is_truthy(&self) -> bool {
        match self {
            Value::Null    => false,
            Value::Int(n)  => *n != 0,
            Value::Bool(b) => *b,
            Value::Str(s)  => !s.is_empty(),
            Value::Bytes(b) => !b.is_empty(),
            Value::Array(a) => a.lock().map(|g| !g.is_empty()).unwrap_or(false),
            Value::Float(f) => *f != 0.0,
        }
    }

    // ── Array helpers ─────────────────────────────────────────────
    //
    // Per the storage-model doc above, callers should NEVER pattern-match
    // on Value::Array and treat the inner Vec as owned — use these helpers
    // so the shared-reference semantics are preserved.

    /// Construct a `Value::Array` from a `Vec<Value>`. Wraps the vec in
    /// the shared-reference storage. Use this everywhere we used to
    /// write `Value::Array(vec![...])`.
    pub fn new_array(items: Vec<Value>) -> Self {
        Value::Array(Arc::new(Mutex::new(items)))
    }

    /// Length of an array. Returns `None` if `self` isn't an Array (or the
    /// mutex was poisoned — should never happen since our locks never panic
    /// while held).
    pub fn array_len(&self) -> Option<usize> {
        match self {
            Value::Array(a) => a.lock().ok().map(|g| g.len()),
            _ => None,
        }
    }

    /// Get a snapshot clone of the element at `idx`. Returns `None` on
    /// out-of-bounds, lock poison, or non-array.
    pub fn array_get(&self, idx: usize) -> Option<Value> {
        match self {
            Value::Array(a) => a.lock().ok()?.get(idx).cloned(),
            _ => None,
        }
    }

    /// Set element `idx` to `val`. Returns `true` if the write happened,
    /// `false` on out-of-bounds, lock poison, or non-array.
    pub fn array_set(&self, idx: usize, val: Value) -> bool {
        match self {
            Value::Array(a) => {
                let mut guard = match a.lock() { Ok(g) => g, Err(_) => return false };
                if idx < guard.len() {
                    guard[idx] = val;
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    /// Snapshot the array contents as an owned `Vec<Value>`. Useful for
    /// iteration when you don't need to mutate. Returns `None` if not an
    /// array.
    pub fn array_snapshot(&self) -> Option<Vec<Value>> {
        match self {
            Value::Array(a) => a.lock().ok().map(|g| g.clone()),
            _ => None,
        }
    }
}

impl From<i64> for Value {
    fn from(n: i64) -> Self { Value::Int(n) }
}
impl From<i32> for Value {
    fn from(n: i32) -> Self { Value::Int(n as i64) }
}
impl From<bool> for Value {
    fn from(b: bool) -> Self { Value::Bool(b) }
}
impl From<String> for Value {
    fn from(s: String) -> Self { Value::Str(s) }
}
impl From<Vec<u8>> for Value {
    fn from(b: Vec<u8>) -> Self { Value::Bytes(b) }
}
impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Self { Value::new_array(v) }
}
