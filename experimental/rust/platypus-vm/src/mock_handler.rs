/// Mock method registry — translates vm/mock_handler.py
///
/// Python used a decorator (@register_mock) to auto-register functions in a
/// global dict keyed by a namespaced string like "Ljava_lang_String_charAt".
/// In Rust we use an explicit HashMap populated at startup via `register_all`.

use std::collections::HashMap;

use super::value::Value;

/// Signature for all mocked methods.
/// args   — resolved register values for each parameter.
/// state  — mutable map of extra state (mirrors Python's STATE_DATA dict).
/// Returns the method's return value, or None.
pub type MockFn = fn(args: Vec<Value>, state: &mut HashMap<String, Value>) -> Option<Value>;

/// Global mock registry populated once at startup.
pub struct MockRegistry {
    fns: HashMap<String, MockFn>,
    /// Dynamic mocks: closures registered at runtime (e.g. from Python).
    /// These take priority over the static `fns` table.
    dynamic_fns: HashMap<String, Box<dyn Fn(Vec<Value>, &mut HashMap<String, Value>) -> Option<Value> + Send + Sync>>,
}

impl MockRegistry {
    pub fn new() -> Self {
        let mut reg = MockRegistry { fns: HashMap::new(), dynamic_fns: HashMap::new() };
        reg.register_all();
        reg
    }

    fn register(&mut self, key: &str, f: MockFn) {
        self.fns.insert(key.to_string(), f);
    }

    /// Register a dynamic (closure-based) mock.  Dynamic mocks shadow any
    /// static mock with the same key.
    pub fn register_dynamic(
        &mut self,
        key: String,
        f: Box<dyn Fn(Vec<Value>, &mut HashMap<String, Value>) -> Option<Value> + Send + Sync>,
    ) {
        self.dynamic_fns.insert(key, f);
    }

    pub fn get(&self, key: &str) -> Option<MockFn> {
        self.fns.get(key).copied()
    }

    /// True if any runtime (e.g. Python-registered) mocks exist. The hot
    /// invoke path uses this to skip building the expensive
    /// signature-specific `full_key` when there are no dynamic mocks that
    /// could ever match it — the overwhelmingly common case for pure
    /// static deobfuscation where only the built-in Rust mocks are live.
    #[inline]
    pub fn has_dynamic_mocks(&self) -> bool {
        !self.dynamic_fns.is_empty()
    }

    /// Translate a DEX method reference (class->method, **no** signature) into
    /// the registry key used by the mock system.
    ///
    ///   `"Ljava/lang/String;->charAt"`             → `"Ljava_lang_String_charAt"`
    ///   `"Ljava/lang/String;->charAt(I)C"`          → `"Ljava_lang_String_charAt"`
    ///   (signature is stripped — use `method_fqn_to_full_key` to preserve it)
    pub fn method_fqn_to_key(method_fqn: &str) -> String {
        // Strip any trailing signature "(...)ret" before processing.
        let fqn_no_sig = method_fqn.split('(').next().unwrap_or(method_fqn);

        let mut parts = fqn_no_sig.splitn(2, "->");
        let class_part  = parts.next().unwrap_or("");
        let method_part = parts.next().unwrap_or("");

        // Single-pass build into one allocation. Previously this did five
        // separate `replace`/`format!` allocations per invoke; on the hot
        // path (every DEX-to-DEX call) those dominate. Translation rules:
        //   class: '/' → '_', trailing ';' dropped
        //   joiner: '_'
        //   method: '<' / '>' → '0'
        let class_trimmed = class_part.trim_end_matches(';');
        let mut key = String::with_capacity(class_trimmed.len() + 1 + method_part.len());
        for c in class_trimmed.chars() {
            key.push(if c == '/' { '_' } else { c });
        }
        key.push('_');
        for c in method_part.chars() {
            key.push(match c { '<' | '>' => '0', other => other });
        }
        key
    }

    /// Translate a **full** DEX method reference (class->method + signature)
    /// into a registry key that includes the parameter types.
    ///
    /// This is used for overload-specific mock registration: a mock registered
    /// with a full-key fires only for that exact signature, while a mock
    /// registered with the short key fires for all overloads.
    ///
    ///   `"Ljava/lang/String;->valueOf(C)Ljava/lang/String;"` →
    ///   `"Ljava_lang_String_valueOf_C_Ljava_lang_String"`
    pub fn method_fqn_to_full_key(method_fqn: &str) -> String {
        let mut parts = method_fqn.splitn(2, "->");
        let class_part = parts.next().unwrap_or("");
        let rest       = parts.next().unwrap_or("");

        let class_key = class_part
            .replace('/', "_")
            .trim_end_matches(';')
            .to_string();

        // Sanitize the method name + signature characters.
        let rest_key = rest
            .replace('<', "0")
            .replace('>', "0")
            .replace('/', "_")
            .replace('(', "_")
            .replace(')', "_")
            .replace(';', "_")
            .replace('[', "A"); // array prefix

        // Collapse runs of underscores and strip trailing ones for readability.
        let rest_key: String = rest_key
            .split('_')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join("_");

        format!("{}_{}", class_key, rest_key)
    }

    /// Execute a mocked method if one is registered.
    ///
    /// Lookup order (highest to lowest priority):
    /// 1. Dynamic mock with exact signature (`full_key`) — overload-specific Python mock
    /// 2. Dynamic mock with name only (`short_key`)      — catch-all Python mock
    /// 3. Static (built-in) mock with name only          — built-in Rust mocks
    ///
    /// Returns:
    /// - `None`           — no mock registered for this method (fall through to DEX)
    /// - `Some(None)`     — mock was hit and returns void
    /// - `Some(Some(v))` — mock was hit and returns a value
    pub fn try_execute(
        &self,
        short_key: &str,
        full_key: &str,
        args: &[Value],
        state: &mut HashMap<String, Value>,
    ) -> Option<Option<Value>> {
        // `args` is borrowed: the overwhelmingly common case is NO mock
        // match (every plain DEX-to-DEX invoke), and we don't want to
        // deep-clone the argument vector (strings/bytes included) on every
        // such invoke. The owned `Vec<Value>` the handler closures expect
        // is materialised only when a handler actually matches.
        // 1. Signature-specific dynamic mock (exact overload match).
        if full_key != short_key {
            if let Some(f) = self.dynamic_fns.get(full_key) {
                return Some(f(args.to_vec(), state));
            }
        }
        // 2. Name-only dynamic mock (catches all overloads).
        if let Some(f) = self.dynamic_fns.get(short_key) {
            return Some(f(args.to_vec(), state));
        }
        // 3. Built-in static mock.
        let f = self.get(short_key)?;
        Some(f(args.to_vec(), state))
    }

    // ── Registration ─────────────────────────────────────────────────────────

    fn register_all(&mut self) {
        // java.lang.String
        self.register("Ljava_lang_String_0init0",    mocks::string::init);
        self.register("Ljava_lang_String_charAt",     mocks::string::char_at);
        self.register("Ljava_lang_String_split",      mocks::string::split);
        self.register("Ljava_lang_String_equals",     mocks::string::equals);
        self.register("Ljava_lang_String_length",     mocks::string::length);
        self.register("Ljava_lang_String_hashCode",   mocks::string::hash_code);
        self.register("Ljava_lang_String_indexOf",    mocks::string::index_of);
        self.register("Ljava_lang_String_valueOf",    mocks::string::value_of);
        self.register("Ljava_lang_String_toLowerCase",mocks::string::to_lower_case);
        self.register("Ljava_lang_String_toUpperCase",mocks::string::to_upper_case);
        self.register("Ljava_lang_String_getBytes",   mocks::string::get_bytes);
        self.register("Ljava_lang_String_toCharArray",mocks::string::to_char_array);

        // java.lang.StringBuilder
        self.register("Ljava_lang_StringBuilder_0init0", mocks::string_builder::init);
        self.register("Ljava_lang_StringBuilder_append",  mocks::string_builder::append);
        self.register("Ljava_lang_StringBuilder_length",  mocks::string_builder::length);
        self.register("Ljava_lang_StringBuilder_toString",mocks::string_builder::to_string);

        // java.lang.Integer
        self.register("Ljava_lang_Integer_valueOf",   mocks::integer::value_of);
        self.register("Ljava_lang_Integer_intValue",  mocks::integer::int_value);

        // java.lang.System
        self.register("Ljava_lang_System_arraycopy", mocks::system::arraycopy);

        // android.util.Base64
        self.register("Landroid_util_Base64_decode",  mocks::base64::decode);

        // java.lang.Object
        self.register("Ljava_lang_Object_hashCode", mocks::object::hash_code);

        // java.lang.StringBuffer
        self.register("Ljava_lang_StringBuffer_0init0",  mocks::string_buffer::init);
        self.register("Ljava_lang_StringBuffer_toString", mocks::string_buffer::to_string);

        // java.lang.Throwable / Thread stack trace
        self.register("Ljava_lang_Throwable_setStackTrace", mocks::throwable::set_stack_trace);

        // java.util.ArrayList
        self.register("Ljava_util_ArrayList_0init0", mocks::array_list::init);
        self.register("Ljava_util_ArrayList_size",   mocks::array_list::size);
        self.register("Ljava_util_ArrayList_add",    mocks::array_list::add);
        self.register("Ljava_util_ArrayList_get",    mocks::array_list::get);

        // java.util.Arrays
        self.register("Ljava_util_Arrays_copyOfRange", mocks::arrays::copy_of_range);

        // java.io.ByteArrayOutputStream
        self.register("Ljava_io_ByteArrayOutputStream_0init0",   mocks::byte_array_output_stream::init);
        self.register("Ljava_io_ByteArrayOutputStream_write",     mocks::byte_array_output_stream::write);
        self.register("Ljava_io_ByteArrayOutputStream_toByteArray", mocks::byte_array_output_stream::to_byte_array);

        // javax.crypto.spec.SecretKeySpec
        self.register("Ljavax_crypto_spec_SecretKeySpec_0init0", mocks::secret_key_spec::init);

        // javax.crypto.spec.IvParameterSpec
        self.register("Ljavax_crypto_spec_IvParameterSpec_0init0", mocks::iv_parameter_spec::init);

        // javax.crypto.Cipher
        self.register("Ljavax_crypto_Cipher_getInstance",  mocks::cipher::get_instance);
        self.register("Ljavax_crypto_Cipher_init",         mocks::cipher::init);
        self.register("Ljavax_crypto_Cipher_doFinal",      mocks::cipher::do_final);

        // kotlin.jvm.internal.Intrinsics
        self.register("Lkotlin_jvm_internal_Intrinsics_checkNotNullParameter", mocks::kotlin_intrinsics::check_not_null_parameter);
        self.register("Lkotlin_jvm_internal_Intrinsics_checkNotNull",          mocks::kotlin_intrinsics::check_not_null);
    }
}

impl Default for MockRegistry {
    fn default() -> Self { Self::new() }
}

// ── Individual mock implementations ──────────────────────────────────────────

pub mod mocks {
    use std::collections::HashMap;
    use super::super::value::Value;

    pub mod string {
        use super::*;

        pub fn init(mut args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            // new String(byte[]) — args[0] = instance (ignored), args[1] = bytes
            let bytes = match args.get(1) {
                Some(Value::Bytes(b)) => b.clone(),
                Some(v @ Value::Array(_)) => v
                    .array_snapshot()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_int().map(|n| n as u8))
                    .collect(),
                _ => return Some(Value::Str(String::new())),
            };
            let s = String::from_utf8_lossy(&bytes).into_owned();
            Some(Value::Str(s))
        }

        pub fn char_at(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let s = args.first()?.as_str()?.to_string();
            let idx = args.get(1)?.as_int()? as usize;
            let c = s.chars().nth(idx)? as i64;
            Some(Value::Int(c))
        }

        pub fn split(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let s = args.first()?.as_str()?.to_string();
            let pat = args.get(1)?.as_str()?.to_string();
            let parts: Vec<Value> = s.split(pat.as_str())
                .map(|p| Value::Str(p.to_string()))
                .collect();
            Some(Value::new_array(parts))
        }

        pub fn equals(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            match (args.first(), args.get(1)) {
                (Some(a), Some(b)) => {
                    let eq = match (a, b) {
                        (Value::Str(x), Value::Str(y)) => x == y,
                        (Value::Int(x), Value::Int(y)) => x == y,
                        _ => false,
                    };
                    Some(Value::Bool(eq))
                }
                _ => Some(Value::Bool(false)),
            }
        }

        pub fn length(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let v = args.first()?;
            let n = match v {
                Value::Str(s)   => s.len() as i64,
                Value::Bytes(b) => b.len() as i64,
                Value::Array(_) => v.array_len().unwrap_or(0) as i64,
                _ => 0,
            };
            Some(Value::Int(n))
        }

        pub fn hash_code(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let s = args.first()?.as_str()?.to_string();
            let mut h: i32 = 0;
            for c in s.chars() {
                h = h.wrapping_mul(31).wrapping_add(c as i32);
            }
            Some(Value::Int(h as i64))
        }

        pub fn index_of(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let s = args.first()?.as_str()?.to_string();
            let needle = match args.get(1)? {
                Value::Int(c)  => char::from_u32(*c as u32).map(|c| c.to_string()),
                Value::Str(p)  => Some(p.clone()),
                _ => None,
            }?;
            let pos = s.find(needle.as_str()).map(|p| p as i64).unwrap_or(-1);
            Some(Value::Int(pos))
        }

        pub fn value_of(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let s = match args.first()? {
                Value::Int(c) => char::from_u32(*c as u32)
                    .map(|c| c.to_string())
                    .unwrap_or_default(),
                Value::Str(s) => s.clone(),
                _ => return None,
            };
            Some(Value::Str(s))
        }

        pub fn to_lower_case(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(Value::Str(args.first()?.as_str()?.to_lowercase()))
        }

        pub fn to_upper_case(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(Value::Str(args.first()?.as_str()?.to_uppercase()))
        }

        pub fn get_bytes(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let bytes = args.first()?.as_str()?.as_bytes().to_vec();
            Some(Value::Bytes(bytes))
        }

        pub fn to_char_array(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let chars: Vec<Value> = args.first()?.as_str()?
                .chars()
                .map(|c| Value::Int(c as i64))
                .collect();
            Some(Value::new_array(chars))
        }
    }

    pub mod string_builder {
        use super::*;

        pub fn init(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(Value::Str(String::new()))
        }

        pub fn append(mut args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let suffix = match args.get(1) {
                Some(Value::Str(s))   => s.clone(),
                Some(Value::Int(n))   => n.to_string(),
                Some(Value::Bytes(b)) => String::from_utf8_lossy(b).into_owned(),
                _ => return Some(args.into_iter().next().unwrap_or(Value::Null)),
            };
            match args.first_mut() {
                Some(Value::Str(s)) => { s.push_str(&suffix); }
                _ => return Some(Value::Str(suffix)),
            }
            Some(args.into_iter().next().unwrap_or(Value::Null))
        }

        pub fn length(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let n = match args.first()? {
                Value::Str(s) => s.len() as i64,
                _ => 0,
            };
            Some(Value::Int(n))
        }

        pub fn to_string(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            match args.first()? {
                Value::Str(s) if s.is_empty() => args.into_iter().nth(1),
                other => Some(other.clone()),
            }
        }
    }

    pub mod integer {
        use super::*;

        pub fn value_of(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(Value::Int(args.first()?.as_int()?))
        }

        pub fn int_value(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(Value::Int(args.first()?.as_int()?))
        }
    }

    pub mod system {
        use super::*;

        /// System.arraycopy(src, srcPos, dst, dstPos, length)
        pub fn arraycopy(mut args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            // We'd need mutable access to both arrays — complex in Rust's ownership model.
            // This is a best-effort stub that returns None (no copy performed).
            None
        }
    }

    pub mod base64 {
        use super::*;

        /// android.util.Base64.decode(byte[]|String, flags) → byte[]
        pub fn decode(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let raw: Vec<u8> = match args.first()? {
                Value::Bytes(b) => b.clone(),
                Value::Str(s)   => s.as_bytes().to_vec(),
                v @ Value::Array(_) => v
                    .array_snapshot()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_int().map(|n| n as u8))
                    .collect(),
                _ => return None,
            };

            // Add padding
            let rem = raw.len() % 4;
            let padded: Vec<u8> = if rem == 0 {
                raw
            } else {
                let mut v = raw;
                v.extend(std::iter::repeat(b'=').take(4 - rem));
                v
            };

            // URL-safe flag: flags & 8 != 0
            let url_safe = args.get(1).and_then(|v| v.as_int()).map(|n| n & 8 != 0).unwrap_or(false);
            let decoded = if url_safe {
                base64_decode_url_safe(&padded)
            } else {
                base64_decode_standard(&padded)
            };

            decoded.map(Value::Bytes)
        }

        fn base64_decode_standard(input: &[u8]) -> Option<Vec<u8>> {
            base64_decode_inner(input, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
        }

        fn base64_decode_url_safe(input: &[u8]) -> Option<Vec<u8>> {
            base64_decode_inner(input, b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        }

        fn base64_decode_inner(input: &[u8], alphabet: &[u8; 64]) -> Option<Vec<u8>> {
            // Build reverse lookup
            let mut rev = [0xffu8; 256];
            for (i, &c) in alphabet.iter().enumerate() {
                rev[c as usize] = i as u8;
            }

            let mut out = Vec::new();
            let mut buf = 0u32;
            let mut bits = 0u32;

            for &b in input {
                if b == b'=' { break; }
                if b == b'\n' || b == b'\r' || b == b' ' { continue; }
                let v = rev[b as usize];
                if v == 0xff { return None; }
                buf = (buf << 6) | v as u32;
                bits += 6;
                if bits >= 8 {
                    bits -= 8;
                    out.push((buf >> bits) as u8);
                    buf &= (1 << bits) - 1;
                }
            }

            Some(out)
        }
    }

    pub mod object {
        use super::*;
        pub fn hash_code(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let s = args.first()?.as_str().unwrap_or("").to_string();
            let mut h: i32 = 0;
            for c in s.chars() {
                h = h.wrapping_mul(31).wrapping_add(c as i32);
            }
            Some(Value::Int(h as i64))
        }
    }

    pub mod string_buffer {
        use super::*;
        pub fn init(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let s = match args.get(1) {
                Some(Value::Str(s))   => s.clone(),
                Some(v @ Value::Array(_)) => v
                    .array_snapshot()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_int().and_then(|n| char::from_u32(n as u32)))
                    .collect(),
                _ => String::new(),
            };
            Some(Value::Str(s))
        }
        pub fn to_string(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(args.into_iter().next().unwrap_or(Value::Str(String::new())))
        }
    }

    pub mod throwable {
        use super::*;
        pub fn set_stack_trace(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            None
        }
    }

    pub mod array_list {
        use super::*;
        pub fn init(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(Value::new_array(Vec::new()))
        }
        pub fn size(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let v = args.first()?;
            let n = match v {
                Value::Array(_) => v.array_len().unwrap_or(0) as i64,
                _ => 0,
            };
            Some(Value::Int(n))
        }
        pub fn add(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            // Mutation via references isn't directly possible in this mock model — return true
            Some(Value::Bool(true))
        }
        pub fn get(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let v = args.first()?;
            if !matches!(v, Value::Array(_)) { return None; }
            let idx = args.get(1)?.as_int()? as usize;
            v.array_get(idx)
        }
    }

    pub mod arrays {
        use super::*;
        pub fn copy_of_range(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            let v = args.first()?;
            let arr = v.array_snapshot()?;
            let start = args.get(1)?.as_int()? as usize;
            let end   = args.get(2)?.as_int()? as usize;
            let end   = end.min(arr.len());
            let start = start.min(end);
            Some(Value::new_array(arr[start..end].to_vec()))
        }
    }

    pub mod byte_array_output_stream {
        use super::*;
        pub fn init(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            Some(Value::Bytes(Vec::new()))
        }
        pub fn write(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            None // mutation not modelled
        }
        pub fn to_byte_array(args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            match args.first()? {
                Value::Bytes(b) => Some(Value::Bytes(b.clone())),
                _ => Some(Value::Bytes(Vec::new())),
            }
        }
    }

    pub mod secret_key_spec {
        use super::*;
        pub fn init(args: Vec<Value>, state: &mut HashMap<String, Value>) -> Option<Value> {
            // args: (this, key_bytes, algorithm_string)
            // Store key bytes in state so Cipher.doFinal can find them.
            if let Some(key) = args.get(1) {
                state.insert("aes_key".to_string(), key.clone());
            }
            // Return the key bytes as the "object" value so callers that pass
            // the key directly to Cipher.init also work.
            args.into_iter().nth(1)
        }
    }

    pub mod iv_parameter_spec {
        use super::*;
        /// new IvParameterSpec(byte[]) — store IV for later Cipher use.
        pub fn init(args: Vec<Value>, state: &mut HashMap<String, Value>) -> Option<Value> {
            // args: (this, iv_bytes)
            if let Some(iv) = args.get(1) {
                state.insert("aes_iv".to_string(), iv.clone());
            }
            args.into_iter().nth(1)
        }
    }

    pub mod cipher {
        use super::*;

        /// Cipher.getInstance(algorithm) — return a sentinel "Cipher" object.
        pub fn get_instance(args: Vec<Value>, state: &mut HashMap<String, Value>) -> Option<Value> {
            if let Some(Value::Str(algo)) = args.first() {
                state.insert("cipher_algo".to_string(), Value::Str(algo.clone()));
            }
            Some(Value::Str("__Cipher__".to_string()))
        }

        /// cipher.init(mode, key, iv) — record mode; key/iv already in state.
        pub fn init(args: Vec<Value>, state: &mut HashMap<String, Value>) -> Option<Value> {
            // args: (cipher_instance, mode, key_obj, iv_obj)
            if let Some(mode) = args.get(1).and_then(|v| v.as_int()) {
                state.insert("cipher_mode".to_string(), Value::Int(mode));
            }
            // If key/iv came in as live Values (not already in state), persist them.
            if let Some(key) = args.get(2) {
                if !matches!(key, Value::Str(s) if s.starts_with("L")) {
                    state.insert("aes_key".to_string(), key.clone());
                }
            }
            if let Some(iv) = args.get(3) {
                if !matches!(iv, Value::Str(s) if s.starts_with("L")) {
                    state.insert("aes_iv".to_string(), iv.clone());
                }
            }
            None
        }

        /// cipher.doFinal(input) — AES-128/256-CBC-PKCS7 decrypt using
        /// key/iv from state. Backed by the dependency-free `platypus-crypto`
        /// AES implementation.
        pub fn do_final(args: Vec<Value>, state: &mut HashMap<String, Value>) -> Option<Value> {
            use platypus_crypto::aes_cbc_pkcs7_decrypt;

            let input: Vec<u8> = match args.get(1).or_else(|| args.first()) {
                Some(Value::Bytes(b)) => b.clone(),
                Some(v @ Value::Array(_)) => v
                    .array_snapshot()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_int().map(|n| n as u8))
                    .collect(),
                _ => return None,
            };

            let key_bytes: Vec<u8> = match state.get("aes_key") {
                Some(Value::Bytes(b)) => b.clone(),
                Some(Value::Str(s))   => s.as_bytes().to_vec(),
                Some(v @ Value::Array(_)) => v
                    .array_snapshot()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_int().map(|n| n as u8))
                    .collect(),
                _ => return None,
            };

            let iv_bytes: Vec<u8> = match state.get("aes_iv") {
                Some(Value::Bytes(b)) => b.clone(),
                Some(Value::Str(s))   => s.as_bytes().to_vec(),
                Some(v @ Value::Array(_)) => v
                    .array_snapshot()
                    .unwrap_or_default()
                    .iter()
                    .filter_map(|v| v.as_int().map(|n| n as u8))
                    .collect(),
                _ => return None,
            };

            if iv_bytes.len() != 16 { return None; }
            let iv_arr: &[u8; 16] = iv_bytes.as_slice().try_into().ok()?;

            // Key length is validated inside `aes_cbc_pkcs7_decrypt`
            // (16 or 32 bytes); anything else returns None just like the
            // old `try_into` guard did.
            let decrypted = aes_cbc_pkcs7_decrypt(&key_bytes, iv_arr, &input)?;
            Some(Value::Bytes(decrypted))
        }
    }

    pub mod kotlin_intrinsics {
        use super::*;
        /// Lkotlin/jvm/internal/Intrinsics;->checkNotNullParameter — no-op.
        pub fn check_not_null_parameter(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            None
        }
        pub fn check_not_null(_args: Vec<Value>, _state: &mut HashMap<String, Value>) -> Option<Value> {
            None
        }
    }
}
