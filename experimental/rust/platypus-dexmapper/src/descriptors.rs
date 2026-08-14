//! JVM type-descriptor + signature parsing utilities, plus the stable
//! content-addressed hashes the producer pipeline uses (class fingerprint,
//! method signature hash, structural hash).
//!
//! Pure-stdlib — only the hash helpers need `sha2`, and that's only when
//! the `producer` feature is enabled. The descriptor parsing itself is
//! always available because the lookup-side (`Deobfuscator`) also wants
//! to validate descriptors.

// ── Descriptor parsing ─────────────────────────────────────────────────────

/// `com/example/Foo` → `com.example.Foo`. Idempotent on dotted input.
pub fn internal_to_fqn(internal: &str) -> String {
    internal.replace('/', ".")
}

/// `com.example.Foo` → `com/example/Foo`. Idempotent on slashed input.
pub fn fqn_to_internal(fqn: &str) -> String {
    fqn.replace('.', "/")
}

/// `(ILjava/lang/String;[B)V` → `(vec!["I","Ljava/lang/String;","[B"], "V")`.
/// Returns `(vec![], desc)` when the descriptor is malformed.
pub fn parse_method_descriptor(desc: &str) -> (Vec<String>, String) {
    let Some(start) = desc.find('(') else { return (Vec::new(), desc.to_string()); };
    let Some(end) = desc.find(')')   else { return (Vec::new(), desc.to_string()); };
    if end < start { return (Vec::new(), desc.to_string()); }
    let params = parse_type_list(&desc[start + 1..end]);
    let ret = desc[end + 1..].to_string();
    (params, ret)
}

/// Parse a concatenated sequence of JVM type descriptors.
fn parse_type_list(s: &str) -> Vec<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let ch = bytes[i];
        if matches!(ch, b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b'V') {
            out.push((ch as char).to_string());
            i += 1;
        } else if ch == b'[' {
            // Consume all leading '[' then base type.
            let mut j = i;
            while j < bytes.len() && bytes[j] == b'[' { j += 1; }
            if j < bytes.len() && bytes[j] == b'L' {
                if let Some(end) = s[j..].find(';') {
                    let abs_end = j + end;
                    out.push(s[i..=abs_end].to_string());
                    i = abs_end + 1;
                    continue;
                }
            }
            if j < bytes.len() {
                out.push(s[i..=j].to_string());
                i = j + 1;
            } else {
                break;
            }
        } else if ch == b'L' {
            if let Some(end) = s[i..].find(';') {
                let abs_end = i + end;
                out.push(s[i..=abs_end].to_string());
                i = abs_end + 1;
            } else {
                break;
            }
        } else {
            i += 1; // unknown char — skip
        }
    }
    out
}

/// Parse a smali class descriptor like `Lcom/example/Foo;` into
/// `(fqn, package, simple_name)`. Accepts either internal or dotted form.
pub fn parse_smali_class_name(smali: &str) -> (String, String, String) {
    let internal: String = if smali.starts_with('L') && smali.ends_with(';') {
        smali[1..smali.len() - 1].to_string()
    } else {
        smali.replace('.', "/").trim_start_matches('L').trim_end_matches(';').to_string()
    };
    let fqn = internal.replace('/', ".");
    let (package, simple) = match fqn.rfind('.') {
        Some(i) => (fqn[..i].to_string(), fqn[i + 1..].to_string()),
        None => (String::new(), fqn.clone()),
    };
    (fqn, package, simple)
}

// ── Access flags ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Default)]
pub struct AccessFlags {
    pub public:       bool,
    pub private:      bool,
    pub protected:    bool,
    pub static_:      bool,
    pub final_:       bool,
    pub synchronized: bool,
    pub abstract_:    bool,
    pub interface:    bool,
    pub enum_:        bool,
}

impl AccessFlags {
    pub fn from_bits(flags: u16) -> Self {
        Self {
            public:       flags & 0x0001 != 0,
            private:      flags & 0x0002 != 0,
            protected:    flags & 0x0004 != 0,
            static_:      flags & 0x0008 != 0,
            final_:       flags & 0x0010 != 0,
            synchronized: flags & 0x0020 != 0,
            abstract_:    flags & 0x0400 != 0,
            interface:    flags & 0x0200 != 0,
            enum_:        flags & 0x4000 != 0,
        }
    }
}

// ── Content-addressed hashes (producer feature) ───────────────────────────

/// Stable 16-hex-char SHA-256 prefix of `(class, method, descriptor)`.
/// Used by the matcher for exact-signature lookups across the index.
#[cfg(feature = "producer")]
pub fn method_signature_hash(class_fqn: &str, method: &str, desc: &str) -> String {
    use sha2::{Digest, Sha256};
    let key = format!("{class_fqn}\x00{method}\x00{desc}");
    let h = Sha256::digest(key.as_bytes());
    hex::encode(&h[..8])
}

/// Full-length SHA-256 hex digest of a class's *sorted* `(name, desc)`
/// method signatures. Two classes with identical method sets get the same
/// fingerprint regardless of source order — this is what powers the
/// content-addressed dedup in the index.
#[cfg(feature = "producer")]
pub fn class_fingerprint(methods: &[(String, String)]) -> String {
    use sha2::{Digest, Sha256};
    let mut canonical: Vec<String> = methods.iter()
        .map(|(n, d)| format!("{n}\x00{d}"))
        .collect();
    canonical.sort();
    let joined = canonical.join("\n");
    let h = Sha256::digest(joined.as_bytes());
    hex::encode(h)
}

/// 16-hex-char structural fingerprint for a method body. Combines
/// param count, return type, invoke/field-access counts, and the sorted
/// list of called-method signature hashes. Two methods with the same
/// outward behaviour have the same struct hash even if their *names*
/// were renamed by R8.
#[cfg(feature = "producer")]
pub fn structural_hash(
    param_count: usize,
    return_descriptor: &str,
    invoke_count: usize,
    field_get_count: usize,
    field_put_count: usize,
    called_method_sigs: &[String],
) -> String {
    use sha2::{Digest, Sha256};
    let mut sigs: Vec<String> = called_method_sigs.to_vec();
    sigs.sort();
    let parts = [
        param_count.to_string(),
        return_descriptor.to_string(),
        invoke_count.to_string(),
        field_get_count.to_string(),
        field_put_count.to_string(),
    ];
    let joined = format!("{}|{}", parts.join("|"), sigs.join("|"));
    let h = Sha256::digest(joined.as_bytes());
    hex::encode(&h[..8])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_split_basic() {
        let (p, r) = parse_method_descriptor("(ILjava/lang/String;[B)V");
        assert_eq!(p, vec!["I", "Ljava/lang/String;", "[B"]);
        assert_eq!(r, "V");
    }

    #[test]
    fn descriptor_split_empty_params() {
        let (p, r) = parse_method_descriptor("()Lokhttp3/Call;");
        assert!(p.is_empty());
        assert_eq!(r, "Lokhttp3/Call;");
    }

    #[test]
    fn descriptor_split_nested_arrays() {
        let (p, _) = parse_method_descriptor("([[Ljava/lang/String;I)V");
        assert_eq!(p, vec!["[[Ljava/lang/String;", "I"]);
    }

    #[test]
    fn smali_class_name_internal() {
        let (fqn, pkg, simple) = parse_smali_class_name("Lcom/example/Foo$Bar;");
        assert_eq!(fqn, "com.example.Foo$Bar");
        assert_eq!(pkg, "com.example");
        assert_eq!(simple, "Foo$Bar");
    }

    #[test]
    fn smali_class_name_dotted() {
        let (fqn, pkg, simple) = parse_smali_class_name("com.example.Foo");
        assert_eq!(fqn, "com.example.Foo");
        assert_eq!(pkg, "com.example");
        assert_eq!(simple, "Foo");
    }

    #[cfg(feature = "producer")]
    #[test]
    fn fingerprints_deterministic_under_reordering() {
        let a = class_fingerprint(&[
            ("a".into(), "()V".into()),
            ("b".into(), "(I)I".into()),
        ]);
        let b = class_fingerprint(&[
            ("b".into(), "(I)I".into()),
            ("a".into(), "()V".into()),
        ]);
        assert_eq!(a, b);
    }

    #[cfg(feature = "producer")]
    #[test]
    fn struct_hash_independent_of_call_order() {
        let a = structural_hash(2, "V", 3, 1, 0, &["x".into(), "y".into(), "z".into()]);
        let b = structural_hash(2, "V", 3, 1, 0, &["z".into(), "x".into(), "y".into()]);
        assert_eq!(a, b);
    }
}
