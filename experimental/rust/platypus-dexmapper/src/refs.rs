//! Parsing for JVM method/field references that appear in the rehydrated
//! IR (`Handler.target`, `AttrOrigin::Dynamic.from_method`, `Compose.method_ref`).
//!
//! Two forms exist in the wild:
//!   - smali / DEX form:   `Lcom/foo/Bar;->method(I)V`
//!   - jadx-ish form:      `com.foo.Bar.method(I)V`
//!
//! We accept both and always produce JVM-internal output. The "field
//! reference" form (`Lcom/foo/Bar;->field:Lcom/foo/X;`) is also recognised
//! but we treat it conservatively — most rehydrate outputs use method refs.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JvmRef {
    /// Internal class name (no `L`/`;` wrapper, slashes preserved).
    pub class: String,
    pub method: String,
    /// Method descriptor including parentheses, e.g. `(I)V`.
    pub desc: String,
}

/// Parse a method reference. Returns `None` when the input doesn't match
/// either supported shape — the caller should pass the value through
/// unchanged in that case rather than producing a corrupted ref.
pub fn parse_method_ref(s: &str) -> Option<JvmRef> {
    // Smali shape: `Lcom/foo/Bar;->method(...)R`
    if let Some(arrow) = s.find("->") {
        let (lhs, rhs) = (&s[..arrow], &s[arrow + 2..]);
        let class = lhs.trim().trim_start_matches('L').trim_end_matches(';').to_string();
        // The descriptor starts at the first '('.
        let paren = rhs.find('(')?;
        let method = rhs[..paren].to_string();
        let desc = rhs[paren..].to_string();
        if class.is_empty() || method.is_empty() { return None; }
        return Some(JvmRef { class, method, desc });
    }
    // Jadx-ish shape: `com.foo.Bar.method(...)R` — split on the last dot
    // before the first '('. Anything trailing after the parens belongs to
    // the descriptor's return-type segment, which `find('(')` already
    // captures correctly.
    let paren = s.find('(')?;
    let head = &s[..paren];
    let dot = head.rfind('.')?;
    let class = head[..dot].replace('.', "/");
    let method = head[dot + 1..].to_string();
    let desc = s[paren..].to_string();
    if class.is_empty() || method.is_empty() { return None; }
    Some(JvmRef { class, method, desc })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_smali_form() {
        let r = parse_method_ref("Lcom/foo/Bar;->baz(I)V").unwrap();
        assert_eq!(r.class, "com/foo/Bar");
        assert_eq!(r.method, "baz");
        assert_eq!(r.desc, "(I)V");
    }

    #[test]
    fn parses_jadx_form() {
        let r = parse_method_ref("com.foo.Bar.baz(I)V").unwrap();
        assert_eq!(r.class, "com/foo/Bar");
        assert_eq!(r.method, "baz");
        assert_eq!(r.desc, "(I)V");
    }

    #[test]
    fn parses_inner_class_smali() {
        let r = parse_method_ref("Lcom/foo/Bar$1;->onClick(Landroid/view/View;)V").unwrap();
        assert_eq!(r.class, "com/foo/Bar$1");
        assert_eq!(r.method, "onClick");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_method_ref("not a method ref").is_none());
        assert!(parse_method_ref("Lcom/foo/Bar;->").is_none());
    }
}
