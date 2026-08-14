//! Parsing and resolution of Android resource references.
//!
//! Android attribute values can take several forms:
//!
//! ```text
//!   "Hello"                 — literal string
//!   "@string/app_name"      — reference by type + name (current package)
//!   "@android:string/ok"    — reference by type + name (other package)
//!   "@+id/my_button"        — id declaration (auto-allocated id)
//!   "@0x7f040001"           — reference by raw resource id (numeric)
//!   "?attr/colorPrimary"    — theme attribute reference
//!   "?android:textSize"     — theme attribute (android namespace)
//! ```
//!
//! Some appear in compiled binary XML as already-resolved IDs (`@0x...`),
//! others survive as `@type/name` pairs. This module recognises every form
//! and exposes a uniform [`Reference`] enum the caller can resolve.

use crate::ResourceTable;

/// A parsed Android resource reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reference {
    /// `@0x7f040001` — already resolved to a numeric ID.
    Id(u32),
    /// `@string/app_name` / `@android:string/ok` — by type + name.
    Named {
        /// `string` / `drawable` / `id` / `layout` / …
        type_name: String,
        name: String,
        /// `Some("android")` for framework refs, `None` for app's own package.
        package: Option<String>,
    },
    /// `@+id/my_button` — id declaration. Treated as a forward reference; we
    /// don't try to *create* the id, just record it.
    IdDecl(String),
    /// `?attr/colorPrimary` / `?android:textSize` — theme attribute reference.
    /// Resolution requires walking the active theme; we surface it as-is.
    ThemeAttr {
        name: String,
        package: Option<String>,
    },
}

impl Reference {
    /// True if this is a resolvable resource reference (everything except
    /// theme attrs, which need theme context to resolve).
    pub fn is_resolvable(&self) -> bool {
        !matches!(self, Reference::ThemeAttr { .. })
    }
}

/// Try to parse a reference out of a string. Returns `None` for plain
/// literals — the caller should treat those as their own value.
pub fn parse_reference(s: &str) -> Option<Reference> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let first = s.chars().next()?;

    match first {
        '@' => parse_at_reference(&s[1..]),
        '?' => parse_theme_reference(&s[1..]),
        _ => None,
    }
}

fn parse_at_reference(rest: &str) -> Option<Reference> {
    // "@+id/name" — id declaration
    if let Some(name) = rest.strip_prefix("+id/") {
        return Some(Reference::IdDecl(name.to_string()));
    }
    // "@0x7f040001" — numeric id
    if let Some(hex) = rest.strip_prefix("0x").or_else(|| rest.strip_prefix("0X")) {
        if let Ok(id) = u32::from_str_radix(hex, 16) {
            return Some(Reference::Id(id));
        }
    }
    // Bare decimal `@123` — also numeric id (uncommon but valid)
    if rest.chars().all(|c| c.is_ascii_digit()) && !rest.is_empty() {
        if let Ok(id) = rest.parse::<u32>() {
            return Some(Reference::Id(id));
        }
    }
    // "@android:string/ok" or "@string/app_name"
    let (package, after_pkg) = match rest.find(':') {
        Some(pos) => (Some(rest[..pos].to_string()), &rest[pos + 1..]),
        None => (None, rest),
    };
    let slash = after_pkg.find('/')?;
    let type_name = &after_pkg[..slash];
    let name = &after_pkg[slash + 1..];
    if type_name.is_empty() || name.is_empty() {
        return None;
    }
    Some(Reference::Named {
        type_name: type_name.to_string(),
        name: name.to_string(),
        package,
    })
}

fn parse_theme_reference(rest: &str) -> Option<Reference> {
    // "?android:attr/colorPrimary" / "?attr/foo" / "?android:foo" / "?foo"
    let (package, body) = match rest.find(':') {
        Some(pos) => (Some(rest[..pos].to_string()), &rest[pos + 1..]),
        None => (None, rest),
    };
    let name = body.strip_prefix("attr/").unwrap_or(body);
    if name.is_empty() {
        return None;
    }
    Some(Reference::ThemeAttr {
        name: name.to_string(),
        package,
    })
}

/// Resolve a reference to its final string value via a [`ResourceTable`].
/// Returns `None` for unresolvable refs (theme attrs, missing entries).
///
/// For `Named` refs the package is checked: framework references (package =
/// "android") aren't in the app's resources.arsc, so they can't be resolved
/// here — callers may want to special-case them (or load framework resources
/// from `framework-res.apk`).
pub fn resolve(reference: &Reference, table: &ResourceTable) -> Option<String> {
    match reference {
        Reference::Id(id) => table.resolve(*id),
        Reference::Named { type_name, name, package } => {
            // Framework refs aren't resolvable from app resources.arsc.
            if package.as_deref() == Some("android") {
                return None;
            }
            // Find the entry by (type, name).
            let entry = table
                .entries()
                .iter()
                .find(|e| e.type_name == *type_name && e.name == *name)?;
            table.resolve(entry.id)
        }
        Reference::IdDecl(_) | Reference::ThemeAttr { .. } => None,
    }
}

/// Convenience: parse + resolve in one step. Returns the original string if
/// it isn't a reference, or if the reference can't be resolved.
pub fn resolve_value(s: &str, table: &ResourceTable) -> String {
    if let Some(r) = parse_reference(s) {
        if let Some(v) = resolve(&r, table) {
            return v;
        }
    }
    s.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_reference() {
        let r = parse_reference("@string/app_name").unwrap();
        assert!(matches!(r, Reference::Named { ref type_name, ref name, package: None }
            if type_name == "string" && name == "app_name"));
    }

    #[test]
    fn parses_namespaced_reference() {
        let r = parse_reference("@android:string/ok").unwrap();
        assert!(matches!(r, Reference::Named { ref type_name, ref name, package: Some(ref p) }
            if type_name == "string" && name == "ok" && p == "android"));
    }

    #[test]
    fn parses_id_decl() {
        let r = parse_reference("@+id/btn").unwrap();
        assert!(matches!(r, Reference::IdDecl(ref n) if n == "btn"));
    }

    #[test]
    fn parses_hex_id() {
        let r = parse_reference("@0x7f040001").unwrap();
        assert!(matches!(r, Reference::Id(0x7f040001)));
    }

    #[test]
    fn parses_theme_attr() {
        let r = parse_reference("?attr/colorPrimary").unwrap();
        assert!(matches!(r, Reference::ThemeAttr { ref name, package: None } if name == "colorPrimary"));
    }

    #[test]
    fn plain_literal_returns_none() {
        assert_eq!(parse_reference("Hello world"), None);
        assert_eq!(parse_reference(""), None);
    }
}
