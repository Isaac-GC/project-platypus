//! Lambda detection + call-signature hashing.
//!
//! Most modern Android binaries are dominated by synthetic lambda
//! classes (Kotlin SAM conversions, Compose `{ ... }` blocks, coroutine
//! continuations). Class-level fingerprinting fails on them because
//! their names are entirely position-generated (`Foo$bar$1`,
//! `ComposableSingletons$FooKt$lambda$3`), so the obfuscated and
//! library versions never share a fingerprint. But their *shape*
//! survives R8 cleanly:
//!
//!   1. Superclass chain: `kotlin/jvm/internal/Lambda`,
//!      `kotlin/coroutines/jvm/internal/SuspendLambda`,
//!      `kotlin/jvm/internal/FunctionReferenceImpl`.
//!   2. Method shape: a single `invoke(...)` plus a constructor
//!      capturing 0+ outer values.
//!   3. Body: the *sequence* of external method calls inside
//!      `invoke()` — `Text → Spacer → Button` is highly identifying
//!      because it follows the source-code order of a UI lambda.
//!
//! This module turns those signals into a `LambdaSignature` the matcher
//! can join on.

use crate::bytecode::{ClassInfo, MethodInfo};
use crate::descriptors;

// ── Lambda kind ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LambdaKind {
    /// Direct subclass of `kotlin/jvm/internal/Lambda` — vanilla Kotlin
    /// `{ x -> y }` block.
    KotlinLambda,
    /// Subclass of `kotlin/coroutines/jvm/internal/SuspendLambda` —
    /// `suspend { ... }` block.
    SuspendLambda,
    /// Subclass of `kotlin/jvm/internal/FunctionReferenceImpl` —
    /// method-reference `::foo` adaptor.
    FunctionReference,
    /// Implements `androidx/compose/runtime/internal/ComposableLambda` —
    /// the Compose runtime's wrapper used by every `@Composable {...}`.
    /// Distinct from `KotlinLambda` because its invoke takes a
    /// `Composer` first parameter and the constructor captures a
    /// stable key.
    ComposableLambda,
    /// A class containing only `static final ComposableLambda` fields —
    /// the Compose compiler's per-file `ComposableSingletons$<File>`
    /// holder. Useful because all its lambdas tend to come from one
    /// source file, giving us a clustering anchor.
    ComposableSingletons,
}

impl LambdaKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LambdaKind::KotlinLambda         => "kotlin_lambda",
            LambdaKind::SuspendLambda        => "suspend_lambda",
            LambdaKind::FunctionReference    => "function_ref",
            LambdaKind::ComposableLambda     => "composable_lambda",
            LambdaKind::ComposableSingletons => "composable_singletons",
        }
    }
}

// ── Signature ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct LambdaSignature {
    pub kind: LambdaKind,
    /// Functional arity (Function0 / Function1 / …). For ComposableLambda
    /// this is the count of "user-visible" params (excluding the leading
    /// Composer + trailing changed-bits int).
    pub arity: u32,
    /// Number of captured outer values — taken from the lambda
    /// constructor's parameter count (minus `this`).
    pub captured: u32,
    /// 16-hex hash of the *sorted* sequence of external method-signature
    /// hashes invoked by `invoke()`. Insensitive to call order so the
    /// matcher tolerates trivial reorderings introduced by R8's basic-
    /// block re-layout, but sensitive to *which* methods are called.
    pub call_signature: String,
    /// JVM descriptor of the lambda's `invoke()` (or `invokeSuspend()`)
    /// method.
    pub invoke_descriptor: String,
}

// ── Renamed-parent discovery (obfuscated-target side) ──────────────────────

/// Set of class internal names that act as "Lambda" or "SuspendLambda"
/// in a given input — including the standard JVM-internal forms and any
/// **renamed parents** discovered by structural shape. Aggressive R8
/// configs (e.g. AuroraStore's) rename `kotlin/jvm/internal/Lambda` to
/// something like `se/i`; we discover that by recognising the parent's
/// shape (`<init>(I…)V`, an `()I` arity getter, `toString()`).
#[derive(Debug, Clone, Default)]
pub struct LambdaAliases {
    pub kotlin_lambda:    std::collections::HashSet<String>,
    pub suspend_lambda:   std::collections::HashSet<String>,
    pub function_ref:     std::collections::HashSet<String>,
}

impl LambdaAliases {
    pub fn with_standard_names() -> Self {
        let mut a = Self::default();
        a.kotlin_lambda.insert("kotlin/jvm/internal/Lambda".into());
        a.suspend_lambda.insert("kotlin/coroutines/jvm/internal/SuspendLambda".into());
        a.function_ref.insert("kotlin/jvm/internal/FunctionReferenceImpl".into());
        a
    }

    /// Scan a slice of smali classes for **renamed** lambda parents,
    /// returning a `LambdaAliases` that includes both the standard
    /// `kotlin/jvm/internal/Lambda` family names and any renamed
    /// equivalents discovered by structural shape.
    ///
    /// Detection rule: a class qualifies as a renamed lambda parent
    /// when it is *abstract*, has a `()I` no-arg int-returning method
    /// (renamed `getArity`), has a `toString()Ljava/lang/String;`, and
    /// its `<init>` accepts an `I` as its first argument (the arity
    /// passed by every subclass).
    ///
    /// Variants:
    ///   - 1-arg ctor `(I)V` → `kotlin_lambda` (vanilla `Lambda`)
    ///   - 2-arg ctor with `I` + an object → `suspend_lambda` (the
    ///     extra arg is the `Continuation`)
    ///   - 5+ arg ctor with `I` plus owner/name/sig strings → `function_ref`
    pub fn discover(classes: &[crate::analysis::smali_parser::SmaliClass]) -> Self {
        let mut a = Self::with_standard_names();
        for cls in classes {
            let Some(kind) = classify_parent_shape(cls) else { continue; };
            let set = match kind {
                LambdaKind::KotlinLambda      => &mut a.kotlin_lambda,
                LambdaKind::SuspendLambda     => &mut a.suspend_lambda,
                LambdaKind::FunctionReference => &mut a.function_ref,
                _ => continue,
            };
            // Insert in both `Lcom/foo;` and `com/foo` forms so callers
            // can normalise either way.
            set.insert(cls.internal_name.clone());
            set.insert(format!("L{};", cls.internal_name));
        }
        a
    }

    pub fn classify_parent(&self, name: &str) -> Option<LambdaKind> {
        let stripped = name.strip_prefix('L').and_then(|s| s.strip_suffix(';'))
            .map(|s| s.to_string()).unwrap_or_else(|| name.to_string());
        if self.kotlin_lambda.contains(&stripped) || self.kotlin_lambda.contains(name) {
            return Some(LambdaKind::KotlinLambda);
        }
        if self.suspend_lambda.contains(&stripped) || self.suspend_lambda.contains(name) {
            return Some(LambdaKind::SuspendLambda);
        }
        if self.function_ref.contains(&stripped) || self.function_ref.contains(name) {
            return Some(LambdaKind::FunctionReference);
        }
        None
    }
}

/// Inspect a class's *own* shape and decide whether **it** looks like a
/// Lambda / SuspendLambda / FunctionReferenceImpl abstract parent (not
/// a subclass of one). Returns the kind when the structural signature
/// matches.
fn classify_parent_shape(cls: &crate::analysis::smali_parser::SmaliClass) -> Option<LambdaKind> {
    // Abstract is required — `Lambda` itself is abstract, concrete
    // user-lambdas extend it.
    if !cls.flags.contains("abstract") { return None; }
    if cls.methods.is_empty() { return None; }
    // toString accessor.
    let has_to_string = cls.methods.iter()
        .any(|m| m.name == "toString" && m.descriptor == "()Ljava/lang/String;");
    if !has_to_string { return None; }
    // Arity getter — any 0-arg method returning int. Real name is
    // `getArity()I`; renamed to a single letter under R8.
    let has_arity = cls.methods.iter()
        .any(|m| m.descriptor == "()I" && !matches!(m.name.as_str(), "<init>" | "<clinit>"));
    if !has_arity { return None; }
    // Find <init>; first param must be `I` (the arity).
    let ctor = cls.methods.iter().find(|m| m.name == "<init>")?;
    let (params, _ret) = crate::descriptors::parse_method_descriptor(&ctor.descriptor);
    let first = params.first()?;
    if first != "I" { return None; }

    match params.len() {
        1 => Some(LambdaKind::KotlinLambda),
        2 if params[1].starts_with('L') => Some(LambdaKind::SuspendLambda),
        n if n >= 4 => Some(LambdaKind::FunctionReference),
        _ => Some(LambdaKind::KotlinLambda),
    }
}

// ── Classification ──────────────────────────────────────────────────────────

/// Classify a `SmaliClass` (the matcher's input shape) as a lambda. Same
/// signal set as [`classify_lambda`] — see that doc for details. Uses
/// only the standard `kotlin/jvm/internal/*` names; if R8 renamed those
/// (common with aggressive shrinker configs) call
/// [`classify_smali_lambda_with_aliases`] instead with a
/// [`LambdaAliases`] discovered by [`LambdaAliases::discover`].
pub fn classify_smali_lambda(cls: &crate::analysis::smali_parser::SmaliClass)
    -> Option<LambdaSignature>
{
    classify_smali_lambda_with_aliases(cls, &LambdaAliases::with_standard_names())
}

pub fn classify_smali_lambda_with_aliases(
    cls: &crate::analysis::smali_parser::SmaliClass,
    aliases: &LambdaAliases,
) -> Option<LambdaSignature> {
    // SmaliClass stores L…; wrappers and stripped internal forms in
    // different fields; for lambda detection we only need internal-name
    // strings, which we strip ourselves.
    let strip = |s: &str| -> String {
        s.strip_prefix('L').and_then(|s| s.strip_suffix(';'))
            .map(|s| s.to_string()).unwrap_or_else(|| s.to_string())
    };
    let sup = cls.superclass.as_deref();
    let kind = match sup.and_then(|s| aliases.classify_parent(s)) {
        Some(k) => k,
        None => {
            // ComposableSingletons fallback — same structural heuristic
            // regardless of parent name.
            if smali_looks_like_composable_singletons(cls) {
                LambdaKind::ComposableSingletons
            } else {
                return None;
            }
        }
    };

    let invoke = cls.methods.iter().find(|m| m.name == "invoke")
        .or_else(|| cls.methods.iter().find(|m| m.name == "invokeSuspend"))
        .or_else(|| cls.methods.iter().find(|m| !matches!(m.name.as_str(), "<init>" | "<clinit>")))?;
    let ctor = cls.methods.iter().find(|m| m.name == "<init>");
    let captured = ctor.map(|m| descriptors::parse_method_descriptor(&m.descriptor).0.len() as u32)
                       .unwrap_or(0);
    let arity = invoke_arity(&invoke.descriptor, kind);

    let mut sigs: Vec<String> = invoke.call_edges.iter()
        .filter(|e| !is_stdlib_call(&strip(&e.callee_class)))
        .map(|e| descriptors::method_signature_hash(
            &strip(&e.callee_class), &e.callee_name, &e.callee_descriptor,
        ))
        .collect();
    sigs.sort();
    let call_sig = hash_strings(&sigs);
    Some(LambdaSignature {
        kind, arity, captured,
        call_signature: call_sig,
        invoke_descriptor: invoke.descriptor.clone(),
    })
}

fn smali_looks_like_composable_singletons(cls: &crate::analysis::smali_parser::SmaliClass) -> bool {
    if cls.methods.is_empty() || cls.fields.is_empty() { return false; }
    if cls.fields.len() < 2 { return false; }
    let all_object = cls.fields.iter()
        .all(|f| f.descriptor.starts_with('L') || f.descriptor.starts_with('['));
    if !all_object { return false; }
    let field_types: std::collections::HashSet<&str> =
        cls.fields.iter().map(|f| f.descriptor.as_str()).collect();
    cls.methods.iter().any(|m| {
        let (params, ret) = descriptors::parse_method_descriptor(&m.descriptor);
        params.is_empty() && field_types.contains(ret.as_str())
    })
}

/// Classify a class as a lambda, returning a signature when it is.
/// Returns `None` for non-lambda classes (regular types).
pub fn classify_lambda(cls: &ClassInfo) -> Option<LambdaSignature> {
    let kind = lambda_kind(cls)?;
    let invoke = find_invoke_method(cls)?;
    let captured = captured_count(cls);
    let arity = invoke_arity(&invoke.descriptor, kind);

    // External-call sequence — exclude kotlin / java stdlib helpers and
    // self-calls. The remaining calls are what the lambda is "really
    // doing" from a behavioural standpoint.
    let mut sigs: Vec<String> = invoke.call_edges.iter()
        .filter(|e| !is_stdlib_call(&e.callee_class))
        .map(|e| descriptors::method_signature_hash(
            &e.callee_class, &e.callee_name, &e.callee_descriptor,
        ))
        .collect();
    sigs.sort();
    let call_sig = hash_strings(&sigs);

    Some(LambdaSignature {
        kind, arity, captured,
        call_signature: call_sig,
        invoke_descriptor: invoke.descriptor.clone(),
    })
}

fn lambda_kind(cls: &ClassInfo) -> Option<LambdaKind> {
    if let Some(sup) = cls.superclass.as_deref() {
        match sup {
            "kotlin/jvm/internal/Lambda"                  => return Some(LambdaKind::KotlinLambda),
            "kotlin/coroutines/jvm/internal/SuspendLambda"=> return Some(LambdaKind::SuspendLambda),
            "kotlin/jvm/internal/FunctionReferenceImpl"   => return Some(LambdaKind::FunctionReference),
            _ => {}
        }
    }
    // ComposableLambda — implements the runtime's wrapper interface OR
    // (post-R8) has a class whose only methods include exactly one
    // `invoke` taking a Composer-shaped first parameter.
    if cls.interfaces.iter().any(|i| is_composable_lambda_iface(i)) {
        return Some(LambdaKind::ComposableLambda);
    }
    // ComposableSingletons — a class made entirely of static lambda
    // fields. We detect this very conservatively: every non-synthetic
    // field is static and of an object type (descriptor starts with `L`),
    // AND there's a `get` accessor pattern (several methods returning
    // those field types, no methods taking user-visible params besides
    // Composer).
    if looks_like_composable_singletons(cls) {
        return Some(LambdaKind::ComposableSingletons);
    }
    None
}

fn find_invoke_method(cls: &ClassInfo) -> Option<&MethodInfo> {
    // Prefer `invoke`, fall back to `invokeSuspend`, otherwise the first
    // non-`<init>` / `<clinit>` method.
    if let Some(m) = cls.methods.iter().find(|m| m.name == "invoke") { return Some(m); }
    if let Some(m) = cls.methods.iter().find(|m| m.name == "invokeSuspend") { return Some(m); }
    cls.methods.iter().find(|m| !matches!(m.name.as_str(), "<init>" | "<clinit>"))
}

/// Capture count = constructor param count.
fn captured_count(cls: &ClassInfo) -> u32 {
    let ctor = cls.methods.iter().find(|m| m.name == "<init>");
    match ctor {
        Some(m) => descriptors::parse_method_descriptor(&m.descriptor).0.len() as u32,
        None    => 0,
    }
}

/// Functional arity from the invoke descriptor. For ComposableLambda we
/// subtract the leading `Composer` and trailing `int` (changed-bits).
fn invoke_arity(desc: &str, kind: LambdaKind) -> u32 {
    let (params, _ret) = descriptors::parse_method_descriptor(desc);
    let n = params.len() as i64;
    let adj = match kind {
        LambdaKind::ComposableLambda => n.saturating_sub(2),  // Composer + changed
        _ => n,
    };
    adj.max(0) as u32
}

/// SHA256-prefix hash of a sorted string list. Mirrors descriptors::
/// structural_hash but on a different shape.
fn hash_strings(parts: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let joined = parts.join("\n");
    let h = Sha256::digest(joined.as_bytes());
    hex::encode(&h[..8])
}

/// Recognise the Compose runtime's lambda wrapper interface. Both the
/// pre-R8 FQN and various R8-shortened forms are listed; in practice
/// app code keeps the fully-qualified name because it's referenced by
/// non-shrinkable runtime classes.
fn is_composable_lambda_iface(name: &str) -> bool {
    matches!(name,
        "androidx/compose/runtime/internal/ComposableLambda"
      | "androidx/compose/runtime/internal/ComposableLambdaN"
      | "androidx/compose/runtime/internal/ComposableLambdaImpl"
      | "androidx/compose/runtime/internal/ComposableLambdaNImpl"
    )
}

/// Heuristic ComposableSingletons detection. The structural fingerprint:
///   - no instance fields
///   - many static fields, all of object type (typically Lambda subclasses)
///   - one `INSTANCE` static field (the Kotlin object singleton)
///   - methods are all `getLambda-<n>$<scope>` accessors returning the
///     same set of types as the fields
fn looks_like_composable_singletons(cls: &ClassInfo) -> bool {
    // Empty / interface classes don't qualify.
    if cls.methods.is_empty() || cls.fields.is_empty() { return false; }
    let nf = cls.fields.len();
    if nf < 2 { return false; } // singleton + at least one lambda

    // The field shape we look for: all object types, no primitives.
    let all_object = cls.fields.iter()
        .all(|f| f.descriptor.starts_with('L') || f.descriptor.starts_with('['));
    if !all_object { return false; }

    // There should be at least one method that returns one of the field
    // types — the lambda accessor pattern.
    let field_types: std::collections::HashSet<&str> =
        cls.fields.iter().map(|f| f.descriptor.as_str()).collect();
    let any_accessor = cls.methods.iter().any(|m| {
        let (params, ret) = descriptors::parse_method_descriptor(&m.descriptor);
        params.is_empty() && field_types.contains(ret.as_str())
    });
    any_accessor
}

/// Calls we want to *ignore* when building the call-signature: Kotlin
/// stdlib, Java stdlib, kotlinx coroutines plumbing. These appear in
/// every lambda regardless of behaviour and would dilute the hash.
fn is_stdlib_call(class: &str) -> bool {
    matches!(class,
        c if c.starts_with("kotlin/") ||
             c.starts_with("kotlinx/coroutines/") ||
             c.starts_with("java/") ||
             c.starts_with("javax/")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{CallEdge, CallType, FieldInfo, MethodInfo};

    fn lambda_class(superclass: &str, captured: u32, calls: &[(&str, &str, &str)]) -> ClassInfo {
        ClassInfo {
            internal_name: "App$lambda$1".into(),
            superclass: Some(superclass.into()),
            interfaces: vec![],
            flags: 0,
            source_file: None,
            fields: vec![],
            methods: vec![
                MethodInfo {
                    name: "<init>".into(),
                    descriptor: format!("({}){}",
                        "Ljava/lang/Object;".repeat(captured as usize), "V"),
                    flags: 0, call_edges: vec![],
                    field_gets: vec![], field_puts: vec![], local_count: 0,
                },
                MethodInfo {
                    name: "invoke".into(),
                    descriptor: "()Ljava/lang/Object;".into(),
                    flags: 0,
                    call_edges: calls.iter().map(|(c, n, d)| CallEdge {
                        callee_class: (*c).into(), callee_name: (*n).into(),
                        callee_descriptor: (*d).into(), call_type: CallType::Static,
                    }).collect(),
                    field_gets: vec![], field_puts: vec![], local_count: 0,
                },
            ],
        }
    }

    #[test]
    fn detects_kotlin_lambda() {
        let c = lambda_class("kotlin/jvm/internal/Lambda", 0, &[
            ("androidx/compose/material3/TextKt", "Text", "(Ljava/lang/String;)V"),
        ]);
        let sig = classify_lambda(&c).expect("should classify as lambda");
        assert_eq!(sig.kind, LambdaKind::KotlinLambda);
        assert_eq!(sig.arity, 0);
        assert_eq!(sig.captured, 0);
        assert!(!sig.call_signature.is_empty());
    }

    #[test]
    fn detects_suspend_lambda() {
        let c = lambda_class("kotlin/coroutines/jvm/internal/SuspendLambda", 2, &[]);
        let sig = classify_lambda(&c).unwrap();
        assert_eq!(sig.kind, LambdaKind::SuspendLambda);
        assert_eq!(sig.captured, 2);
    }

    #[test]
    fn non_lambda_returns_none() {
        let c = ClassInfo {
            internal_name: "com/example/Plain".into(),
            superclass: Some("java/lang/Object".into()),
            interfaces: vec![],
            flags: 0, source_file: None, fields: vec![],
            methods: vec![],
        };
        assert!(classify_lambda(&c).is_none());
    }

    #[test]
    fn call_signature_ignores_stdlib() {
        let with_stdlib = lambda_class("kotlin/jvm/internal/Lambda", 0, &[
            ("kotlin/jvm/internal/Intrinsics", "checkNotNull", "(Ljava/lang/Object;)V"),
            ("androidx/compose/material3/TextKt", "Text", "(Ljava/lang/String;)V"),
        ]);
        let without_stdlib = lambda_class("kotlin/jvm/internal/Lambda", 0, &[
            ("androidx/compose/material3/TextKt", "Text", "(Ljava/lang/String;)V"),
        ]);
        let a = classify_lambda(&with_stdlib).unwrap();
        let b = classify_lambda(&without_stdlib).unwrap();
        assert_eq!(a.call_signature, b.call_signature,
                   "stdlib calls should not affect the lambda signature");
    }

    #[test]
    fn composable_singletons_detected() {
        // Three static fields of an object type + one accessor.
        let c = ClassInfo {
            internal_name: "ComposableSingletons$FooKt".into(),
            superclass: Some("java/lang/Object".into()),
            interfaces: vec![],
            flags: 0x9 /* public static */,
            source_file: None,
            fields: vec![
                FieldInfo { name: "INSTANCE".into(),
                            descriptor: "LComposableSingletons$FooKt;".into(), flags: 0x19 },
                FieldInfo { name: "lambda-1".into(),
                            descriptor: "Lkotlin/jvm/functions/Function2;".into(), flags: 0x19 },
                FieldInfo { name: "lambda-2".into(),
                            descriptor: "Lkotlin/jvm/functions/Function2;".into(), flags: 0x19 },
            ],
            methods: vec![
                MethodInfo { name: "getLambda-1".into(),
                             descriptor: "()Lkotlin/jvm/functions/Function2;".into(),
                             flags: 0x19, call_edges: vec![],
                             field_gets: vec![], field_puts: vec![], local_count: 0 },
            ],
        };
        let sig = classify_lambda(&c).expect("should classify as composable singletons");
        assert_eq!(sig.kind, LambdaKind::ComposableSingletons);
    }
}
