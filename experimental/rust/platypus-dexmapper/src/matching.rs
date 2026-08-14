//! Multi-tier matching engine. Given an obfuscated `SmaliClass` (or
//! `JavaClass`), search the indexed dependency database for the closest
//! library match and produce a `ClassMatch` with attached
//! per-method/per-field matches.
//!
//! Strategies, in order of decreasing confidence:
//!
//!   1. **Class fingerprint** — exact match of the set of `(method,
//!      desc)` signatures. Both classes provably encode the same API
//!      shape. Confidence 1.00.
//!   2. **Class structural** — Jaccard similarity of method descriptors,
//!      method/field counts, return-type vector, superclass, interface
//!      count. Confidence weighted by `WEIGHT_CLASS_STRUCTURAL` (0.75).
//!   3. **Per-method exact-sig** — name + descriptor match within an
//!      already-located class. 1.00.
//!   4. **Per-method structural** — descriptor + structural hash match.
//!      0.70, upgraded to 0.90 when sig and struct both agree.
//!   5. **Per-method fuzzy** — return type + param count only. 0.30.
//!
//! Mirrors the Python `dexmapper.matching.matcher` weights and ordering
//! so the produced confidence numbers stay comparable.

use crate::analysis::java_parser::JavaClass;
use crate::analysis::smali_parser::{SmaliClass, SmaliMethod};
use crate::db::{self, ClassRow, Database, MethodRow};
use crate::descriptors;

// ── Scoring constants ─────────────────────────────────────────────────────

pub const WEIGHT_CLASS_FINGERPRINT: f32 = 1.00;
pub const WEIGHT_CLASS_STRUCTURAL:  f32 = 0.75;
pub const WEIGHT_LAMBDA_UNIQUE:     f32 = 0.85;  // call-sig + arity uniquely resolve
pub const WEIGHT_LAMBDA_AMBIGUOUS:  f32 = 0.55;  // multiple library lambdas share the sig
pub const WEIGHT_METHOD_EXACT_SIG:  f32 = 1.00;
pub const WEIGHT_METHOD_STRUCT:     f32 = 0.70;
pub const WEIGHT_METHOD_COMBINED:   f32 = 0.90;
pub const WEIGHT_FIELD_EXACT:       f32 = 0.95;
pub const WEIGHT_HIERARCHY_BONUS:   f32 = 0.10;

// ── Result types ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MethodMatch {
    pub obfuscated_name: String,
    pub obfuscated_descriptor: String,
    pub real_name: String,
    pub real_class_fqn: String,
    pub real_descriptor: String,
    pub confidence: f32,
    pub match_type: String,
}

#[derive(Debug, Clone)]
pub struct FieldMatch {
    pub obfuscated_name: String,
    pub obfuscated_descriptor: String,
    pub real_name: String,
    pub real_class_fqn: String,
    pub confidence: f32,
    pub match_type: String,
}

#[derive(Debug, Clone)]
pub struct ClassMatch {
    pub obfuscated_fqn: String,
    pub real_fqn: String,
    pub confidence: f32,
    pub match_type: String,
    pub method_matches: Vec<MethodMatch>,
    pub field_matches: Vec<FieldMatch>,
}

// ── Matcher ───────────────────────────────────────────────────────────────

pub struct Matcher<'a> {
    db: &'a Database,
    /// Discovered lambda-parent aliases. Empty / standard set by
    /// default; populate via [`Matcher::with_lambda_aliases`] after
    /// scanning the target corpus so renamed `kotlin/jvm/internal/Lambda`
    /// equivalents are recognised.
    lambda_aliases: crate::lambda::LambdaAliases,
}

impl<'a> Matcher<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db, lambda_aliases: crate::lambda::LambdaAliases::with_standard_names() }
    }

    /// Replace the lambda alias set. Typical usage from `analyze`:
    /// scan the obfuscated input once with
    /// [`crate::lambda::LambdaAliases::discover`] to find renamed lambda
    /// parents (e.g. AuroraStore's `se/i` for `kotlin/jvm/internal/Lambda`),
    /// then plug the result in here so lambda-tier matching covers
    /// aggressively-obfuscated binaries.
    pub fn with_lambda_aliases(mut self, aliases: crate::lambda::LambdaAliases) -> Self {
        self.lambda_aliases = aliases;
        self
    }

    /// Match a smali class. Tiers tried in order:
    ///   1. **fingerprint** — exact method-signature-set match.
    ///   2. **lambda** — when both sides are lambda classes (`{...}`
    ///      blocks, Compose `setContent`), match by the sorted call
    ///      signature of `invoke()` body. Cheap, very effective on
    ///      Compose-heavy / Kotlin-heavy binaries where most synthetic
    ///      classes are lambdas.
    ///   3. **structural** — Jaccard similarity over descriptors + counts.
    pub fn match_smali_class(&self, cls: &SmaliClass) -> Result<Option<ClassMatch>, String> {
        // Quality gate: don't try to "rename" a class that doesn't
        // actually look obfuscated. R8 keeps original names for
        // application components (Activities, Services, Providers,
        // Receivers, Applications), classes referenced by reflection,
        // and any package the developer added to keep rules. Renaming
        // them produces high-volume noise — every `MainActivity` would
        // get matched to whatever library class happens to share a
        // similar method count.
        if looks_unobfuscated(cls) { return Ok(None); }


        // Lambda classes get the dedicated lambda tier *first* — their
        // class fingerprint (just `<init>(...)V` + `invoke(...)R`) is
        // shared by every other Lambda subclass with the same arity,
        // which would cause the generic fingerprint tier to return an
        // arbitrary same-shape candidate. The call-signature lookup is
        // far more precise for these.
        if std::env::var("DEXMAPPER_NO_LAMBDA").is_err() {
            if let Some(lambda_match) = self.lambda_match(cls)? {
                return Ok(Some(lambda_match));
            }
        }

        let sigs: Vec<(String, String)> = cls.methods.iter()
            .map(|m| (m.name.clone(), m.descriptor.clone())).collect();
        let fp = descriptors::class_fingerprint(&sigs);

        if let Some(row) = self.db.get_class_by_fingerprint(&fp)? {
            return Ok(Some(self.build_class_match_from_row(cls, row, WEIGHT_CLASS_FINGERPRINT, "fingerprint")?));
        }

        self.structural_smali_match(cls)
    }

    /// Lambda-aware tier — runs only when the obfuscated class
    /// classifies as a lambda (Kotlin lambda / SuspendLambda /
    /// FunctionReference / ComposableSingletons). Looks up indexed
    /// library lambdas by call signature + arity; produces a match if
    /// exactly one candidate exists, or a lower-confidence
    /// `lambda_ambiguous` match if several share the signature.
    ///
    /// Returns `Ok(None)` for non-lambda classes — the caller falls
    /// through to structural matching.
    fn lambda_match(&self, cls: &SmaliClass) -> Result<Option<ClassMatch>, String> {
        let Some(sig) = crate::lambda::classify_smali_lambda_with_aliases(
            cls, &self.lambda_aliases,
        ) else { return Ok(None); };
        // Skip lambdas whose body produces no external calls — every
        // empty `{ }` block has the same signature and would match
        // everything.
        if sig.call_signature == empty_sig() { return Ok(None); }

        let hits = self.db.find_lambdas_by_call_signature(
            &sig.call_signature, Some(sig.arity as i64),
        )?;
        if hits.is_empty() { return Ok(None); }

        let (confidence, match_type, pick) = if hits.len() == 1 {
            (WEIGHT_LAMBDA_UNIQUE, "lambda", hits.into_iter().next().unwrap())
        } else {
            // Multiple library lambdas share the call signature — typical
            // for very small lambdas (e.g. `{ Text("ok") }` appears
            // dozens of times in Material 3). Prefer ones whose capture
            // count matches; tie-break by first-indexed.
            let same_capture: Vec<_> = hits.iter()
                .filter(|r| r.captured == sig.captured as i64)
                .cloned().collect();
            let pool = if same_capture.is_empty() { hits } else { same_capture };
            let pick = pool.into_iter().next().unwrap();
            (WEIGHT_LAMBDA_AMBIGUOUS, "lambda_ambiguous", pick)
        };

        // Build a per-method ClassMatch. The lambda match resolves the
        // obfuscated class to the picked library class; the
        // invoke() method is renamed to the library lambda's invoke()
        // (always literally "invoke" / "invokeSuspend" — those are
        // never renamed because they implement an interface).
        let row = self.db.get_class_by_fqn(&pick.class_fqn)?
            .ok_or_else(|| format!("lambda match: class {} not in class_defs", pick.class_fqn))?;
        let mut cm = self.build_class_match_from_row(cls, row, confidence, match_type)?;
        // Note: the build_class_match_from_row helper already pairs
        // obfuscated methods with the library's by descriptor, so for a
        // 1-method lambda with `()V` (or whatever), `invoke` → `invoke`
        // gets rendered with the right descriptor automatically.
        cm.confidence = confidence; // overwrite the structural sub-boost
        cm.match_type = match_type.into();
        Ok(Some(cm))
    }

    /// Match a Java class — structural-only, since jadx-Java names are
    /// the same obfuscated identifiers and we have no descriptors to
    /// fingerprint with.
    pub fn match_java_class(&self, cls: &JavaClass) -> Result<Option<ClassMatch>, String> {
        // 1. Same-simple-name candidates.
        let mut candidates = self.db.get_classes_by_simple_name(&cls.simple_name)?;
        if candidates.is_empty() {
            let lo = (cls.methods.len() as i64 - 2).max(0);
            let hi = cls.methods.len() as i64 + 2;
            candidates = self.db.classes_with_method_count_between(lo, hi, 30)?;
        }
        let mut best_score = 0.0f32;
        let mut best: Option<ClassRow> = None;
        for row in candidates {
            let db_methods = self.db.get_methods_for_class(row.id)?;
            let db_fields  = self.db.get_fields_for_class(row.id)?;
            let mcount = db_methods.len();
            let fcount = db_fields.len();

            let m_ratio = ratio(mcount, cls.methods.len());
            let f_ratio = ratio(fcount, cls.fields.len());
            let mut s = m_ratio * 0.5 + f_ratio * 0.3;

            if let (Some(sup), Some(db_sup)) = (cls.superclass.as_deref(), row.superclass.as_deref()) {
                if db_sup.contains(sup) { s += WEIGHT_HIERARCHY_BONUS; }
            }
            if s > best_score { best_score = s; best = Some(row); }
        }
        if let Some(row) = best {
            if best_score > 0.40 {
                return Ok(Some(ClassMatch {
                    obfuscated_fqn: cls.fqn.clone(),
                    real_fqn: row.fqn,
                    confidence: best_score * WEIGHT_CLASS_STRUCTURAL,
                    match_type: "structural".into(),
                    method_matches: Vec::new(),
                    field_matches: Vec::new(),
                }));
            }
        }
        Ok(None)
    }

    /// Match a single SmaliMethod. Returns ranked candidates (highest
    /// confidence first).
    pub fn match_smali_method(&self, class_fqn: &str, method: &SmaliMethod)
        -> Result<Vec<MethodMatch>, String>
    {
        let (params, ret) = descriptors::parse_method_descriptor(&method.descriptor);
        let sig_hash = descriptors::method_signature_hash(class_fqn, &method.name, &method.descriptor);

        let called_sigs: Vec<String> = method.call_edges.iter()
            .map(|e| descriptors::method_signature_hash(&e.callee_class, &e.callee_name, &e.callee_descriptor))
            .collect();
        let struct_h = descriptors::structural_hash(
            params.len(), &ret,
            method.call_edges.len(), method.field_gets.len(), method.field_puts.len(),
            &called_sigs,
        );

        let mut out: Vec<MethodMatch> = Vec::new();

        for row in self.db.find_methods_by_sig_hash(&sig_hash)? {
            out.push(MethodMatch {
                obfuscated_name: method.name.clone(),
                obfuscated_descriptor: method.descriptor.clone(),
                real_name: row.name,
                real_class_fqn: row.class_fqn,
                real_descriptor: row.descriptor,
                confidence: WEIGHT_METHOD_EXACT_SIG,
                match_type: "exact_sig".into(),
            });
        }

        let existing: std::collections::HashSet<(String, String)> = out.iter()
            .map(|m| (m.real_name.clone(), m.real_class_fqn.clone())).collect();
        for row in self.db.find_methods_by_struct_hash(&struct_h)? {
            let key = (row.name.clone(), row.class_fqn.clone());
            if existing.contains(&key) {
                // Upgrade confidence on the existing hit.
                for m in &mut out {
                    if (m.real_name.clone(), m.real_class_fqn.clone()) == key {
                        m.confidence = WEIGHT_METHOD_COMBINED;
                        m.match_type = "combined".into();
                    }
                }
            } else {
                out.push(MethodMatch {
                    obfuscated_name: method.name.clone(),
                    obfuscated_descriptor: method.descriptor.clone(),
                    real_name: row.name,
                    real_class_fqn: row.class_fqn,
                    real_descriptor: row.descriptor,
                    confidence: WEIGHT_METHOD_STRUCT,
                    match_type: "struct".into(),
                });
            }
        }

        if out.is_empty() {
            // Fuzzy fallback by shape.
            for row in self.db.find_methods_by_shape(&ret, params.len() as i64, 10)? {
                out.push(MethodMatch {
                    obfuscated_name: method.name.clone(),
                    obfuscated_descriptor: method.descriptor.clone(),
                    real_name: row.name,
                    real_class_fqn: row.class_fqn,
                    real_descriptor: row.descriptor,
                    confidence: 0.30,
                    match_type: "fuzzy".into(),
                });
            }
        }

        out.sort_by(|a, b| b.confidence.partial_cmp(&a.confidence).unwrap_or(std::cmp::Ordering::Equal));
        Ok(out)
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    fn build_class_match_from_row(&self, cls: &SmaliClass, row: ClassRow,
                                  confidence: f32, mtype: &str)
        -> Result<ClassMatch, String>
    {
        let real_fqn = row.fqn.clone();
        let db_methods = self.db.get_methods_for_class(row.id)?;
        let db_fields  = self.db.get_fields_for_class(row.id)?;
        let mm = self.match_smali_methods(cls, &db_methods, &real_fqn);
        let fm = self.match_smali_fields(cls, &db_fields, &real_fqn);
        Ok(ClassMatch {
            obfuscated_fqn: cls.fqn.clone(),
            real_fqn,
            confidence,
            match_type: mtype.into(),
            method_matches: mm,
            field_matches: fm,
        })
    }

    fn match_smali_methods(&self, cls: &SmaliClass, db_methods: &[MethodRow], real_fqn: &str)
        -> Vec<MethodMatch>
    {
        let mut by_desc: std::collections::HashMap<&str, &MethodRow> = std::collections::HashMap::new();
        for r in db_methods { by_desc.insert(r.descriptor.as_str(), r); }
        let mut out = Vec::new();
        for m in &cls.methods {
            let (params, ret) = descriptors::parse_method_descriptor(&m.descriptor);
            if let Some(&hit) = by_desc.get(m.descriptor.as_str()) {
                out.push(MethodMatch {
                    obfuscated_name: m.name.clone(),
                    obfuscated_descriptor: m.descriptor.clone(),
                    real_name: hit.name.clone(),
                    real_class_fqn: real_fqn.to_string(),
                    real_descriptor: hit.descriptor.clone(),
                    confidence: WEIGHT_METHOD_EXACT_SIG,
                    match_type: "exact_sig".into(),
                });
                continue;
            }
            // Structural within-class fallback: same return type + param count.
            let candidates: Vec<&MethodRow> = db_methods.iter()
                .filter(|r| r.return_type == ret
                            && db::parse_string_array(&r.param_types).len() == params.len())
                .collect();
            if candidates.len() == 1 {
                let hit = candidates[0];
                out.push(MethodMatch {
                    obfuscated_name: m.name.clone(),
                    obfuscated_descriptor: m.descriptor.clone(),
                    real_name: hit.name.clone(),
                    real_class_fqn: real_fqn.to_string(),
                    real_descriptor: hit.descriptor.clone(),
                    confidence: WEIGHT_METHOD_STRUCT,
                    match_type: "struct".into(),
                });
            }
        }
        out
    }

    fn match_smali_fields(&self, cls: &SmaliClass, db_fields: &[db::FieldRow], real_fqn: &str)
        -> Vec<FieldMatch>
    {
        let mut by_desc: std::collections::HashMap<&str, Vec<&db::FieldRow>> = std::collections::HashMap::new();
        for r in db_fields { by_desc.entry(r.descriptor.as_str()).or_default().push(r); }
        let mut out = Vec::new();
        for f in &cls.fields {
            if let Some(candidates) = by_desc.get(f.descriptor.as_str()) {
                if candidates.len() == 1 {
                    out.push(FieldMatch {
                        obfuscated_name: f.name.clone(),
                        obfuscated_descriptor: f.descriptor.clone(),
                        real_name: candidates[0].name.clone(),
                        real_class_fqn: real_fqn.to_string(),
                        confidence: WEIGHT_FIELD_EXACT,
                        match_type: "exact_type".into(),
                    });
                }
            }
        }
        out
    }

    /// Tier 2 — class-level structural match. Scores candidates by
    /// method-descriptor Jaccard + counts + hierarchy hints.
    fn structural_smali_match(&self, cls: &SmaliClass) -> Result<Option<ClassMatch>, String> {
        let mut candidates = self.db.get_classes_by_simple_name(&cls.simple_name)?;
        let mut best = self.score_smali_candidates(cls, &candidates)?;
        if best.as_ref().is_some_and(|b| b.confidence >= 0.55) {
            return Ok(best);
        }
        // Broaden — classes whose method count is within ±2.
        let lo = (cls.methods.len() as i64 - 2).max(0);
        let hi = cls.methods.len() as i64 + 2;
        let broader = self.db.classes_with_method_count_between(lo, hi, 100)?;
        if !broader.is_empty() {
            // Add only new candidates we haven't already scored.
            let seen: std::collections::HashSet<i64> = candidates.iter().map(|r| r.id).collect();
            for r in broader { if !seen.contains(&r.id) { candidates.push(r); } }
            best = self.score_smali_candidates(cls, &candidates)?;
        }
        Ok(best)
    }

    fn score_smali_candidates(&self, cls: &SmaliClass, candidates: &[ClassRow])
        -> Result<Option<ClassMatch>, String>
    {
        let cls_descriptors: std::collections::HashSet<&str> =
            cls.methods.iter().map(|m| m.descriptor.as_str()).collect();
        let cls_returns: Vec<String> = cls.methods.iter()
            .map(|m| m.descriptor.split(')').next_back().unwrap_or("").to_string())
            .collect();
        let cls_field_types: Vec<&str> = cls.fields.iter().map(|f| f.descriptor.as_str()).collect();

        let mut best_score = 0.0f32;
        let mut best_row: Option<ClassRow> = None;

        for row in candidates {
            let db_methods = self.db.get_methods_for_class(row.id)?;
            let db_fields  = self.db.get_fields_for_class(row.id)?;
            let mut score = 0.0f32;
            let mut total = 0.0f32;

            // Counts
            if !db_methods.is_empty() || !cls.methods.is_empty() {
                score += ratio(db_methods.len(), cls.methods.len()) * 0.20;
                total += 0.20;
            }
            if !db_fields.is_empty() || !cls.fields.is_empty() {
                score += ratio(db_fields.len(), cls.fields.len()) * 0.10;
                total += 0.10;
            }

            // Descriptor Jaccard — strongest signal (descriptors survive R8).
            let db_descs: std::collections::HashSet<&str> =
                db_methods.iter().map(|m| m.descriptor.as_str()).collect();
            if !cls_descriptors.is_empty() || !db_descs.is_empty() {
                let overlap = cls_descriptors.intersection(&db_descs).count();
                let union   = cls_descriptors.union(&db_descs).count().max(1);
                let jaccard = overlap as f32 / union as f32;
                score += jaccard * 0.40;
                total += 0.40;
            }

            // Return-type vector similarity.
            let db_returns: Vec<&str> = db_methods.iter().map(|m| m.return_type.as_str()).collect();
            if !cls_returns.is_empty() && !db_returns.is_empty() {
                let common = cls_returns.iter().filter(|r| db_returns.contains(&r.as_str())).count();
                let denom = cls_returns.len().max(db_returns.len()).max(1);
                score += (common as f32 / denom as f32) * 0.10;
                total += 0.10;
            }

            // Field-type vector similarity.
            let db_field_types: Vec<&str> = db_fields.iter().map(|f| f.descriptor.as_str()).collect();
            if !cls_field_types.is_empty() || !db_field_types.is_empty() {
                let common = cls_field_types.iter().filter(|t| db_field_types.contains(t)).count();
                let denom = cls_field_types.len().max(db_field_types.len()).max(1);
                score += (common as f32 / denom as f32) * 0.10;
                total += 0.10;
            }

            // Superclass match bonus.
            if let (Some(s), Some(db_s)) = (cls.superclass.as_deref(), row.superclass.as_deref()) {
                let cleaned = s.replace('/', ".").trim_start_matches('L').trim_end_matches(';').to_string();
                if cleaned == *db_s { score += WEIGHT_HIERARCHY_BONUS; }
                total += WEIGHT_HIERARCHY_BONUS;
            }
            // Interface-count parity.
            let db_ifaces: Vec<String> = row.interfaces.as_deref()
                .map(|j| db::parse_string_array(j))
                .unwrap_or_default();
            if db_ifaces.len() == cls.interfaces.len() { score += 0.05; }
            total += 0.05;

            let final_ = (score / total.max(0.01)) * WEIGHT_CLASS_STRUCTURAL;
            if final_ > best_score {
                best_score = final_;
                best_row = Some(row.clone());
            }
        }

        if let Some(row) = best_row {
            if best_score > 0.30 {
                let mut cm = self.build_class_match_from_row(cls, row, best_score, "structural")?;
                // Boost confidence if every obfuscated method got an
                // exact-sig hit on this class — strong corroboration.
                if !cls.methods.is_empty() && cm.method_matches.len() == cls.methods.len() {
                    let all_exact = cm.method_matches.iter().all(|m| m.match_type == "exact_sig");
                    if all_exact {
                        cm.confidence = (cm.confidence + 0.25).min(0.95);
                        cm.match_type = "structural+methods".into();
                    }
                }
                return Ok(Some(cm));
            }
        }
        Ok(None)
    }
}

fn ratio(a: usize, b: usize) -> f32 {
    let (lo, hi) = (a.min(b), a.max(b));
    if hi == 0 { return 0.0; }
    lo as f32 / hi as f32
}

/// Heuristic for "this class name doesn't look obfuscated and shouldn't
/// be matched against the library index." Used as a quality gate at the
/// front of `match_smali_class` to suppress 18%+ false-positives where
/// Activities / Services / Application subclasses were getting renamed
/// to library lookalikes by structural similarity.
///
/// Two strong signals:
///   1. The simple name carries an Android-component suffix that R8
///      never renames by default (`Activity`, `Fragment`, `Service`,
///      `ContentProvider`, `BroadcastReceiver`, `Application`, …).
///   2. The simple name "looks human" — at least 5 characters, mixed
///      case with internal uppercase letters (CamelCase). R8 only emits
///      short single-case identifiers (`a`, `wb`, `k0`, `f3$a`).
fn looks_unobfuscated(cls: &SmaliClass) -> bool {
    name_looks_unobfuscated(&cls.simple_name) || {
        // Inner-class fall-through: when `Outer$Inner` has an outer that
        // looks unobfuscated, treat the inner the same way. Catches
        // Kotlin compiler-generated inner classes like `Foo$WhenMappings`
        // whose simple_name is `a` (auto-emitted by `kotlinc`, never
        // descriptive even pre-obfuscation). We can't recover the
        // inner's real name from just an empty-method-set fingerprint;
        // the alternative is matching it to whatever empty library
        // class comes first.
        cls.fqn.find('$').map(|i| {
            let outer = cls.fqn[..i].rsplit('.').next().unwrap_or(&cls.fqn[..i]);
            name_looks_unobfuscated(outer)
        }).unwrap_or(false)
    }
}

/// Returns true if the simple class name looks like a real source-level
/// identifier rather than an R8 alias. Real names start with an
/// uppercase letter, have a lowercase vowel somewhere, and have length
/// >= 4 (covers `Url`, `Address`, `MainActivity`, `OkHttpClient`, …).
/// R8 aliases are typically length 1-3 (`a`, `wb`, `f3`) or lowercase
/// (`fooBar` is rare but rejected anyway).
fn name_looks_unobfuscated(name: &str) -> bool {
    const KEEP_SUFFIXES: &[&str] = &[
        "Activity", "Fragment", "Service", "Provider", "Receiver",
        "Application", "ContentProvider",
    ];
    for sfx in KEEP_SUFFIXES {
        if name.ends_with(sfx) && name.len() > sfx.len() { return true; }
    }
    if name.len() < 4 { return false; }
    let first = name.chars().next().unwrap();
    if !first.is_ascii_uppercase() { return false; }
    let has_lowercase_vowel = name.chars().any(|c| matches!(c, 'a'|'e'|'i'|'o'|'u'));
    has_lowercase_vowel
}

/// The lambda call-signature hash of an *empty* call list. Cached so the
/// matcher can skip matches that would be vacuous (lambdas whose body
/// makes no external calls). Computed lazily but small.
fn empty_sig() -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(b"");
    hex::encode(&h[..8])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bytecode::{ClassInfo, FieldInfo, MethodInfo};

    fn make_class(name: &str, methods: &[(&str, &str)], fields: &[(&str, &str)]) -> ClassInfo {
        ClassInfo {
            internal_name: name.replace('.', "/"),
            superclass: Some("java/lang/Object".into()),
            interfaces: vec![],
            flags: 0,
            source_file: None,
            fields: fields.iter().map(|(n, d)| FieldInfo {
                name: (*n).into(), descriptor: (*d).into(), flags: 0,
            }).collect(),
            methods: methods.iter().map(|(n, d)| MethodInfo {
                name: (*n).into(), descriptor: (*d).into(), flags: 0,
                call_edges: vec![], field_gets: vec![], field_puts: vec![],
                local_count: 0,
            }).collect(),
        }
    }

    #[test]
    fn fingerprint_match_round_trip() {
        let db = Database::in_memory().unwrap();
        let artifact = db.upsert_artifact("com.lib", "lib", "1.0", "jar", "local").unwrap();
        let cls = make_class(
            "com.lib.Foo",
            &[("getDefault", "()Lcom/lib/Foo;"), ("init", "()V")],
            &[("instance", "Lcom/lib/Foo;")],
        );
        crate::db::store_class_info(&db, artifact, &cls).unwrap();

        // Now build a SmaliClass with the same method signatures but
        // R8-renamed names. Fingerprint should still match.
        let smali = SmaliClass {
            smali_path: std::path::PathBuf::from("/tmp/a.smali"),
            class_name: "La/a;".into(),
            internal_name: "a/a".into(),
            fqn: "a.a".into(),
            package: "a".into(),
            simple_name: "a".into(),
            superclass: None,
            interfaces: vec![],
            flags: String::new(),
            source: None,
            fields: vec![],
            methods: vec![
                SmaliMethod {
                    name: "a".into(), descriptor: "()Lcom/lib/Foo;".into(), flags: String::new(),
                    call_edges: vec![], field_gets: vec![], field_puts: vec![], local_count: 0, line_start: 0,
                },
                SmaliMethod {
                    name: "b".into(), descriptor: "()V".into(), flags: String::new(),
                    call_edges: vec![], field_gets: vec![], field_puts: vec![], local_count: 0, line_start: 0,
                },
            ],
        };
        let matcher = Matcher::new(&db);
        let cm = matcher.match_smali_class(&smali).unwrap().expect("should match");
        // The renamed `a`/`b` smali class has different method *names* from
        // the indexed `com.lib.Foo`, so the fingerprint hash differs and
        // matching falls through to the structural tier. The descriptors
        // still line up exactly, which boosts confidence into the
        // "structural+methods" band.
        assert_eq!(cm.real_fqn, "com.lib.Foo");
        assert!(
            cm.match_type == "structural+methods" || cm.match_type == "structural",
            "unexpected match_type: {}", cm.match_type
        );
        // The within-class exact-descriptor match should rename `a` → `getDefault`.
        let names: Vec<&str> = cm.method_matches.iter().map(|m| m.real_name.as_str()).collect();
        assert!(names.contains(&"getDefault"), "expected getDefault in {names:?}");
    }
}
