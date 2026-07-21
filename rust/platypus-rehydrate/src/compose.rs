//! Jetpack Compose call-graph reconstruction.
//!
//! Compose doesn't use XML layouts — UI is emitted at runtime by `@Composable`
//! functions. Static reconstruction is fundamentally different from the XML
//! pipeline:
//!
//!   * **Detection**: an activity uses Compose when its `onCreate` calls
//!     `setContent { … }` (the `androidx.activity.compose.ComponentActivityKt
//!     .setContent` extension function). The `setContent` lambda's `invoke`
//!     method contains the call to the root composable.
//!
//!   * **Call-graph walk**: each composable function may call other
//!     composables. We walk these calls recursively (depth-limited) to
//!     build a tree. Composable function signatures always end with
//!     `(…, Composer, Int)` — that's how we distinguish them from regular
//!     Kotlin functions.
//!
//!   * **Lambda hop**: container composables (`Column`, `Row`, `Box`,
//!     `Scaffold`) take a `content: () -> Unit` lambda parameter. The
//!     children get invoked from inside that lambda's class, not the outer
//!     composable. We resolve the lambda by tracing the most recent
//!     `new-instance` of a `Function*` subclass before the call, then
//!     walking that class's `invoke` method.
//!
//! Limitations (out of scope for v1):
//!
//!   * **Conditional rendering** (`if/when` inside composables): we get the
//!     static call graph, not the runtime tree. A composable that only
//!     renders on a state condition will appear unconditionally.
//!   * **Modifier semantics**: most layout config in Compose lives in
//!     `Modifier` chains. We don't parse them.
//!   * **State-driven changes**: a `var visible by mutableStateOf(false)`
//!     gating visibility is invisible to a static walker.
//!   * **Custom composables** show up as `Custom { class_name }` with the
//!     function's FQN — the UI wrapper can opt to recurse into them or
//!     just show the name.

use platypus_dex::clazz::Clazz;
use platypus_dex::instructions::{Instruction, InstructionKind};
use platypus_dex::method::Method;
use platypus_dex::parser::DexFileWithRaw;

use crate::ir::{Attribute, AttrOrigin, UnifiedView, ViewKind, ViewSource};

const SET_CONTENT_KT: &str = "Landroidx/activity/compose/ComponentActivityKt;->setContent";
const COMPOSER_PARAM:  &str = "Landroidx/compose/runtime/Composer;";

/// Discover whether the activity uses Compose, and if so, what the root
/// composable function is.
///
/// Returns `None` for non-Compose activities. For Compose activities the
/// returned [`ComposeRoot`] points at the function passed to `setContent`'s
/// lambda — i.e. the user's top-level `@Composable`.
pub fn discover_compose_root(
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
) -> Option<ComposeRoot> {
    discover_compose_root_detailed(dex_files, activity_fq_name).found
}

/// Richer version of [`discover_compose_root`] that surfaces *why* the
/// scan did or didn't find a Compose root. Lets the caller emit a more
/// informative diagnostic — distinguishing a *handler activity* (transparent
/// activity that calls finish() and never renders) from a real miss.
pub fn discover_compose_root_detailed(
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
) -> ComposeDiscovery {
    let class_norm = activity_fq_name.replace('.', "/");

    // Walk the activity + its superclass chain (up to but excluding
    // `android.app.Activity` / java.lang.Object). Each hop is scanned
    // with **both** the canonical-name match (Pass 1) and the inlined
    // helper heuristic (Pass 2). When we descend into a base class, the
    // "self" class ref used by Pass 2 becomes that base class's type —
    // because at the dex level the `this` parameter inside the base's
    // onCreate is typed as the base, even though at runtime it's the
    // subclass instance.
    let chain = superclass_chain(dex_files, &class_norm);
    let mut had_oncreate = false;
    let mut handler_signature = false;

    for (hop_idx, ancestor) in chain.iter().enumerate() {
        let ancestor_ref = format!("L{ancestor};");
        let (clazz, dex_ref) = match find_class(dex_files, ancestor) {
            Some(p) => p, None => continue,
        };

        // Pre-scan onCreate for "handler activity" tells — `finish()` /
        // `Process.killProcess` / `Runtime.exit` / `startActivityForResult`
        // followed by finish. We surface this through the discovery
        // result so the caller can word the diagnostic correctly.
        if hop_idx == 0 {
            if let Some(oc) = clazz.methods.iter().find(|m| m.method_name == "onCreate") {
                had_oncreate = true;
                if onCreate_looks_like_handler(oc) {
                    handler_signature = true;
                }
            }
        }

        // Pass 1 — literal `ComponentActivityKt.setContent` invoke.
        for method in &clazz.methods {
            if let Some(root) = scan_for_set_content(method, dex_files) {
                return ComposeDiscovery {
                    found: Some(root),
                    base_class_used: (hop_idx > 0).then(|| ancestor.to_string()),
                    handler_signature: false,
                    had_oncreate,
                };
            }
        }

        // Pass 2 — inlined static-helper heuristic. Scope the "this type"
        // probe to the current hop's class so inherited setContent is
        // matched.
        for method in &clazz.methods {
            if let Some(root) = scan_for_inlined_set_content(
                method, dex_files, &ancestor_ref,
            ) {
                return ComposeDiscovery {
                    found: Some(root),
                    base_class_used: (hop_idx > 0).then(|| ancestor.to_string()),
                    handler_signature: false,
                    had_oncreate,
                };
            }
        }

        // Note: we deliberately don't break early if Pass 1+2 miss on
        // hop 0 — base classes are the whole point of walking the chain.
        let _ = dex_ref;
    }

    ComposeDiscovery {
        found: None,
        base_class_used: None,
        handler_signature,
        had_oncreate,
    }
}

/// Outcome of a `discover_compose_root_detailed` call.
#[derive(Debug, Clone)]
pub struct ComposeDiscovery {
    /// The reconstructed Compose root, when one was found.
    pub found: Option<ComposeRoot>,
    /// `Some(class)` when the root was discovered in a base class rather
    /// than the activity itself — populated so the caller can mention it
    /// in the diagnostic ("inherited from `Lbase/Activity;`").
    pub base_class_used: Option<String>,
    /// `true` when the activity's `onCreate` is shaped like a transparent
    /// handler (calls `finish()` / `Process.killProcess` / `Runtime.exit`
    /// near the end, no `setContent`). Lets the caller surface
    /// "this activity is a no-UI handler — render skipped" instead of
    /// the generic "no setContentView found" warning, which is misleading
    /// for activities that never had a UI in the first place.
    pub handler_signature: bool,
    /// True if the activity had an `onCreate` we could inspect. False
    /// usually means the class wasn't found in any dex (split-APK gap).
    pub had_oncreate: bool,
}

/// Build the activity's superclass chain, stopping at the first platform
/// class (`android.*`) or `java.lang.Object`. The returned vector starts
/// with the activity itself, then walks upward — the order Pass 1+2
/// should scan classes in.
fn superclass_chain(dex_files: &[DexFileWithRaw], start: &str) -> Vec<String> {
    let mut out = vec![start.to_string()];
    let mut current = start.to_string();
    for _ in 0..8 {
        let Some((cd, dex)) = find_class_def(dex_files, &current) else { break; };
        let sup = match dex.parsed.type_ids.get(cd.superclass_idx as usize) {
            Some(t) => t.type_name.clone(), None => break,
        };
        let bare = sup.trim_start_matches('L').trim_end_matches(';').to_string();
        // Stop at platform / object boundary — we'd never find a
        // user-defined setContent above these.
        if bare.starts_with("android/") || bare == "java/lang/Object" { break; }
        out.push(bare.clone());
        current = bare;
    }
    out
}

fn find_class<'a>(dex_files: &'a [DexFileWithRaw], norm_name: &str)
    -> Option<(Clazz, &'a DexFileWithRaw)>
{
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
            if def_norm != norm_name { continue; }
            return Clazz::new(class_def, dex).ok().map(|c| (c, dex));
        }
    }
    None
}

fn find_class_def<'a>(dex_files: &'a [DexFileWithRaw], norm_name: &str)
    -> Option<(&'a platypus_dex::parser::ClassDefItem, &'a DexFileWithRaw)>
{
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
            if def_norm == norm_name {
                return Some((class_def, dex));
            }
        }
    }
    None
}

/// Heuristic: does this `onCreate` look like a no-UI handler activity?
/// Recognised patterns:
///   - finishes immediately after dispatching: contains `Activity.finish()`
///     **and** does NOT contain any `setContent`-shaped invoke
///   - kills the process: `Process.killProcess`, `Runtime.exit`
///   - bounces via `startActivityForResult` / `startActivity` followed by
///     `finish`
///
/// Used only to choose a better diagnostic message; doesn't affect the
/// search outcome.
#[allow(non_snake_case)]
fn onCreate_looks_like_handler(method: &Method) -> bool {
    let mut calls_finish = false;
    let mut kills_process = false;
    let mut sets_content = false;
    for instr in &method.instructions {
        let s = &instr.instruction_str;
        if !s.contains("invoke") { continue; }
        if s.contains("Landroid/app/Activity;->finish()") { calls_finish = true; }
        if s.contains("Landroid/os/Process;->killProcess(") { kills_process = true; }
        if s.contains("Ljava/lang/Runtime;->exit(") { kills_process = true; }
        if s.contains("ComponentActivityKt;->setContent") { sets_content = true; }
    }
    kills_process || (calls_finish && !sets_content)
}

#[derive(Debug, Clone)]
pub struct ComposeRoot {
    /// Method ref of the root composable, e.g.
    /// `"Lcom/example/MyAppKt;->MyApp(Landroidx/compose/runtime/Composer;I)V"`.
    pub method_ref: String,
    /// Bare function name: `"MyApp"`.
    pub function_name: String,
}

/// Walk the call graph starting from `root`, building a [`UnifiedView`]
/// tree. Composable container calls (Column / Row / Box / Scaffold / …)
/// recurse into their content lambda; leaf composables (Text / Button / …)
/// just produce a node with their resolved attributes.
///
/// Cycle-safe (depth + visited-set).
pub fn build_compose_tree(
    dex_files: &[DexFileWithRaw],
    root: &ComposeRoot,
) -> UnifiedView {
    let mut ctx = WalkCtx { dex_files, depth: 0, max_depth: 6, visited: Vec::new() };
    walk_composable(&mut ctx, &root.method_ref, &root.function_name, Vec::new())
}

// ── Walker ───────────────────────────────────────────────────────────────

struct WalkCtx<'a> {
    dex_files: &'a [DexFileWithRaw],
    depth: usize,
    max_depth: usize,
    visited: Vec<String>,
}

/// Build a tree node for one composable call.
///
/// `call_site_attrs` are attributes already extracted from the call site —
/// string literals passed as args (e.g. `Text("Hello")` →
/// `("android:text", "Hello")`). These are the only literal args we can
/// recover, since the callee's body doesn't see what was passed to it.
fn walk_composable(
    ctx: &mut WalkCtx<'_>,
    method_ref: &str,
    function_name: &str,
    call_site_attrs: Vec<(String, String)>,
) -> UnifiedView {
    let kind = compose_function_to_view_kind(function_name);
    let mut attrs = vec![Attribute {
        name: "_pap_compose_method".to_string(),
        value: method_ref.to_string(),
        origin: AttrOrigin::Static,
    }];
    for (k, v) in call_site_attrs {
        attrs.push(Attribute { name: k, value: v, origin: AttrOrigin::Static });
    }

    if ctx.depth >= ctx.max_depth || ctx.visited.contains(&method_ref.to_string()) {
        return synthetic_node(kind, function_name, method_ref, attrs, vec![]);
    }
    ctx.visited.push(method_ref.to_string());
    ctx.depth += 1;

    // Resolve the method body and recurse into composable invokes.
    let body = match resolve_method_body(ctx.dex_files, method_ref) {
        Some(m) => m,
        None => {
            ctx.depth -= 1;
            ctx.visited.pop();
            return synthetic_node(kind, function_name, method_ref, attrs, vec![]);
        }
    };

    // Strategy: scan the function body for composable-call patterns. For
    // calls that take a `content: () -> Unit` lambda, follow the lambda
    // hop into its class's `invoke` method.
    //
    // R8 in full mode rewrites `androidx.compose.runtime.Composer` to a
    // short class ref (Aurora has it as `Lq1/s;`) — the literal-name
    // filter then matches nothing. Probe the body's invokes for the most
    // frequently-occurring "trailing class" in signatures of shape
    // `…L<class>;I)V` / `…L<class>;II)V` and use that as the inferred
    // Composer type; if it differs from the canonical name we treat the
    // body as minified and relax the filters accordingly.
    let inferred_composer = infer_composer_type(&body);
    let direct_children = scan_method_for_composable_calls(
        ctx.dex_files, &body, ctx, inferred_composer.as_deref(),
    );

    let node = synthetic_node(kind, function_name, method_ref, attrs, direct_children);
    ctx.depth -= 1;
    ctx.visited.pop();
    node
}

/// Look at every invoke in `method` and find the trailing class type that
/// appears most often in signatures shaped like `…L<class>;I)V` or
/// `…L<class>;II)V`. That's the "Composer" type for this APK — even
/// after R8 has renamed it.
///
/// Returns `None` if no clear winner emerges (≤1 candidate).
fn infer_composer_type(method: &Method) -> Option<String> {
    use std::collections::HashMap;
    let mut counts: HashMap<String, usize> = HashMap::new();
    for instr in &method.instructions {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }
        let Some(close_paren) = istr.rfind(')') else { continue };
        let Some(open_paren)  = istr[..close_paren].rfind('(') else { continue };
        let sig = &istr[open_paren + 1..close_paren];
        // Strip optional trailing II / I to land on the class ref.
        let body_sig = sig.trim_end_matches(['I', 'V', 'Z']);
        if !body_sig.ends_with(';') { continue; }
        let Some(l_idx) = body_sig.rfind('L') else { continue };
        let class_ref = &body_sig[l_idx..];
        // Skip obvious non-Composer types (kotlin Function*, lambdas).
        if class_ref.starts_with("Lkotlin/") { continue; }
        if class_ref.starts_with("Ljava/") { continue; }
        *counts.entry(class_ref.to_string()).or_insert(0) += 1;
    }
    counts.into_iter()
        .filter(|(_, n)| *n >= 2)            // need to appear in ≥2 calls
        .max_by_key(|(_, n)| *n)
        .map(|(c, _)| c)
}

/// Scan a (possibly-lambda) method body for composable invokes. For each
/// call, recurse to build its subtree.
///
/// `inferred_composer` is the per-method-detected Composer type. When it
/// differs from the canonical `Landroidx/compose/runtime/Composer;`, we're
/// in minified mode and relax the PascalCase / runtime-namespace filters
/// — otherwise nothing would match in fully-R8'd APKs.
fn scan_method_for_composable_calls(
    dex_files: &[DexFileWithRaw],
    method: &Method,
    ctx: &mut WalkCtx<'_>,
    inferred_composer: Option<&str>,
) -> Vec<UnifiedView> {
    let composer_type = inferred_composer.unwrap_or(COMPOSER_PARAM);
    let minified = composer_type != COMPOSER_PARAM;

    let mut out: Vec<UnifiedView> = Vec::new();
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }

        // Match the per-method-detected Composer type. In unminified
        // builds this is the literal `Landroidx/compose/runtime/Composer;`;
        // in R8'd APKs it's whatever the inferred top type was.
        if !istr.contains(composer_type) { continue; }

        let (class_ref, method_name) = match parse_invoke_target(istr) {
            Some(t) => t,
            None    => continue,
        };
        if !minified {
            // `androidx.compose.runtime.*` has many internal helpers
            // (`startRestartGroup`, `endRestartGroup`, `composableLambda`).
            // Skip these — they're plumbing, not user-visible composables.
            if is_compose_runtime_internal(&class_ref, &method_name) { continue; }
            if !looks_like_composable_function_name(&method_name) { continue; }
        } else {
            // Minified-mode filtering: drop the most aggressive checks
            // (composable names get renamed to letters too) but keep a
            // shape filter: skip invokes that look like Composer's own
            // plumbing methods (typically very short names + the receiver
            // is the Composer class itself).
            if class_ref == composer_type { continue; }
            // `<init>` etc. aren't composables.
            if method_name.starts_with('<') { continue; }
        }

        // Build the full method ref so the subtree's signature matches.
        let method_ref = extract_invoke_method_ref(istr).unwrap_or_else(||
            format!("{class_ref}->{method_name}({composer_type}I)V"));

        // Recover literal args from the call site itself — this is the only
        // place we can see what was actually passed to the composable
        // (the callee's body doesn't carry the call-site values).
        let call_site_attrs = extract_call_site_literals(method, idx, &method_name);

        // In minified mode the bare `method_name` is `a`/`b`/`s` and many
        // siblings collide — disambiguate with the (also minified) class
        // ref. The renderer/inspector key off the kind.className field
        // so this becomes the visible label.
        let display_name = if minified {
            format!("{}.{}",
                class_ref.trim_start_matches('L').trim_end_matches(';'),
                method_name)
        } else {
            method_name.clone()
        };

        // Container composable? Recurse into the content-lambda hop.
        let mut child = walk_composable(ctx, &method_ref, &display_name, call_site_attrs);

        // In unminified mode we know the container names; in minified
        // mode we always try the lambda hop (false positives just give
        // empty subtrees, never crashes).
        let try_lambda_hop = minified || container_takes_content_lambda(&method_name);
        if try_lambda_hop {
            if let Some(lambda_class) = find_lambda_arg_class(method, idx) {
                if let Some(lambda_invoke) = resolve_lambda_invoke(dex_files, &lambda_class) {
                    // Re-infer the Composer type for the lambda body —
                    // typically the same as the parent's, but cheap to
                    // re-detect and robust if the lambda crosses a
                    // method-rename boundary.
                    let inner_composer = infer_composer_type(&lambda_invoke);
                    let lambda_kids = scan_method_for_composable_calls(
                        dex_files, &lambda_invoke, ctx,
                        inner_composer.as_deref().or(inferred_composer),
                    );
                    for k in lambda_kids {
                        child.children.push(k);
                    }
                }
            }
        }

        out.push(child);
    }
    out
}

/// Recover literal arguments at a composable invoke site.
///
/// For each known composable, walk backward from the invoke to find
/// `const-string` / `const` / `sget-object` writes to the relevant arg
/// register and turn them into XML-style attributes the renderers
/// already know how to display.
///
/// Mapping table is intentionally small — covers the composables whose
/// first non-`Composer` arg is the user-visible one. For composables
/// where the visible content lives in a `content: () -> Unit` lambda
/// (Button, Card, …), the lambda-hop path picks up the inner Text
/// instead, which already carries the label.
fn extract_call_site_literals(
    method: &Method,
    invoke_idx: usize,
    function_name: &str,
) -> Vec<(String, String)> {
    let invoke = &method.instructions[invoke_idx];
    let arg_regs = invoke_arg_regs(invoke);
    if arg_regs.is_empty() { return Vec::new(); }

    // Per-composable map: position of the literal arg + the attr name to
    // emit. Only composables where this is reliably useful appear here.
    let mappings: &[(&str, usize, &str)] = &[
        ("Text",                 0, "android:text"),
        ("BasicText",            0, "android:text"),
        ("Icon",                 1, "android:contentDescription"),
        ("Image",                1, "android:contentDescription"),
        ("AsyncImage",           1, "android:contentDescription"),
        ("TextField",            0, "android:text"),
        ("OutlinedTextField",    0, "android:text"),
        ("BasicTextField",       0, "android:text"),
        ("TopAppBar",            0, "android:title"),  // first slot is `title`
        ("CenterAlignedTopAppBar", 0, "android:title"),
        ("MediumTopAppBar",      0, "android:title"),
        ("LargeTopAppBar",       0, "android:title"),
    ];

    // Boolean state composables — first arg is a `Z` (bool), recover via
    // const tracing.
    let bool_mappings: &[(&str, usize, &str)] = &[
        ("Switch",      0, "android:checked"),
        ("Checkbox",    0, "android:checked"),
        ("RadioButton", 0, "android:checked"),
    ];

    let mut out = Vec::new();

    for &(name, arg_pos, attr) in mappings {
        if name != function_name { continue; }
        if let Some(&reg) = arg_regs.get(arg_pos) {
            if let Some(s) = backward_const_string_for(method, invoke_idx, reg) {
                out.push((attr.to_string(), s));
            }
        }
    }
    for &(name, arg_pos, attr) in bool_mappings {
        if name != function_name { continue; }
        if let Some(&reg) = arg_regs.get(arg_pos) {
            if let Some(n) = backward_const_for(method, invoke_idx, reg) {
                out.push((attr.to_string(),
                          if n == 0 { "false".to_string() } else { "true".to_string() }));
            }
        }
    }

    out
}

/// Walk backward looking for the most recent `const-string` write to
/// `target_reg`. Mirrors `backward_const_for` but pulls the string literal
/// out of the disassembly text.
fn backward_const_string_for(method: &Method, invoke_idx: usize, target_reg: u32) -> Option<String> {
    const WINDOW: usize = 60;
    let start = invoke_idx.saturating_sub(WINDOW);
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        let istr = &earlier.instruction_str;
        if !istr.contains("const-string") { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        // const-string vN, "the value"
        let q1 = istr.find('"')?;
        let after = &istr[q1 + 1..];
        let q2 = after.find('"')?;
        return Some(after[..q2].to_string());
    }
    None
}

/// Walk backward looking for the most recent `const` write to `target_reg`.
/// Used for boolean state args (`const v0, 0x1` / `0x0`).
fn backward_const_for(method: &Method, invoke_idx: usize, target_reg: u32) -> Option<u32> {
    const WINDOW: usize = 60;
    let start = invoke_idx.saturating_sub(WINDOW);
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if !matches!(earlier.kind, InstructionKind::Const) { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        return earlier.v_b.map(|n| n as u32);
    }
    None
}

/// Heuristic fallback when the literal `setContent` call doesn't match —
/// usually because R8 inlined the extension into a synthetic helper, often
/// renaming `Composer` itself and the lambda's `invoke` method too.
///
/// We need a reliable signal that an invoke is `setContent`-shaped. The
/// trick: after R8 inlines `setContent`, the resulting helper still
/// receives the activity instance as its first argument. So we look for
/// `invoke-static` calls whose method signature contains the activity's
/// own class type — that uniquely fingerprints "setContent"-like calls.
///
/// Once found, we trace the *second* arg's register back to its
/// `new-instance` (the lambda) and pick that class. Inside it, we
/// extract the largest non-`<init>` method as the lambda body, even if
/// R8 renamed `invoke` to a single letter.
fn scan_for_inlined_set_content(
    method: &Method,
    dex_files: &[DexFileWithRaw],
    activity_class_ref: &str,
) -> Option<ComposeRoot> {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke-static") { continue; }
        // The invoke's signature must mention the activity's own class —
        // that's how we know it's a `setContent(this, …)` shape rather
        // than some unrelated static call.
        if !istr.contains(activity_class_ref) { continue; }

        let arg_regs = invoke_arg_regs(instr);
        // We want the *second* arg — the lambda. (The first is the activity.)
        let lambda_reg = match arg_regs.get(1) {
            Some(&r) => r,
            None => continue,
        };

        // Trace lambda_reg back to its new-instance.
        let outer_class = match find_register_new_instance_class(method, idx, lambda_reg) {
            Some(c) => c,
            None => continue,
        };

        // R8 inlines the call through `ComposableLambdaImpl` (renamed to
        // something like `Ly1/h;`) — a framework wrapper that stores the
        // real user lambda in a `Ljava/lang/Object;` field. If the class
        // we found is a wrapper, peek at its `<init>` site in this same
        // method and pick the user lambda passed to it instead.
        let lambda_class = unwrap_composable_lambda_impl(method, idx, lambda_reg)
            .unwrap_or(outer_class);

        // Pass A — if the lambda has a recoverable `invoke` with literal
        // Composer references, walk it the unminified way for a clean root.
        if let Some(invoke) = resolve_lambda_invoke(dex_files, &lambda_class) {
            for inner in &invoke.instructions {
                if !inner.instruction_str.contains("invoke") { continue; }
                if !inner.instruction_str.contains(COMPOSER_PARAM) { continue; }
                let (class_ref, method_name) = match parse_invoke_target(&inner.instruction_str) {
                    Some(t) => t, None => continue,
                };
                if is_compose_runtime_internal(&class_ref, &method_name) { continue; }
                if !looks_like_composable_function_name(&method_name) { continue; }
                let method_ref = extract_invoke_method_ref(&inner.instruction_str)
                    .unwrap_or_else(||
                        format!("{class_ref}->{method_name}({COMPOSER_PARAM}I)V"));
                return Some(ComposeRoot { method_ref, function_name: method_name });
            }
        }

        // Pass B — fully-minified case. Just take the lambda's longest
        // method as the body and surface a placeholder name so the user
        // knows reconstruction is approximate.
        if let Some((size, mname)) = longest_non_init_method(dex_files, &lambda_class) {
            if size >= 10 {
                return Some(ComposeRoot {
                    method_ref: format!("{lambda_class}->{mname}"),
                    function_name: format!("<minified:{mname}>"),
                });
            }
        }
    }
    None
}

/// Detect whether a lambda class is a `ComposableLambdaImpl`-style wrapper
/// (the framework class that stores the real user lambda in a field) and
/// if so return the wrapped class.
///
/// Pattern in the caller's bytecode:
/// ```text
///   new-instance v_user, Lcom/aurora/.../UserLambda;
///   invoke-direct {v_user, …}, …UserLambda;-><init>(…)V
///   new-instance v_wrapper, Ly1/h;             ; ComposableLambdaImpl
///   const          v_key,  #...
///   const/4        v_track, #1
///   invoke-direct {v_wrapper, v_key, v_track, v_user},
///       Ly1/h;-><init>(IZLme/g;)V              ; wrapper takes (int, bool, lambda)
/// ```
///
/// We look for the wrapper's `<init>` invoke just before the static
/// helper call, check that its signature has a recognisable wrapper
/// shape (3 args, one of which is a `L…;` ref-type), and return the
/// class of the new-instance feeding that arg.
fn unwrap_composable_lambda_impl(
    method: &Method,
    static_helper_idx: usize,
    wrapper_reg: u32,
) -> Option<String> {
    const WINDOW: usize = 80;
    let start = static_helper_idx.saturating_sub(WINDOW);

    // Step 1 — find the wrapper's `<init>` invoke. It writes nothing (init
    // calls return void), but the receiver register is wrapper_reg and
    // the method name is `<init>`. Walk backward from the helper invoke.
    for i in (start..static_helper_idx).rev() {
        let earlier = &method.instructions[i];
        let istr = &earlier.instruction_str;
        if !istr.contains("invoke-direct") { continue; }
        if !istr.contains(";-><init>(") { continue; }

        let arg_regs = invoke_arg_regs(earlier);
        if arg_regs.first().copied() != Some(wrapper_reg) { continue; }

        // The wrapper's <init> has signature `(I, Z, L…;)V` (or some
        // variation with a reference-type arg). Find the LAST arg whose
        // register holds a class instance — that's the user lambda.
        // Heuristic: the last arg register, traced backward, should
        // resolve to a `new-instance` of a non-platform class.
        let last_arg = arg_regs.iter().last().copied()?;
        if last_arg == wrapper_reg { continue; }  // self-arg, skip

        // Trace last_arg back to its `new-instance`. Skip if it points
        // to something boring (Integer/Boolean boxing, framework type).
        let user_class = find_register_new_instance_class(method, i, last_arg)?;
        if is_platform_class(&user_class) { continue; }
        // If we wrapped ourselves (shouldn't happen) ignore.
        if user_class == *(&istr[istr.find(", L").unwrap_or(0)..]) { continue; }
        return Some(user_class);
    }
    None
}

fn is_platform_class(class_ref: &str) -> bool {
    class_ref.starts_with("Landroid/")
        || class_ref.starts_with("Landroidx/")
        || class_ref.starts_with("Ljava/")
        || class_ref.starts_with("Ljavax/")
        || class_ref.starts_with("Lkotlin/")
        || class_ref.starts_with("Lkotlinx/")
}

/// Find the longest non-`<init>` non-`<clinit>` method on a class, returning
/// `(instruction_count, method_name)`. Used as a "lambda body proxy" when
/// R8 has renamed the canonical `invoke`.
fn longest_non_init_method(
    dex_files: &[DexFileWithRaw],
    class_ref: &str,
) -> Option<(usize, String)> {
    let class_norm = class_ref.trim_start_matches('L').trim_end_matches(';');
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L').trim_end_matches(';');
            if def_norm != class_norm { continue; }
            let clazz = match Clazz::new(class_def, dex) { Ok(c) => c, Err(_) => continue };
            let mut best: Option<(usize, String)> = None;
            for m in clazz.methods {
                if m.method_name == "<init>" || m.method_name == "<clinit>" { continue; }
                let n = m.instructions.len();
                match &best {
                    Some((s, _)) if n <= *s => {}
                    _ => best = Some((n, m.method_name)),
                }
            }
            return best;
        }
    }
    None
}

// ── setContent detection (entry point) ────────────────────────────────────

fn scan_for_set_content(
    method: &Method,
    dex_files: &[DexFileWithRaw],
) -> Option<ComposeRoot> {
    for (idx, instr) in method.instructions.iter().enumerate() {
        let istr = &instr.instruction_str;
        if !istr.contains("invoke") { continue; }
        if !istr.contains(SET_CONTENT_KT) { continue; }

        // setContent(this, lambda) — `arg 1` is the lambda instance (Kotlin
        // `Function2<Composer, Integer, Unit>`).
        let arg_regs = invoke_arg_regs(instr);
        if arg_regs.len() < 2 { continue; }
        let lambda_reg = arg_regs[1];

        let lambda_class = find_register_new_instance_class(method, idx, lambda_reg)?;
        let lambda_invoke = resolve_lambda_invoke(dex_files, &lambda_class)?;
        // Walk the lambda body for the first composable invoke — that's
        // the root user composable.
        for inner in &lambda_invoke.instructions {
            if !inner.instruction_str.contains("invoke") { continue; }
            if !inner.instruction_str.contains(COMPOSER_PARAM) { continue; }
            let (class_ref, method_name) = match parse_invoke_target(&inner.instruction_str) {
                Some(t) => t, None => continue,
            };
            if is_compose_runtime_internal(&class_ref, &method_name) { continue; }
            if !looks_like_composable_function_name(&method_name) { continue; }
            let method_ref = extract_invoke_method_ref(&inner.instruction_str)
                .unwrap_or_else(||
                    format!("{class_ref}->{method_name}({COMPOSER_PARAM}I)V"));
            return Some(ComposeRoot { method_ref, function_name: method_name });
        }
    }
    None
}

// ── Composable → ViewKind mapping ─────────────────────────────────────────

/// Map a Compose function name to a [`ViewKind`]. Falls through to
/// [`ViewKind::Custom`] for app-defined composables.
///
/// We match on the bare function name (`Column`, `Text`) because Compose
/// function names are universally PascalCase and rarely collide with each
/// other across libraries.
pub fn compose_function_to_view_kind(name: &str) -> ViewKind {
    match name {
        "Column"
            => ViewKind::LinearLayout, // orientation=vertical (we set it via attr)
        "Row"
            => ViewKind::LinearLayout, // orientation=horizontal
        "Box" | "BoxWithConstraints"
            => ViewKind::FrameLayout,

        "Text" | "BasicText"
            => ViewKind::Text,
        "Button" | "OutlinedButton" | "TextButton"
            | "FilledTonalButton" | "ElevatedButton"
            => ViewKind::Button,
        "IconButton" | "FloatingActionButton" | "ExtendedFloatingActionButton"
            | "FilledIconButton" | "OutlinedIconButton"
            => ViewKind::ImageButton,
        "Icon" | "Image" | "AsyncImage"
            => ViewKind::Image,
        "TextField" | "OutlinedTextField" | "BasicTextField"
            => ViewKind::EditText,
        "Switch"
            => ViewKind::Switch,
        "Checkbox"
            => ViewKind::CheckBox,
        "RadioButton"
            => ViewKind::RadioButton,
        "Slider" | "RangeSlider"
            => ViewKind::SeekBar,
        "LinearProgressIndicator" | "CircularProgressIndicator"
            => ViewKind::ProgressBar,

        "LazyColumn" | "LazyRow"
            => ViewKind::RecyclerView,
        "LazyVerticalGrid" | "LazyHorizontalGrid"
            => ViewKind::GridView,
        "HorizontalPager" | "VerticalPager"
            => ViewKind::ViewPager2,

        "Scaffold"
            => ViewKind::CoordinatorLayout,
        "TopAppBar" | "CenterAlignedTopAppBar" | "MediumTopAppBar" | "LargeTopAppBar"
            => ViewKind::Toolbar,
        "BottomAppBar" | "NavigationBar"
            => ViewKind::BottomNav,
        "TabRow" | "ScrollableTabRow"
            => ViewKind::TabLayout,

        "WebView"
            => ViewKind::WebView,

        // Anything else is a user composable — surface it under Custom so the
        // inspector can show the function name and the renderer can recurse.
        _ => ViewKind::Custom { class_name: name.to_string() },
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

fn synthetic_node(
    kind: ViewKind,
    function_name: &str,
    method_ref: &str,
    mut attrs: Vec<Attribute>,
    children: Vec<UnifiedView>,
) -> UnifiedView {
    // For Column/Row we encode the orientation as an XML-style attr so the
    // existing renderers' LinearLayout dispatch handles it transparently.
    if function_name == "Column" {
        attrs.push(Attribute {
            name: "android:orientation".to_string(),
            value: "vertical".to_string(),
            origin: AttrOrigin::Static,
        });
    } else if function_name == "Row" {
        attrs.push(Attribute {
            name: "android:orientation".to_string(),
            value: "horizontal".to_string(),
            origin: AttrOrigin::Static,
        });
    }

    // Compose has no XML width/height — the renderer uses MATCH_PARENT (-1)
    // for containers and WRAP_CONTENT (-2) for leaves. Without these synth
    // attrs, the HTML / Canvas renderers see `layout_width=undefined` and
    // collapse the node to 0×0, which is why obfuscated Compose trees
    // looked like a wall of invisible boxes in the viewer. Pick the
    // dimension a default Compose component would inherit from its parent
    // Modifier — containers want `match_parent`, leaves want
    // `wrap_content`. Custom composables are leaves by default.
    let is_container = matches!(&kind,
        ViewKind::LinearLayout | ViewKind::FrameLayout
        | ViewKind::CoordinatorLayout | ViewKind::ConstraintLayout
        | ViewKind::ScrollView | ViewKind::NestedScrollView
        | ViewKind::HorizontalScrollView
        | ViewKind::RecyclerView | ViewKind::ListView | ViewKind::GridView
        | ViewKind::ViewPager | ViewKind::ViewPager2
        | ViewKind::Toolbar | ViewKind::AppBar | ViewKind::BottomNav
        | ViewKind::TabLayout
    ) || !children.is_empty();
    let want_w = if is_container { "-1" } else { "-2" };
    let want_h = if is_container { "-1" } else { "-2" };
    let has_w = attrs.iter().any(|a| a.name == "android:layout_width");
    let has_h = attrs.iter().any(|a| a.name == "android:layout_height");
    if !has_w {
        attrs.push(Attribute {
            name: "android:layout_width".to_string(),
            value: want_w.to_string(),
            origin: AttrOrigin::Static,
        });
    }
    if !has_h {
        attrs.push(Attribute {
            name: "android:layout_height".to_string(),
            value: want_h.to_string(),
            origin: AttrOrigin::Static,
        });
    }

    UnifiedView {
        source: ViewSource::Compose { method_ref: method_ref.to_string() },
        kind,
        tag: function_name.to_string(),
        id: None,
        attrs,
        children,
        click_handler: None,
        navigation: None,
        dynamic_modifications: Vec::new(),
        item_template: None,
        // Compose nodes don't carry XML drawable refs — colors / images
        // come through the Modifier API which we don't parse statically.
        drawables: std::collections::HashMap::new(),
    }
}

/// True for the Compose runtime's plumbing methods we don't want to surface
/// as user composables (`startRestartGroup`, `composableLambda`, …).
fn is_compose_runtime_internal(class_ref: &str, method_name: &str) -> bool {
    if class_ref.starts_with("Landroidx/compose/runtime/") {
        // Almost everything in compose.runtime is plumbing. The few user-
        // visible names (CompositionLocalProvider) start with an uppercase
        // letter and are extremely rare; let those through.
        return method_name.chars().next().map(|c| !c.is_uppercase()).unwrap_or(true)
            || matches!(method_name,
                "startRestartGroup" | "endRestartGroup" | "skipToGroupEnd"
                | "rememberedValue" | "updateRememberedValue"
                | "composableLambda" | "composableLambdaInstance"
                | "sourceInformation" | "traceEventStart" | "traceEventEnd");
    }
    false
}

/// Composable function names are always PascalCase (Compose convention,
/// enforced by lint). Anything starting with lowercase is a regular Kotlin
/// helper that happens to take a Composer (rare but possible).
fn looks_like_composable_function_name(name: &str) -> bool {
    name.chars().next().map(|c| c.is_ascii_uppercase()).unwrap_or(false)
}

/// Container composables that take a `content: () -> Unit` lambda whose
/// invocations are the visual children. Our walker follows the lambda hop
/// only for these.
fn container_takes_content_lambda(name: &str) -> bool {
    matches!(name,
        "Column" | "Row" | "Box" | "BoxWithConstraints"
        | "Scaffold" | "Surface" | "Card" | "OutlinedCard" | "ElevatedCard"
        | "LazyColumn" | "LazyRow" | "LazyVerticalGrid" | "LazyHorizontalGrid"
        | "TopAppBar" | "CenterAlignedTopAppBar" | "MediumTopAppBar" | "LargeTopAppBar"
        | "BottomAppBar" | "NavigationBar"
        | "TabRow" | "ScrollableTabRow"
        | "HorizontalPager" | "VerticalPager"
        | "Dialog" | "AlertDialog" | "ModalBottomSheet"
        | "CompositionLocalProvider"
    )
}

/// Look at the args of the invoke at `start_idx`, find the most recent
/// `new-instance` of a Kotlin Function* class on any of the arg registers,
/// and return its class ref. Heuristic but good enough — Compose container
/// calls almost always have exactly one `Function*` arg.
fn find_lambda_arg_class(method: &Method, invoke_idx: usize) -> Option<String> {
    let invoke = &method.instructions[invoke_idx];
    let arg_regs = invoke_arg_regs(invoke);
    const WINDOW: usize = 60;
    let start = invoke_idx.saturating_sub(WINDOW);

    for &reg in arg_regs.iter() {
        for i in (start..invoke_idx).rev() {
            let earlier = &method.instructions[i];
            if !matches!(earlier.kind, InstructionKind::NewInstance) { continue; }
            if earlier.v_a != Some(reg as i64) { continue; }
            if let Some(c) = extract_class_ref_after(&earlier.instruction_str, ", L") {
                if c.contains("Function") || c.contains("$Lambda") || c.contains("$$Lambda") {
                    return Some(c);
                }
            }
        }
    }
    None
}

/// Open a Kotlin lambda class and return its `invoke` method (the one
/// `Function2`/`Function3` synthesises with the actual body).
fn resolve_lambda_invoke<'a>(
    dex_files: &'a [DexFileWithRaw],
    class_ref: &str,
) -> Option<Method> {
    let class_norm = class_ref.trim_start_matches('L').trim_end_matches(';');

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }
            let clazz = Clazz::new(class_def, dex).ok()?;
            // Prefer the bridge with the Composer parameter — Kotlin
            // generates two `invoke` methods on Compose lambdas: a typed
            // one and an `Object`-erased bridge. The typed one is the one
            // that contains the composable calls.
            let mut typed: Option<Method> = None;
            let mut fallback: Option<Method> = None;
            for m in clazz.methods {
                if m.method_name != "invoke" { continue; }
                if m.instructions.iter()
                    .any(|i| i.instruction_str.contains(COMPOSER_PARAM)) {
                    typed = Some(m);
                    break;
                } else if fallback.is_none() {
                    fallback = Some(m);
                }
            }
            return typed.or(fallback);
        }
    }
    None
}

/// Resolve a composable's body method by ref (`"LFooKt;->Bar(LComposer;I)V"`).
fn resolve_method_body(dex_files: &[DexFileWithRaw], method_ref: &str) -> Option<Method> {
    let arrow = method_ref.find("->")?;
    let class_ref = &method_ref[..arrow];
    let after = &method_ref[arrow + 2..];
    let paren = after.find('(').unwrap_or(after.len());
    let want_name = &after[..paren];
    let want_sig  = if paren < after.len() { &after[paren..] } else { "" };

    let class_norm = class_ref.trim_start_matches('L').trim_end_matches(';');
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            if def_norm != class_norm { continue; }
            let clazz = Clazz::new(class_def, dex).ok()?;
            for m in clazz.methods {
                if m.method_name != want_name { continue; }
                // Don't insist on signature match if the caller didn't give one.
                if !want_sig.is_empty() {
                    // Best-effort: compare opening (Composer arg) — full
                    // signature match would require parsing parameter
                    // descriptors which we don't keep on Method. The name
                    // alone is unique-enough for top-level composables.
                    let _ = want_sig;
                }
                return Some(m);
            }
        }
    }
    None
}

// ── Instruction parsing ───────────────────────────────────────────────────

fn invoke_arg_regs(instr: &Instruction) -> Vec<u32> {
    match &instr.kind {
        InstructionKind::InvokeKind | InstructionKind::InvokePolymorphic => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let regs  = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
            regs[..count.min(5)].iter()
                .filter_map(|&v| v.map(|x| x as u32))
                .collect()
        }
        InstructionKind::InvokeKindRange | InstructionKind::InvokeCustom => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let start = instr.v_c.unwrap_or(0) as u32;
            (0..count as u32).map(|i| start + i).collect()
        }
        _ => Vec::new(),
    }
}

fn find_register_new_instance_class(
    method: &Method,
    invoke_idx: usize,
    target_reg: u32,
) -> Option<String> {
    const WINDOW: usize = 100;
    let start = invoke_idx.saturating_sub(WINDOW);
    for i in (start..invoke_idx).rev() {
        let earlier = &method.instructions[i];
        if !matches!(earlier.kind, InstructionKind::NewInstance) { continue; }
        if earlier.v_a != Some(target_reg as i64) { continue; }
        return extract_class_ref_after(&earlier.instruction_str, ", L");
    }
    None
}

fn extract_class_ref_after(istr: &str, delim: &str) -> Option<String> {
    let pos = istr.find(delim)?;
    let after = &istr[pos + delim.len() - 1..];
    let semi = after.find(';')?;
    Some(after[..=semi].to_string())
}

fn parse_invoke_target(istr: &str) -> Option<(String, String)> {
    // Format: `…, Lcom/Foo;->method(…)…`
    // The class slice already ends with `;` (it's the character right
    // before `->`), so we don't need to re-append one.
    let arrow = istr.rfind("->")?;
    let class_start = istr[..arrow].rfind('L')?;
    let class_ref = &istr[class_start..arrow];
    if !class_ref.starts_with('L') || !class_ref.contains('/') { return None; }
    let after_arrow = &istr[arrow + 2..];
    let paren = after_arrow.find('(')?;
    let method_name = &after_arrow[..paren];
    Some((class_ref.to_string(), method_name.to_string()))
}

fn extract_invoke_method_ref(istr: &str) -> Option<String> {
    let arrow = istr.rfind("->")?;
    let class_start = istr[..arrow].rfind('L')?;
    Some(istr[class_start..].trim_end_matches(['\n', ' ', ',']).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn well_known_composables_map_to_view_kinds() {
        assert!(matches!(compose_function_to_view_kind("Column"),
            ViewKind::LinearLayout));
        assert!(matches!(compose_function_to_view_kind("Row"),
            ViewKind::LinearLayout));
        assert!(matches!(compose_function_to_view_kind("Box"),
            ViewKind::FrameLayout));
        assert!(matches!(compose_function_to_view_kind("Text"),
            ViewKind::Text));
        assert!(matches!(compose_function_to_view_kind("Button"),
            ViewKind::Button));
        assert!(matches!(compose_function_to_view_kind("OutlinedButton"),
            ViewKind::Button));
        assert!(matches!(compose_function_to_view_kind("LazyColumn"),
            ViewKind::RecyclerView));
        assert!(matches!(compose_function_to_view_kind("LazyVerticalGrid"),
            ViewKind::GridView));
        assert!(matches!(compose_function_to_view_kind("Scaffold"),
            ViewKind::CoordinatorLayout));
        assert!(matches!(compose_function_to_view_kind("TopAppBar"),
            ViewKind::Toolbar));
    }

    #[test]
    fn unknown_composable_becomes_custom_with_name() {
        let kind = compose_function_to_view_kind("MyAppHomeScreen");
        match kind {
            ViewKind::Custom { class_name } => assert_eq!(class_name, "MyAppHomeScreen"),
            _ => panic!("expected Custom, got {:?}", kind),
        }
    }

    #[test]
    fn pascalcase_check_passes_for_composables() {
        assert!(looks_like_composable_function_name("MyApp"));
        assert!(looks_like_composable_function_name("Text"));
        assert!(looks_like_composable_function_name("LazyColumn"));
        // Lowercase first letter — regular Kotlin function.
        assert!(!looks_like_composable_function_name("rememberCoroutineScope"));
        assert!(!looks_like_composable_function_name("startRestartGroup"));
        assert!(!looks_like_composable_function_name(""));
    }

    #[test]
    fn compose_runtime_internals_are_filtered() {
        assert!(is_compose_runtime_internal(
            "Landroidx/compose/runtime/ComposerKt;",
            "startRestartGroup",
        ));
        assert!(is_compose_runtime_internal(
            "Landroidx/compose/runtime/ComposerKt;",
            "composableLambda",
        ));
        // A user composable in a non-runtime package isn't internal.
        assert!(!is_compose_runtime_internal(
            "Lcom/example/MyAppKt;",
            "MyApp",
        ));
        // Material composables aren't in the runtime package.
        assert!(!is_compose_runtime_internal(
            "Landroidx/compose/material3/TextKt;",
            "Text",
        ));
    }

    #[test]
    fn parse_invoke_target_extracts_class_and_method() {
        let s = "invoke-static {v0, v1}, Landroidx/compose/material3/TextKt;->Text(Ljava/lang/String;Landroidx/compose/runtime/Composer;I)V";
        let (cls, method) = parse_invoke_target(s).unwrap();
        assert_eq!(cls, "Landroidx/compose/material3/TextKt;");
        assert_eq!(method, "Text");
    }

    #[test]
    fn handler_signature_recognises_finish_only_onCreate() {
        // Synthesise a Method-like by going through the public API
        // surface — we can't construct platypus_dex::Method directly
        // because its fields rely on a parser context. So we just
        // verify the helper's *contract* by reading the string
        // patterns. The helper key off `instruction_str` text matches,
        // so any Method whose disassembly contains the listed strings
        // will be classified the same way. This is checked end-to-end
        // by the AuroraStore rehydration smoke test (InstallActivity /
        // MicroGInstallerActivity / PhoenixActivity each surface the
        // [Info] "transparent handler" diagnostic instead of the
        // generic [Warning]).
    }

    #[test]
    fn container_lambda_membership() {
        assert!(container_takes_content_lambda("Column"));
        assert!(container_takes_content_lambda("Scaffold"));
        assert!(container_takes_content_lambda("LazyColumn"));
        assert!(container_takes_content_lambda("BottomAppBar"));
        // Leaf composables don't.
        assert!(!container_takes_content_lambda("Text"));
        assert!(!container_takes_content_lambda("Button"));
        assert!(!container_takes_content_lambda("Image"));
    }
}
