//! Top-level orchestration — wire activity discovery + layout expansion +
//! IR construction into a single `rehydrate_activity(apk, name)` entry point.
//!
//! The frontend / Python only calls into this module. Phases 7-13 will add
//! more pipeline steps (handler resolution, navigation, dynamics, Compose)
//! without changing this signature — they fill more fields in the IR.

use std::collections::HashMap;

use platypus_apk::zip::ApkZip;
use platypus_dex::parser::DexFileWithRaw;
use platypus_resources::{Manifest, Resources};

use crate::activity_layout::{
    discover_for_activity, binding_class_for_sentinel, binding_class_to_layout_name, HitSource,
};
use crate::compose::{build_compose_tree, discover_compose_root_detailed};
use crate::dynamics::{discover_dynamics, group_by_view_id};
use crate::handlers::{discover_handlers, HandlerHit, HandlerTarget};
use crate::ir::*;
use crate::layout_expander::{
    expand_layout_file, ExpandedLayout, ExpandedView, ViewOrigin,
};
use crate::navigation::{discover_navigation_in_method, NavInfo};
use crate::recycler::{discover_recyclers, RecyclerHit};

/// Rehydrate every activity declared in the manifest.
///
/// Returns one [`ActivityView`] per activity, with diagnostics noting any
/// reconstruction issues. The activity list is taken from the manifest;
/// activities with no recoverable layout still get an entry (with `root =
/// None` and a warning diagnostic) so the inspector can show them.
pub fn rehydrate_all(
    apk: &ApkZip,
    manifest: &Manifest,
    resources: &Resources,
    dex_files: &[DexFileWithRaw],
) -> Vec<ActivityView> {
    let pkg = manifest.package().unwrap_or("").to_string();
    manifest.activities()
        .into_iter()
        .map(|a| {
            let fq = a.resolve_name(&pkg);
            rehydrate_activity(apk, &fq, resources, dex_files)
        })
        .collect()
}

/// Rehydrate a single activity by FQ class name.
pub fn rehydrate_activity(
    apk: &ApkZip,
    activity_fq_name: &str,
    resources: &Resources,
    dex_files: &[DexFileWithRaw],
) -> ActivityView {
    let mut diagnostics: Vec<Diagnostic> = Vec::new();

    // ── 1. DEX-side: find the layout(s) referenced by setContentView ────
    let hits = discover_for_activity(dex_files, activity_fq_name);
    if hits.hits.is_empty() {
        // No XML-based setContentView — try Compose. `setContent { … }`
        // is the modern way to attach a UI tree without a layout XML.
        // `discover_compose_root_detailed` walks the activity's
        // superclass chain so inherited setContent (a common base-class
        // pattern) is recovered.
        let disc = discover_compose_root_detailed(dex_files, activity_fq_name);
        if let Some(root) = disc.found {
            let provenance = match disc.base_class_used {
                Some(base) => format!(
                    "via base class {base} (subclass {activity_fq_name} inherits onCreate)"
                ),
                None => "directly".to_string(),
            };
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Info,
                message: format!(
                    "Activity uses Jetpack Compose. Reconstructed {provenance} \
                     via static call-graph walk from {} (depth-limited, \
                     conditional branches collapsed).", root.method_ref,
                ),
                location: Some(activity_fq_name.to_string()),
            });
            let compose_root = build_compose_tree(dex_files, &root);
            return ActivityView {
                activity_name: activity_fq_name.to_string(),
                layout_id: None,
                layout_path: None,
                root: Some(compose_root),
                diagnostics,
                outgoing_navigations: collect_outgoing_navigations(dex_files, activity_fq_name),
            };
        }

        // No compose root either. Distinguish "transparent handler
        // activity by design" from "we couldn't find the UI" — the
        // former is correct, the latter is a real gap.
        let (severity, message) = if disc.handler_signature {
            (DiagnosticSeverity::Info, format!(
                "Activity {activity_fq_name} is a transparent handler — its \
                 onCreate dispatches and finishes without rendering a UI \
                 (no setContentView, no setContent, calls finish()/exit \
                 directly). Nothing to render."
            ))
        } else if !disc.had_oncreate {
            (DiagnosticSeverity::Warning, format!(
                "No onCreate found in {activity_fq_name}. The activity class \
                 may be in a missing dex (split-APK) or be obfuscated past \
                 the resolver's recognition."
            ))
        } else {
            (DiagnosticSeverity::Warning, format!(
                "No setContentView/inflate or Compose setContent call found \
                 in {activity_fq_name} (nor in any base class up to \
                 android.app.Activity). May use a custom theme window, \
                 dynamically-loaded UI, or a fragment-hosted Compose root \
                 (NavHost-style) which the static walker doesn't follow yet."
            ))
        };
        diagnostics.push(Diagnostic {
            severity, message, location: Some(activity_fq_name.to_string()),
        });
        return ActivityView {
            activity_name: activity_fq_name.to_string(),
            layout_id: None,
            layout_path: None,
            root: None,
            diagnostics,
            outgoing_navigations: collect_outgoing_navigations(dex_files, activity_fq_name),
        };
    }

    // Multiple hits = log them as info; pick the first DirectInt match,
    // falling back to InflaterInflate, then ViewBinding.
    if hits.hits.len() > 1 {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Info,
            message: format!(
                "{} setContentView/inflate sites found in {activity_fq_name}; \
                 picking the highest-priority match. Other hits in: {}",
                hits.hits.len(),
                hits.hits.iter()
                    .map(|h| format!("{}@{}", h.method_name, h.codepoint))
                    .collect::<Vec<_>>().join(", "),
            ),
            location: Some(activity_fq_name.to_string()),
        });
    }
    let chosen = pick_best_hit(&hits.hits, dex_files, activity_fq_name);

    // ── 2. Resolve layout id → file path (handling binding sentinels) ────
    let layout_path = match chosen.source {
        HitSource::ViewBinding => {
            // Look up the binding class from candidate refs in the activity,
            // then derive the layout name and look up its path.
            let binding_candidates = collect_binding_class_refs(
                dex_files, activity_fq_name,
            );
            let bc = binding_class_for_sentinel(chosen.layout_id, &binding_candidates);
            match bc.and_then(|c| binding_class_to_layout_name(&c)) {
                Some(layout_name) => {
                    match resources.layout_path(&layout_name) {
                        Some(path) => Some(path),
                        None => {
                            diagnostics.push(Diagnostic {
                                severity: DiagnosticSeverity::Warning,
                                message: format!(
                                    "ViewBinding hint suggested layout '{layout_name}' \
                                     but no matching res/layout entry was found."
                                ),
                                location: Some(activity_fq_name.to_string()),
                            });
                            None
                        }
                    }
                }
                None => {
                    diagnostics.push(Diagnostic {
                        severity: DiagnosticSeverity::Warning,
                        message: format!(
                            "ViewBinding-style setContentView detected but the \
                             binding class couldn't be matched."
                        ),
                        location: Some(activity_fq_name.to_string()),
                    });
                    None
                }
            }
        }
        _ => match resources.resolve(chosen.layout_id) {
            Some(path) => Some(path),
            None => {
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Error,
                    message: format!(
                        "Layout id 0x{:08x} couldn't be resolved against resources.arsc.",
                        chosen.layout_id
                    ),
                    location: Some(activity_fq_name.to_string()),
                });
                None
            }
        },
    };

    let path = match layout_path.clone() {
        Some(p) => p,
        None => return ActivityView {
            activity_name: activity_fq_name.to_string(),
            layout_id: Some(chosen.layout_id),
            layout_path: None,
            root: None,
            diagnostics,
            outgoing_navigations: collect_outgoing_navigations(dex_files, activity_fq_name),
        },
    };

    // ── 3. Expand the layout file (recursive include/merge/ViewStub) ────
    let expanded = match expand_layout_file(apk, &path, resources) {
        Ok(e) => e,
        Err(e) => {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Error,
                message: format!("Layout expansion failed: {e}"),
                location: Some(path.clone()),
            });
            return ActivityView {
                activity_name: activity_fq_name.to_string(),
                layout_id: Some(chosen.layout_id),
                layout_path: Some(path),
                root: None,
                diagnostics,
                outgoing_navigations: collect_outgoing_navigations(dex_files, activity_fq_name),
            };
        }
    };

    // ── 4. Discover code-side handlers for this activity ────────────────
    // We do this once per activity; the IR builder then attaches matching
    // hits onto the corresponding view nodes by id. Hits without a
    // recoverable view id are surfaced as activity-level diagnostics so
    // they're still discoverable.
    let handler_hits = discover_handlers(dex_files, activity_fq_name);
    let handlers_by_id: HashMap<u32, &HandlerHit> = handler_hits.iter()
        .filter_map(|h| h.view_id.map(|id| (id, h)))
        .collect();

    let unmatched_count = handler_hits.iter().filter(|h| h.view_id.is_none()).count();
    if unmatched_count > 0 {
        diagnostics.push(Diagnostic {
            severity: DiagnosticSeverity::Info,
            message: format!(
                "{unmatched_count} click handler(s) couldn't be tied to a specific \
                 view (likely view-binding fields, lambda captures, or fragment-\
                 attached listeners). They're still in the DEX bytecode."
            ),
            location: Some(activity_fq_name.to_string()),
        });
    }

    // ── 5. Discover post-inflation modifications (setText/setVisibility/…) ──
    let dyn_hits = discover_dynamics(dex_files, activity_fq_name);
    let dynamics_by_id = group_by_view_id(dyn_hits);

    // ── 6. Discover RecyclerView/ListView/GridView item templates ───────
    // For each list-host view we recover the adapter's inflated item layout
    // and pre-expand it so the renderer can repeat it. Indexed by host view id.
    let recycler_hits = discover_recyclers(dex_files, activity_fq_name);
    let item_templates_by_id = expand_item_templates(
        apk, resources, &recycler_hits, &mut diagnostics,
    );

    // ── 7. Convert ExpandedView → UnifiedView IR ─────────────────────────
    let root = build_unified(
        &expanded.root,
        &expanded.source_path,
        apk,
        resources,
        &handlers_by_id,
        &dynamics_by_id,
        &item_templates_by_id,
        dex_files,
        activity_fq_name,
        &mut diagnostics,
    );

    ActivityView {
        activity_name: activity_fq_name.to_string(),
        layout_id: Some(chosen.layout_id),
        layout_path: Some(path),
        root: Some(root),
        diagnostics,
        outgoing_navigations: collect_outgoing_navigations(dex_files, activity_fq_name),
    }
}

/// Aggregate every navigation transition reachable from `activity_fq_name`.
///
/// Scans the activity class itself plus its inner classes (anonymous
/// listeners, nested fragments) for `startActivity` / fragment swap /
/// `NavController.navigate` patterns. Deduped by `(kind, target)`.
///
/// Captures both click-driven navigations AND ones triggered from lifecycle
/// methods (`onCreate` calling `startActivity` directly) — useful for the
/// graph view.
fn collect_outgoing_navigations(
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
) -> Vec<NavTarget> {
    use std::collections::HashSet;
    let class_norm = activity_fq_name.replace('.', "/");
    let mut seen: HashSet<(NavKindKey, String)> = HashSet::new();
    let mut out: Vec<NavTarget> = Vec::new();

    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name
                .trim_start_matches('L')
                .trim_end_matches(';');
            // Activity itself OR any inner class (`Outer$Inner`).
            let is_activity_or_inner = def_norm == class_norm
                || def_norm.starts_with(&format!("{class_norm}$"));
            if !is_activity_or_inner { continue; }

            let class_ref = format!("L{def_norm};");
            for hit in crate::navigation::discover_navigation_in_class(dex_files, &class_ref) {
                let key = (NavKindKey::from(hit.kind), hit.target.clone());
                if seen.insert(key) {
                    out.push(hit.into_target());
                }
            }
        }
    }
    out
}

/// Hashable copy of [`NavKind`] (which doesn't derive Hash/Eq because the
/// IR types stay minimal). Used only to dedupe inside this module.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
enum NavKindKey { StartActivity, StartActivityForResult, ReplaceFragment, NavController }
impl From<NavKind> for NavKindKey {
    fn from(k: NavKind) -> Self {
        match k {
            NavKind::StartActivity          => NavKindKey::StartActivity,
            NavKind::StartActivityForResult => NavKindKey::StartActivityForResult,
            NavKind::ReplaceFragment        => NavKindKey::ReplaceFragment,
            NavKind::NavController          => NavKindKey::NavController,
        }
    }
}

// ── Conversion: expanded view tree → IR ─────────────────────────────────────

fn build_unified(
    ev: &ExpandedView,
    primary_path: &str,
    apk: &ApkZip,
    resources: &Resources,
    handlers_by_id: &HashMap<u32, &HandlerHit>,
    dynamics_by_id: &HashMap<u32, Vec<DynMod>>,
    item_templates_by_id: &HashMap<u32, UnifiedView>,
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
    diagnostics: &mut Vec<Diagnostic>,
) -> UnifiedView {
    let mut attrs: Vec<Attribute> = ev.view.attrs.iter()
        .map(|(k, v)| Attribute {
            name: k.clone(),
            value: v.clone(),
            origin: AttrOrigin::Static,
        })
        .collect();

    // Classify the view kind. For `<fragment>` we also fill in the class name.
    let mut kind = ViewKind::from_tag(&ev.view.tag);
    if let ViewKind::Fragment { class_name } = &mut kind {
        if let Some(name) = ev.view.attr("android:name") {
            *class_name = name.to_string();
        }
        if class_name.is_empty() {
            diagnostics.push(Diagnostic {
                severity: DiagnosticSeverity::Warning,
                message: "<fragment> with no android:name — can't recover its view".into(),
                location: ev.view.id(),
            });
        }
    }

    // Map our internal ViewOrigin onto the IR's ViewSource.
    let source = match &ev.origin {
        ViewOrigin::Direct { layout_path } => ViewSource::Xml {
            layout_path: layout_path.clone(),
        },
        ViewOrigin::Included { from, included } => ViewSource::Included {
            from_layout_path: from.clone(),
            included_layout_path: included.clone(),
        },
        ViewOrigin::Merged { from } => ViewSource::Merged {
            from_layout_path: from.clone(),
        },
        ViewOrigin::StubInflated { stub_in, target } => ViewSource::StubInflated {
            stub_layout_path: stub_in.clone(),
            target_layout_path: target.clone(),
        },
    };
    let _ = primary_path;  // reserved for future "trace back to top file" use

    let view_id = ev.view.id();

    // ── Click-handler resolution ────────────────────────────────────────
    // Order of preference (matches Android's runtime "last setter wins"):
    //   1. DEX setOnClickListener attached to this view's id
    //   2. XML android:onClick="methodName"
    //
    // The lookup also returns the DEX HandlerHit (when applicable) so we
    // can use it to drive navigation discovery — `navigation` only fires
    // when we know which method to scan.
    let (click_handler, source_hit) = resolve_click_handler(
        &attrs, view_id.as_deref(), resources, handlers_by_id,
    );

    // ── Navigation resolution ───────────────────────────────────────────
    // Run navigation discovery on the click target's method body. For DEX
    // handlers we know the (class, method); for XML `android:onClick="foo"`
    // the method lives on the activity itself.
    let navigation = click_handler.as_ref()
        .and_then(|h| navigation_for_handler(h, source_hit, dex_files, activity_fq_name));

    // ── Dynamic modifications ───────────────────────────────────────────
    // Look up modifications by view id (already grouped by the caller) and
    // promote literal-valued ones into matching attributes too — so the
    // renderer reflects `setText("Hello")` even though it never appeared in
    // the layout XML.
    let dynamic_modifications = view_id.as_deref()
        .and_then(|id_str| resources.id_by_name("id", id_str))
        .and_then(|nid| dynamics_by_id.get(&nid).cloned())
        .unwrap_or_default();

    promote_literals_to_attrs(&mut attrs, &dynamic_modifications);

    // Item template lookup — only meaningful for list-host views, but we
    // do the cheap lookup unconditionally and let the type system make
    // sense of it. Renderers branch on view kind anyway.
    let item_template = view_id.as_deref()
        .and_then(|id_str| resources.id_by_name("id", id_str))
        .and_then(|nid| item_templates_by_id.get(&nid).cloned())
        .map(Box::new);

    let children = ev.children.iter()
        .map(|c| build_unified(
            c, primary_path, apk, resources, handlers_by_id, dynamics_by_id,
            item_templates_by_id, dex_files, activity_fq_name, diagnostics,
        ))
        .collect();

    // Drawables — pre-resolve every attribute that references one. This
    // is the place to do it (rather than on-demand at render time)
    // because (a) we already have `apk` + `resources` here, and (b) the
    // result lives in the IR so frontend code is host-agnostic.
    let drawables = resolve_drawables_for(apk, resources, &attrs);

    UnifiedView {
        source,
        kind,
        tag: ev.view.tag.clone(),
        id: view_id,
        attrs,
        children,
        click_handler,
        navigation,
        dynamic_modifications,
        item_template,
        drawables,
    }
}

/// Names of attributes whose value should be resolved through
/// `Resources::resolve_drawable_value`. Anything not in this list is
/// treated as a literal string.
const DRAWABLE_ATTR_NAMES: &[&str] = &[
    "android:background",
    "android:foreground",
    "android:src",
    "android:srcCompat",
    "app:srcCompat",
    "android:drawable",
    "android:icon",
    "android:button",      // CompoundButton's drawable
    "android:thumb",       // SeekBar / Switch
    "android:progressDrawable",
    "android:indeterminateDrawable",
    "android:divider",
    "android:listSelector",
];

/// For each attribute that points at a drawable resource, resolve it via
/// `Resources::resolve_drawable_value` and serialise the result into a
/// JSON value the renderer can branch on. Skips attrs with empty values
/// and ones not in [`DRAWABLE_ATTR_NAMES`].
fn resolve_drawables_for(
    apk: &ApkZip,
    resources: &Resources,
    attrs: &[Attribute],
) -> std::collections::HashMap<String, serde_json::Value> {
    let mut out = std::collections::HashMap::new();
    for a in attrs {
        if !DRAWABLE_ATTR_NAMES.contains(&a.name.as_str()) { continue; }
        if a.value.is_empty() { continue; }
        let drawable = resources.resolve_drawable_value(apk, &a.value);
        if let Ok(v) = serde_json::to_value(&drawable) {
            out.insert(a.name.clone(), v);
        }
    }
    out
}

/// Expand each discovered recycler hit's item layout into a UnifiedView and
/// index by host view id.
///
/// Item-template trees are built with a stripped-down `build_unified` call
/// — they get static attrs only; we don't recursively resolve handlers,
/// navigation, dynamics or *nested* item templates. This is intentional:
/// the template represents one row, and its bytecode-resolved behaviour
/// (handlers etc.) lives in the adapter's `onBindViewHolder`, not the
/// activity. Expanding all of that would be a 2× bytecode scan per row
/// for marginal preview value.
fn expand_item_templates(
    apk: &ApkZip,
    resources: &Resources,
    hits: &[RecyclerHit],
    diagnostics: &mut Vec<Diagnostic>,
) -> HashMap<u32, UnifiedView> {
    let mut out = HashMap::new();

    for hit in hits {
        // Resolve item layout id → file path. Some adapters reference
        // framework layouts (`android.R.layout.simple_list_item_1`) which
        // aren't in the app's resources.arsc — skip those silently.
        let layout_path = match resources.resolve(hit.item_layout_id) {
            Some(p) => p,
            None => {
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Info,
                    message: format!(
                        "RecyclerView item layout 0x{:08x} (adapter {}) couldn't \
                         be resolved against this app's resources — likely a \
                         framework layout. Falling back to the generic stub.",
                        hit.item_layout_id, hit.adapter_class,
                    ),
                    location: Some(hit.adapter_class.clone()),
                });
                continue;
            }
        };

        let expanded = match expand_layout_file(apk, &layout_path, resources) {
            Ok(e) => e,
            Err(e) => {
                diagnostics.push(Diagnostic {
                    severity: DiagnosticSeverity::Warning,
                    message: format!(
                        "Failed to expand item layout {layout_path} for adapter {}: {e}",
                        hit.adapter_class,
                    ),
                    location: Some(layout_path.clone()),
                });
                continue;
            }
        };

        // Group this hit's bindings by view id so the template walker
        // can attach each binding onto its matching view as a DynMod.
        let mut bindings_by_id: HashMap<u32, Vec<DynMod>> = HashMap::new();
        for b in &hit.bindings {
            bindings_by_id.entry(b.view_id).or_default().push(DynMod {
                setter: b.setter.clone(),
                value: b.value.clone(),
                from_method: format!("{}.{}",
                    hit.adapter_class.trim_start_matches('L').trim_end_matches(';')
                        .replace('/', "."),
                    b.from_method,
                ),
                literal: b.literal,
            });
        }

        out.insert(
            hit.view_id,
            build_static_only(apk, resources, &expanded.root, &bindings_by_id),
        );
    }
    out
}

/// Strip-down [`build_unified`] for item templates — produces a static
/// view tree with two pieces of bytecode-derived enrichment:
///   - **Drawables** resolved per attribute (backgrounds + icons render).
///   - **Per-row bindings** (`bindings_by_view_id`) attached to matching
///     views as `dynamic_modifications`, with literals promoted into
///     attrs so `holder.title.setText("Hello")` shows "Hello" in the row.
fn build_static_only(
    apk: &ApkZip,
    resources: &Resources,
    ev: &ExpandedView,
    bindings_by_view_id: &HashMap<u32, Vec<DynMod>>,
) -> UnifiedView {
    let mut attrs: Vec<Attribute> = ev.view.attrs.iter()
        .map(|(k, v)| Attribute {
            name: k.clone(),
            value: v.clone(),
            origin: AttrOrigin::Static,
        })
        .collect();

    let mut kind = ViewKind::from_tag(&ev.view.tag);
    if let ViewKind::Fragment { class_name } = &mut kind {
        if let Some(name) = ev.view.attr("android:name") {
            *class_name = name.to_string();
        }
    }

    let source = match &ev.origin {
        ViewOrigin::Direct { layout_path } => ViewSource::Xml {
            layout_path: layout_path.clone(),
        },
        ViewOrigin::Included { from, included } => ViewSource::Included {
            from_layout_path: from.clone(),
            included_layout_path: included.clone(),
        },
        ViewOrigin::Merged { from } => ViewSource::Merged {
            from_layout_path: from.clone(),
        },
        ViewOrigin::StubInflated { stub_in, target } => ViewSource::StubInflated {
            stub_layout_path: stub_in.clone(),
            target_layout_path: target.clone(),
        },
    };

    // Look up bindings by view id (resolved against this app's resources)
    // and attach them. Literal-valued bindings get promoted into XML-style
    // attrs the same way `dynamic_modifications` does for the activity.
    let view_id = ev.view.id();
    let dynamic_modifications: Vec<DynMod> = view_id.as_deref()
        .and_then(|id_str| resources.id_by_name("id", id_str))
        .and_then(|nid| bindings_by_view_id.get(&nid).cloned())
        .unwrap_or_default();
    promote_literals_to_attrs(&mut attrs, &dynamic_modifications);

    let drawables = resolve_drawables_for(apk, resources, &attrs);

    UnifiedView {
        source,
        kind,
        tag: ev.view.tag.clone(),
        id: view_id,
        attrs,
        children: ev.children.iter()
            .map(|c| build_static_only(apk, resources, c, bindings_by_view_id))
            .collect(),
        click_handler: None,
        navigation: None,
        dynamic_modifications,
        item_template: None,
        drawables,
    }
}

/// Promote literal-valued `setText` / `setVisibility` / etc. modifications
/// into matching attributes so renderers (R1 HTML especially) reflect the
/// runtime state, not just the static layout.
///
/// Mapping is conservative — only setters with a clean XML analogue and a
/// confidently-recovered literal value get promoted. Non-literal ones stay
/// in `dynamic_modifications` for the inspector to surface.
fn promote_literals_to_attrs(attrs: &mut Vec<Attribute>, mods: &[DynMod]) {
    for m in mods {
        if !m.literal { continue; }

        let (attr_name, value) = match m.setter.as_str() {
            "setText"               => ("android:text", strip_quotes(&m.value)),
            "setHint"               => ("android:hint", strip_quotes(&m.value)),
            "setContentDescription" => ("android:contentDescription", strip_quotes(&m.value)),
            "setVisibility"         => ("android:visibility", m.value.to_lowercase()),
            "setEnabled"            => ("android:enabled", m.value.clone()),
            "setSelected"           => ("android:selected", m.value.clone()),
            "setActivated"          => ("android:activated", m.value.clone()),
            "setChecked"            => ("android:checked", m.value.clone()),
            "setBackgroundColor"    => ("android:background", m.value.clone()),
            "setTextColor"          => ("android:textColor", m.value.clone()),
            "setProgress"           => ("android:progress", m.value.clone()),
            "setMax"                => ("android:max", m.value.clone()),
            "setAlpha"              => ("android:alpha", m.value.clone()),
            _                       => continue,
        };

        // Override an existing static attr (the runtime call wins) or
        // append a new one. Either way the origin is Dynamic so the
        // inspector's badge surfaces it.
        let dyn_attr = Attribute {
            name: attr_name.to_string(),
            value,
            origin: AttrOrigin::Dynamic { from_method: m.from_method.clone() },
        };
        if let Some(slot) = attrs.iter_mut().find(|a| a.name == attr_name) {
            *slot = dyn_attr;
        } else {
            attrs.push(dyn_attr);
        }
    }
}

fn strip_quotes(s: &str) -> String {
    let t = s.trim();
    if t.starts_with('"') && t.ends_with('"') && t.len() >= 2 {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Pick the most authoritative click handler for one view.
///
/// Preference: DEX-discovered `setOnClickListener` (matched by view id) over
/// XML `android:onClick` (a runtime listener overrides the XML attribute on
/// real devices, so we mirror that here).
///
/// Returns the IR `Handler` and (when the source was a DEX hit) the
/// underlying [`HandlerHit`] so the caller can drive navigation discovery
/// against the listener's actual class+method.
fn resolve_click_handler<'a>(
    attrs: &[Attribute],
    view_id_str: Option<&str>,
    resources: &Resources,
    handlers_by_id: &HashMap<u32, &'a HandlerHit>,
) -> (Option<Handler>, Option<&'a HandlerHit>) {
    // 1. DEX hit?
    if let Some(id_str) = view_id_str {
        if let Some(numeric_id) = resources.id_by_name("id", id_str) {
            if let Some(&hit) = handlers_by_id.get(&numeric_id) {
                return (Some(Handler {
                    kind: hit.kind,
                    target: hit.target.display(),
                }), Some(hit));
            }
        }
    }
    // 2. XML android:onClick fallback.
    for a in attrs {
        if a.name == "android:onClick" && !a.value.is_empty() {
            return (Some(Handler {
                kind: HandlerKind::XmlOnClick,
                target: a.value.clone(),
            }), None);
        }
    }
    (None, None)
}

/// Resolve which (class, method) the given handler runs, then scan that
/// method's body for navigation idioms. Returns the most-relevant
/// [`NavTarget`], preferring `startActivity` over `replaceFragment` over
/// `navController` (most concrete first).
fn navigation_for_handler(
    handler: &Handler,
    source_hit: Option<&HandlerHit>,
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
) -> Option<NavTarget> {
    let (class_ref, method_name) = match (handler.kind, source_hit) {
        // XML source: the named method lives on the activity class.
        (HandlerKind::XmlOnClick, _) => (
            format!("L{};", activity_fq_name.replace('.', "/")),
            handler.target.clone(),
        ),
        // DEX-source: pull class+method from the HandlerTarget — that's the
        // listener's actual location, not the activity's. Returns `None`
        // for Lambda/Unknown handlers (we can't pinpoint a method to scan).
        (HandlerKind::CodeOnClickListener, Some(hit))
        | (HandlerKind::CodeOnLongClickListener, Some(hit)) => {
            handler_target_class_and_method(&hit.target)?
        }
        // No source hit and not XML — nothing to scan.
        (HandlerKind::CodeOnClickListener, None)
        | (HandlerKind::CodeOnLongClickListener, None) => return None,
    };

    let hits = discover_navigation_in_method(dex_files, &class_ref, &method_name);
    pick_best_nav(hits).map(NavInfo::into_target)
}

/// Pull (class_ref, method_name) out of a [`HandlerTarget`] for DEX-side
/// listeners. Returns `None` for `Lambda` / `Unknown` (where we don't have
/// a clean class+method to scan).
fn handler_target_class_and_method(t: &HandlerTarget) -> Option<(String, String)> {
    match t {
        HandlerTarget::InnerClass { class_ref, method }
        | HandlerTarget::SelfReference { class_ref, method } => {
            // method is `"onClick(Landroid/view/View;)V"` — strip the signature.
            let bare = method.split('(').next().unwrap_or(method);
            if class_ref.is_empty() || bare.is_empty() { return None; }
            Some((class_ref.clone(), bare.to_string()))
        }
        HandlerTarget::Lambda { .. } | HandlerTarget::Unknown { .. } => None,
    }
}

/// Of all discovered nav patterns inside a method, pick the most useful one.
/// Preference: explicit `startActivity` over `startActivityForResult` over
/// `replaceFragment` over `NavController.navigate` — the explicit target
/// is more actionable for a graph view than a nav-graph id.
fn pick_best_nav(hits: Vec<NavInfo>) -> Option<NavInfo> {
    fn rank(k: NavKind) -> i32 {
        match k {
            NavKind::StartActivity          => 0,
            NavKind::StartActivityForResult => 1,
            NavKind::ReplaceFragment        => 2,
            NavKind::NavController          => 3,
        }
    }
    hits.into_iter().min_by_key(|h| rank(h.kind))
}

// ── Internal helpers ───────────────────────────────────────────────────────

/// Pick the best-quality hit when an activity has multiple. Prefer
/// `DirectInt` (most reliable) > `InflaterInflate` > `ViewBinding`.
/// Within the same kind, prefer hits in `onCreate` over other lifecycle
/// methods.
fn pick_best_hit<'a>(
    hits: &'a [crate::activity_layout::LayoutHit],
    _dex_files: &[DexFileWithRaw],
    _activity_fq_name: &str,
) -> &'a crate::activity_layout::LayoutHit {
    fn rank(h: &crate::activity_layout::LayoutHit) -> i32 {
        let kind_rank = match h.source {
            HitSource::DirectInt => 0,
            HitSource::InflaterInflate => 1,
            HitSource::ViewBinding => 2,
        };
        let method_rank = match h.method_name.as_str() {
            "onCreate" => 0,
            "onCreateView" => 1,
            "onViewCreated" => 2,
            _ => 3,
        };
        kind_rank * 10 + method_rank
    }
    hits.iter().min_by_key(|h| rank(h)).expect("non-empty hits slice")
}

/// Collect class refs that look like view-binding classes from the
/// activity's bytecode. Used to resolve binding-sentinel layout ids back
/// to a real layout name.
fn collect_binding_class_refs(
    dex_files: &[DexFileWithRaw],
    activity_fq_name: &str,
) -> Vec<String> {
    use platypus_dex::clazz::Clazz;

    let class_norm = activity_fq_name.replace('.', "/");
    let mut out = Vec::new();
    for dex in dex_files {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
            if def_norm != class_norm { continue; }
            let clazz = match Clazz::new(class_def, dex) { Ok(c) => c, Err(_) => continue };
            for method in &clazz.methods {
                for instr in &method.instructions {
                    let istr = &instr.instruction_str;
                    if !istr.contains("Binding;") { continue; }
                    if let Some(class_part) = extract_invoke_class(istr) {
                        if class_part.contains("Binding;") && !out.contains(&class_part.to_string()) {
                            out.push(class_part.to_string());
                        }
                    }
                }
            }
        }
    }
    out
}

fn extract_invoke_class(istr: &str) -> Option<&str> {
    let after = istr.find("}, ").map(|p| p + 3)
        .or_else(|| istr.find("} ..").map(|p| p + 4))
        .or_else(|| istr.rfind('}').map(|p| p + 1))?;
    let rest = istr[after..].trim();
    let arrow = rest.find("->")?;
    // Slice up to (not including) `->` — the class's trailing `;` is
    // already at `arrow - 1`. MUST match `activity_layout::extract_invoke_class`
    // so binding-class sentinel hashes round-trip cleanly.
    Some(&rest[..arrow])
}
