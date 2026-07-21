//! Layout XML expansion.
//!
//! Android layouts compose smaller layouts via three mechanisms:
//!
//! * `<include layout="@layout/header"/>` — splices the included layout's
//!   root in place of the `<include>` element. Attributes on `<include>`
//!   override the included root's (id, layout_width, layout_height etc.).
//! * `<merge>` — the included root flattens into the parent rather than
//!   nesting (saves a wrapper view in the final tree).
//! * `<ViewStub android:layout="@layout/lazy"/>` — placeholder; gets
//!   replaced by the referenced layout when `viewstub.inflate()` is called
//!   at runtime. For static reconstruction we expand it eagerly.
//!
//! The expander walks the tree, replacing each occurrence with the
//! resolved-and-expanded sub-tree, recursively. A reasonable depth cap
//! (default 8) prevents infinite recursion if a layout includes itself.

use platypus_apk::axml;
use platypus_apk::zip::ApkZip;
use platypus_resources::{Layout, Resources, View};

/// Maximum recursion depth for `<include>` / `<ViewStub>` chains. Real
/// layouts rarely nest more than 2-3 levels; 8 is a generous safety net.
const MAX_DEPTH: usize = 8;

/// Open and expand the layout file at `layout_path` from `apk`. References
/// inside attributes are resolved against `resources`. Returns the
/// fully-flattened tree.
///
/// `apk` is the *raw* `ApkZip` so we can read other layout files when
/// resolving `<include>`s. `resources` is needed both for attribute-value
/// resolution and for layout-name → file-path lookup when an `<include
/// layout="@layout/foo">` references a layout by id rather than path.
pub fn expand_layout_file(
    apk: &ApkZip,
    layout_path: &str,
    resources: &Resources,
) -> Result<ExpandedLayout, ExpandError> {
    let bytes = apk
        .read_entry(layout_path)
        .map_err(|e| ExpandError::IO(format!("read {layout_path}: {e}")))?;
    let layout = Layout::parse_with_resources(&bytes, resources)
        .map_err(ExpandError::Parse)?;
    let mut ctx = ExpandCtx { apk, resources, depth: 0 };
    let expanded = expand_view(&mut ctx, layout.root, layout_path)?;
    Ok(ExpandedLayout {
        root: expanded,
        source_path: layout_path.to_string(),
    })
}

/// Result of expansion.
#[derive(Debug, Clone)]
pub struct ExpandedLayout {
    pub root: ExpandedView,
    /// Path of the *outermost* layout file we expanded. Children may
    /// originate from other files via `<include>` / `<ViewStub>` —
    /// `ExpandedView::origin` records that.
    pub source_path: String,
}

/// A view in the expanded tree, with its origin recorded.
#[derive(Debug, Clone)]
pub struct ExpandedView {
    /// Underlying view (already reference-resolved).
    pub view: View,
    /// Where this node ultimately came from.
    pub origin: ViewOrigin,
    /// Recursively expanded children.
    pub children: Vec<ExpandedView>,
}

#[derive(Debug, Clone)]
pub enum ViewOrigin {
    /// In the layout file we started with (the activity's root).
    Direct { layout_path: String },
    /// Spliced in via `<include>` from another layout file.
    Included { from: String, included: String },
    /// Flattened from a `<merge>` root.
    Merged { from: String },
    /// Substituted from a `<ViewStub>` target.
    StubInflated { stub_in: String, target: String },
}

/// Errors from layout expansion. Manual `Display` + `Error` impl below
/// keeps the crate's dep set minimal — no `thiserror`.
#[derive(Debug)]
pub enum ExpandError {
    IO(String),
    Parse(String),
    DepthExceeded(String),
}

impl std::fmt::Display for ExpandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpandError::IO(s)            => write!(f, "I/O: {s}"),
            ExpandError::Parse(s)         => write!(f, "XML parse: {s}"),
            ExpandError::DepthExceeded(s) => write!(f, "recursion limit at {s}"),
        }
    }
}

impl std::error::Error for ExpandError {}

// ── Recursive expansion ────────────────────────────────────────────────────

struct ExpandCtx<'a> {
    apk: &'a ApkZip,
    resources: &'a Resources,
    depth: usize,
}

fn expand_view(
    ctx: &mut ExpandCtx<'_>,
    view: View,
    in_path: &str,
) -> Result<ExpandedView, ExpandError> {
    match view.tag.as_str() {
        "include" => expand_include(ctx, view, in_path),
        "ViewStub" => expand_view_stub(ctx, view, in_path),
        "merge" => {
            // <merge> at the outer level (not inside an <include>) stays
            // as a passthrough wrapper. The flattening only matters when
            // it's the root of an *included* layout, handled in
            // `expand_include`. Here we just preserve the tag and recurse
            // into children.
            recurse_children(ctx, view, in_path, ViewOrigin::Direct {
                layout_path: in_path.to_string(),
            })
        }
        _ => recurse_children(ctx, view, in_path, ViewOrigin::Direct {
            layout_path: in_path.to_string(),
        }),
    }
}

fn recurse_children(
    ctx: &mut ExpandCtx<'_>,
    view: View,
    in_path: &str,
    origin: ViewOrigin,
) -> Result<ExpandedView, ExpandError> {
    // Take ownership of children before moving `view`.
    let children = view.children.clone();
    let mut expanded_children = Vec::with_capacity(children.len());
    for c in children {
        expanded_children.push(expand_view(ctx, c, in_path)?);
    }
    Ok(ExpandedView {
        view: View {
            tag: view.tag,
            attrs: view.attrs,
            children: Vec::new(), // children carried in `expanded_children` instead
            raw: view.raw,
        },
        origin,
        children: expanded_children,
    })
}

/// Expand an `<include layout="@layout/foo"/>`. The included layout's root
/// becomes this node's content; if it's `<merge>` we splice its children
/// into the parent (the caller flattens — see `expand_include_into_parent`
/// for that).
///
/// Attribute precedence (Android docs): `<include>` overrides id and
/// layout_* attributes from the included root; everything else inherits.
fn expand_include(
    ctx: &mut ExpandCtx<'_>,
    include: View,
    in_path: &str,
) -> Result<ExpandedView, ExpandError> {
    if ctx.depth >= MAX_DEPTH {
        return Err(ExpandError::DepthExceeded(format!(
            "<include> from {in_path}"
        )));
    }

    let layout_ref = include.attr("layout").unwrap_or("").to_string();
    let target_path = match resolve_layout_ref(&layout_ref, ctx.resources) {
        Some(p) => p,
        None => {
            // Couldn't resolve — leave a synthetic include placeholder.
            return Ok(ExpandedView {
                view: include.clone(),
                origin: ViewOrigin::Direct { layout_path: in_path.to_string() },
                children: Vec::new(),
            });
        }
    };

    // Read the target file and parse.
    let bytes = ctx.apk.read_entry(&target_path)
        .map_err(|e| ExpandError::IO(format!("read {target_path}: {e}")))?;
    let target = Layout::parse_with_resources(&bytes, ctx.resources)
        .map_err(ExpandError::Parse)?;

    ctx.depth += 1;
    let result = if target.root.tag == "merge" {
        // <merge> root — flatten its children into the parent's slot.
        // Take ownership of the children before constructing the result
        // so we don't re-borrow `target.root` after a partial move.
        let mut root_view = target.root;
        let children_owned = std::mem::take(&mut root_view.children);
        let mut merged_children = Vec::new();
        for child in children_owned {
            merged_children.push(expand_view(ctx, child, &target_path)?);
        }
        Ok(ExpandedView {
            view: root_view,
            origin: ViewOrigin::Merged { from: target_path.clone() },
            children: merged_children,
        })
    } else {
        // Regular include — replace the <include> tag with the target's
        // root, applying attribute overrides from the <include> itself.
        let merged_root = apply_include_overrides(target.root, &include);
        let mut expanded_children = Vec::new();
        for child in merged_root.children.clone() {
            expanded_children.push(expand_view(ctx, child, &target_path)?);
        }
        Ok(ExpandedView {
            view: View {
                tag: merged_root.tag,
                attrs: merged_root.attrs,
                children: Vec::new(),
                raw: merged_root.raw,
            },
            origin: ViewOrigin::Included {
                from: in_path.to_string(),
                included: target_path.clone(),
            },
            children: expanded_children,
        })
    };
    ctx.depth -= 1;
    result
}

/// Expand a `<ViewStub android:layout="@layout/lazy"/>`. Same shape as
/// `<include>` but with `ViewOrigin::StubInflated`.
fn expand_view_stub(
    ctx: &mut ExpandCtx<'_>,
    stub: View,
    in_path: &str,
) -> Result<ExpandedView, ExpandError> {
    if ctx.depth >= MAX_DEPTH {
        return Err(ExpandError::DepthExceeded(format!("<ViewStub> in {in_path}")));
    }

    let layout_ref = stub.attr("android:layout").unwrap_or("").to_string();
    let target_path = match resolve_layout_ref(&layout_ref, ctx.resources) {
        Some(p) => p,
        None => {
            // Stub with no resolvable target — keep as a leaf placeholder.
            return Ok(ExpandedView {
                view: stub.clone(),
                origin: ViewOrigin::Direct { layout_path: in_path.to_string() },
                children: Vec::new(),
            });
        }
    };

    let bytes = ctx.apk.read_entry(&target_path)
        .map_err(|e| ExpandError::IO(format!("read {target_path}: {e}")))?;
    let target = Layout::parse_with_resources(&bytes, ctx.resources)
        .map_err(ExpandError::Parse)?;

    ctx.depth += 1;
    let mut expanded_children = Vec::new();
    for child in target.root.children.clone() {
        expanded_children.push(expand_view(ctx, child, &target_path)?);
    }
    let result = Ok(ExpandedView {
        view: View {
            tag: target.root.tag.clone(),
            attrs: target.root.attrs.clone(),
            children: Vec::new(),
            raw: target.root.raw.clone(),
        },
        origin: ViewOrigin::StubInflated {
            stub_in: in_path.to_string(),
            target: target_path,
        },
        children: expanded_children,
    });
    ctx.depth -= 1;
    result
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Resolve an `@layout/foo` style ref (or already-resolved path) to a
/// concrete `res/layout/foo.xml` path inside the APK.
///
/// Order of attempts:
/// 1. If the value is already a `res/layout/...` path, return it directly.
/// 2. Try as a numeric ref (`@0x7f0a0001`) and resolve via the table.
/// 3. Try as a named ref (`@layout/activity_main`) and look up by name.
fn resolve_layout_ref(value: &str, resources: &Resources) -> Option<String> {
    if value.is_empty() { return None; }
    if value.starts_with("res/layout") || value.contains("/layout") {
        // Attribute resolution may have already turned the ref into a path.
        return Some(value.to_string());
    }

    // Try ref parsing.
    if let Some(r) = platypus_resources::refs::parse_reference(value) {
        match r {
            platypus_resources::refs::Reference::Id(id) => {
                return resources.resolve(id);
            }
            platypus_resources::refs::Reference::Named { type_name, name, package } => {
                if package.is_some() { return None; }
                if type_name == "layout" {
                    return resources.layout_path(&name);
                }
            }
            _ => {}
        }
    }
    None
}

/// Apply an `<include>`'s overrides to the target layout's root. Per
/// Android docs the include can override:
///   - android:id
///   - any android:layout_* attribute
fn apply_include_overrides(mut root: View, include: &View) -> View {
    for (k, v) in &include.attrs {
        if k == "android:id" || k.starts_with("android:layout_") {
            // Replace if already present, otherwise append.
            if let Some(slot) = root.attrs.iter_mut().find(|(rk, _)| rk == k) {
                slot.1 = v.clone();
            } else {
                root.attrs.push((k.clone(), v.clone()));
            }
        }
    }
    root
}

/// Wraps the unused `axml` import — used transitively via `Layout`.
#[allow(dead_code)]
fn _axml_silencer(b: &[u8]) -> Result<axml::XmlNode, platypus_apk::ApkError> {
    axml::parse(b)
}
