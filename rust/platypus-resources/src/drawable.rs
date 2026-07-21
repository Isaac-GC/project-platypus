//! Drawable resolution — turn an `@drawable/foo` reference (or a resource
//! id) into a structured [`Drawable`] value the renderer can consume.
//!
//! Android drawables come in many forms: PNG/WebP/JPG bitmaps, 9-patch
//! PNGs, vector XML, shape XML, state-list selectors, layer lists, ripples,
//! insets, and inline colors. This module classifies the resource entry
//! and dispatches to the right sub-parser.
//!
//! All XML drawables are stored compiled (binary AXML) inside the APK;
//! we use [`platypus_apk::axml`] to parse them, then walk the resulting
//! `XmlNode` tree.

use serde::{Deserialize, Serialize};

use platypus_apk::axml;
use platypus_apk::zip::ApkZip;
use platypus_apk::arsc::ResourceTable;

use crate::refs::{parse_reference, Reference};

pub mod vector;
pub mod shape;
pub mod selector;
pub mod layer_list;

pub use vector::VectorDrawable;
pub use shape::{ShapeDrawable, ShapeKind, Stroke, Corners, Gradient, GradientKind};
pub use selector::{SelectorDrawable, SelectorItem, ViewState};
pub use layer_list::{LayerListDrawable, LayerItem};

// ── Top-level Drawable enum ────────────────────────────────────────────────

/// A resolved Android drawable — discriminated by kind. Renderers branch
/// on this for paint behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Drawable {
    /// Raster image (PNG / WebP / JPG / GIF). The path inside the APK is
    /// preserved so the renderer can read the bytes itself.
    Bitmap {
        path: String,
        format: BitmapFormat,
    },
    /// 9-patch PNG — like Bitmap but with stretch/padding metadata. We
    /// don't parse the 9-patch chunk here yet (planned for phase 5b);
    /// the renderer can read the PNG directly.
    NinePatch {
        path: String,
    },
    /// Vector drawable — converted to SVG so renderers can use directly.
    Vector(VectorDrawable),
    /// `<shape>` drawable.
    Shape(ShapeDrawable),
    /// `<selector>` drawable — state-list with one item per ViewState.
    Selector(SelectorDrawable),
    /// `<layer-list>` drawable — stacked drawables.
    LayerList(LayerListDrawable),
    /// `<ripple>` drawable — Material ripple effect with optional content
    /// and mask layers.
    Ripple(RippleDrawable),
    /// `<inset>` drawable — wraps another drawable with padding.
    Inset(InsetDrawable),
    /// Inline color reference (e.g. `<drawable name="x">#FF000000</drawable>`).
    /// `rgba` is in the standard 0xAARRGGBB packed layout.
    Color {
        rgba: u32,
    },
    /// Couldn't fully resolve — but we know the type and name. Renderer
    /// can show a placeholder.
    Reference {
        type_name: String,
        name: String,
    },
    /// Anything else — keep the original entry path so the renderer can
    /// do something useful with it (download, hex-dump, etc.).
    Unknown {
        entry_path: String,
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitmapFormat {
    Png,
    Jpg,
    Webp,
    Gif,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RippleDrawable {
    pub color: String,
    pub mask: Option<Box<Drawable>>,
    pub content: Option<Box<Drawable>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InsetDrawable {
    pub drawable: Box<Drawable>,
    /// Inset values in pixels (Android source `dp` is preserved as-is — no
    /// resolution-aware conversion at static-analysis time).
    pub inset_left: i32,
    pub inset_top: i32,
    pub inset_right: i32,
    pub inset_bottom: i32,
}

// ── Top-level resolver ─────────────────────────────────────────────────────

/// Resolve a `@drawable/foo`-style reference (or any resource id) to a
/// structured [`Drawable`]. `apk` is needed because XML drawables live in
/// `res/drawable*/...xml` and must be re-read from the APK.
///
/// `recursion_limit` guards against pathological reference chains
/// (`@drawable/a` → `@drawable/b` → `@drawable/a`). Default 8 is plenty.
pub fn resolve(
    table: &ResourceTable,
    apk: &ApkZip,
    res_id: u32,
    recursion_limit: usize,
) -> Drawable {
    if recursion_limit == 0 {
        return Drawable::Unknown {
            entry_path: format!("@0x{:08x}", res_id),
            reason: "recursion limit reached".into(),
        };
    }

    let entry = match table.get(res_id) {
        Some(e) => e,
        None => return Drawable::Unknown {
            entry_path: format!("@0x{:08x}", res_id),
            reason: "resource id not in table".into(),
        },
    };

    let value = entry.value.clone();
    resolve_value(table, apk, &value, recursion_limit)
}

/// Resolve an arbitrary attribute value as a drawable. Used by the layout
/// rehydrator for `android:background` / `android:src` / `android:drawable`
/// attributes that may be either a literal color or an `@drawable/foo` ref.
pub fn resolve_value(
    table: &ResourceTable,
    apk: &ApkZip,
    value: &str,
    recursion_limit: usize,
) -> Drawable {
    let trimmed = value.trim();

    // ── Inline color literal: "#RRGGBB", "#AARRGGBB", "#RGB" ────────────
    if let Some(rgba) = parse_color_literal(trimmed) {
        return Drawable::Color { rgba };
    }

    // ── Reference: @drawable/foo / @0x7f... / @android:drawable/x ────────
    if let Some(reference) = parse_reference(trimmed) {
        return follow_reference(table, apk, &reference, recursion_limit);
    }

    // ── Direct file path (already resolved by parse_with_resources) ──────
    if trimmed.starts_with("res/") {
        return resolve_path(apk, trimmed);
    }

    Drawable::Unknown {
        entry_path: trimmed.to_string(),
        reason: "value is not a color, reference, or path".into(),
    }
}

fn follow_reference(
    table: &ResourceTable,
    apk: &ApkZip,
    reference: &Reference,
    recursion_limit: usize,
) -> Drawable {
    match reference {
        Reference::Id(id) => resolve(table, apk, *id, recursion_limit - 1),
        Reference::Named { type_name, name, package } => {
            // Framework refs (@android:drawable/...) aren't in app resources.
            if package.as_deref() == Some("android") {
                return Drawable::Reference {
                    type_name: type_name.clone(),
                    name: name.clone(),
                };
            }
            let entry = table.entries().iter().find(|e| {
                e.type_name == *type_name && e.name == *name
            });
            match entry {
                Some(e) => resolve(table, apk, e.id, recursion_limit - 1),
                None => Drawable::Reference {
                    type_name: type_name.clone(),
                    name: name.clone(),
                },
            }
        }
        Reference::IdDecl(_) | Reference::ThemeAttr { .. } => Drawable::Unknown {
            entry_path: format!("{:?}", reference),
            reason: "reference kind not supported by drawable resolver".into(),
        },
    }
}

/// Dispatch on file extension when we have a concrete entry path.
fn resolve_path(apk: &ApkZip, entry_path: &str) -> Drawable {
    let lower = entry_path.to_lowercase();

    // ── 9-patch — ".9.png" suffix (Android packs metadata into the PNG)
    if lower.ends_with(".9.png") {
        return Drawable::NinePatch { path: entry_path.to_string() };
    }

    // ── Bitmap formats (caller reads the bytes directly via APK)
    if let Some(fmt) = bitmap_format_for(&lower) {
        return Drawable::Bitmap {
            path: entry_path.to_string(),
            format: fmt,
        };
    }

    // ── XML drawable
    if lower.ends_with(".xml") {
        let bytes = match apk.read_entry(entry_path) {
            Ok(b) => b,
            Err(e) => return Drawable::Unknown {
                entry_path: entry_path.to_string(),
                reason: format!("read failed: {e}"),
            },
        };
        let root = match axml::parse(&bytes) {
            Ok(r) => r,
            Err(e) => return Drawable::Unknown {
                entry_path: entry_path.to_string(),
                reason: format!("AXML parse failed: {e}"),
            },
        };
        return dispatch_xml(apk, root);
    }

    Drawable::Unknown {
        entry_path: entry_path.to_string(),
        reason: format!("unrecognised extension"),
    }
}

/// Walk an XML root and produce the matching Drawable variant based on the
/// root tag. Recursive — selectors and layer-lists contain inline drawables.
pub(crate) fn dispatch_xml(apk: &ApkZip, root: axml::XmlNode) -> Drawable {
    match root.tag.as_str() {
        "vector"      => Drawable::Vector(vector::parse(root)),
        "shape"       => Drawable::Shape(shape::parse(root)),
        "selector"    => Drawable::Selector(selector::parse(apk, root)),
        "layer-list"  => Drawable::LayerList(layer_list::parse(apk, root)),
        "ripple"      => parse_ripple(apk, root),
        "inset"       => parse_inset(apk, root),
        "bitmap"      => parse_bitmap_xml(root),
        other         => Drawable::Unknown {
            entry_path: String::new(),
            reason: format!("unrecognised root tag <{}>", other),
        },
    }
}

// ── Sub-parsers for the simpler drawable kinds ────────────────────────────

fn parse_ripple(apk: &ApkZip, node: axml::XmlNode) -> Drawable {
    let color = node.attr("android:color").unwrap_or("#FF000000").to_string();
    let mut mask = None;
    let mut content = None;
    for child in &node.children {
        if child.tag != "item" { continue; }
        let item_id = child.attr("android:id").unwrap_or("");
        let inner = child.children.first()
            .map(|n| Box::new(dispatch_xml(apk, n.clone())));
        match item_id {
            "@android:id/mask" => mask = inner,
            _ => content = inner.or(content),
        }
    }
    Drawable::Ripple(RippleDrawable { color, mask, content })
}

fn parse_inset(apk: &ApkZip, node: axml::XmlNode) -> Drawable {
    let parse_inset_attr = |name: &str| -> i32 {
        node.attr(name)
            .and_then(parse_dimen_to_px)
            .unwrap_or(0)
    };
    let inset_left   = parse_inset_attr("android:insetLeft");
    let inset_top    = parse_inset_attr("android:insetTop");
    let inset_right  = parse_inset_attr("android:insetRight");
    let inset_bottom = parse_inset_attr("android:insetBottom");

    // The wrapped drawable is either an inline `<item>` child or a
    // `android:drawable="@drawable/…"` attribute.
    let inner = node.attr("android:drawable")
        .map(|val| Box::new(resolve_value_no_table(apk, val)));
    let inner = inner.or_else(|| {
        node.children.first().map(|c| Box::new(dispatch_xml(apk, c.clone())))
    });

    let drawable = inner.unwrap_or_else(|| Box::new(Drawable::Unknown {
        entry_path: String::new(),
        reason: "<inset> with no inner drawable".into(),
    }));

    Drawable::Inset(InsetDrawable {
        drawable, inset_left, inset_top, inset_right, inset_bottom,
    })
}

fn parse_bitmap_xml(node: axml::XmlNode) -> Drawable {
    // <bitmap android:src="@drawable/foo" android:tileMode="repeat" .../>
    // The interesting part is the src reference — we just expose it as a
    // Bitmap variant (resolution still needs follow-through, but most
    // callers will resolve the parent reference first).
    let src = node.attr("android:src").unwrap_or("").to_string();
    if src.is_empty() {
        return Drawable::Unknown {
            entry_path: String::new(),
            reason: "<bitmap> missing android:src".into(),
        };
    }
    Drawable::Reference {
        type_name: "drawable".into(),
        name: src.trim_start_matches("@drawable/").to_string(),
    }
}

/// Standalone resolver used by the inset parser when we have an APK but
/// not a ResourceTable handle. Just dispatches based on extension; XML
/// children come back as Reference (caller follows up).
fn resolve_value_no_table(apk: &ApkZip, value: &str) -> Drawable {
    let trimmed = value.trim();
    if let Some(rgba) = parse_color_literal(trimmed) {
        return Drawable::Color { rgba };
    }
    if trimmed.starts_with("res/") {
        return resolve_path(apk, trimmed);
    }
    if let Some(rest) = trimmed.strip_prefix("@drawable/") {
        return Drawable::Reference {
            type_name: "drawable".into(),
            name: rest.to_string(),
        };
    }
    Drawable::Unknown { entry_path: trimmed.into(), reason: "unresolved".into() }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn bitmap_format_for(lower_path: &str) -> Option<BitmapFormat> {
    if lower_path.ends_with(".png")  { return Some(BitmapFormat::Png); }
    if lower_path.ends_with(".jpg") || lower_path.ends_with(".jpeg") {
        return Some(BitmapFormat::Jpg);
    }
    if lower_path.ends_with(".webp") { return Some(BitmapFormat::Webp); }
    if lower_path.ends_with(".gif")  { return Some(BitmapFormat::Gif); }
    None
}

/// Parse `#RGB` / `#RRGGBB` / `#AARRGGBB` to a packed `0xAARRGGBB` u32.
/// Returns `None` if the input isn't a hex color literal.
pub fn parse_color_literal(s: &str) -> Option<u32> {
    let s = s.trim();
    let hex = s.strip_prefix('#')?;
    let n = hex.len();
    let parsed = u32::from_str_radix(hex, 16).ok()?;
    Some(match n {
        3 => {
            // #RGB → expand to #RRGGBB with full alpha
            let r = ((parsed >> 8) & 0xF) * 0x11;
            let g = ((parsed >> 4) & 0xF) * 0x11;
            let b = (parsed & 0xF) * 0x11;
            0xFF00_0000 | (r << 16) | (g << 8) | b
        }
        4 => {
            // #ARGB
            let a = ((parsed >> 12) & 0xF) * 0x11;
            let r = ((parsed >> 8)  & 0xF) * 0x11;
            let g = ((parsed >> 4)  & 0xF) * 0x11;
            let b = (parsed & 0xF) * 0x11;
            (a << 24) | (r << 16) | (g << 8) | b
        }
        6 => 0xFF00_0000 | parsed,    // #RRGGBB → assume full alpha
        8 => parsed,                   // #AARRGGBB
        _ => return None,
    })
}

/// Convert a CSS-like color back to `#AARRGGBB` notation. Handy for SVG
/// output (renderers want strings, not packed u32s).
pub fn rgba_to_hex(rgba: u32) -> String {
    format!("#{:08X}", rgba)
}

/// Parse a dimension string like `"16dp"` / `"8sp"` / `"2px"` to integer
/// pixels at 1.0× scale (no DPI awareness — we don't know the target).
/// Returns `None` for unparseable input.
pub fn parse_dimen_to_px(s: &str) -> Option<i32> {
    let s = s.trim();
    // Strip the unit suffix (last 2 chars when alpha).
    let (num_str, _unit) = if s.ends_with("dp") || s.ends_with("sp") || s.ends_with("px") {
        (&s[..s.len() - 2], &s[s.len() - 2..])
    } else if s.ends_with("dip") {
        (&s[..s.len() - 3], &s[s.len() - 3..])
    } else {
        (s, "")
    };
    num_str.parse::<f32>().ok().map(|f| f as i32)
}
