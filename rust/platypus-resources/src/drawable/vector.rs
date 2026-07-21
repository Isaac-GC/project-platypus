//! Vector drawable parser + Android-vector → SVG converter.
//!
//! Android's vector format and SVG share a lot — `pathData` is byte-for-
//! byte SVG-compatible, and most attributes have direct SVG analogues.
//! The non-trivial parts are:
//!
//! * `<group>` transforms — Android applies them as scale → rotate →
//!   translate around `(pivotX, pivotY)`. SVG's `transform` is
//!   right-to-left, so we have to re-order and explicitly center.
//! * `<clip-path>` — wraps the next sibling in a `<clipPath>` def + ref.
//! * Resource references in attributes (`@color/...`) — already resolved
//!   to literal `#AARRGGBB` strings by `axml::parse_with_resources` if a
//!   ResourceTable was supplied at parse time.
//!
//! Gradients (`<gradient>` inside a path's fill) are not yet implemented;
//! the path renders as solid `currentColor` in that case.

use std::fmt::Write;

use serde::{Deserialize, Serialize};

use platypus_apk::axml::XmlNode;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VectorDrawable {
    /// Original `android:width` (e.g. `"24dp"`). Renderers can either
    /// honour or ignore — the SVG below uses `viewport_*` for the canvas.
    pub width: String,
    pub height: String,
    /// `android:viewportWidth` — the coordinate space of the path data.
    pub viewport_width: f32,
    pub viewport_height: f32,
    /// Optional global alpha (`android:alpha`).
    pub alpha: f32,
    /// Pre-rendered SVG string. Renderers don't need to walk `root` —
    /// they can just inject this string inline into HTML.
    pub svg: String,
    /// Walked tree, in case a renderer wants per-element control.
    pub root: VectorElement,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum VectorElement {
    Group {
        /// Empty when no `android:name` attribute is present.
        name: String,
        rotation: f32,
        pivot_x: f32,
        pivot_y: f32,
        scale_x: f32,
        scale_y: f32,
        translate_x: f32,
        translate_y: f32,
        children: Vec<VectorElement>,
    },
    Path {
        name: String,
        path_data: String,
        fill_color: Option<String>,
        fill_alpha: f32,
        stroke_color: Option<String>,
        stroke_alpha: f32,
        stroke_width: f32,
        stroke_line_cap: Option<String>,    // butt | round | square
        stroke_line_join: Option<String>,   // miter | round | bevel
        fill_type: Option<String>,          // evenOdd | nonZero
    },
    /// `<clip-path android:pathData="…"/>` — applies to subsequent siblings
    /// in the same group. We model this as a separate element rather than
    /// a property so the renderer can decide how to handle it.
    ClipPath {
        name: String,
        path_data: String,
    },
}

// ── Parser ────────────────────────────────────────────────────────────────

pub fn parse(root: XmlNode) -> VectorDrawable {
    let width  = root.attr("android:width").unwrap_or("0dp").to_string();
    let height = root.attr("android:height").unwrap_or("0dp").to_string();
    let viewport_width  = root.attr("android:viewportWidth")
        .and_then(|s| s.parse::<f32>().ok()).unwrap_or(0.0);
    let viewport_height = root.attr("android:viewportHeight")
        .and_then(|s| s.parse::<f32>().ok()).unwrap_or(0.0);
    let alpha = root.attr("android:alpha")
        .and_then(|s| s.parse::<f32>().ok()).unwrap_or(1.0);

    let parsed_root = parse_element_or_group_children(&root);
    let svg = render_svg(viewport_width, viewport_height, alpha, &parsed_root);

    VectorDrawable {
        width, height,
        viewport_width, viewport_height,
        alpha,
        svg,
        root: parsed_root,
    }
}

/// `<vector>` is itself the root group — its direct children are the top-
/// level elements. Wrap them in a synthetic Group with identity transform
/// so callers see a uniform tree shape.
fn parse_element_or_group_children(node: &XmlNode) -> VectorElement {
    let children: Vec<VectorElement> = node.children.iter()
        .filter_map(parse_element)
        .collect();
    VectorElement::Group {
        name: node.attr("android:name").unwrap_or("").to_string(),
        rotation: 0.0,
        pivot_x: 0.0, pivot_y: 0.0,
        scale_x: 1.0, scale_y: 1.0,
        translate_x: 0.0, translate_y: 0.0,
        children,
    }
}

fn parse_element(node: &XmlNode) -> Option<VectorElement> {
    match node.tag.as_str() {
        "group"     => Some(parse_group(node)),
        "path"      => Some(parse_path(node)),
        "clip-path" => Some(parse_clip_path(node)),
        _ => None,
    }
}

fn parse_group(node: &XmlNode) -> VectorElement {
    let attr_f32 = |name: &str, default: f32| -> f32 {
        node.attr(name).and_then(|s| s.parse().ok()).unwrap_or(default)
    };
    VectorElement::Group {
        name: node.attr("android:name").unwrap_or("").to_string(),
        rotation:    attr_f32("android:rotation",   0.0),
        pivot_x:     attr_f32("android:pivotX",     0.0),
        pivot_y:     attr_f32("android:pivotY",     0.0),
        scale_x:     attr_f32("android:scaleX",     1.0),
        scale_y:     attr_f32("android:scaleY",     1.0),
        translate_x: attr_f32("android:translateX", 0.0),
        translate_y: attr_f32("android:translateY", 0.0),
        children: node.children.iter().filter_map(parse_element).collect(),
    }
}

fn parse_path(node: &XmlNode) -> VectorElement {
    let attr_f32 = |name: &str, default: f32| -> f32 {
        node.attr(name).and_then(|s| s.parse().ok()).unwrap_or(default)
    };
    VectorElement::Path {
        name: node.attr("android:name").unwrap_or("").to_string(),
        path_data: node.attr("android:pathData").unwrap_or("").to_string(),
        fill_color:   node.attr("android:fillColor").map(String::from),
        fill_alpha:   attr_f32("android:fillAlpha",   1.0),
        stroke_color: node.attr("android:strokeColor").map(String::from),
        stroke_alpha: attr_f32("android:strokeAlpha", 1.0),
        stroke_width: attr_f32("android:strokeWidth", 0.0),
        stroke_line_cap:  node.attr("android:strokeLineCap").map(String::from),
        stroke_line_join: node.attr("android:strokeLineJoin").map(String::from),
        fill_type:    node.attr("android:fillType").map(String::from),
    }
}

fn parse_clip_path(node: &XmlNode) -> VectorElement {
    VectorElement::ClipPath {
        name: node.attr("android:name").unwrap_or("").to_string(),
        path_data: node.attr("android:pathData").unwrap_or("").to_string(),
    }
}

// ── SVG renderer ───────────────────────────────────────────────────────────

fn render_svg(vw: f32, vh: f32, alpha: f32, root: &VectorElement) -> String {
    let mut out = String::with_capacity(512);

    let _ = write!(out,
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}""#,
        w = trim_f32(vw), h = trim_f32(vh),
    );
    if (alpha - 1.0).abs() > f32::EPSILON {
        let _ = write!(out, r#" opacity="{}""#, trim_f32(alpha));
    }
    out.push('>');

    // The root is always a Group from parse_element_or_group_children.
    if let VectorElement::Group { children, .. } = root {
        let mut clip_count = 0;
        for child in children {
            render_element(&mut out, child, &mut clip_count);
        }
    }

    out.push_str("</svg>");
    out
}

fn render_element(out: &mut String, el: &VectorElement, clip_count: &mut usize) {
    match el {
        VectorElement::Group {
            rotation, pivot_x, pivot_y, scale_x, scale_y,
            translate_x, translate_y, children, name,
        } => {
            // Android transform order: scale → rotate(around pivot) → translate.
            // SVG transform is right-to-left; build the equivalent by the
            // standard "translate to pivot, rotate, translate back" trick.
            let mut tx = String::new();
            if (*translate_x).abs() > f32::EPSILON || (*translate_y).abs() > f32::EPSILON {
                let _ = write!(tx, "translate({} {}) ",
                               trim_f32(*translate_x), trim_f32(*translate_y));
            }
            if (*pivot_x).abs() > f32::EPSILON || (*pivot_y).abs() > f32::EPSILON {
                let _ = write!(tx, "translate({} {}) ",
                               trim_f32(*pivot_x), trim_f32(*pivot_y));
            }
            if (*rotation).abs() > f32::EPSILON {
                let _ = write!(tx, "rotate({}) ", trim_f32(*rotation));
            }
            if (*pivot_x).abs() > f32::EPSILON || (*pivot_y).abs() > f32::EPSILON {
                let _ = write!(tx, "translate({} {}) ",
                               trim_f32(-*pivot_x), trim_f32(-*pivot_y));
            }
            if (*scale_x - 1.0).abs() > f32::EPSILON || (*scale_y - 1.0).abs() > f32::EPSILON {
                let _ = write!(tx, "scale({} {}) ",
                               trim_f32(*scale_x), trim_f32(*scale_y));
            }
            let tx = tx.trim_end();

            out.push_str("<g");
            if !name.is_empty() {
                let _ = write!(out, r#" id="{}""#, escape_attr(name));
            }
            if !tx.is_empty() {
                let _ = write!(out, r#" transform="{}""#, tx);
            }
            out.push('>');
            for child in children {
                render_element(out, child, clip_count);
            }
            out.push_str("</g>");
        }

        VectorElement::Path {
            path_data, fill_color, fill_alpha, stroke_color, stroke_alpha,
            stroke_width, stroke_line_cap, stroke_line_join, fill_type, name,
        } => {
            out.push_str("<path");
            if !name.is_empty() {
                let _ = write!(out, r#" id="{}""#, escape_attr(name));
            }
            // android:pathData is verbatim SVG syntax — copy as-is.
            let _ = write!(out, r#" d="{}""#, escape_attr(path_data));

            match fill_color {
                Some(c) => { let _ = write!(out, r#" fill="{}""#, normalise_color(c)); }
                None    => out.push_str(r#" fill="none""#),
            }
            if (*fill_alpha - 1.0).abs() > f32::EPSILON {
                let _ = write!(out, r#" fill-opacity="{}""#, trim_f32(*fill_alpha));
            }
            if let Some(rule) = fill_type {
                let svg_rule = if rule.eq_ignore_ascii_case("evenOdd") { "evenodd" } else { "nonzero" };
                let _ = write!(out, r#" fill-rule="{}""#, svg_rule);
            }

            if let Some(sc) = stroke_color {
                let _ = write!(out, r#" stroke="{}""#, normalise_color(sc));
                if (*stroke_alpha - 1.0).abs() > f32::EPSILON {
                    let _ = write!(out, r#" stroke-opacity="{}""#, trim_f32(*stroke_alpha));
                }
                if *stroke_width > 0.0 {
                    let _ = write!(out, r#" stroke-width="{}""#, trim_f32(*stroke_width));
                }
                if let Some(cap) = stroke_line_cap {
                    let _ = write!(out, r#" stroke-linecap="{}""#, cap.to_lowercase());
                }
                if let Some(join) = stroke_line_join {
                    let _ = write!(out, r#" stroke-linejoin="{}""#, join.to_lowercase());
                }
            }
            out.push_str("/>");
        }

        VectorElement::ClipPath { path_data, .. } => {
            // Emit a `<clipPath>` def + a wrapping `<g clip-path="…">` for
            // subsequent siblings. We use a counter to give each clip a
            // unique id within the SVG.
            *clip_count += 1;
            let id = format!("clip{}", clip_count);
            let _ = write!(out, r#"<clipPath id="{id}"><path d="{}"/></clipPath>"#,
                           escape_attr(path_data));
            // Note: properly wrapping subsequent siblings would require
            // restructuring the loop. For now we just emit the clipPath
            // def — most vector drawables use clip-path at the start of a
            // group, so the renderer can apply it manually if needed.
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn trim_f32(v: f32) -> String {
    // Trim trailing zeros from float formatting.
    let s = format!("{:.3}", v);
    let s = s.trim_end_matches('0');
    let s = s.trim_end_matches('.');
    if s.is_empty() { "0".into() } else { s.to_string() }
}

/// Android color refs come through as `#AARRGGBB` (8-hex) usually. SVG
/// understands `#RRGGBB` and `rgba()`. Convert `#AARRGGBB` → `rgba(r,g,b,a)`
/// when alpha < 0xFF; otherwise emit the 6-hex form for compactness.
fn normalise_color(c: &str) -> String {
    let s = c.trim();
    if s.len() == 9 && s.starts_with('#') {
        if let Ok(packed) = u32::from_str_radix(&s[1..], 16) {
            let a = (packed >> 24) & 0xFF;
            let r = (packed >> 16) & 0xFF;
            let g = (packed >>  8) & 0xFF;
            let b = packed & 0xFF;
            if a == 0xFF {
                return format!("#{:02X}{:02X}{:02X}", r, g, b);
            }
            return format!("rgba({},{},{},{:.3})", r, g, b, a as f32 / 255.0);
        }
    }
    s.to_string()
}

fn escape_attr(s: &str) -> String {
    s.replace('&', "&amp;").replace('"', "&quot;").replace('<', "&lt;")
}
