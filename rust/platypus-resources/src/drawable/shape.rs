//! Shape drawable parser.
//!
//! `<shape>` is a small declarative format for primitive shapes —
//! rectangles, ovals, lines, rings — with optional fill, stroke, corner
//! radii, and gradient. Used heavily for backgrounds, button shapes,
//! dividers, etc.
//!
//! ```xml
//! <shape android:shape="rectangle">
//!     <solid android:color="#FF4285F4"/>
//!     <stroke android:width="2dp" android:color="#FF000000"/>
//!     <corners android:radius="8dp"/>
//!     <padding android:left="8dp"/>
//!     <gradient android:startColor="#F00" android:endColor="#0F0"
//!               android:angle="45"/>
//! </shape>
//! ```

use serde::{Deserialize, Serialize};

use platypus_apk::axml::XmlNode;

use super::parse_dimen_to_px;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ShapeDrawable {
    pub shape_kind: ShapeKind,
    pub solid_color: Option<String>,
    pub stroke: Option<Stroke>,
    pub corners: Corners,
    pub padding: Padding,
    pub gradient: Option<Gradient>,
    /// `<size android:width="…" android:height="…"/>` — optional intrinsic size.
    pub intrinsic_width: Option<i32>,
    pub intrinsic_height: Option<i32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ShapeKind {
    Rectangle,
    Oval,
    Line,
    Ring,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Stroke {
    pub width: i32,
    pub color: String,
    pub dash_width: Option<i32>,
    pub dash_gap: Option<i32>,
}

/// Per-corner radii. When `all` is `Some`, the per-corner fields are unused
/// (Android applies the uniform radius). Otherwise the per-corner fields
/// take effect.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Corners {
    pub all: Option<i32>,
    pub top_left: Option<i32>,
    pub top_right: Option<i32>,
    pub bottom_left: Option<i32>,
    pub bottom_right: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Padding {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Gradient {
    pub kind: GradientKind,
    pub start_color: String,
    pub end_color: String,
    pub center_color: Option<String>,
    /// Angle in degrees (linear gradients only). Must be a multiple of 45 in
    /// Android, but we don't enforce.
    pub angle: f32,
    /// Center coordinates (relative, 0.0–1.0) for radial/sweep gradients.
    pub center_x: f32,
    pub center_y: f32,
    /// Radius in pixels for radial gradients.
    pub gradient_radius: Option<i32>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GradientKind {
    Linear,
    Radial,
    Sweep,
}

// ── Parser ────────────────────────────────────────────────────────────────

pub fn parse(node: XmlNode) -> ShapeDrawable {
    let shape_kind = match node.attr("android:shape").unwrap_or("rectangle") {
        "oval"      => ShapeKind::Oval,
        "line"      => ShapeKind::Line,
        "ring"      => ShapeKind::Ring,
        _           => ShapeKind::Rectangle,
    };

    let mut solid_color = None;
    let mut stroke = None;
    let mut corners = Corners::default();
    let mut padding = Padding::default();
    let mut gradient = None;
    let mut intrinsic_width = None;
    let mut intrinsic_height = None;

    for child in &node.children {
        match child.tag.as_str() {
            "solid" => {
                solid_color = child.attr("android:color").map(String::from);
            }
            "stroke" => {
                let width = child.attr("android:width")
                    .and_then(parse_dimen_to_px).unwrap_or(0);
                let color = child.attr("android:color").unwrap_or("#FF000000").to_string();
                stroke = Some(Stroke {
                    width, color,
                    dash_width: child.attr("android:dashWidth").and_then(parse_dimen_to_px),
                    dash_gap:   child.attr("android:dashGap").and_then(parse_dimen_to_px),
                });
            }
            "corners" => {
                corners.all          = child.attr("android:radius")           .and_then(parse_dimen_to_px);
                corners.top_left     = child.attr("android:topLeftRadius")    .and_then(parse_dimen_to_px);
                corners.top_right    = child.attr("android:topRightRadius")   .and_then(parse_dimen_to_px);
                corners.bottom_left  = child.attr("android:bottomLeftRadius") .and_then(parse_dimen_to_px);
                corners.bottom_right = child.attr("android:bottomRightRadius").and_then(parse_dimen_to_px);
            }
            "padding" => {
                padding.left   = child.attr("android:left")  .and_then(parse_dimen_to_px).unwrap_or(0);
                padding.top    = child.attr("android:top")   .and_then(parse_dimen_to_px).unwrap_or(0);
                padding.right  = child.attr("android:right") .and_then(parse_dimen_to_px).unwrap_or(0);
                padding.bottom = child.attr("android:bottom").and_then(parse_dimen_to_px).unwrap_or(0);
            }
            "size" => {
                intrinsic_width  = child.attr("android:width") .and_then(parse_dimen_to_px);
                intrinsic_height = child.attr("android:height").and_then(parse_dimen_to_px);
            }
            "gradient" => {
                let kind = match child.attr("android:type").unwrap_or("linear") {
                    "radial" => GradientKind::Radial,
                    "sweep"  => GradientKind::Sweep,
                    _        => GradientKind::Linear,
                };
                let attr_f32 = |name: &str, default: f32| -> f32 {
                    child.attr(name).and_then(|s| s.parse().ok()).unwrap_or(default)
                };
                gradient = Some(Gradient {
                    kind,
                    start_color: child.attr("android:startColor").unwrap_or("#000000").to_string(),
                    end_color:   child.attr("android:endColor")  .unwrap_or("#FFFFFF").to_string(),
                    center_color: child.attr("android:centerColor").map(String::from),
                    angle:    attr_f32("android:angle",   0.0),
                    center_x: attr_f32("android:centerX", 0.5),
                    center_y: attr_f32("android:centerY", 0.5),
                    gradient_radius: child.attr("android:gradientRadius").and_then(parse_dimen_to_px),
                });
            }
            _ => {}
        }
    }

    ShapeDrawable {
        shape_kind, solid_color, stroke, corners, padding, gradient,
        intrinsic_width, intrinsic_height,
    }
}
