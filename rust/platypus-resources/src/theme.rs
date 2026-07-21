//! Active-theme resolution + bundled defaults.
//!
//! A [`Theme`] is the effective attribute table the renderer queries when it
//! sees `?attr/colorPrimary` (or `?colorPrimary`). It's built by:
//!
//! 1. Walking the parent chain of the manifest-declared theme via
//!    [`crate::style::flatten_style_chain`], producing a flattened
//!    attribute map.
//! 2. Falling back to a bundled Material 3 / Material You defaults table
//!    for any attribute not defined in the chain — most apps inherit from
//!    `Theme.Material3.DayNight`/`Light`/`Dark` and don't override
//!    everything, so without this fallback `?attr/colorSurface` would just
//!    be missing.
//!
//! The bundled defaults aren't byte-identical to whatever framework version
//! the device shipped — they're a reasonable Material You light-theme set
//! good enough for static reconstruction. Renderers that need exact pixel
//! parity should query the live device.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use platypus_apk::arsc::ResourceTable;

use crate::style::{flatten_style_chain, Style, StyleAttribute};

/// Effective theme — what the renderer should actually consult.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Theme {
    /// Resource id of the theme as declared on the manifest. `0` if no
    /// `android:theme` was set and we're using only bundled defaults.
    pub id: u32,
    /// Theme display name (`Theme.MyApp`, `Theme.Material3.DayNight`, …).
    pub name: String,
    /// Flattened style chain (id → StyleAttribute), keyed by attr id.
    pub attrs: HashMap<u32, StyleAttribute>,
}

impl Theme {
    /// Resolve a `?attr/<name>` reference. Returns the attribute value as
    /// a string (same convention as [`StyleAttribute::value`]). Looks up
    /// by name across all attrs in the theme — slower than by-id but the
    /// caller usually only has the textual reference.
    pub fn attr_by_name(&self, name: &str) -> Option<&StyleAttribute> {
        self.attrs.values().find(|a| a.name == name)
    }

    /// Resolve a `?attr/<id>` reference by raw attribute id (faster than
    /// the name-based lookup).
    pub fn attr_by_id(&self, attr_id: u32) -> Option<&StyleAttribute> {
        self.attrs.get(&attr_id)
    }

    /// All attribute names defined on this theme — useful for dumping /
    /// debugging.
    pub fn attribute_names(&self) -> Vec<&str> {
        let mut out: Vec<&str> = self.attrs.values().map(|a| a.name.as_str()).collect();
        out.sort();
        out
    }
}

/// Build a theme from a resource id (typically the value of
/// `<application android:theme>` or `<activity android:theme>`).
///
/// Walks the parent chain via [`flatten_style_chain`], then layers the
/// bundled Material 3 defaults underneath any attribute the chain didn't
/// already define.
pub fn resolve_theme(theme_id: u32, table: &ResourceTable) -> Theme {
    let style: Option<Style> = if theme_id != 0 {
        flatten_style_chain(theme_id, table)
    } else {
        None
    };

    let (id, name, mut attrs) = match style {
        Some(s) => (s.id, s.name, s.attrs),
        None => (0, "<defaults>".to_string(), HashMap::new()),
    };

    // Layer in defaults — only fill gaps.
    for (attr_id, attr) in material3_defaults() {
        attrs.entry(attr_id).or_insert(attr);
    }

    Theme { id, name, attrs }
}

/// Build a theme purely from the bundled defaults — useful when an app
/// doesn't declare a theme at all (rare) or for previewing.
pub fn default_theme() -> Theme {
    Theme {
        id: 0,
        name: "<material3-defaults>".to_string(),
        attrs: material3_defaults().into_iter().collect(),
    }
}

// ── Bundled Material 3 defaults ───────────────────────────────────────────

/// Material 3 light-theme defaults, keyed by framework attribute id.
///
/// These are the values you'd see if your app inherited from
/// `Theme.Material3.DayNight` and never overrode anything. ARGB colors
/// are encoded as 0xAARRGGBB and stored with `data_type = 0x1c`
/// (TYPE_INT_COLOR_ARGB8).
fn material3_defaults() -> Vec<(u32, StyleAttribute)> {
    // Material 3 baseline palette (M3 spec, light theme).
    let primary           = 0xff6750a4u32;
    let primary_dark      = 0xff4f378bu32;
    let on_primary        = 0xffffffffu32;
    let secondary         = 0xff625b71u32;
    let surface           = 0xfffffbfeu32;
    let on_surface        = 0xff1c1b1fu32;
    let on_surface_var    = 0xff49454fu32;
    let outline           = 0xff79747eu32;
    let background        = 0xfffffbfeu32;
    let error             = 0xffb3261eu32;
    let control_normal    = 0xff49454fu32;
    let control_highlight = 0x1f000000u32; // 12% black

    let color = |name: &'static str, attr_id: u32, package: Option<&'static str>, argb: u32| -> (u32, StyleAttribute) {
        (
            attr_id,
            StyleAttribute {
                attr_id,
                name: name.to_string(),
                package: package.map(|s| s.to_string()),
                data_type: 0x1c, // TYPE_INT_COLOR_ARGB8
                data: argb,
                value: format!("#{:08x}", argb),
                inherited: true,
            },
        )
    };

    let dimen = |name: &'static str, attr_id: u32, package: Option<&'static str>, complex: u32, formatted: &str| -> (u32, StyleAttribute) {
        (
            attr_id,
            StyleAttribute {
                attr_id,
                name: name.to_string(),
                package: package.map(|s| s.to_string()),
                data_type: 0x05, // TYPE_DIMENSION
                data: complex,
                value: formatted.to_string(),
                inherited: true,
            },
        )
    };

    let bool_v = |name: &'static str, attr_id: u32, package: Option<&'static str>, b: bool| -> (u32, StyleAttribute) {
        (
            attr_id,
            StyleAttribute {
                attr_id,
                name: name.to_string(),
                package: package.map(|s| s.to_string()),
                data_type: 0x12, // TYPE_INT_BOOLEAN
                data: if b { 0xffffffff } else { 0 },
                value: if b { "true".to_string() } else { "false".to_string() },
                inherited: true,
            },
        )
    };

    vec![
        // Material colors (framework slot).
        color("colorPrimary",            0x01010435, Some("android"), primary),
        color("colorPrimaryDark",        0x01010434, Some("android"), primary_dark),
        color("colorAccent",             0x01010438, Some("android"), secondary),
        color("colorControlNormal",      0x01010439, Some("android"), control_normal),
        color("colorControlActivated",   0x0101043a, Some("android"), primary),
        color("colorControlHighlight",   0x0101043b, Some("android"), control_highlight),
        color("colorButtonNormal",       0x0101043c, Some("android"), surface),

        // Window backgrounds.
        color("windowBackground",        0x01010054, Some("android"), background),
        color("statusBarColor",          0x01010436, Some("android"), primary_dark),
        color("navigationBarColor",      0x01010437, Some("android"), surface),

        // Text colors.
        color("textColorPrimary",        0x01010098, Some("android"), on_surface),
        color("textColorSecondary",      0x01010099, Some("android"), on_surface_var),
        color("textColorTertiary",       0x0101009a, Some("android"), outline),

        // Text size — 14sp default body, encoded as TYPE_DIMENSION with
        // unit=sp (0x02) and 14.0 in 23.8 fixed-point. Using a friendly
        // pre-formatted string the renderer can re-parse.
        dimen("textSize",                0x01010034, Some("android"), 0x00000e02, "14.0sp"),

        // Common windowing flags.
        bool_v("windowNoTitle",          0x01010056, Some("android"), false),
        bool_v("windowFullscreen",       0x010102d7, Some("android"), false),
        bool_v("windowActionBar",        0x010102d6, Some("android"), true),

        // Synthesised app-side names that aren't framework attrs but renderers
        // commonly want — keyed under arbitrary high IDs in our private
        // namespace (top byte 0x00 = reserved/private). These won't collide
        // with real attrs.
        color("colorOnPrimary",          0x00000001, None, on_primary),
        color("colorSurface",            0x00000002, None, surface),
        color("colorOnSurface",          0x00000003, None, on_surface),
        color("colorOnSurfaceVariant",   0x00000004, None, on_surface_var),
        color("colorError",              0x00000005, None, error),
        color("colorOutline",            0x00000006, None, outline),
    ]
}
