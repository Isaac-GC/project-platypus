//! Style and theme resolution.
//!
//! In compiled resources, a `<style>` (and a `<style>` used as a theme — same
//! thing, different intent) becomes an ARSC *bag entry*: a parent resource id
//! plus a list of `(attribute_id, value)` pairs.
//!
//! This module turns those bag entries into a typed [`Style`] and adds:
//!
//! * **Parent-chain resolution** — `R.style.MyButton` inherits from
//!   `R.style.Widget.Material.Button`; this module walks that chain and
//!   produces a flattened attribute map (child attrs win).
//!
//! * **Attribute name mapping** — bag items reference attributes by numeric
//!   id (e.g. `0x01010435`). For app-defined attrs we look them up by id in
//!   the table (type = `attr`); for framework attrs we fall back to a
//!   bundled table of well-known names ([`framework_attr_name`]). Unknown
//!   ids are kept as `0x...` strings.
//!
//! * **Theme resolution** — `?attr/colorPrimary` is resolved against an
//!   effective theme: walk the active theme's chain → fall back to the
//!   bundled Material 3 defaults in [`crate::theme`].
//!
//! Themes vs. styles: at the binary level there's no difference. The
//! manifest's `android:theme` attribute on `<application>` / `<activity>`
//! picks one bag entry as the active theme; everything else is just a style
//! a `View`'s `style="..."` attribute can point at.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use platypus_apk::arsc::{BagEntry, ResourceTable};

/// A flattened style — parent chain merged into a single attribute map.
///
/// "Flattened" means: parent attributes are included, but a child's
/// `(attr_id, value)` overrides any parent's. This is how the Android
/// framework actually applies a style.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Style {
    /// Resource id of this style (e.g. `0x7f0d0001`).
    pub id:        u32,
    /// Style name (`Theme.MyApp.NoActionBar`, `Widget.MyApp.Button`, …).
    pub name:      String,
    /// Parent style id, or `0` if there's no parent.
    pub parent_id: u32,
    /// Flattened attributes. Keyed by `attr_id` (rendered as decimal in
    /// JSON because JSON map keys must be strings) for fast `?attr/x` lookup.
    pub attrs:     HashMap<u32, StyleAttribute>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StyleAttribute {
    pub attr_id:   u32,
    /// Best-effort attribute name. Resolved via the resources table for
    /// app attrs, or the bundled framework table. Falls back to `attr_<id>`.
    pub name:      String,
    /// `Some("android")` for framework attrs; `None` for app attrs.
    pub package:   Option<String>,
    /// Raw `data_type` from `Res_value` (0x01 = ref, 0x03 = string,
    /// 0x10 = int, 0x1c-0x1f = colors, …). Matches the format used by
    /// [`platypus_apk::arsc::BagItem`].
    pub data_type: u8,
    /// Raw `data` field — interpretation depends on `data_type`.
    pub data:      u32,
    /// Pre-formatted string view (same convention as
    /// [`platypus_apk::arsc::BagItem::value`]).
    pub value:     String,
    /// True when this attribute came from a parent (or grandparent) rather
    /// than the style itself. Useful for tooling that wants to render the
    /// inheritance source.
    pub inherited: bool,
}

/// Build a [`Style`] from a single bag entry.
///
/// This does **not** walk the parent chain — for that use
/// [`flatten_style_chain`].
pub fn style_from_bag(
    id: u32,
    name: &str,
    bag: &BagEntry,
    table: &ResourceTable,
) -> Style {
    let mut attrs = HashMap::with_capacity(bag.items.len());
    for item in &bag.items {
        let (a_name, a_pkg) = attr_name_and_package(item.attr_id, table);
        attrs.insert(
            item.attr_id,
            StyleAttribute {
                attr_id:   item.attr_id,
                name:      a_name,
                package:   a_pkg,
                data_type: item.data_type,
                data:      item.data,
                value:     item.value.clone(),
                inherited: false,
            },
        );
    }
    Style {
        id,
        name: name.to_string(),
        parent_id: bag.parent_id,
        attrs,
    }
}

/// Walk the parent chain starting from `id`, flattening the inherited
/// attributes into a single style. Child attributes win.
///
/// Cycle-safe (depth limit + visited set).
pub fn flatten_style_chain(id: u32, table: &ResourceTable) -> Option<Style> {
    let mut visited: Vec<u32> = Vec::new();
    let mut current = id;
    let mut merged: Option<Style> = None;
    let mut depth = 0;

    loop {
        if depth > 16 || visited.contains(&current) || current == 0 {
            break;
        }
        visited.push(current);
        depth += 1;

        let entry = match table.get(current) {
            Some(e) => e,
            None => break,
        };
        let bag = match entry.bag.as_ref() {
            Some(b) => b,
            None => break,
        };
        let parent = bag.parent_id;
        let level = style_from_bag(current, &entry.name, bag, table);

        merged = Some(match merged {
            None => level,
            Some(mut child) => {
                // Child already populated; treat `level` as parent — only
                // import attrs the child doesn't already define.
                for (k, mut v) in level.attrs {
                    child.attrs.entry(k).or_insert_with(|| {
                        v.inherited = true;
                        v
                    });
                }
                child
            }
        });

        if parent == 0 || parent == current {
            break;
        }
        current = parent;
    }

    merged
}

/// Look up an attribute name from its resource id.
///
/// 1. If the id is an app attr (`type=attr`) present in the resources table,
///    return its key name.
/// 2. Otherwise check the bundled framework attr table.
/// 3. Otherwise return `attr_<hex_id>`.
pub fn attr_name_and_package(attr_id: u32, table: &ResourceTable) -> (String, Option<String>) {
    // Framework: package id 0x01.
    let pkg_id = (attr_id >> 24) & 0xff;
    if pkg_id == 0x01 {
        if let Some(name) = framework_attr_name(attr_id) {
            return (name.to_string(), Some("android".to_string()));
        }
        return (format!("attr_{:08x}", attr_id), Some("android".to_string()));
    }

    // App attr: look it up in the table.
    if let Some(entry) = table.get(attr_id) {
        if entry.type_name == "attr" && !entry.name.is_empty() {
            return (entry.name.clone(), None);
        }
    }
    (format!("attr_{:08x}", attr_id), None)
}

/// Friendly name for a framework attribute id.
///
/// Hand-curated subset of `android.R.attr.*` — covers attributes commonly
/// referenced by Material / AppCompat themes. For anything not in here the
/// caller falls back to `attr_<hex>`.
///
/// Source: `frameworks/base/core/res/res/values/public.xml` (locked once
/// added — these ids are stable across API levels).
pub fn framework_attr_name(id: u32) -> Option<&'static str> {
    Some(match id {
        // Text appearance / typography
        0x01010034 => "textSize",
        0x01010095 => "textColor",
        0x01010098 => "textColorPrimary",
        0x01010099 => "textColorSecondary",
        0x0101009a => "textColorTertiary",
        0x0101009b => "textColorPrimaryInverse",
        0x0101009c => "textColorSecondaryInverse",
        0x0101009d => "textColorTertiaryInverse",
        0x01010097 => "textStyle",
        0x01010096 => "typeface",
        0x010100af => "gravity",
        0x010100ee => "textAppearance",

        // Padding & layout
        0x010100f4 => "padding",
        0x010100f5 => "paddingLeft",
        0x010100f6 => "paddingTop",
        0x010100f7 => "paddingRight",
        0x010100f8 => "paddingBottom",
        0x010100f9 => "scrollX",
        0x010100fa => "scrollY",
        0x010100f0 => "drawableTop",
        0x010100f1 => "drawableBottom",
        0x010100f2 => "drawableLeft",
        0x010100f3 => "drawableRight",
        0x010100d4 => "background",

        // Window
        0x01010054 => "windowBackground",
        0x01010055 => "windowFrame",
        0x01010056 => "windowNoTitle",
        0x01010057 => "windowIsFloating",
        0x01010058 => "windowIsTranslucent",
        0x01010059 => "windowAnimationStyle",
        0x0101005a => "windowSoftInputMode",
        0x010102d6 => "windowActionBar",
        0x010102d7 => "windowFullscreen",
        0x01010436 => "statusBarColor",
        0x01010437 => "navigationBarColor",

        // Material colors (since API 21)
        0x01010435 => "colorPrimary",
        0x01010434 => "colorPrimaryDark",
        0x01010438 => "colorAccent",
        0x01010439 => "colorControlNormal",
        0x0101043a => "colorControlActivated",
        0x0101043b => "colorControlHighlight",
        0x0101043c => "colorButtonNormal",

        // Common widget attrs
        0x010100b3 => "minWidth",
        0x010100b4 => "minHeight",
        0x01010140 => "maxWidth",
        0x01010141 => "maxHeight",
        0x010101e7 => "src",
        0x010100b2 => "scaleType",
        0x010100b1 => "tint",
        0x01010119 => "orientation",

        // Theme parents commonly referenced
        0x010100c1 => "parent",
        0x010100c0 => "name",

        _ => return None,
    })
}
