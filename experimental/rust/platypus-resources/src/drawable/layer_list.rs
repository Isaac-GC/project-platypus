//! Layer-list drawable parser.
//!
//! `<layer-list>` stacks drawables back-to-front. Each `<item>` may have
//! left/top/right/bottom insets relative to the bounding box, plus an
//! optional id (rare in static drawables but used by RippleDrawable's
//! `@android:id/mask` convention).

use serde::{Deserialize, Serialize};

use platypus_apk::axml::XmlNode;
use platypus_apk::zip::ApkZip;

use super::{dispatch_xml, parse_dimen_to_px, resolve_value_no_table, Drawable};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayerListDrawable {
    pub items: Vec<LayerItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LayerItem {
    pub drawable: Box<Drawable>,
    /// Optional `android:id` (`@id/foo` stripped to `foo`). Some renderers
    /// branch on well-known ids (e.g. `mask` for ripple).
    pub id: Option<String>,
    pub inset_left: i32,
    pub inset_top: i32,
    pub inset_right: i32,
    pub inset_bottom: i32,
}

pub(crate) fn parse(apk: &ApkZip, node: XmlNode) -> LayerListDrawable {
    let items = node.children.iter()
        .filter(|c| c.tag == "item")
        .map(|c| parse_item(apk, c))
        .collect();
    LayerListDrawable { items }
}

fn parse_item(apk: &ApkZip, item: &XmlNode) -> LayerItem {
    let drawable: Drawable = match item.attr("android:drawable") {
        Some(s) => resolve_value_no_table(apk, s),
        None => match item.children.first() {
            Some(child) => dispatch_xml(apk, child.clone()),
            None => Drawable::Unknown {
                entry_path: String::new(),
                reason: "<item> with no drawable".into(),
            },
        },
    };

    let id = item.attr("android:id").map(|s| {
        s.trim_start_matches("@android:id/")
         .trim_start_matches("@+id/")
         .trim_start_matches("@id/")
         .to_string()
    });

    let inset = |name: &str| -> i32 {
        item.attr(name).and_then(parse_dimen_to_px).unwrap_or(0)
    };

    LayerItem {
        drawable: Box::new(drawable),
        id,
        inset_left:   inset("android:left"),
        inset_top:    inset("android:top"),
        inset_right:  inset("android:right"),
        inset_bottom: inset("android:bottom"),
    }
}
