//! Selector (state list) drawable parser.
//!
//! `<selector>` picks one drawable per view state — pressed, focused,
//! enabled/disabled, etc. Items are ordered: first matching item wins.
//!
//! ```xml
//! <selector>
//!     <item android:state_pressed="true" android:drawable="@drawable/btn_pressed"/>
//!     <item android:state_focused="true" android:drawable="@drawable/btn_focused"/>
//!     <item android:drawable="@drawable/btn_default"/>      <!-- catch-all -->
//! </selector>
//! ```

use serde::{Deserialize, Serialize};

use platypus_apk::axml::XmlNode;
use platypus_apk::zip::ApkZip;

use super::{dispatch_xml, resolve_value_no_table, Drawable};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectorDrawable {
    pub items: Vec<SelectorItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SelectorItem {
    pub state: ViewState,
    pub drawable: Box<Drawable>,
}

/// Subset of view states Android cares about. We model the common ones;
/// uncommon attributes (`state_window_focused`, `state_drag_can_accept`)
/// fall through to `Default`. Multiple states on one item collapse to the
/// most specific match in this priority order.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ViewState {
    Pressed,
    Focused,
    Selected,
    Activated,
    Hovered,
    Checked,
    Disabled,
    Default,
}

pub(crate) fn parse(apk: &ApkZip, node: XmlNode) -> SelectorDrawable {
    let items = node.children.iter()
        .filter(|c| c.tag == "item")
        .map(|c| parse_item(apk, c))
        .collect();
    SelectorDrawable { items }
}

fn parse_item(apk: &ApkZip, item: &XmlNode) -> SelectorItem {
    let state = classify_state(item);

    // Drawable can be either an `android:drawable="…"` attribute or an
    // inline child element.
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

    SelectorItem { state, drawable: Box::new(drawable) }
}

/// Walk an item's attributes and pick the most-specific positive state.
fn classify_state(item: &XmlNode) -> ViewState {
    fn truthy(v: Option<&str>) -> bool {
        v.map(|s| s == "true").unwrap_or(false)
    }
    if truthy(item.attr("android:state_pressed"))   { return ViewState::Pressed;   }
    if truthy(item.attr("android:state_focused"))   { return ViewState::Focused;   }
    if truthy(item.attr("android:state_selected"))  { return ViewState::Selected;  }
    if truthy(item.attr("android:state_activated")) { return ViewState::Activated; }
    if truthy(item.attr("android:state_hovered"))   { return ViewState::Hovered;   }
    if truthy(item.attr("android:state_checked"))   { return ViewState::Checked;   }
    // `state_enabled="false"` means the item applies when disabled.
    if item.attr("android:state_enabled") == Some("false") { return ViewState::Disabled; }
    ViewState::Default
}
