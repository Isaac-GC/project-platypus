//! Layout-XML parsing with optional resource resolution.
//!
//! Android compiles layout XML to the same binary AXML format used for the
//! manifest. We parse it via [`platypus_apk::axml`], then wrap the raw
//! [`XmlNode`] tree in a typed [`Layout`] / [`View`] view that exposes
//! the things callers actually care about (id, text, references).
//!
//! When constructed with a [`Resources`] handle, every attribute value
//! that's a `@string/foo` / `@drawable/bar` / `@dimen/baz` / `@0xID`
//! reference is resolved in place, so callers reading `view.attr("text")`
//! get `"Hello"` instead of `"@string/greeting"`.
//!
//! ## Long-term goal
//! Combined with DEX-side activity-to-layout resolution (find the
//! `setContentView(R.layout.foo)` call inside `onCreate`), this becomes
//! the foundation for "rebuild the visual tree of activity X" — by then
//! the layout tree here can be walked + rendered to an inspector UI.

use platypus_apk::axml;

use crate::manifest::resolve_xml_in_place;
use crate::resources::Resources;
use crate::XmlNode;

/// A parsed layout XML file (e.g. `res/layout/activity_main.xml`).
#[derive(Debug, Clone)]
pub struct Layout {
    /// The root view of the layout tree.
    pub root: View,
    /// `true` iff [`Layout::with_resources`] was used to resolve `@-references`.
    pub resolved: bool,
}

impl Layout {
    /// Parse the binary AXML from raw bytes (no reference resolution).
    pub fn parse(bytes: &[u8]) -> Result<Self, String> {
        let root_xml = axml::parse(bytes).map_err(|e| e.to_string())?;
        Ok(Self {
            root: View::from_xml(root_xml),
            resolved: false,
        })
    }

    /// Parse the binary AXML and resolve every `@-reference` in attribute
    /// values against the supplied [`Resources`].
    ///
    /// References that can't be resolved (framework refs `@android:...`,
    /// theme attrs `?attr/...`, missing entries) are left unchanged.
    pub fn parse_with_resources(bytes: &[u8], resources: &Resources) -> Result<Self, String> {
        let mut root_xml = axml::parse(bytes).map_err(|e| e.to_string())?;
        resolve_xml_in_place(&mut root_xml, resources);
        Ok(Self {
            root: View::from_xml(root_xml),
            resolved: true,
        })
    }

    /// Resolve `@-references` in an already-parsed layout. Returns a new
    /// `Layout` — the original is untouched.
    pub fn resolved(&self, resources: &Resources) -> Self {
        let mut root_xml = self.root.raw.clone();
        resolve_xml_in_place(&mut root_xml, resources);
        Self {
            root: View::from_xml(root_xml),
            resolved: true,
        }
    }

    /// Convenience: total view count (root + descendants).
    pub fn view_count(&self) -> usize {
        fn walk(v: &View) -> usize {
            1 + v.children.iter().map(walk).sum::<usize>()
        }
        walk(&self.root)
    }

    /// Find the first view (DFS) with `android:id="@id/<id>"` (or `@+id/<id>`).
    /// Pass just the id name (e.g. `"submit_button"`).
    pub fn find_by_id(&self, id: &str) -> Option<&View> {
        self.root.find_by_id(id)
    }

    /// Find every view with the given tag (recursively).
    pub fn find_by_tag(&self, tag: &str) -> Vec<&View> {
        let mut out = Vec::new();
        self.root.collect_by_tag(tag, &mut out);
        out
    }

    /// Render the tree as Android XML — useful for inspector UIs.
    pub fn to_xml_string(&self) -> String {
        self.root.raw.to_xml_string()
    }
}

/// One view (or view-group) in a layout tree. Owns its children.
#[derive(Debug, Clone)]
pub struct View {
    /// XML tag — `"TextView"`, `"LinearLayout"`, fully-qualified custom
    /// view class names, etc.
    pub tag: String,
    /// All `(name, value)` attributes in source order. Reference-resolved
    /// when the parent [`Layout`] was built via `parse_with_resources`.
    pub attrs: Vec<(String, String)>,
    pub children: Vec<View>,
    /// The underlying XmlNode — kept for callers who want raw access.
    pub raw: XmlNode,
}

impl View {
    pub fn from_xml(node: XmlNode) -> Self {
        let children = node.children.iter().cloned().map(View::from_xml).collect();
        Self {
            tag: node.tag.clone(),
            attrs: node.attrs.clone(),
            children,
            raw: node,
        }
    }

    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }

    /// Convenience: `android:id` stripped of any `@id/` / `@+id/` / `@android:id/` prefix.
    pub fn id(&self) -> Option<String> {
        let raw = self.attr("android:id")?;
        let s = raw.trim();
        // "@+id/foo" / "@id/foo" / "@android:id/foo" / raw "foo"
        for p in &["@+id/", "@id/", "@android:id/"] {
            if let Some(rest) = s.strip_prefix(p) {
                return Some(rest.to_string());
            }
        }
        Some(s.to_string())
    }

    /// `android:text` with `@string/...` already resolved when the parent
    /// layout was built via `parse_with_resources`. Returns the literal
    /// string in that case, or the raw reference otherwise.
    pub fn text(&self) -> Option<&str> {
        self.attr("android:text")
    }

    /// `android:contentDescription` (accessibility label).
    pub fn content_description(&self) -> Option<&str> {
        self.attr("android:contentDescription")
    }

    /// `android:onClick` handler (method name on the activity).
    pub fn on_click(&self) -> Option<&str> {
        self.attr("android:onClick")
    }

    /// First descendant (DFS) whose [`id`] matches.
    pub fn find_by_id(&self, id: &str) -> Option<&View> {
        if self.id().as_deref() == Some(id) {
            return Some(self);
        }
        for c in &self.children {
            if let Some(found) = c.find_by_id(id) {
                return Some(found);
            }
        }
        None
    }

    fn collect_by_tag<'a>(&'a self, tag: &str, out: &mut Vec<&'a View>) {
        if self.tag == tag {
            out.push(self);
        }
        for c in &self.children {
            c.collect_by_tag(tag, out);
        }
    }
}
