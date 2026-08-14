//! Higher-level query interface over [`ResourceTable`].
//!
//! [`ResourceTable`] from `platypus-apk` is a flat list of entries; this
//! wrapper indexes them into per-(type, name) and per-id maps for O(1)
//! lookups and adds reference-resolution helpers.
//!
//! Configuration qualifiers (`values-en`, `values-hdpi`, `values-v21`, …)
//! aren't parsed by the underlying [`ResourceTable`] yet, so they're not
//! exposed here either — when that lands the `*_for_config` accessors below
//! become useful. The current implementation returns the default-config
//! value for everything.

use std::collections::HashMap;

use crate::refs::{parse_reference, resolve, Reference};
use crate::{ResourceEntry, ResourceTable};

pub struct Resources {
    table: ResourceTable,
    by_id: HashMap<u32, usize>,                   // res_id → index into entries
    by_type_and_name: HashMap<(String, String), usize>,
}

impl Resources {
    /// Build the index from a parsed table.
    pub fn new(table: ResourceTable) -> Self {
        let mut by_id = HashMap::new();
        let mut by_type_and_name = HashMap::new();
        for (i, e) in table.entries().iter().enumerate() {
            by_id.insert(e.id, i);
            by_type_and_name.insert((e.type_name.clone(), e.name.clone()), i);
        }
        Self { table, by_id, by_type_and_name }
    }

    /// The wrapped underlying table — still useful for serialisation /
    /// callers that want the raw list.
    pub fn table(&self) -> &ResourceTable {
        &self.table
    }

    /// Total number of resource entries.
    pub fn len(&self) -> usize {
        self.table.entries().len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.entries().is_empty()
    }

    /// Distinct type names present in the resources (e.g. `["string",
    /// "drawable", "layout", "color", "dimen", ...]`).
    pub fn types(&self) -> Vec<String> {
        let mut seen: HashMap<String, ()> = HashMap::new();
        for e in self.table.entries() {
            seen.insert(e.type_name.clone(), ());
        }
        let mut out: Vec<String> = seen.into_keys().collect();
        out.sort();
        out
    }

    // ── Lookup by id ─────────────────────────────────────────────────────

    /// Get the full entry for a resource id.
    pub fn get(&self, id: u32) -> Option<&ResourceEntry> {
        let idx = self.by_id.get(&id)?;
        Some(&self.table.entries()[*idx])
    }

    /// Resolve a resource id to its final string value, following any
    /// `@-reference` chain in the table.
    pub fn resolve(&self, id: u32) -> Option<String> {
        self.table.resolve(id)
    }

    /// String-by-id (only returns a value for `type=string` entries; for
    /// drawables/layouts/etc. use [`get`] or [`resolve`]).
    pub fn string(&self, id: u32) -> Option<&str> {
        self.table.get_string(id)
    }

    // ── Lookup by name ───────────────────────────────────────────────────

    /// `R.string.app_name` style: look up the id of `(type_name, name)`.
    pub fn id_by_name(&self, type_name: &str, name: &str) -> Option<u32> {
        let idx = self.by_type_and_name.get(&(type_name.to_string(), name.to_string()))?;
        Some(self.table.entries()[*idx].id)
    }

    /// `R.string.app_name` → "Hello world".
    pub fn string_by_name(&self, name: &str) -> Option<String> {
        let id = self.id_by_name("string", name)?;
        self.resolve(id)
    }

    /// Layout file path for `R.layout.activity_main`. Returns the underlying
    /// stored value, typically `res/layout/activity_main.xml`.
    pub fn layout_path(&self, name: &str) -> Option<String> {
        let id = self.id_by_name("layout", name)?;
        self.resolve(id)
    }

    /// Drawable file path / inline color for `R.drawable.icon`.
    pub fn drawable_path(&self, name: &str) -> Option<String> {
        let id = self.id_by_name("drawable", name)?;
        self.resolve(id)
    }

    /// Mipmap (launcher icons live here on modern apps).
    pub fn mipmap_path(&self, name: &str) -> Option<String> {
        let id = self.id_by_name("mipmap", name)?;
        self.resolve(id)
    }

    /// Generic: any `(type, name)` resolved to its value.
    pub fn value_by_name(&self, type_name: &str, name: &str) -> Option<String> {
        let id = self.id_by_name(type_name, name)?;
        self.resolve(id)
    }

    // ── Bulk queries ─────────────────────────────────────────────────────

    /// All entries of a given type. Returns `&[&ResourceEntry]` style slice.
    pub fn by_type(&self, type_name: &str) -> Vec<&ResourceEntry> {
        self.table.by_type(type_name)
    }

    /// All `string` resources (id, name, value) — common enough to warrant
    /// its own helper.
    pub fn all_strings(&self) -> Vec<(u32, &str, String)> {
        self.by_type("string").into_iter()
            .map(|e| (e.id, e.name.as_str(), e.value.clone()))
            .collect()
    }

    /// All layout resources — useful for "what layouts does this app define?".
    pub fn all_layouts(&self) -> Vec<&ResourceEntry> {
        self.by_type("layout")
    }

    /// All drawable resources.
    pub fn all_drawables(&self) -> Vec<&ResourceEntry> {
        self.by_type("drawable")
    }

    /// Search entry names by case-insensitive substring across all types.
    /// Returns `(type, name, id)` tuples.
    pub fn search(&self, query: &str) -> Vec<(&str, &str, u32)> {
        let q = query.to_lowercase();
        self.table.entries().iter()
            .filter(|e| e.name.to_lowercase().contains(&q))
            .map(|e| (e.type_name.as_str(), e.name.as_str(), e.id))
            .collect()
    }

    // ── Reference handling ───────────────────────────────────────────────

    /// Take any attribute value (literal or `@type/name`/`@0xID`) and
    /// return its resolved string. Falls back to the input unchanged when
    /// the reference can't be resolved (or it's a literal).
    pub fn resolve_value(&self, value: &str) -> String {
        if let Some(r) = parse_reference(value) {
            if let Some(v) = self.resolve_reference(&r) {
                return v;
            }
        }
        value.to_string()
    }

    // ── Drawable resolution ─────────────────────────────────────────────

    /// Resolve a drawable resource id to a structured [`Drawable`]. Reads
    /// XML drawables (vector, shape, selector, etc.) from `apk` and parses
    /// them via the [`crate::drawable`] module.
    pub fn resolve_drawable(
        &self,
        apk: &platypus_apk::zip::ApkZip,
        res_id: u32,
    ) -> crate::drawable::Drawable {
        crate::drawable::resolve(&self.table, apk, res_id, 8)
    }

    /// Same as [`resolve_drawable`] but looks up by name first.
    pub fn resolve_drawable_by_name(
        &self,
        apk: &platypus_apk::zip::ApkZip,
        name: &str,
    ) -> Option<crate::drawable::Drawable> {
        let id = self.id_by_name("drawable", name)
            .or_else(|| self.id_by_name("mipmap", name))?;
        Some(self.resolve_drawable(apk, id))
    }

    /// Resolve any attribute value (literal color / `@drawable/foo` / direct
    /// path) to a structured Drawable. Use for `android:background`,
    /// `android:src`, `android:drawable` etc.
    pub fn resolve_drawable_value(
        &self,
        apk: &platypus_apk::zip::ApkZip,
        value: &str,
    ) -> crate::drawable::Drawable {
        crate::drawable::resolve_value(&self.table, apk, value, 8)
    }

    // ── Styles & themes ──────────────────────────────────────────────────

    /// Resolve a `R.style.<name>` to a flattened [`crate::style::Style`]
    /// (parent chain merged in). Returns `None` if the style isn't a bag
    /// entry or doesn't exist.
    pub fn style_by_name(&self, name: &str) -> Option<crate::style::Style> {
        let id = self.id_by_name("style", name)?;
        crate::style::flatten_style_chain(id, &self.table)
    }

    /// Resolve a style id to a flattened [`crate::style::Style`].
    pub fn style(&self, id: u32) -> Option<crate::style::Style> {
        crate::style::flatten_style_chain(id, &self.table)
    }

    /// Build the effective [`crate::theme::Theme`] for a theme id (typically
    /// the value of `<application android:theme>` or `<activity android:theme>`).
    /// Falls back to bundled Material 3 defaults for any attribute not
    /// defined in the theme's parent chain.
    pub fn theme(&self, theme_id: u32) -> crate::theme::Theme {
        crate::theme::resolve_theme(theme_id, &self.table)
    }

    /// Same as [`theme`] but looks up the theme by name first
    /// (`Theme.MyApp.NoActionBar`).
    pub fn theme_by_name(&self, name: &str) -> Option<crate::theme::Theme> {
        let id = self.id_by_name("style", name)?;
        Some(self.theme(id))
    }

    /// Convenience: resolve a `?attr/<name>` reference against a given theme,
    /// returning the underlying value as a string. This handles the
    /// `?attr` → final value flow (theme attrs → resource refs → literals).
    pub fn resolve_theme_attr(
        &self,
        theme: &crate::theme::Theme,
        attr_name: &str,
    ) -> Option<String> {
        let attr = theme.attr_by_name(attr_name)?;
        // If the attr's value is itself a reference, follow it.
        if attr.data_type == 0x01 {
            return self.resolve(attr.data);
        }
        Some(attr.value.clone())
    }

    /// Resolve a parsed [`Reference`] through this table.
    pub fn resolve_reference(&self, r: &Reference) -> Option<String> {
        match r {
            Reference::Id(id) => self.resolve_id_typed(*id),
            Reference::Named { type_name, name, package } => {
                if package.as_deref() == Some("android") {
                    // Framework reference — not in app's resources.arsc.
                    return None;
                }
                // For named refs to `id`-type resources, keep the symbolic
                // `@id/<name>` form rather than resolving to the stored
                // boolean — same reasoning as `resolve_id_typed` below.
                if type_name == "id" {
                    return Some(format!("@id/{}", name));
                }
                self.value_by_name(type_name, name)
            }
            // Use the standalone `refs::resolve` for completeness — it
            // handles the same cases but without the by-name index.
            other => resolve(other, &self.table),
        }
    }

    /// Resolve a resource id, with type-aware behaviour:
    ///   * `id`-type resources → `@id/<name>` (Android stores ids as
    ///     boolean markers; the literal value is useless to consumers).
    ///   * Everything else → the entry's value (the original behaviour
    ///     of `Resources::resolve`).
    fn resolve_id_typed(&self, res_id: u32) -> Option<String> {
        let entry = self.get(res_id)?;
        if entry.type_name == "id" {
            return Some(format!("@id/{}", entry.name));
        }
        self.resolve(res_id)
    }
}
