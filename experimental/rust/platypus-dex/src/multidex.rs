/// Multi-DEX container — translates vm/vm.py's `add_dex_files` + `lookup_map` logic.
///
/// `MultiDex` owns a collection of `DexFileWithRaw` instances and maintains a
/// unified lookup map so callers can resolve class names and method names across
/// all loaded DEX files in one shot.

use std::collections::HashMap;

use super::parser::{ClassDefItem, DexFileWithRaw, MethodIdItem};

// ── Lookup entry ─────────────────────────────────────────────────────────────

/// Identifies where a class lives inside the `MultiDex::dex_files` vector.
#[derive(Debug, Clone, Copy)]
pub struct MultiDexEntry {
    /// Index into `MultiDex::dex_files`.
    pub dex_idx: usize,
    /// Index into `dex_files[dex_idx].parsed.class_defs`.
    pub class_def_idx: usize,
}

// ── MultiDex ─────────────────────────────────────────────────────────────────

/// Aggregates multiple DEX files into a single lookup namespace.
///
/// Class-name keys are stored in the DEX descriptor form `Ljava/lang/String;`.
/// The first DEX file that defines a given class wins; duplicates in later files
/// are silently ignored (matching Python's behaviour).
pub struct MultiDex {
    pub dex_files: Vec<DexFileWithRaw>,
    /// Maps descriptor → (dex_idx, class_def_idx).
    pub lookup: HashMap<String, MultiDexEntry>,
}

impl MultiDex {
    // ── Construction ─────────────────────────────────────────────────────────

    pub fn new() -> Self {
        MultiDex {
            dex_files: Vec::new(),
            lookup: HashMap::new(),
        }
    }

    /// Load a DEX file and register every class it defines.
    ///
    /// The first DEX file to define a class name wins; subsequent files whose
    /// class set overlaps are accepted but the duplicate entries are skipped.
    pub fn add_dex_file(&mut self, dex: DexFileWithRaw) {
        let dex_idx = self.dex_files.len();

        for (class_def_idx, class_def) in dex.parsed.class_defs.iter().enumerate() {
            // Normalise the key to the bare descriptor form.
            let key = normalize_class_owned(&class_def.type_name);

            // First-wins: skip if another DEX already claimed this class.
            self.lookup.entry(key).or_insert(MultiDexEntry {
                dex_idx,
                class_def_idx,
            });
        }

        self.dex_files.push(dex);
    }

    // ── Lookups ───────────────────────────────────────────────────────────────

    /// Find a class by name.
    ///
    /// `class_name` may be in any of these forms:
    /// - `Ljava/lang/String;`  (descriptor — stored as-is after strip)
    /// - `java/lang/String`    (already stripped)
    /// - `java.lang.String`    (dot-separated — NOT normalised here; caller must
    ///                          pass slashes or a descriptor)
    ///
    /// Returns `(owning DEX file, ClassDefItem reference)` or `None`.
    pub fn find_class(&self, class_name: &str) -> Option<(&DexFileWithRaw, &ClassDefItem)> {
        let key = normalize_class(class_name);
        let entry = self.lookup.get(key)?;
        let dex = &self.dex_files[entry.dex_idx];
        let class_def = &dex.parsed.class_defs[entry.class_def_idx];
        Some((dex, class_def))
    }

    /// Find a method by class name and method name.
    ///
    /// Searches the `method_ids` table of the DEX that owns the class, matching
    /// on the resolved class name and the bare method name.
    ///
    /// Returns `(owning DEX file, MethodIdItem reference, absolute method index)`
    /// or `None` if not found.
    pub fn find_method(
        &self,
        class_name: &str,
        method_name: &str,
    ) -> Option<(&DexFileWithRaw, &MethodIdItem, usize)> {
        // Resolve the class first so we know which DEX owns it.
        let (dex, class_def) = self.find_class(class_name)?;

        // The class's type descriptor as stored in the DEX method_ids table.
        let target_class = &class_def.type_name;

        for (idx, method_id) in dex.parsed.method_ids.iter().enumerate() {
            if &method_id.class_name == target_class && method_id.method_name == method_name {
                return Some((dex, method_id, idx));
            }
        }

        None
    }

    // ── Statistics ────────────────────────────────────────────────────────────

    /// Total number of unique classes across all loaded DEX files.
    pub fn class_count(&self) -> usize {
        self.lookup.len()
    }

    /// Total number of method_id entries across all loaded DEX files (may
    /// include duplicates if the same method appears in multiple DEX files).
    pub fn method_count(&self) -> usize {
        self.dex_files
            .iter()
            .map(|d| d.parsed.method_ids.len())
            .sum()
    }
}

impl Default for MultiDex {
    fn default() -> Self {
        Self::new()
    }
}

// ── Normalisation helpers ────────────────────────────────────────────────────

/// Strip the leading `L` and trailing `;` from a DEX class descriptor.
///
/// Examples:
/// - `Ljava/lang/String;` → `java/lang/String`
/// - `java/lang/String`   → `java/lang/String`  (already bare — returned as-is)
///
/// Returns a sub-slice of the original string, so no allocation is needed.
pub fn normalize_class(name: &str) -> &str {
    let s = name.strip_prefix('L').unwrap_or(name);
    s.strip_suffix(';').unwrap_or(s)
}

/// Owned version of `normalize_class` — allocates only when the input needs
/// stripping.
fn normalize_class_owned(name: &str) -> String {
    normalize_class(name).to_string()
}
