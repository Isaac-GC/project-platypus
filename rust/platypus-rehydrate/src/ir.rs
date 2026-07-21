//! UnifiedView IR — the single tree representation produced by every
//! rehydration backend (XML now, Compose later) and consumed by every
//! renderer (TreeView R3, HtmlRenderer R1, CanvasRenderer R2).
//!
//! Designed once for the entire phase 0-13 roadmap so we don't have to
//! reshape the IR mid-pipeline. Fields that aren't populated yet (compose
//! source, dynamic modifications, click handlers, navigation) get stubbed
//! with `None`/empty defaults — phases that fill them just write into
//! existing fields rather than redesigning the type.

use serde::{Deserialize, Serialize};

// ── Top-level entry: per-activity view tree ─────────────────────────────────

/// Result of rehydrating one activity. The `root` is `None` when no layout
/// could be discovered (activity has no `setContentView` call, uses Compose
/// without phase-12 support, or the layout file is missing).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivityView {
    /// Fully-qualified activity class name, e.g. `"com.example.MainActivity"`.
    pub activity_name: String,
    /// Resource id of the root layout if discovered (e.g. `0x7f0a0001`).
    pub layout_id: Option<u32>,
    /// Layout file path if resolved, e.g. `"res/layout/activity_main.xml"`.
    pub layout_path: Option<String>,
    /// Resolved + expanded view tree. `None` when discovery failed (see
    /// `diagnostics` for the reason).
    pub root: Option<UnifiedView>,
    /// Per-activity warnings — missing layouts, unresolved styles, Compose
    /// fall-through, etc. The renderer surfaces these so analysts know
    /// *why* something didn't render rather than just seeing a blank screen.
    pub diagnostics: Vec<Diagnostic>,
    /// All distinct navigation transitions reachable from this activity —
    /// the union of every `NavTarget` attached to a view PLUS any
    /// navigation found in lifecycle methods (`onCreate` etc.) that isn't
    /// tied to a click. Feeds the cross-activity navigation graph view.
    pub outgoing_navigations: Vec<NavTarget>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub message: String,
    /// Optional location hint — view id, file path, method ref.
    pub location: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    /// Worth knowing about, doesn't break rendering.
    Info,
    /// Some content couldn't be reconstructed (e.g. fragment placeholder).
    Warning,
    /// Fundamental gap — rendered tree is misleading without manual review.
    Error,
}

// ── The unified view node ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnifiedView {
    /// Where this node came from in source (XML file, Compose function, etc).
    pub source: ViewSource,
    /// Coarse classification — what kind of view this is. Renderers branch
    /// on this for layout/paint behaviour.
    pub kind: ViewKind,
    /// Original XML tag (or Compose function name) — useful when `kind` is
    /// generic (`Custom`, `Other`).
    pub tag: String,
    /// `android:id` value with `@id/` / `@+id/` prefixes stripped. `None`
    /// when no id was assigned.
    pub id: Option<String>,
    /// All resolved attributes. Order is source order; reference values
    /// have already been resolved via `Resources::resolve_value`.
    pub attrs: Vec<Attribute>,
    /// Children in source order. Empty for leaf views.
    pub children: Vec<UnifiedView>,
    /// Click / long-click / focus handler if statically discoverable.
    /// Populated in phase 7 (XML `android:onClick` + DEX `setOnClickListener`).
    pub click_handler: Option<Handler>,
    /// Where this view navigates if clicked — resolved in phase 8.
    pub navigation: Option<NavTarget>,
    /// Post-inflation modifications discovered via DEX analysis (phase 9):
    /// `findViewById(R.id.x).setText("…")`, `setVisibility(GONE)`, etc.
    pub dynamic_modifications: Vec<DynMod>,
    /// For list-host views (RecyclerView/ListView/GridView/ViewPager):
    /// the recovered item-row template — resolved in phase 10 by tracing
    /// `setAdapter` → adapter class → `onCreateViewHolder` → `inflate(R.layout.X)`.
    /// Renderers repeat this template a few times instead of showing a
    /// generic placeholder. `None` for non-list views and for list views
    /// where the adapter's item layout couldn't be recovered.
    pub item_template: Option<Box<UnifiedView>>,
    /// Pre-resolved drawables, keyed by attribute name. For any attribute
    /// whose value is a drawable reference (`@drawable/foo`,
    /// `@android:drawable/bar`, a color literal, or a direct path), the
    /// builder pre-resolves it through `Resources::resolve_drawable_value`
    /// and stuffs the structured result here.
    ///
    /// Renderers consult this map for `background` / `src` / `srcCompat` /
    /// `drawable` / `foreground` / `icon` attributes — vector drawables
    /// arrive as ready-to-use SVG strings, shapes as typed colour/corner/
    /// stroke records, etc. Color literals get a `{kind: "color", rgba}`
    /// entry too so renderers don't have to hex-parse the attribute value.
    ///
    /// Empty for views that don't reference any drawables.
    #[serde(default)]
    pub drawables: std::collections::HashMap<String, serde_json::Value>,
}

/// Where this node was reconstructed from. Useful for the "go to source"
/// affordance in the inspector and for diagnosing reconstruction issues.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase", tag = "kind")]
pub enum ViewSource {
    /// Defined in a layout XML file at this path.
    Xml { layout_path: String },
    /// Inlined into the parent via `<include layout="@layout/x">`. We track
    /// the include source so the inspector can show the boundary.
    Included { from_layout_path: String, included_layout_path: String },
    /// Inlined into the parent via `<merge>`.
    Merged { from_layout_path: String },
    /// Replaced from a `<ViewStub android:layout="…">` at inflate time.
    StubInflated { stub_layout_path: String, target_layout_path: String },
    /// Compose-emitted — we know the @Composable that produced this. Filled
    /// in phase 12.
    Compose { method_ref: String },
    /// Synthesised by the rehydrate pipeline — placeholder for things we
    /// can't recover (fragments without static binding, lazy lists, etc.).
    Synthetic,
}

/// Coarse classification of view kinds. Renderers use this for layout
/// semantics. Custom/unknown kinds preserve the tag string for inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase", tag = "kind")]
pub enum ViewKind {
    // ── Layout containers ──
    LinearLayout,
    RelativeLayout,
    FrameLayout,
    ConstraintLayout,
    CoordinatorLayout,
    GridLayout,
    TableLayout,
    ScrollView,
    HorizontalScrollView,
    NestedScrollView,
    // ── Content views ──
    Text,                 // TextView
    EditText,
    Button,
    ImageButton,
    Image,                // ImageView
    Switch,
    CheckBox,
    RadioButton,
    SeekBar,
    ProgressBar,
    Spinner,
    Toolbar,
    AppBar,
    BottomNav,
    TabLayout,
    // ── Lists / paging ──
    RecyclerView,
    ListView,
    GridView,
    ViewPager,
    ViewPager2,
    // ── Containers we partially handle ──
    /// `<fragment android:name="…">` — implementation lives in the named class.
    /// Layout reconstruction requires running its `onCreateView`.
    Fragment { class_name: String },
    /// `<ViewStub>` — should normally be `StubInflated`'d into the target,
    /// but kept as a leaf when we couldn't resolve the stub's target.
    ViewStub { stub_layout_path: Option<String> },
    /// `<include>` placeholder — should normally be expanded.
    Include { included_layout_path: Option<String> },
    /// `<merge>` — typically flattened by the expander.
    Merge,
    // ── Web ──
    WebView,
    // ── Custom view (FQN of the class) ──
    Custom { class_name: String },
    /// Anything else — preserve the tag so the inspector still shows it.
    Other { tag: String },
}

impl ViewKind {
    /// Best-guess classification from the XML tag.
    pub fn from_tag(tag: &str) -> Self {
        match tag {
            "LinearLayout"          => ViewKind::LinearLayout,
            "RelativeLayout"        => ViewKind::RelativeLayout,
            "FrameLayout"           => ViewKind::FrameLayout,
            "androidx.constraintlayout.widget.ConstraintLayout"
            | "ConstraintLayout"    => ViewKind::ConstraintLayout,
            "androidx.coordinatorlayout.widget.CoordinatorLayout"
            | "CoordinatorLayout"   => ViewKind::CoordinatorLayout,
            "GridLayout"            => ViewKind::GridLayout,
            "TableLayout"           => ViewKind::TableLayout,
            "ScrollView"            => ViewKind::ScrollView,
            "HorizontalScrollView"  => ViewKind::HorizontalScrollView,
            "androidx.core.widget.NestedScrollView"
            | "NestedScrollView"    => ViewKind::NestedScrollView,

            "TextView"
            | "androidx.appcompat.widget.AppCompatTextView"
            | "com.google.android.material.textview.MaterialTextView"
                                    => ViewKind::Text,
            "EditText"
            | "androidx.appcompat.widget.AppCompatEditText"
            | "com.google.android.material.textfield.TextInputEditText"
                                    => ViewKind::EditText,
            "Button"
            | "androidx.appcompat.widget.AppCompatButton"
            | "com.google.android.material.button.MaterialButton"
                                    => ViewKind::Button,
            "ImageButton"
            | "androidx.appcompat.widget.AppCompatImageButton"
                                    => ViewKind::ImageButton,
            "ImageView"
            | "androidx.appcompat.widget.AppCompatImageView"
                                    => ViewKind::Image,
            "Switch"
            | "androidx.appcompat.widget.SwitchCompat"
            | "com.google.android.material.switchmaterial.SwitchMaterial"
                                    => ViewKind::Switch,
            "CheckBox"              => ViewKind::CheckBox,
            "RadioButton"           => ViewKind::RadioButton,
            "SeekBar"               => ViewKind::SeekBar,
            "ProgressBar"           => ViewKind::ProgressBar,
            "Spinner"               => ViewKind::Spinner,
            "androidx.appcompat.widget.Toolbar"
            | "Toolbar"             => ViewKind::Toolbar,
            "com.google.android.material.appbar.AppBarLayout"
                                    => ViewKind::AppBar,
            "com.google.android.material.bottomnavigation.BottomNavigationView"
                                    => ViewKind::BottomNav,
            "com.google.android.material.tabs.TabLayout"
                                    => ViewKind::TabLayout,

            "androidx.recyclerview.widget.RecyclerView"
                                    => ViewKind::RecyclerView,
            "ListView"              => ViewKind::ListView,
            "GridView"              => ViewKind::GridView,
            "androidx.viewpager.widget.ViewPager"
            | "ViewPager"           => ViewKind::ViewPager,
            "androidx.viewpager2.widget.ViewPager2"
                                    => ViewKind::ViewPager2,

            "WebView"               => ViewKind::WebView,
            "ViewStub"              => ViewKind::ViewStub { stub_layout_path: None },
            "include"               => ViewKind::Include { included_layout_path: None },
            "merge"                 => ViewKind::Merge,

            // `<fragment android:name="X">` is recognised by tag + having an
            // android:name attribute; the caller fills `class_name` in.
            "fragment"              => ViewKind::Fragment { class_name: String::new() },

            // Tags containing a dot are almost always custom view classes.
            t if t.contains('.')    => ViewKind::Custom { class_name: t.to_string() },

            other                   => ViewKind::Other { tag: other.to_string() },
        }
    }
}

// ── Attributes ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attribute {
    /// Attribute name as declared in XML (`"android:text"`, `"layout_width"`).
    pub name: String,
    /// Resolved value — strings, dimensions, colors all as strings; numeric
    /// values formatted in their original form ("16dp", "#ff0000", "12sp").
    pub value: String,
    /// Where this attribute value came from. Phase 9 fills in `Dynamic`.
    pub origin: AttrOrigin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", rename_all_fields = "camelCase", tag = "kind")]
pub enum AttrOrigin {
    /// Came from layout XML (the default).
    Static,
    /// Set at runtime via `findViewById(R.id.x).setX(...)` — the source
    /// method ref is preserved so the inspector can jump-to-source.
    Dynamic { from_method: String },
    /// Pulled from a `<style>`. Useful to show "this came from the theme,
    /// not the layout" in the inspector.
    Style { style_name: String },
}

// ── Click handlers + navigation ────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Handler {
    pub kind: HandlerKind,
    /// What the handler does — method ref for code handlers, method name
    /// for `android:onClick`.
    pub target: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum HandlerKind {
    /// `android:onClick="methodName"` in XML.
    XmlOnClick,
    /// `view.setOnClickListener(...)` in code.
    CodeOnClickListener,
    /// `view.setOnLongClickListener(...)`.
    CodeOnLongClickListener,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NavTarget {
    pub kind: NavKind,
    /// Activity FQN, fragment class name, or nav-graph destination id.
    pub target: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NavKind {
    StartActivity,
    StartActivityForResult,
    ReplaceFragment,
    NavController,
}

// ── Dynamic modifications (phase 9) ────────────────────────────────────────

/// One post-inflation modification discovered via DEX analysis. Examples:
/// `findViewById(R.id.title).setText("Hello")`,
/// `findViewById(R.id.error).setVisibility(View.GONE)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DynMod {
    /// Setter method, e.g. `"setText"`, `"setVisibility"`, `"setBackgroundColor"`.
    pub setter: String,
    /// Argument as a string — literal when statically known
    /// ("Hello"), otherwise the source method ref it derives from.
    pub value: String,
    /// Where the modification was discovered.
    pub from_method: String,
    /// True iff the value is a literal (so the renderer can show it
    /// confidently rather than as "derived").
    pub literal: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn json(v: &impl Serialize) -> String {
        serde_json::to_string(v).unwrap()
    }

    #[test]
    fn view_source_struct_variants_use_camel_case_fields() {
        assert!(json(&ViewSource::Xml { layout_path: "p".into() })
            .contains("\"layoutPath\":\"p\""));

        let s = json(&ViewSource::Included {
            from_layout_path: "a".into(),
            included_layout_path: "b".into(),
        });
        assert!(s.contains("\"fromLayoutPath\":\"a\""));
        assert!(s.contains("\"includedLayoutPath\":\"b\""));

        assert!(json(&ViewSource::Merged { from_layout_path: "a".into() })
            .contains("\"fromLayoutPath\":\"a\""));

        let s = json(&ViewSource::StubInflated {
            stub_layout_path: "a".into(),
            target_layout_path: "b".into(),
        });
        assert!(s.contains("\"stubLayoutPath\":\"a\""));
        assert!(s.contains("\"targetLayoutPath\":\"b\""));

        assert!(json(&ViewSource::Compose { method_ref: "m".into() })
            .contains("\"methodRef\":\"m\""));
    }

    #[test]
    fn view_kind_struct_variants_use_camel_case_fields() {
        assert!(json(&ViewKind::Fragment { class_name: "c".into() })
            .contains("\"className\":\"c\""));
        assert!(json(&ViewKind::ViewStub { stub_layout_path: Some("p".into()) })
            .contains("\"stubLayoutPath\":\"p\""));
        assert!(json(&ViewKind::Include { included_layout_path: Some("p".into()) })
            .contains("\"includedLayoutPath\":\"p\""));
        assert!(json(&ViewKind::Custom { class_name: "c".into() })
            .contains("\"className\":\"c\""));
    }

    #[test]
    fn attr_origin_struct_variants_use_camel_case_fields() {
        assert!(json(&AttrOrigin::Dynamic { from_method: "m".into() })
            .contains("\"fromMethod\":\"m\""));
        assert!(json(&AttrOrigin::Style { style_name: "s".into() })
            .contains("\"styleName\":\"s\""));
    }

    #[test]
    fn struct_variants_roundtrip() {
        let kinds = vec![
            ViewKind::Fragment { class_name: "com.example.F".into() },
            ViewKind::Custom { class_name: "com.example.V".into() },
        ];
        for k in kinds {
            let s = serde_json::to_string(&k).unwrap();
            let back: ViewKind = serde_json::from_str(&s).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), s);
        }
    }
}
