//! Reconstruct Android activity view trees by combining the manifest,
//! resources, layout XML, and DEX bytecode analysis.
//!
//! This crate is the *backend* of the activity-viewer pipeline. It produces
//! a [`UnifiedView`] IR that downstream renderers (TreeView R3,
//! HtmlRenderer R1, CanvasRenderer R2) consume. All renderers — and the
//! standalone-viewer app + Project Platypus integration — share this IR.
//!
//! ## What's implemented (phase 0, 1, 7, 8, 9, 10, 12)
//! * Activity → root layout discovery via DEX analysis
//!   ([`activity_layout::discover_for_activity`])
//! * Layout XML expansion (`<include>`, `<merge>`, `<ViewStub>`)
//!   ([`layout_expander::expand_layout_file`])
//! * Click-handler discovery — XML `android:onClick` + DEX
//!   `setOnClickListener`/`setOnLongClickListener`/`setOnTouchListener`
//!   patterns ([`handlers::discover_handlers`])
//! * Cross-activity navigation — `startActivity` / `startActivityForResult`
//!   with explicit Intent class, `FragmentTransaction.replace`, and
//!   `NavController.navigate(int)` ([`navigation::discover_navigation_in_method`])
//! * Post-inflation modifications — `findViewById(R.id.x).setText("…")` /
//!   `setVisibility(GONE)` / `setBackgroundColor(0x…)` /
//!   `setEnabled(false)` etc. ([`dynamics::discover_dynamics`])
//! * RecyclerView / ListView / GridView item-template recovery —
//!   `setAdapter` → adapter class → `onCreateViewHolder` →
//!   `inflate(R.layout.X)` ([`recycler::discover_recyclers`])
//! * Jetpack Compose call-graph reconstruction — `setContent { … }`
//!   detection, well-known composable → `ViewKind` mapping, recursive
//!   walk through composable bodies AND their content lambdas
//!   ([`compose::discover_compose_root`] + [`compose::build_compose_tree`])
//! * Top-level orchestration ([`builder::rehydrate_activity`])
//! * Comprehensive [`ir::UnifiedView`] IR — fields for click handlers,
//!   navigation, dynamic modifications, Compose source.

pub mod activity_layout;
pub mod builder;
pub mod compose;
pub mod dynamics;
pub mod handlers;
pub mod ir;
pub mod layout_expander;
pub mod navigation;
pub mod recycler;

// Convenience re-exports so callers don't need to know the module layout.
pub use builder::{rehydrate_activity, rehydrate_all};
pub use compose::{
    discover_compose_root, discover_compose_root_detailed, build_compose_tree,
    ComposeRoot, ComposeDiscovery,
};
pub use dynamics::{discover_dynamics, group_by_view_id, DynModHit};
pub use handlers::{discover_handlers, HandlerHit, HandlerTarget};
pub use ir::{
    ActivityView, Attribute, AttrOrigin, Diagnostic, DiagnosticSeverity,
    DynMod, Handler, HandlerKind, NavKind, NavTarget, UnifiedView, ViewKind,
    ViewSource,
};
pub use navigation::{discover_navigation_in_method, discover_navigation_in_class, NavInfo};
pub use recycler::{discover_recyclers, BindingHit, RecyclerHit};
