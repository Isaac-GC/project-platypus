//! Androguard-style high-level queries over Android resources.
//!
//! This crate sits on top of [`platypus_apk::axml`] and [`platypus_apk::arsc`]
//! and adds a typed query layer:
//!
//! * [`manifest`] — parsed AndroidManifest.xml with typed component / filter /
//!   permission accessors. Avoids the "string-typed everything" pain of
//!   walking [`XmlNode`] manually.
//! * [`resources`] — richer interface over [`ResourceTable`]: lookup by name
//!   ↔ id, by type, by configuration qualifier, with reference resolution
//!   (`@string/foo`, `@drawable/bar`, `?attr/baz`, `@+id/qux`).
//! * [`layout`] — parse layout XML with attribute references resolved through
//!   a [`Resources`] handle. Foundation for "rebuild the UI tree of activity X".
//! * [`refs`] — parse and follow Android resource references in arbitrary
//!   attribute strings.
//!
//! Long-term goal: combine this with DEX analysis (find `setContentView(R.layout.xxx)`
//! calls in an activity's onCreate) to reconstruct the visual tree of any
//! activity declared in the manifest. The pieces here are the static half of
//! that pipeline — the dynamic call-graph half lives in `platypus-dex`/the
//! main crate's analysis module.

// Re-export the underlying parser types so consumers don't have to depend on
// platypus-apk directly when they're already pulling in this crate.
pub use platypus_apk::axml::XmlNode;
pub use platypus_apk::arsc::{BagEntry, BagItem, ResourceEntry, ResourceTable};

pub mod drawable;
pub mod manifest;
pub mod refs;
pub mod resources;
pub mod layout;
pub mod style;
pub mod theme;

// Convenience re-exports.
pub use manifest::{
    Manifest, Application, Activity, ActivityAlias, Service, Receiver, Provider,
    IntentFilter, IntentData, MetaData, UsesFeature, UsesLibrary, UsesPermission,
    Permission, Query,
};
pub use resources::Resources;
pub use refs::{Reference, parse_reference};
pub use layout::{Layout, View};
pub use drawable::{
    Drawable, BitmapFormat, RippleDrawable, InsetDrawable,
    VectorDrawable, ShapeDrawable, ShapeKind, Stroke, Corners, Gradient, GradientKind,
    SelectorDrawable, SelectorItem, ViewState,
    LayerListDrawable, LayerItem,
};
pub use style::{Style, StyleAttribute, flatten_style_chain, framework_attr_name};
pub use theme::{Theme, resolve_theme, default_theme};
