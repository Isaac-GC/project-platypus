//! Apply a `Deobfuscator` to a freshly-rehydrated `ActivityView`,
//! replacing every obfuscated class/method ref we recognise. Pure
//! string substitution — never *fails*; unknown names pass through
//! unchanged. The IR shape is preserved.
//!
//! Touch list (kept in sync with `platypus_rehydrate::ir`):
//!   - `ActivityView.activity_name`                              (FQN)
//!   - `ActivityView.outgoing_navigations[].target`              (FQN-ish)
//!   - `UnifiedView.source` if `Compose { method_ref }`          (JVM method ref)
//!   - `UnifiedView.kind`   if `Fragment|Custom { class_name }`  (FQN)
//!   - `UnifiedView.attrs[].origin` if `Dynamic|Style`           (method ref / style)
//!   - `UnifiedView.click_handler.target` for code handlers      (JVM method ref)
//!   - `UnifiedView.navigation.target`                           (FQN)
//!   - `UnifiedView.dynamic_modifications[].from_method`         (JVM method ref)
//!   - `UnifiedView.item_template` recurses
//!   - `Diagnostic.location` — best effort string replacement

use platypus_rehydrate::ir::{
    ActivityView, AttrOrigin, Handler, HandlerKind, NavTarget, UnifiedView, ViewKind, ViewSource,
};

use crate::Deobfuscator;

pub fn activity_view(d: &Deobfuscator, view: &mut ActivityView) {
    view.activity_name = d.translate_class(&view.activity_name);
    for nav in &mut view.outgoing_navigations {
        translate_nav(d, nav);
    }
    if let Some(root) = view.root.as_mut() {
        unified_view(d, root);
    }
}

fn unified_view(d: &Deobfuscator, v: &mut UnifiedView) {
    match &mut v.source {
        ViewSource::Compose { method_ref } => {
            *method_ref = d.translate_method_ref(method_ref);
        }
        _ => {}
    }
    match &mut v.kind {
        ViewKind::Fragment { class_name } |
        ViewKind::Custom   { class_name } => {
            if !class_name.is_empty() {
                *class_name = d.translate_class(class_name);
            }
        }
        _ => {}
    }
    for attr in &mut v.attrs {
        match &mut attr.origin {
            AttrOrigin::Dynamic { from_method } => {
                *from_method = d.translate_method_ref(from_method);
            }
            // Style names live in the resources arsc, not in the dex
            // mapping, so we don't try to rewrite them — but we leave
            // the arm here so the match stays exhaustive if AttrOrigin
            // grows new variants.
            AttrOrigin::Style { .. } | AttrOrigin::Static => {}
        }
    }
    if let Some(h) = v.click_handler.as_mut() {
        translate_handler(d, h);
    }
    if let Some(n) = v.navigation.as_mut() {
        translate_nav(d, n);
    }
    for m in &mut v.dynamic_modifications {
        m.from_method = d.translate_method_ref(&m.from_method);
    }
    if let Some(t) = v.item_template.as_mut() {
        unified_view(d, t);
    }
    for c in &mut v.children {
        unified_view(d, c);
    }
}

fn translate_handler(d: &Deobfuscator, h: &mut Handler) {
    match h.kind {
        // Code handlers carry a JVM method ref.
        HandlerKind::CodeOnClickListener | HandlerKind::CodeOnLongClickListener => {
            h.target = d.translate_method_ref(&h.target);
        }
        // XML `android:onClick="methodName"` — only a method *name*, no
        // class context to look up. Leave it alone.
        HandlerKind::XmlOnClick => {}
    }
}

fn translate_nav(d: &Deobfuscator, n: &mut NavTarget) {
    // `target` is usually an activity / fragment FQN. Some variants
    // (NavController destinations) are nav-graph ids, which won't be in
    // the dex mapping and will pass through unchanged.
    n.target = d.translate_class(&n.target);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::MappingFile;
    use platypus_rehydrate::ir::*;

    fn deob() -> Deobfuscator {
        let f = MappingFile::parse_json(r#"{
          "mappings": [
            { "obfuscated_class": "a.b.c", "real_class": "com.example.MainActivity",
              "methods": [], "fields": [] },
            { "obfuscated_class": "a.b.d", "real_class": "com.example.SettingsActivity",
              "methods": [
                {"obfuscated_name":"e","obfuscated_descriptor":"(Landroid/view/View;)V",
                 "real_name":"onLoginClicked"}
              ], "fields": [] }
          ]
        }"#).unwrap();
        Deobfuscator::from_file(f)
    }

    fn empty_view() -> UnifiedView {
        UnifiedView {
            source: ViewSource::Synthetic,
            kind: ViewKind::Other { tag: "View".into() },
            tag: "View".into(),
            id: None,
            attrs: vec![],
            children: vec![],
            click_handler: None,
            navigation: None,
            dynamic_modifications: vec![],
            item_template: None,
            drawables: Default::default(),
        }
    }

    #[test]
    fn rewrites_activity_name_and_handler() {
        let d = deob();
        let mut av = ActivityView {
            activity_name: "a.b.c".into(),
            layout_id: None,
            layout_path: None,
            root: Some({
                let mut v = empty_view();
                v.click_handler = Some(Handler {
                    kind: HandlerKind::CodeOnClickListener,
                    target: "La/b/d;->e(Landroid/view/View;)V".into(),
                });
                v.kind = ViewKind::Custom { class_name: "a.b.d".into() };
                v
            }),
            diagnostics: vec![],
            outgoing_navigations: vec![NavTarget {
                kind: NavKind::StartActivity,
                target: "a.b.d".into(),
            }],
        };
        d.apply_to_activity_view(&mut av);
        assert_eq!(av.activity_name, "com.example.MainActivity");
        assert_eq!(av.outgoing_navigations[0].target, "com.example.SettingsActivity");
        let root = av.root.as_ref().unwrap();
        match &root.kind {
            ViewKind::Custom { class_name } => assert_eq!(class_name, "com.example.SettingsActivity"),
            other => panic!("expected Custom, got {other:?}"),
        }
        assert_eq!(root.click_handler.as_ref().unwrap().target,
                   "Lcom/example/SettingsActivity;->onLoginClicked(Landroid/view/View;)V");
    }

    /// CLI `apply` reads JSON from disk, runs through the deobfuscator,
    /// then writes JSON back. The shape must roundtrip through serde with
    /// `rename_all = "camelCase"` intact.
    #[test]
    fn json_roundtrip_through_apply() {
        let d = deob();
        let mut av = ActivityView {
            activity_name: "a.b.c".into(),
            layout_id: None,
            layout_path: Some("res/layout/x.xml".into()),
            root: Some({
                let mut v = empty_view();
                v.kind = ViewKind::Custom { class_name: "a.b.d".into() };
                v
            }),
            diagnostics: vec![],
            outgoing_navigations: vec![],
        };
        let json = serde_json::to_string(&av).unwrap();
        let mut parsed: ActivityView = serde_json::from_str(&json).unwrap();
        d.apply_to_activity_view(&mut parsed);
        assert_eq!(parsed.activity_name, "com.example.MainActivity");
        match parsed.root.unwrap().kind {
            ViewKind::Custom { class_name } => assert_eq!(class_name, "com.example.SettingsActivity"),
            other => panic!("expected Custom, got {other:?}"),
        }
        // Also: in-place mutation followed by re-serialise still yields a
        // valid camelCase JSON the frontend can consume.
        av.activity_name = "a.b.d".into();
        let s = serde_json::to_string(&av).unwrap();
        assert!(s.contains("\"activityName\""));
        assert!(s.contains("\"layoutPath\""));
    }

    #[test]
    fn leaves_xml_onclick_alone() {
        let d = deob();
        let mut v = empty_view();
        v.click_handler = Some(Handler {
            kind: HandlerKind::XmlOnClick,
            target: "onLoginClicked".into(),
        });
        let mut av = ActivityView {
            activity_name: "a.b.c".into(),
            layout_id: None, layout_path: None,
            root: Some(v),
            diagnostics: vec![],
            outgoing_navigations: vec![],
        };
        d.apply_to_activity_view(&mut av);
        assert_eq!(av.root.unwrap().click_handler.unwrap().target, "onLoginClicked");
    }
}
