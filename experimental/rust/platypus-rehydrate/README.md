# platypus-rehydrate

Reconstruct Android activity view trees by combining the manifest,
resources, layout XML, and DEX bytecode analysis. The output is the
**UnifiedView IR** (`ir::ActivityView`) — a single typed tree the
activity-viewer renderers (Tree / HTML / Canvas / Graph) consume.

This crate is the centrepiece of Project Platypus's visual analysis.
Point it at an APK + an activity FQN, and it tells you what the user
would have seen on screen — layout, drawables, click handlers,
navigation, dynamic modifications, list-item templates, Compose
content — *without running the app*.

```
   apk + activity_name + dex_files + resources
                                │
                                ▼
                      ┌─────────────────────────┐
                      │  builder::              │
                      │   rehydrate_activity    │
                      └─────────────────────────┘
                                │
   ┌────────────────────────────┼────────────────────────────────┐
   │            │               │              │                 │
   ▼            ▼               ▼              ▼                 ▼
activity_   layout_       handlers       dynamics           recycler
layout      expander       discovery     discovery         discovery
            ┌───────┐                                       (item template)
            │ XML +  │                              ┌──────────────┐
            │ <include>│                            │   compose    │
            │ <merge> │                             │ discover +   │
            │ ViewStub│                             │ build tree   │
            └───────┘                               └──────────────┘
                                │
                                ▼
                       ir::ActivityView
                       (camelCase JSON to the frontend)
```

---

## Module map

| Module             | Responsibility                                                                                                |
|--------------------|---------------------------------------------------------------------------------------------------------------|
| `builder`          | Top-level orchestrator. `rehydrate_activity` / `rehydrate_all`.                                                |
| `ir`               | The `UnifiedView` IR — `ActivityView`, `UnifiedView`, `ViewKind`, `ViewSource`, `Handler`, `NavTarget`, `DynMod`, … |
| `activity_layout`  | DEX scan for `setContentView(R.layout.X)` calls on a given activity.                                          |
| `layout_expander`  | Layout XML walker — expands `<include>`, flattens `<merge>`, replaces resolved `<ViewStub>`s.                 |
| `handlers`         | XML `android:onClick` + DEX `setOnClickListener`/`setOnLongClickListener`/`setOnTouchListener` discovery.     |
| `navigation`       | Cross-activity transitions — `startActivity`, `startActivityForResult`, `FragmentTransaction.replace`, `NavController.navigate(int)`. |
| `dynamics`         | Post-inflation `findViewById(R.id.x).setX(…)` modifications, grouped by view id.                               |
| `recycler`         | `RecyclerView` / `ListView` / `GridView` item-template recovery from adapters.                                |
| `compose`          | Jetpack Compose call-graph reconstruction (Phase 12).                                                          |

---

## Quickstart — full rehydration

```rust
use platypus_apk::{arsc, axml, zip::ApkZip};
use platypus_dex::parser::DexFileWithRaw;
use platypus_resources::Resources;
use platypus_rehydrate::{rehydrate_activity, ir::ActivityView};

let apk      = ApkZip::open("app.apk")?;
let table    = arsc::parse(&apk.read_entry("resources.arsc")?)?;
let resources = Resources::new(table);

let dex_files: Vec<DexFileWithRaw> = apk.dex_files().into_iter()
    .filter_map(|(n, b)| DexFileWithRaw::from_bytes(b, n).ok())
    .collect();

let view: ActivityView = rehydrate_activity(
    &apk, "com.example.MainActivity", &resources, &dex_files,
);
println!("layout: {:?}", view.layout_path);
println!("root  : {}",   view.root.as_ref().map(|r| r.tag.as_str()).unwrap_or(""));
for n in &view.outgoing_navigations {
    println!("nav: {:?} → {}", n.kind, n.target);
}
```

`rehydrate_all` is the bulk variant — rehydrate every activity in one
call.

---

## The `UnifiedView` IR

```rust
pub struct ActivityView {
    pub activity_name: String,
    pub layout_id:     Option<u32>,
    pub layout_path:   Option<String>,
    pub root:          Option<UnifiedView>,
    pub diagnostics:   Vec<Diagnostic>,
    pub outgoing_navigations: Vec<NavTarget>,
}

pub struct UnifiedView {
    pub source: ViewSource,           // xml / include / merge / stub / compose / synthetic
    pub kind:   ViewKind,             // LinearLayout / Text / Button / Custom / …
    pub tag:    String,
    pub id:     Option<String>,
    pub attrs:  Vec<Attribute>,       // each with origin: static / dynamic / style
    pub children:               Vec<UnifiedView>,
    pub click_handler:          Option<Handler>,
    pub navigation:             Option<NavTarget>,
    pub dynamic_modifications:  Vec<DynMod>,
    pub item_template:          Option<Box<UnifiedView>>,
    pub drawables:              HashMap<String, serde_json::Value>,
}
```

Every field that can be unfilled has an `Option` or an empty `Vec` — the
IR is designed once for every phase (current and planned) so renderers
never crash on a stage that didn't run.

### `ViewKind`

Coarse classification — `LinearLayout`, `RelativeLayout`,
`ConstraintLayout`, `RecyclerView`, `Text`, `Button`, … plus
`Custom { class_name }` for app-specific views and `Other { tag }` as
a fallback. Renderers branch on this for paint semantics.

### `ViewSource`

Tracks provenance — was this node inflated from a layout XML file?
From an `<include>`? Did it come out of `<ViewStub>` resolution? Was
it emitted by a Compose function? Critical for "jump to source" UI
affordances.

### Drawables

Pre-resolved at rehydration time. Vector drawables arrive as **SVG
strings** (no DOM, no canvas — just embed them); shape drawables as
typed `solid_color` / `stroke` / `corners` / `gradient` records.

---

## Sub-phase APIs

Each discovery phase is independently usable, in case you only need
part of the IR (e.g. just handlers, or just navigation):

### Handlers

```rust
use platypus_rehydrate::handlers::{discover_handlers, HandlerHit, HandlerTarget};

let hits = discover_handlers(&dex_files, "Lcom/example/MainActivity;");
for h in hits {
    println!("R.id.{} → {}", h.view_id, h.target.display());
}
```

`HandlerTarget` covers method refs (`Lcom/foo/Bar;->onClick(…)V`) and
lambda forms. The IR feeds these into `UnifiedView.click_handler`.

### Navigation

```rust
use platypus_rehydrate::navigation::discover_navigation_in_class;

let navs = discover_navigation_in_class(&dex_files, "Lcom/example/MainActivity;");
for n in navs {
    println!("{:?}  →  {}", n.kind, n.target);
}
```

Recognises `startActivity`, `startActivityForResult`, fragment
replacement, and `NavController.navigate(R.id.X)`. The integer →
nav-graph destination resolution lives in the consumer when a
nav-graph XML is available.

### Dynamic modifications

```rust
use platypus_rehydrate::dynamics::{discover_dynamics, group_by_view_id};

let hits = discover_dynamics(&dex_files, "Lcom/example/MainActivity;");
let by_id = group_by_view_id(hits);
for (vid, mods) in by_id {
    println!("R.id.{vid}");
    for m in mods { println!("  {} = {}", m.setter, m.value); }
}
```

Patterns recognised: `findViewById(R.id.X).setText(literal)`,
`setVisibility(View.GONE)`, `setEnabled(bool)`, `setBackgroundColor(0xXX)`,
`setImageResource(R.drawable.Y)`, …

### Recycler / list item templates

```rust
use platypus_rehydrate::recycler::{discover_recyclers, RecyclerHit};

let hits = discover_recyclers(&dex_files, "Lcom/example/MainActivity;");
for h in hits {
    println!("RecyclerView@{} → adapter {} → item layout {:?}",
             h.view_id, h.adapter_class, h.item_layout_path);
}
```

The scanner follows `setAdapter` → adapter class →
`onCreateViewHolder` → `inflate(R.layout.X)` to recover the row
template. The IR then expands that template under `item_template` and
the renderer repeats it.

### Compose

```rust
use platypus_rehydrate::compose::{discover_compose_root, build_compose_tree, ComposeRoot};

if let Some(root) = discover_compose_root(&dex_files, "Lcom/example/MainActivity;") {
    let tree = build_compose_tree(&dex_files, &root);
    /* … */
}
```

The Compose path recognises `setContent { … }`, walks the lambda body,
maps well-known composables (`Text`, `Button`, `Column`, `Box`, `Row`,
`LazyColumn`, `Image`, …) to `ViewKind`, and recurses into composable
bodies AND their content lambdas — so a `Card { Column { Text(…) } }`
shows as nested `UnifiedView` nodes.

---

## Diagnostics

Every phase records non-fatal issues into
`ActivityView.diagnostics: Vec<Diagnostic>`. Severities are
`info` / `warning` / `error`. Examples:

* `"no setContentView call found"` (error — root is `None`)
* `"fragment <name> has no static class binding"` (warning — fragment
  rendered as placeholder)
* `"adapter onCreateViewHolder() too complex to recover"` (warning —
  item template falls back to a generic shape)

The activity-viewer's inspector pane surfaces these so analysts know
*why* a sub-tree is missing, instead of seeing a blank.

---

## Pairing with `platypus-dexmapper`

When R8 has minified library names, the rehydrate output is full of
`p.q.a` identifiers. Pair with
[`platypus-dexmapper`](../platypus-dexmapper) (built with the
`rehydrate` feature) to rewrite the IR in place after rehydration:

```rust
use platypus_dexmapper::Deobfuscator;

let mut view = rehydrate_activity(&apk, fqn, &resources, &dex_files);
let deob = Deobfuscator::load("mapping.json")?;
deob.apply_to_activity_view(&mut view);
// view.activity_name etc. now use the library FQNs.
```

Both Tauri viewer shells turn this on automatically when a mapping is
loaded via the "Load mapping…" header control.

---

## Implementation status

Current phases implemented:

* Phase 0 — pipeline scaffolding
* Phase 1 — layout XML expansion (`<include>` / `<merge>` / `<ViewStub>`)
* Phase 7 — click / long-click / touch handlers
* Phase 8 — cross-activity navigation
* Phase 9 — dynamic modifications (`findViewById(...).setX(...)`)
* Phase 10 — RecyclerView / ListView / GridView item templates
* Phase 12 — Jetpack Compose

Phases 2-6, 11, 13+ are reserved for future work (animations,
fragments-with-dynamic-binding, multi-window layouts, …). The IR
already has fields for them — they currently arrive empty.
