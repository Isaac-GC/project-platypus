# platypus-resources

Androguard-style high-level queries over the Android manifest, the
compiled resource table (`resources.arsc`), layout XML, drawables,
themes, and styles. Sits one layer above [`platypus-apk`](../platypus-apk),
turning its "string-typed everything" output into typed accessors that
the rest of the pipeline (decompiler, rehydrate, viewer) can call
without reaching for `XmlNode.attr("…")` every time.

```
   AXML / arsc bytes           ┌──────────────────────────┐
   (platypus-apk)              │     Resources            │
        │                      │ ──────────────────────── │
        ▼                      │  by name ↔ id            │
   XmlNode / ResourceTable ───▶│  by type                 │
                               │  reference resolution    │
                               │  drawable / style / theme│
                               │  resolution              │
                               └──────────────────────────┘
                                          │
                                          ▼
                                ┌──────────────────────────┐
                                │ Manifest │ Layout │ etc. │
                                └──────────────────────────┘
```

---

## Module map

| Module      | What it covers                                                                   |
|-------------|----------------------------------------------------------------------------------|
| `manifest`  | Typed `AndroidManifest.xml` — package, version, components, intent-filters, permissions, queries, uses-features, uses-libraries. |
| `resources` | Typed handle over `ResourceTable` — lookup-by-name, lookup-by-type, reference resolution. |
| `refs`      | Parse and follow `@type/name`, `@+id/name`, `?attr/name`, `@0x7f0a0001` references. |
| `layout`    | Parse one layout XML file with attribute references resolved through a `Resources`. |
| `drawable`  | Resolve drawable resources into structured records — vector (SVG), shape, selector, layer-list, ripple, inset, bitmap. |
| `style`     | Flatten a `<style>` and its parent chain into one attribute set.                 |
| `theme`     | Flatten a theme + Material 3 defaults into a queryable attribute map.            |

---

## The typed manifest

```rust
use platypus_apk::{axml, arsc, zip::ApkZip};
use platypus_resources::{Manifest, Resources};

let apk      = ApkZip::open("app.apk")?;
let table    = arsc::parse(&apk.read_entry("resources.arsc")?)?;
let resources = Resources::new(table);

let raw      = axml::parse_with_resources(&apk.read_entry("AndroidManifest.xml")?, resources.table())?;
let manifest = Manifest::from_xml(raw).resolved(&resources);

println!("package      {}", manifest.package().unwrap_or(""));
println!("version_name {:?}", manifest.version_name());
println!("min_sdk      {:?}", manifest.min_sdk());
println!("target_sdk   {:?}", manifest.target_sdk());

for a in manifest.activities() {
    println!("activity: {}{}{}",
             a.resolve_name(manifest.package().unwrap_or("")),
             if a.is_launcher()        { "  [launcher]" } else { "" },
             if a.exported.unwrap_or(false) { "  [exported]" } else { "" });
}

for p in manifest.permission_names()        { println!("uses-permission: {p}"); }
for q in manifest.queries()                 { /* declared <queries> */ }
for c in manifest.exported_components()     { println!("exported: {} ({})", c.name(), c.kind()); }

// Direct lookup by FQN
let act = manifest.activity_by_name("com.example.MainActivity")?;
```

The typed components — `Activity`, `Service`, `Receiver`, `Provider`,
`ActivityAlias` — share a common shape: name, label, theme, exported
flag, intent-filters, meta-data. Lookups like
`Activity::is_launcher()` recognise the
`android.intent.action.MAIN` + `android.intent.category.LAUNCHER`
filter pair without any string surgery in the caller.

---

## The typed resource table

```rust
use platypus_resources::Resources;

let r = Resources::new(arsc::parse(&bytes)?);

// Direct id lookups.
let entry = r.get(0x7f0a0001)?;
let val   = r.resolve(0x7f0a0001)?;  // best-effort String
let s     = r.string(0x7f0e0023)?;   // borrowed string slice

// Lookups by (type, name).
let id      = r.id_by_name("layout",   "activity_main")?;
let value   = r.value_by_name("string", "app_name")?;
let path    = r.layout_path("activity_main")?;   // "res/layout/activity_main.xml"
let drawable = r.drawable_path("ic_launcher")?;

// Reference resolution — applies recursively until a literal is reached.
let resolved = r.resolve_value("@string/app_name");

// Drawable values get structured back into typed records.
let drawable: Drawable = r.resolve_drawable_by_name("ic_launcher_background", &apk)?;

// Themes — flattened against Material 3 defaults.
let theme = r.theme(0x7f120104);
let color_primary = theme.attr_by_name("colorPrimary")?.data; // packed RGBA
```

`Resources::search` runs a free-text query across names and is used by
the standalone-viewer's "find" feature.

---

## Layout XML

```rust
use platypus_resources::Layout;

let bytes = apk.read_entry("res/layout/activity_main.xml")?;
let layout = Layout::parse_with_resources(&bytes, &resources)?;

println!("{} views total",         layout.view_count());
println!("root: {}", layout.root.tag);

let login = layout.find_by_id("login_button")?;
println!("login.text = {:?}", login.text());
println!("onClick    = {:?}", login.on_click());

// Pretty-print back out
println!("{}", layout.to_xml_string());
```

`View` exposes typed accessors (`id()`, `text()`, `on_click()`,
`content_description()`) and a generic `attr(name)` fallback. References
inside attributes are pre-resolved when you go through
`parse_with_resources` / `resolved`.

---

## Drawables (`drawable::Drawable`)

Android stores drawables in many shapes (PNG bitmaps, 9-patches,
vectors, shapes, selectors, layer-lists, ripples, insets, colour
literals). `Drawable` is one enum covering them all, with each variant
shaped for the renderer's needs:

```rust
use platypus_resources::drawable::Drawable;

match drawable {
    Drawable::Bitmap     { path, format }       => /* PNG / WEBP / JPG / GIF */,
    Drawable::NinePatch  { path }               => /* res/drawable*/9p */,
    Drawable::Vector     { svg, intrinsic_width_dp, intrinsic_height_dp }
                                                => /* ready-to-paint SVG */,
    Drawable::Shape(s)                          => /* rect / oval / ring / line */,
    Drawable::Selector { items }                => /* state list */,
    Drawable::LayerList { items }               => /* stacked layers */,
    Drawable::Ripple { color, content, mask }   => /* M3 ripple */,
    Drawable::Inset(i)                          => /* padded wrapper */,
    Drawable::Color { rgba }                    => /* colour literal */,
    Drawable::Reference { type_name, name }     => /* couldn't resolve */,
    Drawable::Unknown { entry_path, reason }    => /* explains why */,
}
```

The resolver decodes vector drawables to SVG **strings** (no DOM, no
canvas) so the renderer just embeds them.

Helper functions for low-level work:
* `drawable::parse_color_literal("#ff6750a4")` → `Some(0xff6750a4)`
* `drawable::rgba_to_hex(0xff6750a4)` → `"#ff6750a4"`
* `drawable::parse_dimen_to_px("16dp")` → `Some(16)`

---

## Themes

```rust
use platypus_resources::theme::resolve_theme;

let theme = resolve_theme(theme_id, resources.table());
// `theme.attrs: HashMap<u32, StyleAttribute>` — already merged against
// bundled Material 3 defaults so every renderer query succeeds.

let primary = theme.attr_by_name("colorPrimary")?;
println!("primary = #{:08x}", primary.data);

// Walk all set attributes
for name in theme.attribute_names() {
    println!("  {name}");
}
```

`Theme` carries an `inherited` bit on each attribute so the inspector
can show "this came from the parent style" vs "this was defined on
the theme itself".

---

## Styles

```rust
use platypus_resources::style::{flatten_style_chain, framework_attr_name};

let style = flatten_style_chain(style_id, resources.table())?;
for attr in &style.attributes {
    let (name, pkg) = (attr.name.as_str(), attr.package.as_deref().unwrap_or(""));
    println!("{pkg}:{name} = {}", attr.value);
}

// Framework attr id → friendly name
assert_eq!(framework_attr_name(0x0101030e), Some("textColorPrimary"));
```

---

## References

```rust
use platypus_resources::refs::{parse_reference, Reference};

match parse_reference("@drawable/ic_launcher") {
    Some(Reference::Named { type_name, name, package }) => /* … */,
    Some(Reference::Id(id))                              => /* @0x7f0a0001 */,
    Some(Reference::Attr { name, package })              => /* ?attr/colorPrimary */,
    Some(Reference::PendingId { name })                  => /* @+id/foo */,
    None                                                 => /* not a reference */,
}
```

---

## When to reach for which crate

* **Just need raw XML?** → `platypus-apk::axml`.
* **Just need raw resource entries?** → `platypus-apk::arsc`.
* **Want resolved values, typed components, theme/style flattening,
  drawable resolution?** → `platypus-resources` (this crate).
* **Want a full activity tree with handlers and dynamic
  modifications?** → `platypus-rehydrate`, which builds on top of this.
