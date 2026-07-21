# platypus-apk

Pure-Rust parsers for the binary formats that live inside an Android
package. No `aapt2`, no `apktool`, no JDK — every byte is decoded
in-process.

| Module    | What it parses                                                          | Key types                                      |
|-----------|-------------------------------------------------------------------------|------------------------------------------------|
| `zip`     | The APK's outer ZIP container                                           | `ApkZip`                                       |
| `axml`    | Android binary XML — `AndroidManifest.xml`, every `res/layout/*.xml`    | `XmlNode`                                      |
| `arsc`    | Compiled resource table (`resources.arsc`)                              | `ResourceTable`, `ResourceEntry`, `BagEntry`   |
| `split`   | xapk / apkm / apks / aab multi-file bundles                             | `SplitApk`                                     |

All four modules return ordinary owned Rust values — no zero-copy
lifetime games — so you can hold them across threads, send them to
worker pools, or serialise them through `serde` without surprise.

---

## `zip::ApkZip`

```rust
use platypus_apk::zip::ApkZip;

// Open from path or from an in-memory buffer.
let apk = ApkZip::open("app.apk")?;
let apk = ApkZip::from_bytes(buf)?;

// Standard ZIP queries.
let names: Vec<String> = apk.list_entries();
let manifest_bytes: Vec<u8> = apk.read_entry("AndroidManifest.xml")?;
assert!(apk.has_entry("classes.dex"));

// Convenience: every classes*.dex in central-directory order.
for (name, bytes) in apk.dex_files() {
    println!("{name}: {} bytes", bytes.len());
}

// Raw bytes are kept around so callers can hand them to other parsers
// without re-reading the file from disk.
let raw: &[u8] = apk.raw_bytes();
```

`ApkZip` is backed by the [`zip`](https://crates.io/crates/zip) crate
and supports deflate. The whole APK is read into memory once; subsequent
`read_entry` calls are cheap.

---

## `axml::parse` / `axml::XmlNode`

Android compiles XML to a custom binary format before packing it into
the APK. `axml::parse` accepts the raw bytes and yields an ordinary
tree:

```rust
use platypus_apk::axml;

let xml = axml::parse(&apk.read_entry("AndroidManifest.xml")?)?;
println!("package = {:?}", xml.attr("package"));

for activity in xml.find_all("activity") {
    println!("activity: {:?}", activity.attr("android:name"));
}
```

`XmlNode` is a recursive struct with `tag`, `attrs`, and `children` —
the standard shape every layout walker expects. Each attribute carries
the original raw string, the resolved value (after reference lookup),
the resource id, and the namespace.

### Resolved-attribute mode

When you have a `ResourceTable` handy, pass it to `parse_with_resources`
to get attributes pre-resolved (`@string/foo` → the actual string,
`@color/primary` → `#ff6750a4`, etc.):

```rust
use platypus_apk::{axml, arsc};

let table = arsc::parse(&apk.read_entry("resources.arsc")?)?;
let manifest = axml::parse_with_resources(&apk.read_entry("AndroidManifest.xml")?, &table)?;
```

---

## `arsc::parse` / `arsc::ResourceTable`

`resources.arsc` is the **only** place in an APK that maps resource ids
(`0x7f0a0001`) to names (`R.id.login_button`). Without it, every
layout XML attribute looks like an opaque integer.

```rust
use platypus_apk::arsc;

let table = arsc::parse(&bytes)?;

// Walk every entry.
for entry in table.entries() {
    println!("0x{:08x} = {}.{} = {:?}",
             entry.id, entry.type_name, entry.name, entry.value);
}

// Look up by id.
if let Some(e) = table.get(0x7f0a0001) { /* ... */ }
```

`ResourceEntry` covers simple typed values (string / int / color / bool
/ dimension / reference) AND **bag entries** — themes, styles, arrays,
and `<attr>` declarations — via `BagEntry { items: Vec<BagItem> }`. Each
`BagItem` carries the parent id + the typed value.

For the **typed** query layer (lookup-by-name, configuration filtering,
reference resolution) use [`platypus-resources::Resources`](../platypus-resources)
which wraps `ResourceTable` and adds those niceties.

---

## `split::SplitApk` — xapk / apkm / apks / aab

Modern Android distributions ship multiple split APKs in a single
container (`base.apk`, `config.arm64_v8a.apk`, `config.xxhdpi.apk`,
etc.). `SplitApk` merges them into one searchable view:

```rust
use platypus_apk::split::SplitApk;

let bundle = SplitApk::from_dir("./unpacked-xapk/")?;
// or:
let bundle = SplitApk::from_files(&["base.apk", "config.arm64_v8a.apk"])?;
// or:
let bundle = SplitApk::from_bytes_list(vec![("base.apk".into(), bytes_a)])?;

println!("package: {:?}", bundle.package_name());
println!("version: {:?}", bundle.version_name());
println!("splits:  {}",   bundle.split_count());

// File queries dedup across splits — the base APK wins ties.
for (name, src_split) in bundle.list_files_with_prefix("res/layout/") {
    println!("{name} (from {src_split})");
}

// Convenience: every dex / drawable / layout entry, transparently
// flattened across all splits.
for (name, bytes) in bundle.dex_files() { /* ... */ }
for (name, src)  in bundle.drawables()   { /* ... */ }
for (name, src)  in bundle.layouts()     { /* ... */ }

let manifest: XmlNode = bundle.manifest_resolved()?;
let table:    ResourceTable = bundle.resources()?;
```

---

## Errors

Every fallible function returns `Result<_, ApkError>`. `ApkError` has
four variants:

```rust
pub enum ApkError {
    Io(std::io::Error),  // file or buffer IO
    Zip(String),         // malformed ZIP central directory
    Parse(String),       // AXML / arsc decode failure
    NotFound(String),    // missing entry name
}
```

`From<std::io::Error>` and `From<zip::result::ZipError>` are
implemented so `?` works in user code without manual conversion.

---

## Dependencies

Just `zip` (for ZIP/deflate) and `serde` (re-exported through derives on
the public types). Crate compiles in a few seconds and has no transitive
graph of any size.
