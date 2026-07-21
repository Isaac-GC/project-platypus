# platypus-dexmapper

Standalone Rust loader for [dexmapper](https://github.com/you/dexmapper) deobfuscation mappings. Resolves obfuscated class, method, and field names back to their library originals — the names R8 erased when it shrank `okhttp3.OkHttpClient` down to `p.q.a`.

Reads both formats the Python `dexmapper` tool emits:

* **JSON** — richer; includes confidence + match type.
* **ProGuard** — `obf -> real:` text format, what apps usually ship with their symbol bundles.

Format is sniffed automatically (`{` → JSON, else ProGuard).

---

## Standalone build

The default build has zero workspace deps. Two crates only: `serde` + `serde_json`.

```sh
# Inside the project_platypus repo:
cargo build  -p platypus-dexmapper --release
cargo install --path rust/platypus-dexmapper

# Or — outside the repo, after copying just this crate out:
cd /tmp && cp -R /path/to/project_platypus/rust/platypus-dexmapper .
cd platypus-dexmapper
# Crate is self-contained; cargo will resolve serde from crates.io.
cargo build --release
```

The crate can be lifted out of the workspace as-is — nothing in `src/` references sibling crates in the standalone configuration.

### Standalone CLI

```sh
platypus-dexmapper info            mapping.json
platypus-dexmapper lookup-class    mapping.json p.q.a
platypus-dexmapper lookup-method   mapping.json p.q.a a "(Lokhttp3/Request;)Lokhttp3/Call;"
platypus-dexmapper translate-ref   mapping.json "Lp/q/a;->a(Lokhttp3/Request;)Lokhttp3/Call;"
```

Output of `info`:

```
path:    /path/to/mapping.json
format:  json
classes: 15
methods: 149
fields:  9
```

### Standalone library API

```rust
use platypus_dexmapper::Deobfuscator;

let d = Deobfuscator::load("mapping.json")?;

// Class lookups accept dotted and JVM-internal forms.
assert_eq!(d.real_class("p.q.a"),  Some("okhttp3.OkHttpClient"));
assert_eq!(d.real_class("Lp/q/a;"), Some("okhttp3.OkHttpClient"));

// Method lookups — pass the JVM descriptor to disambiguate overloads.
let real = d.real_method("p.q.a", "a", Some("(Lokhttp3/Request;)Lokhttp3/Call;"));
assert_eq!(real, Some("newCall"));

// Translate inner classes by suffix when the outer class is known.
assert_eq!(d.translate_class("p.q.a$Builder"), "okhttp3.OkHttpClient$Builder");

// Translate a full smali/jadx method ref in one call.
let real = d.translate_method_ref("Lp/q/a;->a(Lokhttp3/Request;)Lokhttp3/Call;");
assert_eq!(real, "Lokhttp3/OkHttpClient;->newCall(Lokhttp3/Request;)Lokhttp3/Call;");
```

---

## Optional integration with `platypus-rehydrate`

Enable the `rehydrate` feature to pull in the `platypus-rehydrate` crate and unlock:

* `Deobfuscator::apply_to_activity_view(&mut ActivityView)` — mutates a freshly-rehydrated activity IR in place, rewriting every obfuscated name we recognise (activity FQN, custom/fragment class names, click handlers, dynamic-modification source methods, attr-origin method refs, compose method refs, navigation targets, recursive children + item templates).
* The `apply` CLI subcommand — `platypus-dexmapper apply mapping.json activity-view.json -o out.json` (or stdout).

```sh
cargo build  -p platypus-dexmapper --features rehydrate
cargo install --path rust/platypus-dexmapper --features rehydrate
platypus-dexmapper apply mapping.json activity.json -o activity.deob.json
```

Both Tauri viewer shells (`standalone-viewer`, `ui-react`) declare this feature in their `Cargo.toml`, so the `activity_rehydrate` Tauri command automatically deobfuscates IR before returning it to the frontend whenever a mapping is loaded.

---

## What gets deobfuscated

When `Deobfuscator::apply_to_activity_view` runs, the following IR fields are rewritten:

| IR location                                    | Treated as            |
|------------------------------------------------|-----------------------|
| `ActivityView.activity_name`                   | dotted FQN            |
| `ActivityView.outgoing_navigations[].target`   | dotted FQN            |
| `UnifiedView.source::Compose.method_ref`       | JVM method ref        |
| `UnifiedView.kind::{Fragment, Custom}.class_name` | dotted FQN         |
| `UnifiedView.attrs[].origin::Dynamic.from_method` | JVM method ref     |
| `UnifiedView.click_handler.target` (code handlers) | JVM method ref    |
| `UnifiedView.navigation.target`                | dotted FQN            |
| `UnifiedView.dynamic_modifications[].from_method` | JVM method ref     |
| `UnifiedView.item_template` + `children`       | recurses              |

XML `android:onClick` handlers carry a bare method name with no class context, so they're left alone. Names with no mapping pass through unchanged — the call never fails.

---

## Mapping file shapes

### JSON

```json
{
  "mappings": [
    {
      "obfuscated_class": "p.q.a",
      "real_class": "okhttp3.OkHttpClient",
      "confidence": 0.93,
      "match_type": "structural+methods",
      "methods": [
        {
          "obfuscated_name": "a",
          "obfuscated_descriptor": "(Lokhttp3/Request;)Lokhttp3/Call;",
          "real_name": "newCall",
          "real_descriptor": "(Lokhttp3/Request;)Lokhttp3/Call;"
        }
      ],
      "fields": [
        {
          "obfuscated_name": "b",
          "obfuscated_descriptor": "Lokhttp3/Dispatcher;",
          "real_name": "dispatcher"
        }
      ]
    }
  ]
}
```

`confidence`, `match_type`, `methods`, and `fields` are all optional. A bare top-level array of mappings (without the `{"mappings": [...]}` wrapper) is also accepted.

### ProGuard

```
e.a -> org.greenrobot.eventbus.EventBus:  # confidence=0.93
    ()Lorg/greenrobot/eventbus/EventBus; a -> getDefault
    (Ljava/lang/Object;)V b -> unregister
    Lorg/greenrobot/eventbus/EventBus; a -> defaultInstance
```

Indentation distinguishes member lines from class headers. `#` starts a comment that runs to end-of-line. Methods are detected by their `(...)R` descriptor; everything else is treated as a field.

Both formats are also **writable** — `MappingFile::to_proguard()`, `MappingFile::to_json()`, and `MappingFile::save(path, fmt)`. The matcher writes mappings out in either format via the `analyze --mapping-output ...` CLI command.

---

## Producer pipeline (`--features producer`)

The default build only consumes existing mapping files. Enable the
`producer` feature for the full **build-your-own-mapping** pipeline —
download library JARs from Maven Central, parse their `.class` files,
index them into a SQLite database, then match obfuscated smali / java
against the index to produce a new mapping.

```sh
cargo install --path rust/platypus-dexmapper --features producer
```

### Pipeline

```
       Maven Central / Google Maven           Local .dex / .apk
                  │                                  │
                  ▼  resolver::download_artifact     │
       JAR / AAR (cached at ~/.dexmapper/cache/)     │
                  │                                  │
                  ▼  bytecode::extract_classes_*     ▼  bytecode_dex::classes_from_{dex,apk}
       ClassInfo  (constant pool + methods + fields + call graph)
                  │
                  ▼  descriptors::class_fingerprint  (content-addressed)
                  │  descriptors::method_signature_hash
                  │  descriptors::structural_hash
                  ▼
       SQLite index (~/.dexmapper/index.db)
       └── WAL mode · foreign keys · dedup on class_defs.fingerprint
                  │
                  ▼  analysis::smali_parser::parse_smali_dir
                  │  analysis::java_parser::parse_java_dir
                  │  analysis::dex_target::smali_classes_from_apk
       Obfuscated SmaliClass / JavaClass  (decompiled source OR raw APK)
                  │
                  ▼  matching::Matcher
       ClassMatch (fingerprint / structural / structural+methods)
                  │
                  ▼  patching::MappingBuilder
       MappingFile  (writable as ProGuard or JSON)
                  │
                  ▼  patching::SmaliPatcher / JavaPatcher
       Patched smali / java tree on disk
```

### Modules

| Module                              | Role                                                                                                  |
|-------------------------------------|-------------------------------------------------------------------------------------------------------|
| `bytecode`                          | Pure-Rust JVM `.class` parser. Constant pool, fields, methods, Code attribute walker, opcode widths.  |
| `bytecode_dex`                      | DEX bridge — converts `platypus_dex::Clazz` into the same `ClassInfo` shape so `.dex` / `.apk` files feed the indexer alongside JAR/AAR. |
| `descriptors`                       | Descriptor parsing + the three content-addressed hashes (`class_fingerprint`, `method_signature_hash`, `structural_hash`). |
| `db`                                | SQLite schema + CRUD: artifacts, classes (deduped by fingerprint), fields, methods, call edges, method/field-access fingerprints. |
| `sources::resolver`                 | Maven Central / Google Maven downloader (ureq). POM `<dependency>` walker (quick-xml). SHA-1 verification. Local-file convenience wrapper. |
| `analysis::smali_parser`            | Pure-regex smali parser — class header, fields, methods, invokes, iget/iput/sget/sput.                |
| `analysis::java_parser`             | Pure-regex jadx-Java parser — class decl, fields, methods, constructors, body-call extraction.        |
| `analysis::dex_target`              | DEX → `SmaliClass` adapter — lets the matcher consume parsed `.dex` / `.apk` classes directly, skipping baksmali / jadx. |
| `analysis::indexer`                 | Orchestrator: resolve → extract → store. JAR/AAR via Maven or local; `.dex` / `.apk` via `bytecode_dex`. Optional POM-driven transitive walk. |
| `matching`                          | Multi-tier matcher: fingerprint → structural → exact-sig → struct-hash → fuzzy.                       |
| `patching`                          | `MappingBuilder` (collect `ClassMatch` → `MappingFile`), `SmaliPatcher`, `JavaPatcher`.               |

### Multi-tier matching strategy

| Tier              | When it fires                                              | Confidence |
|-------------------|------------------------------------------------------------|-----------:|
| Class fingerprint | Identical set of `(method-name, descriptor)` pairs.         | 1.00       |
| Class structural  | Method/field count + descriptor Jaccard + hierarchy.        | 0.30-0.75  |
| structural+methods| Above, with every obfuscated method matched exact-desc.    | up to 0.95 |
| Method exact-sig  | Per-method name + full descriptor inside a matched class.   | 1.00       |
| Method struct     | Param/return + call-graph + field-access pattern match.    | 0.70       |
| Method combined   | Both exact-sig and struct hashes hit the same method.       | 0.90       |
| Method fuzzy      | Last-resort: same return type + param count.                | 0.30       |
| Field exact-type  | Within a matched class, single descriptor-only candidate.   | 0.95       |

Weights mirror the Python dexmapper exactly, so confidence values
produced by either implementation are directly comparable.

### Producer CLI

```sh
# 1a. Index from a Maven artifact (auto-resolves "LATEST").
platypus-dexmapper index com.squareup.okhttp3:okhttp:4.12.0
platypus-dexmapper index com.squareup.okhttp3:okhttp        # latest
platypus-dexmapper index --packaging aar androidx.appcompat:appcompat:1.6.1
platypus-dexmapper index --transitive com.squareup.retrofit2:retrofit:2.9.0
platypus-dexmapper index --repos https://my.nexus/maven2 com.example:lib:1.0.0

# 1b. Or index from a local JAR / AAR (no network).
platypus-dexmapper index-local /path/to/library.jar
platypus-dexmapper index-local /path/to/library.aar

# 1c. Or index Android `.dex` / `.apk` files directly — uses the
#     platypus-dex parser, no baksmali / d8 needed. Multi-dex APKs
#     are walked transparently.
platypus-dexmapper index-dex /path/to/classes.dex
platypus-dexmapper index-apk /path/to/app.apk

# 1d. Or batch-index Maven coords from a JSON manifest.
cat > deps.json <<EOF
[
  {"group": "com.squareup.okhttp3", "artifact": "okhttp", "version": "4.12.0"},
  {"group": "com.google.code.gson", "artifact": "gson",   "version": "2.10.1"}
]
EOF
platypus-dexmapper index-batch deps.json

# 2. Stats + lookups (query an existing index).
platypus-dexmapper stats
platypus-dexmapper artifacts
platypus-dexmapper lookup okhttp3.OkHttpClient
platypus-dexmapper match-method "a.b.c" "a" "(Lokhttp3/Request;)Lokhttp3/Call;"

# 3a. Analyze decompiled smali / java → produce a mapping.
platypus-dexmapper analyze --format smali \
    --mapping-output mapping.json \
    --output ./patched-smali \
    --min-confidence 0.50 \
    /path/to/decompiled/smali

# 3b. Or analyze an APK / DEX *directly* — match obfuscated classes
#     against the index without going through baksmali / jadx first.
#     `--output` isn't supported for the DEX path (no on-disk files
#     to rewrite); produce a mapping file and apply with `patch`.
platypus-dexmapper analyze --format dex \
    --mapping-output mapping.json \
    --min-confidence 0.50 \
    /path/to/app.apk
platypus-dexmapper analyze --format dex \
    --mapping-output mapping.json \
    /path/to/classes.dex

# 4. Apply an existing mapping to a source tree without re-matching.
platypus-dexmapper patch --format smali --mapping mapping.json \
    --output ./patched-smali /path/to/decompiled/smali
```

Default database location: `~/.dexmapper/index.db` — the same path the
Python tool uses, so the two implementations can share an index. Pass
`--db /custom/path` to override.

### Producer Rust API

```rust
use platypus_dexmapper::analysis::indexer::Indexer;
use platypus_dexmapper::analysis::smali_parser;
use platypus_dexmapper::db::Database;
use platypus_dexmapper::matching::Matcher;
use platypus_dexmapper::patching::{MappingBuilder, SmaliPatcher};

let db = Database::open("/tmp/index.db")?;

// 1. Index a library.
let mut log = |m: &str| eprintln!("{m}");
Indexer::new(&db).index_artifact(
    "com.squareup.okhttp3", "okhttp", "4.12.0",
    None, None, /*transitive=*/ false, &mut log,
)?;

// 2. Walk an obfuscated smali tree and build a mapping.
let classes = smali_parser::parse_smali_dir("./decompiled/smali");
let matcher = Matcher::new(&db);
let mut builder = MappingBuilder::new();
for cls in &classes {
    if let Some(cm) = matcher.match_smali_class(cls)? {
        builder.add_class_match(&cm, /*min_confidence=*/ 0.5);
    }
}
let mapping = builder.build();
mapping.save("mapping.json", "json")?;

// 3. Patch the smali tree in-place.
let patcher = SmaliPatcher::new(&mapping);
let stats = patcher.patch_directory(
    std::path::Path::new("./decompiled/smali"),
    std::path::Path::new("./patched-smali"),
    &classes,
)?;
println!("patched {}, copied {}", stats.patched, stats.skipped);
```

### Shared index with the Python tool

The SQLite schema is bit-for-bit compatible with
`dexmapper.core.db.SCHEMA_VERSION = 1`. Switch between implementations
freely — index with Python, match with Rust, or vice versa.

---

## Tests

`cargo test -p platypus-dexmapper --features "producer rehydrate"` — 43
unit tests + 1 doc test covering both format parsers, JVM-ref parsing,
inner-class translation, method-overload disambiguation, the rehydrate
IR mutation roundtrip, JVM `.class` parsing, the DEX-bridge invoke
opcode table + `L…;` stripping, SQLite schema + dedup, smali / java
source parsing, matcher fingerprint+structural tiers, ProGuard / JSON
mapping writers, the Maven POM dependency parser, inline SHA-1, and
the smali / java patchers.
