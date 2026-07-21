# Project Platypus — Rust workspace

The Rust side of [Project Platypus](../readme.md): a layered set of crates for
**parsing, analysing, and reconstructing Android applications**. Together they
cover the entire pipeline from raw `.apk` bytes to a fully-rehydrated activity
view tree with click handlers, navigation, dynamic modifications, and
deobfuscated library names — without running the app.

```
                        ┌─────────────────────────────────────────┐
APK bytes ──▶  apk      │   zip · binary-XML (AXML) · arsc · split│
                        └─────────────────────────────────────────┘
                               │                       │
                               ▼                       ▼
                        ┌────────────┐         ┌──────────────────┐
                        │    dex     │         │    resources     │
                        │  parser +  │         │  manifest queries│
                        │ instr.decoder       layout · drawables  │
                        └────────────┘         │  themes · styles │
                               │               └──────────────────┘
                               │                       │
                               ▼                       │
                        ┌────────────┐                 │
                        │     vm     │                 │
                        │  Smali     │                 │
                        │  emulator  │                 │
                        └────────────┘                 │
                               │                       │
                               ▼                       ▼
                        ┌──────────────┐       ┌──────────────────┐
                        │   codegen    │       │   rehydrate      │
                        │ Smali · Java │       │ UnifiedView IR   │
                        │ decompiler   │       │ (activity tree)  │
                        └──────────────┘       └──────────────────┘
                                                       │
                                                       ▼
                                                ┌──────────────┐
                                                │  dexmapper   │
                                                │ deobfuscation│
                                                │   overlay    │
                                                └──────────────┘
```

Every crate is **independently usable** — you can pull in `platypus-apk` alone
to just unzip an APK and walk its binary XML, or jump straight to
`platypus-rehydrate` for full activity reconstruction. There are no circular
dependencies, and most crates have zero external runtime deps beyond
`serde`.

---

## Crate map

| Crate                                             | Purpose                                                                                                                              |
|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| [`platypus-apk`](platypus-apk/)                   | Raw container parsers: ZIP, Android binary XML (AXML), compiled resource table (`resources.arsc`), split-APK / xapk bundles.         |
| [`platypus-dex`](platypus-dex/)                   | DEX parser + full Dalvik instruction decoder; multi-dex aware; surfaces classes, methods, fields, code items, try/catch, debug info. |
| [`platypus-vm`](platypus-vm/)                     | Smali / DEX-bytecode emulator. Symbolic execution + concrete evaluation, mock-handler injection, resource lookup, instruction caps.  |
| [`platypus-codegen`](platypus-codegen/)           | Code generation backends. Pretty-printed Smali, plus a Java decompiler with SSA, dominator tree, and structured control flow.        |
| [`platypus-resources`](platypus-resources/)       | High-level typed queries over the manifest, resource table, layout XML, drawables (vector/shape/selector/layer/ripple), and themes. |
| [`platypus-rehydrate`](platypus-rehydrate/)       | Reconstructs activity view trees. Combines manifest, resources, layout XML, DEX analysis, Compose call graph → `UnifiedView` IR.    |
| [`platypus-dexmapper`](platypus-dexmapper/)       | Loads dexmapper mapping files (JSON / ProGuard) and applies them to the rehydrate IR so R8 single-letter aliases become real names. |
| [`project_platypus_native`](src/) (root crate)    | Aggregates the above, adds taint analysis + dex-loader detection, optional PyO3 bindings (`--features python`), and a `platypus` CLI.|

The viewer apps in [`standalone-viewer/`](../standalone-viewer/) and
[`ui-react/`](../ui-react/) sit on top of `platypus-rehydrate` +
`platypus-dexmapper`; the React activity-viewer in
[`packages/activity-viewer`](../packages/activity-viewer) consumes the
serialised `UnifiedView` IR.

---

## What can it do?

### Static analysis of APKs

* **Open any APK / xapk / apkm / apks / aab.** [`platypus-apk`] handles
  ZIP central-directory parsing without unpacking the file to disk, walks
  split-APK manifests, and pulls individual entries on demand.
* **Decode binary XML and `resources.arsc`** — without a JDK, without
  `aapt2`, in pure Rust. Resolves `@string/…`, `@drawable/…`, `@id/+name`,
  `?attr/…`, and the chained-reference variants.
* **Walk every class, method, field, and instruction** in every `.dex`
  ([`platypus-dex`]). Multi-dex support out of the box; the decoder
  handles all standard Dalvik opcodes including invoke-polymorphic,
  invoke-custom, and the const-method-handle / const-method-type forms.

### Reverse engineering

* **Smali pretty-printing** ([`platypus-codegen::smali`]) — emit
  baksmali-style output from parsed DEX, suitable for diff/patch
  workflows.
* **Java decompilation** ([`platypus-codegen::java`]) — SSA-based with
  dominator-tree control flow recovery. Recovers `if`/`else`,
  `while`/`for`, `switch`, `try`/`catch`, ternary expressions; collapses
  synthetic accessors and lambda thunks; reconstructs Unicode string
  literals.
* **Symbolic + concrete execution** ([`platypus-vm`]) — emulate a method
  or instruction trace, install **mock handlers** for native / framework
  calls (`Cipher.doFinal`, `Base64.decode`, custom XOR routines), surface
  resolved constants. Used as the engine behind string-decryption-stub
  identification.
* **Cross-reference (xref) + call-graph** queries via the root crate's
  `analysis` module. CFG extraction per method, caller/callee maps.
* **Taint analysis** ([root crate `taint`]) — propagate taint through DEX
  instructions to find sources → sinks (the classic obfuscated-data-flow
  problem). Forward and backward expansion.
* **Native ELF loader detection** (`dex_loader_analysis`) — locate
  in-memory dex loaders and self-decrypting class loaders.

### Activity reconstruction (rehydration)

[`platypus-rehydrate`] is the centrepiece. Given an APK + activity FQN,
it produces an [`ActivityView`] containing:

* The **resolved view tree** — layout XML with `<include>`/`<merge>`/
  `<ViewStub>` expanded, every `@reference` resolved, drawables turned
  into structured records (SVG strings for vector, typed colour/corner/
  stroke records for shape, etc.).
* **Click / long-click / touch handlers** — XML `android:onClick` AND
  DEX `setOnClickListener` discovery.
* **Cross-activity navigation** — `startActivity` / `startActivityForResult`
  with explicit `Intent`, `FragmentTransaction.replace`,
  `NavController.navigate(int)`.
* **Post-inflation modifications** — `findViewById(R.id.x).setText("…")`,
  `setVisibility(GONE)`, `setBackgroundColor(0x…)`, `setEnabled(false)`,
  etc., grouped by view id.
* **Item templates** for `RecyclerView` / `ListView` / `GridView` /
  `ViewPager` — recovers the row layout from the adapter's
  `onCreateViewHolder` so the renderer can show repeated rows instead
  of a placeholder.
* **Jetpack Compose** reconstruction — `setContent { … }` discovery,
  composable → `ViewKind` mapping, recursive walk through composable
  bodies + their content lambdas.
* **Diagnostics** — every step records non-fatal warnings (missing
  layout, unresolved style, fragment without static binding) so the
  inspector can show *why* something wasn't reconstructed.

### Deobfuscation overlay

[`platypus-dexmapper`] reads mapping files produced by the Python
[dexmapper](../../dexmapper) tool — both flavours: JSON (rich, includes
confidence scores) and ProGuard text (de-facto interchange format).

The crate is **standalone** (no workspace deps) by default — just
mapping parsing, class/method/field lookup, JVM-ref translation. Enable
the `rehydrate` feature to also get
`Deobfuscator::apply_to_activity_view`, which rewrites every class /
method ref inside a rehydrated `ActivityView` in place so the rendered
tree shows `okhttp3.OkHttpClient.newCall` instead of `p.q.a.a`.

Both Tauri viewer shells turn the feature on and expose
`load_mapping_dialog` / `current_mapping` / `clear_mapping` commands —
loading a mapping immediately re-renders the active activity with real
names.

---

## Building

```sh
# Whole workspace
cargo build --release

# Single crate
cargo build -p platypus-rehydrate
cargo build -p platypus-dexmapper --features rehydrate

# Tests across the workspace
cargo test
```

The root crate has an optional `python` feature that builds the PyO3
extension module consumed by `main.py`:

```sh
cargo build --release --features python
```

The Tauri viewer shells live outside the workspace and build via their
own `Cargo.toml` files — see
[`standalone-viewer/src-tauri`](../standalone-viewer/src-tauri/Cargo.toml)
and [`ui-react/src-tauri`](../ui-react/src-tauri/Cargo.toml).

---

## Design choices

**Pure Rust, no JDK / SDK.** Every binary format the project consumes
is parsed in-process. No subprocess shelling out to `aapt2`,
`baksmali`, `apktool`, or `d8`. This means deterministic, reproducible
output across machines (a stated goal in the project [readme](../readme.md)).

**Zero AI in the analysis path.** Decompilation, deobfuscation, and
rehydration are all rule-based. The dexmapper integration uses
signature matching (exact + structural), not learned models.

**Layered crates, no circular deps.** You can replace the decompiler
backend, swap in a different VM, or skip rehydration entirely without
touching the rest. The activity-viewer frontend consumes a serialised
IR — it never imports any Rust type directly.

**Tauri + React for the UI.** Both shells are thin: file picker, drag
+ drop, Tauri commands that delegate to the Rust crates. The
`@platypus/activity-viewer` React package renders the IR and is
shell-agnostic — the same component drives the standalone viewer and
the main Project Platypus integration window.

---

## Where to start

* "I want to **parse an APK** and get a list of activities." →
  [`platypus-resources::Manifest`](platypus-resources/), backed by
  [`platypus-apk::axml`](platypus-apk/).
* "I want to **decompile** classes." → [`platypus-codegen::java`](platypus-codegen/)
  on top of [`platypus-dex`](platypus-dex/).
* "I want to **emulate** a string-decryption stub and see what it
  produces." → [`platypus-vm`](platypus-vm/).
* "I want the **rendered activity tree**, with click handlers + dynamic
  modifications." → [`platypus-rehydrate::rehydrate_activity`](platypus-rehydrate/).
* "I want **real names** instead of R8 aliases." →
  [`platypus-dexmapper`](platypus-dexmapper/).
* "I just want a UI for browsing one APK." → run the
  [standalone-viewer](../standalone-viewer/).

[`platypus-apk`]:        platypus-apk/
[`platypus-dex`]:        platypus-dex/
[`platypus-vm`]:         platypus-vm/
[`platypus-codegen`]:    platypus-codegen/
[`platypus-resources`]:  platypus-resources/
[`platypus-rehydrate`]:  platypus-rehydrate/
[`platypus-dexmapper`]:  platypus-dexmapper/
[`ActivityView`]:        platypus-rehydrate/
[`platypus-codegen::smali`]: platypus-codegen/
[`platypus-codegen::java`]:  platypus-codegen/
[root crate `taint`]:    src/taint.rs
