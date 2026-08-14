# Project Platypus — Features

Project Platypus is an Android reverse-engineering toolkit: a Rust analysis engine
(APK/DEX parsing, decompilation, a Dalvik VM, packer unpacking, taint analysis)
exposed both as a command-line tool and as a Tauri + React desktop application.

The same Rust crates power the CLI, the desktop UI, and an optional Python binding,
so every capability below is available from at least one of those front-ends.

---

## Supported inputs

| Format | Notes |
| --- | --- |
| `.apk` | Single / monolithic APKs |
| Split APKs | A base APK + config splits (density / language / ABI) loaded as one unit; base auto-detected |
| `.xapk` | Bundled APK + OBB packages |
| `.aab` | Android App Bundle (DEX extracted from module splits) |
| `.aar` | Android archive libraries |
| `.jar` | Java archives containing DEX/classes |
| `.dex` | Raw Dalvik executables (multidex `classes2.dex`, `classes3.dex`, … supported) |
| Embedded APKs | Nested/payload APKs found inside a loaded slot can be opened as their own slot |

Mapping files for de-obfuscation: ProGuard/R8 (`.txt`, `.map`, `.proguard`) and
Dexmapper JSON (`.json`).

---

## Decompilation & code generation

- **Java decompiler** — Dalvik bytecode → readable pseudo-Java via an SSA-based
  pipeline (SSA construction, dominator-tree / loop analysis, AST building, type
  inference, exception-handler reconstruction, import management). Option to keep or
  strip Kotlin intrinsics.
- **Smali generation** — faithful one-to-one bytecode rendering with formatted
  classes, methods, fields, and annotations.
- **Dual view** — toggle any class between decompiled Java and Smali.
- **Fully-qualified, collision-aware names** — when an obfuscated simple name (e.g.
  `wfg`) is reused across packages, references are emitted fully-qualified so they
  remain unambiguous instead of resolving to the wrong class.
- **AndroidManifest decoding** — binary `AndroidManifest.xml` (and other binary XML)
  decoded to text.

## Navigation & search

- **Package/class tree** with compacted single-child packages, access-flag badges,
  method signatures, and per-DEX grouping with class/method counts.
- **Click-to-navigate** cross-references — jump from a call site to the target
  method/class definition.
- **Global search** across class, method, and field names and string constants, with
  an optional package filter and per-kind result counts.
- **Standalone search window** (JADX-style) with tabbed filtering (All / Class /
  Method / Field / String) and query history.

## Static analysis

- **Cross-references (xrefs)** — find every caller of a method, with caller class,
  method, and code offset.
- **Call graph** — bidirectional (callers + callees), rendered as an interactive
  flow graph (pan/zoom, expand nodes, hierarchical layout).
- **Control-flow graph (CFG)** — per-method basic-block graph with block typing
  (entry / return / throw / exception-handler / normal) and classified edges
  (true / false / exception / unconditional), drawn as an SVG diagram.
- **Dynamic-DEX-loader detection** — locates `DexClassLoader`,
  `InMemoryDexClassLoader`, `PathClassLoader`, `BaseDexClassLoader`, and
  `DelegateLastClassLoader` usage, pairs them with the asset/file byte sources in the
  same method, and surfaces candidate payload paths.
- **Taint analysis** — intra-procedural forward dataflow from sources (parameters,
  sensitive API returns) to sinks across categories such as logging, network, SMS,
  storage, database, file write, crypto, reflection, command execution, WebView, and
  IPC. Available as an interactive graph that expands forward (toward sinks) and
  backward (toward sources), with per-branch overrides and re-analysis.

## Dynamic analysis — built-in Dalvik VM

- **Dalvik interpreter** executing 200+ opcodes (moves, consts, arithmetic/logic,
  memory, branching, invokes, returns) with a typed register file, a simulated object
  heap, exception semantics, and virtual-call resolution.
- **Run any method** with literal arguments and capture the result.
- **Framework mocking** — common framework calls (e.g. `Context.getString`, `Log.*`)
  are intercepted so methods run without a full Android runtime; resource IDs resolve
  against the parsed `resources.arsc`.
- **Instruction budget** (default 5,000,000) guards against infinite loops.
- **Execution tracing** at multiple verbosity levels and an optional time-travel
  debugger (per-instruction register snapshots, breakpoints, step in/over/out).
- **Cooperative threading** for methods that spawn work.

## Deobfuscation workflow

Designed for string/data deobfuscators common in obfuscated and malicious apps:

- **Mark a method** as a deobfuscator (persisted per-APK).
- **Scan call sites** — statically find every invocation, with the literal arguments
  resolved by backward constant propagation (consts, `sget`, resource-ID → string).
- **Execute** the deobfuscator at one site, all sites for a method, or every visible
  (filtered) site — run in parallel via the VM.
- **Resolved values** are applied back into the code view as inline annotations or
  substitutions (configurable).
- **Live progress** — each method row shows an `x / y deobfuscated` counter that
  updates in real time as batches complete.
- **Stop control** — cancel a slow/long run at the next batch boundary; results
  already computed are kept.
- **Caching & persistence** — scanned call sites and successfully-resolved values are
  cached per method and persist across reloads of the same APK, until the method is
  unmarked.
- **Determinism check** — optionally re-execute every site without caching to flag
  non-deterministic results.

## Packer unpacking

Static (no-device) unpacking backends with automatic packer fingerprinting:

- **Jiagu / Qihoo 360** — static carving of the hidden DEX (optional AArch64
  emulation hook for hard samples).
- **FengYue** — AES-128-CBC payload decryption + DEX carving/validation.
- **Ijiami** — locates and decrypts the secondary encrypted DEX.
- **DexShield** — carves and deobfuscates the protected DEX.
- **Virbox** — experimental / partial.

Detection reports the packer family and confidence; output is the recovered DEX
file(s) plus a JSON manifest describing stages and any unrecovered items.

## Deobfuscation mappings (ProGuard / R8 / Dexmapper)

- Load ProGuard/R8 text mappings or Dexmapper JSON.
- Reverse obfuscated class/method/field names back to originals (overload-aware),
  including inner-class propagation, applied throughout the UI.

## Resources, manifest & UI rehydration

- **Resource table** browsing (strings, colors, drawables, …) with reference
  resolution (`@string/…`, `@drawable/…`, `?attr/…`) and configuration qualifiers.
- **Manifest queries** — activities, services, receivers, providers, permissions,
  intent filters, meta-data.
- **Activity rehydration** — reconstructs an activity's UI tree from the manifest,
  layout XML (resolving `<include>` / `<merge>` / `<ViewStub>`), styles/themes,
  click handlers (`android:onClick` and dynamic listeners), navigation targets
  (`startActivity`, fragment/nav transactions), post-inflation view mutations, and
  RecyclerView/ListView adapters. Includes Jetpack Compose `setContent { … }`
  detection. Available in a standalone Activity Viewer window.
- **ZIP entry viewer** — read any entry; binary XML auto-decoded, text returned as
  UTF-8, binary shown as a hex dump.

## Multi-APK projects & diffing

- **Slots** — load multiple APKs simultaneously, each with a display name; switch the
  active (decompiled) slot freely.
- **Comparison slot** — designate a second APK and **diff** classes/methods
  side-by-side (LCS line diff: equal / add / remove, with a plaintext fallback for
  very large files).
- **Persistent project** — slots, deobfuscation marks/values, open tabs, applied
  renames, and per-slot view state are cached and restored across sessions.

## Python scripting

- Embedded **CodeMirror** editor with Python syntax highlighting.
- **Live Platypus API** exposed to scripts, with introspected autocomplete and
  linting.
- Save / load / rename / delete scripts from a persistent library.
- Run with captured stdout/stderr, a run timeline with timings, traceback mapping to
  user code, and a kill button.

## Desktop UI overview

- **Resizable multi-pane layout**: navigator tree (left), code viewer (center),
  details (right), and a tabbed bottom panel.
- **Right-panel tabs**: Info (class metadata), Xrefs, CFG, Run (method execution),
  Script.
- **Bottom-panel tabs**: Logs, Execution (find-and-execute), Deobfuscation, Search,
  Diff.
- **Standalone windows**: Search, Taint Analysis, Activity Viewer.
- **Settings**: code font size/family, theme (light/dark), and deobfuscation view
  mode (annotated vs. substituted).
- Keyboard shortcuts (e.g. search, settings); cross-window communication over the
  Tauri event bus.

## Command-line interface (`platypus`)

Accepts an APK/XAPK/AAB/split-directory/DEX and supports:

- **Decompilation**: `--smali`, `--java`, `--smali-out <dir>`, `--java-out <dir>`,
  with `--class <substr>` / `--method <substr>` filters and `--threads <n>`.
- **VM execution**: `--run <Lclass;->method>`, `--run-args <a,b,…>`, and
  `--verbose 1|2|3` execution tracing.
- **Call-site analysis & deobfuscation**: `--find <method>`,
  `--find-exec <method>` (resolve args and execute each site, caching identical
  inputs), and `--validate-deobf` (determinism check).
- **Output formats**: `--output text | json | csv` (NDJSON for streaming/`jq`).
- Reports DEX version, SHA-256, and class/method/instruction/block statistics.

A separate `unpack` binary runs the packer-unpacking backends in batch.

---

## Architecture (Rust workspace)

| Crate | Responsibility |
| --- | --- |
| `platypus-apk` | ZIP/APK/XAPK parsing, split-APK aggregation, binary AXML & `resources.arsc` decoding, AES-CBC helpers |
| `platypus-dex` | DEX parser, class/method/field model, instruction decoding, CFG construction, multidex, debug info |
| `platypus-codegen` | Smali generation and the SSA/dominator-tree/AST-based Java decompiler |
| `platypus-vm` | Dalvik bytecode interpreter (heap, exceptions, mocks, debugger, threading) |
| `platypus-unpackers` | Packer detection + static unpacking backends (Jiagu, FengYue, Ijiami, DexShield, …) |
| `platypus-dexmapper` | ProGuard/R8 + JSON mapping loading and name resolution |
| `platypus-resources` | Typed manifest/resource/layout/style/theme queries |
| `platypus-rehydrate` | Activity UI-tree reconstruction (layouts, handlers, navigation, RecyclerView, Compose) |
| `project_platypus_native` (root) | Orchestration: call-site analysis, taint, dynamic-loader detection, the `platypus` CLI, and PyO3 Python bindings |

The desktop app (`ui-react/`) is a React front-end over a Tauri (Rust) backend that
calls these crates directly.
