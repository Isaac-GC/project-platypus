# platypus-codegen

Code-generation backends that turn parsed DEX (`platypus-dex::ParsedDex`)
into human-readable output. Two backends:

* `smali::` — baksmali-style **Smali** pretty-printer. One method or
  one class, in.  → Smali text, out.
* `java::` — **Java decompiler**. SSA-based, with dominator-tree
  control-flow recovery, dead-code elimination, deobfuscation passes,
  and Unicode-literal reconstruction.

Both backends operate on already-parsed `Method` / `Clazz` values; they
do not touch the file system or APK. Wire them up against
[`platypus-dex`](../platypus-dex), optionally with a
[`platypus-vm`](../platypus-vm) instance for constant resolution.

```
   ParsedDex + Method ──┬─▶  smali::SmaliGenerator ──▶ String  (.smali)
                        │
                        └─▶  java::SsaBuilder ──▶ SsaForm
                                                  │
                                                  ▼
                                           DominatorTree
                                           DeadCodeDetector
                                           DeobfuscationEngine
                                                  │
                                                  ▼
                                            JavaGenerator ──▶ String (.java)
```

---

## Smali backend

The fast path. Given a method and its parent dex, emit baksmali-format
Smali — directives, instruction mnemonics with operands, label
resolution, try/catch annotations.

```rust
use platypus_codegen::smali::smali_generator::SmaliGenerator;

let smali = SmaliGenerator::new(&dex.parsed)
    .render_method(&method);
println!("{smali}");
```

`SmaliGenerator::render_class(&class_def)` emits the whole class with
field declarations, then every method body in source order. Output is
deterministic so it's safe to diff between APK versions.

---

## Java backend

The Java decompiler is layered — each pass operates on its own IR and
is independently usable.

### Pipeline

```
instructions
    │
    ▼
ssa_builder::build       ──▶  SsaForm  (phi nodes, def-use chains, value lattice)
    │
    ▼
dominator_tree::compute  ──▶  Cfg with dominators + post-dominators
    │
    ▼
z_algorithm::ReachabilityAnalyzer   ──▶  reachable / unreachable bb marks
z_algorithm::DeadCodeDetector       ──▶  DeadCodeResult (folds + drops)
    │
    ▼
deobf_engine::DeobfuscationEngine   ──▶  flattened, peephole-cleaned IR
    │
    ▼
decompiler                          ──▶  high-level Java AST (statements + expressions)
    │
    ▼
java_generator::JavaGenerator       ──▶  String (.java)
```

### One-shot use

```rust
use platypus_codegen::java::{
    java_generator::JavaGenerator,
    ssa_builder,
};

let ssa = ssa_builder::build(&method, &dex.parsed);
let java = JavaGenerator::new(&method, &dex.parsed, &ssa).render();
println!("{java}");
```

### Filtering / suppression

```rust
use platypus_codegen::java::java_generator::{JavaGenerator, MethodFilter};

let mut filter = MethodFilter::empty();
filter.suppress_class("Lcom/example/SyntheticAccessor;");
filter.suppress_method("Lcom/example/Main;", "<clinit>");

let gen = JavaGenerator::new_with_filter(&method, &dex.parsed, &ssa, &filter);
let java = gen.render();
println!("imports: {:?}", gen.import_statements());
println!("package: {}",  gen.package_name());
```

### What the decompiler recovers

* `if` / `else` / `else if`
* `while`, `do-while`, `for` (when the SSA walker can identify induction
  variables)
* `switch` (sparse + packed)
* `try` / `catch` / `finally` — driven off the CFG's exception edges
* Ternary `cond ? a : b` collapses
* String concatenation via `StringBuilder` chains
* Unicode string literals (via the `unicode` module — recovers
  `\uXXXX` escapes from compiled UTF-16)
* Synthetic-accessor and lambda-thunk inlining
* Class / method / field renaming via the deobfuscation engine
* Dead-code elimination guided by reachability + constant folding

### Deobfuscation engine

`deobf_engine::DeobfuscationEngine` is a peephole-style IR rewriter
configured by an `AnalysisConfig`. It can fold:

* `xor`-chain string decryption stubs into the resulting literal
* Junk control-flow flattening (state-machine dispatch loops)
* Identity / no-op casts and moves
* Redundant phi nodes left over from a heavy SSA pass

```rust
use platypus_codegen::java::deobf_engine::DeobfuscationEngine;

let mut engine = DeobfuscationEngine::new(&analysis_config);
let cleaned = engine.apply(decoded_instructions);
```

Each rewrite is recorded as a `DeobfuscationChange { reason, before,
after }` so the caller can present an audit trail.

### Dead-code detection

```rust
use platypus_codegen::java::z_algorithm::{DeadCodeDetector, ReachabilityAnalyzer};

let mut reach = ReachabilityAnalyzer::new(&cfg);
reach.analyze();

let mut dcd = DeadCodeDetector::new(&cfg, &insns, &analysis_config);
let result = dcd.detect();
println!("{} folded, {} dropped", result.folded.len(), result.dropped.len());
```

The Z-algorithm utility (`ZAlgorithm`) is the same one used to find
repeated instruction sequences across methods — useful for spotting
boilerplate that should be hoisted into helper functions or just
suppressed from the output.

---

## Performance + determinism

* Output is fully deterministic — same bytes in → same string out.
  Safe to commit decompiler output and diff it between APK versions.
* Decompiling a typical activity (~50 methods) takes single-digit
  milliseconds.
* Both backends are `Send + Sync` and can be run across all methods of
  a class in parallel.

---

## When to use which backend

* **Smali** — when you want a 1:1 round-trippable view of the
  bytecode. Patching workflows, manual byte-level analysis, diffing.
* **Java** — when you want to *read* the code, understand control
  flow, or feed into a higher-level analysis (the rehydrate pipeline
  uses the decoded method IR but operates closer to the SSA layer than
  the rendered Java text).

For analyses that just need typed access to instructions, skip both
backends and use [`platypus-dex`](../platypus-dex) directly.
