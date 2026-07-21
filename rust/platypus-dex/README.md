# platypus-dex

DEX parser + full Dalvik instruction decoder for Android `.dex` files.
Pure Rust, no JDK, no `baksmali` — every byte of the format is
hand-decoded, and the resulting structures are owned (`Vec<…>`,
`String`, no lifetimes) so callers don't have to fight the borrow
checker.

```
.dex bytes ─▶ parser ─▶ ParsedDex { strings, types, protos, fields, methods, classes, code }
                          │
                          ▼
                    instructions::decode_instructions ─▶ Vec<Instruction>
                          │
                          ▼
                    code_block::build_cfg ─▶ CFG with basic blocks + edges
```

The library is the foundation every higher-level crate sits on:

* [`platypus-vm`](../platypus-vm) emulates instructions decoded here.
* [`platypus-codegen`](../platypus-codegen) generates Smali and Java
  from these structures.
* [`platypus-rehydrate`](../platypus-rehydrate) walks methods + their
  CFGs to find `setContentView`, `setOnClickListener`, `startActivity`,
  Compose call graphs, …

---

## Module map

| Module           | Responsibility                                                                 |
|------------------|--------------------------------------------------------------------------------|
| `parser`         | Header, string/type/proto/field/method tables, class defs, code items, debug info. |
| `reader`         | LEB128 / sleb128 / utf-mutf-8 string decoding helpers used by the parser.      |
| `instructions`   | All 256+ Dalvik opcodes — fixed-size + variable-length (`packed-switch`, `fill-array-data`). |
| `opcode_helper`  | Mnemonic / format tables.                                                      |
| `access_flags`   | `public`, `static`, `final`, `synthetic`, etc. — typed accessors.              |
| `clazz`          | High-level `Clazz` view: fields + methods + super + interfaces.                |
| `field`          | `EncodedField` → typed `Field` with access flags + initial-value resolution.   |
| `method`         | `EncodedMethod` → `Method` with try/catch + decoded instructions on demand.    |
| `code_block`     | Build a CFG from a method's instruction list.                                  |
| `debug_info`     | DEX line-number programs (used by callers that want source positions).         |
| `multidex`       | Wrap N `DexFileWithRaw`s and resolve cross-dex class/method lookups.           |
| `helpers`        | Misc descriptor / signature utilities.                                         |

---

## Loading a dex

```rust
use platypus_dex::parser::DexFileWithRaw;

// From an APK entry (or a standalone .dex file)
let dex = DexFileWithRaw::from_bytes(bytes, "classes.dex")?;

// The decoded tables are owned and immediately queryable
let parsed = &dex.parsed;
println!("{} classes, {} methods, {} strings",
         parsed.classes.len(), parsed.methods.len(), parsed.strings.len());
```

`DexFileWithRaw` keeps the raw bytes around alongside the parsed
tables so the instruction decoder can re-read packed-switch and
fill-array-data payloads without re-opening the APK.

---

## Multi-dex

Modern apps have `classes.dex`, `classes2.dex`, `classes3.dex`, … —
the Android runtime treats them as a single classpath. `MultiDex`
mirrors that:

```rust
use platypus_dex::multidex::MultiDex;

let mut multi = MultiDex::new();
for (name, bytes) in apk.dex_files() {
    multi.add_dex_file(DexFileWithRaw::from_bytes(bytes, &name)?);
}

// Cross-dex queries
let (dex, class_def) = multi.find_class("Lcom/example/MainActivity;").unwrap();
let (dex, m_idx)     = multi.find_method("Lcom/example/MainActivity;", "onCreate").unwrap();

println!("classes: {}, methods: {}", multi.class_count(), multi.method_count());
```

`multidex::normalize_class` converts `com.example.MainActivity` to
`Lcom/example/MainActivity;` so both forms work as inputs.

---

## Decoding instructions

```rust
use platypus_dex::instructions::{decode_instructions, Instruction};

let method = /* ... pick an EncodedMethod ... */;
let code   = method.code.as_ref().unwrap();
let insns: Vec<Instruction> = decode_instructions(&code.insns, &dex.parsed);

for ins in &insns {
    println!("0x{:04x}: {}  {:?}", ins.offset, ins.mnemonic, ins.operands);
}
```

`Instruction` is one flat struct with:

* `opcode: u8` + `mnemonic: &'static str`
* `operands: Vec<Operand>` (typed: register, immediate, string-idx,
  type-idx, method-idx, field-idx, label-offset, …)
* `length: u8` (in 16-bit code units)
* `offset: u32` (start, in code units)
* Resolved metadata for invoke-* (class FQN, method name, descriptor)
  and const-string / const-class
* Variable payloads (switch tables, fill-array-data) attached when the
  decoder encounters the corresponding `payload-…` opcodes — handled
  transparently by `decode_instructions`.

The decoder is **complete** — every opcode from the [official DEX
spec](https://source.android.com/docs/core/runtime/dalvik-bytecode) is
covered, including the modern call-site forms (`invoke-polymorphic`,
`invoke-custom`, `const-method-handle`, `const-method-type`).

---

## Methods, fields, classes

```rust
use platypus_dex::clazz::Clazz;

let clazz = Clazz::from_class_def(class_def, &dex.parsed)?;

println!("class:      {}", clazz.name);            // "Lcom/example/MainActivity;"
println!("super:      {}", clazz.superclass);
println!("interfaces: {:?}", clazz.interfaces);
println!("methods:    {}", clazz.methods.len());
println!("fields:     {}", clazz.fields.len());

for m in &clazz.methods {
    if m.is_static() && m.name == "decryptString" {
        let insns = m.decoded_instructions(&dex.parsed);
        // … hand to platypus-vm
    }
}
```

`Method` and `Field` carry typed access flags
(`is_public()`, `is_static()`, `is_final()`, `is_synthetic()`,
`is_native()`, `is_abstract()`, …) so callers don't have to bit-twiddle.

---

## CFG (control-flow graph)

```rust
use platypus_dex::code_block::build_cfg;

let cfg = build_cfg(&insns);
for block in &cfg.blocks {
    println!("BB{} [{}..{}] → {:?}",
             block.id, block.start, block.end, block.successors);
}
```

Blocks split at branch targets, throws, and switch destinations.
Try/catch ranges are recorded as edges so the downstream Java
decompiler can recover `try`/`catch` structure.

---

## Performance notes

* Parsing a 50 MB multi-dex APK takes ~100-300 ms on a laptop, dominated
  by the variable-length string-data decode.
* Instructions are decoded **on demand** — `Method::decoded_instructions`
  caches the result so repeated calls are free.
* Everything is `Send + Sync`; multi-threaded analysis (e.g. xref
  scanning across all methods) just works with `rayon`.
