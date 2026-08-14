# platypus-vm

A Dalvik bytecode emulator for `.dex` files. Executes Smali
instructions concretely or symbolically, mocks framework / native
calls, and surfaces concrete values so the rest of the pipeline can
recover decrypted strings, resolved constants, and call arguments —
all **without an Android runtime**.

This is the engine behind Project Platypus's string-decryption-stub
identification and its "what does this obfuscated initialiser
produce?" workflows.

```
   DexFileWithRaw           ┌──────────────────────────────────────┐
        │                   │              Vm                      │
        ▼                   │ ──────────────────────────────────── │
   Vm::add_dex_file ───────▶│  registers · memory · resource table │
                            │  instruction cap                     │
                            │  optional logger                     │
                            └──────────────────────────────────────┘
                                            │
                            args ──▶ Vm::call_method ──▶ Option<Value>
                                            ▲
                                            │
                                     MockRegistry
                                  (framework / native)
```

---

## Module map

| Module               | Responsibility                                                                  |
|----------------------|---------------------------------------------------------------------------------|
| `vm`                 | The `Vm` itself — instruction dispatch, register file, call frames.             |
| `value`              | The `Value` enum (int / string / object / null / class / array).                |
| `memory`             | Object heap + array store. Refs are id-typed; reference equality preserved.     |
| `call_site_resolver` | Resolve `invoke-*` opcodes to concrete `(class_idx, method_idx)` across dexes.  |
| `mock_handler`       | `MockRegistry` + bundled mocks for `String`, `StringBuilder`, `Math`, etc.      |
| `logger`             | Pluggable instruction trace logger (level-gated).                               |

---

## A first run

```rust
use platypus_vm::{Vm, value::Value};
use platypus_dex::parser::DexFileWithRaw;

let dex = DexFileWithRaw::from_bytes(bytes, "classes.dex")?;

let mut vm = Vm::new();
vm.add_dex_file(&dex);
vm.set_instr_limit(50_000);

let result: Option<Value> = vm.call_method(
    "Lcom/example/Crypto;",
    "decryptString",
    vec![Value::Str("zVHC0sAaQ==".into())],
);
println!("decrypted = {:?}", result);
```

`call_method` walks bytecode for as many instructions as the cap
allows, then returns the value the method `return-*`'d (or `None`
when it ran past the cap or hit an unsupported opcode).

The VM is stateful — `vm.reset_for_call(limit)` clears the call stack
+ instruction counter without re-loading any dex files, so you can
emulate thousands of methods cheaply.

---

## Resource lookups inside emulation

```rust
vm.load_resources([
    (0x7f0e0023, "Welcome".to_string()),
    (0x7f0e0024, "Goodbye".to_string()),
]);

// invoke-* of getString(int) now returns the resolved literal.
```

This is how the rehydrate pipeline gets `setContentView(R.layout.X)`
to resolve to a layout path — the VM uses a small resource map
prepared from `platypus-resources::Resources` so it doesn't have to
re-walk arsc on every call.

---

## Mock handlers — replacing real calls

Framework / native methods don't have bytecode the VM can execute. To
keep emulation going, register a **mock** that produces the desired
return value:

```rust
use platypus_vm::mock_handler::MockRegistry;
use platypus_vm::value::Value;

let mut mocks = MockRegistry::new();
mocks.register_dynamic(
    "Ljava/util/Base64;->decode(Ljava/lang/String;)[B",
    |args, _state| {
        let s = args.get(0)?.as_str()?;
        let bytes = base64::decode(s).ok()?;
        Some(Value::Bytes(bytes))
    },
);
vm.mocks = mocks;
```

`MockRegistry` ships with bundled mocks for most of the common
String / StringBuilder / Math / Math / Character / Arrays / Base64
methods — see `mock_handler::builtin_*`. You only need custom mocks
for app-specific native routines (XOR-decryptors, NDK obfuscators).

Two key resolution functions:
* `method_fqn_to_key("Ljava/lang/String;->charAt(I)C")` — class +
  method-name key. Used for class-method dispatch.
* `method_fqn_to_full_key(…)` — same plus full descriptor; used
  when overload disambiguation matters.

The mocks live with the VM and survive `reset_for_call`.

---

## Concrete vs symbolic

The `Value` enum is purposely small:

```rust
pub enum Value {
    Null,
    Int(i64),
    Str(String),
    Class(String),
    Object(u64),          // id into the memory heap
    Array(u64),
    Bytes(Vec<u8>),
    Unknown,              // ← stands in for symbolic / unresolved
}
```

When an instruction operates on `Unknown`, the result is `Unknown`.
This lets the VM run past instructions it can't fully evaluate (e.g.
a method that reads a system property) while still surfacing concrete
results from the parts it *can* evaluate.

---

## Instruction caps

Every `Vm::call_method` is bounded by the configured instruction
limit (default 50,000). The cap protects against:

* **Infinite loops** in obfuscated code that branches on `Unknown`.
* **Resource exhaustion** when running emulation across thousands of
  methods (e.g. mass-decrypting strings).

Hit the cap? `call_method` returns `None` and the VM is safe to reset
or reuse.

---

## Logging

```rust
vm.enable_logging(2); // 0=off, 1=summary, 2=per-instruction
```

The logger writes to stderr by default. Useful for debugging mocked
behaviour or seeing exactly where emulation diverged.

---

## What it's used for in this repo

* **String-decryption** — find a stub method (heuristic: takes one
  `String`, returns one `String`, calls a known crypto routine),
  point the VM at it, run it against every call site. Recovers
  plaintext strings the obfuscator hid.
* **Resource-id resolution** — emulating `getString(int)` /
  `getResourceEntryName(int)` so the rehydrate pipeline can map
  static `setContentView(R.layout.foo)` calls to layout paths.
* **Setter-argument capture** — finding `setText("…")` /
  `setBackgroundColor(0xff…)` literals on `findViewById(R.id.X)`
  chains for the dynamic-modifications phase of rehydrate.

---

## When NOT to use this

* You need full Android-runtime fidelity (lifecycle callbacks, real
  framework class hierarchy, networking). Use a real emulator or a
  test device.
* You need to execute native (`.so`) code. The bundled mocks cover
  Java mainline; native libs need a different tool — see the
  `harness-loader` workspace referenced from `ui-react/src-tauri`.
