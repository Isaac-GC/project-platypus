# OLLVM binary hardening — status & runbook

Status of compiling the Project Platypus native binaries with OLLVM-style
obfuscation (control-flow flattening, bogus control flow, instruction
substitution, MBA, global/string encryption, indirect calls). The goal is
defense-in-depth for the license gate — make `require_feature`
(see [`licensing.md`](licensing.md)) costly to patch out.

> **This is a parked, out-of-repo effort.** The toolchain is built and compiling
> but unverified and **not** applied to any shipped binary. This doc exists so
> that state isn't only living in an untracked sibling directory.

---

## TL;DR

| Piece | State |
|---|---|
| Passes ported to LLVM 21.1 (from Pluto / OLLVM) | ✅ all 7 + 2 helpers, placed in the LLVM tree |
| `libLLVMObfuscation.a` built | ✅ standalone **and** inside the Rust toolchain's LLVM |
| Patched `rustc` built | ✅ through **stage1** (`aarch64-apple-darwin`) |
| Toolchain installed (`x.py install`) | ❌ `rust-install/` not created |
| Passes semantically verified (smoke test) | ❌ status is `compiles`, not `tested` |
| Wired into the Platypus build | ❌ no `RUSTFLAGS` / toolchain pin / CI reference |

Net: the toolchain is assembled and compiling; it has **never obfuscated a real
Platypus binary**.

---

## Where it lives

Everything is in the untracked sibling directory
`/Users/isaac/Develop/ollvm-build/` (not under git):

```text
ollvm-build/
├── ollvm-port/       # the port plan + the pass sources (README = the spec)
├── llvm-project/     # LLVM 21.1 checkout with the Obfuscation passes applied
│   ├── llvm/lib/Transforms/Obfuscation/   # ported .cpp/.h land here
│   └── build-obf/lib/libLLVMObfuscation.a # standalone pass-library build
├── rust/             # rust-lang/rust checkout (rustc 1.93 pin) building against
│   │                 # the patched llvm-project
│   ├── bootstrap.toml                     # the toolchain wiring (below)
│   └── build/aarch64-apple-darwin/
│       ├── stage1/bin/rustc               # the patched compiler
│       └── llvm/lib/libLLVMObfuscation.a  # obfuscation lib linked into libLLVM
├── pluto/            # upstream Pluto-Obfuscator (LLVM 14) — the port source
└── heroims-ollvm/    # legacy-PM OLLVM patches — reference only
```

The authoritative spec is **`ollvm-build/ollvm-port/README.md`**: the pass
inventory, every LLVM 14→21 API change handled, the deviations from upstream
(notably MBA without libz3, and `LowerSwitch` now being the caller's job), and
the build + smoke-test commands.

## Pass inventory

All ported and at status **`compiles`** (built clean, not yet `tested`):

| Pass | `-passes=` name | What it does |
|---|---|---|
| Substitution | `ollvm-sub` | rewrite arithmetic into equivalent obscured forms |
| BogusControlFlow | `ollvm-bcf` | inject never-taken branches guarded by opaque predicates |
| Flattening | `ollvm-fla` | control-flow flattening (the dispatcher/state-machine shape) |
| MBAObfuscation | `ollvm-mba` | mixed boolean-arithmetic identities |
| GlobalEncryption | `ollvm-gle` | encrypt globals / string literals, decrypt at runtime |
| IndirectCall | `ollvm-idc` | route direct calls through a pointer table |

Helpers `CryptoUtils` and `MBAUtils` have no registry entry. `ollvm-fla` does
**not** run `LowerSwitch` itself — prepend `lowerswitch,` if the input has
`switch` instructions.

## Toolchain wiring (`ollvm-build/rust/bootstrap.toml`)

- `build.target = ["aarch64-apple-darwin"]`, **stage 1 only** (stage 0 uses the
  downloaded beta compiler unchanged; stage 1 rebuilds rustc + libstd against the
  patched LLVM).
- `install.prefix = "/Users/isaac/Develop/ollvm-build/rust-install"`.
- `rust.download-rustc = false`, `llvm.download-ci-llvm = false` (use the local
  patched LLVM, not a CI download).
- `llvm.targets = "AArch64"`, assertions off.
- The critical line links the patched Obfuscation library into `libLLVM` — without
  it the passes build but never get registered in the compiler that ships.

---

## Finishing it: three steps to wire into Platypus

### 1. Verify the passes (`compiles → tested`)

From `ollvm-build/llvm-project/build-obf` (after a `ninja LLVMObfuscation
LLVMPasses opt clang`):

```sh
echo 'int main(int c, char **v){ return c + 1 - 1; }' > /tmp/hello.c
./bin/clang -O1 /tmp/hello.c -mllvm -passes=ollvm-sub -o /tmp/hello && /tmp/hello
echo "exit=$?"   # must match the unobfuscated build (0)
```

Repeat per pass (`ollvm-bcf`, `lowerswitch,ollvm-fla`, `ollvm-mba`, `ollvm-gle`,
`ollvm-idc`). Each pass that round-trips a real input gets promoted from
`compiles` to `tested` in `ollvm-port/README.md`.

### 2. Build + install the toolchain

```sh
cd ollvm-build/rust
./x.py build  --stage 1
./x.py install               # populates ollvm-build/rust-install/  (currently missing)
rustup toolchain link ollvm-platypus /Users/isaac/Develop/ollvm-build/rust-install
```

### 3. Apply it to the Platypus build (CI-only recommended)

Don't gate developer builds on it — it's slow and only matters for shipped
binaries. Apply it in `release.yml` for the Rust/Tauri build steps:

```sh
# pin the toolchain for the release job
rustup override set ollvm-platypus      # or +ollvm-platypus on each cargo call

# request the passes via llvm-args; start conservative (sub + bcf) and add fla last
export RUSTFLAGS="-C llvm-args=-passes=ollvm-sub,ollvm-bcf -C llvm-args=-mllvm"
cargo build --release -p project-platypus-ui
```

Apply selectively — obfuscate the crates that hold the gate
(`platypus-license`, the Tauri `license`/command layer), not the whole
workspace, to keep size and build time sane. There is **no project_platypus
wiring today** (no `rust-toolchain.toml`, no `RUSTFLAGS`, no CI reference); this
step is greenfield.

---

## Caveats

- **Not DRM.** Obfuscation raises the cost of patching the license check; it does
  not make it impossible. Same honest limit as `docs/licensing.md` §6 — this is
  defense-in-depth, layered on the node-locked token, not a replacement for it.
- **Cost.** Flattening + BCF inflate binary size and slow hot paths; MBA is the
  heaviest. Measure, and scope passes to the gate crates rather than the VM /
  decompiler hot loops.
- **Debuggability.** Obfuscated release crashes are painful to triage — keep an
  unobfuscated build of the same commit for symbolication, and don't obfuscate
  debug builds.
- **Maintenance.** The port pins LLVM 21.1 / rustc 1.93. Each Rust upgrade may
  move LLVM and reopen the 14→21-style API churn documented in the port README.
- **macOS only.** The build targets `aarch64-apple-darwin`. Windows/Linux release
  targets would each need their own patched toolchain.

## Related, but separate: detecting OLLVM in *targets*

Distinct from hardening our own binaries, the analyzer **identifies**
OLLVM-obfuscated input binaries: `malware_analyzer/catalog.py` carries
byte-signatures for Obfuscator-LLVM, its successor Arkari, and a lowercase
`ollvm` marker (control-flow flattening + bogus control flow + substitution).
That is detection only — there is no native OLLVM *deobfuscator* in the product.
