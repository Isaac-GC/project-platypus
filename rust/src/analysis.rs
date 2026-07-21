//! Shared DEX analysis: call-site discovery and VM-assisted execution.

use std::collections::HashMap;

use crate::apk::arsc::ResourceTable;
use crate::dex::instructions::Instruction;
use crate::dex::method::Method;
use crate::dex::parser::DexFileWithRaw;
use crate::dex::clazz::Clazz;
use crate::dex::debug_info;
use crate::vm::vm::Vm;
use crate::vm::value::Value;
use crate::vm::logger::format_value;

// ── Call site ─────────────────────────────────────────────────────────────────

/// One call site where a target method is invoked.
#[derive(Debug, Clone)]
pub struct CallSite {
    pub caller_class:  String,
    pub caller_method: String,
    pub source_file:   String,
    pub line_number:   Option<u32>,
    pub invoke_cp:     u32,
    pub invoke_str:    String,
    pub arg_regs:      Vec<u32>,
    /// Statically resolved arg values, encoded as strings.
    /// See `resolve_static_args` for the encoding format.
    pub static_args:   Vec<(u32, Option<String>)>,
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Scan all classes/methods in `dex` for invoke instructions matching
/// `target_pattern` (e.g. `"Lhivhi/wfg;->bihvbhi"`).
pub fn find_calls(dex: &DexFileWithRaw, target_pattern: &str) -> Vec<CallSite> {
    let mut sites = Vec::new();
    let no_index: u32 = 0xffff_ffff;

    for class_def in &dex.parsed.class_defs {
        let source_file = if class_def.source_file_idx != no_index {
            dex.parsed.strings
                .get(class_def.source_file_idx as usize)
                .map(|s| s.data.clone())
                .unwrap_or_default()
        } else {
            String::new()
        };

        let clazz = match Clazz::new(class_def, dex) {
            Ok(c) => c,
            Err(_) => continue,
        };

        for method in &clazz.methods {
            for instr in &method.instructions {
                let istr = &instr.instruction_str;
                if !istr.contains("invoke") { continue; }

                let matches = if let Some(pos) = istr.find("}, ") {
                    istr[pos + 3..].contains(target_pattern)
                } else if let Some(pos) = istr.find("} ..") {
                    istr[pos..].contains(target_pattern)
                } else {
                    istr.contains(target_pattern)
                };
                if !matches { continue; }

                let arg_regs   = extract_arg_regs(instr);
                let static_args = resolve_static_args(
                    &method.instructions, instr.codepoint, &arg_regs,
                );
                let line_number = debug_info::lookup_line(&method.line_map, instr.codepoint);

                sites.push(CallSite {
                    caller_class:  method.class_name.clone(),
                    caller_method: format!("{}{}", method.method_name, method.proto_desc),
                    source_file:   source_file.clone(),
                    line_number,
                    invoke_cp:     instr.codepoint,
                    invoke_str:    istr.clone(),
                    arg_regs,
                    static_args,
                });
            }
        }
    }

    sites
}

/// Execute the target method (identified by `target`, e.g. `"Lhivhi/wfg;->bihvbhi"`)
/// once for each call site in `sites`, using statically resolved + resource-resolved args.
///
/// Returns `(site, Option<Value>)` pairs in the same order as `sites`.
///
/// `resources` — if provided, string resources are loaded into the VM so that
/// `Context.getString(int)` calls and R$string field references are resolved.
///
/// `instr_limit` — maximum instructions per call (default 5_000_000).
///
/// **Default budget rationale:** real-world deobfuscators typically need
/// 100k–2M instructions per call (initial table builds, AES-CBC chains, etc),
/// so the historic 50k cap silently bricked most non-trivial methods. 5M is
/// generous enough for almost everything while still bounding pathological
/// loops at ~30s wall-clock at our debug-build interpreter rate.
pub fn exec_calls(
    dex: &DexFileWithRaw,
    sites: &[CallSite],
    target: &str,
    resources: Option<&ResourceTable>,
    instr_limit: Option<u64>,
) -> Vec<(CallSite, Option<Value>)> {
    const DEFAULT_LIMIT: u64 = 5_000_000;
    let limit = instr_limit.unwrap_or(DEFAULT_LIMIT);

    let (target_class, target_method_name) = match parse_target_ref(target) {
        Some(pair) => pair,
        None       => return sites.iter().cloned().map(|s| (s, None)).collect(),
    };

    let target_method = match find_method_in_dex(dex, &target_class, &target_method_name) {
        Some(m) => m,
        None    => return sites.iter().cloned().map(|s| (s, None)).collect(),
    };

    let mut vm = Vm::new();
    // Use the already-parsed DEX directly. `add_dex_file` clones it into
    // the VM's own storage, so re-parsing it from raw bytes here was pure
    // duplicated work.
    vm.add_dex_file(dex);

    // Preload string resources so getString() calls resolve.
    if let Some(table) = resources {
        vm.load_resources(
            table.entries().iter()
                .filter(|e| e.type_name == "string")
                .filter_map(|e| table.resolve(e.id).map(|v| (e.id, v)))
        );
    }

    // ── In-batch result memoisation ──
    // Two call sites that pass the same static-arg fingerprint resolve to the
    // same plaintext (assuming the deobfuscator is pure of inputs — true for
    // every string/method-name decryption helper we've seen). For 100 call
    // sites with 30 unique inputs this is roughly a 3× speedup; the cache
    // covers BOTH the resolution pass (which can recursively invoke other
    // VM methods for `@sget:` / `@invoke!` chains) and the execution pass
    // (running the deobfuscator's bytecode).
    //
    // Cache lifetime is the duration of this call only — discarded when we
    // return so it doesn't leak into a subsequent batch where the deobf
    // implementation may have changed.
    let mut cache: HashMap<String, Option<Value>> = HashMap::new();
    let mut results = Vec::with_capacity(sites.len());
    for site in sites {
        let key = static_args_fingerprint(&site.static_args);
        if let Some(cached) = cache.get(&key) {
            results.push((site.clone(), cached.clone()));
            continue;
        }

        // Resolution pass: resolve @invoke! / @sget: chains.
        vm.reset_for_call(limit);
        let args = coalesce_call_args(
            &site.static_args,
            &site.invoke_str,
            &target_method.proto_desc,
            resources,
            &mut vm,
        );

        // Execution pass.
        vm.reset_for_call(limit);
        let result = vm.call_method(&target_method, args);
        cache.insert(key, result.clone());
        results.push((site.clone(), result));
    }

    results
}

/// Stable fingerprint for a call site's `static_args` vec. Two sites whose
/// static_args produce the same fingerprint will, by construction, decrypt
/// to the same plaintext via a pure deobfuscator — which lets `exec_calls`
/// memoise results across the batch.
///
/// Uses ASCII unit-separator (0x1F) as a delimiter — it never appears in our
/// arg encodings (literal strings are quoted, hex is bare, `@sget:`/`@invoke!`
/// only use printable chars).
///
/// Public so the CLI `--find-exec` path (`exec_usages` in `main.rs`) can
/// share the exact same key and stay consistent with `exec_calls`.
pub fn static_args_fingerprint(static_args: &[(u32, Option<String>)]) -> String {
    static_args.iter()
        .map(|(_, v)| v.as_deref().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\x1f")
}

/// Convenience: find all call sites for `target` in `dex`, then execute each one.
/// Equivalent to `exec_calls(dex, &find_calls(dex, target), target, resources, instr_limit)`.
pub fn find_and_exec(
    dex: &DexFileWithRaw,
    target: &str,
    resources: Option<&ResourceTable>,
    instr_limit: Option<u64>,
) -> Vec<(CallSite, Option<Value>)> {
    let sites = find_calls(dex, target);
    exec_calls(dex, &sites, target, resources, instr_limit)
}

// ── Parallel exec ─────────────────────────────────────────────────────────────
//
// `exec_calls_parallel` chunks `sites` across `num_threads` workers,
// each with its own `Vm`. This is the right shape for a single
// deobfuscator with many call sites — building a fresh VM per worker
// is cheap (one DEX clone + lookup-map build) but executing many
// sites is not. With method_cache + class_index it's typically <100ms
// of VM-setup per worker; the per-site execution time dominates.
//
// Trade-off vs the sequential `exec_calls`: we lose the in-batch
// memoisation cache (each worker has its own), so call sites that
// would have hit the cache pay the full VM cost. For real
// deobfuscators where N sites share K distinct arg fingerprints
// (K << N), sequential is sometimes faster. We mitigate by
// preserving each worker's intra-chunk memo — workers that get
// adjacent sites (likely from the same caller) hit their local
// caches just as well.
//
// `num_threads` of 0 or 1 falls back to the sequential path.

/// Parallel version of [`exec_calls`]. Splits `sites` into approximately
/// equal chunks across `num_threads` scoped-thread workers (via the
/// internal [`platypus_dex::parallel`] helper — no external threadpool);
/// each worker runs its chunk against its own VM. Results are returned in
/// the same order as `sites`.
pub fn exec_calls_parallel(
    dex: &DexFileWithRaw,
    sites: &[CallSite],
    target: &str,
    resources: Option<&ResourceTable>,
    instr_limit: Option<u64>,
    num_threads: usize,
) -> Vec<(CallSite, Option<Value>)> {
    use platypus_dex::parallel;

    if sites.is_empty() {
        return Vec::new();
    }
    // Falling back keeps the in-batch memo for small workloads where
    // VM-setup dominates.
    if num_threads <= 1 || sites.len() < 4 {
        return exec_calls(dex, sites, target, resources, instr_limit);
    }

    // Round-robin sites into chunks of roughly equal size so adjacent
    // sites (likely from the same caller class) stay in the same
    // worker's local memo — improves intra-chunk cache hit rate vs a
    // contiguous split.
    let chunks: Vec<Vec<CallSite>> = {
        let mut chunks: Vec<Vec<CallSite>> = (0..num_threads).map(|_| Vec::new()).collect();
        for (i, s) in sites.iter().enumerate() {
            chunks[i % num_threads].push(s.clone());
        }
        chunks
    };

    // Each worker gets a snapshot of `(index, site)` so we can reassemble
    // original order after the parallel pass.
    let chunk_indices: Vec<Vec<usize>> = {
        let mut idxs: Vec<Vec<usize>> = (0..num_threads).map(|_| Vec::new()).collect();
        for i in 0..sites.len() {
            idxs[i % num_threads].push(i);
        }
        idxs
    };

    // Each worker runs the sequential `exec_calls` path on its chunk:
    // that builds its own VM (Vm is !Sync, so one per worker is required)
    // and keeps its own in-batch memo cache. The parsed `dex` is shared by
    // reference across workers (DexFileWithRaw is Sync), so there's no
    // per-worker DEX re-parse or raw-byte clone anymore — only the single
    // unavoidable clone `add_dex_file` makes into each worker's VM.
    //
    // `parallel::map_heavy` spawns one scoped thread per chunk (these are
    // coarse work units — each runs a whole VM), so the caller's
    // `num_threads` chunking directly sets the parallelism. No external
    // threadpool: the helper is built on `std::thread::scope`.
    let work: Vec<(Vec<CallSite>, Vec<usize>)> =
        chunks.into_iter().zip(chunk_indices).collect();
    let worker_results: Vec<Vec<(usize, Option<Value>)>> =
        parallel::map_heavy(work, |(my_sites, my_indices)| {
            let local = exec_calls(dex, &my_sites, target, resources, instr_limit);
            my_indices.into_iter()
                .zip(local.into_iter().map(|(_site, val)| val))
                .collect()
        });

    // Reassemble in original site order.
    let mut results: Vec<Option<(CallSite, Option<Value>)>> = vec![None; sites.len()];
    for chunk in worker_results {
        for (idx, val) in chunk {
            if let Some(slot) = results.get_mut(idx) {
                *slot = Some((sites[idx].clone(), val));
            }
        }
    }
    results.into_iter()
        .map(|opt| opt.unwrap_or_else(|| (CallSite {
            caller_class: String::new(), caller_method: String::new(),
            source_file: String::new(), line_number: None,
            invoke_cp: 0, invoke_str: String::new(),
            arg_regs: Vec::new(), static_args: Vec::new(),
        }, None)))
        .collect()
}

/// Parallel variant of [`find_and_exec`]: find all sites for `target`
/// in `dex`, then execute them across `num_threads` workers.
pub fn find_and_exec_parallel(
    dex: &DexFileWithRaw,
    target: &str,
    resources: Option<&ResourceTable>,
    instr_limit: Option<u64>,
    num_threads: usize,
) -> Vec<(CallSite, Option<Value>)> {
    let sites = find_calls(dex, target);
    exec_calls_parallel(dex, &sites, target, resources, instr_limit, num_threads)
}

/// Format a `Value` as a human-readable string (delegates to the VM logger helper).
pub fn format_result(v: &Option<Value>) -> String {
    match v {
        Some(v) => format_value(v),
        None    => "void".to_string(),
    }
}

// ── Internal helpers (mirrors main.rs) ────────────────────────────────────────

fn extract_arg_regs(instr: &Instruction) -> Vec<u32> {
    use crate::dex::instructions::InstructionKind;
    match &instr.kind {
        InstructionKind::InvokeKind => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let regs  = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
            regs[..count.min(5)].iter()
                .filter_map(|&v| v.map(|x| x as u32))
                .collect()
        }
        InstructionKind::InvokeKindRange => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let start = instr.v_c.unwrap_or(0) as u32;
            (0..count as u32).map(|i| start + i).collect()
        }
        _ => Vec::new(),
    }
}

fn resolve_static_args(
    instructions: &[Instruction],
    invoke_cp: u32,
    arg_regs: &[u32],
) -> Vec<(u32, Option<String>)> {
    let mut results: Vec<(u32, Option<String>)> =
        arg_regs.iter().map(|&r| (r, None)).collect();
    let mut unresolved: std::collections::HashSet<usize> = (0..results.len()).collect();

    let mut before: Vec<&Instruction> = instructions
        .iter()
        .filter(|i| i.codepoint < invoke_cp)
        .collect();
    before.sort_by_key(|i| i.codepoint);

    let n = before.len();
    let mut idx = n;
    while idx > 0 && !unresolved.is_empty() {
        idx -= 1;
        let instr = before[idx];
        let istr  = &instr.instruction_str;

        if istr.starts_with("const-string") {
            if let Some(dest_reg) = parse_dest_reg(istr) {
                if let Some(comma) = istr.find(", ") {
                    let value = istr[comma + 2..].trim().trim_matches('"').to_string();
                    mark_resolved(&mut results, &mut unresolved, dest_reg,
                                  Some(format!("\"{}\"", value)));
                }
            }
        } else if istr.starts_with("const") && !istr.starts_with("const-string") {
            if let Some(dest_reg) = parse_dest_reg(istr) {
                if let Some(comma) = istr.find(", ") {
                    let value_part = istr[comma + 2..].trim().to_string();
                    mark_resolved(&mut results, &mut unresolved, dest_reg, Some(value_part));
                }
            }
        } else if istr.starts_with("sget") {
            if let Some(dest_reg) = parse_dest_reg(istr) {
                let is_relevant = unresolved.iter().any(|&i| results[i].0 == dest_reg);
                if is_relevant {
                    if let Some(comma) = istr.find(", ") {
                        let field_ref = istr[comma + 2..].trim().to_string();
                        mark_resolved(&mut results, &mut unresolved, dest_reg,
                                      Some(format!("@sget:{}", field_ref)));
                    }
                }
            }
        } else if istr.starts_with("move-result") {
            if let Some(dest_reg) = parse_dest_reg(istr) {
                let is_relevant = unresolved.iter().any(|&i| results[i].0 == dest_reg);
                if is_relevant && idx > 0 {
                    let prev      = before[idx - 1];
                    let prev_istr = &prev.instruction_str;
                    if prev_istr.contains("invoke") {
                        if let Some(method_ref) = extract_method_ref_from_invoke(prev_istr) {
                            let prev_arg_regs = extract_arg_regs(prev);
                            let inner         = resolve_static_args(
                                instructions, prev.codepoint, &prev_arg_regs,
                            );
                            let inner_encoded: Vec<String> = inner.iter().map(|(_, v)| {
                                v.clone().unwrap_or_else(|| "@unresolved".to_string())
                            }).collect();
                            let encoded = format!(
                                "@invoke!{}!{}", method_ref, inner_encoded.join("|")
                            );
                            mark_resolved(&mut results, &mut unresolved, dest_reg, Some(encoded));
                        }
                    }
                }
            }
        }
    }

    results
}

fn parse_dest_reg(istr: &str) -> Option<u32> {
    let after_op = istr.split_whitespace().nth(1)?;
    let reg_str  = after_op.trim_end_matches(',');
    if reg_str.starts_with('v') { reg_str[1..].parse().ok() } else { None }
}

fn extract_method_ref_from_invoke(istr: &str) -> Option<String> {
    let after = istr.find("}, ")
        .or_else(|| istr.find("} .."))
        .map(|p| p + 3)
        .unwrap_or_else(|| istr.rfind('}').map(|p| p + 1).unwrap_or(0));
    let ref_and_sig  = istr[after..].trim();
    let method_ref   = ref_and_sig.split('(').next()?.trim().to_string();
    if method_ref.is_empty() { None } else { Some(method_ref) }
}

fn mark_resolved(
    results:    &mut Vec<(u32, Option<String>)>,
    unresolved: &mut std::collections::HashSet<usize>,
    reg: u32,
    value: Option<String>,
) {
    let to_mark: Vec<usize> = unresolved.iter()
        .filter(|&&i| results[i].0 == reg)
        .cloned()
        .collect();
    for idx in to_mark {
        results[idx].1 = value.clone();
        unresolved.remove(&idx);
    }
}

fn parse_target_ref(target: &str) -> Option<(String, String)> {
    let mut parts = target.splitn(2, "->");
    let class  = parts.next()?.to_string();
    let method = parts.next()?
        .splitn(2, '(').next().unwrap_or("").trim().to_string();
    Some((class, method))
}

pub fn find_method_in_dex(dex: &DexFileWithRaw, class_raw: &str, method_name: &str) -> Option<Method> {
    let class_norm = class_raw.trim_start_matches('L').trim_end_matches(';');
    for class_def in &dex.parsed.class_defs {
        let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
        if def_norm != class_norm { continue; }
        let clazz = Clazz::new(class_def, dex).ok()?;
        for m in clazz.methods {
            if m.method_name == method_name { return Some(m); }
        }
    }
    None
}

/// Parse a Dalvik proto descriptor like `"(JLjava/lang/String;)V"` into a
/// vector of single-type descriptors: `["J", "Ljava/lang/String;"]`.
///
/// Each entry is one *Java parameter*, NOT one register slot — the
/// caller of this function combines that knowledge with the slot
/// widths (J/D = 2, all others = 1) to walk a `static_args` vector
/// that's indexed by register operand.
fn parse_param_types(proto: &str) -> Vec<String> {
    let mut params = Vec::new();
    let open = match proto.find('(') {
        Some(i) => i + 1,
        None    => return params,
    };
    let close = match proto[open..].find(')') {
        Some(i) => open + i,
        None    => return params,
    };
    let chars: Vec<char> = proto[open..close].chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '[' => {
                let start = i;
                while i < chars.len() && chars[i] == '[' { i += 1; }
                if i < chars.len() && chars[i] == 'L' {
                    // Array of objects — consume through `;`.
                    while i < chars.len() && chars[i] != ';' { i += 1; }
                    if i < chars.len() { i += 1; } // consume ';'
                } else if i < chars.len() {
                    i += 1; // consume primitive element type
                }
                params.push(chars[start..i].iter().collect());
            }
            'L' => {
                let start = i;
                while i < chars.len() && chars[i] != ';' { i += 1; }
                if i < chars.len() { i += 1; } // consume ';'
                params.push(chars[start..i].iter().collect());
            }
            _ => {
                params.push(chars[i].to_string());
                i += 1;
            }
        }
    }
    params
}

/// Build the `Vec<Value>` to hand to `Vm::call_method` from a call
/// site's static args, **respecting wide-register layout** for `J`/`D`
/// parameters.
///
/// **Why this exists.** The static-arg backprop walks back from the
/// invoke instruction and notes whichever register a `const-wide`
/// instruction wrote to. For a long `0xfff69efc00025a53` stored via
/// `const-wide v0`, the analysis ends up with
/// `static_args = [(v0, Some("0xfff69efc00025a53")), (v1, None)]`.
/// The full 64-bit value is attached to v0 (because that's the
/// instruction's named destination), and v1 — the wide pair's other
/// slot — stays unresolved.
///
/// Naïvely mapping each `static_args` entry to one `Value` via
/// `resolve_arg_encoding` gives `[Int(full_long), Null]`. The VM's
/// `call_method` then drops those into two consecutive register slots
/// and a downstream `move-wide` reads:
/// `(slot_N_as_i32 << 32) | slot_N+1_as_u32`. The high half gets
/// truncated to its low 32 bits, the low half becomes 0, and the
/// reconstructed long is wrong. SystemAndroid (an AES-CBC key
/// derivation keyed off the long) then decrypts to garbage and
/// returns void — which is the bug the user reported on `--find-exec`.
///
/// **What this does.** Parses the target's proto descriptor and walks
/// the static_args in lockstep:
/// * For a non-wide param (everything except `J`/`D`) — push one
///   `Value` resolved from the corresponding `static_args` entry.
/// * For a wide param — read the 64-bit value from the *current*
///   static_args slot (where the disassembler attributed it), split it
///   into `(high, low)` per the VM's `read_wide` contract (`slot N =
///   high`, `slot N+1 = low`), and push both `Value::Int`s. The
///   second static_args entry (the previously-unresolved high slot)
///   is consumed and discarded.
///
/// Instance methods get an implicit `this` slot at static_args\[0\];
/// we detect that from `invoke_str` and pass it through unchanged
/// (typically `Value::Null` for deobfuscator analysis — the
/// deobfuscator doesn't read its `this`).
///
/// Any encoding that doesn't parse as an integer falls through to
/// `resolve_arg_encoding`, preserving the existing behaviour for
/// strings, `@sget:` chains, and `@invoke!` chains.
pub fn coalesce_call_args(
    static_args: &[(u32, Option<String>)],
    invoke_str: &str,
    proto_desc: &str,
    resources: Option<&ResourceTable>,
    vm: &mut Vm,
) -> Vec<Value> {
    let param_types = parse_param_types(proto_desc);
    let is_instance = !invoke_str.contains("invoke-static");

    let mut out: Vec<Value> = Vec::with_capacity(static_args.len());
    let mut cursor = 0usize;

    // Instance methods: first register operand is `this`. The
    // deobfuscator path almost always sees `Value::Null` here (the
    // backprop doesn't track instance-field reads), and that's fine
    // because pure deobfuscators don't touch `this`. We pass it
    // through verbatim so the slot alignment in `call_method` is
    // preserved.
    if is_instance && cursor < static_args.len() {
        out.push(static_arg_to_value(&static_args[cursor].1, resources, vm));
        cursor += 1;
    }

    for ty in &param_types {
        if cursor >= static_args.len() {
            break;
        }
        let is_wide = matches!(ty.as_str(), "J" | "D");
        let val_str = static_args[cursor].1.as_deref();
        if is_wide {
            // Try to parse the attached value as a 64-bit integer
            // first — that's the const-wide constant we want to
            // split. Anything else (`@invoke!`, `@sget:`, a string)
            // falls back to whatever resolve_arg_encoding produces,
            // which we then split if it happens to yield an Int.
            let full = val_str.and_then(parse_i64_literal)
                .or_else(|| {
                    val_str.map(|s| resolve_arg_encoding(s, resources, vm))
                        .and_then(|v| if let Value::Int(n) = v { Some(n) } else { None })
                });
            match full {
                Some(n) => {
                    let high = (n >> 32) as i32 as i64;
                    let low  = (n as u32) as i64;
                    out.push(Value::Int(high));
                    out.push(Value::Int(low));
                }
                None => {
                    // Couldn't recover a numeric — best effort: leave
                    // both slots as Null so the VM treats the long as
                    // zero rather than crashing on a half-set register
                    // pair.
                    out.push(Value::Null);
                    out.push(Value::Null);
                }
            }
            // Skip the second slot's static_args entry — it's the
            // implicit "other half" of this wide pair.
            cursor += 2;
        } else {
            out.push(static_arg_to_value(&static_args[cursor].1, resources, vm));
            cursor += 1;
        }
    }

    // Tail-spill: if the proto and the invoke disagree (defensive —
    // shouldn't happen with well-formed dex), copy any remaining
    // static_args through so we never drop a register-slot the callee
    // might read.
    while cursor < static_args.len() {
        out.push(static_arg_to_value(&static_args[cursor].1, resources, vm));
        cursor += 1;
    }

    out
}

/// Split user-supplied args (one per Java parameter) into register-slot
/// args (one per Dalvik register slot) for `Vm::call_method`. Used by
/// the CLI `--run` and Tauri `run_method` paths where the human types
/// `'-2639944598005165'` for a `(J)`-shaped method and would otherwise
/// land a corrupted long in the callee.
///
/// Differs from [`coalesce_call_args`] in input shape: callers here
/// already have one [`Value`] per Java parameter. Wide params (J/D)
/// produce TWO output values (high slot first, low slot second);
/// everything else passes through unchanged.
///
/// Non-`Int` values for wide slots — e.g. the user typed a string for
/// a `J` slot — get duplicated across both halves so the callee at
/// least sees the same `Value` in both, rather than a half-Null pair
/// that would silently corrupt. (Better: surface a type-mismatch
/// error; out of scope for this pass.)
pub fn pack_user_args(user_args: Vec<Value>, proto_desc: &str) -> Vec<Value> {
    let params = parse_param_types(proto_desc);
    let mut out: Vec<Value> = Vec::with_capacity(user_args.len() + params.len());

    let mut iter = user_args.into_iter();
    for ty in &params {
        let val = match iter.next() {
            Some(v) => v,
            None    => break,
        };
        if matches!(ty.as_str(), "J" | "D") {
            if let Value::Int(n) = val {
                let high = (n >> 32) as i32 as i64;
                let low  = (n as u32) as i64;
                out.push(Value::Int(high));
                out.push(Value::Int(low));
            } else {
                // Non-int for a wide slot — duplicate so both register
                // slots contain *something*. The callee may still
                // misinterpret, but at least we don't half-set the
                // pair (which read_wide_python_or treats as
                // `high << 32 | 0` and silently loses the low half).
                out.push(val.clone());
                out.push(val);
            }
        } else {
            out.push(val);
        }
    }
    // Tail-spill: if the user provided more args than the proto
    // describes, pass them through verbatim. Lets advanced users
    // override register-slot layout when they know what they're doing.
    out.extend(iter);
    out
}

/// Wrapper for resolve_arg_encoding that handles the `None` (unresolved
/// register) → `Value::Null` translation up front.
fn static_arg_to_value(
    val: &Option<String>,
    resources: Option<&ResourceTable>,
    vm: &mut Vm,
) -> Value {
    match val {
        Some(s) => resolve_arg_encoding(s, resources, vm),
        None    => Value::Null,
    }
}

/// Best-effort parse of a numeric arg encoding into i64. Handles plain
/// decimal (`-123`), hex (`0xff00`, `-0x10`), and the Java L/F/D
/// suffixes used by user-typed args. Returns None for anything that
/// isn't a bare integer — strings, `@sget:`, `@invoke!`, etc.
fn parse_i64_literal(s: &str) -> Option<i64> {
    let s = s.trim();
    // Trim Java numeric suffixes (but not from hex — `f` is a digit).
    let is_hex = s.starts_with("0x") || s.starts_with("-0x") || s.starts_with("+0x");
    let candidate: String = if is_hex {
        s.chars().filter(|c| *c != '_').collect()
    } else {
        s.trim_end_matches(|c: char| matches!(c, 'L' | 'l' | 'F' | 'f' | 'D' | 'd'))
            .chars().filter(|c| *c != '_').collect()
    };
    if let Ok(n) = candidate.parse::<i64>() { return Some(n); }
    if let Some(rest) = candidate.strip_prefix("0x") {
        if let Ok(n) = u64::from_str_radix(rest, 16) { return Some(n as i64); }
    }
    if let Some(rest) = candidate.strip_prefix("-0x") {
        if let Ok(n) = i64::from_str_radix(rest, 16) { return Some(-n); }
    }
    None
}

pub fn resolve_arg_encoding(
    encoded: &str,
    resources: Option<&ResourceTable>,
    vm: &mut Vm,
) -> Value {
    if encoded.starts_with('"') && encoded.ends_with('"') && encoded.len() >= 2 {
        return Value::Str(encoded[1..encoded.len() - 1].to_string());
    }
    let trimmed = encoded.trim();

    // Accept Java numeric literal suffixes so users can paste smali /
    // Java-style values directly: `123L`, `12.5F`, `12.5D`. We don't
    // distinguish long vs int storage at the Value layer (everything
    // is i64), so stripping the suffix is enough — without this,
    // `-2645377731634605L` falls through to `Value::Str(...)` and the
    // callee method gets gibberish, often producing degenerate output
    // or a very long run as the deobfuscator loops over wrong indices.
    // Underscores inside the digits (e.g. `1_000_000L`) are also
    // accepted — Java/Kotlin allow them and they're harmless here.
    //
    // We skip suffix-stripping for hex (`0x..`) because `f` and `d`
    // are valid hex digits — stripping them would eat the value.
    let is_hex = trimmed.starts_with("0x")
              || trimmed.starts_with("-0x")
              || trimmed.starts_with("+0x");
    let numeric_candidate: String = if is_hex {
        trimmed.chars().filter(|c| *c != '_').collect()
    } else {
        trimmed
            .trim_end_matches(|c: char| matches!(c, 'L' | 'l' | 'F' | 'f' | 'D' | 'd'))
            .chars()
            .filter(|c| *c != '_')
            .collect()
    };

    if let Ok(n) = numeric_candidate.parse::<i64>() { return Value::Int(n); }
    if let Some(hex) = numeric_candidate.strip_prefix("0x") {
        if let Ok(n) = i64::from_str_radix(hex, 16) { return Value::Int(n); }
    }
    if let Some(neg_hex) = numeric_candidate.strip_prefix("-0x") {
        if let Ok(n) = i64::from_str_radix(neg_hex, 16) { return Value::Int(-n); }
    }
    if let Some(rest) = encoded.strip_prefix("@sget:") {
        return resolve_sget_encoding(rest, resources);
    }
    if let Some(rest) = encoded.strip_prefix("@invoke!") {
        let bang        = rest.find('!').unwrap_or(rest.len());
        let method_ref  = &rest[..bang];
        let inner_str   = if bang < rest.len() { &rest[bang + 1..] } else { "" };

        let inner_values: Vec<Value> = inner_str.split('|')
            .filter(|s| !s.is_empty())
            .map(|enc| resolve_arg_encoding(enc, resources, vm))
            .collect();

        // Fast path: any Int inner arg → resource table lookup.
        let found_res = inner_values.iter().find_map(|v| {
            if let Value::Int(n) = v { Some(*n as u32) } else { None }
        });
        if let Some(res_id) = found_res {
            if let Some(s) = vm.resolve_resource_id(res_id) {
                return Value::Str(s.to_string());
            }
        }

        // Slow path: execute via VM.
        let mut ref_parts = method_ref.splitn(2, "->");
        let class_name  = ref_parts.next().unwrap_or("").to_string();
        let method_name = ref_parts.next().unwrap_or("").to_string();
        if !class_name.is_empty() && !method_name.is_empty() {
            if let Some(m) = vm.find_and_clone_method(&class_name, &method_name) {
                if let Some(v) = vm.call_method(&m, inner_values.clone()) {
                    return v;
                }
            }
        }
        return Value::Null;
    }
    Value::Str(encoded.to_string())
}

#[cfg(test)]
mod proto_and_packing_tests {
    use super::*;
    use crate::vm::vm::Vm;

    // ── parse_param_types ──────────────────────────────────────────

    #[test]
    fn proto_single_long() {
        assert_eq!(parse_param_types("(J)Ljava/lang/String;"), vec!["J"]);
    }

    #[test]
    fn proto_mixed_primitive_object_long() {
        assert_eq!(
            parse_param_types("(IJLjava/lang/String;)V"),
            vec!["I", "J", "Ljava/lang/String;"],
        );
    }

    #[test]
    fn proto_array_types() {
        assert_eq!(
            parse_param_types("([I[[Ljava/lang/String;)V"),
            vec!["[I", "[[Ljava/lang/String;"],
        );
    }

    #[test]
    fn proto_zero_args() {
        assert_eq!(parse_param_types("()V"), Vec::<String>::new());
    }

    // ── pack_user_args ─────────────────────────────────────────────

    /// The motivating case: the user types ONE arg for a `(J)` method
    /// and we have to split into the (high, low) register-slot pair
    /// `Vm::call_method` expects.
    #[test]
    fn pack_splits_long_into_high_low_pair() {
        // -2639944598005165 = 0xfff69ef127a99853
        // high 32 = 0xfff69ef1 (sign-extended) = -603918
        // low  32 = 0x27a99853                  = 665030227
        let out = pack_user_args(vec![Value::Int(-2639944598005165)], "(J)Ljava/lang/String;");
        assert_eq!(out.len(), 2, "long produces two register-slot values");
        if let (Value::Int(hi), Value::Int(lo)) = (&out[0], &out[1]) {
            // Reassemble per the VM's read_wide contract:
            //   (high << 32) | (low as u32)
            let combined = ((*hi as i32 as i64) << 32) | (*lo as u32 as i64);
            assert_eq!(combined, -2639944598005165,
                "split pair must reassemble to the original long");
        } else {
            panic!("expected two Int values, got {:?}", out);
        }
    }

    /// Doubles are wide too — share the same code path.
    #[test]
    fn pack_splits_double_into_high_low_pair() {
        let out = pack_user_args(vec![Value::Int(0x12345678_9abcdef0u64 as i64)], "(D)V");
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn pack_passes_narrow_args_through() {
        let out = pack_user_args(
            vec![Value::Int(7), Value::Str("x".into())],
            "(ILjava/lang/String;)V",
        );
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], Value::Int(7)));
        assert!(matches!(out[1], Value::Str(ref s) if s == "x"));
    }

    #[test]
    fn pack_handles_mixed_narrow_and_wide() {
        // (IJL...) — int, long (wide), object. User provides 3 args,
        // expect 4 register slots: [int, long_high, long_low, obj].
        let out = pack_user_args(
            vec![Value::Int(1), Value::Int(0x1234_5678_9abc_def0u64 as i64), Value::Null],
            "(IJLjava/lang/String;)V",
        );
        assert_eq!(out.len(), 4);
        assert!(matches!(out[0], Value::Int(1)));
        // out[1]/out[2] are the split long halves
        assert!(matches!(out[3], Value::Null));
    }

    // ── coalesce_call_args ─────────────────────────────────────────

    /// The SystemAndroid case: invoke-static with a const-wide arg.
    /// static_args has (v1, full_long) + (v2, None); we expect the
    /// long split across two register slots, no implicit `this`.
    #[test]
    fn coalesce_handles_static_invoke_with_const_wide() {
        let mut vm = Vm::new();
        let static_args = vec![
            (1u32, Some("0xfff69efc00025a53".to_string())),
            (2u32, None),
        ];
        let out = coalesce_call_args(
            &static_args,
            "invoke-static {v1, v2}, Lcom/foo;->bar(J)Ljava/lang/String;",
            "(J)Ljava/lang/String;",
            None,
            &mut vm,
        );
        assert_eq!(out.len(), 2, "wide pair → two register-slot values");
        if let (Value::Int(hi), Value::Int(lo)) = (&out[0], &out[1]) {
            let combined = ((*hi as i32 as i64) << 32) | (*lo as u32 as i64);
            assert_eq!(combined, 0xfff69efc00025a53u64 as i64);
        } else {
            panic!("expected two Int values, got {:?}", out);
        }
    }

    /// Instance invoke: first register operand is `this`. The proto
    /// describes only the explicit params, so `this` rides through as
    /// an extra leading slot (typically Value::Null for deobf paths).
    #[test]
    fn coalesce_passes_through_this_for_instance_invoke() {
        let mut vm = Vm::new();
        let static_args = vec![
            (0u32, None),                                   // this
            (1u32, Some("0xdeadbeef00112233".to_string())), // long low
            (2u32, None),                                   // long high (implicit)
        ];
        let out = coalesce_call_args(
            &static_args,
            "invoke-virtual {v0, v1, v2}, Lcom/foo;->bar(J)V",
            "(J)V",
            None,
            &mut vm,
        );
        // [this, long_high, long_low] — 3 register slots total
        assert_eq!(out.len(), 3);
        assert!(matches!(out[0], Value::Null));
    }

    /// Narrow-only invoke: behaves like the old per-register mapping
    /// (no wide splitting, no instance offset for invoke-static).
    #[test]
    fn coalesce_handles_narrow_only_static_invoke() {
        let mut vm = Vm::new();
        let static_args = vec![
            (1u32, Some("42".to_string())),
            (2u32, Some("\"hello\"".to_string())),
        ];
        let out = coalesce_call_args(
            &static_args,
            "invoke-static {v1, v2}, Lcom/foo;->bar(ILjava/lang/String;)V",
            "(ILjava/lang/String;)V",
            None,
            &mut vm,
        );
        assert_eq!(out.len(), 2);
        assert!(matches!(out[0], Value::Int(42)));
        assert!(matches!(out[1], Value::Str(ref s) if s == "hello"));
    }
}

#[cfg(test)]
mod resolve_arg_encoding_tests {
    use super::*;
    use crate::vm::vm::Vm;

    fn r(s: &str) -> Value {
        let mut vm = Vm::new();
        resolve_arg_encoding(s, None, &mut vm)
    }

    #[test]
    fn plain_int_parses() {
        assert!(matches!(r("42"), Value::Int(42)));
        assert!(matches!(r("-7"), Value::Int(-7)));
    }

    #[test]
    fn java_long_suffix_l_is_stripped() {
        // Regression: the UI accepts user-typed `123L` / `-9999999L`.
        // Previously fell through to Value::Str, which caused
        // SystemAndroid-style methods to receive a string arg and run
        // against degenerate values for a long time. Both the original
        // report value and a later re-report (different digits, same
        // shape) are pinned so a future change to the parser can't
        // silently reintroduce the fallback.
        assert!(matches!(r("-2645377731634605L"), Value::Int(-2645377731634605)));
        assert!(matches!(r("-2639944598005165L"), Value::Int(-2639944598005165)));
        assert!(matches!(r("100l"), Value::Int(100)));
    }

    #[test]
    fn float_double_suffixes_are_stripped() {
        // We don't have a Value::Float arithmetic path yet — these
        // collapse to Int. Stripping the suffix keeps them parseable.
        assert!(matches!(r("3F"), Value::Int(3)));
        assert!(matches!(r("3d"), Value::Int(3)));
    }

    #[test]
    fn underscored_digits_are_stripped() {
        assert!(matches!(r("1_000_000"), Value::Int(1_000_000)));
        assert!(matches!(r("1_000_000L"), Value::Int(1_000_000)));
    }

    #[test]
    fn hex_still_parses() {
        if let Value::Int(n) = r("0xff") { assert_eq!(n, 0xff); } else { panic!() }
        if let Value::Int(n) = r("-0x10") { assert_eq!(n, -0x10); } else { panic!() }
    }

    #[test]
    fn quoted_string_falls_through_to_str() {
        if let Value::Str(s) = r("\"hello\"") { assert_eq!(s, "hello"); } else { panic!() }
    }

    #[test]
    fn unparseable_input_falls_through_to_str() {
        if let Value::Str(s) = r("nope") { assert_eq!(s, "nope"); } else { panic!() }
    }
}

pub fn resolve_sget_encoding(field_ref: &str, resources: Option<&ResourceTable>) -> Value {
    let mut parts   = field_ref.splitn(2, "->");
    let class_part  = parts.next().unwrap_or("");
    let field_part  = parts.next().unwrap_or("");
    let field_name  = field_part.split(':').next().unwrap_or(field_part);

    if class_part.contains("R$string") {
        if let Some(table) = resources {
            if let Some(entry) = table.entries().iter()
                .find(|e| e.type_name == "string" && e.name == field_name)
            {
                return Value::Int(entry.id as i64);
            }
        }
    }
    Value::Null
}
