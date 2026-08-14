use platypus_apk as apk;
use platypus_dex as dex;
use platypus_vm as vm;
use platypus_codegen as codegen;
use project_platypus_native::analysis;

use apk::zip::ApkZip;
use apk::arsc::{self, ResourceTable};
use apk::split::SplitApk;

use std::env;
use std::fs;
use std::num::NonZeroUsize;
use std::path::Path;
use std::thread;


use dex::access_flags::{ClassAccessFlag, FieldAccessFlag, MethodAccessFlag};
use dex::clazz::Clazz;
use dex::parser::{ClassDefItem, DexFileWithRaw, ParsedDex};
use dex::method::Method;
use dex::debug_info;
use dex::instructions::Instruction;
use codegen::smali::smali_generator::SmaliClassCodeGen;
use codegen::java::analysis::AnalysisConfig;
use codegen::java::decompiler::JavaDecompiler;
use codegen::java::java_generator::{JavaGenerator, class_package, simple_class_from_descriptor};
use codegen::java::ssa_builder::SsaBuilder;
use codegen::java::dominator_tree::DominatorTree;
use vm::vm::Vm;
use vm::value::Value;
use vm::logger::format_value;

// ── CLI ───────────────────────────────────────────────────────────────────────

fn usage(prog: &str) -> ! {
    eprintln!("Usage: {} <input> [options]", prog);
    eprintln!();
    eprintln!("  <input> can be:");
    eprintln!("    file.dex          Raw DEX file");
    eprintln!("    file.apk          Single APK (base or monolithic)");
    eprintln!("    file.xapk         XAPK bundle");
    eprintln!("    <directory>       Folder containing split APKs (base.apk + config splits)");
    eprintln!();
    eprintln!("Options:");
    eprintln!("  --smali             Print Smali for every class to stdout");
    eprintln!("  --java              Print decompiled Java for every class to stdout");
    eprintln!("  --smali-out <dir>   Write one .smali file per class into <dir>");
    eprintln!("  --java-out  <dir>   Write one .java file per class into <dir>");
    eprintln!("  --class  <substr>   Restrict to classes whose name contains <substr>");
    eprintln!("  --method <substr>   Restrict method output to names containing <substr>");
    eprintln!("  --threads <n>       Worker thread count (default: # of logical CPUs)");
    eprintln!();
    eprintln!("VM execution:");
    eprintln!("  --run <class->method>   Execute a method via the interpreter");
    eprintln!("                          e.g. --run 'Lcom/example/Foo;->bar'");
    eprintln!("  --run-args <a,b,...>    Comma-separated literal args (strings or ints)");
    eprintln!("  --verbose [N]  -v [N]   Verbosity level (default 2 if N omitted):");
    eprintln!("                            1 — root call enter/exit only");
    eprintln!("                            2 — all call enter/exit");
    eprintln!("                            3 — all calls + every instruction + branches");
    eprintln!();
    eprintln!("Call-site search:");
    eprintln!("  --find <method>        Find all call sites that invoke <method>");
    eprintln!("                         e.g. --find 'Lhivhi/wfg;->bihvbhi'");
    eprintln!("  --find-exec <method>   Same, then execute each caller via the VM");
    eprintln!();
    eprintln!("Output format (applies to --find, --find-exec, --run):");
    eprintln!("  --output text|json|csv   Default: text (human-readable).");
    eprintln!("                           json: NDJSON, one record per line (one site or one run).");
    eprintln!("                           csv:  header row + one row per site/run.");
    eprintln!();
    eprintln!("Determinism check (--find-exec only):");
    eprintln!("  --validate-deobf         Disable the per-batch result cache and execute every");
    eprintln!("                           call site fresh. After the run, group results by static");
    eprintln!("                           arg fingerprint and flag any group whose calls returned");
    eprintln!("                           DIFFERENT values — a divergence implies a non-deterministic");
    eprintln!("                           VM or deobfuscator (a real bug). Slower; default off.");
    std::process::exit(1);
}

/// Output format for the structured commands (`--find`, `--find-exec`, `--run`).
///
/// `Text` keeps the historic indented-list output (what humans see at a
/// terminal). `Json` emits NDJSON — one JSON object per line, never a
/// surrounding array — so the output is streamable and `jq -c` friendly.
/// `Csv` emits a header row followed by one row per site; useful for
/// spreadsheet import.
///
/// The static-args field gets flattened differently per format:
/// * Json — a JSON array of `{register, value}` objects, preserving
///   structure.
/// * Csv  — a single `static_args` column containing
///   `reg=value|reg=value`. Pipe is safe because register IDs are
///   numeric and values never contain raw pipes (string literals are
///   quoted, hex/int are bare numerics).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat { Text, Json, Csv }

impl OutputFormat {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "csv"  => Some(Self::Csv),
            _      => None,
        }
    }
}

// ── Per-class result collected from worker threads ────────────────────────────

struct ClassResult {
    /// Original index in class_defs — used to restore deterministic output order.
    index:          usize,
    class_name:     String,
    smali_text:     Option<String>,
    java_text:      Option<String>,
    /// (method_name, instr_count, block_count, preview_lines)
    method_previews: Vec<(String, usize, usize, Vec<String>)>,
    total_instrs:   usize,
    total_blocks:   usize,
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    let argv: Vec<String> = env::args().collect();
    if argv.len() < 2 { usage(&argv[0]); }

    let dex_path = &argv[1];
    let mut print_smali   = false;
    let mut print_java    = false;
    let mut smali_out:     Option<String> = None;
    let mut java_out:      Option<String> = None;
    let mut class_filter:  Option<String> = None;
    let mut method_filter: Option<String> = None;
    let mut num_threads:   Option<usize>  = None;
    let mut run_target:    Option<String> = None;  // "ClassName->methodName"
    let mut run_args_str:  Option<String> = None;  // comma-separated literals
    let mut run_verbose:   u8             = 0;     // 0 = silent, 1–3 = verbosity levels
    let mut find_target:      Option<String> = None;  // --find <method>
    let mut find_exec_target: Option<String> = None;  // --find-exec <method>
    let mut output_fmt:       OutputFormat   = OutputFormat::Text; // --output
    let mut validate_deobf:   bool           = false;              // --validate-deobf

    let mut i = 2;
    while i < argv.len() {
        match argv[i].as_str() {
            "--smali"       => { print_smali = true; }
            "--java"        => { print_java  = true; }
            "--smali-out"   => { i += 1; smali_out     = argv.get(i).cloned(); }
            "--java-out"    => { i += 1; java_out      = argv.get(i).cloned(); }
            "--class"       => { i += 1; class_filter  = argv.get(i).cloned(); }
            "--method"      => { i += 1; method_filter = argv.get(i).cloned(); }
            "--threads"     => {
                i += 1;
                num_threads = argv.get(i)
                    .and_then(|s| s.parse().ok())
                    .or(Some(1));
            }
            "--run"         => { i += 1; run_target   = argv.get(i).cloned(); }
            "--run-args"    => { i += 1; run_args_str = argv.get(i).cloned(); }
            "--find"        => { i += 1; find_target      = argv.get(i).cloned(); }
            "--find-exec"   => { i += 1; find_exec_target = argv.get(i).cloned(); }
            "--output"      => {
                i += 1;
                let raw = argv.get(i).cloned().unwrap_or_default();
                match OutputFormat::parse(&raw) {
                    Some(f) => output_fmt = f,
                    None    => {
                        eprintln!("[-] Unknown --output value: {:?} (expected: text, json, csv)", raw);
                        std::process::exit(1);
                    }
                }
            }
            "--validate-deobf" => { validate_deobf = true; }
            // --verbose [N]  where N defaults to 2 if omitted
            "--verbose" | "-v" => {
                let next = argv.get(i + 1).map(|s| s.as_str());
                match next {
                    Some("1") => { run_verbose = 1; i += 1; }
                    Some("2") => { run_verbose = 2; i += 1; }
                    Some("3") => { run_verbose = 3; i += 1; }
                    _         => { run_verbose = 2; }          // default level
                }
            }
            "--run-verbose" => { run_verbose = 3; }            // legacy alias
            other => { eprintln!("Unknown flag: {}", other); usage(&argv[0]); }
        }
        i += 1;
    }

    if let Some(ref d) = smali_out { fs::create_dir_all(d).expect("failed to create smali-out dir"); }
    if let Some(ref d) = java_out  { fs::create_dir_all(d).expect("failed to create java-out dir");  }

    // Banner lines (`[+] Loading: …`, DEX stats, etc.) — go to stdout
    // in text mode so they appear in the user's terminal as before,
    // but to stderr in json/csv mode so the structured output stream
    // stays parseable by `jq`, Python's `csv` module, etc. Without
    // this split, every NDJSON/CSV consumer would have to filter out
    // the `[+]`-prefixed prelude.
    let say = |msg: String| {
        if matches!(output_fmt, OutputFormat::Text) {
            println!("{}", msg);
        } else {
            eprintln!("{}", msg);
        }
    };

    // ── Load DEX ──────────────────────────────────────────────────────────────
    say(format!("[+] Loading: {}", dex_path));

    // `all_dex_files` — every DEX across all splits/multidex shards, used by
    //   --find and --find-exec to search the full codebase.
    // `top_resources`  — resources.arsc from the base APK (if available).
    let (all_dex_files, top_resources): (Vec<DexFileWithRaw>, Option<ResourceTable>) =
        if Path::new(dex_path).is_dir() {
            // ── Split-APK directory ───────────────────────────────────────────
            let split = SplitApk::from_dir(dex_path).unwrap_or_else(|e| {
                eprintln!("[-] Failed to load split APKs from directory: {}", e);
                std::process::exit(1);
            });
            // Report which APK was auto-detected as the base.
            let split_names = split.split_names();
            let base_name = split_names.first().map(|s| s.as_str()).unwrap_or("?");
            say(format!("[+] Base APK      : {} (auto-detected)", base_name));
            let resources = split.resources().ok();
            if resources.is_some() {
                say(format!("[+] Resources     : loaded from {}", base_name));
            }
            let dexes: Vec<DexFileWithRaw> = split
                .dex_files()
                .into_iter()
                .filter_map(|(name, bytes)| {
                    DexFileWithRaw::from_bytes(bytes, name.clone())
                        .map_err(|e| eprintln!("[!] Skipping DEX {} — {}", name, e))
                        .ok()
                })
                .collect();
            if dexes.is_empty() {
                eprintln!("[-] No DEX files found in directory: {}", dex_path);
                std::process::exit(1);
            }
            say(format!("[+] Split APKs    : {} split(s), {} DEX file(s)",
                     split.split_count(), dexes.len()));
            (dexes, resources)
        } else if dex_path.ends_with(".apk") || dex_path.ends_with(".xapk") {
            // ── Single APK ────────────────────────────────────────────────────
            match ApkZip::open(dex_path) {
                Ok(apk) => {
                    let resources = apk.read_entry("resources.arsc")
                        .ok()
                        .and_then(|data| arsc::parse(&data).ok());
                    let dexes: Vec<DexFileWithRaw> = apk
                        .dex_files()
                        .into_iter()
                        .filter_map(|(name, bytes)| {
                            DexFileWithRaw::from_bytes(bytes, name.clone())
                                .map_err(|e| eprintln!("[!] Skipping DEX {} — {}", name, e))
                                .ok()
                        })
                        .collect();
                    if dexes.is_empty() {
                        eprintln!("[-] No DEX files found in APK");
                        std::process::exit(1);
                    }
                    (dexes, resources)
                }
                Err(e) => { eprintln!("[-] Failed to open APK: {}", e); std::process::exit(1); }
            }
        } else {
            // ── Raw DEX ───────────────────────────────────────────────────────
            match DexFileWithRaw::from_file(dex_path) {
                Ok(d)  => (vec![d], None),
                Err(e) => { eprintln!("[-] Failed to parse DEX: {}", e); std::process::exit(1); }
            }
        };

    // The primary DEX (first shard / base APK) drives stats and smali/java output.
    let dex_file = &all_dex_files[0];

    say(format!("[+] DEX version  : {}", dex_file.parsed.header.version_str));
    say(format!("[+] SHA-256      : {}", dex_file.parsed.digest));
    if all_dex_files.len() > 1 {
        let total_classes: usize = all_dex_files.iter().map(|d| d.parsed.class_defs.len()).sum();
        let total_methods: usize = all_dex_files.iter().map(|d| d.parsed.method_ids.len()).sum();
        say(format!("[+] DEX shards   : {}", all_dex_files.len()));
        say(format!("[+] Class defs   : {} (across all shards)", total_classes));
        say(format!("[+] Method IDs   : {} (across all shards)", total_methods));
    } else {
        say(format!("[+] Strings      : {}", dex_file.parsed.strings.len()));
        say(format!("[+] Types        : {}", dex_file.parsed.type_ids.len()));
        say(format!("[+] Field IDs    : {}", dex_file.parsed.field_ids.len()));
        say(format!("[+] Method IDs   : {}", dex_file.parsed.method_ids.len()));
        say(format!("[+] Class defs   : {}", dex_file.parsed.class_defs.len()));
    }

    // ── --find / --find-exec ──────────────────────────────────────────────────
    if let Some(ref target) = find_target {
        // Search across ALL DEX files (all splits / multidex shards).
        let mut sites: Vec<UsageSite> = Vec::new();
        for dex in &all_dex_files {
            sites.extend(find_usages(dex, target));
        }
        print_usages(&sites, target, output_fmt);
        std::process::exit(0);
    }
    if let Some(ref target) = find_exec_target {
        // Collect call sites from all DEX files, then execute.
        // `all_dex_files` and `top_resources` were already built during loading —
        // no need to re-open the APK/directory.
        let mut sites: Vec<UsageSite> = Vec::new();
        for dex in &all_dex_files {
            sites.extend(find_usages(dex, target));
        }
        exec_usages(&all_dex_files, &sites, target, run_verbose, top_resources.as_ref(), output_fmt, validate_deobf);
        std::process::exit(0);
    }

    // ── --run: execute a method via the VM and exit ───────────────────────────
    if let Some(ref target) = run_target {
        let args = run_args_str.as_deref()
            .map(parse_run_args)
            .unwrap_or_default();
        run_vm_method(dex_file, target, args, run_verbose, output_fmt);
        std::process::exit(0);
    }

    let parsed = &dex_file.parsed;

    // ── Choose thread count ───────────────────────────────────────────────────
    let n_threads = num_threads.unwrap_or_else(|| {
        thread::available_parallelism()
            .unwrap_or(NonZeroUsize::new(4).unwrap())
            .get()
    });
    println!("[+] Worker threads: {}", n_threads);
    println!();

    // ── Filter classes ────────────────────────────────────────────────────────
    let work_items: Vec<(usize, &ClassDefItem)> = parsed.class_defs
        .iter()
        .enumerate()
        .filter(|(_, cd)| {
            class_filter.as_deref()
                .map(|f| cd.type_name.contains(f))
                .unwrap_or(true)
        })
        .collect();

    if work_items.is_empty() {
        println!("[-] No classes matched the filter.");
        std::process::exit(0);
    }

    // ── Chunk work across threads ─────────────────────────────────────────────
    // Each thread gets a contiguous slice of (index, &ClassDefItem).
    let n_threads  = n_threads.min(work_items.len());
    let chunk_size = (work_items.len() + n_threads - 1) / n_threads;

    let config         = AnalysisConfig::default();
    let method_filter  = method_filter.as_deref();
    let do_smali       = print_smali || smali_out.is_some();
    let do_java        = print_java  || java_out.is_some();
    let stats_only     = !do_smali && !do_java;

    // thread::scope lets threads borrow from the enclosing stack frame.
    let mut all_results: Vec<ClassResult> = thread::scope(|s| {
        let chunks: Vec<&[(usize, &ClassDefItem)]> = work_items.chunks(chunk_size).collect();

        // Spawn one thread per chunk; each returns Vec<ClassResult>.
        let handles: Vec<_> = chunks
            .into_iter()
            .map(|chunk| {
                s.spawn(|| -> Vec<ClassResult> {
                    process_chunk(
                        chunk,
                        &dex_file,
                        parsed,
                        &config,
                        method_filter,
                        do_smali,
                        do_java,
                        stats_only,
                    )
                })
            })
            .collect();

        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });

    // ── Restore original ordering ─────────────────────────────────────────────
    all_results.sort_unstable_by_key(|r| r.index);

    // ── Output phase (single-threaded, ordered) ───────────────────────────────
    let mut total_methods = 0usize;
    let mut total_instrs  = 0usize;
    let mut total_blocks  = 0usize;

    for result in &all_results {
        println!("class: {}", result.class_name);

        if print_smali {
            if let Some(ref txt) = result.smali_text {
                println!("{}", txt);
            }
        }
        if let Some(ref dir) = smali_out {
            if let Some(ref txt) = result.smali_text {
                let out_path = Path::new(dir).join(class_safe_filename(&result.class_name, "smali"));
                fs::write(&out_path, txt.as_bytes()).expect("write smali failed");
                println!("  [smali] → {}", out_path.display());
            }
        }

        if print_java {
            if let Some(ref txt) = result.java_text {
                println!("{}", txt);
            }
        }
        if let Some(ref dir) = java_out {
            if let Some(ref txt) = result.java_text {
                let out_path = Path::new(dir).join(class_safe_filename(&result.class_name, "java"));
                fs::write(&out_path, txt.as_bytes()).expect("write java failed");
                println!("  [java]  → {}", out_path.display());
            }
        }

        if stats_only {
            for (mname, ic, bc, preview) in &result.method_previews {
                println!("  method: {}  [{} instrs, {} blocks]", mname, ic, bc);
                for line in preview { println!("    {}", line); }
            }
        }

        total_methods += result.method_previews.len();
        total_instrs  += result.total_instrs;
        total_blocks  += result.total_blocks;
    }

    println!();
    println!("[+] Total classes      : {}", all_results.len());
    println!("[+] Total methods      : {}", total_methods);
    println!("[+] Total instructions : {}", total_instrs);
    println!("[+] Total basic blocks : {}", total_blocks);
}

// ── Worker: process a chunk of class_defs ─────────────────────────────────────

fn process_chunk(
    chunk:         &[(usize, &ClassDefItem)],
    dex_file:      &DexFileWithRaw,
    parsed:        &ParsedDex,
    config:        &AnalysisConfig,
    method_filter: Option<&str>,
    do_smali:      bool,
    do_java:       bool,
    stats_only:    bool,
) -> Vec<ClassResult> {
    let mut results = Vec::with_capacity(chunk.len());

    for &(index, class_def) in chunk {
        let clazz = match Clazz::new(class_def, dex_file) {
            Ok(c)  => c,
            Err(e) => {
                eprintln!("[-] Skipping {}: {}", class_def.type_name, e);
                continue;
            }
        };

        let smali_text = if do_smali {
            Some(SmaliClassCodeGen::new(&clazz, parsed).format())
        } else {
            None
        };

        let java_text = if do_java {
            Some(decompile_class(&clazz, parsed, config, method_filter))
        } else {
            None
        };

        let mut method_previews = Vec::new();
        let mut total_instrs    = 0usize;
        let mut total_blocks    = 0usize;

        for method in &clazz.methods {
            if let Some(f) = method_filter {
                if !method.method_name.contains(f) { continue; }
            }
            let ic = method.instructions.len();
            let bc = method.cfg.as_ref().map(|c| c.blocks.len()).unwrap_or(0);
            total_instrs += ic;
            total_blocks += bc;

            let preview = if stats_only && ic > 0 {
                let mut lines: Vec<String> = method.instructions.iter().take(5)
                    .map(|ins| format!("cp={:#06x}  op={:#04x}  {}", ins.codepoint, ins.opcode, ins.instruction_str))
                    .collect();
                if ic > 5 { lines.push(format!("... ({} more)", ic - 5)); }
                lines
            } else {
                Vec::new()
            };

            method_previews.push((method.method_name.clone(), ic, bc, preview));
        }

        results.push(ClassResult {
            index,
            class_name: clazz.class_name.clone(),
            smali_text,
            java_text,
            method_previews,
            total_instrs,
            total_blocks,
        });
    }

    results
}

// ── Decompile an entire class to a Java string ───────────────────────────────

fn decompile_class(
    clazz:         &Clazz,
    parsed:        &ParsedDex,
    config:        &AnalysisConfig,
    method_filter: Option<&str>,
) -> String {
    let decompiler = JavaDecompiler::new(Some(config.clone()));

    // ── Pass 1: generate method texts + collect all imports ───────────────────
    let mut method_texts: Vec<String> = Vec::new();
    let mut all_imports: std::collections::HashSet<String> = std::collections::HashSet::new();

    for method in &clazz.methods {
        if let Some(f) = method_filter {
            if !method.method_name.contains(f) { continue; }
        }

        // Per-method annotation lines (emitted above the signature).
        // Each line is bare (no indent) — the outer indent pass at
        // line ~558 prefixes every line with 4 spaces.
        let ann_lines = render_annotations(&method.annotations, "");

        if method.instructions.is_empty() {
            // Abstract / native — emit as a one-liner stub, with
            // annotations stacked above it.
            let af  = format_java_method_flags(&method.access_flags);
            let sig = java_method_signature(method, parsed);
            let stub = format!("{} {};", af, sig);
            let combined = if ann_lines.is_empty() {
                stub
            } else {
                let mut lines = ann_lines;
                lines.push(stub);
                lines.join("\n")
            };
            method_texts.push(combined);
            continue;
        }

        let ast = decompiler.decompile(method);

        let mut cfg_clone = method.cfg.clone();
        if let Some(ref mut cfg) = cfg_clone {
            DominatorTree::compute(cfg);
        }
        let ssa = cfg_clone.as_ref()
            .map(|cfg| SsaBuilder::new().build(cfg, &method.instructions,
                                                method.registers_size, method.ins_size))
            .unwrap_or_else(SsaBuilder::empty_ssa);

        let mut gen = JavaGenerator::new(method, parsed, &ssa);
        let method_text = gen.gen_class_method(&ast);
        // Collect imports from this method's generator.
        for imp in gen.import_statements() {
            // imp is "import foo.bar.Baz;"
            all_imports.insert(imp);
        }
        // Prepend annotation lines onto the method body.
        let combined = if ann_lines.is_empty() {
            method_text
        } else {
            let mut lines = ann_lines;
            lines.push(method_text);
            lines.join("\n")
        };
        method_texts.push(combined);
    }

    // ── Pass 2: assemble full file ────────────────────────────────────────────
    let mut out: Vec<String> = Vec::new();

    // Package declaration.
    let pkg = class_package(&clazz.class_name);
    if !pkg.is_empty() {
        out.push(format!("package {};", pkg));
        out.push(String::new());
    }

    // Import statements (sorted, filter same package).
    let mut sorted_imports: Vec<String> = all_imports.into_iter().collect();
    sorted_imports.sort();
    sorted_imports.retain(|imp| {
        // imp = "import foo.bar.Baz;"  → dotted name = "foo.bar.Baz"
        let name = imp.trim_start_matches("import ").trim_end_matches(';');
        let imp_pkg = name.rfind('.').map(|i| &name[..i]).unwrap_or("");
        imp_pkg != pkg
    });
    for imp in &sorted_imports {
        out.push(imp.clone());
    }
    if !sorted_imports.is_empty() {
        out.push(String::new());
    }

    // Class-level annotations (one per line, above the header).
    for line in render_annotations(&clazz.annotations, "") {
        out.push(line);
    }

    // Class header.
    //
    // We compose the line manually so we can suppress redundant
    // tokens (e.g. `abstract` is implicit for interfaces; the
    // keyword itself is `class` vs `interface` depending on the
    // Interface flag) and inject `extends` / `implements` lists
    // that the bare flag formatter doesn't know about.
    let header = format_java_class_header(clazz);
    out.push(format!("{} {{", header));
    out.push(String::new());

    // Fields. Each field's annotations (if any) are emitted on
    // their own lines above the declaration, indented to match.
    for f in clazz.static_fields.iter().chain(clazz.instance_fields.iter()) {
        for ann_line in render_annotations(&f.annotations, "    ") {
            out.push(ann_line);
        }
        let af = format_java_field_flags(&f.access_flags);
        out.push(format!("    {} {} {};", af, dalvik_type_to_java(&f.type_name), f.name));
    }
    if !clazz.static_fields.is_empty() || !clazz.instance_fields.is_empty() {
        out.push(String::new());
    }

    // Methods (indent each line by 4 spaces).
    for (i, m_text) in method_texts.iter().enumerate() {
        for line in m_text.lines() {
            out.push(format!("    {}", line));
        }
        if i + 1 < method_texts.len() {
            out.push(String::new());
        }
    }

    out.push("}".to_string());
    out.join("\n")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn class_safe_filename(class_name: &str, ext: &str) -> String {
    let bare = class_name.trim_start_matches('L').trim_end_matches(';');
    format!("{}.{}", bare.replace('/', "_"), ext)
}


pub fn dalvik_type_to_java(t: &str) -> String {
    match t {
        "I" => "int".into(),     "J" => "long".into(),    "F" => "float".into(),
        "D" => "double".into(),  "Z" => "boolean".into(), "B" => "byte".into(),
        "S" => "short".into(),   "C" => "char".into(),    "V" => "void".into(),
        _ if t.starts_with('[') => format!("{}[]", dalvik_type_to_java(&t[1..])),
        _ => {
            let bare = t.trim_start_matches('L').trim_end_matches(';');
            bare.rsplit('/').next().unwrap_or(bare).to_string()
        }
    }
}

/// Render the signature of an abstract / native / interface method
/// — i.e. one with no body, where we emit `[flags] retType name(args);`
/// at the call site.
///
/// Returns just `retType name(args)` — the call site is responsible
/// for prefixing flags and the trailing semicolon. We deliberately
/// don't include flags here because the older version did, and the
/// call site ALSO prefixed flags, producing `public abstract public
/// abstract …`.
///
/// Per-parameter annotations from `method.param_annotations` (if any)
/// are inlined before each parameter's type: `@Nullable String p0`.
/// The single-element shorthand (`@X(v)` vs `@X(name=v)`) is shared
/// with `render_annotations` via the same logic.
///
/// `_parsed` is unused now that we parse the proto descriptor
/// directly via `parse_proto_desc`; kept in the signature so existing
/// call sites don't have to change.
fn java_method_signature(method: &Method, _parsed: &ParsedDex) -> String {
    use platypus_codegen::java::java_generator::parse_proto_desc;

    let (param_types, ret_desc) = parse_proto_desc(&method.proto_desc);
    let ret_java = dalvik_type_to_java(&ret_desc);

    // Parameter naming: abstract methods have no instruction stream so
    // there's no SSA-derived name to use. Generate `p0`, `p1`, … which
    // is the conventional jadx-style placeholder and matches what the
    // non-abstract code path also falls back to.
    let params: Vec<String> = param_types.iter().enumerate()
        .map(|(i, td)| {
            let ann_prefix = method.param_annotations.get(i)
                .map(|anns| render_inline_annotations(anns))
                .unwrap_or_default();
            format!("{}{} p{}", ann_prefix, dalvik_type_to_java(td), i)
        })
        .collect();

    format!("{} {}({})", ret_java, method.method_name, params.join(", "))
}

/// Render an annotation list as a single space-separated inline
/// string suitable for splatting before a parameter type:
/// `@Nullable @Validated `  (trailing space if non-empty so the
/// caller can concatenate directly with the type).
///
/// Empty annotation list returns empty string — caller-friendly.
fn render_inline_annotations(anns: &[platypus_dex::parser::AnnotationItem]) -> String {
    if anns.is_empty() { return String::new(); }
    let mut out = String::new();
    for ann in anns {
        let name = dalvik_type_to_java(&ann.type_name);
        if ann.elements.is_empty() {
            out.push_str(&format!("@{} ", name));
        } else if ann.elements.len() == 1 && ann.elements[0].0 == "value" {
            out.push_str(&format!("@{}({}) ", name, ann.elements[0].1));
        } else {
            let parts: Vec<String> = ann.elements.iter()
                .map(|(k, v)| format!("{} = {}", k, v))
                .collect();
            out.push_str(&format!("@{}({}) ", name, parts.join(", ")));
        }
    }
    out
}

/// Render an annotation list as a Vec of source-lines, each already
/// indented with `prefix` and decorated with the standard shorthands:
///
///   - no elements      → `@Name`
///   - one element named "value" → `@Name(value-repr)`
///   - otherwise        → `@Name(name1 = v1, name2 = v2, ...)`
///
/// Returns an empty Vec when `anns` is empty so the caller can splat
/// directly into its output without checking.
fn render_annotations(anns: &[platypus_dex::parser::AnnotationItem], prefix: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(anns.len());
    for ann in anns {
        let name = dalvik_type_to_java(&ann.type_name);
        if ann.elements.is_empty() {
            out.push(format!("{}@{}", prefix, name));
        } else if ann.elements.len() == 1 && ann.elements[0].0 == "value" {
            out.push(format!("{}@{}({})", prefix, name, ann.elements[0].1));
        } else {
            let parts: Vec<String> = ann.elements.iter()
                .map(|(k, v)| format!("{} = {}", k, v))
                .collect();
            out.push(format!("{}@{}({})", prefix, name, parts.join(", ")));
        }
    }
    out
}

fn format_java_class_flags(flags: &[ClassAccessFlag]) -> String {
    let mut parts = Vec::new();
    for f in flags {
        match f {
            ClassAccessFlag::Public    => parts.push("public"),
            ClassAccessFlag::Final     => parts.push("final"),
            ClassAccessFlag::Abstract  => parts.push("abstract"),
            ClassAccessFlag::Interface => parts.push("interface"),
            ClassAccessFlag::Enum      => parts.push("enum"),
            _ => {}
        }
    }
    if parts.is_empty() { "/* package-private */".to_string() } else { parts.join(" ") }
}

/// Build a complete Java class-header line *without* the trailing
/// `{`: modifiers + kind keyword + name + extends/implements clauses.
///
/// This replaces the older flat "`{access} class {name}`" formatter,
/// which couldn't tell the difference between a class and an interface
/// (or between an enum and a regular abstract class), and which
/// blindly concatenated both `interface` AND `class` because both
/// keywords are valid access-flag tokens in Dalvik even though they're
/// mutually exclusive in Java source. Examples produced now:
///
/// ```text
///   public final class Foo extends Bar implements Baz
///   abstract interface VisibilityInterface extends TransitionInterface
///   enum FooKind
/// ```
///
/// Dropped redundancies:
/// - `interface` implies `abstract` — we don't emit both.
/// - `extends Object` is implicit for any non-interface — we drop it.
/// - `enum` already implies a particular shape — we drop `final`.
fn format_java_class_header(clazz: &Clazz) -> String {
    use platypus_dex::access_flags::ClassAccessFlag;

    let flags = &clazz.access_flags;
    let is_interface = flags.contains(&ClassAccessFlag::Interface);
    let is_enum      = flags.contains(&ClassAccessFlag::Enum);
    let is_annotation = flags.contains(&ClassAccessFlag::Annotation);

    // Choose the structural keyword exactly once.
    let kind_kw = if is_annotation {
        "@interface"
    } else if is_interface {
        "interface"
    } else if is_enum {
        "enum"
    } else {
        "class"
    };

    // Modifiers, with the structural keyword + abstract/final
    // redundancies suppressed.
    let mut mods: Vec<&str> = Vec::new();
    for f in flags {
        match f {
            ClassAccessFlag::Public    => mods.push("public"),
            // `final` doesn't apply to enums/interfaces in source.
            ClassAccessFlag::Final     if !is_interface && !is_enum && !is_annotation => mods.push("final"),
            // `abstract` is implicit for interfaces / annotations.
            ClassAccessFlag::Abstract  if !is_interface && !is_annotation => mods.push("abstract"),
            _ => {} // Interface/Enum/Annotation collapsed into `kind_kw` above.
        }
    }
    // Stable order: `public`/`protected` first, then modifiers.
    // (The flag order from the dex is already mostly stable but the
    //  `dedup` below also protects against weird inputs.)
    mods.dedup();

    let short_name = simple_class_from_descriptor(&clazz.class_name).to_string();

    // extends clause. For annotation types we suppress everything —
    // the dex models annotations as `class extends java.lang.annotation.Annotation`
    // but Java source uses `@interface Foo {}` with no extends/implements
    // clauses. For interfaces, the type list at interfaces_off is
    // actually the "extends" list (Java's interface-extends-interfaces
    // syntax). For regular classes, the superclass goes here and
    // `extends Object` is suppressed.
    let extends_clause: String = if is_annotation {
        // Annotations: no extends or implements in source.
        String::new()
    } else if is_interface {
        if clazz.interfaces.is_empty() {
            String::new()
        } else {
            let names: Vec<String> = clazz.interfaces.iter()
                .map(|d| dalvik_type_to_java(d))
                .collect();
            format!(" extends {}", names.join(", "))
        }
    } else {
        let sup = clazz.superclass_name.as_str();
        if sup.is_empty() || sup == "Ljava/lang/Object;" {
            String::new()
        } else {
            format!(" extends {}", dalvik_type_to_java(sup))
        }
    };

    // implements clause. Only meaningful for non-interfaces and
    // non-annotations (interfaces use `extends` instead, handled above;
    // annotations have neither in source).
    let implements_clause: String = if !is_interface && !is_annotation && !clazz.interfaces.is_empty() {
        let names: Vec<String> = clazz.interfaces.iter()
            .map(|d| dalvik_type_to_java(d))
            .collect();
        format!(" implements {}", names.join(", "))
    } else {
        String::new()
    };

    let mods_prefix = if mods.is_empty() {
        String::new()
    } else {
        format!("{} ", mods.join(" "))
    };
    format!("{}{} {}{}{}", mods_prefix, kind_kw, short_name, extends_clause, implements_clause)
}

fn format_java_method_flags(flags: &[MethodAccessFlag]) -> String {
    let mut parts = Vec::new();
    for f in flags {
        match f {
            MethodAccessFlag::Public       => parts.push("public"),
            MethodAccessFlag::Private      => parts.push("private"),
            MethodAccessFlag::Protected    => parts.push("protected"),
            MethodAccessFlag::Static       => parts.push("static"),
            MethodAccessFlag::Final        => parts.push("final"),
            MethodAccessFlag::Synchronized => parts.push("synchronized"),
            MethodAccessFlag::Native       => parts.push("native"),
            MethodAccessFlag::Abstract     => parts.push("abstract"),
            _ => {}
        }
    }
    parts.join(" ")
}

// ── VM execution helpers ──────────────────────────────────────────────────────

/// Parse a comma-separated argument list like `"hello,42,world"` into Values.
fn parse_run_args(raw: &str) -> Vec<Value> {
    raw.split(',')
        .map(|tok| {
            let tok = tok.trim();
            if let Ok(n) = tok.parse::<i64>() {
                Value::Int(n)
            } else {
                Value::Str(tok.to_string())
            }
        })
        .collect()
}

/// Load the DEX into a fresh VM and execute the requested method.
/// `target` format: `"Lcom/example/Foo;->bar"` or `"com/example/Foo->bar"`
///
/// `fmt` controls the output format. Text mode preserves the historic
/// `[result] <value>` line; json/csv emit one record describing the
/// invocation + result so the run can be piped into a script.
///
/// **Note**: VM verbose logging (`-v`) still prints to stderr/stdout in
/// all modes — the `--output` flag governs only the final result
/// rendering. Pipe to `2>/dev/null` if you want a clean json stream
/// alongside `-v`.
fn run_vm_method(dex: &DexFileWithRaw, target: &str, args: Vec<Value>, verbose: u8, fmt: OutputFormat) {
    let mut parts = target.splitn(2, "->");
    let class_raw  = parts.next().unwrap_or("").trim();
    let method_raw = parts.next().unwrap_or("").trim();

    if class_raw.is_empty() || method_raw.is_empty() {
        eprintln!("[-] --run requires 'ClassName->methodName' format");
        return;
    }

    // Find the method, then clone the DEX into the VM.
    let method = find_method_in_dex(dex, class_raw, method_raw);
    let dex_clone = DexFileWithRaw::from_bytes(dex.raw_bytes().to_vec(), dex.parsed.filename.clone())
        .expect("re-parse of already-loaded DEX failed");

    let mut vm = Vm::new();
    vm.enable_logging(verbose);
    vm.add_dex_file(&dex_clone);

    match method {
        Some(m) => {
            // Snapshot the args for the structured record before
            // call_method consumes the vec.
            let arg_displays: Vec<String> = args.iter().map(format_value).collect();
            // Split long/double user args across the two register
            // slots they occupy — otherwise `(J)`-shaped methods see
            // a corrupted long (full value in slot N, Null in N+1) and
            // produce garbage. See `analysis::pack_user_args` for
            // why this is needed.
            let packed = analysis::pack_user_args(args, &m.proto_desc);
            let result = vm.call_method(&m, packed);

            // Format the result the same way --find-exec does so the
            // value/type/resource_string fields stay consistent across
            // commands. Resource-ID resolution applies here too.
            let (result_display, resource_string, result_type) = format_call_result(&result, &vm);

            match fmt {
                OutputFormat::Text => {
                    if let Some(ref log) = vm.logger {
                        log.log_result(&result);
                    } else {
                        let printable = match resource_string {
                            Some(ref s) => format!("{} (\"{}\")", result_display, s),
                            None        => result_display,
                        };
                        println!("[result] {}", printable);
                    }
                }
                OutputFormat::Json => {
                    let rec = RunRecord {
                        target: format!("{}->{}", class_raw, method_raw),
                        args:   arg_displays,
                        result: ResultRecord {
                            value:           result_display,
                            value_type:      result_type,
                            resource_string,
                        },
                    };
                    match serde_json::to_string(&rec) {
                        Ok(s)  => println!("{}", s),
                        Err(e) => eprintln!("[-] JSON encode failed: {}", e),
                    }
                }
                OutputFormat::Csv => {
                    println!("{}", RUN_CSV_HEADER);
                    println!("{},{},{},{},{}",
                        csv_escape(&format!("{}->{}", class_raw, method_raw)),
                        csv_escape(&arg_displays.join("|")),
                        csv_escape(&result_display),
                        csv_escape(&result_type),
                        csv_escape(resource_string.as_deref().unwrap_or("")),
                    );
                }
            }
        }
        None => {
            eprintln!("[-] Method not found: {}->{}", class_raw, method_raw);
            eprintln!("    Tip: use the full descriptor, e.g. 'Lcom/example/Foo;->bar'");
        }
    }
}

const RUN_CSV_HEADER: &str = "target,args,result_value,result_type,result_resource_string";

/// `--run` record. Args carry the input values (pipe-joined in CSV
/// mode) for traceability — useful when batching many `--run` calls
/// from a script.
#[derive(Debug, serde::Serialize)]
struct RunRecord {
    target: String,
    args:   Vec<String>,
    #[serde(flatten)]
    result: ResultRecord,
}

/// Search a DEX for a method matching (class_raw, method_name).
fn find_method_in_dex(dex: &DexFileWithRaw, class_raw: &str, method_name: &str) -> Option<Method> {
    let class_norm = class_raw.trim_start_matches('L').trim_end_matches(';');

    for class_def in &dex.parsed.class_defs {
        let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
        if def_norm != class_norm { continue; }

        let clazz = Clazz::new(class_def, dex).ok()?;
        for m in clazz.methods {
            if m.method_name == method_name {
                return Some(m);
            }
        }
    }
    None
}

fn format_java_field_flags(flags: &[FieldAccessFlag]) -> String {
    let mut parts = Vec::new();
    for f in flags {
        match f {
            FieldAccessFlag::Public    => parts.push("public"),
            FieldAccessFlag::Private   => parts.push("private"),
            FieldAccessFlag::Protected => parts.push("protected"),
            FieldAccessFlag::Static    => parts.push("static"),
            FieldAccessFlag::Final     => parts.push("final"),
            FieldAccessFlag::Volatile  => parts.push("volatile"),
            _ => {}
        }
    }
    parts.join(" ")
}

// ── --find / --find-exec implementation ──────────────────────────────────────

/// One call site where the target method is invoked.
struct UsageSite {
    caller_class:   String,
    caller_method:  String,
    source_file:    String,
    line_number:    Option<u32>,
    invoke_cp:      u32,
    invoke_str:     String,
    arg_regs:       Vec<u32>,
    static_args:    Vec<(u32, Option<String>)>,
    /// Pre-extracted caller Method object (populated by find_usages so that
    /// exec_usages workers don't need to re-parse the DEX).
    caller_method_obj: Option<Method>,
}

/// Extract argument register indices from an invoke instruction.
/// For non-range (35c fmt): up to v_a args starting at v_c..v_g.
/// For range (3rc fmt): v_a consecutive registers starting at v_c.
fn extract_arg_regs(instr: &Instruction) -> Vec<u32> {
    use dex::instructions::InstructionKind;
    match &instr.kind {
        InstructionKind::InvokeKind => {
            let count = instr.v_a.unwrap_or(0) as usize;
            let regs = [instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g];
            regs[..count.min(5)]
                .iter()
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

/// Backward constant-propagation from `invoke_cp` through `instructions`.
/// Returns (reg_index, Option<encoded_value>) for each arg register.
///
/// Encoded value formats:
///   "\"text\""          — string literal (quoted)
///   "42" / "0x2a"       — integer literal
///   "@sget:Lclass;->field:T"          — static field reference
///   "@invoke!method_ref!arg1|arg2"    — result of intermediate method call
fn resolve_static_args(
    instructions: &[Instruction],
    invoke_cp: u32,
    arg_regs: &[u32],
) -> Vec<(u32, Option<String>)> {
    let mut results: Vec<(u32, Option<String>)> = arg_regs.iter().map(|&r| (r, None)).collect();
    let mut unresolved: std::collections::HashSet<usize> = (0..results.len()).collect();

    // Collect and sort instructions before invoke_cp by codepoint ascending.
    let mut before: Vec<&Instruction> = instructions
        .iter()
        .filter(|i| i.codepoint < invoke_cp)
        .collect();
    before.sort_by_key(|i| i.codepoint);

    // Scan in reverse (most recent assignment wins).
    let n = before.len();
    let mut idx = n;
    while idx > 0 && !unresolved.is_empty() {
        idx -= 1;
        let instr = before[idx];
        let istr = &instr.instruction_str;

        // const-string vX, "..."
        if istr.starts_with("const-string") {
            if let Some(dest_reg) = parse_dest_reg(istr) {
                if let Some(comma) = istr.find(", ") {
                    let value = istr[comma + 2..].trim().trim_matches('"').to_string();
                    mark_resolved(&mut results, &mut unresolved, dest_reg,
                                  Some(format!("\"{}\"", value)));
                }
            }
        }
        // const/4, const/16, const, const/high16
        else if istr.starts_with("const") && !istr.starts_with("const-string") {
            if let Some(dest_reg) = parse_dest_reg(istr) {
                if let Some(comma) = istr.find(", ") {
                    let value_part = istr[comma + 2..].trim().to_string();
                    mark_resolved(&mut results, &mut unresolved, dest_reg, Some(value_part));
                }
            }
        }
        // sget / sget-object vX, Lclass;->field:TYPE — static field read
        else if istr.starts_with("sget") {
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
        }
        // move-result / move-result-object vX — result of the immediately preceding invoke
        else if istr.starts_with("move-result") {
            if let Some(dest_reg) = parse_dest_reg(istr) {
                // Only do (expensive) recursive resolution when this register is
                // actually one of the arg registers we need.  Without this guard
                // we'd recurse for every move-result in the method regardless of
                // whether it writes to a register we care about, which is O(k^depth).
                let is_relevant = unresolved.iter().any(|&i| results[i].0 == dest_reg);
                if is_relevant && idx > 0 {
                    let prev = before[idx - 1];
                    let prev_istr = &prev.instruction_str;
                    if prev_istr.contains("invoke") {
                        // Extract the method reference ("Lclass;->method").
                        if let Some(method_ref) = extract_method_ref_from_invoke(prev_istr) {
                            // Recursively resolve the preceding invoke's own args (one level).
                            let prev_arg_regs = extract_arg_regs(prev);
                            let inner = resolve_static_args(
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

/// Parse the destination register from the first token of an instruction string.
/// e.g. "const-string v3, \"hello\"" → Some(3)
fn parse_dest_reg(istr: &str) -> Option<u32> {
    // format: "opcode vN, ..." — find first space then parse vN
    let after_op = istr.split_whitespace().nth(1)?;
    let reg_str = after_op.trim_end_matches(',');
    if reg_str.starts_with('v') {
        reg_str[1..].parse().ok()
    } else {
        None
    }
}

/// Extract "Lclass;->method" from an invoke instruction string.
/// e.g. "invoke-static {v1}, Lhivhi/wfg;->wfg(I)Ljava/lang/String;" → Some("Lhivhi/wfg;->wfg")
fn extract_method_ref_from_invoke(istr: &str) -> Option<String> {
    // The method reference follows "}, "
    let after = istr.find("}, ")
        .or_else(|| istr.find("} .."))  // range invoke: "}, " may look like "} .., "
        .map(|p| p + 3)
        .unwrap_or_else(|| {
            // Fallback: skip past the last '}'
            istr.rfind('}').map(|p| p + 1).unwrap_or(0)
        });
    let ref_and_sig = istr[after..].trim();
    // Strip the descriptor: "Lhivhi/wfg;->wfg(I)Ret" → "Lhivhi/wfg;->wfg"
    let method_ref = ref_and_sig.split('(').next()?.trim().to_string();
    if method_ref.is_empty() { None } else { Some(method_ref) }
}

fn mark_resolved(
    results: &mut Vec<(u32, Option<String>)>,
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

/// Scan all classes/methods in the DEX for invoke instructions matching `target_pattern`.
fn find_usages(dex: &DexFileWithRaw, target_pattern: &str) -> Vec<UsageSite> {
    let mut sites = Vec::new();
    let no_index: u32 = 0xffff_ffff;

    for class_def in &dex.parsed.class_defs {
        // Resolve source file name
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
                // Match: instruction_str contains target_pattern after "}, " separator
                // (the method reference part)
                let istr = &instr.instruction_str;
                if !istr.contains("invoke") { continue; }

                // Check if the method reference part (after "}, ") matches
                let matches = if let Some(pos) = istr.find("}, ") {
                    istr[pos + 3..].contains(target_pattern)
                } else if let Some(pos) = istr.find("} ..") {
                    // range form: "invoke-* {v0 .. v1}, Target"
                    // Actually range format: "{v0 .. vN}, Method"
                    // find the last "}, " or just check the whole string
                    istr[pos..].contains(target_pattern)
                } else {
                    // fallback: check whole string
                    istr.contains(target_pattern)
                };

                if !matches { continue; }

                let arg_regs = extract_arg_regs(instr);
                let static_args = resolve_static_args(
                    &method.instructions,
                    instr.codepoint,
                    &arg_regs,
                );
                let line_number = debug_info::lookup_line(&method.line_map, instr.codepoint);

                sites.push(UsageSite {
                    caller_class:  method.class_name.clone(),
                    caller_method: format!("{}{}", method.method_name, method.proto_desc),
                    source_file:   source_file.clone(),
                    line_number,
                    invoke_cp:     instr.codepoint,
                    invoke_str:    istr.clone(),
                    arg_regs,
                    static_args,
                    caller_method_obj: Some(method.clone()),
                });
            }
        }
    }

    sites
}

/// Print find results in the documented format.
fn print_usages(sites: &[UsageSite], target: &str, fmt: OutputFormat) {
    match fmt {
        OutputFormat::Text => print_usages_text(sites, target),
        OutputFormat::Json => print_usages_json(sites),
        OutputFormat::Csv  => print_usages_csv(sites),
    }
}

fn print_usages_text(sites: &[UsageSite], target: &str) {
    println!();
    println!("[find] {}  ({} call site{})", target, sites.len(),
             if sites.len() == 1 { "" } else { "s" });

    for (i, site) in sites.iter().enumerate() {
        println!();
        println!("  #{}  {}->{}",
                 i + 1, site.caller_class, site.caller_method);

        if !site.source_file.is_empty() {
            let line_str = site.line_number
                .map(|l| format!(":{}", l))
                .unwrap_or_default();
            println!("      {}{}",  site.source_file, line_str);
        }

        println!("      {}", site.invoke_str);

        // Static args
        let args_str = format_args_list(&site.arg_regs, &site.static_args);
        println!("      args (static): {}", args_str);
    }
    println!();
}

/// NDJSON output for `--find`: one JSON object per line. We do not wrap
/// in an array — that keeps the output streamable and trivially
/// consumed by `jq -c`, `python -c "import json; ..."`, etc.
fn print_usages_json(sites: &[UsageSite]) {
    for (i, site) in sites.iter().enumerate() {
        let rec = FindRecord::from_site(site, i + 1);
        match serde_json::to_string(&rec) {
            Ok(s)  => println!("{}", s),
            Err(e) => eprintln!("[-] JSON encode failed at site {}: {}", i + 1, e),
        }
    }
}

/// CSV output for `--find`. Header row first, then one row per site.
/// Static args are flattened into a single `static_args` cell as
/// `reg=value|reg=value` — see the `OutputFormat::Csv` docs for why.
fn print_usages_csv(sites: &[UsageSite]) {
    println!("{}", FIND_CSV_HEADER);
    for (i, site) in sites.iter().enumerate() {
        let rec = FindRecord::from_site(site, i + 1);
        println!("{}", rec.to_csv_row());
    }
}

const FIND_CSV_HEADER: &str =
    "index,caller_class,caller_method,source_file,line_number,invoke_str,static_args";

/// Structured snapshot of a single call site used for `json`/`csv` output.
/// Lives at the top level rather than inside the printers so it can be
/// flattened into `FindExecRecord` for `--find-exec` without code dup.
#[derive(Debug, serde::Serialize)]
struct FindRecord {
    /// 1-based — matches the index humans see in text mode.
    index:         usize,
    caller_class:  String,
    caller_method: String,
    source_file:   String,
    /// Source line number from the dex debug info, if present.
    line_number:   Option<u32>,
    /// Raw smali-style invoke text (e.g. `invoke-static {v1,v2}, L…;->…(J)L…;`).
    invoke_str:    String,
    /// Per-register static-arg encoding (register → either a literal or
    /// `@invoke!`/`@sget:` chain). Matches the wire format
    /// `resolve_arg_encoding` understands.
    static_args:   Vec<StaticArgRecord>,
}

#[derive(Debug, serde::Serialize)]
struct StaticArgRecord {
    register: u32,
    /// None when the static-arg backprop couldn't resolve the register
    /// (e.g. the value comes from a runtime computation or wide pair's
    /// second half). Serialises as JSON `null` / empty CSV cell.
    value: Option<String>,
}

impl FindRecord {
    fn from_site(site: &UsageSite, index: usize) -> Self {
        let static_args = site.static_args.iter()
            .map(|(reg, val)| StaticArgRecord { register: *reg, value: val.clone() })
            .collect();
        FindRecord {
            index,
            caller_class:  site.caller_class.clone(),
            caller_method: site.caller_method.clone(),
            source_file:   site.source_file.clone(),
            line_number:   site.line_number,
            invoke_str:    site.invoke_str.clone(),
            static_args,
        }
    }

    fn to_csv_row(&self) -> String {
        let args_cell = self.static_args.iter()
            .map(|a| format!("v{}={}", a.register, a.value.as_deref().unwrap_or("")))
            .collect::<Vec<_>>()
            .join("|");
        let line = self.line_number.map(|n| n.to_string()).unwrap_or_default();
        format!("{},{},{},{},{},{},{}",
            self.index,
            csv_escape(&self.caller_class),
            csv_escape(&self.caller_method),
            csv_escape(&self.source_file),
            line,
            csv_escape(&self.invoke_str),
            csv_escape(&args_cell),
        )
    }
}

/// Escape a single CSV cell per RFC 4180. We always quote fields that
/// contain a comma, quote, or newline — otherwise we emit the raw
/// string. Quoting a double-quote means doubling it (`"` → `""`).
fn csv_escape(s: &str) -> String {
    let needs_quote = s.contains(',') || s.contains('"') || s.contains('\n');
    if !needs_quote {
        return s.to_string();
    }
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        if c == '"' { out.push('"'); }
        out.push(c);
    }
    out.push('"');
    out
}

#[cfg(test)]
mod output_format_tests {
    use super::{OutputFormat, csv_escape};

    #[test]
    fn output_format_parse_accepts_known_modes() {
        assert_eq!(OutputFormat::parse("text"), Some(OutputFormat::Text));
        assert_eq!(OutputFormat::parse("json"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("csv"),  Some(OutputFormat::Csv));
        // Case-insensitive — `--output JSON` and `--output Json` both work.
        assert_eq!(OutputFormat::parse("JSON"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("Csv"),  Some(OutputFormat::Csv));
    }

    #[test]
    fn output_format_parse_rejects_unknown() {
        assert_eq!(OutputFormat::parse(""),       None);
        assert_eq!(OutputFormat::parse("yaml"),   None);
        assert_eq!(OutputFormat::parse("ndjson"), None);
    }

    /// A cell with no special characters passes through verbatim — we
    /// don't quote unnecessarily so the output stays as compact as
    /// possible for spreadsheet imports.
    #[test]
    fn csv_escape_passes_safe_cells_through() {
        assert_eq!(csv_escape("hello"),       "hello");
        assert_eq!(csv_escape("L;->foo"),     "L;->foo");
        assert_eq!(csv_escape("0xff00aabb"),  "0xff00aabb");
        assert_eq!(csv_escape(""),            "");
    }

    /// Comma, double-quote, and newline all trigger quoting per RFC 4180.
    /// Embedded quotes are doubled.
    #[test]
    fn csv_escape_quotes_when_needed() {
        assert_eq!(csv_escape("a,b"),     "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line1\nline2"), "\"line1\nline2\"");
    }

    /// The string value `"MediaItem{"` (already quoted by format_value)
    /// round-trips correctly: inner double-quotes get doubled, and the
    /// whole thing is wrapped.
    #[test]
    fn csv_escape_round_trips_format_value_string() {
        assert_eq!(csv_escape("\"MediaItem{\""), "\"\"\"MediaItem{\"\"\"");
    }
}

/// Parse a target pattern like `"Lcom/Foo;->bar"` into `(class, method_name)`.
/// Strips any parameter descriptor from the method name.
fn parse_target_ref(target: &str) -> Option<(String, String)> {
    let mut parts = target.splitn(2, "->");
    let class  = parts.next()?.to_string();
    let method = parts.next()?
        .splitn(2, '(')
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    Some((class, method))
}

/// Convert a site's static args into a `Vec<Value>` suitable for `call_method`.
///
/// `resolve_static_args` wraps string constants in surrounding double-quote
/// characters for display (e.g. `"\"hello\""`) — strip those before handing
/// the value to the VM so the runtime sees the bare string, not the quoted one.
/// Integer-looking values are converted to `Value::Int`.
/// Unresolved registers become `Value::Null`.
fn static_args_to_values(static_args: &[(u32, Option<String>)]) -> Vec<Value> {
    static_args.iter().map(|(_, val)| {
        match val {
            Some(s) => {
                // String constants are wrapped in quotes for display — unwrap them.
                if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
                    Value::Str(s[1..s.len()-1].to_string())
                } else if let Ok(n) = s.parse::<i64>() {
                    Value::Int(n)
                } else {
                    Value::Str(s.clone())
                }
            }
            None => Value::Null,
        }
    }).collect()
}

/// Resolve an encoded arg string (from `resolve_static_args`) to a `Value`.
///
/// Handles:
/// - `"\"text\""` — string literal
/// - integer / hex literals
/// - `"@sget:Lclass;->field:T"` — static field; R$string fields are resolved
///   to their resource ID integer via the resource table
/// - `"@invoke!method_ref!inner1|inner2"` — execute an intermediate method call;
///   inner args are resolved recursively first
///
/// When an intermediate method call is needed, the VM is used to execute it.
/// `resources` is the optional preloaded resource table.
fn resolve_arg_encoding(
    encoded: &str,
    resources: Option<&ResourceTable>,
    vm: &mut Vm,
) -> Value {
    // --- String literal ---
    if encoded.starts_with('"') && encoded.ends_with('"') && encoded.len() >= 2 {
        return Value::Str(encoded[1..encoded.len() - 1].to_string());
    }

    // --- Integer literal (decimal or hex) ---
    let trimmed = encoded.trim();
    if let Ok(n) = trimmed.parse::<i64>() {
        return Value::Int(n);
    }
    if let Some(hex) = trimmed.strip_prefix("0x") {
        if let Ok(n) = i64::from_str_radix(hex, 16) {
            return Value::Int(n);
        }
    }
    if let Some(neg_hex) = trimmed.strip_prefix("-0x") {
        if let Ok(n) = i64::from_str_radix(neg_hex, 16) {
            return Value::Int(-n);
        }
    }

    // --- @sget:Lclass;->field:T ---
    if let Some(rest) = encoded.strip_prefix("@sget:") {
        return resolve_sget_encoding(rest, resources);
    }

    // --- @invoke!method_ref!inner_arg1|inner_arg2|... ---
    if let Some(rest) = encoded.strip_prefix("@invoke!") {
        // Split into method_ref and inner args on the first '!'
        let bang = rest.find('!').unwrap_or(rest.len());
        let method_ref = &rest[..bang];
        let inner_str = if bang < rest.len() { &rest[bang + 1..] } else { "" };

        // Resolve each inner arg recursively.
        let inner_values: Vec<Value> = inner_str
            .split('|')
            .filter(|s| !s.is_empty())
            .map(|enc| resolve_arg_encoding(enc, resources, vm))
            .collect();

        // Fast path: if any resolved inner arg is a resource ID, look it up directly
        // in the preloaded resource table.  Covers both:
        //   wfg(R.string.foo)          — static wrapper, res_id is args[0]
        //   context.getString(res_id)  — instance call, `this` is args[0], res_id is args[1]
        let found_res = inner_values.iter().find_map(|v| {
            if let Value::Int(n) = v { Some(*n as u32) } else { None }
        });
        if let Some(res_id) = found_res {
            if let Some(s) = vm.resolve_resource_id(res_id) {
                return Value::Str(s.to_string());
            }
        }

        // Slow path: execute the intermediate method via the VM.
        // Only reached when the resource table doesn't have the answer (e.g. the
        // intermediate method does more than a simple getString).
        let mut ref_parts = method_ref.splitn(2, "->");
        let class_name  = ref_parts.next().unwrap_or("").to_string();
        let method_name = ref_parts.next().unwrap_or("").to_string();

        if !class_name.is_empty() && !method_name.is_empty() {
            if let Some(m) = vm.find_and_clone_method(&class_name, &method_name) {
                let result = vm.call_method(&m, inner_values.clone());
                if let Some(v) = result {
                    return v;
                }
            }
        }

        return Value::Null;
    }

    // Unrecognised — treat as opaque string
    Value::Str(encoded.to_string())
}

/// Resolve a `@sget` field reference to a Value.
/// R$string fields → `Value::Int(resource_id)` (looked up by name in the resource table).
fn resolve_sget_encoding(field_ref: &str, resources: Option<&ResourceTable>) -> Value {
    // field_ref = "Lcom/fen/jecac/R$string;->ready_user_info_success:I"
    let mut parts = field_ref.splitn(2, "->");
    let class_part = parts.next().unwrap_or("");
    let field_part  = parts.next().unwrap_or("");
    let field_name  = field_part.split(':').next().unwrap_or(field_part);

    if class_part.contains("R$string") || class_part.contains("R\\$string") {
        if let Some(table) = resources {
            // Look up by name in string resources → return resource ID as Int.
            if let Some(entry) = table.entries().iter()
                .find(|e| e.type_name == "string" && e.name == field_name)
            {
                return Value::Int(entry.id as i64);
            }
        }
    }

    Value::Null
}

/// Execute the TARGET method at each call site with its statically-resolved args.
///
/// Strategy: parse the DEX once, load it into a single VM, find the target
/// method once, then run all sites sequentially using `reset_for_call` to
/// clear transient state between invocations.  This is much faster than
/// re-parsing the DEX per site because the DEX parse dominates execution time.
///
/// A 50 000-instruction per-call budget prevents infinite loops.
/// `dex_files` — all DEX shards/splits loaded; ALL are added to the VM so that
/// cross-shard helper calls (e.g. crypto util in a config split) can be resolved.
fn exec_usages(
    dex_files: &[DexFileWithRaw],
    sites: &[UsageSite],
    target: &str,
    verbose: u8,
    resources: Option<&ResourceTable>,
    fmt: OutputFormat,
    validate_deobf: bool,
) {
    const INSTR_LIMIT: u64 = 50_000;

    // ── Header / banner ──
    // text:  the historic two-line preamble.
    // json:  no preamble — NDJSON is records-only.
    // csv:   header row only.
    match fmt {
        OutputFormat::Text => {
            println!();
            println!("[find-exec] {}  ({} call site{})", target, sites.len(),
                     if sites.len() == 1 { "" } else { "s" });
            if dex_files.len() > 1 {
                println!("[find-exec] {} DEX shard(s) loaded into VM", dex_files.len());
            }
        }
        OutputFormat::Json => {}
        OutputFormat::Csv  => println!("{}", FIND_EXEC_CSV_HEADER),
    }

    // Parse the target into class + method name.
    let (target_class, target_method_name) = match parse_target_ref(target) {
        Some(pair) => pair,
        None => {
            eprintln!("[-] Could not parse target: {}", target);
            return;
        }
    };

    // Find the target method across all loaded DEX shards.
    let target_method = dex_files.iter().find_map(|dex| {
        find_method_in_dex(dex, &target_class, &target_method_name)
    });
    let target_method = match target_method {
        Some(m) => m,
        None => {
            eprintln!("[-] Target method not found: {}->{}", target_class, target_method_name);
            return;
        }
    };

    // Build the VM and load ALL DEX shards so nested calls across splits resolve.
    let mut vm = Vm::new();
    vm.enable_logging(verbose);
    for dex in dex_files {
        let clone = DexFileWithRaw::from_bytes(dex.raw_bytes().to_vec(), dex.parsed.filename.clone())
            .expect("re-parse of already-loaded DEX failed");
        vm.add_dex_file(&clone);
    }
    // Load resources into the VM so getString() calls resolve correctly.
    if let Some(table) = resources {
        vm.load_resources(
            table.entries().iter()
                .filter(|e| e.type_name == "string" && !e.value.starts_with('@'))
                .map(|e| (e.id, e.value.clone()))
        );
    }

    // ── Per-batch result cache ──
    // Deobfuscators are pure functions of their static args (no I/O,
    // no clock, no PRNG), so two sites with the same fingerprint MUST
    // decrypt to the same plaintext. We exploit that invariant to skip
    // re-executing identical inputs. The cache lives for the duration
    // of this --find-exec run only, so a fresh invocation re-checks
    // everything (in case the deobfuscator implementation changed).
    //
    // When `validate_deobf` is set we disable the skip-path AND keep
    // a per-fingerprint "all results seen" map so we can flag any
    // input that produced more than one distinct result — that would
    // indicate a non-deterministic VM or deobfuscator (a real bug,
    // not a feature). See the divergence summary at the bottom of
    // this fn for the report shape.
    //
    // Same key function as `analysis::exec_calls`, kept consistent
    // via the shared `static_args_fingerprint`.
    use std::collections::HashMap;
    let mut result_cache: HashMap<String, Option<vm::value::Value>> = HashMap::new();
    let mut cache_hits: usize = 0;

    // In validate mode we record every (fingerprint → distinct
    // results) pair; outside validate mode this stays empty.
    // Distinct-result keys are the formatted display value (string)
    // since `Value` doesn't implement Hash + Eq across all variants.
    let mut divergence_tracker: HashMap<String, HashMap<String, usize>> = HashMap::new();

    for (i, site) in sites.iter().enumerate() {
        let key = analysis::static_args_fingerprint(&site.static_args);

        // Cache fast-path — only consulted when validate mode is OFF.
        // Validate mode disables this so every site is executed and
        // we can post-hoc compare against earlier results with the
        // same fingerprint.
        let mut result: Option<vm::value::Value> = None;
        if !validate_deobf {
            if let Some(cached) = result_cache.get(&key) {
                cache_hits += 1;
                result = cached.clone();
            }
        }

        if result.is_none() && (!result_cache.contains_key(&key) || validate_deobf) {
            // Fresh execution.
            //
            // We bridge the static_args (one entry per *register
            // operand* in the invoke) to call_method's argument
            // convention via `coalesce_call_args`. The coalescer
            // splits long/double values across the two register slots
            // that `read_wide` expects — without it, `--find-exec`
            // on a `(J)` deobfuscator returns void because the long
            // arrives corrupted (see the helper's doc comment).
            vm.reset_for_call(INSTR_LIMIT);
            let args = analysis::coalesce_call_args(
                &site.static_args,
                &site.invoke_str,
                &target_method.proto_desc,
                resources,
                &mut vm,
            );
            vm.reset_for_call(INSTR_LIMIT);
            let fresh = vm.call_method(&target_method, args);
            if !validate_deobf {
                result_cache.insert(key.clone(), fresh.clone());
            }
            result = fresh;
        }

        // In validate mode, record this result against the
        // fingerprint so we can detect any group whose calls
        // diverged. The displayed form is the canonicalisation key —
        // two calls "agree" iff their formatted output strings match.
        if validate_deobf {
            let display_key = match &result {
                Some(v) => format!("{}|{}", infer_value_type(v), format_value(v)),
                None    => "void|void".to_string(),
            };
            *divergence_tracker
                .entry(key.clone())
                .or_default()
                .entry(display_key)
                .or_insert(0) += 1;
        }

        // Build the structured per-site record once and dispatch on format.
        // resource_string is populated when the result is an Android
        // resource ID (0x7fXXXXXX) we can resolve to a literal string.
        let (result_display, resource_string, result_type) = format_call_result(&result, &vm);
        let exec_rec = FindExecRecord {
            site: FindRecord::from_site(site, i + 1),
            result: ResultRecord {
                value:           result_display.clone(),
                value_type:      result_type,
                resource_string: resource_string.clone(),
            },
        };

        match fmt {
            OutputFormat::Text => {
                println!();
                println!("  #{}  {}->{}",
                         i + 1, site.caller_class, site.caller_method);

                if !site.source_file.is_empty() {
                    let line_str = site.line_number
                        .map(|l| format!(":{}", l))
                        .unwrap_or_default();
                    println!("      {}{}", site.source_file, line_str);
                }

                println!("      {}", site.invoke_str);

                let args_str = format_args_list(&site.arg_regs, &site.static_args);
                println!("      args (static):  {}", args_str);

                // Text mode still gets the resolved-resource-id annotation
                // appended inline (matches historic output).
                let printable = match resource_string {
                    Some(ref s) => format!("{} (\"{}\")", result_display, s),
                    None        => result_display,
                };
                println!("      result:  {}", printable);
            }
            OutputFormat::Json => {
                match serde_json::to_string(&exec_rec) {
                    Ok(s)  => println!("{}", s),
                    Err(e) => eprintln!("[-] JSON encode failed at site {}: {}", i + 1, e),
                }
            }
            OutputFormat::Csv => {
                println!("{}", exec_rec.to_csv_row());
            }
        }
    }
    // ── Cache-effectiveness summary ──
    // Always reported, but routed to the same place as the banner
    // (`say` semantics — stdout in text mode, stderr in json/csv) so
    // structured-output consumers don't have to filter it.
    let total = sites.len();
    let unique = total - cache_hits;
    let pct = if total > 0 { (cache_hits as f64) * 100.0 / (total as f64) } else { 0.0 };
    let summary = if validate_deobf {
        format!(
            "[find-exec] validate-deobf: cache disabled, {} site(s) executed fresh",
            total,
        )
    } else {
        format!(
            "[find-exec] cache: {} unique input(s) → {} site(s) executed, {} skipped ({:.1}% cache hit rate)",
            unique, unique, cache_hits, pct,
        )
    };
    match fmt {
        OutputFormat::Text => println!("{}", summary),
        _                  => eprintln!("{}", summary),
    }

    // ── Validate-mode divergence report ──
    // Walk every fingerprint group that we saw more than one
    // distinct output for. Each one is a deterministic-deobfuscator
    // assumption violation — either a VM bug or a deobfuscator that
    // actually does have state. Worth surfacing loudly.
    if validate_deobf {
        let mut diverged: Vec<(&String, &HashMap<String, usize>)> = divergence_tracker.iter()
            .filter(|(_, results)| results.len() > 1)
            .collect();
        diverged.sort_by_key(|(k, _)| (*k).clone());

        if diverged.is_empty() {
            let msg = format!(
                "[find-exec] validate-deobf: ✓ all {} unique input(s) produced consistent results",
                divergence_tracker.len(),
            );
            match fmt {
                OutputFormat::Text => println!("{}", msg),
                _                  => eprintln!("{}", msg),
            }
        } else {
            let header = format!(
                "[find-exec] validate-deobf: ✗ {} input(s) produced divergent results:",
                diverged.len(),
            );
            match fmt {
                OutputFormat::Text => println!("{}", header),
                _                  => eprintln!("{}", header),
            }
            // Show up to 10 examples so the report stays readable.
            for (fingerprint, results) in diverged.iter().take(10) {
                let line = format!("  input {:?} → {} distinct result(s):", fingerprint, results.len());
                match fmt {
                    OutputFormat::Text => println!("{}", line),
                    _                  => eprintln!("{}", line),
                }
                for (rendered, count) in results.iter() {
                    let item = format!("      {}× {}", count, rendered);
                    match fmt {
                        OutputFormat::Text => println!("{}", item),
                        _                  => eprintln!("{}", item),
                    }
                }
            }
            if diverged.len() > 10 {
                let tail = format!("  … {} more diverging input(s) elided", diverged.len() - 10);
                match fmt {
                    OutputFormat::Text => println!("{}", tail),
                    _                  => eprintln!("{}", tail),
                }
            }
        }
    }

    if matches!(fmt, OutputFormat::Text) {
        println!();
    }
}

/// Format a call_method result for display, optionally resolving an
/// Android resource ID to its string value. Returns
/// (display_value, resolved_resource_string, type_name).
///
/// * **Int** in the `0x7fXXXXXX` range — looked up in the VM's
///   preloaded resource table. text mode appends the lookup inline as
///   `42 ("Hello")`; json/csv keep them in separate fields so a
///   downstream consumer can choose its own rendering.
/// * **All other Value variants** — pass through `format_value` and
///   leave `resolved_resource_string` as None.
fn format_call_result(
    result: &Option<Value>,
    vm: &Vm,
) -> (String, Option<String>, String) {
    match result {
        Some(Value::Int(n)) => {
            let uid = *n as u32;
            let resolved = if uid >> 24 == 0x7f {
                vm.resolve_resource_id(uid).map(|s| s.to_string())
            } else {
                None
            };
            (format_value(&Value::Int(*n)), resolved, "int".to_string())
        }
        Some(v) => (format_value(v), None, infer_value_type(v).to_string()),
        None    => ("void".to_string(), None, "void".to_string()),
    }
}

fn infer_value_type(v: &Value) -> &'static str {
    match v {
        Value::Null     => "null",
        Value::Int(_)   => "int",
        Value::Float(_) => "float",
        Value::Bool(_)  => "boolean",
        Value::Str(_)   => "String",
        Value::Bytes(_) => "byte[]",
        Value::Array(_) => "Object[]",
    }
}

const FIND_EXEC_CSV_HEADER: &str =
    "index,caller_class,caller_method,source_file,line_number,invoke_str,static_args,\
     result_value,result_type,result_resource_string";

/// `--find-exec` record. Flattens a `FindRecord` (the site itself)
/// with a `ResultRecord` (what the VM produced). The flatten attr
/// keeps the JSON keys at the top level — no nested `site` object
/// the consumer has to unwrap.
#[derive(Debug, serde::Serialize)]
struct FindExecRecord {
    #[serde(flatten)]
    site:   FindRecord,
    #[serde(flatten)]
    result: ResultRecord,
}

/// Snapshot of one VM call's result.
///
/// `value` is the human-readable rendering (e.g. `"hello"` for a String,
/// `123` for an int, `bytes[N]=<hex>...` for a byte array).
/// `value_type` is the Java-style type name (`String`, `int`, `byte[]`).
/// `resource_string` is the resolved string literal when `value` is a
/// 0x7fXXXXXX Android resource ID — None otherwise.
#[derive(Debug, serde::Serialize)]
struct ResultRecord {
    value:           String,
    value_type:      String,
    resource_string: Option<String>,
}

impl FindExecRecord {
    fn to_csv_row(&self) -> String {
        let mut row = self.site.to_csv_row();
        row.push(',');
        row.push_str(&csv_escape(&self.result.value));
        row.push(',');
        row.push_str(&csv_escape(&self.result.value_type));
        row.push(',');
        row.push_str(&csv_escape(self.result.resource_string.as_deref().unwrap_or("")));
        row
    }
}

/// Format the static args list for display.
fn format_args_list(arg_regs: &[u32], static_args: &[(u32, Option<String>)]) -> String {
    if arg_regs.is_empty() {
        return "(no args)".to_string();
    }
    let parts: Vec<String> = static_args.iter().map(|(reg, val)| {
        match val {
            Some(v) => {
                let display = if v.starts_with("@invoke!") {
                    // "@invoke!Lhivhi/wfg;->wfg!@sget:L...;->field_name:I"
                    // → "<wfg(R.string.field_name)>"
                    let rest = &v["@invoke!".len()..];
                    let bang = rest.find('!').unwrap_or(rest.len());
                    let method = rest[..bang].rsplit("->").next().unwrap_or(&rest[..bang]);
                    let inner  = if bang < rest.len() { &rest[bang+1..] } else { "" };
                    let inner_display = if let Some(sget_rest) = inner.strip_prefix("@sget:") {
                        let field = sget_rest.split("->").nth(1)
                            .and_then(|f| f.split(':').next())
                            .unwrap_or(sget_rest);
                        format!("R.string.{}", field)
                    } else {
                        inner.to_string()
                    };
                    format!("<{}({})>", method, inner_display)
                } else if let Some(rest) = v.strip_prefix("@sget:") {
                    // "@sget:Lclass;->field_name:I" → "sget(R.string.field_name)"
                    let field = rest.split("->").nth(1)
                        .and_then(|f| f.split(':').next())
                        .unwrap_or(rest);
                    format!("sget({})", field)
                } else {
                    v.clone()
                };
                format!("v{} = {}", reg, display)
            }
            None => format!("v{} = <register not resolved>", reg),
        }
    }).collect();
    parts.join(", ")
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod class_header_tests {
    use super::*;
    use platypus_dex::access_flags::ClassAccessFlag;

    /// Build a stub Clazz with the access flags + supertypes we want
    /// to test against. The other fields are placeholders that
    /// format_java_class_header doesn't read.
    fn mk(
        class_name: &str,
        flags: &[ClassAccessFlag],
        superclass: &str,
        interfaces: &[&str],
    ) -> Clazz {
        Clazz {
            class_id: 0,
            class_name: class_name.to_string(),
            access_flags: flags.to_vec(),
            methods: Vec::new(),
            static_fields: Vec::new(),
            instance_fields: Vec::new(),
            superclass_name: superclass.to_string(),
            interfaces: interfaces.iter().map(|s| s.to_string()).collect(),
            annotations: Vec::new(),
        }
    }

    #[test]
    fn plain_class_with_object_superclass_omits_extends() {
        let c = mk("Lcom/Foo;", &[ClassAccessFlag::Public], "Ljava/lang/Object;", &[]);
        assert_eq!(format_java_class_header(&c), "public class Foo");
    }

    #[test]
    fn class_with_non_object_superclass_emits_extends() {
        let c = mk("Lcom/Foo;", &[ClassAccessFlag::Public], "Lcom/Bar;", &[]);
        assert_eq!(format_java_class_header(&c), "public class Foo extends Bar");
    }

    #[test]
    fn class_implementing_interfaces() {
        let c = mk("Lcom/Foo;",
                   &[ClassAccessFlag::Public, ClassAccessFlag::Final],
                   "Lcom/Bar;",
                   &["Lcom/I1;", "Lcom/I2;"]);
        assert_eq!(format_java_class_header(&c), "public final class Foo extends Bar implements I1, I2");
    }

    #[test]
    fn interface_drops_abstract_and_class_keywords() {
        // Regression: previously emitted "interface abstract class …".
        // Interfaces are implicitly abstract in Java source and use the
        // `interface` keyword, not `class`.
        let c = mk("Lcom/Foo;",
                   &[ClassAccessFlag::Abstract, ClassAccessFlag::Interface],
                   "Ljava/lang/Object;",
                   &[]);
        assert_eq!(format_java_class_header(&c), "interface Foo");
    }

    #[test]
    fn interface_with_super_interfaces_uses_extends_not_implements() {
        // Java syntax: `interface X extends Y, Z`, not `implements`.
        let c = mk("Lcom/Foo;",
                   &[ClassAccessFlag::Abstract, ClassAccessFlag::Interface],
                   "Ljava/lang/Object;",
                   &["Lcom/I1;", "Lcom/I2;"]);
        assert_eq!(format_java_class_header(&c), "interface Foo extends I1, I2");
    }

    #[test]
    fn enum_uses_enum_keyword_and_drops_final() {
        // The dex always tags enums as final; that's already implied by
        // the `enum` keyword so we suppress it.
        let c = mk("Lcom/Foo;",
                   &[ClassAccessFlag::Public, ClassAccessFlag::Final, ClassAccessFlag::Enum],
                   "Ljava/lang/Enum;",
                   &[]);
        // Superclass for enums is `Enum`, which IS non-Object — we
        // still emit `extends Enum` because filtering that would
        // require special-casing on the Enum class itself; jadx
        // similarly leaves it implicit at source level by emitting
        // `enum Foo` only, but our minimum-viable correctness is OK
        // with the explicit form.
        assert_eq!(format_java_class_header(&c), "public enum Foo extends Enum");
    }

    #[test]
    fn class_header_does_not_include_annotations() {
        // format_java_class_header just emits the access modifiers +
        // structural keyword + name + extends/implements — annotations
        // are rendered on separate lines above this header by the
        // decompile_class caller. Verify the header itself is unchanged
        // when annotations are set, so we don't accidentally couple
        // the two passes.
        use platypus_dex::parser::AnnotationItem;
        let mut c = mk("Lcom/Foo;", &[ClassAccessFlag::Public], "Ljava/lang/Object;", &[]);
        c.annotations = vec![
            AnnotationItem { type_name: "Lcom/Bar;".into(), elements: vec![] },
            AnnotationItem { type_name: "Lcom/Baz;".into(), elements: vec![] },
        ];
        assert_eq!(format_java_class_header(&c), "public class Foo");
    }

    #[test]
    fn annotation_class_uses_at_interface_keyword() {
        let c = mk("Lcom/Foo;",
                   &[ClassAccessFlag::Abstract, ClassAccessFlag::Interface, ClassAccessFlag::Annotation],
                   "Ljava/lang/Object;",
                   &[]);
        assert_eq!(format_java_class_header(&c), "@interface Foo");
    }

    #[test]
    fn annotation_class_suppresses_extends_implements() {
        // Regression: the dex models annotation types as `class extends
        // java.lang.annotation.Annotation` (sometimes with implements
        // entries for marker interfaces too), but Java source uses
        // `@interface Foo {}` with no extends/implements clause.
        // Verify both lists are suppressed.
        let c = mk("Lcom/Foo;",
                   &[ClassAccessFlag::Abstract, ClassAccessFlag::Interface, ClassAccessFlag::Annotation],
                   "Ljava/lang/annotation/Annotation;",
                   &["Ljava/lang/SomeMarker;"]);
        assert_eq!(format_java_class_header(&c), "@interface Foo");
    }
}
