//! `platypus-dexmapper` CLI — query and apply mappings produced by the
//! Python `dexmapper` tool.
//!
//! Usage:
//!   platypus-dexmapper info <mapping>
//!   platypus-dexmapper lookup-class  <mapping> <obfuscated>
//!   platypus-dexmapper lookup-method <mapping> <obf-class> <obf-method> [desc]
//!   platypus-dexmapper translate-ref <mapping> <method-ref>
//!   platypus-dexmapper apply <mapping> <activity-view.json> [-o out.json]   (requires `rehydrate` feature)
//!
//! `apply` reads a serialised `ActivityView` (the same JSON the viewer's
//! `activity_rehydrate` command returns) and writes a deobfuscated copy.
//! Useful for piping or batch processing outside the viewer. Only
//! available when the binary is built with `--features rehydrate` — the
//! default standalone build omits the `platypus-rehydrate` dep, so the
//! `apply` subcommand fails fast with a clear error.

use std::process::ExitCode;

use platypus_dexmapper::Deobfuscator;

#[cfg(feature = "rehydrate")]
use std::io::Write;
#[cfg(feature = "rehydrate")]
use platypus_rehydrate::ir::ActivityView;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("platypus-dexmapper: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    match sub {
        // ── Consumer (always available) ──
        "info"           => cmd_info(&args[2..]),
        "lookup-class"   => cmd_lookup_class(&args[2..]),
        "lookup-method"  => cmd_lookup_method(&args[2..]),
        "translate-ref"  => cmd_translate_ref(&args[2..]),
        "apply"          => cmd_apply(&args[2..]),
        // ── Producer (--features producer) ──
        "index"          => cmd_index(&args[2..]),
        "index-local"    => cmd_index_local(&args[2..]),
        "index-batch"    => cmd_index_batch(&args[2..]),
        "index-dex"      => cmd_index_dex(&args[2..]),
        "index-apk"      => cmd_index_apk(&args[2..]),
        "analyze"        => cmd_analyze(&args[2..]),
        "patch"          => cmd_patch(&args[2..]),
        "stats"          => cmd_stats(&args[2..]),
        "artifacts"      => cmd_artifacts(&args[2..]),
        "lookup"         => cmd_lookup(&args[2..]),
        "match-method"   => cmd_match_method(&args[2..]),
        "-h" | "--help" | "help" | "" => { print_usage(); Ok(()) }
        other => Err(format!("unknown subcommand `{other}` — try `platypus-dexmapper --help`")),
    }
}

fn print_usage() {
    let exe = std::env::args().next().unwrap_or_else(|| "platypus-dexmapper".into());
    eprintln!("\
{exe} — query, produce, and apply dexmapper mappings

CONSUMER (always available):
    {exe} info <mapping>
    {exe} lookup-class  <mapping> <obf-class>
    {exe} lookup-method <mapping> <obf-class> <obf-method> [desc]
    {exe} translate-ref <mapping> <method-ref>
    {exe} apply <mapping> <activity-view.json> [-o out.json]      (requires --features rehydrate)

PRODUCER (requires --features producer):
    {exe} index        [--db path] [--repos url,...] [--transitive] [--packaging jar|aar] <group:artifact[:version]>
    {exe} index-local  [--db path] <path.jar|path.aar>
    {exe} index-batch  [--db path] [--transitive] <batch.json>
    {exe} index-dex    [--db path] <path.dex>
    {exe} index-apk    [--db path] <path.apk>
    {exe} analyze      [--db path] --format smali|java|dex [--min-confidence 0.4] [--output dir]
                                   [--mapping-output mapping.json] <source-dir|path.apk|path.dex>
    {exe} patch        [--format smali|java] --mapping mapping.json --output out-dir <source-dir>
    {exe} stats        [--db path]
    {exe} artifacts    [--db path]
    {exe} lookup       [--db path] <class-fqn>
    {exe} match-method [--db path] <obf-class> <obf-method> <descriptor>

Default DB path: ~/.dexmapper/index.db (override with --db).
Mapping files may be ProGuard text or JSON (auto-detected).");
}

fn cmd_info(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing <mapping> path")?;
    let d = Deobfuscator::load(path)?;
    let info = d.info();
    println!("path:    {}", info.path.as_deref().unwrap_or("<unknown>"));
    println!("format:  {}", info.format.as_deref().unwrap_or("?"));
    println!("classes: {}", info.class_count);
    println!("methods: {}", info.method_count);
    println!("fields:  {}", info.field_count);
    Ok(())
}

fn cmd_lookup_class(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing <mapping> path")?;
    let obf  = args.get(1).ok_or("missing <obf-class>")?;
    let d = Deobfuscator::load(path)?;
    match d.real_class(obf) {
        Some(real) => { println!("{real}"); Ok(()) }
        None => Err(format!("no mapping for class `{obf}`")),
    }
}

fn cmd_lookup_method(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing <mapping> path")?;
    let cls  = args.get(1).ok_or("missing <obf-class>")?;
    let m    = args.get(2).ok_or("missing <obf-method>")?;
    let desc = args.get(3).map(String::as_str);
    let d = Deobfuscator::load(path)?;
    match d.real_method(cls, m, desc) {
        Some(real) => { println!("{real}"); Ok(()) }
        None => Err(format!("no mapping for {cls}.{m}{}",
                            desc.map(|d| format!(" {d}")).unwrap_or_default())),
    }
}

fn cmd_translate_ref(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing <mapping> path")?;
    let r    = args.get(1).ok_or("missing <method-ref>")?;
    let d = Deobfuscator::load(path)?;
    println!("{}", d.translate_method_ref(r));
    Ok(())
}

#[cfg(feature = "rehydrate")]
fn cmd_apply(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("missing <mapping> path")?;
    let input = args.get(1).ok_or("missing <activity-view.json> path")?;

    // Optional `-o out.json`.
    let mut out_path: Option<&str> = None;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "-o" | "--output" => {
                out_path = Some(args.get(i + 1)
                    .ok_or("`-o` requires a path argument")?);
                i += 2;
            }
            other => return Err(format!("unexpected arg `{other}`")),
        }
    }

    let d = Deobfuscator::load(path)?;
    let text = std::fs::read_to_string(input)
        .map_err(|e| format!("read {input}: {e}"))?;
    let mut view: ActivityView = serde_json::from_str(&text)
        .map_err(|e| format!("parse activity-view json: {e}"))?;
    d.apply_to_activity_view(&mut view);

    let out_json = serde_json::to_string_pretty(&view)
        .map_err(|e| format!("serialize: {e}"))?;
    match out_path {
        Some(p) => std::fs::write(p, out_json)
            .map_err(|e| format!("write {p}: {e}"))?,
        None => {
            let stdout = std::io::stdout();
            let mut lk = stdout.lock();
            lk.write_all(out_json.as_bytes()).map_err(|e| e.to_string())?;
            lk.write_all(b"\n").map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Stub for builds without the `rehydrate` feature. Tells the user how to
/// re-enable it instead of failing with a cryptic "unknown subcommand".
#[cfg(not(feature = "rehydrate"))]
fn cmd_apply(_args: &[String]) -> Result<(), String> {
    Err("`apply` requires the `rehydrate` feature.\n\
         Rebuild with:\n  \
         cargo install --path . --features rehydrate\n  \
         cargo build  --features rehydrate\n\
         Standalone builds support `info`, `lookup-class`, `lookup-method`, \
         and `translate-ref`.".into())
}

// ═══════════════════════════════════════════════════════════════════════════
// Producer subcommands — only meaningful when built with --features producer.
// In standalone builds these print a friendly "feature not enabled" error.
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(not(feature = "producer"))]
fn producer_disabled(sub: &str) -> Result<(), String> {
    Err(format!(
        "`{sub}` requires the `producer` feature.\n\
         Rebuild with:\n  cargo install --path . --features producer"
    ))
}

#[cfg(not(feature = "producer"))] fn cmd_index(_a: &[String])        -> Result<(), String> { producer_disabled("index") }
#[cfg(not(feature = "producer"))] fn cmd_index_local(_a: &[String])  -> Result<(), String> { producer_disabled("index-local") }
#[cfg(not(feature = "producer"))] fn cmd_index_batch(_a: &[String])  -> Result<(), String> { producer_disabled("index-batch") }
#[cfg(not(feature = "producer"))] fn cmd_index_dex(_a: &[String])    -> Result<(), String> { producer_disabled("index-dex") }
#[cfg(not(feature = "producer"))] fn cmd_index_apk(_a: &[String])    -> Result<(), String> { producer_disabled("index-apk") }
#[cfg(not(feature = "producer"))] fn cmd_analyze(_a: &[String])      -> Result<(), String> { producer_disabled("analyze") }
#[cfg(not(feature = "producer"))] fn cmd_patch(_a: &[String])        -> Result<(), String> { producer_disabled("patch") }
#[cfg(not(feature = "producer"))] fn cmd_stats(_a: &[String])        -> Result<(), String> { producer_disabled("stats") }
#[cfg(not(feature = "producer"))] fn cmd_artifacts(_a: &[String])    -> Result<(), String> { producer_disabled("artifacts") }
#[cfg(not(feature = "producer"))] fn cmd_lookup(_a: &[String])       -> Result<(), String> { producer_disabled("lookup") }
#[cfg(not(feature = "producer"))] fn cmd_match_method(_a: &[String]) -> Result<(), String> { producer_disabled("match-method") }

// ── Producer implementations ──────────────────────────────────────────────

#[cfg(feature = "producer")]
mod producer_impl {
    use std::path::PathBuf;

    use platypus_dexmapper::analysis::indexer::Indexer;
    use platypus_dexmapper::analysis::{smali_parser, java_parser};
    use platypus_dexmapper::db::Database;
    use platypus_dexmapper::matching::Matcher;
    use platypus_dexmapper::patching::{JavaPatcher, MappingBuilder, SmaliPatcher};
    use platypus_dexmapper::format::MappingFile;

    /// Default DB path: `~/.dexmapper/index.db` (matches the Python tool).
    pub fn default_db_path() -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
        PathBuf::from(home).join(".dexmapper").join("index.db")
    }

    /// Parse `--db <path>` out of args, returning the rest of the args
    /// without it. `Default: ~/.dexmapper/index.db`.
    pub fn extract_db(args: &[String]) -> (PathBuf, Vec<String>) {
        let mut db: Option<PathBuf> = None;
        let mut rest = Vec::new();
        let mut it = args.iter().peekable();
        while let Some(a) = it.next() {
            if a == "--db" {
                if let Some(v) = it.next() { db = Some(PathBuf::from(v)); }
            } else { rest.push(a.clone()); }
        }
        (db.unwrap_or_else(default_db_path), rest)
    }

    pub fn extract_flag<'a>(args: &mut Vec<String>, flag: &str) -> Option<String> {
        let mut i = 0;
        while i < args.len() {
            if args[i] == flag && i + 1 < args.len() {
                let val = args.remove(i + 1);
                args.remove(i);
                return Some(val);
            }
            i += 1;
        }
        None
    }

    pub fn extract_bool_flag(args: &mut Vec<String>, flag: &str) -> bool {
        if let Some(pos) = args.iter().position(|a| a == flag) { args.remove(pos); true } else { false }
    }

    pub fn open_db(path: &std::path::Path) -> Result<Database, String> {
        Database::open(path)
    }

    pub fn cmd_index(args: &[String]) -> Result<(), String> {
        let (db_path, mut rest) = extract_db(args);
        let repos_csv     = extract_flag(&mut rest, "--repos");
        let packaging     = extract_flag(&mut rest, "--packaging");
        let transitive    = extract_bool_flag(&mut rest, "--transitive");
        let coord = rest.first().ok_or("missing <group:artifact[:version]>")?;
        let parts: Vec<&str> = coord.split(':').collect();
        if parts.len() < 2 { return Err("coord must be group:artifact[:version]".into()); }
        let (group, artifact) = (parts[0], parts[1]);
        let version = parts.get(2).copied().unwrap_or("LATEST");
        let repos_owned: Option<Vec<String>> = repos_csv.map(|s| s.split(',').map(|p| p.trim().to_string()).collect());
        let repos_refs: Option<Vec<&str>> = repos_owned.as_ref().map(|v| v.iter().map(String::as_str).collect());

        let db = open_db(&db_path)?;
        let idx = Indexer::new(&db);
        let mut progress = |msg: &str| eprintln!("[dexmapper] {msg}");
        let summary = idx.index_artifact(
            group, artifact, version, packaging.as_deref(),
            repos_refs.as_deref(), transitive, &mut progress,
        ).map_err(|e| format!("index: {e}"))?;
        println!("{} → {} ({} classes, {} methods)", summary.artifact, summary.status, summary.classes, summary.methods);
        Ok(())
    }

    pub fn cmd_index_dex(args: &[String]) -> Result<(), String> {
        let (db_path, rest) = extract_db(args);
        let path = rest.first().ok_or("missing <path.dex>")?;
        let db = open_db(&db_path)?;
        let idx = Indexer::new(&db);
        let mut progress = |msg: &str| eprintln!("[dexmapper] {msg}");
        let summary = idx.index_dex(std::path::Path::new(path), &mut progress)
            .map_err(|e| format!("index-dex: {e}"))?;
        println!("{} → {} ({} classes, {} methods)", summary.artifact, summary.status, summary.classes, summary.methods);
        Ok(())
    }

    pub fn cmd_index_apk(args: &[String]) -> Result<(), String> {
        let (db_path, rest) = extract_db(args);
        let path = rest.first().ok_or("missing <path.apk>")?;
        let db = open_db(&db_path)?;
        let idx = Indexer::new(&db);
        let mut progress = |msg: &str| eprintln!("[dexmapper] {msg}");
        let summary = idx.index_apk(std::path::Path::new(path), &mut progress)
            .map_err(|e| format!("index-apk: {e}"))?;
        println!("{} → {} ({} classes, {} methods)", summary.artifact, summary.status, summary.classes, summary.methods);
        Ok(())
    }

    pub fn cmd_index_local(args: &[String]) -> Result<(), String> {
        let (db_path, rest) = extract_db(args);
        let path = rest.first().ok_or("missing <path>")?;
        let db = open_db(&db_path)?;
        let idx = Indexer::new(&db);
        let mut progress = |msg: &str| eprintln!("[dexmapper] {msg}");
        let summary = idx.index_local(std::path::Path::new(path), &mut progress)
            .map_err(|e| format!("index-local: {e}"))?;
        println!("{} → {} ({} classes, {} methods)", summary.artifact, summary.status, summary.classes, summary.methods);
        Ok(())
    }

    pub fn cmd_index_batch(args: &[String]) -> Result<(), String> {
        let (db_path, mut rest) = extract_db(args);
        let transitive = extract_bool_flag(&mut rest, "--transitive");
        let batch_path = rest.first().ok_or("missing <batch.json>")?;
        let text = std::fs::read_to_string(batch_path).map_err(|e| format!("read batch: {e}"))?;
        #[derive(serde::Deserialize)]
        struct Entry { group: String, artifact: String, #[serde(default)] version: Option<String> }
        let entries: Vec<Entry> = serde_json::from_str(&text).map_err(|e| format!("batch parse: {e}"))?;

        let db = open_db(&db_path)?;
        let idx = Indexer::new(&db);
        let mut progress = |msg: &str| eprintln!("[dexmapper] {msg}");
        for e in entries {
            let v = e.version.as_deref().unwrap_or("LATEST");
            match idx.index_artifact(&e.group, &e.artifact, v, None, None, transitive, &mut progress) {
                Ok(s)  => println!("{} → {}", s.artifact, s.status),
                Err(e) => eprintln!("skip: {e}"),
            }
        }
        Ok(())
    }

    pub fn cmd_analyze(args: &[String]) -> Result<(), String> {
        let (db_path, mut rest) = extract_db(args);
        let format         = extract_flag(&mut rest, "--format").ok_or("--format smali|java required")?;
        let min_conf_str   = extract_flag(&mut rest, "--min-confidence");
        let output_dir     = extract_flag(&mut rest, "--output");
        let mapping_output = extract_flag(&mut rest, "--mapping-output");
        let mapping_format = extract_flag(&mut rest, "--mapping-format").unwrap_or_else(|| "json".into());
        let src_dir = rest.first().ok_or("missing <source-dir>")?.clone();
        let min_conf: f32 = min_conf_str.as_deref()
            .map(|s| s.parse().unwrap_or(0.40))
            .unwrap_or(0.40);

        let db = open_db(&db_path)?;
        let matcher = Matcher::new(&db);
        let mut builder = MappingBuilder::new();
        let mut class_count = 0usize;
        let mut match_count = 0usize;
        match format.as_str() {
            "smali" => {
                let classes = smali_parser::parse_smali_dir(&src_dir);
                class_count = classes.len();
                for cls in &classes {
                    if let Some(cm) = matcher.match_smali_class(cls).map_err(|e| format!("match: {e}"))? {
                        match_count += 1;
                        builder.add_class_match(&cm, min_conf);
                    }
                }
                let m = builder.build();
                if let Some(out) = mapping_output { m.save(out, &mapping_format)?; }
                if let Some(dir) = output_dir {
                    let p = SmaliPatcher::new(&m);
                    let stats = p.patch_directory(std::path::Path::new(&src_dir),
                                                  std::path::Path::new(&dir), &classes)?;
                    eprintln!("patched: {}, copied: {}", stats.patched, stats.skipped);
                }
            }
            "java" => {
                let classes = java_parser::parse_java_dir(&src_dir);
                class_count = classes.len();
                for cls in &classes {
                    if let Some(cm) = matcher.match_java_class(cls).map_err(|e| format!("match: {e}"))? {
                        match_count += 1;
                        builder.add_class_match(&cm, min_conf);
                    }
                }
                let m = builder.build();
                if let Some(out) = mapping_output { m.save(out, &mapping_format)?; }
                if let Some(dir) = output_dir {
                    let p = JavaPatcher::new(&m);
                    let stats = p.patch_directory(std::path::Path::new(&src_dir),
                                                  std::path::Path::new(&dir), &classes)?;
                    eprintln!("patched: {}, copied: {}", stats.patched, stats.skipped);
                }
            }
            "dex" => {
                // `src_dir` is either an APK or a single .dex file.
                use platypus_dexmapper::analysis::dex_target;
                let path = std::path::Path::new(&src_dir);
                let classes = if path.extension().and_then(|s| s.to_str()) == Some("dex") {
                    let bytes = std::fs::read(path).map_err(|e| format!("read dex: {e}"))?;
                    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("classes.dex").to_string();
                    let dex = platypus_dex::parser::DexFileWithRaw::from_bytes(bytes, name.clone())
                        .map_err(|e| format!("parse dex: {e}"))?;
                    dex_target::smali_classes_from_dex(&dex, &name)
                } else {
                    dex_target::smali_classes_from_apk(path)
                };
                class_count = classes.len();

                // Discover renamed lambda parents — aggressive R8
                // configs rename `kotlin/jvm/internal/Lambda` itself.
                // We detect the renamed parent class structurally
                // (abstract + `<init>(I…)V` + `()I` arity getter +
                // `toString`) and feed the alias set into the matcher
                // so the lambda tier finds these subclasses.
                let aliases = platypus_dexmapper::lambda::LambdaAliases::discover(&classes);
                let total_aliases = aliases.kotlin_lambda.len()
                                  + aliases.suspend_lambda.len()
                                  + aliases.function_ref.len();
                eprintln!("[dexmapper] lambda parent aliases: kotlin={}, suspend={}, fnref={}",
                          aliases.kotlin_lambda.len(),
                          aliases.suspend_lambda.len(),
                          aliases.function_ref.len());
                let _ = total_aliases;
                let matcher = matcher.with_lambda_aliases(aliases);

                for cls in &classes {
                    if let Some(cm) = matcher.match_smali_class(cls).map_err(|e| format!("match: {e}"))? {
                        match_count += 1;
                        builder.add_class_match(&cm, min_conf);
                    }
                }
                let m = builder.build();
                if let Some(out) = mapping_output { m.save(out, &mapping_format)?; }
                if output_dir.is_some() {
                    return Err("--output is not supported for `--format dex` (in-place patching requires real on-disk smali / java files; use baksmali first, then `analyze --format smali`)".into());
                }
            }
            other => return Err(format!("unknown --format `{other}` (smali|java|dex)")),
        }
        println!("classes: {class_count}, matched: {match_count}");
        Ok(())
    }

    pub fn cmd_patch(args: &[String]) -> Result<(), String> {
        let mut rest: Vec<String> = args.to_vec();
        let format  = extract_flag(&mut rest, "--format").unwrap_or_else(|| "smali".into());
        let mapping_path = extract_flag(&mut rest, "--mapping").ok_or("--mapping path required")?;
        let output = extract_flag(&mut rest, "--output").ok_or("--output dir required")?;
        let src = rest.first().ok_or("missing <source-dir>")?.clone();

        let m_text = std::fs::read_to_string(&mapping_path).map_err(|e| format!("read mapping: {e}"))?;
        let mapping = MappingFile::parse_auto(&m_text)?;

        match format.as_str() {
            "smali" => {
                let classes = smali_parser::parse_smali_dir(&src);
                let p = SmaliPatcher::new(&mapping);
                let stats = p.patch_directory(std::path::Path::new(&src),
                                              std::path::Path::new(&output), &classes)?;
                eprintln!("patched: {}, copied: {}", stats.patched, stats.skipped);
            }
            "java" => {
                let classes = java_parser::parse_java_dir(&src);
                let p = JavaPatcher::new(&mapping);
                let stats = p.patch_directory(std::path::Path::new(&src),
                                              std::path::Path::new(&output), &classes)?;
                eprintln!("patched: {}, copied: {}", stats.patched, stats.skipped);
            }
            other => return Err(format!("unknown --format `{other}` (smali|java)")),
        }
        Ok(())
    }

    pub fn cmd_stats(args: &[String]) -> Result<(), String> {
        let (db_path, _) = extract_db(args);
        let db = open_db(&db_path)?;
        let s = db.stats()?;
        println!("db:          {}", db_path.display());
        println!("artifacts:   {}", s.artifacts);
        println!("classes:     {}", s.classes);
        println!("methods:     {}", s.methods);
        println!("fields:      {}", s.fields);
        println!("call edges:  {}", s.call_edges);
        println!("lambdas:     {}", s.lambdas);
        // Lambda breakdown by kind.
        let kinds = db.lambda_stats()?;
        for (kind, count) in kinds {
            println!("    {kind:25}  {count}");
        }
        Ok(())
    }

    pub fn cmd_artifacts(args: &[String]) -> Result<(), String> {
        let (db_path, _) = extract_db(args);
        let db = open_db(&db_path)?;
        for a in db.list_artifacts()? {
            println!("{:30} {:20} {:15} ({} from {})", a.group_id, a.artifact_id, a.version, a.packaging, a.source);
        }
        Ok(())
    }

    pub fn cmd_lookup(args: &[String]) -> Result<(), String> {
        let (db_path, rest) = extract_db(args);
        let fqn = rest.first().ok_or("missing <class-fqn>")?;
        let db = open_db(&db_path)?;
        match db.get_class_by_fqn(fqn)? {
            Some(c) => {
                println!("class: {}  ({}{})", c.fqn,
                         if c.is_interface { "interface " } else { "" },
                         if c.is_enum { "enum" } else { "class" });
                println!("simple_name: {}", c.simple_name);
                println!("package: {}", c.package);
                println!("superclass: {}", c.superclass.unwrap_or_default());
                println!("methods:");
                for m in db.get_methods_for_class(c.id)? {
                    println!("  {} {}", m.name, m.descriptor);
                }
                println!("fields:");
                for f in db.get_fields_for_class(c.id)? {
                    println!("  {} {}", f.name, f.descriptor);
                }
            }
            None => return Err(format!("no class indexed for `{fqn}`")),
        }
        Ok(())
    }

    pub fn cmd_match_method(args: &[String]) -> Result<(), String> {
        let (db_path, rest) = extract_db(args);
        if rest.len() < 3 { return Err("usage: match-method <obf-class> <obf-method> <desc>".into()); }
        let class = &rest[0];
        let name  = &rest[1];
        let desc  = &rest[2];
        let db = open_db(&db_path)?;
        let matcher = Matcher::new(&db);
        let method = platypus_dexmapper::analysis::smali_parser::SmaliMethod {
            name: name.clone(),
            descriptor: desc.clone(),
            flags: String::new(),
            call_edges: Vec::new(),
            field_gets: Vec::new(),
            field_puts: Vec::new(),
            local_count: 0,
            line_start: 0,
        };
        let hits = matcher.match_smali_method(class, &method).map_err(|e| format!("match: {e}"))?;
        if hits.is_empty() { println!("no matches"); } else {
            for h in hits {
                println!("{}.{}  ({:.2}, {})", h.real_class_fqn, h.real_name, h.confidence, h.match_type);
            }
        }
        Ok(())
    }
}

#[cfg(feature = "producer")] fn cmd_index(a: &[String])        -> Result<(), String> { producer_impl::cmd_index(a) }
#[cfg(feature = "producer")] fn cmd_index_local(a: &[String])  -> Result<(), String> { producer_impl::cmd_index_local(a) }
#[cfg(feature = "producer")] fn cmd_index_batch(a: &[String])  -> Result<(), String> { producer_impl::cmd_index_batch(a) }
#[cfg(feature = "producer")] fn cmd_index_dex(a: &[String])    -> Result<(), String> { producer_impl::cmd_index_dex(a) }
#[cfg(feature = "producer")] fn cmd_index_apk(a: &[String])    -> Result<(), String> { producer_impl::cmd_index_apk(a) }
#[cfg(feature = "producer")] fn cmd_analyze(a: &[String])      -> Result<(), String> { producer_impl::cmd_analyze(a) }
#[cfg(feature = "producer")] fn cmd_patch(a: &[String])        -> Result<(), String> { producer_impl::cmd_patch(a) }
#[cfg(feature = "producer")] fn cmd_stats(a: &[String])        -> Result<(), String> { producer_impl::cmd_stats(a) }
#[cfg(feature = "producer")] fn cmd_artifacts(a: &[String])    -> Result<(), String> { producer_impl::cmd_artifacts(a) }
#[cfg(feature = "producer")] fn cmd_lookup(a: &[String])       -> Result<(), String> { producer_impl::cmd_lookup(a) }
#[cfg(feature = "producer")] fn cmd_match_method(a: &[String]) -> Result<(), String> { producer_impl::cmd_match_method(a) }
