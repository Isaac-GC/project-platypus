//! Quick diagnostic — given an APK path, print every activity's
//! rehydration result (layout id, layout path, root tag if any,
//! diagnostics).
//!
//! Run with:
//!   cargo run --release -p platypus-rehydrate --example diagnose -- path/to.apk
//!
//! Useful when an APK fails to load in the standalone viewer and you
//! want to see exactly where the pipeline gives up.

use std::env;
use std::process::ExitCode;

use platypus_apk::axml;
use platypus_apk::zip::ApkZip;
use platypus_dex::clazz::Clazz;
use platypus_dex::parser::DexFileWithRaw;
use platypus_rehydrate::rehydrate_all;
use platypus_resources::{Manifest, Resources};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let apk_path = match args.get(1) {
        Some(p) => p.clone(),
        None => {
            eprintln!("usage: diagnose <apk-path>");
            return ExitCode::from(2);
        }
    };

    let apk = match ApkZip::open(&apk_path) {
        Ok(a) => a,
        Err(e) => { eprintln!("open APK: {e}"); return ExitCode::from(1); }
    };
    println!("== APK: {apk_path}");

    // Resources.
    let resources = match (|| -> Result<Resources, String> {
        let bytes = apk.read_entry("resources.arsc").map_err(|e| e.to_string())?;
        let table = platypus_apk::arsc::parse(&bytes).map_err(|e| e.to_string())?;
        Ok(Resources::new(table))
    })() {
        Ok(r) => {
            println!("   resources.arsc: {} entries", r.len());
            r
        }
        Err(e) => { eprintln!("read resources.arsc: {e}"); return ExitCode::from(1); }
    };

    // Manifest.
    let manifest = match (|| -> Result<Manifest, String> {
        let bytes = apk.read_entry("AndroidManifest.xml").map_err(|e| e.to_string())?;
        let root = axml::parse_with_resources(&bytes, resources.table())
            .map_err(|e| e.to_string())?;
        Ok(Manifest::from_xml(root).resolved(&resources))
    })() {
        Ok(m) => m,
        Err(e) => { eprintln!("read manifest: {e}"); return ExitCode::from(1); }
    };
    let pkg = manifest.package().unwrap_or("").to_string();
    let activities = manifest.activities();
    println!("   package: {pkg}");
    println!("   {} activities in manifest", activities.len());

    // Dex files.
    let dex_pairs = apk.dex_files();
    println!("   {} dex files", dex_pairs.len());
    let dex_files: Vec<DexFileWithRaw> = dex_pairs.into_iter()
        .filter_map(|(name, bytes)| {
            match DexFileWithRaw::from_bytes(bytes, name.clone()) {
                Ok(d) => Some(d),
                Err(e) => {
                    eprintln!("   skipped {name}: {e}");
                    None
                }
            }
        })
        .collect();
    println!("   {} dex files parsed OK", dex_files.len());

    // Layout names available — sanity check resources have any layouts at all.
    let layouts: Vec<&platypus_resources::ResourceEntry> = resources.by_type("layout");
    println!("   {} layout resources defined", layouts.len());
    if layouts.is_empty() {
        println!("   ⚠ NO LAYOUTS in resources.arsc — the APK likely uses Compose only.");
    }
    if !layouts.is_empty() {
        for e in layouts.iter().take(5) {
            println!("       layout {} → {}", e.name, e.value);
        }
        if layouts.len() > 5 { println!("       … and {} more", layouts.len() - 5); }
    }

    // Run rehydrate on every activity.
    println!();
    println!("== Activities");
    let views = rehydrate_all(&apk, &manifest, &resources, &dex_files);

    let mut with_layout = 0;
    let mut compose_only = 0;
    let mut empty = 0;

    for v in &views {
        let status = match (&v.root, &v.layout_path) {
            (Some(r), Some(p)) => {
                with_layout += 1;
                format!("✓ root=<{}> layout={}", r.tag, p)
            }
            (Some(r), None) => {
                compose_only += 1;
                format!("◆ compose root=<{}>", r.tag)
            }
            (None, _) => {
                empty += 1;
                "✗ no layout".to_string()
            }
        };
        println!("  {status}  {}", v.activity_name);
        for d in &v.diagnostics {
            let icon = match d.severity {
                platypus_rehydrate::DiagnosticSeverity::Info    => "  ℹ",
                platypus_rehydrate::DiagnosticSeverity::Warning => "  ⚠",
                platypus_rehydrate::DiagnosticSeverity::Error   => "  ✗",
            };
            println!("{icon} {}", d.message);
        }
    }

    println!();
    println!("== Summary: {} with layout · {} compose-only · {} empty (of {} total)",
        with_layout, compose_only, empty, views.len());

    // Helper: `<apk> --ir <activity-fq>` prints the full UnifiedView IR
    // for one activity as pretty JSON — exactly what the renderer sees.
    // Useful when a screen renders blank: diff this against a known-good
    // activity to find the suspect field.
    if args.get(2).map(String::as_str) == Some("--ir") {
        let target = args.get(3).cloned().unwrap_or_default();
        let view = platypus_rehydrate::rehydrate_activity(&apk, &target, &resources, &dex_files);
        match serde_json::to_string_pretty(&view) {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("serialise: {e}"),
        }
        return ExitCode::SUCCESS;
    }

    // Helper: `<apk> --class Lc0/g0;` dumps an arbitrary class's methods.
    // Useful when the verbose dump reveals a lambda we want to inspect.
    if args.get(2).map(String::as_str) == Some("--class") {
        let target_class = args.get(3).cloned().unwrap_or_default();
        let want_norm = target_class.trim_start_matches('L').trim_end_matches(';');
        let mut found = false;
        for dex in &dex_files {
            for class_def in &dex.parsed.class_defs {
                let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
                if def_norm != want_norm { continue; }
                found = true;
                let clazz = match Clazz::new(class_def, dex) {
                    Ok(c) => c, Err(_) => continue,
                };
                println!("== Class {target_class} — {} methods", clazz.methods.len());
                for m in &clazz.methods {
                    println!("  ── {} ({} insns)", m.method_name, m.instructions.len());
                    for instr in &m.instructions {
                        println!("       {}", instr.instruction_str);
                    }
                }
            }
        }
        if !found { println!("⚠ class not found"); }
        return ExitCode::SUCCESS;
    }

    // Optional verbose mode: `diagnose <apk> <activity-fq-name>` dumps every
    // invoke from that activity's methods, useful for figuring out *why*
    // the discovery missed.
    if let Some(target) = args.get(2) {
        println!();
        println!("== Verbose dump for {target}");
        let class_norm = target.replace('.', "/");
        let mut found = false;
        for dex in &dex_files {
            for class_def in &dex.parsed.class_defs {
                let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
                if def_norm != class_norm { continue; }
                found = true;
                let clazz = match Clazz::new(class_def, dex) {
                    Ok(c) => c, Err(e) => { eprintln!("clazz load: {e}"); continue; }
                };
                println!("  {} methods", clazz.methods.len());
                for m in &clazz.methods {
                    println!("  ── {}::{}  ({} insns)", target, m.method_name, m.instructions.len());
                    for instr in &m.instructions {
                        // Show every instruction at full verbosity if a 3rd
                        // arg "all" is passed; otherwise filter to invokes
                        // and the keyword set.
                        let show_all = args.get(3).map(String::as_str) == Some("all");
                        let s = &instr.instruction_str;
                        if show_all {
                            println!("       {s}");
                        } else if s.contains("invoke") && (
                            s.contains("setContentView") || s.contains("setContent")
                            || s.contains("inflate") || s.contains("Compose")
                            || s.contains("Binding;") || s.contains("getRoot")
                            || s.contains("Function") || s.contains("Lambda")
                        ) {
                            println!("       {s}");
                        }
                    }
                }
            }
        }
        if !found { println!("  ⚠ class not found in any dex"); }
    }

    ExitCode::SUCCESS
}
