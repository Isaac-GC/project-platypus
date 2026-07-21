use std::collections::HashMap;

use rayon::prelude::*;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindowBuilder, WebviewUrl};

use project_platypus_native::apk::{axml, zip::ApkZip};
use project_platypus_native::codegen::java::analysis::AnalysisConfig;
use project_platypus_native::codegen::java::decompiler::JavaDecompiler;
use project_platypus_native::codegen::java::dominator_tree::DominatorTree;
use project_platypus_native::codegen::java::java_generator::{JavaGenerator, MethodFilter, class_package};
use project_platypus_native::codegen::java::ssa_builder::SsaBuilder;
use project_platypus_native::codegen::smali::smali_generator::SmaliClassCodeGen;
use project_platypus_native::dex::access_flags::{parse_class_access_flags, parse_method_access_flags};
use project_platypus_native::dex::clazz::Clazz;
use project_platypus_native::dex::parser::DexFileWithRaw;
use project_platypus_native::vm::logger::format_value;
use project_platypus_native::vm::vm::Vm;
use project_platypus_native::analysis;
use project_platypus_native::taint;
use project_platypus_native::dex_loader_analysis;

use crate::state::AppState;

// ── Serialisable tree node sent to the frontend ───────────────────────────────

#[derive(Serialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TreeNodeSer {
    pub id: String,
    pub name: String,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub full_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub access_flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub return_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub register_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dex_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<TreeNodeSer>,
}

// ── Load result ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoadResult {
    pub path: String,
    pub tree: Vec<TreeNodeSer>,
    pub dex_files: Vec<String>,
    pub package_count: usize,
    pub class_count: usize,
    pub method_count: usize,
    pub entry_names: Vec<String>,
}

// ── XRef result ───────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct XRefResult {
    pub caller_class: String,
    pub caller_method: String,
    pub caller_signature: String,
    pub offset: u32,
    pub instruction: String,
}

// ── Run result ────────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunResult {
    pub return_value: String,
    pub return_type: String,
    pub logs: Vec<String>,
    pub error: Option<String>,
    pub execution_time_ms: u64,
    /// When the result was a `byte[]` that parsed as a ZIP containing
    /// `classes*.dex`, the path to the cached file. The frontend can offer a
    /// one-click "Load as APK" using this path.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apk_cache_path: Option<String>,
}

// ── Find-exec result ──────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResultItem {
    pub call_site: String,
    pub caller_class: String,
    pub caller_method: String,
    pub offset: u32,
    pub resolved_value: String,
    pub resolved_type: String,
    pub error: Option<String>,
    /// When the result was a `byte[]` that parsed as a ZIP containing
    /// `classes*.dex`, the path to the cached file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub apk_cache_path: Option<String>,
}

// ── Search result ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SearchResultItem {
    /// "class" | "method" | "field" | "string" | "reference" | "resource".
    pub kind: String,
    /// For code hits: the dex class (slash form, no L/;) where the match
    /// lives. For resource hits: the resource *type* (e.g. "string").
    pub class_name: String,
    /// For code hits: the member (method/field) the match lives in — for
    /// call-sites/strings/refs this is the *caller* method, so navigation
    /// lands in the right place. For resource hits: the resource name.
    pub member_name: Option<String>,
    /// A human-readable preview. For code: the matched instruction / member
    /// signature. For resources: the resolved value.
    pub snippet: String,
    /// Instruction codepoint for instruction-level hits (used as a tie-break
    /// + display). The frontend resolves the *rendered* line from `snippet`.
    pub line: Option<u32>,
    /// Resource id for `kind == "resource"` — lets the UI open the matching
    /// resource entry view. `None` for code hits.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub res_id: Option<u32>,
}

// ── Tree builder ──────────────────────────────────────────────────────────────

fn access_flag_strings(flags: &[project_platypus_native::dex::access_flags::MethodAccessFlag]) -> Vec<String> {
    use project_platypus_native::dex::access_flags::MethodAccessFlag;
    let mut out = Vec::new();
    if flags.contains(&MethodAccessFlag::Public)    { out.push("public".into()); }
    if flags.contains(&MethodAccessFlag::Private)   { out.push("private".into()); }
    if flags.contains(&MethodAccessFlag::Protected) { out.push("protected".into()); }
    if flags.contains(&MethodAccessFlag::Static)    { out.push("static".into()); }
    if flags.contains(&MethodAccessFlag::Final)     { out.push("final".into()); }
    if flags.contains(&MethodAccessFlag::Abstract)  { out.push("abstract".into()); }
    if flags.contains(&MethodAccessFlag::Native)    { out.push("native".into()); }
    if flags.contains(&MethodAccessFlag::Synthetic) { out.push("synthetic".into()); }
    if flags.contains(&MethodAccessFlag::Constructor) { out.push("constructor".into()); }
    out
}

fn class_access_flag_strings(flags: &[project_platypus_native::dex::access_flags::ClassAccessFlag]) -> Vec<String> {
    use project_platypus_native::dex::access_flags::ClassAccessFlag;
    let mut out = Vec::new();
    if flags.contains(&ClassAccessFlag::Public)    { out.push("public".into()); }
    if flags.contains(&ClassAccessFlag::Final)     { out.push("final".into()); }
    if flags.contains(&ClassAccessFlag::Interface) { out.push("interface".into()); }
    if flags.contains(&ClassAccessFlag::Abstract)  { out.push("abstract".into()); }
    if flags.contains(&ClassAccessFlag::Synthetic) { out.push("synthetic".into()); }
    if flags.contains(&ClassAccessFlag::Enum)      { out.push("enum".into()); }
    out
}

/// Parse the return type and parameter types from a proto descriptor like `(Ljava/lang/String;I)V`.
fn parse_proto(proto_desc: &str) -> (String, Vec<String>) {
    if let Some(close) = proto_desc.rfind(')') {
        let return_type = proto_desc[close + 1..].to_string();
        let params_str  = &proto_desc[1..close]; // strip '(' and ')'
        let params = split_type_list(params_str);
        (return_type, params)
    } else {
        (proto_desc.to_string(), Vec::new())
    }
}

/// Split a concatenated list of DEX type descriptors (no separators) into individual types.
fn split_type_list(s: &str) -> Vec<String> {
    let mut types = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'L' => {
                // Reference type: Ljava/lang/String;
                if let Some(end) = s[i..].find(';') {
                    types.push(s[i..=i + end].to_string());
                    i += end + 1;
                } else {
                    types.push(s[i..].to_string());
                    break;
                }
            }
            b'[' => {
                // Array type — collect all leading '[' then the element type
                let start = i;
                while i < bytes.len() && bytes[i] == b'[' { i += 1; }
                if i < bytes.len() {
                    if bytes[i] == b'L' {
                        if let Some(end) = s[i..].find(';') {
                            types.push(s[start..=i + end].to_string());
                            i += end + 1;
                            continue;
                        }
                    } else {
                        types.push(s[start..=i].to_string());
                        i += 1;
                    }
                }
            }
            _ => {
                // Primitive
                types.push((bytes[i] as char).to_string());
                i += 1;
            }
        }
    }
    types
}

fn build_tree_for_dex(dex: &DexFileWithRaw) -> (Vec<TreeNodeSer>, usize, usize, usize) {
    // Build (pkg, class_node, method_count) tuples in parallel across all class_defs.
    // We bypass Clazz::new() entirely — no instruction decoding, no CFG building.
    // Only the 16-byte code_item header is read per method (registers_size + insns_size).
    let class_entries: Vec<(String, TreeNodeSer, usize)> = dex.parsed.class_defs
        .par_iter()
        .filter_map(|class_def| {
            let full = &class_def.type_name;
            let stripped = full.trim_start_matches('L').trim_end_matches(';');
            let (pkg, class_name) = if let Some(pos) = stripped.rfind('/') {
                (stripped[..pos].to_string(), &stripped[pos + 1..])
            } else {
                (String::new(), stripped)
            };

            let class_flags = class_access_flag_strings(
                &parse_class_access_flags(class_def.access_flags),
            );

            let mut children: Vec<TreeNodeSer> = Vec::new();
            let mut method_count = 0usize;

            if let Some(ref class_data) = class_def.class_data {
                // direct_methods and virtual_methods have independent idx accumulation
                for method_group in [
                    class_data.direct_methods.as_slice(),
                    class_data.virtual_methods.as_slice(),
                ] {
                    let mut curr_idx = 0usize;
                    for e in method_group {
                        curr_idx = if curr_idx == 0 {
                            e.method_idx_diff as usize
                        } else {
                            curr_idx + e.method_idx_diff as usize
                        };
                        let mid = match dex.parsed.method_ids.get(curr_idx) {
                            Some(m) => m,
                            None => continue,
                        };
                        let (registers_size, insns_size) = if e.code_off != 0 {
                            dex.read_code_item_header(e.code_off).unwrap_or((0, 0))
                        } else {
                            (0, 0)
                        };
                        let flags = access_flag_strings(
                            &parse_method_access_flags(e.access_flags as u32),
                        );
                        let (return_type, params) = parse_proto(&mid.proto_desc);
                        children.push(TreeNodeSer {
                            id: format!("{}::{}", full, mid.method_name),
                            name: mid.method_name.clone(),
                            kind: "method",
                            full_name: Some(format!("{}->{}{}", full, mid.method_name, mid.proto_desc)),
                            access_flags: flags,
                            return_type: Some(return_type),
                            params,
                            signature: Some(mid.proto_desc.clone()),
                            register_count: Some(registers_size as u32),
                            instruction_count: Some(insns_size),
                            dex_name: Some(dex.parsed.filename.clone()),
                            children: Vec::new(),
                        });
                        method_count += 1;
                    }
                }

                // static_fields (independent idx sequence)
                let mut curr_idx = 0usize;
                for e in &class_data.static_fields {
                    curr_idx = if curr_idx == 0 {
                        e.field_idx_diff as usize
                    } else {
                        curr_idx + e.field_idx_diff as usize
                    };
                    if let Some(fid) = dex.parsed.field_ids.get(curr_idx) {
                        children.push(TreeNodeSer {
                            id: format!("{}:field:s:{}", full, fid.field_name),
                            name: fid.field_name.clone(),
                            kind: "field",
                            full_name: Some(format!("{}->{}", full, fid.field_name)),
                            access_flags: Vec::new(),
                            return_type: Some(fid.type_name.clone()),
                            params: Vec::new(),
                            signature: Some(format!("{}:{}", fid.field_name, fid.type_name)),
                            register_count: None,
                            instruction_count: None,
                            dex_name: Some(dex.parsed.filename.clone()),
                            children: Vec::new(),
                        });
                    }
                }

                // instance_fields (independent idx sequence)
                curr_idx = 0;
                for e in &class_data.instance_fields {
                    curr_idx = if curr_idx == 0 {
                        e.field_idx_diff as usize
                    } else {
                        curr_idx + e.field_idx_diff as usize
                    };
                    if let Some(fid) = dex.parsed.field_ids.get(curr_idx) {
                        children.push(TreeNodeSer {
                            id: format!("{}:field:i:{}", full, fid.field_name),
                            name: fid.field_name.clone(),
                            kind: "field",
                            full_name: Some(format!("{}->{}", full, fid.field_name)),
                            access_flags: Vec::new(),
                            return_type: Some(fid.type_name.clone()),
                            params: Vec::new(),
                            signature: Some(format!("{}:{}", fid.field_name, fid.type_name)),
                            register_count: None,
                            instruction_count: None,
                            dex_name: Some(dex.parsed.filename.clone()),
                            children: Vec::new(),
                        });
                    }
                }
            }

            let class_node = TreeNodeSer {
                id: full.clone(),
                name: class_name.to_string(),
                kind: "class",
                full_name: Some(stripped.to_string()),
                access_flags: class_flags,
                return_type: None,
                params: Vec::new(),
                signature: None,
                register_count: None,
                instruction_count: None,
                dex_name: Some(dex.parsed.filename.clone()),
                children,
            };

            Some((pkg, class_node, method_count))
        })
        .collect();

    // Aggregate into packages map (sequential, but O(n) with no heavy work)
    let mut packages: HashMap<String, Vec<TreeNodeSer>> = HashMap::new();
    let mut class_count = 0usize;
    let mut method_count = 0usize;
    for (pkg, class_node, methods) in class_entries {
        packages.entry(pkg).or_default().push(class_node);
        class_count += 1;
        method_count += methods;
    }

    let package_count = packages.len();
    let pkg_nodes = packages_to_nested_tree(packages);
    (pkg_nodes, package_count, class_count, method_count)
}

/// Build a nested package tree from a flat `{ "com/example/foo" -> [classes] }` map.
fn packages_to_nested_tree(packages: HashMap<String, Vec<TreeNodeSer>>) -> Vec<TreeNodeSer> {
    let mut sorted_paths: Vec<String> = packages.keys().cloned().collect();
    sorted_paths.sort();
    build_pkg_level(&sorted_paths, &packages, "")
}

fn build_pkg_level(
    all_paths: &[String],
    packages: &HashMap<String, Vec<TreeNodeSer>>,
    prefix: &str,
) -> Vec<TreeNodeSer> {
    // Collect the immediate child segments directly under `prefix`.
    let mut children: Vec<String> = Vec::new();
    for path in all_paths {
        let tail = if prefix.is_empty() {
            path.as_str()
        } else {
            match path.strip_prefix(&format!("{}/", prefix)) {
                Some(t) => t,
                None    => continue, // not a descendent of prefix
            }
        };
        if tail.is_empty() { continue; } // exact match for the prefix itself
        let seg = tail.split('/').next().unwrap_or("");
        if seg.is_empty() { continue; }
        let child_full = if prefix.is_empty() {
            seg.to_string()
        } else {
            format!("{}/{}", prefix, seg)
        };
        if !children.contains(&child_full) {
            children.push(child_full);
        }
    }

    children.into_par_iter().map(|child_path| {
        let seg_name = child_path.split('/').next_back().unwrap_or(&child_path).to_string();

        // Sub-package nodes (recursive).
        let mut sub_nodes = build_pkg_level(all_paths, packages, &child_path);

        // Direct classes in this package, sorted by name.
        let mut class_nodes = packages.get(&child_path).cloned().unwrap_or_default();
        class_nodes.sort_by(|a, b| a.name.cmp(&b.name));

        // Compact single-child packages: if this node has no classes and exactly
        // one sub-package child, merge the names (like IntelliJ's "compact packages").
        while class_nodes.is_empty() && sub_nodes.len() == 1 && sub_nodes[0].kind == "package" {
            let only_child = sub_nodes.remove(0);
            let merged_name = format!("{}.{}", seg_name, only_child.name);
            // Re-root with the child's children and the merged name.
            return TreeNodeSer {
                id: only_child.id,
                name: merged_name,
                kind: "package",
                full_name: only_child.full_name,
                access_flags: Vec::new(),
                return_type: None,
                params: Vec::new(),
                signature: None,
                register_count: None,
                instruction_count: None,
                dex_name: None,
                children: only_child.children,
            };
        }

        sub_nodes.extend(class_nodes);

        TreeNodeSer {
            id: format!("pkg:{}", child_path),
            name: seg_name,
            kind: "package",
            full_name: Some(child_path),
            access_flags: Vec::new(),
            return_type: None,
            params: Vec::new(),
            signature: None,
            register_count: None,
            instruction_count: None,
            dex_name: None,
            children: sub_nodes,
        }
    }).collect()
}

// ── load_file ─────────────────────────────────────────────────────────────────

/// Build the `LoadResult` payload (file tree + counts) from already-parsed dex files.
/// `id_prefix` is the namespace for tree-node ids — empty for slot A, `"b:"` for slot B.
/// `has_manifest` controls whether an `AndroidManifest.xml` leaf is appended.
fn assemble_load_result(
    path: String,
    dex_files: &[DexFileWithRaw],
    has_manifest: bool,
    entry_names: Vec<String>,
) -> LoadResult {
    assemble_load_result_with_prefix(path, dex_files, has_manifest, entry_names, "")
}

fn assemble_load_result_with_prefix(
    path: String,
    dex_files: &[DexFileWithRaw],
    has_manifest: bool,
    entry_names: Vec<String>,
    id_prefix: &str,
) -> LoadResult {
    let dex_file_names: Vec<String> = dex_files.iter()
        .map(|d| d.parsed.filename.clone())
        .collect();

    let mut total_packages = 0usize;
    let mut total_classes  = 0usize;
    let mut total_methods  = 0usize;
    let mut dex_nodes: Vec<TreeNodeSer> = Vec::new();

    for dex in dex_files {
        let (pkg_nodes, pkgs, classes, methods) = build_tree_for_dex(dex);
        total_packages += pkgs;
        total_classes  += classes;
        total_methods  += methods;
        dex_nodes.push(TreeNodeSer {
            id: format!("{}dex:{}", id_prefix, dex.parsed.filename),
            name: dex.parsed.filename.clone(),
            kind: "dexfile",
            full_name: None,
            access_flags: Vec::new(),
            return_type: None,
            params: Vec::new(),
            signature: None,
            register_count: None,
            instruction_count: None,
            dex_name: None,
            children: pkg_nodes,
        });
    }

    let source_root = TreeNodeSer {
        id: format!("{}root:source", id_prefix),
        name: "Source Code".into(),
        kind: "source_root",
        full_name: None,
        access_flags: Vec::new(),
        return_type: None,
        params: Vec::new(),
        signature: None,
        register_count: None,
        instruction_count: None,
        dex_name: None,
        children: dex_nodes,
    };

    let mut tree = vec![source_root];
    if has_manifest {
        tree.push(TreeNodeSer {
            id: format!("{}manifest", id_prefix),
            name: "AndroidManifest.xml".into(),
            kind: "manifest",
            full_name: None,
            access_flags: Vec::new(),
            return_type: None,
            params: Vec::new(),
            signature: None,
            register_count: None,
            instruction_count: None,
            dex_name: None,
            children: Vec::new(),
        });
    }

    LoadResult {
        path,
        tree,
        dex_files: dex_file_names,
        package_count: total_packages,
        class_count: total_classes,
        method_count: total_methods,
        entry_names,
    }
}

#[tauri::command]
pub async fn load_file(
    path: String,
    state: State<'_, AppState>,
) -> Result<LoadResult, String> {
    // Build a Slot via the project loader (handles single APK, split bundle, raw DEX).
    let slot = crate::project::load_slot_from_disk(
        "", "", &path, &[], None, false,
    )?;

    if slot.dex_files.is_empty() {
        return Err("No DEX files found".into());
    }

    // Build the LoadResult BEFORE moving the slot into the project.
    let load_result = assemble_load_result(
        path.clone(),
        &slot.dex_files,
        slot.manifest_xml.is_some(),
        slot.entry_names.iter().map(|(_, n)| n.clone()).collect(),
    );

    // Insert into the project (idempotent on sha256), set active, persist.
    let mut project = state.project.write().await;
    let id = project.upsert(slot);
    project.active_slot_id = Some(id);
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;

    Ok(load_result)
}

// ── get_class_smali ───────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_class_smali(
    class_name: String,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let project = state.project.read().await;
    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;
    // class_name is like "com/example/Foo" or "Lcom/example/Foo;"
    let target = if class_name.starts_with('L') {
        class_name.clone()
    } else {
        format!("L{};", class_name)
    };

    for dex in dex_files.iter() {
        if let Some(class_def) = dex.parsed.class_defs.iter()
            .find(|cd| cd.type_name == target || cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_name)
        {
            let clazz = Clazz::new(class_def, dex).map_err(|e| e.to_string())?;
            let gen = SmaliClassCodeGen::new(&clazz, &dex.parsed);
            return Ok(gen.format());
        }
    }
    Err(format!("Class not found: {}", class_name))
}

/// Resolve a slot by id, or fall back to the active slot when `slot_id` is
/// `None`. Lets read commands operate on a non-active slot (e.g. an embedded
/// APK browsed inline under the "Embedded APKs" tree group) without changing
/// the active project.
fn resolve_slot<'a>(
    project: &'a Project,
    slot_id: &Option<String>,
) -> Result<&'a project::Slot, String> {
    match slot_id.as_deref() {
        Some(id) => project.find(id).ok_or_else(|| format!("Slot '{}' not found", id)),
        None => project.active().ok_or_else(|| "No APK loaded".to_string()),
    }
}

// ── get_class_java ────────────────────────────────────────────────────────────

/// Decompile `class_name` to Java pseudo-source.
///
/// `keep_kotlin_intrinsics` controls whether the Kotlin runtime null-check /
/// boilerplate calls (e.g. `Intrinsics.checkNotNullParameter`) are kept in the
/// output. Default (false / null) preserves the historical behaviour of
/// hiding them; set true to surface them for review.
#[tauri::command]
pub async fn get_class_java(
    class_name: String,
    keep_kotlin_intrinsics: Option<bool>,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let project = state.project.read().await;
    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;
    let target = if class_name.starts_with('L') {
        class_name.clone()
    } else {
        format!("L{};", class_name)
    };

    let filter = if keep_kotlin_intrinsics.unwrap_or(false) {
        MethodFilter::empty()
    } else {
        MethodFilter::default()
    };

    for dex in dex_files.iter() {
        if let Some(class_def) = dex.parsed.class_defs.iter()
            .find(|cd| cd.type_name == target || cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_name)
        {
            let clazz = Clazz::new(class_def, dex).map_err(|e| e.to_string())?;
            let config = AnalysisConfig::default();
            let decompiler = JavaDecompiler::new(Some(config));
            let mut method_texts: Vec<String> = Vec::new();
            let mut all_imports: std::collections::HashSet<String> = std::collections::HashSet::new();

            for method in &clazz.methods {
                if method.instructions.is_empty() {
                    method_texts.push(String::new());
                    continue;
                }
                let ast = decompiler.decompile(method);
                let mut cfg_clone = method.cfg.clone();
                if let Some(ref mut cfg) = cfg_clone {
                    DominatorTree::compute(cfg);
                }
                let ssa = cfg_clone.as_ref()
                    .map(|cfg| SsaBuilder::new().build(cfg, &method.instructions, method.registers_size, method.ins_size))
                    .unwrap_or_else(SsaBuilder::empty_ssa);
                let mut gen = JavaGenerator::new_with_filter(method, &dex.parsed, &ssa, filter.clone());
                let text = gen.gen_class_method(&ast);
                for imp in gen.import_statements() {
                    all_imports.insert(imp);
                }
                method_texts.push(text);
            }

            let mut out = Vec::new();
            let pkg = class_package(&clazz.class_name);
            if !pkg.is_empty() {
                out.push(format!("package {};", pkg));
                out.push(String::new());
            }
            let mut sorted_imports: Vec<String> = all_imports.into_par_iter()
                .filter(|s| s.starts_with("import "))   // defensive: drop any malformed entries
                .collect();
            sorted_imports.sort();
            for imp in sorted_imports {
                out.push(imp);
            }
            if !method_texts.is_empty() {
                out.push(String::new());
            }
            for t in method_texts {
                if !t.is_empty() {
                    out.push(t);
                }
            }
            return Ok(out.join("\n"));
        }
    }
    Err(format!("Class not found: {}", class_name))
}

// ── get_manifest ──────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_manifest(state: State<'_, AppState>) -> Result<String, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    slot.manifest_xml.clone().ok_or_else(|| "No manifest loaded".into())
}

// ── get_xrefs ─────────────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_xrefs(
    class_name: String,
    method_name: String,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<XRefResult>, String> {
    let project = state.project.read().await;
    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;
    // Build the target pattern: "Lcom/example/Foo;->bar"
    let class_desc = if class_name.starts_with('L') {
        class_name.clone()
    } else {
        format!("L{};", class_name.replace('.', "/"))
    };
    // Strip prototype from method_name if present
    let method_bare = method_name.split('(').next().unwrap_or(&method_name);
    let target = format!("{}->{}", class_desc, method_bare);

    let mut results = Vec::new();
    for dex in dex_files.iter() {
        let sites = analysis::find_calls(dex, &target);
        for site in sites {
            results.push(XRefResult {
                caller_class: site.caller_class,
                caller_method: site.caller_method.clone(),
                caller_signature: site.invoke_str.clone(),
                offset: site.invoke_cp,
                instruction: site.invoke_str,
            });
        }
    }
    Ok(results)
}

// ── run_method ────────────────────────────────────────────────────────────────

/// Execute one method via the Dalvik VM and return the formatted result.
/// `instr_limit` — optional per-call instruction budget. `None`/null uses 5M.
#[tauri::command]
pub async fn run_method(
    class_name: String,
    method_name: String,
    args: Vec<String>,
    instr_limit: Option<u64>,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<RunResult, String> {
    use project_platypus_native::vm::value::Value;
    use project_platypus_native::analysis::resolve_arg_encoding;
    use std::time::Instant;

    // ── Step-by-step timing trace ──────────────────────────────────────
    // Each step prints to stderr so a user reporting a "hang" can see
    // exactly which phase is slow. The amounts add up to the value
    // we eventually report as `execution_time_ms`. Removing these would
    // make a future hang invisible again — the previous regression
    // ("loads forever" on -2645377731634605L) was a classic case where
    // the time was lost in arg resolution, not the VM.
    let t_total = Instant::now();
    let t_lock = Instant::now();
    let project = state.project.read().await;
    eprintln!("[run_method] project.read lock: {:?}", t_lock.elapsed());

    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;
    let resources = slot.resources.as_ref();

    let class_norm = class_name.trim_start_matches('L').trim_end_matches(';');
    let method_bare = method_name.split('(').next().unwrap_or(&method_name).trim();

    // Find the method
    let t_find = Instant::now();
    let method = dex_files.iter().find_map(|dex| {
        dex.parsed.class_defs.iter()
            .find(|cd| cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_norm)
            .and_then(|cd| Clazz::new(cd, dex).ok())
            .and_then(|clazz| clazz.methods.into_iter().find(|m| m.method_name == method_bare))
    });
    eprintln!("[run_method] find method ({} dex files): {:?}", dex_files.len(), t_find.elapsed());

    let method = method.ok_or_else(|| format!("Method not found: {}::{}", class_name, method_name))?;

    // Build VM
    let t_vm = Instant::now();
    let mut vm = Vm::new();
    for dex in dex_files.iter() {
        let clone = DexFileWithRaw::from_bytes(dex.raw_bytes().to_vec(), dex.parsed.filename.clone())
            .map_err(|e| e.to_string())?;
        vm.add_dex_file(&clone);
    }
    eprintln!("[run_method] vm + add_dex_files: {:?}", t_vm.elapsed());
    if let Some(table) = resources {
        let t_res = Instant::now();
        vm.load_resources(
            table.entries().iter()
                .filter(|e| e.type_name == "string")
                .filter_map(|e| table.resolve(e.id).map(|v| (e.id, v)))
        );
        eprintln!("[run_method] load_resources: {:?}", t_res.elapsed());
    }

    let t_args = Instant::now();
    let values: Vec<Value> = args.iter()
        .map(|s| resolve_arg_encoding(s, resources, &mut vm))
        .collect();
    // Pack wide args (J/D) across two register slots — without this
    // the callee reads a corrupted long from the (Int, Null) pair.
    // Same fix as the CLI `--run` path. See analysis::pack_user_args.
    let packed = project_platypus_native::analysis::pack_user_args(values, &method.proto_desc);
    eprintln!("[run_method] resolve_arg_encoding + pack_user_args ({} args): {:?} → {:?}",
        args.len(), t_args.elapsed(), packed);

    vm.reset_for_call(instr_limit.unwrap_or(5_000_000));
    let start = Instant::now();
    let result = vm.call_method(&method, packed);
    let elapsed = start.elapsed().as_millis() as u64;
    eprintln!("[run_method] call_method: {}ms → {:?}", elapsed, result.is_some());
    eprintln!("[run_method] TOTAL: {:?}", t_total.elapsed());

    let (return_value, return_type, error) = match &result {
        Some(v) => (format_value(v), infer_type(v), None),
        None    => ("void".into(), "void".into(), None),
    };
    let apk_cache_path = try_cache_apk_value(result.as_ref(), &state.cache_dir, "run.apk");

    Ok(RunResult {
        return_value,
        return_type,
        logs: Vec::new(),
        error,
        execution_time_ms: elapsed,
        apk_cache_path,
    })
}

/// If `value` is a `Value::Bytes` that parses as a ZIP containing classes.dex,
/// write it to the cache and return the path. Used by `find_exec` and
/// `run_method` to surface a "Load as APK" affordance on byte-array results.
fn try_cache_apk_value(
    value: Option<&project_platypus_native::vm::value::Value>,
    cache_dir: &std::path::Path,
    suggested_name: &str,
) -> Option<String> {
    use project_platypus_native::vm::value::Value;
    match value {
        Some(Value::Bytes(b)) => {
            project::cache_bytes_as_apk(b, suggested_name, cache_dir)
                .ok()
                .map(|p| p.to_string_lossy().into_owned())
        }
        _ => None,
    }
}

fn infer_type(v: &project_platypus_native::vm::value::Value) -> String {
    use project_platypus_native::vm::value::Value;
    match v {
        Value::Null     => "null",
        Value::Int(_)   => "int",
        Value::Float(_) => "float",
        Value::Bool(_)  => "boolean",
        Value::Str(_)   => "String",
        Value::Bytes(_) => "byte[]",
        Value::Array(_) => "Object[]",
    }.into()
}

// ── find_exec ─────────────────────────────────────────────────────────────────

/// `instr_limit` — optional per-call instruction budget. `None`/null uses the
/// 5,000,000 default. Frontend exposes this as a configurable input on the
/// Execution row so users can dial it up for slow deobfuscators.
#[tauri::command]
pub async fn find_exec(
    target: String,
    instr_limit: Option<u64>,
    num_threads: Option<usize>,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<ExecResultItem>, String> {
    let project = state.project.read().await;
    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;
    let resource_table = slot.resources.as_ref();

    // Same chunking choice as `deobf_run_all_marks`: 0/None = rayon's
    // default pool size, 1 = sequential, n = chunk into n shards.
    let threads = match num_threads {
        Some(0) | None => rayon::current_num_threads().max(1),
        Some(n)        => n.max(1),
    };

    let mut items = Vec::new();
    for dex in dex_files.iter() {
        let results = analysis::find_and_exec_parallel(dex, &target, resource_table, instr_limit, threads);
        for (site, value) in results {
            let (resolved_value, resolved_type, error) = match &value {
                Some(v) => (format_value(v), infer_type(v), None),
                None    => ("(no result)".into(), "void".into(), None),
            };
            // Auto-cache APK-shaped byte results so the frontend can offer
            // "Load as APK" without re-running the call.
            let suggested = format!("{}_cp{}.apk",
                site.caller_method.split('(').next().unwrap_or("exec"),
                site.invoke_cp);
            let apk_cache_path = try_cache_apk_value(value.as_ref(), &state.cache_dir, &suggested);
            items.push(ExecResultItem {
                call_site: site.invoke_str.clone(),
                caller_class: site.caller_class,
                caller_method: site.caller_method,
                offset: site.invoke_cp,
                resolved_value,
                resolved_type,
                error,
                apk_cache_path,
            });
        }
    }
    Ok(items)
}

// ── search_code ───────────────────────────────────────────────────────────────

/// Substring search across class names, method names, and `const-string`
/// instructions in the active slot's DEX files.
///
/// `package_filter` is an optional substring filter on the **class name**.
/// Dots in user input are normalised to slashes so users can type
/// `com.example.auth` or `com/example/auth` interchangeably. Empty/null = no filter.
#[tauri::command]
pub async fn search_code(
    query: String,
    package_filter: Option<String>,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<SearchResultItem>, String> {
    let project = state.project.read().await;
    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;
    let base_path = slot.base_path.clone();

    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return Ok(Vec::new());
    }
    // Whole-query in class-path form (dots → slashes, strip any L…; wrapper).
    // Used for class-name and reference-class matching so users can type
    // `com.example.Foo` or `com/example/Foo` interchangeably.
    let q_class = q
        .trim_start_matches('l')
        .trim_end_matches(';')
        .replace('.', "/");

    // Structure-aware split: `Class.member`, `Class->member`, `Class;->member`.
    // When present, member-qualified queries match a class part AND a member
    // part — this is what makes `cipher.doFinal` find calls to
    // `javax/crypto/Cipher;->doFinal`, instead of the old behaviour where the
    // dotted query matched nothing meaningful (or coincidental substrings).
    let qualified: Option<(String, String)> = parse_qualified_query(&q);

    // Normalise the package filter: lowercase + dots → slashes.
    let pkg_filter: Option<String> = package_filter
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_lowercase().replace('.', "/"));

    const LIMIT: usize = 300;
    let mut results: Vec<SearchResultItem> = Vec::new();

    'dex_loop: for dex in dex_files.iter() {
        for class_def in &dex.parsed.class_defs {
            if results.len() >= LIMIT { break 'dex_loop; }

            let type_name = &class_def.type_name;
            let display = type_name.trim_start_matches('L').trim_end_matches(';');
            let display_l = display.to_lowercase();

            // Apply package filter — class names use `/` internally.
            if let Some(pf) = &pkg_filter {
                if !display_l.contains(pf) {
                    continue;
                }
            }

            // ── Class-name match ──
            // Match the whole-query class-path form. For a qualified query we
            // do NOT treat the class part alone as a class hit (that would be
            // noisy); members are handled below.
            if display_l.contains(&q_class) {
                results.push(SearchResultItem {
                    kind: "class".into(),
                    class_name: display.to_string(),
                    member_name: None,
                    snippet: display.to_string(),
                    line: None,
                    res_id: None,
                });
                // Don't `continue` — a class whose name matches may also
                // contain matching members/refs the user wants.
            }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };

            // ── Field definitions ──
            for f in clazz.static_fields.iter().chain(clazz.instance_fields.iter()) {
                if results.len() >= LIMIT { break 'dex_loop; }
                let name_l = f.name.to_lowercase();
                let hit = match &qualified {
                    Some((cls, mem)) => display_l.contains(cls.as_str()) && name_l.contains(mem.as_str()),
                    None => name_l.contains(&q),
                };
                if hit {
                    results.push(SearchResultItem {
                        kind: "field".into(),
                        class_name: display.to_string(),
                        member_name: Some(f.name.clone()),
                        snippet: format!("{}: {}", f.name, f.type_name),
                        line: None,
                        res_id: None,
                    });
                }
            }

            // ── Methods: definitions + instruction-level refs/strings ──
            for method in &clazz.methods {
                if results.len() >= LIMIT { break 'dex_loop; }

                // Method definition match.
                let mname_l = method.method_name.to_lowercase();
                let def_hit = match &qualified {
                    Some((cls, mem)) => display_l.contains(cls.as_str()) && mname_l.contains(mem.as_str()),
                    None => mname_l.contains(&q),
                };
                if def_hit {
                    results.push(SearchResultItem {
                        kind: "method".into(),
                        class_name: display.to_string(),
                        member_name: Some(method.method_name.clone()),
                        snippet: format!("{}.{}{}", display, method.method_name, method.proto_desc),
                        line: None,
                        res_id: None,
                    });
                }

                // Instruction-level: const-strings and method/field references
                // (call sites). This is the path that surfaces *call sites* of
                // a target like `cipher.doFinal`.
                for instr in &method.instructions {
                    if results.len() >= LIMIT { break 'dex_loop; }
                    let istr = &instr.instruction_str;

                    // String literals.
                    if istr.contains("const-string") {
                        if istr.to_lowercase().contains(&q) {
                            results.push(SearchResultItem {
                                kind: "string".into(),
                                class_name: display.to_string(),
                                member_name: Some(method.method_name.clone()),
                                snippet: istr.clone(),
                                line: Some(instr.codepoint),
                                res_id: None,
                            });
                        }
                        continue;
                    }

                    // Method/field references (invoke-*, *get/*put). Parse the
                    // `Lclass;->member` ref and match structurally.
                    if let Some((ref_class, ref_member)) = parse_ref(istr) {
                        let rc_l = ref_class.to_lowercase();
                        let rm_l = ref_member.to_lowercase();
                        let ref_hit = match &qualified {
                            Some((cls, mem)) => rc_l.contains(cls.as_str()) && rm_l.contains(mem.as_str()),
                            None => rm_l.contains(&q) || rc_l.contains(&q_class),
                        };
                        if ref_hit {
                            results.push(SearchResultItem {
                                kind: "reference".into(),
                                class_name: display.to_string(),
                                member_name: Some(method.method_name.clone()),
                                snippet: istr.clone(),
                                line: Some(instr.codepoint),
                                res_id: None,
                            });
                        }
                    }
                }
            }
        }
    }

    // ── Resources ──
    // Iterate resources.arsc on demand (never cached) and match resource
    // name OR resolved value. Skipped when a package filter is active
    // (resources aren't class-scoped). Opening the APK + parsing the arsc
    // per search is the explicit "don't cache, iterate live" design.
    if pkg_filter.is_none() && results.len() < LIMIT {
        if let Ok(apk) = open_apk_zip(&base_path) {
            if let Ok(res) = open_resources(&apk) {
                for entry in res.table().entries() {
                    if results.len() >= LIMIT { break; }
                    let name_l = entry.name.to_lowercase();
                    let val_l = entry.value.to_lowercase();
                    if name_l.contains(&q) || val_l.contains(&q) {
                        results.push(SearchResultItem {
                            kind: "resource".into(),
                            class_name: entry.type_name.clone(),
                            member_name: Some(entry.name.clone()),
                            snippet: entry.value.clone(),
                            line: None,
                            res_id: Some(entry.id),
                        });
                    }
                }
            }
        }
    }

    Ok(results)
}

/// Split a search query into `(class_part, member_part)` when it looks
/// member-qualified. Recognises `Class->member`, `Class;->member`, and
/// `Class.member` (splitting on the last dot). The class part is
/// normalised to slash form. Returns `None` for a bare query.
fn parse_qualified_query(q: &str) -> Option<(String, String)> {
    if let Some(idx) = q.find("->") {
        let cls = q[..idx].trim_start_matches('l').trim_end_matches(';').replace('.', "/");
        let mem = q[idx + 2..].split('(').next().unwrap_or("").to_string();
        if !cls.is_empty() && !mem.is_empty() {
            return Some((cls, mem));
        }
        return None;
    }
    // Last-dot split. Require a non-empty member and at least one dot so we
    // don't fire on bare class names like "foo".
    if let Some(idx) = q.rfind('.') {
        let cls = q[..idx].replace('.', "/");
        let mem = &q[idx + 1..];
        if !cls.is_empty() && !mem.is_empty() {
            return Some((cls, mem.to_string()));
        }
    }
    None
}

/// Extract `(class, member)` from a method/field reference inside an
/// instruction string, e.g.
///   `invoke-virtual {v0, v1}, Ljavax/crypto/Cipher;->doFinal([B)[B`
///     → `("javax/crypto/Cipher", "doFinal")`
///   `sget-object v0, Lcom/Foo;->BAR:[Ljava/lang/String;`
///     → `("com/Foo", "BAR")`
/// Returns `None` when the instruction has no `;->` reference.
fn parse_ref(istr: &str) -> Option<(&str, &str)> {
    let arrow = istr.rfind(";->")?;
    let class_start = istr[..arrow].rfind('L')?;
    let class = &istr[class_start + 1..arrow]; // between L and ;
    let after = &istr[arrow + 3..];
    let end = after
        .find(|c| c == '(' || c == ':' || c == ' ')
        .unwrap_or(after.len());
    let member = after[..end].trim();
    if class.is_empty() || member.is_empty() {
        return None;
    }
    Some((class, member))
}

// ── open_file_dialog ──────────────────────────────────────────────────────────

#[tauri::command]
pub async fn open_file_dialog(app: tauri::AppHandle) -> Result<Option<String>, String> {
    use tauri_plugin_dialog::DialogExt;
    let path = app.dialog()
        .file()
        .add_filter("Android Files", &["apk", "dex", "xapk", "aab", "aar", "jar"])
        .blocking_pick_file();
    Ok(path.map(|p| p.to_string()))
}

// ── get_call_graph ────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphNode {
    pub class_name: String,
    pub method_name: String,
    pub signature: String,
    pub offset: Option<u32>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CallGraphResult {
    pub callers: Vec<CallGraphNode>,
    pub callees: Vec<CallGraphNode>,
}

#[tauri::command]
pub async fn get_call_graph(
    class_name: String,
    method_name: String,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<CallGraphResult, String> {
    let project = state.project.read().await;
    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;

    // Normalise the class descriptor.
    let class_desc = if class_name.starts_with('L') {
        class_name.clone()
    } else {
        format!("L{};", class_name.replace('.', "/"))
    };
    // Strip prototype from method name if present.
    let method_bare = method_name.split('(').next().unwrap_or(&method_name);
    let target = format!("{}->{}", class_desc, method_bare);

    // ── Callers: who calls this method ────────────────────────────────────────
    let mut callers: Vec<CallGraphNode> = Vec::new();
    let mut seen_callers: std::collections::HashSet<String> = Default::default();

    for dex in dex_files.iter() {
        for site in analysis::find_calls(dex, &target) {
            let key = format!("{}::{}", site.caller_class, site.caller_method);
            if seen_callers.insert(key) {
                let (caller_method_bare, sig) = split_method_sig(&site.caller_method);
                callers.push(CallGraphNode {
                    class_name: site.caller_class,
                    method_name: caller_method_bare,
                    signature: sig,
                    offset: Some(site.invoke_cp),
                });
            }
        }
    }

    // ── Callees: what this method calls ───────────────────────────────────────
    let mut callees: Vec<CallGraphNode> = Vec::new();
    let mut seen_callees: std::collections::HashSet<String> = Default::default();

    let class_norm = class_desc.trim_start_matches('L').trim_end_matches(';');

    'outer: for dex in dex_files.iter() {
        for class_def in &dex.parsed.class_defs {
            let def_norm = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
            if def_norm != class_norm { continue; }

            let clazz = match Clazz::new(class_def, dex) {
                Ok(c) => c,
                Err(_) => continue,
            };

            for method in &clazz.methods {
                if method.method_name != method_bare { continue; }

                for instr in &method.instructions {
                    let istr = &instr.instruction_str;
                    if !istr.contains("invoke") { continue; }

                    // Extract the method reference from the invoke instruction.
                    if let Some(method_ref) = extract_invoke_target(istr) {
                        if seen_callees.insert(method_ref.clone()) {
                            if let Some((callee_class, callee_method)) = method_ref.split_once("->") {
                                let (bare, sig) = split_method_sig(callee_method);
                                let display_class = callee_class
                                    .trim_start_matches('L')
                                    .trim_end_matches(';')
                                    .to_string();
                                callees.push(CallGraphNode {
                                    class_name: display_class,
                                    method_name: bare,
                                    signature: sig,
                                    offset: None,
                                });
                            }
                        }
                    }
                }
                break 'outer;
            }
        }
    }

    Ok(CallGraphResult { callers, callees })
}

fn split_method_sig(method_with_sig: &str) -> (String, String) {
    if let Some(paren) = method_with_sig.find('(') {
        (method_with_sig[..paren].to_string(), method_with_sig[paren..].to_string())
    } else {
        (method_with_sig.to_string(), String::new())
    }
}

fn extract_invoke_target(istr: &str) -> Option<String> {
    // Invoke instructions look like:
    //   invoke-virtual {v0, v1}, Lcom/foo/Bar;->baz(I)V
    let after = istr.find("}, ")
        .map(|p| p + 3)
        .or_else(|| istr.find("} ..").map(|p| p + 4))
        .or_else(|| istr.rfind('}').map(|p| p + 1))?;
    let rest = istr[after..].trim();
    // rest = "Lcom/foo/Bar;->baz(I)V"
    if rest.contains("->") { Some(rest.to_string()) } else { None }
}

// ── get_method_cfg ────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CfgBlockSer {
    pub id: usize,
    pub block_type: String,
    pub instructions: Vec<String>,
    pub first_codepoint: u32,
    pub is_entry: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CfgEdgeSer {
    pub source_id: usize,
    pub target_id: usize,
    pub kind: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MethodCfgResult {
    pub blocks: Vec<CfgBlockSer>,
    pub edges: Vec<CfgEdgeSer>,
    pub entry_id: usize,
}

#[tauri::command]
pub async fn get_method_cfg(
    class_name: String,
    method_name: String,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<MethodCfgResult, String> {
    let project = state.project.read().await;
    let slot = resolve_slot(&project, &slot_id)?;
    let dex_files = &slot.dex_files;

    let class_desc = if class_name.starts_with('L') {
        class_name.clone()
    } else {
        format!("L{};", class_name.replace('.', "/"))
    };
    let class_norm = class_desc.trim_start_matches('L').trim_end_matches(';');
    let method_bare = method_name.split('(').next().unwrap_or(&method_name);

    for dex in dex_files.iter() {
        let class_def = dex.parsed.class_defs.iter()
            .find(|cd| cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_norm);

        if let Some(cd) = class_def {
            let clazz = Clazz::new(cd, dex).map_err(|e| e.to_string())?;

            if let Some(method) = clazz.methods.iter().find(|m| m.method_name == method_bare) {
                let cfg = method.cfg.as_ref()
                    .ok_or_else(|| "Method has no control flow graph (abstract/native)".to_string())?;

                let blocks: Vec<CfgBlockSer> = cfg.blocks.iter().map(|b| {
                    let instructions: Vec<String> = b.instr_indices.iter()
                        .filter_map(|&i| method.instructions.get(i))
                        .map(|instr| instr.instruction_str.clone())
                        .collect();
                    CfgBlockSer {
                        id: b.id,
                        block_type: format!("{:?}", b.block_type).to_lowercase(),
                        instructions,
                        first_codepoint: b.first_codepoint,
                        is_entry: b.id == 0,
                    }
                }).collect();

                let edges: Vec<CfgEdgeSer> = cfg.edges.iter().map(|e| {
                    let kind = format!("{:?}", e.kind)
                        .chars()
                        .enumerate()
                        .map(|(i, c)| if i > 0 && c.is_uppercase() {
                            format!("_{}", c.to_lowercase())
                        } else {
                            c.to_lowercase().to_string()
                        })
                        .collect::<String>();
                    CfgEdgeSer {
                        source_id: e.source_id,
                        target_id: e.target_id,
                        kind,
                    }
                }).collect();

                return Ok(MethodCfgResult {
                    blocks,
                    edges,
                    entry_id: 0,
                });
            }
            return Err(format!("Method not found: {}", method_bare));
        }
    }
    Err(format!("Class not found: {}", class_name))
}

// ── load_file_b ───────────────────────────────────────────────────────────────
// Loads an APK/DEX into the comparison slot (B) without touching slot A.

#[tauri::command]
pub async fn load_file_b(
    path: String,
    state: State<'_, AppState>,
) -> Result<LoadResult, String> {
    let slot = crate::project::load_slot_from_disk(
        "", "", &path, &[], None, false,
    )?;

    if slot.dex_files.is_empty() {
        return Err("No DEX files found in slot B".into());
    }

    // Build the LoadResult BEFORE moving the slot into the project. Slot B's tree
    // ids are namespaced with "b:" so they don't collide with slot A's.
    let load_result = assemble_load_result_with_prefix(
        path.clone(),
        &slot.dex_files,
        false, // historical: load_file_b never appended a manifest node
        slot.entry_names.iter().map(|(_, n)| n.clone()).collect(),
        "b:",
    );

    let mut project = state.project.write().await;
    let id = project.upsert(slot);
    project.compare_slot_id = Some(id);
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;

    Ok(load_result)
}

// ── get_class_smali_b / get_class_java_b ─────────────────────────────────────

#[tauri::command]
pub async fn get_class_smali_b(
    class_name: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let project = state.project.read().await;
    let slot = project.compare().ok_or_else(|| "No comparison APK selected".to_string())?;
    let dex_files = &slot.dex_files;
    let target = if class_name.starts_with('L') {
        class_name.clone()
    } else {
        format!("L{};", class_name)
    };
    for dex in dex_files.iter() {
        if let Some(class_def) = dex.parsed.class_defs.iter()
            .find(|cd| cd.type_name == target || cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_name)
        {
            let clazz = Clazz::new(class_def, dex).map_err(|e| e.to_string())?;
            return Ok(SmaliClassCodeGen::new(&clazz, &dex.parsed).format());
        }
    }
    Err(format!("Class not found in slot B: {}", class_name))
}

#[tauri::command]
pub async fn get_class_java_b(
    class_name: String,
    keep_kotlin_intrinsics: Option<bool>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let project = state.project.read().await;
    let slot = project.compare().ok_or_else(|| "No comparison APK selected".to_string())?;
    let dex_files = &slot.dex_files;
    let target = if class_name.starts_with('L') {
        class_name.clone()
    } else {
        format!("L{};", class_name)
    };
    let filter = if keep_kotlin_intrinsics.unwrap_or(false) {
        MethodFilter::empty()
    } else {
        MethodFilter::default()
    };
    for dex in dex_files.iter() {
        if let Some(class_def) = dex.parsed.class_defs.iter()
            .find(|cd| cd.type_name == target || cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_name)
        {
            let clazz = Clazz::new(class_def, dex).map_err(|e| e.to_string())?;
            let config = AnalysisConfig::default();
            let decompiler = JavaDecompiler::new(Some(config));
            let mut method_texts: Vec<String> = Vec::new();
            let mut all_imports: std::collections::HashSet<String> = std::collections::HashSet::new();
            for method in &clazz.methods {
                if method.instructions.is_empty() { method_texts.push(String::new()); continue; }
                let ast = decompiler.decompile(method);
                let mut cfg_clone = method.cfg.clone();
                if let Some(ref mut cfg) = cfg_clone { DominatorTree::compute(cfg); }
                let ssa = cfg_clone.as_ref()
                    .map(|cfg| SsaBuilder::new().build(cfg, &method.instructions, method.registers_size, method.ins_size))
                    .unwrap_or_else(SsaBuilder::empty_ssa);
                let mut gen = JavaGenerator::new_with_filter(method, &dex.parsed, &ssa, filter.clone());
                method_texts.push(gen.gen_class_method(&ast));
                for imp in gen.import_statements() { all_imports.insert(imp); }
            }
            let mut out = Vec::new();
            let pkg = class_package(&clazz.class_name);
            if !pkg.is_empty() { out.push(format!("package {};", pkg)); out.push(String::new()); }
            let mut sorted_imports: Vec<String> = all_imports.into_par_iter()
                .filter(|s| s.starts_with("import "))   // defensive: drop any malformed entries
                .collect();
            sorted_imports.sort();
            for imp in sorted_imports { out.push(imp); }
            if !method_texts.is_empty() { out.push(String::new()); }
            for t in method_texts { if !t.is_empty() { out.push(t); } }
            return Ok(out.join("\n"));
        }
    }
    Err(format!("Class not found in slot B: {}", class_name))
}

// ── get_resources ─────────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResourceEntryItem {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub type_name: String,
    pub path: String,
    pub content: Option<String>,
}

// ── get_entry ─────────────────────────────────────────────────────────────────

/// Read a raw ZIP entry from the loaded APK and return its content as a string.
///
/// • `.xml` entries are decoded from Android binary XML (axml) and returned as
///   pretty-printed XML text.
/// • Other entries are attempted as UTF-8; if they are valid UTF-8 they are
///   returned as-is.
/// • Binary entries (images, compiled files, etc.) return a hex-dump preview
///   prefixed with "// [binary: N bytes]\n".
#[tauri::command]
pub async fn get_entry(
    entry_path: String,
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let path = {
        let project = state.project.read().await;
        let slot = resolve_slot(&project, &slot_id)?;
        slot.base_path.clone()
    };

    let apk = ApkZip::open(&path).map_err(|e| e.to_string())?;
    let bytes = apk.read_entry(&entry_path).map_err(|e| e.to_string())?;

    // Try Android binary XML first (all .xml files inside APKs are binary).
    if entry_path.ends_with(".xml") {
        if let Ok(root) = axml::parse(&bytes) {
            return Ok(root.to_xml_string());
        }
    }

    // Try UTF-8 text.
    if let Ok(text) = std::str::from_utf8(&bytes) {
        return Ok(text.to_string());
    }

    // Binary fallback: hex dump of up to 512 bytes.
    let preview_len = bytes.len().min(512);
    let hex: String = bytes[..preview_len]
        .chunks(16)
        .enumerate()
        .map(|(i, chunk)| {
            let hex_part: String = chunk.iter().map(|b| format!("{:02x} ", b)).collect();
            let ascii_part: String = chunk
                .iter()
                .map(|&b| if b.is_ascii_graphic() || b == b' ' { b as char } else { '.' })
                .collect();
            format!("{:08x}  {:<48} |{}|", i * 16, hex_part, ascii_part)
        })
        .collect::<Vec<_>>()
        .join("\n");

    Ok(format!(
        "// [binary: {} bytes{}]\n\n{}",
        bytes.len(),
        if bytes.len() > 512 { ", showing first 512" } else { "" },
        hex
    ))
}

/// Categorise an APK entry by extension. Returns `(content_type, kind)`
/// where `kind` is the high-level classification the frontend uses to
/// pick a viewer ("image" / "font" / "axml" / "arsc" / "dex" / "elf"
/// / "text" / "binary").
fn asset_category(name: &str) -> (&'static str, &'static str) {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".png")  { return ("image/png",     "image"); }
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") {
        return ("image/jpeg", "image");
    }
    if lower.ends_with(".webp") { return ("image/webp",    "image"); }
    if lower.ends_with(".gif")  { return ("image/gif",     "image"); }
    if lower.ends_with(".svg")  { return ("image/svg+xml", "image"); }
    if lower.ends_with(".ttf") || lower.ends_with(".otf") {
        return ("font/ttf", "font");
    }
    if lower.ends_with(".woff") { return ("font/woff",  "font"); }
    if lower.ends_with(".woff2"){ return ("font/woff2", "font"); }
    if lower.ends_with(".json") { return ("application/json", "text"); }
    if lower.ends_with(".xml")  { return ("application/xml",  "axml"); }
    if lower.ends_with(".arsc") { return ("application/octet-stream", "arsc"); }
    if lower.ends_with(".dex")  { return ("application/octet-stream", "dex"); }
    if lower.ends_with(".so")   { return ("application/octet-stream", "elf"); }
    ("application/octet-stream", "binary")
}

/// Return raw bytes for an APK entry — the binary analogue of
/// `get_entry`. The frontend uses this for `<img>` sources, font
/// loading, and anything else that needs the unmodified payload.
/// AXML (binary `res/*.xml`) is decoded to its text form on the way
/// out so consumers can pass the bytes directly to an XML parser.
#[tauri::command]
pub async fn get_asset_bytes(
    entry_path: String,
    state: State<'_, AppState>,
) -> Result<Vec<u8>, String> {
    let path = {
        let project = state.project.read().await;
        let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
        slot.base_path.clone()
    };
    let apk = ApkZip::open(&path).map_err(|e| e.to_string())?;
    let bytes = apk.read_entry(&entry_path).map_err(|e| e.to_string())?;

    let (_, kind) = asset_category(&entry_path);
    if kind == "axml" {
        if let Ok(root) = axml::parse(&bytes) {
            return Ok(root.to_xml_string().into_bytes());
        }
    }
    Ok(bytes)
}

/// Lightweight metadata for an APK entry — size, MIME, classification.
/// Use this to decide which viewer (image / hex / text / smali) to load
/// before fetching the full body via `get_asset_bytes`.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetInfo {
    pub path: String,
    pub size: usize,
    pub content_type: String,
    pub decoded_kind: String,
}

#[tauri::command]
pub async fn get_asset_info(
    entry_path: String,
    state: State<'_, AppState>,
) -> Result<AssetInfo, String> {
    let path = {
        let project = state.project.read().await;
        let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
        slot.base_path.clone()
    };
    let apk = ApkZip::open(&path).map_err(|e| e.to_string())?;
    let bytes = apk.read_entry(&entry_path).map_err(|e| e.to_string())?;

    let (ct, kind) = asset_category(&entry_path);
    Ok(AssetInfo {
        path: entry_path,
        size: bytes.len(),
        content_type: ct.to_string(),
        decoded_kind: kind.to_string(),
    })
}

#[tauri::command]
pub async fn get_resources(state: State<'_, AppState>) -> Result<Vec<ResourceEntryItem>, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let items = match &slot.resources {
        Some(table) => table
            .entries()
            .iter()
            .map(|e| ResourceEntryItem {
                id: format!("{:#010x}", e.id),
                name: e.name.clone(),
                type_name: e.type_name.clone(),
                path: format!("{}:{}", e.type_name, e.name),
                content: table.resolve(e.id),
            })
            .collect(),
        None => Vec::new(),
    };
    Ok(items)
}

// ── Python scripting ───────────────────────────────────────────────────────────

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptRunResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: u64,
    /// Number of lines the wrapper prepends before the user's code starts
    /// (sys.path setup + LOADED_APK injection). The frontend uses this to
    /// map `File "/tmp/wrapper.py", line N` traceback frames back to
    /// **user-code** line N — without this, every clickable traceback link
    /// would jump to the wrong line. Currently the wrapper writes:
    ///   line 1: `import sys as _sys`
    ///   line 2: `_sys.path.insert(0, r"{project_root}")`
    ///   line 3: `LOADED_APK = ...`
    /// so this is `3` (= user code is on lines 4..).
    pub prologue_lines: u32,
    /// Absolute path of the wrapper temp file we wrote. The frontend
    /// recognises this in traceback frames and treats them as
    /// "open in editor" rather than "copy path".
    pub wrapper_path: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LintDiagnostic {
    pub line: u32,
    pub col: u32,
    pub end_line: Option<u32>,
    pub end_col: Option<u32>,
    pub code: String,
    pub message: String,
    pub severity: String,
}

// ── Python toolchain resolution ─────────────────────────────────────────────
//
// Scripting shells out to a Python interpreter (and `ruff` for linting). To
// support a bundled, relocatable install we resolve each tool in priority
// order:
//   1. An explicit env override (PLATYPUS_PYTHON / PLATYPUS_RUFF /
//      PLATYPUS_PYROOT) — power users / CI can point at any interpreter.
//   2. A Python bundled into the app under `resources/python/` (assembled by
//      scripts/bundle-python.sh and shipped via tauri.conf.json
//      `bundle.resources`). The `platypus` extension module is pip-installed
//      into that interpreter, so `import platypus` works with no extra wiring.
//   3. The system `python3` / `ruff` on PATH (dev machines, or installs that
//      deliberately don't bundle Python).

/// `bin/` dir of the bundled Python, if one was shipped in the resource dir.
/// `None` when unbundled (dev) or before `bundle-python.sh` has populated it.
fn bundled_python_bindir(app: &AppHandle) -> Option<std::path::PathBuf> {
    let res = app.path().resource_dir().ok()?;
    // python-build-standalone "install_only" layout puts the interpreter at
    // `<prefix>/bin/python3` (Unix) or `<prefix>/python.exe` (Windows). The
    // prefix lands under the resource dir; depending on how Tauri copies the
    // `bundle.resources` entry it may be `python/` or `resources/python/`, so
    // probe both and take whichever exists.
    let prefixes = [res.join("resources").join("python"), res.join("python")];
    for prefix in prefixes {
        let bindir = if cfg!(windows) { prefix } else { prefix.join("bin") };
        if bindir.exists() {
            return Some(bindir);
        }
    }
    None
}

/// Interpreter used to run scripts and the completions probe.
fn resolve_python(app: &AppHandle) -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PLATYPUS_PYTHON") {
        if !p.is_empty() { return std::path::PathBuf::from(p); }
    }
    if let Some(bindir) = bundled_python_bindir(app) {
        let exe = bindir.join(if cfg!(windows) { "python.exe" } else { "python3" });
        if exe.exists() { return exe; }
    }
    std::path::PathBuf::from("python3")
}

/// `ruff` binary for linting (pip-installed alongside the bundled interpreter).
fn resolve_ruff(app: &AppHandle) -> std::path::PathBuf {
    if let Ok(p) = std::env::var("PLATYPUS_RUFF") {
        if !p.is_empty() { return std::path::PathBuf::from(p); }
    }
    if let Some(bindir) = bundled_python_bindir(app) {
        // Console scripts: `python/bin/ruff` (Unix) / `python/Scripts/ruff.exe`
        // (Windows — bindir is `python/` there).
        let exe = if cfg!(windows) {
            bindir.join("Scripts").join("ruff.exe")
        } else {
            bindir.join("ruff")
        };
        if exe.exists() { return exe; }
    }
    std::path::PathBuf::from("ruff")
}

/// Project root prepended to `sys.path` so scripts can import the legacy
/// Python tree (when present). `import platypus` does NOT depend on this — it
/// resolves from the bundled interpreter's site-packages. A missing path is
/// harmless: Python simply ignores non-existent `sys.path` entries.
fn resolve_pyroot(app: &AppHandle) -> String {
    if let Ok(p) = std::env::var("PLATYPUS_PYROOT") {
        if !p.is_empty() { return p; }
    }
    if let Ok(res) = app.path().resource_dir() {
        let pysrc = res.join("pysrc");
        if pysrc.exists() { return pysrc.to_string_lossy().into_owned(); }
    }
    // Dev fallback: the source checkout this binary was compiled from.
    env!("CARGO_MANIFEST_DIR").replace("/ui-react/src-tauri", "")
}

/// Run a Python script with the platypus project root on sys.path.
/// The loaded APK path is injected as `LOADED_APK`.
///
/// The subprocess PID is recorded in `AppState::running_script_pid` while the
/// script is running, so `kill_script` can terminate it. Only one script can
/// run at a time — the frontend disables Run while `isScriptRunning` is true.
#[tauri::command]
pub async fn run_script(
    code: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ScriptRunResult, String> {
    use std::io::Write;
    use std::process::Stdio;
    use std::time::Instant;
    use tokio::process::Command;

    // Resolve the project root (bundled `pysrc` resource, env override, or the
    // dev source checkout) and the interpreter (bundled → env → system).
    let project_root = resolve_pyroot(&app);
    let python = resolve_python(&app);

    let loaded_apk = {
        let project = state.project.read().await;
        project.active().map(|s| s.base_path.clone()).unwrap_or_default()
    };

    // Write a small wrapper that sets up sys.path and the LOADED_APK global.
    let wrapper = format!(
        r#"import sys as _sys
_sys.path.insert(0, r"{project_root}")
LOADED_APK = {apk_repr}
{user_code}
"#,
        project_root = project_root,
        apk_repr = if loaded_apk.is_empty() {
            "None".to_string()
        } else {
            format!("r\"{}\"", loaded_apk)
        },
        user_code = code,
    );

    // Write to a temp file. Hold the NamedTempFile binding across the await
    // so the file isn't deleted before python3 reads it.
    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    tmp.write_all(wrapper.as_bytes()).map_err(|e| e.to_string())?;
    let tmp_path = tmp.path().to_path_buf();

    let t0 = Instant::now();
    let mut child = Command::new(&python)
        .arg(&tmp_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Could not run python ({}): {e}", python.display()))?;

    // Record the PID so `kill_script` can target it.
    let pid = child.id();
    {
        let mut guard = state.running_script_pid.lock().await;
        *guard = pid;
    }

    let wait_result = child.wait_with_output().await;

    // Always clear the PID so a kill request after completion is a no-op
    // rather than racing a freshly-spawned next script.
    {
        let mut guard = state.running_script_pid.lock().await;
        *guard = None;
    }

    let output = wait_result.map_err(|e| format!("python3 wait failed: {e}"))?;

    Ok(ScriptRunResult {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
        duration_ms: t0.elapsed().as_millis() as u64,
        // Three prologue lines: `import sys as _sys`,
        // `_sys.path.insert(...)`, and `LOADED_APK = ...`. Keep this
        // in sync with the `wrapper` format! above — if the prologue
        // changes shape, the frontend's traceback line-mapping will
        // be off by however many lines drifted.
        prologue_lines: 3,
        wrapper_path: tmp_path.to_string_lossy().into_owned(),
    })
}

/// Send `SIGTERM` to the currently-running `python3` script subprocess, if any.
/// Returns true if a process was killed, false if no script was running.
/// Falls back to `SIGKILL` after a short grace period would be nicer but
/// for now SIGTERM is enough — Python responds promptly to it.
#[tauri::command]
pub async fn kill_script(state: State<'_, AppState>) -> Result<bool, String> {
    let pid_opt = {
        // Take the PID out so a subsequent kill request is idempotent.
        let mut guard = state.running_script_pid.lock().await;
        guard.take()
    };

    let Some(pid) = pid_opt else { return Ok(false); };

    #[cfg(unix)]
    unsafe {
        // SIGTERM = 15. Python's default handler will raise KeyboardInterrupt
        // / clean up and exit, so the wait_with_output in `run_script` returns
        // with the partial stdout/stderr.
        let rc = libc::kill(pid as libc::pid_t, libc::SIGTERM);
        if rc != 0 {
            // `std::io::Error::last_os_error()` reads errno portably (macOS
            // uses `__error()`, Linux `__errno_location()`); using it keeps
            // this compiling across Unix platforms and yields a readable
            // message instead of a bare errno number.
            return Err(format!(
                "kill({}) failed: {}", pid, std::io::Error::last_os_error()
            ));
        }
    }
    #[cfg(windows)]
    {
        // Best-effort on Windows: spawn a `taskkill /PID <pid> /T /F`.
        // We don't have nice signal semantics here.
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .output();
    }
    Ok(true)
}

/// Lint a Python code snippet with ruff and return diagnostics.
#[tauri::command]
pub async fn lint_script(code: String, app: AppHandle) -> Result<Vec<LintDiagnostic>, String> {
    use std::io::Write;

    if code.trim().is_empty() {
        return Ok(vec![]);
    }

    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    tmp.write_all(code.as_bytes()).map_err(|e| e.to_string())?;
    let tmp_path = tmp.path().to_path_buf();

    // ruff check --output-format json <file>
    let ruff = resolve_ruff(&app);
    let output = std::process::Command::new(&ruff)
        .args(["check", "--output-format", "json"])
        .arg(&tmp_path)
        .output()
        .map_err(|e| format!("Could not run ruff ({}): {e}", ruff.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return Ok(vec![]);
    }

    // Parse ruff JSON output: array of { code, message, location: { row, column },
    //   end_location: { row, column }, ... }
    let raw: serde_json::Value = serde_json::from_str(&stdout).unwrap_or(serde_json::json!([]));
    let diags = raw
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let code = item["code"].as_str().unwrap_or("E").to_string();
                    let message = item["message"].as_str().unwrap_or("").to_string();
                    let row = item["location"]["row"].as_u64()? as u32;
                    let col = item["location"]["column"].as_u64()? as u32;
                    let end_row = item["end_location"]["row"].as_u64().map(|v| v as u32);
                    let end_col = item["end_location"]["column"].as_u64().map(|v| v as u32);
                    // ruff uses 1-based rows/cols; frontend expects 0-based
                    let severity = if code.starts_with('E') || code.starts_with('F') {
                        "error"
                    } else if code.starts_with('W') {
                        "warning"
                    } else {
                        "info"
                    };
                    Some(LintDiagnostic {
                        line: row.saturating_sub(1),
                        col: col.saturating_sub(1),
                        end_line: end_row.map(|r| r.saturating_sub(1)),
                        end_col: end_col.map(|c| c.saturating_sub(1)),
                        code,
                        message,
                        severity: severity.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    Ok(diags)
}

/// Open the JADX-style global search window. If it's already open, just focus
/// it. The window is persistent (stays open as the user works) and runs the
/// `SearchApp` component (see `src/SearchApp.tsx`).
#[tauri::command]
pub async fn open_search_window(app: AppHandle) -> Result<(), String> {
    let label = "search";
    if let Some(win) = app.get_webview_window(label) {
        win.set_focus().ok();
        return Ok(());
    }

    WebviewWindowBuilder::new(&app, label, WebviewUrl::App("/#/search".into()))
        .title("Search")
        .inner_size(900.0, 650.0)
        .min_inner_size(560.0, 360.0)
        .resizable(true)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
pub async fn open_taint_window(
    app: AppHandle,
    class_name: String,
    method_name: String,
) -> Result<(), String> {
    let label = "taint";
    // If already open, just focus it and emit new params via event.
    if let Some(win) = app.get_webview_window(label) {
        win.set_focus().ok();
        app.emit("taint:navigate", serde_json::json!({
            "className": class_name,
            "methodName": method_name,
        })).map_err(|e| e.to_string())?;
        return Ok(());
    }

    let url = format!(
        "/#/taint?class={}&method={}",
        urlencoding::encode(&class_name),
        urlencoding::encode(&method_name)
    );

    WebviewWindowBuilder::new(&app, label, WebviewUrl::App(url.into()))
        .title(format!("Taint — {}", method_name))
        .inner_size(1000.0, 750.0)
        .min_inner_size(640.0, 480.0)
        .resizable(true)
        .build()
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// Taint analysis — single method, no overrides. Kept for the legacy summary card
/// view; new code should prefer the graph-based commands below.
#[tauri::command]
pub async fn run_taint_analysis(
    class_name: String,
    method_name: String,
    state: State<'_, AppState>,
) -> Result<taint::TaintResult, String> {
    crate::license::require_feature(&state, "taint")?;
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let dex_files = &slot.dex_files;
    taint::analyze_class_method(dex_files, &class_name, &method_name)
}

// ── Inter-procedural taint graph ─────────────────────────────────────────────
//
// The graph is held by the frontend and round-tripped on every command. Each
// expansion adds either callers (backward) or callees (forward) one step at a
// time. Overrides may be supplied with any call to influence the analysis.

/// Build the initial graph: just the root method, analysed, with no edges.
#[tauri::command]
pub async fn taint_build_root(
    class_name: String,
    method_name: String,
    overrides: Option<taint::OverrideMap>,
    state: State<'_, AppState>,
) -> Result<taint::TaintGraph, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let dex_files = &slot.dex_files;
    let ovs = overrides.unwrap_or_default();
    taint::build_root_graph(dex_files, &class_name, &method_name, &ovs)
}

/// Add the callees of `node_id` to the graph (one step forward).
#[tauri::command]
pub async fn taint_expand_forward(
    graph: taint::TaintGraph,
    node_id: String,
    overrides: Option<taint::OverrideMap>,
    state: State<'_, AppState>,
) -> Result<taint::TaintGraph, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let dex_files = &slot.dex_files;
    let ovs = overrides.unwrap_or_default();
    taint::expand_forward(dex_files, graph, &node_id, &ovs)
}

/// Add the callers of `node_id` to the graph (one step backward).
#[tauri::command]
pub async fn taint_expand_backward(
    graph: taint::TaintGraph,
    node_id: String,
    overrides: Option<taint::OverrideMap>,
    state: State<'_, AppState>,
) -> Result<taint::TaintGraph, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let dex_files = &slot.dex_files;
    let ovs = overrides.unwrap_or_default();
    taint::expand_backward(dex_files, graph, &node_id, &ovs)
}

/// Re-run the per-node analysis on every node in `graph` with `overrides`.
/// Edges and expansion state are preserved.
#[tauri::command]
pub async fn taint_reanalyze(
    graph: taint::TaintGraph,
    overrides: taint::OverrideMap,
    state: State<'_, AppState>,
) -> Result<taint::TaintGraph, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let dex_files = &slot.dex_files;
    taint::reanalyze_with_overrides(dex_files, graph, &overrides)
}

// ═══════════════════════════════════════════════════════════════════════════
// Multi-APK project commands
// ═══════════════════════════════════════════════════════════════════════════

use crate::project::{self, Project, SlotSummary};

/// Snapshot returned to the frontend — slot summaries + active/compare ids.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProjectSnapshot {
    pub slots: Vec<SlotSummary>,
    pub active_slot_id: Option<String>,
    pub compare_slot_id: Option<String>,
    pub cache_dir: String,
}

fn snapshot(project: &Project, cache_dir: &std::path::Path) -> ProjectSnapshot {
    ProjectSnapshot {
        slots: project.slots.iter().map(|s| s.summary()).collect(),
        active_slot_id: project.active_slot_id.clone(),
        compare_slot_id: project.compare_slot_id.clone(),
        cache_dir: cache_dir.to_string_lossy().into_owned(),
    }
}

/// Called once on frontend mount to retrieve the persisted project state.
#[tauri::command]
pub async fn project_init(state: State<'_, AppState>) -> Result<ProjectSnapshot, String> {
    let project = state.project.read().await;
    Ok(snapshot(&project, &state.cache_dir))
}

#[tauri::command]
pub async fn project_list_slots(state: State<'_, AppState>) -> Result<ProjectSnapshot, String> {
    let project = state.project.read().await;
    Ok(snapshot(&project, &state.cache_dir))
}

/// Add an APK as a new slot (or refocus an existing one if SHA-256 matches).
/// Sets the new/found slot active and persists the project. `is_cached` is
/// auto-detected from whether `path` lives inside the cache directory.
#[tauri::command]
pub async fn project_add_apk(
    path: String,
    parent_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    let is_cached = std::path::Path::new(&path).starts_with(&state.cache_dir);
    let slot = project::load_slot_from_disk(
        "",                 // empty → derive id from sha256
        "",                 // empty → derive display name from package or filename
        &path,
        &[],
        parent_id,
        is_cached,
    )?;
    let mut project = state.project.write().await;
    let id = project.upsert(slot);
    project.active_slot_id = Some(id);
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

/// Attach a split APK to an existing slot's bundle. Triggers a re-parse of
/// the combined base + splits view.
#[tauri::command]
pub async fn project_add_split(
    slot_id: String,
    split_path: String,
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    let mut project = state.project.write().await;
    let (base_path, mut split_paths, parent_id, is_cached, display_name) = {
        let slot = project.find(&slot_id).ok_or_else(|| format!("Slot '{}' not found", slot_id))?;
        (
            slot.base_path.clone(),
            slot.split_paths.clone(),
            slot.parent_id.clone(),
            slot.is_cached,
            slot.display_name.clone(),
        )
    };
    if !split_paths.contains(&split_path) {
        split_paths.push(split_path);
    }
    let new_slot = project::load_slot_from_disk(
        &slot_id,
        &display_name,
        &base_path,
        &split_paths,
        parent_id,
        is_cached,
    )?;
    if let Some(slot) = project.find_mut(&slot_id) {
        *slot = new_slot;
    }
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

#[tauri::command]
pub async fn project_remove_slot(
    slot_id: String,
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    let mut project = state.project.write().await;
    project.remove(&slot_id);
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

#[tauri::command]
pub async fn project_set_active_slot(
    slot_id: String,
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    let mut project = state.project.write().await;
    if !project.set_active(&slot_id) {
        return Err(format!("Slot '{}' not found", slot_id));
    }
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

/// Set/clear the slot used as the diff "B" side. Pass `None` to clear.
#[tauri::command]
pub async fn project_set_compare_slot(
    slot_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    let mut project = state.project.write().await;
    if !project.set_compare(slot_id.as_deref()) {
        return Err(format!("Slot '{}' not found", slot_id.unwrap_or_default()));
    }
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

/// Re-read a slot's APK files from disk, throwing away cached parsed data.
#[tauri::command]
pub async fn project_force_reload_slot(
    slot_id: String,
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    let mut project = state.project.write().await;
    let (base_path, split_paths, parent_id, is_cached, display_name) = {
        let slot = project.find(&slot_id).ok_or_else(|| format!("Slot '{}' not found", slot_id))?;
        (
            slot.base_path.clone(),
            slot.split_paths.clone(),
            slot.parent_id.clone(),
            slot.is_cached,
            slot.display_name.clone(),
        )
    };
    let new_slot = project::load_slot_from_disk(
        &slot_id,
        &display_name,
        &base_path,
        &split_paths,
        parent_id,
        is_cached,
    )?;
    if let Some(slot) = project.find_mut(&slot_id) {
        *slot = new_slot;
    }
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

/// Wipe `<cache>/extracted/` and remove any slots that pointed into it.
#[tauri::command]
pub async fn project_clear_extracted(
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    let mut project = state.project.write().await;
    let removed_ids: Vec<String> = project.slots.iter()
        .filter(|s| s.is_cached)
        .map(|s| s.id.clone())
        .collect();
    for id in &removed_ids {
        project.remove(id);
    }
    project::wipe_extracted(&state.cache_dir).map_err(|e| e.to_string())?;
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

#[tauri::command]
pub async fn project_cache_dir(state: State<'_, AppState>) -> Result<String, String> {
    Ok(state.cache_dir.to_string_lossy().into_owned())
}

/// Load an embedded APK/ZIP-with-DEX from `parent_slot_id`'s assets into a
/// new child slot. The bytes are extracted from the parent's ZIP, written to
/// `<cache>/extracted/`, and registered as a slot with `parent_id` set.
#[tauri::command]
pub async fn project_load_embedded(
    parent_slot_id: String,
    entry_path: String,
    state: State<'_, AppState>,
) -> Result<ProjectSnapshot, String> {
    // Phase 1 — extract under a read-lock on the project (parent slot is &Slot).
    let cache_path = {
        let project = state.project.read().await;
        let parent = project.find(&parent_slot_id)
            .ok_or_else(|| format!("Parent slot '{}' not found", parent_slot_id))?;
        project::extract_embedded_to_cache(parent, &entry_path, &state.cache_dir)?
    };
    let cache_path_str = cache_path.to_string_lossy().into_owned();

    // Phase 2 — parse the extracted file as a fresh slot.
    let display_name_hint = std::path::Path::new(&entry_path)
        .file_name().and_then(|s| s.to_str()).unwrap_or("embedded").to_string();
    let slot = project::load_slot_from_disk(
        "",                              // derive id from sha256
        &display_name_hint,
        &cache_path_str,
        &[],
        Some(parent_slot_id.clone()),
        true,                            // lives in the cache dir
    )?;

    // Phase 3 — insert + activate + persist (write-lock on the project).
    let mut project = state.project.write().await;
    let id = project.upsert(slot);
    project.active_slot_id = Some(id);
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(snapshot(&project, &state.cache_dir))
}

/// Tree + identity of an embedded APK loaded for *inline* browsing.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedLoadResult {
    /// Id of the child slot the embedded APK was parsed into.
    pub slot_id: String,
    /// Class/package tree of the embedded APK.
    pub tree: Vec<TreeNodeSer>,
    /// Raw ZIP entry names (for the embedded APK's resources subtree).
    pub entry_names: Vec<String>,
    /// Payloads nested *inside* this embedded APK (recursive drill-down). The UI
    /// renders these as a further "Embedded code" group under it.
    pub embedded: Vec<project::EmbeddedCandidate>,
}

/// Like [`project_load_embedded`], but parses the embedded APK into a child slot
/// **without** changing the active slot, and returns its tree so the UI can
/// expand it inline under the "Embedded APKs" group. Class/entry reads on the
/// returned `slot_id` go through `get_class_java` / `get_class_smali` /
/// `get_entry` with their `slot_id` argument set.
#[tauri::command]
pub async fn project_load_embedded_nested(
    parent_slot_id: String,
    entry_path: String,
    state: State<'_, AppState>,
) -> Result<EmbeddedLoadResult, String> {
    // Phase 1 — extract under a read-lock.
    let cache_path = {
        let project = state.project.read().await;
        let parent = project.find(&parent_slot_id)
            .ok_or_else(|| format!("Parent slot '{}' not found", parent_slot_id))?;
        project::extract_embedded_to_cache(parent, &entry_path, &state.cache_dir)?
    };
    let cache_path_str = cache_path.to_string_lossy().into_owned();

    // Phase 2 — parse as a fresh (inactive) child slot.
    let display_name_hint = std::path::Path::new(&entry_path)
        .file_name().and_then(|s| s.to_str()).unwrap_or("embedded").to_string();
    let slot = project::load_slot_from_disk(
        "", &display_name_hint, &cache_path_str, &[], Some(parent_slot_id.clone()), true,
    )?;
    if slot.dex_files.is_empty() {
        return Err("No DEX files found in embedded APK".into());
    }

    // Build the tree + capture nested payloads BEFORE moving the slot.
    let load = assemble_load_result(
        cache_path_str.clone(),
        &slot.dex_files,
        slot.manifest_xml.is_some(),
        slot.entry_names.iter().map(|(_, n)| n.clone()).collect(),
    );
    let embedded = slot.embedded_candidates.clone();

    // Phase 3 — register WITHOUT activating; persist.
    let mut project = state.project.write().await;
    let slot_id = project.upsert(slot);
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;

    Ok(EmbeddedLoadResult {
        slot_id,
        tree: load.tree,
        entry_names: load.entry_names,
        embedded,
    })
}

/// Static scan for `DexClassLoader` / `InMemoryDexClassLoader` /
/// `PathClassLoader` / `BaseDexClassLoader` / `DelegateLastClassLoader`
/// constructions across the active slot's DEX files. Returns one entry per
/// loader site, each with byte-source observations + statically resolvable
/// asset names from the same containing method.
#[tauri::command]
pub async fn analyze_dex_loaders(
    state: State<'_, AppState>,
) -> Result<Vec<dex_loader_analysis::DexLoaderSite>, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    Ok(dex_loader_analysis::analyze_all(&slot.dex_files))
}

// ═══════════════════════════════════════════════════════════════════════════
// Script-pane code completions (dynamic introspection of the platypus module)
// ═══════════════════════════════════════════════════════════════════════════
//
// Rather than hardcoding the platypus API surface in the frontend (which drifts
// every time we add a method to a PyO3 class), we run a small Python
// introspection script via subprocess. The script imports `platypus`, walks
// every class with `inspect.getmembers`, and emits a JSON description of every
// class/method/property — signatures, kinds, and docstrings.
//
// The frontend calls this once on app start, caches the result, and uses it to
// drive its CodeMirror autocomplete provider.

const INTROSPECT_SCRIPT: &str = r#"#!/usr/bin/env python3
"""Introspect the platypus module for the script panel's autocomplete."""
import inspect, json, sys, types

try:
    import platypus
except ImportError as e:
    print(json.dumps({"error": f"platypus module not importable: {e}"}))
    sys.exit(0)

def safe_signature(member):
    try:
        return str(inspect.signature(member))
    except (ValueError, TypeError):
        ts = getattr(member, "__text_signature__", None)
        return ts if isinstance(ts, str) else ""

def safe_doc(member, max_len=400):
    doc = inspect.getdoc(member)
    return (doc or "")[:max_len]

def member_kind(cls, name, member):
    raw = cls.__dict__.get(name)
    if isinstance(raw, staticmethod):    return "static_method"
    if isinstance(raw, classmethod):     return "class_method"
    if isinstance(raw, property):        return "property"
    if type(raw).__name__ == "getset_descriptor":  return "property"
    if isinstance(raw, types.MemberDescriptorType): return "property"
    if isinstance(member, types.BuiltinFunctionType): return "method"
    if callable(member): return "method"
    return "attribute"

def describe_class(cls):
    members = []
    for name in dir(cls):
        if name.startswith("_"): continue
        try:
            member = getattr(cls, name)
        except AttributeError:
            continue
        kind = member_kind(cls, name, member)
        members.append({
            "name": name,
            "kind": kind,
            "signature": safe_signature(member) if kind in ("method", "static_method", "class_method") else "",
            "doc": safe_doc(member),
        })
    members.sort(key=lambda m: m["name"])
    return {"name": cls.__name__, "doc": safe_doc(cls), "members": members}

classes  = {}
globals_ = []
for name in dir(platypus):
    if name.startswith("_"): continue
    obj = getattr(platypus, name)
    if inspect.isclass(obj):
        classes[name] = describe_class(obj)
    elif callable(obj):
        globals_.append({
            "name": name, "kind": "function",
            "signature": safe_signature(obj), "doc": safe_doc(obj),
        })

print(json.dumps({"classes": classes, "globals": globals_}))
"#;

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptCompletionsResult {
    /// Raw introspection JSON returned from the Python helper, parsed and
    /// re-emitted to the frontend. Pass-through to keep this layer dumb.
    pub introspection: serde_json::Value,
    /// True when the script ran but `platypus` couldn't be imported.
    pub platypus_unavailable: bool,
    /// Stderr from the Python invocation (only populated on actual failure).
    pub error: Option<String>,
}

/// Introspect the `platypus` module and return a description of every
/// class/method/property for use by the script panel's autocomplete.
#[tauri::command]
pub async fn script_get_completions(app: AppHandle) -> Result<ScriptCompletionsResult, String> {
    use std::io::Write;

    let project_root = resolve_pyroot(&app);

    // Wrap the introspection script with the same sys.path setup `run_script` uses
    // so the platypus extension module is reachable from the project venv.
    let wrapper = format!(
        "import sys as _sys\n_sys.path.insert(0, r\"{root}\")\n{body}",
        root = project_root,
        body = INTROSPECT_SCRIPT,
    );

    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    tmp.write_all(wrapper.as_bytes()).map_err(|e| e.to_string())?;
    let tmp_path = tmp.path().to_path_buf();

    let python = resolve_python(&app);
    let output = std::process::Command::new(&python)
        .arg(&tmp_path)
        .output()
        .map_err(|e| format!("Could not run python ({}): {e}", python.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    if !output.status.success() {
        return Ok(ScriptCompletionsResult {
            introspection: serde_json::json!({}),
            platypus_unavailable: true,
            error: Some(format!("python3 exited {}: {}",
                output.status.code().unwrap_or(-1), stderr)),
        });
    }

    // Parse the JSON the helper emitted on stdout.
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim())
        .map_err(|e| format!("Could not parse introspection output: {e}\nstdout was: {stdout}"))?;

    let error_msg = parsed.get("error")
        .and_then(|v| v.as_str())
        .map(String::from);
    let unavailable = error_msg.is_some();

    Ok(ScriptCompletionsResult {
        introspection: parsed,
        platypus_unavailable: unavailable,
        error: error_msg,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Script library — multiple named .py files under <cache>/scripts/
// ═══════════════════════════════════════════════════════════════════════════
//
// Each saved script is one file in the scripts subdirectory of the platypus
// cache dir. The "id" of a script is just its filename — we keep things
// boringly file-based so users can edit/share/back-up scripts with their
// existing tools.
//
// File layout: <cache_dir>/scripts/<safe-name>.py
//
// Names are restricted to a safe character set (alphanumerics, dash, underscore,
// dot, space) and forced to end in `.py`. Path-traversal attempts are rejected
// at the API boundary by `safe_script_name`.

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptInfo {
    pub name: String,
    pub size_bytes: u64,
    /// Last-modified time, milliseconds since the Unix epoch.
    pub last_modified_ms: i64,
}

fn scripts_dir(cache_dir: &std::path::Path) -> std::path::PathBuf {
    cache_dir.join("scripts")
}

/// Sanitise/normalise a script filename. Returns Err for path-traversal,
/// empty, or otherwise unsafe input.
fn safe_script_name(name: &str) -> Result<String, String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err("Script name cannot be empty".into());
    }
    // Reject path separators outright.
    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
        return Err(format!("Invalid script name: {}", trimmed));
    }
    // Restrict to a safe character set: alnum, `-`, `_`, `.`, space.
    if !trimmed.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | ' ')) {
        return Err(format!(
            "Script name contains disallowed characters: {} (allowed: a-z A-Z 0-9 - _ . space)",
            trimmed,
        ));
    }
    // Force the .py extension.
    let with_ext = if trimmed.to_lowercase().ends_with(".py") {
        trimmed.to_string()
    } else {
        format!("{}.py", trimmed)
    };
    Ok(with_ext)
}

fn ensure_scripts_dir(cache_dir: &std::path::Path) -> Result<std::path::PathBuf, String> {
    let dir = scripts_dir(cache_dir);
    std::fs::create_dir_all(&dir).map_err(|e| format!("Could not create scripts dir: {}", e))?;
    Ok(dir)
}

fn last_modified_ms(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[tauri::command]
pub async fn script_list(state: State<'_, AppState>) -> Result<Vec<ScriptInfo>, String> {
    let dir = ensure_scripts_dir(&state.cache_dir)?;
    let mut out = Vec::new();
    let entries = std::fs::read_dir(&dir).map_err(|e| e.to_string())?;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() { continue; }
        let name = match path.file_name().and_then(|s| s.to_str()) {
            Some(n) if n.to_lowercase().ends_with(".py") => n.to_string(),
            _ => continue,
        };
        let meta = match entry.metadata() { Ok(m) => m, Err(_) => continue };
        out.push(ScriptInfo {
            name,
            size_bytes: meta.len(),
            last_modified_ms: last_modified_ms(&meta),
        });
    }
    // Stable ordering by name so the tab bar doesn't shuffle on every reload.
    out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    Ok(out)
}

#[tauri::command]
pub async fn script_load(name: String, state: State<'_, AppState>) -> Result<String, String> {
    let safe = safe_script_name(&name)?;
    let dir = ensure_scripts_dir(&state.cache_dir)?;
    let path = dir.join(&safe);
    std::fs::read_to_string(&path).map_err(|e| format!("Could not read {}: {}", safe, e))
}

/// Save (creating if necessary). Returns the (possibly normalised) name used.
#[tauri::command]
pub async fn script_save(
    name: String,
    content: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let safe = safe_script_name(&name)?;
    let dir = ensure_scripts_dir(&state.cache_dir)?;
    let path = dir.join(&safe);
    std::fs::write(&path, content.as_bytes())
        .map_err(|e| format!("Could not write {}: {}", safe, e))?;
    Ok(safe)
}

#[tauri::command]
pub async fn script_create(
    name: String,
    initial_content: Option<String>,
    state: State<'_, AppState>,
) -> Result<ScriptInfo, String> {
    let safe = safe_script_name(&name)?;
    let dir = ensure_scripts_dir(&state.cache_dir)?;
    let path = dir.join(&safe);
    if path.exists() {
        return Err(format!("Script {} already exists", safe));
    }
    let body = initial_content.unwrap_or_default();
    std::fs::write(&path, body.as_bytes())
        .map_err(|e| format!("Could not create {}: {}", safe, e))?;
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    Ok(ScriptInfo {
        name: safe,
        size_bytes: meta.len(),
        last_modified_ms: last_modified_ms(&meta),
    })
}

#[tauri::command]
pub async fn script_delete(name: String, state: State<'_, AppState>) -> Result<(), String> {
    let safe = safe_script_name(&name)?;
    let dir = ensure_scripts_dir(&state.cache_dir)?;
    let path = dir.join(&safe);
    if !path.exists() {
        return Ok(()); // idempotent
    }
    std::fs::remove_file(&path).map_err(|e| format!("Could not delete {}: {}", safe, e))?;
    Ok(())
}

#[tauri::command]
pub async fn script_rename(
    old_name: String,
    new_name: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let safe_old = safe_script_name(&old_name)?;
    let safe_new = safe_script_name(&new_name)?;
    if safe_old == safe_new {
        return Ok(safe_new);
    }
    let dir = ensure_scripts_dir(&state.cache_dir)?;
    let old_path = dir.join(&safe_old);
    let new_path = dir.join(&safe_new);
    if !old_path.exists() {
        return Err(format!("Script {} doesn't exist", safe_old));
    }
    if new_path.exists() {
        return Err(format!("Script {} already exists", safe_new));
    }
    std::fs::rename(&old_path, &new_path).map_err(|e| format!("Could not rename: {}", e))?;
    Ok(safe_new)
}

/// Returns the resolved scripts directory path (e.g. for "Reveal in Finder").
#[tauri::command]
pub async fn script_dir(state: State<'_, AppState>) -> Result<String, String> {
    let dir = ensure_scripts_dir(&state.cache_dir)?;
    Ok(dir.to_string_lossy().into_owned())
}

// ═══════════════════════════════════════════════════════════════════════════
// Activity viewer (phase 4 — Project Platypus integration)
// ═══════════════════════════════════════════════════════════════════════════
//
// Three commands wrap the platypus-rehydrate crate against the active slot:
//
//   * `activity_list` — shaped to match the JS `ActivitySummary` type in
//     `@platypus/activity-viewer`. Pulls activities from the typed manifest.
//   * `activity_rehydrate` — runs `platypus_rehydrate::rehydrate_activity`
//     and returns the IR as a JSON value (camelCase via serde rename_all).
//   * `open_activity_viewer_window` — Tauri WebviewWindow opener with
//     focus-if-already-open, mirroring the search/taint window pattern.

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ActivitySummary {
    pub name: String,
    pub label: Option<String>,
    pub is_launcher: bool,
    pub exported: bool,
}

/// List every activity in the active slot with summary info for the picker.
#[tauri::command]
pub async fn activity_list(
    state: State<'_, AppState>,
) -> Result<Vec<ActivitySummary>, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;

    let apk = open_apk_zip(&slot.base_path)?;
    let resources = open_resources(&apk).ok();
    let manifest = open_typed_manifest(&apk, resources.as_ref())?;

    let pkg = manifest.package().unwrap_or("").to_string();
    let activities = manifest.activities().into_iter()
        .map(|a| ActivitySummary {
            name: a.resolve_name(&pkg),
            label: a.label.clone(),
            is_launcher: a.is_launcher(),
            exported: a.exported.unwrap_or(false),
        })
        .collect();
    Ok(activities)
}

/// Rehydrate one activity to its UnifiedView IR. Returns serde_json::Value
/// so the camelCase shape matches the TS `ActivityView` type without a
/// hand-rolled per-field serializer.
#[tauri::command]
pub async fn activity_rehydrate(
    activity_name: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;

    // Re-parse fresh — platypus-rehydrate takes borrowed &ApkZip /
    // &Resources, and ResourceTable doesn't impl Clone cheaply. Cost is
    // one ZIP central-directory parse + one arsc parse per request,
    // measured in milliseconds even on big APKs.
    let apk = open_apk_zip(&slot.base_path)?;
    let resources = open_resources(&apk)?;

    let mut view = project_platypus_native::rehydrate::rehydrate_activity(
        &apk, &activity_name, &resources, &slot.dex_files,
    );

    // Apply the active dexmapper mapping (if any) in place. Pure string
    // rewrite; the IR shape and types are preserved so renderers don't
    // need to care whether a mapping was loaded.
    if let Some(deob) = state.deobfuscator.read().await.as_ref() {
        deob.apply_to_activity_view(&mut view);
    }

    serde_json::to_value(&view)
        .map_err(|e| format!("Could not serialise rehydration result: {e}"))
}

/// Effective theme for an activity — backs `ViewerApi.theme()` for the
/// HTML/CSS renderer (R1). Resolution chain: activity-level
/// `android:theme` → `<application android:theme>` → bundled Material 3
/// defaults.
#[tauri::command]
pub async fn activity_theme(
    activity_name: String,
    state: State<'_, AppState>,
) -> Result<serde_json::Value, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;

    let apk = open_apk_zip(&slot.base_path)?;
    let resources = open_resources(&apk)?;
    let manifest = open_typed_manifest(&apk, Some(&resources))?;
    let pkg = manifest.package().unwrap_or("").to_string();

    let theme_ref = manifest.activities().into_iter()
        .find(|a| a.resolve_name(&pkg) == activity_name)
        .and_then(|a| a.theme.clone())
        .or_else(|| manifest.application().and_then(|app| app.theme.clone()));

    let theme = match theme_ref.as_deref() {
        Some(r) => resolve_theme_ref(r, &resources),
        None => resources.theme(0),
    };

    serde_json::to_value(&theme)
        .map_err(|e| format!("Could not serialise theme: {e}"))
}

/// Take a raw `android:theme` value (`@style/Theme.MyApp`,
/// `@android:style/Theme.Material.Light`, or a resolved `@0x...` id) and
/// turn it into the effective `Theme`. Falls back to bundled defaults if
/// the reference can't be resolved (e.g. a framework-only theme).
fn resolve_theme_ref(
    raw: &str,
    resources: &project_platypus_native::resources::Resources,
) -> project_platypus_native::resources::theme::Theme {
    use project_platypus_native::resources::refs::{parse_reference, Reference};
    if let Some(r) = parse_reference(raw) {
        match r {
            Reference::Id(id) => return resources.theme(id),
            Reference::Named { type_name, name, package } => {
                if package.as_deref() != Some("android") && type_name == "style" {
                    if let Some(t) = resources.theme_by_name(&name) {
                        return t;
                    }
                }
            }
            _ => {}
        }
    }
    resources.theme(0)
}

/// Open (or focus) the activity-viewer window. Optional `initial_activity`
/// is encoded into the hash so the window lands on that activity directly.
#[tauri::command]
pub async fn open_activity_viewer_window(
    app: AppHandle,
    initial_activity: Option<String>,
) -> Result<(), String> {
    let label = "activity-viewer";
    if let Some(win) = app.get_webview_window(label) {
        win.set_focus().ok();
        // Notify the existing window of the new initial activity (if any),
        // mirroring the taint:navigate pattern.
        if let Some(name) = initial_activity {
            app.emit("activity-viewer:navigate", serde_json::json!({
                "activityName": name,
            })).map_err(|e| e.to_string())?;
        }
        return Ok(());
    }

    let url = match initial_activity {
        Some(name) => format!("/#/activity-viewer?activity={}",
                              urlencoding::encode(&name)),
        None => "/#/activity-viewer".to_string(),
    };
    WebviewWindowBuilder::new(&app, label, WebviewUrl::App(url.into()))
        .title("Activity Viewer")
        .inner_size(1200.0, 800.0)
        .min_inner_size(720.0, 480.0)
        .resizable(true)
        .build()
        .map_err(|e| e.to_string())?;
    Ok(())
}

// ═══════════════════════════════════════════════════════════════════════════
// Dexmapper integration
// ═══════════════════════════════════════════════════════════════════════════
//
// Four commands manage a Deobfuscator held in app state:
//   * `load_mapping_dialog` — pick a JSON or ProGuard mapping via the OS dialog
//   * `load_mapping`        — load from an explicit path
//   * `current_mapping`     — info about the loaded mapping (or `None`)
//   * `clear_mapping`       — drop the loaded mapping
//
// While a mapping is loaded, `activity_rehydrate` rewrites every class /
// method ref in the returned IR so the frontend's tree, code, and graph
// views show real library names instead of single-letter R8 aliases.

#[tauri::command]
pub async fn load_mapping_dialog(
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Option<platypus_dexmapper::MappingInfo>, String> {
    use tauri_plugin_dialog::{DialogExt, FilePath};
    let (tx, rx) = tokio::sync::oneshot::channel::<Option<FilePath>>();
    app.dialog()
        .file()
        .add_filter("Dexmapper mappings", &["json", "txt", "map", "proguard"])
        .pick_file(move |selected| { let _ = tx.send(selected); });
    let selected = rx.await.map_err(|e| e.to_string())?;
    let Some(p) = selected.and_then(|fp| fp.into_path().ok()) else {
        return Ok(None);
    };
    let deob = platypus_dexmapper::Deobfuscator::load(&p)?;
    let info = deob.info();
    *state.deobfuscator.write().await = Some(deob);
    Ok(Some(info))
}

#[tauri::command]
pub async fn load_mapping(
    path: String,
    state: State<'_, AppState>,
) -> Result<platypus_dexmapper::MappingInfo, String> {
    let deob = platypus_dexmapper::Deobfuscator::load(&path)?;
    let info = deob.info();
    *state.deobfuscator.write().await = Some(deob);
    Ok(info)
}

#[tauri::command]
pub async fn current_mapping(
    state: State<'_, AppState>,
) -> Result<Option<platypus_dexmapper::MappingInfo>, String> {
    Ok(state.deobfuscator.read().await.as_ref().map(|d| d.info()))
}

#[tauri::command]
pub async fn clear_mapping(state: State<'_, AppState>) -> Result<(), String> {
    *state.deobfuscator.write().await = None;
    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn open_apk_zip(
    base_path: &str,
) -> Result<project_platypus_native::apk::zip::ApkZip, String> {
    use project_platypus_native::apk::zip::ApkZip;
    ApkZip::open(base_path)
        .map_err(|e| format!("Could not open {}: {}", base_path, e))
}

/// Parse `resources.arsc` from `apk` and wrap as a typed
/// [`Resources`](platypus_resources::Resources) — the one with by-name
/// lookups and reference-resolution helpers.
fn open_resources(
    apk: &project_platypus_native::apk::zip::ApkZip,
) -> Result<project_platypus_native::resources::Resources, String> {
    use project_platypus_native::apk::arsc;
    use project_platypus_native::resources::Resources;
    let bytes = apk.read_entry("resources.arsc")
        .map_err(|e| format!("Could not read resources.arsc: {e}"))?;
    let table = arsc::parse(&bytes)
        .map_err(|e| format!("resources.arsc parse failed: {e}"))?;
    Ok(Resources::new(table))
}

/// Parse the manifest into a typed `Manifest` with `@-references` resolved
/// when `resources` is supplied.
fn open_typed_manifest(
    apk: &project_platypus_native::apk::zip::ApkZip,
    resources: Option<&project_platypus_native::resources::Resources>,
) -> Result<project_platypus_native::resources::Manifest, String> {
    use project_platypus_native::apk::axml;
    use project_platypus_native::resources::Manifest;

    let bytes = apk.read_entry("AndroidManifest.xml")
        .map_err(|e| format!("Could not read AndroidManifest.xml: {e}"))?;
    let root = match resources {
        Some(r) => axml::parse_with_resources(&bytes, r.table()),
        None    => axml::parse(&bytes),
    }.map_err(|e| format!("Manifest parse failed: {e}"))?;
    let m = Manifest::from_xml(root);
    Ok(match resources {
        Some(r) => m.resolved(r),
        None    => m,
    })
}

// ── DEOBFUSCATION marks ──────────────────────────────────────────────────────
//
// User-curated list of methods that act as deobfuscation helpers. The
// list is persisted per-slot (see `Slot::deobf_marks`) so reopening an
// APK restores whatever the user marked previously.
//
// API surface:
//   deobf_mark_method   — add a (class, method) mark to the active slot
//   deobf_unmark_method — remove a mark
//   deobf_list_marks    — return the active slot's marks (sorted, stable order)
//   deobf_scan_sites    — static-only call-site scan (no VM exec, no resolved values)
//   deobf_run_all_marks — execute every call site of every marked method;
//                         returns grouped results suitable for the bottom-bar tab
//
// Single-site execution and single-method bulk execution reuse the
// existing `run_method` and `find_exec` commands respectively — the
// frontend already knows how to drive them, and there's no value in
// duplicating that surface here.

/// One marked method, ready for the frontend list view.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeobfMarkItem {
    /// Normalised class name (no `L`/`;`), e.g. `com/dualtext/compare/SystemSingleton`.
    pub class_name: String,
    /// Bare method name (no proto), e.g. `KotlinClass`.
    pub method_name: String,
}

/// One call site of a marked method. Returned by `deobf_scan_sites` —
/// purely static, no VM execution. The frontend uses this to populate
/// the per-method expanded view with literal args; an actual deobf run
/// then goes through `run_method` (single) or `deobf_run_all_marks`
/// (bulk).
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeobfSiteItem {
    pub caller_class: String,
    pub caller_method: String,
    pub offset: u32,
    /// The full invoke instruction text (helpful as a stable display).
    pub call_site: String,
    /// Statically resolved literal arg values, encoded as strings using
    /// the same format `resolve_arg_encoding` understands (quoted
    /// strings, bare ints/hex, `@sget:…`, `@invoke!…`). The frontend
    /// shows these inline so the user can see *what* would be passed
    /// before deciding to run.
    pub static_args: Vec<String>,
}

/// One marked method's execution results, used by `deobf_run_all_marks`.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeobfBulkResultItem {
    pub class_name: String,
    pub method_name: String,
    /// One entry per call site executed (same shape as `find_exec`).
    pub sites: Vec<ExecResultItem>,
}

/// Normalise a class name to the form `Slot::deobf_marks` stores
/// (`L…;` wrappers stripped). The frontend may pass either form.
fn normalise_class(s: &str) -> String {
    s.trim_start_matches('L').trim_end_matches(';').to_string()
}

#[tauri::command]
pub async fn deobf_mark_method(
    class_name: String,
    method_name: String,
    state: State<'_, AppState>,
) -> Result<Vec<DeobfMarkItem>, String> {
    let mut project = state.project.write().await;
    let active_id = project.active_slot_id.clone()
        .ok_or_else(|| "No APK loaded".to_string())?;
    let slot = project.find_mut(&active_id)
        .ok_or_else(|| "Active slot lookup failed".to_string())?;

    let key = (normalise_class(&class_name), method_name);
    slot.deobf_marks.insert(key);
    let marks: Vec<DeobfMarkItem> = slot.deobf_marks.iter()
        .map(|(c, m)| DeobfMarkItem {
            class_name: c.clone(),
            method_name: m.clone(),
        })
        .collect();
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(marks)
}

#[tauri::command]
pub async fn deobf_unmark_method(
    class_name: String,
    method_name: String,
    state: State<'_, AppState>,
) -> Result<Vec<DeobfMarkItem>, String> {
    let mut project = state.project.write().await;
    let active_id = project.active_slot_id.clone()
        .ok_or_else(|| "No APK loaded".to_string())?;
    let slot = project.find_mut(&active_id)
        .ok_or_else(|| "Active slot lookup failed".to_string())?;

    let key = (normalise_class(&class_name), method_name);
    slot.deobf_marks.remove(&key);
    let marks: Vec<DeobfMarkItem> = slot.deobf_marks.iter()
        .map(|(c, m)| DeobfMarkItem {
            class_name: c.clone(),
            method_name: m.clone(),
        })
        .collect();
    project.save(&state.cache_dir).map_err(|e| e.to_string())?;
    Ok(marks)
}

#[tauri::command]
pub async fn deobf_list_marks(
    state: State<'_, AppState>,
) -> Result<Vec<DeobfMarkItem>, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    Ok(slot.deobf_marks.iter()
        .map(|(c, m)| DeobfMarkItem {
            class_name: c.clone(),
            method_name: m.clone(),
        })
        .collect())
}

#[tauri::command]
pub async fn deobf_scan_sites(
    class_name: String,
    method_name: String,
    state: State<'_, AppState>,
) -> Result<Vec<DeobfSiteItem>, String> {
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;

    // Build the same target pattern format `find_calls` / `find_exec` use:
    // `Lcom/Foo;->bar` (no proto — matches any overload).
    let class_norm = normalise_class(&class_name);
    let target = format!("L{};->{}", class_norm, method_name);

    let mut items = Vec::new();
    for dex in slot.dex_files.iter() {
        for site in analysis::find_calls(dex, &target) {
            // Map static_args (Vec<(u32, Option<String>)>) into the
            // frontend-friendly Vec<String>. We drop the register
            // index — the UI only cares about the literal values for
            // display purposes; ordering is the call's positional
            // argument order.
            let static_args: Vec<String> = site.static_args.iter()
                .map(|(_, v)| v.as_deref().unwrap_or("(none)").to_string())
                .collect();
            items.push(DeobfSiteItem {
                caller_class: site.caller_class,
                caller_method: site.caller_method,
                offset: site.invoke_cp,
                call_site: site.invoke_str,
                static_args,
            });
        }
    }
    Ok(items)
}

/// Execute every call site of every marked method in the active slot.
/// Returns grouped results so the UI can render per-method sections.
///
/// **Parallelisation:** under the hood this farms work to rayon's
/// global thread pool in two layers:
///   1. Each mark is its own rayon task — N marks run concurrently
///      bounded by the pool's worker count.
///   2. Within a mark, the call sites are split across workers via
///      `find_and_exec_parallel`, so single-method bulk runs also
///      benefit even when there's only one mark.
/// Net effect: the frontend issues one Tauri call (O(1)), and
/// wall-clock scales close to linearly with available cores until
/// the slowest individual deobfuscator dominates.
///
/// `instr_limit` follows the same default as `find_exec` (5M) — bumps it
/// for AES-CBC-style heavy deobfuscators by passing a larger limit.
///
/// `num_threads`:
///   - `None` or `Some(0)` → use rayon's default (`num_cpus`).
///   - `Some(1)`           → strictly sequential (matches old behaviour).
///   - `Some(n)`           → hard cap, but rayon's global pool still
///     limits actual parallelism — see the module-level comment on
///     `exec_calls_parallel` for why we don't spawn private pools.
#[tauri::command]
pub async fn deobf_run_all_marks(
    instr_limit: Option<u64>,
    num_threads: Option<usize>,
    state: State<'_, AppState>,
) -> Result<Vec<DeobfBulkResultItem>, String> {
    // Read the slot under the project lock. We hold the lock for the
    // entire run — that's safe because mark/unmark (the writers) will
    // simply queue behind us, and with rayon parallelism the run is
    // typically seconds, not minutes. The previous "snapshot then
    // release" model can't work directly because `ResourceTable`
    // isn't Clone; rather than refactor analysis::* to accept the
    // resource-strings projection separately, we just hold the lock.
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let marks: Vec<(String, String)> = slot.deobf_marks.iter().cloned().collect();

    // Pick the chunking width. 0/None → "let rayon decide" (we still
    // need a positive int for the chunker so we use the pool's
    // worker count as the upper bound). 1 → sequential fallback.
    let threads_for_chunking = match num_threads {
        Some(0) | None => rayon::current_num_threads().max(1),
        Some(n)        => n.max(1),
    };

    // Per-mark rayon farm. `into_par_iter` here means each mark runs
    // on its own worker; within the worker, `find_and_exec_parallel`
    // splits sites across a second tier of workers. Both `dex_files`
    // and `resources` are `Sync` (held behind the read lock), so the
    // rayon workers borrow them directly.
    use rayon::prelude::*;
    let groups: Vec<DeobfBulkResultItem> = marks
        .par_iter()
        .map(|(class_norm, method_name)| {
            let target = format!("L{};->{}", class_norm, method_name);
            let mut sites: Vec<ExecResultItem> = Vec::new();

            for dex in slot.dex_files.iter() {
                let results = analysis::find_and_exec_parallel(
                    dex,
                    &target,
                    slot.resources.as_ref(),
                    instr_limit,
                    threads_for_chunking,
                );
                for (site, value) in results {
                    let (resolved_value, resolved_type, error) = match &value {
                        Some(v) => (format_value(v), infer_type(v), None),
                        None    => ("(no result)".into(), "void".into(), None),
                    };
                    let suggested = format!("{}_cp{}.apk",
                        site.caller_method.split('(').next().unwrap_or("exec"),
                        site.invoke_cp);
                    let apk_cache_path = try_cache_apk_value(value.as_ref(), &state.cache_dir, &suggested);
                    sites.push(ExecResultItem {
                        call_site: site.invoke_str.clone(),
                        caller_class: site.caller_class,
                        caller_method: site.caller_method,
                        offset: site.invoke_cp,
                        resolved_value,
                        resolved_type,
                        error,
                        apk_cache_path,
                    });
                }
            }

            DeobfBulkResultItem {
                class_name: class_norm.clone(),
                method_name: method_name.clone(),
                sites,
            }
        })
        .collect();

    Ok(groups)
}

// ── deobf_run_specific_sites ─────────────────────────────────────────────────
//
// Granular execution path for the DEOBFUSCATION tab's per-row ▶ and
// "Deobfuscate Shown" buttons. The frontend ships a list of
// (className, methodName, args, callerClass, offset) tuples — one
// per call site the user wants to execute right now — and we run
// them in parallel via rayon, returning ExecResults in the same
// order so the UI can correlate by position.
//
// Stays at **1 IPC call** regardless of how many sites the user
// selected; same O(1) round-trip story as `deobf_run_all_marks`.
// The per-mark static scan + result cache in the frontend means we
// never have to re-do the (expensive) call-site discovery here —
// the caller already knows exactly which sites it wants.

/// One specific call site the frontend wants executed.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeobfSiteRunRequest {
    /// Deobfuscator class (L/;-stripped or wrapped — both work).
    pub class_name: String,
    pub method_name: String,
    /// Argument values encoded with the same format `run_method` and
    /// `resolve_arg_encoding` understand. Comes straight from the
    /// `staticArgs` field returned by `deobf_scan_sites`.
    pub args: Vec<String>,
    /// Caller info — purely for echoing back in the result so the
    /// frontend can pair the response with the originating row.
    pub caller_class: String,
    pub caller_method: String,
    pub offset: u32,
    pub call_site: String,
}

#[tauri::command]
pub async fn deobf_run_specific_sites(
    sites: Vec<DeobfSiteRunRequest>,
    instr_limit: Option<u64>,
    num_threads: Option<usize>,
    state: State<'_, AppState>,
) -> Result<Vec<ExecResultItem>, String> {
    use project_platypus_native::vm::value::Value;
    use project_platypus_native::analysis::{resolve_arg_encoding, find_method_in_dex};
    use rayon::prelude::*;

    if sites.is_empty() {
        return Ok(Vec::new());
    }

    // Hold the read lock for the duration (same reasoning as
    // deobf_run_all_marks — ResourceTable isn't Clone and the run is
    // short enough that mark/unmark writers won't notice).
    let project = state.project.read().await;
    let slot = project.active().ok_or_else(|| "No APK loaded".to_string())?;
    let dex_files = &slot.dex_files;
    let resources = slot.resources.as_ref();

    // Cap rayon chunking the same way as the other deobf commands so
    // the user's thread-count slider has consistent meaning.
    let threads = match num_threads {
        Some(0) | None => rayon::current_num_threads().max(1),
        Some(n)        => n.max(1),
    };

    // Build a rayon pool scoped to this call so we can honour the
    // user's thread count without disturbing the global pool. For
    // n == rayon::current_num_threads() this is a no-op clone of the
    // global behaviour; for smaller n it caps parallelism.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .build()
        .map_err(|e| format!("Failed to build thread pool: {e}"))?;

    // ── Dedupe pre-pass ──
    // Deobfuscators are pure functions of their static_args (same
    // invariant exec_usages in the CLI exploits via its per-batch
    // result cache). Two sites that share a fingerprint MUST decrypt
    // to the same plaintext, so we collapse them to one VM run per
    // unique input and scatter the result back to every original site
    // afterwards. Big win when the user clicks "Deobfuscate Shown" on
    // a method invoked many times with a small set of distinct args
    // (e.g. Math.max-style helpers).
    let fingerprints: Vec<String> = sites.iter().map(|req| {
        let static_args: Vec<(u32, Option<String>)> = req.args.iter()
            .enumerate()
            .map(|(i, s)| (
                i as u32,
                if s == "(none)" { None } else { Some(s.clone()) },
            ))
            .collect();
        analysis::static_args_fingerprint(&static_args)
    }).collect();

    // First-occurrence index per fingerprint — preserves a stable
    // "representative site" for each group without losing ordering of
    // unique work.
    let mut unique_order: Vec<(String, usize)> = Vec::new();
    let mut seen: HashMap<String, ()> = HashMap::new();
    for (idx, fp) in fingerprints.iter().enumerate() {
        if seen.insert(fp.clone(), ()).is_none() {
            unique_order.push((fp.clone(), idx));
        }
    }

    let total = sites.len();
    let unique = unique_order.len();
    let pct = if total > 0 { (total - unique) as f64 * 100.0 / total as f64 } else { 0.0 };
    eprintln!(
        "[deobf_run_specific_sites] dedupe: {} unique / {} total ({:.1}% saved)",
        unique, total, pct,
    );

    // Cached payload shared across sites with the same fingerprint.
    // We deliberately store the post-format strings (not the raw
    // Value) so Bytes results don't get cloned per duplicate. The
    // apk_cache_path is content-addressed (sha256 of bytes), so the
    // representative site's path is correct for every duplicate as
    // well — no need to rerun try_cache_apk_value during scatter.
    struct CachedExec {
        resolved_value: String,
        resolved_type:  String,
        error:          Option<String>,
        apk_cache_path: Option<String>,
    }

    // ── Parallel execution over UNIQUE fingerprints ──
    let computed: Vec<(String, CachedExec)> = pool.install(|| {
        unique_order.par_iter().map_init(
            // Built ONCE per rayon worker thread and reused across every
            // fingerprint that thread handles (rayon's map_init contract).
            // This amortizes the O(total classes) index build + resource
            // load over the thread count instead of paying it per unique
            // input — previously the dominant overhead on large apps.
            // Reusing one VM across many calls is the same pattern
            // `exec_calls` uses; each call is isolated by `reset_for_call`
            // and call_method's per-call register file, while the shared
            // class_index / method_cache make repeated lookups free.
            || {
                let mut vm = Vm::new();
                for dex in dex_files.iter() {
                    vm.add_dex_file(dex);
                }
                if let Some(table) = resources {
                    vm.load_resources(
                        table.entries().iter()
                            .filter(|e| e.type_name == "string")
                            .filter_map(|e| table.resolve(e.id).map(|v| (e.id, v)))
                    );
                }
                vm
            },
            |vm, (fp, idx)| {
            let req = &sites[*idx];

            // Locate the target method. Try each dex until one resolves —
            // we don't know which dex hosts the deobfuscator. The
            // per-thread VM's method_cache absorbs repeated lookups of the
            // same method across fingerprints.
            let target_method = dex_files.iter()
                .find_map(|dex| find_method_in_dex(dex, &req.class_name, &req.method_name));

            let target_method = match target_method {
                Some(m) => m,
                None    => return (fp.clone(), CachedExec {
                    resolved_value: "(method not found)".into(),
                    resolved_type:  "void".into(),
                    error: Some(format!("Could not resolve {}->{}", req.class_name, req.method_name)),
                    apk_cache_path: None,
                }),
            };

            vm.reset_for_call(instr_limit.unwrap_or(5_000_000));

            // Rebuild the (register, Option<encoding>) shape that
            // `coalesce_call_args` expects: the frontend collapsed
            // unresolved registers to the literal sentinel "(none)"
            // back in `deobf_scan_sites`, so reverse that here. The
            // register IDs themselves are irrelevant to the coalescer
            // (it only cares about positional layout), so we use the
            // arg index as a stand-in. Identical to the shape we
            // fingerprinted with above — same encoding, same key.
            let static_args: Vec<(u32, Option<String>)> = req.args.iter()
                .enumerate()
                .map(|(i, s)| (
                    i as u32,
                    if s == "(none)" { None } else { Some(s.clone()) },
                ))
                .collect();

            // Coalesce wide args (J/D) — without this, `(J)`
            // deobfuscators receive the long across two slots wrong
            // (full value in the high slot, Null in the low slot)
            // and decrypt to garbage. Same fix as `--find-exec` in
            // the CLI; see `coalesce_call_args` for the rationale.
            let arg_values = project_platypus_native::analysis::coalesce_call_args(
                &static_args,
                &req.call_site,
                &target_method.proto_desc,
                resources,
                vm,
            );
            vm.reset_for_call(instr_limit.unwrap_or(5_000_000));
            let result = vm.call_method(&target_method, arg_values);

            let (resolved_value, resolved_type, error) = match &result {
                Some(v) => (format_value(v), infer_type(v), None),
                None    => ("(no result)".into(), "void".into(), None),
            };
            let suggested = format!("{}_cp{}.apk",
                req.caller_method.split('(').next().unwrap_or("exec"),
                req.offset);
            let apk_cache_path = try_cache_apk_value(result.as_ref(), &state.cache_dir, &suggested);

            (fp.clone(), CachedExec { resolved_value, resolved_type, error, apk_cache_path })
        },
        ).collect()
    });

    let cache: HashMap<String, CachedExec> = computed.into_iter().collect();

    // ── Scatter ──
    // Walk the original sites vec and stamp each one with the cached
    // payload for its fingerprint. The caller/site-identity fields are
    // taken from the original request so the frontend can still pair
    // every response with its originating row.
    let items: Vec<ExecResultItem> = sites.iter().zip(fingerprints.iter())
        .map(|(req, fp)| {
            let cached = &cache[fp];
            ExecResultItem {
                call_site:    req.call_site.clone(),
                caller_class: req.caller_class.clone(),
                caller_method: req.caller_method.clone(),
                offset:       req.offset,
                resolved_value: cached.resolved_value.clone(),
                resolved_type:  cached.resolved_type.clone(),
                error:          cached.error.clone(),
                apk_cache_path: cached.apk_cache_path.clone(),
            }
        })
        .collect();

    Ok(items)
}

// ── UI state persistence (cross-platform, file-backed) ──────────────────────
//
// The frontend persists its UI state (settings, per-slot deobf/rename
// snapshots, the active script name, search history) to `localStorage`.
// That works on macOS (WKWebView) and Windows (WebView2), but **not on
// Linux**: the Tauri webview is WebKitGTK, which does not persist
// `localStorage` across restarts for the custom `tauri://` origin — so on
// Ubuntu the state silently vanishes on every relaunch.
//
// These commands give the frontend a durable key→value store backed by
// files under `<cache_dir>/ui_state/`, which works identically on all
// three platforms. The frontend keeps using `localStorage` as a fast
// same-session cache and mirrors writes here; on a fresh launch it reads
// back from here when `localStorage` is empty. Values are opaque strings
// (the frontend stores JSON); we never parse them.

/// Sanitise a UI-state key into a safe single-path-segment filename.
/// The frontend only uses a small fixed set of ASCII keys, but we guard
/// against path traversal regardless.
fn ui_state_filename(key: &str) -> String {
    // Allow only `[A-Za-z0-9_-]`; everything else (including `.` and `/`)
    // becomes `_`. Dropping `.` entirely means no `.`/`..` segment can
    // survive, so path traversal is impossible by construction.
    let s: String = key
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' })
        .collect();
    if s.is_empty() { "_".to_string() } else { s }
}

fn ui_state_dir(cache_dir: &std::path::Path) -> std::path::PathBuf {
    cache_dir.join("ui_state")
}

// Pure file-store helpers (no Tauri State) so the round-trip is unit-testable.

fn ui_state_read(cache_dir: &std::path::Path, key: &str) -> std::io::Result<Option<String>> {
    let path = ui_state_dir(cache_dir).join(ui_state_filename(key));
    match std::fs::read_to_string(&path) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

fn ui_state_write(cache_dir: &std::path::Path, key: &str, value: &str) -> std::io::Result<()> {
    let dir = ui_state_dir(cache_dir);
    std::fs::create_dir_all(&dir)?;
    let name = ui_state_filename(key);
    let path = dir.join(&name);
    // Atomic-ish write: write to a temp file then rename into place so a
    // crash mid-write can't truncate the previous good state.
    let tmp = dir.join(format!("{name}.tmp"));
    std::fs::write(&tmp, value.as_bytes())?;
    std::fs::rename(&tmp, &path)?;
    Ok(())
}

fn ui_state_delete(cache_dir: &std::path::Path, key: &str) -> std::io::Result<()> {
    let path = ui_state_dir(cache_dir).join(ui_state_filename(key));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

#[tauri::command]
pub async fn ui_state_get(
    key: String,
    state: State<'_, AppState>,
) -> Result<Option<String>, String> {
    ui_state_read(&state.cache_dir, &key).map_err(|e| format!("ui_state_get {key}: {e}"))
}

#[tauri::command]
pub async fn ui_state_set(
    key: String,
    value: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    ui_state_write(&state.cache_dir, &key, &value).map_err(|e| format!("ui_state_set {key}: {e}"))
}

#[tauri::command]
pub async fn ui_state_remove(
    key: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    ui_state_delete(&state.cache_dir, &key).map_err(|e| format!("ui_state_remove {key}: {e}"))
}

#[cfg(test)]
mod search_helper_tests {
    use super::{
        parse_qualified_query, parse_ref, ui_state_delete, ui_state_filename, ui_state_read,
        ui_state_write,
    };

    #[test]
    fn ui_state_file_round_trip() {
        // Use a unique temp dir to mimic the app cache dir.
        let base = std::env::temp_dir().join(format!("platypus_uistate_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);

        // Missing key reads as None.
        assert_eq!(ui_state_read(&base, "platypus_cache").unwrap(), None);

        // Write → read round-trips the exact (JSON) payload.
        let payload = r#"{"settings":{"fontSize":13},"slotFrontendStates":{}}"#;
        ui_state_write(&base, "platypus_cache", payload).unwrap();
        assert_eq!(ui_state_read(&base, "platypus_cache").unwrap().as_deref(), Some(payload));

        // Overwrite replaces cleanly (atomic rename, no leftover .tmp surfacing).
        ui_state_write(&base, "platypus_cache", "v2").unwrap();
        assert_eq!(ui_state_read(&base, "platypus_cache").unwrap().as_deref(), Some("v2"));

        // A second key is independent.
        ui_state_write(&base, "platypus_active_script", "scratch.py").unwrap();
        assert_eq!(ui_state_read(&base, "platypus_active_script").unwrap().as_deref(), Some("scratch.py"));
        assert_eq!(ui_state_read(&base, "platypus_cache").unwrap().as_deref(), Some("v2"));

        // Remove is idempotent.
        ui_state_delete(&base, "platypus_cache").unwrap();
        assert_eq!(ui_state_read(&base, "platypus_cache").unwrap(), None);
        ui_state_delete(&base, "platypus_cache").unwrap(); // second remove: no error

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ui_state_key_sanitisation() {
        assert_eq!(ui_state_filename("platypus_cache"), "platypus_cache");
        assert_eq!(ui_state_filename("platypus_active_script"), "platypus_active_script");
        // Path-traversal attempts collapse to safe single-segment names
        // (no `.` survives, so `..` / `/` can't escape the dir).
        assert_eq!(ui_state_filename("../etc/passwd"), "___etc_passwd");
        assert_eq!(ui_state_filename(".."), "__");
        assert_eq!(ui_state_filename(""), "_");
        assert!(!ui_state_filename("../../x").contains('.'));
        assert!(!ui_state_filename("a/b/c").contains('/'));
    }


    #[test]
    fn qualified_dot_split() {
        // `cipher.doFinal` (lowercased by the caller) → class "cipher", member "dofinal".
        assert_eq!(
            parse_qualified_query("cipher.dofinal"),
            Some(("cipher".into(), "dofinal".into()))
        );
    }

    #[test]
    fn qualified_arrow_split() {
        assert_eq!(
            parse_qualified_query("ljavax/crypto/cipher;->dofinal"),
            Some(("javax/crypto/cipher".into(), "dofinal".into()))
        );
    }

    #[test]
    fn qualified_dotted_classpath_still_splits_but_class_search_covers_it() {
        // `com.example.foo` splits to ("com/example","foo") — the whole-query
        // class search (handled separately) covers the real class hit.
        assert_eq!(
            parse_qualified_query("com.example.foo"),
            Some(("com/example".into(), "foo".into()))
        );
    }

    #[test]
    fn bare_query_is_not_qualified() {
        assert_eq!(parse_qualified_query("dofinal"), None);
    }

    #[test]
    fn parse_invoke_ref() {
        let istr = "invoke-virtual {v0, v1}, Ljavax/crypto/Cipher;->doFinal([B)[B";
        assert_eq!(parse_ref(istr), Some(("javax/crypto/Cipher", "doFinal")));
    }

    #[test]
    fn parse_field_ref() {
        let istr = "iget-object v0, v1, Lcom/Foo;->field:Lcom/Bar;";
        assert_eq!(parse_ref(istr), Some(("com/Foo", "field")));
    }

    #[test]
    fn parse_ref_none_for_non_ref() {
        assert_eq!(parse_ref("const/4 v0, 0x0"), None);
    }
}
