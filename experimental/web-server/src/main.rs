// Project Platypus — Rocket.rs web backend
//
// Exposes the same API that the React adapter calls in web mode:
//
//   POST /api/upload               — upload an APK/DEX file (multipart)
//   POST /api/load                 — load by path (local filesystem)
//   GET  /api/smali/<class>        — get Smali for a class
//   GET  /api/java/<class>         — get Java for a class
//   GET  /api/manifest             — get AndroidManifest.xml
//   GET  /api/xrefs?class=&method= — get XREFs
//   POST /api/run                  — run a method
//   POST /api/find_exec            — find & exec all call sites
//   GET  /api/resources            — list resources
//   GET  /api/search?q=            — search classes/methods/strings
//
// The server is single-session (one loaded file at a time).
// Run with:  cargo run --release -- [--port 8080] [--dist ../ui-react/dist]

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use rocket::data::{Data, Limits, ToByteUnit};
use rocket::fairing::{Fairing, Info, Kind};
use rocket::fs::FileServer;
use rocket::http::{ContentType, Header, Method, Status};
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use rocket::{Request, Response};
use rocket::{get, post, routes, State};
use tokio::sync::RwLock;

use project_platypus_native::apk::{arsc, axml, split::SplitApk, zip::ApkZip};
use project_platypus_native::codegen::java::analysis::AnalysisConfig;
use project_platypus_native::codegen::java::decompiler::JavaDecompiler;
use project_platypus_native::codegen::java::dominator_tree::DominatorTree;
use project_platypus_native::codegen::java::java_generator::{JavaGenerator, class_package};
use project_platypus_native::codegen::java::ssa_builder::SsaBuilder;
use project_platypus_native::codegen::smali::smali_generator::SmaliClassCodeGen;
use project_platypus_native::dex::clazz::Clazz;
use project_platypus_native::dex::parser::DexFileWithRaw;
use project_platypus_native::vm::logger::format_value;
use project_platypus_native::vm::value::Value;
use project_platypus_native::vm::vm::Vm;
use project_platypus_native::apk::arsc::ResourceTable;
use project_platypus_native::analysis;

use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

// ── Shared state ─────────────────────────────────────────────────────────────

pub struct ServerState {
    /// Slot A — primary loaded file.
    pub loaded_path:  Arc<RwLock<Option<String>>>,
    pub dex_files:    Arc<RwLock<Vec<DexFileWithRaw>>>,
    pub resources:    Arc<RwLock<Option<ResourceTable>>>,
    pub manifest_xml: Arc<RwLock<Option<String>>>,
    /// Slot B — comparison APK for diffing.
    pub loaded_path_b: Arc<RwLock<Option<String>>>,
    pub dex_files_b:   Arc<RwLock<Vec<DexFileWithRaw>>>,
}

impl ServerState {
    fn new() -> Self {
        Self {
            loaded_path:   Arc::new(RwLock::new(None)),
            dex_files:     Arc::new(RwLock::new(Vec::new())),
            resources:     Arc::new(RwLock::new(None)),
            manifest_xml:  Arc::new(RwLock::new(None)),
            loaded_path_b: Arc::new(RwLock::new(None)),
            dex_files_b:   Arc::new(RwLock::new(Vec::new())),
        }
    }
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct TreeNodeSer {
    id: String,
    name: String,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    full_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    access_flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    return_type: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    params: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    register_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    instruction_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    dex_name: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    #[schema(no_recursion)]
    children: Vec<TreeNodeSer>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct LoadResult {
    path: String,
    tree: Vec<TreeNodeSer>,
    dex_files: Vec<String>,
    package_count: usize,
    class_count: usize,
    method_count: usize,
    entry_names: Vec<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct XRefResult {
    caller_class: String,
    caller_method: String,
    caller_signature: String,
    offset: u32,
    instruction: String,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct RunResult {
    return_value: String,
    return_type: String,
    logs: Vec<String>,
    error: Option<String>,
    execution_time_ms: u64,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct ExecResultItem {
    call_site: String,
    caller_class: String,
    caller_method: String,
    offset: u32,
    resolved_value: String,
    resolved_type: String,
    error: Option<String>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct SearchResultItem {
    kind: String,
    class_name: String,
    member_name: Option<String>,
    snippet: String,
    line: Option<u32>,
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct ResourceEntryItem {
    id: String,
    name: String,
    #[serde(rename = "type")]
    type_name: String,
    path: String,
    content: Option<String>,
}

// ── Request types ─────────────────────────────────────────────────────────────

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct LoadByPathRequest {
    path: String,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct RunRequest {
    class_name: String,
    method_name: String,
    args: Vec<String>,
}

#[derive(Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct FindExecRequest {
    target: String,
}

// ── CORS fairing ──────────────────────────────────────────────────────────────

pub struct Cors;

#[rocket::async_trait]
impl Fairing for Cors {
    fn info(&self) -> Info {
        Info { name: "CORS", kind: Kind::Response }
    }

    async fn on_response<'r>(&self, req: &'r Request<'_>, res: &mut Response<'r>) {
        res.set_header(Header::new("Access-Control-Allow-Origin", "*"));
        res.set_header(Header::new(
            "Access-Control-Allow-Methods",
            "GET, POST, PUT, DELETE, OPTIONS",
        ));
        res.set_header(Header::new(
            "Access-Control-Allow-Headers",
            "Content-Type, Authorization",
        ));
        if req.method() == Method::Options {
            res.set_status(Status::Ok);
        }
    }
}

// ── Tree builder helpers ──────────────────────────────────────────────────────

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

fn parse_proto(proto_desc: &str) -> (String, Vec<String>) {
    if let Some(close) = proto_desc.rfind(')') {
        let return_type = proto_desc[close + 1..].to_string();
        let params_str  = &proto_desc[1..close];
        (return_type, split_type_list(params_str))
    } else {
        (proto_desc.to_string(), Vec::new())
    }
}

fn split_type_list(s: &str) -> Vec<String> {
    let mut types = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'L' => {
                if let Some(end) = s[i..].find(';') {
                    types.push(s[i..=i + end].to_string());
                    i += end + 1;
                } else {
                    types.push(s[i..].to_string()); break;
                }
            }
            b'[' => {
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
            _ => { types.push((bytes[i] as char).to_string()); i += 1; }
        }
    }
    types
}

fn build_tree_for_dex(dex: &DexFileWithRaw) -> (Vec<TreeNodeSer>, usize, usize, usize) {
    let mut packages: HashMap<String, Vec<TreeNodeSer>> = HashMap::new();
    let mut class_count = 0usize;
    let mut method_count = 0usize;

    for class_def in &dex.parsed.class_defs {
        let full     = &class_def.type_name;
        let stripped = full.trim_start_matches('L').trim_end_matches(';');
        let (pkg, class_name) = if let Some(pos) = stripped.rfind('/') {
            (&stripped[..pos], &stripped[pos + 1..])
        } else {
            ("", stripped)
        };

        let clazz = match Clazz::new(class_def, dex) {
            Ok(c) => c,
            Err(_) => continue,
        };

        let class_flags = class_access_flag_strings(&clazz.access_flags);
        let mut children: Vec<TreeNodeSer> = Vec::new();

        for method in &clazz.methods {
            let (return_type, params) = parse_proto(&method.proto_desc);
            let flags = access_flag_strings(&method.access_flags);
            children.push(TreeNodeSer {
                id: format!("{}::{}", full, method.method_name),
                name: method.method_name.clone(),
                kind: "method",
                full_name: Some(format!("{}->{}{}", full, method.method_name, method.proto_desc)),
                access_flags: flags,
                return_type: Some(return_type),
                params,
                signature: Some(method.proto_desc.clone()),
                register_count: Some(method.registers_size as u32),
                instruction_count: Some(method.instructions.len() as u32),
                dex_name: Some(dex.parsed.filename.clone()),
                children: Vec::new(),
            });
            method_count += 1;
        }

        for field in clazz.static_fields.iter().chain(clazz.instance_fields.iter()) {
            children.push(TreeNodeSer {
                id: format!("{}:field:{}", full, field.name),
                name: field.name.clone(),
                kind: "field",
                full_name: Some(format!("{}->{}", full, field.name)),
                access_flags: Vec::new(),
                return_type: Some(field.type_name.clone()),
                params: Vec::new(),
                signature: Some(format!("{}:{}", field.name, field.type_name)),
                register_count: None,
                instruction_count: None,
                dex_name: Some(dex.parsed.filename.clone()),
                children: Vec::new(),
            });
        }

        packages.entry(pkg.to_string()).or_default().push(TreeNodeSer {
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
        });
        class_count += 1;
    }

    let package_count = packages.len();
    let mut pkg_nodes: Vec<TreeNodeSer> = packages.into_iter().map(|(pkg_path, classes)| {
        let pkg_name = pkg_path.rsplit('/').next().unwrap_or(&pkg_path).to_string();
        TreeNodeSer {
            id: format!("pkg:{}", pkg_path),
            name: if pkg_path.is_empty() { "(default)".into() } else { pkg_name },
            kind: "package",
            full_name: Some(pkg_path),
            access_flags: Vec::new(),
            return_type: None,
            params: Vec::new(),
            signature: None,
            register_count: None,
            instruction_count: None,
            dex_name: None,
            children: classes,
        }
    }).collect();
    pkg_nodes.sort_by(|a, b| a.name.cmp(&b.name));
    (pkg_nodes, package_count, class_count, method_count)
}

fn assemble_load_result(
    path: String,
    dex_files_raw: &[DexFileWithRaw],
    has_manifest: bool,
    entry_names: Vec<String>,
) -> LoadResult {
    let dex_file_names: Vec<String> = dex_files_raw.iter().map(|d| d.parsed.filename.clone()).collect();
    let mut total_packages = 0;
    let mut total_classes = 0;
    let mut total_methods = 0;
    let mut dex_nodes: Vec<TreeNodeSer> = Vec::new();

    for dex in dex_files_raw {
        let (pkg_nodes, pkgs, classes, methods) = build_tree_for_dex(dex);
        total_packages += pkgs;
        total_classes  += classes;
        total_methods  += methods;
        dex_nodes.push(TreeNodeSer {
            id: format!("dex:{}", dex.parsed.filename),
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
        id: "root:source".into(),
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
            id: "manifest".into(),
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

fn infer_type(v: &Value) -> String {
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

// ── CORS preflight ────────────────────────────────────────────────────────────

#[rocket::options("/<_..>")]
fn options() -> Status {
    Status::Ok
}

// ── POST /api/upload ──────────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/api/upload",
    request_body(content = String, content_type = "multipart/form-data",
        description = "APK, DEX, AAB, or JAR file (max 200 MB)"),
    responses(
        (status = 200, body = LoadResult),
        (status = 400, description = "Bad request / parse error"),
        (status = 422, description = "No DEX found in file"),
    ),
    tag = "platypus"
)]
#[post("/api/upload", data = "<data>")]
async fn upload(
    content_type: &rocket::http::ContentType,
    data: Data<'_>,
    state: &State<ServerState>,
) -> Result<Json<LoadResult>, Custom<String>> {
    use rocket_multipart_form_data::{
        MultipartFormData, MultipartFormDataField, MultipartFormDataOptions,
    };

    let options = MultipartFormDataOptions::with_multipart_form_data_fields(vec![
        MultipartFormDataField::raw("file").size_limit(200.megabytes().as_u64()),
    ]);

    let mut form = MultipartFormData::parse(content_type, data, options)
        .await
        .map_err(|e| Custom(Status::BadRequest, e.to_string()))?;

    let raw_field = form
        .raw
        .remove("file")
        .and_then(|mut v| v.pop())
        .ok_or_else(|| Custom(Status::BadRequest, "no file field".into()))?;

    let filename = raw_field
        .file_name
        .unwrap_or_else(|| "upload.apk".to_string());
    let bytes = raw_field.raw;

    process_bytes(bytes, filename, state).await
}

// ── POST /api/load ────────────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/api/load",
    request_body = LoadByPathRequest,
    responses(
        (status = 200, body = LoadResult),
        (status = 404, description = "File not found"),
        (status = 500, description = "Internal error"),
    ),
    tag = "platypus"
)]
#[post("/api/load", data = "<req>")]
async fn load_by_path(
    req: Json<LoadByPathRequest>,
    state: &State<ServerState>,
) -> Result<Json<LoadResult>, Custom<String>> {
    let path = req.into_inner().path;
    let p = std::path::Path::new(&path);

    if p.is_dir() {
        let split = SplitApk::from_dir(&path)
            .map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
        let resources = split.resources().ok();
        let manifest_xml = split.manifest_resolved()
            .or_else(|_| split.manifest())
            .map(|r| r.to_xml_string()).ok();
        let dexes: Vec<DexFileWithRaw> = split.dex_files().into_iter()
            .filter_map(|(n, b)| DexFileWithRaw::from_bytes(b, n).ok())
            .collect();
        if dexes.is_empty() {
            return Err(Custom(Status::BadRequest, "No DEX files found in directory".into()));
        }
        let has_manifest = manifest_xml.is_some();
        let result = assemble_load_result(path.clone(), &dexes, has_manifest, vec![]);
        *state.loaded_path.write().await  = Some(path);
        *state.dex_files.write().await    = dexes;
        *state.resources.write().await    = resources;
        *state.manifest_xml.write().await = manifest_xml;
        return Ok(Json(result));
    }

    let bytes = std::fs::read(&path)
        .map_err(|e| Custom(Status::NotFound, e.to_string()))?;
    let name = p.file_name().map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.clone());
    process_bytes(bytes, name, state).await
}

// ── Shared byte processor ─────────────────────────────────────────────────────

async fn process_bytes(
    bytes: Vec<u8>,
    filename: String,
    state: &State<ServerState>,
) -> Result<Json<LoadResult>, Custom<String>> {
    let is_apk = filename.ends_with(".apk")
        || filename.ends_with(".xapk")
        || filename.ends_with(".aab")
        || filename.ends_with(".aar")
        || filename.ends_with(".jar");

    let (dexes, resources, manifest_xml, entry_names) = if is_apk {
        // Treat as ZIP/APK
        let apk = ApkZip::from_bytes(bytes)
            .map_err(|e| Custom(Status::UnprocessableEntity, e.to_string()))?;
        let entry_names = apk.list_entries();
        let resources = apk.read_entry("resources.arsc")
            .ok()
            .and_then(|d| arsc::parse(&d).ok());
        let manifest_xml = apk.read_entry("AndroidManifest.xml")
            .ok()
            .and_then(|d| {
                if let Some(ref res) = resources {
                    axml::parse_with_resources(&d, res).ok()
                } else {
                    axml::parse(&d).ok()
                }
            })
            .map(|r| r.to_xml_string());
        let dexes: Vec<DexFileWithRaw> = apk.dex_files().into_iter()
            .filter_map(|(n, b)| DexFileWithRaw::from_bytes(b, n).ok())
            .collect();
        (dexes, resources, manifest_xml, entry_names)
    } else {
        // Raw DEX
        let dex = DexFileWithRaw::from_bytes(bytes, filename.clone())
            .map_err(|e| Custom(Status::UnprocessableEntity, e.to_string()))?;
        (vec![dex], None, None, vec![])
    };

    if dexes.is_empty() {
        return Err(Custom(Status::UnprocessableEntity, "No DEX files found".into()));
    }

    let has_manifest = manifest_xml.is_some();
    let result = assemble_load_result(filename.clone(), &dexes, has_manifest, entry_names);
    *state.loaded_path.write().await  = Some(filename);
    *state.dex_files.write().await    = dexes;
    *state.resources.write().await    = resources;
    *state.manifest_xml.write().await = manifest_xml;
    Ok(Json(result))
}

// ── GET /api/smali/<class> ────────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/api/smali/{class_name}",
    params(("class_name" = String, Path, description = "Class descriptor or dotted name")),
    responses(
        (status = 200, description = "Smali disassembly", body = String),
        (status = 404, description = "Class not found"),
    ),
    tag = "platypus"
)]
#[get("/api/smali/<class_name>")]
async fn get_smali(
    class_name: String,
    state: &State<ServerState>,
) -> Result<String, Custom<String>> {
    let dex_files = state.dex_files.read().await;
    let target = normalise_class(&class_name);
    for dex in dex_files.iter() {
        if let Some(cd) = find_class_def(dex, &target) {
            let clazz = Clazz::new(cd, dex).map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
            return Ok(SmaliClassCodeGen::new(&clazz, &dex.parsed).format());
        }
    }
    Err(Custom(Status::NotFound, format!("Class not found: {}", class_name)))
}

// ── GET /api/java/<class> ─────────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/api/java/{class_name}",
    params(("class_name" = String, Path, description = "Class descriptor or dotted name")),
    responses(
        (status = 200, description = "Decompiled Java source", body = String),
        (status = 404, description = "Class not found"),
    ),
    tag = "platypus"
)]
#[get("/api/java/<class_name>")]
async fn get_java(
    class_name: String,
    state: &State<ServerState>,
) -> Result<String, Custom<String>> {
    let dex_files = state.dex_files.read().await;
    let target = normalise_class(&class_name);
    for dex in dex_files.iter() {
        if let Some(cd) = find_class_def(dex, &target) {
            let clazz = Clazz::new(cd, dex).map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
            let config = AnalysisConfig::default();
            let decompiler = JavaDecompiler::new(Some(config));
            let mut method_texts: Vec<String> = Vec::new();
            let mut all_imports: std::collections::HashSet<String> = Default::default();

            for method in &clazz.methods {
                if method.instructions.is_empty() { method_texts.push(String::new()); continue; }
                let ast = decompiler.decompile(method);
                let mut cfg_clone = method.cfg.clone();
                if let Some(ref mut cfg) = cfg_clone { DominatorTree::compute(cfg); }
                let ssa = cfg_clone.as_ref()
                    .map(|cfg| SsaBuilder::new().build(cfg, &method.instructions, method.registers_size, method.ins_size))
                    .unwrap_or_else(SsaBuilder::empty_ssa);
                let mut gen = JavaGenerator::new(method, &dex.parsed, &ssa);
                method_texts.push(gen.gen_class_method(&ast));
                for imp in gen.import_statements() { all_imports.insert(imp); }
            }

            let mut out = Vec::new();
            let pkg = class_package(&clazz.class_name);
            if !pkg.is_empty() { out.push(format!("package {};", pkg)); out.push(String::new()); }
            let mut sorted_imports: Vec<String> = all_imports.into_iter()
                .filter(|s| s.starts_with("import "))   // defensive: drop any malformed entries
                .collect();
            sorted_imports.sort();
            for imp in sorted_imports { out.push(imp); }
            if !method_texts.is_empty() { out.push(String::new()); }
            for t in method_texts { if !t.is_empty() { out.push(t); } }
            return Ok(out.join("\n"));
        }
    }
    Err(Custom(Status::NotFound, format!("Class not found: {}", class_name)))
}

// ── GET /api/manifest ─────────────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/api/manifest",
    responses(
        (status = 200, description = "Decoded AndroidManifest.xml text", body = String),
        (status = 404, description = "No APK loaded"),
    ),
    tag = "platypus"
)]
#[get("/api/manifest")]
async fn get_manifest(state: &State<ServerState>) -> Result<String, Custom<String>> {
    state.manifest_xml.read().await.clone()
        .ok_or_else(|| Custom(Status::NotFound, "No manifest loaded".into()))
}

// ── GET /api/xrefs ────────────────────────────────────────────────────────────

#[derive(rocket::form::FromForm)]
struct XrefQuery {
    class: String,
    method: String,
}

#[utoipa::path(
    get, path = "/api/xrefs",
    params(
        ("class" = String, Query, description = "Class descriptor, e.g. Lcom/example/Foo;"),
        ("method" = String, Query, description = "Method name (bare, no signature)"),
    ),
    responses((status = 200, body = Vec<XRefResult>)),
    tag = "platypus"
)]
#[get("/api/xrefs?<params..>")]
async fn get_xrefs(
    params: XrefQuery,
    state: &State<ServerState>,
) -> Json<Vec<XRefResult>> {
    let dex_files = state.dex_files.read().await;
    let class_desc = if params.class.starts_with('L') {
        params.class.clone()
    } else {
        format!("L{};", params.class.replace('.', "/"))
    };
    let method_bare = params.method.split('(').next().unwrap_or(&params.method).to_string();
    let target = format!("{}->{}", class_desc, method_bare);

    let mut results = Vec::new();
    for dex in dex_files.iter() {
        for site in analysis::find_calls(dex, &target) {
            results.push(XRefResult {
                caller_class: site.caller_class,
                caller_method: site.caller_method.clone(),
                caller_signature: site.invoke_str.clone(),
                offset: site.invoke_cp,
                instruction: site.invoke_str,
            });
        }
    }
    Json(results)
}

// ── POST /api/run ─────────────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/api/run",
    request_body = RunRequest,
    responses(
        (status = 200, body = RunResult),
        (status = 404, description = "Method not found"),
    ),
    tag = "platypus"
)]
#[post("/api/run", data = "<req>")]
async fn run_method(
    req: Json<RunRequest>,
    state: &State<ServerState>,
) -> Result<Json<RunResult>, Custom<String>> {
    let RunRequest { class_name, method_name, args } = req.into_inner();
    let dex_files = state.dex_files.read().await;
    let resources = state.resources.read().await;

    let class_norm  = class_name.trim_start_matches('L').trim_end_matches(';');
    let method_bare = method_name.split('(').next().unwrap_or(&method_name).trim().to_string();

    let method = dex_files.iter().find_map(|dex| {
        dex.parsed.class_defs.iter()
            .find(|cd| cd.type_name.trim_start_matches('L').trim_end_matches(';') == class_norm)
            .and_then(|cd| Clazz::new(cd, dex).ok())
            .and_then(|clazz| clazz.methods.into_iter().find(|m| m.method_name == method_bare))
    }).ok_or_else(|| Custom(Status::NotFound, format!("Method not found: {}::{}", class_name, method_name)))?;

    let mut vm = Vm::new();
    for dex in dex_files.iter() {
        if let Ok(clone) = DexFileWithRaw::from_bytes(dex.raw_bytes().to_vec(), dex.parsed.filename.clone()) {
            vm.add_dex_file(&clone);
        }
    }
    if let Some(ref table) = *resources {
        vm.load_resources(
            table.entries().iter()
                .filter(|e| e.type_name == "string")
                .filter_map(|e| table.resolve(e.id).map(|v| (e.id, v))),
        );
    }

    let values: Vec<Value> = args.iter()
        .map(|s| analysis::resolve_arg_encoding(s, resources.as_ref(), &mut vm))
        .collect();

    vm.reset_for_call(50_000);
    let start = Instant::now();
    let result = vm.call_method(&method, values);
    let elapsed = start.elapsed().as_millis() as u64;

    let (return_value, return_type, error) = match &result {
        Some(v) => (format_value(v), infer_type(v), None),
        None    => ("void".into(), "void".into(), None),
    };

    Ok(Json(RunResult { return_value, return_type, logs: Vec::new(), error, execution_time_ms: elapsed }))
}

// ── POST /api/find_exec ───────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/api/find_exec",
    request_body = FindExecRequest,
    responses((status = 200, body = Vec<ExecResultItem>)),
    tag = "platypus"
)]
#[post("/api/find_exec", data = "<req>")]
async fn find_exec(
    req: Json<FindExecRequest>,
    state: &State<ServerState>,
) -> Json<Vec<ExecResultItem>> {
    let target = req.into_inner().target;
    let dex_files = state.dex_files.read().await;
    let resources = state.resources.read().await;

    let mut items = Vec::new();
    for dex in dex_files.iter() {
        for (site, value) in analysis::find_and_exec(dex, &target, resources.as_ref(), None) {
            let (resolved_value, resolved_type, error) = match &value {
                Some(v) => (format_value(v), infer_type(v), None),
                None    => ("(no result)".into(), "void".into(), None),
            };
            items.push(ExecResultItem {
                call_site: site.invoke_str,
                caller_class: site.caller_class,
                caller_method: site.caller_method,
                offset: site.invoke_cp,
                resolved_value,
                resolved_type,
                error,
            });
        }
    }
    Json(items)
}

// ── GET /api/resources ────────────────────────────────────────────────────────

#[utoipa::path(
    get, path = "/api/resources",
    responses((status = 200, body = Vec<ResourceEntryItem>)),
    tag = "platypus"
)]
#[get("/api/resources")]
async fn get_resources(state: &State<ServerState>) -> Json<Vec<ResourceEntryItem>> {
    let resources = state.resources.read().await;
    let items = match &*resources {
        Some(table) => table.entries().iter().map(|e| ResourceEntryItem {
            id: format!("{:#010x}", e.id),
            name: e.name.clone(),
            type_name: e.type_name.clone(),
            path: format!("{}:{}", e.type_name, e.name),
            content: table.resolve(e.id),
        }).collect(),
        None => Vec::new(),
    };
    Json(items)
}

// ── GET /api/search ───────────────────────────────────────────────────────────

#[derive(rocket::form::FromForm)]
struct SearchQuery {
    q: String,
}

#[utoipa::path(
    get, path = "/api/search",
    params(("q" = String, Query, description = "Query string (matches class/method names and string constants)")),
    responses((status = 200, body = Vec<SearchResultItem>)),
    tag = "platypus"
)]
#[get("/api/search?<params..>")]
async fn search_code(
    params: SearchQuery,
    state: &State<ServerState>,
) -> Json<Vec<SearchResultItem>> {
    let dex_files = state.dex_files.read().await;
    let q = params.q.to_lowercase();
    let mut results: Vec<SearchResultItem> = Vec::new();

    'outer: for dex in dex_files.iter() {
        for class_def in &dex.parsed.class_defs {
            let display = class_def.type_name.trim_start_matches('L').trim_end_matches(';');
            if display.to_lowercase().contains(&q) {
                results.push(SearchResultItem { kind: "class".into(), class_name: display.to_string(), member_name: None, snippet: display.to_string(), line: None });
                if results.len() >= 200 { break 'outer; }
                continue;
            }
            let clazz = match Clazz::new(class_def, dex) { Ok(c) => c, Err(_) => continue };
            for method in &clazz.methods {
                if method.method_name.to_lowercase().contains(&q) {
                    results.push(SearchResultItem { kind: "method".into(), class_name: display.to_string(), member_name: Some(method.method_name.clone()), snippet: format!("{}.{}", display, method.method_name), line: None });
                }
                for instr in &method.instructions {
                    if instr.instruction_str.contains("const-string") && instr.instruction_str.to_lowercase().contains(&q) {
                        results.push(SearchResultItem { kind: "string".into(), class_name: display.to_string(), member_name: Some(method.method_name.clone()), snippet: instr.instruction_str.clone(), line: None });
                    }
                }
                if results.len() >= 200 { break 'outer; }
            }
        }
    }
    Json(results)
}

// ── POST /api/load_b  ─────────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/api/load_b",
    request_body = LoadByPathRequest,
    responses(
        (status = 200, description = "Comparison slot loaded", body = LoadResult),
        (status = 404, description = "File not found"),
    ),
    tag = "platypus"
)]
#[post("/api/load_b", data = "<req>")]
async fn load_b_by_path(
    req: Json<LoadByPathRequest>,
    state: &State<ServerState>,
) -> Result<Json<LoadResult>, Custom<String>> {
    let path = req.into_inner().path;
    let p = std::path::Path::new(&path);

    let (dexes, entry_names): (Vec<DexFileWithRaw>, Vec<String>) = if p.is_dir() {
        let split = SplitApk::from_dir(&path)
            .map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
        let dexes = split.dex_files().into_iter()
            .filter_map(|(n, b)| DexFileWithRaw::from_bytes(b, n).ok())
            .collect();
        (dexes, vec![])
    } else {
        let bytes = std::fs::read(&path)
            .map_err(|e| Custom(Status::NotFound, e.to_string()))?;
        let name = p.file_name().map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.clone());
        if name.ends_with(".apk") || name.ends_with(".xapk") {
            let apk = ApkZip::from_bytes(bytes)
                .map_err(|e| Custom(Status::UnprocessableEntity, e.to_string()))?;
            let entry_names = apk.list_entries();
            let dexes = apk.dex_files().into_iter()
                .filter_map(|(n, b)| DexFileWithRaw::from_bytes(b, n).ok())
                .collect();
            (dexes, entry_names)
        } else {
            let dex = DexFileWithRaw::from_bytes(bytes, name)
                .map_err(|e| Custom(Status::UnprocessableEntity, e.to_string()))?;
            (vec![dex], vec![])
        }
    };

    if dexes.is_empty() {
        return Err(Custom(Status::BadRequest, "No DEX files found".into()));
    }
    let result = assemble_load_result(path.clone(), &dexes, false, entry_names);
    *state.loaded_path_b.write().await = Some(path);
    *state.dex_files_b.write().await   = dexes;
    Ok(Json(result))
}

// ── POST /api/upload_b ────────────────────────────────────────────────────────

#[utoipa::path(
    post, path = "/api/upload_b",
    request_body(content = String, content_type = "multipart/form-data",
        description = "Comparison APK file (max 200 MB)"),
    responses(
        (status = 200, description = "Comparison slot loaded", body = LoadResult),
        (status = 400, description = "Bad request"),
    ),
    tag = "platypus"
)]
#[post("/api/upload_b", data = "<data>")]
async fn upload_b(
    content_type: &rocket::http::ContentType,
    data: rocket::Data<'_>,
    state: &State<ServerState>,
) -> Result<Json<LoadResult>, Custom<String>> {
    use rocket_multipart_form_data::{MultipartFormData, MultipartFormDataField, MultipartFormDataOptions, mime};
    let options = MultipartFormDataOptions::with_multipart_form_data_fields(vec![
        MultipartFormDataField::raw("file").size_limit(200.megabytes().as_u64()),
    ]);
    let mut form = MultipartFormData::parse(content_type, data, options)
        .await
        .map_err(|e| Custom(Status::BadRequest, e.to_string()))?;
    let raw_field = form.raw.remove("file")
        .and_then(|mut v| v.pop())
        .ok_or_else(|| Custom(Status::BadRequest, "no file field".into()))?;
    let filename = raw_field.file_name.unwrap_or_else(|| "upload.apk".to_string());
    let bytes = raw_field.raw;

    let is_apk = filename.ends_with(".apk") || filename.ends_with(".xapk")
        || filename.ends_with(".aab") || filename.ends_with(".aar") || filename.ends_with(".jar");
    let (dexes, entry_names): (Vec<DexFileWithRaw>, Vec<String>) = if is_apk {
        let apk = ApkZip::from_bytes(bytes)
            .map_err(|e| Custom(Status::UnprocessableEntity, e.to_string()))?;
        let entry_names = apk.list_entries();
        let dexes = apk.dex_files().into_iter()
            .filter_map(|(n, b)| DexFileWithRaw::from_bytes(b, n).ok())
            .collect();
        (dexes, entry_names)
    } else {
        let dex = DexFileWithRaw::from_bytes(bytes, filename.clone())
            .map_err(|e| Custom(Status::UnprocessableEntity, e.to_string()))?;
        (vec![dex], vec![])
    };
    if dexes.is_empty() {
        return Err(Custom(Status::UnprocessableEntity, "No DEX files found".into()));
    }
    let result = assemble_load_result(filename.clone(), &dexes, false, entry_names);
    *state.loaded_path_b.write().await = Some(filename);
    *state.dex_files_b.write().await   = dexes;
    Ok(Json(result))
}

// ── GET /api/smali_b/<class>  /  GET /api/java_b/<class> ─────────────────────

#[utoipa::path(
    get, path = "/api/smali_b/{class_name}",
    params(("class_name" = String, Path, description = "Class in comparison slot")),
    responses(
        (status = 200, description = "Smali disassembly", body = String),
        (status = 404, description = "Class not found"),
    ),
    tag = "platypus"
)]
#[get("/api/smali_b/<class_name>")]
async fn get_smali_b(
    class_name: String,
    state: &State<ServerState>,
) -> Result<String, Custom<String>> {
    let dex_files = state.dex_files_b.read().await;
    let target = normalise_class(&class_name);
    for dex in dex_files.iter() {
        if let Some(cd) = find_class_def(dex, &target) {
            let clazz = Clazz::new(cd, dex).map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
            return Ok(SmaliClassCodeGen::new(&clazz, &dex.parsed).format());
        }
    }
    Err(Custom(Status::NotFound, format!("Class not found in slot B: {}", class_name)))
}

#[utoipa::path(
    get, path = "/api/java_b/{class_name}",
    params(("class_name" = String, Path, description = "Class in comparison slot")),
    responses(
        (status = 200, description = "Decompiled Java", body = String),
        (status = 404, description = "Class not found"),
    ),
    tag = "platypus"
)]
#[get("/api/java_b/<class_name>")]
async fn get_java_b(
    class_name: String,
    state: &State<ServerState>,
) -> Result<String, Custom<String>> {
    let dex_files = state.dex_files_b.read().await;
    let target = normalise_class(&class_name);
    for dex in dex_files.iter() {
        if let Some(cd) = find_class_def(dex, &target) {
            let clazz = Clazz::new(cd, dex).map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
            let config = AnalysisConfig::default();
            let decompiler = JavaDecompiler::new(Some(config));
            let mut method_texts: Vec<String> = Vec::new();
            let mut all_imports: std::collections::HashSet<String> = Default::default();
            for method in &clazz.methods {
                if method.instructions.is_empty() { method_texts.push(String::new()); continue; }
                let ast = decompiler.decompile(method);
                let mut cfg_clone = method.cfg.clone();
                if let Some(ref mut cfg) = cfg_clone { DominatorTree::compute(cfg); }
                let ssa = cfg_clone.as_ref()
                    .map(|cfg| SsaBuilder::new().build(cfg, &method.instructions, method.registers_size, method.ins_size))
                    .unwrap_or_else(SsaBuilder::empty_ssa);
                let mut gen = JavaGenerator::new(method, &dex.parsed, &ssa);
                method_texts.push(gen.gen_class_method(&ast));
                for imp in gen.import_statements() { all_imports.insert(imp); }
            }
            let mut out = Vec::new();
            let pkg = class_package(&clazz.class_name);
            if !pkg.is_empty() { out.push(format!("package {};", pkg)); out.push(String::new()); }
            let mut sorted: Vec<String> = all_imports.into_iter().collect(); sorted.sort();
            for imp in sorted { out.push(imp); }
            if !method_texts.is_empty() { out.push(String::new()); }
            for t in method_texts { if !t.is_empty() { out.push(t); } }
            return Ok(out.join("\n"));
        }
    }
    Err(Custom(Status::NotFound, format!("Class not found in slot B: {}", class_name)))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn normalise_class(name: &str) -> String {
    if name.starts_with('L') { name.to_string() } else { format!("L{};", name) }
}

fn find_class_def<'a>(
    dex: &'a DexFileWithRaw,
    target: &str,
) -> Option<&'a project_platypus_native::dex::parser::ClassDefItem> {
    let stripped = target.trim_start_matches('L').trim_end_matches(';');
    dex.parsed.class_defs.iter().find(|cd| {
        cd.type_name == target
            || cd.type_name.trim_start_matches('L').trim_end_matches(';') == stripped
    })
}

// ── GET /api/entry/<path> ─────────────────────────────────────────────────────

/// Read a raw ZIP entry from the loaded APK.
/// Returns UTF-8 text (or decoded binary XML for .xml entries), falling back
/// to a hex-dump preview for non-UTF-8 binary content.
#[utoipa::path(
    get, path = "/api/entry/{path}",
    params(("path" = String, Path, description = "ZIP entry path")),
    responses(
        (status = 200, description = "Text content, decoded XML, or hex dump", body = String),
        (status = 404, description = "Entry not found"),
    ),
    tag = "platypus"
)]
#[get("/api/entry/<entry_path..>")]
async fn get_entry(
    entry_path: std::path::PathBuf,
    state: &State<ServerState>,
) -> Result<String, Custom<String>> {
    let path = {
        let lp = state.loaded_path.read().await;
        lp.clone().ok_or_else(|| Custom(Status::BadRequest, "No APK loaded".into()))?
    };
    let entry_name = entry_path.to_string_lossy().into_owned();

    let apk = ApkZip::open(&path).map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
    let bytes = apk.read_entry(&entry_name).map_err(|e| Custom(Status::NotFound, e.to_string()))?;

    // Android binary XML
    if entry_name.ends_with(".xml") {
        if let Ok(root) = axml::parse(&bytes) {
            return Ok(root.to_xml_string());
        }
    }

    // Plain UTF-8
    if let Ok(text) = std::str::from_utf8(&bytes) {
        return Ok(text.to_string());
    }

    // Binary hex-dump preview
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

// ── Raw asset serving ─────────────────────────────────────────────────────────
//
// `/api/entry/<path>` decodes everything to text and is meant for human
// inspection.  The web UI needs the OPPOSITE — raw bytes with proper
// content types so `<img src=…>` / `fetch().arrayBuffer()` work directly.
// These two routes serve that need.

/// Detected category for an APK entry — drives both content-type
/// selection and the `decodedKind` hint surfaced by `/api/asset_info`.
fn asset_category(name: &str) -> (&'static str, &'static str) {
    // Returns (content_type, decoded_kind_hint).
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

#[utoipa::path(
    get, path = "/api/asset/{path}",
    params(("path" = String, Path, description = "ZIP entry path")),
    responses(
        (status = 200, description = "Raw asset bytes; Content-Type inferred from extension",
                       content_type = "application/octet-stream"),
        (status = 404, description = "Entry not found"),
    ),
    tag = "platypus"
)]
#[get("/api/asset/<entry_path..>")]
async fn get_asset(
    entry_path: std::path::PathBuf,
    state: &State<ServerState>,
) -> Result<(ContentType, Vec<u8>), Custom<String>> {
    let path = {
        let lp = state.loaded_path.read().await;
        lp.clone().ok_or_else(|| Custom(Status::BadRequest, "No APK loaded".into()))?
    };
    let entry_name = entry_path.to_string_lossy().into_owned();

    let apk = ApkZip::open(&path).map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
    let bytes = apk.read_entry(&entry_name)
        .map_err(|e| Custom(Status::NotFound, e.to_string()))?;

    let (ct_str, kind) = asset_category(&entry_name);

    // Special handling: AXML (`.xml` inside an APK is binary AXML).  If
    // the caller wants the decoded text, they hit /api/entry/<path>;
    // here we serve the original BINARY so something like a vector
    // drawable XML editor can round-trip the bytes.  But for `.xml`
    // entries that the UI specifically expects as text/xml, we ALSO
    // try a text decode — if it parses as AXML we emit the decoded
    // form (browsers can render it).  Anything that doesn't parse
    // gets the raw bytes.
    let body = if kind == "axml" {
        match axml::parse(&bytes) {
            Ok(root) => root.to_xml_string().into_bytes(),
            Err(_)   => bytes,
        }
    } else {
        bytes
    };

    let ct = ContentType::parse_flexible(ct_str)
        .unwrap_or(ContentType::Binary);
    Ok((ct, body))
}

#[derive(Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct AssetInfo {
    /// Entry path inside the APK.
    path: String,
    /// Raw size in bytes.
    size: usize,
    /// MIME type we'd serve via `/api/asset/<path>`.
    content_type: String,
    /// High-level classification: image / font / text / axml / arsc /
    /// dex / elf / binary. Lets the frontend pick the right viewer.
    decoded_kind: String,
}

#[utoipa::path(
    get, path = "/api/asset_info/{path}",
    params(("path" = String, Path, description = "ZIP entry path")),
    responses(
        (status = 200, description = "Asset metadata", body = AssetInfo),
        (status = 404, description = "Entry not found"),
    ),
    tag = "platypus"
)]
#[get("/api/asset_info/<entry_path..>")]
async fn get_asset_info(
    entry_path: std::path::PathBuf,
    state: &State<ServerState>,
) -> Result<Json<AssetInfo>, Custom<String>> {
    let path = {
        let lp = state.loaded_path.read().await;
        lp.clone().ok_or_else(|| Custom(Status::BadRequest, "No APK loaded".into()))?
    };
    let entry_name = entry_path.to_string_lossy().into_owned();

    let apk = ApkZip::open(&path).map_err(|e| Custom(Status::InternalServerError, e.to_string()))?;
    let bytes = apk.read_entry(&entry_name)
        .map_err(|e| Custom(Status::NotFound, e.to_string()))?;

    let (ct, kind) = asset_category(&entry_name);
    Ok(Json(AssetInfo {
        path: entry_name,
        size: bytes.len(),
        content_type: ct.to_string(),
        decoded_kind: kind.to_string(),
    }))
}

// ── Python scripting ───────────────────────────────────────────────────────────

#[derive(serde::Deserialize, utoipa::ToSchema)]
struct ScriptRequest {
    code: String,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct ScriptRunResult {
    stdout: String,
    stderr: String,
    exit_code: i32,
    duration_ms: u64,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "camelCase")]
struct LintDiagnostic {
    line: u32,
    col: u32,
    end_line: Option<u32>,
    end_col: Option<u32>,
    code: String,
    message: String,
    severity: String,
}

/// Resolve the platypus project root: web-server binary lives at
/// `project_platypus/web-server/target/…`, so we go up three times.
fn project_root() -> String {
    // At runtime we don't have CARGO_MANIFEST_DIR, so use the current exe path.
    if let Ok(exe) = std::env::current_exe() {
        // exe: …/project_platypus/web-server/target/<profile>/binary
        // go up 4 dirs to reach project_platypus/
        if let Some(root) = exe
            .ancestors()
            .nth(4)
            .and_then(|p| p.to_str())
        {
            return root.to_string();
        }
    }
    // Fallback: current working directory
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| ".".to_string())
}

#[utoipa::path(
    post, path = "/api/run_script",
    request_body = ScriptRequest,
    responses((status = 200, body = ScriptRunResult)),
    tag = "platypus"
)]
#[post("/api/run_script", data = "<req>")]
async fn run_script(
    req: rocket::serde::json::Json<ScriptRequest>,
    state: &State<ServerState>,
) -> rocket::serde::json::Json<ScriptRunResult> {
    use std::io::Write;
    use std::time::Instant;

    let root = project_root();
    let loaded_apk = {
        let lp = state.loaded_path.read().await;
        lp.clone().unwrap_or_default()
    };

    let apk_repr = if loaded_apk.is_empty() {
        "None".to_string()
    } else {
        format!("r\"{}\"", loaded_apk)
    };

    let wrapper = format!(
        "import sys as _sys\n_sys.path.insert(0, r\"{root}\")\nLOADED_APK = {apk}\n{code}\n",
        root = root,
        apk = apk_repr,
        code = req.code,
    );

    let mut tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(e) => {
            return rocket::serde::json::Json(ScriptRunResult {
                stdout: String::new(),
                stderr: format!("Could not create temp file: {e}"),
                exit_code: -1,
                duration_ms: 0,
            });
        }
    };
    let _ = tmp.write_all(wrapper.as_bytes());
    let tmp_path = tmp.path().to_path_buf();

    let t0 = Instant::now();
    let output = match std::process::Command::new("python3")
        .arg(&tmp_path)
        .output()
    {
        Ok(o) => o,
        Err(e) => {
            return rocket::serde::json::Json(ScriptRunResult {
                stdout: String::new(),
                stderr: format!("Could not run python3: {e}"),
                exit_code: -1,
                duration_ms: 0,
            });
        }
    };

    rocket::serde::json::Json(ScriptRunResult {
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        exit_code: output.status.code().unwrap_or(-1),
        duration_ms: t0.elapsed().as_millis() as u64,
    })
}

#[utoipa::path(
    post, path = "/api/lint_script",
    request_body = ScriptRequest,
    responses((status = 200, body = Vec<LintDiagnostic>)),
    tag = "platypus"
)]
#[post("/api/lint_script", data = "<req>")]
async fn lint_script(
    req: rocket::serde::json::Json<ScriptRequest>,
) -> rocket::serde::json::Json<Vec<LintDiagnostic>> {
    use std::io::Write;

    if req.code.trim().is_empty() {
        return rocket::serde::json::Json(vec![]);
    }

    let mut tmp = match tempfile::NamedTempFile::new() {
        Ok(f) => f,
        Err(_) => return rocket::serde::json::Json(vec![]),
    };
    let _ = tmp.write_all(req.code.as_bytes());
    let tmp_path = tmp.path().to_path_buf();

    let output = match std::process::Command::new("ruff")
        .args(["check", "--output-format", "json"])
        .arg(&tmp_path)
        .output()
    {
        Ok(o) => o,
        Err(_) => return rocket::serde::json::Json(vec![]),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() {
        return rocket::serde::json::Json(vec![]);
    }

    let raw: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or(serde_json::json!([]));

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

    rocket::serde::json::Json(diags)
}

// ── OpenAPI spec ──────────────────────────────────────────────────────────────

#[derive(OpenApi)]
#[openapi(
    paths(
        upload, load_by_path,
        get_smali, get_java, get_manifest, get_xrefs,
        run_method, find_exec, get_resources, get_entry,
        get_asset, get_asset_info,
        search_code,
        load_b_by_path, upload_b, get_smali_b, get_java_b,
        run_script, lint_script,
    ),
    components(schemas(
        LoadResult, TreeNodeSer, XRefResult, RunResult,
        ExecResultItem, SearchResultItem, ResourceEntryItem,
        LoadByPathRequest, RunRequest, FindExecRequest,
        ScriptRequest, ScriptRunResult, LintDiagnostic,
        AssetInfo,
    )),
    tags((name = "platypus", description = "Project Platypus Android Analysis API")),
    info(title = "Project Platypus", version = "0.1.0")
)]
struct ApiDoc;

// ── main ──────────────────────────────────────────────────────────────────────

#[rocket::main]
async fn main() -> Result<(), rocket::Error> {
    // Determine dist folder for static file serving
    let dist_path: Option<PathBuf> = {
        let p = PathBuf::from("../ui-react/dist");
        if p.exists() { Some(p) } else { None }
    };

    let figment = rocket::Config::figment()
        .merge(("port", 8080u16))
        .merge(("address", "127.0.0.1"))
        .merge(("limits", rocket::data::Limits::new()
            .limit("bytes", 200.megabytes())
            .limit("data-form", 200.megabytes())
            .limit("file", 200.megabytes())));

    let routes = routes![
        options,
        upload,
        load_by_path,
        get_smali,
        get_java,
        get_manifest,
        get_xrefs,
        run_method,
        find_exec,
        get_resources,
        get_entry,
        get_asset,
        get_asset_info,
        search_code,
        load_b_by_path,
        upload_b,
        get_smali_b,
        get_java_b,
        run_script,
        lint_script,
    ];

    let rocket = rocket::custom(figment)
        .attach(Cors)
        .manage(ServerState::new());

    let rocket = if let Some(dist) = dist_path {
        rocket.mount("/", FileServer::from(dist))
    } else {
        rocket
    };

    rocket
        .mount(
            "/",
            SwaggerUi::new("/swagger-ui/<_..>")
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
        .mount("/", routes)
        .launch().await?;
    Ok(())
}
