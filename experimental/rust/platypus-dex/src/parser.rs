/// DEX file parser — translates dex/dex.py (Kaitai structs) + dex/dexfile.py
///
/// Parses the binary DEX format eagerly, producing a `ParsedDex` that holds
/// all string/type/proto/field/method/class tables.

use std::io;

use super::parallel;
use super::reader::DexReader;

// ── Header ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DexHeader {
    pub magic: [u8; 4],
    pub version_str: String,
    pub checksum: u32,
    pub signature: [u8; 20],
    pub file_size: u32,
    pub header_size: u32,
    pub endian_tag: u32,
    pub link_size: u32,
    pub link_off: u32,
    pub map_off: u32,
    pub string_ids_size: u32,
    pub string_ids_off: u32,
    pub type_ids_size: u32,
    pub type_ids_off: u32,
    pub proto_ids_size: u32,
    pub proto_ids_off: u32,
    pub field_ids_size: u32,
    pub field_ids_off: u32,
    pub method_ids_size: u32,
    pub method_ids_off: u32,
    pub class_defs_size: u32,
    pub class_defs_off: u32,
    pub data_size: u32,
    pub data_off: u32,
}

// ── Table item types ─────────────────────────────────────────────────────────

/// Resolved string data (StringIdItem → StringDataItem).
#[derive(Debug, Clone)]
pub struct StringData {
    pub data: String,
}

/// type_ids entry — resolved to type name string.
#[derive(Debug, Clone)]
pub struct TypeIdItem {
    pub descriptor_idx: u32,
    pub type_name: String,
}

/// proto_ids entry.
#[derive(Debug, Clone)]
pub struct ProtoIdItem {
    pub shorty_idx: u32,
    pub return_type_idx: u32,
    pub parameters_off: u32,
    pub shorty_desc: String,
    pub return_type: String,
    pub param_types: Vec<String>,
    /// Pre-computed full descriptor "(param_types)return_type" — avoids per-method format!/join.
    pub proto_desc: String,
}

/// field_ids entry.
#[derive(Debug, Clone)]
pub struct FieldIdItem {
    pub class_idx: u16,
    pub type_idx: u16,
    pub name_idx: u32,
    pub class_name: String,
    pub type_name: String,
    pub field_name: String,
}

/// method_ids entry.
#[derive(Debug, Clone)]
pub struct MethodIdItem {
    pub class_idx: u16,
    pub proto_idx: u16,
    pub name_idx: u32,
    pub class_name: String,
    pub proto_desc: String,
    pub method_name: String,
}

/// Encoded field (inside class_data_item).
#[derive(Debug, Clone)]
pub struct EncodedField {
    pub field_idx_diff: u64,
    pub access_flags: u64,
}

/// Encoded method (inside class_data_item).
#[derive(Debug, Clone)]
pub struct EncodedMethod {
    pub method_idx_diff: u64,
    pub access_flags: u64,
    pub code_off: u64,
}

/// class_data_item.
#[derive(Debug, Clone)]
pub struct ClassDataItem {
    pub static_fields: Vec<EncodedField>,
    pub instance_fields: Vec<EncodedField>,
    pub direct_methods: Vec<EncodedMethod>,
    pub virtual_methods: Vec<EncodedMethod>,
}

/// class_defs entry.
#[derive(Debug, Clone)]
pub struct ClassDefItem {
    pub class_idx: u32,
    pub access_flags: u32,
    pub superclass_idx: u32,
    pub interfaces_off: u32,
    pub source_file_idx: u32,
    pub annotations_off: u32,
    pub class_data_off: u32,
    pub static_values_off: u32,
    pub type_name: String,
    pub class_data: Option<ClassDataItem>,
    /// Resolved superclass descriptor (e.g. `"Ljava/lang/Object;"`).
    /// Empty when `superclass_idx == 0xFFFFFFFF` (no_index — true only
    /// for `Object` itself).
    pub superclass_name: String,
    /// Implemented interface descriptors, in declaration order.
    /// Resolved from the `type_list` at `interfaces_off`. Empty when
    /// the class implements no interfaces.
    pub interfaces: Vec<String>,
    /// Class-level annotations with their element-value pairs.
    /// Each entry is `(type_descriptor, [(element_name, value_repr)…])`.
    /// `value_repr` is already formatted (e.g. `"14"`, `"\"unchecked\""`,
    /// `"int.class"`) so the renderer can splat it directly. Empty
    /// element list = no-argument annotation.
    pub annotations: Vec<AnnotationItem>,
    /// Per-method annotations, keyed by method_idx (the same idx used
    /// by `Method::new`). Methods without annotations don't appear in
    /// the map.
    pub method_annotations: std::collections::HashMap<u32, Vec<AnnotationItem>>,
    /// Per-field annotations, keyed by field_idx.
    pub field_annotations: std::collections::HashMap<u32, Vec<AnnotationItem>>,
    /// Per-parameter annotations, keyed by method_idx. Inner Vec
    /// indexed by parameter position (0..n_params). Inner-inner Vec
    /// is the annotation list for that parameter (empty when the
    /// parameter has none, even if other parameters of the same
    /// method are annotated).
    pub parameter_annotations: std::collections::HashMap<u32, Vec<Vec<AnnotationItem>>>,
}

/// One annotation attached to a class / field / method.
#[derive(Debug, Clone)]
pub struct AnnotationItem {
    /// Annotation class descriptor, e.g. `"Landroid/annotation/TargetApi;"`.
    pub type_name: String,
    /// `(element_name, value_repr)` pairs. `value_repr` is pre-formatted
    /// for direct splat into the rendered annotation (int → `"14"`,
    /// String → `"\"foo\""`, Type → `"int.class"`, etc.).
    pub elements: Vec<(String, String)>,
}

/// try_item inside a code_item.
#[derive(Debug, Clone)]
pub struct TryItem {
    pub start_addr: u32,
    pub insn_count: u16,
    pub handler_offset: u16,
}

/// One exception handler inside encoded_catch_handler.
#[derive(Debug, Clone)]
pub struct CatchHandler {
    pub type_idx: u64,
    pub addr: u64,
}

/// encoded_catch_handler.
#[derive(Debug, Clone)]
pub struct EncodedCatchHandler {
    pub handlers: Vec<CatchHandler>,
    pub catch_all_addr: Option<u64>,
}

/// code_item — raw binary data extracted from the DEX for one method body.
#[derive(Debug, Clone)]
pub struct CodeItem {
    pub registers_size: u16,
    pub ins_size: u16,
    pub outs_size: u16,
    pub tries_size: u16,
    pub debug_info_off: u32,
    pub insns_size: u32,
    /// raw instruction bytes (insns_size * 2 bytes)
    pub insns: Vec<u8>,
    pub try_items: Vec<TryItem>,
    pub handlers: Vec<EncodedCatchHandler>,
}

// ── Main parsed DEX ───────────────────────────────────────────────────────────

/// The fully-parsed contents of one DEX file.
/// Corresponds to Python's `Dex` (Kaitai) + `DexFile` wrapper.
#[derive(Clone)]
pub struct ParsedDex {
    pub header: DexHeader,
    pub strings: Vec<StringData>,
    pub type_ids: Vec<TypeIdItem>,
    pub proto_ids: Vec<ProtoIdItem>,
    pub field_ids: Vec<FieldIdItem>,
    pub method_ids: Vec<MethodIdItem>,
    pub class_defs: Vec<ClassDefItem>,
    /// SHA-256 digest of the file bytes.
    pub digest: String,
    /// Original filename (last path component).
    pub filename: String,
}

impl ParsedDex {
    // ── Constructor ──────────────────────────────────────────────────────────

    pub fn from_file(path: &str) -> io::Result<Self> {
        let mut reader = DexReader::from_file(path)?;
        let digest = sha256_hex(reader.data());
        let filename = path.split('/').last().unwrap_or(path).to_string();
        Self::parse(&mut reader, digest, filename)
    }

    pub fn from_bytes(data: Vec<u8>, filename: String) -> io::Result<Self> {
        let digest = sha256_hex(&data);
        let mut reader = DexReader::new(data);
        Self::parse(&mut reader, digest, filename)
    }

    fn parse(r: &mut DexReader, digest: String, filename: String) -> io::Result<Self> {
        let header = parse_header(r)?;

        // --- string table ---------------------------------------------------
        let strings = parse_string_ids(r, &header)?;

        // --- type_ids -------------------------------------------------------
        let type_ids = parse_type_ids(r, &header, &strings)?;

        // --- proto_ids ------------------------------------------------------
        let proto_ids = parse_proto_ids(r, &header, &strings, &type_ids)?;

        // --- field_ids ------------------------------------------------------
        let field_ids = parse_field_ids(r, &header, &strings, &type_ids)?;

        // --- method_ids -----------------------------------------------------
        let method_ids = parse_method_ids(r, &header, &strings, &type_ids, &proto_ids)?;

        // --- class_defs -----------------------------------------------------
        let class_defs = parse_class_defs(r, &header, &strings, &type_ids, &field_ids)?;

        Ok(ParsedDex {
            header,
            strings,
            type_ids,
            proto_ids,
            field_ids,
            method_ids,
            class_defs,
            digest,
            filename,
        })
    }

    // ── Lookup helpers (mirrors DexFile methods) ─────────────────────────────

    pub fn lookup_string(&self, idx: usize) -> Option<&str> {
        self.strings.get(idx).map(|s| s.data.as_str())
    }

    pub fn lookup_type(&self, idx: usize) -> Option<&str> {
        self.type_ids.get(idx).map(|t| t.type_name.as_str())
    }

    pub fn lookup_field_str(&self, idx: usize) -> Option<String> {
        let f = self.field_ids.get(idx)?;
        Some(format!("{}->{}: {}", f.class_name, f.field_name, f.type_name))
    }

    pub fn lookup_method_str(&self, idx: usize) -> Option<String> {
        let m = self.method_ids.get(idx)?;
        Some(format!("{}->{}{}", m.class_name, m.method_name, m.proto_desc))
    }

    /// Read the code_item for a method at `_code_off` (byte offset into file).
    pub fn read_code_item(&self, _code_off: u64) -> io::Result<CodeItem> {
        let _data = &self.header; // just need len
        // Re-create a reader from the original data is impractical here
        // because ParsedDex doesn't keep the raw bytes.
        // Return an error; callers should use DexFileWithRaw instead.
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Use DexFileWithRaw::read_code_item instead",
        ))
    }
}

// ── DexFileWithRaw: keeps original bytes ─────────────────────────────────────

/// Wraps `ParsedDex` and retains the raw byte buffer so that `code_item`
/// data can be read on demand (mirrors Python `DexFile.fd`).
#[derive(Clone)]
pub struct DexFileWithRaw {
    pub parsed: ParsedDex,
    raw: Vec<u8>,
}

impl DexFileWithRaw {
    pub fn from_file(path: &str) -> io::Result<Self> {
        let raw = std::fs::read(path)?;
        let parsed = ParsedDex::from_bytes(raw.clone(), path.to_string())?;
        Ok(DexFileWithRaw { parsed, raw })
    }

    pub fn from_bytes(data: Vec<u8>, filename: String) -> io::Result<Self> {
        // Avoid cloning: pass data into the reader, parse, then reclaim the buffer.
        let digest = sha256_hex(&data);
        let mut reader = DexReader::new(data);
        let parsed = ParsedDex::parse(&mut reader, digest, filename)?;
        let raw = reader.into_inner();
        Ok(DexFileWithRaw { parsed, raw })
    }

    pub fn reader(&self) -> DexReader {
        DexReader::new(self.raw.clone())
    }

    /// Borrow the raw bytes of the DEX file (needed for debug info parsing).
    pub fn raw_bytes(&self) -> &[u8] {
        &self.raw
    }

    /// Parse the code_item at `code_off` (byte offset from file start).
    pub fn read_code_item(&self, code_off: u64) -> io::Result<CodeItem> {
        let off = code_off as usize;
        if off > self.raw.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "code_off out of bounds"));
        }
        // Slice from code_off to avoid cloning the entire DEX buffer
        let mut r = DexReader::new(self.raw[off..].to_vec());
        parse_code_item(&mut r)
    }

    /// Read only the code_item header (16 bytes) — fast path for tree building.
    /// Returns `(registers_size, insns_size)` without decoding instructions.
    pub fn read_code_item_header(&self, code_off: u64) -> io::Result<(u16, u32)> {
        let off = code_off as usize;
        if off + 16 > self.raw.len() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "code_off out of bounds"));
        }
        let raw = &self.raw[off..];
        // code_item layout: registers_size(u16), ins_size(u16), outs_size(u16),
        //                   tries_size(u16), debug_info_off(u32), insns_size(u32)
        let registers_size = u16::from_le_bytes([raw[0], raw[1]]);
        let insns_size     = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
        Ok((registers_size, insns_size))
    }
}

// ── Parsing helpers ───────────────────────────────────────────────────────────

fn parse_header(r: &mut DexReader) -> io::Result<DexHeader> {
    let magic_bytes = r.read_bytes(4)?;
    if &magic_bytes != b"dex\n" {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid DEX magic"));
    }
    let magic: [u8; 4] = magic_bytes.try_into().unwrap();

    // Version string: 4 bytes, null-terminated
    let ver_bytes = r.read_bytes(4)?;
    let version_str = String::from_utf8_lossy(
        ver_bytes.split(|&b| b == 0).next().unwrap_or(&ver_bytes),
    )
    .into_owned();

    let checksum = r.read_u32_le()?;
    let sig_bytes = r.read_bytes(20)?;
    let signature: [u8; 20] = sig_bytes.try_into().unwrap();
    let file_size     = r.read_u32_le()?;
    let header_size   = r.read_u32_le()?;
    let endian_tag    = r.read_u32_le()?;
    let link_size     = r.read_u32_le()?;
    let link_off      = r.read_u32_le()?;
    let map_off       = r.read_u32_le()?;
    let string_ids_size = r.read_u32_le()?;
    let string_ids_off  = r.read_u32_le()?;
    let type_ids_size   = r.read_u32_le()?;
    let type_ids_off    = r.read_u32_le()?;
    let proto_ids_size  = r.read_u32_le()?;
    let proto_ids_off   = r.read_u32_le()?;
    let field_ids_size  = r.read_u32_le()?;
    let field_ids_off   = r.read_u32_le()?;
    let method_ids_size = r.read_u32_le()?;
    let method_ids_off  = r.read_u32_le()?;
    let class_defs_size = r.read_u32_le()?;
    let class_defs_off  = r.read_u32_le()?;
    let data_size       = r.read_u32_le()?;
    let data_off        = r.read_u32_le()?;

    Ok(DexHeader {
        magic, version_str, checksum, signature, file_size, header_size,
        endian_tag, link_size, link_off, map_off,
        string_ids_size, string_ids_off,
        type_ids_size, type_ids_off,
        proto_ids_size, proto_ids_off,
        field_ids_size, field_ids_off,
        method_ids_size, method_ids_off,
        class_defs_size, class_defs_off,
        data_size, data_off,
    })
}

/// Decode a ULEB128 from a raw byte slice. Returns (value, bytes_consumed).
fn read_uleb128_slice(data: &[u8]) -> (u64, usize) {
    let mut result: u64 = 0;
    let mut shift = 0u32;
    let mut i = 0;
    loop {
        if i >= data.len() { break; }
        let byte = data[i];
        i += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 { break; }
        shift += 7;
        if shift >= 64 { break; }
    }
    (result, i)
}

fn parse_string_ids(r: &mut DexReader, h: &DexHeader) -> io::Result<Vec<StringData>> {
    // Read all string_data offsets sequentially
    r.seek(h.string_ids_off as u64)?;
    let mut offsets = Vec::with_capacity(h.string_ids_size as usize);
    for _ in 0..h.string_ids_size {
        offsets.push(r.read_u32_le()? as usize);
    }

    // Resolve strings in parallel using raw slice access (no cursor/seek overhead)
    let raw = r.data();
    let strings: Vec<StringData> = parallel::map(&offsets, |&off| {
        let slice = &raw[off..];
        // Skip ULEB128 utf16_size (length hint)
        let (_, consumed) = read_uleb128_slice(slice);
        // Read bytes until null terminator
        let data_slice = &slice[consumed..];
        let end = data_slice.iter().position(|&b| b == 0).unwrap_or(data_slice.len());
        let data = String::from_utf8_lossy(&data_slice[..end]).into_owned();
        StringData { data }
    });

    Ok(strings)
}

fn parse_type_ids(
    r: &mut DexReader,
    h: &DexHeader,
    strings: &[StringData],
) -> io::Result<Vec<TypeIdItem>> {
    r.seek(h.type_ids_off as u64)?;
    // Read all raw descriptor indices first (sequential)
    let mut raw_indices = Vec::with_capacity(h.type_ids_size as usize);
    for _ in 0..h.type_ids_size {
        raw_indices.push(r.read_u32_le()?);
    }
    // Resolve in parallel
    let items: Vec<TypeIdItem> = parallel::map_owned(raw_indices, |descriptor_idx| {
        let type_name = strings
            .get(descriptor_idx as usize)
            .map(|s| s.data.clone())
            .unwrap_or_default();
        TypeIdItem { descriptor_idx, type_name }
    });
    Ok(items)
}

fn parse_proto_ids(
    r: &mut DexReader,
    h: &DexHeader,
    strings: &[StringData],
    types: &[TypeIdItem],
) -> io::Result<Vec<ProtoIdItem>> {
    r.seek(h.proto_ids_off as u64)?;
    // Read raw tuples sequentially (requires cursor, not parallelizable)
    let mut raw_protos: Vec<(u32, u32, u32)> = Vec::with_capacity(h.proto_ids_size as usize);
    for _ in 0..h.proto_ids_size {
        let shorty_idx      = r.read_u32_le()?;
        let return_type_idx = r.read_u32_le()?;
        let parameters_off  = r.read_u32_le()?;
        raw_protos.push((shorty_idx, return_type_idx, parameters_off));
    }
    // Resolve param_types for protos with parameters_off != 0
    // (seeks are needed, must be sequential)
    let mut items = Vec::with_capacity(raw_protos.len());
    for (shorty_idx, return_type_idx, parameters_off) in raw_protos {
        let shorty_desc = strings.get(shorty_idx as usize).map(|s| s.data.clone()).unwrap_or_default();
        let return_type = types.get(return_type_idx as usize).map(|t| t.type_name.clone()).unwrap_or_default();
        let param_types = if parameters_off != 0 {
            r.at(parameters_off as u64, |r| parse_type_list(r, types))?
        } else {
            Vec::new()
        };
        // Precompute full proto descriptor here to avoid per-method format!/join in parse_method_ids
        let proto_desc = format!("({}){}", param_types.join(""), return_type);
        items.push(ProtoIdItem {
            shorty_idx, return_type_idx, parameters_off,
            shorty_desc, return_type, param_types, proto_desc,
        });
    }
    Ok(items)
}

fn parse_type_list(r: &mut DexReader, types: &[TypeIdItem]) -> io::Result<Vec<String>> {
    let size = r.read_u32_le()?;
    let mut list = Vec::with_capacity(size as usize);
    for _ in 0..size {
        let type_idx = r.read_u16_le()? as usize;
        list.push(
            types.get(type_idx).map(|t| t.type_name.clone()).unwrap_or_default()
        );
    }
    Ok(list)
}

// ── Annotation parsing ───────────────────────────────────────────────────────
//
// Dex annotation layout (see <https://source.android.com/devices/tech/dalvik/dex-format#annotations-directory>):
//
//   annotations_directory_item
//     ├─ class_annotations_off → annotation_set_item (one per class)
//     ├─ field_annotations[]   (skipped in MVP)
//     ├─ method_annotations[]  (skipped in MVP)
//     └─ parameter_annotations[] (skipped in MVP)
//
//   annotation_set_item
//     └─ entries[size] → uint offsets, each pointing to an annotation_item
//
//   annotation_item
//     ├─ visibility: ubyte    (0 = build, 1 = runtime, 2 = system)
//     └─ annotation: encoded_annotation
//
//   encoded_annotation
//     ├─ type_idx: uleb128    (→ type_ids, descriptor of the annotation class)
//     ├─ size:     uleb128    (number of name/value pairs)
//     └─ elements[size]       (skipped in MVP; encoded_value is 22 variant types,
//                              not worth the complexity for the first visible win)
//
// For v1 we only extract class-level annotation TYPE NAMES — no element
// values. That means `@RequiresApi(14)` renders as `@RequiresApi` in
// our output. Better than nothing; element-value parsing can be added
// later by extending `parse_encoded_annotation` to walk the elements.

/// Parsed annotations_directory: class-level, per-method, per-field,
/// per-parameter. Parameters use a nested list (`Vec<Vec<…>>`) — the
/// outer vec is indexed by parameter position, the inner vec is the
/// annotation list for that single parameter.
struct AnnotationsDirectory {
    class: Vec<AnnotationItem>,
    methods: std::collections::HashMap<u32, Vec<AnnotationItem>>,
    fields:  std::collections::HashMap<u32, Vec<AnnotationItem>>,
    parameters: std::collections::HashMap<u32, Vec<Vec<AnnotationItem>>>,
}

/// Parse the annotation directory referenced by a `ClassDefItem`.
/// Returns class-level, per-method, and per-field annotations (each
/// already resolved into `(type_name, elements)` form).
///
/// Best-effort: a malformed annotation table never fails the dex
/// parse — corrupted sections silently produce empty results.
fn parse_class_annotations(
    r: &mut DexReader,
    directory_off: u32,
    strings:   &[StringData],
    types:     &[TypeIdItem],
    field_ids: &[FieldIdItem],
) -> AnnotationsDirectory {
    let empty = AnnotationsDirectory {
        class:      Vec::new(),
        methods:    std::collections::HashMap::new(),
        fields:     std::collections::HashMap::new(),
        parameters: std::collections::HashMap::new(),
    };
    if directory_off == 0 { return empty; }

    // Step 1: read the directory header.
    //
    // annotations_directory_item:
    //   class_annotations_off:           uint
    //   fields_size:                     uint
    //   annotated_methods_size:          uint
    //   annotated_parameters_size:       uint
    //   field_annotations[fields_size]:           field_idx: uint, annotations_off: uint
    //   method_annotations[annotated_methods_size]: method_idx: uint, annotations_off: uint
    //   parameter_annotations[annotated_parameters_size]: method_idx: uint, annotations_off: uint
    //                                       (→ annotation_set_ref_list)
    //
    // We read the whole header + per-field/per-method index pairs up
    // front so we can drop the `r.at(...)` cursor and visit each
    // annotation_set without holding the directory's position.
    struct Hdr {
        class_off:  u32,
        fields:     Vec<(u32, u32)>,   // (field_idx, annotations_off)
        methods:    Vec<(u32, u32)>,   // (method_idx, annotations_off)
        parameters: Vec<(u32, u32)>,   // (method_idx, annotation_set_ref_list_off)
    }
    let hdr = match r.at(directory_off as u64, |rr| {
        let class_off              = rr.read_u32_le()?;
        let fields_size            = rr.read_u32_le()? as usize;
        let methods_size           = rr.read_u32_le()? as usize;
        let parameters_size        = rr.read_u32_le()? as usize;

        let mut fields = Vec::with_capacity(fields_size);
        for _ in 0..fields_size {
            let field_idx  = rr.read_u32_le()?;
            let ann_off    = rr.read_u32_le()?;
            fields.push((field_idx, ann_off));
        }
        let mut methods = Vec::with_capacity(methods_size);
        for _ in 0..methods_size {
            let method_idx = rr.read_u32_le()?;
            let ann_off    = rr.read_u32_le()?;
            methods.push((method_idx, ann_off));
        }
        let mut parameters = Vec::with_capacity(parameters_size);
        for _ in 0..parameters_size {
            let method_idx = rr.read_u32_le()?;
            let ann_off    = rr.read_u32_le()?;
            parameters.push((method_idx, ann_off));
        }
        Ok(Hdr { class_off, fields, methods, parameters })
    }) {
        Ok(h)  => h,
        Err(_) => return empty,
    };

    // Helper: read one annotation_set_item at `off` into `Vec<AnnotationItem>`,
    // applying the same system-visibility filter we use for class sets.
    let read_set = |r: &mut DexReader, off: u32| -> Vec<AnnotationItem> {
        if off == 0 { return Vec::new(); }
        let entry_offs: Vec<u32> = match r.at(off as u64, |rr| {
            let size = rr.read_u32_le()?;
            let mut offs = Vec::with_capacity(size as usize);
            for _ in 0..size {
                offs.push(rr.read_u32_le()?);
            }
            Ok(offs)
        }) {
            Ok(v)  => v,
            Err(_) => return Vec::new(),
        };
        const VISIBILITY_SYSTEM: u8 = 2;
        let mut out = Vec::with_capacity(entry_offs.len());
        for off in entry_offs {
            if off == 0 { continue; }
            let parsed = r.at(off as u64, |rr| {
                let visibility = rr.read_u8()?;
                let (type_idx, elements) = read_encoded_annotation(rr, strings, types, field_ids)?;
                Ok((visibility, type_idx, elements))
            });
            let (visibility, type_idx, elements) = match parsed {
                Ok(v)  => v,
                Err(_) => continue,
            };
            if visibility == VISIBILITY_SYSTEM { continue; }
            if let Some(t) = types.get(type_idx) {
                out.push(AnnotationItem {
                    type_name: t.type_name.clone(),
                    elements,
                });
            }
        }
        out
    };

    let class = read_set(r, hdr.class_off);
    let mut methods = std::collections::HashMap::new();
    for (mi, off) in hdr.methods {
        let set = read_set(r, off);
        if !set.is_empty() { methods.insert(mi, set); }
    }
    let mut fields = std::collections::HashMap::new();
    for (fi, off) in hdr.fields {
        let set = read_set(r, off);
        if !set.is_empty() { fields.insert(fi, set); }
    }

    // Parameter annotations: each method points at an
    // annotation_set_ref_list, which is a list of annotation_set_item
    // offsets (one per parameter position). The set at index `i` is
    // the annotation list for the method's i-th parameter; a zero
    // offset means "no annotations for this parameter".
    let mut parameters = std::collections::HashMap::new();
    for (mi, ref_list_off) in hdr.parameters {
        if ref_list_off == 0 { continue; }
        // Read the annotation_set_ref_list itself.
        let inner_offs: Vec<u32> = match r.at(ref_list_off as u64, |rr| {
            let size = rr.read_u32_le()?;
            let mut offs = Vec::with_capacity(size as usize);
            for _ in 0..size {
                offs.push(rr.read_u32_le()?);
            }
            Ok(offs)
        }) {
            Ok(v)  => v,
            Err(_) => continue,
        };
        // For each parameter slot, resolve its annotation_set_item.
        // We preserve empty positions (zero offsets) so the renderer
        // can map by parameter index.
        let per_param: Vec<Vec<AnnotationItem>> = inner_offs.iter()
            .map(|&off| read_set(r, off))
            .collect();
        // Don't insert if *every* parameter is unannotated — saves a
        // tiny amount of memory and lets renderers cheaply skip the
        // common case via `HashMap::get`.
        if per_param.iter().any(|p| !p.is_empty()) {
            parameters.insert(mi, per_param);
        }
    }

    AnnotationsDirectory { class, methods, fields, parameters }
}

/// Parse one `encoded_annotation`: `type_idx (uleb128), size (uleb128),
/// elements[size] (annotation_element)`. Returns `(type_idx, [(name,
/// value_repr), …])`.
fn read_encoded_annotation(
    r: &mut DexReader,
    strings:   &[StringData],
    types:     &[TypeIdItem],
    field_ids: &[FieldIdItem],
) -> io::Result<(usize, Vec<(String, String)>)> {
    let type_idx = r.read_uleb128()? as usize;
    let size     = r.read_uleb128()? as usize;
    let mut elements = Vec::with_capacity(size);
    for _ in 0..size {
        let name_idx = r.read_uleb128()? as usize;
        let name = strings.get(name_idx)
            .map(|s| s.data.clone())
            .unwrap_or_default();
        let value = read_encoded_value(r, strings, types, field_ids)?;
        elements.push((name, value));
    }
    Ok((type_idx, elements))
}

/// Parse one `encoded_value` and render it as a Java source snippet.
///
/// The dex encoded_value format packs a 1-byte header
/// `(value_arg << 5) | value_type` followed by 0..n payload bytes
/// (length implied by value_arg+1 for the integer/string-ref family).
/// We handle the most common types directly and emit a `/* type=… */`
/// placeholder for the rare ones (array, nested annotation, method
/// handle) so the rendered annotation at least preserves the element
/// name even when we can't render the value.
///
/// The rendered string is ready for direct splat into the generated
/// Java — integers as decimal literals, strings already quoted, type
/// refs as `Foo.class`, etc.
fn read_encoded_value(
    r: &mut DexReader,
    strings:   &[StringData],
    types:     &[TypeIdItem],
    field_ids: &[FieldIdItem],
) -> io::Result<String> {
    let header   = r.read_u8()?;
    let value_arg  = (header >> 5) & 0x07;
    let value_type = header & 0x1f;

    // Helper to read a `value_arg + 1`-byte little-endian unsigned int.
    fn read_n(r: &mut DexReader, n: usize) -> io::Result<u64> {
        let mut v: u64 = 0;
        for i in 0..n {
            let b = r.read_u8()? as u64;
            v |= b << (8 * i);
        }
        Ok(v)
    }
    // Sign-extend an n-byte unsigned int to i64.
    fn sign_extend(raw: u64, bytes: usize) -> i64 {
        let bits = bytes * 8;
        if bits >= 64 { return raw as i64; }
        let sign_bit = 1u64 << (bits - 1);
        if raw & sign_bit != 0 {
            // Fill the upper bits with 1s.
            (raw | (!0u64 << bits)) as i64
        } else {
            raw as i64
        }
    }

    let bytes_len = (value_arg as usize) + 1;
    let rendered = match value_type {
        // VALUE_BYTE: 1 byte, signed.
        0x00 => format!("{}", sign_extend(read_n(r, 1)?, 1)),
        // VALUE_SHORT: 1..2 bytes, signed.
        0x02 => format!("{}", sign_extend(read_n(r, bytes_len)?, bytes_len)),
        // VALUE_CHAR: 1..2 bytes, unsigned (char codepoint).
        0x03 => {
            let n = read_n(r, bytes_len)?;
            match char::from_u32(n as u32) {
                Some(c) if !c.is_control() => format!("'{}'", c.escape_default()),
                _                          => format!("(char) {}", n),
            }
        }
        // VALUE_INT: 1..4 bytes, signed.
        0x04 => format!("{}", sign_extend(read_n(r, bytes_len)?, bytes_len)),
        // VALUE_LONG: 1..8 bytes, signed.
        0x06 => format!("{}L", sign_extend(read_n(r, bytes_len)?, bytes_len)),
        // VALUE_FLOAT / VALUE_DOUBLE: zero-pad the payload on the RIGHT
        // (high-order bytes) rather than left. Rendered as the raw
        // numeric form; precision loss when fewer than 4/8 bytes are
        // present is mirrored from the dex (it's how the encoder
        // shrinks zero-padded values).
        0x10 => {
            let raw = read_n(r, bytes_len)?;
            let padded = (raw << ((4 - bytes_len) * 8)) as u32;
            format!("{}f", f32::from_bits(padded))
        }
        0x11 => {
            let raw = read_n(r, bytes_len)?;
            let padded = raw << ((8 - bytes_len) * 8);
            format!("{}", f64::from_bits(padded))
        }
        // VALUE_STRING: idx → string_ids.
        0x17 => {
            let idx = read_n(r, bytes_len)? as usize;
            let raw = strings.get(idx).map(|s| s.data.as_str()).unwrap_or("");
            // Cheap Java escape — keep the renderer self-contained.
            let mut esc = String::with_capacity(raw.len() + 2);
            esc.push('"');
            for c in raw.chars() {
                match c {
                    '"'  => esc.push_str("\\\""),
                    '\\' => esc.push_str("\\\\"),
                    '\n' => esc.push_str("\\n"),
                    '\r' => esc.push_str("\\r"),
                    '\t' => esc.push_str("\\t"),
                    c    => esc.push(c),
                }
            }
            esc.push('"');
            esc
        }
        // VALUE_TYPE: idx → type_ids; rendered as `Foo.class`.
        0x18 => {
            let idx = read_n(r, bytes_len)? as usize;
            let desc = types.get(idx).map(|t| t.type_name.as_str()).unwrap_or("");
            // Convert `Lcom/Foo$Bar;` → `Foo$Bar.class` for the class
            // literal form. Primitive types like `I` → `int.class`.
            let simple = simple_java_class_name(desc);
            format!("{}.class", simple)
        }
        // VALUE_NULL: no payload, value_arg must be 0.
        0x1e => "null".to_string(),
        // VALUE_BOOLEAN: payload is in value_arg (no bytes follow).
        0x1f => if value_arg != 0 { "true".to_string() } else { "false".to_string() },
        // VALUE_ARRAY: encoded_array follows — `size: uleb128`, then
        // size values. We render a `{ a, b, c }` initialiser to
        // match Java array-element notation in annotations.
        0x1c => {
            let size = r.read_uleb128()? as usize;
            let mut items = Vec::with_capacity(size);
            for _ in 0..size {
                items.push(read_encoded_value(r, strings, types, field_ids)?);
            }
            format!("{{{}}}", items.join(", "))
        }
        // VALUE_ANNOTATION: nested encoded_annotation. Render as
        // `@Inner(...)` recursively.
        0x1d => {
            let (inner_type_idx, inner_elements) =
                read_encoded_annotation(r, strings, types, field_ids)?;
            let inner_name = types.get(inner_type_idx)
                .map(|t| simple_java_class_name(&t.type_name))
                .unwrap_or_else(|| "Unknown".to_string());
            let body = render_annotation_elements(&inner_elements);
            format!("@{}{}", inner_name, body)
        }
        // VALUE_ENUM: idx → field_ids. The enum CONSTANT is a static
        // field on the enum class — `RetentionPolicy.CLASS` is
        // really `Ljava/lang/annotation/RetentionPolicy;->CLASS`.
        // Resolve through the field_ids table to get both halves.
        0x1b => {
            let idx = read_n(r, bytes_len)? as usize;
            match field_ids.get(idx) {
                Some(f) => format!("{}.{}",
                    simple_java_class_name(&f.class_name),
                    f.field_name),
                None    => format!("/* enum #{} */", idx),
            }
        }
        // VALUE_METHOD / VALUE_FIELD / VALUE_METHOD_TYPE / VALUE_METHOD_HANDLE
        // — same story: render placeholders, consume the bytes.
        0x15 | 0x16 | 0x19 | 0x1a => {
            let _idx = read_n(r, bytes_len)?;
            format!("/* type=0x{:02x} */", value_type)
        }
        _ => {
            // Unknown / future type — consume what value_arg implies
            // so we don't fall out of sync with the byte stream.
            for _ in 0..bytes_len { let _ = r.read_u8(); }
            format!("/* type=0x{:02x} */", value_type)
        }
    };
    Ok(rendered)
}

/// Render an `encoded_annotation`'s element list as the `(...)` body
/// of a Java annotation, with the standard single-element-named-"value"
/// shorthand: `@X(v)` instead of `@X(value=v)`.
fn render_annotation_elements(elements: &[(String, String)]) -> String {
    if elements.is_empty() { return String::new(); }
    if elements.len() == 1 && elements[0].0 == "value" {
        return format!("({})", elements[0].1);
    }
    let parts: Vec<String> = elements.iter()
        .map(|(k, v)| format!("{} = {}", k, v))
        .collect();
    format!("({})", parts.join(", "))
}

/// Convert a Dalvik type descriptor (`Lcom/Foo$Bar;`, `I`,
/// `[Ljava/lang/String;`) to a Java source form (`Foo.Bar`, `int`,
/// `String[]`). Inner-class `$` separators become `.` for source
/// readability (`RestrictTo$Scope` → `RestrictTo.Scope`). Local to
/// this module — codegen has its own variant but parser.rs shouldn't
/// pull in the codegen crate just for one helper.
fn simple_java_class_name(desc: &str) -> String {
    match desc {
        "V" => return "void".into(),    "Z" => return "boolean".into(),
        "B" => return "byte".into(),    "S" => return "short".into(),
        "C" => return "char".into(),    "I" => return "int".into(),
        "J" => return "long".into(),    "F" => return "float".into(),
        "D" => return "double".into(),
        _ => {}
    }
    if let Some(inner) = desc.strip_prefix('[') {
        return format!("{}[]", simple_java_class_name(inner));
    }
    let inner = desc.trim_start_matches('L').trim_end_matches(';');
    let simple = inner.rsplit('/').next().unwrap_or(inner);
    // Convert dollar-separated inner-class names to dot-separated for
    // source-level readability. Anonymous inner-class compiler names
    // (`Foo$1`, `Foo$$Lambda$0`) would also be affected; we accept
    // that since jadx makes the same trade-off and the alternative
    // (regex-detecting digit suffixes) misses too many real cases.
    simple.replace('$', ".")
}

fn parse_field_ids(
    r: &mut DexReader,
    h: &DexHeader,
    strings: &[StringData],
    types: &[TypeIdItem],
) -> io::Result<Vec<FieldIdItem>> {
    r.seek(h.field_ids_off as u64)?;
    // Read all raw tuples first (sequential)
    let mut raw: Vec<(u16, u16, u32)> = Vec::with_capacity(h.field_ids_size as usize);
    for _ in 0..h.field_ids_size {
        let class_idx = r.read_u16_le()?;
        let type_idx  = r.read_u16_le()?;
        let name_idx  = r.read_u32_le()?;
        raw.push((class_idx, type_idx, name_idx));
    }
    // Resolve strings in parallel
    let items: Vec<FieldIdItem> = parallel::map_owned(raw, |(class_idx, type_idx, name_idx)| {
        let class_name = types.get(class_idx as usize).map(|t| t.type_name.clone()).unwrap_or_default();
        let type_name  = types.get(type_idx  as usize).map(|t| t.type_name.clone()).unwrap_or_default();
        let field_name = strings.get(name_idx as usize).map(|s| s.data.clone()).unwrap_or_default();
        FieldIdItem { class_idx, type_idx, name_idx, class_name, type_name, field_name }
    });
    Ok(items)
}

fn parse_method_ids(
    r: &mut DexReader,
    h: &DexHeader,
    strings: &[StringData],
    types: &[TypeIdItem],
    protos: &[ProtoIdItem],
) -> io::Result<Vec<MethodIdItem>> {
    r.seek(h.method_ids_off as u64)?;
    // Read all raw tuples first (sequential I/O)
    let mut raw: Vec<(u16, u16, u32)> = Vec::with_capacity(h.method_ids_size as usize);
    for _ in 0..h.method_ids_size {
        let class_idx = r.read_u16_le()?;
        let proto_idx = r.read_u16_le()?;
        let name_idx  = r.read_u32_le()?;
        raw.push((class_idx, proto_idx, name_idx));
    }
    // Resolve strings in parallel — proto_desc is pre-built in ProtoIdItem, so no format!/join here
    let items: Vec<MethodIdItem> = parallel::map_owned(raw, |(class_idx, proto_idx, name_idx)| {
        let class_name  = types.get(class_idx as usize).map(|t| t.type_name.clone()).unwrap_or_default();
        let proto_desc  = protos.get(proto_idx as usize).map(|p| p.proto_desc.clone()).unwrap_or_default();
        let method_name = strings.get(name_idx as usize).map(|s| s.data.clone()).unwrap_or_default();
        MethodIdItem { class_idx, proto_idx, name_idx, class_name, proto_desc, method_name }
    });
    Ok(items)
}

fn parse_class_defs(
    r: &mut DexReader,
    h: &DexHeader,
    strings: &[StringData],
    types: &[TypeIdItem],
    field_ids: &[FieldIdItem],
) -> io::Result<Vec<ClassDefItem>> {
    r.seek(h.class_defs_off as u64)?;
    let mut items = Vec::with_capacity(h.class_defs_size as usize);
    for _ in 0..h.class_defs_size {
        let class_idx          = r.read_u32_le()?;
        let access_flags       = r.read_u32_le()?;
        let superclass_idx     = r.read_u32_le()?;
        let interfaces_off     = r.read_u32_le()?;
        let source_file_idx    = r.read_u32_le()?;
        let annotations_off    = r.read_u32_le()?;
        let class_data_off     = r.read_u32_le()?;
        let static_values_off  = r.read_u32_le()?;

        let type_name = types.get(class_idx as usize)
            .map(|t| t.type_name.clone())
            .unwrap_or_default();

        // Resolve the superclass and implemented-interface descriptors
        // up front so consumers (decompiler, smali emitter, codegen) don't
        // each have to re-walk the dex bytes. The dex format uses
        // 0xFFFFFFFF as the "no superclass" sentinel — only `Object`
        // itself triggers that path.
        let superclass_name = if superclass_idx == u32::MAX {
            String::new()
        } else {
            types.get(superclass_idx as usize)
                .map(|t| t.type_name.clone())
                .unwrap_or_default()
        };
        let interfaces = if interfaces_off == 0 {
            Vec::new()
        } else {
            // Best-effort: a corrupt offset shouldn't take down the whole
            // dex parse — fall back to no interfaces on read failure.
            r.at(interfaces_off as u64, |rr| parse_type_list(rr, types))
                .unwrap_or_default()
        };

        // Annotations: class-level + per-method + per-field +
        // per-parameter, all in one walk of annotations_directory_item.
        // Best-effort like interfaces — a bad table shouldn't take
        // down the parse.
        let ann_dir = parse_class_annotations(r, annotations_off, strings, types, field_ids);
        let annotations           = ann_dir.class;
        let method_annotations    = ann_dir.methods;
        let field_annotations     = ann_dir.fields;
        let parameter_annotations = ann_dir.parameters;

        let class_data = if class_data_off != 0 {
            Some(r.at(class_data_off as u64, parse_class_data_item)?)
        } else {
            None
        };

        items.push(ClassDefItem {
            class_idx, access_flags, superclass_idx, interfaces_off,
            source_file_idx, annotations_off, class_data_off, static_values_off,
            type_name, class_data, superclass_name, interfaces, annotations,
            method_annotations, field_annotations, parameter_annotations,
        });
    }
    Ok(items)
}

fn parse_class_data_item(r: &mut DexReader) -> io::Result<ClassDataItem> {
    let static_fields_size   = r.read_uleb128()? as usize;
    let instance_fields_size = r.read_uleb128()? as usize;
    let direct_methods_size  = r.read_uleb128()? as usize;
    let virtual_methods_size = r.read_uleb128()? as usize;

    let static_fields   = parse_encoded_fields(r, static_fields_size)?;
    let instance_fields = parse_encoded_fields(r, instance_fields_size)?;
    let direct_methods  = parse_encoded_methods(r, direct_methods_size)?;
    let virtual_methods = parse_encoded_methods(r, virtual_methods_size)?;

    Ok(ClassDataItem { static_fields, instance_fields, direct_methods, virtual_methods })
}

fn parse_encoded_fields(r: &mut DexReader, count: usize) -> io::Result<Vec<EncodedField>> {
    let mut fields = Vec::with_capacity(count);
    for _ in 0..count {
        let field_idx_diff = r.read_uleb128()?;
        let access_flags   = r.read_uleb128()?;
        fields.push(EncodedField { field_idx_diff, access_flags });
    }
    Ok(fields)
}

fn parse_encoded_methods(r: &mut DexReader, count: usize) -> io::Result<Vec<EncodedMethod>> {
    let mut methods = Vec::with_capacity(count);
    for _ in 0..count {
        let method_idx_diff = r.read_uleb128()?;
        let access_flags    = r.read_uleb128()?;
        let code_off        = r.read_uleb128()?;
        methods.push(EncodedMethod { method_idx_diff, access_flags, code_off });
    }
    Ok(methods)
}

/// Parse a code_item starting at the current reader position.
pub fn parse_code_item(r: &mut DexReader) -> io::Result<CodeItem> {
    let registers_size  = r.read_u16_le()?;
    let ins_size        = r.read_u16_le()?;
    let outs_size       = r.read_u16_le()?;
    let tries_size      = r.read_u16_le()?;
    let debug_info_off  = r.read_u32_le()?;
    let insns_size      = r.read_u32_le()?;

    // insns: insns_size code units = insns_size * 2 bytes
    let insns = r.read_bytes(insns_size as usize * 2)?;

    // Optional padding + try_items
    let mut try_items: Vec<TryItem> = Vec::new();
    let mut handlers: Vec<EncodedCatchHandler> = Vec::new();

    if tries_size > 0 {
        // Align to 4 bytes if insns_size is odd
        if insns_size % 2 != 0 {
            let _ = r.read_u16_le(); // padding
        }
        for _ in 0..tries_size {
            let start_addr     = r.read_u32_le()?;
            let insn_count     = r.read_u16_le()?;
            let handler_offset = r.read_u16_le()?;
            try_items.push(TryItem { start_addr, insn_count, handler_offset });
        }
        handlers = parse_encoded_catch_handler_list(r)?;
    }

    Ok(CodeItem { registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size, insns, try_items, handlers })
}

fn parse_encoded_catch_handler_list(r: &mut DexReader) -> io::Result<Vec<EncodedCatchHandler>> {
    let size = r.read_uleb128()? as usize;
    let mut list = Vec::with_capacity(size);
    for _ in 0..size {
        list.push(parse_encoded_catch_handler(r)?);
    }
    Ok(list)
}

fn parse_encoded_catch_handler(r: &mut DexReader) -> io::Result<EncodedCatchHandler> {
    let size_sleb = r.read_sleb128()?;
    let is_catch_all = size_sleb <= 0;
    let handler_count = size_sleb.unsigned_abs() as usize;

    let mut handlers = Vec::with_capacity(handler_count);
    for _ in 0..handler_count {
        let type_idx = r.read_uleb128()?;
        let addr     = r.read_uleb128()?;
        handlers.push(CatchHandler { type_idx, addr });
    }

    let catch_all_addr = if is_catch_all {
        Some(r.read_uleb128()?)
    } else {
        None
    };

    Ok(EncodedCatchHandler { handlers, catch_all_addr })
}

// ── SHA-256 (stdlib only) ────────────────────────────────────────────────────

/// Compute a hex-encoded SHA-256 digest using only std.
/// This is a pure-Rust implementation of SHA-256 without external crates.
fn sha256_hex(data: &[u8]) -> String {
    let hash = sha256(data);
    hash.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sha256(data: &[u8]) -> [u8; 32] {
    // SHA-256 constants
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ];

    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing: add padding
    let mut msg: Vec<u8> = data.to_vec();
    let bit_len = (data.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());

    // Process each 512-bit (64-byte) block
    for block in msg.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[i*4], block[i*4+1], block[i*4+2], block[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1   = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch   = (e & f) ^ (!e & g);
            let tmp1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0   = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj  = (a & b) ^ (a & c) ^ (b & c);
            let tmp2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e;
            e = d.wrapping_add(tmp1);
            d = c; c = b; b = a;
            a = tmp1.wrapping_add(tmp2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, &v) in h.iter().enumerate() {
        out[i*4..i*4+4].copy_from_slice(&v.to_be_bytes());
    }
    out
}
