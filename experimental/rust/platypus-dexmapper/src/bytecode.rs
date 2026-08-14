//! Pure-Rust JVM `.class` file parser. Reads constant pool, access flags,
//! this/super/interfaces, fields, methods, the `Code` attribute (for call
//! edges + field accesses), and the `SourceFile` attribute. No JDK, no
//! `javap`, no native deps — just byte-level decoding per JVMS §4.
//!
//! Mirrors the Python `dexmapper.core.bytecode` module — same public
//! shape, same semantics.
//!
//! Use [`extract_classes_from_jar`] / [`extract_classes_from_aar`] to
//! batch-parse every class out of a Maven artifact.

use std::io::{self, Cursor, Read};
use std::path::Path;

// ── Constant-pool tags (JVMS §4.4) ─────────────────────────────────────────

const CP_UTF8:           u8 = 1;
const CP_INTEGER:        u8 = 3;
const CP_FLOAT:          u8 = 4;
const CP_LONG:           u8 = 5;
const CP_DOUBLE:         u8 = 6;
const CP_CLASS:          u8 = 7;
const CP_STRING:         u8 = 8;
const CP_FIELDREF:       u8 = 9;
const CP_METHODREF:      u8 = 10;
const CP_INTERFACE_MREF: u8 = 11;
const CP_NAME_AND_TYPE:  u8 = 12;
const CP_METHOD_HANDLE:  u8 = 15;
const CP_METHOD_TYPE:    u8 = 16;
const CP_DYNAMIC:        u8 = 17;
const CP_INVOKE_DYNAMIC: u8 = 18;
const CP_MODULE:         u8 = 19;
const CP_PACKAGE:        u8 = 20;

// ── Public types ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub descriptor: String,
    pub flags: u16,
}

#[derive(Debug, Clone)]
pub struct CallEdge {
    pub callee_class: String,       // internal name, no L/; wrapper
    pub callee_name: String,
    pub callee_descriptor: String,
    pub call_type: CallType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallType { Virtual, Static, Interface, Special }

impl CallType {
    pub fn as_str(self) -> &'static str {
        match self {
            CallType::Virtual   => "virtual",
            CallType::Static    => "static",
            CallType::Interface => "interface",
            CallType::Special   => "special",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FieldRef {
    pub class: String,
    pub name: String,
    pub descriptor: String,
}

#[derive(Debug, Clone)]
pub struct MethodInfo {
    pub name: String,
    pub descriptor: String,
    pub flags: u16,
    pub call_edges: Vec<CallEdge>,
    pub field_gets: Vec<FieldRef>,
    pub field_puts: Vec<FieldRef>,
    pub local_count: u32,
}

#[derive(Debug, Clone)]
pub struct ClassInfo {
    pub internal_name: String,         // com/example/Foo
    pub superclass: Option<String>,
    pub interfaces: Vec<String>,
    pub flags: u16,
    pub source_file: Option<String>,
    pub fields: Vec<FieldInfo>,
    pub methods: Vec<MethodInfo>,
}

impl ClassInfo {
    pub fn fqn(&self) -> String { self.internal_name.replace('/', ".") }
    pub fn package(&self) -> String {
        let fqn = self.fqn();
        fqn.rfind('.').map(|i| fqn[..i].to_string()).unwrap_or_default()
    }
    pub fn simple_name(&self) -> String {
        let fqn = self.fqn();
        fqn.rfind('.').map(|i| fqn[i + 1..].to_string()).unwrap_or(fqn)
    }
    pub fn is_interface(&self) -> bool { self.flags & 0x0200 != 0 }
    pub fn is_abstract(&self)  -> bool { self.flags & 0x0400 != 0 }
    pub fn is_enum(&self)      -> bool { self.flags & 0x4000 != 0 }
}

// ── Parser ─────────────────────────────────────────────────────────────────

/// Tag + payload for one constant-pool entry. We only carry payload for
/// the entries the rest of the pipeline reads.
#[derive(Debug, Clone)]
enum CpEntry {
    /// Reserved long/double half-slot — never read directly.
    Unused,
    /// Other tags we don't need details from — only the tag matters.
    Tag(u8),
    Utf8(String),
    Class { name_idx: u16 },
    StringRef { utf8_idx: u16 },
    Ref { _tag: u8, class_idx: u16, nat_idx: u16 }, // fieldref / methodref / interface-methodref
    NameAndType { name_idx: u16, desc_idx: u16 },
}

pub struct ClassFileParser<'a> {
    buf: Cursor<&'a [u8]>,
    cp: Vec<CpEntry>,
}

impl<'a> ClassFileParser<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { buf: Cursor::new(data), cp: Vec::new() }
    }

    /// Parse the class. Returns `None` on any error — we deliberately
    /// swallow malformed entries because we want batch-extraction (over
    /// a jar with thousands of classes) to keep going.
    pub fn parse(mut self) -> Option<ClassInfo> {
        let magic = self.r4().ok()?;
        if magic != 0xCAFEBABE { return None; }
        let _minor = self.r2().ok()?;
        let _major = self.r2().ok()?;

        let cp_count = self.r2().ok()? as usize;
        self.parse_constant_pool(cp_count).ok()?;

        let flags = self.r2().ok()?;
        let this_idx = self.r2().ok()?;
        let this_class = self.cp_class(this_idx).unwrap_or_default();
        let super_idx = self.r2().ok()?;
        let superclass = if super_idx == 0 { None } else { self.cp_class(super_idx) };

        let iface_count = self.r2().ok()? as usize;
        let mut interfaces = Vec::with_capacity(iface_count);
        for _ in 0..iface_count {
            let idx = self.r2().ok()?;
            if let Some(name) = self.cp_class(idx) { interfaces.push(name); }
        }

        // Fields
        let field_count = self.r2().ok()? as usize;
        let mut fields = Vec::with_capacity(field_count);
        for _ in 0..field_count {
            let f_flags = self.r2().ok()?;
            // Split into two statements per name/desc — `self.r2()` is a
            // mutable borrow and `self.cp_str(...)` an immutable one,
            // and the borrow checker can't see they touch disjoint fields.
            let name_idx = self.r2().ok()?;
            let f_name = self.cp_str(name_idx).unwrap_or_default();
            let desc_idx = self.r2().ok()?;
            let f_desc = self.cp_str(desc_idx).unwrap_or_default();
            let attr_count = self.r2().ok()? as usize;
            self.skip_attributes(attr_count).ok()?;
            fields.push(FieldInfo { name: f_name, descriptor: f_desc, flags: f_flags });
        }

        // Methods
        let method_count = self.r2().ok()? as usize;
        let mut methods = Vec::with_capacity(method_count);
        for _ in 0..method_count {
            let m_flags = self.r2().ok()?;
            let name_idx = self.r2().ok()?;
            let m_name = self.cp_str(name_idx).unwrap_or_default();
            let desc_idx = self.r2().ok()?;
            let m_desc = self.cp_str(desc_idx).unwrap_or_default();
            let attr_count = self.r2().ok()? as usize;
            let attrs = self.read_attributes(attr_count).ok()?;

            let mut local_count = 0u32;
            let mut call_edges  = Vec::new();
            let mut field_gets  = Vec::new();
            let mut field_puts  = Vec::new();
            if let Some(code) = attrs.iter().find(|(name, _)| name == "Code").map(|(_, d)| d) {
                if let Ok((locals, edges, gets, puts)) = self.parse_code_attribute(code) {
                    local_count = locals as u32;
                    call_edges  = edges;
                    field_gets  = gets;
                    field_puts  = puts;
                }
            }

            methods.push(MethodInfo {
                name: m_name, descriptor: m_desc, flags: m_flags,
                call_edges, field_gets, field_puts, local_count,
            });
        }

        // Class attributes — pluck SourceFile if present.
        let attr_count = self.r2().ok()? as usize;
        let class_attrs = self.read_attributes(attr_count).ok()?;
        let source_file = class_attrs.iter()
            .find(|(name, _)| name == "SourceFile")
            .and_then(|(_, data)| {
                if data.len() < 2 { return None; }
                let idx = u16::from_be_bytes([data[0], data[1]]);
                self.cp_str(idx)
            });

        Some(ClassInfo {
            internal_name: this_class,
            superclass,
            interfaces,
            flags,
            source_file,
            fields,
            methods,
        })
    }

    // ── Constant pool ──────────────────────────────────────────────────────

    fn parse_constant_pool(&mut self, count: usize) -> io::Result<()> {
        self.cp = vec![CpEntry::Unused; count]; // cp[0] unused
        let mut i = 1;
        while i < count {
            let tag = self.r1()?;
            match tag {
                CP_UTF8 => {
                    let len = self.r2()? as usize;
                    let mut bytes = vec![0u8; len];
                    self.buf.read_exact(&mut bytes)?;
                    let s = decode_mutf8(&bytes);
                    self.cp[i] = CpEntry::Utf8(s);
                }
                CP_INTEGER | CP_FLOAT => { let _ = self.r4()?; self.cp[i] = CpEntry::Tag(tag); }
                CP_LONG | CP_DOUBLE => {
                    let _ = self.r4()?; let _ = self.r4()?;
                    self.cp[i] = CpEntry::Tag(tag);
                    if i + 1 < count { self.cp[i + 1] = CpEntry::Unused; }
                    i += 1;
                }
                CP_CLASS => { let name_idx = self.r2()?; self.cp[i] = CpEntry::Class { name_idx }; }
                CP_STRING => { let utf8_idx = self.r2()?; self.cp[i] = CpEntry::StringRef { utf8_idx }; }
                CP_FIELDREF | CP_METHODREF | CP_INTERFACE_MREF => {
                    let class_idx = self.r2()?;
                    let nat_idx   = self.r2()?;
                    self.cp[i] = CpEntry::Ref { _tag: tag, class_idx, nat_idx };
                }
                CP_NAME_AND_TYPE => {
                    let name_idx = self.r2()?;
                    let desc_idx = self.r2()?;
                    self.cp[i] = CpEntry::NameAndType { name_idx, desc_idx };
                }
                CP_METHOD_HANDLE => { let _ = self.r1()?; let _ = self.r2()?; self.cp[i] = CpEntry::Tag(tag); }
                CP_METHOD_TYPE | CP_MODULE | CP_PACKAGE => { let _ = self.r2()?; self.cp[i] = CpEntry::Tag(tag); }
                CP_DYNAMIC | CP_INVOKE_DYNAMIC => { let _ = self.r4()?; self.cp[i] = CpEntry::Tag(tag); }
                _ => { self.cp[i] = CpEntry::Tag(tag); } // unknown — stop reading payload
            }
            i += 1;
        }
        Ok(())
    }

    fn cp_str(&self, idx: u16) -> Option<String> {
        let i = idx as usize;
        if i == 0 || i >= self.cp.len() { return None; }
        match &self.cp[i] {
            CpEntry::Utf8(s) => Some(s.clone()),
            CpEntry::Class { name_idx } => self.cp_str(*name_idx),
            CpEntry::NameAndType { name_idx, .. } => self.cp_str(*name_idx),
            CpEntry::StringRef { utf8_idx } => self.cp_str(*utf8_idx),
            _ => None,
        }
    }

    fn cp_class(&self, idx: u16) -> Option<String> {
        let i = idx as usize;
        if i == 0 || i >= self.cp.len() { return None; }
        match &self.cp[i] {
            CpEntry::Class { name_idx } => self.cp_str(*name_idx),
            _ => None,
        }
    }

    fn cp_name_and_type(&self, idx: u16) -> Option<(String, String)> {
        let i = idx as usize;
        if i == 0 || i >= self.cp.len() { return None; }
        if let CpEntry::NameAndType { name_idx, desc_idx } = &self.cp[i] {
            Some((self.cp_str(*name_idx)?, self.cp_str(*desc_idx)?))
        } else { None }
    }

    // ── Attribute table ────────────────────────────────────────────────────

    fn read_attributes(&mut self, count: usize) -> io::Result<Vec<(String, Vec<u8>)>> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            let name_idx = self.r2()?;
            let len = self.r4()? as usize;
            let mut data = vec![0u8; len];
            self.buf.read_exact(&mut data)?;
            let name = self.cp_str(name_idx).unwrap_or_default();
            out.push((name, data));
        }
        Ok(out)
    }

    fn skip_attributes(&mut self, count: usize) -> io::Result<()> {
        for _ in 0..count {
            let _name_idx = self.r2()?;
            let len = self.r4()? as usize;
            let mut sink = vec![0u8; len];
            self.buf.read_exact(&mut sink)?;
        }
        Ok(())
    }

    // ── Code attribute walker ──────────────────────────────────────────────

    fn parse_code_attribute(&self, data: &[u8])
        -> io::Result<(u16, Vec<CallEdge>, Vec<FieldRef>, Vec<FieldRef>)>
    {
        let mut c = Cursor::new(data);
        let mut buf2 = [0u8; 2]; let mut buf4 = [0u8; 4];
        c.read_exact(&mut buf2)?;  // max_stack
        c.read_exact(&mut buf2)?;
        let max_locals = u16::from_be_bytes(buf2);
        c.read_exact(&mut buf4)?;
        let code_len = u32::from_be_bytes(buf4) as usize;

        // Pull the bytecode body — we only need to walk it, no need to
        // also load exception table / nested attributes.
        let mut code = vec![0u8; code_len];
        c.read_exact(&mut code)?;

        let mut edges = Vec::new();
        let mut gets  = Vec::new();
        let mut puts  = Vec::new();

        // Helper closure: safe little-endian-style 2-byte cp index read.
        // Returns None when there aren't 2 bytes left in the buffer (malformed
        // code that ends mid-instruction — we treat it as a stop signal).
        let read_u16_at = |buf: &[u8], pos: usize| -> Option<u16> {
            if pos + 2 > buf.len() { None } else {
                Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
            }
        };

        let mut i = 0;
        while i < code.len() {
            let op = code[i];
            match op {
                // invokevirtual / invokespecial / invokestatic / invokeinterface
                0xb6 | 0xb7 | 0xb8 | 0xb9 => {
                    if let Some(idx) = read_u16_at(&code, i + 1) {
                        // Bounds-check the cp index — `idx` comes from the
                        // bytecode and a corrupt or mis-walked stream could
                        // exceed `self.cp.len()`. Silently skip in that case.
                        if (idx as usize) < self.cp.len() {
                            if let CpEntry::Ref { class_idx, nat_idx, .. } = &self.cp[idx as usize] {
                                let cls = self.cp_class(*class_idx).unwrap_or_default();
                                if let Some((name, desc)) = self.cp_name_and_type(*nat_idx) {
                                    let call_type = match op {
                                        0xb6 => CallType::Virtual,
                                        0xb7 => CallType::Special,
                                        0xb8 => CallType::Static,
                                        _    => CallType::Interface,
                                    };
                                    edges.push(CallEdge {
                                        callee_class: cls,
                                        callee_name: name,
                                        callee_descriptor: desc,
                                        call_type,
                                    });
                                }
                            }
                        }
                    }
                    i += if op == 0xb9 { 5 } else { 3 };
                    continue;
                }
                // getstatic / putstatic / getfield / putfield
                0xb2 | 0xb3 | 0xb4 | 0xb5 => {
                    if let Some(idx) = read_u16_at(&code, i + 1) {
                        if (idx as usize) < self.cp.len() {
                            if let CpEntry::Ref { class_idx, nat_idx, .. } = &self.cp[idx as usize] {
                                let cls = self.cp_class(*class_idx).unwrap_or_default();
                                if let Some((name, desc)) = self.cp_name_and_type(*nat_idx) {
                                    let r = FieldRef { class: cls, name, descriptor: desc };
                                    if matches!(op, 0xb2 | 0xb4) { gets.push(r); } else { puts.push(r); }
                                }
                            }
                        }
                    }
                    i += 3;
                    continue;
                }
                // wide — JVMS §6.5.wide. Wraps a 16-bit-indexed load/store
                // (4 bytes total) or iinc (6 bytes total).
                0xc4 => {
                    if i + 1 >= code.len() { break; }
                    let next_op = code[i + 1];
                    i += if next_op == 0x84 /* iinc */ { 6 } else { 4 };
                    continue;
                }
                // tableswitch — variable length. JVMS §6.5.tableswitch.
                //   header: u8 opcode, 0-3 pad bytes (4-byte align), i32 default,
                //           i32 low, i32 high, then (high-low+1) × i32 offsets.
                0xaa => {
                    let pad = (4 - ((i + 1) % 4)) % 4;
                    let mut j = i + 1 + pad;
                    if j + 12 > code.len() { break; }
                    j += 4; // skip default
                    let low  = i32::from_be_bytes([code[j], code[j+1], code[j+2], code[j+3]]); j += 4;
                    let high = i32::from_be_bytes([code[j], code[j+1], code[j+2], code[j+3]]); j += 4;
                    let entry_count = (high as i64 - low as i64 + 1).max(0) as usize;
                    // Saturating arithmetic — pathological values shouldn't
                    // wrap or panic; an overflow simply jumps past the code
                    // and the outer while loop terminates.
                    j = j.saturating_add(entry_count.saturating_mul(4));
                    i = j;
                    continue;
                }
                // lookupswitch — JVMS §6.5.lookupswitch.
                //   header: u8 opcode, pad, i32 default, i32 npairs,
                //           then npairs × (i32 match, i32 offset).
                0xab => {
                    let pad = (4 - ((i + 1) % 4)) % 4;
                    let mut j = i + 1 + pad;
                    if j + 8 > code.len() { break; }
                    j += 4; // skip default
                    let npairs = i32::from_be_bytes([code[j], code[j+1], code[j+2], code[j+3]]).max(0) as usize;
                    j += 4;
                    j = j.saturating_add(npairs.saturating_mul(8));
                    i = j;
                    continue;
                }
                _ => { i = i.saturating_add(opcode_width(op).max(1)); }
            }
        }

        Ok((max_locals, edges, gets, puts))
    }

    // ── Byte-level helpers ─────────────────────────────────────────────────

    fn r1(&mut self) -> io::Result<u8>  { let mut b = [0u8; 1]; self.buf.read_exact(&mut b)?; Ok(b[0]) }
    fn r2(&mut self) -> io::Result<u16> { let mut b = [0u8; 2]; self.buf.read_exact(&mut b)?; Ok(u16::from_be_bytes(b)) }
    fn r4(&mut self) -> io::Result<u32> { let mut b = [0u8; 4]; self.buf.read_exact(&mut b)?; Ok(u32::from_be_bytes(b)) }
}

// ── Opcode-width table ─────────────────────────────────────────────────────

/// Complete JVM instruction-width table per JVMS §6 (instruction width
/// including opcode byte).
///
///   - **Variable-width** opcodes (`wide`, `tableswitch`, `lookupswitch`)
///     are handled inline in `parse_code_attribute` and shouldn't reach
///     this table. We give them a sentinel width of 0 — callers should
///     `.max(1)` to keep the outer loop advancing if we ever hit them.
///   - **Reserved / impdep** opcodes (0xca-0xff except the listed ones)
///     fall through to width 1 so the walker doesn't stall.
///
/// The previous version of this table missed several 2-byte opcodes
/// (istore/lstore/fstore/dstore/astore in their explicit-index form,
/// `newarray`) and a couple of 3-byte opcodes (`sipush`, the `jsr`
/// family) — leading to mis-aligned reads on real-world JARs (gson,
/// guava, …). This rewrite is built from JVMS Table 6.5 directly.
fn opcode_width(op: u8) -> usize {
    match op {
        // ── 1-byte (no operands) ──
        0x00..=0x0f => 1,                       // nop / aconst_null / iconst_* / lconst_* / fconst_* / dconst_*
        0x1a..=0x2d => 1,                       // iload_0..3, lload_0..3, fload_0..3, dload_0..3, aload_0..3
        0x2e..=0x35 => 1,                       // iaload..saload (array loads)
        0x3b..=0x4e => 1,                       // istore_0..3, lstore_0..3, fstore_0..3, dstore_0..3, astore_0..3
        0x4f..=0x56 => 1,                       // iastore..sastore (array stores)
        0x57..=0x5f => 1,                       // pop/pop2/dup/dup_x1/dup_x2/dup2/dup2_x1/dup2_x2/swap
        0x60..=0x83 => 1,                       // add/sub/mul/div/rem/neg/shift/and/or/xor (all primitive)
        0x85..=0x93 => 1,                       // i2l..i2s (conversions)
        0x94..=0x98 => 1,                       // lcmp, fcmpl, fcmpg, dcmpl, dcmpg
        0xac..=0xb1 => 1,                       // ireturn..return
        0xbe        => 1,                       // arraylength
        0xbf        => 1,                       // athrow
        0xc2        => 1,                       // monitorenter
        0xc3        => 1,                       // monitorexit

        // ── 2-byte (1-byte index/operand) ──
        0x10        => 2,                       // bipush
        0x12        => 2,                       // ldc
        0x15..=0x19 => 2,                       // iload..aload (explicit u8 index form)
        0x36..=0x3a => 2,                       // istore..astore (explicit u8 index form)
        0xa9        => 2,                       // ret
        0xbc        => 2,                       // newarray

        // ── 3-byte (2-byte index/branch) ──
        0x11        => 3,                       // sipush
        0x13        => 3,                       // ldc_w
        0x14        => 3,                       // ldc2_w
        0x84        => 3,                       // iinc (1-byte idx + 1-byte const) — but JVMS gives total 3
        0x99..=0xa8 => 3,                       // if<cond>, if_icmp<cond>, if_acmp<cond>, goto, jsr
        0xb2..=0xb8 => 3,                       // getstatic, putstatic, getfield, putfield, invoke{virtual,special,static}
        0xbb        => 3,                       // new
        0xbd        => 3,                       // anewarray
        0xc0        => 3,                       // checkcast
        0xc1        => 3,                       // instanceof
        0xc6..=0xc7 => 3,                       // ifnull, ifnonnull

        // ── 4-byte ──
        0xc5        => 4,                       // multianewarray (cp idx + dimensions byte)

        // ── 5-byte ──
        0xb9        => 5,                       // invokeinterface (cp + count byte + zero byte)
        0xba        => 5,                       // invokedynamic (cp + two zero bytes)
        0xc8        => 5,                       // goto_w
        0xc9        => 5,                       // jsr_w

        // ── Variable-width — handled inline in parse_code_attribute. ──
        0xaa | 0xab | 0xc4 => 0,                // tableswitch / lookupswitch / wide

        // ── Reserved + impdep. Default to 1 so the walker advances. ──
        _ => 1,
    }
}

// ── Modified UTF-8 ─────────────────────────────────────────────────────────

/// Decode JVM modified-UTF-8 (JVMS §4.4.7). For the vast majority of
/// class-file strings this is identical to plain UTF-8, but we tolerate
/// the differences (0x00 encoded as 0xC0 0x80, supplementary chars
/// encoded as surrogate pairs).
fn decode_mutf8(bytes: &[u8]) -> String {
    // Fast path — try plain UTF-8 first.
    if let Ok(s) = std::str::from_utf8(bytes) { return s.to_string(); }
    // Fallback: lossy.
    String::from_utf8_lossy(bytes).into_owned()
}

// ── JAR / AAR extraction ───────────────────────────────────────────────────

/// Extract every `.class` file from a JAR into `ClassInfo`s. Failures on
/// individual entries are silently skipped (matches the Python behaviour).
pub fn extract_classes_from_jar<P: AsRef<Path>>(jar_path: P) -> Vec<ClassInfo> {
    let Ok(file) = std::fs::File::open(jar_path.as_ref()) else { return Vec::new(); };
    let Ok(mut zf) = zip::ZipArchive::new(file) else { return Vec::new(); };
    let mut out = Vec::new();
    for i in 0..zf.len() {
        let Ok(mut entry) = zf.by_index(i) else { continue; };
        if !entry.name().ends_with(".class") { continue; }
        let mut data = Vec::with_capacity(entry.size() as usize);
        if entry.read_to_end(&mut data).is_err() { continue; }
        if let Some(cls) = ClassFileParser::new(&data).parse() { out.push(cls); }
    }
    out
}

/// Extract classes from an AAR. AARs contain `classes.jar` (and
/// sometimes `libs/*.jar`); we follow both.
pub fn extract_classes_from_aar<P: AsRef<Path>>(aar_path: P) -> Vec<ClassInfo> {
    let Ok(file) = std::fs::File::open(aar_path.as_ref()) else { return Vec::new(); };
    let Ok(mut zf) = zip::ZipArchive::new(file) else { return Vec::new(); };
    let mut out = Vec::new();
    let mut inner_jars: Vec<Vec<u8>> = Vec::new();
    for i in 0..zf.len() {
        let Ok(mut entry) = zf.by_index(i) else { continue; };
        let name = entry.name().to_string();
        if name == "classes.jar" || (name.starts_with("libs/") && name.ends_with(".jar")) {
            let mut data = Vec::with_capacity(entry.size() as usize);
            if entry.read_to_end(&mut data).is_ok() { inner_jars.push(data); }
        }
    }
    for data in inner_jars {
        if let Ok(mut zf2) = zip::ZipArchive::new(Cursor::new(data)) {
            for j in 0..zf2.len() {
                let Ok(mut entry) = zf2.by_index(j) else { continue; };
                if !entry.name().ends_with(".class") { continue; }
                let mut cdata = Vec::with_capacity(entry.size() as usize);
                if entry.read_to_end(&mut cdata).is_err() { continue; }
                if let Some(cls) = ClassFileParser::new(&cdata).parse() { out.push(cls); }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal hand-crafted .class file: empty public class `Foo`
    /// extending `java.lang.Object`. Magic + minor/major + CP with 4 used
    /// entries + access + this + super + 0 ifaces + 0 fields + 0 methods
    /// + 0 attrs. Used to smoke-test the parser without depending on a
    /// JAR fixture.
    fn empty_class_bytes() -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&0xCAFEBABE_u32.to_be_bytes());
        b.extend_from_slice(&0u16.to_be_bytes());     // minor
        b.extend_from_slice(&52u16.to_be_bytes());    // major (Java 8)
        // cp_count = 5 (slots 1..4 used)
        b.extend_from_slice(&5u16.to_be_bytes());
        // #1 Utf8 "Foo"
        b.push(CP_UTF8); b.extend_from_slice(&3u16.to_be_bytes()); b.extend_from_slice(b"Foo");
        // #2 Class -> #1
        b.push(CP_CLASS); b.extend_from_slice(&1u16.to_be_bytes());
        // #3 Utf8 "java/lang/Object"
        b.push(CP_UTF8); b.extend_from_slice(&16u16.to_be_bytes()); b.extend_from_slice(b"java/lang/Object");
        // #4 Class -> #3
        b.push(CP_CLASS); b.extend_from_slice(&3u16.to_be_bytes());

        b.extend_from_slice(&0x0001_u16.to_be_bytes()); // public
        b.extend_from_slice(&2u16.to_be_bytes());       // this = #2
        b.extend_from_slice(&4u16.to_be_bytes());       // super = #4
        b.extend_from_slice(&0u16.to_be_bytes());       // 0 ifaces
        b.extend_from_slice(&0u16.to_be_bytes());       // 0 fields
        b.extend_from_slice(&0u16.to_be_bytes());       // 0 methods
        b.extend_from_slice(&0u16.to_be_bytes());       // 0 attrs
        b
    }

    #[test]
    fn parses_empty_class() {
        let b = empty_class_bytes();
        let cls = ClassFileParser::new(&b).parse().expect("parse should succeed");
        assert_eq!(cls.internal_name, "Foo");
        assert_eq!(cls.superclass.as_deref(), Some("java/lang/Object"));
        assert_eq!(cls.fqn(), "Foo");
        assert!(cls.is_interface() == false);
    }

    #[test]
    fn rejects_bad_magic() {
        let bytes = vec![0u8; 32];
        assert!(ClassFileParser::new(&bytes).parse().is_none());
    }
}
