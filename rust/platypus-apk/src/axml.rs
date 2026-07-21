/// Binary Android XML (AXML) parser.
///
/// Parses the binary XML format used in AndroidManifest.xml and layout files.

use std::collections::HashMap;

// ── Public types ──────────────────────────────────────────────────────────────

/// A node in the parsed XML tree.
#[derive(Debug, Clone)]
pub struct XmlNode {
    pub tag: String,
    pub attrs: Vec<(String, String)>, // (name, value) — ordered
    pub children: Vec<XmlNode>,
}

impl XmlNode {
    /// Serialize back to a human-readable XML string.
    pub fn to_xml_string(&self) -> String {
        let mut out = String::new();
        self.write_xml(&mut out, 0);
        out
    }

    fn write_xml(&self, out: &mut String, depth: usize) {
        let indent = "    ".repeat(depth);
        out.push_str(&indent);
        out.push('<');
        out.push_str(&self.tag);
        for (k, v) in &self.attrs {
            out.push(' ');
            out.push_str(k);
            out.push_str("=\"");
            out.push_str(&xml_escape(v));
            out.push('"');
        }
        if self.children.is_empty() {
            out.push_str(" />\n");
        } else {
            out.push_str(">\n");
            for child in &self.children {
                child.write_xml(out, depth + 1);
            }
            out.push_str(&indent);
            out.push_str("</");
            out.push_str(&self.tag);
            out.push_str(">\n");
        }
    }

    /// Get attribute value by name (case-sensitive).
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// Depth-first search for all nodes with the given tag.
    pub fn find_all(&self, tag: &str) -> Vec<&XmlNode> {
        let mut result = Vec::new();
        self.find_all_impl(tag, &mut result);
        result
    }

    fn find_all_impl<'a>(&'a self, tag: &str, result: &mut Vec<&'a XmlNode>) {
        if self.tag == tag {
            result.push(self);
        }
        for child in &self.children {
            child.find_all_impl(tag, result);
        }
    }

    /// Get the first child with the given tag.
    pub fn find_first(&self, tag: &str) -> Option<&XmlNode> {
        for child in &self.children {
            if child.tag == tag {
                return Some(child);
            }
            if let Some(found) = child.find_first(tag) {
                return Some(found);
            }
        }
        None
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ── Parser ────────────────────────────────────────────────────────────────────

const CHUNK_STRING_POOL:   u16 = 0x0001;
const CHUNK_START_NS:      u16 = 0x0100;
const CHUNK_END_NS:        u16 = 0x0101;
const CHUNK_START_ELEMENT: u16 = 0x0102;
const CHUNK_END_ELEMENT:   u16 = 0x0103;

const FLAG_UTF8: u32 = 1 << 8;
const ANDROID_NS_URI: &str = "http://schemas.android.com/apk/res/android";

/// Meaningful bytes per attribute entry: ns, name, rawValue, typedValue meta,
/// data — five u32s. The header's `attributeSize` may be larger (padding);
/// it must be at least this.
const ATTR_ENTRY_MIN: usize = 20;

/// Parse AXML bytes into an XmlNode tree. Returns the root element.
pub fn parse(data: &[u8]) -> Result<XmlNode, super::ApkError> {
    let mut p = Parser::new(data);
    p.parse()
}

/// Parse AXML and then resolve all `@0x...` attribute value references via the
/// provided ResourceTable. Values that cannot be resolved stay as `@0x...`.
pub fn parse_with_resources(
    data: &[u8],
    resources: &super::arsc::ResourceTable,
) -> Result<XmlNode, super::ApkError> {
    let mut root = parse(data)?;
    resolve_node_refs(&mut root, resources);
    Ok(root)
}

fn resolve_node_refs(node: &mut XmlNode, resources: &super::arsc::ResourceTable) {
    for (name, value) in &mut node.attrs {
        if !value.starts_with("@0x") { continue; }
        let Ok(id) = u32::from_str_radix(&value[3..], 16) else { continue };

        // Look up the entry to see what TYPE this reference resolves to.
        // Naively resolving every `@0x...` to its value is wrong for IDs
        // (Android stores `R.id.foo` as a boolean marker — resolving
        // `android:id="@0x7f090190"` would turn it into `"false"`!) and
        // for layout/menu refs (where the value IS the file path the
        // caller wants — strings/colors/dimens are the only refs we
        // should always inline).
        let Some(entry) = resources.get(id) else { continue };
        match entry.type_name.as_str() {
            // IDs: keep the symbolic form so consumers can still strip
            // the `@id/` prefix to recover a usable id name. Resolving
            // to the id resource's stored boolean would lose the name.
            "id" => {
                *value = format!("@id/{}", entry.name);
            }
            // Don't inline another reference type — the value sometimes
            // is just the file path or a chained reference and the
            // caller already knows how to handle them.
            "layout" | "menu" | "anim" | "animator" | "drawable" | "mipmap"
            | "xml" | "raw" | "font" | "navigation" => {
                // Keep the path-y resolved value AND emit a symbolic form
                // so consumers can match by name. We pick the resolved
                // value because most callers want the file path.
                if let Some(resolved) = resources.resolve(id) {
                    *value = resolved;
                }
            }
            // Strings / colors / dimens / bools / integers / styles —
            // inline the value (the original behaviour).
            _ => {
                if let Some(resolved) = resources.resolve(id) {
                    *value = resolved;
                }
            }
        }
        let _ = name;
    }
    for child in &mut node.children {
        resolve_node_refs(child, resources);
    }
}

struct Parser<'a> {
    data: &'a [u8],
    pos: usize,
    strings: Vec<String>,
    // prefix -> uri
    ns_map: HashMap<String, String>,
    // uri -> prefix
    ns_uri_to_prefix: HashMap<String, String>,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Parser {
            data,
            pos: 0,
            strings: Vec::new(),
            ns_map: HashMap::new(),
            ns_uri_to_prefix: HashMap::new(),
        }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8, super::ApkError> {
        if self.pos >= self.data.len() {
            return Err(super::ApkError::Parse("unexpected EOF (u8)".into()));
        }
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    fn read_u16(&mut self) -> Result<u16, super::ApkError> {
        if self.pos + 2 > self.data.len() {
            return Err(super::ApkError::Parse("unexpected EOF (u16)".into()));
        }
        let v = u16::from_le_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }

    fn read_u32(&mut self) -> Result<u32, super::ApkError> {
        if self.pos + 4 > self.data.len() {
            return Err(super::ApkError::Parse("unexpected EOF (u32)".into()));
        }
        let v = u32::from_le_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }

    fn skip(&mut self, n: usize) -> Result<(), super::ApkError> {
        if self.pos + n > self.data.len() {
            return Err(super::ApkError::Parse(format!("unexpected EOF (skip {})", n)));
        }
        self.pos += n;
        Ok(())
    }

    fn str_at(&self, idx: u32) -> String {
        if idx == 0xFFFFFFFF {
            return String::new();
        }
        self.strings
            .get(idx as usize)
            .cloned()
            .unwrap_or_default()
    }

    fn parse(&mut self) -> Result<XmlNode, super::ApkError> {
        // Skip the outer XML file header (8 bytes: type=0x0003, hdr_size, chunk_size)
        if self.data.len() < 8 {
            return Err(super::ApkError::Parse("AXML too short".into()));
        }
        // Read outer file chunk header
        let _file_type  = self.read_u16()?;
        let _hdr_size   = self.read_u16()?;
        let _chunk_size = self.read_u32()?;

        // Stack for tree building
        let mut stack: Vec<XmlNode> = Vec::new();
        let mut root: Option<XmlNode> = None;

        while self.remaining() >= 8 {
            let chunk_start = self.pos;
            let chunk_type  = self.read_u16()?;
            let _hdr_size   = self.read_u16()?;
            let chunk_size  = self.read_u32()? as usize;

            if chunk_size < 8 {
                break;
            }

            match chunk_type {
                CHUNK_STRING_POOL => {
                    self.parse_string_pool(chunk_start, chunk_size)?;
                }
                CHUNK_START_NS => {
                    let _line    = self.read_u32()?;
                    let _comment = self.read_u32()?;
                    let prefix   = self.read_u32()?;
                    let uri      = self.read_u32()?;
                    let prefix_s = self.str_at(prefix);
                    let uri_s    = self.str_at(uri);
                    self.ns_map.insert(prefix_s.clone(), uri_s.clone());
                    self.ns_uri_to_prefix.insert(uri_s, prefix_s);
                    // seek to chunk end
                    self.pos = chunk_start + chunk_size;
                }
                CHUNK_END_NS => {
                    self.pos = chunk_start + chunk_size;
                }
                CHUNK_START_ELEMENT => {
                    let node = self.parse_start_element(chunk_start, chunk_size)?;
                    stack.push(node);
                }
                CHUNK_END_ELEMENT => {
                    // line, comment, ns, name
                    self.pos = chunk_start + chunk_size;
                    if let Some(node) = stack.pop() {
                        if let Some(parent) = stack.last_mut() {
                            parent.children.push(node);
                        } else {
                            root = Some(node);
                        }
                    }
                }
                _ => {
                    // Unknown chunk — skip
                    self.pos = chunk_start + chunk_size;
                }
            }
        }

        // If stack still has items (malformed), pop them up
        while stack.len() > 1 {
            let node = stack.pop().unwrap();
            stack.last_mut().unwrap().children.push(node);
        }
        if root.is_none() {
            root = stack.pop();
        }

        root.ok_or_else(|| super::ApkError::Parse("no root element found in AXML".into()))
    }

    fn parse_string_pool(
        &mut self,
        chunk_start: usize,
        chunk_size: usize,
    ) -> Result<(), super::ApkError> {
        // We are positioned right after the 8-byte chunk header.
        let string_count  = self.read_u32()? as usize;
        let _style_count  = self.read_u32()?;
        let flags         = self.read_u32()?;
        let strings_start = self.read_u32()? as usize; // from chunk_start
        let _styles_start = self.read_u32()?;

        let is_utf8 = (flags & FLAG_UTF8) != 0;

        // Read offsets array
        let mut offsets = Vec::with_capacity(string_count);
        for _ in 0..string_count {
            offsets.push(self.read_u32()? as usize);
        }

        // Base of strings data = chunk_start + strings_start
        let strings_base = chunk_start + strings_start;

        let mut strings = Vec::with_capacity(string_count);
        for off in offsets {
            let abs = strings_base + off;
            if abs >= self.data.len() {
                strings.push(String::new());
                continue;
            }
            let s = if is_utf8 {
                read_utf8_string(self.data, abs)
            } else {
                read_utf16_string(self.data, abs)
            };
            strings.push(s);
        }

        self.strings = strings;
        self.pos = chunk_start + chunk_size;
        Ok(())
    }

    fn parse_start_element(
        &mut self,
        chunk_start: usize,
        chunk_size: usize,
    ) -> Result<XmlNode, super::ApkError> {
        let _line_number = self.read_u32()?;
        let _comment     = self.read_u32()?;
        // `ResXMLTree_attrExt` begins here (the `ns` field). `attr_start` and
        // `attr_size` are measured from this point.
        let attr_ext_start = self.pos;
        let elem_ns      = self.read_u32()?;
        let elem_name    = self.read_u32()?;
        let attr_start   = self.read_u16()? as usize;
        let attr_size    = self.read_u16()? as usize;
        let attr_count   = self.read_u16()? as usize;
        let _id_idx      = self.read_u16()?;
        let _class_idx   = self.read_u16()?;
        let _style_idx   = self.read_u16()?;

        let tag = self.resolve_name(elem_ns, elem_name);

        // Honor `attributeStart` / `attributeSize` from the header instead of
        // assuming attributes begin right after the 20-byte attrExt and are
        // exactly 20 bytes each. Obfuscated manifests (e.g. this Godfather
        // sample) inflate `attributeSize` to 24 — Android reads each attribute
        // at the declared stride, but a parser hardcoding 20 drifts 4 bytes per
        // attribute and mangles every attribute after the first. Five u32s
        // (ns, name, rawValue, typedValue.{meta}, data) are meaningful; any
        // remainder up to `stride` is padding we skip.
        let stride = attr_size.max(ATTR_ENTRY_MIN);
        let attrs_base = attr_ext_start + attr_start;

        let mut attrs = Vec::with_capacity(attr_count);
        for i in 0..attr_count {
            let off = match attrs_base.checked_add(i * stride) {
                Some(o) if o + ATTR_ENTRY_MIN <= self.data.len() => o,
                _ => break,
            };
            self.pos = off;
            let attr_ns    = self.read_u32()?;
            let attr_name  = self.read_u32()?;
            let raw_value  = self.read_u32()?;
            let value_type = self.read_u32()?;
            let data       = self.read_u32()?;

            let name  = self.resolve_name(attr_ns, attr_name);
            let value = self.format_value(raw_value, value_type, data);
            attrs.push((name, value));
        }

        self.pos = chunk_start + chunk_size;
        Ok(XmlNode {
            tag,
            attrs,
            children: Vec::new(),
        })
    }

    fn resolve_name(&self, ns_idx: u32, name_idx: u32) -> String {
        let name = self.str_at(name_idx);
        if ns_idx == 0xFFFFFFFF {
            return name;
        }
        let uri = self.str_at(ns_idx);
        if uri == ANDROID_NS_URI {
            format!("android:{}", name)
        } else if let Some(prefix) = self.ns_uri_to_prefix.get(&uri) {
            if prefix.is_empty() {
                name
            } else {
                format!("{}:{}", prefix, name)
            }
        } else {
            name
        }
    }

    fn format_value(&self, raw_value: u32, value_type: u32, data: u32) -> String {
        // value_type holds the Res_value's first 4 bytes:
        //   bytes 0-1: size (always 8)
        //   byte 2:    res0 (always 0)
        //   byte 3:    dataType  ← what we want
        // In LE u32 layout the dataType byte ends up in bits 24-31.
        let type_byte = ((value_type >> 24) & 0xFF) as u8;

        // For TYPE_STRING, prefer the rawValue index when set — otherwise
        // it's typically equal to data anyway.
        if raw_value != 0xFFFFFFFF && type_byte == 0x03 {
            return self.str_at(raw_value);
        }

        match type_byte {
            0x00 => "@null".to_string(),                          // TYPE_NULL
            0x01 => format!("@0x{:08x}", data),                   // TYPE_REFERENCE
            0x02 => format!("?0x{:08x}", data),                   // TYPE_ATTRIBUTE
            0x03 => self.str_at(data),                            // TYPE_STRING
            0x04 => format_float(data),                           // TYPE_FLOAT
            0x05 => format_complex(data, /*fraction*/ false),     // TYPE_DIMENSION
            0x06 => format_complex(data, /*fraction*/ true),      // TYPE_FRACTION
            0x10 => (data as i32).to_string(),                    // TYPE_INT_DEC
            0x11 => format!("0x{:x}", data),                      // TYPE_INT_HEX
            0x12 => if data != 0 { "true".into() } else { "false".into() },  // TYPE_INT_BOOLEAN
            // TYPE_INT_COLOR_* (ARGB8 / RGB8 / ARGB4 / RGB4). Always
            // emit as #aarrggbb so renderers can parse uniformly.
            0x1c | 0x1d | 0x1e | 0x1f => format!("#{:08x}", data),
            // Anything else — at least don't lie about the bytes.
            _ => format!("0x{:x}", data),
        }
    }
}

/// Decode a TYPE_FLOAT (0x04) value — the data field IS an IEEE-754 f32
/// reinterpreted as bits. Format with reasonable precision; trim trailing
/// zeros so `1.0` shows as `1`.
fn format_float(data: u32) -> String {
    let f = f32::from_bits(data);
    if !f.is_finite() {
        return format!("0x{:x}", data);
    }
    // Up to 6 sig figs, then trim trailing zeros + dangling dot.
    let s = format!("{:.6}", f);
    let trimmed = s.trim_end_matches('0').trim_end_matches('.').to_string();
    if trimmed.is_empty() { "0".to_string() } else { trimmed }
}

/// Decode a TYPE_DIMENSION (0x05) or TYPE_FRACTION (0x06) packed value.
///
/// Layout (per AOSP `ResourceTypes.h`):
///   bits 0-3:  unit  (dimension: 0=px / 1=dip / 2=sp / 3=pt / 4=in / 5=mm
///                     fraction:  0=basic / 1=parent)
///   bits 4-5:  radix (0=23.0 / 1=16.7 / 2=8.15 / 3=0.23)
///   bits 8-31: 24-bit signed mantissa (pre-shifted by `radix`'s frac bits)
fn format_complex(data: u32, fraction: bool) -> String {
    let unit  = (data & 0x0f) as usize;
    let radix = ((data >> 4) & 0x03) as usize;

    // Sign-extend the 24-bit mantissa: arithmetic-shift the i32 right by 8.
    let mantissa = (data as i32) >> 8;

    // Each radix bucket shifts more bits into the fractional position.
    let frac_bits: i32 = [0, 7, 15, 23][radix];
    let mut value = mantissa as f32 / (1u32 << frac_bits) as f32;

    // Fractions store percentages — the encoded value is in [0, 1].
    if fraction { value *= 100.0; }

    // Trim trailing zeros so `16.0dp` becomes `16dp`.
    let mag = format!("{:.4}", value);
    let mag = mag.trim_end_matches('0').trim_end_matches('.').to_string();
    let mag = if mag.is_empty() { "0".to_string() } else { mag };

    let suffix = if fraction {
        match unit { 1 => "%p", _ => "%" }
    } else {
        match unit {
            0 => "px", 1 => "dp", 2 => "sp", 3 => "pt",
            4 => "in", 5 => "mm",
            _ => "px",
        }
    };
    format!("{mag}{suffix}")
}

fn read_utf8_string(data: &[u8], pos: usize) -> String {
    if pos >= data.len() {
        return String::new();
    }
    // char_len (u8), byte_len (u8), then byte_len bytes
    let mut p = pos;
    let _char_len = data[p] as usize;
    p += 1;
    if p >= data.len() {
        return String::new();
    }
    // Handle extended lengths (bit 7 set means 2-byte length)
    let byte_len = if data[p] & 0x80 != 0 {
        if p + 1 >= data.len() {
            return String::new();
        }
        let hi = (data[p] & 0x7F) as usize;
        let lo = data[p + 1] as usize;
        p += 2;
        (hi << 8) | lo
    } else {
        let v = data[p] as usize;
        p += 1;
        v
    };
    if p + byte_len > data.len() {
        return String::new();
    }
    String::from_utf8_lossy(&data[p..p + byte_len]).into_owned()
}

fn read_utf16_string(data: &[u8], pos: usize) -> String {
    if pos + 2 > data.len() {
        return String::new();
    }
    // char_len (u16), then char_len * 2 bytes
    let char_len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
    let start = pos + 2;
    let end = start + char_len * 2;
    if end > data.len() {
        return String::new();
    }
    let u16s: Vec<u16> = data[start..end]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    String::from_utf16_lossy(&u16s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal UTF-16 AXML: one element `root` with attributes `a` and
    /// `b` (integer values 1 and 2), using the given `attr_size` stride. When
    /// `attr_size > 20` the extra bytes per attribute are padding — exactly the
    /// shape the Godfather manifest uses (`attr_size = 24`) to drift parsers
    /// that hardcode a 20-byte stride.
    fn build_axml(attr_size: u16) -> Vec<u8> {
        fn u16le(v: u16) -> [u8; 2] { v.to_le_bytes() }
        fn u32le(v: u32) -> [u8; 4] { v.to_le_bytes() }
        fn utf16(s: &str, out: &mut Vec<u8>) {
            out.extend_from_slice(&u16le(s.chars().count() as u16));
            for c in s.encode_utf16() { out.extend_from_slice(&u16le(c)); }
            out.extend_from_slice(&u16le(0)); // null terminator
        }

        // ── String pool (UTF-16): ["root","a","b"] ──
        let mut sdata = Vec::new();
        let off_root = sdata.len() as u32; utf16("root", &mut sdata);
        let off_a = sdata.len() as u32; utf16("a", &mut sdata);
        let off_b = sdata.len() as u32; utf16("b", &mut sdata);
        let strings_start = 8 + 20 + 12; // chunk hdr + 5 u32 + 3 offsets
        let sp_size = strings_start + sdata.len();
        let mut sp = Vec::new();
        sp.extend_from_slice(&u16le(CHUNK_STRING_POOL));
        sp.extend_from_slice(&u16le(28));               // header size
        sp.extend_from_slice(&u32le(sp_size as u32));   // chunk size
        sp.extend_from_slice(&u32le(3));                // string count
        sp.extend_from_slice(&u32le(0));                // style count
        sp.extend_from_slice(&u32le(0));                // flags: UTF-16
        sp.extend_from_slice(&u32le(strings_start as u32)); // strings start
        sp.extend_from_slice(&u32le(0));                // styles start
        sp.extend_from_slice(&u32le(off_root));
        sp.extend_from_slice(&u32le(off_a));
        sp.extend_from_slice(&u32le(off_b));
        sp.extend_from_slice(&sdata);

        // ── Start element `root` with 2 attrs at the given stride ──
        let stride = attr_size as usize;
        let se_size = 36 + 2 * stride;
        let mut se = Vec::new();
        se.extend_from_slice(&u16le(CHUNK_START_ELEMENT));
        se.extend_from_slice(&u16le(16));               // header size
        se.extend_from_slice(&u32le(se_size as u32));
        se.extend_from_slice(&u32le(0));                // line
        se.extend_from_slice(&u32le(0xFFFF_FFFF));      // comment
        se.extend_from_slice(&u32le(0xFFFF_FFFF));      // ns (none)
        se.extend_from_slice(&u32le(0));                // name = "root"
        se.extend_from_slice(&u16le(20));               // attributeStart
        se.extend_from_slice(&u16le(attr_size));        // attributeSize
        se.extend_from_slice(&u16le(2));                // attributeCount
        se.extend_from_slice(&u16le(0));                // id index
        se.extend_from_slice(&u16le(0));                // class index
        se.extend_from_slice(&u16le(0));                // style index
        for (name_idx, val) in [(1u32, 1u32), (2u32, 2u32)] {
            se.extend_from_slice(&u32le(0xFFFF_FFFF));  // attr ns
            se.extend_from_slice(&u32le(name_idx));     // attr name
            se.extend_from_slice(&u32le(0xFFFF_FFFF));  // raw value
            se.extend_from_slice(&u32le(0x1000_0008));  // typed: size=8, type=INT_DEC(0x10)
            se.extend_from_slice(&u32le(val));          // data
            se.resize(se.len() + (stride - 20), 0);     // padding
        }

        // ── End element `root` ──
        let mut ee = Vec::new();
        ee.extend_from_slice(&u16le(CHUNK_END_ELEMENT));
        ee.extend_from_slice(&u16le(16));
        ee.extend_from_slice(&u32le(24));
        ee.extend_from_slice(&u32le(0));                // line
        ee.extend_from_slice(&u32le(0xFFFF_FFFF));      // comment
        ee.extend_from_slice(&u32le(0xFFFF_FFFF));      // ns
        ee.extend_from_slice(&u32le(0));                // name

        // ── Outer file header ──
        let total = 8 + sp.len() + se.len() + ee.len();
        let mut out = Vec::new();
        out.extend_from_slice(&u16le(0x0003));          // RES_XML_TYPE
        out.extend_from_slice(&u16le(8));
        out.extend_from_slice(&u32le(total as u32));
        out.extend_from_slice(&sp);
        out.extend_from_slice(&se);
        out.extend_from_slice(&ee);
        out
    }

    fn attr_names(node: &XmlNode) -> Vec<String> {
        node.attrs.iter().map(|(n, _)| n.clone()).collect()
    }

    #[test]
    fn honors_standard_attribute_size() {
        let node = parse(&build_axml(20)).expect("parses");
        assert_eq!(node.tag, "root");
        assert_eq!(attr_names(&node), ["a", "b"]);
    }

    /// The regression: a non-standard `attributeSize` (24) must not drift the
    /// parser. Before the fix, the second attribute came back as garbage.
    #[test]
    fn honors_inflated_attribute_size() {
        let node = parse(&build_axml(24)).expect("parses");
        assert_eq!(node.tag, "root");
        assert_eq!(attr_names(&node), ["a", "b"],
            "inflated attributeSize must be respected as the per-attribute stride");
    }
}
