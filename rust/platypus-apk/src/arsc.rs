/// Binary resources.arsc parser.

const CHUNK_TABLE:       u16 = 0x0002;
const CHUNK_STRING_POOL: u16 = 0x0001;
const CHUNK_PACKAGE:     u16 = 0x0200;
const CHUNK_TYPE_SPEC:   u16 = 0x0202;
const CHUNK_TYPE_ENTRY:  u16 = 0x0201;

const FLAG_UTF8: u32 = 1 << 8;

#[derive(Debug, Clone)]
pub struct ResourceEntry {
    pub id:        u32,
    pub name:      String,
    pub type_name: String,
    /// For simple entries: the formatted value (or `"<bag>"` placeholder for
    /// backwards-compat when the entry is complex).
    pub value:     String,
    /// For complex (bag) entries — styles, themes, attr declarations, plurals,
    /// arrays. `None` for simple entries.
    pub bag:       Option<BagEntry>,
}

/// Complex resource entry (style, theme, declare-styleable, array, plurals).
///
/// In the binary format these are `ResTable_map_entry` records: a parent
/// resource id followed by a list of `(attribute_id, value)` pairs.
#[derive(Debug, Clone)]
pub struct BagEntry {
    /// Resource id of the parent (style chain). `0` if there's no parent.
    pub parent_id: u32,
    pub items:     Vec<BagItem>,
}

/// One key-value pair inside a bag entry.
#[derive(Debug, Clone)]
pub struct BagItem {
    /// Attribute resource id (e.g. `0x010100d4` for `android:colorPrimary`),
    /// or for arrays/plurals a special pseudo-id (`0x01000000 | index` for
    /// array items, `0x01000004..0x01000009` for plural quantities).
    pub attr_id:   u32,
    pub data_type: u8,
    pub data:      u32,
    /// Pre-formatted string view of `(data_type, data)` — same convention as
    /// the simple-entry `value` field.
    pub value:     String,
}

pub struct ResourceTable {
    entries:       Vec<ResourceEntry>,
    value_strings: Vec<String>,
}

impl ResourceTable {
    /// Get the string value for a resource ID (e.g. 0x7f040001).
    pub fn get_string(&self, res_id: u32) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.id == res_id && e.type_name == "string")
            .map(|e| e.value.as_str())
    }

    /// Get a resource entry by ID.
    pub fn get(&self, res_id: u32) -> Option<&ResourceEntry> {
        self.entries.iter().find(|e| e.id == res_id)
    }

    /// All entries.
    pub fn entries(&self) -> &[ResourceEntry] {
        &self.entries
    }

    /// All entries of a given type name (e.g. "string", "layout", "drawable").
    pub fn by_type(&self, type_name: &str) -> Vec<&ResourceEntry> {
        self.entries
            .iter()
            .filter(|e| e.type_name == type_name)
            .collect()
    }

    /// Resolve a resource ID to its final string/value, following reference chains.
    /// Returns None if the resource is not found.
    pub fn resolve(&self, res_id: u32) -> Option<String> {
        let mut id = res_id;
        let mut depth = 0;
        loop {
            if depth > 10 { return None; } // prevent infinite loops
            let entry = self.get(id)?;
            // If value starts with "@0x", it's a reference — follow the chain
            if entry.value.starts_with("@0x") {
                if let Ok(next_id) = u32::from_str_radix(&entry.value[3..], 16) {
                    id = next_id;
                    depth += 1;
                    continue;
                }
            }
            return Some(entry.value.clone());
        }
    }

    /// Get a string resource by name (e.g. "app_name").
    pub fn string_by_name(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|e| e.type_name == "string" && e.name == name)
            .map(|e| e.value.as_str())
    }
}

/// Parse resources.arsc bytes.
pub fn parse(data: &[u8]) -> Result<ResourceTable, super::ApkError> {
    if data.len() < 8 {
        return Err(super::ApkError::Parse("arsc too short".into()));
    }

    let mut p = Parser::new(data);
    p.parse()
}

// ── Internal parser ───────────────────────────────────────────────────────────

struct Parser<'a> {
    data: &'a [u8],
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Parser { data }
    }

    fn read_u8_at(&self, pos: usize) -> Result<u8, super::ApkError> {
        self.data.get(pos).copied().ok_or_else(|| {
            super::ApkError::Parse(format!("unexpected EOF at {}", pos))
        })
    }

    fn read_u16_at(&self, pos: usize) -> Result<u16, super::ApkError> {
        if pos + 2 > self.data.len() {
            return Err(super::ApkError::Parse(format!("unexpected EOF (u16 at {})", pos)));
        }
        Ok(u16::from_le_bytes([self.data[pos], self.data[pos + 1]]))
    }

    fn read_u32_at(&self, pos: usize) -> Result<u32, super::ApkError> {
        if pos + 4 > self.data.len() {
            return Err(super::ApkError::Parse(format!("unexpected EOF (u32 at {})", pos)));
        }
        Ok(u32::from_le_bytes([
            self.data[pos],
            self.data[pos + 1],
            self.data[pos + 2],
            self.data[pos + 3],
        ]))
    }

    fn parse(&self) -> Result<ResourceTable, super::ApkError> {
        // Outer table chunk header
        let chunk_type  = self.read_u16_at(0)?;
        if chunk_type != CHUNK_TABLE {
            return Err(super::ApkError::Parse(format!(
                "expected RES_TABLE_TYPE 0x0002, got 0x{:04x}", chunk_type
            )));
        }
        let hdr_size   = self.read_u16_at(2)? as usize;
        let _chunk_size = self.read_u32_at(4)? as usize;
        let _pkg_count  = self.read_u32_at(8)?;

        let mut pos = hdr_size; // usually 12
        let mut value_strings: Vec<String> = Vec::new();
        let mut entries: Vec<ResourceEntry> = Vec::new();

        while pos + 8 <= self.data.len() {
            let c_type  = self.read_u16_at(pos)?;
            let c_hdr   = self.read_u16_at(pos + 2)? as usize;
            let c_size  = self.read_u32_at(pos + 4)? as usize;

            if c_size < 8 || pos + c_size > self.data.len() {
                break;
            }

            match c_type {
                CHUNK_STRING_POOL => {
                    value_strings = self.parse_string_pool(pos)?;
                }
                CHUNK_PACKAGE => {
                    let pkg_entries = self.parse_package(pos, &value_strings)?;
                    entries.extend(pkg_entries);
                }
                _ => { /* skip */ }
            }

            pos += c_size;
        }

        Ok(ResourceTable { entries, value_strings })
    }

    // ── String pool ───────────────────────────────────────────────────────────

    fn parse_string_pool(&self, chunk_start: usize) -> Result<Vec<String>, super::ApkError> {
        // chunk_start points to chunk header (8 bytes)
        let string_count  = self.read_u32_at(chunk_start + 8)?  as usize;
        let _style_count  = self.read_u32_at(chunk_start + 12)?;
        let flags         = self.read_u32_at(chunk_start + 16)?;
        let strings_start = self.read_u32_at(chunk_start + 20)? as usize;
        let _styles_start = self.read_u32_at(chunk_start + 24)?;

        let is_utf8 = (flags & FLAG_UTF8) != 0;

        // offsets start at chunk_start + 28
        let offsets_base = chunk_start + 28;
        let strings_base = chunk_start + strings_start;

        let mut strings = Vec::with_capacity(string_count);
        for i in 0..string_count {
            let off = self.read_u32_at(offsets_base + i * 4)? as usize;
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
        Ok(strings)
    }

    // ── Package ───────────────────────────────────────────────────────────────

    fn parse_package(
        &self,
        pkg_start: usize,
        value_strings: &[String],
    ) -> Result<Vec<ResourceEntry>, super::ApkError> {
        // chunk header: 8 bytes
        let pkg_hdr_size = self.read_u16_at(pkg_start + 2)? as usize;
        let pkg_chunk_size = self.read_u32_at(pkg_start + 4)? as usize;

        let package_id = self.read_u32_at(pkg_start + 8)?;

        // name: 256 UTF-16LE chars at offset 12
        // type_strings_offset: u32 at offset 268
        // key_strings_offset: u32 at offset 276
        let type_strings_off = self.read_u32_at(pkg_start + 268)? as usize;
        let key_strings_off  = self.read_u32_at(pkg_start + 276)? as usize;

        // Parse type and key string pools
        let type_strings = self.parse_string_pool(pkg_start + type_strings_off)?;
        let key_strings  = self.parse_string_pool(pkg_start + key_strings_off)?;

        // Now iterate through the rest of the package chunk looking for type specs and type entries
        let mut entries: Vec<ResourceEntry> = Vec::new();

        // Start scanning after the package header
        let pkg_end = pkg_start + pkg_chunk_size;

        // Find the position after the key string pool chunk
        let key_pool_size = self.read_u32_at(pkg_start + key_strings_off + 4)? as usize;
        let mut pos = pkg_start + key_strings_off + key_pool_size;

        while pos + 8 <= pkg_end && pos + 8 <= self.data.len() {
            let c_type  = self.read_u16_at(pos)?;
            let _c_hdr  = self.read_u16_at(pos + 2)? as usize;
            let c_size  = self.read_u32_at(pos + 4)? as usize;

            if c_size < 8 || pos + c_size > self.data.len() {
                break;
            }

            match c_type {
                CHUNK_TYPE_SPEC => {
                    // skip
                }
                CHUNK_TYPE_ENTRY => {
                    let type_entries = self.parse_type_entry(
                        pos,
                        package_id,
                        &type_strings,
                        &key_strings,
                        value_strings,
                    )?;
                    entries.extend(type_entries);
                }
                _ => {}
            }

            pos += c_size;
        }

        Ok(entries)
    }

    // ── Type entry chunk ──────────────────────────────────────────────────────

    fn parse_type_entry(
        &self,
        chunk_start: usize,
        package_id: u32,
        type_strings: &[String],
        key_strings: &[String],
        value_strings: &[String],
    ) -> Result<Vec<ResourceEntry>, super::ApkError> {
        // chunk header (8 bytes) already read externally
        let _hdr_size     = self.read_u16_at(chunk_start + 2)? as usize;
        let chunk_size    = self.read_u32_at(chunk_start + 4)? as usize;

        // type id (1-based), flags, reserved
        let type_id      = self.read_u8_at(chunk_start + 8)? as u32; // 1-based
        let _flags       = self.read_u8_at(chunk_start + 9)?;
        // 2 bytes reserved
        let entry_count  = self.read_u32_at(chunk_start + 12)? as usize;
        let entries_start = self.read_u32_at(chunk_start + 16)? as usize; // from chunk start

        // config_size at offset 20
        let config_size  = self.read_u32_at(chunk_start + 20)? as usize;
        // Skip the config (config_size bytes starting at chunk_start + 20)
        // After config: entry offsets array
        let offsets_base = chunk_start + 20 + config_size;

        if type_id == 0 || type_id as usize > type_strings.len() {
            return Ok(Vec::new());
        }
        let type_name = type_strings[(type_id - 1) as usize].clone();

        let entries_base = chunk_start + entries_start;

        let mut results = Vec::new();

        for i in 0..entry_count {
            let off_pos = offsets_base + i * 4;
            if off_pos + 4 > self.data.len() {
                break;
            }
            let entry_off = self.read_u32_at(off_pos)?;
            if entry_off == 0xFFFFFFFF {
                continue;
            }

            let entry_abs = entries_base + entry_off as usize;
            if entry_abs + 8 > self.data.len() {
                continue;
            }

            let entry_size  = self.read_u16_at(entry_abs)?;
            let entry_flags = self.read_u16_at(entry_abs + 2)?;
            let key_idx     = self.read_u32_at(entry_abs + 4)? as usize;

            let is_complex = (entry_flags & 0x0001) != 0;

            let key_name = key_strings.get(key_idx).cloned().unwrap_or_default();

            let res_id = (package_id << 24) | ((type_id as u32) << 16) | (i as u32);

            let (value, bag) = if is_complex {
                // ResTable_map_entry adds two more u32s after the common entry
                // header: parent (u32) at offset 8, count (u32) at offset 12.
                // Then `count` × ResTable_map records (12 bytes each).
                let map_base = entry_abs + 8;
                if map_base + 8 > self.data.len() {
                    continue;
                }
                let parent_id = self.read_u32_at(map_base)?;
                let count     = self.read_u32_at(map_base + 4)? as usize;

                let items_base = entry_abs + entry_size as usize;
                let mut items = Vec::with_capacity(count);
                for j in 0..count {
                    let p = items_base + j * 12;
                    if p + 12 > self.data.len() {
                        break;
                    }
                    let attr_id   = self.read_u32_at(p)?;
                    // ResTable_map.value: Res_value (size u16, res0 u8, data_type u8, data u32)
                    let _val_size  = self.read_u16_at(p + 4)?;
                    let _res0      = self.read_u8_at(p + 6)?;
                    let data_type  = self.read_u8_at(p + 7)?;
                    let data       = self.read_u32_at(p + 8)?;

                    items.push(BagItem {
                        attr_id,
                        data_type,
                        data,
                        value: format_res_value(data_type, data, value_strings),
                    });
                }

                ("<bag>".to_string(), Some(BagEntry { parent_id, items }))
            } else {
                // Res_value: u16 size, u8 res0, u8 data_type, u32 data
                let val_base = entry_abs + 8;
                if val_base + 8 > self.data.len() {
                    continue;
                }
                let _val_size  = self.read_u16_at(val_base)?;
                let _res0      = self.read_u8_at(val_base + 2)?;
                let data_type  = self.read_u8_at(val_base + 3)?;
                let data       = self.read_u32_at(val_base + 4)?;

                (format_res_value(data_type, data, value_strings), None)
            };

            results.push(ResourceEntry {
                id:        res_id,
                name:      key_name,
                type_name: type_name.clone(),
                value,
                bag,
            });
        }

        Ok(results)
    }
}

fn format_res_value(data_type: u8, data: u32, value_strings: &[String]) -> String {
    match data_type {
        0x03 => value_strings.get(data as usize).cloned().unwrap_or_default(),
        0x10 => (data as i32).to_string(),
        0x11 => format!("0x{:x}", data),
        0x12 => {
            if data != 0 {
                "true".to_string()
            } else {
                "false".to_string()
            }
        }
        0x01 => format!("@0x{:08x}", data),
        _    => format!("0x{:x}", data),
    }
}

fn read_utf8_string(data: &[u8], pos: usize) -> String {
    if pos >= data.len() {
        return String::new();
    }
    let mut p = pos;
    // char_len may be 1 or 2 bytes (high bit set = 2-byte)
    if p >= data.len() {
        return String::new();
    }
    if data[p] & 0x80 != 0 {
        p += 2;
    } else {
        p += 1;
    }
    // byte_len
    if p >= data.len() {
        return String::new();
    }
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
