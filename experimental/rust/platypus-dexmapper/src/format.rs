//! Mapping file formats — JSON (dexmapper's preferred output) and the
//! ProGuard text format (de-facto standard for shipping with apps).
//!
//! Both parse into the same `MappingFile` struct so the rest of the crate
//! is format-agnostic.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MappingFormat {
    #[default]
    Json,
    Proguard,
}

impl MappingFormat {
    pub fn as_str(self) -> &'static str {
        match self { MappingFormat::Json => "json", MappingFormat::Proguard => "proguard" }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MappingFile {
    pub mappings: Vec<Mapping>,
    /// Detected format. Skipped in serialised JSON because the upstream
    /// dexmapper output doesn't carry this field; we only set it during
    /// parsing.
    #[serde(skip)]
    pub format: MappingFormat,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mapping {
    pub obfuscated_class: String,
    pub real_class: String,
    /// Confidence score from the matcher (0-1). Optional because
    /// ProGuard mappings don't carry one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub match_type: Option<String>,
    #[serde(default)]
    pub methods: Vec<MethodEntry>,
    #[serde(default)]
    pub fields: Vec<FieldEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethodEntry {
    pub obfuscated_name: String,
    /// Optional because ProGuard methods *with* a return type but no
    /// arg list look the same as fields when the desc is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_descriptor: Option<String>,
    pub real_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub real_descriptor: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldEntry {
    pub obfuscated_name: String,
    /// JVM type descriptor — `Lcom/foo/Bar;`, `I`, `[Ljava/lang/String;`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfuscated_descriptor: Option<String>,
    pub real_name: String,
}

impl MappingFile {
    /// Sniff the format and parse. JSON is detected by a leading `{` (after
    /// optional whitespace / BOM); anything else is treated as ProGuard.
    pub fn parse_auto(text: &str) -> Result<Self, String> {
        let stripped = text.trim_start_matches('\u{feff}').trim_start();
        if stripped.starts_with('{') {
            Self::parse_json(text)
        } else {
            Self::parse_proguard(text)
        }
    }

    pub fn parse_json(text: &str) -> Result<Self, String> {
        // Allow either `{ "mappings": [...] }` or a bare top-level array
        // (some scripts hand-roll mapping JSONs that way).
        let v: serde_json::Value = serde_json::from_str(text)
            .map_err(|e| format!("json parse: {e}"))?;
        let mappings: Vec<Mapping> = match v {
            serde_json::Value::Object(mut o) => {
                let inner = o.remove("mappings").ok_or("expected top-level `mappings` key")?;
                serde_json::from_value(inner).map_err(|e| format!("`mappings` decode: {e}"))?
            }
            serde_json::Value::Array(_) => {
                serde_json::from_value(v).map_err(|e| format!("array decode: {e}"))?
            }
            _ => return Err("json mapping must be an object or array".into()),
        };
        Ok(Self { mappings, format: MappingFormat::Json })
    }

    /// Parse a ProGuard-style mapping file.
    ///
    /// Grammar (relaxed — we only consume what dexmapper produces and
    /// what R8 typically emits):
    ///
    /// ```text
    /// <obf-class> -> <real-class>:               [# comment]
    ///     [<desc>] <obf-name> -> <real-name>     [# comment]
    /// ```
    ///
    /// Comment lines starting with `#` are skipped. Blank lines are
    /// skipped. Indentation distinguishes member lines from class lines.
    pub fn parse_proguard(text: &str) -> Result<Self, String> {
        let mut mappings: Vec<Mapping> = Vec::new();
        let mut current: Option<Mapping> = None;

        for (lineno, raw) in text.lines().enumerate() {
            let line_num = lineno + 1;
            let line = strip_inline_comment(raw);
            let trimmed = line.trim();
            if trimmed.is_empty() { continue; }

            let is_member = raw.starts_with(' ') || raw.starts_with('\t');
            if is_member {
                // Member line — needs a current class.
                let Some(cur) = current.as_mut() else {
                    return Err(format!("line {line_num}: member line outside a class header"));
                };
                parse_member_line(trimmed, cur)
                    .map_err(|e| format!("line {line_num}: {e}"))?;
            } else {
                // New class header. Flush the previous one.
                if let Some(prev) = current.take() { mappings.push(prev); }
                current = Some(parse_class_header(trimmed)
                    .map_err(|e| format!("line {line_num}: {e}"))?);
            }
        }
        if let Some(last) = current.take() { mappings.push(last); }

        Ok(Self { mappings, format: MappingFormat::Proguard })
    }
}

fn strip_inline_comment(line: &str) -> &str {
    if let Some(hash) = line.find('#') {
        // `#` inside a quoted name (unlikely in proguard maps) — but we
        // don't have quoting, so always strip.
        &line[..hash]
    } else { line }
}

/// `p.q.a -> okhttp3.OkHttpClient:`
fn parse_class_header(line: &str) -> Result<Mapping, String> {
    let line = line.trim_end_matches(':').trim();
    let (obf, real) = split_arrow(line)
        .ok_or_else(|| format!("expected `obf -> real:`, got `{line}`"))?;
    Ok(Mapping {
        obfuscated_class: obf.to_string(),
        real_class: real.to_string(),
        confidence: None,
        match_type: None,
        methods: Vec::new(),
        fields: Vec::new(),
    })
}

/// Member line. Two shapes:
///   `<desc> <obf-name> -> <real-name>`   when prefixed with a JVM descriptor
///   `<obf-name> -> <real-name>`          when bare (field with no desc, etc.)
///
/// We tell methods from fields by looking at the descriptor:
///   - `(...)R` → method
///   - bare type (`I`, `Lcom/foo;`, `[I`) → field
///   - no descriptor → assume method when name looks JVM-y, else field;
///     in practice dexmapper always emits a descriptor.
fn parse_member_line(line: &str, into: &mut Mapping) -> Result<(), String> {
    let (lhs, real_name) = split_arrow(line)
        .ok_or_else(|| format!("expected `... -> name`, got `{line}`"))?;
    let real_name = real_name.trim();

    // Split lhs into optional descriptor + obfuscated name. The name is
    // the last whitespace-separated token; everything before it is the
    // descriptor (may itself contain spaces in pathological cases but
    // dexmapper output never does, and neither does r8).
    let lhs = lhs.trim();
    let (desc, obf_name) = match lhs.rsplit_once(char::is_whitespace) {
        Some((d, n)) => (Some(d.trim()), n.trim()),
        None => (None, lhs),
    };

    let is_method = desc.is_some_and(|d| d.starts_with('('));
    if is_method {
        into.methods.push(MethodEntry {
            obfuscated_name: obf_name.to_string(),
            obfuscated_descriptor: desc.map(str::to_string),
            real_name: real_name.to_string(),
            real_descriptor: desc.map(str::to_string),
        });
    } else {
        into.fields.push(FieldEntry {
            obfuscated_name: obf_name.to_string(),
            obfuscated_descriptor: desc.map(str::to_string),
            real_name: real_name.to_string(),
        });
    }
    Ok(())
}

fn split_arrow(s: &str) -> Option<(&str, &str)> {
    let idx = s.find("->")?;
    Some((s[..idx].trim(), s[idx + 2..].trim()))
}

// ── Writers ────────────────────────────────────────────────────────────────

impl MappingFile {
    /// Serialise to the ProGuard text format dexmapper produces. Entries
    /// are sorted by obfuscated class name (matches the Python writer).
    /// Confidence / match-type are placed in a trailing `#` comment so a
    /// vanilla ProGuard reader still consumes the file correctly.
    pub fn to_proguard(&self) -> String {
        let mut sorted: Vec<&Mapping> = self.mappings.iter().collect();
        sorted.sort_by(|a, b| a.obfuscated_class.cmp(&b.obfuscated_class));

        let mut out = String::new();
        out.push_str("# DexMapper generated mapping\n");
        out.push_str("# Format: obfuscated -> real\n\n");
        for m in sorted {
            let conf = m.confidence.unwrap_or(0.0);
            let mtype = m.match_type.as_deref().unwrap_or("");
            out.push_str(&format!(
                "{} -> {}:  # confidence={:.2} type={}\n",
                m.obfuscated_class, m.real_class, conf, mtype
            ));
            for me in &m.methods {
                let desc = me.obfuscated_descriptor.as_deref().unwrap_or("");
                out.push_str(&format!(
                    "    {} {} -> {}\n",
                    desc, me.obfuscated_name, me.real_name,
                ));
            }
            for fe in &m.fields {
                let desc = fe.obfuscated_descriptor.as_deref().unwrap_or("");
                out.push_str(&format!(
                    "    {} {} -> {}\n",
                    desc, fe.obfuscated_name, fe.real_name,
                ));
            }
            out.push('\n');
        }
        out
    }

    /// Serialise to the JSON shape the Python tool emits — the same
    /// shape the `Deobfuscator::load_json` reader parses, with a
    /// top-level `"mappings"` array and rounded confidence.
    pub fn to_json(&self) -> serde_json::Value {
        let entries: Vec<serde_json::Value> = self.mappings.iter().map(|m| {
            let conf = m.confidence.unwrap_or(0.0);
            let conf = (conf * 10_000.0).round() / 10_000.0;  // 4dp
            let methods: Vec<serde_json::Value> = m.methods.iter().map(|me| {
                serde_json::json!({
                    "obfuscated_name":       me.obfuscated_name,
                    "obfuscated_descriptor": me.obfuscated_descriptor,
                    "real_name":             me.real_name,
                    "real_descriptor":       me.real_descriptor,
                })
            }).collect();
            let fields: Vec<serde_json::Value> = m.fields.iter().map(|fe| {
                serde_json::json!({
                    "obfuscated_name":       fe.obfuscated_name,
                    "obfuscated_descriptor": fe.obfuscated_descriptor,
                    "real_name":             fe.real_name,
                })
            }).collect();
            serde_json::json!({
                "obfuscated_class": m.obfuscated_class,
                "real_class":       m.real_class,
                "confidence":       conf,
                "match_type":       m.match_type.clone().unwrap_or_default(),
                "methods":          methods,
                "fields":           fields,
            })
        }).collect();
        serde_json::json!({ "mappings": entries })
    }

    /// Write a mapping to disk. `fmt` is `"json"` or `"proguard"`.
    pub fn save<P: AsRef<std::path::Path>>(&self, path: P, fmt: &str) -> Result<(), String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir: {e}"))?;
        }
        let text = match fmt {
            "json" => serde_json::to_string_pretty(&self.to_json())
                .map_err(|e| format!("json serialise: {e}"))?,
            _      => self.to_proguard(),
        };
        std::fs::write(path, text).map_err(|e| format!("write: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod writer_tests {
    use super::*;

    fn sample() -> MappingFile {
        MappingFile {
            mappings: vec![Mapping {
                obfuscated_class: "p.q.a".into(),
                real_class: "okhttp3.OkHttpClient".into(),
                confidence: Some(0.92),
                match_type: Some("fingerprint".into()),
                methods: vec![MethodEntry {
                    obfuscated_name: "a".into(),
                    obfuscated_descriptor: Some("()V".into()),
                    real_name: "newCall".into(),
                    real_descriptor: Some("()V".into()),
                }],
                fields: vec![FieldEntry {
                    obfuscated_name: "b".into(),
                    obfuscated_descriptor: Some("Lokhttp3/Dispatcher;".into()),
                    real_name: "dispatcher".into(),
                }],
            }],
            format: MappingFormat::Json,
        }
    }

    #[test]
    fn proguard_roundtrip() {
        let m = sample();
        let text = m.to_proguard();
        assert!(text.contains("p.q.a -> okhttp3.OkHttpClient:"));
        assert!(text.contains("confidence=0.92"));
        assert!(text.contains("a -> newCall"));
        assert!(text.contains("b -> dispatcher"));
        // Round-trips through the reader.
        let parsed = MappingFile::parse_proguard(&text).unwrap();
        assert_eq!(parsed.mappings.len(), 1);
        assert_eq!(parsed.mappings[0].methods[0].real_name, "newCall");
    }

    #[test]
    fn json_roundtrip() {
        let m = sample();
        let v = m.to_json();
        let text = serde_json::to_string(&v).unwrap();
        let parsed = MappingFile::parse_json(&text).unwrap();
        assert_eq!(parsed.mappings.len(), 1);
        assert_eq!(parsed.mappings[0].real_class, "okhttp3.OkHttpClient");
        assert_eq!(parsed.mappings[0].fields[0].real_name, "dispatcher");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proguard_methods_and_fields() {
        let text = "\
# header comment
e.a -> org.greenrobot.eventbus.EventBus:  # confidence=0.93
    ()Lorg/greenrobot/eventbus/EventBus; a -> getDefault
    (Ljava/lang/Object;)V b -> unregister
    Lorg/greenrobot/eventbus/EventBus; a -> defaultInstance

g.a -> com.google.gson.Gson:
    (Ljava/lang/Object;)Ljava/lang/String; a -> toJson
";
        let f = MappingFile::parse_proguard(text).unwrap();
        assert_eq!(f.format, MappingFormat::Proguard);
        assert_eq!(f.mappings.len(), 2);
        let eb = &f.mappings[0];
        assert_eq!(eb.obfuscated_class, "e.a");
        assert_eq!(eb.real_class, "org.greenrobot.eventbus.EventBus");
        assert_eq!(eb.methods.len(), 2);
        assert_eq!(eb.fields.len(), 1);
        assert_eq!(eb.methods[0].obfuscated_descriptor.as_deref(),
                   Some("()Lorg/greenrobot/eventbus/EventBus;"));
        assert_eq!(eb.methods[0].real_name, "getDefault");
    }

    #[test]
    fn parses_json_with_top_object() {
        let json = r#"{"mappings":[{"obfuscated_class":"a","real_class":"b"}]}"#;
        let f = MappingFile::parse_json(json).unwrap();
        assert_eq!(f.mappings.len(), 1);
    }

    #[test]
    fn parses_json_as_bare_array() {
        let json = r#"[{"obfuscated_class":"a","real_class":"b"}]"#;
        let f = MappingFile::parse_json(json).unwrap();
        assert_eq!(f.mappings.len(), 1);
    }

    #[test]
    fn auto_detects_format() {
        let json = r#"{"mappings":[]}"#;
        assert_eq!(MappingFile::parse_auto(json).unwrap().format, MappingFormat::Json);
        assert_eq!(MappingFile::parse_auto("a -> b:\n").unwrap().format, MappingFormat::Proguard);
    }
}
