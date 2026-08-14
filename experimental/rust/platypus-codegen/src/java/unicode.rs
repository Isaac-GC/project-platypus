/// Unicode string analysis — translates codegen/java/unicode.py

use std::collections::HashSet;

use super::analysis::AnalysisConfig;

// ── Character sets ────────────────────────────────────────────────────────────

/// Zero-width characters (invisible but present in encoded strings).
fn is_zero_width(c: char) -> bool {
    matches!(c, '\u{200b}' | '\u{200c}' | '\u{200d}' | '\u{feff}' | '\u{00ad}')
}

/// BIDI override / isolate characters.
fn is_bidi_override(c: char) -> bool {
    matches!(
        c,
        '\u{202a}'
            | '\u{202b}'
            | '\u{202c}'
            | '\u{202d}'
            | '\u{202e}'
            | '\u{2066}'
            | '\u{2067}'
            | '\u{2068}'
            | '\u{2069}'
    )
}

// ── Script / category helpers ─────────────────────────────────────────────────

/// Rough Unicode script tag for a single character.
fn script_tag(c: char) -> &'static str {
    let cp = c as u32;
    match cp {
        0x0041..=0x005a | 0x0061..=0x007a => "LATIN",
        0x0030..=0x0039 => "DIGIT",
        0x0009 | 0x000a | 0x000d | 0x0020 => "SPACE",
        // Basic Latin control etc. → treat as LATIN for simplicity
        0x0000..=0x007f => "LATIN",
        // Latin-1 Supplement, Latin Extended
        0x0080..=0x024f => "LATIN",
        // Greek
        0x0370..=0x03ff => "GREEK",
        // Cyrillic
        0x0400..=0x04ff => "CYRILLIC",
        // Arabic
        0x0600..=0x06ff => "ARABIC",
        // Hebrew
        0x0590..=0x05ff => "HEBREW",
        // CJK unified ideographs
        0x4e00..=0x9fff => "CJK",
        // Hangul syllables
        0xac00..=0xd7af => "HANGUL",
        // Hiragana / Katakana
        0x3040..=0x30ff => "HIRAGANA",
        // Devanagari
        0x0900..=0x097f => "DEVANAGARI",
        _ => "UNKNOWN",
    }
}

// ── UnicodeString ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct UnicodeString {
    pub raw:                String,
    pub codepoint:          u32,
    pub source:             String, // "direct", "escaped", "char_array", "xor_decoded"
    pub has_unicode:        bool,
    pub unicode_chars:      Vec<char>,
    pub script_categories:  HashSet<String>,
    pub is_suspicious:      bool,
    pub display_forms:      Vec<(String, String)>, // ordered (key, value) pairs
}

impl UnicodeString {
    pub fn new(raw: String, codepoint: u32, source: &str) -> Self {
        UnicodeString {
            raw,
            codepoint,
            source: source.to_string(),
            has_unicode: false,
            unicode_chars: Vec::new(),
            script_categories: HashSet::new(),
            is_suspicious: false,
            display_forms: Vec::new(),
        }
    }

    pub fn analyze(&mut self) {
        self.unicode_chars = self.raw.chars().filter(|&c| c as u32 > 127).collect();
        self.has_unicode   = !self.unicode_chars.is_empty();
        self.script_categories = self.categorize_scripts();
        self.is_suspicious = self.check_suspicious();
        self.display_forms = self.build_display_forms();
    }

    fn categorize_scripts(&self) -> HashSet<String> {
        let mut cats = HashSet::new();
        for c in self.raw.chars() {
            if c as u32 > 127 {
                cats.insert(script_tag(c).to_string());
            }
        }
        cats
    }

    fn check_suspicious(&self) -> bool {
        let latin_scripts: HashSet<&str> = ["LATIN", "DIGIT", "SPACE"].iter().copied().collect();
        let non_latin: HashSet<&str> = self
            .script_categories
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !latin_scripts.contains(s))
            .collect();
        let has_mixed = self.script_categories.iter().any(|s| latin_scripts.contains(s.as_str()))
            && !non_latin.is_empty();

        let has_zero_width = self.raw.chars().any(is_zero_width);
        let has_bidi       = self.raw.chars().any(is_bidi_override);

        has_mixed || has_zero_width || has_bidi
    }

    fn build_display_forms(&self) -> Vec<(String, String)> {
        let mut forms = vec![
            ("raw".to_string(),     self.raw.clone()),
            ("escaped".to_string(), self.to_escaped()),
            ("unicode".to_string(), self.to_unicode_names()),
            ("hex".to_string(),     self.to_hex()),
        ];
        if self.is_suspicious {
            forms.push(("safe".to_string(), self.to_safe()));
        }
        forms
    }

    fn to_escaped(&self) -> String {
        let mut out = String::new();
        for c in self.raw.chars() {
            if c as u32 > 127 {
                out.push_str(&format!("\\u{:04x}", c as u32));
            } else {
                out.push(c);
            }
        }
        out
    }

    fn to_unicode_names(&self) -> String {
        let mut out = String::new();
        for c in self.raw.chars() {
            if c as u32 > 127 {
                out.push_str(&format!("[U+{:04X}]", c as u32));
            } else {
                out.push(c);
            }
        }
        out
    }

    fn to_hex(&self) -> String {
        self.raw
            .chars()
            .map(|c| format!("{:04x}", c as u32))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn to_safe(&self) -> String {
        let mut out = String::new();
        for c in self.raw.chars() {
            if is_zero_width(c) {
                out.push_str(&format!("[ZWS:U+{:04X}]", c as u32));
            } else if is_bidi_override(c) {
                out.push_str(&format!("[BIDI:U+{:04X}]", c as u32));
            } else {
                out.push(c);
            }
        }
        out
    }

    fn display_form(&self, key: &str) -> Option<&str> {
        self.display_forms.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
    }

    pub fn format(&self, config: &AnalysisConfig) -> String {
        if !self.has_unicode {
            return format!("\"{}\"", self.raw);
        }
        let mode = config.unicode_display.as_str();
        if mode == "unicode" {
            return format!("\"{}\"", self.raw);
        }
        if mode == "escaped" {
            return format!("\"{}\"", self.to_escaped());
        }
        // "both" or other — include both raw and escaped as a comment
        let escaped = self.to_escaped();
        if self.is_suspicious {
            let safe = self.display_form("safe").unwrap_or(&escaped);
            format!("\"{}\" /* SUSPICIOUS: {} */", self.raw, safe)
        } else {
            format!("\"{}\" /* {} */", self.raw, escaped)
        }
    }
}

// ── Unicode (recovery engine) ─────────────────────────────────────────────────

/// Heuristic Unicode/obfuscated string recovery for a single method.
/// The method is modelled generically via the instruction slice and register
/// access; the actual DEX string look-up is left as a hook since in Rust the
/// DEX data is separate from the method.
pub struct Unicode<'a> {
    pub instructions: &'a [platypus_dex::instructions::Instruction],
    pub config: &'a AnalysisConfig,
}

impl<'a> Unicode<'a> {
    pub fn new(
        instructions: &'a [platypus_dex::instructions::Instruction],
        config: &'a AnalysisConfig,
    ) -> Self {
        Unicode { instructions, config }
    }

    /// Trace backwards from `from_idx` to find a const assignment to `reg`.
    pub fn trace_register_value(&self, from_idx: usize, reg: i64) -> Option<i64> {
        let start = if from_idx == 0 { 0 } else { from_idx.saturating_sub(20) };
        for i in (start..from_idx).rev() {
            let instr = &self.instructions[i];
            if instr.v_a == Some(reg) && matches!(instr.opcode, 0x12 | 0x13 | 0x14) {
                return instr.v_b;
            }
        }
        None
    }

    /// Detect potential XOR-decoded strings (register-level heuristic).
    /// Returns (xor_reg, decoded_chars) pairs where we found enough chars.
    pub fn find_xor_sequences(&self) -> Vec<(i64, Vec<char>)> {
        use std::collections::HashMap;
        let mut xor_regs: HashMap<i64, Vec<char>> = HashMap::new();

        for (i, instr) in self.instructions.iter().enumerate() {
            let op = instr.opcode;
            // xor-int/lit8 (0xd7)
            if op == 0xd7 {
                if let (Some(reg), Some(val)) = (instr.v_a, instr.v_b) {
                    if let Some(original) = self.trace_register_value(i, val) {
                        let decoded_char_val = original ^ val;
                        if let Some(c) = char::from_u32(decoded_char_val as u32) {
                            xor_regs.entry(reg).or_default().push(c);
                        }
                    }
                }
            }
        }

        xor_regs
            .into_iter()
            .filter(|(_, chars)| chars.len() >= 2)
            .collect()
    }

    /// Detect char-array construction patterns.
    pub fn find_char_array_sequences(&self) -> Vec<(u32, String)> {
        let mut results = Vec::new();
        let instrs = self.instructions;
        let mut i = 0;

        while i < instrs.len() {
            let instr = &instrs[i];
            // new-array (0x23) — check if char array via type annotation is skipped here
            if instr.opcode == 0x23 {
                let (chars, end_idx) = self.extract_char_sequence(i);
                if !chars.is_empty() {
                    let s: String = chars
                        .iter()
                        .filter_map(|&v| char::from_u32(v as u32))
                        .collect();
                    results.push((instr.codepoint, s));
                    i = end_idx;
                    continue;
                }
            }
            i += 1;
        }

        results
    }

    fn extract_char_sequence(&self, start: usize) -> (Vec<i64>, usize) {
        let mut chars: Vec<i64> = Vec::new();
        let instrs = self.instructions;
        let mut i = start + 1;
        let mut pending_const: Option<(i64, i64)> = None; // (reg, val)

        while i < instrs.len() && i < start + 100 {
            let instr = &instrs[i];
            let op = instr.opcode;

            if op == 0x12 || op == 0x13 {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    pending_const = Some((va, vb));
                }
            } else if op == 0x49 {
                if let Some((pc_reg, pc_val)) = pending_const {
                    if instr.v_a == Some(pc_reg) {
                        chars.push(pc_val);
                        pending_const = None;
                    }
                }
            } else if op == 0x6e || op == 0x70 {
                return (chars, i);
            }

            i += 1;
        }

        (chars, i)
    }
}
