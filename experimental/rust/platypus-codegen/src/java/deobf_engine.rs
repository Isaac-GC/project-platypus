/// Deobfuscation engine — translates codegen/java/deobf_engine.py

use platypus_dex::helpers::sign_extend;
use platypus_dex::instructions::Instruction;
use super::analysis::AnalysisConfig;

// ── DeobfuscationChange ───────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct DeobfuscationChange {
    pub kind:      String,
    pub codepoint: u32,
    pub before:    String,
    pub after:     String,
}

impl std::fmt::Display for DeobfuscationChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] @{:#x}: {} -> {}]", self.kind, self.codepoint, self.before, self.after)
    }
}

// ── FoldedInstruction ─────────────────────────────────────────────────────────

/// A synthesised const instruction produced by constant folding.
/// It wraps the original instruction and carries the folded value.
#[derive(Debug, Clone)]
pub struct FoldedInstruction {
    pub original:   Box<Instruction>,
    pub result_reg: i64,
    pub result_val: i64,
}

impl FoldedInstruction {
    /// Build an `Instruction`-like view suitable for downstream consumers.
    /// We reuse the `Instruction` struct directly, patching opcode/operands.
    pub fn into_instruction(self) -> Instruction {
        let mut instr = *self.original;
        instr.opcode = 0x14; // treat as const/4
        instr.v_a = Some(self.result_reg);
        instr.v_b = Some(self.result_val);
        instr.v_c = None;
        instr.instruction_str = format!("const v{}, {} /* folded */", self.result_reg, self.result_val);
        instr
    }
}

// ── DeobfuscationEngine ───────────────────────────────────────────────────────

pub struct DeobfuscationEngine<'a> {
    pub config:  &'a AnalysisConfig,
    pub changes: Vec<DeobfuscationChange>,
}

impl<'a> DeobfuscationEngine<'a> {
    pub fn new(config: &'a AnalysisConfig) -> Self {
        DeobfuscationEngine { config, changes: Vec::new() }
    }

    /// Apply deobfuscation passes to an instruction list and return the
    /// (possibly modified) result.
    pub fn apply(&mut self, instructions: Vec<Instruction>) -> Vec<Instruction> {
        let level = self.config.deobfuscation_level;
        let mut instrs = instructions;

        // Level 1 — always applied
        instrs = self.fold_constants(instrs);
        instrs = self.simplify_goto_chains(instrs);
        instrs = self.remove_nop_padding(instrs);

        if level >= 2 {
            instrs = self.decrypt_xor_strings(instrs);
            instrs = self.inline_single_use_consts(instrs);
        }

        if level >= 3 {
            instrs = self.heuristic_rename(instrs);
            instrs = self.collapse_move_chains(instrs);
        }

        instrs
    }

    // ── Level 1 ──────────────────────────────────────────────────────────────

    fn fold_constants(&mut self, instrs: Vec<Instruction>) -> Vec<Instruction> {
        use std::collections::HashMap;
        let mut const_vals: HashMap<i64, i64> = HashMap::new();
        let mut result = Vec::with_capacity(instrs.len());

        for instr in instrs {
            let op = instr.opcode;

            if matches!(op, 0x12 | 0x13 | 0x14) {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    const_vals.insert(va, vb);
                }
                result.push(instr);
            } else if (0x90..=0x9a).contains(&op) {
                let vb_val = instr.v_b.and_then(|r| const_vals.get(&r).copied());
                let vc_val = instr.v_c.and_then(|r| const_vals.get(&r).copied());

                if let (Some(bv), Some(cv)) = (vb_val, vc_val) {
                    if let Some(folded) = Self::eval_binary(op, bv, cv) {
                        if let Some(va) = instr.v_a {
                            const_vals.insert(va, folded);
                            self.changes.push(DeobfuscationChange {
                                kind:      "constant_fold".to_string(),
                                codepoint: instr.codepoint,
                                before:    instr.instruction_str.clone(),
                                after:     format!("const v{}, {}", va, folded),
                            });
                            let mut patched = instr;
                            patched.opcode = 0x14;
                            patched.v_b = Some(folded);
                            patched.instruction_str = format!("const v{}, {} /* folded */", va, folded);
                            result.push(patched);
                            continue;
                        }
                    }
                }
                result.push(instr);
            } else {
                // Invalidate constant if vA is written
                if let Some(va) = instr.v_a {
                    const_vals.remove(&va);
                }
                result.push(instr);
            }
        }

        result
    }

    fn simplify_goto_chains(&mut self, instrs: Vec<Instruction>) -> Vec<Instruction> {
        use std::collections::HashMap;
        let cp_to_idx: HashMap<u32, usize> = instrs
            .iter()
            .enumerate()
            .map(|(i, instr)| (instr.codepoint, i))
            .collect();

        let mut result = instrs;

        for i in 0..result.len() {
            if !matches!(result[i].opcode, 0x28 | 0x29 | 0x2a) {
                continue;
            }

            let bits = match result[i].opcode { 0x28 => 8, 0x29 => 16, _ => 32 };
            let mut target = (result[i].codepoint as i64 + sign_extend(result[i].v_a.unwrap_or(0), bits)) as u32;
            let origin_cp  = result[i].codepoint;
            let origin_str = result[i].instruction_str.clone();
            let mut hops   = 0u32;

            while hops < 10 {
                let Some(&tidx) = cp_to_idx.get(&target) else { break };
                let t_op = result[tidx].opcode;
                if !matches!(t_op, 0x28 | 0x29 | 0x2a) { break }
                let bits2 = match t_op { 0x28 => 8, 0x29 => 16, _ => 32 };
                let new_target = (result[tidx].codepoint as i64 + sign_extend(result[tidx].v_a.unwrap_or(0), bits2)) as u32;
                if new_target == target { break }
                target = new_target;
                hops += 1;
            }

            if hops > 0 {
                self.changes.push(DeobfuscationChange {
                    kind:      "goto_chain".to_string(),
                    codepoint: origin_cp,
                    before:    origin_str,
                    after:     format!("goto :resolved_{:x} /* chain depth {} */", target, hops),
                });
            }
        }

        result
    }

    fn remove_nop_padding(&mut self, instrs: Vec<Instruction>) -> Vec<Instruction> {
        let mut result = Vec::with_capacity(instrs.len());
        let mut nop_run = 0u32;

        for instr in instrs {
            let is_bare_nop = instr.opcode == 0x00
                && !matches!(instr.kind,
                    platypus_dex::instructions::InstructionKind::PackedSwitchPayload { .. }
                    | platypus_dex::instructions::InstructionKind::SparseSwitchPayload { .. }
                    | platypus_dex::instructions::InstructionKind::FillArrayDataPayload { .. });

            if is_bare_nop {
                nop_run += 1;
                if nop_run <= 1 {
                    result.push(instr);
                } else {
                    self.changes.push(DeobfuscationChange {
                        kind:      "nop_removal".to_string(),
                        codepoint: instr.codepoint,
                        before:    "nop".to_string(),
                        after:     "/* removed nop padding */".to_string(),
                    });
                }
            } else {
                nop_run = 0;
                result.push(instr);
            }
        }

        result
    }

    // ── Level 2 ──────────────────────────────────────────────────────────────

    fn decrypt_xor_strings(&mut self, instrs: Vec<Instruction>) -> Vec<Instruction> {
        // Heuristic: track string-load into a register then detect xor-int/lit8
        use std::collections::HashMap;
        let mut encrypted_strings: HashMap<i64, String> = HashMap::new();

        for instr in &instrs {
            // const-string (0x1a) / const-string/jumbo (0x1b) — we can't resolve
            // the string index without DEX data here, so we skip actual lookup.
            // The change annotation is still emitted when we spot the xor.
            if matches!(instr.opcode, 0x1a | 0x1b) {
                // placeholder — real implementation needs ParsedDex
                if let Some(va) = instr.v_a {
                    encrypted_strings.insert(va, "<string>".to_string());
                }
            }

            if instr.opcode == 0xd7 {
                if let Some(vb) = instr.v_b {
                    if let Some(src_str) = encrypted_strings.get(&vb) {
                        let key = instr.v_c.unwrap_or(0) & 0xff;
                        let decrypted: String = src_str
                            .chars()
                            .map(|c| char::from_u32((c as u32) ^ (key as u32)).unwrap_or(c))
                            .collect();
                        if Self::is_printable(&decrypted) {
                            self.changes.push(DeobfuscationChange {
                                kind:      "xor_decrypt".to_string(),
                                codepoint: instr.codepoint,
                                before:    format!("xor-encrypted: \"{}\"", src_str),
                                after:     format!("decrypted: '{}'", decrypted),
                            });
                        }
                    }
                }
            }
        }

        instrs
    }

    fn inline_single_use_consts(&mut self, instrs: Vec<Instruction>) -> Vec<Instruction> {
        use std::collections::HashMap;
        let mut use_count: HashMap<i64, usize> = HashMap::new();
        let mut def_instr: HashMap<i64, usize> = HashMap::new();

        for (i, instr) in instrs.iter().enumerate() {
            for reg in [instr.v_b, instr.v_c, instr.v_d, instr.v_e, instr.v_f, instr.v_g]
                .iter()
                .flatten()
            {
                *use_count.entry(*reg).or_insert(0) += 1;
            }
            if let Some(va) = instr.v_a {
                if matches!(instr.opcode, 0x12 | 0x13 | 0x14) {
                    def_instr.insert(va, i);
                }
            }
        }

        for (reg, count) in &use_count {
            if *count == 1 {
                if let Some(&def_idx) = def_instr.get(reg) {
                    self.changes.push(DeobfuscationChange {
                        kind:      "inline_const".to_string(),
                        codepoint: instrs[def_idx].codepoint,
                        before:    instrs[def_idx].instruction_str.clone(),
                        after:     "/* inlined into use site */".to_string(),
                    });
                }
            }
        }

        instrs
    }

    // ── Level 3 ──────────────────────────────────────────────────────────────

    fn heuristic_rename(&mut self, instrs: Vec<Instruction>) -> Vec<Instruction> {
        const HINTS: &[(&str, &str)] = &[
            ("Ljava/lang/String;->length", "strLen"),
            ("Ljava/lang/String;->charAt", "strChar"),
            ("Ljava/util/List;->size",     "listSize"),
            ("Ljava/util/Map;->get",       "mapVal"),
            ("Landroid/content/Context;",  "ctx"),
            ("Landroid/app/Activity;",     "activity"),
        ];

        for instr in &instrs {
            if matches!(instr.opcode, 0x6e..=0x72) {
                let ref_str = &instr.instruction_str;
                for (pattern, hint) in HINTS {
                    if ref_str.contains(pattern) {
                        self.changes.push(DeobfuscationChange {
                            kind:      "rename_hint".to_string(),
                            codepoint: instr.codepoint,
                            before:    ref_str.clone(),
                            after:     format!("/* result likely: {} */", hint),
                        });
                    }
                }
            }
        }

        instrs
    }

    fn collapse_move_chains(&mut self, instrs: Vec<Instruction>) -> Vec<Instruction> {
        use std::collections::HashMap;
        let mut move_source: HashMap<i64, i64> = HashMap::new();
        let mut result = Vec::with_capacity(instrs.len());

        for instr in instrs {
            let op = instr.opcode;
            if (0x01..=0x09).contains(&op) {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    // Follow chain to original source
                    let mut src = vb;
                    while let Some(&next) = move_source.get(&src) {
                        if next == src { break; }
                        src = next;
                    }
                    if src != vb {
                        self.changes.push(DeobfuscationChange {
                            kind:      "move_chain".to_string(),
                            codepoint: instr.codepoint,
                            before:    instr.instruction_str.clone(),
                            after:     format!("move v{}, v{} /* chain collapsed */", va, src),
                        });
                        move_source.insert(src, src);
                    }
                    move_source.insert(va, src);
                }
            } else {
                if let Some(va) = instr.v_a {
                    move_source.remove(&va);
                }
                result.push(instr);
                continue;
            }
            result.push(instr);
        }

        result
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn eval_binary(op: u8, a: i64, b: i64) -> Option<i64> {
        let result = match op {
            0x90 => a.checked_add(b)?,
            0x91 => a.checked_sub(b)?,
            0x92 => a.checked_mul(b)?,
            0x93 => if b != 0 { a.checked_div(b)? } else { return None },
            0x94 => if b != 0 { a.checked_rem(b)? } else { return None },
            0x95 => a & b,
            0x96 => a | b,
            0x97 => a ^ b,
            0x98 => a << (b & 31),
            0x99 => a >> (b & 31),
            0x9a => ((a as u64) >> ((b & 31) as u64)) as i64,
            _ => return None,
        };
        Some(result)
    }

    fn is_printable(s: &str) -> bool {
        s.chars().all(|c| {
            !c.is_control() || matches!(c, '\n' | '\t' | '\r')
        })
    }
}
