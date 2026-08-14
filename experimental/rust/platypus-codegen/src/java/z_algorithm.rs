/// Z-Algorithm and dead code detection — translates codegen/java/z_algorithm.py

use std::collections::{HashMap, HashSet};

use platypus_dex::code_block::Cfg;
use platypus_dex::helpers::sign_extend;
use platypus_dex::instructions::Instruction;
use super::analysis::AnalysisConfig;

// ── Z-Algorithm ───────────────────────────────────────────────────────────────

pub struct ZAlgorithm;

impl ZAlgorithm {
    /// Compute the Z-array for a slice of strings (each entry = longest substring
    /// starting at position `i` that is a prefix of the whole slice).
    pub fn compute(pattern: &[String]) -> Vec<usize> {
        let n = pattern.len();
        if n == 0 {
            return Vec::new();
        }
        let mut z = vec![0usize; n];
        z[0] = n;
        let mut l = 0usize;
        let mut r = 0usize;

        for i in 1..n {
            if i < r {
                z[i] = (r - i).min(z[i - l]);
            }
            while i + z[i] < n && pattern[z[i]] == pattern[i + z[i]] {
                z[i] += 1;
            }
            if i + z[i] > r {
                l = i;
                r = i + z[i];
            }
        }
        z
    }

    /// Find positions where the prefix of length >= `min_length` recurs.
    /// Returns `(prefix_start=0, match_start, length)` tuples.
    pub fn find_repeated_sequences(
        instructions: &[Instruction],
        min_length: usize,
    ) -> Vec<(usize, usize, usize)> {
        let mnemonics: Vec<String> = instructions
            .iter()
            .map(|i| {
                i.instruction_str
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        let z_arr = Self::compute(&mnemonics);
        z_arr
            .iter()
            .enumerate()
            .filter(|(_, &length)| length >= min_length)
            .map(|(i, &length)| (0, i, length))
            .collect()
    }
}

// ── ReachabilityAnalyzer ──────────────────────────────────────────────────────

pub struct ReachabilityAnalyzer<'a> {
    cfg: &'a Cfg,
    pub reachable:   HashSet<usize>, // block ids
    pub unreachable: HashSet<usize>,
}

impl<'a> ReachabilityAnalyzer<'a> {
    pub fn new(cfg: &'a Cfg) -> Self {
        ReachabilityAnalyzer {
            cfg,
            reachable: HashSet::new(),
            unreachable: HashSet::new(),
        }
    }

    pub fn analyze(&mut self) {
        if !self.cfg.blocks.is_empty() {
            self.dfs(0);
        }
        for block in &self.cfg.blocks {
            if !self.reachable.contains(&block.id) {
                self.unreachable.insert(block.id);
            }
        }
    }

    fn dfs(&mut self, block_id: usize) {
        if self.reachable.contains(&block_id) {
            return;
        }
        self.reachable.insert(block_id);
        let edge_indices: Vec<usize> = self.cfg.blocks[block_id].successor_edges.clone();
        for edge_idx in edge_indices {
            let target_id = self.cfg.edges[edge_idx].target_id;
            self.dfs(target_id);
        }
    }
}

// ── DeadCodeResult ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct DeadCodeResult {
    /// Block ids that are unreachable.
    pub unreachable_block_ids:  Vec<usize>,
    /// (prefix_start, match_start, length) tuples from Z-algorithm.
    pub repeated_sequences:     Vec<(usize, usize, usize)>,
    /// Codepoints of dead instructions.
    pub dead_instruction_cps:   Vec<u32>,
    pub dead_code_percentage:   f64,
    /// codepoint → annotation string.
    pub annotations:            HashMap<u32, String>,
}

// ── DeadCodeDetector ─────────────────────────────────────────────────────────

pub struct DeadCodeDetector<'a> {
    cfg:          &'a Cfg,
    instructions: &'a [Instruction],
    config:       &'a AnalysisConfig,
    reachability: ReachabilityAnalyzer<'a>,
}

impl<'a> DeadCodeDetector<'a> {
    const PADDING_PATTERNS: &'static [&'static [&'static str]] = &[
        &["nop"],
        &["nop", "nop"],
        &["goto", "nop"],
        &["const/4", "goto"],
        &["move", "move"],
    ];

    pub fn new(cfg: &'a Cfg, instructions: &'a [Instruction], config: &'a AnalysisConfig) -> Self {
        DeadCodeDetector {
            cfg,
            instructions,
            config,
            reachability: ReachabilityAnalyzer::new(cfg),
        }
    }

    pub fn detect(&mut self) -> DeadCodeResult {
        self.reachability.analyze();

        let unreachable_block_ids: Vec<usize> = self.reachability.unreachable.iter().copied().collect();
        let dead_cps_from_blocks = self.collect_dead_instruction_cps(&unreachable_block_ids);

        let mut dead_cps: Vec<u32> = dead_cps_from_blocks.clone();
        let mut repeated = Vec::new();
        let algo = self.config.dead_code_algorithm.as_str();

        if algo == "z" || algo == "both" {
            let (rep, extra_dead) = self.z_algorithm_detection(&dead_cps_from_blocks);
            repeated = rep;
            dead_cps.extend(extra_dead);
        }

        if algo == "reachability" || algo == "both" {
            dead_cps.extend(self.detect_post_terminator_dead_code());
        }

        dead_cps.extend(self.detect_contradictory_branches());
        dead_cps.extend(self.detect_padding_patterns(&dead_cps_from_blocks));

        // Deduplicate
        let mut seen = HashSet::new();
        let unique_dead: Vec<u32> = dead_cps
            .into_iter()
            .filter(|cp| seen.insert(*cp))
            .collect();

        let mut annotations = HashMap::new();
        let dead_block_set: HashSet<u32> = dead_cps_from_blocks.into_iter().collect();
        for &cp in &unique_dead {
            let ann = if dead_block_set.contains(&cp) {
                "/* DEAD CODE: start of unreachable block */"
            } else {
                "/* DEAD CODE: end of unreachable block */"
            };
            annotations.insert(cp, ann.to_string());
        }

        let total = self.instructions.len();
        let dead  = unique_dead.len();
        let pct   = if total > 0 { dead as f64 / total as f64 * 100.0 } else { 0.0 };

        DeadCodeResult {
            unreachable_block_ids,
            repeated_sequences: repeated,
            dead_instruction_cps: unique_dead,
            dead_code_percentage: pct,
            annotations,
        }
    }

    fn collect_dead_instruction_cps(&self, unreachable_ids: &[usize]) -> Vec<u32> {
        let mut cps = Vec::new();
        for &bid in unreachable_ids {
            let block = &self.cfg.blocks[bid];
            for &idx in &block.instr_indices {
                cps.push(self.instructions[idx].codepoint);
            }
        }
        cps
    }

    fn z_algorithm_detection(
        &self,
        dead_cps: &[u32],
    ) -> (Vec<(usize, usize, usize)>, Vec<u32>) {
        let dead_set: HashSet<u32> = dead_cps.iter().copied().collect();

        let dead_instrs: Vec<&Instruction> = self
            .instructions
            .iter()
            .filter(|i| dead_set.contains(&i.codepoint))
            .collect();

        let dead_refs: Vec<Instruction> = dead_instrs.iter().map(|&&ref i| i.clone()).collect();
        let rep_in_dead = ZAlgorithm::find_repeated_sequences(&dead_refs, 3);

        let all_seqs = ZAlgorithm::find_repeated_sequences(self.instructions, 5);
        let mut cloned_cps = Vec::new();
        for (_, mtch, _) in &all_seqs {
            let cp = self.instructions[*mtch].codepoint;
            if dead_set.contains(&cp) {
                cloned_cps.push(cp);
            }
        }

        (rep_in_dead, cloned_cps)
    }

    fn detect_post_terminator_dead_code(&self) -> Vec<u32> {
        let mut dead = Vec::new();
        for block in &self.cfg.blocks {
            let mut found_terminator = false;
            for &idx in &block.instr_indices {
                let instr = &self.instructions[idx];
                if found_terminator {
                    dead.push(instr.codepoint);
                }
                let op = instr.opcode;
                if matches!(op, 0x0e..=0x11 | 0x27 | 0x28 | 0x29 | 0x2a) {
                    found_terminator = true;
                }
            }
        }
        dead
    }

    fn detect_contradictory_branches(&self) -> Vec<u32> {
        let mut dead = Vec::new();
        let mut const_regs: HashMap<i64, i64> = HashMap::new();

        for instr in self.instructions {
            let op = instr.opcode;

            // Track const assignments
            if matches!(op, 0x12 | 0x13 | 0x14) {
                if let (Some(va), Some(vb)) = (instr.v_a, instr.v_b) {
                    const_regs.insert(va, vb);
                }
            }

            // if-z branches
            if (0x38..=0x3d).contains(&op) {
                if let Some(va) = instr.v_a {
                    if let Some(&val) = const_regs.get(&va) {
                        let taken    = Self::eval_ifz(op, val);
                        let target   = (instr.codepoint as i64 + sign_extend(instr.v_b.unwrap_or(0), 16)) as u32;
                        let fallthru = instr.codepoint + 2;
                        let dead_cp  = if taken { fallthru } else { target };
                        for other in self.instructions {
                            if other.codepoint == dead_cp {
                                dead.push(other.codepoint);
                            }
                        }
                    }
                }
            }

            // two-reg if branches
            if (0x32..=0x37).contains(&op) {
                let va_const = instr.v_a.and_then(|r| const_regs.get(&r).copied());
                let vb_const = instr.v_b.and_then(|r| const_regs.get(&r).copied());
                if let (Some(a), Some(b)) = (va_const, vb_const) {
                    let taken    = Self::eval_if(op, a, b);
                    let target   = (instr.codepoint as i64 + sign_extend(instr.v_c.unwrap_or(0), 16)) as u32;
                    let fallthru = instr.codepoint + 2;
                    let dead_cp  = if taken { fallthru } else { target };
                    for other in self.instructions {
                        if other.codepoint == dead_cp {
                            dead.push(other.codepoint);
                        }
                    }
                }
            }
        }
        dead
    }

    fn detect_padding_patterns(&self, dead_cps: &[u32]) -> Vec<u32> {
        let dead_set: HashSet<u32> = dead_cps.iter().copied().collect();
        let mnemonics: Vec<String> = self
            .instructions
            .iter()
            .map(|i| {
                i.instruction_str
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_string()
            })
            .collect();

        let mut dead = Vec::new();

        for pattern in Self::PADDING_PATTERNS {
            let pat_len = pattern.len();
            let mut combined: Vec<String> = pattern.iter().map(|s| s.to_string()).collect();
            combined.push("$".to_string());
            combined.extend_from_slice(&mnemonics);

            let z_arr = ZAlgorithm::compute(&combined);
            let offset = pat_len + 1;

            for (i, &z_val) in z_arr.iter().enumerate().skip(offset) {
                if z_val >= pat_len {
                    let instr_idx = i - offset;
                    if instr_idx < self.instructions.len() {
                        let cp = self.instructions[instr_idx].codepoint;
                        if dead_set.contains(&cp) {
                            for j in instr_idx..instr_idx + pat_len {
                                if j < self.instructions.len() {
                                    dead.push(self.instructions[j].codepoint);
                                }
                            }
                        }
                    }
                }
            }
        }

        dead
    }

    pub fn eval_ifz(op: u8, val: i64) -> bool {
        match op {
            0x38 => val == 0,
            0x39 => val != 0,
            0x3a => val < 0,
            0x3b => val >= 0,
            0x3c => val > 0,
            0x3d => val <= 0,
            _ => false,
        }
    }

    pub fn eval_if(op: u8, a: i64, b: i64) -> bool {
        match op {
            0x32 => a == b,
            0x33 => a != b,
            0x34 => a == b,
            0x35 => a != b,
            0x36 => a == b,
            0x37 => a != b,
            _ => false,
        }
    }
}
