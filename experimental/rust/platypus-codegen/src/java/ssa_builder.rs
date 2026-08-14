/// SSA form construction — implements the classic Cytron et al. algorithm
/// (dominance-frontier-based phi placement + dominator-tree rename pass).
///
/// The dominator tree (block.dominator, block.dom_children, block.dom_frontier)
/// must already be populated on the Cfg before calling `SsaBuilder::build`.

use std::collections::{HashMap, HashSet, VecDeque};

use platypus_dex::code_block::Cfg;
use platypus_dex::instructions::Instruction;

// ── Public types ──────────────────────────────────────────────────────────────

/// A single source contribution to a phi node: (predecessor block id, register, version).
#[derive(Debug, Clone)]
pub struct PhiSource {
    pub pred_block: usize,
    pub reg:        i64,
    pub version:    usize,
}

/// A phi function placed at a block entry for one register.
#[derive(Debug, Clone)]
pub struct PhiNode {
    /// Destination register.
    pub dst_reg:     i64,
    /// Version assigned to the destination.
    pub dst_version: usize,
    /// One source per predecessor (filled during the rename pass).
    pub sources:     Vec<PhiSource>,
}

/// A versioned register reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SsaVar {
    pub reg:     i64,
    pub version: usize,
}

/// The complete SSA form for a method body.
#[derive(Debug)]
pub struct SsaForm {
    /// block_id → phi nodes placed at that block's entry.
    pub phi_nodes: HashMap<usize, Vec<PhiNode>>,
    /// (block_id, reg) → version number live at that block's *exit*.
    pub versions:  HashMap<(usize, i64), usize>,
    /// (reg, version) → human-readable name  ("v3_1", "p0", …).
    pub var_names: HashMap<(i64, usize), String>,
    /// Number of registers declared in the method.
    pub registers_size: u16,
    /// Number of in-parameters.
    pub ins_size: u16,
}

impl SsaForm {
    /// Return the canonical name for a (reg, version) pair.
    pub fn var_name(&self, reg: i64, version: usize) -> String {
        if let Some(n) = self.var_names.get(&(reg, version)) {
            return n.clone();
        }
        // Fallback — should not normally be reached.
        Self::compute_name(reg, version, self.registers_size, self.ins_size)
    }

    /// Compute the canonical name without a lookup table.
    pub fn compute_name(reg: i64, version: usize, registers_size: u16, ins_size: u16) -> String {
        let param_threshold = (registers_size as i64) - (ins_size as i64);
        if reg >= param_threshold {
            // Parameter register: p0, p1, …  (no version suffix)
            format!("p{}", reg - param_threshold)
        } else {
            format!("v{}_{}", reg, version)
        }
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

pub struct SsaBuilder {
    /// Global version counter — incremented each time a new version is minted.
    next_version: usize,
}

impl SsaBuilder {
    pub fn new() -> Self {
        SsaBuilder { next_version: 0 }
    }

    /// Return an empty SsaForm for methods with no instructions/cfg.
    pub fn empty_ssa() -> SsaForm {
        SsaForm {
            phi_nodes:      std::collections::HashMap::new(),
            versions:       std::collections::HashMap::new(),
            var_names:      std::collections::HashMap::new(),
            registers_size: 0,
            ins_size:       0,
        }
    }

    /// Build SSA form for a method.
    ///
    /// `cfg`            — control-flow graph (dominator tree already computed).
    /// `instructions`   — flat instruction list for the method.
    /// `registers_size` — total registers declared.
    /// `ins_size`       — number of in-parameters.
    pub fn build(
        &mut self,
        cfg:            &Cfg,
        instructions:   &[Instruction],
        registers_size: u16,
        ins_size:       u16,
    ) -> SsaForm {
        if cfg.blocks.is_empty() {
            return SsaForm {
                phi_nodes: HashMap::new(),
                versions:  HashMap::new(),
                var_names: HashMap::new(),
                registers_size,
                ins_size,
            };
        }

        // ── Step 1: collect the set of registers defined in each block ────────
        let defs_by_block: Vec<HashSet<i64>> = Self::collect_defs(cfg, instructions);

        // ── Step 2: collect the universe of all registers ever defined ────────
        let all_regs: HashSet<i64> = defs_by_block.iter().flat_map(|s| s.iter().copied()).collect();

        // ── Step 3: place phi nodes using dominance frontiers ─────────────────
        let mut phi_nodes: HashMap<usize, Vec<PhiNode>> = HashMap::new();
        Self::place_phi_nodes(cfg, &defs_by_block, &all_regs, &mut phi_nodes);

        // ── Step 4: rename variables with a DFS over the dominator tree ───────
        // Stack of current versions per register.
        let mut version_stacks: HashMap<i64, Vec<usize>> = HashMap::new();
        // Seed parameters with version 0.
        let param_threshold = (registers_size as i64) - (ins_size as i64);
        for p in 0..(ins_size as i64) {
            let reg = param_threshold + p;
            let v   = self.fresh_version();
            version_stacks.entry(reg).or_default().push(v);
        }

        let mut versions:  HashMap<(usize, i64), usize> = HashMap::new();
        let mut var_names: HashMap<(i64, usize), String> = HashMap::new();

        self.rename_block(
            0,
            cfg,
            instructions,
            &mut phi_nodes,
            &mut version_stacks,
            &mut versions,
            &mut var_names,
            registers_size,
            ins_size,
        );

        SsaForm { phi_nodes, versions, var_names, registers_size, ins_size }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn fresh_version(&mut self) -> usize {
        let v = self.next_version;
        self.next_version += 1;
        v
    }

    /// For each block, collect every register that is *defined* (written) by
    /// any instruction in that block.  The definition is the v_a operand for
    /// most instructions that produce a value.
    fn collect_defs(cfg: &Cfg, instructions: &[Instruction]) -> Vec<HashSet<i64>> {
        let mut defs = vec![HashSet::new(); cfg.blocks.len()];
        for (block_id, block) in cfg.blocks.iter().enumerate() {
            for &idx in &block.instr_indices {
                if let Some(reg) = instructions[idx].v_a {
                    // Only count it as a def if the instruction actually writes a register.
                    // We use a simple heuristic: exclude pure control-flow opcodes.
                    let op = instructions[idx].opcode;
                    if is_def_opcode(op) {
                        defs[block_id].insert(reg);
                    }
                }
            }
        }
        defs
    }

    /// Classic worklist-based phi placement (Cytron et al.).
    fn place_phi_nodes(
        cfg:           &Cfg,
        defs_by_block: &[HashSet<i64>],
        all_regs:      &HashSet<i64>,
        phi_nodes:     &mut HashMap<usize, Vec<PhiNode>>,
    ) {
        for &reg in all_regs {
            // Blocks that define this register.
            let mut worklist: VecDeque<usize> = defs_by_block
                .iter()
                .enumerate()
                .filter(|(_, defs)| defs.contains(&reg))
                .map(|(id, _)| id)
                .collect();

            // Tracks which blocks already have a phi for this register.
            let mut has_phi: HashSet<usize> = HashSet::new();

            while let Some(block_id) = worklist.pop_front() {
                for &frontier_id in &cfg.blocks[block_id].dom_frontier {
                    if has_phi.insert(frontier_id) {
                        // Count predecessors (non-exception) for this block.
                        let pred_count = cfg.blocks[frontier_id].predecessor_edges.len();
                        phi_nodes.entry(frontier_id).or_default().push(PhiNode {
                            dst_reg:     reg,
                            dst_version: 0, // filled during rename
                            sources:     Vec::with_capacity(pred_count),
                        });
                        // If this block wasn't already in the def set, add it now
                        // because the phi itself is a definition.
                        if !defs_by_block[frontier_id].contains(&reg) {
                            worklist.push_back(frontier_id);
                        }
                    }
                }
            }
        }
    }

    /// Recursive rename pass — DFS over the dominator tree.
    #[allow(clippy::too_many_arguments)]
    fn rename_block(
        &mut self,
        block_id:       usize,
        cfg:            &Cfg,
        instructions:   &[Instruction],
        phi_nodes:      &mut HashMap<usize, Vec<PhiNode>>,
        stacks:         &mut HashMap<i64, Vec<usize>>,
        versions:       &mut HashMap<(usize, i64), usize>,
        var_names:      &mut HashMap<(i64, usize), String>,
        registers_size: u16,
        ins_size:       u16,
    ) {
        // Track how many versions we push in this block so we can pop them later.
        let mut pushed: Vec<(i64, usize)> = Vec::new(); // (reg, version) pairs we pushed

        // ── (a) Assign new versions to phi-node destinations ──────────────────
        if let Some(phis) = phi_nodes.get_mut(&block_id) {
            for phi in phis.iter_mut() {
                let v = self.fresh_version();
                phi.dst_version = v;
                stacks.entry(phi.dst_reg).or_default().push(v);
                pushed.push((phi.dst_reg, v));
                let name = SsaForm::compute_name(phi.dst_reg, v, registers_size, ins_size);
                var_names.insert((phi.dst_reg, v), name);
            }
        }

        // ── (b) Rename uses and defs in each instruction ──────────────────────
        for &idx in &cfg.blocks[block_id].instr_indices {
            let instr = &instructions[idx];
            let op = instr.opcode;

            // For any instruction that defines a register (v_a), mint a new version.
            if let Some(dst_reg) = instr.v_a {
                if is_def_opcode(op) {
                    let v = self.fresh_version();
                    stacks.entry(dst_reg).or_default().push(v);
                    pushed.push((dst_reg, v));
                    let name = SsaForm::compute_name(dst_reg, v, registers_size, ins_size);
                    var_names.insert((dst_reg, v), name);
                }
            }
        }

        // Record exit versions for every register that has an active version.
        for (&reg, stack) in stacks.iter() {
            if let Some(&v) = stack.last() {
                versions.insert((block_id, reg), v);
            }
        }

        // ── (c) Fill phi-source slots in each successor ───────────────────────
        for &edge_idx in &cfg.blocks[block_id].successor_edges {
            let succ_id = cfg.edges[edge_idx].target_id;
            if let Some(phis) = phi_nodes.get_mut(&succ_id) {
                for phi in phis.iter_mut() {
                    let v = stacks
                        .get(&phi.dst_reg)
                        .and_then(|s| s.last().copied())
                        .unwrap_or(0);
                    phi.sources.push(PhiSource {
                        pred_block: block_id,
                        reg:        phi.dst_reg,
                        version:    v,
                    });
                }
            }
        }

        // ── (d) Recurse into dominator-tree children ──────────────────────────
        let children: Vec<usize> = cfg.blocks[block_id].dom_children.clone();
        for child_id in children {
            self.rename_block(
                child_id, cfg, instructions, phi_nodes, stacks,
                versions, var_names, registers_size, ins_size,
            );
        }

        // ── (e) Pop versions we pushed in this block ──────────────────────────
        for (reg, _version) in pushed.into_iter().rev() {
            if let Some(stack) = stacks.get_mut(&reg) {
                stack.pop();
            }
        }
    }
}

impl Default for SsaBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ── Opcode helpers ────────────────────────────────────────────────────────────

/// Returns true if this opcode produces a value in its first operand (v_a).
/// Instructions that only read registers or are pure control-flow return false.
fn is_def_opcode(op: u8) -> bool {
    match op {
        // nop, payloads
        0x00 => false,
        // return-* and throw do not define a register
        0x0e..=0x11 | 0x27 => false,
        // goto family — no register def
        0x28..=0x2a => false,
        // if-* and if-*z — no register def
        0x32..=0x3d => false,
        // switch — no register def
        0x2b | 0x2c => false,
        // iput / sput / aput — store, v_a is the *source* register
        0x59..=0x5f => false, // iput variants
        0x67..=0x6d => false, // sput variants
        0x4b..=0x51 => false, // aput variants
        // invoke family — result goes through move-result, not v_a
        0x6e..=0x72 | 0x74..=0x78 | 0xfa..=0xfc => false,
        // monitor-enter / monitor-exit
        0x1d | 0x1e => false,
        // Everything else is treated as defining v_a when v_a is Some.
        _ => true,
    }
}
