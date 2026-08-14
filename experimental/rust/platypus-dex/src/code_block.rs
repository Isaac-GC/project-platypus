/// Basic block / CFG construction — translates dex/code_block.py

use std::collections::{HashMap, HashSet};

use super::instructions::{Instruction, InstructionKind};
use super::helpers::sign_extend;

// ── Block & edge types ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicBlockType {
    Return,
    Throw,
    Goto,
    If,
    Switch,
    Generic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeKind {
    FallThrough,
    Jump,
    Exception,
    Switch,
}

#[derive(Debug, Clone)]
pub struct CfgEdge {
    pub source_id: usize,
    pub target_id: usize,
    pub kind: EdgeKind,
    pub switch_key: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub id: usize,
    /// Indices into the instruction vector.
    pub instr_indices: Vec<usize>,
    pub block_type: BasicBlockType,
    /// Codepoint of the first instruction (or u32::MAX if empty).
    pub first_codepoint: u32,
    /// Absolute codepoint target for GOTO/IF blocks.
    pub next_branch: Option<u32>,

    // CFG connectivity (stored as edge indices into the parent CFG's edge vec)
    pub successor_edges:   Vec<usize>,
    pub predecessor_edges: Vec<usize>,

    // Dominator fields (populated by a separate pass if needed)
    pub dominator: Option<usize>,
    pub dom_children: Vec<usize>,
    pub dom_frontier: Vec<usize>,

    pub loop_header: bool,
}

impl BasicBlock {
    fn new(id: usize) -> Self {
        BasicBlock {
            id,
            instr_indices: Vec::new(),
            block_type: BasicBlockType::Generic,
            first_codepoint: u32::MAX,
            next_branch: None,
            successor_edges: Vec::new(),
            predecessor_edges: Vec::new(),
            dominator: None,
            dom_children: Vec::new(),
            dom_frontier: Vec::new(),
            loop_header: false,
        }
    }
}

// ── CFG ───────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Cfg {
    pub blocks: Vec<BasicBlock>,
    pub edges: Vec<CfgEdge>,
    /// Maps codepoint → block id.
    pub addr_lookup: HashMap<u32, usize>,
}

impl Cfg {
    /// Reverse post-order traversal (excluding exception edges).
    pub fn reverse_postorder(&self) -> Vec<usize> {
        if self.blocks.is_empty() {
            return Vec::new();
        }
        let mut visited = HashSet::new();
        let mut result  = Vec::new();
        self.dfs_rpo(0, &mut visited, &mut result);
        result.reverse();
        result
    }

    fn dfs_rpo(&self, block_id: usize, visited: &mut HashSet<usize>, result: &mut Vec<usize>) {
        if visited.contains(&block_id) {
            return;
        }
        visited.insert(block_id);
        let block = &self.blocks[block_id];
        for &edge_idx in &block.successor_edges {
            let edge = &self.edges[edge_idx];
            if edge.kind != EdgeKind::Exception {
                self.dfs_rpo(edge.target_id, visited, result);
            }
        }
        result.push(block_id);
    }

    /// Look up a block by codepoint.
    pub fn block_at(&self, codepoint: u32) -> Option<&BasicBlock> {
        self.addr_lookup.get(&codepoint).map(|&id| &self.blocks[id])
    }
}

// ── Builder ───────────────────────────────────────────────────────────────────

pub struct CfgBuilder<'a> {
    instructions: &'a [Instruction],
}

impl<'a> CfgBuilder<'a> {
    pub fn new(instructions: &'a [Instruction]) -> Self {
        CfgBuilder { instructions }
    }

    pub fn build(
        &self,
        try_items: &[super::parser::TryItem],
        handlers: &[super::parser::EncodedCatchHandler],
    ) -> Cfg {
        let leaders = self.find_leaders();
        let (mut blocks, addr_lookup, instr_to_block) = self.build_blocks(&leaders);

        for block in &mut blocks {
            classify_block(block, self.instructions);
        }

        let mut edges: Vec<CfgEdge> = Vec::new();
        let sorted_cps: Vec<u32> = {
            let mut v: Vec<u32> = addr_lookup.keys().copied().collect();
            v.sort_unstable();
            v
        };

        connect_edges(&mut blocks, &mut edges, &addr_lookup, &sorted_cps, self.instructions);
        add_exception_edges(&mut blocks, &mut edges, &addr_lookup, try_items, handlers);

        Cfg { blocks, edges, addr_lookup }
    }

    fn find_leaders(&self) -> HashSet<u32> {
        let instrs = self.instructions;
        if instrs.is_empty() {
            return HashSet::new();
        }
        let mut leaders: HashSet<u32> = HashSet::new();
        leaders.insert(instrs[0].codepoint);

        for (i, instr) in instrs.iter().enumerate() {
            let op = instr.opcode;

            let mark_next = |leaders: &mut HashSet<u32>| {
                if i + 1 < instrs.len() {
                    leaders.insert(instrs[i + 1].codepoint);
                }
            };

            match op {
                // unconditional goto family
                0x28 | 0x29 | 0x2a => {
                    let bits = match op { 0x28 => 8, 0x29 => 16, _ => 32 };
                    let offset = instr.v_a.unwrap_or(0);
                    let target = (instr.codepoint as i64 + sign_extend(offset, bits)) as u32;
                    leaders.insert(target);
                    mark_next(&mut leaders);
                }
                // if-* (two-register)
                0x32..=0x37 => {
                    let offset = instr.v_c.unwrap_or(0);
                    let target = (instr.codepoint as i64 + sign_extend(offset, 16)) as u32;
                    leaders.insert(target);
                    mark_next(&mut leaders);
                }
                // if-*z (zero compare)
                0x38..=0x3d => {
                    let offset = instr.v_b.unwrap_or(0);
                    let target = (instr.codepoint as i64 + sign_extend(offset, 16)) as u32;
                    leaders.insert(target);
                    mark_next(&mut leaders);
                }
                // switch
                0x2b | 0x2c => {
                    if let InstructionKind::Switch { ref table } = instr.kind {
                        for &rel in table.table.values() {
                            let target = (instr.codepoint as i64 + rel as i64) as u32;
                            leaders.insert(target);
                        }
                    }
                    mark_next(&mut leaders);
                }
                // return / throw
                0x0e..=0x11 | 0x27 => {
                    mark_next(&mut leaders);
                }
                _ => {}
            }
        }
        leaders
    }

    fn build_blocks(
        &self,
        leaders: &HashSet<u32>,
    ) -> (Vec<BasicBlock>, HashMap<u32, usize>, HashMap<usize, usize>) {
        let mut blocks: Vec<BasicBlock>         = Vec::new();
        let mut addr_lookup: HashMap<u32, usize> = HashMap::new();
        let mut instr_to_block: HashMap<usize, usize> = HashMap::new();

        let mut current_id: Option<usize> = None;

        for (idx, instr) in self.instructions.iter().enumerate() {
            if leaders.contains(&instr.codepoint) {
                let id = blocks.len();
                let mut block = BasicBlock::new(id);
                block.first_codepoint = instr.codepoint;
                blocks.push(block);
                addr_lookup.insert(instr.codepoint, id);
                current_id = Some(id);
            }
            if let Some(id) = current_id {
                blocks[id].instr_indices.push(idx);
                instr_to_block.insert(idx, id);
            }
        }

        (blocks, addr_lookup, instr_to_block)
    }
}

// ── Edge building ─────────────────────────────────────────────────────────────

fn classify_block(block: &mut BasicBlock, instrs: &[Instruction]) {
    let last_idx = *block.instr_indices.last().unwrap_or(&0);
    if block.instr_indices.is_empty() {
        return;
    }
    let last = &instrs[last_idx];
    let op = last.opcode;

    block.block_type = match op {
        0x0e..=0x11 => BasicBlockType::Return,
        0x27 => BasicBlockType::Throw,
        0x28 => {
            block.next_branch = Some((last.codepoint as i64 + sign_extend(last.v_a.unwrap_or(0), 8)) as u32);
            BasicBlockType::Goto
        }
        0x29 => {
            block.next_branch = Some((last.codepoint as i64 + sign_extend(last.v_a.unwrap_or(0), 16)) as u32);
            BasicBlockType::Goto
        }
        0x2a => {
            block.next_branch = Some((last.codepoint as i64 + sign_extend(last.v_a.unwrap_or(0), 32)) as u32);
            BasicBlockType::Goto
        }
        0x32..=0x37 => {
            block.next_branch = Some((last.codepoint as i64 + sign_extend(last.v_c.unwrap_or(0), 16)) as u32);
            BasicBlockType::If
        }
        0x38..=0x3d => {
            block.next_branch = Some((last.codepoint as i64 + sign_extend(last.v_b.unwrap_or(0), 16)) as u32);
            BasicBlockType::If
        }
        0x2b | 0x2c => BasicBlockType::Switch,
        _ => BasicBlockType::Generic,
    };
}

fn connect_edges(
    blocks: &mut Vec<BasicBlock>,
    edges: &mut Vec<CfgEdge>,
    addr_lookup: &HashMap<u32, usize>,
    sorted_cps: &[u32],
    instrs: &[Instruction],
) {
    let block_count = blocks.len();
    for block_id in 0..block_count {
        let last_instr_idx = *blocks[block_id].instr_indices.last().unwrap_or(&usize::MAX);
        if last_instr_idx == usize::MAX { continue; }
        let last = &instrs[last_instr_idx];
        let op = last.opcode;

        let next_block_id = |cp: u32| -> Option<usize> {
            let pos = sorted_cps.binary_search(&cp).ok()?;
            sorted_cps.get(pos + 1).and_then(|&next_cp| addr_lookup.get(&next_cp).copied())
        };

        let target_id = |cp: u32| -> Option<usize> { addr_lookup.get(&cp).copied() };

        let first_cp = blocks[block_id].first_codepoint;

        match op {
            0x28 => {
                let t = (last.codepoint as i64 + sign_extend(last.v_a.unwrap_or(0), 8)) as u32;
                if let Some(tid) = target_id(t) {
                    add_edge(blocks, edges, block_id, tid, EdgeKind::Jump, None);
                }
            }
            0x29 => {
                let t = (last.codepoint as i64 + sign_extend(last.v_a.unwrap_or(0), 16)) as u32;
                if let Some(tid) = target_id(t) {
                    add_edge(blocks, edges, block_id, tid, EdgeKind::Jump, None);
                }
            }
            0x2a => {
                let t = (last.codepoint as i64 + sign_extend(last.v_a.unwrap_or(0), 32)) as u32;
                if let Some(tid) = target_id(t) {
                    add_edge(blocks, edges, block_id, tid, EdgeKind::Jump, None);
                }
            }
            0x32..=0x37 => {
                let t = (last.codepoint as i64 + sign_extend(last.v_c.unwrap_or(0), 16)) as u32;
                if let Some(tid) = target_id(t) {
                    add_edge(blocks, edges, block_id, tid, EdgeKind::Jump, None);
                }
                if let Some(fid) = next_block_id(first_cp) {
                    add_edge(blocks, edges, block_id, fid, EdgeKind::FallThrough, None);
                }
            }
            0x38..=0x3d => {
                let t = (last.codepoint as i64 + sign_extend(last.v_b.unwrap_or(0), 16)) as u32;
                if let Some(tid) = target_id(t) {
                    add_edge(blocks, edges, block_id, tid, EdgeKind::Jump, None);
                }
                if let Some(fid) = next_block_id(first_cp) {
                    add_edge(blocks, edges, block_id, fid, EdgeKind::FallThrough, None);
                }
            }
            0x2b | 0x2c => {
                if let InstructionKind::Switch { ref table } = last.kind {
                    for (&key, &rel) in &table.table {
                        let t = (last.codepoint as i64 + rel as i64) as u32;
                        if let Some(tid) = target_id(t) {
                            add_edge(blocks, edges, block_id, tid, EdgeKind::Switch, Some(key));
                        }
                    }
                }
                if let Some(fid) = next_block_id(first_cp) {
                    add_edge(blocks, edges, block_id, fid, EdgeKind::FallThrough, None);
                }
            }
            0x0e..=0x11 | 0x27 => {
                // terminators — no successors
            }
            _ => {
                // fall-through
                if let Some(fid) = next_block_id(first_cp) {
                    add_edge(blocks, edges, block_id, fid, EdgeKind::FallThrough, None);
                }
            }
        }
    }
}

fn add_exception_edges(
    blocks: &mut Vec<BasicBlock>,
    edges: &mut Vec<CfgEdge>,
    addr_lookup: &HashMap<u32, usize>,
    try_items: &[super::parser::TryItem],
    handlers: &[super::parser::EncodedCatchHandler],
) {
    for try_item in try_items {
        let start = try_item.start_addr;
        let end   = start + try_item.insn_count as u32;

        // Every block whose first codepoint falls in [start, end) may throw
        let covered_blocks: Vec<usize> = addr_lookup
            .iter()
            .filter(|(&cp, _)| start <= cp && cp < end)
            .map(|(_, &id)| id)
            .collect();

        for handler in handlers {
            for h in &handler.handlers {
                let handler_addr = h.addr as u32;
                if let Some(&handler_block_id) = addr_lookup.get(&handler_addr) {
                    for &src_id in &covered_blocks {
                        add_edge(blocks, edges, src_id, handler_block_id, EdgeKind::Exception, None);
                    }
                }
            }
            if let Some(catch_all) = handler.catch_all_addr {
                let handler_addr = catch_all as u32;
                if let Some(&handler_block_id) = addr_lookup.get(&handler_addr) {
                    for &src_id in &covered_blocks {
                        add_edge(blocks, edges, src_id, handler_block_id, EdgeKind::Exception, None);
                    }
                }
            }
        }
    }
}

fn add_edge(
    blocks: &mut Vec<BasicBlock>,
    edges: &mut Vec<CfgEdge>,
    src_id: usize,
    dst_id: usize,
    kind: EdgeKind,
    switch_key: Option<i32>,
) {
    let edge_idx = edges.len();
    edges.push(CfgEdge { source_id: src_id, target_id: dst_id, kind, switch_key });
    blocks[src_id].successor_edges.push(edge_idx);
    blocks[dst_id].predecessor_edges.push(edge_idx);
}
