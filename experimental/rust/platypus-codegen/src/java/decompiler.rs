/// CFG → AST structure recovery decompiler.
///
/// Converts a method's control-flow graph into a high-level AST composed of
/// sequences, if/else, while, do-while, and loop nodes.  The dominator tree
/// must have been computed on the `Cfg` before calling `decompile`.

use std::collections::{HashMap, HashSet, VecDeque};

use super::analysis::AnalysisConfig;
use super::ast::{AstNode, IfNode, LoopNode, SequenceNode, WhileNode};
use super::dominator_tree::DominatorTree;
use super::ssa_builder::{SsaBuilder, SsaForm};
use platypus_dex::code_block::{BasicBlock, BasicBlockType, Cfg, CfgEdge, EdgeKind};
use platypus_dex::instructions::Instruction;
use platypus_dex::method::Method;

// ── Public API ────────────────────────────────────────────────────────────────

pub struct JavaDecompiler {
    pub config: AnalysisConfig,
}

impl JavaDecompiler {
    pub fn new(config: Option<AnalysisConfig>) -> Self {
        JavaDecompiler { config: config.unwrap_or_default() }
    }

    /// Main decompilation entry point.  Returns a single `AstNode` that
    /// represents the entire method body.
    pub fn decompile(&self, method: &Method) -> AstNode {
        // Guard: no code.
        let cfg = match method.cfg.as_ref() {
            Some(c) if !c.blocks.is_empty() && !method.instructions.is_empty() => c,
            _ => return AstNode::Sequence(SequenceNode::multi(vec![])),
        };

        // Clone so that the dominator tree can be (re-)computed on our copy.
        let mut cfg_owned = clone_cfg(cfg);
        DominatorTree::compute(&mut cfg_owned);

        // Build SSA.
        let mut builder = SsaBuilder::new();
        let ssa = builder.build(
            &cfg_owned,
            &method.instructions,
            method.registers_size,
            method.ins_size,
        );

        // RPO positions for dominance comparisons.
        let rpo = cfg_owned.reverse_postorder();
        let mut rpo_pos: HashMap<usize, usize> = HashMap::new();
        for (pos, &bid) in rpo.iter().enumerate() {
            rpo_pos.insert(bid, pos);
        }

        // Identify loop headers (back-edge targets).
        let loop_headers = find_loop_headers(&cfg_owned, &rpo_pos);

        // Recover structure starting from the entry block.
        structure_region(
            0,
            None,
            &cfg_owned,
            &method.instructions,
            &ssa,
            method.registers_size,
            method.ins_size,
            &loop_headers,
            &rpo_pos,
            &mut HashSet::new(),
        )
    }
}

// ── Register naming ───────────────────────────────────────────────────────────

/// Return the canonical register name: "p0"/"p1"… for parameters, "v0"/"v1"…
/// for locals.
pub fn reg_name(reg: i64, reg_size: u16, ins_size: u16) -> String {
    let threshold = (reg_size as i64) - (ins_size as i64);
    if reg >= threshold {
        format!("p{}", reg - threshold)
    } else {
        format!("v{}", reg)
    }
}

// ── Condition extraction ──────────────────────────────────────────────────────

/// Build the condition string for a branch instruction, using SSA names when
/// available.
pub fn extract_condition(
    instr:    &Instruction,
    ssa:      &SsaForm,
    reg_size: u16,
    ins_size: u16,
) -> String {
    // Best-effort: look up the most recent SSA name for a register.
    let name = |reg: i64| -> String {
        ssa.var_names
            .iter()
            .find(|((r, _v), _)| *r == reg)
            .map(|(_, n)| n.clone())
            .unwrap_or_else(|| reg_name(reg, reg_size, ins_size))
    };

    match instr.opcode {
        0x32 => format!("{} == {}", name(instr.v_a.unwrap_or(0)), name(instr.v_b.unwrap_or(0))),
        0x33 => format!("{} != {}", name(instr.v_a.unwrap_or(0)), name(instr.v_b.unwrap_or(0))),
        0x34 => format!("{} < {}",  name(instr.v_a.unwrap_or(0)), name(instr.v_b.unwrap_or(0))),
        0x35 => format!("{} >= {}", name(instr.v_a.unwrap_or(0)), name(instr.v_b.unwrap_or(0))),
        0x36 => format!("{} > {}",  name(instr.v_a.unwrap_or(0)), name(instr.v_b.unwrap_or(0))),
        0x37 => format!("{} <= {}", name(instr.v_a.unwrap_or(0)), name(instr.v_b.unwrap_or(0))),
        0x38 => format!("{} == 0", name(instr.v_a.unwrap_or(0))),
        0x39 => format!("{} != 0", name(instr.v_a.unwrap_or(0))),
        0x3a => format!("{} < 0",  name(instr.v_a.unwrap_or(0))),
        0x3b => format!("{} >= 0", name(instr.v_a.unwrap_or(0))),
        0x3c => format!("{} > 0",  name(instr.v_a.unwrap_or(0))),
        0x3d => format!("{} <= 0", name(instr.v_a.unwrap_or(0))),
        _    => "true".to_string(),
    }
}

// ── Structure recovery ────────────────────────────────────────────────────────

/// Recursively recovers the AST for the CFG region starting at `entry` and
/// ending just before `exit` (exclusive).
///
/// `visited` prevents re-processing blocks that belong to a containing region.
#[allow(clippy::too_many_arguments)]
fn structure_region(
    entry:        usize,
    exit:         Option<usize>,
    cfg:          &Cfg,
    instructions: &[Instruction],
    ssa:          &SsaForm,
    reg_size:     u16,
    ins_size:     u16,
    loop_headers: &HashSet<usize>,
    rpo_pos:      &HashMap<usize, usize>,
    visited:      &mut HashSet<usize>,
) -> AstNode {
    // Base cases.
    if visited.contains(&entry) {
        return AstNode::Sequence(SequenceNode::multi(vec![]));
    }
    if Some(entry) == exit {
        return AstNode::Sequence(SequenceNode::multi(vec![]));
    }

    let block_type = cfg.blocks[entry].block_type;

    // ── Loop header ───────────────────────────────────────────────────────────
    if loop_headers.contains(&entry) {
        visited.insert(entry);

        // The loop body begins at the fall-through (or "then") successor.
        let body_entry = non_back_edge_successor(entry, cfg, loop_headers, rpo_pos);

        // Where control leaves the loop. `find_loop_exit`'s dominator-based
        // search misses the common case where the exit block *is* dominated
        // by the header (e.g. a plain `while (cond) {…}` whose exit is the
        // header's other forward successor) — there it returns None, which
        // used to drop the post-loop tail (e.g. the trailing `return`).
        // Fall back to "the header's forward successor that isn't the body".
        let loop_exit = find_loop_exit(entry, cfg, rpo_pos)
            .or_else(|| other_forward_successor(entry, cfg, rpo_pos, body_entry));

        let body = if let Some(be) = body_entry {
            structure_region(
                be, loop_exit, cfg, instructions, ssa,
                reg_size, ins_size, loop_headers, rpo_pos, visited,
            )
        } else {
            AstNode::Sequence(SequenceNode::multi(vec![]))
        };

        // The header's conditional branch describes when it is *taken*. When
        // the taken (Jump) edge leaves the loop — i.e. it targets the exit —
        // the `while` continue-condition is the NEGATION of the branch
        // condition (`if-eqz v, exit` ⇒ `while (v != 0)`). When the taken
        // edge re-enters the body instead, the condition stands as-is.
        let raw_condition = last_branch_condition(entry, cfg, instructions, ssa, reg_size, ins_size);
        let condition = if raw_condition != "true"
            && header_jump_target(entry, cfg) == loop_exit
            && loop_exit.is_some()
        {
            invert_condition(raw_condition)
        } else {
            raw_condition
        };

        let loop_node = if condition != "true" {
            AstNode::While(Box::new(WhileNode {
                condition,
                body: Box::new(body),
                header: entry,
            }))
        } else {
            AstNode::Loop(Box::new(LoopNode {
                body: Box::new(body),
                header: entry,
            }))
        };

        // Continue with whatever follows the loop exit.
        return if let Some(ex) = loop_exit {
            let tail = structure_region(
                ex, exit, cfg, instructions, ssa,
                reg_size, ins_size, loop_headers, rpo_pos, visited,
            );
            prepend_ast(loop_node, tail)
        } else {
            loop_node
        };
    }

    // ── If / if-else ──────────────────────────────────────────────────────────
    if block_type == BasicBlockType::If {
        visited.insert(entry);

        let condition = last_branch_condition(entry, cfg, instructions, ssa, reg_size, ins_size);

        // Non-exception successors, deduplicated, preserving order.
        let succs = non_exception_successors(entry, cfg);

        let merge = find_merge_point(&succs, cfg, rpo_pos);

        let (then_id, else_id) = match succs.as_slice() {
            [a, b] => (*a, Some(*b)),
            [a]    => (*a, None),
            _      => return AstNode::Sequence(SequenceNode::single(entry)),
        };

        let true_body = structure_region(
            then_id, merge, cfg, instructions, ssa,
            reg_size, ins_size, loop_headers, rpo_pos, visited,
        );

        let false_body = else_id.map(|eid| Box::new(structure_region(
            eid, merge, cfg, instructions, ssa,
            reg_size, ins_size, loop_headers, rpo_pos, visited,
        )));

        // If one branch is the merge itself, its structured body comes
        // back empty. Drop the empty `else { }` and — when the empty
        // side is the *then* branch — invert the condition so we emit
        // `if (!cond) { body }` instead of `if (cond) { } else { body }`.
        let (condition, true_body, false_body) = collapse_empty_branch(
            condition, true_body, false_body,
        );

        let if_node = AstNode::If(Box::new(IfNode {
            condition,
            true_body: Box::new(true_body),
            false_body,
            header: entry,
        }));

        return if let Some(m) = merge {
            let tail = structure_region(
                m, exit, cfg, instructions, ssa,
                reg_size, ins_size, loop_headers, rpo_pos, visited,
            );
            prepend_ast(if_node, tail)
        } else {
            if_node
        };
    }

    // ── Straight-line sequence ────────────────────────────────────────────────
    visited.insert(entry);
    let mut seq_blocks = vec![entry];
    let mut cur = entry;

    loop {
        // Find the single fall-through successor (if any).
        let nexts = non_exception_successors(cur, cfg);
        if nexts.len() != 1 {
            break;
        }
        let n = nexts[0];
        if Some(n) == exit || visited.contains(&n) {
            break;
        }
        if loop_headers.contains(&n) || cfg.blocks[n].block_type == BasicBlockType::If {
            // Hand off to a recursive call and attach the result.
            let sub = structure_region(
                n, exit, cfg, instructions, ssa,
                reg_size, ins_size, loop_headers, rpo_pos, visited,
            );
            let prefix = AstNode::Sequence(SequenceNode::multi(seq_blocks));
            return prepend_ast(prefix, sub);
        }
        visited.insert(n);
        seq_blocks.push(n);
        cur = n;
    }

    AstNode::Sequence(SequenceNode::multi(seq_blocks))
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Detect back edges and return the set of loop-header block ids.
fn find_loop_headers(cfg: &Cfg, rpo_pos: &HashMap<usize, usize>) -> HashSet<usize> {
    let mut headers = HashSet::new();
    for block in &cfg.blocks {
        for &edge_idx in &block.successor_edges {
            let edge = &cfg.edges[edge_idx];
            if edge.kind == EdgeKind::Exception {
                continue;
            }
            let src = edge.source_id;
            let dst = edge.target_id;
            let src_pos = rpo_pos.get(&src).copied().unwrap_or(usize::MAX);
            let dst_pos = rpo_pos.get(&dst).copied().unwrap_or(usize::MAX);
            // Back edge: dst appears earlier in RPO and dst dominates src.
            if dst_pos <= src_pos && dominates(dst, src, cfg) {
                headers.insert(dst);
            }
        }
    }
    headers
}

/// Returns true if `dom` dominates `node` (dom is on the path from root to node
/// in the dominator tree).
fn dominates(dom: usize, mut node: usize, cfg: &Cfg) -> bool {
    loop {
        if node == dom {
            return true;
        }
        match cfg.blocks[node].dominator {
            Some(parent) if parent != node => node = parent,
            _ => return false,
        }
    }
}

/// Find the loop-exit block: the first successor of `header` (in RPO order)
/// that is NOT dominated by the header (i.e., it lies outside the loop).
fn find_loop_exit(header: usize, cfg: &Cfg, rpo_pos: &HashMap<usize, usize>) -> Option<usize> {
    cfg.blocks[header]
        .successor_edges
        .iter()
        .filter(|&&ei| cfg.edges[ei].kind != EdgeKind::Exception)
        .map(|&ei| cfg.edges[ei].target_id)
        .filter(|&s| !dominates(header, s, cfg) || s == header)
        .min_by_key(|s| rpo_pos.get(s).copied().unwrap_or(usize::MAX))
}

/// Return the successor of a loop header that is entered when the loop body
/// executes (i.e. the successor that is dominated by the header, excluding
/// back-edges to the header itself).
fn non_back_edge_successor(
    header:       usize,
    cfg:          &Cfg,
    loop_headers: &HashSet<usize>,
    rpo_pos:      &HashMap<usize, usize>,
) -> Option<usize> {
    let header_pos = rpo_pos.get(&header).copied().unwrap_or(0);
    cfg.blocks[header]
        .successor_edges
        .iter()
        .filter(|&&ei| cfg.edges[ei].kind != EdgeKind::Exception)
        .map(|&ei| cfg.edges[ei].target_id)
        .filter(|&s| {
            let s_pos = rpo_pos.get(&s).copied().unwrap_or(usize::MAX);
            // Forward edge: successor appears after the header in RPO.
            s_pos > header_pos
        })
        .min_by_key(|s| rpo_pos.get(s).copied().unwrap_or(usize::MAX))
}

/// Return non-exception successors, deduplicated, in edge order.
fn non_exception_successors(block_id: usize, cfg: &Cfg) -> Vec<usize> {
    let mut seen = HashSet::new();
    let mut result = Vec::new();
    for &ei in &cfg.blocks[block_id].successor_edges {
        let edge = &cfg.edges[ei];
        if edge.kind != EdgeKind::Exception && seen.insert(edge.target_id) {
            result.push(edge.target_id);
        }
    }
    result
}

/// Find the merge point for a set of successors: the block with the smallest
/// RPO position that is reachable from ALL successors and appears after all of
/// them in RPO order.
///
/// A successor may *itself* be the merge — this is the "if-then-no-else"
/// pattern where one branch contains the body and the other falls straight
/// through to the join. Without that allowance the if-statement is structured
/// with no merge, no tail is appended, and the fall-through block (which often
/// holds the method's only `return`) is silently dropped.
fn find_merge_point(
    succs:   &[usize],
    cfg:     &Cfg,
    rpo_pos: &HashMap<usize, usize>,
) -> Option<usize> {
    if succs.is_empty() {
        return None;
    }
    let reachable: Vec<HashSet<usize>> = succs.iter().map(|&s| bfs_reachable(s, cfg)).collect();

    let common: HashSet<usize> = reachable
        .iter()
        .skip(1)
        .fold(reachable[0].clone(), |acc, r| acc.intersection(r).copied().collect());

    common
        .into_iter()
        .filter(|b| {
            let merge_pos = rpo_pos.get(b).copied().unwrap_or(usize::MAX);
            succs.iter().all(|s| {
                *s == *b || rpo_pos.get(s).copied().unwrap_or(0) < merge_pos
            })
        })
        .min_by_key(|b| rpo_pos.get(b).copied().unwrap_or(usize::MAX))
}

/// BFS reachability over non-exception edges.
fn bfs_reachable(start: usize, cfg: &Cfg) -> HashSet<usize> {
    let mut visited = HashSet::new();
    let mut queue   = VecDeque::new();
    queue.push_back(start);
    visited.insert(start);
    while let Some(bid) = queue.pop_front() {
        for &ei in &cfg.blocks[bid].successor_edges {
            let edge = &cfg.edges[ei];
            if edge.kind != EdgeKind::Exception && visited.insert(edge.target_id) {
                queue.push_back(edge.target_id);
            }
        }
    }
    visited
}

/// The target of `header`'s taken (Jump) edge — i.e. where its conditional
/// branch goes when the condition holds. `None` when the header has no
/// Jump successor (shouldn't happen for a conditional loop header).
fn header_jump_target(header: usize, cfg: &Cfg) -> Option<usize> {
    cfg.blocks[header]
        .successor_edges
        .iter()
        .map(|&ei| &cfg.edges[ei])
        .find(|e| e.kind == EdgeKind::Jump)
        .map(|e| e.target_id)
}

/// Fallback loop-exit finder for the common natural-loop shape where the
/// exit block is dominated by the header (so `find_loop_exit`'s
/// `!dominates` filter rejects it). Returns the header's forward,
/// non-exception successor that is NOT the loop body entry — that's the
/// block control falls to when the loop ends. `None` when there's no such
/// distinct successor (e.g. an unconditional/infinite loop).
fn other_forward_successor(
    header:     usize,
    cfg:        &Cfg,
    rpo_pos:    &HashMap<usize, usize>,
    body_entry: Option<usize>,
) -> Option<usize> {
    let header_pos = rpo_pos.get(&header).copied().unwrap_or(0);
    cfg.blocks[header]
        .successor_edges
        .iter()
        .map(|&ei| &cfg.edges[ei])
        .filter(|e| e.kind != EdgeKind::Exception)
        .map(|e| e.target_id)
        .filter(|&s| {
            // Forward edge (after the header in RPO) that isn't the body.
            let s_pos = rpo_pos.get(&s).copied().unwrap_or(usize::MAX);
            s_pos > header_pos && Some(s) != body_entry
        })
        .min_by_key(|s| rpo_pos.get(s).copied().unwrap_or(usize::MAX))
}

/// Extract the branch-condition string from the last instruction of `block_id`.
fn last_branch_condition(
    block_id:     usize,
    cfg:          &Cfg,
    instructions: &[Instruction],
    ssa:          &SsaForm,
    reg_size:     u16,
    ins_size:     u16,
) -> String {
    if let Some(&last_idx) = cfg.blocks[block_id].instr_indices.last() {
        extract_condition(&instructions[last_idx], ssa, reg_size, ins_size)
    } else {
        "true".to_string()
    }
}

/// Returns true for a structured AST that emits nothing.
fn is_empty_ast(node: &AstNode) -> bool {
    matches!(node, AstNode::Sequence(s) if s.blocks.is_empty() && s.block.is_none())
        || matches!(node, AstNode::Compound(v) if v.is_empty())
}

/// Cheap textual inversion of a branch condition produced by
/// [`extract_condition`]. Swaps the comparison operator when the shape is
/// recognised; otherwise wraps the whole condition in `!(...)`.
fn invert_condition(cond: String) -> String {
    let pairs: &[(&str, &str)] = &[
        (" == ", " != "),
        (" != ", " == "),
        (" <= ", " > "),
        (" >= ", " < "),
        (" < ",  " >= "),
        (" > ",  " <= "),
    ];
    for (from, to) in pairs {
        // Match only one occurrence (extract_condition emits exactly one).
        if let Some(idx) = cond.find(from) {
            let mut out = String::with_capacity(cond.len());
            out.push_str(&cond[..idx]);
            out.push_str(to);
            out.push_str(&cond[idx + from.len()..]);
            return out;
        }
    }
    format!("!({})", cond)
}

/// Drop an empty `else { }` and, when the *then* branch is the empty one,
/// swap with the (non-empty) else and invert the condition. Returns the
/// possibly-rewritten (condition, true_body, false_body) triple.
fn collapse_empty_branch(
    condition:  String,
    true_body:  AstNode,
    false_body: Option<Box<AstNode>>,
) -> (String, AstNode, Option<Box<AstNode>>) {
    let false_is_empty = false_body.as_deref().map(is_empty_ast).unwrap_or(true);
    let true_is_empty  = is_empty_ast(&true_body);

    match (true_is_empty, false_is_empty) {
        (false, true)  => (condition, true_body, None),
        (true,  false) => {
            // false_body is Some(non-empty) — promote it to the then branch.
            let fb = false_body.expect("non-empty false_body");
            (invert_condition(condition), *fb, None)
        }
        _ => (condition, true_body, false_body),
    }
}

/// Prepend `prefix` before `suffix`, returning a `Compound` of the two.
///
/// Both sides are flattened in-place: a `Compound` is merged into the
/// resulting Vec rather than being nested. An empty `Sequence` on
/// either side is dropped so straight-line code doesn't pick up
/// spurious wrappers.
///
/// **History:** the original implementation wrapped non-empty suffixes
/// in `AstNode::Loop`, which the generator renders as `while (true)
/// { ... }`. That turned every if-statement with a continuation into
/// an unwanted infinite loop. The new `AstNode::Compound` variant
/// expresses "sequence of statements" directly so the loop wrapper is
/// no longer needed.
fn prepend_ast(prefix: AstNode, suffix: AstNode) -> AstNode {
    // Skip empty wrappers; this avoids `Compound([Sequence(empty), …])`
    // junk in the tree.
    if is_empty_ast(&suffix) { return prefix; }
    if is_empty_ast(&prefix) { return suffix; }

    let mut nodes: Vec<AstNode> = Vec::with_capacity(2);
    match prefix {
        AstNode::Compound(mut v) => nodes.append(&mut v),
        other                    => nodes.push(other),
    }
    match suffix {
        AstNode::Compound(mut v) => nodes.append(&mut v),
        other                    => nodes.push(other),
    }
    AstNode::Compound(nodes)
}

// ── CFG shallow clone ─────────────────────────────────────────────────────────

fn clone_cfg(cfg: &Cfg) -> Cfg {
    use std::collections::HashMap;

    let blocks: Vec<BasicBlock> = cfg.blocks.iter().map(|b| BasicBlock {
        id:                b.id,
        instr_indices:     b.instr_indices.clone(),
        block_type:        b.block_type,
        first_codepoint:   b.first_codepoint,
        next_branch:       b.next_branch,
        successor_edges:   b.successor_edges.clone(),
        predecessor_edges: b.predecessor_edges.clone(),
        dominator:         b.dominator,
        dom_children:      b.dom_children.clone(),
        dom_frontier:      b.dom_frontier.clone(),
        loop_header:       b.loop_header,
    }).collect();

    let edges: Vec<CfgEdge> = cfg.edges.iter().map(|e| CfgEdge {
        source_id:  e.source_id,
        target_id:  e.target_id,
        kind:       e.kind,
        switch_key: e.switch_key,
    }).collect();

    let addr_lookup: HashMap<u32, usize> = cfg.addr_lookup.clone();

    Cfg { blocks, edges, addr_lookup }
}

#[cfg(test)]
mod prepend_ast_tests {
    use super::*;
    use crate::java::ast::{AstNode, SequenceNode, IfNode};

    fn seq_single(b: usize) -> AstNode {
        AstNode::Sequence(SequenceNode::single(b))
    }
    fn empty_seq() -> AstNode {
        AstNode::Sequence(SequenceNode::multi(vec![]))
    }
    fn if_with(header: usize) -> AstNode {
        AstNode::If(Box::new(IfNode {
            condition: "true".into(),
            true_body: Box::new(empty_seq()),
            false_body: None,
            header,
        }))
    }

    #[test]
    fn empty_suffix_returns_prefix_unchanged() {
        let p = seq_single(7);
        let result = prepend_ast(p, empty_seq());
        assert!(matches!(result, AstNode::Sequence(s) if s.block == Some(7)));
    }

    #[test]
    fn empty_prefix_returns_suffix_unchanged() {
        let s = seq_single(7);
        let result = prepend_ast(empty_seq(), s);
        assert!(matches!(result, AstNode::Sequence(s) if s.block == Some(7)));
    }

    #[test]
    fn non_empty_pair_produces_compound_of_two() {
        let result = prepend_ast(if_with(3), seq_single(5));
        match result {
            AstNode::Compound(v) => assert_eq!(v.len(), 2),
            other => panic!("expected Compound, got {:?}", other),
        }
    }

    #[test]
    fn compound_prefix_is_flattened_not_nested() {
        // prepend_ast(Compound([a,b]), c) → Compound([a,b,c]) not
        // Compound([Compound([a,b]), c]).
        let prefix = AstNode::Compound(vec![if_with(1), seq_single(2)]);
        let result = prepend_ast(prefix, seq_single(3));
        match result {
            AstNode::Compound(v) => assert_eq!(v.len(), 3),
            other => panic!("expected flat Compound, got {:?}", other),
        }
    }

    #[test]
    fn compound_suffix_is_flattened_not_nested() {
        let suffix = AstNode::Compound(vec![seq_single(2), seq_single(3)]);
        let result = prepend_ast(if_with(1), suffix);
        match result {
            AstNode::Compound(v) => assert_eq!(v.len(), 3),
            other => panic!("expected flat Compound, got {:?}", other),
        }
    }

    #[test]
    fn regression_no_loop_wrapping_for_if_with_continuation() {
        // The bug we fixed: prepend_ast used to wrap any non-empty
        // suffix in AstNode::Loop, which the generator renders as
        // `while (true) { ... }`. With Compound in place, that path
        // never triggers — the result MUST NOT be a Loop.
        let result = prepend_ast(if_with(1), seq_single(2));
        assert!(!matches!(result, AstNode::Loop(_)),
            "prepend_ast must not synthesise a Loop for an if-with-tail");
    }
}

#[cfg(test)]
mod structure_region_tests {
    use super::*;
    use crate::java::ssa_builder::SsaForm;
    use platypus_dex::code_block::{BasicBlock, BasicBlockType, Cfg, CfgEdge, EdgeKind};
    use std::collections::HashMap;

    fn block(id: usize, ty: BasicBlockType, successor_edges: Vec<usize>) -> BasicBlock {
        BasicBlock {
            id,
            instr_indices:     Vec::new(),
            block_type:        ty,
            first_codepoint:   id as u32,
            next_branch:       None,
            successor_edges,
            predecessor_edges: Vec::new(),
            dominator:         None,
            dom_children:      Vec::new(),
            dom_frontier:      Vec::new(),
            loop_header:       false,
        }
    }

    fn edge(source_id: usize, target_id: usize, kind: EdgeKind) -> CfgEdge {
        CfgEdge { source_id, target_id, kind, switch_key: None }
    }

    fn empty_ssa() -> SsaForm {
        SsaForm {
            phi_nodes:      HashMap::new(),
            versions:       HashMap::new(),
            var_names:      HashMap::new(),
            registers_size: 0,
            ins_size:       0,
        }
    }

    /// Run `structure_region` over a synthetic CFG and return its AST. Builds
    /// rpo_pos / loop_headers in a way that mirrors the real decompile entry.
    fn structure(cfg: &Cfg) -> AstNode {
        structure_with_loops(cfg, &HashSet::new())
    }

    /// Like [`structure`] but with an explicit loop-header set, so we can
    /// exercise the loop-reconstruction path. Computes the dominator tree
    /// first — exactly as the real `get_class_java` pipeline does — because
    /// `find_loop_exit`/`dominates` rely on it.
    fn structure_with_loops(cfg: &Cfg, loop_headers: &HashSet<usize>) -> AstNode {
        let mut cfg = clone_cfg(cfg);
        // The synthetic `block()` helper only wires `successor_edges`; the real
        // CFG builder also fills `predecessor_edges`, which the dominator
        // computation reads. Derive them here from the edge list.
        for b in &mut cfg.blocks {
            b.predecessor_edges.clear();
        }
        for (ei, e) in cfg.edges.iter().enumerate() {
            cfg.blocks[e.target_id].predecessor_edges.push(ei);
        }
        crate::java::dominator_tree::DominatorTree::compute(&mut cfg);
        let rpo = cfg.reverse_postorder();
        let rpo_pos: HashMap<usize, usize> =
            rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();
        let ssa = empty_ssa();
        structure_region(
            0, None, &cfg, &[], &ssa, 0, 0,
            loop_headers, &rpo_pos, &mut HashSet::new(),
        )
    }

    /// Recursively count `Sequence` block-ids visited under `node`. Used as a
    /// proxy for "the fall-through block actually made it into the AST".
    fn collect_seq_blocks(node: &AstNode, out: &mut Vec<usize>) {
        match node {
            AstNode::Sequence(s) => {
                if let Some(b) = s.block { out.push(b); }
                out.extend(&s.blocks);
            }
            AstNode::Compound(v)  => v.iter().for_each(|n| collect_seq_blocks(n, out)),
            AstNode::If(i)        => {
                collect_seq_blocks(&i.true_body, out);
                if let Some(fb) = &i.false_body { collect_seq_blocks(fb, out); }
            }
            AstNode::While(w)     => collect_seq_blocks(&w.body, out),
            AstNode::DoWhile(d)   => collect_seq_blocks(&d.body, out),
            AstNode::Loop(l)      => collect_seq_blocks(&l.body, out),
        }
    }

    /// Regression for the canScrollVertically bug: an if-then-else where the
    /// else branch falls straight through to the same block the then branch
    /// reaches via `goto`. B1 is the merge AND a direct successor of B0.
    ///
    /// CFG:
    ///   B0 [If]   succs: [B2 (Jump), B1 (FallThrough)]
    ///   B2 [Goto] succs: [B1 (Jump)]
    ///   B1 [Return]
    ///
    /// Pre-fix, `find_merge_point` rejected B1 because its RPO position was
    /// not strictly greater than every successor's, so the if had no merge,
    /// no tail was attached, and B1 (carrying the only return on the
    /// fall-through path) disappeared from the AST.
    #[test]
    fn if_then_no_else_tail_block_is_kept() {
        let cfg = Cfg {
            blocks: vec![
                block(0, BasicBlockType::If,     vec![0, 1]),
                block(1, BasicBlockType::Return, vec![]),
                block(2, BasicBlockType::Goto,   vec![2]),
            ],
            edges: vec![
                edge(0, 2, EdgeKind::Jump),
                edge(0, 1, EdgeKind::FallThrough),
                edge(2, 1, EdgeKind::Jump),
            ],
            addr_lookup: HashMap::new(),
        };

        let ast = structure(&cfg);

        // The AST must end up containing B1 somewhere — that's the bug.
        let mut seen = Vec::new();
        collect_seq_blocks(&ast, &mut seen);
        assert!(seen.contains(&1),
            "fall-through merge block (B1) was dropped from the AST: {:?}", seen);

        // And the if itself should have no else clause now — it collapsed to
        // `if (cond) { then } <tail>`.
        match &ast {
            AstNode::Compound(parts) => {
                let if_node = parts.iter().find_map(|n| match n {
                    AstNode::If(i) => Some(i),
                    _              => None,
                }).expect("expected an If in the Compound");
                assert!(if_node.false_body.is_none(),
                    "if-then-no-else should not synthesise an empty else clause");
            }
            other => panic!("expected Compound([If, tail]), got {:?}", other),
        }
    }

    /// Regression for the "post-loop tail dropped" bug. A natural `while`
    /// loop whose exit block carries the method's `return`:
    ///
    ///   B0 [If]     header/loop  succs: [B2 (Jump→exit), B1 (FallThrough→body)]
    ///   B1 [Goto]   body         succs: [B0 (Jump, back-edge)]
    ///   B2 [Return] exit
    ///
    /// `find_loop_exit` rejected B2 (it's dominated by the header), returning
    /// None, so the loop node was emitted with no tail and B2's return
    /// vanished. The `other_forward_successor` fallback must recover B2.
    #[test]
    fn while_loop_keeps_exit_tail_block() {
        let cfg = Cfg {
            blocks: vec![
                block(0, BasicBlockType::If,     vec![0, 1]),
                block(1, BasicBlockType::Goto,   vec![2]),
                block(2, BasicBlockType::Return, vec![]),
            ],
            edges: vec![
                edge(0, 2, EdgeKind::Jump),        // taken → exit
                edge(0, 1, EdgeKind::FallThrough), // fall-through → body
                edge(1, 0, EdgeKind::Jump),        // back-edge
            ],
            addr_lookup: HashMap::new(),
        };
        let loops: HashSet<usize> = [0].into_iter().collect();
        let ast = structure_with_loops(&cfg, &loops);

        let mut seen = Vec::new();
        collect_seq_blocks(&ast, &mut seen);
        assert!(seen.contains(&2),
            "exit/return block (B2) was dropped from the AST: {:?}", seen);
    }

    /// `header_jump_target` returns the taken-branch target, and
    /// `other_forward_successor` returns the non-body forward successor —
    /// the two signals the loop reconstructor uses to (a) recover the exit
    /// and (b) decide whether to negate the `while` condition.
    #[test]
    fn loop_exit_and_jump_target_helpers() {
        let cfg = Cfg {
            blocks: vec![
                block(0, BasicBlockType::If,     vec![0, 1]),
                block(1, BasicBlockType::Goto,   vec![2]),
                block(2, BasicBlockType::Return, vec![]),
            ],
            edges: vec![
                edge(0, 2, EdgeKind::Jump),
                edge(0, 1, EdgeKind::FallThrough),
                edge(1, 0, EdgeKind::Jump),
            ],
            addr_lookup: HashMap::new(),
        };
        let rpo = cfg.reverse_postorder();
        let rpo_pos: HashMap<usize, usize> =
            rpo.iter().enumerate().map(|(i, &b)| (b, i)).collect();

        // Taken edge of the header goes to the exit (B2).
        assert_eq!(header_jump_target(0, &cfg), Some(2));
        // Body entry is the fall-through (B1); the "other" forward successor
        // is the exit (B2).
        assert_eq!(other_forward_successor(0, &cfg, &rpo_pos, Some(1)), Some(2));
        // Since the taken edge == exit, the reconstructor will negate the
        // loop condition (verified end-to-end by the differential harness).
    }
}
