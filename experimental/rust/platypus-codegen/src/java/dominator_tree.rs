/// Dominator tree computation.
///
/// Implements Cooper, Harvey, and Kennedy (2001):
/// "A Simple, Fast Dominance Algorithm"
///
/// Key properties of this implementation:
/// - Exception edges (EdgeKind::Exception) are ignored throughout, matching
///   the Python reference.
/// - `usize::MAX` is the sentinel for "undefined / not yet computed".
/// - The entry block's idom is set to itself (index 0).
/// - After the fixed-point loop, dom_children and dom_frontier are populated,
///   and loop_header is set for any block that a back-edge points to.

use platypus_dex::code_block::{Cfg, EdgeKind};

pub struct DominatorTree;

impl DominatorTree {
    /// Compute the dominator tree for `cfg` in-place.
    ///
    /// After this call:
    /// - `cfg.blocks[b].dominator`    — `Some(idom_block_id)` for every reachable
    ///                                   non-entry block; `None` for unreachable ones.
    /// - `cfg.blocks[b].dom_children` — block IDs immediately dominated by `b`.
    /// - `cfg.blocks[b].dom_frontier` — dominance frontier of `b`.
    /// - `cfg.blocks[b].loop_header`  — `true` when at least one back-edge targets `b`.
    pub fn compute(cfg: &mut Cfg) {
        if cfg.blocks.is_empty() {
            return;
        }

        let n = cfg.blocks.len();

        // ── Step 1: RPO order and position map ───────────────────────────────
        //
        // rpo[i]      = block ID at RPO position i
        // rpo_pos[b]  = RPO position of block b
        //
        // Blocks not reachable from the entry (via non-exception edges) will not
        // appear in `rpo`; their rpo_pos entry stays at usize::MAX.

        let rpo = cfg.reverse_postorder(); // Vec<block_id>, entry first
        let mut rpo_pos = vec![usize::MAX; n];
        for (pos, &block_id) in rpo.iter().enumerate() {
            rpo_pos[block_id] = pos;
        }

        // ── Step 2: Cooper iterative fixed-point ─────────────────────────────
        //
        // idom[b] = immediate dominator of block b (by block ID).
        // Sentinel: usize::MAX = "undefined".

        let mut idom = vec![usize::MAX; n];

        // Entry block dominates itself.
        let entry = rpo[0];
        idom[entry] = entry;

        let mut changed = true;
        while changed {
            changed = false;

            // Process blocks in RPO order (skip the entry at position 0).
            for &b in rpo.iter().skip(1) {
                // Collect predecessors reachable in RPO order, skipping exception edges.
                let pred_ids: Vec<usize> = cfg.blocks[b]
                    .predecessor_edges
                    .iter()
                    .map(|&eidx| &cfg.edges[eidx])
                    .filter(|e| e.kind != EdgeKind::Exception)
                    .map(|e| e.source_id)
                    .filter(|&p| rpo_pos[p] != usize::MAX) // only reachable predecessors
                    .collect();

                if pred_ids.is_empty() {
                    continue;
                }

                // Start with the first processed predecessor (lowest RPO position
                // among those whose idom is already defined).
                let new_idom_opt = pred_ids
                    .iter()
                    .copied()
                    .find(|&p| idom[p] != usize::MAX);

                let mut new_idom = match new_idom_opt {
                    Some(p) => p,
                    None => continue, // no predecessor has a defined idom yet
                };

                // Intersect with every other processed predecessor.
                for &p in &pred_ids {
                    if p == new_idom {
                        continue;
                    }
                    if idom[p] != usize::MAX {
                        new_idom = intersect(p, new_idom, &idom, &rpo_pos);
                    }
                }

                if idom[b] != new_idom {
                    idom[b] = new_idom;
                    changed = true;
                }
            }
        }

        // ── Step 3: Write results back into cfg.blocks ───────────────────────

        // dominator field
        for &b in &rpo {
            if b == entry {
                // Entry's idom is itself; leave dominator as None.
                continue;
            }
            if idom[b] != usize::MAX {
                cfg.blocks[b].dominator = Some(idom[b]);
            }
        }

        // dom_children — clear first, then populate
        for block in &mut cfg.blocks {
            block.dom_children.clear();
        }
        for &b in rpo.iter().skip(1) {
            if idom[b] != usize::MAX && idom[b] != b {
                let parent = idom[b];
                cfg.blocks[parent].dom_children.push(b);
            }
        }

        // ── Step 4: Dominance frontiers ──────────────────────────────────────
        //
        // DF(b) = { y | ∃ predecessor p of y s.t. b dominates p but b does not
        //               strictly dominate y }
        //
        // The standard O(N) algorithm: for every join point y (≥ 2 non-exception
        // predecessors), walk up the dominator tree from each predecessor p until
        // we reach idom(y), adding y to DF of each node on the way.

        for block in &mut cfg.blocks {
            block.dom_frontier.clear();
        }

        for &b in &rpo {
            // Collect non-exception predecessors that are reachable.
            let preds: Vec<usize> = cfg.blocks[b]
                .predecessor_edges
                .iter()
                .map(|&eidx| &cfg.edges[eidx])
                .filter(|e| e.kind != EdgeKind::Exception)
                .map(|e| e.source_id)
                .filter(|&p| rpo_pos[p] != usize::MAX)
                .collect();

            if preds.len() < 2 {
                continue; // only join points have non-trivial frontiers
            }

            for p in preds {
                let mut runner = p;
                while runner != idom[b] {
                    // Add b to runner's dominance frontier (avoid duplicates).
                    if !cfg.blocks[runner].dom_frontier.contains(&b) {
                        cfg.blocks[runner].dom_frontier.push(b);
                    }
                    if idom[runner] == usize::MAX || idom[runner] == runner {
                        break; // reached a root
                    }
                    runner = idom[runner];
                }
            }
        }

        // ── Step 5: Loop headers via back-edge detection ─────────────────────
        //
        // A back edge is an edge (p → b) where rpo_pos[b] ≤ rpo_pos[p], i.e. the
        // target appears earlier in RPO than the source.  Any block that is the
        // target of at least one back edge is a loop header.
        //
        // We collect (source, target) pairs first to avoid holding an immutable
        // slice borrow on `cfg.blocks` while we mutably write `loop_header`.

        for block in &mut cfg.blocks {
            block.loop_header = false;
        }

        // Gather back-edge targets into a local vec, skipping exception edges.
        let back_edge_targets: Vec<usize> = rpo
            .iter()
            .flat_map(|&b| {
                cfg.blocks[b]
                    .successor_edges
                    .iter()
                    .filter_map(|&eidx| {
                        let edge = &cfg.edges[eidx];
                        if edge.kind == EdgeKind::Exception {
                            return None;
                        }
                        let target = edge.target_id;
                        // Back edge: target's RPO position ≤ source's RPO position.
                        if rpo_pos[target] != usize::MAX
                            && rpo_pos[b] != usize::MAX
                            && rpo_pos[target] <= rpo_pos[b]
                        {
                            Some(target)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .collect();

        for target in back_edge_targets {
            cfg.blocks[target].loop_header = true;
        }
    }
}

// ── Cooper intersect helper ───────────────────────────────────────────────────

/// Walk up the dominator tree from `b1` and `b2` simultaneously until the
/// two fingers meet at their common dominator.
///
/// This is the `intersect` function from Figure 3 of Cooper et al.  The
/// comparison is done on RPO positions: the node with the *larger* RPO number
/// is closer to the entry in the idom chain, so we advance the *smaller* one.
fn intersect(mut b1: usize, mut b2: usize, idom: &[usize], rpo_pos: &[usize]) -> usize {
    loop {
        if b1 == b2 {
            return b1;
        }
        // Advance the finger that is further from the entry (higher RPO index =
        // further from entry in the post-order, but *lower* in RPO numbering
        // where entry = 0).  We want to advance the one with the larger RPO
        // position number (i.e., processed later, further from entry).
        while rpo_pos[b1] > rpo_pos[b2] {
            b1 = idom[b1];
        }
        while rpo_pos[b2] > rpo_pos[b1] {
            b2 = idom[b2];
        }
    }
}
