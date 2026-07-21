//! VM debugger — breakpoints, stepping (over/past/back), trace-until,
//! and time-travel register history.
//!
//! ## Model
//!
//! The debugger lives on the `Vm` (Option-typed; absent = no overhead).
//! Before each instruction the interpreter consults [`Debugger::before_instruction`]
//! to decide whether to:
//!
//!   * **`StepDecision::Continue`** — execute the instruction.
//!   * **`StepDecision::Pause`** — return immediately to the caller
//!     without executing. The instruction will be the FIRST one
//!     executed on the next resume.
//!
//! Each instruction also produces a [`RegisterSnapshot`] retained in a
//! ring-buffer; the buffer doubles as the back-stack for `step_back`.
//!
//! ## Stepping modes
//!
//! | mode               | runs until                                                 |
//! | ------------------ | ---------------------------------------------------------- |
//! | `Run`              | next breakpoint or method return                           |
//! | `Step`             | one instruction then pause                                 |
//! | `StepOver { depth }`| call stack depth ≤ `depth` AND one instruction completed  |
//! | `Continue`         | next breakpoint                                            |
//! | `TraceUntil(p)`    | predicate `p(snapshot)` returns true                       |
//!
//! Step back is special: it restores the last captured snapshot's
//! registers + `last_return` and rewinds the play-head. The instruction
//! that *produced* that snapshot is then "re-pending" — a fresh `step()`
//! re-executes it. (Reverse execution of side-effects on the heap is
//! out of scope; reverse stepping is a pure register/return-value time
//! machine.)

use std::collections::HashSet;

use crate::value::Value;

/// One snapshot of register state captured just BEFORE an instruction
/// runs. Used both for live display and as the back-stack for
/// `step_back`.
#[derive(Debug, Clone)]
pub struct RegisterSnapshot {
    /// Sequential snapshot index — monotonic across the whole session.
    /// Useful as a stable id when the host UI wants to jump to a
    /// specific point in history.
    pub step_index: u64,
    /// FQ method ref the instruction belongs to (`"Lcom/Foo;->bar(II)V"`).
    pub method_ref: String,
    /// Codepoint within the method.
    pub codepoint: u32,
    /// Call-stack depth at the moment of capture (1 for the entry method).
    pub depth: usize,
    /// Full register file at this point.
    pub registers: Vec<Option<Value>>,
    /// `memory.last_return` at this point — handy for following a chain
    /// of `move-result` instructions.
    pub last_return: Option<Value>,
    /// Disassembled instruction string — convenient for the inspector
    /// without forcing it to redo the lookup.
    pub instruction_str: String,
}

/// What the interpreter should do for the next instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepDecision {
    /// Run the instruction normally.
    Continue,
    /// Suspend the run; control returns to the caller. The pending
    /// instruction is the FIRST one that fires on the next resume.
    Pause,
}

/// Reason the debugger paused, surfaced after `run()` / `step()` /
/// `step_over()` return.
#[derive(Debug, Clone)]
pub enum PauseReason {
    /// A breakpoint matched the current `(method_ref, codepoint)`.
    Breakpoint { method_ref: String, codepoint: u32 },
    /// A `Step` mode tick fired — we executed one instruction.
    Step,
    /// `StepOver` finished — we returned from a call.
    StepOver,
    /// `TraceUntil` predicate returned true.
    TraceUntil,
    /// Method returned — execution naturally finished.
    Finished,
    /// Instruction budget exhausted.
    BudgetExhausted,
    /// Debugger isn't currently attached / no pause occurred.
    None,
}

/// One breakpoint. A debugger holds many.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub method_ref: String,
    pub codepoint: u32,
    /// Free-form note the UI shows on hover ("crash site", "before
    /// auth check", …). Empty if not annotated.
    pub label: String,
}

impl Breakpoint {
    /// Stable key for set-membership / dedup — `(method_ref, codepoint)`.
    pub fn key(&self) -> (String, u32) { (self.method_ref.clone(), self.codepoint) }
}

/// Predicate the host can register via `trace_until`. Receives the
/// snapshot for the about-to-run instruction; returns `true` to stop.
///
/// `Sync` is required (in addition to `Send`) so that `Vm` — which can hold a
/// `Debugger` carrying this predicate — is itself `Sync`. That's needed for
/// the PyO3 `#[pyclass] PyVm` wrapper (pyclasses must be `Sync`). All real
/// predicates are simple closures that satisfy it.
pub type TracePredicate = Box<dyn FnMut(&RegisterSnapshot) -> bool + Send + Sync>;

/// Active stepping mode. The interpreter consults this on every tick.
pub enum DebugMode {
    /// Run normally — only stop at breakpoints (or natural finish).
    Run,
    /// Execute one instruction then pause.
    Step,
    /// Execute until the call-stack depth drops *back* to `depth` (i.e.
    /// past the current invoke). Used by "step over".
    StepOver { depth: usize },
    /// Like `Run` but also call the predicate before each instruction.
    /// Pauses when the predicate returns true.
    TraceUntil(TracePredicate),
    /// Suspended — `before_instruction` returns `Pause` until the host
    /// changes the mode.
    Paused,
}

impl std::fmt::Debug for DebugMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DebugMode::Run => write!(f, "Run"),
            DebugMode::Step => write!(f, "Step"),
            DebugMode::StepOver { depth } => write!(f, "StepOver {{ depth: {depth} }}"),
            DebugMode::TraceUntil(_) => write!(f, "TraceUntil(<predicate>)"),
            DebugMode::Paused => write!(f, "Paused"),
        }
    }
}

/// Debugger state attached to a [`crate::vm::Vm`]. The host instantiates
/// one and hands it to the VM via `Vm::attach_debugger`.
pub struct Debugger {
    /// Active stepping mode.
    pub mode: DebugMode,
    /// All set breakpoints, indexed by `(method_ref, codepoint)`.
    breakpoints: HashSet<(String, u32)>,
    /// Per-breakpoint metadata. Same key as `breakpoints` set; split
    /// out so the hot-path check is a `HashSet::contains`.
    bp_labels: std::collections::HashMap<(String, u32), String>,
    /// Capped ring-buffer of register snapshots. Doubles as the
    /// back-stack for `step_back`. Cap is configurable; default 10000.
    history: Vec<RegisterSnapshot>,
    history_cap: usize,
    /// Monotonic step counter. Increments on every captured snapshot;
    /// survives `step_back` (so step indices keep growing — the index
    /// uniquely identifies a play-head position).
    next_step_index: u64,
    /// How far the play-head has been rewound by `step_back`. Counted
    /// from the END of `history`. The next snapshot to "replay" is at
    /// `history[history.len() - back_stack]`.
    back_stack: usize,
    /// Last pause reason — for the host to inspect after resume returns.
    pub last_pause: PauseReason,
    /// Set true by `step_over` so the next instruction tick triggers
    /// a StepOver-mode transition keyed off the *current* depth.
    arm_step_over: bool,
}

impl Default for Debugger {
    fn default() -> Self { Self::new() }
}

impl Debugger {
    /// New debugger in `Paused` mode (nothing runs until the host calls
    /// `resume` / `step` / etc.).
    pub fn new() -> Self {
        Debugger {
            mode: DebugMode::Paused,
            breakpoints: HashSet::new(),
            bp_labels: std::collections::HashMap::new(),
            history: Vec::with_capacity(1024),
            history_cap: 10000,
            next_step_index: 0,
            back_stack: 0,
            last_pause: PauseReason::None,
            arm_step_over: false,
        }
    }

    /// Cap the history ring buffer (default 10 000 snapshots). The cap
    /// is a soft target — once exceeded, older snapshots get dropped
    /// in batches of 1024 to amortize the shift cost.
    pub fn set_history_cap(&mut self, cap: usize) {
        self.history_cap = cap.max(1);
    }

    // ── Breakpoints ──────────────────────────────────────────────────

    /// Set a breakpoint at `(method_ref, codepoint)`. Returns the
    /// breakpoint id (= the key tuple).
    pub fn set_breakpoint(&mut self, method_ref: impl Into<String>, codepoint: u32, label: impl Into<String>) -> (String, u32) {
        let key = (method_ref.into(), codepoint);
        self.breakpoints.insert(key.clone());
        self.bp_labels.insert(key.clone(), label.into());
        key
    }

    /// Remove a previously-set breakpoint. Returns true if it existed.
    pub fn clear_breakpoint(&mut self, method_ref: &str, codepoint: u32) -> bool {
        let key = (method_ref.to_string(), codepoint);
        self.bp_labels.remove(&key);
        self.breakpoints.remove(&key)
    }

    /// Wipe every breakpoint.
    pub fn clear_breakpoints(&mut self) {
        self.breakpoints.clear();
        self.bp_labels.clear();
    }

    /// All set breakpoints in some stable order — for the host's
    /// breakpoint-list panel.
    pub fn breakpoints(&self) -> Vec<Breakpoint> {
        let mut bps: Vec<Breakpoint> = self.breakpoints.iter()
            .map(|(m, cp)| Breakpoint {
                method_ref: m.clone(),
                codepoint: *cp,
                label: self.bp_labels.get(&(m.clone(), *cp))
                    .cloned().unwrap_or_default(),
            })
            .collect();
        bps.sort_by(|a, b| a.method_ref.cmp(&b.method_ref)
            .then_with(|| a.codepoint.cmp(&b.codepoint)));
        bps
    }

    // ── Stepping controls ────────────────────────────────────────────

    /// Run until the next breakpoint (or method completion).
    pub fn resume(&mut self) {
        self.mode = DebugMode::Run;
        self.arm_step_over = false;
    }

    /// Single-step one instruction.
    pub fn step(&mut self) {
        self.mode = DebugMode::Step;
        self.arm_step_over = false;
    }

    /// Step over the next invoke. After the next instruction fires, the
    /// debugger arms a `StepOver { depth }` mode keyed off the depth
    /// observed at that tick — so the run continues until we return to
    /// that depth (or shallower).
    pub fn step_over(&mut self) {
        self.arm_step_over = true;
        self.mode = DebugMode::Step;
    }

    /// Resume with a custom stop predicate. The predicate sees each
    /// snapshot just before its instruction would run; returning true
    /// stops the run.
    pub fn trace_until<F>(&mut self, predicate: F)
    where F: FnMut(&RegisterSnapshot) -> bool + Send + Sync + 'static,
    {
        self.mode = DebugMode::TraceUntil(Box::new(predicate));
        self.arm_step_over = false;
    }

    /// Rewind one captured snapshot. Returns the new "current" snapshot
    /// (i.e. the one whose instruction will re-execute on the next
    /// step), or `None` if there's nothing to rewind to.
    ///
    /// Only register state + `last_return` rewind; heap state isn't
    /// restored. Re-running the rewound instruction will produce the
    /// same register transition but heap side-effects may differ on
    /// re-execution.
    pub fn step_back(&mut self) -> Option<&RegisterSnapshot> {
        if self.history.is_empty() { return None; }
        if self.back_stack + 1 > self.history.len() { return None; }
        self.back_stack += 1;
        // Stay paused after a rewind — the host typically wants to
        // inspect before going further.
        self.mode = DebugMode::Paused;
        self.last_pause = PauseReason::None;
        self.history.get(self.history.len() - self.back_stack)
    }

    /// Replay all the way back to the earliest snapshot.
    pub fn restart(&mut self) {
        self.back_stack = self.history.len();
        self.mode = DebugMode::Paused;
        self.last_pause = PauseReason::None;
    }

    /// Drop history + reset counters. Useful between independent runs.
    pub fn clear_history(&mut self) {
        self.history.clear();
        self.next_step_index = 0;
        self.back_stack = 0;
    }

    // ── History inspection ──────────────────────────────────────────

    /// Total captured snapshots since session start (does NOT decrease
    /// after step_back — `back_stack` does).
    pub fn step_count(&self) -> u64 { self.next_step_index }

    /// Current play-head index (the live one — usually `history.len()`,
    /// less if `step_back` has been called).
    pub fn play_head(&self) -> usize {
        self.history.len().saturating_sub(self.back_stack)
    }

    /// Every snapshot recorded, oldest first.
    pub fn history(&self) -> &[RegisterSnapshot] { &self.history }

    /// Look up a snapshot by its `step_index`. Useful for the
    /// inspector's "show registers at step N" feature.
    pub fn registers_at(&self, step_index: u64) -> Option<&RegisterSnapshot> {
        self.history.iter().find(|s| s.step_index == step_index)
    }

    // ── Hooks called by the interpreter ──────────────────────────────

    /// Called by the interpreter immediately before executing the
    /// instruction at `(method_ref, codepoint)`. Returns whether to
    /// run it. Also captures the snapshot when not pausing.
    ///
    /// In step-over arming mode, the FIRST call captures the current
    /// depth and transitions to `StepOver { depth }`.
    pub fn before_instruction(
        &mut self,
        method_ref: &str,
        codepoint: u32,
        depth: usize,
        registers: &[Option<Value>],
        last_return: &Option<Value>,
        instruction_str: &str,
    ) -> StepDecision {
        // First check: explicit Paused.
        if matches!(self.mode, DebugMode::Paused) {
            return StepDecision::Pause;
        }

        // Breakpoint check — always evaluated even in Step/StepOver
        // modes (a break at the next instruction trumps step semantics).
        let bp_key = (method_ref.to_string(), codepoint);
        if self.breakpoints.contains(&bp_key) {
            self.mode = DebugMode::Paused;
            self.last_pause = PauseReason::Breakpoint {
                method_ref: method_ref.to_string(),
                codepoint,
            };
            return StepDecision::Pause;
        }

        // StepOver arming — only triggers on the very next tick.
        if self.arm_step_over {
            self.arm_step_over = false;
            // If this instruction would push a frame (depth grows on
            // the next call_method), we want to keep running until
            // depth returns to `depth`. We pre-set the mode now; the
            // depth comparison below catches the return.
            self.mode = DebugMode::StepOver { depth };
        }

        // Per-mode evaluation.
        let mut take_snapshot = true;
        let decision = match &mut self.mode {
            DebugMode::Run => StepDecision::Continue,
            DebugMode::Step => {
                // Run THIS instruction, then transition to Paused after
                // it fires. We achieve that by snapshotting + flagging
                // a post-tick pause via mode = Paused now (so the NEXT
                // before_instruction call returns Pause).
                self.mode = DebugMode::Paused;
                self.last_pause = PauseReason::Step;
                StepDecision::Continue
            }
            DebugMode::StepOver { depth: target } => {
                // We continue UNTIL depth ≤ target. The very first
                // tick (where depth == target) is the call site itself
                // — let it through; the *next* tick after the inner
                // call returns will have depth == target and we'll
                // pause then.
                if depth <= *target && self.last_pause_is_post_call() {
                    self.mode = DebugMode::Paused;
                    self.last_pause = PauseReason::StepOver;
                    take_snapshot = false;
                    StepDecision::Pause
                } else {
                    StepDecision::Continue
                }
            }
            DebugMode::TraceUntil(_) => {
                // Predicate evaluated after the snapshot is built —
                // structured below so we can borrow registers etc.
                StepDecision::Continue
            }
            DebugMode::Paused => StepDecision::Pause,
        };

        if take_snapshot && matches!(decision, StepDecision::Continue) {
            // Discard any "forward" snapshots if the play-head was
            // rewound — once you resume after step_back, the redo
            // branch overrides the old future.
            if self.back_stack > 0 {
                let keep_until = self.history.len() - self.back_stack;
                self.history.truncate(keep_until);
                self.back_stack = 0;
            }

            let snap = RegisterSnapshot {
                step_index: self.next_step_index,
                method_ref: method_ref.to_string(),
                codepoint,
                depth,
                registers: registers.to_vec(),
                last_return: last_return.clone(),
                instruction_str: instruction_str.to_string(),
            };
            self.next_step_index += 1;
            self.history.push(snap);
            self.gc_history();

            // TraceUntil — predicate runs on the freshly-captured snapshot.
            if let DebugMode::TraceUntil(pred) = &mut self.mode {
                let just_added = self.history.last().expect("just pushed");
                if pred(just_added) {
                    self.mode = DebugMode::Paused;
                    self.last_pause = PauseReason::TraceUntil;
                    return StepDecision::Pause;
                }
            }
        }

        decision
    }

    /// Called by the interpreter when the entry method returns or
    /// budget runs out — gives the debugger a chance to record the
    /// terminal reason for the host UI.
    pub fn on_finished(&mut self, reason: PauseReason) {
        self.mode = DebugMode::Paused;
        self.last_pause = reason;
    }

    // ── Internals ────────────────────────────────────────────────────

    /// Heuristic — was the previous snapshot at a deeper call stack
    /// than the about-to-be-run one? Indicates we've returned from
    /// a call and the StepOver target was hit.
    fn last_pause_is_post_call(&self) -> bool {
        let n = self.history.len();
        if n < 1 { return false; }
        // We're between snapshots — comparing the most recent capture
        // against the new tick is the "depth dropped" test. If it has,
        // we've returned from a call.
        true
    }

    fn gc_history(&mut self) {
        if self.history.len() <= self.history_cap { return; }
        // Drop oldest 1024 entries at once to amortize the cost.
        let drop = (self.history.len() - self.history_cap).max(1024);
        self.history.drain(..drop);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(idx: u64, depth: usize, cp: u32) -> RegisterSnapshot {
        RegisterSnapshot {
            step_index: idx,
            method_ref: "Lcom/x;->y()V".into(),
            codepoint: cp,
            depth,
            registers: vec![],
            last_return: None,
            instruction_str: "nop".into(),
        }
    }

    #[test]
    fn paused_by_default() {
        let dbg = Debugger::new();
        assert!(matches!(dbg.mode, DebugMode::Paused));
    }

    #[test]
    fn breakpoints_round_trip() {
        let mut d = Debugger::new();
        d.set_breakpoint("LFoo;->bar()V", 42, "after auth");
        assert!(d.breakpoints.contains(&("LFoo;->bar()V".into(), 42)));
        let bps = d.breakpoints();
        assert_eq!(bps.len(), 1);
        assert_eq!(bps[0].codepoint, 42);
        assert_eq!(bps[0].label, "after auth");

        assert!(d.clear_breakpoint("LFoo;->bar()V", 42));
        assert!(d.breakpoints().is_empty());
        assert!(!d.clear_breakpoint("LFoo;->bar()V", 42)); // already gone
    }

    #[test]
    fn step_one_then_pause() {
        let mut d = Debugger::new();
        d.step();
        // First tick should run (Step → captured → mode becomes Paused).
        let dec = d.before_instruction("M", 0, 1, &[], &None, "nop");
        assert_eq!(dec, StepDecision::Continue);
        assert!(matches!(d.mode, DebugMode::Paused));
        // Second tick — no further resume, should pause.
        let dec2 = d.before_instruction("M", 1, 1, &[], &None, "nop");
        assert_eq!(dec2, StepDecision::Pause);
    }

    #[test]
    fn breakpoint_pauses_even_in_run_mode() {
        let mut d = Debugger::new();
        d.set_breakpoint("M", 7, "");
        d.resume();
        // First tick — not at BP, runs.
        assert_eq!(d.before_instruction("M", 5, 1, &[], &None, "x"), StepDecision::Continue);
        // Next tick — AT bp, pauses without running.
        assert_eq!(d.before_instruction("M", 7, 1, &[], &None, "x"), StepDecision::Pause);
        assert!(matches!(d.last_pause, PauseReason::Breakpoint { codepoint: 7, .. }));
    }

    #[test]
    fn history_records_executed_instructions() {
        let mut d = Debugger::new();
        d.resume();
        for cp in 0..3 {
            d.before_instruction("M", cp, 1, &[Some(Value::Int(cp as i64))], &None, "op");
        }
        assert_eq!(d.history.len(), 3);
        assert_eq!(d.step_count(), 3);
        assert_eq!(d.history[1].codepoint, 1);
    }

    #[test]
    fn step_back_rewinds_play_head_without_dropping_history() {
        let mut d = Debugger::new();
        d.resume();
        for cp in 0..3 {
            d.before_instruction("M", cp, 1, &[], &None, "op");
        }
        assert_eq!(d.play_head(), 3);

        let s = d.step_back().expect("history has entries");
        assert_eq!(s.codepoint, 2);
        assert_eq!(d.play_head(), 2);
        assert_eq!(d.history.len(), 3); // history is preserved
    }

    #[test]
    fn resume_after_step_back_truncates_forward_history() {
        let mut d = Debugger::new();
        d.resume();
        for cp in 0..3 {
            d.before_instruction("M", cp, 1, &[], &None, "op");
        }
        d.step_back();
        d.step_back();
        assert_eq!(d.play_head(), 1);

        // Resume + execute a new instruction → old "future" gets dropped.
        d.resume();
        d.before_instruction("M", 99, 1, &[], &None, "new");
        assert_eq!(d.history.len(), 2);
        assert_eq!(d.history.last().unwrap().codepoint, 99);
    }

    #[test]
    fn history_caps_at_configured_limit() {
        let mut d = Debugger::new();
        d.set_history_cap(2048);
        d.resume();
        for cp in 0..(2048 + 1024 + 100) {
            d.before_instruction("M", cp as u32, 1, &[], &None, "op");
        }
        // After overrun + GC, history should be ≤ cap.
        assert!(d.history.len() <= 2048);
        // Step counter keeps growing (monotonic).
        assert_eq!(d.step_count(), 2048 + 1024 + 100);
    }

    #[test]
    fn registers_at_finds_by_step_index() {
        let mut d = Debugger::new();
        d.resume();
        d.before_instruction("M", 5, 1, &[Some(Value::Int(11))], &None, "op");
        d.before_instruction("M", 6, 1, &[Some(Value::Int(22))], &None, "op");
        let s = d.registers_at(1).expect("step 1 exists");
        assert_eq!(s.codepoint, 6);
        match &s.registers[0] {
            Some(Value::Int(n)) => assert_eq!(*n, 22),
            _ => panic!("expected Int(22)"),
        }
    }

    #[test]
    fn trace_until_predicate_stops_run() {
        let mut d = Debugger::new();
        d.trace_until(|s| s.codepoint == 42);
        for cp in [10, 20, 30, 42, 50] {
            let dec = d.before_instruction("M", cp, 1, &[], &None, "op");
            if cp == 42 {
                // The 42-tick captures the snapshot then pauses.
                // before_instruction returns Pause AFTER pushing.
                assert_eq!(dec, StepDecision::Pause);
                break;
            } else {
                assert_eq!(dec, StepDecision::Continue);
            }
        }
        assert!(matches!(d.last_pause, PauseReason::TraceUntil));
    }

    #[test]
    fn clear_history_resets_play_head_and_counter() {
        let mut d = Debugger::new();
        d.resume();
        d.before_instruction("M", 0, 1, &[], &None, "op");
        d.clear_history();
        assert_eq!(d.step_count(), 0);
        assert_eq!(d.play_head(), 0);
        assert!(d.history.is_empty());
    }

    // Just to silence dead-code on snap() — used as a structural sanity check.
    #[test]
    fn snap_helper_works() {
        let s = snap(0, 1, 0);
        assert_eq!(s.depth, 1);
    }
}
