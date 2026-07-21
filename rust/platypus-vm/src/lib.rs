pub mod call_site_resolver;
pub mod debugger;
pub mod logger;
pub mod memory;
pub mod mock_handler;
pub mod opcodes;
pub mod threading;
pub mod value;
pub mod vm;

// Convenience re-exports — the public surface most callers want.
pub use debugger::{
    Breakpoint, DebugMode, Debugger, PauseReason, RegisterSnapshot,
    StepDecision, TracePredicate,
};
pub use threading::{ThreadHandle, ThreadInfo, ThreadScheduler, ThreadStatus};
