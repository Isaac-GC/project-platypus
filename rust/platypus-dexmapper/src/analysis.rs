//! Source parsers and the indexing orchestrator. The producer pipeline
//! lives here:
//!   - `smali_parser` — read .smali files (baksmali / jadx output)
//!   - `java_parser`  — read .java files (jadx-decompiled)
//!   - `indexer`      — download → extract → store pipeline

pub mod smali_parser;
pub mod java_parser;
pub mod indexer;
/// DEX target adapter — convert parsed DEX classes into the same
/// `SmaliClass` shape the matcher consumes, so an APK can be matched
/// directly against the index without first running baksmali/jadx.
pub mod dex_target;
