//! Maven Central + Google Maven resolver. Pure-Rust download path
//! (ureq + native-tls) and POM dependency walker (quick-xml).
//!
//! Mirrors `dexmapper.sources.resolver` — same default cache layout
//! (`~/.dexmapper/cache/`), same SHA-1 verification flow, same
//! POM-then-fallback resolution order.

pub mod resolver;
pub use resolver::*;
