//! Indexer — orchestrates the producer pipeline:
//!
//!   1. Resolve a Maven coordinate (or accept a local path) → JAR/AAR
//!   2. Extract every `.class` via `bytecode::extract_classes_from_*`
//!   3. Store each class + methods + fields + call edges + structural
//!      fingerprints into the SQLite index, with the
//!      content-addressed dedup on `class_defs.fingerprint`
//!   4. Optionally walk POM-declared transitive dependencies and recurse
//!
//! Mirrors `dexmapper.analysis.indexer.Indexer` — same return shape,
//! same idempotency guarantee (re-indexing an already-indexed artifact
//! is a no-op short-circuit).

use std::path::{Path, PathBuf};

use crate::bytecode::{self, ClassInfo};
use crate::db::{self, Database};
use crate::sources::resolver::{self, ResolvedArtifact, ResolverError};

/// Build a synthetic `version` string out of a file's mtime — used for
/// the DEX / APK index paths where there's no proper GAV coordinate.
/// Re-indexing the same file is a no-op; modifying it changes the
/// version and forces re-extraction.
fn synthetic_version(path: &Path) -> String {
    let mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("mtime-{mtime}")
}

/// Per-call summary returned by `index_artifact` / `index_local`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct IndexSummary {
    pub artifact: String,        // "group:artifact:version"
    pub status: String,          // "indexed" | "already_indexed"
    pub classes: usize,
    pub methods: usize,
}

/// Caller-supplied progress reporter — invoked with short status strings
/// so a CLI can print them and a Tauri command can stream them.
pub type ProgressFn<'a> = &'a mut dyn FnMut(&str);

pub struct Indexer<'a> {
    pub db: &'a Database,
    pub cache_dir: Option<PathBuf>,
}

impl<'a> Indexer<'a> {
    pub fn new(db: &'a Database) -> Self {
        Self { db, cache_dir: None }
    }
    pub fn with_cache_dir(mut self, dir: PathBuf) -> Self {
        self.cache_dir = Some(dir); self
    }

    /// Resolve + download + index one Maven artifact. When `transitive`
    /// is true, walks POM `<dependency>`s with scope in (compile, runtime).
    pub fn index_artifact(
        &self,
        group: &str, artifact: &str, version: &str,
        packaging: Option<&str>,
        repos: Option<&[&str]>,
        transitive: bool,
        progress: ProgressFn<'_>,
    ) -> Result<IndexSummary, ResolverError> {
        progress(&format!("Resolving {group}:{artifact}:{version}"));
        let resolved = resolver::download_artifact(
            group, artifact, version, packaging, self.cache_dir.as_deref(), repos,
        )?;
        progress(&format!("Downloaded {}", resolved.local_path.display()));
        let summary = self.index_resolved(&resolved, progress)?;

        if transitive {
            if let Some(pom) = resolver::fetch_pom(
                &resolved.group_id, &resolved.artifact_id, &resolved.version, repos,
            ) {
                let deps = resolver::parse_pom_dependencies(&pom);
                for d in deps {
                    if d.scope.is_empty() || d.scope == "compile" || d.scope == "runtime" {
                        progress(&format!("Transitive: {}:{}", d.group, d.artifact));
                        let r = self.index_artifact(
                            &d.group, &d.artifact, &d.version, None, repos, false, progress,
                        );
                        if let Err(e) = r { progress(&format!("  Skipped {}: {e}", d.artifact)); }
                    }
                }
            }
        }
        Ok(summary)
    }

    /// Index a local JAR / AAR file (no network).
    pub fn index_local(
        &self, path: &Path, progress: ProgressFn<'_>,
    ) -> Result<IndexSummary, ResolverError> {
        let artifact = resolver::resolve_local(path)?;
        progress(&format!("Indexing local: {}", artifact.local_path.display()));
        self.index_resolved(&artifact, progress)
    }

    /// Index a single `.dex` file directly. The class list is decoded
    /// via [`bytecode_dex::classes_from_dex_path`]. Artifact is
    /// recorded as `local:<file-stem>:<file-mtime>` so re-running on a
    /// modified dex re-indexes, while an unchanged dex short-circuits.
    pub fn index_dex(
        &self, path: &Path, progress: ProgressFn<'_>,
    ) -> Result<IndexSummary, ResolverError> {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("dex").to_string();
        let version = synthetic_version(path);
        let key = format!("local:{stem}:{version}");
        progress(&format!("Indexing dex: {}", path.display()));

        if self.db.get_artifact("local", &stem, &version)
            .map_err(|e| ResolverError::BadFormat(format!("db: {e}")))?.is_some()
        {
            progress(&format!("Already indexed: {key}"));
            return Ok(IndexSummary { artifact: key, status: "already_indexed".into(), classes: 0, methods: 0 });
        }

        let classes = crate::bytecode_dex::classes_from_dex_path(path);
        progress(&format!("Extracted {} classes from dex", classes.len()));

        let art_id = self.db.upsert_artifact("local", &stem, &version, "dex", "local_dex")
            .map_err(|e| ResolverError::BadFormat(format!("upsert_artifact: {e}")))?;
        let mut method_total = 0usize;
        for cls in &classes {
            if let Ok(n) = crate::db::store_class_info(self.db, art_id, cls) {
                method_total += n;
            }
        }
        progress(&format!("Stored {} classes, {} methods", classes.len(), method_total));
        Ok(IndexSummary {
            artifact: key, status: "indexed".into(),
            classes: classes.len(), methods: method_total,
        })
    }

    /// Index every `classes*.dex` inside an APK as one artifact —
    /// `local:<apk-name>:<file-mtime>`. Same idempotent short-circuit
    /// as `index_dex`.
    pub fn index_apk(
        &self, path: &Path, progress: ProgressFn<'_>,
    ) -> Result<IndexSummary, ResolverError> {
        let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("app").to_string();
        let version = synthetic_version(path);
        let key = format!("local:{stem}:{version}");
        progress(&format!("Indexing apk: {}", path.display()));

        if self.db.get_artifact("local", &stem, &version)
            .map_err(|e| ResolverError::BadFormat(format!("db: {e}")))?.is_some()
        {
            progress(&format!("Already indexed: {key}"));
            return Ok(IndexSummary { artifact: key, status: "already_indexed".into(), classes: 0, methods: 0 });
        }

        let classes = crate::bytecode_dex::classes_from_apk(path);
        progress(&format!("Extracted {} classes across all dex files", classes.len()));

        let art_id = self.db.upsert_artifact("local", &stem, &version, "apk", "local_apk")
            .map_err(|e| ResolverError::BadFormat(format!("upsert_artifact: {e}")))?;
        let mut method_total = 0usize;
        for cls in &classes {
            if let Ok(n) = crate::db::store_class_info(self.db, art_id, cls) {
                method_total += n;
            }
        }
        progress(&format!("Stored {} classes, {} methods", classes.len(), method_total));
        Ok(IndexSummary {
            artifact: key, status: "indexed".into(),
            classes: classes.len(), methods: method_total,
        })
    }

    // ── Internal ──────────────────────────────────────────────────────────

    fn index_resolved(
        &self, artifact: &ResolvedArtifact, progress: ProgressFn<'_>,
    ) -> Result<IndexSummary, ResolverError> {
        let key = format!("{}:{}:{}", artifact.group_id, artifact.artifact_id, artifact.version);
        let existing = self.db.get_artifact(&artifact.group_id, &artifact.artifact_id, &artifact.version)
            .map_err(|e| ResolverError::BadFormat(format!("db: {e}")))?;
        if existing.is_some() {
            progress(&format!("Already indexed: {}", key));
            return Ok(IndexSummary { artifact: key, status: "already_indexed".into(), classes: 0, methods: 0 });
        }

        let classes: Vec<ClassInfo> = match artifact.packaging.as_str() {
            "aar" => bytecode::extract_classes_from_aar(&artifact.local_path),
            _     => bytecode::extract_classes_from_jar(&artifact.local_path),
        };
        progress(&format!("Extracted {} classes", classes.len()));

        let art_id = self.db.upsert_artifact(
            &artifact.group_id, &artifact.artifact_id, &artifact.version,
            &artifact.packaging, &artifact.source,
        ).map_err(|e| ResolverError::BadFormat(format!("upsert_artifact: {e}")))?;

        let mut method_total: usize = 0;
        for cls in &classes {
            match db::store_class_info(self.db, art_id, cls) {
                Ok(n)  => method_total += n,
                Err(_) => { /* keep going — one bad class shouldn't fail the batch */ }
            }
        }
        progress(&format!("Stored {} classes, {} methods", classes.len(), method_total));

        Ok(IndexSummary {
            artifact: key, status: "indexed".into(),
            classes: classes.len(), methods: method_total,
        })
    }
}
