//! SQLite-backed index. WAL mode, foreign keys, content-addressed class
//! dedup. Mirrors the Python `dexmapper.core.db` schema exactly so a
//! database produced by either implementation is interchangeable.
//!
//! The schema:
//!
//! ```text
//! artifacts(id, group, artifact, version, packaging, source, indexed_at)
//!     │
//!     ▼  many-to-many
//! artifact_classes(artifact_id, class_id)
//!     │
//!     ▼
//! class_defs(id, fingerprint UNIQUE, fqn, simple_name, package, …)
//!     │
//!     ├─▶ fields (id, class_id, name, descriptor, flags)
//!     │
//!     └─▶ methods (id, class_id, name, descriptor, return_type, param_types, flags)
//!             │
//!             ├─▶ method_fingerprints (sig_hash, struct_hash, counts)
//!             ├─▶ call_edges (caller_id, callee_id, call_type)
//!             └─▶ method_field_accesses (method_id, field_id, get|put)
//! ```
//!
//! `class_defs.fingerprint` is the content-addressed key — two library
//! versions that compile to identical method-signature sets share the
//! same `class_defs` row, with the version differences expressed only
//! through `artifact_classes` rows.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension, Row};

use crate::descriptors;

pub const SCHEMA_VERSION: i32 = 1;

const DDL: &str = "
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS artifacts (
    id            INTEGER PRIMARY KEY,
    group_id      TEXT NOT NULL,
    artifact_id   TEXT NOT NULL,
    version       TEXT NOT NULL,
    packaging     TEXT NOT NULL DEFAULT 'jar',
    source        TEXT NOT NULL,
    indexed_at    INTEGER NOT NULL,
    UNIQUE(group_id, artifact_id, version)
);

CREATE TABLE IF NOT EXISTS class_defs (
    id              INTEGER PRIMARY KEY,
    fingerprint     TEXT NOT NULL UNIQUE,
    fqn             TEXT NOT NULL,
    simple_name     TEXT NOT NULL,
    package         TEXT NOT NULL,
    is_interface    INTEGER NOT NULL DEFAULT 0,
    is_abstract     INTEGER NOT NULL DEFAULT 0,
    is_enum         INTEGER NOT NULL DEFAULT 0,
    superclass      TEXT,
    interfaces      TEXT,
    source_file     TEXT
);

CREATE TABLE IF NOT EXISTS artifact_classes (
    artifact_id  INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
    class_id     INTEGER NOT NULL REFERENCES class_defs(id) ON DELETE CASCADE,
    PRIMARY KEY (artifact_id, class_id)
);

CREATE TABLE IF NOT EXISTS fields (
    id          INTEGER PRIMARY KEY,
    class_id    INTEGER NOT NULL REFERENCES class_defs(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    descriptor  TEXT NOT NULL,
    flags       INTEGER NOT NULL DEFAULT 0,
    UNIQUE(class_id, name, descriptor)
);

CREATE TABLE IF NOT EXISTS methods (
    id              INTEGER PRIMARY KEY,
    class_id        INTEGER NOT NULL REFERENCES class_defs(id) ON DELETE CASCADE,
    name            TEXT NOT NULL,
    descriptor      TEXT NOT NULL,
    return_type     TEXT NOT NULL,
    param_types     TEXT NOT NULL,
    flags           INTEGER NOT NULL DEFAULT 0,
    UNIQUE(class_id, name, descriptor)
);

CREATE TABLE IF NOT EXISTS call_edges (
    id          INTEGER PRIMARY KEY,
    caller_id   INTEGER NOT NULL REFERENCES methods(id) ON DELETE CASCADE,
    callee_id   INTEGER NOT NULL REFERENCES methods(id) ON DELETE CASCADE,
    call_type   TEXT NOT NULL DEFAULT 'virtual',
    UNIQUE(caller_id, callee_id, call_type)
);

CREATE TABLE IF NOT EXISTS method_fingerprints (
    method_id       INTEGER PRIMARY KEY REFERENCES methods(id) ON DELETE CASCADE,
    sig_hash        TEXT NOT NULL,
    struct_hash     TEXT NOT NULL,
    param_count     INTEGER NOT NULL,
    local_count     INTEGER NOT NULL DEFAULT 0,
    invoke_count    INTEGER NOT NULL DEFAULT 0,
    field_get_count INTEGER NOT NULL DEFAULT 0,
    field_put_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS method_field_accesses (
    id          INTEGER PRIMARY KEY,
    method_id   INTEGER NOT NULL REFERENCES methods(id) ON DELETE CASCADE,
    field_id    INTEGER NOT NULL REFERENCES fields(id) ON DELETE CASCADE,
    access_type TEXT NOT NULL DEFAULT 'get',
    UNIQUE(method_id, field_id, access_type)
);

-- Lambda metadata, one row per lambda *class*. We carry the kind +
-- functional arity + capture count + a call-signature hash that
-- captures the *sorted* sequence of external method invocations made
-- by the lambda's invoke() body. The matcher can lookup-by-call-
-- signature to recover lambdas across builds even when class names
-- are entirely synthetic.
CREATE TABLE IF NOT EXISTS lambdas (
    class_id           INTEGER PRIMARY KEY REFERENCES class_defs(id) ON DELETE CASCADE,
    kind               TEXT NOT NULL,           -- kotlin_lambda | suspend_lambda | function_ref | composable_lambda | composable_singletons
    arity              INTEGER NOT NULL,
    captured           INTEGER NOT NULL,
    call_signature     TEXT NOT NULL,
    invoke_descriptor  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_artifacts_gav      ON artifacts(group_id, artifact_id, version);
CREATE INDEX IF NOT EXISTS idx_lambdas_callsig    ON lambdas(call_signature);
CREATE INDEX IF NOT EXISTS idx_lambdas_kind       ON lambdas(kind);
CREATE INDEX IF NOT EXISTS idx_class_fqn          ON class_defs(fqn);
CREATE INDEX IF NOT EXISTS idx_class_simple       ON class_defs(simple_name);
CREATE INDEX IF NOT EXISTS idx_class_fingerprint  ON class_defs(fingerprint);
CREATE INDEX IF NOT EXISTS idx_methods_class      ON methods(class_id);
CREATE INDEX IF NOT EXISTS idx_methods_name       ON methods(name);
CREATE INDEX IF NOT EXISTS idx_methods_desc       ON methods(descriptor);
CREATE INDEX IF NOT EXISTS idx_mfp_sig            ON method_fingerprints(sig_hash);
CREATE INDEX IF NOT EXISTS idx_mfp_struct         ON method_fingerprints(struct_hash);
CREATE INDEX IF NOT EXISTS idx_fields_class       ON fields(class_id);
CREATE INDEX IF NOT EXISTS idx_artifact_classes   ON artifact_classes(artifact_id, class_id);
";

// ── Row types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ArtifactRow {
    pub id: i64,
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,
    pub source: String,
    pub indexed_at: i64,
}

#[derive(Debug, Clone)]
pub struct ClassRow {
    pub id: i64,
    pub fingerprint: String,
    pub fqn: String,
    pub simple_name: String,
    pub package: String,
    pub is_interface: bool,
    pub is_abstract: bool,
    pub is_enum: bool,
    pub superclass: Option<String>,
    /// JSON-encoded `Vec<String>`.
    pub interfaces: Option<String>,
    pub source_file: Option<String>,
}

#[derive(Debug, Clone)]
pub struct FieldRow {
    pub id: i64,
    pub class_id: i64,
    pub name: String,
    pub descriptor: String,
    pub flags: i64,
}

#[derive(Debug, Clone)]
pub struct MethodRow {
    pub id: i64,
    pub class_id: i64,
    pub name: String,
    pub descriptor: String,
    pub return_type: String,
    /// JSON-encoded `Vec<String>`.
    pub param_types: String,
    pub flags: i64,
}

/// Joined row from `find_methods_by_*` — carries the parent class FQN and
/// the structural counts so the matcher can score without a second query.
#[derive(Debug, Clone)]
pub struct MethodMatchRow {
    pub id: i64,
    pub class_id: i64,
    pub class_fqn: String,
    pub name: String,
    pub descriptor: String,
    pub return_type: String,
    pub param_types: String,
    pub sig_hash: String,
    pub struct_hash: String,
    pub param_count: i64,
    pub invoke_count: i64,
    pub field_get_count: i64,
    pub field_put_count: i64,
}

#[derive(Debug, Clone)]
pub struct LambdaRow {
    pub class_id: i64,
    pub class_fqn: String,
    pub kind: String,
    pub arity: i64,
    pub captured: i64,
    pub call_signature: String,
    pub invoke_descriptor: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct DbStats {
    pub artifacts: i64,
    pub classes: i64,
    pub methods: i64,
    pub fields: i64,
    pub call_edges: i64,
    pub lambdas: i64,
}

// ── Database ──────────────────────────────────────────────────────────────

pub struct Database {
    conn: Connection,
}

impl Database {
    /// Open / create a database at `path`. Applies the schema in WAL mode.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        let conn = Connection::open(path).map_err(|e| format!("open {}: {e}", path.display()))?;
        conn.execute_batch(DDL).map_err(|e| format!("DDL: {e}"))?;
        conn.execute(
            "INSERT OR IGNORE INTO schema_meta(key, value) VALUES('version', ?1)",
            params![SCHEMA_VERSION.to_string()],
        ).map_err(|e| format!("schema_meta: {e}"))?;
        Ok(Self { conn })
    }

    /// In-memory database — useful for tests and ephemeral indexing.
    pub fn in_memory() -> Result<Self, String> {
        let conn = Connection::open_in_memory().map_err(|e| format!("memdb: {e}"))?;
        conn.execute_batch(DDL).map_err(|e| format!("DDL: {e}"))?;
        Ok(Self { conn })
    }

    pub fn conn(&self) -> &Connection { &self.conn }

    // ── Artifact CRUD ─────────────────────────────────────────────────────

    pub fn upsert_artifact(&self, group_id: &str, artifact_id: &str, version: &str,
                            packaging: &str, source: &str) -> Result<i64, String> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64).unwrap_or(0);
        self.conn.execute(
            "INSERT INTO artifacts(group_id,artifact_id,version,packaging,source,indexed_at)
             VALUES (?1,?2,?3,?4,?5,?6)
             ON CONFLICT(group_id,artifact_id,version) DO UPDATE SET
               packaging=excluded.packaging,
               source=excluded.source,
               indexed_at=excluded.indexed_at",
            params![group_id, artifact_id, version, packaging, source, ts],
        ).map_err(|e| format!("upsert_artifact: {e}"))?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM artifacts WHERE group_id=?1 AND artifact_id=?2 AND version=?3",
            params![group_id, artifact_id, version],
            |r| r.get(0),
        ).map_err(|e| format!("upsert_artifact lookup: {e}"))?;
        Ok(id)
    }

    pub fn get_artifact(&self, group_id: &str, artifact_id: &str, version: &str)
        -> Result<Option<ArtifactRow>, String>
    {
        self.conn.query_row(
            "SELECT id, group_id, artifact_id, version, packaging, source, indexed_at
             FROM artifacts WHERE group_id=?1 AND artifact_id=?2 AND version=?3",
            params![group_id, artifact_id, version],
            row_to_artifact,
        ).optional().map_err(|e| format!("get_artifact: {e}"))
    }

    pub fn list_artifacts(&self) -> Result<Vec<ArtifactRow>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, group_id, artifact_id, version, packaging, source, indexed_at
             FROM artifacts ORDER BY group_id, artifact_id, version"
        ).map_err(|e| format!("list_artifacts prep: {e}"))?;
        let mapped = stmt.query_map([], row_to_artifact)
            .map_err(|e| format!("list_artifacts query: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("list_artifacts row: {e}"))
    }

    // ── Class CRUD ────────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_class(
        &self, fingerprint: &str, fqn: &str, simple_name: &str, package: &str,
        is_interface: bool, is_abstract: bool, is_enum: bool,
        superclass: Option<&str>, interfaces: Option<&[String]>,
        source_file: Option<&str>,
    ) -> Result<i64, String> {
        let ifaces_json = serde_json::to_string(interfaces.unwrap_or(&[])).unwrap_or_else(|_| "[]".into());
        self.conn.execute(
            "INSERT INTO class_defs(fingerprint,fqn,simple_name,package,
                                     is_interface,is_abstract,is_enum,superclass,interfaces,source_file)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)
             ON CONFLICT(fingerprint) DO NOTHING",
            params![fingerprint, fqn, simple_name, package,
                    is_interface as i32, is_abstract as i32, is_enum as i32,
                    superclass, ifaces_json, source_file],
        ).map_err(|e| format!("upsert_class: {e}"))?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM class_defs WHERE fingerprint=?1",
            params![fingerprint],
            |r| r.get(0),
        ).map_err(|e| format!("upsert_class lookup: {e}"))?;
        Ok(id)
    }

    pub fn link_artifact_class(&self, artifact_id: i64, class_id: i64) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR IGNORE INTO artifact_classes(artifact_id, class_id) VALUES (?1, ?2)",
            params![artifact_id, class_id],
        ).map_err(|e| format!("link_artifact_class: {e}"))?;
        Ok(())
    }

    pub fn get_class_by_fqn(&self, fqn: &str) -> Result<Option<ClassRow>, String> {
        self.conn.query_row(
            "SELECT id, fingerprint, fqn, simple_name, package, is_interface, is_abstract,
                    is_enum, superclass, interfaces, source_file
             FROM class_defs WHERE fqn=?1",
            params![fqn], row_to_class,
        ).optional().map_err(|e| format!("get_class_by_fqn: {e}"))
    }

    pub fn get_class_by_fingerprint(&self, fp: &str) -> Result<Option<ClassRow>, String> {
        self.conn.query_row(
            "SELECT id, fingerprint, fqn, simple_name, package, is_interface, is_abstract,
                    is_enum, superclass, interfaces, source_file
             FROM class_defs WHERE fingerprint=?1",
            params![fp], row_to_class,
        ).optional().map_err(|e| format!("get_class_by_fingerprint: {e}"))
    }

    pub fn get_classes_by_simple_name(&self, name: &str) -> Result<Vec<ClassRow>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, fingerprint, fqn, simple_name, package, is_interface, is_abstract,
                    is_enum, superclass, interfaces, source_file
             FROM class_defs WHERE simple_name=?1"
        ).map_err(|e| format!("get_classes_by_simple_name prep: {e}"))?;
        let mapped = stmt.query_map(params![name], row_to_class)
            .map_err(|e| format!("query: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("row: {e}"))
    }

    pub fn classes_with_method_count_between(&self, lo: i64, hi: i64, limit: i64)
        -> Result<Vec<ClassRow>, String>
    {
        let mut stmt = self.conn.prepare(
            "SELECT cd.id, cd.fingerprint, cd.fqn, cd.simple_name, cd.package, cd.is_interface,
                    cd.is_abstract, cd.is_enum, cd.superclass, cd.interfaces, cd.source_file
             FROM class_defs cd
             WHERE (SELECT COUNT(*) FROM methods WHERE class_id=cd.id) BETWEEN ?1 AND ?2
             LIMIT ?3"
        ).map_err(|e| format!("prep: {e}"))?;
        let mapped = stmt.query_map(params![lo, hi, limit], row_to_class)
            .map_err(|e| format!("q: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("r: {e}"))
    }

    // ── Field CRUD ────────────────────────────────────────────────────────

    pub fn upsert_field(&self, class_id: i64, name: &str, descriptor: &str, flags: i64)
        -> Result<i64, String>
    {
        self.conn.execute(
            "INSERT INTO fields(class_id, name, descriptor, flags) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(class_id, name, descriptor) DO NOTHING",
            params![class_id, name, descriptor, flags],
        ).map_err(|e| format!("upsert_field: {e}"))?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM fields WHERE class_id=?1 AND name=?2 AND descriptor=?3",
            params![class_id, name, descriptor],
            |r| r.get(0),
        ).map_err(|e| format!("upsert_field lookup: {e}"))?;
        Ok(id)
    }

    pub fn get_fields_for_class(&self, class_id: i64) -> Result<Vec<FieldRow>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, class_id, name, descriptor, flags FROM fields WHERE class_id=?1 ORDER BY name"
        ).map_err(|e| format!("prep: {e}"))?;
        let mapped = stmt.query_map(params![class_id], |r| Ok(FieldRow {
            id: r.get(0)?, class_id: r.get(1)?, name: r.get(2)?,
            descriptor: r.get(3)?, flags: r.get(4)?,
        })).map_err(|e| format!("q: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("r: {e}"))
    }

    // ── Method CRUD ───────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_method(
        &self, class_id: i64, name: &str, descriptor: &str,
        return_type: &str, param_types: &[String], flags: i64,
    ) -> Result<i64, String> {
        let pjson = serde_json::to_string(param_types).unwrap_or_else(|_| "[]".into());
        self.conn.execute(
            "INSERT INTO methods(class_id, name, descriptor, return_type, param_types, flags)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(class_id, name, descriptor) DO NOTHING",
            params![class_id, name, descriptor, return_type, pjson, flags],
        ).map_err(|e| format!("upsert_method: {e}"))?;
        let id: i64 = self.conn.query_row(
            "SELECT id FROM methods WHERE class_id=?1 AND name=?2 AND descriptor=?3",
            params![class_id, name, descriptor],
            |r| r.get(0),
        ).map_err(|e| format!("upsert_method lookup: {e}"))?;
        Ok(id)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn upsert_method_fingerprint(
        &self, method_id: i64, sig_hash: &str, struct_hash: &str,
        param_count: i64, local_count: i64,
        invoke_count: i64, field_get_count: i64, field_put_count: i64,
    ) -> Result<(), String> {
        self.conn.execute(
            "INSERT INTO method_fingerprints
                (method_id, sig_hash, struct_hash, param_count, local_count,
                 invoke_count, field_get_count, field_put_count)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(method_id) DO UPDATE SET
               sig_hash=excluded.sig_hash,
               struct_hash=excluded.struct_hash,
               param_count=excluded.param_count,
               local_count=excluded.local_count,
               invoke_count=excluded.invoke_count,
               field_get_count=excluded.field_get_count,
               field_put_count=excluded.field_put_count",
            params![method_id, sig_hash, struct_hash, param_count, local_count,
                    invoke_count, field_get_count, field_put_count],
        ).map_err(|e| format!("upsert_mfp: {e}"))?;
        Ok(())
    }

    pub fn add_call_edge(&self, caller_id: i64, callee_id: i64, call_type: &str) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR IGNORE INTO call_edges(caller_id, callee_id, call_type) VALUES (?1, ?2, ?3)",
            params![caller_id, callee_id, call_type],
        ).map_err(|e| format!("add_call_edge: {e}"))?;
        Ok(())
    }

    pub fn add_field_access(&self, method_id: i64, field_id: i64, access_type: &str) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR IGNORE INTO method_field_accesses(method_id, field_id, access_type)
             VALUES (?1, ?2, ?3)",
            params![method_id, field_id, access_type],
        ).map_err(|e| format!("add_field_access: {e}"))?;
        Ok(())
    }

    pub fn get_methods_for_class(&self, class_id: i64) -> Result<Vec<MethodRow>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id, class_id, name, descriptor, return_type, param_types, flags
             FROM methods WHERE class_id=?1 ORDER BY name, descriptor"
        ).map_err(|e| format!("prep: {e}"))?;
        let mapped = stmt.query_map(params![class_id], |r| Ok(MethodRow {
            id: r.get(0)?, class_id: r.get(1)?, name: r.get(2)?,
            descriptor: r.get(3)?, return_type: r.get(4)?,
            param_types: r.get(5)?, flags: r.get(6)?,
        })).map_err(|e| format!("q: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("r: {e}"))
    }

    pub fn find_methods_by_sig_hash(&self, sig_hash: &str) -> Result<Vec<MethodMatchRow>, String> {
        self.find_methods_by_hash_col("sig_hash", sig_hash)
    }

    pub fn find_methods_by_struct_hash(&self, struct_hash: &str) -> Result<Vec<MethodMatchRow>, String> {
        self.find_methods_by_hash_col("struct_hash", struct_hash)
    }

    fn find_methods_by_hash_col(&self, col: &str, value: &str) -> Result<Vec<MethodMatchRow>, String> {
        let sql = format!(
            "SELECT m.id, m.class_id, cd.fqn, m.name, m.descriptor, m.return_type, m.param_types,
                    mfp.sig_hash, mfp.struct_hash, mfp.param_count, mfp.invoke_count,
                    mfp.field_get_count, mfp.field_put_count
             FROM method_fingerprints mfp
             JOIN methods m ON m.id = mfp.method_id
             JOIN class_defs cd ON cd.id = m.class_id
             WHERE mfp.{col}=?1"
        );
        let mut stmt = self.conn.prepare(&sql).map_err(|e| format!("prep: {e}"))?;
        let mapped = stmt.query_map(params![value], row_to_method_match)
            .map_err(|e| format!("q: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("r: {e}"))
    }

    pub fn find_methods_by_shape(&self, return_type: &str, param_count: i64, limit: i64)
        -> Result<Vec<MethodMatchRow>, String>
    {
        let mut stmt = self.conn.prepare(
            "SELECT m.id, m.class_id, cd.fqn, m.name, m.descriptor, m.return_type, m.param_types,
                    mfp.sig_hash, mfp.struct_hash, mfp.param_count, mfp.invoke_count,
                    mfp.field_get_count, mfp.field_put_count
             FROM methods m
             JOIN class_defs cd ON cd.id = m.class_id
             JOIN method_fingerprints mfp ON mfp.method_id = m.id
             WHERE m.return_type=?1 AND mfp.param_count=?2
             LIMIT ?3"
        ).map_err(|e| format!("prep: {e}"))?;
        let mapped = stmt.query_map(params![return_type, param_count, limit], row_to_method_match)
            .map_err(|e| format!("q: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("r: {e}"))
    }

    pub fn stats(&self) -> Result<DbStats, String> {
        let c = |sql: &str| -> Result<i64, String> {
            self.conn.query_row(sql, [], |r| r.get::<_, i64>(0))
                .map_err(|e| format!("count: {e}"))
        };
        Ok(DbStats {
            artifacts:  c("SELECT COUNT(*) FROM artifacts")?,
            classes:    c("SELECT COUNT(*) FROM class_defs")?,
            methods:    c("SELECT COUNT(*) FROM methods")?,
            fields:     c("SELECT COUNT(*) FROM fields")?,
            call_edges: c("SELECT COUNT(*) FROM call_edges")?,
            lambdas:    c("SELECT COUNT(*) FROM lambdas")?,
        })
    }

    // ── Lambda CRUD ───────────────────────────────────────────────────────

    /// Upsert a lambda row for a class. Idempotent — overwriting with the
    /// same call-signature is a no-op.
    pub fn upsert_lambda(
        &self, class_id: i64, kind: &str, arity: i64, captured: i64,
        call_signature: &str, invoke_descriptor: &str,
    ) -> Result<(), String> {
        self.conn.execute(
            "INSERT INTO lambdas(class_id, kind, arity, captured, call_signature, invoke_descriptor)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(class_id) DO UPDATE SET
               kind=excluded.kind, arity=excluded.arity, captured=excluded.captured,
               call_signature=excluded.call_signature, invoke_descriptor=excluded.invoke_descriptor",
            params![class_id, kind, arity, captured, call_signature, invoke_descriptor],
        ).map_err(|e| format!("upsert_lambda: {e}"))?;
        Ok(())
    }

    /// Look up indexed lambdas by call-signature. Returns rows joined with
    /// `class_defs` so the matcher can produce a real FQN immediately.
    /// `arity` filter is applied when non-negative.
    pub fn find_lambdas_by_call_signature(&self, sig: &str, arity: Option<i64>)
        -> Result<Vec<LambdaRow>, String>
    {
        let mut stmt = self.conn.prepare(
            "SELECT l.class_id, cd.fqn, l.kind, l.arity, l.captured,
                    l.call_signature, l.invoke_descriptor
             FROM lambdas l
             JOIN class_defs cd ON cd.id = l.class_id
             WHERE l.call_signature = ?1
               AND (?2 < 0 OR l.arity = ?2)"
        ).map_err(|e| format!("prep: {e}"))?;
        let arity_val: i64 = arity.unwrap_or(-1);
        let mapped = stmt.query_map(params![sig, arity_val], |r| Ok(LambdaRow {
            class_id: r.get(0)?, class_fqn: r.get(1)?,
            kind: r.get(2)?, arity: r.get(3)?, captured: r.get(4)?,
            call_signature: r.get(5)?, invoke_descriptor: r.get(6)?,
        })).map_err(|e| format!("q: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("r: {e}"))
    }

    pub fn get_lambda_for_class(&self, class_id: i64) -> Result<Option<LambdaRow>, String> {
        self.conn.query_row(
            "SELECT l.class_id, cd.fqn, l.kind, l.arity, l.captured,
                    l.call_signature, l.invoke_descriptor
             FROM lambdas l
             JOIN class_defs cd ON cd.id = l.class_id
             WHERE l.class_id = ?1",
            params![class_id],
            |r| Ok(LambdaRow {
                class_id: r.get(0)?, class_fqn: r.get(1)?,
                kind: r.get(2)?, arity: r.get(3)?, captured: r.get(4)?,
                call_signature: r.get(5)?, invoke_descriptor: r.get(6)?,
            }),
        ).optional().map_err(|e| format!("get_lambda: {e}"))
    }

    /// Stats specifically about lambda corpus.
    pub fn lambda_stats(&self) -> Result<Vec<(String, i64)>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT kind, COUNT(*) FROM lambdas GROUP BY kind ORDER BY COUNT(*) DESC"
        ).map_err(|e| format!("prep: {e}"))?;
        let mapped = stmt.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, i64>(1)?)))
            .map_err(|e| format!("q: {e}"))?;
        let rows: Result<Vec<_>, _> = mapped.collect();
        rows.map_err(|e| format!("r: {e}"))
    }
}

// ── Row → struct helpers ───────────────────────────────────────────────────

fn row_to_artifact(r: &Row<'_>) -> rusqlite::Result<ArtifactRow> {
    Ok(ArtifactRow {
        id: r.get(0)?, group_id: r.get(1)?, artifact_id: r.get(2)?,
        version: r.get(3)?, packaging: r.get(4)?, source: r.get(5)?,
        indexed_at: r.get(6)?,
    })
}

fn row_to_class(r: &Row<'_>) -> rusqlite::Result<ClassRow> {
    Ok(ClassRow {
        id: r.get(0)?, fingerprint: r.get(1)?, fqn: r.get(2)?, simple_name: r.get(3)?,
        package: r.get(4)?, is_interface: r.get::<_, i64>(5)? != 0,
        is_abstract: r.get::<_, i64>(6)? != 0, is_enum: r.get::<_, i64>(7)? != 0,
        superclass: r.get(8)?, interfaces: r.get(9)?, source_file: r.get(10)?,
    })
}

fn row_to_method_match(r: &Row<'_>) -> rusqlite::Result<MethodMatchRow> {
    Ok(MethodMatchRow {
        id: r.get(0)?, class_id: r.get(1)?, class_fqn: r.get(2)?,
        name: r.get(3)?, descriptor: r.get(4)?, return_type: r.get(5)?,
        param_types: r.get(6)?,
        sig_hash: r.get(7)?, struct_hash: r.get(8)?,
        param_count: r.get(9)?, invoke_count: r.get(10)?,
        field_get_count: r.get(11)?, field_put_count: r.get(12)?,
    })
}

/// Parse the JSON `interfaces` / `param_types` columns back into `Vec<String>`.
/// Returns an empty `Vec` on malformed JSON rather than failing — these
/// columns are produced internally and shouldn't ever be malformed, but
/// we don't want a corrupt row to take down a whole batch.
pub fn parse_string_array(json: &str) -> Vec<String> {
    serde_json::from_str(json).unwrap_or_default()
}

// ── Helper: store a fully-parsed ClassInfo into the index ──────────────────

/// Store a single [`crate::bytecode::ClassInfo`] under `artifact_id`.
/// Returns the number of methods stored. Idempotent — running twice with
/// the same input is a no-op.
///
/// Side effect: when the class classifies as a lambda (see
/// [`crate::lambda::classify_lambda`]), a row is also written to the
/// `lambdas` table so the matcher's lambda tier can find it later.
pub fn store_class_info(
    db: &Database,
    artifact_id: i64,
    cls: &crate::bytecode::ClassInfo,
) -> Result<usize, String> {
    let method_sigs: Vec<(String, String)> = cls.methods.iter()
        .map(|m| (m.name.clone(), m.descriptor.clone()))
        .collect();
    let fingerprint = descriptors::class_fingerprint(&method_sigs);

    let class_id = db.upsert_class(
        &fingerprint, &cls.fqn(), &cls.simple_name(), &cls.package(),
        cls.is_interface(), cls.is_abstract(), cls.is_enum(),
        cls.superclass.as_deref(),
        Some(&cls.interfaces),
        cls.source_file.as_deref(),
    )?;
    db.link_artifact_class(artifact_id, class_id)?;

    // Fields first — we need their ids for the field-access linkage.
    let mut field_id_map: std::collections::HashMap<(String, String), i64> =
        std::collections::HashMap::new();
    for f in &cls.fields {
        let fid = db.upsert_field(class_id, &f.name, &f.descriptor, f.flags as i64)?;
        field_id_map.insert((f.name.clone(), f.descriptor.clone()), fid);
    }

    // Methods — two passes (so call edges can resolve callee ids that
    // are forward-declared within this same class).
    let mut method_id_map: std::collections::HashMap<(String, String), i64> =
        std::collections::HashMap::new();
    for m in &cls.methods {
        let (params, ret) = descriptors::parse_method_descriptor(&m.descriptor);
        let mid = db.upsert_method(
            class_id, &m.name, &m.descriptor, &ret, &params, m.flags as i64,
        )?;
        method_id_map.insert((m.name.clone(), m.descriptor.clone()), mid);
    }

    for m in &cls.methods {
        let Some(&mid) = method_id_map.get(&(m.name.clone(), m.descriptor.clone())) else { continue; };
        let (params, ret) = descriptors::parse_method_descriptor(&m.descriptor);
        let sig_hash = descriptors::method_signature_hash(&cls.fqn(), &m.name, &m.descriptor);
        let called_sigs: Vec<String> = m.call_edges.iter()
            .map(|e| descriptors::method_signature_hash(&e.callee_class, &e.callee_name, &e.callee_descriptor))
            .collect();
        let struct_h = descriptors::structural_hash(
            params.len(), &ret,
            m.call_edges.len(), m.field_gets.len(), m.field_puts.len(),
            &called_sigs,
        );
        db.upsert_method_fingerprint(
            mid, &sig_hash, &struct_h,
            params.len() as i64, m.local_count as i64,
            m.call_edges.len() as i64, m.field_gets.len() as i64, m.field_puts.len() as i64,
        )?;

        // Call edges that resolve within this same class.
        for edge in &m.call_edges {
            if let Some(&callee_mid) = method_id_map
                .get(&(edge.callee_name.clone(), edge.callee_descriptor.clone()))
            {
                db.add_call_edge(mid, callee_mid, edge.call_type.as_str())?;
            }
        }
        for fr in &m.field_gets {
            if let Some(&fid) = field_id_map.get(&(fr.name.clone(), fr.descriptor.clone())) {
                db.add_field_access(mid, fid, "get")?;
            }
        }
        for fr in &m.field_puts {
            if let Some(&fid) = field_id_map.get(&(fr.name.clone(), fr.descriptor.clone())) {
                db.add_field_access(mid, fid, "put")?;
            }
        }
    }

    // Lambda classification — costless when the class isn't a lambda
    // (`classify_lambda` short-circuits on the superclass check).
    if let Some(sig) = crate::lambda::classify_lambda(cls) {
        db.upsert_lambda(
            class_id, sig.kind.as_str(),
            sig.arity as i64, sig.captured as i64,
            &sig.call_signature, &sig.invoke_descriptor,
        )?;
    }

    Ok(cls.methods.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_creates_clean() {
        let db = Database::in_memory().unwrap();
        let s = db.stats().unwrap();
        assert_eq!(s.artifacts, 0);
        assert_eq!(s.classes,   0);
    }

    #[test]
    fn upsert_artifact_idempotent() {
        let db = Database::in_memory().unwrap();
        let a = db.upsert_artifact("com.foo", "bar", "1.0", "jar", "maven_central").unwrap();
        let b = db.upsert_artifact("com.foo", "bar", "1.0", "jar", "maven_central").unwrap();
        assert_eq!(a, b);
        assert_eq!(db.stats().unwrap().artifacts, 1);
    }

    #[test]
    fn dedup_class_by_fingerprint() {
        let db = Database::in_memory().unwrap();
        let a1 = db.upsert_artifact("com.foo", "bar", "1.0", "jar", "maven_central").unwrap();
        let a2 = db.upsert_artifact("com.foo", "bar", "2.0", "jar", "maven_central").unwrap();
        let fp = "abc";
        let c1 = db.upsert_class(fp, "com.foo.X", "X", "com.foo",
                                 false, false, false, None, None, None).unwrap();
        let c2 = db.upsert_class(fp, "com.foo.X", "X", "com.foo",
                                 false, false, false, None, None, None).unwrap();
        assert_eq!(c1, c2);  // dedup
        db.link_artifact_class(a1, c1).unwrap();
        db.link_artifact_class(a2, c1).unwrap();
        assert_eq!(db.stats().unwrap().classes, 1);
    }
}
