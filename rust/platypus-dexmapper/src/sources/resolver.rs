//! Maven artifact downloader. Mirrors `dexmapper.sources.resolver` —
//! handles version resolution (`maven-metadata.xml`), SHA-1
//! verification, AAR/JAR fallback ordering, POM dependency parsing,
//! and the local-file convenience wrapper.

use std::path::{Path, PathBuf};

pub const MAVEN_CENTRAL: &str = "https://repo1.maven.org/maven2";
pub const GOOGLE_MAVEN:  &str = "https://dl.google.com/dl/android/maven2";

pub fn default_cache_dir() -> PathBuf {
    if let Ok(env) = std::env::var("DEXMAPPER_CACHE") {
        return PathBuf::from(env);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    PathBuf::from(home).join(".dexmapper").join("cache")
}

#[derive(Debug, Clone)]
pub struct ResolvedArtifact {
    pub group_id: String,
    pub artifact_id: String,
    pub version: String,
    pub packaging: String,    // "jar" | "aar"
    pub local_path: PathBuf,
    pub source: String,       // "maven_central" | "google_maven" | "local"
}

#[derive(Debug, Clone)]
pub struct PomDependency {
    pub group: String,
    pub artifact: String,
    pub version: String,      // "LATEST" when omitted
    pub scope: String,        // "compile" | "runtime" | "test" | ...
}

/// Combined error type for everything the resolver can fail at — HTTP,
/// SHA-1 mismatch, malformed XML, missing local file.
#[derive(Debug)]
pub enum ResolverError {
    Http(String),
    Io(std::io::Error),
    NotFound(String),
    BadFormat(String),
    Sha1Mismatch { url: String, expected: String, actual: String },
}

impl std::fmt::Display for ResolverError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolverError::Http(s)         => write!(f, "{s}"),
            ResolverError::Io(e)           => write!(f, "{e}"),
            ResolverError::NotFound(s)     => write!(f, "not found: {s}"),
            ResolverError::BadFormat(s)    => write!(f, "{s}"),
            ResolverError::Sha1Mismatch { url, expected, actual } =>
                write!(f, "SHA1 mismatch for {url}: expected {expected}, got {actual}"),
        }
    }
}

impl std::error::Error for ResolverError {}

impl From<std::io::Error> for ResolverError {
    fn from(e: std::io::Error) -> Self { ResolverError::Io(e) }
}

// ── HTTP plumbing ──────────────────────────────────────────────────────────

fn user_agent() -> &'static str { "dexmapper/1.0 (platypus-dexmapper)" }

fn fetch_text(url: &str) -> Result<String, ResolverError> {
    let resp = ureq::get(url)
        .set("User-Agent", user_agent())
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => ResolverError::Http(format!("HTTP {code}: {url}")),
            ureq::Error::Transport(t)    => ResolverError::Http(format!("{url}: {t}")),
        })?;
    resp.into_string().map_err(|e| ResolverError::Http(format!("{url}: {e}")))
}

fn fetch_bytes(url: &str) -> Result<Vec<u8>, ResolverError> {
    let resp = ureq::get(url)
        .set("User-Agent", user_agent())
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, _) => ResolverError::Http(format!("HTTP {code}: {url}")),
            ureq::Error::Transport(t)    => ResolverError::Http(format!("{url}: {t}")),
        })?;
    let mut buf = Vec::new();
    resp.into_reader().read_to_end(&mut buf).map_err(ResolverError::Io)?;
    Ok(buf)
}

fn gav_path(group: &str, artifact: &str, version: &str, filename: &str) -> String {
    format!("{}/{artifact}/{version}/{filename}", group.replace('.', "/"))
}

// ── Version resolution ─────────────────────────────────────────────────────

/// Resolve the *latest* release version for `group:artifact` by reading
/// `maven-metadata.xml` from each repository in order. Returns the first
/// hit. `None` when no repo has the artifact.
pub fn resolve_latest_version(group: &str, artifact: &str, repos: Option<&[&str]>)
    -> Option<String>
{
    let repos: Vec<&str> = repos.map(|r| r.to_vec()).unwrap_or_else(|| vec![MAVEN_CENTRAL, GOOGLE_MAVEN]);
    for base in repos {
        let url = format!("{base}/{}/{artifact}/maven-metadata.xml", group.replace('.', "/"));
        let Ok(text) = fetch_text(&url) else { continue; };
        // Prefer <release> then <latest>; fall back to last <version>.
        if let Some(v) = extract_xml_text(&text, "release") { return Some(v); }
        if let Some(v) = extract_xml_text(&text, "latest")  { return Some(v); }
        if let Some(v) = extract_xml_text_last(&text, "version") { return Some(v); }
    }
    None
}

/// Return every version listed for `group:artifact` (across the first
/// repo that responds successfully).
pub fn list_versions(group: &str, artifact: &str, repos: Option<&[&str]>) -> Vec<String> {
    let repos: Vec<&str> = repos.map(|r| r.to_vec()).unwrap_or_else(|| vec![MAVEN_CENTRAL, GOOGLE_MAVEN]);
    for base in repos {
        let url = format!("{base}/{}/{artifact}/maven-metadata.xml", group.replace('.', "/"));
        let Ok(text) = fetch_text(&url) else { continue; };
        let v = extract_xml_text_all(&text, "version");
        if !v.is_empty() { return v; }
    }
    Vec::new()
}

// ── Artifact download ──────────────────────────────────────────────────────

fn try_download(
    base_url: &str, group: &str, artifact: &str, version: &str,
    packaging: &str, cache: &Path,
) -> Option<(PathBuf, String)> {
    let filename = format!("{artifact}-{version}.{packaging}");
    let url = format!("{base_url}/{}", gav_path(group, artifact, version, &filename));
    let dest = cache.join(group.replace('.', std::path::MAIN_SEPARATOR_STR))
        .join(artifact).join(version).join(&filename);

    // Best-effort SHA1 verification — failure to fetch the .sha1 is non-fatal.
    let sha1: Option<String> = fetch_text(&format!("{url}.sha1")).ok()
        .map(|s| s.split_whitespace().next().unwrap_or("").to_string())
        .filter(|s| !s.is_empty());

    if dest.exists() { /* already cached */ } else {
        if let Some(parent) = dest.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let bytes = fetch_bytes(&url).ok()?;
        if let Some(expected) = &sha1 {
            let actual = sha1_hex(&bytes);
            if actual != *expected { return None; }
        }
        std::fs::write(&dest, &bytes).ok()?;
    }
    let source = if base_url == MAVEN_CENTRAL { "maven_central" } else { "google_maven" };
    Some((dest, source.into()))
}

/// Download `group:artifact:version`. `version="LATEST"` triggers
/// `resolve_latest_version`. `packaging=None` tries both AAR and JAR.
pub fn download_artifact(
    group: &str, artifact: &str, version: &str,
    packaging: Option<&str>,
    cache_dir: Option<&Path>,
    repos: Option<&[&str]>,
) -> Result<ResolvedArtifact, ResolverError> {
    let cache = cache_dir.map(|p| p.to_path_buf()).unwrap_or_else(default_cache_dir);
    std::fs::create_dir_all(&cache)?;

    let resolved_version = if version == "LATEST" {
        resolve_latest_version(group, artifact, repos)
            .ok_or_else(|| ResolverError::NotFound(format!("latest for {group}:{artifact}")))?
    } else { version.to_string() };

    let repos: Vec<&str> = repos.map(|r| r.to_vec()).unwrap_or_else(|| vec![MAVEN_CENTRAL, GOOGLE_MAVEN]);
    let try_pkgs: Vec<&str> = match packaging { Some(p) => vec![p], None => vec!["aar", "jar"] };

    for base in &repos {
        for pkg in &try_pkgs {
            if let Some((path, source)) = try_download(base, group, artifact, &resolved_version, pkg, &cache) {
                return Ok(ResolvedArtifact {
                    group_id: group.to_string(),
                    artifact_id: artifact.to_string(),
                    version: resolved_version,
                    packaging: pkg.to_string(),
                    local_path: path, source,
                });
            }
        }
    }
    Err(ResolverError::NotFound(format!("{group}:{artifact}:{resolved_version}")))
}

/// Wrap a local file as a `ResolvedArtifact`. Used by `dexmapper index-local`.
pub fn resolve_local(path: &Path) -> Result<ResolvedArtifact, ResolverError> {
    if !path.exists() { return Err(ResolverError::NotFound(path.display().to_string())); }
    let canonical = path.canonicalize()?;
    let packaging = canonical.extension().and_then(|s| s.to_str()).unwrap_or("");
    if !matches!(packaging, "jar" | "aar") {
        return Err(ResolverError::BadFormat(format!("unsupported file type: .{packaging}")));
    }
    // Infer artifact-id / version from the filename if possible:
    //   "foo-1.2.3.jar" → artifact "foo", version "1.2.3"
    let stem = canonical.file_stem().and_then(|s| s.to_str()).unwrap_or("");
    let parts: Vec<&str> = stem.split('-').collect();
    let (artifact_id, version) = if parts.len() >= 2 {
        (parts[..parts.len() - 1].join("-"), parts[parts.len() - 1].to_string())
    } else {
        (stem.to_string(), "local".to_string())
    };
    Ok(ResolvedArtifact {
        group_id: "local".to_string(),
        artifact_id, version,
        packaging: packaging.to_string(),
        local_path: canonical,
        source: "local".to_string(),
    })
}

// ── POM resolution ─────────────────────────────────────────────────────────

/// Fetch the POM XML for a specific `group:artifact:version`. Returns
/// `None` if no repo serves it.
pub fn fetch_pom(group: &str, artifact: &str, version: &str, repos: Option<&[&str]>) -> Option<String> {
    let repos: Vec<&str> = repos.map(|r| r.to_vec()).unwrap_or_else(|| vec![MAVEN_CENTRAL, GOOGLE_MAVEN]);
    for base in repos {
        let url = format!("{base}/{}/{artifact}/{version}/{artifact}-{version}.pom",
                          group.replace('.', "/"));
        if let Ok(text) = fetch_text(&url) { return Some(text); }
    }
    None
}

/// Parse a POM XML and return the declared `<dependency>` entries.
/// Namespaced or not — we strip the namespace from each tag name before
/// matching so vanilla maven-style and DEFAULT-namespaced POMs both
/// work.
pub fn parse_pom_dependencies(pom_text: &str) -> Vec<PomDependency> {
    use quick_xml::events::Event;
    use quick_xml::Reader;

    let mut reader = Reader::from_str(pom_text);
    reader.config_mut().trim_text(true);

    let mut deps: Vec<PomDependency> = Vec::new();
    let mut buf = Vec::new();
    let mut path: Vec<String> = Vec::new();          // local-name stack
    let mut cur = PomDependency {
        group: String::new(), artifact: String::new(),
        version: String::new(), scope: String::new(),
    };
    let mut in_dep = false;
    let mut text_buf = String::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let name = local_name(e.name().as_ref());
                path.push(name.clone());
                if name == "dependency" {
                    in_dep = true;
                    cur = PomDependency {
                        group: String::new(), artifact: String::new(),
                        version: String::new(), scope: "compile".into(),
                    };
                }
                text_buf.clear();
            }
            Ok(Event::Text(t)) => {
                if in_dep {
                    text_buf.push_str(&t.unescape().unwrap_or_default());
                }
            }
            Ok(Event::End(e)) => {
                let name = local_name(e.name().as_ref());
                if in_dep {
                    match name.as_str() {
                        "groupId"    => cur.group    = text_buf.trim().to_string(),
                        "artifactId" => cur.artifact = text_buf.trim().to_string(),
                        "version"    => cur.version  = text_buf.trim().to_string(),
                        "scope"      => cur.scope    = text_buf.trim().to_string(),
                        "dependency" => {
                            in_dep = false;
                            if !cur.group.is_empty() && !cur.artifact.is_empty() {
                                let v = if cur.version.is_empty() { "LATEST".into() } else { cur.version.clone() };
                                deps.push(PomDependency {
                                    group: std::mem::take(&mut cur.group),
                                    artifact: std::mem::take(&mut cur.artifact),
                                    version: v,
                                    scope: if cur.scope.is_empty() { "compile".into() } else { std::mem::take(&mut cur.scope) },
                                });
                            }
                        }
                        _ => {}
                    }
                }
                if path.last().map(|s| s.as_str()) == Some(name.as_str()) {
                    path.pop();
                }
                text_buf.clear();
            }
            Ok(Event::Eof) => break,
            Err(_)         => break,
            _              => {}
        }
        buf.clear();
    }
    deps
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Strip `{namespace}` prefix off a tag name's bytes. quick-xml gives us
/// the namespaced form for elements inside a `<project xmlns=…>`.
fn local_name(name: &[u8]) -> String {
    let s = std::str::from_utf8(name).unwrap_or("");
    if let Some(colon) = s.find(':') { return s[colon + 1..].to_string(); }
    s.to_string()
}

fn sha1_hex(data: &[u8]) -> String {
    // Maven publishes `.sha1` siblings — we verify them against the
    // downloaded bytes. SHA-1 is vendored inline below to avoid a
    // separate `sha1` crate dep (we already pull in `sha2` for the
    // descriptor-side fingerprints).
    let h = sha1_hash(data);
    hex::encode(h)
}

/// SHA-1 — RFC 3174. Vendored inline to avoid a new dep just for one hash.
fn sha1_hash(data: &[u8]) -> [u8; 20] {
    // Padding
    let len_bits: u64 = (data.len() as u64).wrapping_mul(8);
    let mut buf = data.to_vec();
    buf.push(0x80);
    while buf.len() % 64 != 56 { buf.push(0); }
    buf.extend_from_slice(&len_bits.to_be_bytes());

    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

    for chunk in buf.chunks(64) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4 + 1], chunk[i*4 + 2], chunk[i*4 + 3]]);
        }
        for i in 16..80 {
            w[i] = (w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19  => ((b & c) | (!b & d),           0x5A827999),
                20..=39 => (b ^ c ^ d,                    0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d),  0x8F1BBCDC),
                _       => (b ^ c ^ d,                    0xCA62C1D6),
            };
            let temp = a.rotate_left(5).wrapping_add(f).wrapping_add(e).wrapping_add(k).wrapping_add(*wi);
            e = d; d = c; c = b.rotate_left(30); b = a; a = temp;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for i in 0..5 { out[i*4..i*4+4].copy_from_slice(&h[i].to_be_bytes()); }
    out
}

/// Find the first `<tag>VALUE</tag>` (namespace-agnostic) in XML text.
fn extract_xml_text(text: &str, tag: &str) -> Option<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut r = Reader::from_str(text);
    let mut buf = Vec::new();
    let mut capture = false;
    let mut value = String::new();
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if local_name(e.name().as_ref()) == tag => { capture = true; value.clear(); }
            Ok(Event::Text(t))  if capture => { value.push_str(&t.unescape().unwrap_or_default()); }
            Ok(Event::End(e))   if capture && local_name(e.name().as_ref()) == tag => {
                return Some(value.trim().to_string());
            }
            Ok(Event::Eof)      => break,
            Err(_)              => break,
            _                   => {}
        }
        buf.clear();
    }
    None
}

fn extract_xml_text_last(text: &str, tag: &str) -> Option<String> {
    extract_xml_text_all(text, tag).into_iter().last()
}

fn extract_xml_text_all(text: &str, tag: &str) -> Vec<String> {
    use quick_xml::events::Event;
    use quick_xml::Reader;
    let mut r = Reader::from_str(text);
    let mut buf = Vec::new();
    let mut out: Vec<String> = Vec::new();
    let mut capture = false;
    let mut value = String::new();
    loop {
        match r.read_event_into(&mut buf) {
            Ok(Event::Start(e)) if local_name(e.name().as_ref()) == tag => { capture = true; value.clear(); }
            Ok(Event::Text(t))  if capture => { value.push_str(&t.unescape().unwrap_or_default()); }
            Ok(Event::End(e))   if capture && local_name(e.name().as_ref()) == tag => {
                out.push(value.trim().to_string()); capture = false;
            }
            Ok(Event::Eof) => break,
            Err(_)         => break,
            _              => {}
        }
        buf.clear();
    }
    out
}

// `std::io::Read::read_to_end` — bring the trait into scope.
use std::io::Read;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vector() {
        // RFC 3174 test: SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
        let h = sha1_hex(b"abc");
        assert_eq!(h, "a9993e364706816aba3e25717850c26c9cd0d89d");
    }

    #[test]
    fn parses_pom_dependencies() {
        let pom = r#"<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>foo</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>com.squareup.okhttp3</groupId>
      <artifactId>okhttp</artifactId>
      <version>4.12.0</version>
    </dependency>
    <dependency>
      <groupId>org.jetbrains.kotlin</groupId>
      <artifactId>kotlin-stdlib</artifactId>
      <scope>compile</scope>
    </dependency>
  </dependencies>
</project>
"#;
        let deps = parse_pom_dependencies(pom);
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0].group, "com.squareup.okhttp3");
        assert_eq!(deps[0].artifact, "okhttp");
        assert_eq!(deps[0].version, "4.12.0");
        assert_eq!(deps[1].artifact, "kotlin-stdlib");
        assert_eq!(deps[1].version, "LATEST");
    }

    #[test]
    fn extracts_xml_release_tag() {
        let metadata = r#"<?xml version="1.0"?>
<metadata>
  <versioning>
    <latest>5.0.0-rc1</latest>
    <release>4.12.0</release>
    <versions>
      <version>4.10.0</version>
      <version>4.11.0</version>
      <version>4.12.0</version>
    </versions>
  </versioning>
</metadata>"#;
        assert_eq!(extract_xml_text(metadata, "release"), Some("4.12.0".into()));
        assert_eq!(extract_xml_text_last(metadata, "version"), Some("4.12.0".into()));
        assert_eq!(extract_xml_text_all(metadata, "version").len(), 3);
    }

    #[test]
    fn resolve_local_infers_gav() {
        let dir = std::env::temp_dir().join("dexmapper-test-resolve-local");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("okhttp-4.12.0.jar");
        std::fs::write(&p, b"PKfake").unwrap();
        let r = resolve_local(&p).unwrap();
        assert_eq!(r.artifact_id, "okhttp");
        assert_eq!(r.version,     "4.12.0");
        assert_eq!(r.packaging,   "jar");
        assert_eq!(r.source,      "local");
    }
}
