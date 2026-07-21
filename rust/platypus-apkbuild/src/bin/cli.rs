//! `platypus-apkbuild` CLI.
//!
//! Four subcommands:
//!
//!   keygen   — generate a fresh self-signed RSA-2048 keypair + cert (PEM)
//!   repack   — apply file replacements/additions/deletions to an APK
//!   sign     — apply v2 (and optionally v1) signing to an APK
//!   verify   — light-weight check that an APK has the v2 signing block
//!
//! Subcommands are deliberately independent — you can repack without
//! signing (e.g. as part of a CI step that signs elsewhere) and sign
//! without repacking (e.g. signing an apk you already built).

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use platypus_apkbuild::{ApkBuilder, KeyPair};
use platypus_apkbuild::signing::{SignerConfig, sign_apk};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("platypus-apkbuild: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<(), String> {
    let sub = args.get(1).map(String::as_str).unwrap_or("");
    match sub {
        "keygen"     => cmd_keygen(&args[2..]),
        "repack"     => cmd_repack(&args[2..]),
        "sign"       => cmd_sign(&args[2..]),
        "verify"     => cmd_verify(&args[2..]),
        "-h" | "--help" | "help" | "" => { print_usage(); Ok(()) }
        other => Err(format!("unknown subcommand `{other}` — try `platypus-apkbuild --help`")),
    }
}

fn print_usage() {
    let exe = std::env::args().next().unwrap_or_else(|| "platypus-apkbuild".into());
    eprintln!("\
{exe} — repack and sign Android APKs.

USAGE:
    {exe} keygen --out-key <key.pem> --out-cert <cert.pem>
                 [--cn <subject CN>] [--years <validity>]

    {exe} repack <input.apk> <output.apk>
                 [--replace <entry>=<file>]...
                 [--add     <entry>=<file>]...
                 [--delete  <entry>]...
                 [--keep-signatures]  [--no-zipalign]

    {exe} sign <input.apk> <output.apk>
               --key <key.pem> --cert <cert.pem>
               [--schemes v2]                       (default v2; v1 is a no-op for now)

    {exe} verify <apk>
                 (lightweight: checks for the v2 signing block)

Notes:
  • `repack` strips existing META-INF/*.{{MF,SF,RSA,EC,DSA}} by default.
  • `sign` only emits v2 today. v1 needs a PKCS#7 SignedData blob, which is
    a follow-up — v2 alone makes the apk install on Android 7+.");
}

// ── keygen ─────────────────────────────────────────────────────────────────

fn cmd_keygen(args: &[String]) -> Result<(), String> {
    let mut out_key: Option<PathBuf> = None;
    let mut out_cert: Option<PathBuf> = None;
    let mut cn = "Platypus Debug Signing".to_string();
    let mut years = 30u32;

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out-key"  => out_key = Some(it.next().ok_or("--out-key needs a value")?.into()),
            "--out-cert" => out_cert = Some(it.next().ok_or("--out-cert needs a value")?.into()),
            "--cn"       => cn = it.next().ok_or("--cn needs a value")?.into(),
            "--years"    => years = it.next().ok_or("--years needs a value")?.parse()
                                       .map_err(|_| "--years must be an integer")?,
            other => return Err(format!("unexpected arg `{other}`")),
        }
    }
    let out_key = out_key.ok_or("--out-key required")?;
    let out_cert = out_cert.ok_or("--out-cert required")?;

    eprintln!("[keygen] CN={cn} years={years} → {} + {}",
              out_key.display(), out_cert.display());
    let kp = platypus_apkbuild::generate_self_signed(&cn, years)
        .map_err(|e| format!("keygen: {e}"))?;
    std::fs::write(&out_key, &kp.key_pem)
        .map_err(|e| format!("write key: {e}"))?;
    std::fs::write(&out_cert, &kp.cert_pem)
        .map_err(|e| format!("write cert: {e}"))?;
    eprintln!("[keygen] done. cert valid {years} year(s) from now.");
    Ok(())
}

// ── repack ─────────────────────────────────────────────────────────────────

fn cmd_repack(args: &[String]) -> Result<(), String> {
    if args.len() < 2 { return Err("usage: repack <input.apk> <output.apk> [flags]".into()); }
    let input  = Path::new(&args[0]);
    let output = Path::new(&args[1]);

    let mut replaces: Vec<(String, PathBuf)> = Vec::new();
    let mut adds:     Vec<(String, PathBuf)> = Vec::new();
    let mut deletes:  Vec<String>            = Vec::new();
    let mut strip_signatures = true;
    let mut zipalign = true;

    let mut it = args[2..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--replace" => replaces.push(parse_kv(it.next().ok_or("--replace needs entry=file")?)?),
            "--add"     => adds.push(    parse_kv(it.next().ok_or("--add needs entry=file")?)?),
            "--delete"  => deletes.push( it.next().ok_or("--delete needs an entry name")?.into()),
            "--keep-signatures" => strip_signatures = false,
            "--no-zipalign"     => zipalign = false,
            other => return Err(format!("unexpected arg `{other}`")),
        }
    }

    let mut builder = ApkBuilder::from_apk(input).map_err(|e| format!("open input: {e}"))?;
    if !strip_signatures { builder.keep_existing_signatures(); }
    if !zipalign         { builder.no_zipalign(); }
    for (entry, path) in &replaces {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        builder.replace(entry.clone(), bytes);
    }
    for (entry, path) in &adds {
        let bytes = std::fs::read(path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let stored = entry.starts_with("lib/") && entry.ends_with(".so");
        builder.add(entry.clone(), bytes, stored);
    }
    for entry in &deletes { builder.delete(entry.clone()); }

    let (bytes, outcome) = builder.build().map_err(|e| format!("build: {e}"))?;
    std::fs::write(output, &bytes).map_err(|e| format!("write output: {e}"))?;
    eprintln!(
        "[repack] {} → {}  ({}B; {} inherited, {} replaced, {} added, {} deleted)",
        input.display(), output.display(), bytes.len(),
        outcome.entries_inherited, outcome.entries_replaced,
        outcome.entries_added, outcome.entries_deleted,
    );
    Ok(())
}

fn parse_kv(s: &str) -> Result<(String, PathBuf), String> {
    let (k, v) = s.split_once('=')
        .ok_or_else(|| format!("expected entry=file, got `{s}`"))?;
    Ok((k.to_string(), PathBuf::from(v)))
}

// ── sign ───────────────────────────────────────────────────────────────────

fn cmd_sign(args: &[String]) -> Result<(), String> {
    if args.len() < 2 { return Err("usage: sign <input.apk> <output.apk> [flags]".into()); }
    let input  = Path::new(&args[0]);
    let output = Path::new(&args[1]);

    let mut key_path:  Option<PathBuf> = None;
    let mut cert_path: Option<PathBuf> = None;
    let mut p12_path:  Option<PathBuf> = None;
    let mut p12_pass:  Option<String>  = None;
    let mut p12_alias: Option<String>  = None;
    let mut schemes = "v2".to_string();
    let mut v4_sidecar: Option<PathBuf> = None;
    let mut it = args[2..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--key"         => key_path    = Some(it.next().ok_or("--key needs a path")?.into()),
            "--cert"        => cert_path   = Some(it.next().ok_or("--cert needs a path")?.into()),
            "--p12"         => p12_path    = Some(it.next().ok_or("--p12 needs a path")?.into()),
            "--p12-pass"    => p12_pass    = Some(it.next().ok_or("--p12-pass needs a value")?.into()),
            "--p12-alias"   => p12_alias   = Some(it.next().ok_or("--p12-alias needs a value")?.into()),
            "--schemes"     => schemes     = it.next().ok_or("--schemes needs a value")?.into(),
            "--v4-sidecar"  => v4_sidecar  = Some(it.next().ok_or("--v4-sidecar needs a path")?.into()),
            other => return Err(format!("unexpected arg `{other}`")),
        }
    }
    let key = match (p12_path, key_path, cert_path) {
        (Some(p12), _, _) => {
            let pwd = p12_pass.unwrap_or_default();
            KeyPair::from_pkcs12_file(&p12, &pwd, p12_alias.as_deref())
                .map_err(|e| format!("load p12: {e}"))?
        }
        (None, Some(k), Some(c)) => {
            KeyPair::from_pem_files(&k, &c)
                .map_err(|e| format!("load keypair: {e}"))?
        }
        _ => return Err(
            "supply either `--p12 <path> [--p12-pass <pwd>] [--p12-alias <name>]` \
             OR `--key <pem> --cert <pem>`".into()
        ),
    };
    let mut config = SignerConfig::default();
    for s in schemes.split(',') {
        match s.trim() {
            "v1" => config.v1 = true,
            "v2" => config.v2 = true,
            "v3" => config.v3 = true,
            "v4" => return Err("v4 needs --v4-sidecar <path>, not --schemes v4".into()),
            other => return Err(format!("unknown scheme `{other}` (supported: v1, v2, v3)")),
        }
    }
    config.v4_sidecar_path = v4_sidecar;
    let outcome = sign_apk(input, output, &key, config)
        .map_err(|e| format!("sign: {e}"))?;
    eprintln!(
        "[sign] {} → {}  ({}B; v1={}, v2={})",
        input.display(), output.display(), outcome.output_size,
        outcome.v1_applied, outcome.v2_applied,
    );
    Ok(())
}

// ── verify ─────────────────────────────────────────────────────────────────

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let path = args.first().ok_or("usage: verify <apk>")?;
    let bytes = std::fs::read(path).map_err(|e| format!("read: {e}"))?;
    let layout = platypus_apkbuild::zip_layout::ZipLayout::parse(&bytes)
        .map_err(|e| format!("layout: {e}"))?;
    println!("apk:           {}", path);
    println!("size:          {} bytes", bytes.len());
    println!("cd_start:      {}", layout.cd_start);
    println!("cd_size:       {}", layout.cd_size);
    println!("eocd_start:    {}", layout.eocd_start);

    const MAGIC: &[u8] = b"APK Sig Block 42";
    let cd = layout.cd_start as usize;
    if cd >= MAGIC.len() && &bytes[cd - MAGIC.len()..cd] == MAGIC {
        println!("v2 signing:    present");
    } else {
        println!("v2 signing:    NOT present");
    }
    use std::io::Cursor;
    use zip::ZipArchive;
    let zr = ZipArchive::new(Cursor::new(&bytes))
        .map_err(|e| format!("zip: {e}"))?;
    let has_v1 = zr.file_names().any(|n| {
        let u = n.to_ascii_uppercase();
        n.starts_with("META-INF/") && (u.ends_with(".RSA") || u.ends_with(".SF")
                                       || u == "META-INF/MANIFEST.MF")
    });
    println!("v1 signing:    {}", if has_v1 { "present" } else { "NOT present" });
    Ok(())
}
