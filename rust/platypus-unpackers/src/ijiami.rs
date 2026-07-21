//! Ijiami (爱加密) backend — scaffold.
//!
//! Direct port of `unpacker/packer_backends/ijiami.py`. No Ijiami
//! samples in this engagement's corpus; we only carve loader SOs +
//! data assets and flag the inner DEX as unrecoverable (the cipher is
//! XOR+AES with runtime-derived material, similar to Jiagu).

use std::path::Path;

use regex::Regex;

use crate::common::{
    carve_all_dexs, carve_entries, extract_base_apk_if_xapk, read_manifest_strings,
    write_manifest, write_unrecovered, Manifest, Stage, Unrecovered,
};
use crate::{opts_as_json, Backend, RunOptions, RunResult};

pub struct Ijiami;

const PACKER_NAME: &str = "ijiami";

impl Backend for Ijiami {
    fn name() -> &'static str {
        PACKER_NAME
    }

    fn run(input_path: &Path, out_dir: &Path, opts: &RunOptions) -> RunResult {
        std::fs::create_dir_all(out_dir)?;
        let apk_path = extract_base_apk_if_xapk(input_path, &out_dir.join("xapk"))?;
        let extracted_dir = out_dir.join("extracted");
        std::fs::create_dir_all(&extracted_dir)?;

        let loader_re = Regex::new(
            r"lib/[^/]+/(libsecmain|libsecexe|libexec|libexecmain|libsmainso)\.so$",
        )
        .unwrap();
        let dat_re = Regex::new(r"assets/(ijiami\.dat|ijiami\.ajm|ijm_lib/.+)$").unwrap();

        let bytes = std::fs::read(&apk_path)?;
        let mut zf = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;

        let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
        let manifest_strs = read_manifest_strings(&mut zf);

        let loaders: Vec<String> =
            names.iter().filter(|n| loader_re.is_match(n)).cloned().collect();
        let dats: Vec<String> =
            names.iter().filter(|n| dat_re.is_match(n)).cloned().collect();
        let stub_present = manifest_strs.iter().any(|s| {
            matches!(
                s.as_str(),
                "com.shell.NativeApplication"
                    | "com.shell.NativeApplicationE"
                    | "cn.securitystack.stss.NativeApplication"
            )
        });

        let mut stages: Vec<Stage> = Vec::new();
        let mut recovered = Vec::new();
        let mut unrecovered: Vec<Unrecovered> = Vec::new();
        let mut notes = serde_json::Map::new();

        let any_marker = !loaders.is_empty() || !dats.is_empty() || stub_present;
        stages.push(Stage::new(
            "verify_markers",
            any_marker,
            format!(
                "loaders={} dats={} stub={}",
                loaders.len(),
                dats.len(),
                stub_present
            ),
        ));
        let mut marker_map = serde_json::Map::new();
        marker_map.insert(
            "loaders".into(),
            serde_json::Value::Array(loaders.iter().map(|s| serde_json::Value::String(s.clone())).collect()),
        );
        marker_map.insert(
            "dats".into(),
            serde_json::Value::Array(dats.iter().map(|s| serde_json::Value::String(s.clone())).collect()),
        );
        marker_map.insert("stub_present".into(), serde_json::Value::Bool(stub_present));
        notes.insert("markers".into(), serde_json::Value::Object(marker_map));

        let mut dex_recs = carve_all_dexs(&mut zf, out_dir)?;
        for r in &mut dex_recs {
            r.ok = r.valid_dex_magic;
            r.recovery = "verbatim copy of outer stub DEX (Ijiami Java shell)".into();
        }
        let dex_count = dex_recs.len();
        recovered.extend(dex_recs);
        stages.push(Stage::new(
            "carve_outer_stub_dex",
            dex_count > 0,
            format!("{} stub DEX file(s) copied", dex_count),
        ));

        let mut carve_targets = loaders.clone();
        carve_targets.extend(dats.clone());
        let carved = carve_entries(&mut zf, &carve_targets, &extracted_dir)?;
        stages.push(Stage::new(
            "carve_ijiami_assets",
            !carved.is_empty(),
            format!("{} file(s) carved to extracted/", carved.len()),
        ));
        notes.insert(
            "carved_artefacts".into(),
            serde_json::to_value(&carved).unwrap_or(serde_json::Value::Null),
        );

        unrecovered.push(Unrecovered {
            item: "inner classes.dex (real app DEX)".into(),
            reason: "Ijiami's loader (libsecmain/libsecexe/libexecmain) derives \
                     the XOR/AES key set from per-build constants and the \
                     encrypted blob ijiami.dat at runtime. Static recovery not \
                     implemented in this engagement; backend reports the artefacts \
                     carved out for analyst follow-up."
                .into(),
        });
        stages.push(Stage::new(
            "inner_dex_decryption",
            false,
            "flagged unrecoverable — runtime key derivation",
        ));

        let manifest = Manifest {
            packer: PACKER_NAME.into(),
            backend: "platypus_unpackers::ijiami".into(),
            input: std::fs::canonicalize(input_path)
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| input_path.to_string_lossy().into_owned()),
            out_dir: out_dir
                .canonicalize()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|_| out_dir.to_string_lossy().into_owned()),
            options: opts_as_json(opts),
            stages,
            recovered_dexs: recovered,
            unrecovered: unrecovered.clone(),
            notes,
            detection: serde_json::Value::Null,
            elapsed_sec: None,
            scaffold_note: Some(
                "no Ijiami samples in this engagement's corpus; scaffold only".into(),
            ),
        };
        write_manifest(out_dir, &manifest)?;
        write_unrecovered(out_dir, &unrecovered, PACKER_NAME)?;
        Ok(manifest)
    }
}
