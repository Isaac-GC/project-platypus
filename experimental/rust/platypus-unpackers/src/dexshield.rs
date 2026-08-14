//! DexShield (libDexHelper) backend — scaffold.
//!
//! Direct port of `unpacker/packer_backends/dexshield.py`. No DexShield
//! samples were observed in this engagement's corpus, so the backend
//! only carves the loader SO + outer stub DEX and flags the inner DEX
//! as unrecoverable. A real backend would need a libDexHelper-specific
//! lifter.

use std::path::Path;

use regex::Regex;

use crate::common::{
    self, carve_all_dexs, carve_entries, extract_base_apk_if_xapk, write_manifest,
    write_unrecovered, Manifest, Stage, Unrecovered,
};
use crate::{opts_as_json, Backend, RunOptions, RunResult};

pub struct Dexshield;

const PACKER_NAME: &str = "dexshield";

impl Backend for Dexshield {
    fn name() -> &'static str {
        PACKER_NAME
    }

    fn run(input_path: &Path, out_dir: &Path, opts: &RunOptions) -> RunResult {
        std::fs::create_dir_all(out_dir)?;
        let apk_path = extract_base_apk_if_xapk(input_path, &out_dir.join("xapk"))?;
        let extracted_dir = out_dir.join("extracted");
        std::fs::create_dir_all(&extracted_dir)?;

        let mut stages: Vec<Stage> = Vec::new();
        let mut recovered = Vec::new();
        let mut unrecovered: Vec<Unrecovered> = Vec::new();
        let mut notes = serde_json::Map::new();

        let dexhelper_re = Regex::new(r"lib/[^/]+/libDexHelper(-x86)?\.so$").unwrap();
        let bytes = std::fs::read(&apk_path)?;
        let mut zf = zip::ZipArchive::new(std::io::Cursor::new(bytes))?;

        let names: Vec<String> = zf.file_names().map(|s| s.to_string()).collect();
        let helpers: Vec<String> = names
            .iter()
            .filter(|n| dexhelper_re.is_match(n))
            .cloned()
            .collect();
        stages.push(Stage::new(
            "verify_markers",
            !helpers.is_empty(),
            format!("libDexHelper={}", helpers.len()),
        ));
        let mut marker_map = serde_json::Map::new();
        marker_map.insert(
            "libDexHelper".into(),
            serde_json::Value::Array(helpers.iter().map(|s| serde_json::Value::String(s.clone())).collect()),
        );
        notes.insert("markers".into(), serde_json::Value::Object(marker_map));

        let mut dex_recs = carve_all_dexs(&mut zf, out_dir)?;
        for r in &mut dex_recs {
            r.ok = r.valid_dex_magic;
            r.recovery = "verbatim copy of outer stub DEX (DexShield Java shell)".into();
        }
        let dex_count = dex_recs.len();
        recovered.extend(dex_recs);
        stages.push(Stage::new(
            "carve_outer_stub_dex",
            dex_count > 0,
            format!("{} stub DEX file(s) copied", dex_count),
        ));

        let carved = carve_entries(&mut zf, &helpers, &extracted_dir)?;
        stages.push(Stage::new(
            "carve_dexshield_assets",
            !carved.is_empty(),
            format!(
                "{} file(s) carved to {}/",
                carved.len(),
                extracted_dir.file_name().and_then(|s| s.to_str()).unwrap_or("extracted")
            ),
        ));
        notes.insert(
            "carved_artefacts".into(),
            serde_json::to_value(&carved).unwrap_or(serde_json::Value::Null),
        );

        unrecovered.push(Unrecovered {
            item: "inner classes.dex (real app DEX)".into(),
            reason: "DexShield hides DEX bytecode inside libDexHelper's data \
                     sections with per-method indirection. Static recovery \
                     requires a DexHelper-specific lifter and is not implemented \
                     in this engagement (no DexShield samples in scope)."
                .into(),
        });
        stages.push(Stage::new(
            "inner_dex_decryption",
            false,
            "flagged unrecoverable — DEX hidden inside DexHelper data sections",
        ));

        let manifest = Manifest {
            packer: PACKER_NAME.into(),
            backend: "platypus_unpackers::dexshield".into(),
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
                "no DexShield samples in this engagement's corpus; scaffold only".into(),
            ),
        };
        write_manifest(out_dir, &manifest)?;
        write_unrecovered(out_dir, &unrecovered, PACKER_NAME)?;
        // Suppress unused-import warning when `common::` is otherwise only used
        // for `RecoveredDex`'s indirect access through carve_*.
        let _ = common::sha256_bytes;
        Ok(manifest)
    }
}
