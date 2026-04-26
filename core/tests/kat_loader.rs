//! Smoke test: every JSON KAT file under `tests/data/` parses as JSON.
//!
//! Guards against typos and structural breakage in the fixtures themselves.
//! Per-field validation lives in the family-specific tests that consume
//! each KAT via [`common::load_kat`].

use std::fs;
use std::path::PathBuf;

#[test]
fn every_kat_json_parses() {
    let mut data_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    data_dir.push("tests");
    data_dir.push("data");

    let mut json_files: Vec<PathBuf> = fs::read_dir(&data_dir)
        .unwrap_or_else(|e| panic!("read {}: {}", data_dir.display(), e))
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
        .collect();
    json_files.sort();

    for path in &json_files {
        let bytes = fs::read(path).unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        let _: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            panic!("KAT file {} failed to parse as JSON: {}", path.display(), e)
        });
    }
}
