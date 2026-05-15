//! Cross-language FFI conformance KAT replay (B.6 v1 read-only path).
//!
//! Loads `core/tests/data/conformance_kat.json` and replays each
//! vector through the secretary-ffi-bridge crate, asserting the
//! observable output matches the pinned expectation. This is the
//! Rust side of a three-way contract; the Swift + Kotlin replays
//! live under `ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/`.
//!
//! Two entry points:
//!
//! - `replay_conformance_kat` — runs on every `cargo test` and
//!   gates protocol changes.
//! - `generate_conformance_kat` — `#[ignore]`-marked; runs the
//!   bridge crate against `golden_vault_001` and emits the JSON.
//!   Manually triggered on intentional protocol change; the diff
//!   is human-reviewed before commit.

#![forbid(unsafe_code)]

use serde::Deserialize;
use std::path::PathBuf;

fn kat_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
        .join("conformance_kat.json")
}

#[derive(Debug, Deserialize)]
struct Kat {
    version: u32,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    comment: String,
    #[allow(dead_code)] // scaffold field; Task 2/3 will iterate over vectors.
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    #[allow(dead_code)] // scaffold field; Task 2/3 will match on name.
    name: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    description: String,
}

#[test]
fn replay_conformance_kat_loads_kat_file() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let kat: Kat = serde_json::from_str(&raw).expect("conformance_kat.json must parse");
    assert_eq!(kat.version, 1, "KAT version must be 1");
}
