//! Replays committed fuzz crash repros through their respective decoders
//! and asserts no panic. Each input lives in
//! `core/tests/data/fuzz_regressions/<target>/`. The contract is "must
//! not panic" — `Err` returns are accepted; the whole point of a fuzz
//! regression is that an attacker-supplied byte sequence must never
//! crash a process.
//!
//! See docs/superpowers/specs/2026-04-30-fuzz-harness-design.md §
//! "Regression mechanics".

use std::fs;
use std::path::PathBuf;

fn replay_dir<F: Fn(&[u8])>(target: &str, decoder: F) {
    // CARGO_MANIFEST_DIR resolves to `core/` at compile time. Anchoring on it
    // makes the test cwd-independent (cargo test sets cwd to the package root
    // by default, but explicit anchoring removes that as a hidden requirement).
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/fuzz_regressions")
        .join(target);
    for entry in fs::read_dir(&dir).expect("regression dir exists") {
        let entry = entry.expect("readable dir entry");
        let path = entry.path();
        // Skip the .gitkeep placeholder.
        if path.file_name().and_then(|s| s.to_str()) == Some(".gitkeep") {
            continue;
        }
        if !path.is_file() {
            continue;
        }
        let bytes = fs::read(&path).expect("read regression input");
        // Must not panic. Result is intentionally discarded.
        decoder(&bytes);
    }
}

#[test]
fn vault_toml_regressions_no_panic() {
    replay_dir("vault_toml", |bytes| {
        if let Ok(s) = std::str::from_utf8(bytes) {
            let _ = secretary_core::unlock::vault_toml::decode(s);
        }
    });
}

#[test]
fn record_regressions_no_panic() {
    replay_dir("record", |bytes| {
        let _ = secretary_core::vault::record::decode(bytes);
    });
}

#[test]
fn contact_card_regressions_no_panic() {
    replay_dir("contact_card", |bytes| {
        let _ = secretary_core::identity::card::ContactCard::from_canonical_cbor(bytes);
    });
}

#[test]
fn bundle_file_regressions_no_panic() {
    replay_dir("bundle_file", |bytes| {
        let _ = secretary_core::unlock::bundle_file::decode(bytes);
    });
}

#[test]
fn manifest_file_regressions_no_panic() {
    replay_dir("manifest_file", |bytes| {
        let _ = secretary_core::vault::manifest::decode_manifest_file(bytes);
    });
}

#[test]
fn block_file_regressions_no_panic() {
    replay_dir("block_file", |bytes| {
        let _ = secretary_core::vault::block::decode_block_file(bytes);
    });
}
