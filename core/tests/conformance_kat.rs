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
//!
//! Implementation helpers live in `conformance_kat_helpers`; this
//! file is the test-fn entry surface only.

#![forbid(unsafe_code)]

mod conformance_kat_helpers;

use conformance_kat_helpers::dispatch::{
    assert_open_ok, assert_read_block_ok, run_open_password, run_open_recovery, run_read_block,
};
use conformance_kat_helpers::errors::{
    assert_err, read_block_err_detail, read_block_err_variant, variant_name_vault,
    vault_error_detail,
};
use conformance_kat_helpers::fixtures::{fixtures_dir, kat_path, resolve_source};
use conformance_kat_helpers::types::{Expected, Kat, Operation};

use std::collections::HashMap;

#[test]
fn replay_conformance_kat() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let kat: Kat = serde_json::from_str(&raw).expect("conformance_kat.json must parse");
    assert_eq!(kat.version, 1, "KAT version must be 1");

    let mut cache: HashMap<String, secretary_ffi_bridge::vault::OpenVaultOutput> = HashMap::new();

    for vector in &kat.vectors {
        let label = &vector.name;
        match (&vector.operation, &vector.after) {
            (Operation::OpenVaultWithPassword, None) => {
                let result = run_open_password(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => {
                        assert_open_ok(label, &out, payload);
                        cache.insert(label.clone(), out);
                    }
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => panic!("{label}: expected Ok, got Err {e:?}"),
                    (Expected::Err { .. }, Ok(_)) => panic!("{label}: expected Err, got Ok"),
                }
            }
            (Operation::OpenVaultWithRecovery, None) => {
                let result = run_open_recovery(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => {
                        assert_open_ok(label, &out, payload);
                        cache.insert(label.clone(), out);
                    }
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => panic!("{label}: expected Ok, got Err {e:?}"),
                    (Expected::Err { .. }, Ok(_)) => panic!("{label}: expected Err, got Ok"),
                }
            }
            (Operation::ReadBlock, Some(predecessor)) => {
                let cached = cache.get(predecessor).unwrap_or_else(|| {
                    panic!("{label}: predecessor '{predecessor}' did not produce a cacheable Ok")
                });
                let result = run_read_block(&vector.inputs, cached);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => assert_read_block_ok(label, &out, payload),
                    (Expected::Err { .. }, Err(e)) => {
                        let v = read_block_err_variant(&e);
                        let d = read_block_err_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => {
                        panic!(
                            "{label}: expected Ok, got Err {}",
                            read_block_err_variant(&e)
                        )
                    }
                    (Expected::Err { .. }, Ok(_)) => panic!("{label}: expected Err, got Ok"),
                }
            }
            (Operation::ReadBlock, None) => {
                panic!("{label}: ReadBlock vectors must specify `after:`")
            }
            (Operation::OpenVaultWithPassword | Operation::OpenVaultWithRecovery, Some(_)) => {
                panic!("{label}: open_vault_* vectors must not specify `after:`")
            }
            // v2 lifecycle ops — not yet wired in the replay loop (Tasks 7+).
            (
                Operation::OpenVaultWithPasswordWritable
                | Operation::SaveBlock
                | Operation::ShareBlock
                | Operation::TrashBlock
                | Operation::RestoreBlock,
                _,
            ) => {
                panic!("{label}: v2 lifecycle op not yet implemented in replay")
            }
        }
    }
}

/// Re-emits `core/tests/data/conformance_kat.json` with `read_block_happy`'s
/// `records[]` array populated from the bridge crate's read_block output.
///
/// Run manually only on an intentional protocol change:
///
///     cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture
///
/// The diff is human-reviewed before commit. If the diff touches anything
/// OTHER than `read_block_happy.expected.records`, that's a regression in
/// the bridge crate or a wider protocol change — investigate before
/// accepting the generated file.
#[test]
#[ignore]
fn generate_conformance_kat() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let mut kat: serde_json::Value =
        serde_json::from_str(&raw).expect("conformance_kat.json must parse");

    // Unlock golden_vault_001 once.
    let vault_dir = fixtures_dir().join("golden_vault_001");
    let password = resolve_source("golden_vault_001_inputs.json:password");
    let opened = secretary_ffi_bridge::vault::open_vault_with_password(&vault_dir, &password)
        .expect("open_vault_with_password(golden_vault_001) must succeed");

    let block_uuid_hex = "112233445566778899aabbccddeeff00";
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&hex::decode(block_uuid_hex).unwrap());
    let read = secretary_ffi_bridge::record::read_block(&opened.identity, &opened.manifest, &uuid)
        .expect("read_block(golden_vault_001 block) must succeed");

    let mut records_json = Vec::new();
    for i in 0..read.record_count() {
        let rec = read.record_at(i).expect("record_at must succeed");
        let mut fields_json = Vec::new();
        for j in 0..rec.field_count() {
            let f = rec.field_at(j).expect("field_at must succeed");
            let field_obj = if f.is_text() {
                serde_json::json!({
                    "name": f.name(),
                    "type": "text",
                    "value_utf8": f.expose_text().expect("text field must expose"),
                })
            } else {
                serde_json::json!({
                    "name": f.name(),
                    "type": "bytes",
                    "value_hex": hex::encode(f.expose_bytes().expect("bytes field must expose")),
                })
            };
            fields_json.push(field_obj);
        }
        records_json.push(serde_json::json!({
            "record_uuid_hex": hex::encode(rec.record_uuid()),
            "record_type": rec.record_type(),
            "tags": rec.tags(),
            "fields": fields_json,
        }));
    }

    let vectors = kat
        .get_mut("vectors")
        .and_then(|v| v.as_array_mut())
        .expect("vectors must be an array");
    let happy = vectors
        .iter_mut()
        .find(|v| v.get("name").and_then(|n| n.as_str()) == Some("read_block_happy"))
        .expect("read_block_happy vector must exist in the skeleton");
    happy
        .get_mut("expected")
        .and_then(|e| e.as_object_mut())
        .expect("expected must be an object")
        .insert(
            "records".to_string(),
            serde_json::Value::Array(records_json),
        );

    let pretty = serde_json::to_string_pretty(&kat).expect("KAT must reserialize") + "\n";
    std::fs::write(kat_path(), pretty).expect("KAT must be writable");
    eprintln!(
        "generate_conformance_kat: wrote {} ({} records under read_block_happy)",
        kat_path().display(),
        read.record_count()
    );
}
