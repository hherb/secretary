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
    assert_open_ok, assert_post_state, assert_read_block_ok, run_open_password, run_open_recovery,
    run_open_writable, run_read_block, run_restore_block, run_save_block, run_share_block,
    run_trash_block,
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
    assert!(
        kat.version == 1 || kat.version == 2,
        "KAT version must be 1 or 2 (got {})",
        kat.version
    );

    let mut cache: HashMap<String, secretary_ffi_bridge::vault::OpenVaultOutput> = HashMap::new();
    let mut tempdirs: Vec<tempfile::TempDir> = Vec::new();
    let mut writable_vault_dirs: HashMap<String, std::path::PathBuf> = HashMap::new();

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
            (Operation::OpenVaultWithPasswordWritable, None) => {
                let result = run_open_writable(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok((out, tmp))) => {
                        assert_open_ok(label, &out, payload);
                        writable_vault_dirs.insert(label.clone(), tmp.path().to_path_buf());
                        tempdirs.push(tmp);
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
            (Operation::SaveBlock, Some(predecessor)) => {
                let cache_key = find_cache_ancestor_name(predecessor, &cache, &kat.vectors)
                    .unwrap_or_else(|| {
                        panic!("{label}: no cached ancestor along after-chain from {predecessor}")
                    });
                let cached = cache.get(&cache_key).unwrap();
                let result = run_save_block(&vector.inputs, cached);
                handle_write_op_result(label, &vector.expected, result, cached);
            }
            (Operation::ShareBlock, Some(predecessor)) => {
                let writable_dir =
                    find_writable_dir(predecessor, &writable_vault_dirs, &kat.vectors)
                        .unwrap_or_else(|| {
                            panic!(
                                "{label}: cannot find writable vault dir along after-chain from {predecessor}"
                            )
                        });
                let cache_key = find_cache_ancestor_name(predecessor, &cache, &kat.vectors)
                    .unwrap_or_else(|| {
                        panic!("{label}: no cached ancestor along after-chain from {predecessor}")
                    });
                let cached = cache.get(&cache_key).unwrap();
                let result = run_share_block(&vector.inputs, cached, &writable_dir);
                handle_write_op_result(label, &vector.expected, result, cached);
            }
            (Operation::TrashBlock, Some(predecessor)) => {
                let cache_key = find_cache_ancestor_name(predecessor, &cache, &kat.vectors)
                    .unwrap_or_else(|| {
                        panic!("{label}: no cached ancestor along after-chain from {predecessor}")
                    });
                let cached = cache.get(&cache_key).unwrap();
                let result = run_trash_block(&vector.inputs, cached);
                handle_write_op_result(label, &vector.expected, result, cached);
            }
            (Operation::RestoreBlock, Some(predecessor)) => {
                let cache_key = find_cache_ancestor_name(predecessor, &cache, &kat.vectors)
                    .unwrap_or_else(|| {
                        panic!("{label}: no cached ancestor along after-chain from {predecessor}")
                    });
                let cached = cache.get(&cache_key).unwrap();
                let result = run_restore_block(&vector.inputs, cached);
                handle_write_op_result(label, &vector.expected, result, cached);
            }
            (Operation::ReadBlock, None) => {
                panic!("{label}: ReadBlock vectors must specify `after:`")
            }
            (Operation::OpenVaultWithPassword | Operation::OpenVaultWithRecovery, Some(_)) => {
                panic!("{label}: open_vault_* vectors must not specify `after:`")
            }
            (Operation::OpenVaultWithPasswordWritable, Some(_)) => {
                panic!("{label}: open_vault_with_password_writable must not specify `after:`")
            }
            (
                Operation::SaveBlock
                | Operation::ShareBlock
                | Operation::TrashBlock
                | Operation::RestoreBlock,
                None,
            ) => {
                panic!("{label}: write-op vectors must specify `after:`")
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

    // v2 lifecycle generator: run save_block_insert_happy against a
    // writable copy of golden_vault_001 and capture the round-trip
    // read_block records. Only this one vector has a generator-filled
    // placeholder; the other 8 v2 vectors are fully hand-pinned.
    {
        // Open writable copy. Mirrors run_open_writable.
        let tmp = conformance_kat_helpers::fixtures::copy_vault_to_tempdir("golden_vault_001");
        let password = conformance_kat_helpers::fixtures::resolve_source(
            "golden_vault_001_inputs.json:password",
        );
        let out = secretary_ffi_bridge::vault::open_vault_with_password(tmp.path(), &password)
            .expect("generator: open writable vault_001");

        // Dispatch save_block_insert_happy. Hardcoded inputs match the
        // vector pinned in conformance_kat.json. Keeping these in sync
        // is a manual review responsibility — the generator regen diff
        // catches drift between the two.
        use secretary_core::crypto::secret::SecretString;
        use secretary_ffi_bridge::{BlockInput, FieldInput, FieldInputValue, RecordInput};
        let input = BlockInput {
            block_uuid: [0xABu8; 16],
            block_name: "Notes".to_string(),
            records: vec![RecordInput {
                record_uuid: [0xCDu8; 16],
                record_type: "note".to_string(),
                tags: Vec::new(),
                fields: vec![FieldInput {
                    name: "title".to_string(),
                    value: FieldInputValue::Text(SecretString::from("wifi password")),
                }],
            }],
        };
        secretary_ffi_bridge::save_block(
            &out.identity,
            &out.manifest,
            input,
            [0x07u8; 16],
            1_715_000_000_000,
        )
        .expect("generator: save_block_insert_happy");

        // Round-trip read.
        let read_out =
            secretary_ffi_bridge::record::read_block(&out.identity, &out.manifest, &[0xABu8; 16])
                .expect("generator: round-trip read_block");

        // Build the JSON array for records.
        let records_json: Vec<serde_json::Value> = (0..read_out.record_count())
            .map(|i| {
                let rec = read_out.record_at(i).unwrap();
                let fields: Vec<serde_json::Value> = (0..rec.field_count())
                    .map(|j| {
                        let f = rec.field_at(j).unwrap();
                        let (ty, value_field, value_val): (&str, &str, serde_json::Value) =
                            if f.is_text() {
                                let s = f.expose_text().unwrap();
                                ("text", "value_utf8", serde_json::Value::String(s))
                            } else {
                                let b = f.expose_bytes().unwrap();
                                (
                                    "bytes",
                                    "value_hex",
                                    serde_json::Value::String(hex::encode(b)),
                                )
                            };
                        serde_json::json!({
                            "name": f.name(),
                            "type": ty,
                            value_field: value_val,
                        })
                    })
                    .collect();
                serde_json::json!({
                    "record_uuid_hex": hex::encode(rec.record_uuid()),
                    "record_type": rec.record_type(),
                    "tags": rec.tags(),
                    "fields": fields,
                })
            })
            .collect();

        // Patch the JSON document. Find the save_block_insert_happy vector
        // and replace its read_block.records placeholder with the actual
        // round-trip output.
        let v2_target = kat["vectors"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|v| v["name"] == "save_block_insert_happy")
            .expect("save_block_insert_happy must be in conformance_kat.json before regen");
        v2_target["expected"]["post_state"]["read_block"]["records"] =
            serde_json::Value::Array(records_json);

        // Drop the tempdir explicitly to free disk space before the
        // serializer writes; not strictly necessary (TempDir drops at
        // end-of-scope) but explicit is clearer for a long generator fn.
        drop(out.identity);
        drop(out.manifest);
        drop(tmp);
    }

    let pretty = serde_json::to_string_pretty(&kat).expect("KAT must reserialize") + "\n";
    std::fs::write(kat_path(), pretty).expect("KAT must be writable");
    eprintln!(
        "generate_conformance_kat: wrote {} ({} records under read_block_happy)",
        kat_path().display(),
        read.record_count()
    );
}

/// Walk the `after:` chain from `start` back to the first vector whose
/// name appears in `writable_vault_dirs`. Returns that vector's tempdir
/// path. Returns `None` if no writable-open vector is upstream — which
/// is a vector-authoring error (every share_block needs a writable
/// vault upstream for the contact-card read).
fn find_writable_dir(
    start: &str,
    writable_vault_dirs: &HashMap<String, std::path::PathBuf>,
    vectors: &[conformance_kat_helpers::types::Vector],
) -> Option<std::path::PathBuf> {
    let mut current = start.to_string();
    // Bounded by vectors.len() — an authoring-error `after:` cycle would
    // otherwise hang CI. Panic loudly so the cycle is fixable, not silent.
    for _ in 0..=vectors.len() {
        if let Some(dir) = writable_vault_dirs.get(&current) {
            return Some(dir.clone());
        }
        let parent = vectors
            .iter()
            .find(|v| v.name == current)
            .and_then(|v| v.after.clone());
        match parent {
            Some(p) => current = p,
            None => return None,
        }
    }
    panic!("after-chain cycle detected starting at '{start}' (depth exceeded vectors.len())");
}

/// Walk the `after:` chain from `start` back to the first vector whose
/// name appears in `cache`. Returns the cache key. Used by chained
/// write ops to find the writable-open ancestor that holds the live
/// OpenVaultOutput (write ops mutate it in place via interior
/// mutability and do not re-key the cache under their own name).
fn find_cache_ancestor_name(
    start: &str,
    cache: &HashMap<String, secretary_ffi_bridge::vault::OpenVaultOutput>,
    vectors: &[conformance_kat_helpers::types::Vector],
) -> Option<String> {
    let mut current = start.to_string();
    // Cycle guard: see find_writable_dir.
    for _ in 0..=vectors.len() {
        if cache.contains_key(&current) {
            return Some(current);
        }
        let parent = vectors
            .iter()
            .find(|v| v.name == current)
            .and_then(|v| v.after.clone());
        match parent {
            Some(p) => current = p,
            None => return None,
        }
    }
    panic!("after-chain cycle detected starting at '{start}' (depth exceeded vectors.len())");
}

fn handle_write_op_result(
    label: &str,
    expected: &conformance_kat_helpers::types::Expected,
    result: Result<(), conformance_kat_helpers::types::BridgeOrSyntheticErr>,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) {
    use conformance_kat_helpers::types::Expected;
    match (expected, result) {
        (Expected::Ok(payload), Ok(())) => {
            if let Some(ps) = &payload.post_state {
                assert_post_state(label, cached, ps);
            }
        }
        (Expected::Err { .. }, Err(e)) => {
            let v = read_block_err_variant(&e);
            let d = read_block_err_detail(&e);
            assert_err(label, v, d, expected);
        }
        (Expected::Ok(_), Err(e)) => panic!(
            "{label}: expected Ok, got Err {}",
            read_block_err_variant(&e)
        ),
        (Expected::Err { .. }, Ok(())) => panic!("{label}: expected Err, got Ok"),
    }
}
