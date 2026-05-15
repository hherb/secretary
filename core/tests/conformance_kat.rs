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
use std::collections::HashMap;
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
    vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
struct Vector {
    name: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    description: String,
    operation: Operation,
    inputs: serde_json::Value,
    #[serde(default)]
    after: Option<String>,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Operation {
    OpenVaultWithPassword,
    OpenVaultWithRecovery,
    ReadBlock,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Expected {
    Ok(OkPayload),
    Err {
        variant: String,
        #[serde(default)]
        detail_contains: Option<String>,
    },
}

#[derive(Debug, Deserialize, Default)]
struct OkPayload {
    // Open ops:
    #[serde(default)]
    display_name: Option<String>,
    #[serde(default)]
    block_count: Option<u64>,
    #[serde(default)]
    block_uuid_hex: Option<String>,
    // read_block records:
    #[serde(default)]
    records: Option<Vec<ExpectedRecord>>,
}

#[derive(Debug, Deserialize)]
struct ExpectedRecord {
    record_uuid_hex: String,
    record_type: String,
    tags: Vec<String>,
    fields: Vec<ExpectedField>,
}

#[derive(Debug, Deserialize)]
struct ExpectedField {
    name: String,
    #[serde(rename = "type")]
    field_type: String, // "text" or "bytes"
    #[serde(default)]
    value_utf8: Option<String>,
    #[serde(default)]
    value_hex: Option<String>,
}

// ---------------------------------------------------------------------------
// Input-resolution helpers
// ---------------------------------------------------------------------------

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("data")
}

/// Resolves a `*_source` style input (e.g. `golden_vault_001_inputs.json:password`)
/// to its concrete bytes. Returns the UTF-8 bytes of the named JSON string field.
fn resolve_source(source: &str) -> Vec<u8> {
    let (file, field) = source
        .split_once(':')
        .unwrap_or_else(|| panic!("malformed source ref: {source}"));
    let path = fixtures_dir().join(file);
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()));
    let json: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("failed to parse {}: {e}", path.display()));
    let value = json
        .get(field)
        .unwrap_or_else(|| panic!("field '{field}' missing in {}", path.display()));
    value
        .as_str()
        .unwrap_or_else(|| panic!("field '{field}' in {} is not a string", path.display()))
        .as_bytes()
        .to_vec()
}

fn resolve_vault_dir(inputs: &serde_json::Value) -> PathBuf {
    if let Some(s) = inputs.get("vault_dir").and_then(|v| v.as_str()) {
        return fixtures_dir().join(s);
    }
    if let Some(s) = inputs.get("vault_dir_literal").and_then(|v| v.as_str()) {
        return PathBuf::from(s);
    }
    panic!(
        "inputs must carry one of vault_dir / vault_dir_literal: {}",
        inputs
    );
}

fn resolve_password(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("password_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("password_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_password vector missing password_* input");
}

fn resolve_mnemonic(inputs: &serde_json::Value) -> Vec<u8> {
    if let Some(s) = inputs.get("mnemonic_source").and_then(|v| v.as_str()) {
        return resolve_source(s);
    }
    if let Some(s) = inputs.get("mnemonic_literal_utf8").and_then(|v| v.as_str()) {
        return s.as_bytes().to_vec();
    }
    panic!("open_vault_with_recovery vector missing mnemonic_* input");
}

// ---------------------------------------------------------------------------
// Error → variant-name mapping
// ---------------------------------------------------------------------------

fn variant_name_vault(e: &secretary_ffi_bridge::error::FfiVaultError) -> &'static str {
    use secretary_ffi_bridge::error::FfiVaultError as E;
    match e {
        E::WrongPasswordOrCorrupt => "WrongPasswordOrCorrupt",
        E::WrongMnemonicOrCorrupt => "WrongMnemonicOrCorrupt",
        E::InvalidMnemonic { .. } => "InvalidMnemonic",
        E::VaultMismatch => "VaultMismatch",
        E::CorruptVault { .. } => "CorruptVault",
        E::FolderInvalid { .. } => "FolderInvalid",
        E::BlockNotFound { .. } => "BlockNotFound",
        E::SaveCryptoFailure { .. } => "SaveCryptoFailure",
        E::NotAuthor { .. } => "NotAuthor",
        E::RecipientAlreadyPresent => "RecipientAlreadyPresent",
        E::MissingRecipientCard { .. } => "MissingRecipientCard",
        E::CardDecodeFailure { .. } => "CardDecodeFailure",
        E::BlockUuidAlreadyLive { .. } => "BlockUuidAlreadyLive",
        E::BlockNotInTrash { .. } => "BlockNotInTrash",
    }
}

fn vault_error_detail(e: &secretary_ffi_bridge::error::FfiVaultError) -> Option<&str> {
    use secretary_ffi_bridge::error::FfiVaultError as E;
    match e {
        E::InvalidMnemonic { detail } => Some(detail.as_str()),
        E::CorruptVault { detail } => Some(detail.as_str()),
        E::FolderInvalid { detail } => Some(detail.as_str()),
        E::SaveCryptoFailure { detail } => Some(detail.as_str()),
        E::CardDecodeFailure { detail } => Some(detail.as_str()),
        E::BlockUuidAlreadyLive { detail } => Some(detail.as_str()),
        E::BlockNotInTrash { detail } => Some(detail.as_str()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Vector execution dispatch
// ---------------------------------------------------------------------------

fn run_open_password(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let password = resolve_password(inputs);
    secretary_ffi_bridge::vault::open_vault_with_password(&vault_dir, &password)
}

fn run_open_recovery(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let mnemonic = resolve_mnemonic(inputs);
    secretary_ffi_bridge::vault::open_vault_with_recovery(&vault_dir, &mnemonic)
}

fn assert_open_ok(
    label: &str,
    output: &secretary_ffi_bridge::vault::OpenVaultOutput,
    expected: &OkPayload,
) {
    if let Some(name) = &expected.display_name {
        assert_eq!(
            &output.identity.display_name(),
            name,
            "{label}: display_name mismatch"
        );
    }
    if let Some(count) = expected.block_count {
        assert_eq!(
            output.manifest.block_count(),
            count,
            "{label}: block_count mismatch"
        );
    }
    if let Some(hex_str) = &expected.block_uuid_hex {
        // Validate format up front; decode result discarded — we compare lowercase
        // hex strings, which is what hex::encode emits.
        hex::decode(hex_str).expect("block_uuid_hex must be valid hex");
        let summaries = output.manifest.block_summaries();
        assert!(
            !summaries.is_empty(),
            "{label}: manifest has no blocks but block_uuid_hex was pinned"
        );
        let actual_hex = hex::encode(summaries[0].block_uuid);
        assert_eq!(
            actual_hex,
            hex_str.to_lowercase(),
            "{label}: block_uuid mismatch"
        );
    }
}

fn assert_err(label: &str, actual_variant: &str, actual_detail: Option<&str>, expected: &Expected) {
    let Expected::Err {
        variant,
        detail_contains,
    } = expected
    else {
        panic!("{label}: assert_err called but vector.expected is Ok — programmer error in caller");
    };
    assert_eq!(actual_variant, variant, "{label}: variant mismatch");
    if let Some(needle) = detail_contains {
        let haystack = actual_detail.unwrap_or("");
        assert!(
            haystack.contains(needle.as_str()),
            "{label}: detail '{haystack}' does not contain '{needle}'"
        );
    }
}

// ---------------------------------------------------------------------------
// read_block dispatch helpers (Task 3)
// ---------------------------------------------------------------------------

/// Internal wrapper letting `run_read_block` surface either a real
/// FfiVaultError (from the bridge) OR a synthesized "InvalidArgument"
/// case-name when the input fails the wrong-length pre-check (the
/// bridge's read_block signature is &[u8; 16] so wrong-length is
/// rejected at the binding layer in production, not in core).
///
/// Task 3 synthesis: see design doc §11 + plan Task 3 Step 2 note.
#[derive(Debug)]
enum BridgeOrSyntheticErr {
    Bridge(secretary_ffi_bridge::error::FfiVaultError),
    Synthetic {
        variant: &'static str,
        #[allow(dead_code)] // surfaced via read_block_err_detail helper below.
        detail: String,
    },
}

fn run_read_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<secretary_ffi_bridge::record::BlockReadOutput, BridgeOrSyntheticErr> {
    let bytes_hex = inputs
        .get("block_uuid_hex")
        .or_else(|| inputs.get("block_uuid_bytes_hex"))
        .and_then(|v| v.as_str())
        .expect("read_block inputs need block_uuid_hex or block_uuid_bytes_hex");
    let bytes = hex::decode(bytes_hex).expect("block_uuid hex must decode");

    if bytes.len() != 16 {
        return Err(BridgeOrSyntheticErr::Synthetic {
            variant: "InvalidArgument",
            detail: format!("block_uuid must be exactly 16 bytes, got {}", bytes.len()),
        });
    }
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&bytes);
    secretary_ffi_bridge::record::read_block(&cached.identity, &cached.manifest, &uuid)
        .map_err(BridgeOrSyntheticErr::Bridge)
}

fn read_block_err_variant(e: &BridgeOrSyntheticErr) -> &str {
    match e {
        BridgeOrSyntheticErr::Bridge(b) => variant_name_vault(b),
        BridgeOrSyntheticErr::Synthetic { variant, .. } => variant,
    }
}

fn read_block_err_detail(e: &BridgeOrSyntheticErr) -> Option<&str> {
    match e {
        BridgeOrSyntheticErr::Bridge(b) => vault_error_detail(b),
        BridgeOrSyntheticErr::Synthetic { detail, .. } => Some(detail.as_str()),
    }
}

fn assert_read_block_ok(
    label: &str,
    output: &secretary_ffi_bridge::record::BlockReadOutput,
    expected: &OkPayload,
) {
    let Some(records) = &expected.records else {
        // Vector pinned only the success shape; nothing more to check.
        return;
    };
    assert_eq!(
        output.record_count(),
        records.len(),
        "{label}: record_count mismatch"
    );
    for (i, exp_rec) in records.iter().enumerate() {
        let rec = output
            .record_at(i)
            .unwrap_or_else(|| panic!("{label}: record_at({i}) returned None"));
        assert_eq!(
            hex::encode(rec.record_uuid()),
            exp_rec.record_uuid_hex,
            "{label}: records[{i}].record_uuid mismatch"
        );
        assert_eq!(
            rec.record_type(),
            exp_rec.record_type,
            "{label}: records[{i}].record_type mismatch"
        );
        assert_eq!(
            rec.tags(),
            exp_rec.tags,
            "{label}: records[{i}].tags mismatch"
        );
        assert_eq!(
            rec.field_count(),
            exp_rec.fields.len(),
            "{label}: records[{i}].field_count mismatch"
        );
        for (j, exp_field) in exp_rec.fields.iter().enumerate() {
            let field = rec
                .field_at(j)
                .unwrap_or_else(|| panic!("{label}: records[{i}].field_at({j}) None"));
            assert_eq!(
                field.name(),
                exp_field.name,
                "{label}: records[{i}].fields[{j}].name mismatch"
            );
            match exp_field.field_type.as_str() {
                "text" => {
                    assert!(
                        field.is_text(),
                        "{label}: records[{i}].fields[{j}] expected text"
                    );
                    let actual = field
                        .expose_text()
                        .unwrap_or_else(|| panic!("{label}: expose_text returned None"));
                    assert_eq!(
                        &actual,
                        exp_field
                            .value_utf8
                            .as_ref()
                            .expect("text field must pin value_utf8"),
                        "{label}: records[{i}].fields[{j}].value_utf8 mismatch"
                    );
                }
                "bytes" => {
                    assert!(
                        field.is_bytes(),
                        "{label}: records[{i}].fields[{j}] expected bytes"
                    );
                    let actual = field
                        .expose_bytes()
                        .unwrap_or_else(|| panic!("{label}: expose_bytes returned None"));
                    let expected_bytes = hex::decode(
                        exp_field
                            .value_hex
                            .as_ref()
                            .expect("bytes field must pin value_hex"),
                    )
                    .expect("value_hex must decode");
                    assert_eq!(
                        actual, expected_bytes,
                        "{label}: records[{i}].fields[{j}].value_hex mismatch"
                    );
                }
                other => panic!("{label}: unknown field type '{other}'"),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

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

    // Find the read_block_happy vector and populate its records.
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
