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
    // read_block: scaffold for Task 3; unused in Task 2.
    #[serde(default)]
    #[allow(dead_code)]
    records: Option<Vec<ExpectedRecord>>,
}

// Task 3 scaffold types — deserialized but not yet read by the dispatch loop.
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct ExpectedRecord {
    record_uuid_hex: String,
    record_type: String,
    tags: Vec<String>,
    fields: Vec<ExpectedField>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
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
// Tests
// ---------------------------------------------------------------------------

#[test]
fn replay_conformance_kat() {
    let raw = std::fs::read_to_string(kat_path()).expect("conformance_kat.json must be readable");
    let kat: Kat = serde_json::from_str(&raw).expect("conformance_kat.json must parse");
    assert_eq!(kat.version, 1, "KAT version must be 1");

    for vector in &kat.vectors {
        let label = &vector.name;
        if vector.after.is_some() {
            // Chained vectors land in Task 3.
            continue;
        }
        match vector.operation {
            Operation::OpenVaultWithPassword => {
                let result = run_open_password(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => assert_open_ok(label, &out, payload),
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => {
                        panic!("{label}: expected Ok, got Err {:?}", e)
                    }
                    (Expected::Err { .. }, Ok(_)) => {
                        panic!("{label}: expected Err, got Ok")
                    }
                }
            }
            Operation::OpenVaultWithRecovery => {
                let result = run_open_recovery(&vector.inputs);
                match (&vector.expected, result) {
                    (Expected::Ok(payload), Ok(out)) => assert_open_ok(label, &out, payload),
                    (Expected::Err { .. }, Err(e)) => {
                        let v = variant_name_vault(&e);
                        let d = vault_error_detail(&e);
                        assert_err(label, v, d, &vector.expected);
                    }
                    (Expected::Ok(_), Err(e)) => {
                        panic!("{label}: expected Ok, got Err {:?}", e)
                    }
                    (Expected::Err { .. }, Ok(_)) => {
                        panic!("{label}: expected Err, got Ok")
                    }
                }
            }
            Operation::ReadBlock => {
                continue; // chained — Task 3
            }
        }
    }
}
