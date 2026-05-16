//! Per-operation dispatch + Ok-payload assertion helpers.
//!
//! `run_*` invoke the bridge crate; `assert_*` check the observable
//! output against the pinned expectation. The synthesis path in
//! `run_read_block` handles non-16-byte UUIDs at the test layer
//! because `FfiVaultError` doesn't expose an `InvalidArgument` variant
//! (that variant lives only on the uniffi-projected `VaultError`).

use super::fixtures::{resolve_mnemonic, resolve_password, resolve_vault_dir};
use super::types::{BridgeOrSyntheticErr, OkPayload};

pub fn run_open_password(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let password = resolve_password(inputs);
    secretary_ffi_bridge::vault::open_vault_with_password(&vault_dir, &password)
}

pub fn run_open_recovery(
    inputs: &serde_json::Value,
) -> Result<secretary_ffi_bridge::vault::OpenVaultOutput, secretary_ffi_bridge::error::FfiVaultError>
{
    let vault_dir = resolve_vault_dir(inputs);
    let mnemonic = resolve_mnemonic(inputs);
    secretary_ffi_bridge::vault::open_vault_with_recovery(&vault_dir, &mnemonic)
}

pub fn run_read_block(
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

pub fn assert_open_ok(
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

pub fn assert_read_block_ok(
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
