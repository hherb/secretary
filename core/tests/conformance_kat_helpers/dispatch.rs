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
    assert_read_block_records(label, output, records);
}

use super::types::ExpectedRecord;

pub fn assert_read_block_records(
    label: &str,
    output: &secretary_ffi_bridge::record::BlockReadOutput,
    records: &[ExpectedRecord],
) {
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

// ── v2 input-parsing helpers ─────────────────────────────────────────────────

use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_ffi_bridge::{BlockInput, FieldInput, FieldInputValue, RecordInput};

/// Parse a `*_hex` or `*_bytes_hex` input field into a `[u8; 16]`.
/// Returns `Err(BridgeOrSyntheticErr::Synthetic{"InvalidArgument"})`
/// for any non-16-byte input — matches the uniffi-layer
/// `uuid_from_vec` behavior so Swift/Kotlin get a real
/// VaultError.InvalidArgument while Rust gets the synthesized analogue.
fn uuid_from_inputs(
    inputs: &serde_json::Value,
    primary_field: &str,
    bytes_field: &str,
    label: &str,
) -> Result<[u8; 16], BridgeOrSyntheticErr> {
    let raw = inputs
        .get(primary_field)
        .or_else(|| inputs.get(bytes_field))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("inputs need {primary_field} or {bytes_field} (vector dispatch error)")
        });
    let bytes =
        hex::decode(raw).unwrap_or_else(|e| panic!("{label}: {primary_field} hex decode: {e}"));
    if bytes.len() != 16 {
        return Err(BridgeOrSyntheticErr::Synthetic {
            variant: "InvalidArgument",
            detail: format!("{label} must be exactly 16 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build a `BlockInput` from the JSON `inputs.records` array. Each
/// record has `record_uuid_hex` + `fields[]`; each field has `name`,
/// `type` (`"text"` or `"bytes"`), and a value (`value_utf8` or
/// `value_hex`). The bridge's `RecordInput` does not carry `record_type`
/// or `tags` (both default to empty inside `into_core_record`).
fn block_input_from_inputs(inputs: &serde_json::Value) -> BlockInput {
    let block_uuid_hex = inputs
        .get("block_uuid_hex")
        .and_then(|v| v.as_str())
        .expect("save_block inputs need block_uuid_hex");
    let block_uuid_bytes = hex::decode(block_uuid_hex).expect("block_uuid hex decode");
    assert_eq!(
        block_uuid_bytes.len(),
        16,
        "save_block.block_uuid must be 16 bytes (use save_block_invalid_input with block_uuid_bytes_hex for the wrong-length path)"
    );
    let mut block_uuid = [0u8; 16];
    block_uuid.copy_from_slice(&block_uuid_bytes);

    let block_name = inputs
        .get("block_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let records: Vec<RecordInput> = inputs
        .get("records")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|rec| {
                    let record_uuid_hex = rec
                        .get("record_uuid_hex")
                        .and_then(|v| v.as_str())
                        .expect("record needs record_uuid_hex");
                    let mut record_uuid = [0u8; 16];
                    record_uuid.copy_from_slice(
                        &hex::decode(record_uuid_hex).expect("record_uuid hex decode"),
                    );
                    let fields: Vec<FieldInput> = rec
                        .get("fields")
                        .and_then(|v| v.as_array())
                        .map(|fs| {
                            fs.iter()
                                .map(|f| {
                                    let name = f
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .expect("field needs name")
                                        .to_string();
                                    let ftype = f
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .expect("field needs type");
                                    let value = match ftype {
                                        "text" => FieldInputValue::Text(SecretString::from(
                                            f.get("value_utf8")
                                                .and_then(|v| v.as_str())
                                                .expect("text field needs value_utf8")
                                                .to_string(),
                                        )),
                                        "bytes" => FieldInputValue::Bytes(SecretBytes::from(
                                            hex::decode(
                                                f.get("value_hex")
                                                    .and_then(|v| v.as_str())
                                                    .expect("bytes field needs value_hex"),
                                            )
                                            .expect("value_hex decode"),
                                        )),
                                        other => panic!("unknown field type {other}"),
                                    };
                                    FieldInput { name, value }
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    RecordInput {
                        record_uuid,
                        fields,
                    }
                })
                .collect()
        })
        .unwrap_or_default();

    BlockInput {
        block_uuid,
        block_name,
        records,
    }
}

/// Extract `now_ms` (required for all v2 write ops).
fn now_ms_from_inputs(inputs: &serde_json::Value) -> u64 {
    inputs
        .get("now_ms")
        .and_then(|v| v.as_u64())
        .expect("v2 write-op vector needs now_ms")
}

// ── v2 run_* dispatch helpers ─────────────────────────────────────────────────

use super::fixtures::copy_vault_to_tempdir;

/// Copies the named fixture vault to a fresh tempdir, opens the copy
/// with the resolved password, and returns the open output paired with
/// the TempDir handle. The caller is responsible for holding the TempDir
/// alongside the cached OpenVaultOutput so the dir survives until replay
/// completes.
pub fn run_open_writable(
    inputs: &serde_json::Value,
) -> Result<
    (
        secretary_ffi_bridge::vault::OpenVaultOutput,
        tempfile::TempDir,
    ),
    secretary_ffi_bridge::error::FfiVaultError,
> {
    let vault_name = inputs
        .get("vault_dir")
        .and_then(|v| v.as_str())
        .expect("open_vault_with_password_writable needs vault_dir (fixture-relative)");
    let tmp = copy_vault_to_tempdir(vault_name);
    let password = super::fixtures::resolve_password(inputs);
    let out = secretary_ffi_bridge::vault::open_vault_with_password(tmp.path(), &password)?;
    Ok((out, tmp))
}

/// Dispatch save_block. Returns the BridgeOrSyntheticErr wrapper so
/// non-16-byte block_uuid / device_uuid synthesize `InvalidArgument`
/// at the test layer (matching the uniffi-layer length checks; the
/// bridge's `[u8; 16]` parameters are type-bounded so the bridge itself
/// can't surface that variant).
pub fn run_save_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<(), BridgeOrSyntheticErr> {
    // Length-check device_uuid first (uniffi checks this before
    // building the BlockInput). block_uuid is checked inside
    // block_input_from_inputs via uuid_from_inputs if we go through
    // the bytes_hex path; the happy-path uses block_uuid_hex (validated
    // to 16 bytes by block_input_from_inputs).
    let device_uuid = uuid_from_inputs(
        inputs,
        "device_uuid_hex",
        "device_uuid_bytes_hex",
        "device_uuid",
    )?;
    // If the vector pinned block_uuid_bytes_hex (wrong-length test),
    // synthesize InvalidArgument before building the BlockInput.
    if let Some(raw) = inputs.get("block_uuid_bytes_hex").and_then(|v| v.as_str()) {
        let bytes = hex::decode(raw).expect("block_uuid_bytes_hex decode");
        if bytes.len() != 16 {
            return Err(BridgeOrSyntheticErr::Synthetic {
                variant: "InvalidArgument",
                detail: format!(
                    "input.block_uuid must be exactly 16 bytes, got {}",
                    bytes.len()
                ),
            });
        }
    }
    let input = block_input_from_inputs(inputs);
    let now_ms = now_ms_from_inputs(inputs);
    secretary_ffi_bridge::save_block(
        &cached.identity,
        &cached.manifest,
        input,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}

use super::fixtures::read_contact_card_bytes;

/// Dispatch share_block. Reads existing_recipient_cards from the
/// manifest (`owner_card_bytes()`) augmented by the
/// `existing_recipient_uuid_hexes` JSON array (each entry is a
/// 32-char user_uuid_hex of a contact card already in
/// <writable_vault>/contacts/). new_recipient is read from
/// `<writable_vault>/contacts/<new_recipient_user_uuid_hex>.card`.
pub fn run_share_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
    writable_vault_dir: &std::path::Path,
) -> Result<(), BridgeOrSyntheticErr> {
    let block_uuid = uuid_from_inputs(
        inputs,
        "block_uuid_hex",
        "block_uuid_bytes_hex",
        "block_uuid",
    )?;
    let device_uuid = uuid_from_inputs(
        inputs,
        "device_uuid_hex",
        "device_uuid_bytes_hex",
        "device_uuid",
    )?;
    let now_ms = now_ms_from_inputs(inputs);

    // existing_recipient_cards: start with the manifest's owner card,
    // then append any extras listed in inputs.existing_recipient_uuid_hexes
    // (used for the duplicate-share case where the existing list must
    // include alice's card from the previous share_block_happy).
    let mut existing_recipient_cards: Vec<Vec<u8>> = Vec::new();
    let owner_bytes = cached
        .manifest
        .owner_card_bytes()
        .expect("owner_card_bytes I/O")
        .expect("owner_card_bytes returned None — manifest wiped?");
    existing_recipient_cards.push(owner_bytes);
    if let Some(extras) = inputs
        .get("existing_recipient_uuid_hexes")
        .and_then(|v| v.as_array())
    {
        for hex_val in extras {
            let h = hex_val
                .as_str()
                .expect("existing_recipient_uuid_hexes entry must be string");
            existing_recipient_cards.push(read_contact_card_bytes(writable_vault_dir, h));
        }
    }

    let new_recipient_hex = inputs
        .get("new_recipient_user_uuid_hex")
        .and_then(|v| v.as_str())
        .expect("share_block inputs need new_recipient_user_uuid_hex");
    let new_recipient = read_contact_card_bytes(writable_vault_dir, new_recipient_hex);

    secretary_ffi_bridge::share_block(
        &cached.identity,
        &cached.manifest,
        block_uuid,
        &existing_recipient_cards,
        &new_recipient,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}

pub fn run_trash_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<(), BridgeOrSyntheticErr> {
    let block_uuid = uuid_from_inputs(
        inputs,
        "block_uuid_hex",
        "block_uuid_bytes_hex",
        "block_uuid",
    )?;
    let device_uuid = uuid_from_inputs(
        inputs,
        "device_uuid_hex",
        "device_uuid_bytes_hex",
        "device_uuid",
    )?;
    let now_ms = now_ms_from_inputs(inputs);
    secretary_ffi_bridge::trash_block(
        &cached.identity,
        &cached.manifest,
        block_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}

pub fn run_restore_block(
    inputs: &serde_json::Value,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
) -> Result<(), BridgeOrSyntheticErr> {
    let block_uuid = uuid_from_inputs(
        inputs,
        "block_uuid_hex",
        "block_uuid_bytes_hex",
        "block_uuid",
    )?;
    let device_uuid = uuid_from_inputs(
        inputs,
        "device_uuid_hex",
        "device_uuid_bytes_hex",
        "device_uuid",
    )?;
    let now_ms = now_ms_from_inputs(inputs);
    secretary_ffi_bridge::restore_block(
        &cached.identity,
        &cached.manifest,
        block_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(BridgeOrSyntheticErr::Bridge)
}

// ── v2 post_state assertion helper ───────────────────────────────────────────

use super::types::PostState;

/// Assert all pinned post_state fields against the post-call manifest.
/// `cached` is the same OpenVaultOutput the write op mutated in place
/// (the bridge's OpenVaultManifest uses interior mutability).
///
/// For `read_block` round-trip assertions, the engine calls
/// `secretary_ffi_bridge::record::read_block` against the cached
/// manifest using the pinned `find_block_uuid_hex` as the lookup key
/// (the same uuid the save op just inserted).
pub fn assert_post_state(
    label: &str,
    cached: &secretary_ffi_bridge::vault::OpenVaultOutput,
    pinned: &PostState,
) {
    if let Some(count) = pinned.block_count {
        assert_eq!(
            cached.manifest.block_count(),
            count,
            "{label}: post_state.block_count mismatch"
        );
    }
    let mut round_trip_uuid: Option<[u8; 16]> = None;
    if let Some(maybe_hex) = &pinned.find_block_uuid_hex {
        match maybe_hex {
            None => {
                // pinned as JSON null → assert absent.
                // The pin doesn't carry which uuid to check, so the
                // calling vector MUST also pin the uuid via the vector's
                // own `inputs.block_uuid_hex`. We re-extract it from the
                // most recently dispatched op via the cached manifest's
                // block list (trash_block sets find_block to null for
                // the just-trashed uuid; this assertion catches a
                // regression where the bridge keeps it findable).
                // For null assertion we don't need the uuid — we just
                // check no block currently lives under any of the
                // post_state.find_block_uuid_hex inputs. But since this
                // is a singleton field, the trash/restore vectors
                // *explicitly* re-read the uuid from inputs. Implement
                // that here:
                panic!(
                    "{label}: post_state.find_block_uuid_hex=null requires the calling vector \
                     to supply the uuid via inputs.block_uuid_hex; the engine asserts this in \
                     the dispatch arm, not here."
                );
            }
            Some(hex_str) => {
                let bytes = hex::decode(hex_str)
                    .unwrap_or_else(|e| panic!("{label}: find_block_uuid_hex decode: {e}"));
                assert_eq!(
                    bytes.len(),
                    16,
                    "{label}: find_block_uuid_hex must be 16 bytes"
                );
                let mut uuid = [0u8; 16];
                uuid.copy_from_slice(&bytes);
                let summary = cached.manifest.find_block(&uuid).unwrap_or_else(|| {
                    panic!("{label}: post_state.find_block_uuid_hex={hex_str} not in manifest")
                });
                assert_eq!(
                    hex::encode(summary.block_uuid),
                    hex_str.to_lowercase(),
                    "{label}: find_block returned wrong uuid"
                );
                round_trip_uuid = Some(uuid);
            }
        }
    }
    if let Some(rc) = pinned.recipient_count {
        let uuid = round_trip_uuid.expect(
            "post_state.recipient_count requires post_state.find_block_uuid_hex to be set so \
             the engine knows which block to inspect",
        );
        let summary = cached
            .manifest
            .find_block(&uuid)
            .expect("recipient_count: block must be findable");
        assert_eq!(
            summary.recipient_uuids.len() as u64,
            rc,
            "{label}: post_state.recipient_count mismatch"
        );
    }
    if let Some(read_pin) = &pinned.read_block {
        let uuid = round_trip_uuid
            .expect("post_state.read_block requires post_state.find_block_uuid_hex to be set");
        let output =
            secretary_ffi_bridge::record::read_block(&cached.identity, &cached.manifest, &uuid)
                .unwrap_or_else(|e| panic!("{label}: round-trip read_block failed: {e:?}"));
        assert_read_block_records(label, &output, &read_pin.records);
    }
}
