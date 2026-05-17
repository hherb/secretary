//! v2 write-op dispatchers (`save_block`, `share_block`, `trash_block`,
//! `restore_block`) plus `assert_post_state`.
//!
//! Each `run_*` consults `super::inputs` for UUID + payload parsing,
//! then invokes the bridge directly. Wrong-length UUID inputs surface
//! `BridgeOrSyntheticErr::Synthetic { "InvalidArgument" }` symmetrically
//! with the uniffi-layer length checks — see `super::inputs` for details.

use super::super::fixtures::read_contact_card_bytes;
use super::super::types::{BridgeOrSyntheticErr, PostState};
use super::inputs::{block_input_from_inputs, now_ms_from_inputs, uuid_from_inputs};
use super::read::assert_read_block_records;

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
    // building the BlockInput). block_uuid + record_uuid lengths are
    // validated inside `block_input_from_inputs`, which synthesizes
    // `InvalidArgument` symmetrically for either path.
    let device_uuid = uuid_from_inputs(
        inputs,
        "device_uuid_hex",
        "device_uuid_bytes_hex",
        "device_uuid",
    )?;
    let input = block_input_from_inputs(inputs)?;
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
    if let Some(hex_str) = &pinned.find_block_uuid_hex {
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
