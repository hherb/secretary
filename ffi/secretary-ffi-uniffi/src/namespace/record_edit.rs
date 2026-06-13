//! uniffi namespace projection of the bridge's record-edit primitives.
//!
//! Four thin wrappers over `secretary_ffi_bridge::{append_record,
//! edit_record, tombstone_record, resurrect_record}`. Each length-validates
//! its uuid arguments (16 bytes each → otherwise [`VaultError::InvalidArgument`],
//! mirroring `save_block`/`trash_block`), converts the flat `RecordContent`
//! into the bridge type (wrapping payloads in zeroize-on-drop carriers), and
//! maps `FfiVaultError` via the existing `From` impl on [`VaultError`].
//!
//! The bridge primitives own all CRDT semantics (preserve per-field clocks
//! on unchanged fields, freeze `tombstoned_at_ms`, carry forward `unknown`
//! maps); this layer adds none of its own.

use super::uuid_from_vec;
use crate::errors::VaultError;
use crate::wrappers::identity::UnlockedIdentity;
use crate::wrappers::vault::OpenVaultManifest;

/// Convert a uniffi-side [`crate::RecordContent`] into a bridge-side
/// [`secretary_ffi_bridge::RecordContent`], wrapping each field payload in
/// the appropriate zeroize-on-drop secret carrier (`SecretString` /
/// `SecretBytes`).
fn convert_record_content(c: crate::RecordContent) -> secretary_ffi_bridge::RecordContent {
    use secretary_core::crypto::secret::{SecretBytes, SecretString};

    let fields = c
        .fields
        .into_iter()
        .map(|f| secretary_ffi_bridge::FieldInput {
            name: f.name,
            value: match f.value {
                crate::FieldInputValue::Text { text } => {
                    secretary_ffi_bridge::FieldInputValue::Text(SecretString::from(text))
                }
                crate::FieldInputValue::Bytes { data } => {
                    secretary_ffi_bridge::FieldInputValue::Bytes(SecretBytes::from(data))
                }
            },
        })
        .collect();

    secretary_ffi_bridge::RecordContent {
        record_type: c.record_type,
        tags: c.tags,
        fields,
    }
}

/// Append a new record to an existing block. (record-edit slice)
///
/// `block_uuid`, `record_uuid`, and `device_uuid` must each be exactly 16
/// bytes; otherwise returns [`VaultError::InvalidArgument`]. Routes to
/// [`secretary_ffi_bridge::append_record`], which preserves every sibling
/// record and all `unknown` maps natively.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::BlockNotFound`] — `block_uuid` not in the manifest.
/// - [`VaultError::CorruptVault`] — decrypt failure / wiped handle.
/// - save-tail surface ([`VaultError::FolderInvalid`] / [`VaultError::SaveCryptoFailure`]).
#[allow(clippy::too_many_arguments)]
pub fn append_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: crate::RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    let content = convert_record_content(content);
    secretary_ffi_bridge::append_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        content,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Replace one live record's editable part (type / tags / fields),
/// preserving its `record_uuid`, `created_at_ms`, `tombstoned_at_ms`, and
/// every `unknown` map; untouched fields keep their prior clock /
/// `device_uuid`. (record-edit slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::RecordNotFound`] — no live record with this UUID in the block.
/// - [`VaultError::BlockNotFound`] / [`VaultError::CorruptVault`] / save-tail surface.
#[allow(clippy::too_many_arguments)]
pub fn edit_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: crate::RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    let content = convert_record_content(content);
    secretary_ffi_bridge::edit_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        content,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Soft-delete one live record (set tombstone + death clock). (record-edit slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::RecordNotFound`] — no LIVE record with this UUID.
/// - [`VaultError::BlockNotFound`] / [`VaultError::CorruptVault`] / save-tail surface.
pub fn tombstone_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::tombstone_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Resurrect one tombstoned record (clear tombstone, bump `last_mod_ms`
/// to `now_ms`, preserve `tombstoned_at_ms`). (record-edit slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::RecordNotFound`] — no TOMBSTONED record with this UUID.
/// - [`VaultError::BlockNotFound`] / [`VaultError::CorruptVault`] / save-tail surface.
pub fn resurrect_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::resurrect_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}
