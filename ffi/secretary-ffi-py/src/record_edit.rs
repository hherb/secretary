//! Record-edit entry points (record-edit slice): `append_record`,
//! `edit_record`, `tombstone_record`, `resurrect_record`, plus the
//! `RecordContent` input pyclass.
//!
//! `RecordContent` projects the bridge's `RecordContent` 1:1, reusing the
//! same `FieldInput` pyclass as `save_block`. Zeroize discipline matches
//! `save.rs`: text/bytes land in `SecretString`/`SecretBytes` as soon as
//! the `FieldInputValue` constructor fires; the Python str/bytes remain
//! caller-owned.

use pyo3::prelude::*;
use secretary_ffi_bridge::RecordContent as BridgeRecordContent;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::save::FieldInput;
use crate::vault::OpenVaultManifest;

/// The editable delta for one record on append/edit. Construct with
/// `RecordContent(fields=[FieldInput(...)], record_type="login", tags=[...])`.
/// `record_uuid` / `created_at_ms` / `unknown` are owned by the edit
/// primitives, not supplied here.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct RecordContent {
    /// Open-ended record-type discriminator. Empty allowed.
    #[pyo3(get, set)]
    pub record_type: String,
    /// Cross-cutting tags.
    #[pyo3(get, set)]
    pub tags: Vec<String>,
    /// Ordered list of fields.
    pub fields: Vec<FieldInput>,
}

#[pymethods]
impl RecordContent {
    /// Construct a record-content delta. `record_type` defaults to "" and
    /// `tags` to [] for ergonomic construction.
    #[new]
    #[pyo3(signature = (fields, record_type=String::new(), tags=Vec::new()))]
    fn new(fields: Vec<FieldInput>, record_type: String, tags: Vec<String>) -> Self {
        Self {
            record_type,
            tags,
            fields,
        }
    }
}

/// Convert the pyclass `RecordContent` into the bridge type via
/// `FieldInput::to_bridge`. Same brief secret-doubling tradeoff as
/// `save_block`'s record clone.
fn to_bridge_content(c: &RecordContent) -> BridgeRecordContent {
    BridgeRecordContent {
        record_type: c.record_type.clone(),
        tags: c.tags.clone(),
        fields: c.fields.iter().map(FieldInput::to_bridge).collect(),
    }
}

/// Append a new record to an existing block. `block_uuid` / `record_uuid`
/// / `device_uuid` must each be 16 bytes (else `ValueError`). Raises
/// `VaultBlockNotFound` for an unknown block; `VaultCorruptVault` on a
/// wiped handle; `VaultFolderInvalid` on an IO failure during the atomic
/// write; `VaultSaveCryptoFailure` on a crypto/encoding failure.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn append_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: &RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::append_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        to_bridge_content(content),
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Replace one live record's editable part. Raises `VaultRecordNotFound`
/// if no live record with this UUID; `VaultBlockNotFound` for an unknown
/// block; `VaultCorruptVault` on a wiped handle; `VaultFolderInvalid` on
/// an IO failure during the atomic write; `VaultSaveCryptoFailure` on a
/// crypto/encoding failure. Same uuid-length contract as `append_record`.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn edit_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: &RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::edit_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        to_bridge_content(content),
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Soft-delete one live record. Raises `VaultRecordNotFound` if no LIVE
/// record with this UUID; `VaultBlockNotFound` for an unknown block;
/// `VaultCorruptVault` on a wiped handle; `VaultFolderInvalid` on an IO
/// failure during the atomic write; `VaultSaveCryptoFailure` on a
/// crypto/encoding failure.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn tombstone_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::tombstone_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Resurrect one tombstoned record (clear tombstone, bump last_mod_ms,
/// preserve `tombstoned_at_ms`). Raises `VaultRecordNotFound` if no
/// TOMBSTONED record with this UUID; `VaultBlockNotFound` for an unknown
/// block; `VaultCorruptVault` on a wiped handle; `VaultFolderInvalid` on
/// an IO failure during the atomic write; `VaultSaveCryptoFailure` on a
/// crypto/encoding failure. Assumes `now_ms` is monotonic (≥ the
/// preserved `tombstoned_at_ms`); a stale clock would momentarily produce
/// `tombstoned_at_ms > last_mod_ms`, which core defensively clamps on merge.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn resurrect_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::resurrect_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}
