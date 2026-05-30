//! Block-save entry point (B.4c) plus the four input pyclasses
//! ([`BlockInput`] / [`RecordInput`] / [`FieldInput`] / [`FieldInputValue`]).
//!
//! The four input types are pure value carriers — they project the bridge
//! crate's `BlockInput` / `RecordInput` / `FieldInput` / `FieldInputValue`
//! 1:1. Python callers construct them with `BlockInput(block_uuid=..., ...)`
//! and pass the resulting tree to `save_block(...)`.
//!
//! Zeroize discipline: text and bytes payloads land inside the bridge's
//! `SecretString` / `SecretBytes` wrappers as soon as the `FieldInputValue`
//! constructor fires. The Python str / bytes objects passed in remain
//! caller-owned; the caller is responsible for clearing them after the
//! `save_block` call returns (the bridge cannot reach into Python's heap).

use pyo3::prelude::*;
use secretary_ffi_bridge::{
    BlockInput as BridgeBlockInput, FieldInput as BridgeFieldInput,
    FieldInputValue as BridgeFieldInputValue, RecordInput as BridgeRecordInput,
};

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Tagged value for a single field on save. Construct via the static
/// methods `text(s)` / `bytes(b)` — both wrap the payload in a zeroize-
/// on-drop carrier (`SecretString` / `SecretBytes`).
///
/// Frozen because foreign-side mutation of an already-constructed value
/// would have no effect on the wrapped secret carrier. The
/// `from_py_object` opt-in keeps PyO3's auto-`FromPyObject` derive so
/// instances of this class can be passed by-value into `FieldInput.__init__`
/// without manual `extract` plumbing.
#[pyclass(frozen, from_py_object)]
#[derive(Clone)]
pub struct FieldInputValue {
    inner: BridgeFieldInputValue,
}

#[pymethods]
impl FieldInputValue {
    /// Wrap a UTF-8 text payload as the field's value.
    #[staticmethod]
    fn text(s: String) -> Self {
        use secretary_core::crypto::secret::SecretString;
        Self {
            inner: BridgeFieldInputValue::Text(SecretString::from(s)),
        }
    }

    /// Wrap a raw bytes payload as the field's value.
    #[staticmethod]
    #[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required to move into SecretBytes
    fn bytes(b: Vec<u8>) -> Self {
        use secretary_core::crypto::secret::SecretBytes;
        Self {
            inner: BridgeFieldInputValue::Bytes(SecretBytes::from(b)),
        }
    }
}

/// One field on a record being saved. `name` is plaintext (CBOR map keys
/// are plaintext on the wire — secrets live in the value, not the key).
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct FieldInput {
    /// Field name (plaintext).
    #[pyo3(get, set)]
    pub name: String,
    /// Tagged value carrying the (zeroize-on-drop) secret payload.
    pub value: FieldInputValue,
}

#[pymethods]
impl FieldInput {
    /// Construct a new field input from a name and value.
    #[new]
    fn new(name: String, value: FieldInputValue) -> Self {
        Self { name, value }
    }
}

/// One record being saved. Duplicate field names inside `fields` collapse
/// to last-write-wins inside the resulting `BTreeMap<String, RecordField>`
/// (matching `core::Record::fields`'s key invariant).
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct RecordInput {
    /// 16-byte stable record UUID.
    pub record_uuid: [u8; 16],
    /// Open-ended record-type discriminator. Empty allowed. (#141)
    #[pyo3(get, set)]
    pub record_type: String,
    /// Cross-cutting tags. (#141)
    #[pyo3(get, set)]
    pub tags: Vec<String>,
    /// Ordered list of fields.
    pub fields: Vec<FieldInput>,
}

#[pymethods]
impl RecordInput {
    /// Construct a new record input. `record_uuid` must be exactly 16 bytes;
    /// otherwise raises `ValueError`. `record_type` defaults to "" and `tags`
    /// to [] so existing 2-arg callers keep working.
    #[new]
    #[pyo3(signature = (record_uuid, fields, record_type=String::new(), tags=Vec::new()))]
    #[allow(clippy::needless_pass_by_value)]
    fn new(
        record_uuid: Vec<u8>,
        fields: Vec<FieldInput>,
        record_type: String,
        tags: Vec<String>,
    ) -> PyResult<Self> {
        let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
        Ok(Self {
            record_uuid,
            record_type,
            tags,
            fields,
        })
    }
}

/// One block being saved. Empty `records` is allowed (the spec permits
/// empty blocks). Same `block_uuid` on a subsequent save replaces the
/// existing manifest entry in-place; new UUID appends.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct BlockInput {
    /// 16-byte stable block UUID.
    pub block_uuid: [u8; 16],
    /// User-visible block name (plaintext within the encrypted manifest).
    #[pyo3(get, set)]
    pub block_name: String,
    /// Records to save in this block.
    pub records: Vec<RecordInput>,
}

#[pymethods]
impl BlockInput {
    /// Construct a new block input. `block_uuid` must be exactly 16 bytes;
    /// otherwise raises `ValueError`.
    #[new]
    #[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
    fn new(block_uuid: Vec<u8>, block_name: String, records: Vec<RecordInput>) -> PyResult<Self> {
        let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
        Ok(Self {
            block_uuid,
            block_name,
            records,
        })
    }
}

/// Encrypt and atomically persist one block of records. (B.4c)
///
/// Mirrors the free-function shape of `read_block`. v1 single-author:
/// recipients are owner-only (multi-recipient is B.4d).
///
/// # Arguments
///
/// - `identity` — live `UnlockedIdentity` from `open_vault_with_password`
///   or `open_vault_with_recovery`.
/// - `manifest` — live `OpenVaultManifest` from the same open call.
/// - `input` — the block + records to save (length-validated by
///   `BlockInput.__init__`).
/// - `device_uuid` — 16-byte device identifier used for per-record /
///   per-field provenance metadata.
/// - `now_ms` — wall-clock millisecond timestamp; written to `created_at_ms`
///   for new records and `last_mod_ms` for both new and updated records.
///
/// # Errors
///
/// - `ValueError` — `device_uuid` length ≠ 16. (Length-check on
///   `block_uuid` / `record_uuid` already ran inside the input
///   constructors, so the only remaining wrong-length case is here.)
/// - `VaultCorruptVault` — either handle has been wiped.
/// - `VaultFolderInvalid` — IO failure during atomic write.
/// - `VaultSaveCryptoFailure` — crypto / encoding failure on already-
///   validated inputs.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> for bytes ∪ bytearray accept
pub(crate) fn save_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    input: &BlockInput,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;

    // Clone inputs into bridge types. Cloning SecretString / SecretBytes
    // briefly doubles the secret material in memory; both copies zeroize
    // on drop (the bridge value via consumption inside save_block, the
    // pyclass-held original on later GC). Same brief-doubling tradeoff as
    // the bridge's clone_inner_bundle helper.
    let bridge_records: Vec<BridgeRecordInput> = input
        .records
        .iter()
        .map(|r| BridgeRecordInput {
            record_uuid: r.record_uuid,
            record_type: r.record_type.clone(),
            tags: r.tags.clone(),
            fields: r
                .fields
                .iter()
                .map(|f| BridgeFieldInput {
                    name: f.name.clone(),
                    value: f.value.inner.clone(),
                })
                .collect(),
        })
        .collect();

    let bridge_input = BridgeBlockInput {
        block_uuid: input.block_uuid,
        block_name: input.block_name.clone(),
        records: bridge_records,
    };

    secretary_ffi_bridge::save_block(&identity.0, &manifest.0, bridge_input, device_uuid, now_ms)
        .map_err(ffi_vault_error_to_pyerr)
}
