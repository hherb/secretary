//! Block-read entry point (B.4b) and the per-record / per-field handles.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use secretary_ffi_bridge::{
    BlockReadOutput as BridgeBlockReadOutput, FieldHandle as BridgeFieldHandle,
    Record as BridgeRecord,
};

use crate::errors::ffi_vault_error_to_pyerr;
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// Per-field handle. Returns secret-payload accessors via explicit
/// `expose_text()` / `expose_bytes()` calls. Use as a context manager
/// to ensure `wipe()` runs on exit (the bridge's underlying SecretString
/// / SecretBytes is zeroize-on-drop; wipe is the explicit, deterministic
/// trigger).
#[pyclass]
pub struct FieldHandle(BridgeFieldHandle);

#[pymethods]
impl FieldHandle {
    /// Field name (e.g. `"password"`). Returns `""` if wiped.
    fn name(&self) -> String {
        self.0.name()
    }
    /// Per-field last-modification timestamp, ms. Returns 0 if wiped.
    fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    /// 16-byte UUID of the device that last modified this field.
    fn device_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.device_uuid())
    }
    /// `True` if the payload is text. `False` if bytes or wiped.
    fn is_text(&self) -> bool {
        self.0.is_text()
    }
    /// `True` if the payload is bytes. `False` if text or wiped.
    fn is_bytes(&self) -> bool {
        self.0.is_bytes()
    }
    /// Pull the secret payload as `str`. Returns `None` if the field
    /// is bytes or has been wiped. Caller is responsible for clearing
    /// the returned string (e.g. `del secret_str`) — the bridge's
    /// underlying `SecretString` is zeroized on drop, but the `str`
    /// handed back to Python is a fresh caller-owned heap copy that
    /// outlives the bridge wipe.
    fn expose_text(&self) -> Option<String> {
        self.0.expose_text()
    }
    /// Pull the secret payload as `bytes`. Returns `None` if the field
    /// is text or has been wiped. Caller is responsible for clearing
    /// the returned bytes (e.g. `del secret_bytes`) — the bridge's
    /// underlying `SecretBytes` is zeroized on drop, but the `bytes`
    /// handed back to Python is a fresh caller-owned heap copy that
    /// outlives the bridge wipe.
    fn expose_bytes<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.expose_bytes().map(|v| PyBytes::new(py, &v))
    }
    /// Drop the underlying secret now. Idempotent.
    fn wipe(&self) {
        self.0.wipe();
    }
    /// Context-manager `__enter__`. Returns `self` so `with field as f`
    /// binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
    /// Context-manager `__exit__`. Calls `wipe()` and returns `False` so
    /// any exception raised inside the `with`-block propagates after wipe
    /// runs.
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.0.wipe();
        false
    }
}

/// Per-record handle. Wraps non-secret metadata + an ordered list of
/// [`FieldHandle`]s. Use as a context manager to ensure `wipe()` runs
/// on exit, cascading wipe to every contained field.
#[pyclass]
pub struct Record(BridgeRecord);

#[pymethods]
impl Record {
    fn record_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.record_uuid())
    }
    fn record_type(&self) -> String {
        self.0.record_type()
    }
    fn tags(&self) -> Vec<String> {
        self.0.tags()
    }
    fn created_at_ms(&self) -> u64 {
        self.0.created_at_ms()
    }
    fn last_mod_ms(&self) -> u64 {
        self.0.last_mod_ms()
    }
    fn tombstone(&self) -> bool {
        self.0.tombstone()
    }
    fn field_count(&self) -> usize {
        self.0.field_count()
    }
    /// Field names in BTreeMap iteration order.
    fn field_names(&self) -> Vec<String> {
        self.0.field_names()
    }
    /// Look up a field by name. Returns `None` if no field has this
    /// name or the record has been wiped. Returns a fresh
    /// [`FieldHandle`] that shares the underlying Arc<...>; wiping
    /// either invalidates both.
    fn field_by_name(&self, name: &str) -> Option<FieldHandle> {
        self.0.field_by_name(name).map(FieldHandle)
    }
    fn field_at(&self, idx: usize) -> Option<FieldHandle> {
        self.0.field_at(idx).map(FieldHandle)
    }
    fn wipe(&self) {
        self.0.wipe();
    }
    /// Context-manager `__enter__`. Returns `self` so `with record as r`
    /// binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
    /// Context-manager `__exit__`. Calls `wipe()` and returns `False` so
    /// any exception raised inside the `with`-block propagates after wipe
    /// runs.
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.0.wipe();
        false
    }
}

/// Container handle for one block's decrypted records. `wipe()` cascades
/// to every contained record + field. Use as a context manager.
#[pyclass]
pub struct BlockReadOutput(BridgeBlockReadOutput);

#[pymethods]
impl BlockReadOutput {
    fn block_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.block_uuid())
    }
    fn block_name(&self) -> String {
        self.0.block_name()
    }
    fn record_count(&self) -> usize {
        self.0.record_count()
    }
    fn record_at(&self, idx: usize) -> Option<Record> {
        self.0.record_at(idx).map(Record)
    }
    fn wipe(&self) {
        self.0.wipe();
    }
    /// Context-manager `__enter__`. Returns `self` so `with output as o`
    /// binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }
    /// Context-manager `__exit__`. Calls `wipe()` and returns `False` so
    /// any exception raised inside the `with`-block propagates after wipe
    /// runs.
    fn __exit__(
        &self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        self.0.wipe();
        false
    }
}

/// Decrypt one block of an open vault and return its records.
///
/// `block_uuid` must be exactly 16 bytes; otherwise raises `ValueError`.
/// Wrong-length input is a programmer error and surfaces distinctly
/// from the data-error variant `VaultBlockNotFound` (which fires when
/// the UUID doesn't match any block in the manifest).
///
/// When `include_deleted` is false, tombstoned (soft-deleted) records are
/// withheld (their field handles are never built, so no secret bytes cross
/// the FFI seam); when true they are returned carrying `tombstone == True`.
///
/// # Raises
///
/// - `ValueError` — `block_uuid` length ≠ 16.
/// - `VaultBlockNotFound` — UUID not in manifest's live blocks list.
/// - `VaultCorruptVault` — block file missing/malformed/decryption failed.
/// - `VaultFolderInvalid` — block file present but unreadable for non-NotFound IO reasons.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for bytes ∪ bytearray accept
pub(crate) fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    include_deleted: bool,
) -> PyResult<BlockReadOutput> {
    if block_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "block_uuid must be 16 bytes, got {}",
            block_uuid.len()
        )));
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(&block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array, include_deleted)
        .map(BlockReadOutput)
        .map_err(ffi_vault_error_to_pyerr)
}
