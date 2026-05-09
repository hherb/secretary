//! Python bindings for secretary-core via PyO3.
//!
//! The crate-level `#![allow(unsafe_code)]` is the minimal escape hatch
//! for PyO3's #[pymodule] / #[pyfunction] macros, which expand to unsafe
//! blocks (the CPython C-API bridge is inherently unsafe). The crate-local
//! lint relaxation (workspace `forbid` → crate-local `deny`) is required
//! because `forbid` is non-overridable by inner #[allow]; see Cargo.toml.
//!
//! The `#[allow]` is **crate-level** rather than item-level because the
//! function-style `#[pymodule]` macro generates code at crate scope (an
//! `extern "C"` PyInit symbol alongside the entry-point function); a
//! narrower item-level `#[allow]` doesn't cover that expansion. The
//! tradeoff: a future contributor who adds a hand-rolled `unsafe` block
//! anywhere in this crate gets silence rather than a `deny` error. The
//! crate is intentionally tiny and reviewed; new `unsafe` blocks should
//! be challenged in code review.
//!
//! B.2 (this version) adds the `open_with_password` entry-point and the
//! `UnlockedIdentity` opaque handle, projecting `secretary-ffi-bridge`'s
//! FFI-friendly facade through PyO3.
//!
//! B.3a adds the `open_with_recovery` entry-point and 2 new exception
//! classes (`WrongMnemonicOrCorrupt`, `InvalidMnemonic`). Mnemonic
//! input is `bytes`/`bytearray` (UTF-8 encoded); the bridge's UTF-8-
//! validation seam surfaces malformed-UTF-8 input as `InvalidMnemonic`
//! with `detail: "phrase contained invalid UTF-8"`.
//!
//! Rationale (B.2): docs/superpowers/specs/2026-05-04-ffi-b2-vault-unlock-design.md
//!
//! Rationale (B.3a): docs/superpowers/specs/2026-05-04-ffi-b3a-recovery-unlock-design.md
//!
//! Rationale: docs/superpowers/specs/2026-05-03-ffi-b1-py-bindings-boilerplate-design.md
//!
//! B.3b adds the `create_vault` entry-point and 2 new opaque-handle
//! types (`CreateVaultOutput`, `MnemonicOutput`). Bridge instantiates
//! `OsRng` and `Argon2idParams::V1_DEFAULT` internally; foreign callers
//! get neither knob. The freshly-generated 24-word recovery mnemonic
//! crosses the FFI back via `MnemonicOutput.take_phrase()` as `bytes`,
//! one-shot — second call returns `None`. Caller-zeroize discipline on
//! the returned `bytes` parallels the input-side discipline from B.2
//! / B.3a, inverted in direction.
//!
//! Rationale (B.3b): docs/superpowers/specs/2026-05-05-ffi-b3b-create-vault-design.md
//!
//! B.4a adds the `open_vault_with_password` and `open_vault_with_recovery`
//! folder-in entry points. Foreign caller passes a folder path; Rust core
//! reads `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, and the
//! owner contact card. Returns `OpenVaultOutput` containing two take-once
//! opaque handles: `identity` (live `UnlockedIdentity`) and `manifest`
//! (read-only `OpenVaultManifest` with block-list accessors). Six new
//! Python exception classes prefixed `Vault` disambiguate from the
//! bytes-in `FfiUnlockError` exception classes.
//!
//! Rationale (B.4a): docs/superpowers/specs/2026-05-06-ffi-b4a-open-vault-design.md

#![allow(unsafe_code)]

use pyo3::prelude::*;

/// Returns the vault format version exposed by the core crate.
///
/// Kept as a free function so Rust callers (and the Rust unit tests below)
/// can use it without going through PyO3 / a Python interpreter.
pub fn version() -> u16 {
    secretary_core::version::FORMAT_VERSION
}

/// Python-exposed addition. B.1 round-trip target. Uses `wrapping_add`
/// to make the overflow contract explicit (matches default Rust `+`
/// semantics in release builds, which silently wrap); B.2 will reconsider
/// when fallible crypto operations make `PyResult` first-class.
#[pyfunction]
fn add(a: u32, b: u32) -> u32 {
    a.wrapping_add(b)
}

/// Python-exposed wrapper around `version()`. Renamed at the PyO3 layer
/// from the Rust ident `version_py` to the Python name `version` so the
/// Python-side surface stays clean.
#[pyfunction]
#[pyo3(name = "version")]
fn version_py() -> u32 {
    u32::from(version())
}

// ---------------------------------------------------------------------------
// B.2: open_with_password + UnlockedIdentity + exception classes.
//
// The actual logic lives in secretary-ffi-bridge; this file is the PyO3
// projection layer.
// ---------------------------------------------------------------------------

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::types::{PyBytes, PyType};
use secretary_ffi_bridge::{
    BlockReadOutput as BridgeBlockReadOutput, BlockSummary as BridgeBlockSummary, FfiUnlockError,
    FfiVaultError, FieldHandle as BridgeFieldHandle, OpenVaultManifest as BridgeOpenVaultManifest,
    Record as BridgeRecord,
};
use zeroize::Zeroize;

create_exception!(secretary_ffi_py, WrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultMismatch, PyException);
create_exception!(secretary_ffi_py, CorruptVault, PyException);
create_exception!(secretary_ffi_py, WrongMnemonicOrCorrupt, PyException);
create_exception!(secretary_ffi_py, InvalidMnemonic, PyException);

// FfiVaultError → Python exception classes (B.4a). Five mirror the
// FfiUnlockError exceptions byte-identical on Display string, but they're
// distinct Python classes so foreign callers can `except VaultFolderInvalid:`
// without needing to introspect the exception's source error type.
//
// Naming: prefix with "Vault" to disambiguate from the FfiUnlockError
// classes; the bytes-in callers raise the existing classes, the folder-in
// callers raise these. `VaultMismatchFolder` is renamed from the logical
// `VaultMismatch` to avoid collision with the existing `VaultMismatch`
// class above (which maps to `FfiUnlockError::VaultMismatch`).
create_exception!(secretary_ffi_py, VaultWrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultWrongMnemonicOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultInvalidMnemonic, PyException);
create_exception!(secretary_ffi_py, VaultMismatchFolder, PyException);
create_exception!(secretary_ffi_py, VaultCorruptVault, PyException);
create_exception!(secretary_ffi_py, VaultFolderInvalid, PyException);
create_exception!(secretary_ffi_py, VaultBlockNotFound, PyException);

/// Map a bridge-crate `FfiUnlockError` to the matching Python exception
/// class. Used at the `open_with_password` boundary via `.map_err`. A
/// free function (rather than a `From` impl) is preferred because the
/// orphan rules forbid `impl From<FfiUnlockError> for PyErr` from a
/// downstream crate, and `?`-routing isn't needed at the single call
/// site.
fn ffi_unlock_error_to_pyerr(e: FfiUnlockError) -> PyErr {
    match e {
        FfiUnlockError::WrongPasswordOrCorrupt => WrongPasswordOrCorrupt::new_err(e.to_string()),
        FfiUnlockError::WrongMnemonicOrCorrupt => WrongMnemonicOrCorrupt::new_err(e.to_string()),
        FfiUnlockError::InvalidMnemonic { detail } => InvalidMnemonic::new_err(detail),
        FfiUnlockError::VaultMismatch => VaultMismatch::new_err(e.to_string()),
        FfiUnlockError::CorruptVault { detail } => CorruptVault::new_err(detail),
    }
}

/// Map a bridge-crate `FfiVaultError` to the matching Python exception
/// class (B.4a folder-in entry points). Parallels `ffi_unlock_error_to_pyerr`
/// with one-to-one variant translation to the `Vault`-prefixed exception
/// classes. A free function (rather than a `From` impl) mirrors the existing
/// `ffi_unlock_error_to_pyerr` pattern — the orphan rules forbid
/// `impl From<FfiVaultError> for PyErr` here since both types are external.
fn ffi_vault_error_to_pyerr(e: FfiVaultError) -> PyErr {
    match e {
        FfiVaultError::WrongPasswordOrCorrupt => {
            VaultWrongPasswordOrCorrupt::new_err(e.to_string())
        }
        FfiVaultError::WrongMnemonicOrCorrupt => {
            VaultWrongMnemonicOrCorrupt::new_err(e.to_string())
        }
        FfiVaultError::InvalidMnemonic { detail } => VaultInvalidMnemonic::new_err(detail),
        FfiVaultError::VaultMismatch => VaultMismatchFolder::new_err(e.to_string()),
        FfiVaultError::CorruptVault { detail } => VaultCorruptVault::new_err(detail),
        FfiVaultError::FolderInvalid { detail } => VaultFolderInvalid::new_err(detail),
        FfiVaultError::BlockNotFound { uuid_hex } => {
            // Pass uuid_hex as the exception payload so foreign callers
            // can `except VaultBlockNotFound as e: e.args[0]` to get the
            // hex string back.
            VaultBlockNotFound::new_err(uuid_hex)
        }
    }
}

/// Opaque Python-side handle to a successfully-unlocked vault identity.
/// Newtype around `secretary_ffi_bridge::UnlockedIdentity`; methods are
/// thin forwarders. Implements the context-manager protocol so the
/// idiomatic usage is `with open_with_password(...) as id: ...`.
#[pyclass]
pub struct UnlockedIdentity(secretary_ffi_bridge::UnlockedIdentity);

#[pymethods]
impl UnlockedIdentity {
    /// User-facing display name from the IdentityBundle. Returns `""` if
    /// the handle has been explicitly closed.
    fn display_name(&self) -> String {
        self.0.display_name()
    }

    /// 16-byte stable identifier from the IdentityBundle. Returns
    /// `b'\x00' * 16` if the handle has been explicitly closed.
    fn user_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.0.user_uuid())
    }

    /// Drop the wrapped identity now, zeroizing all secret fields at
    /// exactly this moment. Idempotent. Forwards to the bridge crate's
    /// `UnlockedIdentity::wipe()`; the Python-facing method is named
    /// `close()` for the context-manager protocol idiom.
    fn close(&self) {
        self.0.wipe();
    }

    /// Context-manager `__enter__`. Returns `self` so `with ... as id`
    /// binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Calls `close()` and returns `False`
    /// so any exception raised inside the `with`-block propagates after
    /// close runs.
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

/// Opaque Python-side handle to a one-shot recovery mnemonic. Newtype
/// around `secretary_ffi_bridge::MnemonicOutput`; methods are thin
/// forwarders. Implements the context-manager protocol so the idiomatic
/// usage is `with output.mnemonic as mn: phrase = mn.take_phrase()`.
///
/// `take_phrase()` returns `bytes` once; subsequent calls return `None`.
/// `close()` (and the equivalent context-manager `__exit__`) is
/// idempotent and wipes any still-resident phrase from Rust-side memory.
#[pyclass]
pub struct MnemonicOutput(secretary_ffi_bridge::MnemonicOutput);

#[pymethods]
impl MnemonicOutput {
    /// Take the recovery phrase as `bytes`. ONE-SHOT — second call
    /// returns `None`. The returned `bytes` is fresh caller-owned heap;
    /// the caller is responsible for zeroizing it after use (e.g. by
    /// converting to `bytearray` and overwriting in place; PyO3 cannot
    /// hand back a mutable buffer typed as a foreign Sensitive analog).
    fn take_phrase<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.take_phrase().map(|v| PyBytes::new(py, &v))
    }

    /// Drop any still-resident inner mnemonic now, zeroizing its
    /// `Sensitive<...>` fields. Idempotent.
    fn close(&self) {
        self.0.wipe();
    }

    /// Context-manager `__enter__`. Returns `self` so
    /// `with output.mnemonic as mn` binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Calls `close()` and returns `False`
    /// so any exception raised inside the `with`-block propagates after
    /// close runs. Mirrors the exit pattern on `UnlockedIdentity`.
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

// ---------------------------------------------------------------------------
// FFI input convention (lib.rs):
//   - `Vec<u8>` for any `bytes`-like parameter that the foreign caller may
//     reasonably pass as either `bytes` (immutable) or `bytearray` (mutable,
//     for caller-zeroize discipline). PyO3's automatic conversion accepts
//     both for Vec<u8>; for &[u8] it accepts only bytes.
//   - This applies uniformly to UUIDs, passwords, mnemonics, and any other
//     bytes-typed input. Mirrors the uniffi UDL `bytes -> Vec<u8>`
//     projection so the two binding-flavor crates stay aligned.
//   - The 16-byte (or similar small-fixed-length) heap copy is negligible.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// B.4a: BlockSummary + OpenVaultManifest + OpenVaultOutput pyclasses.
// ---------------------------------------------------------------------------

/// Read-only metadata projection of one block in the vault manifest.
/// All five fields are plaintext in the manifest already — no secret
/// material crosses through `BlockSummary`. Frozen because foreign-side
/// mutation would have no effect on the underlying Rust state.
#[pyclass(frozen)]
pub struct BlockSummary {
    /// 16-byte block UUID identifying the block file on disk.
    #[pyo3(get)]
    pub block_uuid: Vec<u8>,
    /// User-visible block name. Plaintext within the encrypted manifest.
    #[pyo3(get)]
    pub block_name: String,
    /// Wall-clock millisecond timestamp at block creation.
    #[pyo3(get)]
    pub created_at_ms: u64,
    /// Wall-clock millisecond timestamp at last modification.
    #[pyo3(get)]
    pub last_modified_ms: u64,
    /// List of 16-byte recipient UUIDs (always includes owner). Plaintext.
    #[pyo3(get)]
    pub recipient_uuids: Vec<Vec<u8>>,
}

impl From<BridgeBlockSummary> for BlockSummary {
    fn from(b: BridgeBlockSummary) -> Self {
        Self {
            block_uuid: b.block_uuid.to_vec(),
            block_name: b.block_name,
            created_at_ms: b.created_at_ms,
            last_modified_ms: b.last_modified_ms,
            recipient_uuids: b.recipient_uuids.into_iter().map(|u| u.to_vec()).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// B.4b: FieldHandle + Record + BlockReadOutput pyclasses + read_block fn.
// ---------------------------------------------------------------------------

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
/// # Raises
///
/// - `ValueError` — `block_uuid` length ≠ 16.
/// - `VaultBlockNotFound` — UUID not in manifest's live blocks list.
/// - `VaultCorruptVault` — block file missing/malformed/decryption failed.
/// - `VaultFolderInvalid` — block file present but unreadable for non-NotFound IO reasons.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for bytes ∪ bytearray accept
fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
) -> PyResult<BlockReadOutput> {
    if block_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "block_uuid must be 16 bytes, got {}",
            block_uuid.len()
        )));
    }
    let mut uuid_array = [0u8; 16];
    uuid_array.copy_from_slice(&block_uuid);
    secretary_ffi_bridge::read_block(&identity.0, &manifest.0, &uuid_array)
        .map(BlockReadOutput)
        .map_err(ffi_vault_error_to_pyerr)
}

/// Opaque handle to a successfully-opened vault's manifest. Provides
/// read-only block-list accessors. Use as a context manager so `wipe()`
/// is called automatically on exit — the IBK is zeroized at that point.
///
/// RAII is the safety net if the foreign caller forgets to use `with`.
#[pyclass]
pub struct OpenVaultManifest(BridgeOpenVaultManifest);

#[pymethods]
impl OpenVaultManifest {
    /// 16-byte vault UUID. Returns 16 zero bytes if wiped.
    pub fn vault_uuid(&self) -> Vec<u8> {
        self.0.vault_uuid()
    }

    /// 16-byte owner user UUID. Returns 16 zero bytes if wiped.
    pub fn owner_user_uuid(&self) -> Vec<u8> {
        self.0.owner_user_uuid()
    }

    /// Number of blocks in the manifest. Returns 0 if wiped.
    pub fn block_count(&self) -> u64 {
        self.0.block_count()
    }

    /// All block summaries in ascending-by-block_uuid order. Returns an
    /// empty list if wiped.
    pub fn block_summaries(&self) -> Vec<BlockSummary> {
        self.0
            .block_summaries()
            .into_iter()
            .map(BlockSummary::from)
            .collect()
    }

    /// Locate one block by its 16-byte UUID. Returns `None` if wiped or
    /// no matching block exists.
    ///
    /// `block_uuid` is `Vec<u8>` rather than `&[u8]` so PyO3 accepts both
    /// `bytes` and `bytearray` inputs — `&[u8]` would restrict to
    /// immutable `bytes` only. The 16-byte heap copy is negligible; the
    /// foreign-friendly accept-both ergonomics + parity with uniffi's
    /// UDL `bytes` → `Vec<u8>` projection are worth it.
    pub fn find_block(&self, block_uuid: Vec<u8>) -> Option<BlockSummary> {
        self.0.find_block(&block_uuid).map(BlockSummary::from)
    }

    /// Drop the wrapped manifest now, zeroizing the IBK at exactly this
    /// moment. Idempotent.
    pub fn wipe(&self) {
        self.0.wipe();
    }

    /// Context-manager `__enter__`. Returns `self` so `with manifest as m`
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

/// Output of `open_vault_with_password` / `open_vault_with_recovery`.
/// Holds two opaque take-once handles: `identity` (live
/// `UnlockedIdentity`) and `manifest` (read-only `OpenVaultManifest`).
///
/// The handles are accessed through take-once getter properties. The
/// first access MOVES the handle out of the parent struct; subsequent
/// accesses raise `RuntimeError`. The pattern mirrors B.3b's
/// `CreateVaultOutput.identity` and `.mnemonic` getters exactly.
///
/// Use as a context manager so both inner handles have the opportunity
/// to wipe themselves on exit even if the caller forgot to enter them:
///
/// ```python
/// with open_vault_with_password(folder, pw) as out:
///     with out.identity as id, out.manifest as m:
///         print(id.display_name())
/// ```
#[pyclass]
pub struct OpenVaultOutput {
    /// Live opaque handle, taken once. Wrapped in `Option` so the getter
    /// can move it out exactly once via `Option::take()`.
    identity: Option<UnlockedIdentity>,
    /// Read-only manifest handle, taken once. Same take-once pattern.
    manifest: Option<OpenVaultManifest>,
}

#[pymethods]
impl OpenVaultOutput {
    /// Take ownership of the live `UnlockedIdentity` handle. ONE-SHOT —
    /// the first read MOVES the handle out of the parent struct; every
    /// subsequent read raises `RuntimeError`. Mirrors the shape of
    /// `CreateVaultOutput.identity`.
    #[getter]
    fn identity(&mut self) -> PyResult<UnlockedIdentity> {
        self.identity.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "OpenVaultOutput.identity already taken (one-shot)",
            )
        })
    }

    /// Take ownership of the `OpenVaultManifest` handle. ONE-SHOT —
    /// same destructive take-once semantics as `identity`.
    #[getter]
    fn manifest(&mut self) -> PyResult<OpenVaultManifest> {
        self.manifest.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "OpenVaultOutput.manifest already taken (one-shot)",
            )
        })
    }

    /// Context-manager `__enter__`. Returns `self` so `with out as o`
    /// binds the output handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Drops both inner handles if still
    /// resident (which runs their own zeroize-on-drop chains). Returns
    /// `False` so any exception propagates.
    fn __exit__(
        &mut self,
        _exc_type: Option<&Bound<'_, PyType>>,
        _exc_value: Option<&Bound<'_, PyAny>>,
        _traceback: Option<&Bound<'_, PyAny>>,
    ) -> bool {
        // Drop identity: close() zeroizes the IBK + secret keys via the
        // bridge's wipe() forwarder.
        if let Some(id) = self.identity.take() {
            id.close();
        }
        // Drop manifest: wipe() zeroizes the IBK.
        if let Some(m) = self.manifest.take() {
            m.wipe();
        }
        false
    }
}

/// Output of `create_vault`. Holds the on-disk byte artifacts plus two
/// opaque handles for the live identity and the one-shot recovery
/// mnemonic. The fields are accessed through getter methods because
/// `#[pyclass]` types cannot expose non-trivial fields directly.
#[pyclass]
pub struct CreateVaultOutput {
    /// Vault metadata bytes — non-secret. Caller writes these to
    /// `<vault-dir>/vault.toml` atomically.
    vault_toml_bytes: Vec<u8>,
    /// Encrypted identity bundle bytes — non-secret. Caller writes these
    /// to `<vault-dir>/identity.bundle.enc` atomically.
    identity_bundle_bytes: Vec<u8>,
    /// Live opaque handle to the just-created identity. Wrapped in
    /// `Option` so the getter can move it out exactly once (see
    /// `take_identity`); after that the field becomes `None` and
    /// subsequent calls raise.
    identity: Option<UnlockedIdentity>,
    /// One-shot opaque handle for the recovery mnemonic. Same Option
    /// take-once pattern as `identity`.
    mnemonic: Option<MnemonicOutput>,
}

#[pymethods]
impl CreateVaultOutput {
    /// Vault metadata bytes — non-secret. Returns a fresh `bytes` object
    /// each call (PyO3 copies from the underlying `Vec<u8>`).
    #[getter]
    fn vault_toml_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.vault_toml_bytes)
    }

    /// Encrypted identity bundle bytes — non-secret.
    #[getter]
    fn identity_bundle_bytes<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.identity_bundle_bytes)
    }

    /// Take ownership of the live `UnlockedIdentity` handle. ONE-SHOT —
    /// the first read MOVES the handle out of the parent struct, and
    /// every subsequent read of `output.identity` raises
    /// `RuntimeError`. Despite the `#[getter]` shape (Python sees a
    /// property), this access is *destructive*; do not call it from
    /// debug introspection paths (`repr`, logging, REPL tab-completion
    /// previews) and then try to reuse the handle. The Python idiom is
    /// to bind the property directly to a `with` block, e.g.
    /// `with output.identity as id: ...`.
    ///
    /// Implemented via interior take rather than a borrowed reference
    /// because Python `with` semantics need to OWN the context manager;
    /// returning a reference into a `#[pyclass]` field would couple the
    /// `with`-block's lifetime to the parent `output` value in ways that
    /// are awkward at the FFI boundary. The README's "Vault creation
    /// (B.3b)" section documents the consequences for callers.
    #[getter]
    fn identity(&mut self) -> PyResult<UnlockedIdentity> {
        self.identity.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "CreateVaultOutput.identity already taken (one-shot)",
            )
        })
    }

    /// Take ownership of the one-shot `MnemonicOutput` handle. Same
    /// destructive take-once semantics as `identity` — see that
    /// method's docstring for the full caveat.
    #[getter]
    fn mnemonic(&mut self) -> PyResult<MnemonicOutput> {
        self.mnemonic.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "CreateVaultOutput.mnemonic already taken (one-shot)",
            )
        })
    }
}

/// Unlock a vault using its master password. See module-level docs for
/// the exception classes raised on failure.
#[pyfunction]
fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mut password: Vec<u8>,
) -> PyResult<UnlockedIdentity> {
    // The bridge crate copies into SecretBytes (which zeroizes on drop).
    // This Vec is a transient cleartext residue on the wrapper's heap;
    // zero it explicitly so we don't leave the password lingering after
    // the call returns. Mirrors the stack-residue discipline in
    // docs/manual/contributors/memory-hygiene-audit-internal.md.
    let result = secretary_ffi_bridge::open_with_password(
        vault_toml_bytes,
        identity_bundle_bytes,
        &password,
    )
    .map(UnlockedIdentity)
    .map_err(ffi_unlock_error_to_pyerr);
    password.zeroize();
    result
}

/// Unlock a vault using its 24-word BIP-39 recovery phrase. See
/// module-level docs for the exception classes raised on failure.
#[pyfunction]
fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mut mnemonic: Vec<u8>,
) -> PyResult<UnlockedIdentity> {
    // Mirrors the open_with_password wrapper-side zeroize discipline:
    // the bridge takes &[u8] and never retains; this Vec is the wrapper's
    // owned copy of the foreign caller's bytes-like input. Zero it after
    // the bridge returns so the password-equivalent doesn't linger on
    // the wrapper heap.
    let result = secretary_ffi_bridge::open_with_recovery(
        vault_toml_bytes,
        identity_bundle_bytes,
        &mnemonic,
    )
    .map(UnlockedIdentity)
    .map_err(ffi_unlock_error_to_pyerr);
    mnemonic.zeroize();
    result
}

/// Create a fresh v1 vault. Bridge instantiates `OsRng` and
/// `Argon2idParams::V1_DEFAULT` internally; foreign callers get
/// neither knob.
///
/// Returns a `CreateVaultOutput` containing:
/// - `vault_toml_bytes`, `identity_bundle_bytes` — non-secret bytes the
///   caller persists atomically.
/// - `identity` — live `UnlockedIdentity`, ready for vault operations.
/// - `mnemonic` — one-shot `MnemonicOutput` for the 24-word recovery
///   phrase.
///
/// See module-level docs for the exception classes raised on failure.
#[pyfunction]
fn create_vault(
    mut password: Vec<u8>,
    display_name: &str,
    created_at_ms: u64,
) -> PyResult<CreateVaultOutput> {
    // Mirrors the open_with_password / open_with_recovery wrapper-side
    // zeroize discipline: the bridge's create_vault wraps password into
    // SecretBytes (which zeroizes on drop). This Vec is a transient
    // cleartext residue on the wrapper's heap; zero it explicitly so we
    // don't leave the password lingering after the call returns.
    let result = secretary_ffi_bridge::create_vault(&password, display_name, created_at_ms);
    password.zeroize();
    let bridge_out = result.map_err(ffi_unlock_error_to_pyerr)?;

    let secretary_ffi_bridge::CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity,
        mnemonic,
    } = bridge_out;

    Ok(CreateVaultOutput {
        vault_toml_bytes,
        identity_bundle_bytes,
        identity: Some(UnlockedIdentity(identity)),
        mnemonic: Some(MnemonicOutput(mnemonic)),
    })
}

// ---------------------------------------------------------------------------
// B.4a: open_vault_with_password + open_vault_with_recovery entry points.
// ---------------------------------------------------------------------------

/// Open a vault folder using its master password (B.4a).
///
/// Reads `vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`, and
/// the owner contact card from `folder` via `core::vault::open_vault`.
/// Returns an `OpenVaultOutput` with two take-once handles: `identity`
/// (live `UnlockedIdentity`) and `manifest` (read-only `OpenVaultManifest`).
///
/// # Caller zeroize
///
/// `password` is owned bytes (`Vec<u8>`); the bridge wraps it in
/// `SecretBytes` (zeroize-on-drop). The wrapper here additionally zeroizes
/// the wrapper-side `Vec<u8>` after the bridge call returns. The foreign
/// caller's input buffer (e.g. a Python `bytearray`) is the foreign side's
/// responsibility — wipe it after the call returns.
///
/// # Raises
///
/// - `VaultWrongPasswordOrCorrupt` — password is wrong, or vault data
///   integrity failure (anti-oracle conflation).
/// - `VaultMismatchFolder` — `vault.toml` and `identity.bundle.enc`
///   reference different vaults.
/// - `VaultCorruptVault` — manifest decode / verification / cross-check
///   failed post-unlock.
/// - `VaultFolderInvalid` — folder doesn't exist, isn't readable, or is
///   missing one of the four required files.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
fn open_vault_with_password(
    folder: std::path::PathBuf,
    mut password: Vec<u8>,
) -> PyResult<OpenVaultOutput> {
    let result = secretary_ffi_bridge::open_vault_with_password(&folder, &password)
        .map_err(ffi_vault_error_to_pyerr);
    password.zeroize();
    let bridge_out = result?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput {
        identity: Some(UnlockedIdentity(identity)),
        manifest: Some(OpenVaultManifest(manifest)),
    })
}

/// Open a vault folder using its 24-word BIP-39 recovery phrase (B.4a).
///
/// Reads the same set of files as `open_vault_with_password`. The
/// `mnemonic` input is UTF-8-encoded bytes; the bridge surfaces
/// malformed-UTF-8 as `VaultInvalidMnemonic` with `detail` =
/// `"phrase contained invalid UTF-8"` — parallel to B.3a's
/// `open_with_recovery`.
///
/// # Caller zeroize
///
/// `mnemonic` is owned bytes; the wrapper zeroizes them after the
/// bridge call returns. The foreign caller's input buffer is the foreign
/// side's responsibility.
///
/// # Raises
///
/// - `VaultWrongMnemonicOrCorrupt` — phrase is wrong, or vault data
///   integrity failure (anti-oracle conflation).
/// - `VaultInvalidMnemonic` — phrase failed BIP-39 validation BEFORE any
///   decryption was attempted (wrong word count, unknown word, bad
///   checksum, or invalid UTF-8 input).
/// - `VaultMismatchFolder` — `vault.toml` and `identity.bundle.enc`
///   reference different vaults.
/// - `VaultCorruptVault` — manifest decode / verification / cross-check
///   failed post-unlock.
/// - `VaultFolderInvalid` — folder doesn't exist, isn't readable, or is
///   missing one of the four required files.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required for zeroize discipline
fn open_vault_with_recovery(
    folder: std::path::PathBuf,
    mut mnemonic: Vec<u8>,
) -> PyResult<OpenVaultOutput> {
    let result = secretary_ffi_bridge::open_vault_with_recovery(&folder, &mnemonic)
        .map_err(ffi_vault_error_to_pyerr);
    mnemonic.zeroize();
    let bridge_out = result?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput {
        identity: Some(UnlockedIdentity(identity)),
        manifest: Some(OpenVaultManifest(manifest)),
    })
}

/// `#[pymodule]` entrypoint. The function name (`secretary_ffi_py`) is the
/// Python module name that `import` looks up; it must match the wheel name
/// declared in `pyproject.toml` (`[tool.maturin] module-name`).
#[pymodule]
fn secretary_ffi_py(py: Python<'_>, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Existing B.1 surface:
    m.add_function(wrap_pyfunction!(add, m)?)?;
    m.add_function(wrap_pyfunction!(version_py, m)?)?;

    // B.2 surface:
    m.add_class::<UnlockedIdentity>()?;
    m.add_function(wrap_pyfunction!(open_with_password, m)?)?;
    m.add(
        "WrongPasswordOrCorrupt",
        py.get_type::<WrongPasswordOrCorrupt>(),
    )?;
    m.add("VaultMismatch", py.get_type::<VaultMismatch>())?;
    m.add("CorruptVault", py.get_type::<CorruptVault>())?;

    // B.3a surface:
    m.add_function(wrap_pyfunction!(open_with_recovery, m)?)?;
    m.add(
        "WrongMnemonicOrCorrupt",
        py.get_type::<WrongMnemonicOrCorrupt>(),
    )?;
    m.add("InvalidMnemonic", py.get_type::<InvalidMnemonic>())?;

    // B.3b surface:
    m.add_class::<CreateVaultOutput>()?;
    m.add_class::<MnemonicOutput>()?;
    m.add_function(wrap_pyfunction!(create_vault, m)?)?;

    // B.4a surface:
    m.add_class::<BlockSummary>()?;
    m.add_class::<OpenVaultManifest>()?;
    m.add_class::<OpenVaultOutput>()?;
    m.add_function(wrap_pyfunction!(open_vault_with_password, m)?)?;
    m.add_function(wrap_pyfunction!(open_vault_with_recovery, m)?)?;
    m.add(
        "VaultWrongPasswordOrCorrupt",
        py.get_type::<VaultWrongPasswordOrCorrupt>(),
    )?;
    m.add(
        "VaultWrongMnemonicOrCorrupt",
        py.get_type::<VaultWrongMnemonicOrCorrupt>(),
    )?;
    m.add(
        "VaultInvalidMnemonic",
        py.get_type::<VaultInvalidMnemonic>(),
    )?;
    m.add("VaultMismatchFolder", py.get_type::<VaultMismatchFolder>())?;
    m.add("VaultCorruptVault", py.get_type::<VaultCorruptVault>())?;
    m.add("VaultFolderInvalid", py.get_type::<VaultFolderInvalid>())?;

    // B.4b surface:
    m.add_class::<FieldHandle>()?;
    m.add_class::<Record>()?;
    m.add_class::<BlockReadOutput>()?;
    m.add_function(wrap_pyfunction!(read_block, m)?)?;
    m.add("VaultBlockNotFound", py.get_type::<VaultBlockNotFound>())?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_format_version() {
        assert_eq!(version(), secretary_core::version::FORMAT_VERSION);
    }

    #[test]
    fn add_returns_arithmetic_sum() {
        assert_eq!(add(2, 3), 5);
    }

    #[test]
    fn add_wraps_on_overflow() {
        // Pin the wrapping contract: u32::MAX + 1 wraps to 0. A future
        // change to checked_add / saturating_add (or a switch to PyResult
        // ergonomics in B.2) is a deliberate test failure rather than a
        // silent contract change.
        assert_eq!(add(u32::MAX, 1), 0);
    }
}
