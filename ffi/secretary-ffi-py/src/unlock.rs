//! Bytes-in unlock / create entry points (B.2 / B.3a / B.3b).
//!
//! Three pyfunctions ([`open_with_password`], [`open_with_recovery`],
//! [`create_vault`]) and two opaque handles ([`MnemonicOutput`] +
//! [`CreateVaultOutput`]). Both `UnlockedIdentity` (used by all three
//! pyfunctions) and the error translators live in sibling modules.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use zeroize::Zeroize;

use crate::errors::{ffi_unlock_error_to_pyerr, ffi_vault_error_to_pyerr};
use crate::identity::UnlockedIdentity;

/// Opaque Python-side handle to a one-shot recovery mnemonic. Newtype
/// around `secretary_ffi_bridge::MnemonicOutput`; methods are thin
/// forwarders. Implements the context-manager protocol so the idiomatic
/// usage is `with output.mnemonic as mn: phrase = mn.take_phrase()`.
///
/// `take_phrase()` returns `bytes` once; subsequent calls return `None`.
/// `close()` (and the equivalent context-manager `__exit__`) is
/// idempotent and wipes any still-resident phrase from Rust-side memory.
#[pyclass]
pub struct MnemonicOutput(pub(crate) secretary_ffi_bridge::MnemonicOutput);

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
pub(crate) fn open_with_password(
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
pub(crate) fn open_with_recovery(
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
pub(crate) fn create_vault(
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

/// Create a fresh v1 vault on disk in an existing empty `folder` and return
/// the one-shot recovery `MnemonicOutput`. Writes all four canonical files
/// via the bridge's folder-writing path; the caller re-opens with
/// `open_vault_with_password` to browse (no auto-open). Bridge hardcodes
/// `OsRng` + `Argon2idParams::V1_DEFAULT`.
///
/// Raises `VaultFolderNotEmpty` if the directory is non-empty,
/// `VaultFolderInvalid` if it is missing / unreadable, `VaultCorruptVault`
/// on rare crypto failure.
#[pyfunction]
pub(crate) fn create_vault_in_folder(
    folder: std::path::PathBuf,
    mut password: Vec<u8>,
    display_name: &str,
    created_at_ms: u64,
) -> PyResult<MnemonicOutput> {
    // Mirrors create_vault's wrapper-side zeroize discipline: the bridge
    // wraps password into SecretBytes; this Vec is the projection-side
    // cleartext transient. Zero it whether the call succeeds or fails.
    let result = secretary_ffi_bridge::create_vault_in_folder(
        &folder,
        &password,
        display_name,
        created_at_ms,
    );
    password.zeroize();
    let mnemonic = result.map_err(ffi_vault_error_to_pyerr)?;
    Ok(MnemonicOutput(mnemonic))
}
