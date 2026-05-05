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
use secretary_ffi_bridge::FfiUnlockError;

create_exception!(secretary_ffi_py, WrongPasswordOrCorrupt, PyException);
create_exception!(secretary_ffi_py, VaultMismatch, PyException);
create_exception!(secretary_ffi_py, CorruptVault, PyException);
create_exception!(secretary_ffi_py, WrongMnemonicOrCorrupt, PyException);
create_exception!(secretary_ffi_py, InvalidMnemonic, PyException);

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
    /// exactly this moment. Idempotent.
    fn close(&self) {
        self.0.close();
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
        self.0.close();
        false
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
    use zeroize::Zeroize;
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
    use zeroize::Zeroize;
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
