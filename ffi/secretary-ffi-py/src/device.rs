//! Device-slot folder-in entry points (ADR 0009 / B.2):
//! [`add_device_slot`], [`open_with_device_secret`], [`remove_device_slot`]
//! and the one-shot [`DeviceSecretOutput`] handle.
//!
//! # Design
//!
//! Mirrors [`crate::unlock::MnemonicOutput`] exactly: the `SecretBytes`
//! wrapping the 32-byte device secret lives Rust-side inside a
//! `Mutex<Option<SecretBytes>>` (via the bridge crate's
//! `secretary_ffi_bridge::DeviceSecretOutput`); the Python handle exposes a
//! one-shot [`DeviceSecretOutput::take_secret`] accessor that copies the
//! bytes into a fresh caller-owned `PyBytes`, then drops the inner
//! `SecretBytes` so its `ZeroizeOnDrop` impl fires.
//!
//! # Zeroize discipline
//!
//! - `password` / `device_secret` are owned `Vec<u8>` inputs; the wrapper
//!   moves each into a wrapper type — `SecretBytes` for `password`, or a
//!   `Sensitive<[u8; 32]>` built via `array32_into_or_value_error` for the
//!   `device_secret` array — immediately at function entry, before any
//!   validation runs. `Drop` then covers the wipe on every exit path,
//!   including an unwinding panic inside the bridge call (#513), rather
//!   than relying on a trailing `.zeroize()` statement control flow could
//!   skip. This matches the `open_with_password` / `open_vault_with_password`
//!   patterns in [`crate::unlock`] and [`crate::vault`].
//! - For `open_with_device_secret` this also structurally prevents a bug
//!   class the function used to carry: reading `device_secret.len()` for
//!   a `ValueError` message AFTER a manual `.zeroize()` call always
//!   reported "got 0", since `Vec::zeroize()` clears the vector. With no
//!   manual wipe preceding any read, that ordering mistake cannot recur.
//!
//! # Context-manager protocol
//!
//! [`DeviceSecretOutput`] implements `__enter__` / `__exit__` so the
//! idiomatic Python usage is `with out.device_secret as s: bytes = s.take_secret()`.
//! `__exit__` calls `wipe()` / `close()` and returns `False` so exceptions
//! propagate.

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};
use secretary_core::crypto::secret::{SecretBytes, Sensitive};

use crate::errors::{array32_into_or_value_error, ffi_vault_error_to_pyerr};
use crate::identity::UnlockedIdentity;
use crate::vault::{OpenVaultManifest, OpenVaultOutput};

/// Opaque Python-side handle to a one-shot device secret. Newtype around
/// `secretary_ffi_bridge::DeviceSecretOutput`; methods are thin forwarders.
/// Implements the context-manager protocol so the idiomatic usage is
/// `with out.device_secret as s: secret_bytes = s.take_secret()`.
///
/// `take_secret()` returns `bytes` once; subsequent calls return `None`.
/// `close()` (and the equivalent context-manager `__exit__`) is idempotent
/// and wipes any still-resident secret from Rust-side memory.
#[pyclass]
pub struct DeviceSecretOutput(pub(crate) secretary_ffi_bridge::DeviceSecretOutput);

#[pymethods]
impl DeviceSecretOutput {
    /// Take the device secret as `bytes`. ONE-SHOT — second call returns
    /// `None`. The returned `bytes` is fresh caller-owned heap; the caller
    /// is responsible for zeroizing it after delivering it to the Secure
    /// Enclave / biometric release layer.
    fn take_secret<'py>(&self, py: Python<'py>) -> Option<Bound<'py, PyBytes>> {
        self.0.take_secret().map(|v| {
            // PyBytes::new copies into Python-owned memory, but it also
            // documents "Panics if out of memory" (pyo3 0.29
            // src/types/bytes.rs:76) — a genuine unwinding panic between a
            // fill and a trailing `.zeroize()` that the old shape left
            // open (#513). Wrapping BEFORE the call means `Drop` covers
            // the wipe on every exit path, panic included.
            let v = SecretBytes::new(v);
            PyBytes::new(py, v.expose())
        })
    }

    /// Drop any still-resident inner secret now, zeroizing its
    /// `SecretBytes` field. Idempotent.
    fn close(&self) {
        self.0.wipe();
    }

    /// Context-manager `__enter__`. Returns `self` so
    /// `with out.device_secret as s` binds the handle.
    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    /// Context-manager `__exit__`. Calls `close()` and returns `False`
    /// so any exception raised inside the `with`-block propagates after
    /// close runs. Mirrors the exit pattern on `MnemonicOutput`.
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

/// Output of `add_device_slot`. Holds the 16-byte device UUID plus the
/// one-shot opaque `DeviceSecretOutput` handle.
///
/// The `device_secret` getter is DESTRUCTIVE — the first access MOVES the
/// handle out of the parent struct and every subsequent access raises
/// `RuntimeError`. Same take-once semantics as `CreateVaultOutput.mnemonic`
/// and `OpenVaultOutput.identity`.
#[pyclass]
pub struct DeviceEnrollOutput {
    /// 16-byte device UUID (non-secret; this is the filename stem under
    /// `devices/<uuid>.wrap`).
    pub(crate) device_uuid: Vec<u8>,
    /// One-shot opaque handle for the freshly-generated 32-byte device
    /// secret. Wrapped in `Option` so the getter can move it out exactly
    /// once (via `Option::take()`); after that the field is `None` and
    /// subsequent calls raise `RuntimeError`.
    pub(crate) device_secret: Option<DeviceSecretOutput>,
}

#[pymethods]
impl DeviceEnrollOutput {
    /// The 16-byte device UUID. Non-secret; returns a fresh `bytes` object
    /// each call (PyO3 copies from the underlying `Vec<u8>`).
    #[getter]
    fn device_uuid<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.device_uuid)
    }

    /// Take ownership of the one-shot `DeviceSecretOutput` handle. ONE-SHOT —
    /// the first read MOVES the handle out of the parent struct, and every
    /// subsequent read raises `RuntimeError`. Despite the `#[getter]` shape
    /// (Python sees a property), this access is *destructive*; do not call it
    /// from debug introspection paths and then try to reuse the handle.
    ///
    /// The Python idiom is to bind the property directly to a `with` block:
    /// `with out.device_secret as s: bytes = s.take_secret()`.
    #[getter]
    fn device_secret(&mut self) -> PyResult<DeviceSecretOutput> {
        self.device_secret.take().ok_or_else(|| {
            pyo3::exceptions::PyRuntimeError::new_err(
                "DeviceEnrollOutput.device_secret already taken (one-shot)",
            )
        })
    }
}

/// Enroll a new per-device wrap slot using the vault's master password (ADR 0009 / B.2).
///
/// Reads `vault.toml` and `identity.bundle.enc` from `folder_path`,
/// recovers the IBK using `password`, generates a fresh 16-byte device UUID
/// and 32-byte device secret, wraps the IBK under the derived device KEK,
/// and writes `devices/<uuid>.wrap` atomically.
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes
///   (accepted as `Vec<u8>` for symmetry with the other folder-in
///   pyfunctions; `ValueError` on non-UTF-8 input).
/// - `password` — master password as raw bytes (owned; zeroized after the
///   bridge call returns on all paths).
///
/// # Returns
///
/// `DeviceEnrollOutput` with:
/// - `device_uuid` (16 bytes, non-secret).
/// - `device_secret` (one-shot `DeviceSecretOutput` handle — call
///   `take_secret()` once, deliver to the Secure Enclave, then zeroize
///   your copy).
///
/// # Raises
///
/// - `VaultWrongPasswordOrCorrupt` — bad password or corrupt vault files.
/// - `VaultFolderInvalid` — folder doesn't exist or is missing required files.
/// - `ValueError` — `folder_path` is not valid UTF-8.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required to move into SecretBytes
pub(crate) fn add_device_slot(
    folder_path: &[u8],
    password: Vec<u8>,
) -> PyResult<DeviceEnrollOutput> {
    // Wrapped immediately so `Drop` covers the wipe on every exit path,
    // including an unwinding panic inside the bridge call (#513).
    let password = SecretBytes::new(password);

    let folder_str = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8"))?;
    let folder = std::path::Path::new(folder_str);

    let bridge_out = secretary_ffi_bridge::add_device_slot(folder, password.expose())
        .map_err(ffi_vault_error_to_pyerr)?;

    Ok(DeviceEnrollOutput {
        device_uuid: bridge_out.device_uuid,
        device_secret: Some(DeviceSecretOutput(bridge_out.device_secret)),
    })
}

/// Open a vault folder using a per-device secret (ADR 0009 / B.2).
///
/// Reads `vault.toml`, `identity.bundle.enc`, `devices/<device_uuid>.wrap`,
/// `manifest.cbor.enc`, and the owner contact card from `folder_path` via
/// `core::vault::open_vault`. Returns an `OpenVaultOutput` with two take-once
/// handles: `identity` (live `UnlockedIdentity`) and `manifest`
/// (read-only `OpenVaultManifest`).
///
/// # Length pre-checks
///
/// - `device_uuid` must be exactly 16 bytes → `ValueError` if not.
/// - `device_secret` must be exactly 32 bytes → `ValueError` if not.
///
/// # Caller zeroize
///
/// `device_secret` is owned bytes; the wrapper moves it into a
/// `SecretBytes` at function entry, before either length check runs, and
/// the 32-byte stack copy is built via [`Sensitive::try_build`] +
/// [`array32_into_or_value_error`] rather than a bare `[u8; 32]` +
/// trailing `.zeroize()`. `Drop` therefore covers the wipe of both on
/// every exit path — normal return, an early `ValueError`, or an
/// unwinding panic inside the bridge call (#513) — with no manual
/// `.zeroize()` call anywhere in this function.
///
/// # Raises
///
/// - `VaultDeviceSlotNotFound` — no `devices/<uuid>.wrap` file for this UUID.
/// - `VaultWrongDeviceSecretOrCorrupt` — AEAD tag failure (wrong secret or
///   corruption — indistinguishable by design, anti-oracle property).
/// - `VaultDeviceUuidMismatch` — vault-format §3a relabel integrity check
///   failure.
/// - `VaultFolderInvalid` — folder doesn't exist or is missing required files.
/// - `ValueError` — `folder_path` not valid UTF-8, or UUID / secret wrong length.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // owned Vec<u8> required to move into SecretBytes
pub(crate) fn open_with_device_secret(
    folder_path: &[u8],
    device_uuid: &[u8],
    device_secret: Vec<u8>,
) -> PyResult<OpenVaultOutput> {
    // Wrapped immediately, before any validation, so `Drop` covers the
    // wipe on every exit path. This also structurally retires a bug this
    // function used to carry: a previous version read
    // `device_secret.len()` for the ValueError message AFTER manually
    // zeroizing it (`Vec::zeroize()` calls `self.clear()`), so a
    // wrong-length secret always reported "got 0" regardless of what was
    // actually received. With no manual wipe preceding any read, that
    // ordering mistake cannot recur.
    let device_secret = SecretBytes::new(device_secret);

    if device_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            crate::detail::arg_len("device_uuid", 16, device_uuid.len()),
        ));
    }

    // Same relative position as the original manual length check: after
    // device_uuid, before the folder_path UTF-8 check. The length
    // validation and the array fill happen together here —
    // `array32_into_or_value_error` reports the actual wrong length
    // (never a post-wipe zero) because nothing has zeroized `device_secret`
    // by the time it reads it.
    let secret_arr = Sensitive::try_build([0u8; 32], |slot| {
        array32_into_or_value_error(device_secret.expose(), slot, "device_secret")
    })?;

    let folder_str = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8"))?;
    let folder = std::path::Path::new(folder_str);

    // SAFETY: length checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");

    let bridge_out =
        secretary_ffi_bridge::open_with_device_secret(folder, &uuid_arr, secret_arr.expose())
            .map_err(ffi_vault_error_to_pyerr)?;
    let secretary_ffi_bridge::OpenVaultOutput { identity, manifest } = bridge_out;
    Ok(OpenVaultOutput::from_bridge(
        UnlockedIdentity(identity),
        OpenVaultManifest(manifest),
    ))
}

/// Revoke a device slot by deleting its `devices/<device_uuid>.wrap` file.
///
/// # Inputs
///
/// - `folder_path` — UTF-8 path to the vault directory as raw bytes.
/// - `device_uuid` — the 16-byte device UUID returned by `add_device_slot`.
///   `ValueError` if not exactly 16 bytes.
///
/// # Raises
///
/// - `VaultDeviceSlotNotFound` — no wrap file for this UUID.
/// - `VaultFolderInvalid` — IO failure other than missing file.
/// - `ValueError` — `folder_path` not valid UTF-8, or `device_uuid` wrong length.
#[pyfunction]
pub(crate) fn remove_device_slot(folder_path: &[u8], device_uuid: &[u8]) -> PyResult<()> {
    if device_uuid.len() != 16 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            crate::detail::arg_len("device_uuid", 16, device_uuid.len()),
        ));
    }
    let folder_str = std::str::from_utf8(folder_path)
        .map_err(|_| pyo3::exceptions::PyValueError::new_err("folder_path must be valid UTF-8"))?;
    let folder = std::path::Path::new(folder_str);
    // SAFETY: lengths were checked above; unwrap cannot panic here.
    let uuid_arr: [u8; 16] = device_uuid.try_into().expect("length checked above");
    secretary_ffi_bridge::remove_device_slot(folder, &uuid_arr).map_err(ffi_vault_error_to_pyerr)
}
