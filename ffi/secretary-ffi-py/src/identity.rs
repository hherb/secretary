//! [`UnlockedIdentity`] pyclass — thin newtype around the bridge crate's
//! `secretary_ffi_bridge::UnlockedIdentity`. Shared by every entry point
//! that produces or consumes a live identity (B.2 / B.3a / B.3b bytes-in,
//! B.4a folder-in, B.4b read, B.4c save, B.4d share).

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyType};

/// Opaque Python-side handle to a successfully-unlocked vault identity.
/// Newtype around `secretary_ffi_bridge::UnlockedIdentity`; methods are
/// thin forwarders. Implements the context-manager protocol so the
/// idiomatic usage is `with open_with_password(...) as id: ...`.
#[pyclass]
pub struct UnlockedIdentity(pub(crate) secretary_ffi_bridge::UnlockedIdentity);

#[pymethods]
impl UnlockedIdentity {
    /// Whether this handle has been closed/wiped. Call before acting on
    /// `user_uuid()` / `display_name()`, which return safe defaults on a
    /// wiped handle (#362).
    fn is_wiped(&self) -> bool {
        self.0.is_wiped()
    }

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
    pub(crate) fn close(&self) {
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
