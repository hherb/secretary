//! Settings entry points: `read_settings` (returns a `Settings`; load
//! warnings dropped — no python consumer needs them) + `write_settings`.
//! `Settings` is both input and output, so it carries a `#[new]` and
//! `set_all` (unlike the output-only retention DTOs).

use pyo3::prelude::*;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::vault::OpenVaultManifest;

/// App settings persisted in the vault. Constructible from Python (for
/// `write_settings`) and returned by `read_settings`.
///
/// `skip_from_py_object` opts out of PyO3's (now-deprecated) auto-derived
/// `FromPyObject` for `Clone`-able pyclasses: `Settings` is always passed
/// as `&Settings` (a pyclass ref) into `write_settings`, never extracted
/// by value, so the derive would be dead weight —
/// [[project_secretary_pyo3_028_fromtopyobject_deprecation]].
#[pyclass(get_all, set_all, skip_from_py_object)]
#[derive(Clone)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
    pub retention_window_ms: u64,
}

#[pymethods]
impl Settings {
    #[new]
    fn new(
        auto_lock_timeout_ms: u64,
        require_password_before_edits: bool,
        reauth_grace_window_ms: u64,
        retention_window_ms: u64,
    ) -> Self {
        Self {
            auto_lock_timeout_ms,
            require_password_before_edits,
            reauth_grace_window_ms,
            retention_window_ms,
        }
    }
}

impl From<secretary_ffi_bridge::Settings> for Settings {
    fn from(s: secretary_ffi_bridge::Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
            retention_window_ms: s.retention_window_ms,
        }
    }
}

impl From<&Settings> for secretary_ffi_bridge::Settings {
    fn from(s: &Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
            retention_window_ms: s.retention_window_ms,
        }
    }
}

/// Read the vault settings record. Load warnings are not surfaced.
#[pyfunction]
pub(crate) fn read_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> PyResult<Settings> {
    secretary_ffi_bridge::read_settings(&identity.0, &manifest.0)
        .map(|(s, _warnings)| Settings::from(s))
        .map_err(ffi_vault_error_to_pyerr)
}

/// Persist the vault settings record. `device_uuid` must be 16 bytes; the
/// settings must be in range (else `ValueError`).
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn write_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    settings: &Settings,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    let bridge_settings = secretary_ffi_bridge::Settings::from(settings);
    secretary_ffi_bridge::validate_save_settings(&bridge_settings).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "settings out of range: [{}, {}]",
            e.min, e.max
        ))
    })?;
    secretary_ffi_bridge::write_settings(
        &identity.0,
        &manifest.0,
        &bridge_settings,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}
