//! uniffi-side `Settings` value type mirroring the bridge `Settings`. Pure
//! data; the namespace fns convert to/from the bridge type. Field
//! names/shapes match `secretary.udl`'s `Settings` dictionary exactly.

/// App settings persisted in the vault (uniffi projection of the bridge
/// `Settings`). Passed by value both ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
    pub retention_window_ms: u64,
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

impl From<Settings> for secretary_ffi_bridge::Settings {
    fn from(s: Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
            require_password_before_edits: s.require_password_before_edits,
            reauth_grace_window_ms: s.reauth_grace_window_ms,
            retention_window_ms: s.retention_window_ms,
        }
    }
}
