//! The `Settings` value type, its bound constants, and the deterministic
//! block/record UUID derivation. Pure — no I/O, no vault handles. Lifted
//! from `desktop/src-tauri/src/{settings/parse.rs, constants.rs}` so all
//! platforms share one definition of the on-disk settings schema.

/// Block name of the app-settings block (frozen on-disk identifier).
pub const SETTINGS_BLOCK_NAME: &str = "__secretary_app_settings__";
/// Record type discriminator for the settings record (frozen).
pub const SETTINGS_RECORD_TYPE: &str = "secretary.settings.v1";

/// Settings field name: the auto-lock timeout in milliseconds.
pub const SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS: &str = "auto_lock_timeout_ms";
/// Settings field name: the on/off toggle for write re-auth.
pub const SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS: &str = "require_password_before_edits";
/// Settings field name: the write re-auth grace window in milliseconds.
pub const SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS: &str = "reauth_grace_window_ms";
/// Settings field name: the trash retention window in milliseconds.
pub const SETTINGS_FIELD_RETENTION_WINDOW_MS: &str = "retention_window_ms";

/// Milliseconds in one day.
pub const MS_PER_DAY: u64 = 86_400_000;

/// Default trash retention window, in milliseconds (90 d — mirrors core's
/// frozen `DEFAULT_RETENTION_WINDOW_MS` so the default can never drift).
pub const RETENTION_WINDOW_DEFAULT_MS: u64 = secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS;
/// Lower bound for `retention_window_ms` (1 d).
pub const RETENTION_WINDOW_MIN_MS: u64 = MS_PER_DAY;
/// Upper bound for `retention_window_ms` (3650 d / 10 y).
pub const RETENTION_WINDOW_MAX_MS: u64 = 3650 * MS_PER_DAY;

/// Default auto-lock timeout, in milliseconds (10 min).
pub const AUTO_LOCK_DEFAULT_MS: u64 = 600_000;
/// Lower bound for `auto_lock_timeout_ms` (1 min).
pub const AUTO_LOCK_MIN_MS: u64 = 60_000;
/// Upper bound for `auto_lock_timeout_ms` (24 h).
pub const AUTO_LOCK_MAX_MS: u64 = 86_400_000;

/// Default write re-auth grace window, in milliseconds (2 min).
pub const REAUTH_WINDOW_DEFAULT_MS: u64 = 120_000;
/// Lower bound for `reauth_grace_window_ms` (0 — re-auth before every write).
pub const REAUTH_WINDOW_MIN_MS: u64 = 0;
/// Upper bound for `reauth_grace_window_ms` (1 h).
pub const REAUTH_WINDOW_MAX_MS: u64 = 3_600_000;

/// Default for the require-password-before-edits flag (secure by default).
pub const REQUIRE_PASSWORD_DEFAULT: bool = true;

/// Number of bytes taken from the front of a SHA-256 digest to form a
/// 128-bit UUID.
const UUID_BYTE_LEN: usize = 16;

/// Parsed app settings — pure value type, no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    /// Auto-lock timeout in milliseconds. Bounded by [`AUTO_LOCK_MIN_MS`] /
    /// [`AUTO_LOCK_MAX_MS`]; defaults to [`AUTO_LOCK_DEFAULT_MS`].
    pub auto_lock_timeout_ms: u64,
    /// Whether a mutating write requires a fresh password re-auth (subject
    /// to [`reauth_grace_window_ms`](Settings::reauth_grace_window_ms)).
    /// Defaults to [`REQUIRE_PASSWORD_DEFAULT`].
    pub require_password_before_edits: bool,
    /// Grace window, in milliseconds, during which one successful write
    /// re-auth covers subsequent mutating writes. Bounded by
    /// [`REAUTH_WINDOW_MIN_MS`] / [`REAUTH_WINDOW_MAX_MS`]; defaults to
    /// [`REAUTH_WINDOW_DEFAULT_MS`].
    pub reauth_grace_window_ms: u64,
    /// Trash retention window in milliseconds — trashed blocks older than
    /// this are eligible for auto-purge. Bounded by
    /// [`RETENTION_WINDOW_MIN_MS`] / [`RETENTION_WINDOW_MAX_MS`]; defaults
    /// to [`RETENTION_WINDOW_DEFAULT_MS`].
    pub retention_window_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
            require_password_before_edits: REQUIRE_PASSWORD_DEFAULT,
            reauth_grace_window_ms: REAUTH_WINDOW_DEFAULT_MS,
            retention_window_ms: RETENTION_WINDOW_DEFAULT_MS,
        }
    }
}

/// Deterministic 16-byte UUID for a vault-internal name/record_type via
/// `SHA-256(input)[0..16]`. Two clients minting the same block independently
/// produce identical UUIDs, so the CRDT layer treats them as concurrent
/// updates of one block. Reuses core's `sha256` (no extra dependency).
pub fn deterministic_uuid_16(input: &str) -> [u8; UUID_BYTE_LEN] {
    let hash = secretary_core::crypto::hash::sha256(input.as_bytes());
    let mut out = [0u8; UUID_BYTE_LEN];
    out.copy_from_slice(&hash[0..UUID_BYTE_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_matches_constants() {
        let d = Settings::default();
        assert_eq!(d.auto_lock_timeout_ms, AUTO_LOCK_DEFAULT_MS);
        assert_eq!(d.require_password_before_edits, REQUIRE_PASSWORD_DEFAULT);
        assert_eq!(d.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
        assert_eq!(d.retention_window_ms, RETENTION_WINDOW_DEFAULT_MS);
    }

    #[test]
    fn deterministic_uuid_is_sha256_prefix_and_stable() {
        let a = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
        let b = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
        assert_eq!(a, b, "same input → same uuid");
        let full = secretary_core::crypto::hash::sha256(SETTINGS_BLOCK_NAME.as_bytes());
        assert_eq!(a, full[0..16], "uuid is the 16-byte SHA-256 prefix");
        assert_ne!(
            deterministic_uuid_16(SETTINGS_BLOCK_NAME),
            deterministic_uuid_16(SETTINGS_RECORD_TYPE),
            "distinct inputs → distinct uuids"
        );
    }

    #[test]
    fn retention_default_equals_core_frozen_value() {
        assert_eq!(
            RETENTION_WINDOW_DEFAULT_MS,
            secretary_core::vault::DEFAULT_RETENTION_WINDOW_MS
        );
    }

    // Compile-time bound ordering (mirrors desktop's const-asserts).
    const _: () = assert!(RETENTION_WINDOW_MIN_MS < RETENTION_WINDOW_DEFAULT_MS);
    const _: () = assert!(RETENTION_WINDOW_DEFAULT_MS < RETENTION_WINDOW_MAX_MS);
    const _: () = assert!(REAUTH_WINDOW_MIN_MS < REAUTH_WINDOW_DEFAULT_MS);
    const _: () = assert!(REAUTH_WINDOW_DEFAULT_MS < REAUTH_WINDOW_MAX_MS);
    const _: () = assert!(AUTO_LOCK_MIN_MS < AUTO_LOCK_DEFAULT_MS);
    const _: () = assert!(AUTO_LOCK_DEFAULT_MS < AUTO_LOCK_MAX_MS);
}
