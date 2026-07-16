//! Canonical constants for the desktop app. Every value is documented with
//! its rationale; the spec §8 "Constants" table is the canonical source —
//! this file mirrors it verbatim.
//!
//! NO MAGIC NUMBERS POLICY: every value the desktop app uses that isn't
//! self-explanatory (e.g. 0, 1, 2 for indexing) lives here with a name.
//!
//! See: docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md §8
//!
//! The settings-record schema (`SETTINGS_*` names, the `AUTO_LOCK_*` /
//! `REAUTH_WINDOW_*` / `RETENTION_WINDOW_*` bounds, `REQUIRE_PASSWORD_DEFAULT`,
//! `MS_PER_DAY`, and `deterministic_uuid_16`) moved to
//! `secretary_ffi_bridge` (Task 1 of the mobile-vault-settings epic) so
//! desktop and mobile share one Rust definition of the on-disk schema —
//! re-exported below rather than redefined.

pub use secretary_ffi_bridge::{
    deterministic_uuid_16, AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS, MS_PER_DAY,
    REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS, REQUIRE_PASSWORD_DEFAULT,
    RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MAX_MS, RETENTION_WINDOW_MIN_MS,
    SETTINGS_BLOCK_NAME, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
    SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS, SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
    SETTINGS_FIELD_RETENTION_WINDOW_MS, SETTINGS_RECORD_TYPE,
};

// =============================================================================
// Auto-lock timing
// =============================================================================

/// Tick interval for the auto-lock timer thread.
///
/// **Value:** 5_000 (5 seconds).
/// **Rationale:** Coarse enough to be free of measurable CPU cost; fine
/// enough that auto-lock fires within 5s of the threshold expiring
/// (acceptable jitter vs the 1-minute minimum threshold).
pub const AUTO_LOCK_TICK_MS: u64 = 5_000;

/// Minimum interval between frontend `notify_activity` IPC calls (debounce).
///
/// **Value:** 2_000 (2 seconds).
/// **Rationale:** Each mousemove during typing shouldn't issue an IPC; 2s
/// is well below any plausible threshold so the timer never spuriously fires
/// while the user is active.
///
/// Shared with `desktop/src/lib/auto_lock.ts::ACTIVITY_NOTIFY_MIN_INTERVAL_MS` —
/// change both together.
pub const ACTIVITY_NOTIFY_MIN_INTERVAL_MS: u64 = 2_000;

// =============================================================================
// Desktop-local presence (biometric) preference (#277)
// =============================================================================

/// Subdirectory under `<data_dir>/secretary-desktop/` holding per-vault
/// presence (biometric) preference files, named `<vault_uuid_hex>.json`.
/// Sibling of the existing `devices/` subtree.
pub const PRESENCE_PREF_SUBDIR: &str = "presence";

/// Default: biometric re-auth is used when hardware is available. A fresh
/// vault (no pref file) opts in; the user disables it explicitly (e.g. before
/// travelling through a high-risk area).
pub const PRESENCE_BIOMETRIC_ENABLED_DEFAULT: bool = true;

#[cfg(test)]
mod tests {
    use super::*;

    /// Frozen hex prefix of `SHA-256("__secretary_app_settings__")`.
    /// Drift = vault-format break risk; see `settings_block_uuid_is_deterministic_and_frozen`.
    const FROZEN_SETTINGS_BLOCK_UUID_HEX: &str = "04fcc7aa05345f631e7f1ce2db78ba9a";

    /// Frozen hex prefix of `SHA-256("secretary.settings.v1")`.
    /// Drift = vault-format break risk; see `settings_record_uuid_is_deterministic_and_frozen`.
    const FROZEN_SETTINGS_RECORD_UUID_HEX: &str = "4145cb7a4531f1ac41af6717e205e1a9";

    // Sanity: ensure constant relationships hold. These are
    // compile-time-known so we use const blocks — clippy correctly
    // flags `assert!` on compile-time constants as not a runtime test.
    // The const-block form upgrades the check to a compile error if the
    // relationship is ever violated.
    #[test]
    fn auto_lock_bounds_are_ordered() {
        const _: () = assert!(AUTO_LOCK_MIN_MS < AUTO_LOCK_DEFAULT_MS);
        const _: () = assert!(AUTO_LOCK_DEFAULT_MS < AUTO_LOCK_MAX_MS);
    }

    #[test]
    fn tick_interval_smaller_than_min_threshold() {
        // Otherwise auto-lock can never fire within the user's chosen
        // threshold — spec §6 invariant.
        const _: () = assert!(AUTO_LOCK_TICK_MS < AUTO_LOCK_MIN_MS);
    }

    #[test]
    fn settings_block_uuid_is_deterministic_and_frozen() {
        // Frozen-string test: if this assertion ever fails, the on-disk
        // settings-block UUID has drifted from what shipped clients expect.
        // That's a vault-format break — investigate before changing.
        let uuid = deterministic_uuid_16(SETTINGS_BLOCK_NAME);
        assert_eq!(
            hex::encode(uuid),
            FROZEN_SETTINGS_BLOCK_UUID_HEX,
            "settings block UUID drift — vault-format break risk"
        );
    }

    #[test]
    fn settings_record_uuid_is_deterministic_and_frozen() {
        let uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);
        assert_eq!(
            hex::encode(uuid),
            FROZEN_SETTINGS_RECORD_UUID_HEX,
            "settings record UUID drift — vault-format break risk"
        );
    }

    #[test]
    fn reauth_window_bounds_are_ordered() {
        const _: () = assert!(REAUTH_WINDOW_MIN_MS < REAUTH_WINDOW_DEFAULT_MS);
        const _: () = assert!(REAUTH_WINDOW_DEFAULT_MS < REAUTH_WINDOW_MAX_MS);
    }

    #[test]
    fn reauth_default_is_two_minutes() {
        const TWO_MINUTES_MS: u64 = 2 * 60 * 1_000;
        assert_eq!(REAUTH_WINDOW_DEFAULT_MS, TWO_MINUTES_MS);
    }

    #[test]
    fn retention_window_bounds_are_ordered() {
        const _: () = assert!(RETENTION_WINDOW_MIN_MS < RETENTION_WINDOW_DEFAULT_MS);
        const _: () = assert!(RETENTION_WINDOW_DEFAULT_MS < RETENTION_WINDOW_MAX_MS);
    }

    #[test]
    fn reauth_field_names_are_snake_case_and_distinct() {
        assert_eq!(
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
            "require_password_before_edits"
        );
        assert_eq!(
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS,
            "reauth_grace_window_ms"
        );
        assert_ne!(
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS
        );
    }
}
