//! Canonical constants for the desktop app. Every value is documented with
//! its rationale; the spec §8 "Constants" table is the canonical source —
//! this file mirrors it verbatim.
//!
//! NO MAGIC NUMBERS POLICY: every value the desktop app uses that isn't
//! self-explanatory (e.g. 0, 1, 2 for indexing) lives here with a name.
//!
//! See: docs/superpowers/specs/2026-05-27-d11-tauri-walking-skeleton-design.md §8

use sha2::{Digest, Sha256};

// =============================================================================
// Auto-lock timing
// =============================================================================

/// Default auto-lock timeout in milliseconds. Used when no settings record
/// exists in the vault (first-unlock or default-only users).
///
/// **Value:** 600_000 (10 minutes).
/// **Rationale:** Matches 1Password (10 min default), Bitwarden (15 min).
/// Long enough to not annoy; short enough that "I walked away for lunch"
/// leaves the vault locked.
pub const AUTO_LOCK_DEFAULT_MS: u64 = 600_000;

/// Lower bound for `auto_lock_timeout_ms` settings validation.
///
/// **Value:** 60_000 (1 minute).
/// **Rationale:** Below this, re-prompts become tedious for the user with no
/// security gain — a 30-second adversary window vs 60-second isn't materially
/// different in a physical-access threat model.
pub const AUTO_LOCK_MIN_MS: u64 = 60_000;

/// Upper bound for `auto_lock_timeout_ms` settings validation.
///
/// **Value:** 86_400_000 (24 hours).
/// **Rationale:** Anything longer is effectively "never auto-lock" —
/// security antipattern we won't ship as configurable.
pub const AUTO_LOCK_MAX_MS: u64 = 86_400_000;

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
// Consumer lands in Task 5 (auto-lock timer thread) / Task 6 (frontend
// debounce). Allowed dead at this Task-2 checkpoint by design — the
// constants module ships ahead of its consumers per the plan.
#[allow(dead_code)]
pub const ACTIVITY_NOTIFY_MIN_INTERVAL_MS: u64 = 2_000;

// =============================================================================
// Settings record schema
// =============================================================================

/// Reserved block name for the secretary-app settings record.
///
/// **Value:** `"__secretary_app_settings__"`.
/// **Rationale:** Double-underscore prefix/suffix marks "internal"; unlikely
/// to collide with user-created block names.
pub const SETTINGS_BLOCK_NAME: &str = "__secretary_app_settings__";

/// Versioned record_type string for the settings record.
///
/// **Value:** `"secretary.settings.v1"`.
/// **Rationale:** Versioned. Future schema migrations get `v2`. Forward-compat:
/// unknown version on load falls back to `Settings::default()` + warning.
pub const SETTINGS_RECORD_TYPE: &str = "secretary.settings.v1";

/// Field name for the auto-lock timeout setting.
///
/// **Value:** `"auto_lock_timeout_ms"`.
/// **Rationale:** Snake-case matches Rust convention; matches the constant
/// name `AUTO_LOCK_DEFAULT_MS` for grep-ability.
pub const SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS: &str = "auto_lock_timeout_ms";

// =============================================================================
// Deterministic UUID derivation (for the settings block and record)
// =============================================================================

/// Number of bytes consumed from the front of a SHA-256 digest to form the
/// deterministic 16-byte UUID. The vault format uses 128-bit UUIDs; SHA-256
/// produces 256 bits so we discard the high half.
const UUID_BYTE_LEN: usize = 16;

/// Compute the deterministic 16-byte UUID for a vault-internal block name
/// or record_type string, via `SHA-256(input)[0..16]`.
///
/// Used for the settings block and the settings record so that two devices
/// creating the same block independently produce identical UUIDs — the CRDT
/// merge layer then treats their writes as concurrent updates of one block
/// rather than two separate blocks. See spec §8 for the full rationale.
pub fn deterministic_uuid_16(input: &str) -> [u8; UUID_BYTE_LEN] {
    let hash = Sha256::digest(input.as_bytes());
    let mut out = [0u8; UUID_BYTE_LEN];
    out.copy_from_slice(&hash[0..UUID_BYTE_LEN]);
    out
}

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
}
