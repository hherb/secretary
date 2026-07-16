//! Desktop presence proof (macOS Touch ID) — the ONLY crate permitting `unsafe`.
//!
//! Presence proof, NOT a cryptographic binding: `evaluate` returns whether the
//! device owner authenticated with biometry; it never touches vault key
//! material. Password re-entry remains the KEK-knowledge fallback.
//!
//! All unit tests are `cfg(all(test, target_os = "macos"))` — Linux CI
//! compiling this crate with 0 tests is by design, not a coverage gap.

#[cfg(target_os = "macos")]
mod macos;
#[cfg(not(target_os = "macos"))]
mod unsupported;

/// Result of one biometric evaluation. Control-flow, not an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceOutcome {
    /// Biometry succeeded — the write may proceed.
    Authenticated,
    /// User asked for the password path (tapped the sheet's "Use Password").
    Fallback,
    /// Biometry cannot be used right now (unavailable / not enrolled / locked
    /// out / any unmapped error) — the caller must fall back to the password.
    Unavailable,
    /// User cancelled — the write should be aborted.
    Cancelled,
}

/// Whether biometric evaluation can proceed on this machine right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PresenceAvailability {
    /// Hardware present and a biometric is enrolled.
    Available,
    /// Hardware present but no biometric enrolled.
    NotEnrolled,
    /// No usable biometric hardware (or biometry disabled).
    NotAvailable,
    /// This platform has no supported provider (non-macOS in this release).
    Unsupported,
}

// LAError codes we map explicitly (Apple `LAError.Code`, stable ABI integers).
// Named to avoid magic numbers; values from the LocalAuthentication headers.
#[cfg(target_os = "macos")]
const LA_ERROR_USER_CANCEL: i64 = -2;
#[cfg(target_os = "macos")]
const LA_ERROR_USER_FALLBACK: i64 = -3;
#[cfg(target_os = "macos")]
const LA_ERROR_SYSTEM_CANCEL: i64 = -4;
#[cfg(target_os = "macos")]
const LA_ERROR_BIOMETRY_NOT_AVAILABLE: i64 = -6;
#[cfg(target_os = "macos")]
const LA_ERROR_BIOMETRY_NOT_ENROLLED: i64 = -7;
#[cfg(target_os = "macos")]
const LA_ERROR_BIOMETRY_LOCKOUT: i64 = -8;
// NOT an LAError code: our sentinel for "evaluatePolicy reported failure but
// passed a nil NSError". All real LAError codes are negative, so 0 can never
// collide with one; `classify` maps it through the unmapped-code arm to
// `Unavailable` (fail-safe to the password path).
#[cfg(target_os = "macos")]
const LA_ERROR_NONE_SENTINEL: i64 = 0;

/// Map the raw `evaluatePolicy` result to an outcome. PURE + host-tested —
/// `macos.rs` is a thin shell around this, so the classification logic carries
/// no `unsafe`. `Ok(())` = biometry succeeded; `Err(code)` = the `LAError`
/// code from the NSError. Any unmapped code is `Unavailable` (fail-safe: send
/// the user to the password path, never silently through the gate).
/// macOS-gated because only the macOS provider produces LAError codes.
#[cfg(target_os = "macos")]
pub(crate) fn classify(result: Result<(), i64>) -> PresenceOutcome {
    match result {
        Ok(()) => PresenceOutcome::Authenticated,
        Err(LA_ERROR_USER_CANCEL) | Err(LA_ERROR_SYSTEM_CANCEL) => PresenceOutcome::Cancelled,
        Err(LA_ERROR_USER_FALLBACK) => PresenceOutcome::Fallback,
        Err(LA_ERROR_BIOMETRY_NOT_AVAILABLE)
        | Err(LA_ERROR_BIOMETRY_NOT_ENROLLED)
        | Err(LA_ERROR_BIOMETRY_LOCKOUT) => PresenceOutcome::Unavailable,
        Err(_) => PresenceOutcome::Unavailable,
    }
}

/// Presence availability on this machine. Platform-dispatched.
pub fn availability() -> PresenceAvailability {
    #[cfg(target_os = "macos")]
    {
        macos::availability()
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsupported::availability()
    }
}

/// Present the biometric sheet and block until the outcome is known.
/// Platform-dispatched. Non-macOS returns `Unavailable`.
pub fn evaluate(reason: &str) -> PresenceOutcome {
    #[cfg(target_os = "macos")]
    {
        macos::evaluate(reason)
    }
    #[cfg(not(target_os = "macos"))]
    {
        unsupported::evaluate(reason)
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn success_maps_to_authenticated() {
        assert_eq!(classify(Ok(())), PresenceOutcome::Authenticated);
    }

    #[test]
    fn user_cancel_maps_to_cancelled() {
        assert_eq!(
            classify(Err(LA_ERROR_USER_CANCEL)),
            PresenceOutcome::Cancelled
        );
    }

    #[test]
    fn system_cancel_maps_to_cancelled() {
        assert_eq!(
            classify(Err(LA_ERROR_SYSTEM_CANCEL)),
            PresenceOutcome::Cancelled
        );
    }

    #[test]
    fn user_fallback_maps_to_fallback() {
        assert_eq!(
            classify(Err(LA_ERROR_USER_FALLBACK)),
            PresenceOutcome::Fallback
        );
    }

    #[test]
    fn not_available_enrolled_lockout_map_to_unavailable() {
        for code in [
            LA_ERROR_BIOMETRY_NOT_AVAILABLE,
            LA_ERROR_BIOMETRY_NOT_ENROLLED,
            LA_ERROR_BIOMETRY_LOCKOUT,
        ] {
            assert_eq!(classify(Err(code)), PresenceOutcome::Unavailable);
        }
    }

    #[test]
    fn unknown_code_fails_safe_to_unavailable() {
        // Realistic LAError codes we deliberately leave unmapped —
        // authenticationFailed (-1), passcodeNotSet (-5), appCancel (-9) —
        // plus an out-of-range code and the nil-NSError sentinel (0). All
        // must fail safe to the password path.
        for code in [-1, -5, -9, -999, 0] {
            assert_eq!(classify(Err(code)), PresenceOutcome::Unavailable);
        }
    }
}
