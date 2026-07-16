//! Desktop presence proof (macOS Touch ID) — the ONLY crate permitting `unsafe`.
//!
//! Presence proof, NOT a cryptographic binding: `evaluate` returns whether the
//! device owner authenticated with biometry; it never touches vault key
//! material. Password re-entry remains the KEK-knowledge fallback.

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
const LA_ERROR_USER_CANCEL: i64 = -2;
const LA_ERROR_USER_FALLBACK: i64 = -3;
const LA_ERROR_SYSTEM_CANCEL: i64 = -4;
const LA_ERROR_BIOMETRY_NOT_AVAILABLE: i64 = -6;
const LA_ERROR_BIOMETRY_NOT_ENROLLED: i64 = -7;
const LA_ERROR_BIOMETRY_LOCKOUT: i64 = -8;

/// Map the raw `evaluatePolicy` result to an outcome. PURE + host-tested —
/// `macos.rs` is a thin shell around this, so the classification logic carries
/// no `unsafe`. `Ok(())` = biometry succeeded; `Err(code)` = the `LAError`
/// code from the NSError. Any unmapped code is `Unavailable` (fail-safe: send
/// the user to the password path, never silently through the gate).
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

#[cfg(test)]
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
        assert_eq!(classify(Err(-999)), PresenceOutcome::Unavailable);
        assert_eq!(classify(Err(0)), PresenceOutcome::Unavailable);
    }
}
