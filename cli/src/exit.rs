//! Exit code mapping. See spec §"Public surface" exit-code table.

use secretary_core::sync::SyncError;

/// Documented exit codes for `secretary-sync`. The discriminant is the
/// numeric exit code surfaced to the operator.
///
/// Per spec §"Public surface":
///
/// | Code | Meaning |
/// |---|---|
/// | 0  | Success (any non-Rollback outcome; clean shutdown). |
/// | 1  | Generic error (vault format, IO, unlock, state-file). |
/// | 2  | Usage error. |
/// | 10 | RollbackRejected. |
/// | 11 | Reserved — non-interactive veto-policy refusal (currently unreachable). |
/// | 12 | EvidenceStale after retry budget exhausted. |
/// | 13 | BlockFingerprintMismatch on commit. |
/// | 14 | Lockfile held — another secretary-sync process is running on this vault. |
// The non-`GenericError` variants and `from_sync_error` are consumed by
// the pipeline + dispatch wiring landed in Task 5 onward. Task 1 ships
// only the skeleton; the unit tests below exercise every variant so
// the discriminant table is locked in. The allow lifts once Task 5
// references the rest of the surface.
// TODO(#113): remove this `#[allow(dead_code)]` when Task 5 wires the
// dispatch layer that consumes every variant.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum ExitCode {
    Success = 0,
    GenericError = 1,
    UsageError = 2,
    RollbackRejected = 10,
    VetoPolicyRefused = 11,
    EvidenceStale = 12,
    BlockFingerprintMismatch = 13,
    LockfileHeld = 14,
}

impl ExitCode {
    /// Map a `SyncError` to the documented exit code. Variants without a
    /// dedicated code map to `GenericError`.
    #[must_use]
    // TODO(#113): remove this `#[allow(dead_code)]` when Task 5 wires
    // the dispatch layer that calls `from_sync_error`.
    #[allow(dead_code)]
    pub fn from_sync_error(err: &SyncError) -> Self {
        match err {
            SyncError::EvidenceStale => Self::EvidenceStale,
            SyncError::Vault(secretary_core::vault::VaultError::BlockFingerprintMismatch {
                ..
            }) => Self::BlockFingerprintMismatch,
            _ => Self::GenericError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_is_zero() {
        assert_eq!(ExitCode::Success as i32, 0);
    }

    #[test]
    fn generic_error_is_one() {
        assert_eq!(ExitCode::GenericError as i32, 1);
    }

    #[test]
    fn usage_error_is_two() {
        assert_eq!(ExitCode::UsageError as i32, 2);
    }

    #[test]
    fn rollback_rejected_is_ten() {
        assert_eq!(ExitCode::RollbackRejected as i32, 10);
    }

    #[test]
    fn veto_policy_refused_is_eleven() {
        assert_eq!(ExitCode::VetoPolicyRefused as i32, 11);
    }

    #[test]
    fn evidence_stale_is_twelve() {
        assert_eq!(ExitCode::EvidenceStale as i32, 12);
    }

    #[test]
    fn block_fingerprint_mismatch_is_thirteen() {
        assert_eq!(ExitCode::BlockFingerprintMismatch as i32, 13);
    }

    #[test]
    fn lockfile_held_is_fourteen() {
        assert_eq!(ExitCode::LockfileHeld as i32, 14);
    }

    #[test]
    fn evidence_stale_error_maps() {
        let mapped = ExitCode::from_sync_error(&SyncError::EvidenceStale);
        assert_eq!(mapped, ExitCode::EvidenceStale);
    }
}
