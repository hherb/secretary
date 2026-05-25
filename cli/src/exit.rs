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
// As of C.2 Task 5, `ExitCode` is library-public (`secretary_cli::exit::ExitCode`)
// and the discriminant table is locked in by the per-variant unit tests
// below. Variants not yet referenced from `main.rs` will be wired by
// the dispatch path in Task 9 (`run_one` outcome → exit code), but the
// surface is part of the library API today, so no `#[allow(dead_code)]`
// is needed.
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
