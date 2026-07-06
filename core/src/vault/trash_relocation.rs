//! Observability for the best-effort `blocks/ → trash/` relocation (#376).
//!
//! The physical move is organizational, not a security boundary: a trashed
//! block's ciphertext is equally decryptable in `trash/` as in `blocks/`
//! (same bytes, same recipient wraps), and every relocation outcome leaves a
//! correct, restorable vault. Before #376 a persistent failure (EXDEV
//! cross-mount `trash/`, permissions) was silently swallowed. This module
//! turns that swallow into a structured `tracing::warn!` so a mis-configured
//! vault is observable to an operator, while keeping the move best-effort.

use crate::vault::orchestrators::format_uuid_hyphenated;

/// Outcome of a best-effort `blocks/ → trash/` relocation, for logging only.
///
/// `Relocated` covers success (and the already-relocated no-op). `CrossDevice`
/// is EXDEV — `trash/` on a different filesystem than `blocks/`, an actionable
/// mis-config. `OtherFailure` is any other I/O error (permissions, transient
/// FS error). All three leave the vault correct and the block restorable.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum RelocationOutcome {
    Relocated,
    CrossDevice,
    OtherFailure,
}

/// Emit the operator-facing `warn!` for a relocation attempt and return its
/// outcome. Callers drop the return value; it exists so the kind → message
/// routing is unit-testable without capturing a `tracing` subscriber. Single
/// source of truth for the mapping — matched exactly once.
pub(crate) fn log_relocation(
    block_uuid: &[u8; 16],
    result: Result<(), std::io::Error>,
) -> RelocationOutcome {
    match &result {
        Ok(()) => RelocationOutcome::Relocated,
        Err(e) if e.kind() == std::io::ErrorKind::CrossesDevices => {
            tracing::warn!(
                block_uuid = %format_uuid_hyphenated(block_uuid),
                "trash relocation skipped: trash/ is on a different filesystem than blocks/ \
                 (EXDEV); the trashed ciphertext remains a benign, still-restorable orphan in \
                 blocks/ — co-locate trash/ on the same mount to enable relocation"
            );
            RelocationOutcome::CrossDevice
        }
        Err(e) => {
            tracing::warn!(
                block_uuid = %format_uuid_hyphenated(block_uuid),
                error = %e,
                "trash relocation failed; trashed ciphertext remains a benign, still-restorable \
                 orphan in blocks/"
            );
            RelocationOutcome::OtherFailure
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    const UUID: [u8; 16] = [0x11; 16];

    #[test]
    fn ok_result_is_relocated_and_emits_nothing() {
        assert_eq!(log_relocation(&UUID, Ok(())), RelocationOutcome::Relocated);
    }

    #[test]
    fn cross_device_error_maps_to_cross_device() {
        let err = Error::from(ErrorKind::CrossesDevices);
        assert_eq!(
            log_relocation(&UUID, Err(err)),
            RelocationOutcome::CrossDevice
        );
    }

    #[test]
    fn other_io_error_maps_to_other_failure() {
        let err = Error::from(ErrorKind::PermissionDenied);
        assert_eq!(
            log_relocation(&UUID, Err(err)),
            RelocationOutcome::OtherFailure
        );
    }
}
