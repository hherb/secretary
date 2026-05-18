//! Typed errors surfaced by `sync_once` and `SyncState` codec.

use thiserror::Error;

use crate::vault::VaultError;

#[derive(Debug, Error)]
pub enum SyncError {
    #[error(
        "vault_uuid in SyncState ({state_vault_uuid:?}) does not match \
         vault manifest ({folder_vault_uuid:?})"
    )]
    VaultUuidMismatch {
        state_vault_uuid: [u8; 16],
        folder_vault_uuid: [u8; 16],
    },

    #[error("SyncState CBOR decode failed: {detail}")]
    StateDecodeFailed { detail: String },

    #[error("SyncState CBOR encode failed: {detail}")]
    StateEncodeFailed { detail: String },

    #[error(transparent)]
    Vault(#[from] VaultError),

    #[error("invalid argument: {detail}")]
    InvalidArgument { detail: String },

    /// I/O failure while enumerating sibling files during conflict-copy
    /// ingestion. Per-file decode / authentication failures are
    /// silently dropped per spec §1a-D3 — this variant only fires for
    /// folder-level errors (e.g. read_dir on a missing/unreadable
    /// folder, or read_dir on the blocks/ subdirectory).
    #[error("conflict-copy scan failed: failed to enumerate folder: {source}")]
    ConflictCopyScanIoFailed {
        #[source]
        source: std::io::Error,
    },

    /// The on-disk canonical manifest envelope hash differs from
    /// `draft.manifest_hash` recorded by `prepare_merge`. A concurrent
    /// writer modified the manifest between `prepare_merge` and
    /// `commit_with_decisions`. The commit is aborted with zero disk
    /// writes; the caller retries from `sync_once`.
    #[error("manifest changed on disk between prepare_merge and commit_with_decisions")]
    EvidenceStale,

    /// The caller passed a `VetoDecision` whose `record_id` is not in
    /// the `DraftMerge.vetoes` set. Decisions and vetoes must be a
    /// bijection (design doc D5).
    #[error("decision references unknown veto record_id: {record_id:02x?}")]
    UnknownVetoDecision { record_id: [u8; 16] },

    /// The caller did not supply a `VetoDecision` for a `record_id`
    /// present in `DraftMerge.vetoes`. Bijection check, mirror of
    /// [`SyncError::UnknownVetoDecision`].
    #[error("decision missing for tombstone veto record_id: {record_id:02x?}")]
    MissingVetoDecision { record_id: [u8; 16] },

    /// Defensive: a merge produced no `merged_records` but populated
    /// `vetoes`. Currently unreachable because every veto's `record_id`
    /// is also present in `merged_records` (vetoes are derived per-
    /// record from the merged set). Surfaced as a typed variant so a
    /// future change that breaks this invariant fails loudly instead
    /// of silently dropping records.
    #[error("merge produced no draft records but vetoes are non-empty (internal invariant)")]
    EmptyDraftWithVetoes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vault_uuid_mismatch_display_is_stable() {
        let err = SyncError::VaultUuidMismatch {
            state_vault_uuid: [1u8; 16],
            folder_vault_uuid: [2u8; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("vault_uuid in SyncState"));
        assert!(s.contains("does not match vault manifest"));
    }

    #[test]
    fn state_decode_failed_display_is_stable() {
        let err = SyncError::StateDecodeFailed {
            detail: "trailing bytes".into(),
        };
        assert_eq!(
            format!("{err}"),
            "SyncState CBOR decode failed: trailing bytes"
        );
    }

    #[test]
    fn state_encode_failed_display_is_stable() {
        let err = SyncError::StateEncodeFailed {
            detail: "encoder primitive error".into(),
        };
        assert_eq!(
            format!("{err}"),
            "SyncState CBOR encode failed: encoder primitive error"
        );
    }

    #[test]
    fn invalid_argument_display_is_stable() {
        let err = SyncError::InvalidArgument {
            detail: "duplicate device_uuid".into(),
        };
        assert_eq!(format!("{err}"), "invalid argument: duplicate device_uuid");
    }

    #[test]
    fn vault_error_forwards_via_from() {
        // VaultError variants are tested in core::vault; here we only
        // certify the From impl exists and folds into the Vault arm.
        // Pick a small variant that doesn't need fixture setup —
        // OwnerUuidMismatch is a plain two-field struct variant.
        let inner: VaultError = VaultError::OwnerUuidMismatch {
            vault: [0u8; 16],
            found: [1u8; 16],
        };
        let outer: SyncError = inner.into();
        assert!(matches!(outer, SyncError::Vault(_)));
    }

    #[test]
    fn evidence_stale_display_is_stable() {
        let err = SyncError::EvidenceStale;
        assert_eq!(
            format!("{err}"),
            "manifest changed on disk between prepare_merge and commit_with_decisions",
        );
    }

    #[test]
    fn unknown_veto_decision_display_includes_record_id() {
        let err = SyncError::UnknownVetoDecision {
            record_id: [0xAB; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("decision references unknown veto record_id"));
        // `{:02x?}` Debug-formats the slice as `[ab, ab, ...]`.
        assert!(s.contains("ab"));
    }

    #[test]
    fn missing_veto_decision_display_includes_record_id() {
        let err = SyncError::MissingVetoDecision {
            record_id: [0xCD; 16],
        };
        let s = format!("{err}");
        assert!(s.contains("decision missing for tombstone veto record_id"));
        assert!(s.contains("cd"));
    }

    #[test]
    fn empty_draft_with_vetoes_display_is_stable() {
        let err = SyncError::EmptyDraftWithVetoes;
        assert_eq!(
            format!("{err}"),
            "merge produced no draft records but vetoes are non-empty (internal invariant)",
        );
    }
}
