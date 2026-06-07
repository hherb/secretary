//! Bridge DTOs for the interactive conflict-resolution flow: the
//! [`SyncOutcomeDto`] result enum (mirrors `InspectOutcome`), the
//! metadata-only veto / collision projections the resolution UI consumes,
//! the caller's [`VetoDecisionDto`], and the hex helpers + the
//! `From<InspectOutcome>` projection. Pure data + conversions — the
//! orchestration (`sync_vault` / `sync_commit_decisions`) lives in
//! [`super::orchestration`].

use secretary_cli::pipeline::InspectOutcome;

use crate::error::FfiVaultError;

/// Result of one [`super::orchestration::sync_vault`] pass. Mirrors
/// `InspectOutcome` as a bridge DTO.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncOutcomeDto {
    /// No remote state to ingest; vault and state unchanged.
    NothingToDo,
    /// A fast-forward / single-writer advance was applied; state persisted.
    AppliedAutomatically,
    /// Concurrent but non-diverging copies merged silently; state persisted.
    SilentMerge,
    /// Concurrent diverging copies merged cleanly with no vetoes; state persisted.
    MergedClean,
    /// Concurrent diverging copies produced tombstone vetoes — the pass paused.
    /// Carries the metadata the UI needs + the freshness token for the commit.
    ConflictsPending {
        /// Tombstone disputes needing a human decision (metadata only).
        vetoes: Vec<VetoDto>,
        /// Field-level LWW collisions surfaced for the "auto-merged" notice.
        collisions: Vec<CollisionDto>,
        /// BLAKE3-256 of the manifest envelope at inspect time; opaque token the
        /// caller passes back to `sync_commit_decisions`.
        manifest_hash: Vec<u8>,
    },
    /// A would-be rollback was rejected; vault and state unchanged.
    RollbackRejected,
}

/// Metadata-only projection of a [`secretary_core::sync::RecordTombstoneVeto`]
/// for the resolution UI. NO secret values — only the plaintext identifiers a
/// user needs to recognize the disputed record (mirrors the browse-path
/// secret-hygiene model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VetoDto {
    /// 32-char lowercase hex of the disputed record's UUID.
    pub record_uuid_hex: String,
    /// The record's `record_type` (e.g. "login", "note").
    pub record_type: String,
    /// The record's tags.
    pub tags: Vec<String>,
    /// The record's field names (keys only — never values).
    pub field_names: Vec<String>,
    /// Local copy's last-modified timestamp (Unix ms).
    pub local_last_mod_ms: u64,
    /// When the peer tombstoned this record (Unix ms).
    pub peer_tombstoned_at_ms: u64,
    /// 32-char lowercase hex of the device that tombstoned the record.
    pub peer_device_hex: String,
}

/// Metadata-only field-collision summary for the "auto-merged" notice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CollisionDto {
    /// 32-char lowercase hex of the auto-merged record's UUID.
    pub record_uuid_hex: String,
    /// Names of the fields that collided (keys only — never values).
    pub field_names: Vec<String>,
}

/// Caller's per-record decision. `keep_local = true` → reject the peer
/// tombstone; `false` → accept the delete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VetoDecisionDto {
    /// 32-char lowercase hex of the record this decision applies to.
    pub record_uuid_hex: String,
    /// `true` → reject the peer tombstone (keep local); `false` → accept delete.
    pub keep_local: bool,
}

impl VetoDecisionDto {
    /// Parse the 32-char hex `record_uuid` into a core [`VetoDecision`].
    ///
    /// [`VetoDecision`]: secretary_core::sync::VetoDecision
    // Exercised by the unit test today; wired into `sync_commit_decisions`
    // (Task 5 commit 2). Allow until that caller lands so the refactor commit
    // stays a pure move.
    #[allow(dead_code)]
    pub(crate) fn to_core(&self) -> Result<secretary_core::sync::VetoDecision, FfiVaultError> {
        let bytes = hex_to_16(&self.record_uuid_hex)?;
        Ok(if self.keep_local {
            secretary_core::sync::VetoDecision::KeepLocal { record_id: bytes }
        } else {
            secretary_core::sync::VetoDecision::AcceptTombstone { record_id: bytes }
        })
    }
}

/// 16-byte hex → [u8;16]; typed error otherwise (exactly 16 bytes / 32 hex chars).
// Reached only via `VetoDecisionDto::to_core`, itself dead until Task 5 commit 2.
#[allow(dead_code)]
pub(crate) fn hex_to_16(s: &str) -> Result<[u8; 16], FfiVaultError> {
    let bytes = hex::decode(s).map_err(|_| FfiVaultError::SyncFailed {
        detail: "invalid record_uuid hex".into(),
    })?;
    bytes.try_into().map_err(|_| FfiVaultError::SyncFailed {
        detail: "record_uuid must be 16 bytes".into(),
    })
}

fn project_veto(v: &secretary_core::sync::RecordTombstoneVeto) -> VetoDto {
    VetoDto {
        record_uuid_hex: hex::encode(v.record_id),
        record_type: v.local_state.record_type.clone(),
        tags: v.local_state.tags.clone(),
        field_names: v.local_state.fields.keys().cloned().collect(),
        local_last_mod_ms: v.local_state.last_mod_ms,
        peer_tombstoned_at_ms: v.disk_tombstone_at_ms,
        peer_device_hex: hex::encode(v.disk_tombstoner_device),
    }
}

impl From<InspectOutcome> for SyncOutcomeDto {
    fn from(o: InspectOutcome) -> Self {
        match o {
            InspectOutcome::NothingToDo => SyncOutcomeDto::NothingToDo,
            InspectOutcome::AppliedAutomatically => SyncOutcomeDto::AppliedAutomatically,
            InspectOutcome::SilentMerge => SyncOutcomeDto::SilentMerge,
            InspectOutcome::MergedClean => SyncOutcomeDto::MergedClean,
            InspectOutcome::RollbackRejected => SyncOutcomeDto::RollbackRejected,
            InspectOutcome::ConflictsPending {
                vetoes,
                collisions,
                manifest_hash,
            } => SyncOutcomeDto::ConflictsPending {
                vetoes: vetoes.iter().map(project_veto).collect(),
                collisions: collisions
                    .iter()
                    .map(|c| CollisionDto {
                        record_uuid_hex: hex::encode(c.record_id),
                        field_names: c.field_names.clone(),
                    })
                    .collect(),
                manifest_hash: manifest_hash.0.to_vec(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn veto_decision_dto_round_trips_to_core() {
        let d = VetoDecisionDto {
            record_uuid_hex: "0a".repeat(16),
            keep_local: true,
        };
        assert!(matches!(
            d.to_core().unwrap(),
            secretary_core::sync::VetoDecision::KeepLocal { .. }
        ));
        let d2 = VetoDecisionDto {
            record_uuid_hex: "ff".repeat(16),
            keep_local: false,
        };
        assert!(matches!(
            d2.to_core().unwrap(),
            secretary_core::sync::VetoDecision::AcceptTombstone { .. }
        ));
        assert!(VetoDecisionDto {
            record_uuid_hex: "zz".into(),
            keep_local: true
        }
        .to_core()
        .is_err());
        assert!(VetoDecisionDto {
            record_uuid_hex: "0a".into(),
            keep_local: true
        }
        .to_core()
        .is_err()); // too short
    }
}
