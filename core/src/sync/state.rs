//! `SyncState` — per-vault sync orchestration state, caller-persisted.
//!
//! Holds the `vault_uuid` (binding the state to one specific vault) and
//! `highest_vector_clock_seen` (per `docs/crypto-design.md` §10).
//!
//! Invariant on `highest_vector_clock_seen`: entries sorted ascending by
//! `device_uuid` and no duplicate `device_uuid`. The constructor
//! `SyncState::new` and the CBOR decoder enforce this in both
//! directions (per the design spec — both paths validate so a
//! programmer-error path produces a typed error rather than corrupting
//! merge dispatch).

use crate::sync::error::SyncError;
use crate::vault::block::VectorClockEntry;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncState {
    pub vault_uuid: [u8; 16],
    pub highest_vector_clock_seen: Vec<VectorClockEntry>,
}

impl SyncState {
    /// Fresh state for a vault we've never synced on this device.
    /// First `sync_once` call will produce `AppliedAutomatically` for
    /// any non-empty disk clock (the empty vector clock is the lattice
    /// bottom).
    pub fn empty(vault_uuid: [u8; 16]) -> Self {
        Self {
            vault_uuid,
            highest_vector_clock_seen: Vec::new(),
        }
    }

    /// Construct with explicit clock entries; validates the sorted +
    /// deduped invariant.
    pub fn new(
        vault_uuid: [u8; 16],
        highest_vector_clock_seen: Vec<VectorClockEntry>,
    ) -> Result<Self, SyncError> {
        validate_clock_canonical(&highest_vector_clock_seen)?;
        Ok(Self {
            vault_uuid,
            highest_vector_clock_seen,
        })
    }
}

/// Shared validator used by `SyncState::new` and the CBOR decoder.
/// Returns `InvalidArgument` if entries are unsorted or duplicated.
pub(crate) fn validate_clock_canonical(
    entries: &[VectorClockEntry],
) -> Result<(), SyncError> {
    for pair in entries.windows(2) {
        match pair[0].device_uuid.cmp(&pair[1].device_uuid) {
            std::cmp::Ordering::Less => continue,
            std::cmp::Ordering::Equal => {
                return Err(SyncError::InvalidArgument {
                    detail: "duplicate device_uuid in highest_vector_clock_seen".into(),
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(SyncError::InvalidArgument {
                    detail:
                        "highest_vector_clock_seen entries not sorted ascending by device_uuid"
                            .into(),
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(b: u8, counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid: [b; 16],
            counter,
        }
    }

    #[test]
    fn empty_constructor_produces_empty_clock() {
        let s = SyncState::empty([0u8; 16]);
        assert_eq!(s.vault_uuid, [0u8; 16]);
        assert!(s.highest_vector_clock_seen.is_empty());
    }

    #[test]
    fn new_accepts_sorted_unique_entries() {
        let s = SyncState::new([7u8; 16], vec![entry(1, 5), entry(2, 3), entry(3, 9)])
            .expect("sorted unique entries must be accepted");
        assert_eq!(s.highest_vector_clock_seen.len(), 3);
    }

    #[test]
    fn new_accepts_empty_clock() {
        let s = SyncState::new([7u8; 16], vec![]).expect("empty clock must be accepted");
        assert!(s.highest_vector_clock_seen.is_empty());
    }

    #[test]
    fn new_rejects_unsorted_entries() {
        let err = SyncState::new([0u8; 16], vec![entry(2, 1), entry(1, 1)]).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("not sorted ascending"));
    }

    #[test]
    fn new_rejects_duplicate_device_uuid() {
        let err = SyncState::new([0u8; 16], vec![entry(1, 1), entry(1, 2)]).unwrap_err();
        assert!(matches!(err, SyncError::InvalidArgument { .. }));
        assert!(format!("{err}").contains("duplicate device_uuid"));
    }
}
