//! Refuse a merge that would cover a copy without reading it (#781).
//!
//! A block diverges because some conflict-copy manifest claims a version of
//! it the canonical one does not cover. The merge's manifest clock covers
//! every copy, so a version the fold never read would be lost for good: the
//! next sync sees an equal clock and reads no sibling, and the copy's own
//! device adopts the merged manifest.

use std::collections::BTreeSet;

use crate::crypto::hash::hash as blake3_hash;
use crate::sync::bundle::{BlockEnvelope, ManifestSnapshot};
use crate::sync::error::SyncError;
use crate::sync::ingest::copy_version_is_uncovered;
use crate::vault::block::VectorClockEntry;

/// Check that every version of `block_uuid` a copy manifest claims and
/// `canonical_clock` does not cover has an envelope in `envelopes`, matched
/// by BLAKE3-256 fingerprint as `parent_block_clock` pairs them.
///
/// # Errors
///
/// [`SyncError::BlockCopyUnavailable`] for the first uncovered version with
/// no envelope: its sibling file is missing, out of size bounds, or failed
/// authentication at ingest.
pub(super) fn ensure_uncovered_copies_are_readable(
    block_uuid: &[u8; 16],
    canonical_clock: &[VectorClockEntry],
    copies: &[ManifestSnapshot],
    envelopes: &[BlockEnvelope],
) -> Result<(), SyncError> {
    let readable: BTreeSet<_> = envelopes
        .iter()
        .map(|e| *blake3_hash(&e.bytes).as_bytes())
        .collect();
    let all_readable = copies
        .iter()
        .flat_map(|c| c.manifest.blocks.iter())
        .filter(|entry| entry.block_uuid == *block_uuid)
        .filter(|entry| copy_version_is_uncovered(canonical_clock, &entry.vector_clock_summary))
        .all(|entry| readable.contains(&entry.fingerprint));
    if all_readable {
        Ok(())
    } else {
        Err(SyncError::BlockCopyUnavailable {
            block_uuid: *block_uuid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::prepare::parent_block_clock_tests::{block_entry, empty_manifest, snapshot};
    use std::path::PathBuf;

    const BLOCK: [u8; 16] = [0xAA; 16];
    const CANONICAL_DEVICE: [u8; 16] = [0x01; 16];
    const COPY_DEVICE: [u8; 16] = [0x02; 16];
    const OTHER_COPY_DEVICE: [u8; 16] = [0x03; 16];

    fn vc(device_uuid: [u8; 16], counter: u64) -> VectorClockEntry {
        VectorClockEntry {
            device_uuid,
            counter,
        }
    }

    fn envelope(bytes: &[u8]) -> BlockEnvelope {
        BlockEnvelope {
            bytes: bytes.to_vec(),
            source_path: PathBuf::from("/dev/null"),
        }
    }

    /// A copy manifest holding `BLOCK` at `clock`, authored by `bytes`.
    fn copy_holding(bytes: &[u8], clock: Vec<VectorClockEntry>) -> ManifestSnapshot {
        let mut m = empty_manifest();
        m.blocks
            .push(block_entry(BLOCK, *blake3_hash(bytes).as_bytes(), clock));
        snapshot(m)
    }

    fn check(copies: &[ManifestSnapshot], envelopes: &[BlockEnvelope]) -> Result<(), SyncError> {
        ensure_uncovered_copies_are_readable(&BLOCK, &[vc(CANONICAL_DEVICE, 2)], copies, envelopes)
    }

    #[test]
    fn an_uncovered_version_with_its_envelope_is_accepted() {
        let copies = [copy_holding(b"copy", vec![vc(COPY_DEVICE, 1)])];
        assert!(check(&copies, &[envelope(b"copy")]).is_ok());
    }

    #[test]
    fn an_uncovered_version_without_its_envelope_is_refused() {
        let copies = [copy_holding(b"copy", vec![vc(COPY_DEVICE, 1)])];
        assert!(matches!(
            check(&copies, &[]),
            Err(SyncError::BlockCopyUnavailable { block_uuid }) if block_uuid == BLOCK
        ));
    }

    /// Another copy's envelope does not stand in for a missing version.
    #[test]
    fn one_missing_version_among_two_is_refused() {
        let copies = [
            copy_holding(b"one", vec![vc(COPY_DEVICE, 1)]),
            copy_holding(b"two", vec![vc(OTHER_COPY_DEVICE, 1)]),
        ];
        assert!(check(&copies, &[envelope(b"one")]).is_err());
    }

    /// A copy the canonical version dominates or equals holds nothing new,
    /// so a missing file for it must not hold up the merge.
    #[test]
    fn a_covered_version_needs_no_envelope() {
        let copies = [
            copy_holding(b"older", vec![vc(CANONICAL_DEVICE, 1)]),
            copy_holding(b"same", vec![vc(CANONICAL_DEVICE, 2)]),
        ];
        assert!(check(&copies, &[]).is_ok());
    }

    #[test]
    fn a_copy_without_the_block_needs_no_envelope() {
        assert!(check(&[snapshot(empty_manifest())], &[]).is_ok());
    }
}
