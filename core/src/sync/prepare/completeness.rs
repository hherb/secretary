//! Refuse a merge that would cover a copy without reading it (#781).
//!
//! A block diverges because some conflict-copy manifest claims a version of
//! it the canonical one does not cover. The merge's manifest clock covers
//! every copy, so a version the fold never read would be lost for good: the
//! next sync sees an equal clock and reads no sibling, and the copy's own
//! device adopts the merged manifest.

use std::collections::BTreeSet;

use crate::crypto::hash::hash as blake3_hash;
use crate::sync::bundle::{BlockEnvelope, ManifestSnapshot, VaultBundle};
use crate::sync::error::SyncError;
use crate::sync::ingest::{
    blocks_new_to_canonical, copy_version_is_uncovered, listed_block_diverges,
};
use crate::sync::outcome::DiffPlan;
use crate::vault::block::VectorClockEntry;
use crate::vault::BlockEntry;

/// Check that every block a merge must read is in `plan`: each block new to
/// the canonical manifest (crypto-design §11.7), and each block it lists that
/// a copy's version diverges from. Both are decided from the manifests alone.
/// Ingest leaves a block out when the file standing in for its local side,
/// `blocks/<uuid>.cbor.enc`, is missing, out of size bounds or fails
/// authentication.
///
/// # Errors
///
/// [`SyncError::BlockCopyUnavailable`] for the first such block not planned.
pub(super) fn ensure_divergent_blocks_are_planned(
    bundle: &VaultBundle,
    plan: &DiffPlan,
) -> Result<(), SyncError> {
    let canonical = &bundle.canonical.manifest;
    let listed = canonical
        .blocks
        .iter()
        .filter(|entry| listed_block_diverges(entry, &bundle.copies))
        .map(|entry| entry.block_uuid);
    match blocks_new_to_canonical(canonical, &bundle.copies)
        .into_iter()
        .chain(listed)
        .find(|uuid| !plan.diverging_blocks.contains(uuid))
    {
        Some(block_uuid) => Err(unavailable(block_uuid, "its own block file")),
        None => Ok(()),
    }
}

/// The refusal, logged at warn so the stuck block is named somewhere: the
/// FFI projection carries no payload, and a file that fails authentication
/// will not clear on retry.
fn unavailable(block_uuid: [u8; 16], what: &'static str) -> SyncError {
    tracing::warn!(
        block_uuid = %crate::vault::orchestrators::format_uuid_hyphenated(&block_uuid),
        missing = what,
        "merge refused: a version it must read is unreadable (missing, out of size bounds, or failing authentication)"
    );
    SyncError::BlockCopyUnavailable { block_uuid }
}

/// Check that every version of `block_uuid` a copy manifest claims is
/// covered by one the fold will read: its clock is equal to or dominated by
/// `canonical_clock`, or by the clock of a version with an envelope in
/// `envelopes` (matched by BLAKE3-256 fingerprint, as `parent_block_clock`
/// pairs them). Its own envelope counts, so an uncovered version needs one.
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
    let versions: Vec<&BlockEntry> = copies
        .iter()
        .flat_map(|c| c.manifest.blocks.iter())
        .filter(|entry| entry.block_uuid == *block_uuid)
        .collect();
    // The clocks of the versions the fold will read: canonical's, and every
    // copy version whose file arrived.
    let read_clocks: Vec<&[VectorClockEntry]> = std::iter::once(canonical_clock)
        .chain(
            versions
                .iter()
                .filter(|e| readable.contains(&e.fingerprint))
                .map(|e| e.vector_clock_summary.as_slice()),
        )
        .collect();
    // A version some read version dominates or equals holds nothing new.
    let all_covered = versions.iter().all(|e| {
        read_clocks
            .iter()
            .any(|c| !copy_version_is_uncovered(c, &e.vector_clock_summary))
    });
    if all_covered {
        Ok(())
    } else {
        Err(unavailable(*block_uuid, "a conflict copy's block file"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sync::prepare::parent_block_clock_tests::{block_entry, empty_manifest, snapshot};
    use crate::vault::Manifest;
    use std::collections::BTreeMap;
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

    /// A copy manifest holding `BLOCK` at `clock`, its fingerprint `BLAKE3(bytes)`.
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

    /// A version another readable copy dominates is subsumed by it, so its
    /// own missing file must not hold up the merge (#781 review).
    #[test]
    fn a_version_a_readable_copy_dominates_needs_no_envelope() {
        let copies = [
            copy_holding(b"newer", vec![vc(COPY_DEVICE, 1), vc(OTHER_COPY_DEVICE, 2)]),
            copy_holding(b"older", vec![vc(OTHER_COPY_DEVICE, 1)]),
        ];
        assert!(check(&copies, &[envelope(b"newer")]).is_ok());
    }

    /// The mirror of the case above: a missing version that dominates the
    /// readable one still holds content no read version has.
    #[test]
    fn a_missing_version_that_dominates_a_readable_one_is_refused() {
        let copies = [
            copy_holding(b"newer", vec![vc(COPY_DEVICE, 1), vc(OTHER_COPY_DEVICE, 2)]),
            copy_holding(b"older", vec![vc(OTHER_COPY_DEVICE, 1)]),
        ];
        assert!(check(&copies, &[envelope(b"older")]).is_err());
    }

    fn bundle(canonical: Manifest, copies: Vec<ManifestSnapshot>) -> VaultBundle {
        VaultBundle {
            canonical: snapshot(canonical),
            copies,
            diverging_blocks: BTreeMap::new(),
        }
    }

    fn planned(blocks: &[[u8; 16]]) -> DiffPlan {
        DiffPlan {
            diverging_blocks: blocks.to_vec(),
        }
    }

    /// Of two blocks new to the canonical manifest, the unplanned one is named.
    #[test]
    fn an_unplanned_new_block_is_named() {
        let other: [u8; 16] = [0xBB; 16];
        let mut copy = empty_manifest();
        copy.blocks
            .push(block_entry(BLOCK, [1; 32], vec![vc(COPY_DEVICE, 1)]));
        copy.blocks
            .push(block_entry(other, [2; 32], vec![vc(COPY_DEVICE, 1)]));
        let b = bundle(empty_manifest(), vec![snapshot(copy)]);
        assert!(ensure_divergent_blocks_are_planned(&b, &planned(&[BLOCK, other])).is_ok());
        assert!(matches!(
            ensure_divergent_blocks_are_planned(&b, &planned(&[BLOCK])),
            Err(SyncError::BlockCopyUnavailable { block_uuid }) if block_uuid == other
        ));
    }

    /// A block the canonical manifest lists, which a copy's version diverges
    /// from, must be planned too: ingest leaves it out when its own file is
    /// unreadable, and the merge would then cover the copy without it.
    #[test]
    fn an_unplanned_diverging_listed_block_is_refused() {
        let mut canonical = empty_manifest();
        canonical
            .blocks
            .push(block_entry(BLOCK, [1; 32], vec![vc(CANONICAL_DEVICE, 2)]));
        let mut copy = empty_manifest();
        copy.blocks
            .push(block_entry(BLOCK, [2; 32], vec![vc(COPY_DEVICE, 1)]));
        let b = bundle(canonical.clone(), vec![snapshot(copy)]);
        assert!(ensure_divergent_blocks_are_planned(&b, &planned(&[BLOCK])).is_ok());
        assert!(matches!(
            ensure_divergent_blocks_are_planned(&b, &planned(&[])),
            Err(SyncError::BlockCopyUnavailable { block_uuid }) if block_uuid == BLOCK
        ));

        // A copy the canonical entry dominates needs no plan.
        let mut older = empty_manifest();
        older
            .blocks
            .push(block_entry(BLOCK, [3; 32], vec![vc(CANONICAL_DEVICE, 1)]));
        let b = bundle(canonical, vec![snapshot(older)]);
        assert!(ensure_divergent_blocks_are_planned(&b, &planned(&[])).is_ok());
    }

    #[test]
    fn a_copy_without_the_block_needs_no_envelope() {
        assert!(check(&[snapshot(empty_manifest())], &[]).is_ok());
    }
}
