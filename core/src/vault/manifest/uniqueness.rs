//! §4.2's repeated-value rules, expressed once for both directions.
//!
//! `docs/vault-format.md` §4.2 constrains four of the manifest's five
//! sorted arrays to hold no repeated value:
//!
//! | Array | Unique by |
//! |---|---|
//! | `vector_clock` | `device_uuid` |
//! | each block's `vector_clock_summary` | `device_uuid` |
//! | `blocks` | `block_uuid` |
//! | `trash` | `block_uuid` |
//!
//! `recipients` is the **explicit exception** — a repeated `contact_uuid`
//! denotes no additional grant, so it is accepted and round-trips. Do not
//! "tidy up" that asymmetry into a fifth rule: it would narrow a v1-frozen
//! decoder, and both
//! `encode::tests::encode_manifest_accepts_a_duplicate_contact_uuid_in_recipients`
//! (plain backticks, not an intra-doc link: it is a `#[cfg(test)]` item, so
//! the link would never resolve — and this module is private, so the #92
//! rustdoc gate would never say so) and the
//! `recipients__duplicate_contact_uuid` row of
//! `core/tests/data/manifest_uniqueness_kat.json` exist to red when
//! someone tries.
//!
//! ## Why this is a module rather than four inline scans
//!
//! **Sortedness and distinctness are independent**, which is what makes
//! these rules need their own enforcement at all: `[x, x]` *is* sorted, so
//! neither the encoder's sort nor the decoder's §4.3 step-4
//! re-encode-and-compare can see a repeat. A body carrying one re-encodes
//! to itself byte for byte.
//!
//! The rule was written out three times in `decode/entries.rs` and,
//! after #600, needed four more on the encode side. Seven hand-copies of
//! one sentence from a frozen spec is how the two directions drift — and
//! they had already drifted, which is the whole of #600: the reader
//! enforced all four rules and the writer enforced none, so
//! `encode_manifest` could emit, and `sign_manifest` sign, a body
//! `decode_manifest` refuses to open. Both directions now call
//! [`has_repeat`], so deleting it reds both.

use super::{Manifest, ManifestError};
use crate::vault::block::VectorClockEntry;

/// Whether `ids` holds the same value twice.
///
/// Sorts and scans adjacent pairs: `O(n log n)` and no `HashSet`
/// allocation for what is typically a handful of entries. Adjacency is
/// exhaustive *because* the input is sorted first — equal values cannot
/// be separated by an unequal one.
///
/// Takes the `Vec` **by value**. Callers materialise the key list anyway
/// (the ids are `Copy` 16-byte arrays projected out of larger entry
/// structs), and consuming it means this function can sort in place
/// without either cloning or mutating a caller's buffer.
///
/// `sort_unstable` rather than `sort`: the only question asked of the
/// result is whether *some* adjacent pair is equal, and every ordering of
/// equal elements answers it identically. There is no tie whose
/// resolution is observable.
pub(super) fn has_repeat<T: Ord>(mut ids: Vec<T>) -> bool {
    ids.sort_unstable();
    ids.windows(2).any(|w| w[0] == w[1])
}

/// The `device_uuid` of every entry in one vector-clock array.
///
/// Shared by the two arrays §4.2 constrains by `device_uuid` — the
/// vault-level `vector_clock` and each block's `vector_clock_summary` —
/// which is also why the read side gives them one shared error variant.
pub(super) fn device_uuids(entries: &[VectorClockEntry]) -> Vec<[u8; super::UUID_LEN]> {
    entries.iter().map(|e| e.device_uuid).collect()
}

/// Reject a [`Manifest`] that violates any of §4.2's four repeated-value
/// rules, BEFORE it is encoded (#600).
///
/// The writer half of a rule whose reader half `decode_manifest` has
/// enforced since v1. Order of the checks is not observable — a manifest
/// violating two rules is rejected either way — so they run cheapest
/// first: the three flat top-level arrays before the per-block walk.
pub(super) fn check_no_repeated_array_values(m: &Manifest) -> Result<(), ManifestError> {
    if has_repeat(device_uuids(&m.vector_clock)) {
        return Err(ManifestError::EncodeVectorClockDuplicateDevice);
    }
    if has_repeat(m.blocks.iter().map(|b| b.block_uuid).collect()) {
        return Err(ManifestError::EncodeDuplicateBlockUuid);
    }
    if has_repeat(m.trash.iter().map(|t| t.block_uuid).collect()) {
        return Err(ManifestError::EncodeDuplicateTrashUuid);
    }
    // §4.2 constrains "**each** block's" summary, not merely the first: a
    // writer checking only `blocks[0]` is a divergence the corpus's
    // `vector_clock_summary__duplicate_device_uuid` row plants in
    // `blocks[1]` precisely to catch.
    for block in &m.blocks {
        if has_repeat(device_uuids(&block.vector_clock_summary)) {
            return Err(ManifestError::EncodeVectorClockDuplicateDevice);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
