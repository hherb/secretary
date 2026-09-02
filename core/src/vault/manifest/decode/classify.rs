//! Best-effort classification of a §4.3 step-4 canonical re-encode failure
//! (#590).
//!
//! [`decode_manifest`] rejects a manifest body whose re-encoding is not
//! byte-identical to its input. Until #590 that rejection was a single
//! fieldless variant whose message named four candidate causes and no
//! position, on the path **every vault open** takes — and #572 narrowed the
//! accepted-manifest set for anything this codebase did not write, so the
//! reader most likely to see it is a peer or clean-room client with an
//! encoder bug.
//!
//! Everything here is a pure function over the parsed [`Manifest`] and the
//! two byte buffers the check already holds. Nothing in this module can
//! change a verdict: [`classify_non_canonical`] runs only once the byte
//! comparison has already decided to reject.
//!
//! [`decode_manifest`]: super::decode_manifest

use super::super::cause::NonCanonicalCause;
use super::Manifest;

/// RFC 8949 §3: the low 5 bits of an initial byte carry the additional
/// information; the high 3 bits carry the major type.
const ADDITIONAL_INFO_MASK: u8 = 0b0001_1111;
/// Bit width of the additional-information field.
const MAJOR_TYPE_SHIFT: u32 = 5;

/// Additional information 31 marks an indefinite-length item (major types
/// 2-5) and, under major type 7, the `0xFF` break code.
const AI_INDEFINITE: u8 = 31;
/// The largest argument value RFC 8949 §4.2.1 requires to be encoded in
/// the additional-information field itself rather than a following byte.
const AI_MAX_INLINE: u8 = 23;
/// Additional information 24-27 select a 1-, 2-, 4- or 8-byte argument.
const AI_ARG_ONE_BYTE: u8 = 24;
/// Additional information 25 selects a 2-byte argument.
const AI_ARG_TWO_BYTE: u8 = 25;
/// Additional information 26 selects a 4-byte argument.
const AI_ARG_FOUR_BYTE: u8 = 26;
/// Additional information 27 is the last defined argument width; 28-30 are
/// reserved and are not a shortest-form question.
const AI_ARG_EIGHT_BYTE: u8 = 27;

/// Major type 2 (byte string) is the first that admits an indefinite length.
const MAJOR_BYTE_STRING: u8 = 2;
/// Major type 5 (map) is the last that admits an indefinite length.
const MAJOR_MAP: u8 = 5;
/// Major type 7 carries floats, simple values and the break code. Its
/// shortest-form rules differ from types 0-6, so the non-shortest-form
/// classification deliberately excludes it — see [`classify_head`].
const MAJOR_SIMPLE_OR_FLOAT: u8 = 7;
/// The RFC 8949 break code, which appears only inside an indefinite item.
const BREAK_CODE: u8 = 0xFF;

/// Classify why `re_encoded` and `input` differ, and where.
///
/// Returns the cause together with the offset of the first differing byte.
/// The offset is `None` only when neither buffer differs from the other
/// within its length — i.e. one is a strict prefix of the other, so
/// `zip` finds no mismatched pair.
///
/// **The two outputs answer different questions and are computed
/// independently:** `at` always locates the first divergence, whatever the
/// cause; the cause explains it. An earlier design returned `None` for the
/// offset on the [`NonCanonicalCause::ArraySortOrder`] arm, which threw
/// away a genuine locator (the first byte at which the sorted re-encoding
/// parts company with the input) for no gain.
///
/// Order of resolution matters. The array check runs first because it is
/// the only *decisive* one: it reads the parsed manifest rather than a
/// byte position, so it both cannot false-positive (a sorted input can
/// never diverge because of array order) and cannot be masked by whatever
/// byte happens to sit at the divergence.
pub(super) fn classify_non_canonical(
    manifest: &Manifest,
    input: &[u8],
    re_encoded: &[u8],
) -> (NonCanonicalCause, Option<usize>) {
    let at = first_divergence(input, re_encoded);

    if !arrays_are_sorted(manifest) {
        return (NonCanonicalCause::ArraySortOrder, at);
    }

    let cause = at
        .and_then(|offset| input.get(offset..))
        .and_then(classify_head)
        .unwrap_or(NonCanonicalCause::Unclassified);

    (cause, at)
}

/// Offset of the first byte at which the two buffers differ.
fn first_divergence(input: &[u8], re_encoded: &[u8]) -> Option<usize> {
    input.iter().zip(re_encoded).position(|(a, b)| a != b)
}

/// Classify the CBOR head at the start of `bytes`, if it is one this
/// module can name from the bytes alone.
///
/// Returns `None` — deferring to [`NonCanonicalCause::Unclassified`] —
/// for any head that is canonical in isolation, for the reserved
/// additional-information values 28-30, and for a truncated argument.
///
/// Major type 7 is deliberately excluded from the non-shortest-form arm.
/// Its arguments are simple values and floats rather than integers, with
/// their own encoding rules, and a float cannot reach this code at all:
/// `decode_manifest` runs `reject_floats_and_tags` over the whole body
/// before the re-encode comparison.
fn classify_head(bytes: &[u8]) -> Option<NonCanonicalCause> {
    let head = *bytes.first()?;

    if head == BREAK_CODE {
        return Some(NonCanonicalCause::IndefiniteLength);
    }

    let major = head >> MAJOR_TYPE_SHIFT;
    let additional = head & ADDITIONAL_INFO_MASK;

    if additional == AI_INDEFINITE && (MAJOR_BYTE_STRING..=MAJOR_MAP).contains(&major) {
        return Some(NonCanonicalCause::IndefiniteLength);
    }

    if major == MAJOR_SIMPLE_OR_FLOAT {
        return None;
    }

    if (AI_ARG_ONE_BYTE..=AI_ARG_EIGHT_BYTE).contains(&additional) {
        let argument = read_argument(&bytes[1..], additional)?;
        if !is_shortest_form(argument, additional) {
            return Some(NonCanonicalCause::NonShortestForm);
        }
    }

    None
}

/// Read the big-endian argument that follows a head with additional
/// information `additional` (24-27). `None` if the buffer is truncated.
fn read_argument(rest: &[u8], additional: u8) -> Option<u64> {
    let width = 1usize << (additional - AI_ARG_ONE_BYTE);
    let raw = rest.get(..width)?;

    let mut value = 0u64;
    for byte in raw {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

/// Whether `argument` needs the width `additional` selects, per RFC 8949
/// §4.2.1's shortest-form rule.
fn is_shortest_form(argument: u64, additional: u8) -> bool {
    match additional {
        AI_ARG_ONE_BYTE => argument > u64::from(AI_MAX_INLINE),
        AI_ARG_TWO_BYTE => argument > u64::from(u8::MAX),
        AI_ARG_FOUR_BYTE => argument > u64::from(u16::MAX),
        AI_ARG_EIGHT_BYTE => argument > u64::from(u32::MAX),
        // Not an argument width at all. Unreachable from `classify_head`,
        // which range-checks before calling — but answering "shortest"
        // leaves an unexpected head UNCLASSIFIED rather than inventing a
        // violation, so this function is correct in isolation rather than
        // only under its caller's contract. `_ => false` would report a
        // non-shortest-form cause for a head that has no argument.
        _ => true,
    }
}

/// Whether all five arrays `docs/vault-format.md` §4.2 fixes an order for
/// arrived in it.
///
/// Equal adjacent keys count as sorted, which is correct twice over: they
/// are sorted, and `encode_manifest`'s sorts are stable, so a repeat
/// re-encodes in its input order and cannot be the divergence. Repeats are
/// rejected earlier and separately, by `entries.rs`'s adjacent-equality
/// scans (#594).
fn arrays_are_sorted(manifest: &Manifest) -> bool {
    manifest
        .vector_clock
        .is_sorted_by_key(|entry| entry.device_uuid)
        && manifest.blocks.is_sorted_by_key(|entry| entry.block_uuid)
        && manifest.trash.is_sorted_by_key(|entry| entry.block_uuid)
        && manifest.blocks.iter().all(|block| {
            block.recipients.is_sorted()
                && block
                    .vector_clock_summary
                    .is_sorted_by_key(|entry| entry.device_uuid)
        })
}

#[cfg(test)]
mod tests;
