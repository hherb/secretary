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
//! **Every named cause is DECISIVE — none is read off the divergence
//! position.** The first version of this module classified by reading the
//! CBOR head at the first differing byte, which is only sound when the
//! divergence happens to land on an item boundary. It does not for the
//! shape [`NonCanonicalCause::Unclassified`]'s own doc calls the likeliest:
//! map-key disorder diverges *inside* a key's UTF-8 payload, and an
//! ordinary character there (`_` = `0x5F`, `8` = `0x38`, `x` = `0x78`) was
//! then read as an indefinite-length or non-shortest-form head. Because
//! `Manifest::unknown` keys are wire data, a peer could *choose* which
//! wrong cause a v1 client printed for a body violating a different rule
//! entirely — and the message it replaced had at least listed "key
//! disorder" among its four candidates. [`find_encoding_violation`] walks
//! the whole body instead, so a named encoding cause now means "this body
//! genuinely contains such an item", never "the byte at the divergence
//! looked like one".
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
/// Additional information 24 selects a 1-byte argument.
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
/// Major type 3 (text string), whose payload is skipped by byte length.
const MAJOR_TEXT_STRING: u8 = 3;
/// Major type 4 (array): its argument counts child items.
const MAJOR_ARRAY: u8 = 4;
/// Major type 5 (map) is the last that admits an indefinite length. Its
/// argument counts PAIRS, so it contributes twice as many child items.
const MAJOR_MAP: u8 = 5;
/// Major type 6 (tag) wraps exactly one child item. Tags never reach this
/// module — `reject_floats_and_tags` runs first — but the walk handles
/// them so it is total over well-formed CBOR rather than only over what
/// its caller happens to pass.
const MAJOR_TAG: u8 = 6;
/// Major type 7 carries floats, simple values and the break code. Its
/// shortest-form rules differ from types 0-6, so the non-shortest-form
/// classification deliberately excludes it — see
/// [`find_encoding_violation`].
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
/// cause; the cause explains it, and is derived from the whole input rather
/// than from that position. An earlier design returned `None` for the
/// offset on the [`NonCanonicalCause::ArraySortOrder`] arm, which threw
/// away a genuine locator for no gain.
///
/// Order of resolution matters, though both checks are decisive and so
/// cannot contradict each other: the array check runs first because it is
/// the cause a clean-room implementer is likeliest to hit (#572's
/// narrowing is exactly about array order), and because it is the cheaper
/// of the two.
pub(super) fn classify_non_canonical(
    manifest: &Manifest,
    input: &[u8],
    re_encoded: &[u8],
) -> (NonCanonicalCause, Option<usize>) {
    let at = first_divergence(input, re_encoded);

    if !arrays_are_sorted(manifest) {
        return (NonCanonicalCause::ArraySortOrder, at);
    }

    let cause = find_encoding_violation(input).unwrap_or(NonCanonicalCause::Unclassified);

    (cause, at)
}

/// Offset of the first byte at which the two buffers differ.
fn first_divergence(input: &[u8], re_encoded: &[u8]) -> Option<usize> {
    input.iter().zip(re_encoded).position(|(a, b)| a != b)
}

/// Walk `bytes` as a CBOR item and return the first encoding-level
/// canonicality violation it *contains*, if any.
///
/// **Decisive, not positional.** `ciborium`'s `Value` reader collapses
/// indefinite lengths and non-shortest-form heads on parse, so a body that
/// contains either one and reached the §4.3 step-4 comparison is guaranteed
/// to have diverged because of it. Finding one therefore proves the cause;
/// finding none leaves [`NonCanonicalCause::Unclassified`], which is the
/// honest answer for map-key disorder — the one shape that re-encodes to a
/// different byte string while every individual head stays canonical.
///
/// Only the ONE top-level item is walked. Trailing bytes after it are not
/// scanned: `ciborium::de::from_reader` does not require EOF, so a body can
/// carry them, but garbage after the item is a length divergence rather
/// than a canonicality violation *of* the item, and reporting a head found
/// there as the cause would be the same positional guess this function
/// exists to remove.
///
/// Iterative by construction. CBOR is prefix-ordered — a container's
/// children immediately follow its head — so a single count of items still
/// owed is a complete traversal state, needing neither a stack nor
/// recursion. That also makes the walk immune to adversarial nesting depth,
/// which matters because fuzz inputs reach `decode_manifest`.
///
/// Returns `None` — deferring to `Unclassified` — for a truncated argument
/// or payload, and for the reserved additional-information values 28-30.
/// Neither is a shortest-form question, and neither is well-formed CBOR, so
/// the walk cannot soundly continue past it. Each loop iteration consumes
/// at least one byte, so the walk always terminates.
fn find_encoding_violation(bytes: &[u8]) -> Option<NonCanonicalCause> {
    let mut remaining: u64 = 1;
    let mut pos = 0usize;

    while remaining > 0 {
        remaining -= 1;

        let head = *bytes.get(pos)?;
        pos += 1;

        if head == BREAK_CODE {
            return Some(NonCanonicalCause::IndefiniteLength);
        }

        let major = head >> MAJOR_TYPE_SHIFT;
        let additional = head & ADDITIONAL_INFO_MASK;

        if additional == AI_INDEFINITE && (MAJOR_BYTE_STRING..=MAJOR_MAP).contains(&major) {
            return Some(NonCanonicalCause::IndefiniteLength);
        }

        let argument = if additional <= AI_MAX_INLINE {
            u64::from(additional)
        } else if (AI_ARG_ONE_BYTE..=AI_ARG_EIGHT_BYTE).contains(&additional) {
            let value = read_argument(bytes.get(pos..)?, additional)?;
            pos += argument_width(additional)?;
            // Major type 7's arguments are simple values and floats, which
            // have their own encoding rules. A float cannot reach here at
            // all: `decode_manifest` runs `reject_floats_and_tags` over the
            // whole body before the re-encode comparison.
            if major != MAJOR_SIMPLE_OR_FLOAT && !is_shortest_form(value, additional) {
                return Some(NonCanonicalCause::NonShortestForm);
            }
            value
        } else {
            return None;
        };

        match major {
            // The argument is a payload BYTE length: skip it. This is the
            // step that stops an ordinary character inside a key or a
            // string from ever being read as a head.
            MAJOR_BYTE_STRING | MAJOR_TEXT_STRING => {
                pos = pos.checked_add(usize::try_from(argument).ok()?)?;
                if pos > bytes.len() {
                    return None;
                }
            }
            // The argument is a child-item count.
            MAJOR_ARRAY => remaining = remaining.checked_add(argument)?,
            MAJOR_MAP => remaining = remaining.checked_add(argument.checked_mul(2)?)?,
            MAJOR_TAG => remaining = remaining.checked_add(1)?,
            // Major types 0, 1 and 7 are complete at their head plus
            // argument; they own no payload bytes and no children.
            _ => {}
        }
    }

    None
}

/// Byte width of the argument that additional information `additional`
/// selects. `None` for any value that is not an argument width (0-23,
/// 28-31), so this is correct in isolation rather than only under its
/// caller's contract — the same discipline [`is_shortest_form`] states for
/// itself. A bare `1usize << (additional - AI_ARG_ONE_BYTE)` underflows
/// below 24, which panics under `debug-assertions` (`core/fuzz` sets it).
fn argument_width(additional: u8) -> Option<usize> {
    if !(AI_ARG_ONE_BYTE..=AI_ARG_EIGHT_BYTE).contains(&additional) {
        return None;
    }
    // The range check above is what makes this subtraction provably safe;
    // it is the whole reason this helper exists rather than the expression
    // being inlined at its two call sites.
    Some(1usize << (additional - AI_ARG_ONE_BYTE))
}

/// Read the big-endian argument that follows a head with additional
/// information `additional` (24-27). `None` if `additional` is not an
/// argument width, or if the buffer is truncated.
fn read_argument(rest: &[u8], additional: u8) -> Option<u64> {
    let raw = rest.get(..argument_width(additional)?)?;

    let mut value = 0u64;
    for byte in raw {
        value = (value << 8) | u64::from(*byte);
    }
    Some(value)
}

/// Whether `argument` needs the width `additional` selects, per RFC 8949
/// §4.2.1's shortest-form rule.
///
/// Strictly `>`: the comparison is against the largest value the NEXT
/// width down can hold, so a value exactly equal to that bound still fits
/// below and is non-shortest here. `>=` would wave through `18 17` (23 in
/// a 1-byte argument), `19 00FF`, `1A 0000FFFF` and `1B ..FFFFFFFF` — the
/// four inputs `smallest_value_needing_each_width_is_shortest_form`'s
/// siblings pin, because every other test input agrees under both
/// comparators.
fn is_shortest_form(argument: u64, additional: u8) -> bool {
    match additional {
        AI_ARG_ONE_BYTE => argument > u64::from(AI_MAX_INLINE),
        AI_ARG_TWO_BYTE => argument > u64::from(u8::MAX),
        AI_ARG_FOUR_BYTE => argument > u64::from(u16::MAX),
        AI_ARG_EIGHT_BYTE => argument > u64::from(u32::MAX),
        // Not an argument width at all. Unreachable from
        // `find_encoding_violation`, which range-checks before calling —
        // but answering "shortest" leaves an unexpected head UNCLASSIFIED
        // rather than inventing a violation, so this function is correct in
        // isolation rather than only under its caller's contract.
        // `_ => false` would report a non-shortest-form cause for a head
        // that has no argument.
        _ => true,
    }
}

/// Whether all five arrays `docs/vault-format.md` §4.2 fixes an order for
/// arrived in it.
///
/// Equal adjacent keys count as sorted, which is correct twice over: they
/// are sorted, and `encode_manifest`'s sorts are stable, so a repeat
/// re-encodes in its input order and cannot be the divergence.
///
/// Repeats in FOUR of the five are rejected earlier and separately, by
/// `entries.rs`'s adjacent-equality scans (#594). `recipients` is §4.2's
/// explicit exception and has no such scan — a repeated `contact_uuid`
/// denotes no additional grant and round-trips by design. Do not "tidy up"
/// that asymmetry into a fifth scan: it would narrow a v1-frozen decoder,
/// and `accepts_duplicate_contact_uuid_in_recipients` exists to red if
/// someone does.
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
