//! §4.2's v1 sentinel fields, enforced on the WRITE side (#587).
//!
//! `docs/vault-format.md` §4.2 fixes three fields of every v1 manifest
//! body:
//!
//! | Field | v1 value | Constant |
//! |---|---|---|
//! | `manifest_version` | 1 | [`MANIFEST_VERSION_V1`] |
//! | `format_version` | 1 | [`FORMAT_VERSION_V1`] |
//! | `suite_id` | 1 | [`SUITE_ID_V1`] |
//!
//! `decode_manifest` has rejected anything else since v1. `encode_manifest`
//! did not, and [`Manifest`]'s three sentinel fields are `pub` with no
//! type-level invariant — so a caller could set `manifest_version: 7`,
//! `encode_manifest` would serialise it, and `sign_manifest` (whose step 1
//! *is* `encode_manifest`) would hybrid-sign the result: a signed manifest
//! no v1 client can open.
//!
//! That is the same defect #600 closed for §4.2's repeated-value rules and
//! #586/#602 closed for duplicate map keys — an encoder emitting a signed
//! document its own decoder rejects. It is an availability defect, not a
//! confidentiality one: the manifest is owner-signed, so the producer is
//! always a caller in this process. But for a format frozen for decades
//! with a clean-room mandate, that is still a real defect.
//!
//! # Why the DECODER is deliberately not routed through this module
//!
//! The obvious tidy — one shared checker both directions call, the shape
//! [`super::uniqueness`] has — is **wrong here**, and the reason is a
//! behaviour change that no fixture in this tree would catch.
//!
//! `parse_manifest_map` interleaves each sentinel comparison with the
//! `Once::require` call that produces the value:
//!
//! ```text
//! let manifest_version = manifest_version.require(KEY_MANIFEST_VERSION)?;
//! if manifest_version != MANIFEST_VERSION_V1 { return Err(Unsupported…) }
//! let format_version = format_version.require(KEY_FORMAT_VERSION)?;
//! …
//! ```
//!
//! A shared checker needs all three values at once, so adopting one would
//! hoist the three `require` calls above the three comparisons — and that
//! **changes which error a body reports** when it both declares a bad
//! sentinel and omits a later required key: `UnsupportedManifestVersion`
//! today, `MissingField` after. On a v1-frozen decoder, silently.
//!
//! This is verbatim the #589 lesson: `Once::set` takes a closure precisely
//! because an eager `set(field, index, take_u64(v, KEY)?)` reverses the
//! duplicate-key-vs-malformed-value precedence, and *no test in the tree
//! could see it* because every fixture varies one thing at a time.
//!
//! What sharing would have bought is cheap to buy directly: the three v1
//! values are already single-sourced as the constants above, so the two
//! directions cannot drift on the VALUES. Only the list of WHICH fields
//! are sentinel-checked could drift, and
//! `tests::each_v1_sentinel_is_rejected_in_both_directions` pins that by
//! driving both directions over the same three fields, so a sentinel added
//! to one and not the other reds.

use super::{Manifest, ManifestError, FORMAT_VERSION_V1, MANIFEST_VERSION_V1, SUITE_ID_V1};

/// Reject a [`Manifest`] whose v1 sentinel fields are not the v1 values,
/// BEFORE it is encoded (#587).
///
/// Checked in §4.2 field order — `manifest_version`, `format_version`,
/// `suite_id` — which is also the order `parse_manifest_map` reports them
/// in, so a body violating more than one sentinel names the same field
/// whichever direction rejects it. That agreement is asserted by
/// `tests::a_body_violating_two_sentinels_names_the_first_in_field_order`
/// rather than left to coincidence.
///
/// # It is also on the DECODE path, and cannot fire there
///
/// §4.3 step 4 re-encodes the parsed manifest through
/// [`encode_manifest`] — not through a lower-level helper, deliberately,
/// so the bytes step 4 compares against are the bytes a writer would
/// actually emit — so this function runs on every vault open too.
/// `parse_manifest_map` has already rejected all three non-v1 sentinels
/// by then, with the DECODE-side variants, so what reaches here is v1 by
/// construction.
///
/// **That ordering is what keeps the decoder's own check falsifiable, and
/// the separate `Encode*` variants are what make it so — measured, not
/// argued.** Had the write side reused
/// [`ManifestError::UnsupportedManifestVersion`] and its two siblings,
/// deleting `parse_manifest_map`'s sentinel rejection would leave a bad
/// body still rejected — by this function, at the re-encode, with a
/// byte-identical error — and nothing would say so. Verified by execution:
/// with the variants collapsed onto the decoder's three *and* the
/// decoder's own check deleted, the whole `secretary-core --lib` suite
/// reported **602 passed, 0 failed, exit 0**. With the variants separate,
/// the same deletion reds
/// `tests::the_decode_side_check_is_not_backstopped_by_this_one` and
/// nothing else.
///
/// So this is #600's ruling — "the bytes you gave me" and "the value you
/// asked me to encode" are different events — arriving at the same answer
/// for a second, independent reason. Do not collapse the two directions
/// onto one variant as a tidy-up.
pub(super) fn check_v1_sentinels(m: &Manifest) -> Result<(), ManifestError> {
    if m.manifest_version != MANIFEST_VERSION_V1 {
        return Err(ManifestError::EncodeUnsupportedManifestVersion(
            m.manifest_version,
        ));
    }
    if m.format_version != FORMAT_VERSION_V1 {
        return Err(ManifestError::EncodeUnsupportedFormatVersion(
            m.format_version,
        ));
    }
    if m.suite_id != SUITE_ID_V1 {
        return Err(ManifestError::EncodeUnsupportedSuiteId(m.suite_id));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
