//! The byte-level well-formedness walk, projected onto each vault-body
//! decoder's own error type (#666).
//!
//! `cbor::well_formed::walk_first_item` answers in its own vocabulary
//! ([`WalkFault`]); every caller must turn that into its layer's error enum.
//! `record::decode` did it with a private function. `decode_manifest` and
//! `block::decode_plaintext` need the same projection, and three hand-copies
//! of one rule is where this repo's duplicated-rule failures start (#589's
//! 31 duplicate-key guards, #597's seven required-key checks, #669's
//! `isinstance` copies). So the rule lives here once.
//!
//! **Why here and not in `cbor`.** The rule-4 arms must name
//! [`CanonicalError`], which lives under `vault`; putting this in `cbor`
//! would invert the layering. Not `legacy.rs`, which holds the pre-split
//! helpers.
//!
//! **What each caller still supplies.** Only its own `CborDecode`
//! constructor. The rule-4 arms go through the caller's
//! `From<CanonicalError>`, which each of this function's FOUR callers
//! already has and which already maps these two variants — so this function
//! introduces no new mapping for a future variant to disagree with. Say
//! "these four callers", not "every vault-body error enum" (PR #689
//! review; #691 made `CardError` the fourth): `BundleError` still converts
//! only through its free function `canonical_error_to_bundle_error` and
//! implements no such `From`, so it would not satisfy the `E:
//! From<CanonicalError>` bound without one being added first. `CardError`
//! gained `impl From<CanonicalError> for CardError` (delegating to
//! `canonical_error_to_card_error`) already in #641, ahead of having any
//! caller to use it for; #691 is what made it an actual caller of this
//! function.

use crate::cbor::{walk_first_item, CborFault, WalkFault};

use super::CanonicalError;

/// The `field` hint both rule-4 arms pass.
///
/// The same hint each caller's tree-wide `reject_floats_and_tags` call
/// already passes at the same site, so wiring this walk in front of it does
/// not move the reported message.
const WALK_ROOT_HINT: &str = "<root>";

/// Walk the first CBOR item in `bytes` before anything is parsed, projecting
/// the outcome onto the caller's error type.
///
/// Returns the offset one past the first item. Callers discard it: trailing
/// bytes are judged by the §4.3 step-4 re-encode comparison, where
/// `record::decode` has always judged them, because `ciborium` performs no
/// EOF check.
///
/// **The rule-4 arms DROP the walk's byte offset, deliberately.**
/// `WalkFault::{Tag, Float}` each carry one, and the `Malformed` arm keeps
/// its `CborFault::offset`, so the asymmetry is worth stating rather than
/// leaving to be rediscovered (PR #689 review). `CanonicalError::{TagRejected,
/// FloatRejected}` carry a `&'static str` hint and no position, and widening
/// them is an API change on a v1-frozen error enum reached from four other
/// callers. The practical cost is on the manifest path: a narrow bignum used
/// to be reported as `NonCanonicalEncoding { cause, at }` with a byte offset
/// and is now `Canonical(TagRejected { field: "<root>" })` with none.
///
/// A well-formedness fault anywhere outranks a rule-4 fault anywhere —
/// `docs/vault-format.md` §4.2's precondition. §4.2 requires this ordering
/// of the manifest body; for this function's other three callers,
/// `record::decode`, `block::decode_plaintext` and
/// `ContactCard::from_canonical_cbor`, §5/§6.1/§6.3 fix no report
/// order at all, so the same ordering there is parity with the manifest
/// path rather than a spec obligation, pending #668. That precedence is
/// [`walk_first_item`]'s, not this function's; this function only routes.
pub(crate) fn walk_first_item_checked<E>(
    bytes: &[u8],
    cbor_decode: fn(CborFault) -> E,
) -> Result<usize, E>
where
    E: From<CanonicalError>,
{
    walk_first_item(bytes).map_err(|fault| match fault {
        WalkFault::Malformed(fault) => cbor_decode(fault),
        WalkFault::Tag { .. } => CanonicalError::TagRejected {
            field: WALK_ROOT_HINT,
        }
        .into(),
        WalkFault::Float { .. } => CanonicalError::FloatRejected {
            field: WALK_ROOT_HINT,
        }
        .into(),
    })
}

#[cfg(test)]
mod tests {
    //! These exercise the router through `RecordError`, a type that lives
    //! ABOVE this module in the layering its own doc argues for. That is
    //! deliberate rather than an oversight (PR #689 review raised it): the
    //! property under test is "the caller's `From<CanonicalError>` maps these
    //! two variants where the caller expects", and a synthetic test-only
    //! error implementing the trait would prove that of the synthetic type
    //! only. `RecordError` is the caller whose private
    //! `walk_fault_to_record_error` this function replaced, so it is the one
    //! whose behaviour must be shown unchanged. `#[cfg(test)]`-only, so no
    //! production dependency runs in this direction.

    use super::*;
    use crate::cbor::CborErrorKind;
    use crate::vault::record::RecordError;

    /// A well-formedness fault goes through the caller's own constructor,
    /// carrying the fault verbatim.
    #[test]
    fn a_malformed_body_reaches_the_callers_cbor_decode_arm() {
        // 0x82 opens a 2-element array; the input ends after one element.
        let err = walk_first_item_checked(&[0x82, 0x00], RecordError::CborDecode).unwrap_err();
        match err {
            RecordError::CborDecode(fault) => {
                assert_eq!(fault.kind, CborErrorKind::Io);
                assert!(fault.offset.is_some(), "the walk always reports an offset");
            }
            other => panic!("expected CborDecode, got {other:?}"),
        }
    }

    /// A tag goes through `From<CanonicalError>`, with the root hint.
    #[test]
    fn a_tag_reaches_the_callers_canonical_arm() {
        // c2 41 01 = bignum tag 2 over a 1-byte string.
        let err =
            walk_first_item_checked(&[0xc2, 0x41, 0x01], RecordError::CborDecode).unwrap_err();
        assert!(matches!(err, RecordError::TagRejected), "got {err:?}");
    }

    /// A float likewise, and the hint is the one the tree-wide walk passes.
    #[test]
    fn a_float_reaches_the_callers_canonical_arm_with_the_root_hint() {
        // f9 00 00 = half-precision 0.0
        let err =
            walk_first_item_checked(&[0xf9, 0x00, 0x00], RecordError::CborDecode).unwrap_err();
        match err {
            RecordError::FloatRejected { field } => assert_eq!(field, WALK_ROOT_HINT),
            other => panic!("expected FloatRejected, got {other:?}"),
        }
    }

    /// This function has no ordering logic of its own — it is a pure router
    /// onto the caller's error type — so this only demonstrates that it
    /// forwards whichever fault `walk_first_item` returned, here a
    /// well-formedness fault LATER in the body rather than the rule-4 fault
    /// EARLIER in it. `walk_first_item` is where that precedence actually
    /// lives (`docs/vault-format.md` §4.2, for the manifest body; parity
    /// pending #668 for this function's other three callers); it is pinned
    /// end to end for `record::decode` by `record_walk_tests.rs`.
    #[test]
    fn a_later_malformed_fault_outranks_an_earlier_tag() {
        // 82 c2 41 01 f7 = [bignum, undefined]
        let err = walk_first_item_checked(&[0x82, 0xc2, 0x41, 0x01, 0xf7], RecordError::CborDecode)
            .unwrap_err();
        assert!(matches!(err, RecordError::CborDecode(_)), "got {err:?}");
    }

    /// The accepted body's end offset is returned, so a caller can judge
    /// trailing bytes if it wants to.
    #[test]
    fn an_accepted_body_returns_its_end_offset() {
        let ok =
            walk_first_item_checked::<RecordError>(&[0x81, 0x00, 0xff], RecordError::CborDecode);
        assert_eq!(ok.unwrap(), 2, "the walk consumes only the first item");
    }
}
