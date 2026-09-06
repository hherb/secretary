//! The seven canonical-CBOR subtree shapes, the three nesting levels they
//! are spliced into, and the verdict `docs/vault-format.md` §4.2 assigns
//! each pair.
//!
//! Extracted from `manifest_canonicality_kat.rs` (#612) to keep the entry
//! file -- which holds the `#[test]` fns -- below the project's 500-LOC
//! guideline. Nothing here is a behaviour change; see this crate's
//! `manifest_canonicality_kat.rs` module doc for what the corpus means.

use secretary_core::vault::manifest::NonCanonicalCause;

/// What `decode_manifest` MUST do with a manifest carrying one of the
/// seven subtree shapes -- the specification, not an observed value.
///
/// **One enum rather than a `bool` plus an `Option`.** That is the
/// shape #608's review removed from `manifest_uniqueness_kat.rs`'s
/// `Case` for making two invalid states representable, and this
/// corpus is read as that one's pair. Both states are unrepresentable
/// here: an ACCEPTED shape cannot carry a cause, and a shape rejected
/// before the re-encode cannot carry one either. The accept-plus-cause
/// combination in particular was previously invisible to the
/// GENERATOR -- its cause assertion sat behind `if let Err(..)`, so a
/// mistyped table entry was written into the fixture and the fuzz
/// seeds before anything objected (#614 review).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The decoder must accept a body carrying this subtree.
    Accept,
    /// Rejected BY the §4.3 step-4 re-encode comparison, which #590
    /// gave a cause and a byte locator.
    RejectAtReEncode(NonCanonicalCause),
    /// Rejected BEFORE that comparison ever runs. Today the only such
    /// mechanism is `reject_floats_and_tags`. Naming the state is the
    /// point: as a bare `None` it was indistinguishable from "this
    /// shape accepts, so there is no rejection to explain".
    RejectBeforeReEncode,
}

impl Verdict {
    /// DERIVED, never stored -- which is what stops it disagreeing
    /// with the cause. Same treatment `Case::accepts()` gives the
    /// sibling corpus.
    pub fn accepts(self) -> bool {
        matches!(self, Verdict::Accept)
    }

    /// This shape's `expect_cause` column value: `Some` only for a
    /// rejection the re-encode comparison itself produced.
    pub fn cause(self) -> Option<NonCanonicalCause> {
        match self {
            Verdict::RejectAtReEncode(c) => Some(c),
            Verdict::Accept | Verdict::RejectBeforeReEncode => None,
        }
    }
}

/// One of the seven canonical-CBOR-profile shapes from vault-format
/// §4.2's per-rule table, plus the verdict the spec assigns it.
pub struct Shape {
    pub label: &'static str,
    /// Raw CBOR bytes of the subtree to splice into an `unknown` bag.
    pub bytes: &'static [u8],
    /// See `generate_manifest_canonicality_kat`'s doc for why the
    /// generator asserts this rather than recording whatever comes
    /// out.
    ///
    /// Only two of the four `NonCanonicalCause` variants are reachable
    /// from this corpus. `ArraySortOrder` and `Unclassified` need
    /// bodies that are not `unknown`-subtree splices at all, so they
    /// stay pinned by Rust unit tests only, with no cross-language
    /// agreement -- tracked as #613 rather than left unrecorded.
    pub verdict: Verdict,
}

pub const SHAPES: &[Shape] = &[
    Shape {
        label: "control_canonical",
        // map(1) { "a": 1 } -- fully canonical: definite-length map
        // head (A1), definite-length 1-byte text key (61 = text(1),
        // 61 = 'a'), shortest-form uint 1 (01).
        bytes: &[0xA1, 0x61, 0x61, 0x01],
        verdict: Verdict::Accept,
    },
    Shape {
        label: "control_array",
        // array(2) [1, 2] -- fully canonical: definite-length array
        // head (82), two shortest-form uints (01, 02).
        bytes: &[0x82, 0x01, 0x02],
        verdict: Verdict::Accept,
    },
    Shape {
        label: "rule1_key_order",
        // map(2) { "zz": 1, "a": 2 } -- the 2-byte key "zz" (62 7A 7A)
        // precedes the 1-byte key "a" (61 61), violating RFC 8949
        // §4.2.1's length-then-bytewise key order. TOLERATED:
        // `ciborium::Value::Map` is an ordered Vec of pairs, so entry
        // order survives the parse and re-encodes byte-identically.
        bytes: &[0xA2, 0x62, 0x7A, 0x7A, 0x01, 0x61, 0x61, 0x02],
        verdict: Verdict::Accept,
    },
    Shape {
        label: "rule5_duplicate_key",
        // map(2) { "a": 1, "a": 2 } -- the key "a" (61 61) repeats.
        // TOLERATED for the same reason as rule1 above: `Value::Map`
        // does not deduplicate, so the repeat survives the round
        // trip.
        bytes: &[0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02],
        verdict: Verdict::Accept,
    },
    Shape {
        label: "rule2_indefinite_map",
        // Indefinite-length map head (BF) { "a": 1 }, closed by a
        // break byte (FF), instead of the definite-length A1 head.
        // REJECTED: `ciborium` parses this into a definite-length
        // `Value::Map` on the way in, so the re-encode emits A1 and
        // differs from the indefinite-length input.
        bytes: &[0xBF, 0x61, 0x61, 0x01, 0xFF],
        verdict: Verdict::RejectAtReEncode(NonCanonicalCause::IndefiniteLength),
    },
    Shape {
        label: "rule3_non_shortest_int",
        // map(1) { "a": <uint8-headed 1> } -- the value 1 is written
        // as 18 01 (uint8 additional-info head + payload byte)
        // instead of the shortest form 01. REJECTED: `ciborium`
        // parses the value as the integer 1 and re-encodes it in
        // shortest form, differing from the non-shortest input.
        bytes: &[0xA1, 0x61, 0x61, 0x18, 0x01],
        verdict: Verdict::RejectAtReEncode(NonCanonicalCause::NonShortestForm),
    },
    Shape {
        label: "rule4_float",
        // map(1) { "a": 1.5f32 } -- FA is the major-type-7 float32
        // head, followed by the IEEE-754 big-endian encoding of 1.5
        // (3F C0 00 00). REJECTED outright: §6.2 rule 4 bans floats
        // anywhere in the body, caught by `reject_floats_and_tags`
        // before the re-encode ever runs.
        bytes: &[0xA1, 0x61, 0x61, 0xFA, 0x3F, 0xC0, 0x00, 0x00],
        verdict: Verdict::RejectBeforeReEncode,
    },
];

/// The placeholder subtree spliced into each level's `unknown` bag
/// before generation starts. Byte-identical to `control_canonical`
/// above (a fully canonical `{"a": 1}`) -- deliberately, so it lands
/// at a genuinely decoder-accepted position to splice over. Same
/// splice-over-a-needle technique as
/// `core/src/vault/manifest/decode/tests.rs::unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`.
pub const NEEDLE: &[u8] = &[0xA1, 0x61, 0x61, 0x01];

#[derive(Clone, Copy)]
pub enum Level {
    Top,
    Block,
    Trash,
}

impl Level {
    pub const ALL: [Level; 3] = [Level::Top, Level::Block, Level::Trash];

    pub fn label(self) -> &'static str {
        match self {
            Level::Top => "top",
            Level::Block => "block",
            Level::Trash => "trash",
        }
    }

    /// Inverse of [`Level::label`], for reading a row label back.
    ///
    /// Exhaustive on purpose, like `cause_name`: a fourth `Level`
    /// fails to compile here rather than silently making every row
    /// at that level unrebuildable.
    pub fn from_label(label: &str) -> Option<Level> {
        Level::ALL.into_iter().find(|lvl| lvl.label() == label)
    }
}
