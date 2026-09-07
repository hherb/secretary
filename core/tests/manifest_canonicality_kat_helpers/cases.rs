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
    /// from the SPLICE family: `ArraySortOrder` and `Unclassified`
    /// need bodies that are not `unknown`-subtree splices at all, so
    /// neither can be an eighth `Shape`. That is why the corpus has a
    /// second family ([`mutations`]) rather than more shapes -- #613,
    /// closed in this file. Both causes now carry corpus rows and
    /// cross-language agreement; `causes_seen == ALL_CAUSES` in the
    /// replay is what keeps every variant covered.
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

// ---------------------------------------------------------------------------
// The second case family: whole-body mutations (#613)
// ---------------------------------------------------------------------------
//
// `NonCanonicalCause` has four variants and the splice family above reaches
// two. The other two need bodies that are not `unknown`-subtree splices at
// all, so they cannot be expressed as an eighth `Shape` -- which is what
// left `ArraySortOrder` and `Unclassified` pinned by Rust unit tests only,
// with nothing for a clean-room reader to agree with (#613).
//
// Both are mutations of the SAME base manifest the splice family uses, at
// `Level::Top`, so a divergence between two rows is always the mutation and
// never the base.
//
// **What these rows do NOT do, measured rather than assumed.** An earlier
// version of this comment claimed they "pin the arm a peer could once
// *choose*" -- #590's first classifier read the CBOR head at the first
// differing byte, and an ordinary character inside a wire-supplied
// `unknown` KEY (`_` = 0x5F, `z` = 0x7A) is what it misread. That is false
// for every row here: a whole-map reversal always diverges at the reversed
// map's FIRST KEY HEAD, never inside `zzz_needle`, and all four
// `keyorder__*` bodies diverge on a major-type-3 head with additional-info
// <= 23 (0x70, 0x70, 0x74, 0x6B) -- which the positional classifier reads as
// "no violation", i.e. the same `Unclassified` verdict today's decisive one
// gives. These rows deliver the cross-language pin #613 needed; they do not
// discriminate the two classifiers. A row that did would need its first
// divergence to land on a `_` (0x5F, reads as indefinite-length) or an
// `x`/`z` (0x78/0x7A, reads as non-shortest-form) -- tracked as #624.

/// Which CBOR map a [`Mutation::ReverseMapKeys`] targets.
///
/// Four positions rather than one because they are four different parsers
/// on the RUST side: the top-level map (`parse_manifest_map`), `kdf_params`
/// (`parse_kdf_params`), and the two entry maps (`parse_block_entry` /
/// `parse_trash_entry`). Python has three, not four -- `_decode_manifest_
/// entry_map` serves both entry maps -- so "four different parsers on both
/// sides" would be wrong; what the four positions pin is that no nested map
/// is byte-retained by either reader.
///
/// **No block INDEX here, unlike [`SortedArray`], and the asymmetry is
/// deliberate.** Map-key order is caught by a whole-body re-encode in both
/// implementations -- neither has a per-map order check -- so per-position
/// blindness is not expressible for maps the way it is for arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapPath {
    /// The manifest body's own outer map.
    Top,
    /// The `kdf_params` map.
    KdfParams,
    /// `blocks[0]`'s entry map.
    FirstBlock,
    /// `trash[0]`'s entry map.
    FirstTrash,
}

impl MapPath {
    pub const ALL: [MapPath; 4] = [
        MapPath::Top,
        MapPath::KdfParams,
        MapPath::FirstBlock,
        MapPath::FirstTrash,
    ];

    /// The `keyorder__` suffix this position contributes to a row label.
    pub fn label(self) -> &'static str {
        match self {
            MapPath::Top => "top",
            MapPath::KdfParams => "kdf_params",
            MapPath::FirstBlock => "block",
            MapPath::FirstTrash => "trash",
        }
    }
}

/// One of the five arrays `docs/vault-format.md` §4.2 fixes an order for.
///
/// **A closed enum, not the `outer: &str, inner: Option<&str>` pair this
/// replaced.** That pair made invalid states representable: of the 28
/// reachable key combinations only five named a §4.2 array, and while the
/// other 23 panicked loudly, that coincidence was a property of TODAY's
/// base manifest rather than of the type -- a future `BlockEntry` gaining a
/// third array would silently grow an accepting pair that is not one of the
/// five. It also let a row's LABEL disagree with its selector, which was
/// invisible to both languages (measured: relabelling one row left Sections
/// MCK and MCC green). Labels are now DERIVED from this enum, so the
/// disagreement is unconstructible.
///
/// The two nested variants carry a block INDEX because the sort discipline
/// is enforced per block on both sides, and a corpus that only ever plants
/// at `blocks[0]` cannot see a reader scoped to the first block. That gap
/// was measured, in both languages: narrowing Rust's
/// `classify::arrays_are_sorted` to `.take(1)` left the whole workspace
/// green, and narrowing the Python reader's nested sort check to
/// `blocks[0]` left all 26 `conformance.py` sections green. It is the
/// mirror of the defect #608's review fixed on `manifest_uniqueness_kat`,
/// whose fixtures plant at `blocks[1]` for exactly this reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortedArray {
    /// Top-level `vector_clock`, ordered by `device_uuid`.
    VectorClock,
    /// Top-level `blocks`, ordered by `block_uuid`.
    Blocks,
    /// Top-level `trash`, ordered by `block_uuid`.
    Trash,
    /// `blocks[block].recipients` -- §4.2's uniqueness EXCEPTION, but still
    /// sort-disciplined.
    BlockRecipients { block: usize },
    /// `blocks[block].vector_clock_summary`, ordered by `device_uuid`.
    BlockVectorClockSummary { block: usize },
}

impl SortedArray {
    /// Every array position the corpus carries a row for: the three
    /// top-level arrays, and the two nested ones at BOTH block indices.
    pub const ALL: [SortedArray; 7] = [
        SortedArray::VectorClock,
        SortedArray::Blocks,
        SortedArray::Trash,
        SortedArray::BlockRecipients { block: 0 },
        SortedArray::BlockVectorClockSummary { block: 0 },
        SortedArray::BlockRecipients { block: 1 },
        SortedArray::BlockVectorClockSummary { block: 1 },
    ];

    /// The top-level key, and for a nested array the entry key plus the
    /// block index. One place, so `build.rs` cannot address a different
    /// array than the label names.
    pub fn path(self) -> (&'static str, Option<(&'static str, usize)>) {
        match self {
            SortedArray::VectorClock => ("vector_clock", None),
            SortedArray::Blocks => ("blocks", None),
            SortedArray::Trash => ("trash", None),
            SortedArray::BlockRecipients { block } => ("blocks", Some(("recipients", block))),
            SortedArray::BlockVectorClockSummary { block } => {
                ("blocks", Some(("vector_clock_summary", block)))
            }
        }
    }

    /// The `arraysort__` suffix this array contributes to a row label.
    ///
    /// Block 0 is spelled WITHOUT an index (`block_recipients`, not
    /// `block0_recipients`) so the five labels #613 committed keep their
    /// bytes and the fixture stays additive -- the 21 splice rows and the
    /// original 9 mutation rows are byte-identical across this change.
    pub fn label(self) -> String {
        match self {
            SortedArray::VectorClock => "vector_clock".to_string(),
            SortedArray::Blocks => "blocks".to_string(),
            SortedArray::Trash => "trash".to_string(),
            SortedArray::BlockRecipients { block: 0 } => "block_recipients".to_string(),
            SortedArray::BlockVectorClockSummary { block: 0 } => {
                "block_vector_clock_summary".to_string()
            }
            SortedArray::BlockRecipients { block } => format!("block{block}_recipients"),
            SortedArray::BlockVectorClockSummary { block } => {
                format!("block{block}_vector_clock_summary")
            }
        }
    }
}

/// A structure-preserving mutation of the base manifest body.
///
/// Every variant leaves the manifest's VALUES untouched and reorders only
/// the sequence they arrive in, which is what makes the resulting body
/// non-canonical without being malformed: it parses cleanly, every
/// individual head stays canonical, and only the §4.3 step-4 re-encode
/// comparison objects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mutation {
    /// Reverse one of §4.2's sorted arrays.
    ReverseArray(SortedArray),
    /// Reverse the ENTRY ORDER of one CBOR map, leaving every key and
    /// every value byte-identical.
    ReverseMapKeys(MapPath),
}

impl Mutation {
    /// The row label, DERIVED from the selector rather than written beside
    /// it. A row whose label disagreed with what it mutates used to be
    /// representable and was caught by nothing in either language; it is
    /// now unconstructible.
    pub fn label(self) -> String {
        match self {
            Mutation::ReverseArray(array) => format!("arraysort__{}", array.label()),
            Mutation::ReverseMapKeys(path) => format!("keyorder__{}", path.label()),
        }
    }

    /// Every mutation the corpus carries: one per sorted array, one per map
    /// position. Derived from the two `ALL` tables, so adding a position
    /// adds a row and cannot leave a hand-maintained list behind.
    pub fn all() -> Vec<Mutation> {
        SortedArray::ALL
            .into_iter()
            .map(Mutation::ReverseArray)
            .chain(MapPath::ALL.into_iter().map(Mutation::ReverseMapKeys))
            .collect()
    }
}

/// One row of the mutation family.
///
/// Both fields are DERIVED: the label from the mutation, and the verdict
/// from which kind of mutation it is. Array disorder is decisive on the
/// Rust side (`classify::arrays_are_sorted` reads the parsed `Manifest`),
/// so it yields `ArraySortOrder`; map-key disorder leaves every individual
/// head canonical, so `find_encoding_violation` has nothing to report and
/// the honest answer is `Unclassified` -- the arm #590's first
/// implementation got wrong in the direction a peer could choose, and the
/// one whose correctness argument most wanted a second implementation to
/// agree with it.
#[derive(Clone, Copy)]
pub struct MutationCase {
    pub mutation: Mutation,
}

impl MutationCase {
    pub fn label(self) -> String {
        self.mutation.label()
    }

    pub fn verdict(self) -> Verdict {
        match self.mutation {
            Mutation::ReverseArray(_) => {
                Verdict::RejectAtReEncode(NonCanonicalCause::ArraySortOrder)
            }
            Mutation::ReverseMapKeys(_) => {
                Verdict::RejectAtReEncode(NonCanonicalCause::Unclassified)
            }
        }
    }
}

/// The mutation family, derived from [`Mutation::all`].
pub fn mutations() -> Vec<MutationCase> {
    Mutation::all()
        .into_iter()
        .map(|mutation| MutationCase { mutation })
        .collect()
}

/// One corpus row, in whichever of the two families it belongs to.
///
/// The replay looks a fixture label up in [`all_cases`] and rebuilds that
/// row's bytes from the case, so a hand-edited body reds. Keeping both
/// families in ONE list is what makes that lookup total: a label matching
/// neither family has no case, and the replay panics naming it rather than
/// silently checking one fewer row.
#[derive(Clone, Copy)]
pub enum Case {
    /// A [`Shape`] spliced into the `unknown` bag at `level`.
    Splice { level: Level, shape: &'static Shape },
    /// A whole-body [`Mutation`] of the `Level::Top` base manifest.
    Mutate(MutationCase),
}

impl Case {
    /// The row's fixture label.
    pub fn label(self) -> String {
        match self {
            Case::Splice { level, shape } => format!("{}__{}", level.label(), shape.label),
            Case::Mutate(case) => case.label(),
        }
    }

    /// What `decode_manifest` MUST do with this row's body.
    pub fn verdict(self) -> Verdict {
        match self {
            Case::Splice { shape, .. } => shape.verdict,
            Case::Mutate(case) => case.verdict(),
        }
    }
}

/// The whole corpus: the splice family's `Level::ALL x SHAPES` product,
/// then the mutation family in table order.
pub fn all_cases() -> Vec<Case> {
    let mut cases: Vec<Case> = Level::ALL
        .into_iter()
        .flat_map(|level| {
            SHAPES
                .iter()
                .map(move |shape| Case::Splice { level, shape })
        })
        .collect();
    cases.extend(mutations().into_iter().map(Case::Mutate));
    cases
}
