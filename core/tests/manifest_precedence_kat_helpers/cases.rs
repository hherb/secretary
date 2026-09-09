//! The corpus TABLE: which map a repeat is planted in, what its second
//! copy is, and which rule `docs/vault-format.md` §4.2 requires a
//! conformant reader to report.
//!
//! Every row plants a REPEATED map key. What varies is the second copy's
//! content, and that is the whole point: §4.2's precedence paragraph
//! fixes what a reader reports when a body breaks more than one rule at
//! once, and each shape below breaks a different second rule alongside
//! the repeat.

/// The map a repeat is planted in.
///
/// Six, because these are six DIFFERENT parsers on the Rust side
/// (`parse_manifest_map`, `parse_kdf_params`, `parse_vector_clock_entry`
/// for both the top-level array and each block's summary, and the block
/// and trash entry parsers). Python has fewer -- `_decode_strict_entry_map`
/// serves `kdf_params` and both vector-clock shapes -- so do not describe
/// this as "six parsers on both sides".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// The top-level manifest map.
    Top,
    /// The `kdf_params` map.
    KdfParams,
    /// `vector_clock[1]`.
    VectorClock,
    /// `blocks[1]`.
    Block,
    /// `trash[1]`.
    Trash,
    /// `blocks[1].vector_clock_summary[1]` -- the deepest map in the body.
    BlockSummary,
}

impl Level {
    pub const ALL: [Level; 6] = [
        Level::Top,
        Level::KdfParams,
        Level::VectorClock,
        Level::Block,
        Level::Trash,
        Level::BlockSummary,
    ];

    /// The label fragment naming this map.
    pub fn label(self) -> &'static str {
        match self {
            Level::Top => "top",
            Level::KdfParams => "kdf_params",
            Level::VectorClock => "vector_clock",
            Level::Block => "block",
            Level::Trash => "trash",
            Level::BlockSummary => "block_summary",
        }
    }

    /// The key this level repeats.
    ///
    /// Each is §4.2-REQUIRED in its own map and has a declared type a
    /// text string violates, so [`Shape::WrongType`]'s second copy is
    /// genuinely malformed for it rather than merely unusual.
    pub fn key(self) -> &'static str {
        match self {
            Level::Top => "vault_uuid",
            Level::KdfParams => "iterations",
            Level::VectorClock | Level::BlockSummary => "counter",
            Level::Block | Level::Trash => "block_uuid",
        }
    }
}

/// What the repeated key's SECOND copy contains.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// A body with no repeat at all -- the corpus's accept control.
    ///
    /// Without it every row rejects, and a reader that rejected
    /// everything unconditionally would score a perfect result.
    Control,
    /// A second copy that is a VALID value for the key.
    ///
    /// The base case the other three are measured against: it breaks only
    /// crypto-design §6.2 rule 5, so nothing competes with the repeat and
    /// the reported rule is unambiguous. Without it, a reader could report
    /// the repeat for the wrong reason on every remaining row and still
    /// pass.
    WellTyped,
    /// A second copy of the wrong CBOR type for the key (a text string
    /// where §4.2 requires a byte string or an unsigned integer).
    ///
    /// Breaks rule 5 AND the key's declared type. §4.2 requires the
    /// REPEAT to win: a reader must not interpret a repeated key's second
    /// copy at all.
    WrongType,
    /// A second copy that is a CBOR float.
    ///
    /// Breaks rule 5 AND §6.2 rule 4. §4.2 requires RULE 4 to win,
    /// because it is enforced by a walk of the whole body that completes
    /// before any key is interpreted.
    Float,
    /// A second copy that is WELL-TYPED but whose head is written in
    /// non-shortest form (§6.2 rule 3).
    ///
    /// The row that pins the rule-4 walk's SCOPE. §4.2 orders rule 4 ahead
    /// of the repeat because both reader architectures enforce it by a
    /// separate walk; rules 2 and 3 are explicitly NOT in that ordering,
    /// so a reader must not fold them into the same walk. Widening
    /// `conformance.py`'s pre-pass to `_check_canonical_item` -- i.e.
    /// rules 2, 3 and 4 together -- makes this row report rule 3 where
    /// `decode_manifest` reports the repeat. Measured: before this row
    /// existed that widening left the whole verifier GREEN, so the scope
    /// was documented in three places and pinned in none.
    ///
    /// **`Level::Top` only, and the restriction is the spec's, not a
    /// convenience.** At a nested level a byte-retaining reader checks the
    /// ENCLOSING value's canonicality -- recursively, before any nested
    /// parser sees its own repeat -- while a normalising reader has
    /// already erased the non-shortest head at parse time. That is
    /// precisely the ordering §4.2 declares unspecified, so a nested row
    /// here would assert something no conformant reader owes.
    NonShortest,
    /// A second copy that is a CBOR tag. The rule-4 twin of [`Shape::Float`].
    ///
    /// Both shapes exist because §6.2 rule 4 forbids two different
    /// things, and a reader that walked for floats but not tags would be
    /// conformant against a corpus carrying only [`Shape::Float`]. They
    /// share one [`Expect`] word -- see its doc for why the DISTINCTION
    /// is carried by the label and the bytes rather than by the column.
    Tag,
}

impl Shape {
    /// The four shapes that plant a repeat. [`Shape::Control`] is not
    /// among them and is added once, outside the level product.
    pub const PLANTED: [Shape; 4] = [Shape::WellTyped, Shape::WrongType, Shape::Float, Shape::Tag];

    pub fn label(self) -> &'static str {
        match self {
            Shape::Control => "control",
            Shape::WellTyped => "well_typed",
            Shape::WrongType => "wrong_type",
            Shape::NonShortest => "non_shortest",
            Shape::Float => "float",
            Shape::Tag => "tag",
        }
    }
}

/// What §4.2 requires a conformant reader to report for a row.
///
/// A closed enum rather than a `bool` plus two `Option`s, for the reason
/// #608's review gave `manifest_uniqueness_kat.rs`'s `Verdict`: the
/// looser shape makes "rejected, but the table says nothing about how"
/// representable, and that degrades silently to "rejected somehow" --
/// the vacuity #599 removed from this corpus family once already.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// The body decodes.
    Accept,
    /// The repeat is reported, naming the repeated key, WITHOUT
    /// interpreting its second copy.
    ///
    /// Carries no payload: the key's name is a property of the ROW (see
    /// [`Case::field`]), not of the vocabulary word, and holding it here
    /// would force the replay to mint a `&'static str` from fixture text.
    DuplicateKey,
    /// §6.2 rule 4's whole-body walk fires before any key is
    /// interpreted, so it outranks the repeat.
    ///
    /// ONE word for both the float and the tag shape, deliberately.
    /// Rust's tight spellings -- `CanonicalError::{FloatRejected,
    /// TagRejected}` -- are unavailable across the crate boundary
    /// (`vault::canonical` is `pub(crate)`, `core/src/vault/mod.rs:24`),
    /// exactly as `manifest_canonicality_kat_helpers::assert` records for
    /// its own `FloatWalk` arm. The alternatives were to widen the
    /// crate's public API from inside a test-corpus slice, or to
    /// discriminate on `Display` text -- the substring trap #608's review
    /// found on this corpus family. Neither is worth a distinction the
    /// row's LABEL and its BYTES already carry, the latter pinned by
    /// `every_row_body_matches_the_case_its_label_names`; the tight forms
    /// stay pinned in-crate by `manifest::decode`'s own unit tests.
    Rule4,
}

impl Expect {
    /// The fixture's `expect` column: one closed vocabulary both
    /// languages read.
    pub fn name(self) -> &'static str {
        match self {
            Expect::Accept => "accept",
            Expect::DuplicateKey => "duplicate_key",
            Expect::Rule4 => "rule4",
        }
    }

    /// Every spelling `name` can produce, so a reader can reject an
    /// unrecognised one rather than treating it as "no expectation".
    pub const ALL_NAMES: [&'static str; 3] = ["accept", "duplicate_key", "rule4"];
}

/// One corpus row.
#[derive(Clone, Copy, Debug)]
pub struct Case {
    pub level: Level,
    pub shape: Shape,
}

impl Case {
    /// `<level>__<shape>`, DERIVED from the two fields rather than
    /// written out, so a row whose label disagrees with what it plants is
    /// unconstructible (#613's `Mutation::ReverseArray` lesson).
    pub fn label(&self) -> String {
        match self.shape {
            Shape::Control => "control__no_repeat".to_string(),
            _ => format!("{}__{}", self.level.label(), self.shape.label()),
        }
    }

    /// The repeated key this row names, or `None` where it names none.
    ///
    /// Derived from the level, so a row cannot claim a key its plant did
    /// not touch.
    pub fn field(&self) -> Option<&'static str> {
        match self.expect() {
            Expect::DuplicateKey => Some(self.level.key()),
            _ => None,
        }
    }

    /// The rule §4.2 requires for this row -- derived from the shape, not
    /// stored, so the two cannot disagree.
    pub fn expect(&self) -> Expect {
        match self.shape {
            Shape::Control => Expect::Accept,
            Shape::WellTyped | Shape::WrongType | Shape::NonShortest => Expect::DuplicateKey,
            Shape::Float | Shape::Tag => Expect::Rule4,
        }
    }
}

/// The whole corpus: one accept control, then every (level, planted
/// shape) pair.
pub fn all_cases() -> Vec<Case> {
    let mut out = vec![Case {
        level: Level::Top,
        shape: Shape::Control,
    }];
    for level in Level::ALL {
        for shape in Shape::PLANTED {
            out.push(Case { level, shape });
        }
    }
    // Not part of the product: see `Shape::NonShortest` for why §4.2 makes
    // this row top-level-only rather than convenience making it so.
    out.push(Case {
        level: Level::Top,
        shape: Shape::NonShortest,
    });
    out
}
