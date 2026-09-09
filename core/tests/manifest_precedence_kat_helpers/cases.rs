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
/// FIVE distinct parsers cover these levels on the Rust side, not six:
/// `parse_manifest_map` (serving both [`Level::Top`] and
/// [`Level::TopVersion`]), `parse_kdf_params`, `parse_vector_clock_entry`
/// (serving the top-level array AND each block's summary -- one function,
/// two positions), and the block and trash entry parsers. Python has
/// fewer still, since `_decode_strict_entry_map` serves `kdf_params` and
/// both vector-clock shapes. So do not describe this as "one parser per
/// level" on either side.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// The top-level manifest map, repeating `vault_uuid`.
    Top,
    /// The top-level manifest map, repeating `manifest_version`.
    ///
    /// The same parser as [`Level::Top`], and a separate level only
    /// because [`Shape::BadVersion`] needs a key carrying a version
    /// check. See that shape for why the corpus owes this one a row.
    TopVersion,
    /// The `kdf_params` map.
    KdfParams,
    /// `vector_clock[0]`.
    VectorClock,
    /// `blocks[1]`.
    Block,
    /// `trash[0]`.
    Trash,
    /// `blocks[1].vector_clock_summary[1]` -- the deepest map in the body.
    BlockSummary,
}

impl Level {
    pub const ALL: [Level; 7] = [
        Level::Top,
        Level::TopVersion,
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
            Level::TopVersion => "top_version",
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
            Level::TopVersion => "manifest_version",
            Level::KdfParams => "iterations",
            Level::VectorClock | Level::BlockSummary => "counter",
            Level::Block | Level::Trash => "block_uuid",
        }
    }

    /// The map name `conformance.py` reports for a repeat found here.
    ///
    /// These are the clean-room reader's own spellings. Six maps, seven
    /// levels: [`Level::Top`] and [`Level::TopVersion`] necessarily share
    /// one, being the same map. What is unique per level is the PAIR
    /// `(map_label, key)`, and that is what
    /// `every_level_is_identified_by_its_map_and_key` pins -- neither
    /// column identifies a level on its own, which is exactly why the
    /// corpus needs both. `map_label` tells `block` from `trash` and
    /// `vector_clock` from `block_summary`, where the repeated key is
    /// shared; `key` tells the two top-level rows apart, where the map is.
    ///
    /// The two `entry` spellings are not a naming inconsistency: Python
    /// routes the block and trash maps through `_decode_manifest_entry_map`
    /// and the rest through `_decode_strict_entry_map`, and the labels
    /// follow the parser rather than the field.
    pub fn map_label(self) -> &'static str {
        match self {
            Level::Top | Level::TopVersion => "manifest",
            Level::KdfParams => "kdf_params",
            Level::VectorClock => "vector_clock",
            Level::Block => "blocks entry",
            Level::Trash => "trash entry",
            Level::BlockSummary => "vector_clock_summary",
        }
    }

    /// Which element of its enclosing array a nested level sits in, or
    /// `None` for the two levels that are not inside an array.
    ///
    /// **BOTH ENDS are planted, and that is #608's review lesson in
    /// full.** Planting every nested repeat in element 1 catches a reader
    /// scoped to element 0 and leaves its mirror image -- a reader that
    /// SKIPS element 0, the `for block in blocks.iter().skip(1)` shape
    /// #608 actually measured -- fully conformant. Planting every repeat
    /// in element 0 has the same defect in the other direction. So
    /// `vector_clock` and `trash` plant at 0 while `blocks` and its
    /// nested summary plant at 1, and `both_array_ends_are_planted` reds
    /// if a future edit collapses them onto one end.
    pub fn elem(self) -> Option<usize> {
        match self {
            Level::Top | Level::TopVersion | Level::KdfParams => None,
            Level::VectorClock | Level::Trash => Some(0),
            Level::Block | Level::BlockSummary => Some(1),
        }
    }
}

/// What the repeated key's SECOND copy contains.
///
/// **There is deliberately no shape breaking §6.2 rules 1, 2 or 3**, and
/// re-adding one would make this corpus reject a CONFORMANT reader. §4.2
/// fixes the order of rule 4 and of the repeated-key rule, and declares
/// the order of rules 1-3 against those two unspecified, because the two
/// reader architectures it admits necessarily detect them at different
/// points. A row pairing a repeat with, say, a non-shortest-form head
/// therefore has two correct answers, and demanding either one outlaws a
/// design §4.2 itself permits.
///
/// An earlier revision of this corpus carried exactly such a row
/// (`top__non_shortest`) to pin that the rule-4 walk is rule-4-ONLY.
/// That scope is a property of one implementation, not of `docs/`, so it
/// is now pinned where it belongs: `conformance.py`'s Section CS asserts
/// directly that `reject_floats_and_tags` returns cleanly for a body
/// whose only fault is a rule-2 or rule-3 violation. That is a sharper
/// pin than the row was, and it claims nothing of anyone else's reader.
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
    /// A second copy of the RIGHT CBOR type whose value overflows the
    /// key's declared width (a `u32` field given 2^40).
    ///
    /// §4.2 ordering 2 names three competing checks -- "the type, range
    /// and version checks on that key's value" -- and this is the second.
    /// Without it the corpus enumerated one of the three and the other
    /// two agreed across the two implementations only BY CONSTRUCTION,
    /// which is the state this corpus exists to replace.
    ///
    /// **Level-restricted**, like [`Shape::BadVersion`]: it needs a key
    /// whose declared width is narrower than CBOR's, which among the keys
    /// this corpus repeats is `kdf_params.iterations` (`u32`) alone.
    /// `counter` is a `u64`, and the uuid keys are byte strings.
    OutOfRange,
    /// A second copy that is a well-typed, in-range `u8` carrying a
    /// version this client does not speak.
    ///
    /// The third of §4.2 ordering 2's three competing checks. Its own
    /// level exists for it ([`Level::TopVersion`]) because `manifest_version`
    /// is the only key with a version check, and #587 had just made the
    /// writer half of that check normative -- so the one field whose value
    /// check landed in the immediately preceding slice had no precedence
    /// row at all.
    BadVersion,
    /// A second copy that is a CBOR float.
    ///
    /// Breaks rule 5 AND §6.2 rule 4. §4.2 requires RULE 4 to win,
    /// because it is enforced by a walk of the whole body that completes
    /// before any key is interpreted.
    Float,
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
            Shape::OutOfRange => "out_of_range",
            Shape::BadVersion => "bad_version",
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
            Shape::WellTyped | Shape::WrongType | Shape::OutOfRange | Shape::BadVersion => {
                Expect::DuplicateKey
            }
            Shape::Float | Shape::Tag => Expect::Rule4,
        }
    }

    /// The map name `conformance.py`'s `DuplicateMapKey` must report, or
    /// `None` where the row reports no repeat.
    ///
    /// **Python-only, the mirror of [`PlantedBody::dup_index`] being
    /// Rust-only.** `ManifestError::DuplicateKey` carries a field name and
    /// an ordinal but no map name, so the Rust replay cannot assert this
    /// column; it asserts only that the fixture's value matches this
    /// table. It exists because `_LEVEL_KEYS` alone is MANY-TO-ONE --
    /// `block` and `trash` both repeat `block_uuid`, `vector_clock` and
    /// `block_summary` both repeat `counter` -- so before this column four
    /// of the levels were mutually interchangeable on the clean-room side
    /// and a body swap between them passed Section MPR.
    ///
    /// [`PlantedBody::dup_index`]: super::build::PlantedBody::dup_index
    pub fn map_label(&self) -> Option<&'static str> {
        match self.expect() {
            Expect::DuplicateKey => Some(self.level.map_label()),
            _ => None,
        }
    }
}

/// The whole corpus: one accept control, every (level, planted shape)
/// pair, then the two level-restricted shapes.
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
    // Outside the product because each needs a key the other levels do
    // not have: a width-narrowed integer, and the one field carrying a
    // version check. See the two shapes' own docs.
    out.push(Case {
        level: Level::KdfParams,
        shape: Shape::OutOfRange,
    });
    out.push(Case {
        level: Level::TopVersion,
        shape: Shape::BadVersion,
    });
    out
}
