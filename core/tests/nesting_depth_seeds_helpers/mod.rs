//! Committed seeds for crypto-design §6.2 rule 6, the v1 nesting limit
//! (#667), and the one table the generator and the label-binding check read.
//!
//! **Why both verdicts.** A limit set too LOW is as wrong as none, so each
//! target commits an ACCEPTING body at exactly the limit beside the rejecting
//! one past it. A body far past the limit makes CI prove the Python reader
//! returns a verdict there, where a recursive reader raised `RecursionError`.
//!
//! **Why a separate generator.** `rule_token_seeds.rs` binds a rule TOKEN and
//! can hold no accepting row; this table binds a VERDICT. Its census is
//! scoped to [`SEED_PREFIX`], which that file excludes by name.
//!
//! **Depth arithmetic.** The base's own root map is level 1, so a value
//! holding `d - 1` one-element arrays around a scalar takes the document to
//! exactly `d` levels; a scalar is not a level.

mod prefix;

use std::path::PathBuf;

use ciborium::Value;
pub use prefix::SEED_PREFIX;
use secretary_core::cbor::{CborErrorKind, CborFault, V1_MAX_NESTING_DEPTH};
use secretary_core::vault::manifest::{decode_manifest, encode_manifest, ManifestError};
use secretary_core::vault::record::{self, RecordError};

pub const SEEDED_TARGETS: &[&str] = &["manifest_body", "record"];
/// How many rows the table holds; a row and its seed deleted together are
/// invisible to the two-way census, so the count is pinned separately.
pub const EXPECTED_CASE_COUNT: usize = 9;
/// Past Python's default recursion limit (~1,000), so a recursive reader
/// would fail there with `RecursionError` instead of returning a verdict.
const FAR_PAST_THE_LIMIT: usize = 2048;
/// A key no v1 document defines, so it lands in a forward-compat bag.
const FUTURE_KEY: &str = "zz_future";
const ARRAY_1: u8 = 0x81;
const UINT_0: u8 = 0x00;
const MAP_SMALL_BASE: u8 = 0xa0;
/// The largest count a one-byte map head can carry.
const SMALL_COUNT_MAX: usize = 23;
const SEED_EXTENSION: &str = "bin";

/// Tag 2, the unsigned-bignum tag (RFC 8949 §3.4.3). A duplicate of
/// `nesting_depth_seeds.rs`'s `TAG_BIGNUM_POSITIVE`, deliberately: that file's
/// `Chain` enum builds a document for an in-process assertion
/// (`the_walk_paths_charge_a_level_for_a_short_bignum`), this module's
/// `DeepestLevel` is a seed-TABLE dimension whose file names are a committed
/// contract. Sharing one constant across the two would make this table's
/// seed-generation code reach up into its own caller's private items -- the
/// wrong dependency direction for a helpers module -- for a saving of four
/// one-line constants. `ARRAY_1` / `UINT_0` above are already duplicated the
/// same way for the same reason.
const BIGNUM_TAG: u8 = 0xc2;
/// Major 2 (byte string), length 1.
const BIGNUM_BYTES_1: u8 = 0x41;
/// Major 2, length 9 — one byte past the 8 that fit in a `u64`, which is what
/// makes `ciborium` keep a `Value::Tag` instead of folding it to an integer.
const BIGNUM_BYTES_9: u8 = 0x49;
const BIGNUM_WIDE_LEN: usize = 9;
/// The bignum payload byte, repeated for both widths.
const BIGNUM_PAYLOAD_BYTE: u8 = 0x01;

/// Where the deep value is planted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Under [`FUTURE_KEY`], in the forward-compat bag.
    Unknown,
    /// Under `tags`, a known key whose value would otherwise be a type error.
    KnownTags,
}

/// What sits at the deepest level of the chain.
///
/// `Array` is every pre-#666 row. The two bignum variants exist because
/// `ciborium` charges NO level for a bignum tag over a definite-length byte
/// string of at most 16 bytes, and takes a DIFFERENT path for each width: a
/// value that fits 64 bits is folded to an integer, a 9-16-byte one stays a
/// `Value::Tag`. The byte walk charges a level for both.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeepestLevel {
    Array,
    BignumNarrow,
    BignumWide,
}

impl DeepestLevel {
    /// The EMPTY string for `Array`, so every pre-existing seed keeps its
    /// name byte for byte. A renamed seed would show as a delete plus an add
    /// and lose its history.
    fn label_suffix(self) -> &'static str {
        match self {
            DeepestLevel::Array => "",
            DeepestLevel::BignumNarrow => "_bignum_narrow",
            DeepestLevel::BignumWide => "_bignum_wide",
        }
    }

    /// The bytes that close the chain: one more array level, or a bignum tag
    /// over a byte string of the stated width.
    fn closing_bytes(self) -> Vec<u8> {
        match self {
            DeepestLevel::Array => vec![ARRAY_1, UINT_0],
            DeepestLevel::BignumNarrow => vec![BIGNUM_TAG, BIGNUM_BYTES_1, BIGNUM_PAYLOAD_BYTE],
            DeepestLevel::BignumWide => {
                let mut v = vec![BIGNUM_TAG, BIGNUM_BYTES_9];
                v.extend(std::iter::repeat_n(BIGNUM_PAYLOAD_BYTE, BIGNUM_WIDE_LEN));
                v
            }
        }
    }
}

impl Placement {
    fn key(self) -> &'static str {
        match self {
            Placement::Unknown => FUTURE_KEY,
            Placement::KnownTags => "tags",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Placement::Unknown => "unknown",
            Placement::KnownTags => "known_tags",
        }
    }
}

/// What both decoders must answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    TooDeep,
}

/// What the Rust decoder answered.
#[derive(Debug, PartialEq, Eq)]
pub enum Observed {
    Accepted,
    /// `RecursionLimit`, with the fault's offset (`Some` only from the byte walk).
    TooDeep {
        offset: Option<usize>,
    },
    Other(String),
}

pub struct NestingCase {
    pub target: &'static str,
    pub depth: usize,
    pub placement: Placement,
    pub deepest: DeepestLevel,
}

impl NestingCase {
    /// Derived, never declared, so a row cannot claim a verdict its depth
    /// contradicts.
    pub fn verdict(&self) -> Verdict {
        if self.depth > V1_MAX_NESTING_DEPTH {
            Verdict::TooDeep
        } else {
            Verdict::Accept
        }
    }

    pub fn file_name(&self) -> String {
        format!(
            "{SEED_PREFIX}{}_{}{}.{SEED_EXTENSION}",
            self.depth,
            self.placement.label(),
            self.deepest.label_suffix()
        )
    }

    pub fn path(&self) -> PathBuf {
        seed_dir(self.target).join(self.file_name())
    }

    pub fn bytes(&self) -> Vec<u8> {
        // `Array` takes the untouched pre-#666 path byte for byte, so the
        // seven existing seeds cannot shift by a single byte. The two bignum
        // variants replace only the LAST array level with a bignum tag over
        // a byte string of the stated width.
        let value = match self.deepest {
            DeepestLevel::Array => nested_value(self.depth - 1),
            DeepestLevel::BignumNarrow | DeepestLevel::BignumWide => {
                let mut v = vec![ARRAY_1; self.depth - 2];
                v.extend(self.deepest.closing_bytes());
                v
            }
        };
        with_top_level_entry(&base(self.target), self.placement.key(), value)
    }
}

pub fn all_cases() -> Vec<NestingCase> {
    use DeepestLevel::{Array, BignumNarrow, BignumWide};
    use Placement::{KnownTags, Unknown};
    let row = |target, depth, placement, deepest| NestingCase {
        target,
        depth,
        placement,
        deepest,
    };
    vec![
        row("record", V1_MAX_NESTING_DEPTH, Unknown, Array),
        row("record", V1_MAX_NESTING_DEPTH + 1, Unknown, Array),
        row("record", V1_MAX_NESTING_DEPTH + 1, KnownTags, Array),
        row("record", FAR_PAST_THE_LIMIT, Unknown, Array),
        row("manifest_body", V1_MAX_NESTING_DEPTH, Unknown, Array),
        row("manifest_body", V1_MAX_NESTING_DEPTH + 1, Unknown, Array),
        row("manifest_body", FAR_PAST_THE_LIMIT, Unknown, Array),
        // #666: the short-bignum depth edge, at both widths ciborium takes a
        // different path for (a narrow one folds to an integer, a wide one
        // stays a `Value::Tag`). `manifest_body` only, per the task 9 brief --
        // that target alone is enough to pin the edge cross-language, since
        // the byte walk that makes this a depth fault charges a tag a level
        // identically on every walked decode path.
        row(
            "manifest_body",
            V1_MAX_NESTING_DEPTH + 1,
            Unknown,
            BignumNarrow,
        ),
        row(
            "manifest_body",
            V1_MAX_NESTING_DEPTH + 1,
            Unknown,
            BignumWide,
        ),
    ]
}

/// `core/fuzz/seeds/<target>/`.
pub fn seed_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target)
}

/// The committed ACCEPTING document each target's seeds extend.
pub fn base(target: &str) -> Vec<u8> {
    let name = match target {
        "record" => "login.cbor",
        "manifest_body" => "uniq__control__all_distinct.bin",
        other => panic!("no seed base for target {other}"),
    };
    let path = seed_dir(target).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read seed base {}: {e}", path.display()))
}

/// `levels` one-element arrays around a `0`.
fn nested_value(levels: usize) -> Vec<u8> {
    let mut value = vec![ARRAY_1; levels];
    value.push(UINT_0);
    value
}

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("a seed value encodes");
    out
}

/// The `(key bytes, value bytes)` entries of the definite map `bytes`.
pub fn entries(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Value::Map(pairs) = ciborium::de::from_reader(bytes).expect("a seed base parses") else {
        panic!("a seed base is not a map")
    };
    pairs.iter().map(|(k, v)| (cbor(k), cbor(v))).collect()
}

/// A definite map of `entries`, in the order given.
pub fn map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    assert!(
        entries.len() <= SMALL_COUNT_MAX,
        "seed maps stay in the one-byte head form"
    );
    let count = u8::try_from(entries.len()).expect("a small count fits a byte");
    let mut out = vec![MAP_SMALL_BASE | count];
    for (k, v) in entries {
        out.extend(k);
        out.extend(v);
    }
    out
}

/// `base` with `key: value` inserted where RFC 8949's length-first canonical
/// order puts it. `value` is spliced raw, so it can be deeper than any parser
/// here would build.
pub fn with_top_level_entry(base: &[u8], key: &str, value: Vec<u8>) -> Vec<u8> {
    let key = cbor(&Value::Text(key.to_owned()));
    let mut out = entries(base);
    let at = out
        .iter()
        .position(|(k, _)| (k.len(), k.as_slice()) > (key.len(), key.as_slice()))
        .unwrap_or(out.len());
    out.insert(at, (key, value));
    map(&out)
}

/// The decode → re-encode pipeline the differential replay runs for `target`.
pub fn observe(target: &str, bytes: &[u8]) -> Observed {
    let too_deep = |fault: CborFault| match fault.kind {
        CborErrorKind::RecursionLimit => Observed::TooDeep {
            offset: fault.offset,
        },
        _ => Observed::Other(format!("{fault:?}")),
    };
    match target {
        "record" => match record::decode(bytes).and_then(|r| record::encode(&r)) {
            Ok(_) => Observed::Accepted,
            Err(RecordError::CborDecode(fault)) => too_deep(fault),
            Err(e) => Observed::Other(format!("{e:?}")),
        },
        "manifest_body" => match decode_manifest(bytes).and_then(|m| encode_manifest(&m)) {
            Ok(_) => Observed::Accepted,
            Err(ManifestError::CborDecode(fault)) => too_deep(fault),
            Err(e) => Observed::Other(format!("{e:?}")),
        },
        other => panic!("no Rust decoder for target {other}"),
    }
}
