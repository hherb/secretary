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
pub const EXPECTED_CASE_COUNT: usize = 7;
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

/// Where the deep value is planted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Placement {
    /// Under [`FUTURE_KEY`], in the forward-compat bag.
    Unknown,
    /// Under `tags`, a known key whose value would otherwise be a type error.
    KnownTags,
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
            "{SEED_PREFIX}{}_{}.{SEED_EXTENSION}",
            self.depth,
            self.placement.label()
        )
    }

    pub fn path(&self) -> PathBuf {
        seed_dir(self.target).join(self.file_name())
    }

    pub fn bytes(&self) -> Vec<u8> {
        with_top_level_entry(
            &base(self.target),
            self.placement.key(),
            nested_value(self.depth - 1),
        )
    }
}

pub fn all_cases() -> Vec<NestingCase> {
    use Placement::{KnownTags, Unknown};
    let row = |target, depth, placement| NestingCase {
        target,
        depth,
        placement,
    };
    vec![
        row("record", V1_MAX_NESTING_DEPTH, Unknown),
        row("record", V1_MAX_NESTING_DEPTH + 1, Unknown),
        row("record", V1_MAX_NESTING_DEPTH + 1, KnownTags),
        row("record", FAR_PAST_THE_LIMIT, Unknown),
        row("manifest_body", V1_MAX_NESTING_DEPTH, Unknown),
        row("manifest_body", V1_MAX_NESTING_DEPTH + 1, Unknown),
        row("manifest_body", FAR_PAST_THE_LIMIT, Unknown),
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
