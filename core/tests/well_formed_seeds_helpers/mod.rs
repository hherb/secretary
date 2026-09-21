//! Committed `manifest_body` seeds for the ciborium leniencies the well-
//! formedness walk closes (#666): four shapes `ciborium`'s `Value` reader
//! accepts that RFC 8949 does not, one narrow-bignum rule-4 shape, and two
//! PRECEDENCE rows pinning that a well-formedness fault LATER in byte order
//! outranks a rule-4 fault EARLIER in it (`docs/vault-format.md` §4.2's
//! precondition; `core/src/vault/canonical/walk.rs`'s own unit tests cover
//! the same two byte sequences at the walk layer — these seeds pin the same
//! precedence through the full `decode_manifest` path and the cross-language
//! replay, which that module's tests do not reach).
//!
//! **No census exclusion needs adding anywhere (verified).** `rule_token_seeds.rs`
//! owns `SEEDED_TARGETS = ["block_file", "record"]` — it never scans
//! `manifest_body/` at all. `nesting_depth_seeds_helpers::SEEDED_TARGETS`
//! does own `manifest_body`, but its census in `nesting_depth_seeds.rs` is
//! scoped to files starting with ITS OWN `SEED_PREFIX` (`"nesting__"`), so a
//! `wellformed__*` file is invisible to it. `manifest_body/wellformed__*` is
//! therefore claimed by nobody, and this module's own two-way census in
//! `well_formed_seeds.rs` is the only thing that owns it.
//!
//! **Why a separate generator rather than adding `manifest_body` to
//! `rule_token_seeds.rs`'s `SEEDED_TARGETS`.** That file's census owns EVERY
//! labelled file (one containing `__`) in a seeded target's directory —
//! see its own module doc — so adding `manifest_body` there would make it
//! claim all 47 pre-existing `manifest_body` seeds (`arraysort__`,
//! `keyorder__`, `uniq__`, `valuetype__`, `top__`, `block__`, `trash__`,
//! `nesting__`), none of which its table declares. That is exactly the trap
//! `nesting_depth_seeds_helpers`'s by-name prefix exclusion already
//! documents and exists to avoid; a second seeded target needing its own
//! prefix carve-out is the same lesson, not a new one.
//!
//! **The canonical splice position was MEASURED, not hand-derived.** In
//! `manifest_body/uniq__control__all_distinct.bin`, RFC 8949 §4.2.1's
//! length-first canonical key order is (by length, then bytes):
//! `trash`(5), `blocks`(6), `suite_id`(8), `kdf_params`(10),
//! `vault_uuid`(10), `vector_clock`(12), `format_version`(14),
//! `owner_user_uuid`(15), `manifest_version`(16) — measured directly off the
//! decoded fixture, not derived by hand. [`FUTURE_KEY`] is 9 bytes, so it
//! belongs strictly between `suite_id` (8) and the two 10-byte keys — and of
//! those two, `kdf_params` sorts before `vault_uuid` (`k` < `v`), so the
//! entry immediately following the splice is `kdf_params`, not `vault_uuid`.
//! An earlier attempt in this slice targeted `vault_uuid` and produced a
//! non-canonical body; `well_formed_seeds.rs`'s
//! `the_base_and_a_benign_splice_are_both_accepted` is the check that would
//! catch that mistake if it recurred.

mod prefix;

use std::path::PathBuf;

use ciborium::Value;
pub use prefix::SEED_PREFIX;

/// How many rows the table holds; a row and its seed deleted together are
/// invisible to the two-way census, so the count is pinned separately.
pub const EXPECTED_CASE_COUNT: usize = 7;

/// A key no v1 document defines, so it lands in the manifest's forward-compat
/// `unknown` bag. 9 bytes — see the module doc for why that length is
/// load-bearing.
const FUTURE_KEY: &str = "zz_future";

const SEED_EXTENSION: &str = "bin";

// --- CBOR byte-level primitives, one name per encoded meaning (no magic
// numbers). Each `WellFormedCase::planted` value below is assembled purely
// from these. ---

/// Major 7 (simple/float), additional-info 23: the single-byte, well-formed
/// encoding of `undefined`. RFC 8949 leaves it well-formed;
/// `docs/vault-format.md` §4.2's well-formedness precondition excludes it
/// ("a major-7 value outside `false`/`true`/`null`").
const MAJOR7_UNDEFINED: u8 = 0xf7;

/// Major 7, additional-info 24: "a one-byte simple value follows". RFC 8949
/// §3.3 permits this form only for values 32-255; using it for a value that
/// already has a direct one-byte encoding (0-23) is not well-formed.
const MAJOR7_ONE_BYTE_SIMPLE_HEAD: u8 = 0xf8;

/// The one-byte argument following [`MAJOR7_ONE_BYTE_SIMPLE_HEAD`] above:
/// decimal 21, the simple value `true` — which has its own direct one-byte
/// encoding and must never be spelled through this longer form.
const ONE_BYTE_SIMPLE_VALUE_TRUE: u8 = 0x15;

/// Major 2 (byte string), additional-info 31: opens an indefinite-length
/// byte string, whose chunks RFC 8949 §3.2.3 requires to each be a
/// DEFINITE-length byte string. Used both for the outer string and, planted
/// where a chunk head is expected, for the nested indefinite string that
/// breaks that rule.
const INDEFINITE_BYTE_STRING_HEAD: u8 = 0x5f;

/// Major 2, additional-info 1: a definite byte string of length 1. Doubles
/// as the well-formed chunk that would have been legal in the nested-chunk
/// plant had the nested head not been indefinite.
const DEFINITE_BYTE_STRING_LEN1_HEAD: u8 = 0x41;

/// An arbitrary one-byte payload for a length-1 byte string (ASCII `a`).
const BYTE_STRING_PAYLOAD_BYTE: u8 = 0x61;

/// Major 7, additional-info 31: the `break` code that closes the innermost
/// open indefinite-length container.
const BREAK_CODE: u8 = 0xff;

/// Major 3 (text string), additional-info 1: a definite text string of
/// length 1.
const DEFINITE_TEXT_LEN1_HEAD: u8 = 0x61;

/// A payload byte that is not a valid UTF-8 sequence in any position, so the
/// one-byte text string above fails the walk's UTF-8 check.
const INVALID_UTF8_BYTE: u8 = 0xff;

/// Major 6 (tag), additional-info 2: tag number 2, a positive bignum
/// (RFC 8949 §3.4.3). crypto-design §6.2 rule 4 forbids every tag, this one
/// included.
const TAG_POSITIVE_BIGNUM: u8 = 0xc2;

/// The one-byte bignum payload, chosen arbitrarily; its value is irrelevant
/// to the rule this plant exercises.
const BIGNUM_PAYLOAD_BYTE: u8 = 0x01;

/// Major 4 (array), additional-info 2: a definite array of two items — the
/// container both precedence rows plant their two faults inside.
const ARRAY_LEN2_HEAD: u8 = 0x82;

/// Major 7, additional-info 25: a half-precision (16-bit) IEEE-754 float
/// follows. crypto-design §6.2 rule 4 forbids every float, this one
/// included.
const FLOAT16_HEAD: u8 = 0xf9;

/// The two payload bytes of a half-precision float encoding `+0.0`.
const FLOAT16_ZERO_PAYLOAD: [u8; 2] = [0x00, 0x00];

/// `undefined` alone: well-formed by RFC 8949, excluded by
/// `docs/vault-format.md` §4.2.
const UNDEFINED: [u8; 1] = [MAJOR7_UNDEFINED];

/// `true`, spelled through the disallowed two-byte simple-value form.
const SIMPLE_TRUE_TWO_BYTE: [u8; 2] = [MAJOR7_ONE_BYTE_SIMPLE_HEAD, ONE_BYTE_SIMPLE_VALUE_TRUE];

/// An indefinite-length byte string whose one chunk is itself an
/// indefinite-length byte string — RFC 8949 §3.2.3 forbids a chunk that is
/// not a definite string of the same major.
const NESTED_INDEFINITE_CHUNK: [u8; 6] = [
    INDEFINITE_BYTE_STRING_HEAD,
    INDEFINITE_BYTE_STRING_HEAD,
    DEFINITE_BYTE_STRING_LEN1_HEAD,
    BYTE_STRING_PAYLOAD_BYTE,
    BREAK_CODE,
    BREAK_CODE,
];

/// A one-byte text string whose payload is not valid UTF-8.
const INVALID_UTF8_TEXT: [u8; 2] = [DEFINITE_TEXT_LEN1_HEAD, INVALID_UTF8_BYTE];

/// A positive bignum tag over a 1-byte string: well-formed, but a tag, so
/// crypto-design §6.2 rule 4 rejects it. Narrow enough (fits 64 bits) that
/// `ciborium`'s `Value` reader folds it to an integer and never sees it as a
/// tag at all — the walk answers ahead of that reader precisely so this
/// shape is still caught, and under its own rule rather than the re-encode's
/// `non_canonical_unclassified` (#666).
const BIGNUM_NARROW: [u8; 3] = [
    TAG_POSITIVE_BIGNUM,
    DEFINITE_BYTE_STRING_LEN1_HEAD,
    BIGNUM_PAYLOAD_BYTE,
];

/// `[<bignum tag>, undefined]`: a rule-4 fault (the tag) EARLIER in byte
/// order than a well-formedness fault (`undefined`) LATER in it. The walk
/// must still report `undefined` — a well-formedness fault anywhere
/// outranks a rule-4 fault anywhere (`docs/vault-format.md` §4.2).
const TAG_THEN_MALFORMED: [u8; 5] = [
    ARRAY_LEN2_HEAD,
    TAG_POSITIVE_BIGNUM,
    DEFINITE_BYTE_STRING_LEN1_HEAD,
    BIGNUM_PAYLOAD_BYTE,
    MAJOR7_UNDEFINED,
];

/// `[<float 0.0>, undefined]`: the same precedence pin as
/// [`TAG_THEN_MALFORMED`], with a float standing in for the tag as the
/// earlier rule-4 fault.
const FLOAT_THEN_MALFORMED: [u8; 5] = [
    ARRAY_LEN2_HEAD,
    FLOAT16_HEAD,
    FLOAT16_ZERO_PAYLOAD[0],
    FLOAT16_ZERO_PAYLOAD[1],
    MAJOR7_UNDEFINED,
];

/// A benign one-byte unsigned integer, used only by the control test that
/// proves the splice itself is canonical (the row's `token` is never read).
pub const BENIGN_UINT: [u8; 1] = [0x00];

/// One row: what bytes are planted under [`FUTURE_KEY`], and which
/// [`secretary_core::vault::manifest::RuleToken`] spelling both `decode_manifest`
/// and `conformance.py` must answer.
pub struct WellFormedCase {
    pub label: &'static str,
    pub planted: &'static [u8],
    pub token: &'static str,
}

/// The seven rows. See the module doc for the byte-sequence derivations and
/// for why the two `_then_malformed` rows are the ones that matter most:
/// they are the only cross-language pin on the walk's PARKING behaviour (a
/// rule-4 fault seen first is held, not reported, until well-formedness of
/// the whole item is proven).
pub fn all_cases() -> Vec<WellFormedCase> {
    vec![
        WellFormedCase {
            label: "undefined",
            planted: &UNDEFINED,
            token: "malformed_cbor",
        },
        WellFormedCase {
            label: "two_byte_simple",
            planted: &SIMPLE_TRUE_TWO_BYTE,
            token: "malformed_cbor",
        },
        WellFormedCase {
            label: "nested_indefinite_chunk",
            planted: &NESTED_INDEFINITE_CHUNK,
            token: "malformed_cbor",
        },
        WellFormedCase {
            label: "invalid_utf8",
            planted: &INVALID_UTF8_TEXT,
            token: "malformed_cbor",
        },
        WellFormedCase {
            label: "bignum_narrow",
            planted: &BIGNUM_NARROW,
            token: "rule4_tag_or_float",
        },
        WellFormedCase {
            label: "tag_then_malformed",
            planted: &TAG_THEN_MALFORMED,
            token: "malformed_cbor",
        },
        WellFormedCase {
            label: "float_then_malformed",
            planted: &FLOAT_THEN_MALFORMED,
            token: "malformed_cbor",
        },
    ]
}

/// `core/fuzz/seeds/manifest_body/`.
fn seed_dir_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join("manifest_body")
}

/// Public alias matching the naming other seed-generator test files use.
pub fn seed_dir() -> PathBuf {
    seed_dir_path()
}

/// The committed, accepting control body every row splices its plant into.
pub fn base() -> Vec<u8> {
    let path = seed_dir_path().join("uniq__control__all_distinct.bin");
    std::fs::read(&path).unwrap_or_else(|e| panic!("read seed base {}: {e}", path.display()))
}

fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("a seed value encodes");
    out
}

/// The `(key bytes, value bytes)` entries of the definite map `bytes`, in
/// their on-disk order.
fn entries(bytes: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let Value::Map(pairs) = ciborium::de::from_reader(bytes).expect("the base parses") else {
        panic!("the base is not a map");
    };
    pairs.iter().map(|(k, v)| (encode(k), encode(v))).collect()
}

/// A definite one-byte-head map of `entries`, in the order given. The base
/// has 9 entries and this splice adds one, both well within the one-byte
/// small-count form (0-23), so no wider head is needed.
fn small_definite_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    /// Major 5 (map), the base additional-info byte a small entry count is
    /// OR'd onto.
    const MAP_SMALL_BASE: u8 = 0xa0;
    /// The largest count the one-byte map-head form can carry.
    const SMALL_COUNT_MAX: usize = 23;
    assert!(
        entries.len() <= SMALL_COUNT_MAX,
        "well-formed seed maps stay in the one-byte head form"
    );
    let count = u8::try_from(entries.len()).expect("a small count fits a byte");
    let mut out = vec![MAP_SMALL_BASE | count];
    for (k, v) in entries {
        out.extend(k);
        out.extend(v);
    }
    out
}

/// `base()` with `zz_future: <planted>` inserted at RFC 8949 §4.2.1's
/// canonical position — see the module doc for why that position is between
/// `suite_id` and `kdf_params`, measured rather than assumed. `planted` is
/// spliced in raw, so it can (and for six of the seven rows, does) fail to
/// be a well-formed CBOR item on its own.
pub fn body_for(case: &WellFormedCase) -> Vec<u8> {
    let key = encode(&Value::Text(FUTURE_KEY.to_owned()));
    let mut out = entries(&base());
    let at = out
        .iter()
        .position(|(k, _)| (k.len(), k.as_slice()) > (key.len(), key.as_slice()))
        .unwrap_or(out.len());
    out.insert(at, (key, case.planted.to_vec()));
    small_definite_map(&out)
}

/// `wellformed__<label>.bin`, so a row whose name disagrees with what it
/// plants is unconstructible.
pub fn file_name(case: &WellFormedCase) -> String {
    format!("{SEED_PREFIX}{}.{SEED_EXTENSION}", case.label)
}
