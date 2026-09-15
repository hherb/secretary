//! Which targets the replay walks, which of them are token-compared, and the
//! committed input floor each must clear.
//!
//! Split out of `differential_replay.rs` (#649) because it is the part #641
//! edits: widening the rule-token comparison to another target is a move
//! between the two classification lists below plus a `rust_decode` arm in
//! [`super::rust_decoder`], and nothing in the tolerance predicate.
//! `every_target_is_classified` stays in the entry file so its test name does
//! not change.

pub const TARGETS: &[&str] = &[
    "vault_toml",
    "record",
    "contact_card",
    "bundle_file",
    "manifest_file",
    "manifest_body",
    "block_file",
];

/// Targets whose reject-vs-reject pairs are compared on WHICH rule each side
/// named, not merely on the fact that both rejected (#634).
///
/// `manifest_body` (#634) and `block_file` (#641). `block_file` needed no
/// decoder change: both implementations walk the §6.1 layout in the same
/// order, and #641 split Python's merged sort/repeat check. `record` follows
/// once its Python decoder reports in Rust's phase order. `contact_card`,
/// `bundle_file` and `vault_toml` each still need their own taxonomy (#641);
/// `manifest_file` is blocked for a different, measured reason (#640) —
/// Rust's header raises `UnsupportedFormatVersion` where Python raises the
/// same `ParseError` it raises for every envelope fault, and because that
/// variant is shared with the BODY sentinel check no per-variant token can
/// reconcile the two.
pub const TOKEN_COMPARED_TARGETS: &[&str] = &["manifest_body", "block_file"];

/// The rest, listed explicitly rather than by omission.
///
/// `every_target_is_classified` requires this list and the one above to
/// partition `TARGETS` exactly, so a new target cannot default silently into
/// the loose behaviour — the fail-open shape #595 found in
/// `differential_replay.rs`'s own corpus discovery. `agreement::judge` reads
/// it too, and reports a target in neither list as a harness failure.
pub const NOT_TOKEN_COMPARED_TARGETS: &[&str] = &[
    "vault_toml",
    "record",
    "contact_card",
    "bundle_file",
    "manifest_file",
];

/// The compared targets on which a phase-dependent token may stand against a
/// different token and still count as agreement.
///
/// **The licence is a SPEC SECTION's, not a token's.** `RuleToken::is_phase_dependent`
/// is derived from `docs/vault-format.md` §4.2, which admits two manifest-body
/// reader designs that detect §6.2 rules 1-3 and the array sort disciplines at
/// different points. Nothing gives a §6.1 block-file envelope or a §6.3 record
/// body that freedom, so on every other compared target only EQUAL tokens
/// agree (#641). Applied globally, the per-token predicate would have scored
/// `array_sort_order` against `container_malformed` on `block_file` as
/// agreement — hiding exactly the Python sort/repeat split #641 adds.
///
/// Must be a subset of [`TOKEN_COMPARED_TARGETS`]; `every_target_is_classified`
/// checks it.
pub const PHASE_DEPENDENT_TOLERANCE_TARGETS: &[&str] = &["manifest_body"];

/// The committed input floor for each target.
///
/// `seen > 0` was not enough, and the gap was specific rather than
/// theoretical: `corpus_dirs` skips a missing directory silently, and for
/// `manifest_body` — the ONLY token-compared target —
/// `tests/data/diff_regressions/manifest_body/` holds one always-present
/// committed file. So a renamed or emptied `core/fuzz/seeds/manifest_body/`
/// left the target replaying exactly that one input, which is itself a
/// TOLERATED pair, and the test passed having compared nothing. That is the
/// #595 fail-open shape one level up: the mechanism was guarded, the
/// magnitude was not.
///
/// The figures are the counts committed today, so deleting an input reds
/// rather than quietly shrinking the corpus. **Only COMMITTED inputs are
/// counted toward it** — `CorpusDir::committed` makes the split — because a
/// floor that also counted the gitignored runtime corpus was fail-open on
/// precisely the machine it protects: with `fuzz/corpus/` holding tens of
/// thousands of files, a deleted seed still cleared the floor and the
/// guarantee above held only where `corpus/` was absent (#656 review). It
/// stays a FLOOR rather than an equality so that adding a seed does not red
/// until someone updates the table deliberately.
/// `every_target_is_classified` requires this table to cover `TARGETS`
/// exactly, so a new target cannot arrive without one.
///
/// What it does NOT floor is how many inputs reach a strict token
/// comparison. The committed count is taken from the listing before any
/// decode, and `tokens_agree` short-circuits on either side being
/// phase-dependent, so a change on the Rust raise side could route more of
/// the corpus onto tolerated pairs and shrink the real comparison toward zero
/// with this floor, the tolerance breadth assertion and the negative control
/// all green. Tracked as #658.
pub const MIN_CORPUS_INPUTS: &[(&str, usize)] = &[
    ("vault_toml", 3),
    ("record", 3),
    ("contact_card", 2),
    ("bundle_file", 1),
    ("manifest_file", 1),
    ("manifest_body", 39),
    ("block_file", 16),
];

pub fn min_inputs(target: &str) -> usize {
    MIN_CORPUS_INPUTS
        .iter()
        .find(|(t, _)| *t == target)
        .map(|(_, n)| *n)
        .unwrap_or_else(|| panic!("target {target} has no MIN_CORPUS_INPUTS entry"))
}
