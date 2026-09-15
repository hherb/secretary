//! The rule-token tolerance predicate: when two DIFFERENT tokens still count
//! as agreement.
//!
//! Split out of `differential_replay.rs` (#649) because it is the part #646
//! edits, and it carries normative weight from `docs/vault-format.md` §4.2
//! that the corpus walk does not. Its two tests —
//! `tolerance_admits_only_phase_dependent_pairs` and
//! `an_unknown_token_is_never_tolerated` — stay in the entry file so their
//! test names do not change.

use super::targets::PHASE_DEPENDENT_TOLERANCE_TARGETS;

/// Do two rule tokens count as agreement?
///
/// Equal tokens always do. Unequal tokens do **only** when at least one is
/// phase-dependent, which is DERIVED from `docs/vault-format.md` §4.2's
/// "deliberately unspecified" paragraphs: those rules are detected at
/// different points by the two reader designs §4.2 admits, so ordering them
/// would outlaw one design.
///
/// **Derived from, and strictly BROADER than, those paragraphs — it is not
/// them.** A per-token predicate tolerates every pair its token appears in,
/// so with 4 of the 17 tokens phase-dependent this tolerates **54 of the 136
/// unequal pairs** on `manifest_body` (58 have a phase-dependent member; the
/// `malformed_cbor` exception below withholds four), of which §4.2 frees a
/// strict subset. FOUR groups are
/// tolerated with no §4.2 licence at all, and on the committed corpus the
/// cost is that **17 of the 24 rejecting `manifest_body` seeds never compare
/// the Python token**, because every `NonCanonicalEncoding` cause maps to a
/// phase-dependent token. All four groups and that measurement are stated in
/// full on [`RuleToken::is_phase_dependent`]'s own LIMITS block, beside the
/// predicate rather than beside this caller; #646 tracks closing them.
/// Narrowing the predicate by hand would manufacture false disagreements on
/// the pairs §4.2 genuinely leaves free, so the residual is recorded rather
/// than half-fixed.
///
/// Still deliberately NOT a list of tolerated pairs: a pair list would have
/// to be re-derived every time a token is added and would drift from §4.2
/// silently, where a predicate that is knowably wider can at least have its
/// residual written down.
///
/// An unrecognised token on either side is never agreement. Note the
/// MECHANISM, which is not the one the missing-token guard in
/// [`super::agreement::judge`] uses: an unknown non-null token falls
/// through to `false` here and is reported as an ordinary DISAGREEMENT, while
/// a *missing* token is caught before this function is reached and reported
/// as a harness failure. Both red the test, so nothing is lost — but
/// "unrecognised or missing is a harness failure" is wrong about half of it.
///
/// **Per target (#641).** The phase-dependent licence applies only on
/// [`PHASE_DEPENDENT_TOLERANCE_TARGETS`]; everywhere else unequal tokens
/// never agree. Every other target's breadth is 0, and
/// `tolerance_admits_only_phase_dependent_pairs` pins both figures.
///
/// **`malformed_cbor` is never tolerated, on any target (#641, PR #673
/// review).** §4.2 makes well-formedness the precondition for both of its
/// orderings rather than a third rule inside them: a reader that cannot find
/// a body's item boundaries "reports that instead, whatever else the body
/// also breaks". So a pair naming `malformed_cbor` against a phase-dependent
/// token has no §4.2 licence, and withholding it manufactures no false
/// disagreement. It is why `manifest_body`'s breadth is **54**, not the 58
/// pairs that have a phase-dependent member. One caveat on "false": Rust's
/// `malformed_cbor` also covers ciborium's recursion limit, which is not a
/// well-formedness fault at all. A disagreement it causes is #667's Rust-only
/// depth rejection surfacing, a real divergence, not a spurious one.
///
/// That exception is not cosmetic. Python's scanner raises `malformed_cbor`
/// for `undefined` and for a nested indefinite-length chunk; `ciborium`
/// accepts both, so Rust rejects the same body later, under a phase-dependent
/// token. Tolerating that pair turned what used to be a harness failure (an
/// untokened raise) into agreement, and would have let #666's `manifest_body`
/// seeds pass before the Rust manifest walk exists.
///
/// [`RuleToken::is_phase_dependent`]: secretary_core::vault::manifest::RuleToken::is_phase_dependent
pub fn tokens_agree(target: &str, rust: &str, python: &str) -> bool {
    use secretary_core::vault::manifest::RuleToken;
    let lookup = |s: &str| RuleToken::ALL.iter().find(|t| t.as_str() == s).copied();
    let (Some(r), Some(p)) = (lookup(rust), lookup(python)) else {
        return false;
    };
    if r == p {
        return true;
    }
    let well_formedness_precondition =
        r == RuleToken::MalformedCbor || p == RuleToken::MalformedCbor;
    PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(&target)
        && !well_formedness_precondition
        && (r.is_phase_dependent() || p.is_phase_dependent())
}
