//! The rule-token tolerance predicate: when two DIFFERENT tokens still count
//! as agreement.
//!
//! Split out of `differential_replay.rs` (#649) because it is the part #646
//! edits, and it carries normative weight from `docs/vault-format.md` §4.2
//! that the corpus walk does not. Its two tests —
//! `tolerance_admits_only_phase_dependent_pairs` and
//! `an_unknown_token_is_never_tolerated` — stay in the entry file so their
//! test names do not change.

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
/// so with 4 of the 17 tokens phase-dependent this tolerates **58 of the 136
/// unequal pairs**, of which §4.2 frees a strict subset. FOUR groups are
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
/// MECHANISM, which is not the one the `is_none()` guard in
/// `differential_replay_full_corpus` uses: an unknown non-null token falls
/// through to `false` here and is reported as an ordinary DISAGREEMENT, while
/// a *missing* token is caught before this function is reached and reported
/// as a harness failure. Both red the test, so nothing is lost — but
/// "unrecognised or missing is a harness failure" is wrong about half of it.
///
/// [`RuleToken::is_phase_dependent`]: secretary_core::vault::manifest::RuleToken::is_phase_dependent
pub fn tokens_agree(rust: &str, python: &str) -> bool {
    use secretary_core::vault::manifest::RuleToken;
    let lookup = |s: &str| RuleToken::ALL.iter().find(|t| t.as_str() == s).copied();
    let (Some(r), Some(p)) = (lookup(rust), lookup(python)) else {
        return false;
    };
    r == p || r.is_phase_dependent() || p.is_phase_dependent()
}
