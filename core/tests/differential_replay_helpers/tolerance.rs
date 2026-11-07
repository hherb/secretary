//! The rule-token tolerance relation: when two DIFFERENT tokens still count
//! as agreement.
//!
//! Split out of `differential_replay.rs` (#649) because it carries normative
//! weight from `docs/vault-format.md` §4.2 that the corpus walk does not. Its
//! two tests — `tolerance_admits_only_phase_dependent_pairs` and
//! `an_unknown_token_is_never_tolerated` — stay in the entry file so their
//! test names do not change.

use secretary_core::vault::manifest::RuleToken;

use super::targets::PHASE_DEPENDENT_TOLERANCE_TARGETS;

/// The manifest-body rules §4.2's report-order freedom ranges over: every
/// rule a §4.2 reader can name for a well-formed body, less rule 4.
///
/// Left out, each for a §4.2 reason: [`RuleToken::Rule4TagOrFloat`]
/// (ordering 1 puts it ahead of every other rule), [`RuleToken::MalformedCbor`]
/// (well-formedness is the precondition for both orderings, not a rule inside
/// them), [`RuleToken::UnknownField`] (the manifest has a forward-compat
/// `unknown` bag, so no manifest rule rejects an unknown key), and the
/// envelope, harness and encoder tokens, which no §4.2 body rule produces.
const FREELY_ORDERED_MANIFEST_RULES: &[RuleToken] = &[
    RuleToken::Rule2IndefiniteLength,
    RuleToken::Rule3NonShortestForm,
    RuleToken::NonCanonicalUnclassified,
    RuleToken::ArraySortOrder,
    RuleToken::RepeatedArrayValue,
    RuleToken::DuplicateMapKey,
    RuleToken::MissingField,
    RuleToken::WrongType,
    RuleToken::IntegerOutOfRange,
    RuleToken::UnsupportedVersion,
];

/// Do two rule tokens count as agreement?
///
/// Equal tokens always do. Two unequal tokens do only on a target in
/// [`PHASE_DEPENDENT_TOLERANCE_TARGETS`], and only when §4.2 frees that PAIR
/// (#646). §4.2's "general rule" paragraph says a fault a normalising reader
/// may first detect at the §4.3 step-4 re-encode is unordered against every other rule
/// except rule 4 and the well-formedness precondition. That reading is:
///
/// - one of the two is re-encode-visible ([`RuleToken::is_phase_dependent`]:
///   §6.2 rules 1-3, trailing bytes, the array sort disciplines), and
/// - both are in [`FREELY_ORDERED_MANIFEST_RULES`].
///
/// On `manifest_body` that is 30 of the 153 unequal pairs: the 6 among the
/// four re-encode-visible tokens, plus each of the four against the six
/// interpretation-time rules. `tolerance_admits_only_phase_dependent_pairs`
/// pins the exact set against a second, independent declaration. Until #646
/// this was a per-TOKEN test, which tolerated 58 pairs, including the
/// rule 4 pairs §4.2's ordering 1 fixes.
///
/// Pairs of two interpretation-time rules (`wrong_type` against
/// `missing_field`, say) are NOT tolerated. §4.2 does not fix their order
/// either, but both reader designs check them during interpretation, so the
/// harness holds the two implementations to the same answer. That is parity,
/// not spec.
///
/// An unrecognised token on either side is never agreement. It falls through
/// to `false` here and is reported as an ordinary DISAGREEMENT, while a
/// *missing* token is caught earlier by [`super::agreement::judge`] and
/// reported as a harness failure. Both red the test.
pub fn tokens_agree(target: &str, rust: &str, python: &str) -> bool {
    let lookup = |s: &str| RuleToken::ALL.iter().find(|t| t.as_str() == s).copied();
    let (Some(r), Some(p)) = (lookup(rust), lookup(python)) else {
        return false;
    };
    r == p || report_order_is_free(target, r, p)
}

/// Does §4.2 leave the order of `a` against `b` free on `target`? Symmetric.
fn report_order_is_free(target: &str, a: RuleToken, b: RuleToken) -> bool {
    (grants_tolerance(target, a) || grants_tolerance(target, b))
        && FREELY_ORDERED_MANIFEST_RULES.contains(&a)
        && FREELY_ORDERED_MANIFEST_RULES.contains(&b)
}

/// Can `token` excuse a mismatch on `target`? True for a re-encode-visible
/// token on a licensed target: some other token would be tolerated against it.
///
/// `token_coverage::is_strict_comparison` reads this, so an input counted
/// as strict is one whose tokens excuse nothing. A tolerated pair always has
/// a member for which this is true. `a_strict_pair_is_never_excused_by_the_tolerance`
/// pins that.
pub fn grants_tolerance(target: &str, token: RuleToken) -> bool {
    PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(&target) && token.is_phase_dependent()
}
