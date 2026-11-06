//! Whether a target's token-comparison CLASSIFICATION matches what its two
//! decoders can actually do (#700). Pure.
//!
//! `every_target_is_classified` checks only that [`TOKEN_COMPARED_TARGETS`]
//! and [`super::targets::NOT_TOKEN_COMPARED_TARGETS`] partition `TARGETS`, so
//! moving a compared target into the other list was a well-formed edit that
//! left the whole binary green, and the strict comparison simply stopped
//! (measured at 46/46 in the #698 review). Asserting the literal list would
//! freeze a list that grows one target per slice. So membership is DERIVED
//! from capability instead: a target whose every reject-vs-reject pair carried
//! a rule token on BOTH sides can be compared, and must be, unless it is in
//! [`TOKEN_COMPARISON_BLOCKED`] with the reason it cannot.
//!
//! The opposite direction, a compared target that rejects without a token, was
//! already a harness failure in [`super::agreement::judge`].
//!
//! LIMIT: the evidence is the corpus that was replayed. A target with no
//! reject-vs-reject pair at all proves nothing either way and is not flagged.
//!
//! [`is_strict_comparison`] is the other half (#658): which of those pairs
//! the tolerance cannot excuse, so that their count can be floored.

use secretary_core::crypto::secret::SecretBytes;

use super::python_bridge::PyOutcome;
use super::rust_decoder::RustRejection;
use super::targets::{TOKEN_COMPARED_TARGETS, TOKEN_COMPARISON_BLOCKED};
use super::tolerance::grants_tolerance;

/// Reject-vs-reject pairs seen for one target, and how many of them carried a
/// rule token on both sides.
#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub struct TokenCoverage {
    pub rejected_pairs: usize,
    pub tokened_pairs: usize,
}

/// `coverage` with one more input's verdicts counted. Only a pair where BOTH
/// sides rejected is evidence; an accept, a mismatch or a Python harness
/// failure says nothing about whether the rejections carry tokens.
pub fn observe(
    coverage: TokenCoverage,
    rust: &Result<SecretBytes, RustRejection>,
    python: &PyOutcome,
) -> TokenCoverage {
    match (rust, python) {
        (Err(r), PyOutcome::Reject { rule, .. }) => TokenCoverage {
            rejected_pairs: coverage.rejected_pairs + 1,
            tokened_pairs: coverage.tokened_pairs
                + usize::from(r.token.is_some() && rule.is_some()),
        },
        _ => coverage,
    }
}

/// Did this pair reach a STRICT token comparison (#658)?
///
/// True when `target` is token-compared, both sides rejected, both named a
/// token, and [`tokens_are_strict`] holds for the two tokens. Those are the
/// pairs whose agreement is decided by token EQUALITY alone. The input floor
/// cannot see a raise site on EITHER side re-pointed at a phase-dependent
/// token: the input is still replayed and the pair is still scored as
/// agreement, so only a count of these can red.
pub fn is_strict_comparison(
    target: &str,
    rust: &Result<SecretBytes, RustRejection>,
    python: &PyOutcome,
) -> bool {
    let (
        Err(RustRejection {
            token: Some(rust_token),
            ..
        }),
        PyOutcome::Reject {
            rule: Some(py_token),
            ..
        },
    ) = (rust, python)
    else {
        return false;
    };
    TOKEN_COMPARED_TARGETS.contains(&target) && tokens_are_strict(target, rust_token, py_token)
}

/// Neither token carries the tolerance licence on `target`
/// ([`grants_tolerance`], the same predicate `tokens_agree` reads).
///
/// An unrecognised token grants nothing, so it counts as strict; such a pair
/// never agrees anyway. A `malformed_cbor` token against a phase-dependent
/// one is NOT counted, although `tokens_agree` never tolerates that pair: the
/// phase-dependent side would still excuse any other mismatch, and the pair
/// is always a disagreement, so it cannot inflate a green run's count.
/// `a_strict_pair_is_never_excused_by_the_tolerance` pins the property the
/// floor depends on: no unequal pair counted here is one `tokens_agree`
/// would accept.
pub fn tokens_are_strict(target: &str, rust: &str, python: &str) -> bool {
    use secretary_core::vault::manifest::RuleToken;
    let grants = |s: &str| {
        RuleToken::ALL
            .iter()
            .any(|t| t.as_str() == s && grants_tolerance(target, *t))
    };
    !grants(rust) && !grants(python)
}

/// Does this input count toward [`super::targets::MIN_STRICT_COMPARISONS`]?
/// Committed inputs only, for the reason `MIN_CORPUS_INPUTS` gives: a
/// populated, gitignored `fuzz/corpus/` must not be able to pad the count.
pub fn counts_toward_strict_floor(
    committed: bool,
    target: &str,
    rust: &Result<SecretBytes, RustRejection>,
    python: &PyOutcome,
) -> bool {
    committed && is_strict_comparison(target, rust, python)
}

/// `Some(explanation)` when `target` could be token-compared on this evidence
/// but is classified as not compared and not blocked.
pub fn misclassification(target: &str, coverage: TokenCoverage) -> Option<String> {
    let capable = coverage.rejected_pairs > 0 && coverage.tokened_pairs == coverage.rejected_pairs;
    let excused = TOKEN_COMPARED_TARGETS.contains(&target)
        || TOKEN_COMPARISON_BLOCKED.iter().any(|(t, _)| *t == target);
    (capable && !excused).then(|| {
        format!(
            "target {target:?}: all {} reject-vs-reject pair(s) carried a rule token on \
             both sides, so the two decoders can be compared on WHICH rule they name, \
             but {target:?} is not in TOKEN_COMPARED_TARGETS. Move it there, or list it \
             in TOKEN_COMPARISON_BLOCKED with the reason it cannot be compared (#700).",
            coverage.rejected_pairs
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::differential_replay_helpers::targets::{
        NOT_TOKEN_COMPARED_TARGETS, PHASE_DEPENDENT_TOLERANCE_TARGETS,
    };

    /// Not compared and not blocked: the shape #700 is about. `vault_toml`
    /// is the last such target since `bundle_file` became compared (#641).
    const LOOSE: &str = "vault_toml";
    const COMPARED: &str = "contact_card";
    const BLOCKED: &str = "manifest_file";

    fn coverage(rejected_pairs: usize, tokened_pairs: usize) -> TokenCoverage {
        TokenCoverage {
            rejected_pairs,
            tokened_pairs,
        }
    }

    fn rust_err(token: Option<&'static str>) -> Result<SecretBytes, RustRejection> {
        Err(RustRejection {
            token,
            detail: String::new(),
        })
    }

    fn py_reject(rule: Option<&str>) -> PyOutcome {
        PyOutcome::Reject {
            rule: rule.map(str::to_owned),
            detail: String::new(),
        }
    }

    #[test]
    fn the_fixture_targets_sit_where_the_tests_assume() {
        assert!(NOT_TOKEN_COMPARED_TARGETS.contains(&LOOSE));
        assert!(!TOKEN_COMPARISON_BLOCKED.iter().any(|(t, _)| *t == LOOSE));
        assert!(TOKEN_COMPARED_TARGETS.contains(&COMPARED));
        assert!(TOKEN_COMPARISON_BLOCKED.iter().any(|(t, _)| *t == BLOCKED));
    }

    #[test]
    fn a_fully_tokened_target_left_out_of_the_comparison_is_flagged() {
        let msg = misclassification(LOOSE, coverage(3, 3)).expect("flagged");
        assert!(msg.contains(LOOSE) && msg.contains("TOKEN_COMPARED_TARGETS"));
    }

    #[test]
    fn a_compared_or_blocked_target_is_not_flagged() {
        assert_eq!(misclassification(COMPARED, coverage(3, 3)), None);
        assert_eq!(misclassification(BLOCKED, coverage(3, 3)), None);
    }

    #[test]
    fn one_untokened_pair_means_the_target_cannot_be_compared_yet() {
        assert_eq!(misclassification(LOOSE, coverage(3, 2)), None);
    }

    #[test]
    fn no_rejected_pair_is_no_evidence() {
        assert_eq!(misclassification(LOOSE, coverage(0, 0)), None);
    }

    /// The one target the phase-dependent tolerance applies on.
    const TOLERANT: &str = "manifest_body";

    #[test]
    fn the_strict_fixture_targets_sit_where_the_tests_assume() {
        assert!(PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(&TOLERANT));
        assert!(TOKEN_COMPARED_TARGETS.contains(&TOLERANT));
        assert!(!PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(&COMPARED));
    }

    #[test]
    fn two_ordered_tokens_on_a_compared_target_are_a_strict_comparison() {
        let tok = Some("wrong_type");
        assert!(is_strict_comparison(
            TOLERANT,
            &rust_err(tok),
            &py_reject(tok)
        ));
        assert!(is_strict_comparison(
            COMPARED,
            &rust_err(tok),
            &py_reject(tok)
        ));
    }

    /// The direction #658 is about: a Rust raise site moved onto a
    /// phase-dependent token stops counting, whatever Python says.
    #[test]
    fn a_phase_dependent_token_on_either_side_is_not_strict_where_tolerated() {
        let pd = Some("non_canonical_unclassified");
        let ordered = Some("wrong_type");
        assert!(!is_strict_comparison(
            TOLERANT,
            &rust_err(pd),
            &py_reject(ordered)
        ));
        assert!(!is_strict_comparison(
            TOLERANT,
            &rust_err(ordered),
            &py_reject(pd)
        ));
        assert!(!is_strict_comparison(
            TOLERANT,
            &rust_err(pd),
            &py_reject(pd)
        ));
    }

    /// The tolerance is per target, so the same token is strict elsewhere.
    #[test]
    fn a_phase_dependent_token_is_strict_where_no_tolerance_applies() {
        let pd = Some("non_canonical_unclassified");
        assert!(is_strict_comparison(
            COMPARED,
            &rust_err(pd),
            &py_reject(pd)
        ));
    }

    #[test]
    fn nothing_is_strict_on_an_uncompared_target_or_without_both_tokens() {
        let tok = Some("wrong_type");
        let ok: Result<SecretBytes, RustRejection> = Ok(SecretBytes::new(Vec::new()));
        assert!(!is_strict_comparison(
            LOOSE,
            &rust_err(tok),
            &py_reject(tok)
        ));
        assert!(!is_strict_comparison(
            COMPARED,
            &rust_err(None),
            &py_reject(tok)
        ));
        assert!(!is_strict_comparison(
            COMPARED,
            &rust_err(tok),
            &py_reject(None)
        ));
        assert!(!is_strict_comparison(COMPARED, &ok, &py_reject(tok)));
        assert!(!is_strict_comparison(
            COMPARED,
            &rust_err(tok),
            &PyOutcome::Accept(Vec::new())
        ));
    }

    /// An unrecognised token grants no tolerance, so it counts as ordered.
    #[test]
    fn an_unrecognised_token_counts_as_strict() {
        assert!(is_strict_comparison(
            TOLERANT,
            &rust_err(Some("wrong_type")),
            &py_reject(Some("no_such_token"))
        ));
    }

    /// A gitignored runtime corpus must not pad the floor (#658 review).
    #[test]
    fn only_a_committed_input_counts_toward_the_strict_floor() {
        let tok = Some("wrong_type");
        assert!(counts_toward_strict_floor(
            true,
            COMPARED,
            &rust_err(tok),
            &py_reject(tok)
        ));
        assert!(!counts_toward_strict_floor(
            false,
            COMPARED,
            &rust_err(tok),
            &py_reject(tok)
        ));
    }

    /// The property the floor depends on, over every token pair on every
    /// target: a pair counted as strict is never one the tolerance accepts
    /// unless its tokens are equal. A future widening of `tokens_agree` that
    /// bypasses `grants_tolerance` (a pair list, say) reds here instead of
    /// leaving the floor counting pairs that are no longer compared.
    #[test]
    fn a_strict_pair_is_never_excused_by_the_tolerance() {
        use crate::differential_replay_helpers::targets::TARGETS;
        use crate::differential_replay_helpers::tolerance::tokens_agree;
        use secretary_core::vault::manifest::RuleToken;
        let mut strict_unequal = 0usize;
        for target in TARGETS {
            for r in RuleToken::ALL.iter().map(|t| t.as_str()) {
                for p in RuleToken::ALL.iter().map(|t| t.as_str()) {
                    if r != p && tokens_are_strict(target, r, p) {
                        strict_unequal += 1;
                        assert!(
                            !tokens_agree(target, r, p),
                            "{target}: ({r}, {p}) is counted strict but tolerated"
                        );
                    }
                }
            }
        }
        assert!(strict_unequal > 0, "the sweep checked no pair");
    }

    #[test]
    fn only_a_pair_where_both_sides_rejected_is_counted() {
        let ok: Result<SecretBytes, RustRejection> = Ok(SecretBytes::new(Vec::new()));
        let start = TokenCoverage::default();
        let tok = Some("missing_field");
        assert_eq!(
            observe(start, &rust_err(tok), &py_reject(tok)),
            coverage(1, 1)
        );
        assert_eq!(
            observe(start, &rust_err(None), &py_reject(tok)),
            coverage(1, 0)
        );
        assert_eq!(
            observe(start, &rust_err(tok), &py_reject(None)),
            coverage(1, 0)
        );
        assert_eq!(observe(start, &ok, &py_reject(tok)), start);
        assert_eq!(
            observe(start, &rust_err(tok), &PyOutcome::Accept(Vec::new())),
            start
        );
        assert_eq!(
            observe(start, &rust_err(tok), &PyOutcome::Harness("boom".into())),
            start
        );
    }
}
