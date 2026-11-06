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
//! reject-vs-reject pair at all proves nothing either way and is not flagged;
//! flooring how many pairs reach a comparison is #658's.

use secretary_core::crypto::secret::SecretBytes;

use super::python_bridge::PyOutcome;
use super::rust_decoder::RustRejection;
use super::targets::{TOKEN_COMPARED_TARGETS, TOKEN_COMPARISON_BLOCKED};

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
    use crate::differential_replay_helpers::targets::NOT_TOKEN_COMPARED_TARGETS;

    /// Not compared and not blocked: the shape #700 is about.
    const LOOSE: &str = "bundle_file";
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
