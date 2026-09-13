//! Whether the Rust and Python verdicts on one input AGREE. Pure.
//!
//! Lifted out of `differential_replay_full_corpus`'s loop (#655) so the rules
//! that decide the test's outcome are unit-tested without a Python process,
//! and so #641 (more token-compared targets) and #646 (a narrower tolerance)
//! edit a function rather than the body of the one test that runs the corpus.
//! The message text is unchanged from the loop it came from.

use secretary_core::crypto::secret::SecretBytes;

use super::python_bridge::PyOutcome;
use super::rust_decoder::RustRejection;
use super::targets::TOKEN_COMPARED_TARGETS;
use super::tolerance::tokens_agree;

/// The target whose accept compares no bytes: it is decoded, never
/// re-encoded, on both sides.
const CRASH_ONLY_TARGET: &str = "vault_toml";

/// The outcome of comparing one input's two verdicts.
#[derive(Debug, PartialEq)]
pub enum Judgement {
    Agree,
    /// The two implementations disagree. The message says how.
    Disagree(String),
    /// No COMPARABLE verdict could be obtained. Never a verdict — always a
    /// test failure, reported ahead of disagreements.
    Harness(String),
}

/// Compare `rust` and `python` for one input of `target`.
pub fn judge(
    target: &str,
    rust: &Result<SecretBytes, RustRejection>,
    python: &PyOutcome,
) -> Judgement {
    // A harness failure is not a verdict, so it never reaches the agreement
    // match below: that match reads a Rust `Err` beside a `PyOutcome::Reject`
    // as "both implementations rejected", and a Python crash or timeout
    // establishes nothing at all about the input.
    if let PyOutcome::Harness(msg) = python {
        return Judgement::Harness(msg.clone());
    }

    let token_compared = TOKEN_COMPARED_TARGETS.contains(&target);

    // A missing token on a token-compared target is a harness failure, never
    // an ordinary disagreement: it means the harness cannot tell whether the
    // two agree, not that they differ. This must run BEFORE the `ok` match
    // below, which treats a missing token as a plain "false" — i.e. as a
    // (potentially misleading) disagreement rather than as "we don't know."
    if token_compared {
        if let (Err(r), PyOutcome::Reject { rule, .. }) = (rust, python) {
            if r.token.is_none() || rule.is_none() {
                return Judgement::Harness(format!(
                    "token-compared target rejected with a missing rule \
                     token (rust={:?}, python={:?}). Give the raising site a token \
                     rather than allowlisting this input.",
                    r.token, rule
                ));
            }
        }
    }

    let ok = match (rust, python) {
        // Both reject. For a token-compared target, agreement requires the two
        // to have named the SAME rule -- or for vault-format §4.2 to have left
        // their order free. This arm was an unconditional `true` until #634,
        // which is why #618's two live divergences and #621's third one were
        // all invisible to the harness that exists to catch exactly them.
        (Err(r), PyOutcome::Reject { rule, .. }) => {
            if !token_compared {
                true
            } else {
                match (r.token, rule.as_deref()) {
                    (Some(rt), Some(pt)) => tokens_agree(rt, pt),
                    // Default-deny: unreachable after the missing-token guard
                    // above, and never agreement if it were reached.
                    _ => false,
                }
            }
        }
        // Both accept: for the crash-only target compare nothing; for the
        // rest, compare re-encoded bytes. `.expose()` reads through the
        // wrapper; it does not materialise a second copy the way `.to_vec()`
        // would.
        (Ok(r_bytes), PyOutcome::Accept(p_bytes)) => {
            target == CRASH_ONLY_TARGET || r_bytes.expose() == p_bytes.as_slice()
        }
        // Mismatch: one accepted, one rejected.
        _ => false,
    };
    if ok {
        return Judgement::Agree;
    }
    Judgement::Disagree(format!(
        "rust={} python={}",
        match rust {
            Ok(v) => format!("Ok({} bytes)", v.len()),
            Err(e) => format!("Err({:?}) {}", e.token, e.detail),
        },
        match python {
            PyOutcome::Accept(v) => format!("Ok({} bytes)", v.len()),
            PyOutcome::Reject { rule, detail } => format!("Rejected({:?}) {}", rule, detail),
            PyOutcome::Harness(_) => unreachable!("returned above"),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPARED: &str = "manifest_body";
    const UNCOMPARED: &str = "record";

    fn rust_ok(bytes: &[u8]) -> Result<SecretBytes, RustRejection> {
        Ok(SecretBytes::new(bytes.to_vec()))
    }

    fn rust_err(token: Option<&'static str>) -> Result<SecretBytes, RustRejection> {
        Err(RustRejection {
            token,
            detail: "rust-detail".into(),
        })
    }

    fn py_reject(rule: Option<&str>) -> PyOutcome {
        PyOutcome::Reject {
            rule: rule.map(str::to_owned),
            detail: "py-detail".into(),
        }
    }

    #[test]
    fn the_two_fixture_targets_sit_on_either_side_of_the_classification() {
        assert!(TOKEN_COMPARED_TARGETS.contains(&COMPARED));
        assert!(!TOKEN_COMPARED_TARGETS.contains(&UNCOMPARED));
    }

    #[test]
    fn a_python_harness_failure_is_never_a_verdict() {
        let python = PyOutcome::Harness("boom".into());
        assert_eq!(
            judge(UNCOMPARED, &rust_err(None), &python),
            Judgement::Harness("boom".into())
        );
    }

    #[test]
    fn both_rejecting_an_uncompared_target_agrees_whatever_the_tokens() {
        assert_eq!(
            judge(
                UNCOMPARED,
                &rust_err(None),
                &py_reject(Some("missing_field"))
            ),
            Judgement::Agree
        );
    }

    #[test]
    fn a_missing_token_on_a_compared_target_is_a_harness_failure_on_either_side() {
        for (rust, python) in [
            (rust_err(None), py_reject(Some("missing_field"))),
            (rust_err(Some("missing_field")), py_reject(None)),
        ] {
            assert!(matches!(
                judge(COMPARED, &rust, &python),
                Judgement::Harness(_)
            ));
        }
    }

    #[test]
    fn equal_tokens_on_a_compared_target_agree() {
        assert_eq!(
            judge(
                COMPARED,
                &rust_err(Some("missing_field")),
                &py_reject(Some("missing_field"))
            ),
            Judgement::Agree
        );
    }

    #[test]
    fn two_different_ordered_tokens_on_a_compared_target_disagree() {
        match judge(
            COMPARED,
            &rust_err(Some("rule4_tag_or_float")),
            &py_reject(Some("duplicate_map_key")),
        ) {
            Judgement::Disagree(msg) => assert!(
                msg.contains("rule4_tag_or_float") && msg.contains("duplicate_map_key"),
                "{msg}"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// The tolerance at its CALL SITE. `tokens_agree`'s own tests pin the
    /// predicate, but nothing here did: `tokens_agree(rt, pt)` rewritten as
    /// `rt == pt` left every test in this module green, and only the full
    /// corpus replay, through its one witness input, noticed (#662 review).
    /// This is the line #646 edits, and the reason `judge` was lifted out of
    /// the corpus loop was to test it without Python.
    #[test]
    fn a_phase_dependent_pair_on_a_compared_target_agrees() {
        // #621's witness pair: vault-format §4.2 leaves its order free.
        assert_eq!(
            judge(
                COMPARED,
                &rust_err(Some("array_sort_order")),
                &py_reject(Some("rule2_indefinite_length"))
            ),
            Judgement::Agree
        );
    }

    /// An unrecognised token is a DISAGREEMENT, not a harness failure: the
    /// missing-token guard catches only `None`, and a typo'd token must still
    /// red the run rather than read as tolerated.
    #[test]
    fn an_unknown_token_on_a_compared_target_is_a_disagreement() {
        assert!(matches!(
            judge(
                COMPARED,
                &rust_err(Some("array_sort_order")),
                &py_reject(Some("not_a_real_token"))
            ),
            Judgement::Disagree(_)
        ));
    }

    #[test]
    fn both_accepting_agrees_only_on_identical_bytes() {
        assert_eq!(
            judge(
                UNCOMPARED,
                &rust_ok(b"ab"),
                &PyOutcome::Accept(b"ab".to_vec())
            ),
            Judgement::Agree
        );
        assert!(matches!(
            judge(
                UNCOMPARED,
                &rust_ok(b"ab"),
                &PyOutcome::Accept(b"ac".to_vec())
            ),
            Judgement::Disagree(_)
        ));
    }

    #[test]
    fn the_crash_only_target_compares_no_bytes() {
        assert_eq!(
            judge(
                CRASH_ONLY_TARGET,
                &rust_ok(b""),
                &PyOutcome::Accept(b"anything".to_vec())
            ),
            Judgement::Agree
        );
    }

    #[test]
    fn one_accepting_and_one_rejecting_disagree_in_both_directions() {
        assert!(matches!(
            judge(UNCOMPARED, &rust_ok(b"ab"), &py_reject(None)),
            Judgement::Disagree(_)
        ));
        assert!(matches!(
            judge(
                UNCOMPARED,
                &rust_err(None),
                &PyOutcome::Accept(b"ab".to_vec())
            ),
            Judgement::Disagree(_)
        ));
    }
}
