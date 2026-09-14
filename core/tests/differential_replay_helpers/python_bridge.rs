//! The Python half of the replay's CONTRACT: the command that starts
//! `conformance.py --diff-replay-serve`, and how one of its verdicts is read.
//!
//! The process that runs that command lives in [`super::python_worker`]. This
//! module holds only what is pure, so the verdict rules — the #595
//! default-deny posture above all — are unit-tested without a Python process.

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

/// What the Python child reported.
///
/// The third arm is the point (#595). Before it existed, the bridge returned
/// `Result<Vec<u8>, String>`, so a TIMEOUT, a non-zero exit, an unparseable
/// stdout or a `uv` that could not resolve its dependencies all collapsed
/// into `Err` — and `Err` on both sides was scored as AGREEMENT by the match
/// that is now [`super::agreement::judge`]. A completely non-functional Python side
/// therefore "agreed" on every input the Rust decoder rejects, which is 24 of
/// the 38 committed `manifest_body` seeds (20 canonicality rejects + 4
/// uniqueness rejects; the count moves every time either corpus grows, so
/// re-measure rather than quoting it). A harness failure is not a verdict, and
/// `judge` returns before its agreement match ever sees one.
#[derive(Debug, PartialEq)]
pub enum PyOutcome {
    /// The Python decoder accepted, and re-encoded to these bytes.
    Accept(Vec<u8>),
    /// The Python decoder deliberately rejected the input. A verdict.
    ///
    /// `rule` is the token the reject shape now carries (#634); `None` when
    /// that rejection carries none.
    Reject {
        rule: Option<String>,
        detail: String,
    },
    /// This harness failed. Never a verdict — always a test failure.
    Harness(String),
}

/// The command that starts one serve-mode worker (#655).
///
/// `uv run` with the PEP 723 dependencies spelled out, exactly as the
/// per-input spawn it replaces used, plus `--diff-replay-serve` in place of
/// `--diff-replay <target> <path>`: one process answers the whole corpus.
pub fn serve_command() -> Command {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let conformance = manifest.join("tests/python/conformance.py");
    let mut command = Command::new("uv");
    command.arg("run");
    for dependency in [
        "cryptography",
        "pynacl",
        "pqcrypto",
        "argon2-cffi",
        "blake3",
        "cbor2",
    ] {
        command.arg("--with").arg(dependency);
    }
    command.arg(&conformance).arg("--diff-replay-serve");
    command
}

/// Read one verdict object into a [`PyOutcome`]. Pure.
///
/// `context` is appended to every harness-failure message — the worker's
/// recent stderr, or a traceback the response carried — because a broken
/// Python side that leaves no trace is how #595 went unnoticed.
pub fn parse_verdict(verdict: &Value, context: &str) -> PyOutcome {
    match verdict["status"].as_str() {
        Some("accept") => {
            // A missing or non-string `reencoded_b64` is a HARNESS failure,
            // not an empty acceptance. `unwrap_or("")` decoded to `vec![]`
            // and handed that back as a VERDICT, which the caller then
            // scored as an ordinary byte disagreement — the same
            // degrade-to-a-wrong-answer shape the `rule` field two arms
            // below is carefully protected against. `vault_toml` compares
            // no bytes, so there it was swallowed outright.
            let Some(b64) = verdict["reencoded_b64"].as_str() else {
                return PyOutcome::Harness(format!(
                    "python accepted but its `reencoded_b64` is missing or not a \
                     string: {verdict}"
                ));
            };
            use base64::Engine as _;
            match base64::engine::general_purpose::STANDARD.decode(b64) {
                Ok(v) => PyOutcome::Accept(v),
                Err(e) => PyOutcome::Harness(format!("base64: {}", e)),
            }
        }
        Some("reject") => {
            // As strict as the accept arm above. For six of the seven targets
            // ANY Python reject agrees with any Rust rejection, so this is the
            // arm where a malformed verdict costs most, yet
            // `{"status":"reject"}` alone used to parse, its class and detail
            // defaulted to "unknown" and "" (#662 review). Python always emits
            // both; a verdict without them is a broken harness, not a reason.
            let (Some(class), Some(detail)) =
                (verdict["error_class"].as_str(), verdict["detail"].as_str())
            else {
                return PyOutcome::Harness(format!(
                    "python rejected but its `error_class` or `detail` is missing or \
                     not a string: {verdict}"
                ));
            };
            PyOutcome::Reject {
                rule: verdict["rule"].as_str().map(str::to_owned),
                detail: format!("{class}: {detail}"),
            }
        }
        Some("error") => PyOutcome::Harness(format!(
            "python reported an internal error: {} {} {}",
            verdict["error_class"].as_str().unwrap_or("unknown"),
            verdict["detail"].as_str().unwrap_or(""),
            context
        )),
        // Default-deny: an unrecognised status is a harness failure, not a
        // verdict — the same posture the repo's hygiene guards take.
        other => PyOutcome::Harness(format!(
            "python output has unrecognised status {:?}: {verdict}",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_accept_decodes_its_reencoded_bytes() {
        let v = json!({"status": "accept", "reencoded_b64": "AAEC"});
        assert_eq!(parse_verdict(&v, ""), PyOutcome::Accept(vec![0, 1, 2]));
    }

    #[test]
    fn an_accept_without_reencoded_bytes_is_a_harness_failure_not_an_empty_accept() {
        for v in [
            json!({"status": "accept"}),
            json!({"status": "accept", "reencoded_b64": 7}),
        ] {
            assert!(
                matches!(parse_verdict(&v, ""), PyOutcome::Harness(_)),
                "{v}"
            );
        }
    }

    #[test]
    fn undecodable_base64_is_a_harness_failure() {
        let v = json!({"status": "accept", "reencoded_b64": "!!!"});
        assert!(matches!(parse_verdict(&v, ""), PyOutcome::Harness(_)));
    }

    #[test]
    fn a_reject_carries_its_rule_token_and_class_prefixed_detail() {
        let v =
            json!({"status": "reject", "error_class": "E", "detail": "d", "rule": "missing_field"});
        assert_eq!(
            parse_verdict(&v, ""),
            PyOutcome::Reject {
                rule: Some("missing_field".into()),
                detail: "E: d".into()
            }
        );
    }

    #[test]
    fn a_reject_with_a_null_rule_has_no_token() {
        let v = json!({"status": "reject", "error_class": "E", "detail": "d", "rule": null});
        assert!(matches!(
            parse_verdict(&v, ""),
            PyOutcome::Reject { rule: None, .. }
        ));
    }

    #[test]
    fn a_reject_without_a_string_class_and_detail_is_a_harness_failure() {
        for v in [
            json!({"status": "reject"}),
            json!({"status": "reject", "detail": "d", "rule": null}),
            json!({"status": "reject", "error_class": "E", "rule": null}),
            json!({"status": "reject", "error_class": 7, "detail": "d", "rule": null}),
        ] {
            assert!(
                matches!(parse_verdict(&v, ""), PyOutcome::Harness(_)),
                "{v}"
            );
        }
    }

    #[test]
    fn an_error_status_is_a_harness_failure_carrying_its_context() {
        let v = json!({"status": "error", "error_class": "NameError", "detail": "x"});
        match parse_verdict(&v, "TRACEBACK-TEXT") {
            PyOutcome::Harness(msg) => {
                assert!(
                    msg.contains("NameError") && msg.contains("TRACEBACK-TEXT"),
                    "{msg}"
                )
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unrecognised_or_missing_status_is_a_harness_failure() {
        for v in [json!({"status": "maybe"}), json!({}), json!([1, 2])] {
            assert!(
                matches!(parse_verdict(&v, ""), PyOutcome::Harness(_)),
                "{v}"
            );
        }
    }
}
