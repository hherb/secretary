//! Out-of-loop differential replay: feeds the runtime fuzz corpus
//! (and any committed diff_regressions/) through both Rust decoders
//! and the Python clean-room decoder in
//! `core/tests/python/conformance.py`, asserting agreement on
//! accept/reject, on re-encoded bytes (where applicable), and on WHICH
//! rule each side named when both reject (#634; see
//! [`TOKEN_COMPARED_TARGETS`] and [`tokens_agree`]).
//!
//! Gated by feature `differential-replay`. Off by default to keep
//! `cargo test` Rust-only.
//!
//! See docs/superpowers/specs/2026-04-30-fuzz-harness-design.md §
//! "Out-of-loop differential replay".
//!
//! This entry file holds the `#[test]` fns and nothing else; everything they
//! call lives in [`differential_replay_helpers`], split by role so that the
//! two open issues that will edit this harness do not collide in one file
//! (#649) — see that module's own doc for the layout. The tests stay HERE
//! rather than beside their helpers because a `#[test]` fn's name is its
//! module path, and those names are cited by handoffs, mutation specs and
//! the CI step's own negative control.

#![cfg(feature = "differential-replay")]

use std::fs;

mod differential_replay_helpers;

use differential_replay_helpers as helpers;
use helpers::corpus::corpus_dirs;
use helpers::python_bridge::{python_decode, PyOutcome};
use helpers::rust_decoder::rust_decode;
use helpers::targets::{
    min_inputs, MIN_CORPUS_INPUTS, NOT_TOKEN_COMPARED_TARGETS, TARGETS, TOKEN_COMPARED_TARGETS,
};
use helpers::tolerance::tokens_agree;

#[test]
fn differential_replay_full_corpus() {
    let mut disagreements: Vec<String> = vec![];
    let mut harness_failures: Vec<String> = vec![];
    for target in TARGETS {
        // Per-target input floor (#595). `corpus_dirs` skips any directory
        // that does not exist, with no `else` — so a renamed or moved
        // `fuzz/seeds/` made every target iterate ZERO inputs and this test
        // passed having verified nothing. That is the same fail-open shape
        // `Path.rglob` produced in the payload guard (#496), and this
        // target's own module doc records it happening here. Populating the
        // directory fixed the symptom; this fixes the mechanism.
        //
        // TWO counters, because the floor and the replay do not range over
        // the same set. `seen` is everything replayed; `committed_seen` is
        // the git-tracked subset, and only that may clear the floor. Counting
        // both together left the floor fail-open on the one machine it
        // protects: with a populated `fuzz/corpus/` a deleted committed seed
        // still cleared it by tens of thousands, so "deleting an input reds"
        // was true only where `corpus/` was absent (#656 review).
        let mut seen = 0usize;
        let mut committed_seen = 0usize;
        let dirs = corpus_dirs(target);
        for dir in &dirs {
            for entry in fs::read_dir(&dir.path).expect("read corpus dir") {
                let path = entry.expect("dir entry").path();
                if !path.is_file() {
                    continue;
                }
                if path.file_name().and_then(|s| s.to_str()) == Some(".gitkeep") {
                    continue;
                }
                seen += 1;
                if dir.committed {
                    committed_seen += 1;
                }
                let bytes = fs::read(&path).expect("read input");

                let rust = rust_decode(target, &bytes);
                let python = python_decode(target, &path);

                // A harness failure is not a verdict, so it never reaches
                // the agreement match below: that match reads a Rust `Err`
                // beside a `PyOutcome::Reject` as "both implementations
                // rejected", and a Python crash or timeout establishes
                // nothing at all about the input.
                if let PyOutcome::Harness(msg) = &python {
                    harness_failures.push(format!("[{}] {}: {}", target, path.display(), msg));
                    continue;
                }

                // A missing token on a token-compared target is a harness
                // failure, never an ordinary disagreement: it means the
                // harness cannot tell whether the two agree, not that they
                // differ. This must run BEFORE the `ok` match below, which
                // treats a missing token as a plain "false" — i.e. as a
                // (potentially misleading) disagreement rather than as "we
                // don't know."
                if TOKEN_COMPARED_TARGETS.contains(target) {
                    if let (Err(r), PyOutcome::Reject { rule, .. }) = (&rust, &python) {
                        if r.token.is_none() || rule.is_none() {
                            harness_failures.push(format!(
                                "[{}] {}: token-compared target rejected with a missing rule \
                                 token (rust={:?}, python={:?}). Give the raising site a token \
                                 rather than allowlisting this input.",
                                target,
                                path.display(),
                                r.token,
                                rule
                            ));
                            continue;
                        }
                    }
                }

                let ok = match (&rust, &python) {
                    // Both reject. For a token-compared target, agreement now
                    // requires the two to have named the SAME rule -- or for
                    // vault-format §4.2 to have left their order free. This
                    // arm was an unconditional `true` until #634, which is
                    // why #618's two live divergences and #621's third one
                    // were all invisible to the harness that exists to catch
                    // exactly them.
                    (Err(r), PyOutcome::Reject { rule, .. }) => {
                        if !TOKEN_COMPARED_TARGETS.contains(target) {
                            true
                        } else {
                            match (r.token, rule.as_deref()) {
                                (Some(rt), Some(pt)) => tokens_agree(rt, pt),
                                // Default-deny: a missing token on a
                                // token-compared target is recorded as a
                                // harness failure below, never as agreement.
                                _ => false,
                            }
                        }
                    }
                    // Both accept: for crash-only target (vault_toml) compare nothing;
                    // for the rest, compare re-encoded bytes.
                    (Ok(r_bytes), PyOutcome::Accept(p_bytes)) => {
                        if *target == "vault_toml" {
                            true
                        } else {
                            // `.expose()` reads through the wrapper for the
                            // comparison; it does not materialise a second
                            // copy the way `.to_vec()` would.
                            r_bytes.expose() == p_bytes.as_slice()
                        }
                    }
                    // Mismatch: one accepted, one rejected.
                    _ => false,
                };

                if !ok {
                    disagreements.push(format!(
                        "[{}] {}: rust={} python={}",
                        target,
                        path.display(),
                        match &rust {
                            Ok(v) => format!("Ok({} bytes)", v.len()),
                            Err(e) => format!("Err({:?}) {}", e.token, e.detail),
                        },
                        match &python {
                            PyOutcome::Accept(v) => format!("Ok({} bytes)", v.len()),
                            PyOutcome::Reject { rule, detail } =>
                                format!("Rejected({:?}) {}", rule, detail),
                            PyOutcome::Harness(_) => unreachable!("filtered above"),
                        },
                    ));
                }
            }
        }
        let floor = min_inputs(target);
        let searched: Vec<_> = dirs.iter().map(|d| d.path.display().to_string()).collect();
        assert!(
            committed_seen >= floor,
            "target {target}: replayed {committed_seen} COMMITTED corpus \
             input(s) ({seen} in total), floor is {floor} — searched \
             {searched:?}. A target that replays nothing, or almost nothing, \
             passes vacuously; either restore the committed inputs under \
             core/fuzz/seeds/{target}/ or update MIN_CORPUS_INPUTS \
             deliberately in the same edit. Only git-tracked inputs count: a \
             populated core/fuzz/corpus/ must not be able to mask a deleted \
             seed."
        );
        // `--nocapture` to see these: libtest swallows them on a passing
        // test, which is why a CI log proves only "4 passed" and the input
        // count has to be re-derived from the tree (#656 review).
        eprintln!("[{target}] replayed {seen} input(s), {committed_seen} committed");
    }
    // Harness failures first: a broken Python side makes every verdict
    // below meaningless, so report it as the primary cause rather than
    // burying it under whatever disagreements it happened to produce.
    assert!(
        harness_failures.is_empty(),
        "differential harness failures ({}) — the harness could not obtain a \
         COMPARABLE verdict. Two distinct causes land here and the message \
         above each line says which: the Python side did not produce a verdict \
         at all (a crash, a timeout, a non-zero exit, unparseable stdout), or \
         it produced one carrying no rule token on a token-compared target. \
         The second is a real, deliberate rejection — it simply did not name a \
         rule — so do not read every line below as \"Python is broken\":\n{}",
        harness_failures.len(),
        harness_failures.join("\n")
    );
    if !disagreements.is_empty() {
        panic!(
            "differential disagreements ({}):\n{}",
            disagreements.len(),
            disagreements.join("\n")
        );
    }
}

/// Every target must be classified as token-compared or not. A new target
/// defaulting silently to the loose behaviour is the fail-open shape #595
/// found in this same file's corpus discovery, restated one level up.
#[test]
fn every_target_is_classified() {
    for target in TARGETS {
        assert!(
            TOKEN_COMPARED_TARGETS.contains(target) || NOT_TOKEN_COMPARED_TARGETS.contains(target),
            "target {:?} is in neither classification list",
            target
        );
    }
    for target in TOKEN_COMPARED_TARGETS {
        assert!(
            TARGETS.contains(target),
            "{:?} is compared but not a target",
            target
        );
        assert!(
            !NOT_TOKEN_COMPARED_TARGETS.contains(target),
            "{:?} is in BOTH lists",
            target
        );
    }
    assert_eq!(
        TOKEN_COMPARED_TARGETS.len() + NOT_TOKEN_COMPARED_TARGETS.len(),
        TARGETS.len()
    );

    // The input floor is the other table a new target must not default out
    // of, and it is the one that decides whether this test compares anything
    // at all.
    for target in TARGETS {
        assert!(
            MIN_CORPUS_INPUTS.iter().any(|(t, _)| t == target),
            "target {target} has no MIN_CORPUS_INPUTS entry"
        );
    }
    assert_eq!(
        MIN_CORPUS_INPUTS.len(),
        TARGETS.len(),
        "MIN_CORPUS_INPUTS must cover TARGETS exactly"
    );
}

/// The NEGATIVE control the corpus cannot provide: no committed input makes
/// two ORDERED tokens disagree, so without this test an always-true tolerance
/// would pass.
///
/// **It does NOT check that the tolerance is exactly §4.2's free set**, and an
/// earlier version of this docstring claimed it did — while `tokens_agree`'s
/// own doc (now in `differential_replay_helpers/tolerance.rs`, #649) says in
/// bold that the predicate is strictly BROADER than §4.2. Two doc comments
/// asserting opposite strengths for one predicate is how a reader concludes
/// the residual cannot exist. What is
/// checked here is reflexivity, one tolerated pair, one denied pair, that two
/// ORDERED tokens agree only when equal, and — since the residual is a
/// BREADTH rather than a wrong answer — the exact SIZE of the tolerated set,
/// so that adding a token or flipping a flag cannot widen it silently.
#[test]
fn tolerance_admits_only_phase_dependent_pairs() {
    use secretary_core::vault::manifest::RuleToken;

    // Identical tokens always agree, phase-dependent or not.
    for t in RuleToken::ALL {
        assert!(
            tokens_agree(t.as_str(), t.as_str()),
            "{:?} vs itself",
            t.as_str()
        );
    }

    // #621's pair, BOTH phase-dependent -> tolerated. §4.2's array-sort
    // paragraph licenses it DIRECTLY and by name: "a body that is out of
    // array sort order and also breaks one of §6.2 rules 1-3 may be reported
    // as either". An earlier comment here credited the later "no order among
    // rules 1, 2 and 3 themselves" paragraph instead, which is a different
    // sentence and does not reach a pair one of whose members is an array
    // sort discipline; `diff_regressions/README.md` had it right throughout.
    assert!(tokens_agree("array_sort_order", "rule2_indefinite_length"));
    assert!(tokens_agree("rule2_indefinite_length", "array_sort_order"));

    // #618's pair, BOTH ordered -> a real disagreement. If this ever passes,
    // the divergence #618 fixed could return unseen.
    assert!(!tokens_agree("rule4_tag_or_float", "duplicate_map_key"));
    assert!(!tokens_agree("duplicate_map_key", "rule4_tag_or_float"));

    // Two ordered tokens never agree unless equal.
    let ordered: Vec<&str> = RuleToken::ALL
        .iter()
        .filter(|t| !t.is_phase_dependent())
        .map(|t| t.as_str())
        .collect();
    for a in &ordered {
        for b in &ordered {
            assert_eq!(tokens_agree(a, b), a == b, "{} vs {}", a, b);
        }
    }

    // The BREADTH itself, pinned as a number. The four groups in
    // `is_phase_dependent`'s LIMITS block are tolerated with no §4.2
    // licence, so the honest statement of this predicate is "58 of the 136
    // unequal pairs", not "the pairs §4.2 frees". Asserting the count means
    // a fifth phase-dependent token, or an 18th token, cannot widen the
    // tolerance without someone re-deriving this figure against §4.2 and
    // updating the LIMITS block in the same edit. #646 owns narrowing it.
    let n = RuleToken::ALL.len();
    let mut unequal = 0usize;
    let mut tolerated = 0usize;
    for a in RuleToken::ALL {
        for b in RuleToken::ALL {
            if a >= b {
                continue;
            }
            unequal += 1;
            if tokens_agree(a.as_str(), b.as_str()) {
                tolerated += 1;
            }
        }
    }
    assert_eq!(unequal, n * (n - 1) / 2, "unordered pair count");
    assert_eq!(
        tolerated, 58,
        "the tolerated-pair count moved: re-derive it against vault-format \
         §4.2 and update RuleToken::is_phase_dependent's LIMITS block, which \
         states this figure and the four groups it covers"
    );
}

/// An unknown token is never a tolerated mismatch. A typo on either side is
/// reported as an ordinary DISAGREEMENT — `tokens_agree` returns `false` and
/// the corpus loop records the pair — not as a harness failure, which is the
/// separate `is_none()` branch above for a MISSING token. Both red the test;
/// only the message differs. What must never happen is the third outcome:
/// degrading to "something differs, probably fine".
#[test]
fn an_unknown_token_is_never_tolerated() {
    assert!(!tokens_agree("array_sort_order", "not_a_real_token"));
    assert!(!tokens_agree("not_a_real_token", "not_a_real_token_either"));
}
