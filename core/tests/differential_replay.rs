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
//!
//! The Python side is ONE long-lived `--diff-replay-serve` worker for the
//! whole run (#655), not a process per input; see
//! [`helpers::python_worker`] for what that keeps per input and what it
//! gives up.

#![cfg(feature = "differential-replay")]

use std::fs;
use std::time::Instant;

mod differential_replay_helpers;

use differential_replay_helpers as helpers;
use helpers::agreement::{judge, Judgement};
use helpers::corpus::{corpus_dirs, corpus_inputs};
use helpers::progress;
use helpers::python_bridge::serve_command;
use helpers::python_worker::{PyReplayer, MAX_CONSECUTIVE_WORKER_FAILURES, PER_INPUT_TIMEOUT};
use helpers::rust_decoder::rust_decode;
use helpers::targets::{
    min_inputs, MIN_CORPUS_INPUTS, NOT_TOKEN_COMPARED_TARGETS, PHASE_DEPENDENT_TOLERANCE_TARGETS,
    TARGETS, TOKEN_COMPARED_TARGETS,
};
use helpers::tolerance::tokens_agree;

#[test]
fn differential_replay_full_corpus() {
    let mut disagreements: Vec<String> = vec![];
    let mut harness_failures: Vec<String> = vec![];
    // One worker for every target and every input (#655). The per-input spawn
    // it replaces cost ~0.16 s against a 0.2-0.4 ms decode, which on a
    // fuzzed checkout's 74,924-input corpus was ~3.3 h of apparent hang.
    let mut python = PyReplayer::new(serve_command, PER_INPUT_TIMEOUT);
    // Inputs skipped because the worker-failure cap had tripped. Reported as
    // ONE harness failure after the loop rather than one per input: past the
    // cap there is no verdict left to get, and on a fuzzed checkout a line per
    // input is tens of thousands of lines burying the failures that say why.
    let mut not_replayed = 0usize;
    for target in TARGETS {
        // Per-target input floor (#595). `corpus_dirs` skips any directory
        // that does not exist, with no `else` — so a renamed or moved
        // `fuzz/seeds/` made every target iterate ZERO inputs and this test
        // passed having verified nothing. That is the same fail-open shape
        // `Path.rglob` produced in the payload guard (#496), and this
        // target's own module doc records it happening here. Populating the
        // directory fixed the symptom; this fixes the mechanism.
        //
        // The floor counts only inputs under the two COMMITTED DIRECTORIES
        // (`fuzz/seeds/<target>/` and `tests/data/diff_regressions/<target>/`),
        // never the gitignored runtime corpus. Counting that too left it
        // fail-open on the one machine it protects: with a populated
        // `fuzz/corpus/` a deleted committed seed still cleared the floor by
        // tens of thousands, so "deleting an input reds" was true only where
        // `corpus/` was absent (#656 review).
        //
        // Say DIRECTORY, not "git-tracked": the tagging is positional
        // (`corpus.rs`'s `committed` flag is set per directory), so an
        // untracked file dropped into `fuzz/seeds/<target>/` counts toward the
        // floor too. What actually binds each committed seed to a row is the
        // prefix-scoped two-way census in the generator that owns it — for the
        // `valuetype__` seeds, `acceptance_seeds.rs` (#679 review).
        let inputs = corpus_inputs(target).expect("list corpus inputs");
        let committed = inputs.iter().filter(|i| i.committed).count();
        let started = Instant::now();
        let mut last_report = started;
        let mut compared = 0usize;
        progress::emit(&progress::start_line(target, inputs.len(), committed));
        for (done, input) in inputs.iter().enumerate() {
            if python.abandoned() {
                not_replayed += 1;
                continue;
            }
            let bytes = fs::read(&input.path).expect("read input");
            let rust = rust_decode(target, &bytes);
            let verdict = python.decode(target, &input.path);
            let prefix = format!("[{}] {}", target, input.path.display());
            match judge(target, &rust, &verdict) {
                Judgement::Agree => compared += 1,
                Judgement::Disagree(msg) => {
                    compared += 1;
                    disagreements.push(format!("{prefix}: {msg}"));
                }
                Judgement::Harness(msg) => harness_failures.push(format!("{prefix}: {msg}")),
            }
            let now = Instant::now();
            if progress::is_due(last_report, now) {
                progress::emit(&progress::progress_line(
                    target,
                    done + 1,
                    inputs.len(),
                    now - started,
                ));
                last_report = now;
            }
        }
        let floor = min_inputs(target);
        let searched: Vec<_> = corpus_dirs(target)
            .iter()
            .map(|d| d.path.display().to_string())
            .collect();
        assert!(
            committed >= floor,
            "target {target}: replayed {committed} COMMITTED corpus \
             input(s) ({} in total), floor is {floor} — searched \
             {searched:?}. A target that replays nothing, or almost nothing, \
             passes vacuously; either restore the committed inputs under \
             core/fuzz/seeds/{target}/ or update MIN_CORPUS_INPUTS \
             deliberately in the same edit. Only the committed DIRECTORIES \
             count: a populated core/fuzz/corpus/ must not be able to mask a \
             deleted seed.",
            inputs.len()
        );
        progress::emit(&progress::finish_line(
            target,
            compared,
            inputs.len(),
            committed,
            started.elapsed(),
        ));
    }
    if not_replayed > 0 {
        harness_failures.push(format!(
            "{not_replayed} input(s) not replayed: {MAX_CONSECUTIVE_WORKER_FAILURES} inputs \
             in a row got no answer from a Python worker, so no further worker was \
             started — the failures above say why"
        ));
    }
    // Harness failures first: a broken Python side makes every verdict
    // below meaningless, so report it as the primary cause rather than
    // burying it under whatever disagreements it happened to produce.
    assert!(
        harness_failures.is_empty(),
        "differential harness failures ({}) — the harness could not obtain a \
         COMPARABLE verdict. Two distinct causes land here and the message \
         above each line says which: the Python side did not produce a verdict \
         at all (a worker that crashed, timed out, could not start, wrote a line \
         that is not JSON, or answered for a different input, and any inputs \
         skipped once no further worker was started), or \
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

    // The phase-dependent licence is vault-format §4.2's, i.e. one target's
    // spec section, and only a compared target can use it (#641).
    for target in PHASE_DEPENDENT_TOLERANCE_TARGETS {
        assert!(
            TOKEN_COMPARED_TARGETS.contains(target),
            "{target:?} is licensed for the phase-dependent tolerance but is not token-compared"
        );
    }
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

    const LICENSED: &str = "manifest_body";

    // Identical tokens always agree, phase-dependent or not.
    for t in RuleToken::ALL {
        assert!(
            tokens_agree(LICENSED, t.as_str(), t.as_str()),
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
    assert!(tokens_agree(
        LICENSED,
        "array_sort_order",
        "rule2_indefinite_length"
    ));
    assert!(tokens_agree(
        LICENSED,
        "rule2_indefinite_length",
        "array_sort_order"
    ));

    // #618's pair, BOTH ordered -> a real disagreement. If this ever passes,
    // the divergence #618 fixed could return unseen.
    assert!(!tokens_agree(
        LICENSED,
        "rule4_tag_or_float",
        "duplicate_map_key"
    ));
    assert!(!tokens_agree(
        LICENSED,
        "duplicate_map_key",
        "rule4_tag_or_float"
    ));

    // Two ordered tokens never agree unless equal.
    let ordered: Vec<&str> = RuleToken::ALL
        .iter()
        .filter(|t| !t.is_phase_dependent())
        .map(|t| t.as_str())
        .collect();
    for a in &ordered {
        for b in &ordered {
            assert_eq!(tokens_agree(LICENSED, a, b), a == b, "{} vs {}", a, b);
        }
    }

    // §4.2's well-formedness precondition: a body that is not well-formed
    // CBOR is reported as such "whatever else the body also breaks", so
    // `malformed_cbor` against a phase-dependent token is never licensed
    // (#641, PR #673 review). Without this, Python naming `malformed_cbor`
    // for a shape ciborium parses leniently scored as agreement.
    for t in RuleToken::ALL.iter().filter(|t| t.is_phase_dependent()) {
        assert!(
            !tokens_agree(LICENSED, "malformed_cbor", t.as_str()),
            "{t:?}"
        );
        assert!(
            !tokens_agree(LICENSED, t.as_str(), "malformed_cbor"),
            "{t:?}"
        );
    }

    // The BREADTH itself, pinned as a number. The four groups in
    // `is_phase_dependent`'s LIMITS block are tolerated with no §4.2
    // licence, so the honest statement of this predicate is "54 of the 136
    // unequal pairs", not "the pairs §4.2 frees": 58 pairs have a
    // phase-dependent member, less the four that pair it with
    // `malformed_cbor`. Asserting the count means a fifth phase-dependent
    // token, or an 18th token, cannot widen the tolerance without someone
    // re-deriving this figure against §4.2 and updating the LIMITS block in
    // the same edit. #646 owns narrowing it.
    let n = RuleToken::ALL.len();
    let mut unequal = 0usize;
    let mut tolerated = 0usize;
    for a in RuleToken::ALL {
        for b in RuleToken::ALL {
            if a >= b {
                continue;
            }
            unequal += 1;
            if tokens_agree(LICENSED, a.as_str(), b.as_str()) {
                tolerated += 1;
            }
        }
    }
    assert_eq!(unequal, n * (n - 1) / 2, "unordered pair count");
    assert_eq!(
        tolerated, 54,
        "the tolerated-pair count moved: re-derive it against vault-format \
         §4.2 and update RuleToken::is_phase_dependent's LIMITS block, which \
         states this figure and the four groups it covers"
    );

    // Every other target: no tolerated pair at all. The licence above is
    // §4.2's, the manifest body's; a sequential block-file envelope or a
    // record body inherits none of it (#641).
    //
    // The loop below skips whatever the list names, so on its own it cannot
    // see the list widen: adding `record` to it removed `record` from the
    // loop (PR #673 review). Pin the list's contents first.
    assert_eq!(
        PHASE_DEPENDENT_TOLERANCE_TARGETS,
        ["manifest_body"],
        "widening the phase-dependent licence is a vault-format §4.2 decision, \
         not a table edit"
    );
    for target in TARGETS
        .iter()
        .filter(|t| !PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(t))
    {
        let tolerated_elsewhere = RuleToken::ALL
            .iter()
            .flat_map(|a| RuleToken::ALL.iter().map(move |b| (a, b)))
            .filter(|(a, b)| a != b && tokens_agree(target, a.as_str(), b.as_str()))
            .count();
        assert_eq!(
            tolerated_elsewhere, 0,
            "target {target} tolerates {tolerated_elsewhere} unequal token pairs; only \
             {PHASE_DEPENDENT_TOLERANCE_TARGETS:?} may tolerate any"
        );
    }
}

/// An unknown token is never a tolerated mismatch. A typo on either side is
/// reported as an ordinary DISAGREEMENT — `tokens_agree` returns `false` and
/// the corpus loop records the pair — not as a harness failure, which is
/// `agreement::judge`'s separate missing-token guard for a `None` token. Both red the test;
/// only the message differs. What must never happen is the third outcome:
/// degrading to "something differs, probably fine".
#[test]
fn an_unknown_token_is_never_tolerated() {
    assert!(!tokens_agree(
        "manifest_body",
        "array_sort_order",
        "not_a_real_token"
    ));
    assert!(!tokens_agree(
        "manifest_body",
        "not_a_real_token",
        "not_a_real_token_either"
    ));
}
