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
//! The subprocess/corpus plumbing lives in
//! [`differential_replay_helpers`] so this entry file -- which holds the
//! classification tables, the tolerance predicate, `rust_decode`, and the
//! `#[test]` fns -- stays below the project's 500-LOC guideline. See that
//! module's own doc for the split rationale.

#![cfg(feature = "differential-replay")]

use std::fs;

mod differential_replay_helpers;

use differential_replay_helpers as helpers;
use helpers::corpus::corpus_dirs;
use helpers::python_bridge::{python_decode, PyOutcome};

const TARGETS: &[&str] = &[
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
/// `manifest_body` and nothing else. The five ordinary targets each need
/// their own Rust taxonomy and typed Python exceptions (#641);
/// `manifest_file` is blocked for a different, measured reason (#640) —
/// Rust's header raises `UnsupportedFormatVersion` where Python raises the
/// same `ParseError` it raises for every envelope fault, and because that
/// variant is shared with the BODY sentinel check no per-variant token can
/// reconcile the two.
const TOKEN_COMPARED_TARGETS: &[&str] = &["manifest_body"];

/// The rest, listed explicitly rather than by omission.
///
/// `every_target_is_classified` requires this list and the one above to
/// partition `TARGETS` exactly, so a new target cannot default silently into
/// the loose behaviour — the fail-open shape #595 found in this file's own
/// corpus discovery.
const NOT_TOKEN_COMPARED_TARGETS: &[&str] = &[
    "vault_toml",
    "record",
    "contact_card",
    "bundle_file",
    "manifest_file",
    "block_file",
];

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
/// rather than quietly shrinking the corpus. A developer with a populated
/// `core/fuzz/corpus/` sees more, which is why this is a floor and not an
/// equality. `every_target_is_classified` requires this table to cover
/// `TARGETS` exactly, so a new target cannot arrive without one.
const MIN_CORPUS_INPUTS: &[(&str, usize)] = &[
    ("vault_toml", 3),
    ("record", 3),
    ("contact_card", 2),
    ("bundle_file", 1),
    ("manifest_file", 1),
    ("manifest_body", 39),
    ("block_file", 1),
];

fn min_inputs(target: &str) -> usize {
    MIN_CORPUS_INPUTS
        .iter()
        .find(|(t, _)| *t == target)
        .map(|(_, n)| *n)
        .unwrap_or_else(|| panic!("target {target} has no MIN_CORPUS_INPUTS entry"))
}

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
/// MECHANISM, which is not the one the neighbouring `is_none()` guard uses:
/// an unknown non-null token falls through to `false` here and is reported as
/// an ordinary DISAGREEMENT, while a *missing* token is caught before this
/// function is reached and reported as a harness failure. Both red the test,
/// so nothing is lost — but "unrecognised or missing is a harness failure" is
/// wrong about half of it.
///
/// [`RuleToken::is_phase_dependent`]: secretary_core::vault::manifest::RuleToken::is_phase_dependent
fn tokens_agree(rust: &str, python: &str) -> bool {
    use secretary_core::vault::manifest::RuleToken;
    let lookup = |s: &str| RuleToken::ALL.iter().find(|t| t.as_str() == s).copied();
    let (Some(r), Some(p)) = (lookup(rust), lookup(python)) else {
        return false;
    };
    r == p || r.is_phase_dependent() || p.is_phase_dependent()
}

/// A Rust-side rejection: the token `differential_replay` compares, plus the
/// `Debug` rendering for the failure message.
///
/// `token` is `None` only for targets whose error type has no `rule_token()`
/// yet (#641). For a token-compared target a `None` here is a harness
/// failure, never agreement.
struct RustRejection {
    token: Option<&'static str>,
    detail: String,
}

/// Re-encode one fuzz-corpus input through the Rust decoder for that target.
///
/// Returns [`SecretBytes`](secretary_core::crypto::secret::SecretBytes), not
/// `Vec<u8>`. The `"record"` arm's output is a canonical re-encoding of a
/// decrypted record — every field value it holds — and `record::encode`
/// returns `SecretBytes` by construction as of #558/#565 precisely so that
/// no caller can hold it unwrapped. Unwrapping here with
/// `.expose().to_vec()` to satisfy the old `Vec<u8>` signature would
/// reintroduce exactly the buffer that change eliminates, in a harness whose
/// whole job is replaying a corpus of decoded records — so the wrapper is
/// threaded through the signature instead.
///
/// Five of the other six arms wrap too — `manifest_body`, added later, is
/// the second arm that does not, for the reason its own comment below
/// gives. Their outputs are not decrypted plaintext
/// (a `ContactCard` is the artifact handed to other users; the three `*_file`
/// encoders emit on-disk forms whose bodies are already AEAD ciphertext), so
/// wrapping them buys nothing directly — but a uniform return type keeps the
/// one arm that *does* matter from being the odd one out, which is how it
/// came to be unwrapped in the first place.
fn rust_decode(
    target: &str,
    bytes: &[u8],
) -> Result<secretary_core::crypto::secret::SecretBytes, RustRejection> {
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_core::*;
    match target {
        "vault_toml" => {
            let s = std::str::from_utf8(bytes).map_err(|e| RustRejection {
                token: None,
                detail: format!("utf8: {}", e),
            })?;
            unlock::vault_toml::decode(s)
                .map(|_| SecretBytes::new(Vec::new())) // crash-only target; no roundtrip compare
                .map_err(|e| RustRejection {
                    token: None,
                    detail: format!("{:?}", e),
                })
        }
        "record" => vault::record::decode(bytes)
            .and_then(|r| vault::record::encode(&r))
            .map_err(|e| RustRejection {
                token: None,
                detail: format!("{:?}", e),
            }),
        "contact_card" => identity::card::ContactCard::from_canonical_cbor(bytes)
            .and_then(|c| c.to_canonical_cbor())
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: None,
                detail: format!("{:?}", e),
            }),
        "bundle_file" => unlock::bundle_file::decode(bytes)
            .map(|f| SecretBytes::new(unlock::bundle_file::encode(&f)))
            .map_err(|e| RustRejection {
                token: None,
                detail: format!("{:?}", e),
            }),
        // NOTE: this arm fills `token`, but `manifest_file` is in
        // `NOT_TOKEN_COMPARED_TARGETS`, so the value is only ever printed in a
        // failure message — it is a diagnostic, not coverage. #640 explains why
        // the target cannot be compared and #641 tracks the other five.
        "manifest_file" => vault::manifest::decode_manifest_file(bytes)
            .and_then(|f| vault::manifest::encode_manifest_file(&f))
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        // Unlike `manifest_file` above, `encode_manifest` already returns
        // `SecretBytes` (the manifest *body*, §4.2/§4.3, is decrypted
        // plaintext) — so this arm needs no `SecretBytes::new` wrap, the
        // same reason the "record" arm above has none.
        "manifest_body" => vault::manifest::decode_manifest(bytes)
            .and_then(|m| vault::manifest::encode_manifest(&m))
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        "block_file" => vault::block::decode_block_file(bytes)
            .and_then(|f| vault::block::encode_block_file(&f))
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: None,
                detail: format!("{:?}", e),
            }),
        _ => panic!("unknown target {}", target),
    }
}

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
        let mut seen = 0usize;
        let dirs = corpus_dirs(target);
        for dir in &dirs {
            for entry in fs::read_dir(dir).expect("read corpus dir") {
                let path = entry.expect("dir entry").path();
                if !path.is_file() {
                    continue;
                }
                if path.file_name().and_then(|s| s.to_str()) == Some(".gitkeep") {
                    continue;
                }
                seen += 1;
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
        assert!(
            seen >= floor,
            "target {target}: replayed {seen} corpus input(s), floor is {floor} \
             — searched {dirs:?}. A target that replays nothing, or almost \
             nothing, passes vacuously; either restore the committed inputs \
             under core/fuzz/seeds/{target}/ or update MIN_CORPUS_INPUTS \
             deliberately in the same edit."
        );
        eprintln!("[{target}] replayed {seen} input(s)");
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
/// own doc, 300 lines up, says in bold that the predicate is strictly BROADER
/// than §4.2. Two doc comments in one file asserting opposite strengths for
/// one predicate is how a reader concludes the residual cannot exist. What is
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
