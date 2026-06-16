//! D.4.3 task 4: replay the pinned origin-matching KAT corpus.
//!
//! `tests/data/origin_match_kat.json` is the contract for `origin_match::decide`
//! (design §5). Every vector pins a `{fill | refuse}` + `reason` for a
//! `(top_origin, frame_origin, stored_origin, binding)` input. This replay
//! asserts the engine agrees with the corpus exactly. **Never relax a vector to
//! make the code pass** — a disagreement is a code or spec bug, resolved
//! explicitly (CLAUDE.md "Spec is normative").

use secretary_browser_host::origin_match::{decide, MatchReason, OriginBinding};
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    version: u32,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    top_origin: String,
    frame_origin: String,
    stored_origin: String,
    binding: OriginBinding,
    expect_fill: bool,
    expect_reason: MatchReason,
}

fn load() -> Corpus {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/origin_match_kat.json");
    let raw = std::fs::read_to_string(path).expect("origin_match_kat.json must be readable");
    serde_json::from_str(&raw).expect("origin_match_kat.json must parse")
}

#[test]
fn replay_origin_match_kat() {
    let corpus = load();
    assert_eq!(corpus.version, 1, "unexpected corpus version");
    assert!(
        corpus.vectors.len() >= 20,
        "the corpus should be comprehensive (got {})",
        corpus.vectors.len()
    );

    for v in &corpus.vectors {
        let d = decide(&v.top_origin, &v.frame_origin, &v.stored_origin, v.binding);
        assert_eq!(
            d.fill, v.expect_fill,
            "fill mismatch for '{}': decision={:?}",
            v.name, d
        );
        assert_eq!(
            d.reason, v.expect_reason,
            "reason mismatch for '{}': decision={:?}",
            v.name, d
        );
    }
}

#[test]
fn vector_names_are_unique() {
    let corpus = load();
    let mut names: Vec<&str> = corpus.vectors.iter().map(|v| v.name.as_str()).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate vector name in the corpus");
}
