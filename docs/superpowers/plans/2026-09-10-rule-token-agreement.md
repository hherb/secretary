# Cross-language rule-token agreement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `differential_replay.rs` compare *which rule* the Rust and Python manifest-body decoders report, instead of scoring every reject-vs-reject pair as agreement (#634), and make the remaining legitimate divergence normative rather than accidental (#621).

**Architecture:** One statement in three places. `docs/vault-format.md` §4.2 declares which rule orderings are unspecified; a `RuleToken` enum computed by an exhaustive match on `ManifestError` names rules on the Rust side; a `token` class attribute on typed Python exceptions names them on the Python side. The harness tolerates a token mismatch exactly when either token is *phase-dependent* — a predicate that IS the spec sentence, not a hand-maintained pair list.

**Tech Stack:** Rust (stable, workspace pinned 1.97.0), Python 3 via `uv` (never `pip`), `ciborium`, `cbor2`.

**Spec:** [`docs/superpowers/specs/2026-09-10-rule-token-agreement-design.md`](../specs/2026-09-10-rule-token-agreement-design.md)

> **CORRECTION, final whole-branch review.** This document is an execution log:
> its embedded code snippets and commit messages record what was written at the
> time and are deliberately NOT rewritten here. Two claims they carry are now
> known to be wrong, and the corrected versions live beside the code:
>
> 1. **"a predicate that IS the spec sentence"** (Architecture, above, and three
>    doc-comment snippets below). The predicate is DERIVED from §4.2's
>    "deliberately unspecified" paragraphs and is strictly BROADER — it is
>    per-TOKEN, so it tolerates every pair its token appears in. The two
>    families §4.2 does not free are enumerated in
>    `RuleToken::is_phase_dependent`'s LIMITS block
>    (`core/src/vault/manifest/token.rs`).
> 2. **"an unrecognised or missing token is a harness failure"** (commit-message
>    snippet below). Only a MISSING token is; an unrecognised one falls through
>    `tokens_agree` to `false` and is reported as an ordinary disagreement.
>    Both red the test, so no coverage was lost — the mechanism claim was wrong.
>
> The §4.2 paragraph this plan asked for also over-widened as first written; see
> the design spec's §3.2 for what it should have said and what it now says.

## Global Constraints

- Work in the worktree `/Users/hherb/src/secretary/.worktrees/rule-token-agreement`, branch `feature/rule-token-agreement`. Verify with `pwd && git branch --show-current` before any `cargo` / `git` / `uv` command. **Shell state does not persist between tool calls** — chain or use absolute paths.
- **Never `pip`.** `uv run` only.
- `cargo test` is always `--release` (the crypto crates are unusably slow in debug).
- `#![forbid(unsafe_code)]` is workspace-wide. Do not introduce `unsafe`.
- Clippy must stay clean: `cargo clippy --release --workspace --tests -- -D warnings`. This has caught an error `cargo test` missed in four consecutive sessions — run it, it is not redundant.
- Rustdoc must stay warning-clean: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`. Run `touch core/src/lib.rs` first; rustdoc caches and a ~5s run did nothing.
- Keep every file under 500 lines. Design as a directory module from the start rather than splitting later.
- **Python message text is load-bearing.** Several conformance sections match on message fragments (Section MUQ names the repeated id; Section MSH does `if want not in str(e)`). Every exception change in this plan is **message-preserving**. Verify by running the full `conformance.py`, not by reading.
- **Mutation harness discipline.** Any mutation probe must clear `__pycache__` and set `PYTHONDONTWRITEBYTECODE=1`. CPython invalidates bytecode on `(source_mtime, size)` with whole-second mtime, so a size-preserving Python mutation applied and reverted inside one second reports a **false green**. This trap was hit in the previous session despite being documented.
- Cite issues as `(#N)`, never `Closes #N`. A human closes them after verifying against the code.
- Attribution on every commit: `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.

**Token vocabulary (17 tokens).** Every task uses these exact spellings:

| token | phase-dependent |
|---|---|
| `rule2_indefinite_length` | yes |
| `rule3_non_shortest_form` | yes |
| `rule4_tag_or_float` | no |
| `non_canonical_unclassified` | yes |
| `array_sort_order` | yes |
| `repeated_array_value` | no |
| `duplicate_map_key` | no |
| `missing_field` | no |
| `wrong_type` | no |
| `integer_out_of_range` | no |
| `unsupported_version` | no |
| `malformed_cbor` | no |
| `container_malformed` | no |
| `aead_failure` | no |
| `signature_invalid` | no |
| `encoder_refusal` | no |
| `internal_error` | no |

---

### Task 1: Widen §4.2's "unspecified" sentence to cover the array sort disciplines (#621)

The tolerance predicate in Task 7 is derived from this sentence, so it lands first.

**Files:**
- Modify: `docs/vault-format.md` (the paragraph beginning "**The order of §6.2 rules 1, 2 and 3 against those two is deliberately unspecified**", currently at line 426)

**Interfaces:**
- Consumes: nothing.
- Produces: the normative justification for `RuleToken::is_phase_dependent` (Task 2) and for `differential_replay.rs`'s tolerance (Task 7).

- [ ] **Step 1: Read the existing paragraph in full**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
grep -n "deliberately" -B 2 -A 14 docs/vault-format.md | sed -n '1,40p'
```

Expected: the paragraph reproduced in the spec's §3. Confirm the opening words are `**The order of §6.2 rules 1, 2 and 3 against those two is deliberately unspecified**`. If they differ, stop — `main` has moved and the plan needs re-basing.

- [ ] **Step 2: Replace the paragraph's opening sentence and add the array clause**

Replace exactly this text:

```
**The order of §6.2 rules 1, 2 and 3 against those two is deliberately
unspecified**, and the reason is architectural rather than an omission. This
section admits two reader designs, and each necessarily detects those three
rules at a different point:
```

with:

```
**The order of §6.2 rules 1, 2 and 3, and of this section's five array sort
disciplines, against those two is deliberately unspecified**, and the reason is
architectural rather than an omission. This section admits two reader designs,
and each necessarily detects those rules at a different point:
```

Then, immediately after the existing sentence ending `...outlaw one design or the other.`, insert this paragraph:

```
The five array sort disciplines are in this category for the same reason, one
layer up. A reader whose encoder sorts those arrays on output detects disorder
only at the §4.3 step-4 re-encode comparison, after interpretation; a
byte-retaining reader re-emits its input unconditionally, so its own re-encode
can never see array disorder and it must check the discipline directly, during
its scan. A body that is both out of array sort order and breaks one of the two
fixed orderings above may therefore be reported as either.

This does NOT extend to the repeated-array-value rules. Both reader designs
check those during interpretation — sortedness and distinctness are independent,
and a body carrying a repeat re-encodes to itself byte for byte, so no reader
obtains them from the re-encode. Their order relative to the two fixed orderings
above is therefore not given away here.
```

- [ ] **Step 3: Verify the spec cites no test name**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/spec_test_name_freshness.py; echo "EXIT: $?"
```

Expected: EXIT 0, and the reported count unchanged from `main`. Measure `main`'s count rather than trusting any document:

```bash
git stash list  # must NOT be used; see Global Constraints
git show main:core/tests/python/spec_test_name_freshness.py > /tmp/freshness_main.py 2>/dev/null && echo "baseline script captured"
```

If the count differs, the added prose accidentally names a test — remove the name.

- [ ] **Step 4: Verify the conformance suite is unaffected**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/conformance.py > /tmp/conf1.txt 2>&1; echo "EXIT: $?"
grep -c "^FAIL" /tmp/conf1.txt
```

Expected: EXIT 0 and `0` FAIL lines. A docs-only change must move nothing.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add docs/vault-format.md
git commit -m "$(cat <<'EOF'
spec: the five array sort disciplines are unordered against the fixed rules (#621)

Rust reports ArraySortOrder for a body that is both out of array sort order and
carries an indefinite-length item; conformance.py reports crypto-design §6.2
rule 2. Same bytes, same offset, both conformant — the two designs §4.2 admits
detect array disorder at different points, so fixing an order would outlaw one.

Deliberately NOT extended to the repeated-array-value rules: both designs check
those during interpretation, so that ordering stays free of charge.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 2: `RuleToken` and the shared vocabulary fixture

**Files:**
- Create: `core/src/vault/manifest/token.rs`
- Create: `core/src/vault/manifest/token/tests.rs`
- Create: `core/tests/data/rule_token_vocabulary.json`
- Modify: `core/src/vault/manifest/mod.rs` (add `mod token;` after line 67's `mod types;`, and `pub use token::RuleToken;` beside the other re-exports)

**Interfaces:**
- Consumes: Task 1's spec sentence (as the justification in `is_phase_dependent`'s doc).
- Produces: `secretary_core::vault::manifest::RuleToken`, with `RuleToken::ALL: &[RuleToken]`, `fn as_str(&self) -> &'static str`, `fn is_phase_dependent(&self) -> bool`. Task 3 maps `ManifestError` onto it; Task 5 reads the JSON fixture from Python; Task 7 consumes `as_str` and `is_phase_dependent`.

- [ ] **Step 1: Write the failing tests**

Create `core/src/vault/manifest/token/tests.rs`:

```rust
use super::*;

/// Every token spells itself distinctly. Two tokens sharing a string would
/// make the Python side unable to tell them apart, and the divergence would
/// present as agreement — the exact failure this vocabulary exists to end.
#[test]
fn token_strings_are_distinct() {
    let mut seen = std::collections::BTreeSet::new();
    for t in RuleToken::ALL {
        assert!(
            seen.insert(t.as_str()),
            "two RuleToken variants share the spelling {:?}",
            t.as_str()
        );
    }
    assert_eq!(seen.len(), RuleToken::ALL.len());
}

/// `ALL` must really be all of them. A variant missing from the slice is
/// invisible to the fixture cross-check below and to Python.
#[test]
fn all_lists_every_variant() {
    // Exhaustive match: adding a variant without adding it to ALL is a
    // COMPILE error here, not a silent gap.
    for t in RuleToken::ALL {
        let _covered = match t {
            RuleToken::Rule2IndefiniteLength
            | RuleToken::Rule3NonShortestForm
            | RuleToken::Rule4TagOrFloat
            | RuleToken::NonCanonicalUnclassified
            | RuleToken::ArraySortOrder
            | RuleToken::RepeatedArrayValue
            | RuleToken::DuplicateMapKey
            | RuleToken::MissingField
            | RuleToken::WrongType
            | RuleToken::IntegerOutOfRange
            | RuleToken::UnsupportedVersion
            | RuleToken::MalformedCbor
            | RuleToken::ContainerMalformed
            | RuleToken::AeadFailure
            | RuleToken::SignatureInvalid
            | RuleToken::EncoderRefusal
            | RuleToken::InternalError => (),
        };
    }
    assert_eq!(RuleToken::ALL.len(), 17);
}

/// Exactly the four rules vault-format §4.2 declares unordered are
/// phase-dependent. Pinned as a SET, not per-variant, so widening the
/// predicate without widening the spec reds here.
#[test]
fn phase_dependent_set_matches_the_spec() {
    let got: std::collections::BTreeSet<&str> = RuleToken::ALL
        .iter()
        .filter(|t| t.is_phase_dependent())
        .map(|t| t.as_str())
        .collect();
    let want: std::collections::BTreeSet<&str> = [
        "array_sort_order",
        "non_canonical_unclassified",
        "rule2_indefinite_length",
        "rule3_non_shortest_form",
    ]
    .into_iter()
    .collect();
    assert_eq!(got, want);
}

/// Rule 4 is deliberately NOT phase-dependent: neither reader design obtains
/// it from the re-encode, so §4.2 requires both to run the walk first. If this
/// ever flips, #618's whole precedence paragraph has been undone.
#[test]
fn rule4_is_ordered_not_phase_dependent() {
    assert!(!RuleToken::Rule4TagOrFloat.is_phase_dependent());
}

/// The committed fixture both languages read must agree with this enum, in
/// BOTH directions. Without it the two could drift onto different spellings
/// and every cross-language comparison would silently become a mismatch.
#[test]
fn vocabulary_fixture_matches_the_enum() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data/rule_token_vocabulary.json");
    let raw = std::fs::read_to_string(&path).expect("read rule_token_vocabulary.json");
    let doc: serde_json::Value = serde_json::from_str(&raw).expect("parse vocabulary JSON");
    let rows = doc["tokens"].as_object().expect("`tokens` must be an object");

    assert_eq!(
        rows.len(),
        RuleToken::ALL.len(),
        "fixture has {} tokens, enum has {}",
        rows.len(),
        RuleToken::ALL.len()
    );
    for t in RuleToken::ALL {
        let row = rows
            .get(t.as_str())
            .unwrap_or_else(|| panic!("fixture is missing token {:?}", t.as_str()));
        let want = row["phase_dependent"]
            .as_bool()
            .unwrap_or_else(|| panic!("token {:?} has no boolean phase_dependent", t.as_str()));
        assert_eq!(
            want,
            t.is_phase_dependent(),
            "token {:?}: fixture says phase_dependent={}, enum says {}",
            t.as_str(),
            want,
            t.is_phase_dependent()
        );
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo test --release -p secretary-core --lib manifest::token 2>&1 | tail -20
```

Expected: a compile error — `token.rs` does not exist and `mod token;` is not declared.

- [ ] **Step 3: Write `core/src/vault/manifest/token.rs`**

```rust
//! A language-neutral name for the rule a rejecting manifest decoder is
//! reporting, so two independent implementations can be compared on WHICH
//! rule they named and not merely on whether they rejected (#634).
//!
//! **Deliberately coarser than [`ManifestError`].** Every distinction this
//! vocabulary draws is one both implementations must then maintain forever,
//! so it draws only the ones that carry evidence: enough to separate the
//! divergences #618 and #621 found, and no finer. `ContainerMalformed`
//! merges eight file-level variants for that reason.
//!
//! **A token may only draw a distinction BOTH implementations can make.**
//! Where one is structurally blind, the token coarsens to what they share.
//! The worked example is trailing bytes after the manifest map:
//! `ciborium`'s reader performs no EOF check, so Rust's parse discards them
//! before the §4.3 step-4 comparison and `classify_non_canonical` has
//! nothing in the body to point at — it can only ever say
//! [`Self::NonCanonicalUnclassified`]. `conformance.py` names them exactly.
//! There is therefore no `trailing_bytes` token, and Python's raise carries
//! the coarse one; its own message stays specific, so no human loses a
//! diagnostic.
//!
//! [`ManifestError`]: super::ManifestError

/// Which rule a rejecting manifest decoder is reporting.
///
/// Fieldless by construction (#474): every variant is a compile-time
/// constant, so no decrypted manifest content can ride along.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RuleToken {
    /// crypto-design §6.2 rule 2 — an indefinite-length item.
    Rule2IndefiniteLength,
    /// crypto-design §6.2 rule 3 — a non-shortest-form integer or length head.
    Rule3NonShortestForm,
    /// crypto-design §6.2 rule 4 — a tag or a float, anywhere in the body.
    Rule4TagOrFloat,
    /// The body is not the canonical encoding of the value this reader
    /// parsed, with no finer classification the two implementations agree on.
    ///
    /// Covers map-key disorder (§6.2 rule 1), which leaves nothing in the
    /// body to point at, and trailing bytes — see this module's own doc for
    /// why the latter has no token of its own.
    NonCanonicalUnclassified,
    /// One of `docs/vault-format.md` §4.2's five array sort disciplines.
    ArraySortOrder,
    /// §4.2's repeated-array-value prohibition, in one of the four arrays it
    /// binds. `recipients` is the explicit exception and never produces this.
    RepeatedArrayValue,
    /// A map this reader interprets carries the same key twice.
    DuplicateMapKey,
    /// A §4.2 required key is absent.
    MissingField,
    /// A field's CBOR major type, or a byte string's length, is not what §4.2
    /// requires — including a body that is not a map, and a non-text map key.
    WrongType,
    /// An integer field is outside the width §4.2 gives it.
    IntegerOutOfRange,
    /// A v1 sentinel — `manifest_version`, `format_version`, `suite_id` — is
    /// not the v1 value, at either the body or the file-header layer.
    UnsupportedVersion,
    /// The bytes are not well-formed CBOR at all.
    MalformedCbor,
    /// The §4.1 file envelope is malformed: magic, file kind, header or
    /// section truncation, a declared length that does not match, trailing
    /// bytes after the file, or a wrong signature length.
    ContainerMalformed,
    /// §4.1 AEAD verification failed.
    AeadFailure,
    /// An §8 hybrid signature half did not verify.
    SignatureInvalid,
    /// The ENCODER refused to emit a body its own decoder would reject. Not a
    /// property of any input — a caller built a malformed `Manifest` in
    /// memory (#600, #587).
    EncoderRefusal,
    /// A fault in this implementation rather than in the input: an encode
    /// failure, a capacity bound, a signing error.
    InternalError,
}

impl RuleToken {
    /// Every variant, in declaration order.
    ///
    /// `token/tests.rs` pins that this really is every variant, by an
    /// exhaustive match that fails to COMPILE when a variant is added
    /// without being listed here.
    pub const ALL: &'static [RuleToken] = &[
        RuleToken::Rule2IndefiniteLength,
        RuleToken::Rule3NonShortestForm,
        RuleToken::Rule4TagOrFloat,
        RuleToken::NonCanonicalUnclassified,
        RuleToken::ArraySortOrder,
        RuleToken::RepeatedArrayValue,
        RuleToken::DuplicateMapKey,
        RuleToken::MissingField,
        RuleToken::WrongType,
        RuleToken::IntegerOutOfRange,
        RuleToken::UnsupportedVersion,
        RuleToken::MalformedCbor,
        RuleToken::ContainerMalformed,
        RuleToken::AeadFailure,
        RuleToken::SignatureInvalid,
        RuleToken::EncoderRefusal,
        RuleToken::InternalError,
    ];

    /// The wire spelling, shared with `conformance.py` through
    /// `core/tests/data/rule_token_vocabulary.json`.
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleToken::Rule2IndefiniteLength => "rule2_indefinite_length",
            RuleToken::Rule3NonShortestForm => "rule3_non_shortest_form",
            RuleToken::Rule4TagOrFloat => "rule4_tag_or_float",
            RuleToken::NonCanonicalUnclassified => "non_canonical_unclassified",
            RuleToken::ArraySortOrder => "array_sort_order",
            RuleToken::RepeatedArrayValue => "repeated_array_value",
            RuleToken::DuplicateMapKey => "duplicate_map_key",
            RuleToken::MissingField => "missing_field",
            RuleToken::WrongType => "wrong_type",
            RuleToken::IntegerOutOfRange => "integer_out_of_range",
            RuleToken::UnsupportedVersion => "unsupported_version",
            RuleToken::MalformedCbor => "malformed_cbor",
            RuleToken::ContainerMalformed => "container_malformed",
            RuleToken::AeadFailure => "aead_failure",
            RuleToken::SignatureInvalid => "signature_invalid",
            RuleToken::EncoderRefusal => "encoder_refusal",
            RuleToken::InternalError => "internal_error",
        }
    }

    /// True when the two reader designs `docs/vault-format.md` §4.2 admits
    /// detect this rule at DIFFERENT points, so §4.2 declares its order
    /// against the section's two fixed orderings unspecified.
    ///
    /// This predicate IS that sentence, which is why the cross-language
    /// harness derives its tolerance from it rather than from a
    /// hand-maintained list of tolerated pairs: a pair list would have to be
    /// re-derived every time a token is added and would drift from §4.2
    /// silently.
    ///
    /// A normalising-parse reader sees these only at the §4.3 step-4
    /// re-encode — after interpretation. A byte-retaining reader must see
    /// them during its scan — before it. Rule 4 is deliberately absent:
    /// NEITHER design obtains it from the re-encode, so §4.2 can and does
    /// require both to run the whole-body walk first (#618).
    ///
    /// The repeated-array-value rule is absent for the mirror reason: both
    /// designs check it during interpretation, because `[x, x]` is sorted
    /// and re-encodes to itself, so no reader gets it from the re-encode
    /// either.
    pub fn is_phase_dependent(&self) -> bool {
        match self {
            RuleToken::Rule2IndefiniteLength
            | RuleToken::Rule3NonShortestForm
            | RuleToken::NonCanonicalUnclassified
            | RuleToken::ArraySortOrder => true,
            RuleToken::Rule4TagOrFloat
            | RuleToken::RepeatedArrayValue
            | RuleToken::DuplicateMapKey
            | RuleToken::MissingField
            | RuleToken::WrongType
            | RuleToken::IntegerOutOfRange
            | RuleToken::UnsupportedVersion
            | RuleToken::MalformedCbor
            | RuleToken::ContainerMalformed
            | RuleToken::AeadFailure
            | RuleToken::SignatureInvalid
            | RuleToken::EncoderRefusal
            | RuleToken::InternalError => false,
        }
    }
}

#[cfg(test)]
mod tests;
```

- [ ] **Step 4: Create the vocabulary fixture**

Create `core/tests/data/rule_token_vocabulary.json`:

```json
{
  "_comment": "The shared RuleToken vocabulary (#634). Read by core/src/vault/manifest/token/tests.rs and by conformance_lib/sections/rule_token_vocabulary.py, so the Rust enum and the Python exception attributes cannot drift onto different spellings. `phase_dependent` is docs/vault-format.md §4.2's 'deliberately unspecified' sentence, expressed as data.",
  "tokens": {
    "rule2_indefinite_length": {"phase_dependent": true},
    "rule3_non_shortest_form": {"phase_dependent": true},
    "rule4_tag_or_float": {"phase_dependent": false},
    "non_canonical_unclassified": {"phase_dependent": true},
    "array_sort_order": {"phase_dependent": true},
    "repeated_array_value": {"phase_dependent": false},
    "duplicate_map_key": {"phase_dependent": false},
    "missing_field": {"phase_dependent": false},
    "wrong_type": {"phase_dependent": false},
    "integer_out_of_range": {"phase_dependent": false},
    "unsupported_version": {"phase_dependent": false},
    "malformed_cbor": {"phase_dependent": false},
    "container_malformed": {"phase_dependent": false},
    "aead_failure": {"phase_dependent": false},
    "signature_invalid": {"phase_dependent": false},
    "encoder_refusal": {"phase_dependent": false},
    "internal_error": {"phase_dependent": false}
  }
}
```

- [ ] **Step 5: Wire the module**

In `core/src/vault/manifest/mod.rs`, add `mod token;` in the alphabetically-sorted `mod` block (after `mod sentinel;`, before `mod types;`), and add `pub use token::RuleToken;` alongside the other `pub use` lines (after `pub use header::{...};`, before `pub use types::{...};` — keep the existing alphabetical grouping).

- [ ] **Step 6: Confirm `serde_json` is available to the lib's test target**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
grep -n "serde_json" core/Cargo.toml
```

Expected: a `serde_json` line under `[dev-dependencies]`. If it is only under `[dependencies]` that is also fine. If it appears in neither, add it to `[dev-dependencies]` matching the version already used elsewhere in the workspace (`grep -rn '^serde_json' */Cargo.toml`).

- [ ] **Step 7: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo test --release -p secretary-core --lib manifest::token 2>&1 | tail -12
```

Expected: `5 passed`.

- [ ] **Step 8: Prove the fixture cross-check is not vacuous**

Flip one fixture value, confirm exactly one test reds, restore, confirm green:

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cp core/tests/data/rule_token_vocabulary.json /tmp/vocab.bak
sed -i '' 's/"array_sort_order": {"phase_dependent": true}/"array_sort_order": {"phase_dependent": false}/' core/tests/data/rule_token_vocabulary.json
cargo test --release -p secretary-core --lib manifest::token 2>&1 | grep -E "^test |test result"
cp /tmp/vocab.bak core/tests/data/rule_token_vocabulary.json
shasum -a 256 core/tests/data/rule_token_vocabulary.json /tmp/vocab.bak
cargo test --release -p secretary-core --lib manifest::token 2>&1 | grep "test result"
```

Expected: the mutated run fails `vocabulary_fixture_matches_the_enum` only; the two sha256 sums match after restore; the restored run is `5 passed`.

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add core/src/vault/manifest/token.rs core/src/vault/manifest/token/tests.rs \
        core/src/vault/manifest/mod.rs core/tests/data/rule_token_vocabulary.json
git commit -m "$(cat <<'EOF'
core: a language-neutral RuleToken vocabulary for decoder-agreement (#634)

Seventeen fieldless tokens naming which rule a rejecting manifest decoder is
reporting, plus is_phase_dependent() — which IS vault-format §4.2's
"deliberately unspecified" sentence, so the cross-language harness derives its
tolerance from the spec rather than from a hand-maintained pair list.

Deliberately coarse: every distinction drawn is one both implementations must
maintain forever, so it draws only the ones that carry evidence. A token may
only draw a distinction BOTH implementations can make — hence no trailing_bytes
token, since ciborium performs no EOF check and Rust can only ever say
non_canonical_unclassified there.

core/tests/data/rule_token_vocabulary.json is the shared fixture both languages
read, cross-checked against the enum in both directions.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 3: `ManifestError::rule_token()` — the exhaustive Rust mapping

**Files:**
- Modify: `core/src/vault/manifest/token.rs` (append an `impl ManifestError` block)
- Modify: `core/src/vault/manifest/token/tests.rs` (append the mapping tests)

**Interfaces:**
- Consumes: `RuleToken` (Task 2); `ManifestError`, `CanonicalError` and `NonCanonicalCause` from the crate.
- Produces: `ManifestError::rule_token(&self) -> RuleToken`, consumed by Task 7.

- [ ] **Step 1: Write the failing tests**

Append to `core/src/vault/manifest/token/tests.rs`:

```rust
use crate::vault::manifest::ManifestError;

/// The four causes must each keep their own token. Collapsing any two would
/// make #621's divergence — array sort order vs §6.2 rule 2 — invisible again.
#[test]
fn each_non_canonical_cause_has_its_own_token() {
    use crate::vault::manifest::NonCanonicalCause as C;
    let pairs = [
        (C::ArraySortOrder, RuleToken::ArraySortOrder),
        (C::IndefiniteLength, RuleToken::Rule2IndefiniteLength),
        (C::NonShortestForm, RuleToken::Rule3NonShortestForm),
        (C::Unclassified, RuleToken::NonCanonicalUnclassified),
    ];
    for (cause, want) in pairs {
        let err = ManifestError::NonCanonicalEncoding { cause, at: None };
        assert_eq!(err.rule_token(), want, "cause {:?}", cause);
    }
}

/// A repeated map key and a repeated ARRAY value are different rules and must
/// not share a token: §4.2 orders the first against the type checks and leaves
/// the second alone.
#[test]
fn map_key_repeats_and_array_value_repeats_are_different_tokens() {
    let map_key = ManifestError::DuplicateKey {
        field: "manifest",
        index: 1,
    };
    assert_eq!(map_key.rule_token(), RuleToken::DuplicateMapKey);
    for err in [
        ManifestError::DuplicateBlockUuid,
        ManifestError::DuplicateTrashUuid,
        ManifestError::VectorClockDuplicateDevice,
    ] {
        assert_eq!(err.rule_token(), RuleToken::RepeatedArrayValue);
    }
}

/// A decoder rejection and an ENCODER refusal are different events (#600,
/// #587) and must stay different tokens — otherwise a body a caller built
/// wrong in memory would be compared against a peer's reading of real bytes.
#[test]
fn encoder_refusals_are_not_decoder_rejections() {
    for err in [
        ManifestError::EncodeDuplicateBlockUuid,
        ManifestError::EncodeDuplicateTrashUuid,
        ManifestError::EncodeVectorClockDuplicateDevice,
        ManifestError::EncodeUnsupportedManifestVersion(7),
        ManifestError::EncodeUnsupportedFormatVersion(9),
        ManifestError::EncodeUnsupportedSuiteId(9),
    ] {
        assert_eq!(err.rule_token(), RuleToken::EncoderRefusal);
    }
    assert_eq!(
        ManifestError::UnsupportedManifestVersion(7).rule_token(),
        RuleToken::UnsupportedVersion
    );
}

/// The three v1 sentinels share one token at BOTH layers. `header.rs` raises
/// the same two variants the body sentinel check does, which is exactly why
/// `manifest_file` cannot be token-compared (#640) — recorded here so the
/// reason survives beside the mapping that causes it.
#[test]
fn every_v1_sentinel_maps_to_unsupported_version() {
    for err in [
        ManifestError::UnsupportedManifestVersion(7),
        ManifestError::UnsupportedFormatVersion(9),
        ManifestError::UnsupportedSuiteId(9),
    ] {
        assert_eq!(err.rule_token(), RuleToken::UnsupportedVersion);
    }
}

/// A real decode of a real corrupt body must produce the token the corpus
/// says. Reading the match arms proves nothing about which arm the decoder
/// reaches; this drives `decode_manifest` end to end.
#[test]
fn a_real_rejection_carries_the_expected_token() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/manifest_body");
    let cases = [
        ("top__rule4_float.bin", RuleToken::Rule4TagOrFloat),
        ("top__rule2_indefinite_map.bin", RuleToken::Rule2IndefiniteLength),
        ("top__rule3_non_shortest_int.bin", RuleToken::Rule3NonShortestForm),
        ("keyorder__top.bin", RuleToken::NonCanonicalUnclassified),
        ("arraysort__blocks.bin", RuleToken::ArraySortOrder),
        ("uniq__blocks__duplicate_block_uuid.bin", RuleToken::RepeatedArrayValue),
    ];
    for (name, want) in cases {
        let bytes = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {}: {}", name, e));
        let err = crate::vault::manifest::decode_manifest(&bytes)
            .expect_err(&format!("{} must be rejected", name));
        assert_eq!(err.rule_token(), want, "seed {}", name);
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo test --release -p secretary-core --lib manifest::token 2>&1 | tail -20
```

Expected: compile error, `no method named rule_token`.

- [ ] **Step 3: Append the mapping to `core/src/vault/manifest/token.rs`**

```rust
use super::cause::NonCanonicalCause;
use super::error::ManifestError;
use crate::vault::canonical::CanonicalError;

impl ManifestError {
    /// Which rule this rejection is reporting, as a language-neutral token.
    ///
    /// **Exhaustive by construction.** Adding a `ManifestError` variant
    /// without classifying it is a compile error, which is the whole point:
    /// a wildcard arm would let a new variant fall silently into some
    /// neighbour's token and present a divergence as agreement. Same ruling
    /// as #589's `Once` and #608's `Verdict` — make the obligation a type
    /// obligation, not a convention.
    ///
    /// **Advisory, never a verdict.** Nothing in the crate consults this to
    /// decide acceptance; it exists so two implementations can be compared
    /// on what they said. Same family as [`NonCanonicalCause`] (#590).
    pub fn rule_token(&self) -> RuleToken {
        match self {
            // --- §4.2 body: canonical form -------------------------------
            ManifestError::NonCanonicalEncoding { cause, .. } => match cause {
                NonCanonicalCause::ArraySortOrder => RuleToken::ArraySortOrder,
                NonCanonicalCause::IndefiniteLength => RuleToken::Rule2IndefiniteLength,
                NonCanonicalCause::NonShortestForm => RuleToken::Rule3NonShortestForm,
                NonCanonicalCause::Unclassified => RuleToken::NonCanonicalUnclassified,
            },
            // `reject_floats_and_tags` runs before `parse_manifest_map`, so
            // this is §6.2 rule 4. The DuplicateKey arm is the canonical
            // encoder's own, reached through the §4.3 step-4 re-encode.
            ManifestError::Canonical(e) => match e {
                CanonicalError::FloatRejected { .. } | CanonicalError::TagRejected { .. } => {
                    RuleToken::Rule4TagOrFloat
                }
                CanonicalError::DuplicateKey { .. } => RuleToken::DuplicateMapKey,
                CanonicalError::CborEncode(_) | CanonicalError::CapacityBoundExceeded { .. } => {
                    RuleToken::InternalError
                }
            },

            // --- §4.2 body: schema ---------------------------------------
            ManifestError::DuplicateKey { .. } => RuleToken::DuplicateMapKey,
            ManifestError::MissingField { .. } => RuleToken::MissingField,
            ManifestError::NotAMap
            | ManifestError::NonTextKey
            | ManifestError::WrongType { .. }
            | ManifestError::InvalidByteLength { .. } => RuleToken::WrongType,
            ManifestError::IntegerOutOfRange { .. } => RuleToken::IntegerOutOfRange,

            // --- v1 sentinels, at BOTH layers ----------------------------
            // `header.rs` raises the format/suite pair for the §4.1 file
            // header and `sentinel.rs` raises all three for the §4.2 body.
            // One token cannot tell those apart, which is precisely why
            // `manifest_file` is not token-compared (#640).
            ManifestError::UnsupportedManifestVersion(_)
            | ManifestError::UnsupportedFormatVersion(_)
            | ManifestError::UnsupportedSuiteId(_) => RuleToken::UnsupportedVersion,

            // --- §4.2 arrays ---------------------------------------------
            ManifestError::VectorClockDuplicateDevice
            | ManifestError::DuplicateBlockUuid
            | ManifestError::DuplicateTrashUuid => RuleToken::RepeatedArrayValue,

            // --- the encoder refusing to emit a body ---------------------
            // Not a property of any input: a caller built a malformed
            // `Manifest` in memory. Kept apart from the decoder's tokens for
            // the reason #600 kept the variants apart.
            ManifestError::EncodeDuplicateBlockUuid
            | ManifestError::EncodeDuplicateTrashUuid
            | ManifestError::EncodeVectorClockDuplicateDevice
            | ManifestError::EncodeUnsupportedManifestVersion(_)
            | ManifestError::EncodeUnsupportedFormatVersion(_)
            | ManifestError::EncodeUnsupportedSuiteId(_) => RuleToken::EncoderRefusal,

            // --- CBOR well-formedness ------------------------------------
            ManifestError::CborDecode(_) => RuleToken::MalformedCbor,

            // --- §4.1 file envelope --------------------------------------
            ManifestError::BadMagic { .. }
            | ManifestError::UnsupportedFileKind { .. }
            | ManifestError::HeaderTruncated { .. }
            | ManifestError::SectionTruncated { .. }
            | ManifestError::AeadCtLenMismatch { .. }
            | ManifestError::TrailingBytes(_)
            | ManifestError::SigEdWrongLength { .. }
            | ManifestError::SigPqWrongLength { .. } => RuleToken::ContainerMalformed,
            ManifestError::AeadFailure => RuleToken::AeadFailure,
            ManifestError::Ed25519SignatureInvalid | ManifestError::MlDsa65SignatureInvalid => {
                RuleToken::SignatureInvalid
            }

            // --- this implementation's own faults ------------------------
            ManifestError::CborEncode(_) | ManifestError::SignInternal(_) => {
                RuleToken::InternalError
            }
        }
    }
}
```

Note: the `use` lines go at the TOP of `token.rs`, beside the module doc, not inside the `impl`. If `crate::vault::canonical::CanonicalError` does not resolve, check its actual path with `grep -rn "pub enum CanonicalError" core/src/vault/canonical/` and the re-export in `core/src/vault/canonical/mod.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo test --release -p secretary-core --lib manifest::token 2>&1 | tail -14
```

Expected: `10 passed`.

- [ ] **Step 5: Prove exhaustiveness is real, not decorative**

Temporarily add a wildcard-defeating variant and confirm the compiler rejects the match:

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cp core/src/vault/manifest/error.rs /tmp/error.bak
python3 - <<'EOF'
import pathlib
p = pathlib.Path("core/src/vault/manifest/error.rs")
s = p.read_text()
s = s.replace('    #[error("manifest body must be a CBOR map")]',
              '    #[error("probe")]\n    ZzProbeVariant,\n    #[error("manifest body must be a CBOR map")]', 1)
p.write_text(s)
EOF
cargo build --release -p secretary-core 2>&1 | grep -cE "non-exhaustive patterns|E0004"
cp /tmp/error.bak core/src/vault/manifest/error.rs
shasum -a 256 core/src/vault/manifest/error.rs /tmp/error.bak
cargo build --release -p secretary-core 2>&1 | tail -2
```

Expected: a non-zero count from the grep (the compiler refused the incomplete match), matching sha256 sums after restore, and a clean build.

- [ ] **Step 6: Run the whole lib target and clippy**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo test --release -p secretary-core --lib 2>&1 | grep "test result"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
```

Expected: `0 failed` and clippy exiting cleanly. Do not skip clippy — it has caught an error `cargo test` missed in four consecutive sessions.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add core/src/vault/manifest/token.rs core/src/vault/manifest/token/tests.rs
git commit -m "$(cat <<'EOF'
core: classify every ManifestError variant into a RuleToken (#634)

An exhaustive match, so adding a variant without classifying it is a compile
error rather than a silent fall into a neighbour's token — the same
type-obligation ruling #589's Once and #608's Verdict took.

It lives inside the crate because it must read CanonicalError's variants to
keep §6.2 rule 4 apart from rule 5, and vault::canonical is pub(crate), so an
integration test can only see the Canonical(_) family (#635).

The three v1 sentinels share one token at both the file-header and body layers,
because header.rs and sentinel.rs raise the same variants. That is exactly why
manifest_file cannot be token-compared (#640), recorded beside the mapping that
causes it.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 4: Typed Python exceptions carrying tokens

**Files:**
- Create: `core/tests/python/conformance_lib/codec/manifest_rules.py`
- Modify: `core/tests/python/conformance_lib/codec/manifest_decode.py` (14 raise sites)
- Modify: `core/tests/python/conformance_lib/codec/scanner.py` (add `token` to `NonCanonicalItem` and `DuplicateMapKey`)
- Modify: `core/tests/python/conformance_lib/cursor.py` (add `token` to `ParseError`)

**Interfaces:**
- Consumes: the token spellings from Task 2's fixture.
- Produces: `conformance_lib.codec.manifest_rules.token_for(exc) -> str | None`, plus the exception classes `TrailingBytesAfterMap`, `NonTextMapKey`, `MissingRequiredField`, `WrongFieldType`, `IntegerOutOfRange`, `UnsupportedVersion`, `RepeatedArrayValue`. Consumed by Task 5 (the section) and Task 6 (`diff_replay.py`).

- [ ] **Step 1: Write `core/tests/python/conformance_lib/codec/manifest_rules.py`**

```python
"""Typed rejections for the §4.2 manifest-body decoder, each carrying the
language-neutral rule token `differential_replay.rs` compares (#634).

WHY TYPES AND NOT MESSAGES.  `conformance.py` already learned this twice.
Section MUQ keyed on a message fragment and was satisfied by the ENCODER's
refusal, which happened to contain the same words (#608); #604 replaced a
`"rule 2:"` substring match with `NonCanonicalItem.rule` for the same reason.
A substring match is blind to everything around the fragment: it keeps passing
when the message is reworded into something that no longer means what it did,
and keeps passing when a DIFFERENT check grows a message containing it.

WHY A CLASS ATTRIBUTE AND NOT A LOOKUP TABLE.  A table maps a class to a
token in a second place, so a new subclass silently gets no token; the
attribute travels with the raise site.  `token_for` deliberately reads the
attribute off ANY exception rather than off a base class, because
`cursor.ParseError` is shared with every other target's wire decoder and must
not be reparented under a manifest-specific base.

MESSAGE-PRESERVING.  Every class here is introduced by changing `ValueError`
to a subclass of it at an existing raise site with the message untouched, so
no section that reads `str(e)` moves.  All of these subclass `ValueError`, so
`conformance_lib.rejection`'s allowlist keeps scoring them as verdicts rather
than as harness failures.
"""

from __future__ import annotations


class ManifestRejection(ValueError):
    """A §4.2 manifest-body rejection carrying a rule token.

    `token` is a CLASS attribute: it is a property of the rule, never of the
    instance, so it cannot be set wrong at a raise site.
    """

    token: str = ""


class TrailingBytesAfterMap(ManifestRejection):
    """Bytes follow the manifest map.

    Deliberately shares Rust's coarse token rather than getting one of its
    own.  `ciborium`'s reader performs no EOF check, so the Rust parse
    discards these bytes before the §4.3 step-4 comparison and
    `classify_non_canonical` has nothing in the body to point at — it can
    only ever report `Unclassified`.  A `trailing_bytes` token would be a
    distinction only ONE implementation can make, and the message below stays
    specific so no human reader loses the diagnostic.
    """

    token = "non_canonical_unclassified"


class NonTextMapKey(ManifestRejection):
    """A manifest map key is not a text string (§4.2)."""

    token = "wrong_type"


class MissingRequiredField(ManifestRejection):
    """A §4.2 required key is absent."""

    token = "missing_field"


class WrongFieldType(ManifestRejection):
    """A field's CBOR major type or byte-string length is not what §4.2 says."""

    token = "wrong_type"


class IntegerOutOfRange(ManifestRejection):
    """An integer field is outside the width §4.2 gives it."""

    token = "integer_out_of_range"


class UnsupportedVersion(ManifestRejection):
    """A v1 sentinel is not the v1 value."""

    token = "unsupported_version"


class RepeatedArrayValue(ManifestRejection):
    """One of §4.2's four repeated-value prohibitions.

    NOT the same rule as a repeated MAP key, and deliberately a different
    token: §4.2 orders the map-key rule against the type checks and leaves
    this one unordered.  `recipients` is §4.2's explicit exception and never
    reaches here.
    """

    token = "repeated_array_value"


def token_for(exc: BaseException) -> str | None:
    """The rule token this rejection carries, or `None` if it carries none.

    Reads the attribute off any exception rather than off a base class, so
    `scanner.NonCanonicalItem`, `scanner.DuplicateMapKey` and
    `cursor.ParseError` participate without being reparented.

    `None` is a real answer and the caller must treat it as a HARNESS
    FAILURE, not as "no divergence" — the default-deny posture
    `conformance_lib.rejection` already takes.  A silently untokened
    rejection would restore exactly the blindness #634 exists to remove.
    """
    token = getattr(exc, "token", None)
    return token if isinstance(token, str) and token else None
```

- [ ] **Step 2: Write the failing test — a section stub that will fail until Task 5**

Skip: this task's verification is behavioural (Step 5), because the section that asserts totality is Task 5's deliverable. Proceed to Step 3.

- [ ] **Step 3: Convert the 14 raise sites in `manifest_decode.py`**

Add to that file's imports:

```python
from conformance_lib.codec.manifest_rules import (
    IntegerOutOfRange,
    MissingRequiredField,
    NonTextMapKey,
    RepeatedArrayValue,
    TrailingBytesAfterMap,
    UnsupportedVersion,
    WrongFieldType,
)
```

Then change **only the exception class** at each site, leaving every message byte-identical:

| line (approx) | from | to |
|---|---|---|
| 151 | `ValueError(f"trailing bytes after manifest map: ...")` | `TrailingBytesAfterMap(...)` |
| 160 | `ValueError(f"manifest map key at offset {ks} is not a text string")` | `NonTextMapKey(...)` |
| 203 | `ValueError(f"manifest missing required field: {absent!r}")` | `MissingRequiredField(...)` |
| 282 | `ValueError(f"{field} must be a uint, got ...")` | `WrongFieldType(...)` |
| 284 | `ValueError(f"{field} is out of range for u{bits}: {value}")` | `IntegerOutOfRange(...)` |
| 293 | `ValueError(f"{field} must be a bstr, got ...")` | `WrongFieldType(...)` |
| 295 | `ValueError(f"{field} must be {n} bytes, got {len(value)}")` | `WrongFieldType(...)` |
| 317 | `ValueError(f"unsupported manifest_version: ...")` | `UnsupportedVersion(...)` |
| 320 | `ValueError(f"unsupported format_version: ...")` | `UnsupportedVersion(...)` |
| 323 | `ValueError(f"unsupported suite_id: ...")` | `UnsupportedVersion(...)` |
| 340 | `ValueError(f"blocks[{i}].block_name must be tstr")` | `WrongFieldType(...)` |
| 348 | `ValueError(f"blocks[{i}].recipients must be an array")` | `WrongFieldType(...)` |
| 405 | `ValueError(f"{label} has a repeated {key}: {repeat.hex()}")` | `RepeatedArrayValue(...)` |

Line 237 and 402 already raise `ArraySortOrderViolation`; line 265 already raises `NonCanonicalBody`; line 163 already raises `DuplicateMapKey`. Those four get tokens in Step 4 instead.

**Do not touch the message strings.** Confirm with `git diff` that every changed line differs only in the class name.

- [ ] **Step 4: Add `token` to the four existing typed classes**

In `core/tests/python/conformance_lib/codec/scanner.py`, add a class attribute to each, with a docstring line explaining it:

```python
class NonCanonicalItem(ValueError):
    ...
    # The §4.2-table rule number is per-instance, so the token is derived
    # per-instance too — the only class here that needs a property rather
    # than a class attribute.  Rules 2, 3 and 4 are the only numbers this
    # type is ever constructed with from the manifest path.
    @property
    def token(self) -> str:
        return {
            2: "rule2_indefinite_length",
            3: "rule3_non_shortest_form",
            4: "rule4_tag_or_float",
        }.get(self._rule, "")


class DuplicateMapKey(ValueError):
    ...
    token = "duplicate_map_key"
```

In `core/tests/python/conformance_lib/codec/manifest_decode.py`, on the two classes defined there:

```python
class ArraySortOrderViolation(ValueError):
    ...
    token = "array_sort_order"


class NonCanonicalBody(ValueError):
    ...
    token = "non_canonical_unclassified"
```

In `core/tests/python/conformance_lib/cursor.py`, on `ParseError`:

```python
class ParseError(ValueError):
    ...
    # One token for the whole wire layer.  This class is shared by EVERY
    # target's envelope parser, and every rejection it produces is "the
    # envelope did not parse".  Refining it is what #640 is about, and is
    # the reason `manifest_file` is not token-compared.
    token = "container_malformed"
```

Confirm `ArraySortOrderViolation` and `NonCanonicalBody` are defined in `manifest_decode.py` rather than `scanner.py` before editing:

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
grep -rn "^class ArraySortOrderViolation\|^class NonCanonicalBody\|^class ParseError" core/tests/python/conformance_lib/
```

- [ ] **Step 5: Verify no message moved and the whole suite is green**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git diff -U0 core/tests/python/conformance_lib/codec/manifest_decode.py | grep -E "^[+-]" | grep -v "^[+-][+-]" | grep -c "raise"
uv run core/tests/python/conformance.py > /tmp/conf4.txt 2>&1; echo "EXIT: $?"
grep -c "^FAIL" /tmp/conf4.txt
grep "section registry" /tmp/conf4.txt
```

Expected: EXIT 0, `0` FAIL lines, registry still `28 drivers, 28 registered`. If any section fails, a message moved — compare `git diff` on the raise lines and restore the exact text.

- [ ] **Step 6: Verify every manifest-body rejection now carries a token**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
for f in core/fuzz/seeds/manifest_body/*; do
  uv run core/tests/python/conformance.py --diff-replay manifest_body "$f" 2>/dev/null \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["status"], d.get("error_class",""))'
done | sort | uniq -c
```

Expected: `accept` rows plus reject rows whose `error_class` is now one of the typed names — **no bare `ValueError`**. A remaining `ValueError` means a raise site was missed.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add core/tests/python/conformance_lib/
git commit -m "$(cat <<'EOF'
conformance: give every manifest-body rejection a typed class and rule token (#634)

Fourteen bare ValueError raise sites become typed subclasses; the four already-
typed classes plus cursor.ParseError gain a token attribute. Message-preserving
throughout — Section MUQ names a repeated id and Section MSH does a substring
test, so a reworded message is a silently broken section.

A class attribute rather than a lookup table: a table maps class to token in a
second place, so a new subclass silently gets no token. token_for reads the
attribute off ANY exception, so ParseError participates without being
reparented under a manifest-specific base — it is shared by every target's
wire decoder.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 5: Section RTV — the vocabulary agreement pin

**Files:**
- Create: `core/tests/python/conformance_lib/sections/rule_token_vocabulary.py`
- Modify: `core/tests/python/conformance_lib/sections/registry.py`

**Interfaces:**
- Consumes: `manifest_rules.token_for`, the exception classes from Task 4, and `core/tests/data/rule_token_vocabulary.json` from Task 2.
- Produces: `section_rule_token_vocabulary() -> tuple[bool, list[str]]`, registered as Section `RTV`. Takes REG from 28 to 29.

- [ ] **Step 1: Write the section**

Create `core/tests/python/conformance_lib/sections/rule_token_vocabulary.py`:

```python
"""Section RTV -- the rule-token vocabulary agrees with Rust's, and every
manifest-body rejection this reader can produce carries one (#634).

WHAT THIS PINS, AND WHAT IT DOES NOT.  It pins the SPELLINGS and the
phase-dependence flags against the same JSON fixture
`core/src/vault/manifest/token/tests.rs` checks, so the two languages cannot
drift onto different words -- a drift that would make every cross-language
comparison a mismatch, or worse, a tolerated one.  It does NOT check that the
two implementations assign the same token to the same bytes; that is
`differential_replay.rs`'s job, and it runs only under the
`differential-replay` Cargo feature.

WHY A COVERAGE FLOOR.  Checks 1 and 2 alone pass on a reader that raises
tokened exceptions nowhere: a vocabulary agreeing with a vocabulary is
vacuous.  Check 3 drives the real decoder over the committed corpus and
requires every rejection to carry a token, which is what makes the pin
non-vacuous.
"""

from __future__ import annotations

import json

from conformance_lib import fixtures
from conformance_lib.codec import manifest_rules
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

# Every exception class reachable from `py_decode_manifest` that means "this
# body is non-conformant".  Declared here rather than discovered, so a class
# added without a token is a FAILURE and not an absence.
_TOKENED_CLASSES = (
    manifest_rules.TrailingBytesAfterMap,
    manifest_rules.NonTextMapKey,
    manifest_rules.MissingRequiredField,
    manifest_rules.WrongFieldType,
    manifest_rules.IntegerOutOfRange,
    manifest_rules.UnsupportedVersion,
    manifest_rules.RepeatedArrayValue,
)


def _vocabulary() -> dict:
    path = fixtures.test_data_dir() / "rule_token_vocabulary.json"
    return json.loads(path.read_text())["tokens"]


def _corpus_bodies() -> list:
    seeds = fixtures.test_data_dir().parents[1] / "fuzz" / "seeds" / "manifest_body"
    return sorted(p for p in seeds.iterdir() if p.is_file() and p.name != ".gitkeep")


def section_rule_token_vocabulary() -> tuple[bool, list[str]]:
    lines: list[str] = []
    issues: list[str] = []
    vocab = _vocabulary()

    # --- check 1: every class token is a real token -----------------------
    for cls in _TOKENED_CLASSES:
        token = getattr(cls, "token", None)
        if not token:
            issues.append(f"{cls.__name__} carries no token")
        elif token not in vocab:
            issues.append(f"{cls.__name__} carries {token!r}, absent from the shared vocabulary")
    lines.append(f"PASS 1: {len(_TOKENED_CLASSES)} declared classes carry vocabulary tokens")

    # --- check 2: the phase-dependent set is the spec's -------------------
    # Hard-coded rather than read from the fixture, so an edit to the fixture
    # alone cannot redefine what this reader believes vault-format §4.2 says.
    # The Rust side pins the same set against its own enum; the fixture is
    # what makes the two comparable.
    want_phase_dependent = {
        "array_sort_order",
        "non_canonical_unclassified",
        "rule2_indefinite_length",
        "rule3_non_shortest_form",
    }
    got_phase_dependent = {k for k, v in vocab.items() if v.get("phase_dependent")}
    if got_phase_dependent != want_phase_dependent:
        issues.append(
            "phase-dependent set disagrees with vault-format §4.2: "
            f"fixture has {sorted(got_phase_dependent)}, §4.2 says {sorted(want_phase_dependent)}"
        )
    lines.append(f"PASS 2: {len(want_phase_dependent)} phase-dependent tokens match §4.2")

    # --- check 3: the coverage floor --------------------------------------
    bodies = _corpus_bodies()
    if len(bodies) < 20:
        issues.append(
            f"corpus floor: only {len(bodies)} manifest_body seeds found; "
            "a shrunken corpus makes checks 1 and 2 vacuous"
        )
    rejected = 0
    untokened = 0
    seen_tokens: set[str] = set()
    for path in bodies:
        try:
            py_decode_manifest(path.read_bytes())
        except _REJECTION_EXCEPTIONS as exc:
            rejected += 1
            token = manifest_rules.token_for(exc)
            if token is None:
                untokened += 1
                issues.append(
                    f"{path.name}: rejected by {type(exc).__name__} carrying no rule token"
                )
            elif token not in vocab:
                issues.append(f"{path.name}: token {token!r} absent from the shared vocabulary")
            else:
                seen_tokens.add(token)
    if rejected == 0:
        issues.append("coverage floor: no corpus body was rejected at all")
    lines.append(
        f"PASS 3: {rejected}/{len(bodies)} bodies rejected, "
        f"{rejected - untokened} carrying a vocabulary token, "
        f"{len(seen_tokens)} distinct tokens observed"
    )

    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
```

- [ ] **Step 2: Run it standalone to verify it fails first**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/conformance.py 2>&1 | grep -c "Section RTV"
```

Expected: `0` — the section exists but is not registered, so nothing runs it. This is the exact failure mode Section REG exists to catch; the next step is what makes REG red.

- [ ] **Step 3: Verify Section REG catches the unregistered driver**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/conformance.py 2>&1 | grep -A 5 "Section REG"; echo "EXIT was: $?"
uv run core/tests/python/conformance.py > /dev/null 2>&1; echo "EXIT: $?"
```

Expected: non-zero exit, and REG reporting a discovered-but-unregistered driver. If REG passes, the section's function name does not match REG's shape discovery — check `core/tests/python/conformance_lib/sections/completeness.py` for the expected `section*` prefix.

- [ ] **Step 4: Register it**

In `core/tests/python/conformance_lib/sections/registry.py`, add the import beside the other `manifest_*` imports (alphabetical):

```python
from conformance_lib.sections.rule_token_vocabulary import (
    section_rule_token_vocabulary,
)
```

and the table row immediately after the `MPR` row and before the `RC` row:

```python
    Section("RTV", "rule-token vocabulary agreement, both languages",
            " (#634)", section_rule_token_vocabulary),
```

- [ ] **Step 5: Run and verify**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/conformance.py > /tmp/conf5.txt 2>&1; echo "EXIT: $?"
grep -c "^FAIL" /tmp/conf5.txt
grep -A 4 "Section RTV" /tmp/conf5.txt
grep "section registry" /tmp/conf5.txt
```

Expected: EXIT 0, `0` FAIL lines, RTV printing three PASS lines, registry `29 drivers, 29 registered`.

- [ ] **Step 6: Prove check 3 is not vacuous**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cp core/tests/python/conformance_lib/codec/manifest_decode.py /tmp/md.bak
find core/tests/python -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null
python3 - <<'EOF'
import pathlib
p = pathlib.Path("core/tests/python/conformance_lib/codec/manifest_decode.py")
s = p.read_text()
s = s.replace("class ArraySortOrderViolation(ValueError):", "class ArraySortOrderViolation(ValueError):\n    token = ''  # PROBE", 1)
p.write_text(s)
EOF
find core/tests/python -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null
PYTHONDONTWRITEBYTECODE=1 uv run core/tests/python/conformance.py 2>&1 | grep -E "Section RTV|ISSUE|^FAIL"
cp /tmp/md.bak core/tests/python/conformance_lib/codec/manifest_decode.py
find core/tests/python -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null
shasum -a 256 core/tests/python/conformance_lib/codec/manifest_decode.py /tmp/md.bak
PYTHONDONTWRITEBYTECODE=1 uv run core/tests/python/conformance.py > /dev/null 2>&1; echo "restored EXIT: $?"
```

Expected: the mutated run reports RTV issues naming the seven `arraysort__*` seeds; sha256 sums match after restore; the restored run exits 0. **Both `__pycache__` clears and `PYTHONDONTWRITEBYTECODE` are mandatory** — this mutation changes the file size, but the discipline is uniform so it cannot be skipped by judgement per mutation.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add core/tests/python/conformance_lib/sections/
git commit -m "$(cat <<'EOF'
conformance: Section RTV pins the rule-token vocabulary against Rust's (#634)

Three checks. The first two compare spellings and phase-dependence flags
against the same JSON fixture core/src/vault/manifest/token/tests.rs reads, so
the two languages cannot drift onto different words. The third is the coverage
floor that stops the first two being a vocabulary agreeing with a vocabulary:
it drives py_decode_manifest over the committed corpus and requires every
rejection to carry a token.

The phase-dependent set is hard-coded in the section rather than read from the
fixture, so editing the fixture alone cannot redefine what this reader believes
vault-format §4.2 says.

REG 28 -> 29.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 6: Emit `rule` on the diff-replay reject shape

**Files:**
- Modify: `core/tests/python/conformance_lib/diff_replay.py` (the `except _REJECTION_EXCEPTIONS` arm, around line 134)
- Modify: `docs/manual/contributors/differential-replay-protocol.md`

**Interfaces:**
- Consumes: `manifest_rules.token_for` (Task 4).
- Produces: the reject JSON gains `"rule": "<token>"` or `"rule": null`. Consumed by Task 7.

- [ ] **Step 1: Write the failing check**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/conformance.py --diff-replay manifest_body core/fuzz/seeds/manifest_body/arraysort__blocks.bin \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); print("rule field:", d.get("rule", "<ABSENT>"))'
```

Expected: `rule field: <ABSENT>`.

- [ ] **Step 2: Emit the field**

In `core/tests/python/conformance_lib/diff_replay.py`, add the import at the top:

```python
from conformance_lib.codec.manifest_rules import token_for
```

and change the reject arm from:

```python
    except _REJECTION_EXCEPTIONS as e:
        print(json.dumps({
            "status": "reject",
            "error_class": type(e).__name__,
            "detail": str(e),
        }))
        return 0
```

to:

```python
    except _REJECTION_EXCEPTIONS as e:
        # `rule` is the language-neutral token `differential_replay.rs`
        # compares (#634).  `None` when this rejection carries none, which
        # the Rust side treats as a HARNESS FAILURE for a token-compared
        # target rather than as agreement -- default-deny, the same posture
        # `_REJECTION_EXCEPTIONS` itself takes.  `error_class` and `detail`
        # are unchanged, so nothing that reads them moves.
        print(json.dumps({
            "status": "reject",
            "error_class": type(e).__name__,
            "detail": str(e),
            "rule": token_for(e),
        }))
        return 0
```

Match the surrounding code's exact formatting — read the arm before editing, since the dict may be laid out differently.

- [ ] **Step 3: Verify the field appears**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
for s in arraysort__blocks top__rule4_float keyorder__top uniq__trash__duplicate_block_uuid; do
  printf "%-40s " "$s"
  uv run core/tests/python/conformance.py --diff-replay manifest_body core/fuzz/seeds/manifest_body/$s.bin \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("rule"))'
done
```

Expected, in order: `array_sort_order`, `rule4_tag_or_float`, `non_canonical_unclassified`, `repeated_array_value`.

- [ ] **Step 4: Update the protocol document**

In `docs/manual/contributors/differential-replay-protocol.md`:

1. In "What 'differential replay' is", the numbered list of what the two agree on gains a third item:

```
3. **Which rule each names when both reject** — for targets listed in
   `differential_replay.rs::TOKEN_COMPARED_TARGETS`. See §3 below.
```

2. Replace the whole "### 3. Reject" section body with:

```
```json
{"status": "reject", "error_class": "<class name>", "detail": "<message>", "rule": "<token>"}
```

- `error_class` is `type(e).__name__` and `detail` is `str(e)`. Both are
  informational and neither is compared.
- **`rule` is compared** (#634), for the targets in
  `differential_replay.rs::TOKEN_COMPARED_TARGETS` — today `manifest_body`
  and nothing else. It is one of the tokens in
  `core/tests/data/rule_token_vocabulary.json`, which the Rust enum
  `secretary_core::vault::manifest::RuleToken` and Section RTV both check
  themselves against, so the two languages cannot drift onto different
  spellings.
- `rule` is `null` when the rejection carries no token. For a
  token-compared target that is a **harness failure**, not agreement —
  default-deny, so a new untokened rejection fails loudly rather than
  silently restoring the blindness this field removed.
- A token mismatch is a disagreement **unless either token is
  phase-dependent**, in which case `docs/vault-format.md` §4.2 declares the
  order unspecified and both readers are conformant. The predicate lives on
  `RuleToken::is_phase_dependent`; it IS that sentence, not a list of
  tolerated pairs.
- **`manifest_file` is deliberately NOT token-compared** (#640): Rust's
  header raises `UnsupportedFormatVersion` where Python raises the same
  `ParseError` it raises for every envelope fault, and no mapping reconciles
  that. The other five targets are #641.
```

3. Two stale facts in that document, corrected while it is open:
   - "The fuzz harness drives six Rust decoders" and the `TARGET` list omit `manifest_body`. `TARGETS` holds **seven**: `vault_toml`, `record`, `contact_card`, `bundle_file`, `manifest_file`, `manifest_body`, `block_file`. Verify with `grep -n "const TARGETS" -A 9 core/tests/differential_replay.rs` before writing the number.
   - The four-way agreement matrix's `Reject | Reject` cell reads "Agreement, even with different error classes." Change it to "Agreement on the verdict. For a token-compared target the `rule` tokens must also agree, or one must be phase-dependent — see §3."

- [ ] **Step 5: Verify the suite is still green**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/conformance.py > /tmp/conf6.txt 2>&1; echo "EXIT: $?"
grep -c "^FAIL" /tmp/conf6.txt
```

Expected: EXIT 0, `0` FAIL lines.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add core/tests/python/conformance_lib/diff_replay.py docs/manual/contributors/differential-replay-protocol.md
git commit -m "$(cat <<'EOF'
conformance: the diff-replay reject shape carries a rule token (#634)

error_class and detail are unchanged, so nothing that reads them moves. `rule`
is null when a rejection carries no token, which the Rust side treats as a
harness failure for a token-compared target rather than as agreement.

The protocol doc is updated in the same commit, per its own "extend both sides
in lockstep" rule, and two stale facts in it are corrected: it said six targets
and omitted manifest_body, and its agreement matrix said reject-vs-reject is
agreement "even with different error classes".

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 7: Compare the tokens in `differential_replay.rs`

**Files:**
- Modify: `core/tests/differential_replay.rs`

**Interfaces:**
- Consumes: `RuleToken` and `ManifestError::rule_token()` (Tasks 2, 3); the `rule` JSON field (Task 6).
- Produces: the enforced comparison. Task 8 adds its corpus witness.

- [ ] **Step 1: Write the failing tests**

Append to `core/tests/differential_replay.rs`:

```rust
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
        assert!(TARGETS.contains(target), "{:?} is compared but not a target", target);
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
}

/// The tolerance is derived from vault-format §4.2, so it must tolerate
/// exactly the pairs §4.2 leaves free and nothing else. This is the NEGATIVE
/// control the corpus cannot provide: no committed input makes two ORDERED
/// tokens disagree, so without this test an always-true tolerance would pass.
#[test]
fn tolerance_admits_only_phase_dependent_pairs() {
    use secretary_core::vault::manifest::RuleToken;

    // Identical tokens always agree, phase-dependent or not.
    for t in RuleToken::ALL {
        assert!(tokens_agree(t.as_str(), t.as_str()), "{:?} vs itself", t.as_str());
    }

    // #621's pair: one phase-dependent, one not -> tolerated.
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
}

/// An unknown token is a harness failure, never a tolerated mismatch. A typo
/// on either side must fail loudly rather than degrade to "something differs,
/// probably fine".
#[test]
fn an_unknown_token_is_never_tolerated() {
    assert!(!tokens_agree("array_sort_order", "not_a_real_token"));
    assert!(!tokens_agree("not_a_real_token", "not_a_real_token_either"));
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo test --release -p secretary-core --features differential-replay --test differential_replay 2>&1 | tail -15
```

Expected: compile errors for `TOKEN_COMPARED_TARGETS`, `NOT_TOKEN_COMPARED_TARGETS` and `tokens_agree`.

- [ ] **Step 3: Add the classification table and the tolerance**

Immediately after the `TARGETS` constant in `core/tests/differential_replay.rs`:

```rust
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

/// Do two rule tokens count as agreement?
///
/// Equal tokens always do. Unequal tokens do **only** when at least one is
/// phase-dependent, which is `docs/vault-format.md` §4.2's "deliberately
/// unspecified" sentence: those rules are detected at different points by the
/// two reader designs §4.2 admits, so ordering them would outlaw one design.
///
/// Deliberately NOT a list of tolerated pairs. A pair list would have to be
/// re-derived every time a token is added and would drift from §4.2 silently;
/// this predicate cannot, because it IS the sentence.
///
/// An unrecognised token on either side is never agreement — default-deny, so
/// a typo fails loudly instead of degrading to "something differs".
fn tokens_agree(rust: &str, python: &str) -> bool {
    use secretary_core::vault::manifest::RuleToken;
    let lookup = |s: &str| RuleToken::ALL.iter().find(|t| t.as_str() == s).copied();
    let (Some(r), Some(p)) = (lookup(rust), lookup(python)) else {
        return false;
    };
    r == p || r.is_phase_dependent() || p.is_phase_dependent()
}
```

- [ ] **Step 4: Carry the tokens through `rust_decode` and `python_decode`**

`rust_decode` currently returns `Result<SecretBytes, String>`. Change its error type to carry the token alongside the message:

```rust
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
```

In `rust_decode`, replace each arm's `.map_err(|e| format!("{:?}", e))` with a helper. For the two manifest arms:

```rust
        "manifest_file" => vault::manifest::decode_manifest_file(bytes)
            .and_then(|f| vault::manifest::encode_manifest_file(&f))
            .map(SecretBytes::new)
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
        "manifest_body" => vault::manifest::decode_manifest(bytes)
            .and_then(|m| vault::manifest::encode_manifest(&m))
            .map_err(|e| RustRejection {
                token: Some(e.rule_token().as_str()),
                detail: format!("{:?}", e),
            }),
```

and for every other arm:

```rust
            .map_err(|e| RustRejection { token: None, detail: format!("{:?}", e) })
```

Add the `rule` field to `PyOutcome::Reject`:

```rust
    /// The Python decoder deliberately rejected the input. A verdict.
    ///
    /// `rule` is the token the reject shape now carries (#634); `None` when
    /// that rejection carries none.
    Reject { rule: Option<String>, detail: String },
```

and in `python_decode`'s `Some("reject")` arm:

```rust
        Some("reject") => PyOutcome::Reject {
            rule: json["rule"].as_str().map(str::to_owned),
            detail: format!(
                "{}: {}",
                json["error_class"].as_str().unwrap_or("unknown"),
                json["detail"].as_str().unwrap_or("")
            ),
        },
```

- [ ] **Step 5: Replace the agreement arm**

In `differential_replay_full_corpus`, replace:

```rust
                    // Both reject → agreement (don't compare error classes for now;
                    // can tighten later if we standardize them).
                    (Err(_), PyOutcome::Reject(_)) => true,
```

with:

```rust
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
```

The `disagreements.push(...)` block below reads `rust` and `python`; update its match arms to the new shapes (`Err(e) => format!("Err({})", e.detail)` and `PyOutcome::Reject { rule, detail } => format!("Rejected({:?}) {}", rule, detail)`), and include both tokens in the message so a failure names the divergence rather than only the inputs.

Add a missing-token guard immediately before the `ok` match, so a `None` is reported as a harness failure with a clear remedy rather than as an ordinary disagreement:

```rust
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
```

- [ ] **Step 6: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo test --release -p secretary-core --features differential-replay --test differential_replay 2>&1 | tail -20
```

Expected: `4 passed` (the three new unit tests plus `differential_replay_full_corpus`), **0 failed**. If `differential_replay_full_corpus` fails, read the disagreement lines: each is either a mapping bug in Task 3 or Task 4, or a genuine cross-language finding. **Do not allowlist any of them.** Resolve each explicitly and record which it was.

- [ ] **Step 7: Clippy and the whole workspace**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo test --release --workspace > /tmp/suite7.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite7.txt | awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'
```

Expected: clippy clean, `CARGO EXIT: 0`, and `f` (failures) `0`. Judge by the exit code, not by grep output — a `cargo test | grep` pipeline reports grep's status.

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add core/tests/differential_replay.rs
git commit -m "$(cat <<'EOF'
test: differential replay compares WHICH rule each decoder named (#634)

The reject-vs-reject arm was `true` unconditionally, with a comment saying the
comparison could be tightened "when we standardize them". That is why #618's
two live divergences and #621's third were invisible to the one harness that
exists for cross-language decoder agreement.

Agreement now requires equal rule tokens, or for vault-format §4.2 to have left
their order free — a predicate derived from that sentence rather than a list of
tolerated pairs, which would drift from the spec silently. An unrecognised or
missing token is a harness failure, never agreement.

Targets are classified in a table that must partition TARGETS exactly, so a new
target cannot default into the loose behaviour — the fail-open shape #595 found
in this file's own corpus discovery.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 8: Commit #621's divergent input as the tolerance's corpus witness

**Files:**
- Create: `core/tests/data/diff_regressions/manifest_body/arraysort_plus_indefinite.bin`
- Create: `core/tests/data/diff_regressions/README.md` (one level UP, not inside `manifest_body/` —
  see the Step 5 correction below: the per-target directory is fed to both decoders as
  corpus input, so it cannot hold documentation)

**Interfaces:**
- Consumes: the comparison from Task 7.
- Produces: a committed input whose two tokens differ and are tolerated, exercising the tolerance on every run.

- [ ] **Step 1: Confirm the directory exists and is empty**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
ls -la core/tests/data/diff_regressions/manifest_body/
```

Expected: a `.gitkeep` and nothing else. `corpus_dirs` already includes this directory for every target, so no Rust change is needed.

- [ ] **Step 2: Build the input**

#621 constructs it by splicing the `rule2_indefinite_map` subtree over the `arraysort__vector_clock` body's placeholder. Both seeds derive from one baseline, which is why both report offset 929. Build it with `cbor2`, then verify by measurement rather than by construction:

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run --with cbor2 python3 - <<'EOF'
import pathlib
seeds = pathlib.Path("core/fuzz/seeds/manifest_body")
sort_body = (seeds / "arraysort__vector_clock.bin").read_bytes()
indef_body = (seeds / "top__rule2_indefinite_map.bin").read_bytes()

# The indefinite-length subtree the rule2 seed splices in is the only
# difference between it and the canonical control. Find that difference and
# transplant it onto the out-of-sort-order body.
ctrl = (seeds / "top__control_canonical.bin").read_bytes()
lo = 0
while lo < min(len(ctrl), len(indef_body)) and ctrl[lo] == indef_body[lo]:
    lo += 1
hi_c, hi_i = len(ctrl), len(indef_body)
while hi_c > lo and hi_i > lo and ctrl[hi_c - 1] == indef_body[hi_i - 1]:
    hi_c -= 1
    hi_i -= 1
print(f"control differs from rule2 seed over [{lo}, {hi_c}) -> [{lo}, {hi_i})")

# The same window in the arraysort body (identical baseline, so the prefix
# through `lo` matches there too -- assert it rather than assume it).
assert sort_body[:lo] == ctrl[:lo], "seeds do not share the baseline prefix"
spliced = sort_body[:lo] + indef_body[lo:hi_i] + sort_body[hi_c:]
out = pathlib.Path("core/tests/data/diff_regressions/manifest_body/arraysort_plus_indefinite.bin")
out.write_bytes(spliced)
print("wrote", out, len(spliced), "bytes")
EOF
```

If the assertion fails, the two seeds do not share a prefix and the splice must be rebuilt through a full `cbor2` decode/re-encode of the manifest map instead. Report that rather than forcing the bytes.

- [ ] **Step 3: Verify the input actually diverges**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
uv run core/tests/python/conformance.py --diff-replay manifest_body \
  core/tests/data/diff_regressions/manifest_body/arraysort_plus_indefinite.bin
```

Expected: `"status": "reject"` with `"rule": "rule2_indefinite_length"`.

Then confirm Rust names the other rule, by running the differential test and reading its own report — it iterates this directory automatically:

```bash
cargo test --release -p secretary-core --features differential-replay --test differential_replay 2>&1 | tail -12
```

Expected: **PASS**. If it fails, the splice did not produce a two-rule body, or the tolerance is wrong; read the disagreement line, which names both tokens.

- [ ] **Step 4: Prove the input is the tolerance's witness**

Temporarily make the tolerance strict and confirm this input — and only this input — reds:

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
cp core/tests/differential_replay.rs /tmp/dr.bak
python3 - <<'EOF'
import pathlib
p = pathlib.Path("core/tests/differential_replay.rs")
s = p.read_text()
s = s.replace("    r == p || r.is_phase_dependent() || p.is_phase_dependent()", "    r == p", 1)
p.write_text(s)
EOF
cargo test --release -p secretary-core --features differential-replay --test differential_replay 2>&1 | grep -E "arraysort_plus_indefinite|test result|disagree" | head
cp /tmp/dr.bak core/tests/differential_replay.rs
shasum -a 256 core/tests/differential_replay.rs /tmp/dr.bak
cargo test --release -p secretary-core --features differential-replay --test differential_replay 2>&1 | grep "test result"
```

Expected: the strict run fails, naming `arraysort_plus_indefinite.bin` (and `tolerance_admits_only_phase_dependent_pairs`); sha256 sums match after restore; the restored run passes.

- [ ] **Step 5: Write the directory README**

**Correction (found during execution, #634):** the location below is
unexecutable as written. `differential_replay_full_corpus`'s per-target walk
feeds every file in `diff_regressions/<target>/` to both decoders as raw
input bytes, skipping only `.gitkeep` — no extension filter exists. A
`README.md` committed inside `manifest_body/` was decoded as manifest-body
bytes by both languages; Python's rejection carried no rule token, which the
harness (correctly) reports as a failure rather than as this fixture's
intended disagreement. The content below was written one level UP instead,
at `core/tests/data/diff_regressions/README.md`, which `corpus_dirs`
(`core/tests/differential_replay_helpers/corpus.rs:23`) never joins onto any
target and `fs::read_dir`'s per-target walk never reaches. Every other
`diff_regressions/<target>/` directory holds only `.gitkeep` for the same
reason. Read on for the content that was written there instead:

The content originally planned for that (unexecutable) per-target location was relocated to the parent-level README per the correction above; its intent follows:

```markdown
# `manifest_body` differential regressions

Inputs committed here replay through `core/tests/differential_replay.rs` on
every run under the `differential-replay` feature. `corpus_dirs` picks up
everything in this directory, so a file added here needs no code change.

## `arraysort_plus_indefinite.bin` (#621)

A manifest body that is BOTH out of array sort order and carries an
indefinite-length item — spliced from `arraysort__vector_clock` and
`top__rule2_indefinite_map`, which share a baseline.

```
Rust    -> NonCanonicalEncoding { cause: ArraySortOrder }  -> array_sort_order
Python  -> NonCanonicalItem rule=2                          -> rule2_indefinite_length
```

Both reject, both are conformant, and the tokens differ. It is here as the
**positive control for the tolerance rule** (#634): `docs/vault-format.md`
§4.2 declares the order of the array sort disciplines against §6.2 rules 1-3
unspecified, because the two reader designs §4.2 admits detect them at
different points. `tokens_agree` therefore accepts this pair, and deleting
that tolerance reds this input.

Do NOT "fix" the divergence by making one implementation report the other's
rule. Doing so would require one architecture to detect a rule at a point its
design cannot reach, which is what §4.2's paragraph exists to prevent.
```

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add core/tests/data/diff_regressions/manifest_body/
git commit -m "$(cat <<'EOF'
test: commit #621's divergent body as the tolerance's corpus witness (#634)

A manifest body that is both out of array sort order and carries an
indefinite-length item. Rust names array_sort_order, Python names §6.2 rule 2,
both conformant — the exact pair vault-format §4.2 now declares unordered.

Every corpus row until now broke exactly one rule, so the tolerance had no
witness among real bytes and the comparison would have passed vacuously.
Deleting the tolerance reds this input.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task 9: Full mutation proof, documentation, and gate sweep

**Files:**
- Modify: `CLAUDE.md` (the differential-replay paragraph in "Spec is normative", and the manifest section)
- Modify: `ROADMAP.md`
- Create: the handoff at `docs/handoffs/2026-09-10-rule-token-agreement-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget the symlink)

**Interfaces:**
- Consumes: everything above.
- Produces: the shipped slice.

- [ ] **Step 1: Run the full mutation set**

Each mutation: apply, run, restore, **sha256-verify the restore**, re-run to confirm green. Clear `__pycache__` and set `PYTHONDONTWRITEBYTECODE=1` for every Python mutation without exception.

| # | Mutation | Expected |
|---|---|---|
| M1 | `tokens_agree` returns `r == p` (strict) | RED — `arraysort_plus_indefinite.bin` + `tolerance_admits_only_phase_dependent_pairs` |
| M2 | `tokens_agree` returns `true` | RED — `tolerance_admits_only_phase_dependent_pairs` |
| M3 | `TOKEN_COMPARED_TARGETS` becomes `&[]` | RED — `every_target_is_classified` |
| M4 | Add `"manifest_file"` to `TOKEN_COMPARED_TARGETS` without removing it from the other list | RED — `every_target_is_classified` (both-lists check) |
| M5 | `RuleToken::ArraySortOrder.as_str()` returns `"rule2_indefinite_length"` | RED — `token_strings_are_distinct` |
| M6 | `is_phase_dependent` returns `true` for `Rule4TagOrFloat` | RED — `phase_dependent_set_matches_the_spec`, `rule4_is_ordered_not_phase_dependent` |
| M7 | Rust maps `NonCanonicalCause::ArraySortOrder` to `Rule2IndefiniteLength` | RED — `each_non_canonical_cause_has_its_own_token`, `a_real_rejection_carries_the_expected_token` |
| M8 | Python `ArraySortOrderViolation.token = "rule2_indefinite_length"` | Check carefully: BOTH tokens become phase-dependent so the differential test still passes. Section RTV also passes (the token is in the vocabulary). **If nothing reds, that is a finding** — record it in the handoff as a residual, since a phase-dependent token can be swapped for another phase-dependent one undetected. |
| M9 | Python `RepeatedArrayValue.token = "duplicate_map_key"` | RED — differential replay, on the four `uniq__*` seeds (both ordered) |
| M10 | Delete the `token` attribute from `manifest_rules.WrongFieldType` | RED — Section RTV check 1 |
| M11 | `diff_replay.py` omits the `rule` field | RED — differential replay harness failures on every rejecting seed |
| M12 | Remove `array_sort_order` from the vocabulary fixture | RED — `vocabulary_fixture_matches_the_enum` + Section RTV |
| M13 | Delete `manifest_decode.py`'s trailing-bytes raise | Confirm what still reds; record honestly |

Write the harness to `$SCRATCH/mutate.py` (the session scratchpad, never the source tree — probe residue in a live tree races parallel sessions, which is #516).

- [ ] **Step 2: Run the complete gate set**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
pwd && git branch --show-current
cargo fmt --all --check; echo "FMT: $?"
cargo build --release --workspace; echo "BUILD: $?"
cargo test --release --workspace > /tmp/suite.txt 2>&1; echo "CARGO EXIT: $?"
grep -E "^test result" /tmp/suite.txt | awk '{p+=$4; f+=$6; i+=$8} END {print NR, p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings; echo "CLIPPY: $?"
touch core/src/lib.rs && RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace; echo "DOC: $?"
cargo test --release --workspace --features differential-replay > /tmp/diff.txt 2>&1; echo "DIFF EXIT: $?"
uv run core/tests/python/conformance.py > /tmp/conf.txt 2>&1; echo "CONF: $?"; grep -c "^FAIL" /tmp/conf.txt; grep "section registry" /tmp/conf.txt
uv run core/tests/python/spec_test_name_freshness.py; echo "FRESH: $?"
```

Then the six hygiene guards, each `--self-test` FIRST, as literal commands (zsh does not word-split an unquoted variable, so a loop reports FAIL on all of them):

```bash
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
```

Then `core/fuzz` under the pinned nightly, **after** the differential run rather than in parallel — they contend for cargo's package-cache lock and a blocked run looks wedged:

```bash
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check; echo "FUZZ: $?"
```

- [ ] **Step 3: Diff the test NAME SET against a measured baseline**

Not against a number in any document. The previous session's baton carried a stale count and reconciling against it wasted a cycle.

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git log --oneline -1 main
# Capture main's names from a clean checkout, NOT from a stash dance --
# the stash stack is shared with parallel sessions.
git archive main | tar -x -C "$(mktemp -d /tmp/basemainXXXX)" && echo "baseline extracted"
```

Build and list both name sets with `cargo test --release --workspace -- --list`, sort them, and `diff`. Expected: **0 removed**, and added names exactly the ones this slice introduced.

- [ ] **Step 4: Verify the format invariants**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git diff origin/main...HEAD --stat -- core/fuzz/seeds/
git diff origin/main...HEAD -- ffi/secretary-ffi-uniffi/src/secretary.udl
git diff origin/main...HEAD --name-status -- core/tests/data/
git diff origin/main...HEAD --stat -- docs/ ':!docs/handoffs/' ':!docs/manual/' ':!docs/superpowers/'
```

Expected: seeds EMPTY (this slice adds no seed — a token's value is its expected RULE, which a crash-only fuzz target cannot read); UDL EMPTY; `core/tests/data/` shows exactly two ADDED files (`rule_token_vocabulary.json`, the diff regression) plus the README, and **zero modified**; normative docs is `vault-format.md` only.

- [ ] **Step 5: Update `CLAUDE.md` and `ROADMAP.md`**

In `CLAUDE.md`, the "Spec is normative" section currently says `differential_replay.rs` "scores reject-vs-reject as agreement without comparing `detail` — tracked as **#634** since #618 closed". Replace that clause with what is now true: the comparison is live for `manifest_body`, tolerates exactly the pairs §4.2 leaves free, and is off for the other six targets (#640, #641). Re-measure the `conformance_lib` file count and the largest-module ranking rather than incrementing them — that paragraph's own text records being wrong three PRs running.

In `ROADMAP.md`, record the slice against #634 and #621.

- [ ] **Step 6: Write the handoff and retarget the symlink**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
ln -snf docs/handoffs/2026-09-10-rule-token-agreement-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

The handoff must carry: what shipped with SHAs; what is next with acceptance criteria; open decisions and risks (including M8's result and the `manifest_file` exclusion); and the exact resume commands. Commit the handoff and the retargeted symlink together.

- [ ] **Step 7: Commit, push, open the PR**

```bash
cd /Users/hherb/src/secretary/.worktrees/rule-token-agreement
git add -A && git commit -m "docs: CLAUDE.md, ROADMAP and the baton for the rule-token slice (#634, #621)

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
git push -u origin feature/rule-token-agreement
gh pr create --title "Compare WHICH rule each decoder reports, and make the remaining divergence normative (#634) (#621)" --body "..."
```

The user merges; do not merge.

---

## Self-Review

**Spec coverage.** §3 → Task 1. §4.1/§4.2 of the vocabulary → Task 2. §4.3's mapping → Tasks 3 and 4. §4.4's trailing-bytes ruling → Task 4's `TrailingBytesAfterMap` docstring. §5.1's classification table → Task 7. §5.2's rule → Task 7's `tokens_agree`. §5.3's protocol change → Task 6. §6.1 witness → Task 8. §6.2 negative control → Task 7's `tolerance_admits_only_phase_dependent_pairs`. §6.3 fixture → Tasks 2 and 5. §6.4 mutation → Task 9. §7's file table → all tasks. §8's non-claims → the handoff in Task 9.

**Placeholder scan.** One deliberate `...` remains, in Task 9's `gh pr create --body`, because the PR body summarises results that do not exist until the gates have run. Every code step carries real code. Task 4 Step 2 is explicitly a no-op with its reason stated rather than a "write tests here".

**Type consistency.** `RuleToken::ALL`, `as_str`, `is_phase_dependent` are defined in Task 2 and used unchanged in Tasks 3, 5 and 7. `ManifestError::rule_token()` is defined in Task 3 and used in Task 7. `token_for` is defined in Task 4 and used in Tasks 5 and 6. `RustRejection { token, detail }` and `PyOutcome::Reject { rule, detail }` are introduced together in Task 7 Step 4 and consumed in Step 5. The seven Python class names in Task 4's module match the imports in Task 4 Step 3 and the `_TOKENED_CLASSES` tuple in Task 5.

**Known risk carried deliberately.** Task 9's M8 may not red. That is recorded as an expected-uncertain outcome with instructions to report it honestly rather than as a mutation the plan assumes will pass — a phase-dependent token swapped for another phase-dependent token is tolerated by construction, which is the tolerance working as designed and is worth stating as a residual.
