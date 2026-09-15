# Token-compare `block_file` and `record` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `differential_replay.rs` compare WHICH rule the Rust and Python decoders name for the `block_file` and `record` targets, with zero tolerated pairs, CI teeth from committed single-fault seeds, and the three ciborium well-formedness leniencies closed on the `record` path.

**Architecture:** The tolerance becomes target-aware (phase-dependence licensed on `manifest_body` only). `RecordError`/`BlockError` gain exhaustive `rule_token()` impls. Python's block-envelope sort/repeat check splits; Python's record decoder is reordered into Rust's phase order behind a new iterative well-formedness walk, and Rust's `record::decode` runs a byte-level twin of that walk before ciborium. A Rust generator plants one fault per seed into committed bases; Rust and Python each bind every seed to its file-name token.

**Tech Stack:** Rust 1.97.0 (stable, pinned), `ciborium =0.2.2`, `proptest`; Python via `uv` with `cbor2`; `scripts/mutate.py` for mutation evidence.

**Spec:** `docs/superpowers/specs/2026-09-15-token-compare-record-block-design.md` — read it first; this plan argues from it.

## Global Constraints

- Work ONLY in `/Users/hherb/src/secretary/.worktrees/token-compare-record-block` on branch `feature/token-compare-record-block`. Before any `cargo`/`git`/`uv` command: `pwd && git branch --show-current`.
- The Edit/Write tools take absolute paths: always spell `/Users/hherb/src/secretary/.worktrees/token-compare-record-block/...`, never `/Users/hherb/src/secretary/...` (that is the MAIN checkout).
- Rust is pinned stable 1.97.0; `#![forbid(unsafe_code)]` is workspace-wide — no `unsafe`.
- `cargo clippy --release --locked --workspace --tests -- -D warnings`, `cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings`, `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` and `cargo fmt --all --check` must stay clean at every commit.
- Python: `uv` only — never `pip`. Run the verifier as `uv run core/tests/python/conformance.py`.
- No new rule tokens: `core/tests/data/rule_token_vocabulary.json` is unchanged.
- No `RecordError`/`BlockError` variant, public signature or FFI mapping changes.
- Every file stays under 500 lines.
- No magic numbers: name every CBOR byte and length as a constant.
- Rust test values that look like key material (fingerprints, uuids) come from `rand_core::OsRng` or from committed base files, never from literal byte arrays (CodeQL).
- Commit per task. Subject ends `(#641)`. Body ends with the line `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`.
- Judge every command by its EXIT CODE, read unpiped (`cmd > "$LOG" 2>&1; echo "exit=$?"`). `$?` after a pipe is the pipe's last command.
- Mutation specs and probe scripts go in the session scratchpad `/private/tmp/claude-501/-Users-hherb-src-secretary/5edf5da6-dc60-434f-a442-bf719640e844/scratchpad`, never the tree.
- The replay's CI-shape command is `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay`. A fresh worktree has no `core/fuzz/corpus/`, so it replays committed inputs only.

## File map

| File | Responsibility | Task |
|---|---|---|
| `core/tests/differential_replay_helpers/{targets,tolerance,agreement,rust_decoder}.rs`, `core/tests/differential_replay.rs` | target-aware tolerance; classification; Rust tokens per target | 1, 5, 10 |
| `core/src/vault/rule_tokens/{mod,record,block}.rs`, `.../tests/{mod,record,block}.rs` | `RecordError::rule_token`, `BlockError::rule_token` + independent mapping tests | 2 |
| `core/src/vault/manifest/token.rs` | `RuleToken` doc wording only | 2 |
| `core/tests/rule_token_seeds.rs`, `core/tests/rule_token_seeds_helpers/{mod,block_file,record}.rs` | seed table, generator, label binding | 3, 9 |
| `core/fuzz/seeds/{block_file,record}/*__*.bin` | generated seeds | 3, 9 |
| `core/tests/python/conformance_lib/wire/{envelope_rules,block_file}.py` | typed envelope rejections, split sort/repeat | 4 |
| `core/tests/python/conformance_lib/sections/rule_token_seeds.py`, `sections/registry.py`, `fixtures.py` | Section RTS | 4, 9 |
| `core/src/cbor/well_formed.rs`, `core/src/cbor/well_formed/tests.rs`, `core/src/cbor/mod.rs`, `core/src/vault/record.rs`, `core/src/vault/record_walk_tests.rs`, `core/src/vault/mod.rs` | Rust byte walk, wiring, acceptance proptest | 6 |
| `core/tests/python/conformance_lib/codec/{cbor_faults,well_formed,scanner}.py`, `sections/well_formed_walk.py`, `sections/rule_token_vocabulary.py` | `MalformedCbor`, Python walk, Section WF | 7 |
| `core/tests/python/conformance_lib/codec/{record_rules,record}.py` | record reorder + typed record rejections | 8 |
| `CLAUDE.md`, `ROADMAP.md`, `docs/manual/contributors/differential-replay-protocol.md`, `core/fuzz/README.md`, `.github/workflows/test.yml` (comment only) | docs | 11 |

---

### Task 1: Target-aware tolerance

**Files:**
- Modify: `core/tests/differential_replay_helpers/targets.rs` (add a constant after `NOT_TOKEN_COMPARED_TARGETS`)
- Modify: `core/tests/differential_replay_helpers/tolerance.rs` (`tokens_agree`)
- Modify: `core/tests/differential_replay_helpers/agreement.rs` (call site; `UNCOMPARED` fixture)
- Modify: `core/tests/differential_replay.rs` (`every_target_is_classified`, `tolerance_admits_only_phase_dependent_pairs`, `an_unknown_token_is_never_tolerated`, imports)

**Interfaces:**
- Produces: `pub const PHASE_DEPENDENT_TOLERANCE_TARGETS: &[&str]` in `targets.rs`; `pub fn tokens_agree(target: &str, rust: &str, python: &str) -> bool` in `tolerance.rs`.

- [ ] **Step 1: Write the failing tests** — in `core/tests/differential_replay.rs`:

Change the `use helpers::targets::{...}` import to add `PHASE_DEPENDENT_TOLERANCE_TARGETS`:

```rust
use helpers::targets::{
    min_inputs, MIN_CORPUS_INPUTS, NOT_TOKEN_COMPARED_TARGETS, PHASE_DEPENDENT_TOLERANCE_TARGETS,
    TARGETS, TOKEN_COMPARED_TARGETS,
};
```

At the end of `every_target_is_classified`, before its closing `}`, add:

```rust
    // The phase-dependent licence is vault-format §4.2's, i.e. one target's
    // spec section, and only a compared target can use it (#641).
    for target in PHASE_DEPENDENT_TOLERANCE_TARGETS {
        assert!(
            TOKEN_COMPARED_TARGETS.contains(target),
            "{target:?} is licensed for the phase-dependent tolerance but is not token-compared"
        );
    }
```

In `tolerance_admits_only_phase_dependent_pairs`, add `const LICENSED: &str = "manifest_body";` as the first statement, and change EVERY `tokens_agree(x, y)` call in that function to `tokens_agree(LICENSED, x, y)`. Then, just before the function's closing `}`, add:

```rust
    // Every other target: no tolerated pair at all. The licence above is
    // §4.2's, the manifest body's; a sequential block-file envelope or a
    // record body inherits none of it (#641).
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
```

In `an_unknown_token_is_never_tolerated`, change both calls to pass `"manifest_body"` as the first argument.

In `core/tests/differential_replay_helpers/agreement.rs`'s `mod tests`, change `const UNCOMPARED: &str = "record";` to `const UNCOMPARED: &str = "contact_card";` (record becomes compared in Task 10; `contact_card` stays uncompared).

- [ ] **Step 2: Run to verify it fails**

Run: `cd /Users/hherb/src/secretary/.worktrees/token-compare-record-block && cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay > "$TMPDIR/t1.log" 2>&1; echo "exit=$?"; grep -E "^error" "$TMPDIR/t1.log" | head`
Expected: exit non-zero; `error[E0432]` (unresolved `PHASE_DEPENDENT_TOLERANCE_TARGETS`) and/or `error[E0061]` (wrong argument count for `tokens_agree`).

- [ ] **Step 3: Implement**

In `targets.rs`, after the `NOT_TOKEN_COMPARED_TARGETS` constant, add:

```rust
/// The compared targets on which a phase-dependent token may stand against a
/// different token and still count as agreement.
///
/// **The licence is a SPEC SECTION's, not a token's.** `RuleToken::is_phase_dependent`
/// is derived from `docs/vault-format.md` §4.2, which admits two manifest-body
/// reader designs that detect §6.2 rules 1-3 and the array sort disciplines at
/// different points. Nothing gives a §6.1 block-file envelope or a §6.3 record
/// body that freedom, so on every other compared target only EQUAL tokens
/// agree (#641). Applied globally, the per-token predicate would have scored
/// `array_sort_order` against `container_malformed` on `block_file` as
/// agreement — hiding exactly the Python sort/repeat split #641 adds.
///
/// Must be a subset of [`TOKEN_COMPARED_TARGETS`]; `every_target_is_classified`
/// checks it.
pub const PHASE_DEPENDENT_TOLERANCE_TARGETS: &[&str] = &["manifest_body"];
```

In `tolerance.rs`, replace the function `tokens_agree` (signature and body; keep its doc comment) with:

```rust
pub fn tokens_agree(target: &str, rust: &str, python: &str) -> bool {
    use secretary_core::vault::manifest::RuleToken;
    let lookup = |s: &str| RuleToken::ALL.iter().find(|t| t.as_str() == s).copied();
    let (Some(r), Some(p)) = (lookup(rust), lookup(python)) else {
        return false;
    };
    if r == p {
        return true;
    }
    PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(&target)
        && (r.is_phase_dependent() || p.is_phase_dependent())
}
```

Add `use super::targets::PHASE_DEPENDENT_TOLERANCE_TARGETS;` below the module doc. Append this paragraph to the end of `tokens_agree`'s doc comment (before the `[`RuleToken::is_phase_dependent`]: ...` link-definition line):

```rust
///
/// **Per target (#641).** The phase-dependent licence applies only on
/// [`PHASE_DEPENDENT_TOLERANCE_TARGETS`]; everywhere else unequal tokens
/// never agree. The 58-of-136 breadth above is `manifest_body`'s; every other
/// target's is 0, and `tolerance_admits_only_phase_dependent_pairs` pins both.
```

In `agreement.rs`'s `judge`, change `(Some(rt), Some(pt)) => tokens_agree(rt, pt),` to `(Some(rt), Some(pt)) => tokens_agree(target, rt, pt),`.

- [ ] **Step 4: Run to verify it passes**

Run: `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay > "$TMPDIR/t1.log" 2>&1; echo "exit=$?"; grep -E "test result" "$TMPDIR/t1.log"`
Expected: exit=0; `test result: ok. 43 passed` (the count is unchanged: no test was added or removed, only extended).

Then: `cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings > "$TMPDIR/c1.log" 2>&1; echo "exit=$?"` → exit=0. `cargo fmt --all --check; echo "exit=$?"` → exit=0.

- [ ] **Step 5: Commit**

```bash
git add core/tests/differential_replay_helpers/targets.rs core/tests/differential_replay_helpers/tolerance.rs core/tests/differential_replay_helpers/agreement.rs core/tests/differential_replay.rs
git commit -F - <<'EOF'
Make the rule-token tolerance per target (#641)

tokens_agree tolerated a mismatch whenever either token was
phase-dependent, on every target. That licence is vault-format §4.2's,
derived from its two manifest-body reader designs; a §6.1 block-file
envelope or a §6.3 record body has none of it. Applied globally it
would have scored array_sort_order against container_malformed on
block_file as agreement, hiding the very split #641 adds.

PHASE_DEPENDENT_TOLERANCE_TARGETS = ["manifest_body"], checked to be a
subset of the compared targets. The breadth test now pins 58 of 136 on
manifest_body and 0 on every other target. No behaviour moves today:
manifest_body is the only compared target.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 2: `rule_token()` for `RecordError` and `BlockError`

**Files:**
- Create: `core/src/vault/rule_tokens/mod.rs`
- Create: `core/src/vault/rule_tokens/record.rs`
- Create: `core/src/vault/rule_tokens/block.rs`
- Create: `core/src/vault/rule_tokens/tests/mod.rs`
- Create: `core/src/vault/rule_tokens/tests/record.rs`
- Create: `core/src/vault/rule_tokens/tests/block.rs`
- Modify: `core/src/vault/mod.rs` (declare the module)
- Modify: `core/src/vault/manifest/token.rs` (doc wording only)

**Interfaces:**
- Consumes: `secretary_core::vault::manifest::RuleToken` (unchanged).
- Produces: `pub fn RecordError::rule_token(&self) -> RuleToken`; `pub fn BlockError::rule_token(&self) -> RuleToken` (spec §3.1, §3.2).

- [ ] **Step 1: Declare the module and write the failing tests**

In `core/src/vault/mod.rs`, after the line `pub mod retention;` add:

```rust
mod rule_tokens;
```

Create `core/src/vault/rule_tokens/mod.rs`:

```rust
//! `rule_token()` for [`RecordError`](super::record::RecordError) and
//! [`BlockError`](super::block::BlockError) (#641): which rule a rejecting
//! record or block-file decoder is reporting, as the language-neutral token
//! `core/tests/differential_replay.rs` compares against `conformance.py`.
//!
//! **Why `RuleToken` itself is not here.** It lives in
//! `vault::manifest::token`, where #634 introduced it for the manifest body,
//! and #648 owns the decision about its public home. Moving it now would break
//! its public path and every citation of it for no gain in this slice.
//!
//! **Why not in `record.rs` / `block.rs`.** Both are over 3,000 lines. An
//! inherent `impl` may live anywhere in the crate, so the two impls sit in
//! their own small files beside a second, independent declaration of each
//! mapping in `tests/`.

mod block;
mod record;

#[cfg(test)]
mod tests;
```

Create `core/src/vault/rule_tokens/record.rs` with only its module doc and imports for now (the impl comes in Step 3):

```rust
//! [`RecordError::rule_token`] (#641). Spec §3.1.

use crate::vault::manifest::RuleToken;
use crate::vault::record::RecordError;
```

Create `core/src/vault/rule_tokens/block.rs` likewise:

```rust
//! [`BlockError::rule_token`] (#641). Spec §3.2.

use crate::vault::block::BlockError;
use crate::vault::manifest::RuleToken;
```

Create `core/src/vault/rule_tokens/tests/mod.rs`:

```rust
//! A second, independent declaration of each variant→token mapping, so
//! repointing one arm in `rule_tokens/{record,block}.rs` reds a row here.

mod block;
mod record;
```

Create `core/src/vault/rule_tokens/tests/record.rs`:

```rust
//! Which token each `RecordError` variant carries.

use crate::cbor::{CborErrorKind, CborFault};
use crate::vault::manifest::RuleToken;
use crate::vault::record::RecordError;

/// `RecordError`'s variant count. A new variant is a compile error in the
/// exhaustive match below first, and a failure of this count second.
const RECORD_ERROR_VARIANTS: usize = 14;

fn fault(kind: CborErrorKind) -> CborFault {
    CborFault { kind, offset: None }
}

fn every_variant_and_its_token() -> Vec<(RecordError, RuleToken)> {
    vec![
        (
            RecordError::CborEncode(fault(CborErrorKind::Serialization)),
            RuleToken::InternalError,
        ),
        // Every kind a decode can report is `malformed_cbor`, including
        // `RecursionLimit`: ciborium's depth cap is Rust-only, the residual
        // spec §7 files rather than fixes.
        (
            RecordError::CborDecode(fault(CborErrorKind::Io)),
            RuleToken::MalformedCbor,
        ),
        (
            RecordError::CborDecode(fault(CborErrorKind::Syntax)),
            RuleToken::MalformedCbor,
        ),
        (
            RecordError::CborDecode(fault(CborErrorKind::Semantic)),
            RuleToken::MalformedCbor,
        ),
        (
            RecordError::CborDecode(fault(CborErrorKind::RecursionLimit)),
            RuleToken::MalformedCbor,
        ),
        (RecordError::NotAMap, RuleToken::WrongType),
        (RecordError::NonTextKey, RuleToken::WrongType),
        (
            RecordError::MissingField {
                field: "record_uuid",
            },
            RuleToken::MissingField,
        ),
        (
            RecordError::WrongType {
                field: "tags",
                expected: "array",
            },
            RuleToken::WrongType,
        ),
        (
            RecordError::InvalidUuid {
                field: "record_uuid",
                length: 3,
            },
            RuleToken::WrongType,
        ),
        (
            RecordError::IntegerOverflow {
                field: "created_at_ms",
            },
            RuleToken::IntegerOutOfRange,
        ),
        (
            RecordError::DuplicateKey {
                field: "<record>",
                index: 1,
            },
            RuleToken::DuplicateMapKey,
        ),
        (
            RecordError::FloatRejected { field: "<root>" },
            RuleToken::Rule4TagOrFloat,
        ),
        (RecordError::TagRejected, RuleToken::Rule4TagOrFloat),
        (
            RecordError::NonCanonicalEncoding,
            RuleToken::NonCanonicalUnclassified,
        ),
        (
            RecordError::CanonicalSizeBoundExceeded {
                actual: 2,
                bound: 1,
            },
            RuleToken::InternalError,
        ),
        (
            RecordError::CanonicalDuplicateKey { index: 1 },
            RuleToken::DuplicateMapKey,
        ),
    ]
}

#[test]
fn every_record_error_variant_carries_its_declared_token() {
    let rows = every_variant_and_its_token();
    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive: a fifteenth variant is a COMPILE error here.
    for (err, _) in &rows {
        match err {
            RecordError::CborEncode(_)
            | RecordError::CborDecode(_)
            | RecordError::NotAMap
            | RecordError::NonTextKey
            | RecordError::MissingField { .. }
            | RecordError::WrongType { .. }
            | RecordError::InvalidUuid { .. }
            | RecordError::IntegerOverflow { .. }
            | RecordError::DuplicateKey { .. }
            | RecordError::FloatRejected { .. }
            | RecordError::TagRejected
            | RecordError::NonCanonicalEncoding
            | RecordError::CanonicalSizeBoundExceeded { .. }
            | RecordError::CanonicalDuplicateKey { .. } => (),
        }
    }

    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        RECORD_ERROR_VARIANTS,
        "the table covers {} of the {RECORD_ERROR_VARIANTS} RecordError variants",
        distinct.len()
    );
}
```

Create `core/src/vault/rule_tokens/tests/block.rs`:

```rust
//! Which token each `BlockError` variant carries.

use rand_core::{OsRng, RngCore};

use crate::cbor::{CborErrorKind, CborFault};
use crate::crypto::aead::AeadError;
use crate::crypto::kem::KemError;
use crate::crypto::sig::SigError;
use crate::identity::fingerprint::Fingerprint;
use crate::vault::block::{BlockError, BLOCK_UUID_LEN};
use crate::vault::manifest::RuleToken;
use crate::vault::record::RecordError;

/// `BlockError`'s variant count. A new variant is a compile error in the
/// exhaustive match below first, and a failure of this count second.
const BLOCK_ERROR_VARIANTS: usize = 39;

/// A random 16-byte id. Error payloads never reach the token, but literal
/// byte arrays read as hard-coded key material to CodeQL.
fn random_id() -> [u8; BLOCK_UUID_LEN] {
    let mut id = [0u8; BLOCK_UUID_LEN];
    OsRng.fill_bytes(&mut id);
    id
}

fn random_fingerprint() -> Fingerprint {
    random_id()
}

fn fault() -> CborFault {
    CborFault {
        kind: CborErrorKind::Syntax,
        offset: None,
    }
}

fn every_variant_and_its_token() -> Vec<(BlockError, RuleToken)> {
    use RuleToken as T;
    vec![
        // Delegation: two inner variants with two different tokens.
        (BlockError::Record(RecordError::NonTextKey), T::WrongType),
        (BlockError::Record(RecordError::TagRejected), T::Rule4TagOrFloat),
        (BlockError::CborEncode(fault()), T::InternalError),
        (BlockError::CborDecode(fault()), T::MalformedCbor),
        (BlockError::BadMagic { found: 0 }, T::ContainerMalformed),
        (
            BlockError::UnsupportedFormatVersion { found: 2 },
            T::UnsupportedVersion,
        ),
        (BlockError::UnsupportedSuiteId { found: 2 }, T::UnsupportedVersion),
        (
            BlockError::WrongFileKind {
                found: 2,
                expected: 3,
            },
            T::ContainerMalformed,
        ),
        (BlockError::Truncated { needed: 2, got: 1 }, T::ContainerMalformed),
        (BlockError::VectorClockNotSorted, T::ArraySortOrder),
        (BlockError::VectorClockDuplicateDevice, T::RepeatedArrayValue),
        (
            BlockError::VectorClockCountMismatch {
                declared: 2,
                actual: 1,
            },
            T::ContainerMalformed,
        ),
        (
            BlockError::BlockUuidMismatch {
                header: random_id(),
                plaintext: random_id(),
            },
            T::ContainerMalformed,
        ),
        (
            BlockError::DuplicateRecipient {
                fingerprint: random_fingerprint(),
            },
            T::RepeatedArrayValue,
        ),
        (BlockError::EmptyRecipientList, T::ContainerMalformed),
        (BlockError::TooManyRecipients { count: 2 }, T::EncoderRefusal),
        (BlockError::RecipientsNotSorted, T::ArraySortOrder),
        (
            BlockError::RecipientCtPqWrongLength { found: 1 },
            T::EncoderRefusal,
        ),
        (
            BlockError::RecipientCtWrongLength { found: 1 },
            T::EncoderRefusal,
        ),
        (
            BlockError::NotARecipient {
                fingerprint: random_fingerprint(),
            },
            T::AeadFailure,
        ),
        (BlockError::Aead(AeadError::Decryption), T::AeadFailure),
        (BlockError::Kem(KemError::MlKemDecapsFailed), T::AeadFailure),
        (BlockError::NotAMap, T::WrongType),
        (BlockError::NonTextKey, T::WrongType),
        (
            BlockError::MissingField {
                field: "block_uuid",
            },
            T::MissingField,
        ),
        (
            BlockError::WrongType {
                field: "records",
                expected: "array",
            },
            T::WrongType,
        ),
        (
            BlockError::InvalidUuid {
                field: "block_uuid",
                length: 3,
            },
            T::WrongType,
        ),
        (
            BlockError::IntegerOverflow {
                field: "block_version",
            },
            T::IntegerOutOfRange,
        ),
        (
            BlockError::DuplicateKey {
                field: "<block>",
                index: 1,
            },
            T::DuplicateMapKey,
        ),
        (
            BlockError::FloatRejected { field: "<root>" },
            T::Rule4TagOrFloat,
        ),
        (BlockError::TagRejected, T::Rule4TagOrFloat),
        (BlockError::NonCanonicalEncoding, T::NonCanonicalUnclassified),
        (BlockError::Sig(SigError::Ed25519VerifyFailed), T::SignatureInvalid),
        (BlockError::SigEdWrongLength { found: 1 }, T::ContainerMalformed),
        (BlockError::SigPqTooLong { found: 1 }, T::EncoderRefusal),
        (BlockError::SigPqWrongLength { found: 1 }, T::ContainerMalformed),
        (
            BlockError::AuthorFingerprintMismatch {
                expected: random_fingerprint(),
                found: random_fingerprint(),
            },
            T::SignatureInvalid,
        ),
        (BlockError::TrailingBytes { count: 1 }, T::ContainerMalformed),
        (
            BlockError::CanonicalSizeBoundExceeded {
                actual: 2,
                bound: 1,
            },
            T::InternalError,
        ),
        (
            BlockError::CanonicalDuplicateKey { index: 1 },
            T::DuplicateMapKey,
        ),
    ]
}

#[test]
fn every_block_error_variant_carries_its_declared_token() {
    let rows = every_variant_and_its_token();
    for (err, want) in &rows {
        assert_eq!(err.rule_token(), *want, "variant {err:?}");
    }

    // Exhaustive: a fortieth variant is a COMPILE error here.
    for (err, _) in &rows {
        match err {
            BlockError::Record(_)
            | BlockError::CborEncode(_)
            | BlockError::CborDecode(_)
            | BlockError::BadMagic { .. }
            | BlockError::UnsupportedFormatVersion { .. }
            | BlockError::UnsupportedSuiteId { .. }
            | BlockError::WrongFileKind { .. }
            | BlockError::Truncated { .. }
            | BlockError::VectorClockNotSorted
            | BlockError::VectorClockDuplicateDevice
            | BlockError::VectorClockCountMismatch { .. }
            | BlockError::BlockUuidMismatch { .. }
            | BlockError::DuplicateRecipient { .. }
            | BlockError::EmptyRecipientList
            | BlockError::TooManyRecipients { .. }
            | BlockError::RecipientsNotSorted
            | BlockError::RecipientCtPqWrongLength { .. }
            | BlockError::RecipientCtWrongLength { .. }
            | BlockError::NotARecipient { .. }
            | BlockError::Aead(_)
            | BlockError::Kem(_)
            | BlockError::NotAMap
            | BlockError::NonTextKey
            | BlockError::MissingField { .. }
            | BlockError::WrongType { .. }
            | BlockError::InvalidUuid { .. }
            | BlockError::IntegerOverflow { .. }
            | BlockError::DuplicateKey { .. }
            | BlockError::FloatRejected { .. }
            | BlockError::TagRejected
            | BlockError::NonCanonicalEncoding
            | BlockError::Sig(_)
            | BlockError::SigEdWrongLength { .. }
            | BlockError::SigPqTooLong { .. }
            | BlockError::SigPqWrongLength { .. }
            | BlockError::AuthorFingerprintMismatch { .. }
            | BlockError::TrailingBytes { .. }
            | BlockError::CanonicalSizeBoundExceeded { .. }
            | BlockError::CanonicalDuplicateKey { .. } => (),
        }
    }

    // The two `Record(_)` rows collapse to one discriminant.
    let distinct: std::collections::HashSet<_> = rows
        .iter()
        .map(|(e, _)| std::mem::discriminant(e))
        .collect();
    assert_eq!(
        distinct.len(),
        BLOCK_ERROR_VARIANTS,
        "the table covers {} of the {BLOCK_ERROR_VARIANTS} BlockError variants",
        distinct.len()
    );
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --locked -p secretary-core --lib rule_tokens > "$TMPDIR/t2.log" 2>&1; echo "exit=$?"; grep -E "^error\[" "$TMPDIR/t2.log" | sort | uniq -c`
Expected: exit non-zero; `error[E0599]: no method named rule_token` on both enums. If an import fails instead (for example `KemError::MlKemDecapsFailed` or `BLOCK_UUID_LEN` not found), fix the import against the real definition, not the mapping.

- [ ] **Step 3: Implement both impls**

Append to `core/src/vault/rule_tokens/record.rs`:

```rust

impl RecordError {
    /// Which rule this rejection is reporting, as a language-neutral token
    /// shared with `conformance.py` (#634, #641).
    ///
    /// **Exhaustive by construction.** Adding a `RecordError` variant without
    /// classifying it is a compile error: a wildcard arm would let a new
    /// variant fall silently into some neighbour's token and present a
    /// divergence as agreement.
    ///
    /// **Coarse on purpose.** A token may only draw a distinction both
    /// implementations can make. [`RecordError::NonCanonicalEncoding`] is
    /// fieldless, so this crate cannot tell §6.2 rule 1, 2, 3 or trailing
    /// bytes apart, and `conformance.py` reports all four under the same
    /// token on the record path.
    ///
    /// **Advisory, never a verdict.** Nothing in the crate consults it to
    /// decide acceptance.
    pub fn rule_token(&self) -> RuleToken {
        match self {
            // Every kind, including `RecursionLimit`: ciborium's depth cap is
            // Rust-only, and spec §7 files it rather than fixing it here.
            RecordError::CborDecode(_) => RuleToken::MalformedCbor,
            RecordError::NotAMap
            | RecordError::NonTextKey
            | RecordError::WrongType { .. }
            | RecordError::InvalidUuid { .. } => RuleToken::WrongType,
            RecordError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange,
            RecordError::MissingField { .. } => RuleToken::MissingField,
            // `CanonicalDuplicateKey` is the canonical encoder's twin; it
            // takes the rule it names, as `ManifestError::Canonical`'s
            // `DuplicateKey` arm does.
            RecordError::DuplicateKey { .. } | RecordError::CanonicalDuplicateKey { .. } => {
                RuleToken::DuplicateMapKey
            }
            RecordError::FloatRejected { .. } | RecordError::TagRejected => {
                RuleToken::Rule4TagOrFloat
            }
            RecordError::NonCanonicalEncoding => RuleToken::NonCanonicalUnclassified,
            RecordError::CborEncode(_) | RecordError::CanonicalSizeBoundExceeded { .. } => {
                RuleToken::InternalError
            }
        }
    }
}
```

Append to `core/src/vault/rule_tokens/block.rs`:

```rust

impl BlockError {
    /// Which rule this rejection is reporting, as a language-neutral token
    /// shared with `conformance.py` (#641).
    ///
    /// **Exhaustive by construction**, for the reason
    /// [`RecordError::rule_token`](crate::vault::record::RecordError::rule_token)
    /// gives.
    ///
    /// **What the `block_file` replay target can reach.** That target
    /// round-trips `decode_block_file` → `encode_block_file` and never
    /// decrypts, so only the envelope arms below are compared. The plaintext
    /// arms match `RecordError`'s. The AEAD, KEM, signature and binding arms
    /// are unreachable from that target; each takes the nearest existing
    /// token and is a diagnostic only.
    pub fn rule_token(&self) -> RuleToken {
        match self {
            BlockError::Record(e) => e.rule_token(),

            // --- §6.1 / §6.2 envelope ------------------------------------
            BlockError::Truncated { .. }
            | BlockError::BadMagic { .. }
            | BlockError::WrongFileKind { .. }
            | BlockError::EmptyRecipientList
            | BlockError::SigEdWrongLength { .. }
            | BlockError::SigPqWrongLength { .. }
            | BlockError::TrailingBytes { .. }
            | BlockError::VectorClockCountMismatch { .. } => RuleToken::ContainerMalformed,
            BlockError::UnsupportedFormatVersion { .. } | BlockError::UnsupportedSuiteId { .. } => {
                RuleToken::UnsupportedVersion
            }
            BlockError::VectorClockNotSorted | BlockError::RecipientsNotSorted => {
                RuleToken::ArraySortOrder
            }
            BlockError::VectorClockDuplicateDevice | BlockError::DuplicateRecipient { .. } => {
                RuleToken::RepeatedArrayValue
            }
            // Caller-built values the ENCODER refuses. `TooManyRecipients`
            // also has a decode-side producer (`count * 1208` overflowing
            // `usize`), unreachable on any 64-bit target.
            BlockError::TooManyRecipients { .. }
            | BlockError::RecipientCtPqWrongLength { .. }
            | BlockError::RecipientCtWrongLength { .. }
            | BlockError::SigPqTooLong { .. } => RuleToken::EncoderRefusal,

            // --- §6.3 plaintext, as `RecordError` ------------------------
            BlockError::CborDecode(_) => RuleToken::MalformedCbor,
            BlockError::NotAMap
            | BlockError::NonTextKey
            | BlockError::WrongType { .. }
            | BlockError::InvalidUuid { .. } => RuleToken::WrongType,
            BlockError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange,
            BlockError::MissingField { .. } => RuleToken::MissingField,
            BlockError::DuplicateKey { .. } | BlockError::CanonicalDuplicateKey { .. } => {
                RuleToken::DuplicateMapKey
            }
            BlockError::FloatRejected { .. } | BlockError::TagRejected => RuleToken::Rule4TagOrFloat,
            BlockError::NonCanonicalEncoding => RuleToken::NonCanonicalUnclassified,
            BlockError::CborEncode(_) | BlockError::CanonicalSizeBoundExceeded { .. } => {
                RuleToken::InternalError
            }

            // --- diagnostics only: unreachable from `block_file` ---------
            BlockError::Aead(_) | BlockError::Kem(_) | BlockError::NotARecipient { .. } => {
                RuleToken::AeadFailure
            }
            BlockError::Sig(_) | BlockError::AuthorFingerprintMismatch { .. } => {
                RuleToken::SignatureInvalid
            }
            BlockError::BlockUuidMismatch { .. } => RuleToken::ContainerMalformed,
        }
    }
}
```

- [ ] **Step 4: Generalise `RuleToken`'s doc wording**

In `core/src/vault/manifest/token.rs`, make these exact doc replacements (docs only, no code change):

- `/// Which rule a rejecting manifest decoder is reporting.` → `/// Which rule a rejecting decoder is reporting: the manifest body (#634), and the record and block-file envelope replay targets (#641).`
- `/// §4.2's repeated-array-value prohibition, in one of the four arrays it` → `/// A repeated value in a table that forbids one: §4.2's repeated-array-value prohibition, in one of the four arrays it`, and append this line after that variant's existing doc lines: `/// On a §6.1 block file, the vector clock or the recipient table (#641).`
- `/// One of `docs/vault-format.md` §4.2's five array sort disciplines.` → `/// One of `docs/vault-format.md` §4.2's five array sort disciplines, or a §6.1 block file's vector clock or recipient table out of ascending order (#641).`
- `/// A §4.2 required key is absent.` → `/// A required key is absent (§4.2 manifest body, §6.3 record).`
- `/// An integer field is outside the width §4.2 gives it.` → `/// An integer field is outside the width §4.2 or §6.3 gives it.`
- `/// not the v1 value, at either the body or the file-header layer.` → `/// not the v1 value, at either the body or the file-header layer — including a §6.1 block file's header (#641).`
- `/// The §4.1 file envelope is malformed: magic, file kind, header or` → `/// A §4.1 manifest or §6.1 block file envelope is malformed: magic, file kind, header or`

If a quoted line does not match exactly, read the variant's doc and make the equivalent edit. Do not change any code.

- [ ] **Step 5: Run to verify it passes**

Run: `cargo test --release --locked -p secretary-core --lib > "$TMPDIR/t2.log" 2>&1; echo "exit=$?"; grep -E "test result" "$TMPDIR/t2.log"`
Expected: exit=0. The two new tests pass, and the rest of `--lib` is unchanged. Run the whole `--lib` target, not a `rule_tokens` filter, so the result covers everything.

Then: `cargo clippy --release --locked --workspace --tests -- -D warnings > "$TMPDIR/c2.log" 2>&1; echo "exit=$?"` → exit=0; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace > "$TMPDIR/d2.log" 2>&1; echo "exit=$?"` → exit=0; `cargo fmt --all --check; echo "exit=$?"` → exit=0 (run `cargo fmt --all` first if needed); `uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py; echo "exit=$?"` → exit=0.

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/mod.rs core/src/vault/rule_tokens core/src/vault/manifest/token.rs
git commit -F - <<'EOF'
Give RecordError and BlockError a rule token (#641)

Exhaustive rule_token() impls over all 14 RecordError and 39
BlockError variants, onto the existing 17-token vocabulary: no new
token, no variant or signature change. BlockError::Record delegates.

Only BlockError's envelope arms are reachable from the block_file
replay target, which never decrypts; the AEAD, KEM, signature and
binding arms take the nearest existing token and say so. RecordError's
NonCanonicalEncoding is fieldless, so its token is the coarse
non_canonical_unclassified, and conformance.py will report all four
canonical-form faults under it on the record path.

The impls live in vault/rule_tokens/ rather than in record.rs and
block.rs (3,037 and 3,222 lines). RuleToken stays where #634 put it;
#648 owns its public home. Each mapping is declared a second time in
tests/, with an exhaustive match and a discriminant count.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 3: Seed table, generator and label binding, with the `block_file` seeds

**Files:**
- Create: `core/tests/rule_token_seeds.rs`
- Create: `core/tests/rule_token_seeds_helpers/mod.rs`
- Create: `core/tests/rule_token_seeds_helpers/block_file.rs`
- Create (generated): `core/fuzz/seeds/block_file/<token>__<shape>.bin`, 15 files

**Interfaces:**
- Consumes: `BlockError::rule_token`, `RecordError::rule_token` (Task 2).
- Produces:
  - `pub struct SeedCase { pub target: &'static str, pub token: RuleToken, pub shape: &'static str, pub plant: fn(&[u8]) -> Vec<u8> }` with `file_name()`, `path()`, `bytes()`
  - `pub const LABEL_SEPARATOR: &str = "__"`
  - `pub fn seed_dir(target: &str) -> PathBuf`, `pub fn base(target: &str) -> Vec<u8>`, `pub fn rust_token(target: &str, bytes: &[u8]) -> Option<RuleToken>`, `pub fn all_cases() -> Vec<SeedCase>`
  - `block_file::cases() -> Vec<SeedCase>`

- [ ] **Step 1: Write the table module**

Create `core/tests/rule_token_seeds_helpers/mod.rs`:

```rust
//! The committed single-fault seeds for the token-compared `record` and
//! `block_file` replay targets (#641), and the ONE table the generator and the
//! label-binding check both read.
//!
//! **Why generated.** CI replays only committed inputs. Before #641 these two
//! targets held four, all ACCEPTING, so a strict token comparison on them
//! would have compared nothing in CI.
//!
//! **Why label-bound.** A corpus whose bytes are not bound to their labels
//! can collapse silently (#614's review measured it). A seed's file name is
//! DERIVED from its row, and the check regenerates every row and requires the
//! committed bytes to match, so a label and its bytes cannot disagree.
//!
//! **Why each seed plants ONE fault.** `docs/vault-format.md` §6.1/§6.3 fix no
//! report order, and a committed row must not pin an order the spec leaves
//! open (#618's lesson). A planted fault can have a downstream consequence —
//! an `undefined` value also fails the re-encode — but both implementations
//! meet the planted fault first.

use std::path::PathBuf;

use secretary_core::vault::manifest::RuleToken;

pub mod block_file;

/// One committed seed.
pub struct SeedCase {
    /// The replay target whose seed directory holds this file.
    pub target: &'static str,
    /// The rule BOTH decoders must name for this seed.
    pub token: RuleToken,
    /// What was planted, as a file-name-safe label unique within `token`.
    pub shape: &'static str,
    /// Build the seed from the target's committed accepting base.
    pub plant: fn(&[u8]) -> Vec<u8>,
}

/// Separates a seed's token from its shape in its file name. No token and no
/// accepting base file name contains it.
pub const LABEL_SEPARATOR: &str = "__";

/// A seed's file extension. The replay reads every file in the directory
/// whatever its extension; this only makes the files recognisable.
const SEED_EXTENSION: &str = "bin";

impl SeedCase {
    pub fn file_name(&self) -> String {
        format!(
            "{}{LABEL_SEPARATOR}{}.{SEED_EXTENSION}",
            self.token.as_str(),
            self.shape
        )
    }

    pub fn path(&self) -> PathBuf {
        seed_dir(self.target).join(self.file_name())
    }

    pub fn bytes(&self) -> Vec<u8> {
        (self.plant)(&base(self.target))
    }
}

/// `core/fuzz/seeds/<target>/`.
pub fn seed_dir(target: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("fuzz/seeds")
        .join(target)
}

/// The committed ACCEPTING input each target's seeds are planted into.
pub fn base(target: &str) -> Vec<u8> {
    let name = match target {
        "block_file" => "golden.bin",
        "record" => "login.cbor",
        other => panic!("no seed base for target {other}"),
    };
    let path = seed_dir(target).join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read seed base {}: {e}", path.display()))
}

/// The token the Rust decoder names for `bytes`, or `None` if it accepts.
///
/// The same decode → re-encode pipeline `differential_replay_helpers::rust_decoder`
/// runs for the target.
pub fn rust_token(target: &str, bytes: &[u8]) -> Option<RuleToken> {
    use secretary_core::vault::{block, record};
    match target {
        "block_file" => block::decode_block_file(bytes)
            .and_then(|f| block::encode_block_file(&f))
            .err()
            .map(|e| e.rule_token()),
        "record" => record::decode(bytes)
            .and_then(|r| record::encode(&r))
            .err()
            .map(|e| e.rule_token()),
        other => panic!("no Rust decoder for target {other}"),
    }
}

/// Every case, in a stable order.
pub fn all_cases() -> Vec<SeedCase> {
    block_file::cases()
}
```

- [ ] **Step 2: Write the `block_file` cases**

Create `core/tests/rule_token_seeds_helpers/block_file.rs`:

```rust
//! Single-fault `block_file` seeds, planted into
//! `core/fuzz/seeds/block_file/golden.bin` (1 vector-clock entry, 1
//! recipient).
//!
//! Section boundaries come from the real decoders (`decode_header`,
//! `decode_recipient_table`) rather than hand-counted offsets, so a change to
//! the base cannot silently move a planted fault onto a different field. The
//! sort and repeat shapes splice in a second table entry. That leaves the AAD
//! and signature stale, which neither decoder checks on this target.

use std::mem::size_of;

use secretary_core::crypto::sig::{ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use secretary_core::identity::fingerprint::Fingerprint;
use secretary_core::vault::block::{
    decode_header, decode_recipient_table, FILE_KIND_BLOCK, RECIPIENT_ENTRY_LEN,
};
use secretary_core::vault::manifest::RuleToken;
use secretary_core::version::{FORMAT_VERSION, SUITE_ID};

use super::SeedCase;

// §6.1 header prefix: magic (u32), format_version (u16), suite_id (u16),
// file_kind (u16), in that order.
const MAGIC_AT: usize = 0;
const FORMAT_VERSION_AT: usize = size_of::<u32>();
const SUITE_ID_AT: usize = FORMAT_VERSION_AT + size_of::<u16>();
const FILE_KIND_AT: usize = SUITE_ID_AT + size_of::<u16>();
/// Every table count and signature length prefix is a u16.
const U16_LEN: usize = size_of::<u16>();
/// device_uuid (16) || counter (u64).
const VECTOR_CLOCK_ENTRY_LEN: usize = size_of::<Fingerprint>() + size_of::<u64>();
/// author_fingerprint || sig_ed_len || sig_ed || sig_pq_len || sig_pq.
const SIG_SUFFIX_LEN: usize =
    size_of::<Fingerprint>() + U16_LEN + ED25519_SIG_LEN + U16_LEN + ML_DSA_65_SIG_LEN;
/// Two entries whose leading id bytes are these compare strictly, whatever
/// the rest of the id holds.
const LOW_LEAD: u8 = u8::MIN;
const HIGH_LEAD: u8 = u8::MAX;
/// A byte appended past the signature suffix.
const TRAILING_BYTE: u8 = 0;

/// Where golden.bin's variable sections sit.
struct Layout {
    vc_count_at: usize,
    vc_entries_at: usize,
    vc_len: usize,
    recipient_count_at: usize,
    recipients_at: usize,
    recipients_len: usize,
    sig_suffix_at: usize,
}

fn layout(base: &[u8]) -> Layout {
    let (header, after_header) = decode_header(base).expect("golden block header decodes");
    let header_end = base.len() - after_header.len();
    let vc_len = header.vector_clock.len() * VECTOR_CLOCK_ENTRY_LEN;
    let (recipients, _) =
        decode_recipient_table(after_header).expect("golden recipient table decodes");
    Layout {
        vc_count_at: header_end - vc_len - U16_LEN,
        vc_entries_at: header_end - vc_len,
        vc_len,
        recipient_count_at: header_end,
        recipients_at: header_end + U16_LEN,
        recipients_len: recipients.len() * RECIPIENT_ENTRY_LEN,
        sig_suffix_at: base.len() - SIG_SUFFIX_LEN,
    }
}

fn put_u16(bytes: &mut [u8], at: usize, value: u16) {
    bytes[at..at + U16_LEN].copy_from_slice(&value.to_be_bytes());
}

fn u16_of(value: usize) -> u16 {
    u16::try_from(value).expect("the value fits its u16 wire field")
}

/// `base` with the u16-counted table at `count_at` replaced by `entries`.
fn with_table(
    base: &[u8],
    count_at: usize,
    entries_at: usize,
    old_len: usize,
    entries: &[Vec<u8>],
) -> Vec<u8> {
    let mut out = base[..count_at].to_vec();
    out.extend_from_slice(&u16_of(entries.len()).to_be_bytes());
    for entry in entries {
        out.extend_from_slice(entry);
    }
    out.extend_from_slice(&base[entries_at + old_len..]);
    out
}

fn with_lead_byte(entry: &[u8], lead: u8) -> Vec<u8> {
    let mut e = entry.to_vec();
    e[0] = lead;
    e
}

fn vector_clock_entry(base: &[u8], l: &Layout) -> Vec<u8> {
    base[l.vc_entries_at..l.vc_entries_at + VECTOR_CLOCK_ENTRY_LEN].to_vec()
}

fn recipient_entry(base: &[u8], l: &Layout) -> Vec<u8> {
    base[l.recipients_at..l.recipients_at + RECIPIENT_ENTRY_LEN].to_vec()
}

fn bad_magic(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    b[MAGIC_AT] ^= u8::MAX;
    b
}

fn wrong_file_kind(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    put_u16(&mut b, FILE_KIND_AT, FILE_KIND_BLOCK + 1);
    b
}

fn unsupported_format_version(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    put_u16(&mut b, FORMAT_VERSION_AT, FORMAT_VERSION + 1);
    b
}

fn unsupported_suite_id(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    put_u16(&mut b, SUITE_ID_AT, SUITE_ID + 1);
    b
}

/// Ends one byte into `vault_uuid`.
fn truncated_header(base: &[u8]) -> Vec<u8> {
    base[..FILE_KIND_AT + U16_LEN + 1].to_vec()
}

/// Ends halfway through the first recipient entry.
fn truncated_recipient_table(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    base[..l.recipients_at + RECIPIENT_ENTRY_LEN / 2].to_vec()
}

fn zero_recipients(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    with_table(base, l.recipient_count_at, l.recipients_at, l.recipients_len, &[])
}

fn wrong_sig_ed_len(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let mut b = base.to_vec();
    put_u16(
        &mut b,
        l.sig_suffix_at + size_of::<Fingerprint>(),
        u16_of(ED25519_SIG_LEN - 1),
    );
    b
}

fn wrong_sig_pq_len(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let mut b = base.to_vec();
    put_u16(
        &mut b,
        l.sig_suffix_at + size_of::<Fingerprint>() + U16_LEN + ED25519_SIG_LEN,
        u16_of(ML_DSA_65_SIG_LEN - 1),
    );
    b
}

/// Ends halfway through `sig_pq`.
fn truncated_signature_suffix(base: &[u8]) -> Vec<u8> {
    base[..base.len() - ML_DSA_65_SIG_LEN / 2].to_vec()
}

fn trailing_bytes(base: &[u8]) -> Vec<u8> {
    let mut b = base.to_vec();
    b.push(TRAILING_BYTE);
    b
}

fn unsorted_vector_clock(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = vector_clock_entry(base, &l);
    let entries = [with_lead_byte(&entry, HIGH_LEAD), with_lead_byte(&entry, LOW_LEAD)];
    with_table(base, l.vc_count_at, l.vc_entries_at, l.vc_len, &entries)
}

fn repeated_vector_clock(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = vector_clock_entry(base, &l);
    with_table(base, l.vc_count_at, l.vc_entries_at, l.vc_len, &[entry.clone(), entry])
}

fn unsorted_recipients(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = recipient_entry(base, &l);
    let entries = [with_lead_byte(&entry, HIGH_LEAD), with_lead_byte(&entry, LOW_LEAD)];
    with_table(base, l.recipient_count_at, l.recipients_at, l.recipients_len, &entries)
}

fn repeated_recipients(base: &[u8]) -> Vec<u8> {
    let l = layout(base);
    let entry = recipient_entry(base, &l);
    with_table(
        base,
        l.recipient_count_at,
        l.recipients_at,
        l.recipients_len,
        &[entry.clone(), entry],
    )
}

pub fn cases() -> Vec<SeedCase> {
    let case = |token: RuleToken, shape: &'static str, plant: fn(&[u8]) -> Vec<u8>| SeedCase {
        target: "block_file",
        token,
        shape,
        plant,
    };
    use RuleToken::{ArraySortOrder, ContainerMalformed, RepeatedArrayValue, UnsupportedVersion};
    vec![
        case(ContainerMalformed, "bad_magic", bad_magic),
        case(ContainerMalformed, "wrong_file_kind", wrong_file_kind),
        case(ContainerMalformed, "truncated_header", truncated_header),
        case(ContainerMalformed, "truncated_recipient_table", truncated_recipient_table),
        case(ContainerMalformed, "zero_recipients", zero_recipients),
        case(ContainerMalformed, "wrong_sig_ed_len", wrong_sig_ed_len),
        case(ContainerMalformed, "wrong_sig_pq_len", wrong_sig_pq_len),
        case(ContainerMalformed, "truncated_signature_suffix", truncated_signature_suffix),
        case(ContainerMalformed, "trailing_bytes", trailing_bytes),
        case(UnsupportedVersion, "format_version", unsupported_format_version),
        case(UnsupportedVersion, "suite_id", unsupported_suite_id),
        case(ArraySortOrder, "vector_clock", unsorted_vector_clock),
        case(ArraySortOrder, "recipients", unsorted_recipients),
        case(RepeatedArrayValue, "vector_clock", repeated_vector_clock),
        case(RepeatedArrayValue, "recipients", repeated_recipients),
    ]
}
```

- [ ] **Step 3: Write the test binary, with the label binding as the failing test**

Create `core/tests/rule_token_seeds.rs`:

```rust
//! Committed single-fault seeds for the `record` and `block_file` replay
//! targets (#641): the generator, and the check that binds every committed
//! seed to its label. See `rule_token_seeds_helpers` for the table, and
//! `docs/superpowers/specs/2026-09-15-token-compare-record-block-design.md`
//! §6.1.
//!
//! The Python half of the binding is conformance Section RTS.

mod rule_token_seeds_helpers;

use std::collections::BTreeSet;

use rule_token_seeds_helpers::{all_cases, rust_token, seed_dir, SeedCase, LABEL_SEPARATOR};

/// The targets whose seed directories this table owns every labelled file in.
const SEEDED_TARGETS: &[&str] = &["block_file"];

/// How to regenerate, quoted in every failure that needs it.
const REGENERATE: &str = "cargo test --release --locked -p secretary-core --test \
                          rule_token_seeds -- --ignored generate_rule_token_seeds";

fn assert_rust_names_its_token(case: &SeedCase, bytes: &[u8]) {
    let got = rust_token(case.target, bytes);
    assert_eq!(
        got,
        Some(case.token),
        "seed {} for {}: the Rust decoder named {got:?}, its row says {:?}",
        case.file_name(),
        case.target,
        case.token
    );
}

#[test]
fn every_seed_label_is_unique() {
    let cases = all_cases();
    let labels: BTreeSet<(&str, String)> =
        cases.iter().map(|c| (c.target, c.file_name())).collect();
    assert_eq!(labels.len(), cases.len(), "two rows share a target and file name");
}

#[test]
fn rule_token_seeds_are_committed_and_label_bound() {
    let cases = all_cases();
    for case in &cases {
        assert!(
            SEEDED_TARGETS.contains(&case.target),
            "row {} names target {}, which SEEDED_TARGETS does not own",
            case.file_name(),
            case.target
        );
        let want = case.bytes();
        assert_rust_names_its_token(case, &want);
        let committed = std::fs::read(case.path()).unwrap_or_else(|e| {
            panic!("seed {} is not committed ({e}); run `{REGENERATE}`", case.path().display())
        });
        assert!(
            committed == want,
            "seed {} differs from what its row plants: regenerate deliberately with \
             `{REGENERATE}`, or fix the row",
            case.path().display()
        );
    }

    // Both directions: no committed labelled seed without a row, no row
    // without its file.
    for target in SEEDED_TARGETS {
        let on_disk: BTreeSet<String> = std::fs::read_dir(seed_dir(target))
            .unwrap_or_else(|e| panic!("list seeds for {target}: {e}"))
            .map(|entry| {
                entry
                    .expect("read a seed directory entry")
                    .file_name()
                    .into_string()
                    .expect("seed file names are UTF-8")
            })
            .filter(|name| name.contains(LABEL_SEPARATOR))
            .collect();
        let declared: BTreeSet<String> = cases
            .iter()
            .filter(|c| c.target == *target)
            .map(SeedCase::file_name)
            .collect();
        assert_eq!(
            on_disk, declared,
            "target {target}: the committed labelled seeds and the case table disagree"
        );
    }
}

/// Writes every seed. Every row is built and checked BEFORE anything is
/// written, so a failing row leaves every file untouched (#614's lesson).
#[test]
#[ignore]
fn generate_rule_token_seeds() {
    let built: Vec<_> = all_cases()
        .iter()
        .map(|case| {
            let bytes = case.bytes();
            assert_rust_names_its_token(case, &bytes);
            (case.path(), bytes)
        })
        .collect();
    for (path, bytes) in built {
        std::fs::write(&path, bytes).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
    }
}
```

- [ ] **Step 4: Run to verify the label binding fails (no seeds committed yet)**

Run: `cargo test --release --locked -p secretary-core --test rule_token_seeds > "$TMPDIR/t3.log" 2>&1; echo "exit=$?"; grep -E "test result|panicked|is not committed" "$TMPDIR/t3.log" | head`
Expected: exit=101. `every_seed_label_is_unique` passes, and `rule_token_seeds_are_committed_and_label_bound` panics with "is not committed". If instead a panic says "the Rust decoder named …", a planting function hit a different field: fix the plant, not the table's token.

- [ ] **Step 5: Generate the seeds, then verify**

Run: `cargo test --release --locked -p secretary-core --test rule_token_seeds -- --ignored generate_rule_token_seeds > "$TMPDIR/g3.log" 2>&1; echo "exit=$?"` → exit=0.
Run: `git status --short core/fuzz/seeds/block_file` → exactly 15 new `??` files named `<token>__<shape>.bin`, and `golden.bin` unmodified.
Run: `cargo test --release --locked -p secretary-core --test rule_token_seeds > "$TMPDIR/t3.log" 2>&1; echo "exit=$?"; grep "test result" "$TMPDIR/t3.log"` → exit=0; `2 passed; 0 failed; 1 ignored`.

- [ ] **Step 6: Confirm the replay still passes with the new committed inputs**

`block_file` is still loosely compared at this point, so both decoders rejecting is agreement.
Run: `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay > "$TMPDIR/r3.log" 2>&1; echo "exit=$?"; grep "block_file:" "$TMPDIR/r3.log"` → exit=0, and the finish line reads `block_file: 16 of 16 input(s) compared, 16 committed`.

Then clippy (both spellings from Global Constraints) and `cargo fmt --all --check`, each exit=0.

- [ ] **Step 7: Commit**

```bash
git add core/tests/rule_token_seeds.rs core/tests/rule_token_seeds_helpers core/fuzz/seeds/block_file
git commit -F - <<'EOF'
Generate single-fault block_file seeds and bind each to its label (#641)

CI replays committed inputs only, and block_file held one, the
accepting golden.bin, so a strict token comparison on it would have
compared nothing in CI. Fifteen seeds now plant exactly one envelope
fault each into golden.bin: nine container faults, both version
sentinels, and sort plus repeat at the vector clock and the recipient
table.

File names are derived from each (token, shape) row. The non-ignored
check regenerates every row, requires the committed bytes to match,
requires the Rust decoder to name the file's token, and fails any
stray or missing labelled file. The generator asserts every row before
writing any. Section boundaries come from decode_header and
decode_recipient_table, not hand-counted offsets.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 4: Section RTS for `block_file`, and the Python envelope split

**Files:**
- Create: `core/tests/python/conformance_lib/sections/rule_token_seeds.py`
- Modify: `core/tests/python/conformance_lib/sections/registry.py`
- Modify: `core/tests/python/conformance_lib/fixtures.py`
- Create: `core/tests/python/conformance_lib/wire/envelope_rules.py`
- Modify: `core/tests/python/conformance_lib/wire/block_file.py`

**Interfaces:**
- Consumes: the 15 committed `block_file` seeds (Task 3); `conformance_lib.diff_replay.replay_bytes(target: str, data: bytes) -> Replay` (existing; `Replay.verdict` is a dict with `status`, `rule`, `error_class`, `detail`).
- Produces:
  - `fixtures.fuzz_seed_dir(target: str) -> Path`
  - `envelope_rules.UnsupportedEnvelopeVersion`, `envelope_rules.EnvelopeSortOrder`, `envelope_rules.EnvelopeRepeatedValue`, all subclasses of `cursor.ParseError`
  - `envelope_rules.check_ascending_distinct(ids: list[bytes], what: str, key: str) -> None`
  - `sections.rule_token_seeds.section_rule_token_seeds() -> tuple[bool, list[str]]`, with the module-level tables `_TARGETS` and `_TOKENED_CLASSES` that Task 9 extends

- [ ] **Step 1: Add the fixture anchor**

Append to `core/tests/python/conformance_lib/fixtures.py`:

```python


def fuzz_seed_dir(target: str) -> Path:
    """`core/fuzz/seeds/<target>/` -- the committed fuzz seeds.

    Hangs off `test_data_dir()` like every other path here: `parents[1]` of
    `core/tests/data` is `core`.
    """
    return test_data_dir().parents[1] / "fuzz" / "seeds" / target
```

- [ ] **Step 2: Write Section RTS (the failing test)**

Create `core/tests/python/conformance_lib/sections/rule_token_seeds.py`:

```python
"""Section RTS -- every committed single-fault seed for a token-compared
`block_file` or `record` target is rejected with the rule its file name
says, in this package as in Rust (#641).

WHAT THIS PINS.  `core/tests/rule_token_seeds.rs` generates one seed per
`(token, shape)` row, binds each committed file's BYTES to its row, and
requires the Rust decoder to name the file's token.  This section is the
Python half of the same binding: every `<token>__<shape>.bin` must be
REJECTED -- a verdict, never an `error` -- with exactly `<token>`, through
`diff_replay.replay_bytes`, the very function the differential replay's
worker calls.  So every committed seed is a strict cross-language comparison
in its own right, in the blocking `clean-room conformance` job, independent
of `differential_replay.rs`.

WHY IDENTITY TOO (check 1).  Label binding reaches only the classes some seed
exercises.  Section RTV's check 1 records why the expected token is written
out rather than read off the class: membership in the vocabulary is
satisfied by any of the seventeen.

WHY FLOORS (check 3) AND AN EXPECTED TOKEN SET (check 4).  An emptied
directory satisfies check 2 vacuously, and a directory whose seeds were all
relabelled onto one token satisfies checks 2 and 3.
"""

from __future__ import annotations

from pathlib import Path

from conformance_lib import fixtures
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.wire import envelope_rules

# Mirrors `rule_token_seeds_helpers::LABEL_SEPARATOR`.
LABEL_SEPARATOR = "__"

# Per target: the minimum number of committed labelled seeds, and the exact
# set of tokens those seeds must name between them.
_TARGETS: dict[str, tuple[int, frozenset[str]]] = {
    "block_file": (
        15,
        frozenset(
            {"container_malformed", "unsupported_version", "array_sort_order", "repeated_array_value"}
        ),
    ),
}

# Every typed class this slice adds, with the token written out.
_TOKENED_CLASSES: tuple[tuple[type, str], ...] = (
    (envelope_rules.UnsupportedEnvelopeVersion, "unsupported_version"),
    (envelope_rules.EnvelopeSortOrder, "array_sort_order"),
    (envelope_rules.EnvelopeRepeatedValue, "repeated_array_value"),
)


def _labelled_seeds(target: str) -> list[Path]:
    directory = fixtures.fuzz_seed_dir(target)
    return sorted(p for p in directory.iterdir() if p.is_file() and LABEL_SEPARATOR in p.name)


def _label_token(path: Path) -> str:
    return path.name.split(LABEL_SEPARATOR, 1)[0]


def _identity_issues() -> list[str]:
    issues = []
    for cls, want in _TOKENED_CLASSES:
        got = getattr(cls, "token", None)
        if got != want:
            issues.append(f"{cls.__name__} carries token {got!r}, this section expects {want!r}")
    return issues


def _seed_issues(target: str, floor: int, want_tokens: frozenset[str]) -> tuple[list[str], str]:
    try:
        seeds = _labelled_seeds(target)
    except OSError as exc:
        return [f"{target}: cannot list seeds: {type(exc).__name__}: {exc}"], f"{target}: unlisted"
    issues = []
    for path in seeds:
        want = _label_token(path)
        verdict = replay_bytes(target, path.read_bytes()).verdict
        if verdict.get("status") != "reject":
            issues.append(f"{target}/{path.name}: expected a rejection naming {want!r}, got {verdict}")
        elif verdict.get("rule") != want:
            issues.append(
                f"{target}/{path.name}: Python named {verdict.get('rule')!r}, the file name says "
                f"{want!r} ({verdict.get('error_class')}: {verdict.get('detail')})"
            )
    if len(seeds) < floor:
        issues.append(f"{target}: only {len(seeds)} labelled seeds, floor is {floor}")
    named = {_label_token(p) for p in seeds}
    if named != want_tokens:
        issues.append(
            f"{target}: the seeds name {sorted(named)}, this section expects {sorted(want_tokens)}"
        )
    return issues, f"{target}: {len(seeds)} labelled seeds covering {len(named)} tokens"


def section_rule_token_seeds() -> tuple[bool, list[str]]:
    issues = _identity_issues()
    lines = [f"PASS 1: {len(_TOKENED_CLASSES)} typed classes carry exactly their expected token"]
    for target, (floor, want_tokens) in _TARGETS.items():
        target_issues, summary = _seed_issues(target, floor, want_tokens)
        issues.extend(target_issues)
        lines.append(f"PASS 2-4: {summary}, each rejected with its file name's token")
    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
```

- [ ] **Step 3: Register it**

In `core/tests/python/conformance_lib/sections/registry.py`, add the import (keeping alphabetical order among the `sections.` imports):

```python
from conformance_lib.sections.rule_token_seeds import section_rule_token_seeds
```

and add this row immediately before the `# Last on purpose:` comment that precedes the `REG` row:

```python
    Section("RTS", "rule-token seeds are rejected with the rule their file names",
            " (#641)", section_rule_token_seeds),
```

- [ ] **Step 4: Create envelope_rules.py with the classes only, then run to verify it fails**

The section imports `envelope_rules`, so create `core/tests/python/conformance_lib/wire/envelope_rules.py` with the classes but WITHOUT `check_ascending_distinct` yet:

```python
"""Typed §6.1/§6.2 block-file envelope rejections carrying a rule token (#641).

Subclasses of `cursor.ParseError`, deliberately NOT of a new base: every
existing `except ParseError` in this package -- `sections/block_kat.py`,
`sections/revoke.py`, the golden-vault verifier -- keeps catching them, and
`conformance_lib.rejection` already admits `ParseError` as a verdict.
`ParseError` itself keeps `container_malformed` for every other envelope
fault.

Only distinctions `core/src/vault/block.rs` also draws are drawn here -- the
vocabulary's standing rule that a token may only draw a distinction both
implementations can make.  `manifest_file`'s envelope is untouched; #640 is
about why that one cannot be refined the same way.
"""

from __future__ import annotations

from conformance_lib.cursor import ParseError


class UnsupportedEnvelopeVersion(ParseError):
    """`format_version` or `suite_id` is not the v1 value."""

    token = "unsupported_version"


class EnvelopeSortOrder(ParseError):
    """A vector-clock or recipient table is out of ascending order."""

    token = "array_sort_order"


class EnvelopeRepeatedValue(ParseError):
    """A vector-clock or recipient table repeats an id."""

    token = "repeated_array_value"
```

Run: `cd /Users/hherb/src/secretary/.worktrees/token-compare-record-block && uv run core/tests/python/conformance.py > "$TMPDIR/p4.log" 2>&1; echo "exit=$?"; grep -E "^FAIL|ISSUE" "$TMPDIR/p4.log"`
Expected: exit=1; `FAIL: rule-token seeds are rejected with the rule their file names`, with an ISSUE for each of the 6 seeds `unsupported_version__*`, `array_sort_order__*` and `repeated_array_value__*` ("Python named 'container_malformed'"). Section REG passes at 31/31. No other section fails.

- [ ] **Step 5: Implement the split**

Append to `envelope_rules.py`:

```python


def check_ascending_distinct(ids: list[bytes], what: str, key: str) -> None:
    """Raise at the FIRST adjacent pair that is not strictly ascending.

    Classified the way `block.rs`'s `match w[0].cmp(&w[1])` classifies it:
    an equal pair is a repeat, a descending pair is disorder.  A merged
    `prev >= nxt` check could not tell the two apart, which is why this
    exists.  The disorder message is the one the merged check raised.
    """
    for index, (prev, nxt) in enumerate(zip(ids, ids[1:])):
        if prev == nxt:
            raise EnvelopeRepeatedValue(f"{what} repeat a {key} at positions {index} and {index + 1}")
        if prev > nxt:
            raise EnvelopeSortOrder(f"{what} not strictly ascending by {key}")
```

In `core/tests/python/conformance_lib/wire/block_file.py`, add the import after the `conformance_lib.cursor` import:

```python
from conformance_lib.wire.envelope_rules import UnsupportedEnvelopeVersion, check_ascending_distinct
```

Replace the `format_version` raise with:

```python
        raise UnsupportedEnvelopeVersion(f"unsupported format_version: 0x{format_version:04x}")
```

Replace the `suite_id` raise with:

```python
        raise UnsupportedEnvelopeVersion(f"unsupported suite_id: 0x{suite_id:04x}")
```

Replace the vector-clock loop (the comment line `# §6.1 strict invariant: ascending lexicographic by device_uuid, no dups.` and the two-statement `for prev, nxt in zip(vector_clock, vector_clock[1:]):` block under it) with:

```python
    # §6.1 strict invariant: ascending lexicographic by device_uuid, no dups.
    check_ascending_distinct([e.device_uuid for e in vector_clock], "vector_clock entries", "device_uuid")
```

Replace the recipient loop (the comment `# §6.2: ascending by fingerprint, no dups.` and its `for prev, nxt in zip(recipients, recipients[1:]):` block) with:

```python
    # §6.2: ascending by fingerprint, no dups.
    check_ascending_distinct([r.fingerprint for r in recipients], "recipient_entries", "fingerprint")
```

The disorder messages come out byte-identical: `"vector_clock entries not strictly ascending by device_uuid"` and `"recipient_entries not strictly ascending by fingerprint"`.

- [ ] **Step 6: Run to verify it passes**

Run: `uv run core/tests/python/conformance.py > "$TMPDIR/p4.log" 2>&1; echo "exit=$?"; grep -E "^FAIL|ISSUE|Section RTS|Section REG" -A2 "$TMPDIR/p4.log" | head -20`
Expected: exit=0; no FAIL line; RTS prints `PASS 2-4: block_file: 15 labelled seeds covering 4 tokens`; REG passes at 31/31.

Run the same-slice DRS confirmation too: DRS is one of the sections above, so the exit=0 already covers it.

- [ ] **Step 7: Commit**

```bash
git add core/tests/python/conformance_lib/fixtures.py core/tests/python/conformance_lib/sections/rule_token_seeds.py core/tests/python/conformance_lib/sections/registry.py core/tests/python/conformance_lib/wire/envelope_rules.py core/tests/python/conformance_lib/wire/block_file.py
git commit -F - <<'EOF'
Split the block envelope's sort and repeat checks, and bind block_file seeds in Python (#641)

wire/block_file.py checked both tables with one `prev >= nxt` and
raised the same ParseError (container_malformed) for disorder and for
a repeat, and for a bad format_version or suite_id. block.rs names
all of those separately. Three ParseError subclasses now carry
unsupported_version, array_sort_order and repeated_array_value, and
check_ascending_distinct classifies the first out-of-place pair the way
block.rs's match cmp does. Every existing `except ParseError` still
catches them, and the disorder messages are byte-identical.

New Section RTS is the Python half of the seed label binding: every
committed <token>__<shape>.bin must be rejected through replay_bytes
with exactly its file name's token, plus an identity check per class, a
seed-count floor and an expected token set. Before the split it reds
on the six version, sort and repeat seeds. REG 30 -> 31.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 5: Token-compare `block_file`

**Files:**
- Modify: `core/tests/differential_replay_helpers/rust_decoder.rs` (`"block_file"` arm)
- Modify: `core/tests/differential_replay_helpers/targets.rs` (both lists, their docs, the `MIN_CORPUS_INPUTS` row)
- Modify: `core/tests/differential_replay_helpers/agreement.rs` (one new test)

**Interfaces:**
- Consumes: `BlockError::rule_token` (Task 2); `PHASE_DEPENDENT_TOLERANCE_TARGETS` (Task 1); the 16 committed `block_file` inputs (Task 3).

- [ ] **Step 1: Write the failing test**

In `agreement.rs`'s `mod tests`, add:

```rust
    /// The tolerance is per TARGET (#641). A pair that agrees on
    /// `manifest_body` because one token is phase-dependent is a disagreement
    /// on a compared target the licence does not reach: a `block_file` sort
    /// check mis-reported as a malformed container must red.
    #[test]
    fn a_phase_dependent_pair_on_an_unlicensed_compared_target_disagrees() {
        const UNLICENSED: &str = "block_file";
        assert!(TOKEN_COMPARED_TARGETS.contains(&UNLICENSED));
        assert!(matches!(
            judge(
                UNLICENSED,
                &rust_err(Some("array_sort_order")),
                &py_reject(Some("container_malformed"))
            ),
            Judgement::Disagree(_)
        ));
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay a_phase_dependent_pair_on_an_unlicensed > "$TMPDIR/t5.log" 2>&1; echo "exit=$?"; grep -E "test result|panicked" "$TMPDIR/t5.log"`
Expected: exit=101; the first `assert!` panics because `block_file` is not yet compared.

- [ ] **Step 3: Implement**

In `rust_decoder.rs`, change the `"block_file"` arm's `token: None,` to `token: Some(e.rule_token().as_str()),`.

In `targets.rs`, set:

```rust
pub const TOKEN_COMPARED_TARGETS: &[&str] = &["manifest_body", "block_file"];
```

and remove `"block_file"` from `NOT_TOKEN_COMPARED_TARGETS`. Replace the paragraph of `TOKEN_COMPARED_TARGETS`'s doc that begins `/// `manifest_body` and nothing else.` (through the end of that paragraph) with:

```rust
/// `manifest_body` (#634) and `block_file` (#641). `block_file` needed no
/// decoder change: both implementations walk the §6.1 layout in the same
/// order, and #641 split Python's merged sort/repeat check. `record` follows
/// once its Python decoder reports in Rust's phase order. `contact_card`,
/// `bundle_file` and `vault_toml` each still need their own taxonomy (#641);
/// `manifest_file` is blocked for a different, measured reason (#640) —
/// Rust's header raises `UnsupportedFormatVersion` where Python raises the
/// same `ParseError` it raises for every envelope fault, and because that
/// variant is shared with the BODY sentinel check no per-variant token can
/// reconcile the two.
```

In `MIN_CORPUS_INPUTS`, change `("block_file", 1),` to `("block_file", 16),`.

- [ ] **Step 4: Run the CI-shape replay**

Run: `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay > "$TMPDIR/r5.log" 2>&1; echo "exit=$?"; grep -E "test result|block_file:" "$TMPDIR/r5.log"`
Expected: exit=0; `44 passed`; `block_file: 16 of 16 input(s) compared, 16 committed`.

- [ ] **Step 5: Run the full runtime corpus locally (measurement, recorded for the handoff)**

```bash
cd /Users/hherb/src/secretary/.worktrees/token-compare-record-block
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay -- differential_replay_full_corpus > "$TMPDIR/full5.log" 2>&1; echo "exit=$?"
grep -E "\[differential_replay\] .*compared|test result|disagreements \(" "$TMPDIR/full5.log"
rm core/fuzz/corpus && git status --short | grep -c corpus
```

Expected: exit=0; the `block_file` finish line reports 133 inputs compared (117 runtime + 16 committed); the final `grep -c` prints `0`. If `block_file` disagrees on any runtime input, STOP: it is a mapping bug or a genuine finding. Record the pair, resolve it explicitly, and never allowlist it. Copy every finish line into the scratchpad file `measurements.md`, for the handoff.

- [ ] **Step 6: Commit**

```bash
git add core/tests/differential_replay_helpers/rust_decoder.rs core/tests/differential_replay_helpers/targets.rs core/tests/differential_replay_helpers/agreement.rs
git commit -F - <<'EOF'
Token-compare block_file in the differential replay (#641)

block_file joins manifest_body in TOKEN_COMPARED_TARGETS, and compares
STRICTLY: the phase-dependent licence is manifest_body's alone, so a
new test pins that a sort-order token against container_malformed on
block_file is a disagreement. Its committed floor rises 1 -> 16, and
since no pair is tolerated on this target, every rejecting committed
input is a strict comparison (#658's concern, for this target).

Measured locally over the runtime corpus plus the committed seeds:
all block_file inputs agree.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

- [ ] **Step 7: Negative control through the real gate (after the commit; the harness mutates a clean tree)**

Write `$SCRATCH/t5-control.toml`, where `SCRATCH=/private/tmp/claude-501/-Users-hherb-src-secretary/5edf5da6-dc60-434f-a442-bf719640e844/scratchpad`:

```toml
[[mutation]]
id = "BF1"
lang = "python"
path = "core/tests/python/conformance_lib/wire/envelope_rules.py"
old = 'token = "repeated_array_value"'
new = 'token = "array_sort_order"'
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "Python names a repeat as disorder; strict on block_file, it would have been tolerated before target-awareness"
probe = { module = "conformance_lib.wire.envelope_rules", expr = "EnvelopeRepeatedValue.token", equals = "array_sort_order", syspath = "core/tests/python" }
```

Run: `uv run --with cbor2 scripts/mutate.py "$SCRATCH/t5-control.toml" > "$SCRATCH/t5-control.out" 2>&1; echo "exit=$?"; cat "$SCRATCH/t5-control.out" | tail -8; git status --short`
Expected: exit=0; row `BF1 … RED_AS_EXPECTED`; `git status --short` prints nothing (the harness restored the tree). Paste the table row into `measurements.md`.

---

### Task 6: The Rust byte-level walk, wired into `record::decode`

**Files:**
- Create: `core/src/cbor/well_formed.rs`
- Create: `core/src/cbor/well_formed/tests.rs`
- Modify: `core/src/cbor/mod.rs` (declare + re-export)
- Modify: `core/src/vault/record.rs` (`decode` wiring, a private mapping fn, one import line)
- Create: `core/src/vault/record_walk_tests.rs`
- Modify: `core/src/vault/mod.rs` (declare the `#[cfg(test)]` module)

**Interfaces:**
- Produces:
  - `pub(crate) fn crate::cbor::walk_first_item(bytes: &[u8]) -> Result<usize, WalkFault>`
  - `pub(crate) enum crate::cbor::WalkFault { Malformed(CborFault), Tag { offset: usize }, Float { offset: usize } }`, deriving `Debug, Clone, Copy, PartialEq, Eq`
- Measured behaviour this task pins (probe, 2026-09-15, on today's `record::decode`):

| Input | Today's error |
|---|---|
| `a1 f7 f7` | `NonTextKey` (ciborium reads `undefined` as `null`) |
| `c2 41 61` | `NotAMap` (ciborium turns the bignum into an integer) |
| `a1 7f 7f 61 61 ff ff 00` | `MissingField` (ciborium accepts the nested chunk) |
| `a1 7f 61 c3 61 a9 ff 00` | `CborDecode(Syntax, offset 2)` (ciborium validates UTF-8 per chunk) |

- [ ] **Step 1: Write the walk's unit tests (they will not compile yet)**

Create `core/src/cbor/well_formed/tests.rs`:

```rust
//! Unit coverage for the byte-level walk. Python's twin is conformance
//! Section WF; the two are kept case for case.

use super::{walk_first_item, WalkFault};
use crate::cbor::{CborErrorKind, CborFault};

// RFC 8949 initial bytes, named so each case reads as the shape it plants.
const UINT_0: u8 = 0x00;
const UINT_INDEFINITE: u8 = 0x1f;
const RESERVED_AI_28: u8 = 0x1c;
const BYTES_1: u8 = 0x41;
const BYTES_FOUR_BYTE_LENGTH: u8 = 0x5a;
const TEXT_1: u8 = 0x61;
const TEXT_3: u8 = 0x63;
const TEXT_INDEFINITE: u8 = 0x7f;
const ARRAY_1: u8 = 0x81;
const ARRAY_2: u8 = 0x82;
const ARRAY_INDEFINITE: u8 = 0x9f;
const MAP_1: u8 = 0xa1;
const MAP_INDEFINITE: u8 = 0xbf;
const TAG_1: u8 = 0xc1;
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
const SIMPLE_16: u8 = 0xf0;
const FALSE: u8 = 0xf4;
const TRUE: u8 = 0xf5;
const NULL: u8 = 0xf6;
const UNDEFINED: u8 = 0xf7;
const SIMPLE_ONE_BYTE: u8 = 0xf8;
const FLOAT16: u8 = 0xf9;
const BREAK_BYTE: u8 = 0xff;
const ASCII_A: u8 = b'a';
const INVALID_UTF8: u8 = 0xff;
const UTF8_TWO_BYTE_LEAD: u8 = 0xc3;
const UTF8_CONTINUATION: u8 = 0xa9;
/// A one-byte simple-value argument: 32 is the first value RFC 8949 allows in that form.
const SIMPLE_ARG_32: u8 = 0x20;
/// Deeper than ciborium's recursion limit (256), which the walk does not share.
const DEPTH_BEYOND_CIBORIUM_LIMIT: usize = 300;

fn io(offset: usize) -> WalkFault {
    WalkFault::Malformed(CborFault {
        kind: CborErrorKind::Io,
        offset: Some(offset),
    })
}

fn syntax(offset: usize) -> WalkFault {
    WalkFault::Malformed(CborFault {
        kind: CborErrorKind::Syntax,
        offset: Some(offset),
    })
}

#[test]
fn a_well_formed_item_returns_the_offset_one_past_it() {
    assert_eq!(walk_first_item(&[UINT_0]), Ok(1));
    for simple in [FALSE, TRUE, NULL] {
        assert_eq!(walk_first_item(&[simple]), Ok(1));
    }
    assert_eq!(walk_first_item(&[TEXT_1, ASCII_A]), Ok(2));
    assert_eq!(walk_first_item(&[MAP_1, TEXT_1, ASCII_A, UINT_0]), Ok(4));
    assert_eq!(
        walk_first_item(&[MAP_INDEFINITE, TEXT_1, ASCII_A, UINT_0, BREAK_BYTE]),
        Ok(5)
    );
    assert_eq!(
        walk_first_item(&[TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK_BYTE]),
        Ok(4)
    );
}

#[test]
fn only_the_first_item_is_walked() {
    assert_eq!(walk_first_item(&[UINT_0, UNDEFINED]), Ok(1));
}

#[test]
fn running_out_of_input_is_an_io_fault() {
    assert_eq!(walk_first_item(&[]), Err(io(0)));
    assert_eq!(walk_first_item(&[TEXT_3, ASCII_A]), Err(io(0)));
    assert_eq!(walk_first_item(&[MAP_1, TEXT_1]), Err(io(1)));
    assert_eq!(walk_first_item(&[ARRAY_INDEFINITE, UINT_0]), Err(io(2)));
    assert_eq!(walk_first_item(&[FLOAT16, UINT_0]), Err(io(0)));
    let mut overrun = vec![BYTES_FOUR_BYTE_LENGTH];
    overrun.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(walk_first_item(&overrun), Err(io(0)));
}

#[test]
fn reserved_additional_info_and_misplaced_indefinite_forms_are_syntax_faults() {
    assert_eq!(walk_first_item(&[RESERVED_AI_28]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[UINT_INDEFINITE]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[BREAK_BYTE]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[ARRAY_1, BREAK_BYTE]), Err(syntax(1)));
}

#[test]
fn undefined_and_unassigned_simple_values_are_malformed() {
    assert_eq!(walk_first_item(&[UNDEFINED]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[SIMPLE_16]), Err(syntax(0)));
    assert_eq!(walk_first_item(&[SIMPLE_ONE_BYTE, SIMPLE_ARG_32]), Err(syntax(0)));
}

#[test]
fn a_nested_indefinite_chunk_is_malformed() {
    let nested = [TEXT_INDEFINITE, TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK_BYTE, BREAK_BYTE];
    assert_eq!(walk_first_item(&nested), Err(syntax(1)));
}

#[test]
fn a_chunk_of_another_major_type_is_malformed() {
    let mixed = [TEXT_INDEFINITE, BYTES_1, ASCII_A, BREAK_BYTE];
    assert_eq!(walk_first_item(&mixed), Err(syntax(1)));
}

#[test]
fn invalid_utf8_is_malformed_in_a_string_and_in_a_chunk() {
    assert_eq!(walk_first_item(&[TEXT_1, INVALID_UTF8]), Err(syntax(0)));
    let chunked = [TEXT_INDEFINITE, TEXT_1, INVALID_UTF8, BREAK_BYTE];
    assert_eq!(walk_first_item(&chunked), Err(syntax(1)));
}

/// RFC 8949 §3.2.3 makes each chunk a text string in its own right, so a
/// sequence split across two chunks is invalid. ciborium agrees: measured
/// on 2026-09-15, it rejects the same bytes as `Syntax` at the first chunk.
#[test]
fn a_utf8_sequence_split_across_chunks_is_malformed() {
    let split = [
        TEXT_INDEFINITE,
        TEXT_1,
        UTF8_TWO_BYTE_LEAD,
        TEXT_1,
        UTF8_CONTINUATION,
        BREAK_BYTE,
    ];
    assert_eq!(walk_first_item(&split), Err(syntax(1)));
}

#[test]
fn a_tag_of_any_number_is_rule_four() {
    assert_eq!(walk_first_item(&[TAG_1, UINT_0]), Err(WalkFault::Tag { offset: 0 }));
    assert_eq!(
        walk_first_item(&[TAG_BIGNUM_POSITIVE, BYTES_1, ASCII_A]),
        Err(WalkFault::Tag { offset: 0 })
    );
}

#[test]
fn a_float_is_rule_four() {
    assert_eq!(
        walk_first_item(&[FLOAT16, UINT_0, UINT_0]),
        Err(WalkFault::Float { offset: 0 })
    );
}

#[test]
fn well_formedness_outranks_rule_four_anywhere_in_the_item() {
    assert_eq!(walk_first_item(&[ARRAY_2, TAG_1, UINT_0, UNDEFINED]), Err(syntax(3)));
    assert_eq!(walk_first_item(&[ARRAY_2, UNDEFINED, TAG_1, UINT_0]), Err(syntax(1)));
}

#[test]
fn the_first_rule_four_fault_is_the_one_reported() {
    let both = [ARRAY_2, FLOAT16, UINT_0, UINT_0, TAG_1, UINT_0];
    assert_eq!(walk_first_item(&both), Err(WalkFault::Float { offset: 1 }));
}

#[test]
fn an_indefinite_map_cannot_end_between_a_key_and_its_value() {
    let half = [MAP_INDEFINITE, TEXT_1, ASCII_A, BREAK_BYTE];
    assert_eq!(walk_first_item(&half), Err(syntax(3)));
}

#[test]
fn nesting_has_no_depth_cap_of_its_own() {
    let mut deep = vec![ARRAY_1; DEPTH_BEYOND_CIBORIUM_LIMIT];
    deep.push(UINT_0);
    assert_eq!(walk_first_item(&deep), Ok(DEPTH_BEYOND_CIBORIUM_LIMIT + 1));
}
```

- [ ] **Step 2: Write the walk**

Create `core/src/cbor/well_formed.rs`:

```rust
//! A byte-level walk over the first CBOR item: well-formedness first, then
//! crypto-design §6.2 rule 4 (#641).
//!
//! **Why it exists.** ciborium's `Value` reader is laxer than RFC 8949 and than
//! `docs/vault-format.md` §4.2's well-formedness list in three ways, measured
//! over the fuzz corpus: it reads `undefined` (`0xf7`) as `null`, it turns
//! bignum tags 2 and 3 into integers so a later parsed-tree rule-4 walk never
//! sees the tag, and it accepts nested indefinite-length string chunks. None of
//! those changes whether a record is accepted — none of the forms is canonical,
//! so the re-encode comparison rejects them all — but each changes WHICH error
//! is reported, and `core/tests/differential_replay.rs` compares that against
//! `conformance.py`. Walking the bytes before ciborium reports what the bytes
//! actually are.
//!
//! **What it checks.** RFC 8949 well-formedness plus §4.2's precondition list:
//! a truncated head, argument or payload; reserved additional-info 28-30; the
//! indefinite form on majors 0, 1 and 6; a break outside an indefinite
//! container; an indefinite-string chunk that is not a definite string of the
//! same major (§3.2.3); text that is not valid UTF-8, per string and per chunk;
//! a major-7 simple value other than false/true/null. Then rule 4: any tag
//! (bignum tags included) and any float.
//!
//! **Precedence.** A well-formedness fault anywhere in the item outranks a
//! rule-4 fault anywhere: the first tag or float is remembered and reported only
//! once the whole item has proven well-formed.
//!
//! **Iterative.** An explicit stack, no recursion and no depth cap of its own.
//! ciborium's recursion limit still applies to the parse that follows; that
//! residual is filed, not fixed here.
//!
//! **Pure.** It reads a byte slice and allocates only its container stack;
//! nothing it holds is a copy of a payload.
//!
//! Python's twin is `conformance_lib/codec/well_formed.py`'s `walk_body`.

use crate::cbor::{CborErrorKind, CborFault};

/// Why [`walk_first_item`] stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum WalkFault {
    /// Not well-formed CBOR. The kind is `Io` when the input ended first,
    /// `Syntax` otherwise; the offset is that of the offending head.
    Malformed(CborFault),
    /// §6.2 rule 4: a tag, at `offset`.
    Tag { offset: usize },
    /// §6.2 rule 4: a float, at `offset`.
    Float { offset: usize },
}

const MAJOR_SHIFT: u8 = 5;
const AI_MASK: u8 = 0x1f;
const MAJOR_UINT: u8 = 0;
const MAJOR_NINT: u8 = 1;
const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;
const MAJOR_ARRAY: u8 = 4;
const MAJOR_MAP: u8 = 5;
const MAJOR_TAG: u8 = 6;
/// The largest additional-info value that is itself the argument.
const AI_DIRECT_MAX: u8 = 23;
const AI_ONE_BYTE: u8 = 24;
const AI_TWO_BYTES: u8 = 25;
const AI_FOUR_BYTES: u8 = 26;
const AI_EIGHT_BYTES: u8 = 27;
const AI_INDEFINITE: u8 = 31;
const SIMPLE_FALSE: u8 = 20;
const SIMPLE_TRUE: u8 = 21;
const SIMPLE_NULL: u8 = 22;
/// For major 7, additional-info 25/26/27 is a half/single/double float.
const AI_FLOAT16: u8 = AI_TWO_BYTES;
const AI_FLOAT32: u8 = AI_FOUR_BYTES;
const AI_FLOAT64: u8 = AI_EIGHT_BYTES;
const BREAK: u8 = 0xff;
const BITS_PER_BYTE: u32 = 8;
/// A map's items are keys and values.
const ITEMS_PER_MAP_ENTRY: u64 = 2;

struct Head {
    major: u8,
    ai: u8,
    /// `None` for the indefinite form.
    arg: Option<u64>,
    len: usize,
}

/// An open container.
enum Frame {
    /// A definite array or map, or a tag's single content item, with `left`
    /// items still to read (a map counts keys and values).
    Definite { left: u64 },
    IndefiniteArray,
    /// `mid_entry` is true after a key and before its value.
    IndefiniteMap { mid_entry: bool },
}

fn end_of_input(offset: usize) -> CborFault {
    CborFault {
        kind: CborErrorKind::Io,
        offset: Some(offset),
    }
}

fn syntax(offset: usize) -> CborFault {
    CborFault {
        kind: CborErrorKind::Syntax,
        offset: Some(offset),
    }
}

fn read_head(bytes: &[u8], at: usize) -> Result<Head, CborFault> {
    let Some(&initial) = bytes.get(at) else {
        return Err(end_of_input(at));
    };
    let major = initial >> MAJOR_SHIFT;
    let ai = initial & AI_MASK;
    let arg_len = match ai {
        0..=AI_DIRECT_MAX => {
            return Ok(Head {
                major,
                ai,
                arg: Some(u64::from(ai)),
                len: 1,
            })
        }
        AI_ONE_BYTE => 1,
        AI_TWO_BYTES => 2,
        AI_FOUR_BYTES => 4,
        AI_EIGHT_BYTES => 8,
        AI_INDEFINITE => {
            // RFC 8949 §3.2: valid for strings, arrays and maps, and for
            // major 7 it is the break code. Never for integers or tags.
            return if matches!(major, MAJOR_UINT | MAJOR_NINT | MAJOR_TAG) {
                Err(syntax(at))
            } else {
                Ok(Head {
                    major,
                    ai,
                    arg: None,
                    len: 1,
                })
            };
        }
        _ => return Err(syntax(at)),
    };
    let Some(arg_bytes) = bytes.get(at + 1..at + 1 + arg_len) else {
        return Err(end_of_input(at));
    };
    let arg = arg_bytes
        .iter()
        .fold(0u64, |acc, byte| (acc << BITS_PER_BYTE) | u64::from(*byte));
    Ok(Head {
        major,
        ai,
        arg: Some(arg),
        len: 1 + arg_len,
    })
}

/// The offset one past a string payload of `len` bytes starting at `start`,
/// checking UTF-8 for text. Faults are reported at the string's head.
fn payload_end(
    bytes: &[u8],
    head_at: usize,
    start: usize,
    len: u64,
    text: bool,
) -> Result<usize, CborFault> {
    let end = usize::try_from(len)
        .ok()
        .and_then(|len| start.checked_add(len));
    let Some(content) = end.and_then(|end| bytes.get(start..end)) else {
        return Err(end_of_input(head_at));
    };
    if text && std::str::from_utf8(content).is_err() {
        return Err(syntax(head_at));
    }
    Ok(start + content.len())
}

/// The offset one past the string whose head is at `head_at`.
fn string_end(bytes: &[u8], head_at: usize, head: &Head) -> Result<usize, CborFault> {
    let text = head.major == MAJOR_TEXT;
    let start = head_at + head.len;
    let Some(len) = head.arg else {
        return chunks_end(bytes, start, head.major, text);
    };
    payload_end(bytes, head_at, start, len, text)
}

/// The offset one past the break that ends an indefinite string's chunks.
fn chunks_end(bytes: &[u8], mut at: usize, major: u8, text: bool) -> Result<usize, CborFault> {
    loop {
        match bytes.get(at) {
            None => return Err(end_of_input(at)),
            Some(&BREAK) => return Ok(at + 1),
            Some(_) => {
                let chunk = read_head(bytes, at)?;
                // §3.2.3: every chunk is a DEFINITE string of the same major.
                if chunk.major != major || chunk.arg.is_none() {
                    return Err(syntax(at));
                }
                at = string_end(bytes, at, &chunk)?;
            }
        }
    }
}

/// Close every container whose items are complete, or whose break is next.
fn close_finished_containers(
    bytes: &[u8],
    pos: &mut usize,
    stack: &mut Vec<Frame>,
) -> Result<(), CborFault> {
    loop {
        let at_break = bytes.get(*pos) == Some(&BREAK);
        match stack.last() {
            Some(Frame::Definite { left: 0 }) => {
                stack.pop();
            }
            Some(Frame::IndefiniteArray) if at_break => {
                stack.pop();
                *pos += 1;
            }
            Some(Frame::IndefiniteMap { mid_entry }) if at_break => {
                if *mid_entry {
                    return Err(syntax(*pos));
                }
                stack.pop();
                *pos += 1;
            }
            _ => return Ok(()),
        }
    }
}

/// Account for one item about to be read inside `parent`.
fn count_one_item(parent: Option<&mut Frame>) {
    match parent {
        Some(Frame::Definite { left }) => *left -= 1,
        Some(Frame::IndefiniteMap { mid_entry }) => *mid_entry = !*mid_entry,
        Some(Frame::IndefiniteArray) | None => {}
    }
}

fn open_container(head: &Head) -> Frame {
    match (head.major, head.arg) {
        (MAJOR_ARRAY, Some(count)) => Frame::Definite { left: count },
        (_, Some(count)) => Frame::Definite {
            left: count.saturating_mul(ITEMS_PER_MAP_ENTRY),
        },
        (MAJOR_ARRAY, None) => Frame::IndefiniteArray,
        (_, None) => Frame::IndefiniteMap { mid_entry: false },
    }
}

/// Walk the first CBOR item in `bytes`; return the offset one past it.
///
/// See the module doc for what is checked and in what precedence.
pub(crate) fn walk_first_item(bytes: &[u8]) -> Result<usize, WalkFault> {
    let mut pos = 0usize;
    let mut stack: Vec<Frame> = Vec::new();
    let mut first_rule4: Option<WalkFault> = None;
    let mut started = false;
    loop {
        close_finished_containers(bytes, &mut pos, &mut stack).map_err(WalkFault::Malformed)?;
        if started && stack.is_empty() {
            return match first_rule4 {
                Some(fault) => Err(fault),
                None => Ok(pos),
            };
        }
        started = true;
        count_one_item(stack.last_mut());
        let head = read_head(bytes, pos).map_err(WalkFault::Malformed)?;
        match head.major {
            MAJOR_UINT | MAJOR_NINT => pos += head.len,
            MAJOR_BYTES | MAJOR_TEXT => {
                pos = string_end(bytes, pos, &head).map_err(WalkFault::Malformed)?;
            }
            MAJOR_ARRAY | MAJOR_MAP => {
                pos += head.len;
                stack.push(open_container(&head));
            }
            MAJOR_TAG => {
                first_rule4.get_or_insert(WalkFault::Tag { offset: pos });
                pos += head.len;
                stack.push(Frame::Definite { left: 1 });
            }
            _ => {
                match head.ai {
                    SIMPLE_FALSE | SIMPLE_TRUE | SIMPLE_NULL => {}
                    AI_FLOAT16 | AI_FLOAT32 | AI_FLOAT64 => {
                        first_rule4.get_or_insert(WalkFault::Float { offset: pos });
                    }
                    // `undefined`, every unassigned simple value, the one-byte
                    // simple form, and a break outside an indefinite container.
                    _ => return Err(WalkFault::Malformed(syntax(pos))),
                }
                pos += head.len;
            }
        }
    }
}

#[cfg(test)]
mod tests;
```

In `core/src/cbor/mod.rs`, directly after the line `mod scratch;` (and its following `pub(crate) use` line, if any), add:

```rust
// The byte-level well-formedness and rule-4 walk `record::decode` runs before
// ciborium (#641). `pub(crate)`, like `from_secret_reader`.
mod well_formed;

pub(crate) use well_formed::{walk_first_item, WalkFault};
```

- [ ] **Step 3: Run the walk tests**

`walk_first_item` has no production caller until Step 5, so check with `cargo test` only, not clippy, at this step.
Run: `cargo test --release --locked -p secretary-core --lib cbor::well_formed > "$TMPDIR/t6a.log" 2>&1; echo "exit=$?"; grep -E "test result|FAILED|panicked" "$TMPDIR/t6a.log"`
Expected: exit=0; `15 passed`. A failure means the implementation and the expected offset disagree. Re-derive the offset by hand from the module doc's rules before changing either side, and never loosen an assertion to `is_err()`.

- [ ] **Step 4: Write the acceptance-equality tests (failing: `decode` does not walk yet)**

In `core/src/vault/mod.rs`, directly after the `mod rule_tokens;` line added in Task 2, add:

```rust
#[cfg(test)]
mod record_walk_tests;
```

Create `core/src/vault/record_walk_tests.rs`:

```rust
//! The byte-level walk `record::decode` runs first (#641) changes WHICH error a
//! rejected record reports and never WHETHER a record is accepted.
//!
//! `legacy_decode` is the pre-#641 pipeline, step for step: parse, rule-4 walk
//! over the parsed tree, interpret, re-encode and compare. Why the claim holds:
//! a legacy accept requires the input to be byte-identical to this crate's
//! canonical re-encoding, which never emits a tag, a float, `undefined`, an
//! indefinite item or invalid UTF-8, so no input the walk rejects was ever
//! accepted. The property test checks that argument rather than trusting it.

use proptest::prelude::*;

use crate::cbor::{from_secret_reader, SecretValueTree};
use crate::vault::canonical::reject_floats_and_tags;
use crate::vault::record::{decode, decode_value, encode, Record, RecordError};

/// A canonical record every mutation starts from.
const LOGIN_RECORD: &[u8] = include_bytes!("../../fuzz/seeds/record/login.cbor");
/// Mutations per case: few enough that most inputs stay near a valid record,
/// where acceptance can actually differ.
const MAX_MUTATIONS: usize = 3;
/// More cases than proptest's default 256: each is cheap, and the inputs that
/// could tell the pipelines apart are rare.
const PROPTEST_CASES: u32 = 4096;

// RFC 8949 bytes for the three measured ciborium leniencies.
const MAP_1: u8 = 0xa1;
const UNDEFINED: u8 = 0xf7;
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
const BYTES_1: u8 = 0x41;
const TEXT_1: u8 = 0x61;
const TEXT_INDEFINITE: u8 = 0x7f;
const BREAK: u8 = 0xff;
const UINT_0: u8 = 0x00;
const ASCII_A: u8 = b'a';

fn legacy_decode(bytes: &[u8]) -> Result<Record, RecordError> {
    let parsed = from_secret_reader(bytes).map_err(RecordError::CborDecode)?;
    let parsed = SecretValueTree::new(parsed);
    reject_floats_and_tags(parsed.as_value(), "<root>")?;
    let record = decode_value(parsed.as_value())?;
    let re_encoded = encode(&record)?;
    if re_encoded.expose() != bytes {
        return Err(RecordError::NonCanonicalEncoding);
    }
    Ok(record)
}

#[derive(Debug, Clone)]
enum Mutation {
    Overwrite { at: usize, byte: u8 },
    Insert { at: usize, byte: u8 },
    Truncate { len: usize },
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Overwrite { at, byte }),
        (any::<usize>(), any::<u8>()).prop_map(|(at, byte)| Mutation::Insert { at, byte }),
        any::<usize>().prop_map(|len| Mutation::Truncate { len }),
    ]
}

fn apply(bytes: &mut Vec<u8>, mutation: &Mutation) {
    match *mutation {
        Mutation::Overwrite { at, byte } if !bytes.is_empty() => {
            let i = at % bytes.len();
            bytes[i] = byte;
        }
        Mutation::Insert { at, byte } => {
            let i = at % (bytes.len() + 1);
            bytes.insert(i, byte);
        }
        Mutation::Truncate { len } => bytes.truncate(len % (bytes.len() + 1)),
        Mutation::Overwrite { .. } => {}
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    #[test]
    fn the_walk_never_changes_whether_a_record_is_accepted(
        mutations in proptest::collection::vec(mutation(), 0..=MAX_MUTATIONS)
    ) {
        let mut bytes = LOGIN_RECORD.to_vec();
        for m in &mutations {
            apply(&mut bytes, m);
        }
        prop_assert_eq!(legacy_decode(&bytes).is_ok(), decode(&bytes).is_ok());
    }
}

#[test]
fn the_unmutated_seed_is_accepted_by_both() {
    assert!(legacy_decode(LOGIN_RECORD).is_ok());
    assert!(decode(LOGIN_RECORD).is_ok());
}

/// Each measured leniency is rejected by BOTH pipelines, and only the walk
/// names what the bytes actually are. The `legacy` arms pin ciborium's
/// behaviour as measured on 2026-09-15; if a ciborium bump changes one, this
/// test says so before the differential replay does.
#[test]
fn each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk() {
    let undefined_key = [MAP_1, UNDEFINED, UNDEFINED];
    assert!(matches!(legacy_decode(&undefined_key), Err(RecordError::NonTextKey)));
    assert!(matches!(decode(&undefined_key), Err(RecordError::CborDecode(_))));

    let bignum = [TAG_BIGNUM_POSITIVE, BYTES_1, ASCII_A];
    assert!(matches!(legacy_decode(&bignum), Err(RecordError::NotAMap)));
    assert!(matches!(decode(&bignum), Err(RecordError::TagRejected)));

    let nested_chunk_key = [MAP_1, TEXT_INDEFINITE, TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK, BREAK, UINT_0];
    assert!(matches!(
        legacy_decode(&nested_chunk_key),
        Err(RecordError::MissingField { .. })
    ));
    assert!(matches!(decode(&nested_chunk_key), Err(RecordError::CborDecode(_))));
}
```

Run: `cargo test --release --locked -p secretary-core --lib record_walk_tests > "$TMPDIR/t6b.log" 2>&1; echo "exit=$?"; grep -E "test result|panicked|error\[" "$TMPDIR/t6b.log"`
Expected: exit=101. `each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk` fails on its first `decode(...)` assertion (today `decode` reports `NonTextKey`); the other two pass. If instead a `use` fails to resolve, check the real path: `decode_value` is `pub(crate)` in `record.rs`, `reject_floats_and_tags` is reached through `crate::vault::canonical`, and `from_secret_reader` through `crate::cbor`.

- [ ] **Step 5: Wire the walk into `record::decode`**

In `core/src/vault/record.rs`, change `use crate::cbor::{classify_ser, CborFault, SecretValueTree};` to:

```rust
use crate::cbor::{classify_ser, walk_first_item, CborFault, SecretValueTree, WalkFault};
```

In `pub fn decode`, insert this as the FIRST statement of the body, before the `// `from_secret_reader`, not `from_reader` (#561)` comment:

```rust
    // Byte-level well-formedness, then crypto-design §6.2 rule 4, BEFORE
    // ciborium (#641). ciborium reads `undefined` as `null`, turns bignum tags
    // into integers and accepts nested indefinite chunks. Every such input is
    // still rejected below, by the re-encode at the latest, so this changes
    // which error is reported, never whether a record is accepted —
    // `record_walk_tests` checks that.
    walk_first_item(bytes).map_err(walk_fault_to_record_error)?;
```

Update `decode`'s doc list so its first two items read:

```rust
/// 1. The bytes are well-formed CBOR, and carry no tag or float, checked on
///    the raw bytes before any parse (#641).
/// 2. Top-level item is a map.
```

and renumber the remaining items 3–8, keeping their text.

After the comment block that follows `decode` (the `// `reject_floats_and_tags` lives in …` comment), add:

```rust
/// Map a byte-walk fault onto the variant this decoder has always reported
/// for the same condition (#641): no new variant, no new message.
fn walk_fault_to_record_error(fault: WalkFault) -> RecordError {
    match fault {
        WalkFault::Malformed(fault) => RecordError::CborDecode(fault),
        WalkFault::Tag { .. } => RecordError::TagRejected,
        WalkFault::Float { .. } => RecordError::FloatRejected { field: "<root>" },
    }
}
```

In the existing comment above `reject_floats_and_tags(parsed.as_value(), "<root>")?;`, append:

```rust
    // Since #641 the byte walk above answers first for every tag and float
    // ciborium would still represent; this stays as defence in depth.
```

- [ ] **Step 6: Run to verify it passes**

Run: `cargo test --release --locked -p secretary-core --lib > "$TMPDIR/t6.log" 2>&1; echo "exit=$?"; grep -E "test result|FAILED" "$TMPDIR/t6.log"`
Expected: exit=0, including the three `record_walk_tests` tests and the 15 walk tests. Existing `record.rs` tests that assert an exact error for a malformed, tagged or float input must still pass: the mapping keeps their variants.

If an existing test now fails, read it. A test asserting `RecordError::NonTextKey` or `NotAMap` for a body carrying `undefined`, a bignum or a nested chunk encoded the ciborium leniency. Update its expected variant ONLY if the spec §1.3 reasoning applies, and name that test in the commit message. Any other failure is a bug in the walk.

Then run the rest of the gate set, each exit=0:
- `cargo test --release --locked --workspace > "$TMPDIR/w6.log" 2>&1; echo "exit=$?"`
- `cargo clippy --release --locked --workspace --tests -- -D warnings`
- `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`
- `cargo fmt --all --check`
- `bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh`
- `uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py`

- [ ] **Step 7: Re-measure the record corpus's Rust verdicts (before/after)**

```bash
S=/private/tmp/claude-501/-Users-hherb-src-secretary/5edf5da6-dc60-434f-a442-bf719640e844/scratchpad/spike641
(cd $S/rustprobe && cargo build --release > build-after.log 2>&1; echo "probe build exit=$?")
M=/Users/hherb/src/secretary
$S/rustprobe/target/release/rustprobe record $M/core/fuzz/seeds/record $M/core/fuzz/corpus/record > $S/rust_record_after.tsv
python3 - "$S" <<'EOF'
import sys, collections
S = sys.argv[1]
def status(f):
    return {l.split("\t")[1]: l.split("\t")[2] for l in open(f)}
before, after = status(f"{S}/rust_record_full.tsv"), status(f"{S}/rust_record_after.tsv")
assert before.keys() == after.keys(), "the input sets differ"
moved = [p for p in before if before[p] != after[p]]
print("inputs:", len(before), "accept before:", list(before.values()).count("accept"),
      "accept after:", list(after.values()).count("accept"), "status moved:", len(moved))
EOF
```

Expected: `inputs: 7454 accept before: 3 accept after: 3 status moved: 0`. The probe depends on the worktree's `core` by path, so rebuilding it picks up the walk. Append the printed line to `$S/measurements.md`.

- [ ] **Step 8: Commit**

```bash
git add core/src/cbor/well_formed.rs core/src/cbor/well_formed core/src/cbor/mod.rs core/src/vault/record.rs core/src/vault/record_walk_tests.rs core/src/vault/mod.rs
git commit -F - <<'EOF'
Walk a record's bytes for well-formedness and rule 4 before ciborium (#641)

ciborium's Value reader is laxer than RFC 8949 and vault-format §4.2's
well-formedness list in three measured ways: it reads undefined as
null (57 corpus inputs), turns bignum tags into integers so the
parsed-tree rule-4 walk never sees them (28), and accepts nested
indefinite-length chunks (4). record::decode rejected every one of
them anyway, at the re-encode at the latest, but named a later rule,
and the differential replay compares which rule is named.

cbor::well_formed::walk_first_item walks the first item iteratively:
well-formedness first, then any tag or float, with a well-formedness
fault anywhere outranking a rule-4 fault anywhere. record::decode runs
it first and maps its faults onto CborDecode, TagRejected and
FloatRejected, so no variant, message or FFI mapping changes.

Acceptance is unchanged, three ways: a legacy_decode oracle proptest
over 4,096 mutated records, a test pinning each leniency's before and
after errors, and the full record corpus re-run through a scratch
probe (7,454 inputs, the same 3 accepts, 0 statuses moved).
block.rs's nested decode_value and decode_manifest are untouched and
filed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 7: `MalformedCbor`, the Python walk, and Section WF

**Files:**
- Create: `core/tests/python/conformance_lib/codec/cbor_faults.py`
- Create: `core/tests/python/conformance_lib/codec/well_formed.py`
- Create: `core/tests/python/conformance_lib/sections/well_formed_walk.py`
- Modify: `core/tests/python/conformance_lib/codec/scanner.py` (raise types, two docstrings, two shared predicates)
- Modify: `core/tests/python/conformance_lib/sections/registry.py`
- Modify: `core/tests/python/conformance_lib/sections/rule_token_vocabulary.py` (docstring only)

**Interfaces:**
- Produces:
  - `cbor_faults.MalformedCbor(ValueError)` with `token = "malformed_cbor"`
  - `cbor_faults.require_utf8(buf: bytes, start: int, end: int, head_at: int) -> None`
  - `cbor_faults.require_false_true_or_null(ai: int, off: int) -> None`
  - `well_formed.walk_body(buf: bytes, pos: int = 0) -> int`, raising `MalformedCbor` or `NonCanonicalItem` (rule 4)
  - `well_formed.MAJOR_TEXT`, `well_formed.MAJOR_MAP` (ints), which Task 8 imports

- [ ] **Step 1: Write Section WF (the failing test)**

Create `core/tests/python/conformance_lib/sections/well_formed_walk.py`:

```python
"""Section WF -- `codec/well_formed.py`'s `walk_body`, case for case the twin
of `core/src/cbor/well_formed/tests.rs` (#641).

`py_decode_record` runs `walk_body` before it reads a key, so that a body that
is not well-formed CBOR is reported as that, and a well-formed body carrying a
tag or a float as rule 4 -- the order `record::decode` reports them in.
Section RTS reaches the walk only through the shapes the committed seeds
plant; this section pins every rule, the precedence in both directions, and
the depth behaviour directly.

Each case is `(label, body, outcome, value)`.  `outcome` is `"end"` (the walk
returns `value`, the offset one past the item), `"malformed"` (it raises
`MalformedCbor`), or `"rule4"` (it raises `NonCanonicalItem` with rule 4).
"""

from __future__ import annotations

from conformance_lib.codec.cbor_faults import MalformedCbor
from conformance_lib.codec.scanner import NonCanonicalItem
from conformance_lib.codec.well_formed import walk_body

# RFC 8949 initial bytes, named so each case reads as the shape it plants.
UINT_0 = 0x00
UINT_INDEFINITE = 0x1F
RESERVED_AI_28 = 0x1C
BYTES_1 = 0x41
BYTES_FOUR_BYTE_LENGTH = 0x5A
TEXT_1 = 0x61
TEXT_3 = 0x63
TEXT_INDEFINITE = 0x7F
ARRAY_1 = 0x81
ARRAY_2 = 0x82
ARRAY_INDEFINITE = 0x9F
MAP_1 = 0xA1
MAP_INDEFINITE = 0xBF
TAG_1 = 0xC1
TAG_BIGNUM_POSITIVE = 0xC2
SIMPLE_16 = 0xF0
FALSE, TRUE, NULL, UNDEFINED = 0xF4, 0xF5, 0xF6, 0xF7
SIMPLE_ONE_BYTE = 0xF8
SIMPLE_ARG_32 = 0x20
FLOAT16 = 0xF9
BREAK = 0xFF
ASCII_A = ord("a")
INVALID_UTF8 = 0xFF
UTF8_TWO_BYTE_LEAD, UTF8_CONTINUATION = 0xC3, 0xA9
# Deeper than ciborium's recursion limit, and than a recursive Python walk
# could be trusted with.
DEPTH_BEYOND_CIBORIUM_LIMIT = 300
MAX_U32 = 0xFFFFFFFF


def _b(*items: int) -> bytes:
    return bytes(items)


CASES: tuple[tuple[str, bytes, str, int | None], ...] = (
    ("uint", _b(UINT_0), "end", 1),
    ("false", _b(FALSE), "end", 1),
    ("true", _b(TRUE), "end", 1),
    ("null", _b(NULL), "end", 1),
    ("text", _b(TEXT_1, ASCII_A), "end", 2),
    ("map", _b(MAP_1, TEXT_1, ASCII_A, UINT_0), "end", 4),
    ("indefinite map", _b(MAP_INDEFINITE, TEXT_1, ASCII_A, UINT_0, BREAK), "end", 5),
    ("chunked text", _b(TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK), "end", 4),
    ("first item only", _b(UINT_0, UNDEFINED), "end", 1),
    ("empty input", b"", "malformed", None),
    ("text overruns", _b(TEXT_3, ASCII_A), "malformed", None),
    ("map value missing", _b(MAP_1, TEXT_1), "malformed", None),
    ("indefinite array unterminated", _b(ARRAY_INDEFINITE, UINT_0), "malformed", None),
    ("float truncated", _b(FLOAT16, UINT_0), "malformed", None),
    ("length past input", bytes([BYTES_FOUR_BYTE_LENGTH]) + MAX_U32.to_bytes(4, "big"), "malformed", None),
    ("reserved additional-info", _b(RESERVED_AI_28), "malformed", None),
    ("indefinite integer", _b(UINT_INDEFINITE), "malformed", None),
    ("stray break", _b(BREAK), "malformed", None),
    ("break in a definite array", _b(ARRAY_1, BREAK), "malformed", None),
    ("undefined", _b(UNDEFINED), "malformed", None),
    ("unassigned simple", _b(SIMPLE_16), "malformed", None),
    ("one-byte simple", _b(SIMPLE_ONE_BYTE, SIMPLE_ARG_32), "malformed", None),
    ("nested indefinite chunk",
     _b(TEXT_INDEFINITE, TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK, BREAK), "malformed", None),
    ("chunk of another major", _b(TEXT_INDEFINITE, BYTES_1, ASCII_A, BREAK), "malformed", None),
    ("invalid utf-8", _b(TEXT_1, INVALID_UTF8), "malformed", None),
    ("invalid utf-8 in a chunk", _b(TEXT_INDEFINITE, TEXT_1, INVALID_UTF8, BREAK), "malformed", None),
    ("utf-8 split across chunks",
     _b(TEXT_INDEFINITE, TEXT_1, UTF8_TWO_BYTE_LEAD, TEXT_1, UTF8_CONTINUATION, BREAK), "malformed", None),
    ("tag", _b(TAG_1, UINT_0), "rule4", 0),
    ("bignum tag", _b(TAG_BIGNUM_POSITIVE, BYTES_1, ASCII_A), "rule4", 0),
    ("float", _b(FLOAT16, UINT_0, UINT_0), "rule4", 0),
    ("malformed after a tag", _b(ARRAY_2, TAG_1, UINT_0, UNDEFINED), "malformed", None),
    ("malformed before a tag", _b(ARRAY_2, UNDEFINED, TAG_1, UINT_0), "malformed", None),
    ("first rule-4 fault wins", _b(ARRAY_2, FLOAT16, UINT_0, UINT_0, TAG_1, UINT_0), "rule4", 1),
    ("indefinite map ends mid-entry", _b(MAP_INDEFINITE, TEXT_1, ASCII_A, BREAK), "malformed", None),
    ("deep nesting",
     bytes([ARRAY_1] * DEPTH_BEYOND_CIBORIUM_LIMIT + [UINT_0]), "end", DEPTH_BEYOND_CIBORIUM_LIMIT + 1),
)

# Mirrors the Rust twin's offset for each rule-4 case: the message names it.
_RULE4_OFFSET_FRAGMENT = "at offset {}"


def _case_issue(label: str, body: bytes, outcome: str, value: int | None) -> str | None:
    try:
        end = walk_body(body)
    except MalformedCbor:
        return None if outcome == "malformed" else f"{label}: raised MalformedCbor, expected {outcome}"
    except NonCanonicalItem as exc:
        if outcome != "rule4" or exc.rule != 4:
            return f"{label}: raised rule {exc.rule}, expected {outcome}"
        if _RULE4_OFFSET_FRAGMENT.format(value) not in str(exc):
            return f"{label}: rule 4 reported as {exc}, expected offset {value}"
        return None
    except RecursionError:
        return f"{label}: RecursionError -- the walk must be iterative"
    if outcome != "end" or end != value:
        return f"{label}: returned {end}, expected {outcome} {value}"
    return None


def section_well_formed_walk() -> tuple[bool, list[str]]:
    issues = [issue for case in CASES if (issue := _case_issue(*case)) is not None]
    lines = [f"PASS: {len(CASES) - len(issues)}/{len(CASES)} walk cases behave as the Rust twin's"]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)
```

Register it in `sections/registry.py`: add the import (alphabetical) and add this row directly after the `Section("CS", ...)` row:

```python
from conformance_lib.sections.well_formed_walk import section_well_formed_walk
```

```python
    Section("WF", "well-formedness walk, the twin of cbor::well_formed", " (#641)",
            section_well_formed_walk),
```

- [ ] **Step 2: Run to verify it fails**

Run: `uv run core/tests/python/conformance.py > "$TMPDIR/p7.log" 2>&1; echo "exit=$?"; grep -E "Traceback|ModuleNotFoundError|^FAIL" "$TMPDIR/p7.log" | head -5`
Expected: exit non-zero with `ModuleNotFoundError: No module named 'conformance_lib.codec.cbor_faults'`. The registry import fails before any section runs. That is the red.

- [ ] **Step 3: Create `cbor_faults.py`**

```python
"""Typed CBOR well-formedness rejections, and the two predicates both walks
share (#641).

`MalformedCbor` is what every structural fault in `codec/scanner.py` and
`codec/well_formed.py` raises: truncation, an overrun, reserved
additional-info, a misplaced indefinite form or break, a bad chunk, invalid
UTF-8, a simple value outside false/true/null.  It carries the rule token
`malformed_cbor`, the one Rust's `CborDecode` variants map to.  Before #641
those were bare `ValueError`s carrying no token, so a malformed body on a
token-compared target would have been a harness failure rather than a
comparison.

Subclasses `ValueError` deliberately: `conformance_lib.rejection` admits
`ValueError` as a verdict, and Section CS asserts the base.  Messages are
unchanged from the raises it replaced.

The predicates live here, not in `scanner.py`, so the per-value check
(`_check_canonical_item`) and the whole-body walk (`walk_body`) call ONE
implementation of each rule -- the `_reject_rule4_head` move, for the same
reason: two hand-copies of one rule drift.
"""

from __future__ import annotations

# RFC 8949 §3.3: the only simple values this format admits.
SIMPLE_FALSE = 20
SIMPLE_TRUE = 21
SIMPLE_NULL = 22


class MalformedCbor(ValueError):
    """The bytes are not well-formed CBOR (RFC 8949 and vault-format §4.2's
    well-formedness precondition)."""

    token = "malformed_cbor"


def require_utf8(buf: bytes, start: int, end: int, head_at: int) -> None:
    """RFC 8949 §3.1: a text string's content MUST be valid UTF-8."""
    try:
        buf[start:end].decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedCbor(
            f"RFC 8949 §3.1: invalid UTF-8 in text string at offset {head_at}: {e}"
        ) from e


def require_false_true_or_null(ai: int, off: int) -> None:
    """RFC 8949 §3.3: a major-7 item here must be false, true or null."""
    if ai not in (SIMPLE_FALSE, SIMPLE_TRUE, SIMPLE_NULL):
        raise MalformedCbor(
            f"RFC 8949 §3.3: major-7 value outside {{false, true, null}} "
            f"at offset {off} (ai={ai})"
        )
```

- [ ] **Step 4: Retype the scanner's structural raises**

In `codec/scanner.py`, add `from conformance_lib.codec.cbor_faults import MalformedCbor, require_false_true_or_null, require_utf8` after `from typing import Callable`. Then change `raise ValueError(` to `raise MalformedCbor(` at exactly these sites, leaving each message unchanged:

- `_decode_head`: `truncated CBOR head`, `RFC 8949 §3.2: indefinite-length form is not valid`, `reserved additional-info`, `truncated {n}-byte argument`.
- `_scan_item`: `unexpected break`, `unterminated indefinite-length string`, `bad chunk in indefinite-length string`, `string length {arg} overruns buffer`, `unterminated indefinite-length array/map`, `indefinite-length tag`, `unreachable CBOR major type`.
- `_scan_map_entries`: `unterminated indefinite-length map` ONLY. `expected a CBOR map` stays `ValueError`: it is a type check, not well-formedness.
- `_scan_array_items`: `unterminated indefinite-length array` ONLY. `expected a CBOR array` stays `ValueError`.
- `_check_canonical_item`: `string length {arg} overruns buffer`.

In `_check_canonical_item`, replace the major-7 `if ai not in (20, 21, 22): raise ValueError(...)` block with `require_false_true_or_null(ai, pos)`, and the UTF-8 `try: ... except UnicodeDecodeError ...: raise ValueError(...)` block with `require_utf8(buf, p, p + arg, pos)`.

Verify the count: `grep -c "raise ValueError" core/tests/python/conformance_lib/codec/scanner.py` must print `2` (the two type checks).

Correct the two docstrings this makes false:
- `_check_canonical_item`: replace the clause `(`ciborium::Value`'s major-7 variants are exactly `Bool`/`Null`/`Float`, with no generic "other simple value" case -- `record.rs`/`block.rs`/manifest decode all reject the other six major-7 shapes wholesale, not just inside an `unknown` subtree)` with `(measured 2026-09-15: ciborium reads `undefined` as `null` rather than rejecting it, so the Rust decoders reject it only through their re-encode -- and `record::decode` through its byte walk since #641)`. Replace `and a plain `ValueError` on the two well-formedness properties named above plus the buffer-bounds check` with `and `MalformedCbor` (a `ValueError`) on the two well-formedness properties named above plus the buffer-bounds check`.
- `NonCanonicalItem`: replace the paragraph beginning `Only the five NUMBERED-rule raises use this type.` with:

```text
    Only the five NUMBERED-rule raises use this type.  Every well-formedness
    raise in this module is `cbor_faults.MalformedCbor` (#641), which carries
    the `malformed_cbor` token; the two type checks in `_scan_map_entries` and
    `_scan_array_items` stay plain `ValueError`, because a map where a map was
    required is not a well-formedness fault.
```

- [ ] **Step 5: Create `well_formed.py`**

```python
"""A whole-body well-formedness walk, run before anything is interpreted (#641).

The clean-room twin of `core/src/cbor/well_formed.rs`.  `py_decode_record` runs
it first, so a body that is not well-formed CBOR is reported as that, and a
well-formed body carrying a tag or a float as crypto-design §6.2 rule 4,
before any key is read -- the order `record::decode` reports them in.

WHAT IT CHECKS -- RFC 8949 well-formedness plus vault-format §4.2's
precondition list, then rule 4:
  * a truncated head, argument or payload, and an indefinite item with no break;
  * reserved additional-info 28-30, the indefinite form on majors 0, 1 and 6,
    and a stray break;
  * an indefinite-string chunk that is not a definite string of the same major
    (RFC 8949 §3.2.3) -- which rejects a NESTED indefinite chunk;
  * text that is not valid UTF-8, per string and per chunk (a sequence split
    across two chunks is invalid; ciborium holds the same, measured);
  * a major-7 simple value other than false/true/null;
  * then any tag (bignum tags 2 and 3 included) or float, as rule 4.

PRECEDENCE.  A well-formedness fault anywhere in the item outranks a rule-4
fault anywhere: the first tag or float is remembered and raised only once the
whole item has proven well-formed.

ITERATIVE on purpose.  `scanner._scan_item` recurses, so a deeply nested body
raises `RecursionError` -- a harness failure, not a verdict.  This walk keeps
an explicit stack and has no depth cap of its own, like its Rust twin.

SCOPE.  The first item only.  Trailing bytes are the caller's to judge, and
`py_decode_record` judges them LAST, where `record::decode` meets them: its
parse performs no EOF check.
"""

from __future__ import annotations

from dataclasses import dataclass

from conformance_lib.codec.cbor_faults import MalformedCbor, require_false_true_or_null, require_utf8
from conformance_lib.codec.scanner import CBOR_AI_INDEFINITE, CBOR_BREAK, NonCanonicalItem, _decode_head, _reject_rule4_head

MAJOR_UINT, MAJOR_NINT, MAJOR_BYTES, MAJOR_TEXT, MAJOR_ARRAY, MAJOR_MAP, MAJOR_TAG, MAJOR_SIMPLE = range(8)
# A map's items are keys and values.
ITEMS_PER_MAP_ENTRY = 2


@dataclass
class _Frame:
    """An open container.  A definite one counts the items it still needs (a
    map counts keys and values; a tag needs one); an indefinite map tracks
    whether a key is waiting for its value."""

    definite_left: int | None
    is_map: bool = False
    mid_entry: bool = False


def _rule4_at(major: int, ai: int, pos: int) -> NonCanonicalItem | None:
    try:
        _reject_rule4_head(major, ai, pos)
    except NonCanonicalItem as exc:
        return exc
    return None


def _payload_end(buf: bytes, head_at: int, start: int, length: int, text: bool) -> int:
    end = start + length
    if end > len(buf):
        raise MalformedCbor(f"string length {length} overruns buffer at offset {head_at}")
    if text:
        require_utf8(buf, start, end, head_at)
    return end


def _string_end(buf: bytes, pos: int, major: int, arg: int | None, head: int) -> int:
    text = major == MAJOR_TEXT
    if arg is not None:
        return _payload_end(buf, pos, pos + head, arg, text)
    at = pos + head
    while True:
        if at >= len(buf):
            raise MalformedCbor("unterminated indefinite-length string")
        if buf[at] == CBOR_BREAK:
            return at + 1
        chunk_major, _, chunk_arg, chunk_head = _decode_head(buf, at)
        if chunk_major != major or chunk_arg is None:
            raise MalformedCbor(f"bad chunk in indefinite-length string at {at}")
        at = _payload_end(buf, at, at + chunk_head, chunk_arg, text)


def _close_finished(buf: bytes, pos: int, stack: list[_Frame]) -> int:
    while stack:
        top = stack[-1]
        if top.definite_left == 0:
            stack.pop()
            continue
        at_break = pos < len(buf) and buf[pos] == CBOR_BREAK
        if top.definite_left is None and at_break:
            if top.is_map and top.mid_entry:
                raise MalformedCbor(
                    f"indefinite-length map ends between a key and its value at offset {pos}"
                )
            stack.pop()
            pos += 1
            continue
        break
    return pos


def _count_one_item(stack: list[_Frame]) -> None:
    if not stack:
        return
    top = stack[-1]
    if top.definite_left is not None:
        top.definite_left -= 1
    elif top.is_map:
        top.mid_entry = not top.mid_entry


def walk_body(buf: bytes, pos: int = 0) -> int:
    """Walk the CBOR item at `pos`; return the offset one past it.

    Raises `MalformedCbor` for a well-formedness fault anywhere in the item,
    else `NonCanonicalItem` (rule 4) for the first tag or float.
    """
    stack: list[_Frame] = []
    first_rule4: NonCanonicalItem | None = None
    started = False
    while True:
        pos = _close_finished(buf, pos, stack)
        if started and not stack:
            if first_rule4 is not None:
                raise first_rule4
            return pos
        started = True
        _count_one_item(stack)
        major, ai, arg, head = _decode_head(buf, pos)
        if major in (MAJOR_UINT, MAJOR_NINT):
            pos += head
        elif major in (MAJOR_BYTES, MAJOR_TEXT):
            pos = _string_end(buf, pos, major, arg, head)
        elif major in (MAJOR_ARRAY, MAJOR_MAP):
            is_map = major == MAJOR_MAP
            left = None if arg is None else arg * (ITEMS_PER_MAP_ENTRY if is_map else 1)
            stack.append(_Frame(definite_left=left, is_map=is_map))
            pos += head
        elif major == MAJOR_TAG:
            first_rule4 = first_rule4 or _rule4_at(major, ai, pos)
            stack.append(_Frame(definite_left=1))
            pos += head
        else:
            if ai == CBOR_AI_INDEFINITE:
                raise MalformedCbor(f"unexpected break at offset {pos}")
            rule4 = _rule4_at(major, ai, pos)
            if rule4 is None:
                require_false_true_or_null(ai, pos)
            first_rule4 = first_rule4 or rule4
            pos += head
```

- [ ] **Step 6: Correct Section RTV's now-stale coverage paragraph**

In `sections/rule_token_vocabulary.py`'s module docstring, replace the sentence that begins `THREE modules on `py_decode_manifest`'s own import path raise untokened:` (through `...even though it is an encoder.`) with:

```text
THREE modules on `py_decode_manifest`'s own import path raise untokened, and
#641 shrank the first: `codec/scanner.py` now raises `MalformedCbor`
(`malformed_cbor`) at every well-formedness site and plain `ValueError` at
only its 2 type checks ("expected a CBOR map/array");
`codec/manifest_schema.py` (9, FOUR of them the NESTED twins of top-level
sites that DID get a typed class -- non-text key at `:148`/`:244` and
missing required field at `:163`/`:269`, two per entry-map parser), and
`codec/manifest_encode.py` (3), which is imported at `manifest_decode.py:17`
and CALLED for the §4.3 step-4 re-encode, so its refusals are on the decode
path even though it is an encoder.
```

and replace `FIVE of the seventeen vocabulary rows have no Python producer at all: `malformed_cbor`, `encoder_refusal`,` with `FOUR of the seventeen vocabulary rows have no Python producer at all (`malformed_cbor` gained one in #641): `encoder_refusal`,`. Also fix the list that follows so it names four tokens.

In the "Measured:" sentence of that same docstring (the 40-byte prefix example), replace `rejects with `ValueError("string length 13 overruns buffer at offset 37")` and `"rule": null`` with `rejects with `MalformedCbor("string length 13 overruns buffer at offset 37")`, which since #641 carries `"rule": "malformed_cbor"``. The sentence around it claims the null-rule posture; append: `(That example no longer demonstrates it; a `manifest_schema.py` nested-key site still does.)`

- [ ] **Step 7: Run to verify it passes**

Run: `uv run core/tests/python/conformance.py > "$TMPDIR/p7.log" 2>&1; echo "exit=$?"; grep -E "^FAIL|ISSUE|Section WF|Section REG" -A1 "$TMPDIR/p7.log" | head -20`
Expected: exit=0; WF prints `PASS: 35/35 walk cases behave as the Rust twin's`; REG passes at 32/32; no other section changes verdict. Sections CS, MCK, MCC, MPR, RC and DET depend on scanner messages or error classes, so their PASS here is the evidence the retyping was message-preserving.

Also run the replay's CI shape, because `manifest_body` now carries tokens on malformed rejections: `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay > "$TMPDIR/r7.log" 2>&1; echo "exit=$?"` → exit=0.

- [ ] **Step 8: Commit**

```bash
git add core/tests/python/conformance_lib/codec/cbor_faults.py core/tests/python/conformance_lib/codec/well_formed.py core/tests/python/conformance_lib/codec/scanner.py core/tests/python/conformance_lib/sections/well_formed_walk.py core/tests/python/conformance_lib/sections/registry.py core/tests/python/conformance_lib/sections/rule_token_vocabulary.py
git commit -F - <<'EOF'
Type the scanner's well-formedness faults and add the Python byte walk (#641)

Every structural raise in codec/scanner.py was a bare ValueError
carrying no rule token, so a malformed body on a token-compared target
would have been a harness failure, never a comparison. They are now
MalformedCbor (token malformed_cbor, still a ValueError, messages
unchanged); only the two "expected a CBOR map/array" type checks stay
ValueError. The UTF-8 and simple-value rules move into cbor_faults.py
as the one implementation both walks call.

codec/well_formed.py's walk_body is the twin of cbor::well_formed:
iterative, well-formedness before rule 4 anywhere in the item, UTF-8
checked per chunk, undefined and nested chunks rejected. New Section WF
pins it case for case against the Rust unit tests (35 cases,
REG 31 -> 32).

Two docstrings this made false are corrected: _check_canonical_item
said ciborium rejects every non-{false,true,null} simple value, and
it reads undefined as null; Section RTV said malformed_cbor has no
Python producer.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 8: `py_decode_record` in Rust's phase order, with typed rejections

**Files:**
- Create: `core/tests/python/conformance_lib/codec/record_rules.py`
- Modify: `core/tests/python/conformance_lib/codec/record.py` (`_decode_record_field_map`, `_decode_record_fields_map`, `py_decode_record`, `_validate_record_field`, imports; the encoders and `_reject_floats_and_tags_py` stay unchanged)

**Interfaces:**
- Consumes: `well_formed.walk_body`, `well_formed.MAJOR_TEXT`, `well_formed.MAJOR_MAP` (Task 7).
- Produces:
  - `record_rules.RecordWrongType`, `RecordIntegerOutOfRange`, `RecordDuplicateKey`, `RecordNonCanonical` (all `ValueError`) and `RecordMissingField` (`KeyError`), each with a `token` class attribute
  - `record_rules.check_record_value(key: str, value: Any) -> Any`
  - `record_rules.check_field_value(fname: str, key: str, value: Any) -> Any`
- Constraint: Section DET keys its census on `codec/record.py::py_decode_record` and `codec/record.py::_validate_record_field`. Each of those two functions must keep exactly one `first_missing_key_in_sorted_order` call.

The failing test for this task is the existing verifier. The replay's full-corpus run (Task 10) is the cross-language check, and Section RTS check 5 (Task 9) is the local ordering pin. This task's own red is a scratch check.

- [ ] **Step 1: Write a scratch ordering check that fails today**

Create `$SCRATCH/order_check.py`, where `SCRATCH=/private/tmp/claude-501/-Users-hherb-src-secretary/5edf5da6-dc60-434f-a442-bf719640e844/scratchpad`:

```python
"""THROWAWAY red/green check for Task 8; the durable pin is Section RTS check 5."""
import os, sys
sys.path.insert(0, "/Users/hherb/src/secretary/.worktrees/token-compare-record-block/core/tests/python")
import cbor2
from conformance_lib.diff_replay import replay_bytes

FLOAT16_ZERO = b"\xf9\x00\x00"
TRUNCATED_TEXT_HEAD = b"\x63\xff"   # a 3-byte text head with 1 byte present
MAP_2 = b"\xa2"
UUID_LEN = 16
base = {"record_uuid": os.urandom(UUID_LEN), "record_type": "t", "fields": {},
        "created_at_ms": 0, "last_mod_ms": 0}
no_last_mod = {k: v for k, v in base.items() if k != "last_mod_ms"}
cases = {
    "wrong type beside a missing key": (cbor2.dumps({**no_last_mod, "record_uuid": "text"}, canonical=True), "wrong_type"),
    "repeat whose second copy is a float": (MAP_2 + cbor2.dumps("record_type") + cbor2.dumps("t") + cbor2.dumps("record_type") + FLOAT16_ZERO, "rule4_tag_or_float"),
    "malformed tail behind a non-text key": (MAP_2 + cbor2.dumps(1) + cbor2.dumps(0) + TRUNCATED_TEXT_HEAD, "malformed_cbor"),
    "schema fault then trailing bytes": (cbor2.dumps(no_last_mod, canonical=True) + b"\x00", "missing_field"),
    "negative integer": (cbor2.dumps({**base, "created_at_ms": -1}, canonical=True), "integer_out_of_range"),
    "bool where a uint belongs": (cbor2.dumps({**base, "created_at_ms": True}, canonical=True), "wrong_type"),
}
bad = 0
for label, (body, want) in cases.items():
    v = replay_bytes("record", body).verdict
    ok = v.get("status") == "reject" and v.get("rule") == want
    bad += not ok
    print(("ok  " if ok else "BAD ") + f"{label}: want {want}, got {v.get('status')} {v.get('rule')!r} {v.get('error_class')}")
sys.exit(1 if bad else 0)
```

Run: `uv run --with cbor2 python3 "$SCRATCH/order_check.py"; echo "exit=$?"`
Expected: exit=1 with several `BAD` lines. Today `rule` is `None` on most, since the record path raises untokened errors, and `bool where a uint belongs` is ACCEPTED (`status accept`): `isinstance(True, int)` is true in Python. That acceptance divergence is a real finding. `record.rs::take_u64` rejects a CBOR boolean as `WrongType`. Record it in `$SCRATCH/measurements.md` for the handoff.

- [ ] **Step 2: Create `record_rules.py`**

```python
"""Typed §6.3 record rejections carrying a rule token, and the per-key value
checks `py_decode_record` applies the moment it reads a key (#641).

WHY THE MOMENT IT READS A KEY.  `record.rs::parse_record_map` type- and
range-checks each value inside its entry loop, in wire order, and reports a
missing required key only after the loop.  This package used to check
presence first and types afterwards, so a body carrying both faults named a
different rule in each language.  The order is parity between our two
implementations -- vault-format §6.3 states none -- and Section RTS check 5
pins it.

COARSE ON PURPOSE.  `RecordNonCanonical` covers §6.2 rules 1, 2 and 3 and
trailing bytes alike, because Rust's fieldless
`RecordError::NonCanonicalEncoding` cannot tell them apart, and a token may
only draw a distinction both implementations can make.  The message keeps the
specific text.

`RecordMissingField` subclasses `KeyError` so `str()` renders exactly as the
bare `KeyError` it replaces; every other class is a `ValueError`.  Both bases
are in `conformance_lib.rejection`'s verdict allowlist.
"""

from __future__ import annotations

from typing import Any

# §6.3: `record_uuid` and each field's `device_uuid` are 16-byte bstr.
RECORD_UUID_LEN = 16


class RecordWrongType(ValueError):
    """A key or value has the wrong CBOR type, or a uuid the wrong length."""

    token = "wrong_type"


class RecordIntegerOutOfRange(ValueError):
    """An integer that must be a u64 is negative."""

    token = "integer_out_of_range"


class RecordDuplicateKey(ValueError):
    """A map this decoder interprets repeats a key."""

    token = "duplicate_map_key"


class RecordMissingField(KeyError):
    """A required key is absent."""

    token = "missing_field"


class RecordNonCanonical(ValueError):
    """The record is not in canonical form: §6.2 rule 1, 2 or 3, or trailing bytes."""

    token = "non_canonical_unclassified"


def _is_integer(value: Any) -> bool:
    # `bool` is an `int` subclass in Python; a CBOR boolean is not an integer.
    return isinstance(value, int) and not isinstance(value, bool)


def check_uint(value: Any, message: str) -> Any:
    """`record.rs::take_u64`: a non-integer is a wrong type; a negative
    integer does not fit a u64."""
    if not _is_integer(value):
        raise RecordWrongType(message)
    if value < 0:
        raise RecordIntegerOutOfRange(message)
    return value


def _is_uuid(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == RECORD_UUID_LEN


def check_record_value(key: str, value: Any) -> Any:
    """Check one known top-level value (not `fields`) as `parse_record_map`'s
    arm for `key` does, and return it."""
    if key == "record_uuid":
        if not _is_uuid(value):
            raise RecordWrongType(f"record_uuid must be 16-byte bstr, got {type(value).__name__}")
    elif key == "record_type":
        if not isinstance(value, str):
            raise RecordWrongType("record_type must be tstr")
    elif key in ("created_at_ms", "last_mod_ms", "tombstoned_at_ms"):
        check_uint(value, f"{key} must be uint, got {value!r}")
    elif key == "tags":
        if not isinstance(value, list):
            raise RecordWrongType("record tags must be array")
        if not all(isinstance(t, str) for t in value):
            raise RecordWrongType("record tags entries must be tstr")
    elif key == "tombstone":
        if not isinstance(value, bool):
            raise RecordWrongType("record tombstone must be bool")
    return value


def check_field_value(fname: str, key: str, value: Any) -> Any:
    """Check one known value inside `fields[fname]` as `parse_field_map`'s arm
    for `key` does, and return it."""
    if key == "value":
        if not isinstance(value, (str, bytes)):
            raise RecordWrongType(f"field {fname!r} value must be tstr or bstr")
    elif key == "last_mod":
        check_uint(value, f"field {fname!r} last_mod must be uint")
    elif key == "device_uuid":
        if not _is_uuid(value):
            raise RecordWrongType(f"field {fname!r} device_uuid must be 16-byte bstr")
    return value
```

- [ ] **Step 3: Rewrite the three decode functions in `record.py`**

Replace the import block (the three `from conformance_lib...` lines) with:

```python
from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.record_rules import (
    RecordDuplicateKey,
    RecordMissingField,
    RecordNonCanonical,
    RecordWrongType,
    check_field_value,
    check_record_value,
)
from conformance_lib.codec.required_keys import first_missing_key_in_sorted_order
from conformance_lib.codec.scanner import NonCanonicalItem, _check_canonical_item, _decode_head, _scan_map_entries
from conformance_lib.codec.well_formed import MAJOR_MAP, MAJOR_TEXT, walk_body
```

Replace `_decode_record_field_map` (whole function) with:

```python
def _decode_record_field_map(data: bytes, pos: int, fname: str) -> dict:
    """Decode one `fields[fname]` sub-map (`RecordField`, §6.3.2) in
    `parse_field_map`'s order: per entry in wire order, the key's type, then a
    repeat, then the value checked the moment it is read; this field's missing
    keys last.  Unknown keys are retained as raw bytes under `"unknown"`, the
    second of the two levels a `Record` has an unknown bag at (#592).
    """
    import cbor2

    major, _, _, _ = _decode_head(data, pos)
    if major != MAJOR_MAP:
        raise RecordWrongType(f"record field {fname!r} value must be a map, got major type {major}")
    entries, _ = _scan_map_entries(data, pos)
    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != MAJOR_TEXT:
            raise RecordWrongType(f"record field map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise RecordDuplicateKey(f"duplicate record field-level key: {key!r}")
        seen.add(key)
        if key in RECORD_FIELD_KNOWN_KEYS:
            out[key] = check_field_value(fname, key, cbor2.loads(data[vs:ve]))
        else:
            unknown[key] = data[vs:ve]
    _validate_record_field(fname, out)
    out["unknown"] = unknown
    return out
```

Replace `_decode_record_fields_map` (whole function) with:

```python
def _decode_record_fields_map(data: bytes, pos: int) -> dict:
    """Decode the record's `fields` map at `pos` in `take_fields_map`'s order:
    per entry, the key's type, then a repeated field name, then that field's
    own sub-map in full.  `fields` has no unknown bag of its own -- an
    unrecognised field NAME is simply another field (`record.rs`'s module doc).
    """
    import cbor2

    major, _, _, _ = _decode_head(data, pos)
    if major != MAJOR_MAP:
        raise RecordWrongType(f"record fields must be a map, got major type {major}")
    entries, _ = _scan_map_entries(data, pos)
    out: dict[str, dict] = {}
    for (ks, ke), (vs, _ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != MAJOR_TEXT:
            raise RecordWrongType(f"record fields map key at offset {ks} is not a text string")
        fname = cbor2.loads(data[ks:ke])
        if fname in out:
            raise RecordDuplicateKey(f"duplicate record field name: {fname!r}")
        out[fname] = _decode_record_field_map(data, vs, fname)
    return out
```

Replace `py_decode_record` (whole function, including its docstring) with:

```python
def py_decode_record(data: bytes) -> dict:
    """Strict §6.3 canonical-CBOR record decoder, in `record.rs::decode`'s phase
    order (#641), so that a body breaking several rules names the same one in
    both languages:

      1. `walk_body`: well-formed CBOR, then no tag or float anywhere (rule 4).
      2. The top-level item is a map.
      3. Entries in wire order: key type, then a repeat, then the value checked
         the moment it is read (`fields` recursing in the same order, each
         field's missing keys at the end of that field).
      4. Missing required top-level keys.
      5. Canonical form, last: §6.2 rules 2/3 per value, trailing bytes, then
         the re-encode comparison -- all `RecordNonCanonical`, because Rust's
         fieldless `NonCanonicalEncoding` cannot tell them apart.

    Unknown record-level and per-field keys are RETAINED as raw bytes rather
    than decoded through `cbor2.loads`: §4.2/§6.2 rules 1 and 5 are deliberately
    unenforced inside either forward-compat `unknown` bag (ground truth:
    `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding_at_both_levels`
    in `record.rs`'s tests).

    Returns a dict of parsed fields, with `"unknown"` mapping to
    `{key: raw_bytes}` at BOTH the record level and inside each
    `fields[name]` sub-dict.
    """
    import cbor2

    end = walk_body(data)
    major, _, _, _ = _decode_head(data, 0)
    if major != MAJOR_MAP:
        raise RecordWrongType(f"expected a CBOR map at offset 0, got major type {major}")
    entries, _ = _scan_map_entries(data, 0)

    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()
    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != MAJOR_TEXT:
            raise RecordWrongType(f"record map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise RecordDuplicateKey(f"duplicate record key: {key!r}")
        seen.add(key)
        if key == "fields":
            out[key] = _decode_record_fields_map(data, vs)
        elif key in RECORD_KNOWN_KEYS:
            out[key] = check_record_value(key, cbor2.loads(data[vs:ve]))
        else:
            unknown[key] = data[vs:ve]

    absent = first_missing_key_in_sorted_order(out, RECORD_REQUIRED_KEYS)
    if absent is not None:
        raise RecordMissingField(f"record missing required field: {absent!r}")
    out["unknown"] = unknown

    for _key_span, (vs, _ve) in entries:
        try:
            _check_canonical_item(data, vs)
        except NonCanonicalItem as exc:
            raise RecordNonCanonical(str(exc)) from exc
    if end != len(data):
        raise RecordNonCanonical(f"trailing bytes after record map: {len(data) - end}")
    # What this comparison does and does NOT catch (#595): it catches KEY
    # ORDER inside a nested known map, and map-head non-canonicality. It does
    # NOT catch a DUPLICATE key: those are rejected earlier by the `seen`
    # checks, and a repeat would survive `_scan_map_entries` and compare EQUAL.
    # Do not remove a `seen` set as redundant with this check.
    if py_encode_record(out) != data:
        raise RecordNonCanonical("record is not in canonical CBOR form")
    return out
```

Replace `_validate_record_field` (whole function) with:

```python
def _validate_record_field(fname: str, fval: dict) -> None:
    """The per-field required-key check, run once `fields[fname]`'s map has
    been read -- `parse_field_map` requires its three keys only after its loop.
    Value types are checked as each key is read (`check_field_value`)."""
    REQUIRED_FIELD_KEYS = {"value", "last_mod", "device_uuid"}
    absent = first_missing_key_in_sorted_order(fval, REQUIRED_FIELD_KEYS)
    if absent is not None:
        raise RecordMissingField(f"record field {fname!r} missing {absent!r}")
```

Delete the now-obsolete `#592` explanatory comment block above `RECORD_KNOWN_KEYS` ONLY if it references the removed functions' old behaviour; otherwise leave it. Keep `RECORD_KNOWN_KEYS`, `RECORD_REQUIRED_KEYS`, `RECORD_FIELD_KNOWN_KEYS`, `_reject_floats_and_tags_py` (imported by `codec/trash_entry.py`) and the three encoders unchanged.

Check the size: `wc -l core/tests/python/conformance_lib/codec/record.py core/tests/python/conformance_lib/codec/record_rules.py` → both under 500.

- [ ] **Step 4: Run to verify it passes**

Run: `uv run --with cbor2 python3 "$SCRATCH/order_check.py"; echo "exit=$?"` → exit=0, six `ok` lines.
Run: `uv run core/tests/python/conformance.py > "$TMPDIR/p8.log" 2>&1; echo "exit=$?"; grep -E "^FAIL|ISSUE" "$TMPDIR/p8.log"`
Expected: exit=0, no FAIL. Sections RC (record unknown-subtree canonicality: its reject shapes now raise `RecordNonCanonical` whose message still contains "rule" or "canonical"), DET (record and record_field cases) and DRS (serve and single-shot on the record seeds) are the ones this task could break; all three must PASS.

- [ ] **Step 5: Commit**

```bash
git add core/tests/python/conformance_lib/codec/record_rules.py core/tests/python/conformance_lib/codec/record.py
git commit -F - <<'EOF'
Decode records in Rust's phase order, with typed rejections (#641)

py_decode_record checked presence before types, rules 2/3 per value
inside its entry loop, trailing bytes before anything, and had no
whole-body walk; record::decode does the reverse on every count. A
body with two faults named a different rule in each language, and the
spike measured 2,949 such corpus inputs.

It now runs walk_body first, checks each value the moment its key is
read (fields recursing likewise, each field's missing keys at its
end), then missing top-level keys, then canonical form last. Five
typed classes carry tokens; RecordNonCanonical is deliberately coarse
because Rust's NonCanonicalEncoding is fieldless. Messages are
unchanged, and DET's census functions keep their names.

Also fixes an ACCEPTANCE divergence the reorder exposed: a CBOR
boolean where a u64 belongs was accepted, since bool is an int
subclass in Python; record.rs rejects it as WrongType.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 9: `record` seeds, and Section RTS's record half

**Files:**
- Create: `core/tests/rule_token_seeds_helpers/record.rs`
- Modify: `core/tests/rule_token_seeds_helpers/mod.rs` (`pub mod record;`, `all_cases`)
- Modify: `core/tests/rule_token_seeds.rs` (`SEEDED_TARGETS`)
- Create (generated): `core/fuzz/seeds/record/<token>__<shape>.bin`, 22 files
- Modify: `core/tests/python/conformance_lib/sections/rule_token_seeds.py` (record rows, identity rows, check 5)

**Interfaces:**
- Consumes: `SeedCase`, `LABEL_SEPARATOR` (Task 3); `RecordError::rule_token` (Task 2); the walk (Task 6); the Python record decoder (Task 8).
- Produces: `record::cases() -> Vec<SeedCase>`.

- [ ] **Step 1: Write the `record` cases**

Create `core/tests/rule_token_seeds_helpers/record.rs`:

```rust
//! Single-fault `record` seeds, planted into
//! `core/fuzz/seeds/record/login.cbor` (keys `fields`, `last_mod_ms`,
//! `record_type`, `record_uuid`, `created_at_ms`; fields `username`,
//! `totp_seed`).
//!
//! The base is split into `(key bytes, value bytes)` entries and reassembled,
//! so a planted value can be ANY byte string, canonical or not, while every
//! other entry stays the base's own bytes. Insertions go to the position
//! canonical key order gives them, so no shape plants a key-order fault by
//! accident.

use ciborium::Value;
use secretary_core::vault::manifest::RuleToken;
use secretary_core::vault::record::RECORD_UUID_LEN;

use super::SeedCase;

// RFC 8949 bytes planted below.
const MAP_SMALL_BASE: u8 = 0xa0;
const MAP_ONE_BYTE_COUNT: u8 = 0xb8;
const MAP_INDEFINITE: u8 = 0xbf;
const ARRAY_EMPTY: u8 = 0x80;
const ARRAY_1: u8 = 0x81;
const BYTES_SMALL_BASE: u8 = 0x40;
const TEXT_SMALL_BASE: u8 = 0x60;
const TEXT_INDEFINITE: u8 = 0x7f;
const UINT_ZERO: u8 = 0x00;
const UINT_ONE: u8 = 0x01;
const NINT_ONE: u8 = 0x20;
const TAG_EPOCH: u8 = 0xc1;
const TAG_BIGNUM_POSITIVE: u8 = 0xc2;
const FLOAT16: u8 = 0xf9;
const UNDEFINED: u8 = 0xf7;
const BREAK: u8 = 0xff;
const INVALID_UTF8: u8 = 0xff;
const ASCII_A: u8 = b'a';
/// The largest count a one-byte map head can carry.
const SMALL_COUNT_MAX: usize = 23;
/// A key no v1 record defines, so it lands in the forward-compat bag.
const FUTURE_KEY: &str = "zz_future";
/// The field whose sub-map the nested shapes edit.
const EDITED_FIELD: &str = "username";

type Entry = (Vec<u8>, Vec<u8>);

fn cbor(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    ciborium::ser::into_writer(value, &mut out).expect("a seed value encodes");
    out
}

fn text(s: &str) -> Vec<u8> {
    cbor(&Value::Text(s.to_owned()))
}

/// The `(key, value)` byte pairs of the definite map `bytes`.
fn entries(bytes: &[u8]) -> Vec<Entry> {
    let value: Value = ciborium::de::from_reader(bytes).expect("a seed map parses");
    let Value::Map(pairs) = value else {
        panic!("a seed base value is not a map")
    };
    pairs.iter().map(|(k, v)| (cbor(k), cbor(v))).collect()
}

fn small_count(count: usize) -> u8 {
    assert!(count <= SMALL_COUNT_MAX, "seed maps stay in the one-byte head form");
    u8::try_from(count).expect("a small count fits a byte")
}

fn entry_bytes(entries: &[Entry]) -> Vec<u8> {
    entries.iter().flat_map(|(k, v)| k.iter().chain(v).copied()).collect()
}

fn map(entries: &[Entry]) -> Vec<u8> {
    let mut out = vec![MAP_SMALL_BASE | small_count(entries.len())];
    out.extend(entry_bytes(entries));
    out
}

fn value_of(entries: &[Entry], key: &str) -> Vec<u8> {
    let wanted = text(key);
    entries
        .iter()
        .find(|(k, _)| *k == wanted)
        .unwrap_or_else(|| panic!("seed base has no key {key}"))
        .1
        .clone()
}

fn with_value(entries: &[Entry], key: &str, value: Vec<u8>) -> Vec<Entry> {
    let wanted = text(key);
    entries
        .iter()
        .map(|(k, v)| (k.clone(), if *k == wanted { value.clone() } else { v.clone() }))
        .collect()
}

fn without(entries: &[Entry], key: &str) -> Vec<Entry> {
    let wanted = text(key);
    entries.iter().filter(|(k, _)| *k != wanted).cloned().collect()
}

/// `entries` with `(key, value)` inserted where RFC 8949's length-first
/// canonical order puts it.
fn inserted(entries: &[Entry], key: Vec<u8>, value: Vec<u8>) -> Vec<Entry> {
    let mut out = entries.to_vec();
    let at = out
        .iter()
        .position(|(k, _)| (k.len(), k.as_slice()) > (key.len(), key.as_slice()))
        .unwrap_or(out.len());
    out.insert(at, (key, value));
    out
}

/// `entries` with the entry for `key` repeated right after itself.
fn repeated(entries: &[Entry], key: &str) -> Vec<Entry> {
    let wanted = text(key);
    let at = entries
        .iter()
        .position(|(k, _)| *k == wanted)
        .unwrap_or_else(|| panic!("seed base has no key {key}"));
    let mut out = entries.to_vec();
    out.insert(at + 1, entries[at].clone());
    out
}

/// The base with `EDITED_FIELD`'s sub-map replaced by `edit` of its entries.
fn with_edited_field(base: &[u8], edit: fn(&[Entry]) -> Vec<u8>) -> Vec<u8> {
    let top = entries(base);
    let fields = entries(&value_of(&top, "fields"));
    let field = entries(&value_of(&fields, EDITED_FIELD));
    let fields = with_value(&fields, EDITED_FIELD, edit(&field));
    map(&with_value(&top, "fields", map(&fields)))
}

fn with_future_value(base: &[u8], value: Vec<u8>) -> Vec<u8> {
    map(&inserted(&entries(base), text(FUTURE_KEY), value))
}

fn truncated(base: &[u8]) -> Vec<u8> {
    base[..base.len() - 1].to_vec()
}

fn undefined_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![UNDEFINED])
}

fn nested_indefinite_chunk(base: &[u8]) -> Vec<u8> {
    let chunk = vec![TEXT_INDEFINITE, TEXT_INDEFINITE, TEXT_SMALL_BASE | 1, ASCII_A, BREAK, BREAK];
    with_future_value(base, chunk)
}

fn invalid_utf8_text(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "record_type", vec![TEXT_SMALL_BASE | 1, INVALID_UTF8]))
}

fn float_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![FLOAT16, UINT_ZERO, UINT_ZERO])
}

fn tag_value(base: &[u8]) -> Vec<u8> {
    with_future_value(base, vec![TAG_EPOCH, UINT_ZERO])
}

fn bignum_tag(base: &[u8]) -> Vec<u8> {
    let bignum = vec![TAG_BIGNUM_POSITIVE, BYTES_SMALL_BASE | 1, UINT_ONE];
    map(&with_value(&entries(base), "created_at_ms", bignum))
}

fn top_level_array(base: &[u8]) -> Vec<u8> {
    let mut out = vec![ARRAY_1];
    out.extend_from_slice(base);
    out
}

fn non_text_key(base: &[u8]) -> Vec<u8> {
    map(&inserted(&entries(base), vec![UINT_ONE], vec![UINT_ZERO]))
}

fn record_uuid_text(base: &[u8]) -> Vec<u8> {
    let as_text = text(&"u".repeat(RECORD_UUID_LEN));
    map(&with_value(&entries(base), "record_uuid", as_text))
}

fn record_uuid_short(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let uuid: Value = ciborium::de::from_reader(value_of(&top, "record_uuid").as_slice())
        .expect("record_uuid parses");
    let Value::Bytes(uuid) = uuid else {
        panic!("seed base record_uuid is not a byte string")
    };
    let short = cbor(&Value::Bytes(uuid[..RECORD_UUID_LEN - 1].to_vec()));
    map(&with_value(&top, "record_uuid", short))
}

fn fields_not_a_map(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "fields", vec![ARRAY_EMPTY]))
}

fn negative_created_at_ms(base: &[u8]) -> Vec<u8> {
    map(&with_value(&entries(base), "created_at_ms", vec![NINT_ONE]))
}

fn missing_record_uuid(base: &[u8]) -> Vec<u8> {
    map(&without(&entries(base), "record_uuid"))
}

fn missing_field_value(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| map(&without(field, "value")))
}

fn duplicate_record_key(base: &[u8]) -> Vec<u8> {
    map(&repeated(&entries(base), "record_type"))
}

fn duplicate_field_name(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let fields = repeated(&entries(&value_of(&top, "fields")), EDITED_FIELD);
    map(&with_value(&top, "fields", map(&fields)))
}

fn duplicate_field_level_key(base: &[u8]) -> Vec<u8> {
    with_edited_field(base, |field| map(&repeated(field, "last_mod")))
}

fn key_order(base: &[u8]) -> Vec<u8> {
    let mut top = entries(base);
    top.swap(0, 1);
    map(&top)
}

fn indefinite_map(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let mut fields = vec![MAP_INDEFINITE];
    fields.extend(entry_bytes(&entries(&value_of(&top, "fields"))));
    fields.push(BREAK);
    map(&with_value(&top, "fields", fields))
}

fn non_shortest_map_head(base: &[u8]) -> Vec<u8> {
    let top = entries(base);
    let field_entries = entries(&value_of(&top, "fields"));
    let mut fields = vec![MAP_ONE_BYTE_COUNT, small_count(field_entries.len())];
    fields.extend(entry_bytes(&field_entries));
    map(&with_value(&top, "fields", fields))
}

fn trailing_bytes(base: &[u8]) -> Vec<u8> {
    let mut out = base.to_vec();
    out.push(UINT_ZERO);
    out
}

pub fn cases() -> Vec<SeedCase> {
    let case = |token: RuleToken, shape: &'static str, plant: fn(&[u8]) -> Vec<u8>| SeedCase {
        target: "record",
        token,
        shape,
        plant,
    };
    use RuleToken::{
        DuplicateMapKey, IntegerOutOfRange, MalformedCbor, MissingField,
        NonCanonicalUnclassified, Rule4TagOrFloat, WrongType,
    };
    vec![
        case(MalformedCbor, "truncated", truncated),
        case(MalformedCbor, "undefined_value", undefined_value),
        case(MalformedCbor, "nested_indefinite_chunk", nested_indefinite_chunk),
        case(MalformedCbor, "invalid_utf8_text", invalid_utf8_text),
        case(Rule4TagOrFloat, "float_value", float_value),
        case(Rule4TagOrFloat, "tag_value", tag_value),
        case(Rule4TagOrFloat, "bignum_tag", bignum_tag),
        case(WrongType, "top_level_array", top_level_array),
        case(WrongType, "non_text_key", non_text_key),
        case(WrongType, "record_uuid_text", record_uuid_text),
        case(WrongType, "record_uuid_short", record_uuid_short),
        case(WrongType, "fields_not_a_map", fields_not_a_map),
        case(IntegerOutOfRange, "negative_created_at_ms", negative_created_at_ms),
        case(MissingField, "record_uuid", missing_record_uuid),
        case(MissingField, "field_value", missing_field_value),
        case(DuplicateMapKey, "record_level", duplicate_record_key),
        case(DuplicateMapKey, "fields_level", duplicate_field_name),
        case(DuplicateMapKey, "field_level", duplicate_field_level_key),
        case(NonCanonicalUnclassified, "key_order", key_order),
        case(NonCanonicalUnclassified, "indefinite_map", indefinite_map),
        case(NonCanonicalUnclassified, "non_shortest_map_head", non_shortest_map_head),
        case(NonCanonicalUnclassified, "trailing_bytes", trailing_bytes),
    ]
}

#[test]
fn reassembling_the_base_is_byte_identical() {
    let base = super::base("record");
    assert_eq!(map(&entries(&base)), base, "the entry split must round-trip the base");
}
```

In `rule_token_seeds_helpers/mod.rs`: add `pub mod record;` after `pub mod block_file;`, and change `all_cases` to:

```rust
pub fn all_cases() -> Vec<SeedCase> {
    let mut cases = block_file::cases();
    cases.extend(record::cases());
    cases
}
```

In `core/tests/rule_token_seeds.rs`, change `const SEEDED_TARGETS: &[&str] = &["block_file"];` to `const SEEDED_TARGETS: &[&str] = &["block_file", "record"];`.

- [ ] **Step 2: Run to verify it fails (seeds not committed)**

Run: `cargo test --release --locked -p secretary-core --test rule_token_seeds > "$TMPDIR/t9.log" 2>&1; echo "exit=$?"; grep -E "test result|is not committed|named" "$TMPDIR/t9.log" | head -5`
Expected: exit=101. `reassembling_the_base_is_byte_identical` passes; the label binding panics with "is not committed" on the first record row. A panic saying "the Rust decoder named …" instead means a plant hit a different rule than its row. Fix the plant, never the row's token.

- [ ] **Step 3: Generate, then verify**

Run: `cargo test --release --locked -p secretary-core --test rule_token_seeds -- --ignored generate_rule_token_seeds > "$TMPDIR/g9.log" 2>&1; echo "exit=$?"` → exit=0.
Run: `git status --short core/fuzz/seeds` → exactly 22 new `core/fuzz/seeds/record/*__*.bin`; no modified file (block_file's seeds regenerate byte-identically).
Run: `cargo test --release --locked -p secretary-core --test rule_token_seeds > "$TMPDIR/t9.log" 2>&1; echo "exit=$?"; grep "test result" "$TMPDIR/t9.log"` → exit=0; `3 passed; 0 failed; 1 ignored`.

- [ ] **Step 4: Extend Section RTS (failing until its table is updated)**

Run the verifier first: `uv run core/tests/python/conformance.py > "$TMPDIR/p9a.log" 2>&1; echo "exit=$?"`. It must still pass, because RTS does not yet read `record/`. Now edit `sections/rule_token_seeds.py`.

Add imports:

```python
import os

from conformance_lib.codec import cbor_faults, record_rules
```

Do NOT import `cbor2` at module top. The package's convention is stdlib-only top-level imports with PEP 723 dependencies imported lazily, so `_ordering_issues` below imports it inside the function.

Add a row to `_TARGETS`:

```python
    "record": (
        22,
        frozenset(
            {
                "malformed_cbor",
                "rule4_tag_or_float",
                "wrong_type",
                "integer_out_of_range",
                "missing_field",
                "duplicate_map_key",
                "non_canonical_unclassified",
            }
        ),
    ),
```

Extend `_TOKENED_CLASSES` with:

```python
    (cbor_faults.MalformedCbor, "malformed_cbor"),
    (record_rules.RecordWrongType, "wrong_type"),
    (record_rules.RecordIntegerOutOfRange, "integer_out_of_range"),
    (record_rules.RecordDuplicateKey, "duplicate_map_key"),
    (record_rules.RecordMissingField, "missing_field"),
    (record_rules.RecordNonCanonical, "non_canonical_unclassified"),
```

Add check 5 and call it from the section function:

```python
# Check 5 -- LOCAL parity-order assertions for `record`.  Two-fault bodies
# built here, never committed: vault-format §6.3 states no report order, and a
# committed cross-language row must not pin one (#618).  They pin the order
# `py_decode_record` shares with `record::decode` by design.
_FLOAT16_ZERO = bytes([0xF9, 0x00, 0x00])
_MAP_2_HEAD = bytes([0xA2])
# A text head declaring 3 bytes, followed by 1.
_TRUNCATED_TEXT = bytes([0x63, 0xFF])
_TRAILING_BYTE = bytes([0x00])
_UUID_LEN = record_rules.RECORD_UUID_LEN
# How many parity-order cases `_ordering_issues` declares; asserted there.
_ORDERING_CASES = 4


def _ordering_issues() -> list[str]:
    import cbor2

    base = {
        "record_uuid": os.urandom(_UUID_LEN),
        "record_type": "t",
        "fields": {},
        "created_at_ms": 0,
        "last_mod_ms": 0,
    }
    no_last_mod = {k: v for k, v in base.items() if k != "last_mod_ms"}
    cases = (
        ("a wrong type beside a missing key",
         cbor2.dumps({**no_last_mod, "record_uuid": "text"}, canonical=True), "wrong_type"),
        ("a repeated key whose second copy is a float",
         _MAP_2_HEAD + cbor2.dumps("record_type") + cbor2.dumps("t")
         + cbor2.dumps("record_type") + _FLOAT16_ZERO, "rule4_tag_or_float"),
        ("a malformed tail behind a non-text key",
         _MAP_2_HEAD + cbor2.dumps(1) + cbor2.dumps(0) + _TRUNCATED_TEXT, "malformed_cbor"),
        ("a schema fault followed by trailing bytes",
         cbor2.dumps(no_last_mod, canonical=True) + _TRAILING_BYTE, "missing_field"),
    )
    if len(cases) != _ORDERING_CASES:
        raise AssertionError(f"_ORDERING_CASES is {_ORDERING_CASES}, the table holds {len(cases)}")
    issues = []
    for label, body, want in cases:
        verdict = replay_bytes("record", body).verdict
        if verdict.get("status") != "reject" or verdict.get("rule") != want:
            issues.append(
                f"record order: {label} must report {want!r}, got {verdict.get('status')} "
                f"{verdict.get('rule')!r} ({verdict.get('error_class')}: {verdict.get('detail')})"
            )
    return issues
```

In `section_rule_token_seeds`, before the final `for issue in issues:` loop, add:

```python
    order_issues = _ordering_issues()
    issues.extend(order_issues)
    lines.append(
        f"PASS 5: {_ORDERING_CASES - len(order_issues)}/{_ORDERING_CASES} record parity-order cases"
    )
```

Append to the module docstring:

```text
CHECK 5 IS PARITY, NOT SPEC.  Four two-fault `record` bodies are built in this
section and never committed, because vault-format §6.3 fixes no report order
and a committed cross-language row must not pin one (#618's lesson).  They pin
the phase order `py_decode_record` shares with `record::decode` by design --
walk, map, per-key checks in wire order, missing keys, canonical form last --
so a drift in Python's order reds here rather than only in a local
full-corpus replay.
```

- [ ] **Step 5: Run to verify it passes**

Run: `uv run core/tests/python/conformance.py > "$TMPDIR/p9.log" 2>&1; echo "exit=$?"; grep -E "^FAIL|ISSUE|PASS [0-9-]+:" "$TMPDIR/p9.log" | grep -iE "fail|issue|record|seeds|typed|parity"`
Expected: exit=0; RTS prints `PASS 1: 9 typed classes`, `PASS 2-4: block_file: 15 labelled seeds covering 4 tokens`, `PASS 2-4: record: 22 labelled seeds covering 7 tokens`, and `PASS 5: 4/4 record parity-order cases`. Section DRS now replays 22 more committed record inputs in both modes and must PASS.

- [ ] **Step 6: Commit**

```bash
git add core/tests/rule_token_seeds.rs core/tests/rule_token_seeds_helpers core/fuzz/seeds/record core/tests/python/conformance_lib/sections/rule_token_seeds.py
git commit -F - <<'EOF'
Generate single-fault record seeds and bind them in both languages (#641)

Twenty-two seeds plant one fault each into login.cbor: every record
token, the three duplicate-key levels, the three ciborium leniencies
the Rust walk now names (undefined, bignum tag, nested chunk), and
four canonical-form faults. The base is split into (key, value) byte
entries and reassembled, so a planted value can be any bytes while
the rest stays the base's own; a test pins that the split round-trips.

Section RTS gains the record rows and identity checks for the six
record and well-formedness classes, plus check 5: four two-fault bodies
built in-section, never committed, pinning the phase order
py_decode_record shares with record::decode. §6.3 fixes no report
order, so that pin is parity and says so, rather than a
cross-language row (#618).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

---

### Task 10: Token-compare `record`, and measure the full runtime corpus

**Files:**
- Modify: `core/tests/differential_replay_helpers/rust_decoder.rs` (`"record"` arm)
- Modify: `core/tests/differential_replay_helpers/targets.rs` (lists, doc, `MIN_CORPUS_INPUTS`)
- Modify: `core/tests/differential_replay_helpers/agreement.rs` (one new test)

- [ ] **Step 1: Write the failing test**

In `agreement.rs`'s `mod tests`, add:

```rust
    /// `record` is compared strictly (#641): its canonical-form faults share
    /// one coarse token in both languages, so no phase-dependent pair is
    /// needed, or tolerated.
    #[test]
    fn record_is_compared_strictly() {
        const RECORD: &str = "record";
        assert!(TOKEN_COMPARED_TARGETS.contains(&RECORD));
        assert!(matches!(
            judge(
                RECORD,
                &rust_err(Some("non_canonical_unclassified")),
                &py_reject(Some("wrong_type"))
            ),
            Judgement::Disagree(_)
        ));
    }
```

Run: `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay record_is_compared_strictly > "$TMPDIR/t10.log" 2>&1; echo "exit=$?"` → exit=101 (the first assertion fails).

- [ ] **Step 2: Implement**

- In `rust_decoder.rs`'s `"record"` arm, change `token: None,` to `token: Some(e.rule_token().as_str()),`.
- In `targets.rs`, set `pub const TOKEN_COMPARED_TARGETS: &[&str] = &["record", "manifest_body", "block_file"];` and remove `"record"` from `NOT_TOKEN_COMPARED_TARGETS`, leaving `["vault_toml", "contact_card", "bundle_file", "manifest_file"]`.
- In the doc paragraph Task 5 wrote, replace `` `record` follows once its Python decoder reports in Rust's phase order. `` with `` `record` (#641) compares strictly too, since `conformance.py`'s record decoder reports in `record::decode`'s phase order and `record::decode` walks its bytes for well-formedness before ciborium. ``
- In `MIN_CORPUS_INPUTS`, change `("record", 3),` to `("record", 25),`.

- [ ] **Step 3: Run the CI-shape replay**

Run: `cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay > "$TMPDIR/r10.log" 2>&1; echo "exit=$?"; grep -E "test result|\] (record|block_file|manifest_body):" "$TMPDIR/r10.log"`
Expected: exit=0; `45 passed`; `record: 25 of 25 input(s) compared, 25 committed`; `block_file: 16 of 16`; `manifest_body` unchanged. Record all finish lines in `$SCRATCH/measurements.md`.

- [ ] **Step 4: Run the full runtime corpus (THE acceptance measurement)**

```bash
cd /Users/hherb/src/secretary/.worktrees/token-compare-record-block
test ! -e core/fuzz/corpus && ln -s /Users/hherb/src/secretary/core/fuzz/corpus core/fuzz/corpus
cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay -- differential_replay_full_corpus > "$TMPDIR/full10.log" 2>&1; echo "exit=$?"
grep -E "\[differential_replay\] .* compared|test result|disagreements \(|harness failures \(" "$TMPDIR/full10.log"
rm core/fuzz/corpus && git status --short | grep -c corpus
```

Expected: exit=0; `record: 7476 of 7476 input(s) compared` (7,451 runtime + 25 committed) and `block_file: 133 of 133`; every other target agreeing as before; the final count `0`.

If `record` disagrees on any input: STOP. For each distinct `(rust token, python token)` pair, take one input and classify it:
- **Mapping bug:** a token table disagrees with spec §3 or §5.2. Fix the table.
- **Ordering bug:** Python's order differs from §5.2's. Fix Python, and add the shape as a Section RTS check-5 case.
- **Genuine finding:** a new leniency or strictness in either decoder. Resolve it explicitly (fix the decoder that deviates from RFC 8949 / §4.2, adding a unit test and a seed), or, if it is ciborium's depth limit, it is the filed residual. It must then be removed from the corpus comparison by fixing, never by allowlisting.

Record the distinct pairs, their resolution, and the final finish lines in `$SCRATCH/measurements.md`. A `harness failures` line mentioning `RecursionError` is the Python side's recursion in `_check_canonical_item`/`cbor2.loads` on a deeply nested input. Treat it as the filed depth residual only if that input also exceeds ciborium's limit; otherwise it is a finding.

- [ ] **Step 5: Commit**

```bash
git add core/tests/differential_replay_helpers/rust_decoder.rs core/tests/differential_replay_helpers/targets.rs core/tests/differential_replay_helpers/agreement.rs
git commit -F - <<'EOF'
Token-compare record in the differential replay (#641)

record joins manifest_body and block_file in TOKEN_COMPARED_TARGETS and
compares strictly: no phase-dependent tolerance, because both
languages now report a record's rules in the same phase order and put
every canonical-form fault under one coarse token. Its committed floor
rises 3 -> 25, every one a strict comparison.

Measured locally with the runtime fuzz corpus present: every record
input agrees (7,451 runtime plus 25 committed), where the pre-slice
decoders would have disagreed on 2,949 under the same tokens.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

Correct the numbers in this message to the measured Step 4 figures before committing, if they differ.

- [ ] **Step 6: Negative controls through the real gate (after the commit)**

Write `$SCRATCH/t10-control.toml`:

```toml
[[mutation]]
id = "RC1"
lang = "rust"
path = "core/src/vault/rule_tokens/record.rs"
old = "RecordError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange,"
new = "RecordError::IntegerOverflow { .. } => RuleToken::WrongType,"
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "Rust names a negative timestamp wrong_type where Python names integer_out_of_range"
probe = { package = "secretary-core" }

[[mutation]]
id = "RC2"
lang = "python"
path = "core/tests/python/conformance_lib/codec/record_rules.py"
old = 'token = "duplicate_map_key"'
new = 'token = "wrong_type"'
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["differential_replay_full_corpus"]
note = "Python names a repeated record key wrong_type"
probe = { module = "conformance_lib.codec.record_rules", expr = "RecordDuplicateKey.token", equals = "wrong_type", syspath = "core/tests/python" }
```

Run: `uv run --with cbor2 scripts/mutate.py "$SCRATCH/t10-control.toml" > "$SCRATCH/t10-control.out" 2>&1; echo "exit=$?"; tail -6 "$SCRATCH/t10-control.out"; git status --short`
Expected: exit=0; both rows `RED_AS_EXPECTED`; `git status --short` prints nothing. Paste the table into `measurements.md`.

---

### Task 11: Documentation, and the filed follow-ups

**Files:**
- Modify: `CLAUDE.md`
- Modify: `docs/manual/contributors/differential-replay-protocol.md`
- Modify: `core/fuzz/README.md`
- Modify: `.github/workflows/test.yml` (comment only)
- Modify: `ROADMAP.md`

- [ ] **Step 1: File the four follow-up issues**

Run each command from the worktree and record the numbers `gh` prints:

```bash
gh issue create --title "[test] Walk manifest and block-plaintext bytes for well-formedness before ciborium, in both languages" --body "$(cat <<'EOF'
#641 added `cbor::well_formed::walk_first_item` and wired it into `record::decode` only, with a Python twin (`codec/well_formed.py::walk_body`) run first by `py_decode_record`.

The same ciborium leniencies reach `decode_manifest` and `block::decode_plaintext` (including `block.rs`'s nested `record::decode_value`), which parse through the same `from_secret_reader`:
- `undefined` (0xf7) is read as `null`;
- bignum tags 2/3 become integers, so the parsed-tree `reject_floats_and_tags` never sees them;
- nested indefinite-length string chunks are accepted.

Measured on the record corpus (spec 2026-09-15 §1.3): 57 / 28 / 4 inputs. Nobody has measured the manifest path, because `manifest_body` has no fuzz corpus. vault-format §4.2's well-formedness precondition names the first case explicitly, so the manifest decoder's REPORTED error is non-conformant there today. Acceptance is not affected.

Acceptance: wire the walk into both decoders, in both languages (Python's manifest path runs `reject_floats_and_tags` over `_scan_item`, which checks neither UTF-8 nor simple values); add seeds for the three shapes under `manifest_body`; a legacy-oracle proptest per decoder showing the accepted set does not move.
EOF
)"
gh issue create --title "[test] ciborium's recursion limit is a Rust-only rejection on the record path" --body "$(cat <<'EOF'
After #641, `record::decode` walks a record's bytes iteratively with no depth cap, then parses with ciborium, whose recursion limit (256) still applies. A well-formed record nested deeper than that is `CborDecode(RecursionLimit)` → `malformed_cbor` to Rust, while `conformance.py` has no such limit and reports whatever schema fault the body carries (or, for extreme depth, a `RecursionError` harness failure in `_check_canonical_item` / `cbor2.loads`). No committed or runtime corpus input reached it in #641's measurement, and nothing pins that.

vault-format states no maximum nesting depth. The decision this needs: either state a v1 depth limit normatively and enforce it in both walks (a frozen-spec edit, but ciborium has imposed it on every v1 reader in this codebase since v1), or document it as an implementation limit and make the Python side's recursion iterative so the failure is a verdict, not a harness failure.
EOF
)"
gh issue create --title "[spec] Decide report-order text for vault-format §6.1 (block envelope) and §6.3 (record body)" --body "$(cat <<'EOF'
#641 made `block_file` and `record` token-compared with ZERO tolerated pairs, by making `conformance.py` report in the same phase order as the Rust decoders. That pins parity between OUR two implementations; vault-format §6.1 and §6.3 state no report order, unlike §4.2 for the manifest body (#618).

Committed seeds each plant exactly one fault, so no committed cross-language row pins an unspecified order. The orders ARE pinned by Section RTS check 5 (local, labelled parity) and by any local full-corpus replay.

Decide, together with #646: fix §6.1/§6.3 orders normatively (the natural one for §6.1 is "first violation in wire order"), or state them as unspecified and give those targets a licensed tolerance. The latter widens the tolerated set #646 is trying to narrow.
EOF
)"
```

Do not file a separate issue for `contact_card` / `bundle_file` / `vault_toml`: #641 stays open for them. Add a comment to #641 instead:

```bash
gh issue comment 641 --body "block_file and record are token-compared as of the PR for branch feature/token-compare-record-block (strict, zero tolerated pairs, committed single-fault seeds bound in both languages). contact_card, bundle_file and vault_toml remain; this issue stays open for them. Spec: docs/superpowers/specs/2026-09-15-token-compare-record-block-design.md"
```

- [ ] **Step 2: Update CLAUDE.md**

Make these edits, each against text quoted verbatim from the current file:

1. Layout block: `stale — the verifier is now a 66-file package.` → re-measure with `find core/tests/python/conformance_lib -name '*.py' | wc -l` and write the result, expected `72`.
2. `was 6849 lines; it is now 156, over a **66**-file package` → the same measured count.
3. `MPR; 29/29 after #634's Section RTV; **30/30** since #655 added Section DRS).` → `MPR; 29/29 after #634's Section RTV; 30/30 after #655's Section DRS; **32/32** since #641 added Sections RTS and WF).`
4. In the bullet beginning `- **\`tokens_agree\` tolerates a mismatch iff either token is phase-dependent**`, insert right after that bold lead-in: `— **on \`manifest_body\` only** since #641, which made the licence per TARGET (\`PHASE_DEPENDENT_TOLERANCE_TARGETS\`): §4.2's two reader designs are the manifest body's, so \`record\` and \`block_file\` compare strictly with 0 tolerated pairs, and the breadth test pins both figures —`.
5. Replace the bullet heading `- **Only \`manifest_body\` is token-compared. \`manifest_file\` is BLOCKED, and the` with `- **\`manifest_body\`, \`block_file\` and \`record\` are token-compared (#634, #641). \`manifest_file\` is BLOCKED, and the`, and in the same bullet replace `The other five targets are #641.` with `\`contact_card\`, \`bundle_file\` and \`vault_toml\` remain #641. \`record\` needed its Python decoder reordered into \`record::decode\`'s phase order and a byte-level well-formedness walk in front of ciborium on both sides (ciborium reads \`undefined\` as \`null\`, turns bignum tags into integers and accepts nested indefinite chunks — rejected anyway, but under a later rule); \`block_file\` needed only Python's merged sort/repeat check split. Both have committed single-fault seeds, generated and label-bound by \`core/tests/rule_token_seeds.rs\` and Section RTS, so CI makes a strict comparison per seed; the orders they rely on are PARITY, not spec (§6.1/§6.3 fix none; filed).`
6. In the Commands block's differential-replay comment, after `# CI replays the 50 committed inputs (no \`corpus/\` there).` → change `50` to the Step 3 committed total of Task 10 (expected `87`: 50 + 15 block_file + 22 record), and append the sentence `# #641 added 37 generated single-fault seeds for block_file and record; regenerate with \`cargo test --release --locked -p secretary-core --test rule_token_seeds -- --ignored generate_rule_token_seeds\`.`

Keep every other paragraph unchanged. Where a figure elsewhere in CLAUDE.md now conflicts with a measurement, re-measure it rather than guessing, and list each change in the commit message.

- [ ] **Step 3: Update the protocol memo, the fuzz README and the CI comment**

- `docs/manual/contributors/differential-replay-protocol.md`: replace `— today \`manifest_body\`\n  and nothing else.` (the wrapped sentence under "**`rule` is compared**") with `— today \`manifest_body\`, \`block_file\` and \`record\` (#641).` In the "A token mismatch is a disagreement **unless either token is phase-dependent**" bullet, insert after its first sentence: `Since #641 that tolerance applies on \`manifest_body\` only (\`PHASE_DEPENDENT_TOLERANCE_TARGETS\`); \`block_file\` and \`record\` compare strictly.`
- `core/fuzz/README.md`: add a subsection directly after `### \`seeds/manifest_body/\` has no fuzz target`:

```markdown
### Generated single-fault seeds in `seeds/record/` and `seeds/block_file/`

Every `<token>__<shape>.bin` in those two directories is GENERATED by
`core/tests/rule_token_seeds.rs` (#641): each plants exactly one fault into
the directory's accepting base (`login.cbor`, `golden.bin`), and both
decoders must reject it with the token its name gives. They are fuzz starting
points as well as CI inputs. Do not edit or add one by hand: change the case
table and regenerate with

    cargo test --release --locked -p secretary-core --test rule_token_seeds -- --ignored generate_rule_token_seeds

Changing a base file changes every seed planted into it, and the non-ignored
label-binding test reds until they are regenerated deliberately.
```

- `.github/workflows/test.yml`: in the replay step's comment, after the `WHAT THIS COVERS is the COMMITTED corpus` paragraph, add the comment lines `# Since #641 that includes generated single-fault seeds for \`record\` and`, `# \`block_file\`, so the two targets make a STRICT token comparison per seed here.` Then run `actionlint .github/workflows/test.yml; echo "exit=$?"` → exit=0, and read the step name back unchanged: `grep -n "name: 'cargo test --features differential-replay" .github/workflows/test.yml`.

- [ ] **Step 4: ROADMAP**

Add a bullet directly after the `The whole fuzz corpus replays through both decoders in seconds` bullet (dated 2026-09-15, ✅), in that section's style: what was compared before and after; the spike's 2,949 → 0; the three ciborium leniencies; the bool-as-uint acceptance divergence; target-aware tolerance; 37 generated seeds bound in both languages; REG 30 → 32; the filed issue numbers from Step 1. Use the measured figures from `$SCRATCH/measurements.md`, not this plan's expectations.

- [ ] **Step 5: README check**

Run: `grep -n -i "token\|differential\|replay" README.md`. The last baton recorded that README documents specs and protocols and names no CI job. If this grep shows no sentence this slice made false, do not edit README, and say so in the handoff. Otherwise make the smallest correction.

- [ ] **Step 6: Commit**

```bash
git add CLAUDE.md docs/manual/contributors/differential-replay-protocol.md core/fuzz/README.md .github/workflows/test.yml ROADMAP.md
git commit -F - <<'EOF'
Document block_file and record token comparison (#641)

CLAUDE.md, the differential-replay protocol memo, the fuzz README, the
CI step's comment and ROADMAP now say which targets are compared, that
the phase-dependent tolerance is manifest_body's alone, where the
generated seeds come from and how to regenerate them, and the measured
full-corpus result. Re-measured rather than quoted: the verifier's file
count and REG's section count.

Filed: the walk's rollout to the manifest and block-plaintext
decoders, ciborium's depth limit as a Rust-only rejection, and the
§6.1/§6.3 report-order decision (with #646).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
```

Replace "Filed:" with the actual issue numbers from Step 1.

---

### Task 12: Mutation evidence and the full gate set

**Files:** none in the tree. The spec and outputs go in `$SCRATCH`.

- [ ] **Step 1: Self-test the harness**

Run: `cd /Users/hherb/src/secretary/.worktrees/token-compare-record-block && uv run scripts/mutate.py --self-test > "$SCRATCH/selftest.out" 2>&1; echo "exit=$?"; tail -3 "$SCRATCH/selftest.out"` → exit=0, `20/20`.

- [ ] **Step 2: Check every `old` string occurs exactly once**

The harness refuses a row whose `old` does not occur exactly once. rustfmt may have reflowed a line, so check first:

```bash
for pair in \
  "core/src/vault/rule_tokens/record.rs|RecordError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange," \
  "core/src/vault/rule_tokens/block.rs|RuleToken::RepeatedArrayValue" \
  "core/tests/differential_replay_helpers/tolerance.rs|PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(&target)" \
  "core/src/cbor/well_formed.rs|SIMPLE_FALSE | SIMPLE_TRUE | SIMPLE_NULL => {}" \
  "core/src/cbor/well_formed.rs|if chunk.major != major || chunk.arg.is_none() {" \
  "core/src/cbor/well_formed.rs|first_rule4.get_or_insert(WalkFault::Tag { offset: pos });" \
  "core/src/vault/record.rs|walk_first_item(bytes).map_err(walk_fault_to_record_error)?;" \
  "core/tests/python/conformance_lib/wire/envelope_rules.py|if prev == nxt:" \
  "core/tests/python/conformance_lib/codec/record.py|out[key] = check_record_value(key, cbor2.loads(data[vs:ve]))" \
  "core/tests/python/conformance_lib/codec/well_formed.py|require_utf8(buf, start, end, head_at)" \
  "core/tests/python/conformance_lib/codec/record_rules.py|token = \"non_canonical_unclassified\"" \
  "core/tests/rule_token_seeds_helpers/record.rs|case(DuplicateMapKey, \"record_level\", duplicate_record_key)," \
  "core/tests/python/conformance_lib/codec/cbor_faults.py|token = \"malformed_cbor\""; do
  f="${pair%%|*}"; s="${pair#*|}"; printf '%s  %s\n' "$(grep -cF -- "$s" "$f")" "$f"
done
```

Expected: every line starts with `1`. For any other count, copy the exact current text into the spec row below.

- [ ] **Step 3: Write and run the evidence spec**

Write `$SCRATCH/t12-mutations.toml`:

```toml
[[mutation]]
id = "R1"
lang = "rust"
path = "core/src/vault/rule_tokens/record.rs"
old = "RecordError::IntegerOverflow { .. } => RuleToken::IntegerOutOfRange,"
new = "RecordError::IntegerOverflow { .. } => RuleToken::WrongType,"
gate = "cargo test --release --locked -p secretary-core --lib --test rule_token_seeds"
expect = "red"
expect_red = ["every_record_error_variant_carries_its_declared_token", "rule_token_seeds_are_committed_and_label_bound"]
note = "a RecordError arm repointed at another token"
probe = { package = "secretary-core" }

[[mutation]]
id = "R2"
lang = "rust"
path = "core/src/vault/rule_tokens/block.rs"
old = "RuleToken::RepeatedArrayValue"
new = "RuleToken::ContainerMalformed"
gate = "cargo test --release --locked -p secretary-core --lib --test rule_token_seeds"
expect = "red"
expect_red = ["every_block_error_variant_carries_its_declared_token", "rule_token_seeds_are_committed_and_label_bound"]
note = "a BlockError arm repointed at another token"
probe = { package = "secretary-core" }

[[mutation]]
id = "R3"
lang = "rust"
path = "core/tests/differential_replay_helpers/tolerance.rs"
old = "PHASE_DEPENDENT_TOLERANCE_TARGETS.contains(&target)"
new = "true"
gate = "cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay"
expect = "red"
expect_red = ["tolerance_admits_only_phase_dependent_pairs", "a_phase_dependent_pair_on_an_unlicensed_compared_target_disagrees"]
note = "the tolerance loses target-awareness"
probe = { package = "secretary-core", test = "differential_replay", features = ["differential-replay"] }

[[mutation]]
id = "R4"
lang = "rust"
path = "core/src/cbor/well_formed.rs"
old = "SIMPLE_FALSE | SIMPLE_TRUE | SIMPLE_NULL => {}"
new = "SIMPLE_FALSE..=AI_DIRECT_MAX => {}"
gate = "cargo test --release --locked -p secretary-core --lib --test rule_token_seeds"
expect = "red"
expect_red = ["undefined_and_unassigned_simple_values_are_malformed", "each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk", "rule_token_seeds_are_committed_and_label_bound"]
note = "the walk accepts undefined"
probe = { package = "secretary-core" }

[[mutation]]
id = "R5"
lang = "rust"
path = "core/src/cbor/well_formed.rs"
old = "if chunk.major != major || chunk.arg.is_none() {"
new = "if chunk.major != major {"
gate = "cargo test --release --locked -p secretary-core --lib --test rule_token_seeds"
expect = "red"
expect_red = ["a_nested_indefinite_chunk_is_malformed", "each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk", "rule_token_seeds_are_committed_and_label_bound"]
note = "the walk accepts a nested indefinite chunk"
probe = { package = "secretary-core" }

[[mutation]]
id = "R6"
lang = "rust"
path = "core/src/cbor/well_formed.rs"
old = "first_rule4.get_or_insert(WalkFault::Tag { offset: pos });"
new = "return Err(WalkFault::Tag { offset: pos });"
gate = "cargo test --release --locked -p secretary-core --lib"
expect = "red"
expect_red = ["well_formedness_outranks_rule_four_anywhere_in_the_item"]
note = "the walk reports a tag before proving the item well-formed"
probe = { package = "secretary-core" }

[[mutation]]
id = "R7"
lang = "rust"
path = "core/src/vault/record.rs"
old = "walk_first_item(bytes).map_err(walk_fault_to_record_error)?;"
new = "let _ = walk_first_item(bytes);"
gate = "cargo test --release --locked -p secretary-core --lib --test rule_token_seeds"
expect = "red"
expect_red = ["each_ciborium_leniency_is_rejected_by_both_and_renamed_by_the_walk", "rule_token_seeds_are_committed_and_label_bound"]
note = "record::decode runs the walk but ignores its verdict"
probe = { package = "secretary-core" }

[[mutation]]
id = "P1"
lang = "python"
path = "core/tests/python/conformance_lib/wire/envelope_rules.py"
old = "if prev == nxt:"
new = "if prev == nxt and False:"
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["rule-token seeds are rejected with the rule their file names"]
note = "equal envelope ids are no longer classified as a repeat"
probe = { module = "conformance_lib.wire.envelope_rules", expr = "str(__import__('inspect').getsource(check_ascending_distinct).count('and False'))", equals = "1", syspath = "core/tests/python" }

[[mutation]]
id = "P2"
lang = "python"
path = "core/tests/python/conformance_lib/codec/record.py"
old = "out[key] = check_record_value(key, cbor2.loads(data[vs:ve]))"
new = "out[key] = cbor2.loads(data[vs:ve])"
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["rule-token seeds are rejected with the rule their file names"]
note = "record values are no longer checked as their key is read"
probe = { module = "conformance_lib.codec.record", expr = "str(__import__('inspect').getsource(py_decode_record).count('check_record_value('))", equals = "0", syspath = "core/tests/python" }

[[mutation]]
id = "P3"
lang = "python"
path = "core/tests/python/conformance_lib/codec/well_formed.py"
old = "require_utf8(buf, start, end, head_at)"
new = "pass"
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["well-formedness walk, the twin of cbor::well_formed", "rule-token seeds are rejected with the rule their file names"]
note = "the Python walk stops checking UTF-8"
probe = { module = "conformance_lib.codec.well_formed", expr = "str(__import__('inspect').getsource(_payload_end).count('require_utf8('))", equals = "0", syspath = "core/tests/python" }

[[mutation]]
id = "P4"
lang = "python"
path = "core/tests/python/conformance_lib/codec/record_rules.py"
old = 'token = "non_canonical_unclassified"'
new = 'token = "rule2_indefinite_length"'
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["rule-token seeds are rejected with the rule their file names"]
note = "the record path names rule 2 where Rust cannot"
probe = { module = "conformance_lib.codec.record_rules", expr = "RecordNonCanonical.token", equals = "rule2_indefinite_length", syspath = "core/tests/python" }

[[mutation]]
id = "P5"
lang = "python"
path = "core/tests/python/conformance_lib/codec/cbor_faults.py"
old = 'token = "malformed_cbor"'
new = 'token = "wrong_type"'
gate = "uv run core/tests/python/conformance.py"
expect = "red"
expect_red = ["rule-token seeds are rejected with the rule their file names"]
note = "a well-formedness fault is named a wrong type"
probe = { module = "conformance_lib.codec.cbor_faults", expr = "MalformedCbor.token", equals = "wrong_type", syspath = "core/tests/python" }

[[mutation]]
id = "S1"
lang = "rust"
path = "core/tests/rule_token_seeds_helpers/record.rs"
old = 'case(DuplicateMapKey, "record_level", duplicate_record_key),'
new = 'case(DuplicateMapKey, "record_level", duplicate_field_name),'
gate = "cargo test --release --locked -p secretary-core --test rule_token_seeds"
expect = "red"
expect_red = ["rule_token_seeds_are_committed_and_label_bound"]
note = "a row plants different bytes than its committed seed holds"
probe = { package = "secretary-core", test = "rule_token_seeds" }
```

Run: `uv run --with cryptography --with pynacl --with "pqcrypto<1" --with argon2-cffi --with blake3 --with cbor2 scripts/mutate.py "$SCRATCH/t12-mutations.toml" > "$SCRATCH/t12.out" 2>&1; echo "exit=$?"; git status --short`
Expected: exit=0; 13 rows `RED_AS_EXPECTED`; `git status --short` prints nothing. Paste the rendered table into `$SCRATCH/measurements.md`.

A row that reads anything else is a finding to understand, not a spec to adjust until green:
- **`NOT_LIVE`:** read the diagnostic; the probe could not see the change.
- **`WRONG_TESTS_RED`:** the named test is not the one that caught it. Check whether the claimed test really asserts what the note says.
- **`UNEXPECTED_GREEN`:** a gap. Fix it (a test, a seed, a Section RTS case) in its own commit, then re-run only that row.

- [ ] **Step 4: The full gate set, each read by exit code**

```bash
cd /Users/hherb/src/secretary/.worktrees/token-compare-record-block
cargo test --release --locked --workspace > "$SCRATCH/g-test.log" 2>&1; echo "workspace test exit=$?"; grep -E "^test result" "$SCRATCH/g-test.log" | awk '{p+=$4; f+=$6} END {print "passed", p, "failed", f}'
cargo test --release --locked -p secretary-core --features differential-replay --test differential_replay > "$SCRATCH/g-replay.log" 2>&1; echo "replay exit=$?"
cargo clippy --release --locked --workspace --tests -- -D warnings > "$SCRATCH/g-clippy.log" 2>&1; echo "clippy exit=$?"
cargo clippy --release --locked -p secretary-core --features differential-replay --tests -- -D warnings > "$SCRATCH/g-clippy2.log" 2>&1; echo "clippy feature exit=$?"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace > "$SCRATCH/g-doc.log" 2>&1; echo "rustdoc exit=$?"
cargo fmt --all --check; echo "fmt exit=$?"
uv run core/tests/python/conformance.py > "$SCRATCH/g-conf.log" 2>&1; echo "conformance exit=$?"; grep -c "^FAIL" "$SCRATCH/g-conf.log"
uv run --with pytest python3 -m pytest scripts/mutation_harness -q > "$SCRATCH/g-harness.log" 2>&1; echo "harness pytest exit=$?"; tail -1 "$SCRATCH/g-harness.log"
uv run core/tests/python/spec_test_name_freshness.py > "$SCRATCH/g-fresh.log" 2>&1; echo "freshness exit=$? (exit 1 with 98 unresolved is main's baseline, #642)"; tail -2 "$SCRATCH/g-fresh.log"
actionlint .github/workflows/test.yml; echo "actionlint exit=$?"
bash ffi/scripts/check-lean-binding.sh --self-test         && bash ffi/scripts/check-lean-binding.sh; echo "lean exit=$?"
bash ios/scripts/check-public-log-hygiene.sh --self-test   && bash ios/scripts/check-public-log-hygiene.sh; echo "ios log exit=$?"
bash android/scripts/check-log-hygiene.sh --self-test      && bash android/scripts/check-log-hygiene.sh; echo "android log exit=$?"
bash scripts/check-secret-slot-hygiene.sh --self-test      && bash scripts/check-secret-slot-hygiene.sh; echo "secret slot exit=$?"
uv run scripts/check-error-payload-hygiene.py --self-test  && uv run scripts/check-error-payload-hygiene.py; echo "payload exit=$?"
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py; echo "placement exit=$?"
```

Expected: every exit=0 except `spec_test_name_freshness.py`, which must report the same unresolved count as `main` (98). If it reports more, a new doc citation names a test that does not exist: fix the citation. `grep -c "^FAIL"` prints `0`. Record every line in `measurements.md`, with the workspace test total and the harness pytest count.

Run the workspace test and the clippy lines one after another, not in parallel: parallel cargo invocations queue on the package-cache lock and look hung.

---

### Task 13: Review round, handoff, PR

- [ ] **Step 1: Review the branch**

Invoke `superpowers:requesting-code-review` (or `pr-review-toolkit:review-pr`) over `git diff main...HEAD`. Give reviewers the spec path and this plan. Fix each finding in its own commit, re-running the gates it touches, or file it as an issue. Re-run Task 12 Step 4 after the last fix.

- [ ] **Step 2: Write the handoff and retarget the symlink**

Create `docs/handoffs/2026-09-15-token-compare-record-block-shipped.md` in the style of `docs/handoffs/2026-09-14-corpus-replay-worker-shipped.md`. It must contain:
- **§(0)** the starting-state check. `origin/main` had advanced to `4f350d64` (PR #662) since the last baton; `.worktrees/diff-replay-split` was removed; PR #665 (npm advisories) was opened first.
- **§(1)** what shipped, with commit SHAs from `git log --oneline main..HEAD`, and the measured figures from `$SCRATCH/measurements.md`: spike 2,949 → 0, full-corpus finish lines, before/after accept set, both mutation tables pasted.
- **§(2)** what this slice does NOT claim (spec §7), and that orders are parity, not spec.
- **§(3)** next, with acceptance criteria: #612; #657; #660; the walk rollout issue from Task 11; `contact_card`/`bundle_file` under #641; #646 plus the §6.1/§6.3 order issue.
- **§(4)** open decisions and risks: the depth residual; #648's `RuleToken` home; the bool-as-uint acceptance divergence found and fixed.
- **§(5)** the exact resume commands: `git fetch origin && git log --oneline main..origin/main`, `cd` to the worktree, the CI-shape replay, the seed regeneration command, the full-corpus symlink recipe, the conformance run.

Then:

```bash
ln -snf docs/handoffs/2026-09-15-token-compare-record-block-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
git add docs/handoffs/2026-09-15-token-compare-record-block-shipped.md NEXT_SESSION.md docs/superpowers/plans/2026-09-15-token-compare-record-block.md
git commit -m "Hand off block_file and record token comparison (#641)" -m "Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 3: Push and open the PR**

```bash
git fetch origin && git log --oneline HEAD..origin/main
```

If that prints commits, run `git merge origin/main` and resolve per the `/nextsession` fixup discipline, then re-run Task 12 Step 4.

```bash
git push -u origin feature/token-compare-record-block
gh pr create --base main --title "Token-compare block_file and record in the differential replay (#641)" --body-file "$SCRATCH/pr-body.md"
```

Write `$SCRATCH/pr-body.md` first. Include a summary, the measured before/after table, both mutation tables pasted from `mutate.py`, the filed issue numbers, and a "not claimed" section. End it with the line `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

After CI finishes, read the replay step's finish lines from the `cargo test (ubuntu-latest)` job log (`gh run view --job <id> --log | grep "\[differential_replay\]"`). `record: 25 of 25` and `block_file: 16 of 16` must appear. A green tick alone is not the evidence.

