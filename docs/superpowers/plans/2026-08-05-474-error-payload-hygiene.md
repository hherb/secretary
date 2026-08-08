# #474 — Secret-Free Error Payloads in `core`, Enforced — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make it structurally impossible for a `core` error message to carry decrypted vault plaintext, then remove the wholesale redactions both platform UIs currently apply to compensate.

**Architecture:** Three moves in order. (1) Replace plaintext-bearing `String` payloads with compile-time-constant hints plus ordinals. (2) Discard the `ciborium` error message at the boundary via a new pure `core/src/cbor.rs`, killing a content-traced claim about a third-party crate. (3) Add a fail-closed CI guard so a future plaintext-bearing variant fails in the Rust author's own PR rather than silently degrading a platform two layers away. Only then do the iOS/Android redactions come off — the narrowing is sound *because* of 1–3.

**Tech Stack:** Rust (stable, pinned 1.97.0), `thiserror`, `ciborium` 0.2.2, Python 3 via `uv`, GitHub Actions, Swift 6, Kotlin/Compose.

**Spec:** [`docs/superpowers/specs/2026-08-05-474-error-payload-hygiene-design.md`](../specs/2026-08-05-474-error-payload-hygiene-design.md)

## Global Constraints

- **Worktree:** `/Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene`, branch `feature/474-error-payload-hygiene`. Use an **absolute `cd` in every Bash call** — shell state does not persist between tool calls, and this session's predecessor drifted to the main checkout twice.
- **`#![forbid(unsafe_code)]`** is set workspace-wide. Do not introduce `unsafe`.
- **Clippy must stay clean:** `cargo clippy --release --workspace --tests -- -D warnings`.
- **Rustdoc must stay clean:** `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`. Intra-doc links to items you rename will break the build.
- **Always `--release`** for `cargo test`; the crypto crates are unusably slow in debug.
- **Never `pip`.** Python runs via `uv` exclusively.
- **No on-disk format change, no `FfiVaultError` variant change, no `.udl` change.** If a task seems to require one, stop and escalate — it means the design was wrong.
- **Tests use runtime-random crypto values**, never hardcoded byte arrays (hardcoded arrays trip CodeQL). KAT vectors come from JSON fixtures only.
- **Commit message trailer** (every commit): `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- **Do not run `:app:assembleDebug` for iteration** — it takes ~10 minutes here (cargo-ndk cross-compiles for four Android ABIs). Use `:vault-access:test` and `compileDebugKotlin`; save the full assemble for final acceptance.

## Scope adjustment from the spec — read this before Task 7

The spec places `SyncError::StateDecodeFailed` / `StateEncodeFailed` in Group 2 (full `CborFault` treatment). Implementation reconnaissance found **21 producers**, of which 18 pass fixed structural literals about the local sync-state cache. `SyncState` (`core/src/sync/state.rs:17-20`) holds exactly `vault_uuid: [u8; 16]` and `highest_vector_clock_seen: Vec<VectorClockEntry>` — device UUIDs and counters. **No vault plaintext can reach these messages.**

Converting 21 call sites to eliminate a `String` that provably cannot carry a secret is disproportionate churn. **Task 7 therefore does the one thing that matters** — kills the `ciborium` passthrough at `state.rs:137` — and Task 9 records the two variants as reviewed allowlist entries with that reasoning. This is a deliberate, documented deviation, not an oversight.

## File Structure

**Created:**

| Path | Responsibility |
|---|---|
| `core/src/cbor.rs` | Pure classification of `ciborium` errors into a data-free `CborFault`. No I/O. The only place the upstream message is seen, and it is discarded there. |
| `scripts/check-error-payload-hygiene.py` | The guard. Parses `#[error]` attributes in `core/src/**`, denies runtime-`String` interpolation by default. |
| `scripts/error-payload-hygiene-allowlist.txt` | Reviewed exceptions, keyed on exact trimmed source line. |
| `core/tests/error_payload_hygiene_parity.rs` | Asserts the Python and bash allowlist parsers agree on one shared fixture. |

**Modified:** `core/src/lib.rs` (register `cbor`), `core/src/vault/{record,block,manifest,canonical,mod}.rs`, `core/src/identity/card.rs`, `core/src/unlock/bundle.rs`, `core/src/sync/state.rs`, `.github/workflows/test.yml`, `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift`, `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt`, `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt`, `CLAUDE.md`.

---

## Task 1: `core/src/cbor.rs` — data-free classification of `ciborium` errors

**Files:**
- Create: `core/src/cbor.rs`
- Modify: `core/src/lib.rs`

**Interfaces:**
- Consumes: nothing (self-contained; no callers yet).
- Produces: `secretary_core::cbor::{CborErrorKind, CborFault, classify_de, classify_ser}`.
  - `CborErrorKind` — `enum { Io, Syntax, RecursionLimit, Semantic, Serialization }`, derives `Debug, Clone, Copy, PartialEq, Eq`.
  - `CborFault` — `struct { pub kind: CborErrorKind, pub offset: Option<usize> }`, derives `Debug, Clone, Copy, PartialEq, Eq`, implements `Display`.
  - `pub fn classify_de<E>(e: &ciborium::de::Error<E>) -> CborFault`
  - `pub fn classify_ser<E>(e: &ciborium::ser::Error<E>) -> CborFault`

**Background the implementer needs.** `ciborium::de::Error<T>` (v0.2.2, `src/de/error.rs`) has exactly four variants: `Io(T)`, `Syntax(usize)`, `Semantic(Option<usize>, String)`, `RecursionLimitExceeded`. `ciborium::ser::Error<T>` (`src/ser/error.rs`) has exactly two: `Io(T)`, `Value(String)`. Both implement `Display` as `write!(f, "{:?}", self)` — the **Debug** form — so today's `e.to_string()` prints the `String` payload verbatim. That `String` comes from `serde::de::Error::custom`, and serde's standard `invalid_type` / `invalid_value` messages embed the offending value. Discarding it is the entire point of this module.

- [ ] **Step 1: Write the failing test**

Create `core/src/cbor.rs` with only the test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_de_maps_syntax_to_kind_and_offset() {
        let e: ciborium::de::Error<std::io::Error> = ciborium::de::Error::Syntax(41);
        let fault = classify_de(&e);
        assert_eq!(fault.kind, CborErrorKind::Syntax);
        assert_eq!(fault.offset, Some(41));
    }

    #[test]
    fn classify_de_maps_recursion_limit() {
        let e: ciborium::de::Error<std::io::Error> = ciborium::de::Error::RecursionLimitExceeded;
        let fault = classify_de(&e);
        assert_eq!(fault.kind, CborErrorKind::RecursionLimit);
        assert_eq!(fault.offset, None);
    }

    #[test]
    fn classify_de_maps_io() {
        let e: ciborium::de::Error<std::io::Error> =
            ciborium::de::Error::Io(std::io::Error::other("disk on fire"));
        let fault = classify_de(&e);
        assert_eq!(fault.kind, CborErrorKind::Io);
        assert_eq!(fault.offset, None);
    }

    /// THE test this module exists for. `Semantic`'s `String` is the only
    /// data-bearing field in either upstream error, and serde's standard
    /// `invalid_type` message embeds the offending VALUE. It must not survive
    /// classification, must not appear in `Display`, and must not appear in
    /// `Debug` either — `Debug` is what `{:?}` in an assertion message prints.
    #[test]
    fn classify_de_discards_the_semantic_message() {
        const MARKER: &str = "amex-cvv-4111111111111111";
        let e: ciborium::de::Error<std::io::Error> =
            ciborium::de::Error::Semantic(Some(7), MARKER.to_string());

        let fault = classify_de(&e);

        assert_eq!(fault.kind, CborErrorKind::Semantic);
        assert_eq!(fault.offset, Some(7), "the offset is deliberately kept");
        assert!(
            !format!("{fault}").contains(MARKER),
            "Display leaked the semantic message: {fault}"
        );
        assert!(
            !format!("{fault:?}").contains(MARKER),
            "Debug leaked the semantic message: {fault:?}"
        );
    }

    #[test]
    fn classify_ser_discards_the_value_message() {
        const MARKER: &str = "ex-wife-lawyer-password";
        let e: ciborium::ser::Error<std::io::Error> =
            ciborium::ser::Error::Value(MARKER.to_string());

        let fault = classify_ser(&e);

        assert_eq!(fault.kind, CborErrorKind::Serialization);
        assert!(!format!("{fault}").contains(MARKER));
        assert!(!format!("{fault:?}").contains(MARKER));
    }

    #[test]
    fn classify_ser_maps_io() {
        let e: ciborium::ser::Error<std::io::Error> =
            ciborium::ser::Error::Io(std::io::Error::other("nope"));
        assert_eq!(classify_ser(&e).kind, CborErrorKind::Io);
    }

    #[test]
    fn display_renders_offset_when_present_and_omits_it_when_absent() {
        let with = CborFault { kind: CborErrorKind::Syntax, offset: Some(12) };
        assert_eq!(format!("{with}"), "CBOR syntax error at byte offset 12");

        let without = CborFault { kind: CborErrorKind::RecursionLimit, offset: None };
        assert_eq!(format!("{without}"), "CBOR recursion limit exceeded");
    }
}
```

Register the module in `core/src/lib.rs`. The existing list is alphabetical (`crypto`, `error`, `identity`, `sync`, `unlock`, `vault`, `version`) — insert `cbor` first, before `crypto`:

```rust
pub mod cbor;
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core cbor:: 2>&1 | tail -20
```

Expected: FAIL to compile — `cannot find type CborFault in this scope`, `cannot find function classify_de`.

- [ ] **Step 3: Write minimal implementation**

Prepend to `core/src/cbor.rs`, above the test module:

```rust
//! Data-free classification of `ciborium` codec errors.
//!
//! `ciborium`'s error types implement `Display` as `write!(f, "{:?}", self)` —
//! the **Debug** rendering. `ciborium::de::Error::Semantic(_, String)` and
//! `ciborium::ser::Error::Value(String)` each carry a `serde::de::Error::custom`
//! message, and serde's standard `invalid_type` / `invalid_value` messages embed
//! the offending VALUE. Stringifying such an error into a `core` error variant
//! therefore risks copying decrypted vault plaintext into a message that both
//! platform UIs render and log.
//!
//! Every production `from_reader` call in this crate currently deserializes into
//! `ciborium::value::Value`, which accepts any CBOR item and so cannot raise a
//! value-bearing `Semantic`. **That is a content-traced claim about a
//! third-party crate** — a version bump or a single future typed `from_reader`
//! would invalidate it with no diff near any error definition and no failing
//! test. This module removes the need for the claim: the message is discarded
//! at the boundary, so it cannot reach an error variant regardless of what
//! upstream does.
//!
//! See `docs/superpowers/specs/2026-08-05-474-error-payload-hygiene-design.md`.

use std::fmt;

/// Which upstream codec failure occurred, with no payload of its own.
///
/// A fieldless enum is provably data-free: every value is a compile-time
/// constant, so no runtime content can ride along. This is the same property
/// the Android log guard relies on when it renders a cause chain as
/// fully-qualified type names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CborErrorKind {
    /// The reader or writer returned an I/O error.
    Io,
    /// The byte stream was not well-formed CBOR.
    Syntax,
    /// Nesting exceeded `ciborium`'s recursion limit.
    RecursionLimit,
    /// The decoder rejected a well-formed item on semantic grounds. The
    /// upstream message explaining *which* item is deliberately discarded —
    /// it is the one field in either upstream error that can carry data.
    Semantic,
    /// A value could not be serialized. The upstream description is
    /// discarded for the same reason as [`Self::Semantic`].
    Serialization,
}

impl CborErrorKind {
    /// Fixed human label. `&'static str` by construction.
    fn label(self) -> &'static str {
        match self {
            Self::Io => "CBOR I/O error",
            Self::Syntax => "CBOR syntax error",
            Self::RecursionLimit => "CBOR recursion limit exceeded",
            Self::Semantic => "CBOR semantic error",
            Self::Serialization => "CBOR serialization error",
        }
    }
}

/// A classified `ciborium` failure, carrying no upstream text.
///
/// `offset` is a byte position within the input, kept because it is the single
/// most useful datum when debugging a genuinely corrupt vault.
///
/// **Deliberate residual disclosure:** an offset into decrypted plaintext is a
/// weak length oracle — "duplicate at offset 41" narrows the possible lengths
/// of preceding field names. It is accepted because vault file sizes are
/// already visible on disk to anyone who can read the folder, so the threat
/// model treats plaintext *size* as disclosed. Recorded so the trade is
/// explicit rather than assumed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CborFault {
    /// What went wrong.
    pub kind: CborErrorKind,
    /// Byte offset into the input, when the codec reported one.
    pub offset: Option<usize>,
}

impl fmt::Display for CborFault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.offset {
            Some(off) => write!(f, "{} at byte offset {off}", self.kind.label()),
            None => write!(f, "{}", self.kind.label()),
        }
    }
}

/// Classify a decode error, discarding any upstream message.
///
/// Generic over the reader's I/O error type because `ciborium::de::Error<E>`
/// is — which is exactly why these were stringified originally (see the
/// pre-existing note on `RecordError::CborEncode`). Projecting to a
/// non-generic `CborFault` sidesteps that without `#[from]`.
pub fn classify_de<E>(e: &ciborium::de::Error<E>) -> CborFault {
    use ciborium::de::Error;
    match e {
        Error::Io(_) => CborFault { kind: CborErrorKind::Io, offset: None },
        Error::Syntax(off) => CborFault { kind: CborErrorKind::Syntax, offset: Some(*off) },
        // The `String` is intentionally not bound — see the module doc.
        Error::Semantic(off, _) => CborFault { kind: CborErrorKind::Semantic, offset: *off },
        Error::RecursionLimitExceeded => {
            CborFault { kind: CborErrorKind::RecursionLimit, offset: None }
        }
    }
}

/// Classify an encode error, discarding any upstream description.
pub fn classify_ser<E>(e: &ciborium::ser::Error<E>) -> CborFault {
    use ciborium::ser::Error;
    match e {
        Error::Io(_) => CborFault { kind: CborErrorKind::Io, offset: None },
        // The `String` is intentionally not bound — see the module doc.
        Error::Value(_) => CborFault { kind: CborErrorKind::Serialization, offset: None },
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core cbor:: 2>&1 | tail -20
```

Expected: PASS, 7 tests.

- [ ] **Step 5: Mutation-prove the load-bearing test**

Temporarily change `Error::Semantic(off, _)` to bind and keep the message — e.g. make `CborFault` carry it — or more cheaply, temporarily add `#[derive(Debug)]`-visible passthrough by changing `label()` for `Semantic` to include a bound message. The simplest honest mutation: change the `classify_de` `Semantic` arm to `Error::Semantic(off, msg) => panic!("{msg}")` and confirm `classify_de_discards_the_semantic_message` is the test that fails. Revert.

Expected: exactly `classify_de_discards_the_semantic_message` fails. If it passes, the test is vacuous — fix it before continuing.

- [ ] **Step 6: Lint and commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release -p secretary-core --tests -- -D warnings
git add core/src/cbor.rs core/src/lib.rs
git commit -m "$(cat <<'EOF'
feat(core): add cbor::CborFault — data-free classification of ciborium errors

ciborium implements Display as the Debug form, so `e.to_string()` copies
`Semantic(_, String)` / `Value(String)` verbatim into whatever error variant
captures it. Those Strings come from serde::de::Error::custom, whose standard
invalid_type/invalid_value messages embed the offending value.

Classification discards the message at the boundary. The byte offset is kept
(deliberate, documented: a weak length oracle, but vault file sizes are already
disclosed and it is the most useful datum on a corrupt vault).

No callers yet — the six passthrough variants move over in later commits.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: `RecordError::DuplicateKey` → `{ field, index }`

**Files:**
- Modify: `core/src/vault/record.rs` (variant at `:159-163`; construction sites at `:587`, `:661`, `:692`; existing test at `:1597`)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `RecordError::DuplicateKey { field: &'static str, index: usize }`.

**Background.** This is the variant the issue names. `record.rs:661` takes `key` straight from the decrypted CBOR field-name map, so the message `"duplicate map key: {key}"` embeds a user's field name (`amex-cvv`, `ex-wife-lawyer-password`). There are **three** construction sites, not one; each is at a different map level, and the new `field` hint distinguishes them — strictly more information than the raw key conveyed.

`index` is the 0-based ordinal of the offending entry within its map, rendered 1-based, mirroring `MnemonicError::UnknownWord` (`core/src/unlock/mnemonic.rs:54-55`), which uses `#[error("recovery-phrase word #{} is not in the BIP-39 English list", .index + 1)]`.

The three loops currently iterate with `for (k, v) in map` and have no counter. Add one via `.enumerate()`.

- [ ] **Step 1: Write the failing test**

Replace the existing assertion at `core/src/vault/record.rs:1595-1600` (currently `matches!(err, RecordError::DuplicateKey { ref key } if key == KEY_RECORD_TYPE)`) with:

```rust
        let err = decode(&bytes).expect_err("duplicate key must be rejected");
        assert!(
            matches!(
                err,
                RecordError::DuplicateKey { field: "<record>", index } if index == 1
            ),
            "expected DuplicateKey {{ field: \"<record>\", index: 1 }}, got {err:?}"
        );
        // The decrypted key name must not survive into the message.
        assert!(
            !format!("{err}").contains(KEY_RECORD_TYPE),
            "the map key leaked into the message: {err}"
        );
```

Note: `index == 1` because the test pushes a duplicate `KEY_RECORD_TYPE` as the **second** entry of the map. Verify the actual ordinal when running — the fixture builds entries in a specific order and re-sorts; if the observed index differs, use the observed value and leave a comment explaining which entry it is.

Add two new tests in the same `mod tests` block, covering the other two sites:

```rust
    /// `record.rs:661` — the `fields` map. THE site the issue names: `key`
    /// here is a decrypted user field name, not a spec constant.
    #[test]
    fn duplicate_key_in_fields_map_reports_index_not_the_field_name() {
        const SECRET_FIELD_NAME: &str = "amex-cvv";

        let mut field_entries: Vec<(Value, Value)> = Vec::new();
        field_entries.push((
            Value::Text(SECRET_FIELD_NAME.into()),
            Value::Map(vec![(
                Value::Text(KEY_VALUE.into()),
                Value::Text("4111111111111111".into()),
            )]),
        ));
        field_entries.push((
            Value::Text(SECRET_FIELD_NAME.into()),
            Value::Map(vec![(
                Value::Text(KEY_VALUE.into()),
                Value::Text("duplicate".into()),
            )]),
        ));

        let err = take_fields_map(Value::Map(field_entries))
            .expect_err("duplicate field name must be rejected");

        assert!(
            matches!(
                err,
                RecordError::DuplicateKey { field: "fields", index } if index == 1
            ),
            "expected DuplicateKey {{ field: \"fields\", index: 1 }}, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(SECRET_FIELD_NAME),
            "THE #474 leak: decrypted field name in the message: {err}"
        );
    }

    /// `record.rs:692` — the field-level map.
    #[test]
    fn duplicate_key_in_field_map_reports_index_and_field_hint() {
        let entries: Vec<(Value, Value)> = vec![
            (Value::Text(KEY_VALUE.into()), Value::Text("a".into())),
            (Value::Text(KEY_VALUE.into()), Value::Text("b".into())),
        ];

        let err = parse_field_map(Value::Map(entries))
            .expect_err("duplicate field-level key must be rejected");

        assert!(
            matches!(
                err,
                RecordError::DuplicateKey { field: "<field>", index } if index == 1
            ),
            "expected DuplicateKey {{ field: \"<field>\", index: 1 }}, got {err:?}"
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core --lib vault::record 2>&1 | tail -25
```

Expected: FAIL to compile — `struct variant RecordError::DuplicateKey has no field named field`.

- [ ] **Step 3: Change the variant**

In `core/src/vault/record.rs`, replace the variant at `:159-163`:

```rust
    /// A duplicate map key appeared. RFC 8949 §5.4 forbids duplicates in
    /// canonical input; the codebase enforces this on every CBOR map we
    /// parse.
    ///
    /// Carries the map LEVEL and the offending entry's ordinal, never the
    /// key itself: at the `"fields"` level the key is a decrypted user field
    /// name, which must never reach a log, a crash reporter, or a platform
    /// UI (#474). Same discipline as [`crate::unlock::MnemonicError::UnknownWord`],
    /// which carries a word index rather than the word.
    ///
    /// `field` identifies which map raised it — `"<record>"` (record-level
    /// map), `"fields"` (the record's field map), or `"<field>"` (a single
    /// field's map) — following the coarse entry-point-hint convention
    /// already used by [`Self::FloatRejected`]. `index` is 0-based and
    /// rendered 1-based.
    #[error("duplicate map key at entry #{} of {field}", .index + 1)]
    DuplicateKey {
        /// Which map level raised the error. A compile-time constant.
        field: &'static str,
        /// 0-based ordinal of the duplicate entry within that map.
        index: usize,
    },
```

- [ ] **Step 4: Update the three construction sites**

`:581` — change `for (k, v) in map {` to `for (index, (k, v)) in map.into_iter().enumerate() {`, and `:587`:

```rust
        if !seen_keys.insert(key.clone()) {
            return Err(RecordError::DuplicateKey { field: "<record>", index });
        }
```

`:656` — change `for (k, val) in entries {` to `for (index, (k, val)) in entries.into_iter().enumerate() {`, and `:661`:

```rust
        if out.contains_key(&fname) {
            return Err(RecordError::DuplicateKey { field: "fields", index });
        }
```

`:686` — change `for (k, val) in entries {` to `for (index, (k, val)) in entries.into_iter().enumerate() {`, and `:692`:

```rust
        if !seen_keys.insert(key.clone()) {
            return Err(RecordError::DuplicateKey { field: "<field>", index });
        }
```

If any loop already consumes `map`/`entries` by value, `.into_iter().enumerate()` is a drop-in; if it iterates a reference, use `.iter().enumerate()` and keep the existing binding pattern.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core --lib vault::record 2>&1 | tail -25
```

Expected: PASS. If an index assertion mismatches, read the fixture to find the true ordinal and correct the **test**, not the implementation.

- [ ] **Step 6: Run the whole workspace — this variant is matched elsewhere**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release --workspace 2>&1 | tail -30
```

Fix any other `DuplicateKey { key }` pattern match the compiler reports.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release --workspace --tests -- -D warnings
git add -A core/src/vault/record.rs
git commit -m "$(cat <<'EOF'
fix(core): RecordError::DuplicateKey carries a map level and index, not the key (#474)

record.rs:661 took `key` straight from the decrypted CBOR field-name map, so
"duplicate map key: {key}" embedded a user's field name. It reached iOS as
VaultAccessError.corruptVault and Android as VaultBrowseError.SaveCryptoFailure,
which is why both platforms redact those arms wholesale.

Three construction sites, not the one the issue names. The new `field` hint
distinguishes them ("<record>" / "fields" / "<field>"), which is strictly more
than the raw key conveyed. A &'static str is a compile-time constant and cannot
carry runtime data.

Follows MnemonicError::UnknownWord, which carries a word index, never the word.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `BlockError::DuplicateKey` → `{ field, index }`

**Files:**
- Modify: `core/src/vault/block.rs` (variant at `:310-313`; construction site at `:1008`)

**Interfaces:**
- Consumes: nothing.
- Produces: `BlockError::DuplicateKey { field: &'static str, index: usize }`.

**Background.** This is the **identical leak, and the issue does not mention it.** `block.rs:1008` reads a map key from decoded block *plaintext* — the decrypted contents of a block file. One construction site.

- [ ] **Step 1: Write the failing test**

Add to `core/src/vault/block.rs`'s `mod tests`:

```rust
    /// The #474 sibling the issue does not name: `block.rs:1008` reads a map
    /// key from decrypted block plaintext.
    #[test]
    fn duplicate_key_in_block_plaintext_reports_index_not_the_key() {
        let entries: Vec<(Value, Value)> = vec![
            (Value::Text(KEY_BLOCK_NAME.into()), Value::Text("payroll".into())),
            (Value::Text(KEY_BLOCK_NAME.into()), Value::Text("payroll-dup".into())),
        ];
        let bytes = cbor_map_bytes_unsorted(&entries);

        let err = decode_plaintext(&bytes).expect_err("duplicate key must be rejected");

        assert!(
            matches!(
                err,
                BlockError::DuplicateKey { field: "<block>", index } if index == 1
            ),
            "expected DuplicateKey {{ field: \"<block>\", index: 1 }}, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(KEY_BLOCK_NAME),
            "the map key leaked into the message: {err}"
        );
    }
```

If `cbor_map_bytes_unsorted` does not exist in `block.rs`'s test module, use whatever raw-CBOR test helper that module already has (grep the module for an existing helper that builds an unsorted map); do **not** add a new helper if one exists.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core --lib vault::block 2>&1 | tail -25
```

Expected: FAIL to compile — no field named `field`.

- [ ] **Step 3: Change the variant and the call site**

`core/src/vault/block.rs:310-313` becomes:

```rust
    /// A plaintext map had a duplicate key. RFC 8949 §5.4 forbids
    /// duplicates; the decoder rejects them.
    ///
    /// Carries the map level and the offending entry's ordinal, never the
    /// key: this map is DECRYPTED block plaintext, so the key is user
    /// content (#474). Mirrors [`crate::vault::record::RecordError::DuplicateKey`].
    #[error("duplicate map key at entry #{} of {field}", .index + 1)]
    DuplicateKey {
        /// Which map level raised the error. A compile-time constant.
        field: &'static str,
        /// 0-based ordinal of the duplicate entry within that map.
        index: usize,
    },
```

`:1002` — change `for (k, v) in map {` to `for (index, (k, v)) in map.into_iter().enumerate() {`, and `:1008`:

```rust
        if !seen_keys.insert(key.clone()) {
            return Err(BlockError::DuplicateKey { field: "<block>", index });
        }
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release --workspace 2>&1 | tail -30
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release --workspace --tests -- -D warnings
git add -A core/src/vault/block.rs
git commit -m "$(cat <<'EOF'
fix(core): BlockError::DuplicateKey carries a map level and index (#474)

The identical leak to RecordError::DuplicateKey, in a second enum, unmentioned
by the issue. block.rs:1008 reads a map key from DECRYPTED block plaintext.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: `CborFault` for the four pure-passthrough enums

**Files:**
- Modify: `core/src/vault/record.rs` (`:109-122`, sites `:250`, `:531`), `core/src/vault/block.rs` (`:145-149` area, sites `:914`, `:927`, `:963`), `core/src/vault/manifest.rs` (`:130-138`, sites `:631`, `:633`, `:662`, `:1187`, `:1188`, test at `:2713-2716`), `core/src/vault/canonical.rs` (`:59-64`, plus its `From<CanonicalError> for RecordError` consumer in `record.rs`)

**Interfaces:**
- Consumes: `secretary_core::cbor::{CborFault, classify_de, classify_ser}` from Task 1.
- Produces: `RecordError::CborEncode(CborFault)` / `CborDecode(CborFault)`; same for `BlockError` and `ManifestError`; `CanonicalError::CborEncode(CborFault)`.

**Background.** These four enums' CBOR variants are **pure passthrough** — verified: a grep for `CborDecode("` / `CborEncode("` / `CborDecode(format!` / `CborEncode(format!` across `core/src/vault/` returns **nothing**. Every construction site is `.map_err(|e| XError::CborXcode(e.to_string()))`. So this is a clean type swap with no message loss. (`CardError` and `BundleError` are **not** like this — they carry ~30 hand-written literals and get their own tasks.)

`record.rs` has a `From<CanonicalError> for RecordError` impl (around `:208-218`) whose `CanonicalError::CborEncode(s) => RecordError::CborEncode(s)` arm keeps compiling once both sides carry `CborFault`.

- [ ] **Step 1: Write the failing test**

Add to `core/src/vault/record.rs`'s `mod tests`:

```rust
    /// The ciborium message must not survive into a core error. Today it does:
    /// ciborium's Display is its Debug form, so `Semantic(_, msg)` prints `msg`.
    #[test]
    fn cbor_decode_error_carries_a_classified_fault_not_upstream_text() {
        // Truncated CBOR: a map header promising two entries, with none.
        let truncated: &[u8] = &[0xA2];

        let err = decode(truncated).expect_err("truncated CBOR must be rejected");

        let RecordError::CborDecode(fault) = err else {
            panic!("expected CborDecode, got {err:?}");
        };
        // A syntax/EOF failure classifies as Io or Syntax depending on how
        // ciborium surfaces a short read; both are data-free. Assert the
        // property that matters rather than pinning the arm.
        assert!(
            matches!(
                fault.kind,
                crate::cbor::CborErrorKind::Io | crate::cbor::CborErrorKind::Syntax
            ),
            "unexpected kind {:?}",
            fault.kind
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core --lib vault::record::tests::cbor_decode 2>&1 | tail -20
```

Expected: FAIL to compile — `expected String, found CborFault` in the let-else.

- [ ] **Step 3: Swap the payload type in all four enums**

For each of `RecordError`, `BlockError`, `ManifestError`, replace the two variants. Using `RecordError` as the template (`record.rs:109-122`):

```rust
    /// `ciborium` returned an I/O or serialisation error during encode.
    ///
    /// Carries a classified [`CborFault`] rather than the upstream message:
    /// `ciborium`'s `Display` is its `Debug` form, so stringifying it copies
    /// `ser::Error::Value(String)` verbatim — a `serde` custom message that can
    /// embed the offending value (#474). The generic-source problem that
    /// originally forced a `String` (`ciborium::ser::Error<E>` is generic over
    /// the writer's I/O error, so `#[from]` does not apply) is solved by
    /// [`crate::cbor::classify_ser`] projecting to a non-generic type.
    #[error("CBOR encode error: {0}")]
    CborEncode(CborFault),

    /// `ciborium` returned a parse error during decode (e.g. truncated
    /// input, type mismatch at the byte level). Carries a classified
    /// [`CborFault`] for the same reason as [`Self::CborEncode`].
    #[error("CBOR decode error: {0}")]
    CborDecode(CborFault),
```

Add `use crate::cbor::{classify_de, classify_ser, CborFault};` to each file's imports.

`CanonicalError::CborEncode` (`canonical.rs:59-64`) gets the encode variant only, same shape.

- [ ] **Step 4: Update every construction site**

Mechanical: `e.to_string()` → `classify_de(&e)` for decode sites, `classify_ser(&e)` for encode sites.

- `record.rs:250`, `:531` — decode.
- `block.rs:914`, `:927`, `:963` — decode.
- `manifest.rs:631` — encode; `:633`, `:662` — decode; `:1187` — encode; `:1188` — decode.
- `canonical.rs` — its single `into_writer` encode site.

Example:

```rust
        ciborium::de::from_reader(bytes).map_err(|e| RecordError::CborDecode(classify_de(&e)))?;
```

`manifest.rs:2713-2716`'s existing test comments *"CborDecode carries a String, so use a wildcard match"* — update the comment; the `matches!(err, ManifestError::CborDecode(_))` assertion itself still holds.

- [ ] **Step 5: Build, test, fix fallout**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release --workspace 2>&1 | tail -40
```

Expected: PASS. The compiler will point at any remaining site.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -5
git add -A core/src/vault/
git commit -m "$(cat <<'EOF'
fix(core): Record/Block/Manifest/Canonical CBOR errors carry CborFault (#474)

These four enums' CBOR variants are pure passthrough — every construction site
was `.map_err(|e| ...(e.to_string()))`, with zero hand-written messages — so
this is a clean type swap with no diagnostic loss.

It removes the content-traced claim that ciborium cannot produce a value-bearing
Semantic message on these paths. That claim held only because every production
from_reader targets ciborium::value::Value; a version bump or one typed call
would have invalidated it silently.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: `CardError` decomposition

**Files:**
- Modify: `core/src/identity/card.rs` (variants at `:110-121`; ~27 construction sites listed below)

**Interfaces:**
- Consumes: `crate::cbor::{CborFault, classify_de, classify_ser}`.
- Produces: `CardError::{CborEncode(CborFault), CborDecode(CborFault), Malformed(&'static str), MissingField { field: &'static str }, DuplicateField { field: &'static str }, UnknownField { index: usize }}`.

**Background — why this is not a type swap.** Unlike Task 4's enums, `CardError::CborDecode` is a **general-purpose** decode error carrying ~24 hand-written messages, three shapes of them:

1. Fixed structural literals — `"expected top-level CBOR map"` (`:287`), `"non-string map key"` (`:303`), `"expected unsigned integer"` (`:525`, `:536`), `"expected non-negative integer"` (`:529`), `"integer outside u64 range"` (`:539`), `"expected text string"` (`:545`), `"expected byte string"` (`:552`, `:562`).
2. `format!("missing field {KEY_*}")` ×9 (`:357`, `:365`, `:368`, `:371`, `:373`, `:376`, `:378`, `:381`, `:383`, `:385`) — every `KEY_*` is a `&'static str` constant.
3. Two interpolations of a *runtime* key: `:349` `format!("unknown card field: {other}")` and `:516` `format!("duplicate field: {key}")`.

For (3): `:516` is inside `set_once`, which is reached **only** for keys the match arms recognised — the `other =>` arm at `:348` returns first — so its `key` is always a `KEY_*` constant and becomes `&'static str`. `:349`'s `other` is genuinely arbitrary: a Contact Card is public (crypto-design §6) so this is not vault plaintext, but it is **attacker-controlled text being formatted into a log line**, and the guard default-denies `String` regardless. It becomes an index.

- [ ] **Step 1: Write the failing tests**

Add to `core/src/identity/card.rs`'s `mod tests`:

```rust
    #[test]
    fn unknown_card_field_reports_an_index_not_the_key() {
        const ROGUE: &str = "attacker-controlled-\u{1b}[2Kfield";
        let bytes = card_bytes_with_extra_field(ROGUE);

        let err = ContactCard::from_canonical_cbor(&bytes)
            .expect_err("unknown field must be rejected");

        assert!(
            matches!(err, CardError::UnknownField { .. }),
            "expected UnknownField, got {err:?}"
        );
        assert!(
            !format!("{err}").contains("attacker-controlled"),
            "attacker-controlled text reached the message: {err}"
        );
    }

    #[test]
    fn missing_field_names_the_spec_key_as_a_static_str() {
        let bytes = card_bytes_missing(KEY_CONTACT_UUID);

        let err = ContactCard::from_canonical_cbor(&bytes)
            .expect_err("missing field must be rejected");

        assert!(
            matches!(err, CardError::MissingField { field } if field == KEY_CONTACT_UUID),
            "expected MissingField {{ field: contact_uuid }}, got {err:?}"
        );
    }
```

Write `card_bytes_with_extra_field(&str) -> Vec<u8>` and `card_bytes_missing(&str) -> Vec<u8>` as test helpers **only if** the module has no equivalent. Grep the test module first — `card.rs:671` already builds a `Value` from a card, which suggests a helper exists. Reuse it. Build key material with runtime randomness (`OsRng`), never hardcoded arrays.

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core --lib identity::card 2>&1 | tail -20
```

Expected: FAIL to compile — no variant `UnknownField` / `MissingField` on `CardError`.

- [ ] **Step 3: Restructure the enum**

Replace `CardError::CborEncode(String)` / `CborDecode(String)` (`:110-121`) with six variants:

```rust
    /// `ciborium` failed to serialise the card. Carries a classified fault,
    /// never the upstream message (#474 — see [`crate::cbor`]).
    #[error("CBOR encode error: {0}")]
    CborEncode(CborFault),

    /// `ciborium` failed to parse the input as CBOR at the byte level.
    #[error("CBOR decode error: {0}")]
    CborDecode(CborFault),

    /// The bytes parsed as CBOR but did not match the §6 card shape — wrong
    /// CBOR major type in a known position, a non-text map key, an integer
    /// outside range. The payload is a fixed structural description chosen
    /// from a closed set of literals in this module; it is `&'static str` so
    /// it provably cannot carry card content.
    #[error("malformed contact card: {0}")]
    Malformed(&'static str),

    /// A required §6 field was absent. `field` is the spec CBOR key name, a
    /// compile-time constant.
    #[error("missing required card field: {field}")]
    MissingField {
        /// The §6 CBOR key name.
        field: &'static str,
    },

    /// A known §6 field appeared more than once. `field` is a spec key name:
    /// this is raised from `set_once`, reached only after the unknown-key arm
    /// has rejected anything not in the §6 set.
    #[error("duplicate card field: {field}")]
    DuplicateField {
        /// The §6 CBOR key name.
        field: &'static str,
    },

    /// A map key was present that the §6 card schema does not define.
    ///
    /// Carries the entry's 0-based ordinal, never the key. A Contact Card is
    /// public by design, so this is not vault plaintext — but the key is
    /// arbitrary text from an untrusted party, and formatting untrusted text
    /// into a diagnostic that reaches a log is its own hazard (#474).
    #[error("unknown card field at entry #{}", .index + 1)]
    UnknownField {
        /// 0-based ordinal of the offending entry.
        index: usize,
    },
```

Add `use crate::cbor::{classify_de, classify_ser, CborFault};`.

- [ ] **Step 4: Update all construction sites**

| Sites | Change |
|---|---|
| `:272`, `:501`, `:510` | `CardError::CborEncode(e.to_string())` → `CardError::CborEncode(classify_ser(&e))` |
| `:284` | `CardError::CborDecode(e.to_string())` → `CardError::CborDecode(classify_de(&e))` |
| `:287`, `:303`, `:525`, `:529`, `:536`, `:539`, `:545`, `:552`, `:562` | `CardError::CborDecode("literal".into())` → `CardError::Malformed("literal")` — drop the `.into()` |
| `:357`, `:365`, `:368`, `:371`, `:373`, `:376`, `:378`, `:381`, `:383`, `:385` | `CardError::CborDecode(format!("missing field {KEY_X}"))` → `CardError::MissingField { field: KEY_X }` |
| `:349` | `format!("unknown card field: {other}")` → `CardError::UnknownField { index }` — the enclosing loop needs `.enumerate()` |
| `:516` | `format!("duplicate field: {key}")` → `CardError::DuplicateField { field: key }` — see next step |

For `:516`, `set_once`'s signature is `fn set_once<T>(slot: &mut Option<T>, v: T, key: &str) -> Result<(), CardError>`. Change the parameter to `key: &'static str` and pass the `KEY_*` constant directly at each call site instead of `&key` (the call sites currently pass `&key`, the loop-local `String`; pass the constant from the match arm — e.g. the `KEY_SELF_SIG_ED =>` arm passes `KEY_SELF_SIG_ED`).

- [ ] **Step 5: Run tests and fix fallout**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release --workspace 2>&1 | tail -40
```

Existing tests matching `CardError::CborDecode(_)` for what is now `Malformed` / `MissingField` will fail — update each to the correct new variant. That is the point of the split.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release --workspace --tests -- -D warnings
git add -A core/src/identity/card.rs
git commit -m "$(cat <<'EOF'
fix(core): split CardError so every payload is provably data-free (#474)

CardError::CborDecode was a general-purpose decode error carrying ~24
hand-written messages, not a ciborium passthrough. A blanket swap to CborFault
would have destroyed all of them.

Split by shape instead: CborFault for genuine ciborium failures, Malformed for
the closed set of structural literals, MissingField/DuplicateField for spec key
names (&'static str), and UnknownField for the one genuinely arbitrary key —
which becomes an ordinal. A card is public, so this is not vault plaintext, but
formatting untrusted text into a diagnostic is its own hazard.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: `BundleError` decomposition

**Files:**
- Modify: `core/src/unlock/bundle.rs` (variants at `:99-121`; sites `:339`, `:342`, `:359`, `:406`, `:474`, `:483`, `:503`, `:512`, `:523`, `:541`, `:560`; tests at `:647`, `:735`)

**Interfaces:**
- Consumes: `crate::cbor::{CborFault, classify_de, classify_ser}`.
- Produces: `BundleError::{CborFault(CborFault), Malformed(&'static str), UnknownField { index: usize }, DuplicateField(&'static str)}`.

**Background.** Structurally parallel to Task 5, smaller. `BundleError::CborError(String)` mixes ciborium passthrough (`:339`, `:474`, `:483`) with fixed literals (`:342`, `:359`, `:512`, `:523`, `:541`, `:560`). Separately, `UnknownField(String)` at `:406` carries an arbitrary map key **from the decrypted identity bundle** — this one *is* secret-adjacent, unlike the card's. `DuplicateField(String)` at `:503` is reached only after `:405`'s `other =>` arm rejects unknown keys, so its payload is always a `KEY_*` constant.

- [ ] **Step 1: Write the failing test**

Add to `core/src/unlock/bundle.rs`'s `mod tests`:

```rust
    /// `bundle.rs:406` carries an arbitrary map key from the DECRYPTED
    /// identity bundle. It must become an ordinal (#474).
    #[test]
    fn unknown_bundle_field_reports_an_index_not_the_key() {
        const ROGUE: &str = "rogue-secret-looking-key";
        // Reuse the existing fixture shape from the `rogue` test at :647.
        let bytes = bundle_bytes_with_extra_field(ROGUE);

        let err = IdentityBundle::from_canonical_cbor(&bytes)
            .expect_err("unknown field must be rejected");

        assert!(
            matches!(err, BundleError::UnknownField { .. }),
            "expected UnknownField, got {err:?}"
        );
        assert!(
            !format!("{err}").contains(ROGUE),
            "the decrypted bundle key leaked into the message: {err}"
        );
    }
```

The existing test at `:647` (`matches!(err, BundleError::UnknownField(ref s) if s == "rogue")`) already builds this fixture inline — extract that construction into `bundle_bytes_with_extra_field(&str) -> Vec<u8>` and have both tests use it, then rewrite `:647`'s assertion to the new shape.

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core --lib unlock::bundle 2>&1 | tail -20
```

Expected: FAIL to compile.

- [ ] **Step 3: Restructure the enum**

Replace `CborError(String)` (`:103`), `UnknownField(String)` (`:116`), `DuplicateField(String)` (`:121`):

```rust
    /// `ciborium` failed at the byte level. Carries a classified fault, never
    /// the upstream message (#474 — see [`crate::cbor`]).
    #[error("CBOR error: {0}")]
    CborFault(CborFault),

    /// The bytes parsed as CBOR but did not match the §5 bundle shape.
    /// A fixed structural description from a closed set of literals.
    #[error("malformed identity bundle: {0}")]
    Malformed(&'static str),

    /// A map key was present that the v1 spec does not define. The bundle is
    /// fully-specified; an unknown field signals suite drift and is rejected.
    ///
    /// Carries the entry's 0-based ordinal, never the key: this map is the
    /// DECRYPTED identity bundle, so an unrecognised key is unreviewed
    /// plaintext (#474).
    #[error("unknown bundle field at entry #{}", .index + 1)]
    UnknownField {
        /// 0-based ordinal of the offending entry.
        index: usize,
    },

    /// A known §5 field appeared more than once. RFC 8949 §5.4 forbids
    /// duplicates in canonical input. `field` is a spec key name — this is
    /// raised from `set_once`, reached only after the unknown-key arm has
    /// rejected anything not in the §5 set.
    #[error("duplicate bundle field: {0}")]
    DuplicateField(&'static str),
```

Add `use crate::cbor::{classify_de, classify_ser, CborFault};`. Note the variant is named `CborFault` and the type is `CborFault` — if that shadowing is awkward in this module, import as `use crate::cbor::CborFault as CborFaultPayload;` rather than renaming the variant.

- [ ] **Step 4: Update all construction sites**

| Sites | Change |
|---|---|
| `:339` | `CborError(e.to_string())` → `CborFault(classify_de(&e))` |
| `:474`, `:483` | `CborError(e.to_string())` → `CborFault(classify_ser(&e))` |
| `:342`, `:359`, `:512`, `:523`, `:541`, `:560` | `CborError("literal".into())` → `Malformed("literal")` |
| `:406` | `UnknownField(other.to_string())` → `UnknownField { index }` — enclosing loop needs `.enumerate()` |
| `:503` | `DuplicateField(key.to_string())` → `DuplicateField(key)`, and change `set_once`'s `key: &str` to `key: &'static str`, passing `KEY_*` constants from the match arms |

- [ ] **Step 5: Run tests and fix fallout**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release --workspace 2>&1 | tail -40
```

`:735`'s `matches!(err, BundleError::CborError(_))` becomes `BundleError::Malformed(_)` — that site tests a non-integer `created_at`, which is `:523`'s literal.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release --workspace --tests -- -D warnings
git add -A core/src/unlock/bundle.rs
git commit -m "$(cat <<'EOF'
fix(core): split BundleError so every payload is provably data-free (#474)

Parallel to the CardError split. BundleError::CborError mixed ciborium
passthrough with fixed literals; UnknownField carried an arbitrary map key
read from the DECRYPTED identity bundle, which is the same class as
RecordError::DuplicateKey and equally unmentioned by the issue.

DuplicateField becomes &'static str: it is raised from set_once, reachable only
after the unknown-key arm rejects anything outside the §5 key set.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: Kill the `ciborium` passthrough in `SyncError`

**Files:**
- Modify: `core/src/sync/state.rs:136-138`

**Interfaces:**
- Consumes: `crate::cbor::classify_de`.
- Produces: no signature change — `SyncError::StateDecodeFailed { detail: String }` keeps its shape.

**Background — read the "Scope adjustment" section at the top of this plan.** `SyncError::StateDecodeFailed` / `StateEncodeFailed` have **21 producers**, 18 of them fixed structural literals about the local sync-state cache. `SyncState` holds only `vault_uuid: [u8; 16]` and a vector of `VectorClockEntry` — device UUIDs and counters. No vault plaintext can reach these messages. Converting all 21 to eliminate a provably-safe `String` is disproportionate; Task 9 records the two variants as reviewed allowlist entries instead.

**One producer is not safe by that argument:** `state.rs:137`'s `detail: format!("CBOR parse: {e}")` interpolates a raw `ciborium` error, which is the traced-upstream claim this whole slice exists to remove. Fix that one.

- [ ] **Step 1: Write the failing test**

Add to `core/src/sync/state.rs`'s `mod tests`:

```rust
    /// The ciborium message must not be interpolated into the detail string.
    /// Everything else in this enum is a fixed literal; this was the one
    /// producer carrying third-party text (#474).
    #[test]
    fn state_decode_does_not_interpolate_raw_ciborium_text() {
        // Truncated CBOR: a map header promising two entries, with none.
        let truncated: &[u8] = &[0xA2];

        let err = SyncState::from_canonical_cbor(truncated)
            .expect_err("truncated CBOR must be rejected");

        let rendered = format!("{err}");
        assert!(
            rendered.contains("CBOR"),
            "the message should still say what failed: {rendered}"
        );
        // ciborium's Display is its Debug form, so a passthrough renders the
        // upstream variant name. Its absence is what proves the fix.
        assert!(
            !rendered.contains("Semantic")
                && !rendered.contains("Syntax(")
                && !rendered.contains("RecursionLimitExceeded"),
            "raw ciborium Debug text survived into the detail: {rendered}"
        );
    }
```

- [ ] **Step 2: Run test to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release -p secretary-core --lib sync::state 2>&1 | tail -20
```

Expected: FAIL — the rendered detail contains ciborium's Debug form. If it passes on this input, the truncation classified as `Io` (which renders no variant name); use a different malformed input that provokes `Syntax`, e.g. `&[0x1F]` (a reserved additional-information value), and confirm the test fails before proceeding. **A test that has never been observed failing is not a test.**

- [ ] **Step 3: Route through `classify_de`**

`core/src/sync/state.rs:136-138`:

```rust
        let value: Value =
            ciborium::de::from_reader(bytes).map_err(|e| SyncError::StateDecodeFailed {
                // Classified, not stringified: ciborium's Display is its Debug
                // form, which prints `Semantic(_, String)` verbatim (#474).
                detail: format!("CBOR parse: {}", crate::cbor::classify_de(&e)),
            })?;
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release --workspace 2>&1 | tail -30
```

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release --workspace --tests -- -D warnings
git add -A core/src/sync/state.rs
git commit -m "$(cat <<'EOF'
fix(core): classify the ciborium error in SyncState::from_canonical_cbor (#474)

SyncError's two decode/encode variants have 21 producers, 18 of them fixed
literals over a struct holding only a vault_uuid and vector-clock entries — no
vault plaintext can reach them, so they are recorded as reviewed allowlist
entries rather than churned.

state.rs:137 was the exception: it interpolated a raw ciborium error, which is
the traced-upstream claim this slice exists to remove.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: The guard, landed RED

**Files:**
- Create: `scripts/check-error-payload-hygiene.py`

**Interfaces:**
- Consumes: nothing from earlier tasks (it reads source text).
- Produces: an executable guard with `--self-test`; exit 0 clean, exit 1 on violation.

**Background.** The guard is the third in a family. Read `android/scripts/check-log-hygiene.sh` and `ios/scripts/check-public-log-hygiene.sh` first for the house conventions: two-sided `--self-test` that must run *first* in CI, an exact-trimmed-line allowlist (never substring), a `LIMITS` block stating honestly what the rule cannot see, and readonly tunables at the top.

This one is Python because associating an `#[error]` attribute with the following variant's **field types** spans lines — a line-based matcher structurally cannot do it. Python also removes the need for an `is_comment_line` heuristic (the control that has had two bugs on the shell side): it strips comments by scanning, so there is nothing subtle to share.

**Handle the `mnemonic.rs` shape.** `#[error("recovery-phrase word #{} is not in the BIP-39 English list", .index + 1)]` uses a positional `{}` filled by a trailing argument expression. The parser must extract `.index` from the arguments, not only `{named}` from the format string — otherwise it reports "interpolates nothing" and misses a real case.

- [ ] **Step 1: Write the guard with its self-test, expecting it to FAIL on the real tree**

Create `scripts/check-error-payload-hygiene.py`:

```python
#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Fail-closed guard: no `core` error variant may interpolate a runtime String.

WHY THIS EXISTS (#474)
----------------------
`RecordError::DuplicateKey` formatted a decrypted CBOR field name into its
message. That string reached iOS as `VaultAccessError.corruptVault` and Android
as `VaultBrowseError.SaveCryptoFailure`, which is why both platforms redacted
those arms WHOLESALE — losing the detail for every corruption diagnostic, not
just the leaking one.

The payload types are now data-free by construction. This guard keeps them that
way: a new variant carrying a runtime `String` into its `#[error]` message fails
CI in the Rust author's own pull request, rather than silently degrading a
platform two layers away. That drift — a Rust edit with no platform diff and no
failing test anywhere — is exactly how the original leak shipped.

THE RULE
--------
For every `#[error("...")]` attribute under `core/src/`, resolve the field types
of the variant it is attached to. If the message (or a trailing format argument)
interpolates a field whose declared type is not provably data-free, fail —
unless the attribute's exact trimmed source line is allowlisted.

DEFAULT-DENY: an unrecognised type name is a FAILURE, not a pass. A new payload
type cannot slip through by being unfamiliar to this matcher.

LIMITS (stated, not hidden)
---------------------------
- It sees DECLARATIONS, not construction sites. A variant whose payload is
  `&'static str` is provably safe; a variant allowlisted because "its producers
  all pass literals" is a point-in-time claim this guard cannot verify. Those
  entries say so in the allowlist.
- It covers `core/src/**` only. The FFI bridge builds its own detail strings
  (`ffi/secretary-ffi-bridge/**`) and is NOT scanned — see issue #478.
- Rust is parsed by pattern, not by a real parser. The shapes in this codebase
  are regular (thiserror derives); an exotic macro-generated error enum would
  be invisible. `--self-test` pins the shapes that do occur.
"""
```

> **Correction (2026-08-08, #486):** this passage predates PR #479/#489.
> #478 was closed the broad way by #480 — `ffi/secretary-ffi-bridge/src/**`
> is a scan root, gated by rules E2/E3/E4. The remaining unscanned crates
> were the two BINDING WRAPPERS, which #486 closes. This plan is a
> historical execution artifact; it is not updated in place.

```python
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCAN_ROOT = REPO_ROOT / "core" / "src"
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "error-payload-hygiene-allowlist.txt"

# Types whose every value is a compile-time constant or a pure number, and so
# cannot carry runtime content. Everything else denies.
DATA_FREE_TYPES: frozenset[str] = frozenset(
    {
        "&'static str",
        "bool",
        "char",
        "usize",
        "isize",
        "u8", "u16", "u32", "u64", "u128",
        "i8", "i16", "i32", "i64", "i128",
        # The #474 classification type: a fieldless kind plus a byte offset.
        "CborFault",
        "crate::cbor::CborFault",
    }
)

# `[u8; 16]`, `[u8; RECORD_UUID_LEN]` — fixed-size numeric arrays.
ARRAY_RE = re.compile(r"^\[[ui](?:8|16|32|64|128|size);[^\]]+\]$")
# `Option<T>` is data-free exactly when `T` is.
OPTION_RE = re.compile(r"^Option<(.+)>$")


def is_data_free(ty: str) -> bool:
    """True when a value of `ty` provably cannot carry runtime content."""
    ty = " ".join(ty.split())
    if ty in DATA_FREE_TYPES:
        return True
    if ARRAY_RE.match(ty.replace(" ", "")):
        return True
    inner = OPTION_RE.match(ty)
    if inner:
        return is_data_free(inner.group(1))
    return False


def strip_comments(src: str) -> str:
    """Blank out `//` and `/* */` comments, preserving line structure.

    Replaces comment bytes with spaces rather than deleting them so that line
    numbers and column offsets stay exact. String literals are respected, so a
    `//` inside `"..."` is not treated as a comment.
    """
    out: list[str] = []
    i, n = 0, len(src)
    in_line_comment = in_block_comment = in_string = False
    while i < n:
        ch = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if ch == "\n":
                in_line_comment = False
                out.append(ch)
            else:
                out.append(" ")
            i += 1
        elif in_block_comment:
            if ch == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
            else:
                out.append("\n" if ch == "\n" else " ")
                i += 1
        elif in_string:
            if ch == "\\":
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                in_string = False
            out.append(ch)
            i += 1
        elif ch == "/" and nxt == "/":
            in_line_comment = True
            out.append("  ")
            i += 2
        elif ch == "/" and nxt == "*":
            in_block_comment = True
            out.append("  ")
            i += 2
        elif ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    source_line: str
    variant: str
    field: str
    field_type: str


ERROR_ATTR_RE = re.compile(r"#\[error\(", re.MULTILINE)
# `{name}` / `{name:?}` / `{0}` — but not `{{` (an escaped brace).
PLACEHOLDER_RE = re.compile(r"(?<!\{)\{([A-Za-z_][A-Za-z0-9_]*|\d+)?[^{}]*\}")
# `.index` in a trailing format argument, e.g. `, .index + 1)`.
ARG_FIELD_RE = re.compile(r"\.([A-Za-z_][A-Za-z0-9_]*)")
VARIANT_RE = re.compile(r"^\s*([A-Z][A-Za-z0-9_]*)\s*(\{|\(|,|$)")


def balanced_slice(src: str, start: int) -> tuple[str, int]:
    """Return the `(...)`-balanced text starting at `src[start] == '('`."""
    depth, i, in_string = 0, start, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return src[start : i + 1], i + 1
        i += 1
    return src[start:], len(src)


def parse_fields(body: str) -> dict[str, str]:
    """Map field name -> declared type for a variant body.

    Handles both struct variants (`{ field: &'static str, index: usize }`) and
    tuple variants (`(String)` -> `{"0": "String"}`).
    """
    body = body.strip()
    fields: dict[str, str] = {}
    if body.startswith("{"):
        inner = body[1 : body.rindex("}")] if "}" in body else body[1:]
        for part in split_top_level(inner):
            if ":" not in part:
                continue
            name, ty = part.split(":", 1)
            name = name.strip()
            if name.startswith("///") or not name:
                continue
            fields[name] = " ".join(ty.split())
    elif body.startswith("("):
        inner = body[1 : body.rindex(")")] if ")" in body else body[1:]
        for idx, part in enumerate(split_top_level(inner)):
            if part.strip():
                fields[str(idx)] = " ".join(part.split())
    return fields


def split_top_level(text: str) -> list[str]:
    """Split on commas that are not nested inside <>, (), [] or {}."""
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "<([{":
            depth += 1
        elif ch in ">)]}":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def scan_source(path_label: str, raw: str) -> list[Finding]:
    """Find every `#[error]` variant that interpolates a non-data-free field."""
    src = strip_comments(raw)
    raw_lines = raw.splitlines()
    findings: list[Finding] = []

    for m in ERROR_ATTR_RE.finditer(src):
        attr_text, after = balanced_slice(src, m.end() - 1)
        attr_line_no = src.count("\n", 0, m.start()) + 1

        # Every placeholder name in the format string, plus every `.field`
        # referenced by a trailing format argument (the mnemonic.rs shape).
        names: set[str] = set()
        positional = 0
        for ph in PLACEHOLDER_RE.finditer(attr_text):
            token = ph.group(1)
            if token is None or token == "":
                names.add(f"__positional_{positional}")
                positional += 1
            else:
                names.add(token)
        arg_split = attr_text.find(",")
        if arg_split != -1:
            for am in ARG_FIELD_RE.finditer(attr_text[arg_split:]):
                names.add(am.group(1))
        if not names:
            continue

        # The variant declaration follows the attribute (possibly after `]`
        # and further doc lines, which strip_comments has already blanked).
        tail = src[after:]
        tail = tail[tail.find("]") + 1 :] if tail.lstrip().startswith("]") else tail
        vm = None
        for line in tail.splitlines():
            if line.strip():
                vm = VARIANT_RE.match(line)
                break
        if not vm:
            continue
        variant = vm.group(1)

        rest = tail[tail.find(variant) + len(variant) :].lstrip()
        if rest.startswith("{"):
            body, _ = balanced_braces(rest)
        elif rest.startswith("("):
            body, _ = balanced_slice(rest, 0)
        else:
            body = ""
        fields = parse_fields(body)

        # Positional `{}` placeholders bind to fields in declaration order.
        ordered = list(fields.items())
        for name in sorted(names):
            if name.startswith("__positional_"):
                idx = int(name.rsplit("_", 1)[1])
                if idx < len(ordered):
                    fname, ftype = ordered[idx]
                else:
                    continue
            elif name in fields:
                fname, ftype = name, fields[name]
            elif name.isdigit() and name in fields:
                fname, ftype = name, fields[name]
            else:
                continue
            if not is_data_free(ftype):
                findings.append(
                    Finding(
                        path=path_label,
                        line=attr_line_no,
                        source_line=raw_lines[attr_line_no - 1].strip(),
                        variant=variant,
                        field=fname,
                        field_type=ftype,
                    )
                )
    return findings


def balanced_braces(src: str) -> tuple[str, int]:
    """Return the `{...}`-balanced text starting at `src[0] == '{'`."""
    depth, i, in_string = 0, 0, False
    while i < len(src):
        ch = src[i]
        if in_string:
            if ch == "\\":
                i += 2
                continue
            if ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return src[: i + 1], i + 1
        i += 1
    return src, len(src)


# This guard has exactly one rule. The column exists so the file format is
# byte-identical to the two shell guards' allowlists, which lets
# `scripts/lib/hygiene-allowlist.sh::allowlisted` parse this file unchanged —
# which is what the parity test in `core/tests/` actually exercises.
RULE = "E1"


def load_allowlist(path: Path) -> set[str]:
    """Parse the allowlist into a set of `path\\trule\\texact trimmed line` keys.

    Format, one per line, TAB-separated — IDENTICAL to the two shell guards'
    allowlists so that `scripts/lib/hygiene-allowlist.sh::allowlisted` can parse
    this same file:

        <repo-relative-path><TAB><rule><TAB><exact trimmed source line><TAB><reason>

    Matching is on the EXACT trimmed source line, never a substring: a
    substring entry would exempt every future line in the same file that
    happens to contain it, which was demonstrably exploitable on the two
    log-hygiene guards (#467 / #475).
    """
    entries: set[str] = set()
    if not path.exists():
        return entries
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        entries.add(f"{parts[0].strip()}\t{parts[1].strip()}\t{parts[2].strip()}")
    return entries


def run_real_scan() -> int:
    allowlist = load_allowlist(ALLOWLIST_PATH)
    violations: list[Finding] = []
    for rs in sorted(SCAN_ROOT.rglob("*.rs")):
        label = str(rs.relative_to(REPO_ROOT))
        for f in scan_source(label, rs.read_text(encoding="utf-8")):
            if f"{f.path}\t{RULE}\t{f.source_line}" in allowlist:
                continue
            violations.append(f)

    if violations:
        print("error-payload hygiene: FAIL\n", file=sys.stderr)
        for v in violations:
            print(
                f"  {v.path}:{v.line}\n"
                f"    variant {v.variant} interpolates `{v.field}: {v.field_type}`\n"
                f"    {v.source_line}",
                file=sys.stderr,
            )
        print(
            f"\n{len(violations)} violation(s). A `core` error message must not "
            "interpolate a runtime String — it reaches both platform UIs and "
            "their logs (#474). Carry a &'static str hint plus an ordinal, or "
            "record a reviewed exception in\n  "
            f"{ALLOWLIST_PATH.relative_to(REPO_ROOT)}",
            file=sys.stderr,
        )
        return 1
    print("error-payload hygiene: OK")
    return 0
```

- [ ] **Step 2: Add the two-sided `--self-test`**

Append to the same file:

```python
POSITIVE_CONTROLS: list[tuple[str, str]] = [
    (
        "P1 struct variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key: {key}")]
            DuplicateKey { key: String },
        }
        ''',
    ),
    (
        "P2 tuple variant with a String payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(String),
        }
        ''',
    ),
    (
        "P3 Vec<u8> payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("bad bytes: {raw:?}")]
            BadBytes { raw: Vec<u8> },
        }
        ''',
    ),
    (
        "P4 unrecognised type denies by default",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("wrapped: {inner}")]
            Wrapped { inner: SomeFutureType },
        }
        ''',
    ),
    (
        "P5 trailing format argument (the mnemonic.rs shape)",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("word #{} is unknown", .word)]
            UnknownWord { word: String },
        }
        ''',
    ),
    (
        "P6 multi-line attribute",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error(
                "a long message that wraps: {detail}"
            )]
            Wrapped { detail: String },
        }
        ''',
    ),
    (
        "P7 PathBuf payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("no such folder: {path}")]
            Missing { path: PathBuf },
        }
        ''',
    ),
]

NEGATIVE_CONTROLS: list[tuple[str, str]] = [
    (
        "N1 &'static str hint plus an ordinal — the #474 fix shape",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("duplicate map key at entry #{} of {field}", .index + 1)]
            DuplicateKey { field: &'static str, index: usize },
        }
        ''',
    ),
    (
        "N2 CborFault payload",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("CBOR decode error: {0}")]
            CborDecode(CborFault),
        }
        ''',
    ),
    (
        "N3 fixed-size byte array",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("block {block_uuid:02x?} failed")]
            Failed { block_uuid: [u8; 16] },
        }
        ''',
    ),
    (
        "N4 message interpolates nothing",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected top-level CBOR map")]
            NotAMap,
        }
        ''',
    ),
    (
        "N5 Option<usize>",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("failed at {offset:?}")]
            At { offset: Option<usize> },
        }
        ''',
    ),
    (
        "N6 the whole violation is inside a line comment",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            // #[error("leaky: {key}")]
            // Leaky { key: String },
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N7 the whole violation is inside a block comment",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            /* #[error("leaky: {key}")]
               Leaky { key: String }, */
            #[error("fine")]
            Fine,
        }
        ''',
    ),
    (
        "N8 escaped braces are not placeholders",
        '''
        #[derive(thiserror::Error, Debug)]
        pub enum E {
            #[error("expected {{ }} shape")]
            Shape,
        }
        ''',
    ),
]


def run_self_test() -> int:
    failures: list[str] = []
    for label, src in POSITIVE_CONTROLS:
        if not scan_source("<self-test>", src):
            failures.append(f"POSITIVE control did not fire: {label}")
    for label, src in NEGATIVE_CONTROLS:
        found = scan_source("<self-test>", src)
        if found:
            failures.append(
                f"NEGATIVE control fired: {label} -> "
                f"{[(f.variant, f.field, f.field_type) for f in found]}"
            )
    if failures:
        print("self-test: FAIL", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1
    print(
        f"self-test: OK ({len(POSITIVE_CONTROLS)} positive / "
        f"{len(NEGATIVE_CONTROLS)} negative)"
    )
    return 0


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        sys.exit(run_self_test())
    sys.exit(run_real_scan())
```

- [ ] **Step 3: Run the self-test — it must pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && uv run scripts/check-error-payload-hygiene.py --self-test
```

Expected: `self-test: OK (7 positive / 8 negative)`. If a control misbehaves, fix the parser — not the control — unless the control itself encodes a wrong expectation.

- [ ] **Step 4: Run the real scan — it must FAIL (this is the RED landing)**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && uv run scripts/check-error-payload-hygiene.py; echo "exit=$?"
```

Expected: `exit=1`, listing the Group 3 sites (the four `VaultTomlError` variants, `VaultError::RestoreVerificationFailed`, `RepairRejected`, `SyncError::StateDecodeFailed`, `StateEncodeFailed`, `SyncError::InvalidArgument`) — and **nothing from Tasks 2–7**. If a Task 2–7 variant still appears, that task is incomplete; go back and finish it.

Record the exact violation list in the commit message — Task 9 turns it into the allowlist.

- [ ] **Step 5: Commit RED**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
chmod +x scripts/check-error-payload-hygiene.py
git add scripts/check-error-payload-hygiene.py
git commit -m "$(cat <<'EOF'
feat(scripts): add check-error-payload-hygiene.py, landed RED (#474)

Fail-closed guard: no `core` error variant may interpolate a runtime String
into its #[error] message. Default-deny — an unrecognised payload type is a
failure, not a pass.

Landed RED deliberately: the self-test passes (7 positive / 8 negative) but the
real scan exits 1 on the remaining Group 3 sites, which the next commit records
as reviewed allowlist entries. A guard that is green on arrival has never been
observed doing anything.

Python rather than bash because associating an attribute with the following
variant's FIELD TYPES spans lines, which a line-based matcher structurally
cannot do. That also removes the need for an is_comment_line heuristic — the
control that has had two bugs on the shell side — since this strips comments by
scanning instead of grepping.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: The allowlist, GREEN, and the parity test

**Files:**
- Create: `scripts/error-payload-hygiene-allowlist.txt`, `core/tests/error_payload_hygiene_parity.rs`

**Interfaces:**
- Consumes: `scripts/check-error-payload-hygiene.py` from Task 8; `scripts/lib/hygiene-allowlist.sh` (existing).
- Produces: a green guard.

**Background.** Six-to-nine entries, all reviewed. Keeping the list short is what keeps each entry meaningful — the same reasoning recorded for both log-hygiene allowlists.

The two shell guards share one matcher via `scripts/lib/hygiene-allowlist.sh`; Python cannot source it. Rather than a two-language pipeline, the Python guard implements the same exact-trimmed-line semantics itself and a parity test asserts the two parsers agree on one shared fixture. That makes the duplication non-silent. This is a deliberate departure from #475's extract-don't-duplicate rule, justified because what that rule protected — `is_comment_line`, twice-buggy — has no counterpart in a tokenizing parser.

- [ ] **Step 1: Write the allowlist**

Create `scripts/error-payload-hygiene-allowlist.txt`. Use the **exact** trimmed `#[error(...)]` source lines reported by Task 8 Step 4 — copy them from the guard's own output, do not retype:

```
# Allowlist for check-error-payload-hygiene.sh's Python sibling,
# scripts/check-error-payload-hygiene.py (#474).
#
# THE RULE: a `core` error variant must not interpolate a runtime String into
# its #[error] message. These are the reviewed exceptions.
#
# Format, one per line — IDENTICAL to the two shell guards' allowlists, so that
# scripts/lib/hygiene-allowlist.sh::allowlisted parses this file unchanged (the
# parity test in core/tests/ exercises exactly that):
#   <repo-relative-path><TAB><rule><TAB><exact trimmed source line><TAB><reason>
#
# This guard has exactly ONE rule, `E1`. The column exists for format parity,
# not because a second rule is planned.
#
# The match is on the EXACT source line with leading/trailing whitespace
# stripped — NOT a substring. A substring entry exempts every future line in
# the same file that happens to contain it, which was demonstrably exploitable
# on the two log-hygiene guards (#467 / #475). Re-indenting an exempted line
# keeps the entry valid; editing its content does not.
#
# ---------------------------------------------------------------------------
# SECTION 1 — ALREADY-DISCLOSED CONTENT
# The payload is public per the threat model. Lowest review weight.
# ---------------------------------------------------------------------------

# `vault.toml` is UNENCRYPTED on disk — docs/vault-format.md §2 is titled
# "`vault.toml` — cleartext metadata" and the file's own header comment reads
# "cleartext; not secret". Its bytes are disclosed to anyone who can read the
# vault folder. MalformedToml additionally needs the `toml` crate's message to
# be debuggable at all.
core/src/unlock/vault_toml.rs	E1	#[error("malformed TOML: {0}")]	vault.toml is cleartext on disk (vault-format §2)
core/src/unlock/vault_toml.rs	E1	#[error("unknown key in [kdf] section: {0}")]	vault.toml is cleartext on disk (vault-format §2)
core/src/unlock/vault_toml.rs	E1	#[error("unsupported KDF algorithm: {0}")]	vault.toml is cleartext on disk (vault-format §2)
core/src/unlock/vault_toml.rs	E1	#[error("unsupported KDF version: {0}")]	vault.toml is cleartext on disk (vault-format §2)

# ---------------------------------------------------------------------------
# SECTION 2 — SAFE BY CONSTRUCTION SITE, NOT BY TYPE
# This guard sees DECLARATIONS, not producers. These entries are point-in-time
# claims it cannot verify. HIGHEST review weight — re-check on every edit to a
# producer.
# ---------------------------------------------------------------------------

# 21 producers, 18 of them fixed structural literals. `SyncState`
# (core/src/sync/state.rs:17-20) holds ONLY a vault_uuid and vector-clock
# entries — device UUIDs and counters — so no vault plaintext can reach these.
# The one producer that carried third-party text (state.rs:137's raw ciborium
# interpolation) was fixed in #474 rather than allowlisted.
core/src/sync/error.rs	E1	#[error("SyncState CBOR decode failed: {detail}")]	local sync-state cache only: vault_uuid + vector clocks, no plaintext
core/src/sync/error.rs	E1	#[error("SyncState CBOR encode failed: {detail}")]	local sync-state cache only: vault_uuid + vector clocks, no plaintext

# All three producers pass fixed Kotlin-free string literals
# (sync/error.rs:111, sync/state.rs:56, :61). Left as String rather than
# &'static str only because the churn is not worth it; re-check if a producer
# is added.
core/src/sync/error.rs	E1	#[error("invalid argument: {detail}")]	all three producers pass fixed literals

# `detail` is built only from fixed literals (orchestrators.rs:2512) and
# format!("{e}") over other core errors (:2522, :2553) — all of which #474
# gates. A future producer passing something else would NOT be caught here.
core/src/vault/mod.rs	E1	#[error("trashed block {block_uuid:?} failed verification: {detail}")]	literals plus already-gated core errors
core/src/vault/mod.rs	E1	#[error("repair rejected for block {block_uuid:02x?}: {detail}")]	literals plus already-gated core errors
```

- [ ] **Step 2: Run the guard — it must now be GREEN**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
uv run scripts/check-error-payload-hygiene.py --self-test
uv run scripts/check-error-payload-hygiene.py; echo "exit=$?"
```

Expected: `error-payload hygiene: OK`, `exit=0`.

- [ ] **Step 3: Mutation-prove the allowlist is exact-line, not substring**

Temporarily re-indent an allowlisted line in `core/src/unlock/vault_toml.rs` (add two spaces). Re-run the guard — it must still pass (trimming makes indentation irrelevant). Then temporarily **edit** the message text of that same line. Re-run — it must now FAIL. Revert both.

Expected: re-indent → still green; edit content → red. If editing the content keeps it green, the matcher is substring-based and must be fixed.

- [ ] **Step 4: Write the parity test**

Create `core/tests/error_payload_hygiene_parity.rs`:

```rust
//! Asserts the Python and bash allowlist parsers agree.
//!
//! The two shell log-hygiene guards share one matcher via
//! `scripts/lib/hygiene-allowlist.sh`; `check-error-payload-hygiene.py` cannot
//! source it, so it reimplements the same exact-trimmed-line semantics. This
//! test makes that duplication non-silent: both parsers consume one fixture and
//! must produce identical accept/reject verdicts (#474).
//!
//! The deliberate departure from #475's extract-don't-duplicate rule is
//! justified because what that rule protected — `is_comment_line`, which had
//! the same bug twice — has no counterpart in a tokenizing parser.

use std::process::Command;

/// Four TAB-separated columns: `<path>\t<rule>\t<exact trimmed line>\t<reason>`.
/// Identical to the two shell guards' allowlists, which is the whole point —
/// `allowlisted()` parses this fixture unmodified.
const FIXTURE: &str = concat!(
    "# a comment line, ignored by both\n",
    "\n",
    "core/src/a.rs\tE1\t#[error(\"x: {0}\")]\treason one\n",
    "core/src/b.rs\tE1\t#[error(\"y: {detail}\")]\treason two\n",
);

#[test]
fn python_and_bash_allowlist_parsers_agree() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("fixture-allowlist.txt");
    std::fs::write(&path, FIXTURE).expect("write fixture");

    let probes: &[(&str, &str, bool)] = &[
        ("core/src/a.rs", "#[error(\"x: {0}\")]", true),
        ("core/src/b.rs", "#[error(\"y: {detail}\")]", true),
        // Right line, wrong file.
        ("core/src/a.rs", "#[error(\"y: {detail}\")]", false),
        ("core/src/c.rs", "#[error(\"x: {0}\")]", false),
        // A SUBSTRING of a real entry must NOT match. This is the property
        // whose absence was demonstrably exploitable in #467.
        ("core/src/a.rs", "#[error(\"x:", false),
        // Leading/trailing whitespace is trimmed on both sides, so an
        // indentation change must NOT break a valid entry.
        ("core/src/a.rs", "    #[error(\"x: {0}\")]   ", true),
        ("core/src/a.rs", "# a comment line, ignored by both", false),
    ];

    for &(file, line, expected) in probes {
        let py = probe_python(&path, file, line);
        let sh = probe_bash(&path, file, line);
        assert_eq!(
            py, expected,
            "python parser disagreed with the expectation for ({file}, {line:?})"
        );
        assert_eq!(
            sh, py,
            "bash and python parsers disagreed for ({file}, {line:?})"
        );
    }
}

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// The Python side keys on `path\trule\ttrimmed-line`, so trim here to mirror
/// what `allowlisted()` does to the hit text before comparing.
fn probe_python(allowlist: &std::path::Path, file: &str, line: &str) -> bool {
    let root = repo_root();
    let key = format!("{file}\tE1\t{}", line.trim());
    let script = format!(
        r#"
import importlib.util as u, pathlib, sys
spec = u.spec_from_file_location("guard", sys.argv[1])
mod = u.module_from_spec(spec)
spec.loader.exec_module(mod)
entries = mod.load_allowlist(pathlib.Path(sys.argv[2]))
print("YES" if sys.argv[3] in entries else "NO")
"#
    );
    let out = Command::new("uv")
        .args([
            "run",
            "python",
            "-c",
            &script,
            &root
                .join("scripts/check-error-payload-hygiene.py")
                .to_string_lossy(),
            &allowlist.to_string_lossy(),
            &key,
        ])
        .current_dir(&root)
        .output()
        .expect("run python probe");
    String::from_utf8_lossy(&out.stdout).trim() == "YES"
}

/// `allowlisted()` takes `(rule, hit)` where `hit` is `<file>:<line>:<text>`,
/// and reads `$ALLOWLIST` / `$REPO_ROOT` from the SOURCING scope — it does not
/// take them as arguments. `$ALLOWLIST` must not be `readonly`. See the header
/// of `scripts/lib/hygiene-allowlist.sh`.
fn probe_bash(allowlist: &std::path::Path, file: &str, line: &str) -> bool {
    let root = repo_root();
    let out = Command::new("bash")
        .arg("-c")
        .arg(
            r#"set -euo pipefail
source scripts/lib/hygiene-allowlist.sh
if allowlisted "E1" "$1"; then echo YES; else echo NO; fi"#,
        )
        .arg("bash")
        // `<file>:<line-number>:<text>` — allowlisted() strips the first two
        // colon-delimited fields, so the line number is arbitrary.
        .arg(format!("{file}:1:{line}"))
        .env("ALLOWLIST", allowlist)
        .env("REPO_ROOT", &root)
        .current_dir(&root)
        .output()
        .expect("run bash probe");
    String::from_utf8_lossy(&out.stdout).trim() == "YES"
}
```

**The `allowlisted()` contract, verified against `scripts/lib/hygiene-allowlist.sh` rather than guessed:**

- Signature is `allowlisted <rule> <hit>`, where `hit` is `<file>:<line-number>:<text>`.
- It does **not** take the allowlist path or repo root as arguments — it reads `$ALLOWLIST` and `$REPO_ROOT` from the **sourcing script's scope**. Both must be set and non-empty before the call, and `$ALLOWLIST` must **not** be `readonly` (the shell guards' own `--self-test` retargets it).
- The file format is **four** tab-separated columns: `<path>\t<rule>\t<exact trimmed line>\t<reason>`. Entries whose first column is blank or begins with `#` are skipped.
- It trims leading/trailing whitespace from the hit text before comparing, which is why the re-indentation probe above must return `true`.

This is why the new allowlist carries an `E1` rule column despite the guard having only one rule: format parity is what lets `allowlisted()` parse this guard's file unmodified, which is what makes the parity test meaningful rather than a test of two hand-written parsers that were never going to be run against the same input.

- [ ] **Step 5: Run the parity test**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && cargo test --release --workspace --test error_payload_hygiene_parity 2>&1 | tail -20
```

Expected: PASS. Add `tempfile` to `core`'s `[dev-dependencies]` if it is not already there — note it is pinned to `=3.27.0` as a regular dependency, so reuse that exact pin.

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo clippy --release --workspace --tests -- -D warnings
git add scripts/error-payload-hygiene-allowlist.txt core/tests/error_payload_hygiene_parity.rs core/Cargo.toml
git commit -m "$(cat <<'EOF'
feat(scripts): populate the error-payload allowlist — guard GREEN (#474)

Nine reviewed entries in two sections by review weight. Section 1 is
already-disclosed content (vault.toml is cleartext on disk per vault-format §2).
Section 2 is the honest one: entries safe by CONSTRUCTION SITE, which this guard
structurally cannot verify because it sees declarations, not producers.

The parity test makes the Python/bash allowlist duplication non-silent: one
fixture, both parsers, identical verdicts — including that a substring of a real
entry must NOT match.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: CI wiring

**Files:**
- Modify: `.github/workflows/test.yml`

**Interfaces:**
- Consumes: the guard from Tasks 8–9.
- Produces: a `rust-error-payload-hygiene` job.

**Background.** Copy the shape of the existing `swift-log-hygiene` job at `.github/workflows/test.yml:162-188`. Two conventions are load-bearing:

1. **`--self-test` runs FIRST as its own step.** A guard never observed failing is indistinguishable from a no-op.
2. **Step names are QUOTED.** An unquoted ` #` inside a YAML `name:` starts a comment and silently truncates it — valid YAML, so `actionlint` stays green. That trap cost a fixup in #470.

- [ ] **Step 1: Add the job**

Insert after the `kotlin-log-hygiene` job:

```yaml
  rust-error-payload-hygiene:
    name: rust error payload hygiene
    # Asserts no `core` error variant interpolates a runtime String into its
    # #[error] message (#474). RecordError::DuplicateKey formatted a decrypted
    # CBOR field name, which reached iOS as .corruptVault and Android as
    # SaveCryptoFailure — and is why both platforms redacted those arms
    # WHOLESALE, losing the detail for every corruption diagnostic.
    #
    # The payload types are now data-free by construction. This keeps them that
    # way: a regression fails in the Rust author's own PR instead of silently
    # degrading a platform two layers away. That drift — a Rust edit with no
    # platform diff and no failing test anywhere — is how the original shipped.
    #
    # Pure text analysis over core/src/**, no Rust toolchain, so it runs on
    # ubuntu in seconds.
    runs-on: ubuntu-latest
    timeout-minutes: 10   # runaway cap (vs the 6h default); real duration ~1s
    steps:
      - uses: actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4
      - name: 'install uv'
        uses: astral-sh/setup-uv@v5
      # --self-test FIRST: a guard never observed failing is indistinguishable
      # from a no-op. Two-sided — the matcher must fire on a known-positive AND
      # stay silent on a known-negative.
      #
      # The step names are QUOTED: an unquoted ` #` inside a YAML `name:` starts
      # a comment and silently truncates it — valid YAML, so actionlint stays
      # green. That trap cost a fixup in #470.
      - name: 'check-error-payload-hygiene.py --self-test'
        run: uv run scripts/check-error-payload-hygiene.py --self-test
      - name: 'check-error-payload-hygiene.py'
        run: uv run scripts/check-error-payload-hygiene.py
```

**Check how other jobs in this repo install `uv`** before using `astral-sh/setup-uv@v5` — grep `test.yml` and `audit.yml` for an existing `uv` setup step and copy that exact pinned form (this repo pins action SHAs). If no job installs `uv` yet, pin the action by SHA like the `checkout` above.

- [ ] **Step 2: Lint the workflow**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && actionlint .github/workflows/test.yml
```

Expected: no output.

- [ ] **Step 3: Verify the step names did not truncate**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && uv run python -c "
import yaml, pathlib
d = yaml.safe_load(pathlib.Path('.github/workflows/test.yml').read_text())
for s in d['jobs']['rust-error-payload-hygiene']['steps']:
    print(repr(s.get('name')))
"
```

Expected: both names print in full, including the `--self-test` suffix. `actionlint`-green is not proof — that is the #470 lesson.

- [ ] **Step 4: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
git add .github/workflows/test.yml
git commit -m "$(cat <<'EOF'
ci: gate error-payload hygiene on every PR (#474)

--self-test first, as its own step: a guard never observed failing is
indistinguishable from a no-op. Step names quoted — an unquoted ` #` inside a
YAML name: silently truncates it while actionlint stays green (#470).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## ⛔ Natural stop point

**The branch is coherent and shippable here.** Everything above is the Rust-side fix plus its enforcement; everything below is the payoff. If the session ends, open the PR at this commit and make Tasks 11–13 a small follow-up with the hard proof already merged.

Before stopping, run the full gate set:

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
git diff main... --stat -- ffi/secretary-ffi-uniffi/src/secretary.udl   # MUST be empty
```

The two uniffi conformance runners matter even though `FfiVaultError` is untouched: per `project_secretary_ffivaulterror_workspace_match`, those harnesses are invisible to `cargo`, and `CardError` / `BundleError` reshaping could reach them.

---

## Task 11: iOS — remove the `.corruptVault` redaction

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/SecretFreeError.swift` (the `VaultAccessError` conformance, roughly `:76-119`)
- Modify: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessTests/SecretFreeErrorTests.swift` (exact filename to be confirmed by grep)

**Interfaces:**
- Consumes: the Rust-side guarantee from Tasks 1–10.
- Produces: `VaultAccessError.diagnosticDescription` redacting `.invalidArgument` only.

**Background.** The redaction's own doc comment states its justification: *"at least one of those strings embeds vault plaintext: `RecordError::DuplicateKey { key }` … We do not author those strings, so their content cannot be reviewed here."* Tasks 1–10 make both halves false. `.invalidArgument` **stays redacted** — its payload is Swift-authored (`RecordEditViewModel` interpolates a decrypted field name), a different class entirely, tracked as #473.

- [ ] **Step 1: Write the failing test**

Find the existing test file first:

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && grep -rln "corruptVault" ios/SecretaryVaultAccess/Tests/
```

Add to it:

```swift
    /// #474: the Rust payload is now gated at source, so a corruption
    /// diagnostic must keep its detail. Before #474 this arm was redacted
    /// wholesale because `RecordError::DuplicateKey` embedded a decrypted
    /// field name.
    func testCorruptVaultDetailSurvivesRendering() {
        let error = VaultAccessError.corruptVault("manifest fingerprint mismatch")
        XCTAssertTrue(
            error.diagnosticDescription.contains("manifest fingerprint mismatch"),
            "the corruption detail must survive: \(error.diagnosticDescription)"
        )
        XCTAssertFalse(
            error.diagnosticDescription.contains("<redacted>"),
            "corruptVault should no longer be redacted"
        )
    }

    /// The sibling that must NOT change. `.invalidArgument`'s payload is
    /// SWIFT-authored — `RecordEditViewModel` interpolates a decrypted record
    /// field name into it — so it is a different class from the Rust-authored
    /// payloads #474 gated. Tracked as #473.
    func testInvalidArgumentStaysRedacted() {
        let error = VaultAccessError.invalidArgument("field 'amex-cvv' is not valid hex")
        XCTAssertEqual(error.diagnosticDescription, "invalidArgument(<redacted>)")
        XCTAssertFalse(error.diagnosticDescription.contains("amex-cvv"))
    }
```

- [ ] **Step 2: Run to verify the first test fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene/ios/SecretaryVaultAccess && swift test 2>&1 | tail -25
```

Expected: `testCorruptVaultDetailSurvivesRendering` FAILS (renders `corruptVault(<redacted>)`); `testInvalidArgumentStaysRedacted` passes already.

- [ ] **Step 3: Remove the redaction and rewrite the doc comment**

In `SecretFreeError.swift`, delete the `case .corruptVault: return "corruptVault(<redacted>)"` arm, leaving:

```swift
    public var diagnosticDescription: String {
        switch self {
        case .invalidArgument:
            return "invalidArgument(<redacted>)"
        default:
            return String(describing: self)
        }
    }
```

Replace the `.corruptVault` paragraph of the doc comment (the block beginning *"`.corruptVault` is redacted for the same reason, one layer further down."*) with:

```swift
    /// `.corruptVault` is NO LONGER redacted. Its payload is a Rust-side error
    /// string passed through by `VaultErrorMapping`, and until #474 at least one
    /// of those strings embedded vault plaintext: `RecordError::DuplicateKey`
    /// formatted the decrypted CBOR field name into its message. #474 made every
    /// `core` error payload data-free by construction — plaintext-bearing
    /// payloads carry a `&'static str` hint plus an ordinal, and the `ciborium`
    /// message is discarded at the boundary — and
    /// `scripts/check-error-payload-hygiene.py` fails CI if a new variant
    /// reintroduces a runtime `String`. Restoring this redaction would throw
    /// away every corruption diagnostic for no remaining benefit.
    ///
    /// `.invalidArgument` above is NOT covered by that guarantee and must stay
    /// redacted: its payload is SWIFT-authored, not Rust-authored — see #473.
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene/ios/SecretaryVaultAccess && swift test 2>&1 | tail -25
```

- [ ] **Step 5: Mutation-prove**

Re-add the `.corruptVault` redaction arm. Confirm `testCorruptVaultDetailSurvivesRendering` fails and `testInvalidArgumentStaysRedacted` still passes. Revert.

- [ ] **Step 6: Run the iOS log-hygiene guard and commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh
git add -A ios/
git commit -m "$(cat <<'EOF'
fix(ios): stop redacting VaultAccessError.corruptVault (#474)

The redaction's own doc comment named its cause: RecordError::DuplicateKey
embedded a decrypted CBOR field name, and "we do not author those strings, so
their content cannot be reviewed here". Both halves are now false — every core
error payload is data-free by construction and a CI guard keeps it that way.

The redaction cost the detail for EVERY corruption diagnostic, not just the
leaking one. That was the correct fail-closed trade while the payload was
unreviewable; it is pure loss now.

.invalidArgument stays redacted: its payload is SWIFT-authored (#473).

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 12: Android — remove the `CorruptVault` / `SaveCryptoFailure` redactions

**Files:**
- Modify: `android/vault-access/src/main/kotlin/org/secretary/browse/VaultBrowseError.kt:70-80`
- Modify: `android/kit/src/main/kotlin/org/secretary/browse/BrowseMapping.kt:27`
- Modify: the corresponding test file under `android/vault-access/src/test/`

**Interfaces:**
- Consumes: the Rust-side guarantee from Tasks 1–10.
- Produces: `VaultBrowseError.diagnosticDescription` redacting `InvalidArgument` only.

**Background.** `BrowseMapping.kt:27` maps `SaveCryptoFailure` **explicitly** and carries the raw Rust detail, which via the bridge's fold of `VaultError::Record(_)` was `RecordError::DuplicateKey`'s decrypted field name. `InvalidArgument` **stays redacted** — `RecordEditModel.kt:179` builds `"field '${f.name}' is not valid hex"` and `:193` builds `"duplicate field name: ${v.name}"` from a decrypted record. Kotlin-authored, different class, tracked as #476.

**#475's lesson applies directly here:** assert on message **content**, never on exception **type**. The pre-existing mirror tests asserted only on type, which is exactly why an entire failure path collapsed to `<undisclosed …>` unnoticed.

- [ ] **Step 1: Write the failing test**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene && grep -rln "SaveCryptoFailure" android/vault-access/src/test/
```

Add to that file:

```kotlin
    /** #474: the Rust payload is gated at source, so the detail must survive. */
    @Test
    fun `corruptVault and saveCryptoFailure details survive rendering`() {
        val corrupt = VaultBrowseError.CorruptVault("manifest fingerprint mismatch")
        assertTrue(
            "the corruption detail must survive: ${corrupt.diagnosticDescription}",
            corrupt.diagnosticDescription.contains("manifest fingerprint mismatch"),
        )

        val save = VaultBrowseError.SaveCryptoFailure("AEAD tag mismatch on block write")
        assertTrue(
            "the save detail must survive: ${save.diagnosticDescription}",
            save.diagnosticDescription.contains("AEAD tag mismatch on block write"),
        )
    }

    /**
     * The sibling that must NOT change. `InvalidArgument`'s payload is
     * KOTLIN-authored — RecordEditModel.kt:179/:193 interpolate a decrypted
     * record field name — so it is a different class from the Rust-authored
     * payloads #474 gated. Tracked as #476.
     */
    @Test
    fun `invalidArgument stays redacted`() {
        val e = VaultBrowseError.InvalidArgument("duplicate field name: amex-cvv")
        assertEquals("InvalidArgument(<redacted>)", e.diagnosticDescription)
        assertFalse(e.diagnosticDescription.contains("amex-cvv"))
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene/android && ./gradlew :vault-access:test 2>&1 | tail -30
```

Expected: the first test FAILS; the second passes already.

- [ ] **Step 3: Remove the two redaction arms**

`VaultBrowseError.kt:76-80` becomes:

```kotlin
    override val diagnosticDescription: String
        get() = when (this) {
            is InvalidArgument -> "InvalidArgument(<redacted>)"
            else -> toString()
        }
```

Rewrite the audit KDoc above it. The `NOTE:` paragraph currently warns that an arm's payload can change from a Rust edit with no Kotlin diff — replace it with:

```kotlin
     * As of #474 that drift is no longer silent: every `core` error payload is
     * data-free by construction (plaintext-bearing payloads carry a
     * `&'static str` hint plus an ordinal; the ciborium message is discarded at
     * the boundary), and `scripts/check-error-payload-hygiene.py` fails CI if a
     * new variant reintroduces a runtime String. [CorruptVault] and
     * [SaveCryptoFailure] are therefore no longer redacted.
     *
     * [InvalidArgument] is NOT covered by that guarantee and stays redacted: its
     * payload is KOTLIN-authored — RecordEditModel.kt:179 and :193 interpolate a
     * decrypted record field name — which is a different class. See #476.
     *
     * The guard covers `core/src/**` only. The bridge builds its own detail
     * strings and is not scanned; see #478.
```

> **Correction (2026-08-08, #486):** this passage predates PR #479/#489.
> #478 was closed the broad way by #480 — `ffi/secretary-ffi-bridge/src/**`
> is a scan root, gated by rules E2/E3/E4. The remaining unscanned crates
> were the two BINDING WRAPPERS, which #486 closes. This plan is a
> historical execution artifact; it is not updated in place.

- [ ] **Step 4: Update `BrowseMapping.kt:27`**

If that line applies its own redaction to `SaveCryptoFailure`, remove it so the raw detail is carried. If it merely maps the arm, leave it and delete only the stale comment about the redaction.

- [ ] **Step 5: Run tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene/android && ./gradlew :vault-access:test :kit:testDebugUnitTest 2>&1 | tail -30
```

- [ ] **Step 6: Mutation-prove**

Re-add the `CorruptVault` redaction arm alone; confirm the new test fails naming that arm. Re-add `SaveCryptoFailure` alone; confirm the same. Revert both. A single combined assertion that only ever fails for one arm is the vacuity #475 caught — assert both separately, as written.

- [ ] **Step 7: Compile the consumers and commit**

Per `project_secretary_android_sealed_when_cross_module`, a change to a sealed type in `:vault-access` can break a no-`else` `when` downstream without `:vault-access:test` noticing:

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene/android
./gradlew :kit:compileDebugKotlin :browse-ui:compileDebugKotlin :sync-ui:compileDebugKotlin :app:compileDebugKotlin
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
git add -A android/
git commit -m "$(cat <<'EOF'
fix(android): stop redacting CorruptVault and SaveCryptoFailure (#474)

BrowseMapping.kt:27 mapped SaveCryptoFailure explicitly and carried the raw Rust
detail, which via the bridge's fold of VaultError::Record(_) was
RecordError::DuplicateKey's decrypted CBOR field name. #474 gates that at source.

InvalidArgument stays redacted: RecordEditModel.kt:179/:193 build its payload
from a decrypted record in KOTLIN, a different class (#476).

Tests assert on message CONTENT, not exception type — asserting on type is
exactly why an entire failure path collapsed to `<undisclosed …>` unnoticed
before #475.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 13: Documentation

**Files:**
- Modify: `CLAUDE.md`
- Check: `README.md`, `ROADMAP.md`

**Background.** `CLAUDE.md` currently contains, under the Kotlin log-hygiene section, a paragraph headed *"`VaultBrowseError.SaveCryptoFailure` must stay redacted, and iOS is not a precedent for removing it"*, ending *"Do not 'align the platforms' by deleting the redaction."* That instruction was correct when written and is now **actively wrong**. Leaving it would send a future session to re-add a redaction this work exists to remove.

- [ ] **Step 1: Replace the obsolete CLAUDE.md paragraph**

Replace that paragraph with:

```markdown
- **`SaveCryptoFailure` / `CorruptVault` are no longer redacted — and the reason
  they once were is the reason #474 exists.** `BrowseMapping.kt:27` maps
  `SaveCryptoFailure` explicitly and carries the raw Rust detail, which via the
  bridge's fold of `VaultError::Record(_)` was `RecordError::DuplicateKey`'s
  decrypted CBOR field name. Both platforms redacted the arm wholesale, losing
  the detail for every corruption diagnostic rather than just the leaking one.
  #474 fixed it at the source instead: plaintext-bearing `core` error payloads
  carry a `&'static str` map-level hint plus an ordinal, never the key, and the
  `ciborium` message — whose `Display` is its `Debug` form — is discarded at the
  boundary by `core/src/cbor.rs`. **`InvalidArgument` stays redacted on both
  platforms**: its payload is platform-authored (`RecordEditModel.kt:179`/`:193`
  in Kotlin, `RecordEditViewModel` in Swift), a different class entirely
  (#473 / #476). Do not sweep it into "align the platforms".
```

- [ ] **Step 2: Add the guard to CLAUDE.md's Commands block**

After the Android log-hygiene commands:

```bash
# Assert no `core` error variant interpolates a runtime String into its
# #[error] message (#474). RecordError::DuplicateKey formatted a decrypted CBOR
# field name, which is why both platforms once redacted whole error arms. The
# payload types are now data-free by construction; this keeps them that way, and
# fails in the Rust author's own PR rather than degrading a platform two layers
# away. Default-deny: an unrecognised payload type is a FAILURE, not a pass.
uv run scripts/check-error-payload-hygiene.py --self-test
uv run scripts/check-error-payload-hygiene.py
```

- [ ] **Step 3: Add a CLAUDE.md architecture section**

After the Kotlin log-hygiene section, add a short section — *"Rust error payloads: data-free by construction (#474)"* — covering: the three groups; that `core/src/cbor.rs` is the only place the `ciborium` message is seen; that the allowlist's Section 2 entries are construction-site claims the guard cannot verify; and that the guard scans `core/src/**` only, leaving the bridge's own detail strings to #478.

> **Correction (2026-08-08, #486):** this passage predates PR #479/#489.
> #478 was closed the broad way by #480 — `ffi/secretary-ffi-bridge/src/**`
> is a scan root, gated by rules E2/E3/E4. The remaining unscanned crates
> were the two BINDING WRAPPERS, which #486 closes. This plan is a
> historical execution artifact; it is not updated in place.

- [ ] **Step 4: Decide on README / ROADMAP by precedent grep**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
grep -n "check-log-hygiene\|check-public-log-hygiene\|check-lean-binding\|#467\|#472\|#189" README.md ROADMAP.md
```

The three prior guards (`#189`, `#467`, `#472`) appear in **neither** file. If this grep confirms that, leave both unchanged and say so explicitly in the handoff — "unchanged by precedent" is a finding, not an omission. If the grep shows otherwise, follow the precedent it reveals.

Run this from the worktree with an absolute `cd`: a previous session ran this same grep from the wrong directory and got a wrong answer from `android/README.md`.

- [ ] **Step 5: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/474-error-payload-hygiene
git add -A CLAUDE.md README.md ROADMAP.md
git commit -m "$(cat <<'EOF'
docs: record the #474 invariant and retire the obsolete redaction note

CLAUDE.md instructed future sessions NOT to delete the SaveCryptoFailure
redaction. That was correct while the payload was Rust-authored and
unreviewable; it is actively wrong now and would send someone to re-add a
redaction this work exists to remove.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Self-review notes

**Spec coverage.** Every spec section maps to a task: §1 Group 1 → Tasks 2, 3, 5, 6; §2 Group 2 → Tasks 1, 4, 5, 6, 7; §3 Group 3 → Task 9's allowlist; §4 the guard → Tasks 8–10; §5 platform narrowing → Tasks 11–12; docs → Task 13.

**One deliberate deviation**, flagged at the top of this plan and in Task 7: the spec puts `SyncError`'s two state-codec variants in Group 2; the plan puts them in Group 3 (allowlist) and fixes only the single `ciborium` passthrough. Reason: 21 producers over a struct that provably holds no vault plaintext. If the reviewer disagrees, Task 7 expands rather than any other task changing.

**Type consistency.** `CborFault` / `CborErrorKind` / `classify_de` / `classify_ser` are defined in Task 1 and used with those exact names in Tasks 4, 5, 6, 7 and in the guard's `DATA_FREE_TYPES`. `DuplicateKey { field, index }` is defined in Task 2 and reused verbatim in Task 3.

**Resolved during plan review.** An earlier draft of Task 9 guessed `allowlisted`'s signature. It was verified against `scripts/lib/hygiene-allowlist.sh` instead: the function is `allowlisted <rule> <hit>` reading `$ALLOWLIST`/`$REPO_ROOT` from the sourcing scope, over a **four**-column format. The new allowlist and the Python parser were both changed to carry an `E1` rule column so `allowlisted()` parses this guard's file unmodified — otherwise the parity test would have compared two parsers that could never read the same file, which is worse than no parity test.

**Remaining soft spots, stated rather than hidden.**

- Task 2's index assertions (`index == 1`) are predictions about fixture ordering. Each step says to correct the *test* to the observed ordinal if it differs, never the implementation.
- Task 8's Rust parsing is pattern-based, not a real parser. The `--self-test` controls pin the shapes that occur in this codebase; a macro-generated error enum would be invisible. Stated in the guard's own `LIMITS` block.
- Task 3 and Task 5 reference test helpers (`cbor_map_bytes_unsorted`, card fixture builders) that may or may not exist under those names. Both steps say to grep first and reuse rather than add.
