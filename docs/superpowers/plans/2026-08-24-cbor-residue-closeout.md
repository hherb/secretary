# Canonical-CBOR Residue Closeout — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the six remaining canonical-CBOR plaintext-residue gaps in `secretary-core`, and convert two "the mechanism is right but nothing would notice if it were removed" complaints into compiler-enforced guarantees.

**Architecture:** Two mechanisms, already established in #560. **Eliminate** what we copy — the borrowing `CanonicalValue`/`CanonicalMap` mirror replaces owned `ciborium::Value` construction (T3). **Wipe** what a foreign allocator makes — a new single sanctioned parse entry point owns `ciborium`'s scratch buffer and zeroizes it on drop (T1/T2). Where a wrap exists but is deletable, move the wrapper into the **return type** so a plain `Vec<u8>` no longer typechecks (T4).

**Tech Stack:** Rust (stable, pinned 1.97.0 via `rust-toolchain.toml`), `ciborium` 0.2.2, `zeroize`, `proptest` 1 (already a `secretary-core` dev-dependency).

**Spec:** `docs/superpowers/specs/2026-08-24-cbor-residue-closeout-design.md` — read it before Task 1. Its §2 records three census corrections that changed the design; do not re-derive them.

## Spec-to-plan task numbering

The plan's task numbers are **execution order**; the spec's §3 numbers are
**topic order**. Two differ — cross-reference with this table, do not assume
`Task N` means the same thing in both documents.

| Plan task | Spec §3 | Topic |
|---|---|---|
| Task 1 | T1 | `cbor::scratch` |
| Task 2 | T2 | route the six parse sites |
| **Task 3** | **T4** | **encoders return `SecretBytes`** |
| **Task 4** | **T3** | **bundle encode → `CanonicalMap`** |
| Task 5 | T5 | `set_once` |
| Task 6 | T6 | manifest duplicate keys |
| Task 7 | T7 | key-order proptest |
| Task 8 | T8 | documentation |

The spec's §4 already specifies this execution order (`T1 → T2 → T4 → T3 → …`):
the encoder signature change has the widest ripple and should surface surprises
first, and the bundle migration is the one task that can move on-disk bytes, so
it wants a settled tree underneath it.

## Global Constraints

- **Worktree:** `/Users/hherb/src/secretary/.worktrees/cbor-residue-closeout`, branch `feature/cbor-residue-closeout`. Verify with `pwd && git branch --show-current` before every `cargo` or `git` command. Shell state does not persist between tool calls — use absolute paths or chain in one call.
- **`core/tests/data/` diff MUST stay EMPTY.** Check with `git diff main... --stat -- core/tests/data/` after every task. No on-disk format change is authorised by this plan.
- **`ffi/secretary-ffi-uniffi/src/secretary.udl` diff MUST stay EMPTY.** Nothing here crosses the FFI.
- `#![forbid(unsafe_code)]` is set in the root workspace lints. Do not introduce `unsafe`.
- Clippy must stay clean with `-D warnings`, **both with and without `--tests`**.
- Rustdoc must stay clean: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace`. Narrowing an item's visibility can break a public intra-doc link; widening a `use` can make an explicit link redundant. Both directions are live in this repo.
- **No magic numbers.** Every buffer size, length and index gets a named `const` with a doc comment.
- **Commit messages MUST NOT contain a GitHub auto-close keyword** (`closes`, `fixes`, `resolves` followed by `#N`). Cite issues as `(#N)`. This repo deliberately leaves issues open until a human closes them.
- **Every commit ends with:** `Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>`
- Build/test always `--release` (the crypto crates are unusably slow in debug).
- Per-task iteration: `cargo test --release -p secretary-core <filter>`. Full gate before handoff: `cargo test --release --workspace`.

---

## File Structure

| File | Status | Responsibility |
|---|---|---|
| `core/src/cbor/scratch.rs` | **create** | `CborScratch` + `from_secret_reader` — the one sanctioned parse entry point for secret-bearing CBOR. Owns `ciborium`'s scratch buffer so it can be wiped. |
| `core/src/cbor/mod.rs` | modify | declare + re-export `scratch`. |
| `core/src/cbor/secret_tree/mod.rs` | modify | expose `pub(super) fn note_wipe()` so a sibling module can bump the shared counter; extend the "What this does not claim" section. |
| `core/src/unlock/bundle.rs` | modify | T2 (parse site), T3 (encode → `CanonicalMap`), T5 (`set_once`). |
| `core/src/vault/record.rs` | modify | T2 (2 parse sites), T4 (`encode` returns `SecretBytes`). |
| `core/src/vault/block.rs` | modify | T2 (1 parse site), T4 (`encode_plaintext` returns `SecretBytes`). |
| `core/src/vault/manifest.rs` | modify | T2 (2 parse sites), T4 (`encode_manifest`, `encrypt_manifest_body`), T6 (duplicate-key check). |
| `core/src/vault/canonical/value.rs` | modify | T7 (proptest for the key-order equivalence). |
| `core/src/identity/card.rs` | modify | T2 — **comment only**, recording why this site is deliberately excluded. |
| `core/src/sync/state.rs` | modify | T2 — **comment only**, same. |
| `ffi/secretary-ffi-uniffi/src/wrappers/block.rs` | modify | T8 — correct the #519 comment. |
| `docs/manual/contributors/memory-hygiene-audit-internal.md` | modify | T8. |
| `CLAUDE.md` | modify | T8. |

`core/src/cbor/scratch.rs` is a new file rather than an addition to `cbor/mod.rs` or `secret_tree/mod.rs`: it is a third distinct concern (the parser's own scratch space, as opposed to error classification or the parsed tree), and both existing files are near the project's 500-line threshold.

---

## Task 1: The sanctioned secret-bearing parse entry point

**Files:**
- Create: `core/src/cbor/scratch.rs`
- Modify: `core/src/cbor/mod.rs` (add `mod scratch;` + re-export)
- Modify: `core/src/cbor/secret_tree/mod.rs` (add `pub(super) fn note_wipe()`)
- Test: inline `#[cfg(test)] mod tests` in `core/src/cbor/scratch.rs`

**Interfaces:**
- Consumes: `ciborium::de::{from_reader_with_buffer, Error}`, `ciborium::value::Value`, `zeroize::Zeroize`.
- Produces:
  - `pub(crate) fn from_secret_reader<R: ciborium_io::Read>(reader: R) -> Result<Value, ciborium::de::Error<R::Error>> where R::Error: core::fmt::Debug` — re-exported from `crate::cbor` as `from_secret_reader`. **Tasks 2 consumes this exact name and signature.**
  - `pub(crate) const CBOR_SCRATCH_LEN: usize = 4096;`
  - `pub(super) fn note_wipe()` in `secret_tree` — internal to Task 1, no later task calls it.

### Background you need

`ciborium::de::from_reader` allocates a 4 KiB stack scratch buffer and `read_exact`s **every** `Bytes`/`Text` payload ≤ 4096 bytes straight into it before the visitor copies out. On the record/block/bundle/manifest decode paths that is decrypted plaintext. `SecretValueTree` cannot reach it — it lives in the parser's stack frame, not in the parsed tree.

`from_reader` is **literally** (verified in `ciborium-0.2.2/src/de/mod.rs:825-851`):

```rust
let mut scratch = [0; 4096];
from_reader_with_buffer(reader, &mut scratch)
```

and `from_reader_with_buffer` sets the identical `recurse: 256`. So passing our own 4096-byte buffer is behaviour-identical, not merely believed to be.

The existing wipe counter lives in `core/src/cbor/secret_tree/mod.rs`:

```rust
thread_local! {
    static WIPE_CALLS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn wipe_calls() -> usize {
    WIPE_CALLS.with(std::cell::Cell::get)
}
```

All three existing bump sites are `#[cfg(test)]`-gated, so the counter costs nothing in production. Follow that exactly.

- [ ] **Step 1: Add the counter hook to `secret_tree`**

In `core/src/cbor/secret_tree/mod.rs`, immediately after the `thread_local!` block, add:

```rust
/// Bump the shared wipe counter from a sibling module in `cbor`.
///
/// `WIPE_CALLS` is private to this module, but `scratch::CborScratch`
/// (#561) needs to record its own wipe against the same counter so a
/// caller's test can pin it through `crate::cbor::wipe_calls()`. Exposing
/// one `pub(super)` bump function is a smaller change than relocating the
/// counter into `cbor/mod.rs`, which would touch all three existing
/// bump sites — frozen-adjacent code this task has no reason to churn.
///
/// `#[cfg(test)]`-gated like every other bump site: zero production cost.
#[cfg(test)]
pub(super) fn note_wipe() {
    WIPE_CALLS.with(|c| c.set(c.get() + 1));
}
```

- [ ] **Step 2: Write the failing tests**

Create `core/src/cbor/scratch.rs` containing ONLY the module doc and this test module for now (the production items land in Step 4):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cbor::wipe_calls;

    /// The scratch buffer must be wiped on the SUCCESS path. A caller's
    /// happy-path parse is the common case, so a wipe that only fired on
    /// error would cover almost nothing.
    #[test]
    fn scratch_is_wiped_on_the_success_path() {
        let bytes = canonical_text_item("hello");
        let before = wipe_calls();
        let v = from_secret_reader(bytes.as_slice()).expect("parse");
        assert_eq!(v, Value::Text("hello".to_string()));
        assert_eq!(
            wipe_calls(),
            before + 1,
            "exactly one scratch wipe per successful parse"
        );
    }

    /// ...and on the `?` path. `Drop` is the mechanism precisely because
    /// an early return cannot skip it; a trailing statement could.
    #[test]
    fn scratch_is_wiped_on_the_error_path() {
        // 0x9f = indefinite-length array head, then EOF: a parse error.
        let bytes = [0x9fu8];
        let before = wipe_calls();
        let err = from_secret_reader(bytes.as_slice());
        assert!(err.is_err(), "truncated input must fail to parse");
        assert_eq!(
            wipe_calls(),
            before + 1,
            "the scratch wipe must fire on the `?` path too"
        );
    }

    /// `from_secret_reader` must agree with `ciborium::de::from_reader`
    /// byte-for-byte across the scratch-length boundary. `from_reader` IS
    /// `from_reader_with_buffer(r, &mut [0; 4096])` with the same
    /// `recurse: 256`, so any disagreement means this wrapper changed
    /// parsing behaviour, which it must not.
    #[test]
    fn agrees_with_ciborium_from_reader_across_the_scratch_boundary() {
        for len in [
            0,
            1,
            CBOR_SCRATCH_LEN - 1,
            CBOR_SCRATCH_LEN,
            CBOR_SCRATCH_LEN + 1,
            CBOR_SCRATCH_LEN * 3,
        ] {
            let payload = vec![0xA5u8; len];
            let mut encoded = Vec::new();
            ciborium::ser::into_writer(&Value::Bytes(payload.clone()), &mut encoded)
                .expect("encode");

            let ours = from_secret_reader(encoded.as_slice()).expect("ours");
            let theirs: Value =
                ciborium::de::from_reader(encoded.as_slice()).expect("ciborium");
            assert_eq!(ours, theirs, "disagreement at payload length {len}");
        }
    }

    /// Helper: canonical CBOR for a text item.
    fn canonical_text_item(s: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Text(s.to_string()), &mut buf).expect("encode");
        buf
    }
}
```

Add `mod scratch;` to `core/src/cbor/mod.rs` next to the existing `mod secret_tree;`, and beneath it:

```rust
// `from_secret_reader` is the only sanctioned parse entry point for CBOR
// that may contain decrypted plaintext (#561). It owns `ciborium`'s own
// 4 KiB scratch buffer — into which the parser `read_exact`s every payload
// of 4096 bytes or fewer — so that buffer is zeroized on drop instead of
// being left intact in the parser's frame, which `SecretValueTree` cannot
// reach. Sites that provably carry no secret stay on plain
// `ciborium::de::from_reader`, each with a comment saying why.
pub(crate) use scratch::{from_secret_reader, CBOR_SCRATCH_LEN};
```

- [ ] **Step 3: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib cbor::scratch 2>&1 | tail -20
```

Expected: compile failure — `cannot find function 'from_secret_reader' in this scope`, `cannot find value 'CBOR_SCRATCH_LEN'`.

- [ ] **Step 4: Write the implementation**

Prepend to `core/src/cbor/scratch.rs`, above the test module:

```rust
//! `CborScratch` / `from_secret_reader` (#561): a zeroize-on-drop wrapper
//! for the scratch buffer `ciborium`'s parser uses, and the one sanctioned
//! parse entry point for CBOR that may hold decrypted plaintext.
//!
//! `ciborium::de::from_reader` allocates `[0u8; 4096]` in its own stack
//! frame and `read_exact`s **every** byte-string and text payload of that
//! size or smaller straight into it before the visitor copies out; larger
//! payloads stream through it 4 KiB at a time. That buffer therefore holds
//! decrypted record fields, block plaintext, `block_name`s and the identity
//! bundle's four long-term secret keys, and it is left intact when the
//! parser returns.
//!
//! `SecretValueTree` (see `super::secret_tree`) cannot reach it: that type
//! wraps the parsed `Value` **tree**, and this buffer is not part of the
//! tree — it is the staging area the tree was built from.
//!
//! The fix is to own the buffer ourselves. `ciborium::de::from_reader` is
//! literally
//!
//! ```ignore
//! let mut scratch = [0; 4096];
//! from_reader_with_buffer(reader, &mut scratch)
//! ```
//!
//! (`ciborium-0.2.2/src/de/mod.rs:825-851`), and `from_reader_with_buffer`
//! sets the identical `recurse: 256`, so passing our own buffer of the same
//! length is **behaviour-identical** — verified against the vendored source,
//! not inferred from the docs.
//!
//! # What this does not claim
//!
//! This closes the parser's *scratch* buffer only. `ciborium`'s
//! `deserialize_byte_buf` / `deserialize_string` build the final payload
//! with `Vec::new()` / `String::new()` plus per-chunk `extend_from_slice`,
//! so a payload larger than [`CBOR_SCRATCH_LEN`] still grows by doubling
//! and frees an unwiped prefix at each reallocation — routinely, for any
//! attachment, long note or stored key file. That happens inside the
//! parser's visitor, before any wrapper here sees the value, and there is
//! no public hook for it. Tracked as **#570**.

use ciborium::value::Value;
use zeroize::Zeroize;

/// Length of the parser scratch buffer, in bytes.
///
/// Deliberately equal to `ciborium`'s own default (`de/mod.rs:829`). A
/// different value would be sound but would change how payloads are
/// chunked, and this module's whole claim is that routing through it
/// changes no parsing behaviour.
pub(crate) const CBOR_SCRATCH_LEN: usize = 4096;

/// A parser scratch buffer that is zeroized when it drops.
///
/// The field is module-private and no `&mut` accessor escapes this file:
/// the only code that can hand the buffer to `ciborium` is
/// [`from_secret_reader`] below.
struct CborScratch([u8; CBOR_SCRATCH_LEN]);

impl Drop for CborScratch {
    /// Hand-written rather than `#[derive(ZeroizeOnDrop)]`, deliberately.
    ///
    /// A derived `Drop` bumps no counter, so a test cannot observe it, and
    /// a wipe nothing observes can be deleted with the whole suite green —
    /// which is exactly the complaint #557 and #558 record against two
    /// mechanisms that shipped that way. Writing `Drop` by hand lets this
    /// one be pinned by test from the moment it lands.
    fn drop(&mut self) {
        #[cfg(test)]
        super::secret_tree::note_wipe();
        self.0.zeroize();
    }
}

/// Parse CBOR that may contain decrypted plaintext.
///
/// Behaviourally identical to [`ciborium::de::from_reader`] (see the module
/// doc for why), but the scratch buffer the parser stages payloads through
/// is owned here and wiped on **every** exit — a normal return, an early
/// `?`, or an unwinding panic — rather than left intact in `ciborium`'s
/// frame.
///
/// This is the sanctioned entry point for every secret-bearing parse in the
/// crate. `grep -rn "ciborium::de::from_reader" core/src` shows the
/// remaining plain-`from_reader` sites; each carries a comment saying why
/// it provably holds no secret.
pub(crate) fn from_secret_reader<R: ciborium_io::Read>(
    reader: R,
) -> Result<Value, ciborium::de::Error<R::Error>>
where
    R::Error: core::fmt::Debug,
{
    let mut scratch = CborScratch([0u8; CBOR_SCRATCH_LEN]);
    // `scratch` drops at the end of this function on every path, including
    // the implicit early exit inside `from_reader_with_buffer`'s `?`.
    ciborium::de::from_reader_with_buffer(reader, &mut scratch.0)
}
```

In `core/src/cbor/secret_tree/mod.rs`, the module is declared `mod secret_tree;` (private) in `cbor/mod.rs`. `scratch.rs` reaches `note_wipe` as `super::secret_tree::note_wipe()`.

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib cbor:: 2>&1 | tail -20
```

Expected: PASS, 3 new tests.

- [ ] **Step 6: Prove the wipe is load-bearing (mutation check)**

Temporarily comment out `self.0.zeroize();` in `Drop`, re-run, and confirm nothing fails — then restore it and confirm the counter tests still pass. This proves what the tests DO and do NOT pin: they pin that `Drop` **runs**, not that the bytes are gone (freed/dead stack is not observable from safe Rust). Record that distinction in the commit message. Do not leave the mutation in place.

- [ ] **Step 7: Gates**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all && \
  cargo clippy --release --workspace --tests -- -D warnings && \
  cargo clippy --release --workspace -- -D warnings && \
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -5
```

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout
git add core/src/cbor/scratch.rs core/src/cbor/mod.rs core/src/cbor/secret_tree/mod.rs
git commit -F - <<'MSG'
feat(cbor): own ciborium's parser scratch buffer so it can be wiped (#561)

ciborium::de::from_reader allocates [0u8; 4096] in its own stack frame and
read_exact's every byte-string and text payload of that size or smaller
straight into it before the visitor copies out. On the record, block,
bundle and manifest decode paths that buffer holds decrypted plaintext,
and it is left intact when the parser returns. SecretValueTree cannot
reach it: that type wraps the parsed tree, not the staging area the tree
was built from.

from_secret_reader owns the buffer instead, wiping it on every exit via a
hand-written Drop. Behaviour-identical to from_reader, verified against
ciborium-0.2.2/src/de/mod.rs:825-851 rather than inferred from the docs:
from_reader IS from_reader_with_buffer(reader, &mut [0; 4096]) with the
same recurse: 256.

Drop is hand-written rather than derived so it can bump the shared
WIPE_CALLS counter. A derived wipe is unobservable, and an unobservable
wipe can be deleted with the whole suite green — the complaint #557 and
#558 record against two mechanisms that shipped that way. This one is
pinnable from the moment it lands.

What the tests pin, precisely: that Drop RUNS on both the success and the
`?` path, not that the bytes are gone. Freed heap and dead stack are not
observable from safe Rust; commenting out the zeroize() leaves the suite
green, which is a limit of the observation, not of the mechanism.

No production cost: the counter bump is #[cfg(test)]-gated, matching the
three existing bump sites in secret_tree.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 2: Route the six secret-bearing parse sites onto it

**Files:**
- Modify: `core/src/unlock/bundle.rs:388`
- Modify: `core/src/vault/block.rs:1032`
- Modify: `core/src/vault/manifest.rs:730`, `core/src/vault/manifest.rs:760`
- Modify: `core/src/vault/record.rs:299`, `core/src/vault/record.rs:607`
- Modify: `core/src/identity/card.rs:320` — **comment only**
- Modify: `core/src/sync/state.rs:136` — **comment only**
- Test: add one `wipe_calls()` assertion per converted path, in each file's existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `crate::cbor::from_secret_reader` from Task 1.
- Produces: nothing new. Later tasks touch these same functions but not these lines.

### The eight sites, and why six convert

`grep -rn "ciborium::de::from_reader" core/src` finds eight production calls (the rest are tests). Six carry secrets:

| Site | Carries |
|---|---|
| `unlock/bundle.rs:388` (`IdentityBundle::from_canonical_cbor`) | X25519 sk, ML-KEM-768 dec key (2400 B), Ed25519 sk, ML-DSA-65 seed |
| `vault/block.rs:1032` (`decode_plaintext`) | the entire decrypted block plaintext |
| `vault/manifest.rs:730` (`unknown_value_inner`) | forward-compat plaintext inside the encrypted manifest |
| `vault/manifest.rs:760` (`decode_manifest`) | every `block_name` — user-authored plaintext |
| `vault/record.rs:299` (`UnknownValue::from_canonical_cbor`) | a forward-compat unknown record subtree |
| `vault/record.rs:607` (`decode`) | decrypted record field plaintext |

Two do not, and **must keep a comment saying so** — #561's own site list read as incomplete precisely because its secrecy filter was never stated:

- `identity/card.rs:320` — `ContactCard` holds `card_version`, `contact_uuid`, `display_name`, four **public** keys, `created_at_ms` and two self-signatures. `grep -c "Sensitive\|SecretBytes\|SecretString" core/src/identity/card.rs` returns 0. The contact card is the artifact handed to other users.
- `sync/state.rs:136` — sync bookkeeping (vector clocks, timestamps), no vault content.

- [ ] **Step 1: Write the failing tests**

Add one test per converted path. Each asserts an **exact** count, not `> before` — a weak inequality was tightened to an exact count during #560's review for this same reason. Example for `record::decode` (add to `core/src/vault/record.rs`'s test module):

```rust
/// `decode` must parse through `cbor::from_secret_reader`, whose scratch
/// buffer holds a copy of every decrypted field value in the input
/// (#561). Pinning the COMPOSITION, not just the mechanism: `scratch.rs`'s
/// own tests prove the wipe fires, this one proves this path uses it.
#[test]
fn decode_wipes_the_parser_scratch_buffer() {
    let mut rng = ChaCha20Rng::from_seed([41u8; 32]);
    let record = random_record(&mut rng, true, TombstoneState::Live);
    let bytes = encode(&record).expect("encode");

    let before = crate::cbor::wipe_calls();
    // NOTE: Task 2 runs BEFORE Task 3, so `encode` still returns `Vec<u8>`
    // here. After Task 3 lands, this becomes `decode(bytes.expose())` — the
    // implementer of Task 3 must fix this call site along with the others.
    let decoded = decode(&bytes).expect("decode");
    let after = crate::cbor::wipe_calls();

    assert_eq!(decoded.record_uuid, record.record_uuid);
    // One scratch wipe from `from_secret_reader`, one tree wipe from
    // `SecretValueTree::drop`, and one further scratch wipe from the
    // `re_encoded` comparison's own parse if this path re-parses.
    // Assert the exact observed value, and if it is not 2, work out why
    // before changing the number.
    assert_eq!(after - before, 2, "expected exactly 2 wipes on the decode path");
}
```

**Important:** the exact expected count depends on how many wraps each path drops. Run the test first, read the actual number, and then *justify* it in the assertion comment — do not simply paste whatever the run produced. If a count surprises you, that is a finding, not a number to normalise.

Write the equivalent for `block::decode_plaintext`, `manifest::decode_manifest`, `manifest::unknown_value_inner`, `record::UnknownValue::from_canonical_cbor` and `bundle::IdentityBundle::from_canonical_cbor`. `bundle.rs` already has such a test for `SecretEntries`; extend it rather than adding a second.

- [ ] **Step 2: Run the tests to verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib wipes_the_parser_scratch 2>&1 | tail -25
```

Expected: FAIL — the counts are one lower than asserted, because the paths still call plain `from_reader`.

- [ ] **Step 3: Convert the six sites**

At each, replace `ciborium::de::from_reader(` with `crate::cbor::from_secret_reader(` (or `from_secret_reader(` if already imported) and leave the surrounding `map_err` untouched. Example, `core/src/vault/record.rs:607`:

```rust
    let parsed: Value = crate::cbor::from_secret_reader(bytes)
        .map_err(|e| RecordError::CborDecode(classify_de(&e)))?;
```

Above each converted call, add a one-line reason naming what that site's scratch buffer holds — e.g. for `manifest.rs:760`:

```rust
    // `from_secret_reader`, not `from_reader`: the parser stages every
    // payload through a 4 KiB scratch buffer, and this input's payloads
    // include every `block_name` — user-visible plaintext inside the
    // encrypted manifest (#561).
```

- [ ] **Step 4: Add the exclusion comments**

`core/src/identity/card.rs`, above line 320:

```rust
        // Deliberately plain `from_reader`, not `cbor::from_secret_reader`
        // (#561): a ContactCard holds `card_version`, `contact_uuid`,
        // `display_name`, four PUBLIC keys, `created_at_ms` and two
        // self-signatures — no `Sensitive` / `SecretBytes` / `SecretString`
        // field anywhere in the type. The card is the artifact handed to
        // other users; there is no plaintext here for a scratch buffer to
        // retain. Stated rather than left to inference: #561's own site
        // list read as incomplete because its secrecy filter was unstated.
```

`core/src/sync/state.rs`, above line 136:

```rust
        // Deliberately plain `from_reader`, not `cbor::from_secret_reader`
        // (#561): `SyncState` is sync bookkeeping — vector clocks and
        // timestamps — and carries no vault content. Same reasoning as
        // `identity::card::ContactCard::from_canonical_cbor`.
```

- [ ] **Step 5: Run the tests to verify they pass**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core 2>&1 | tail -15
```

Expected: PASS. If a pre-existing `wipe_calls()` test in `block.rs` or `manifest.rs` now fails on an off-by-one, that is **correct** — those paths gained a wipe. Update the expected count and extend its comment to say the scratch wipe was added.

- [ ] **Step 6: Verify the census is complete**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && grep -rn "ciborium::de::from_reader" core/src | grep -v "^core/src/cbor/"
```

Every remaining hit must be either inside a `#[cfg(test)]` module or one of the two commented exclusions. If a ninth production site exists that this plan did not name, **stop and report it** — do not convert it silently.

- [ ] **Step 7: Gates + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings && \
  git diff main... --stat -- core/tests/data/ && echo "^^ MUST BE EMPTY"
git add -A core/src
git commit -F - <<'MSG'
feat(cbor): route every secret-bearing parse through from_secret_reader (#561)

Six production sites now stage their payloads through a scratch buffer we
own and wipe, instead of the one ciborium allocates in its own frame and
leaves intact: bundle::from_canonical_cbor (four long-term secret keys),
block::decode_plaintext (the whole decrypted block), manifest's
decode_manifest (every block_name) and unknown_value_inner, and record's
decode and UnknownValue::from_canonical_cbor.

Each converted site gains a comment naming what its scratch buffer holds.

The two production sites NOT converted — card.rs and sync/state.rs — now
carry a comment saying why. #561's own site list read as incomplete
because it never stated that secrecy was the filter; ContactCard holds
zero secret-typed fields and is the artifact handed to other users.

Tests assert an exact wipe count per path, not `> before`: a weak
inequality was tightened for this same reason during #560's review.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 3: The encoders return `SecretBytes`

**Files:**
- Modify: `core/src/vault/record.rs:482` (`encode`), `:629` (`re_encoded`)
- Modify: `core/src/vault/block.rs` (`encode_plaintext`), `:1058` (`re_encoded`), `:1788` (`pt_bytes`)
- Modify: `core/src/vault/manifest.rs:438` (`encode_manifest`), `:1545` (`encrypt_manifest_body`), `:1943-1946`
- Modify: every call site of the four, in `core/src` and `core/tests`
- Test: byte-identity assertions at each converted site

**Interfaces:**
- Consumes: `crate::crypto::secret::SecretBytes` (already imported in all three files).
- Produces — **later tasks and reviewers rely on these exact signatures:**
  ```rust
  pub fn encode(record: &Record) -> Result<SecretBytes, RecordError>
  pub fn encode_plaintext(plaintext: &BlockPlaintext) -> Result<SecretBytes, BlockError>
  pub fn encode_manifest(manifest: &Manifest) -> Result<SecretBytes, ManifestError>
  pub fn encrypt_manifest_body(
      header: &ManifestHeader,
      manifest_bytes: &SecretBytes,
      ibk: &AeadKey,
      nonce: &AeadNonce,
  ) -> Result<Vec<u8>, ManifestError>
  ```
  `SecretBytes::expose()` returns `&[u8]`.

### Why this shape

#558 and #565 are the same complaint — *the mechanism is right, nothing would notice if it were removed*. Today `block.rs:1788` reads `SecretBytes::new(encode_plaintext(plaintext)?)`, and deleting the `SecretBytes::new` leaves every one of the 437 core lib tests green (verified during #560's review). Moving the wrapper into the **return type** makes the deletion a compile error instead.

`re_encoded` at `record.rs:629` and `block.rs:1058` then becomes a `SecretBytes` for free — #565 closed by removing the opportunity rather than by adding a wrap.

`aead::encrypt` is deliberately **NOT** changed. Its plaintext is not always secret — `core/tests/aead.rs:149` replays published RFC vectors — and forcing `&SecretBytes` there would churn KATs to express something untrue about the primitive. The pin goes at the manifest/block **body** boundary, where the plaintext genuinely is always secret. The spec's §2 records why #558's own "may be nearly free" premise does not hold.

**Blast radius, already measured:** `cli/src`, `ffi/*/src`, `desktop/src-tauri/src` and `browser/` call **none** of the four functions. This is a public-API change with no external consumer.

- [ ] **Step 1: Write the failing test**

Add to `core/src/vault/block.rs`'s test module:

```rust
/// `encode_plaintext` returns a `SecretBytes`, not a `Vec<u8>`, so the
/// wrap at the AEAD call site cannot be deleted without a compile error
/// (#558) and `decode_plaintext`'s `re_encoded` buffer is wrapped by
/// construction (#565). This test pins the OBSERVABLE half — that the
/// bytes are unchanged; the type itself is pinned by the compiler.
#[test]
fn encode_plaintext_returns_wrapped_bytes_identical_to_the_canonical_form() {
    let mut rng = ChaCha20Rng::from_seed([31u8; 32]);
    let plaintext = random_block_plaintext(&mut rng, 2);
    let wrapped = encode_plaintext(&plaintext).expect("encode");
    let decoded = decode_plaintext(wrapped.expose()).expect("round-trip");
    assert_eq!(decoded.block_uuid, plaintext.block_uuid);
    assert_eq!(
        wrapped.expose(),
        encode_plaintext(&decoded).expect("re-encode").expose(),
        "encoding must be deterministic and unchanged by the wrapper"
    );
}
```

`random_block_plaintext(rng, n)` already exists at `core/src/vault/block.rs:2121`;
the seeded-`ChaCha20Rng` idiom is the file's established one (crypto values must
be generated at runtime, never hardcoded byte arrays — a literal key array trips
CodeQL). Do not invent a new fixture builder.

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib encode_plaintext_returns_wrapped 2>&1 | tail -15
```

Expected: compile failure — `no method named 'expose' found for struct 'Vec<u8>'`.

- [ ] **Step 3: Change the four signatures**

`core/src/vault/record.rs`:

```rust
pub fn encode(record: &Record) -> Result<SecretBytes, RecordError> {
    Ok(SecretBytes::new(to_canonical_vec(&record_to_canonical(record))?))
}
```

Update its doc comment with:

```rust
/// Returns [`SecretBytes`], not `Vec<u8>`: the output is the decrypted
/// canonical form of a record — every field value it holds. Returning the
/// wrapper rather than leaving each caller to apply one means the wrap
/// cannot be deleted without a compile error, which is the difference
/// between this and the deletable `SecretBytes::new(..)` call sites #558
/// and #565 record.
```

`core/src/vault/block.rs`:

```rust
pub fn encode_plaintext(plaintext: &BlockPlaintext) -> Result<SecretBytes, BlockError> {
```

wrapping its final `Ok(..)` in `SecretBytes::new(..)`, and at `:1788`:

```rust
    let pt_bytes = encode_plaintext(plaintext)?;
```

(the `SecretBytes::new` is now redundant — remove it, and update the long comment above it to say the wrap is now structural rather than a call).

`core/src/vault/manifest.rs`: same for `encode_manifest`, then:

```rust
pub fn encrypt_manifest_body(
    header: &ManifestHeader,
    manifest_bytes: &SecretBytes,
    ibk: &AeadKey,
    nonce: &AeadNonce,
) -> Result<Vec<u8>, ManifestError> {
    let aad = header.encode();
    aead::encrypt(ibk, nonce, &aad, manifest_bytes.expose())
        .map_err(|_| ManifestError::AeadFailure)
}
```

Update its doc comment: the `&SecretBytes` parameter is the pin for the seventh `aead::encrypt` site, and the "callers occasionally already have the canonical bytes in hand" sentence must now say those bytes arrive wrapped.

- [ ] **Step 4: Fix the two `re_encoded` comparisons**

`core/src/vault/record.rs:629-631`:

```rust
    let re_encoded = encode(&record)?;
    if re_encoded.expose() != bytes {
        return Err(RecordError::NonCanonicalEncoding);
    }
```

`core/src/vault/block.rs:1058-1060`: the same shape with `BlockError::NonCanonicalEncoding`.

Extend the comment above each to record that `re_encoded` is now wrapped by construction (#565) — this buffer holds a full re-encoding of the decrypted content and was previously freed intact on every successful open.

- [ ] **Step 5: Fix every call site**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo build --release -p secretary-core --tests 2>&1 | grep -E "^error" | head -40
```

Work through them. Most need `.expose()` added. **Read each converted assertion rather than pattern-replacing** — a comparison where both sides changed type would still compile while comparing the wrong thing.

Pay particular attention to `core/tests/revoke_kat.rs:372` and `:517`, which feed encoder output into a KAT JSON comparison. Those must still emit byte-identical output.

- [ ] **Step 6: Run the full core suite**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core 2>&1 | tail -15
```

Expected: PASS. `golden_vault_001_pinned` in particular MUST pass — it rebuilds every vault file with today's encoder and byte-compares against the frozen fixture.

- [ ] **Step 7: Verify no format change**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && git diff main... --stat -- core/tests/data/ && echo "^^ MUST BE EMPTY"
```

- [ ] **Step 8: Gates + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings && \
  cargo clippy --release --workspace -- -D warnings && \
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -5
git add -A core
git commit -F - <<'MSG'
refactor(core): the canonical encoders return SecretBytes (#558, #565)

record::encode, block::encode_plaintext and encode_manifest now return
SecretBytes rather than Vec<u8>, and encrypt_manifest_body takes
&SecretBytes.

This turns two "the mechanism is right, nothing would notice if it were
removed" complaints into compiler checks. block.rs:1788 read
SecretBytes::new(encode_plaintext(..)?), and deleting that wrap left all
437 core lib tests green — verified during #560's review, and the whole
substance of #558. The wrapper now lives in the return type, so the
deletion does not typecheck.

re_encoded on both strict decode paths (record.rs, block.rs) is wrapped
by construction as a consequence — #565 closed by removing the
opportunity rather than by adding a wrap that a later edit could drop.
That buffer is a full re-encoding of the decrypted content and was freed
intact on every successful open.

aead::encrypt is deliberately unchanged. Its plaintext is not always
secret — core/tests/aead.rs:149 replays published RFC vectors — so
forcing &SecretBytes there would churn KATs to express something untrue
about the primitive. #558's premise that the change "may be nearly free"
because all six call sites already pass .expose() does not hold: there
are seven, and the seventh passed a bare &[u8] parameter of the public
encrypt_manifest_body. That parameter is what this commit pins instead.

No external consumer: cli, ffi, desktop/src-tauri and browser call none
of the four functions. core/tests/data/ diff is empty; golden_vault_001
byte-compare unchanged.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 4: `bundle::to_canonical_cbor` borrows instead of copying

**Files:**
- Modify: `core/src/unlock/bundle.rs:292-345` (`to_canonical_cbor`)
- Test: `core/src/unlock/bundle.rs` test module

**Interfaces:**
- Consumes: `crate::vault::canonical::{to_canonical_vec, CanonicalMap, CanonicalValue}` (all `pub(crate)`).
- Produces: `to_canonical_cbor`'s signature is unchanged **except** for Task 3's `SecretBytes` return if you sequence it after — check the current signature in the file rather than assuming.

### What is being removed

`to_canonical_cbor` currently builds 11 owned `ciborium::Value` entries. Four are cleartext copies of long-term secret keys pulled out of their `Sensitive` wrappers on **every** encode:

```rust
Value::Bytes(self.x25519_sk.expose().to_vec()),        // 32 B
Value::Bytes(self.ml_kem_768_sk.expose().clone()),     // 2400 B — the ML-KEM-768 decapsulation key
Value::Bytes(self.ed25519_sk.expose().to_vec()),       // 32 B
Value::Bytes(self.ml_dsa_65_sk.expose().clone()),      // the ML-DSA-65 seed
```

`SecretEntries` wipes them. But wiping is the **fallback** mechanism; CLAUDE.md records that *elimination is strictly stronger wherever achievable*, and here it is achievable — every value is already a borrowable `&[u8]` / `&str` / `u64`.

`SecretEntries` stays on the **decode** side (`from_canonical_cbor`), where `ciborium`'s parser owns the allocation and elimination is not available.

### The one real risk

`Value::Integer(self.created_at_ms.into())` becomes `CanonicalValue::Uint(self.created_at_ms)`. `record.rs` already ships that exact pairing for `created_at_ms`/`last_mod_ms`, so the encoding equivalence is exercised — but not yet for the bundle. `golden_vault_001_pinned` rebuilds `identity.bundle.enc`, so a divergence fails loudly. **If `core/tests/data/` shows a diff after this task, STOP** — do not regenerate the fixture; report it.

- [ ] **Step 1: Write the failing test**

```rust
/// Migrating the bundle encode path to the borrowing `CanonicalMap`
/// mirror (#569) must not move a single on-disk byte. The four secret
/// keys stop being copied out of their `Sensitive` wrappers; the wire
/// form is identical.
#[test]
fn canonical_encoding_is_unchanged_by_the_borrowing_mirror() {
    let mut rng = ChaCha20Rng::from_seed([61u8; 32]);
    let bundle = generate("residue-test", 1_700_000_000_000, &mut rng);

    let encoded = bundle.to_canonical_cbor().expect("encode");
    let round_tripped =
        IdentityBundle::from_canonical_cbor(encoded.as_slice()).expect("decode");
    let re_encoded = round_tripped.to_canonical_cbor().expect("re-encode");
    assert_eq!(
        encoded, re_encoded,
        "encode -> decode -> encode must be byte-stable"
    );

    // The map's keys must come out in RFC 8949 4.2.1 order. Rather than
    // asserting a hardcoded key name, re-derive the expected order from the
    // decoded bytes and compare: this stays correct if a key is ever added,
    // and it fails loudly if the comparator regresses.
    let Value::Map(entries) = ciborium::de::from_reader::<Value, _>(encoded.as_slice())
        .expect("parse")
    else {
        panic!("bundle CBOR must be a map");
    };
    let keys: Vec<&str> = entries
        .iter()
        .map(|(k, _)| match k {
            Value::Text(s) => s.as_str(),
            other => panic!("non-text key: {other:?}"),
        })
        .collect();
    let mut expected = keys.clone();
    expected.sort_by_key(|k| (k.len(), *k));
    assert_eq!(keys, expected, "keys must be in (byte length, bytes) order");
}
```

`generate(display_name, created_at_ms, rng)` is the real builder
(`core/src/unlock/bundle.rs:250`); the seeded-`ChaCha20Rng` idiom matches the
file's existing tests (`bundle.rs:1025` and others). `to_canonical_cbor` returns
`Vec<u8>` — **Task 3 does not change it**, only `record::encode`,
`block::encode_plaintext` and `encode_manifest`.

- [ ] **Step 2: Run to verify it fails or passes-for-the-wrong-reason**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib canonical_encoding_is_unchanged 2>&1 | tail -20
```

This test passes **before** the migration too — that is intentional. It is a **regression guard** established on the old code so the migration has something to violate. Confirm it passes now.

- [ ] **Step 3: Migrate**

Replace the `SecretEntries::new(vec![...])` construction and its `encode_map` call with:

```rust
    // Every value BORROWS. The four long-term secret keys — X25519,
    // ML-KEM-768 (2400 B), Ed25519 and ML-DSA-65 — used to be cloned out
    // of their `Sensitive` wrappers into owned `Value::Bytes` on EVERY
    // encode, then wiped by `SecretEntries::drop`. Wiping is the fallback
    // mechanism; a copy that never exists needs no wipe and cannot be
    // missed by a future caller (#569). `SecretEntries` remains on the
    // DECODE side below, where ciborium's parser owns the allocation and
    // elimination is not available.
    //
    // Push order is irrelevant: `CanonicalMap`'s `Serialize` imposes the
    // RFC 8949 4.2.1 order at serialise time.
    let mut map = CanonicalMap::with_capacity(BUNDLE_FIELD_COUNT);
    map.push(KEY_USER_UUID, CanonicalValue::Bytes(&self.user_uuid));
    map.push(KEY_DISPLAY_NAME, CanonicalValue::Text(&self.display_name));
    map.push(KEY_X25519_SK, CanonicalValue::Bytes(self.x25519_sk.expose()));
    map.push(KEY_X25519_PK, CanonicalValue::Bytes(&self.x25519_pk));
    map.push(KEY_ML_KEM_768_SK, CanonicalValue::Bytes(self.ml_kem_768_sk.expose()));
    map.push(KEY_ML_KEM_768_PK, CanonicalValue::Bytes(&self.ml_kem_768_pk));
    map.push(KEY_ED25519_SK, CanonicalValue::Bytes(self.ed25519_sk.expose()));
    map.push(KEY_ED25519_PK, CanonicalValue::Bytes(&self.ed25519_pk));
    map.push(KEY_ML_DSA_65_SK, CanonicalValue::Bytes(self.ml_dsa_65_sk.expose()));
    map.push(KEY_ML_DSA_65_PK, CanonicalValue::Bytes(&self.ml_dsa_65_pk));
    map.push(KEY_CREATED_AT, CanonicalValue::Uint(self.created_at_ms));

    Ok(to_canonical_vec(&map)?)
```

Add near the other constants:

```rust
/// Number of entries in the §5 identity-bundle CBOR map. A capacity hint
/// for `CanonicalMap::with_capacity`, not an invariant — `push` is correct
/// at any capacity.
const BUNDLE_FIELD_COUNT: usize = 11;
```

`Sensitive<[u8; N]>::expose()` returns `&[u8; N]`, which coerces to `&[u8]`. `Sensitive<Vec<u8>>::expose()` returns `&Vec<u8>`, which also coerces. If a coercion does not fire, write `&self.x.expose()[..]` rather than reaching for `.to_vec()` — a `.to_vec()` here reintroduces exactly the copy this task removes.

You will also need a `From<CanonicalError> for BundleError` impl (or an inline `map_err`) — follow whatever `record.rs` does for `RecordError`.

- [ ] **Step 4: Run the test**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core 2>&1 | tail -15
```

Expected: PASS, including `golden_vault_001_pinned`.

- [ ] **Step 5: Verify no format change — THE gate for this task**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  git diff main... --stat -- core/tests/data/ && echo "^^ MUST BE EMPTY" && \
  cargo test --release -p secretary-core golden_vault 2>&1 | tail -8
```

- [ ] **Step 6: Confirm `SecretEntries` is gone from the encode side only**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && grep -n "SecretEntries" core/src/unlock/bundle.rs
```

Expected: hits only inside `from_canonical_cbor` and its comments/tests. If `to_canonical_cbor` still references it, the migration is incomplete.

- [ ] **Step 7: Gates + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings && \
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace 2>&1 | tail -5
git add -A core
git commit -F - <<'MSG'
refactor(unlock): bundle encode borrows its secret keys instead of copying (#569)

IdentityBundle::to_canonical_cbor built 11 owned ciborium::Value entries,
four of which were cleartext copies of long-term secret keys pulled out
of their Sensitive wrappers on every encode: the X25519 secret key, the
ML-KEM-768 decapsulation key (2400 bytes), the Ed25519 secret key and the
ML-DSA-65 seed. This is the only place in the tree where four long-term
secret keys are copied out of their wrappers on a routine operation.

SecretEntries wiped them. Wiping is the fallback: CLAUDE.md records that
elimination is strictly stronger wherever achievable, and here every value
was already a borrowable &[u8] / &str / u64. A copy that never exists
needs no wipe and cannot be missed by a future caller.

SecretEntries stays on the decode side, where ciborium's parser owns the
allocation and elimination is not available.

card.rs was in #569's scope and is deliberately dropped: ContactCard holds
zero Sensitive / SecretBytes / SecretString fields — it is the artifact
handed to other users, so migrating it reduces no residue. manifest.rs's
encode tree is deferred to ride with the #564 file split rather than
widening a security diff late.

No on-disk change: core/tests/data/ diff empty, golden_vault_001_pinned
green — and that gate rebuilds identity.bundle.enc without round-tripping,
so it would catch a compensating encoder/decoder pair.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 5: `set_once` wipes its rejected duplicate (#566)

**Files:**
- Modify: `core/src/unlock/bundle.rs` (`set_once` and, if needed, its 11 call sites at `:476-540`)
- Test: `core/src/unlock/bundle.rs` test module

**Interfaces:**
- Consumes: `zeroize::Zeroize`.
- Produces: `fn set_once<T: Zeroize>(slot: &mut Option<T>, v: T, key: &'static str) -> Result<(), BundleError>`

### The gap

```rust
fn set_once<T>(slot: &mut Option<T>, v: T, key: &'static str) -> Result<(), BundleError> {
    if slot.is_some() {
        return Err(BundleError::DuplicateField(key));
    }
    *slot = Some(v);
    Ok(())
}
```

`v` has already been evaluated by the time this runs — `take_text(v)?` produced an owned `String`, `take_uuid(v)?` a `[u8; 16]`. On the duplicate path that value is dropped **unwiped**. The `Sensitive`-returning helpers (`take_sized_secret`) are already covered by their own `Drop`; it is specifically the plain `String` / `Vec<u8>` / `[u8; N]` returns that leak.

#560's review fixed every sibling arm (type-mismatch and wrong-length rejects) but not this one, because `set_once` is generic and the fix is a design choice.

**Take shape (a): a `T: Zeroize` bound.** It is the same make-it-unrepresentable instinct as Task 3, and it cannot be forgotten at a future call site. Shape (b) — wrapping each of the 11 call sites individually — leaves a new call site able to omit the wipe silently. Fall back to (b) only if some call site's `T` genuinely cannot implement `Zeroize`; if that happens, **report it rather than mixing the two shapes**.

Severity, for the commit message: post-AEAD, so the content is not attacker-chosen; reachable via a duplicate key in a forward-compat or corrupted bundle.

- [ ] **Step 1: Write the failing test**

```rust
/// A duplicate field must not drop its already-decoded value unwiped
/// (#566). `set_once`'s `v` argument is fully evaluated before the
/// duplicate check runs, so the rejected copy is live at that point.
///
/// What this pins is the WIPE CALL, not the absence of bytes: freed heap
/// is not observable from safe Rust. `Zeroize::zeroize` on the rejected
/// value is the mechanism, and the assertion below is that the duplicate
/// path is reached and rejects — the bound on `T` is what makes the wipe
/// unskippable, and that is enforced by the compiler.
#[test]
fn a_duplicate_field_is_rejected_and_its_value_wiped() {
    let mut slot: Option<String> = Some("first".to_string());
    let err = set_once(&mut slot, "second".to_string(), KEY_DISPLAY_NAME)
        .expect_err("second write must be rejected");
    assert!(matches!(err, BundleError::DuplicateField(KEY_DISPLAY_NAME)));
    assert_eq!(slot.as_deref(), Some("first"), "the first value must stand");
}

/// End-to-end: a bundle whose CBOR carries a repeated key is rejected.
#[test]
fn a_bundle_with_a_repeated_key_is_rejected() {
    let mut rng = ChaCha20Rng::from_seed([62u8; 32]);
    let bundle = generate("dup-test", 1_700_000_000_000, &mut rng);
    let encoded = bundle.to_canonical_cbor().expect("encode");

    // Parse, duplicate the first entry, re-encode. Non-canonical by
    // construction, which is fine: `set_once` must reject it BEFORE the
    // canonicality comparison, so the error must be `DuplicateField`.
    let Value::Map(mut entries) =
        ciborium::de::from_reader::<Value, _>(encoded.as_slice()).expect("parse")
    else {
        panic!("bundle CBOR must be a map");
    };
    entries.push(entries[0].clone());
    let mut doubled = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut doubled).expect("re-encode");

    let err = IdentityBundle::from_canonical_cbor(&doubled)
        .expect_err("a repeated key must be rejected");
    assert!(
        matches!(err, BundleError::DuplicateField(_)),
        "expected DuplicateField, got {err:?}"
    );
}
```

`generate(display_name, created_at_ms, rng)` is the real builder at
`core/src/unlock/bundle.rs:250`; `to_canonical_cbor` returns `Vec<u8>` (Task 3
does not change it), hence `.as_slice()`. The seeded-`ChaCha20Rng` idiom matches
the file's existing tests (`bundle.rs:1025` and others) — crypto values are
generated at runtime, never hardcoded. Do not add a new fixture builder.

- [ ] **Step 2: Run to verify**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib duplicate_field 2>&1 | tail -15
```

The first test likely passes already (the rejection works; only the wipe is missing). The second may too. That is fine — they are the regression guard for the change, exactly as in Task 4 Step 2.

- [ ] **Step 3: Add the bound and the wipe**

```rust
/// Write `v` into `slot`, rejecting a second write for the same key.
///
/// `T: Zeroize` is load-bearing, not decoration. `v` is fully evaluated by
/// the caller — `take_text(v)?` has already produced an owned `String`,
/// `take_uuid(v)?` a `[u8; 16]` — so on the duplicate path that decoded
/// copy is live and would otherwise be dropped unwiped (#566). The
/// `Sensitive`-returning helpers are covered by their own `Drop`; the
/// plain `String` / `Vec<u8>` / `[u8; N]` returns are what this closes.
///
/// The bound is on the signature rather than applied at each of the 11
/// call sites deliberately: a future call site cannot forget it.
fn set_once<T: Zeroize>(
    slot: &mut Option<T>,
    mut v: T,
    key: &'static str,
) -> Result<(), BundleError> {
    if slot.is_some() {
        v.zeroize();
        return Err(BundleError::DuplicateField(key));
    }
    *slot = Some(v);
    Ok(())
}
```

- [ ] **Step 4: Build and fix any call site whose `T` lacks `Zeroize`**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo build --release -p secretary-core 2>&1 | grep -E "^error" | head -20
```

`String`, `Vec<u8>`, `[u8; N]` and `u64` all implement `Zeroize`. `Sensitive<T>` does too. If one does not, **stop and report** — do not silently switch that call site to shape (b).

- [ ] **Step 5: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core 2>&1 | tail -10
```

- [ ] **Step 6: Gates + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings
git add -A core
git commit -F - <<'MSG'
fix(unlock): set_once wipes the duplicate value it rejects (#566)

set_once's `v` argument is fully evaluated before the duplicate check
runs — take_text(v)? has already produced an owned String, take_uuid(v)?
a [u8; 16] — so on the DuplicateField path that decoded copy was dropped
unwiped. The Sensitive-returning helpers were already covered by their
own Drop; the plain String / Vec<u8> / [u8; N] returns were not.

#560's review closed every sibling arm of this class (type-mismatch and
wrong-length rejects, and the non-string-key arm's map KEY) but left this
one, because set_once is generic and the fix was a design choice between
a T: Zeroize bound and wrapping each of the 11 call sites.

Taking the bound. It is the same make-it-unrepresentable move as the
encoder return types, and a future call site cannot forget it — whereas
per-site wrapping can be silently omitted. This slice should not close
one unpinned-mechanism complaint while opening another.

Severity unchanged from the issue: post-AEAD, so the content is not
attacker-chosen; reachable via a duplicate key in a forward-compat or
corrupted bundle.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 6: `parse_manifest_map` rejects duplicate keys (#568)

**Files:**
- Modify: `core/src/vault/manifest.rs:812` (`parse_manifest_map`), plus the `ManifestError` enum
- Test: `core/src/vault/manifest.rs` test module

**Interfaces:**
- Produces: `ManifestError::DuplicateKey { field: &'static str, index: usize }`
- **Adding a `ManifestError` variant is an exhaustive-match obligation.** Build the whole workspace, not just `secretary-core`.

### The gap

`manifest.rs` is the last of four decoders with no duplicate-key check — it silently keeps the last occurrence. The other three reject:

- `record.rs` — `seen_keys` → `RecordError::DuplicateKey { field, index }`
- `block.rs:1087-1099` — `seen_keys` → `BlockError::DuplicateKey { field, index }`
- `unlock/bundle.rs` — `set_once` → `BundleError::DuplicateField`

Silent acceptance is the wrong direction. This is defence-in-depth, not a live hole: the manifest body is covered by the hybrid signature (Ed25519 **AND** ML-DSA-65), and `decode_manifest`'s re-encode-and-compare would reject the resulting non-canonical bytes anyway. It is fixed because "the signature covers it" stops being true after an unrelated refactor.

**The payload must be data-free by construction (#474):** a `&'static str` map-level hint plus an ordinal, never the key itself. `scripts/check-error-payload-hygiene.py`'s E1 rule enforces this, and a `String` field would fail it.

- [ ] **Step 1: Write the failing test**

```rust
/// `parse_manifest_map` is the last of four decoders without a
/// duplicate-key check; the other three reject and this one silently
/// last-wins (#568). Defence in depth — the hybrid signature and the
/// canonicality re-check both already cover the body — but "the signature
/// covers it" stops being true after an unrelated refactor.
#[test]
fn a_manifest_with_a_repeated_key_is_rejected() {
    let m = populated_manifest();
    let bytes = encode_manifest(&m).expect("encode");

    // Re-parse, duplicate the first entry, re-encode. Non-canonical by
    // construction, which is fine: the duplicate check must fire BEFORE
    // the canonicality comparison, so the error must be DuplicateKey and
    // not NonCanonicalEncoding.
    // `encode_manifest` returns `SecretBytes` as of Task 3, hence `.expose()`.
    let mut entries = match ciborium::de::from_reader::<Value, _>(bytes.expose())
        .expect("parse")
    {
        Value::Map(m) => m,
        other => panic!("expected a map, got {other:?}"),
    };
    entries.push(entries[0].clone());
    let mut doubled = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut doubled).expect("re-encode");

    let err = decode_manifest(&doubled).expect_err("a repeated key must be rejected");
    assert!(
        matches!(err, ManifestError::DuplicateKey { field: "<manifest>", index: _ }),
        "expected DuplicateKey, got {err:?}"
    );
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib repeated_key 2>&1 | tail -20
```

Expected: FAIL — `no variant named 'DuplicateKey' found for enum 'ManifestError'`.

`populated_manifest()` already exists at `core/src/vault/manifest.rs:2102`
(`minimal_manifest()` at `:2087` is its smaller sibling). Do not add a new
fixture builder.

- [ ] **Step 3: Add the error variant**

In `ManifestError`, mirroring `BlockError::DuplicateKey`'s doc comment:

```rust
    /// A CBOR map key appeared more than once. RFC 8949 §5.4 leaves this
    /// to the application; every other decoder in this crate rejects, and
    /// silent last-wins is the wrong direction.
    ///
    /// Payload is data-free by construction (#474): `field` is a
    /// compile-time map-level hint, `index` the entry's ordinal. The
    /// repeated key itself is never carried — a forward-compat unknown key
    /// is attacker-influenced text, and `RecordError::DuplicateKey` once
    /// leaked exactly that class.
    #[error("duplicate CBOR map key in {field} at entry {index}")]
    DuplicateKey {
        field: &'static str,
        index: usize,
    },
```

- [ ] **Step 4: Add the check**

In `parse_manifest_map`, mirroring `block.rs:1085-1099`:

```rust
    let mut seen_keys: BTreeSet<String> = BTreeSet::new();

    for (index, (k, v)) in map.iter().enumerate() {
        let key = take_text_key(k)?;
        // RFC 8949 §5.4: reject a repeated key rather than last-wins.
        // `take_text_key` already clones, so `seen_keys` costs one further
        // String per key. These are top-level manifest keys plus
        // forward-compat unknown keys — structural, not user content;
        // `block_name` is a VALUE inside the blocks array, not a key here.
        if !seen_keys.insert(key.clone()) {
            return Err(ManifestError::DuplicateKey {
                field: "<manifest>",
                index,
            });
        }
        match key.as_str() {
```

Add `use std::collections::BTreeSet;` if not present.

- [ ] **Step 5: Run the test**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib repeated_key 2>&1 | tail -10
```

- [ ] **Step 6: Build the WHOLE workspace for exhaustive-match breakage**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo build --release --workspace --tests 2>&1 | grep -E "^error" | head -20
```

A new `ManifestError` variant can break a `match` in the FFI bridge or the desktop backend. Fix every one; do not add a catch-all `_ =>` arm to a match that was previously exhaustive.

- [ ] **Step 7: Run the payload-hygiene guard**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  uv run scripts/check-error-payload-hygiene.py --self-test && \
  uv run scripts/check-error-payload-hygiene.py
```

Expected: OK, with no new allowlist entry. If it demands one, the payload is not data-free — fix the payload, not the allowlist.

- [ ] **Step 8: Gates + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings && \
  cargo test --release --workspace 2>&1 | tail -8
git add -A core ffi desktop 2>/dev/null; git add -A
git commit -F - <<'MSG'
fix(manifest): reject duplicate CBOR map keys in parse_manifest_map (#568)

manifest.rs was the last of four decoders without a duplicate-key check,
and the only one that silently last-wins. record.rs, block.rs and
unlock/bundle.rs all reject.

Defence in depth rather than a live hole: the manifest body is covered by
the hybrid signature (Ed25519 AND ML-DSA-65), and decode_manifest's
re-encode-and-compare canonicality check would reject the resulting
non-canonical bytes anyway. Fixed because "the signature covers it" stops
being true after an unrelated refactor, and because silent acceptance is
the wrong direction for a decoder.

Payload is data-free by construction (#474): a &'static str map-level
hint plus an ordinal, never the repeated key — a forward-compat unknown
key is attacker-influenced text, and RecordError::DuplicateKey once
leaked exactly that class. Passes the payload-hygiene guard with no new
allowlist entry.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 7: Pin the key-order equivalence with a proptest (#567)

**Files:**
- Modify: `core/src/vault/canonical/value.rs` (test module only)
- Test: same file

**Interfaces:**
- Consumes: `proptest` (already `core/Cargo.toml:98`, under `[dev-dependencies]`).
- Produces: nothing consumed by another task.

### Why this matters more than a routine property test

`CanonicalMap::serialize` sorts text keys on `(key.len(), key.as_bytes())` and claims that is exactly RFC 8949 §4.2.1 order. **That claim is what lets the sort read straight through the borrowed `&str`s and materialise no key buffer** — which is the entire security point, because record field names are decrypted plaintext.

The claim has been checked twice by exhaustive sweep (184,041 pairwise comparisons in #560's PR body; 400,000 in an independent Python reproduction during its review; zero mismatches both times) and **neither sweep is committed**. Both live in prose in a handoff document. `grep -rn proptest core/src/vault/canonical core/src/cbor` returns nothing.

It also cannot be caught by the frozen-fixture anchor: every key in `golden_vault_001` is ASCII, so a byte-length → char-count regression produces byte-identical output for that vault (#562).

**The test's `enc_text` must be written locally, not reused from the production encoder** — reusing it would make the test circular.

- [ ] **Step 1: Write the failing test**

Add to `core/src/vault/canonical/value.rs`'s existing `#[cfg(test)] mod tests`:

```rust
    /// The `(byte length, bytes)` comparator `CanonicalMap::serialize`
    /// uses must be *exactly* RFC 8949 §4.2.1 order — i.e. identical to
    /// ordering on each key's full CBOR encoding.
    ///
    /// This is the property that lets the sort read straight through the
    /// borrowed `&str`s and materialise no key buffer, which is the whole
    /// security point: record field names are decrypted plaintext. If it
    /// ever breaks, the on-disk format moves silently.
    ///
    /// It has been checked twice by exhaustive sweep (184,041 pairwise
    /// comparisons; 400,000 in an independent reproduction) and neither
    /// sweep was committed — both lived in prose (#567). This makes it
    /// permanent. `golden_vault_001` cannot cover it: every key there is
    /// ASCII, so a byte-length -> char-count regression yields
    /// byte-identical output for that vault (#562).
    ///
    /// `enc_text` is written locally on purpose. Reusing the production
    /// encoder would make the test circular.
    fn enc_text(s: &str) -> Vec<u8> {
        let n = s.len();
        let mut out = Vec::with_capacity(n + 9);
        // RFC 8949 §3: major type 3 (text string) is 0b011_xxxxx.
        const MAJOR_TEXT: u8 = 0x60;
        match n {
            0..=23 => out.push(MAJOR_TEXT | n as u8),
            24..=0xFF => {
                out.push(MAJOR_TEXT | 24);
                out.push(n as u8);
            }
            0x100..=0xFFFF => {
                out.push(MAJOR_TEXT | 25);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            0x1_0000..=0xFFFF_FFFF => {
                out.push(MAJOR_TEXT | 26);
                out.extend_from_slice(&(n as u32).to_be_bytes());
            }
            _ => {
                out.push(MAJOR_TEXT | 27);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(s.as_bytes());
        out
    }

    proptest::proptest! {
        #[test]
        fn len_then_bytes_matches_full_cbor_encoding_order(a: String, b: String) {
            let by_parts = (a.len(), a.as_bytes()).cmp(&(b.len(), b.as_bytes()));
            let by_encoding = enc_text(&a).cmp(&enc_text(&b));
            proptest::prop_assert_eq!(
                by_parts,
                by_encoding,
                "comparator diverged from RFC 8949 4.2.1 for {:?} vs {:?}",
                a,
                b
            );
        }
    }

    /// `proptest`'s default `String` strategy is heavily ASCII-weighted,
    /// so the property above would rarely exercise the multi-byte case
    /// that a char-count regression breaks. Pin it explicitly.
    #[test]
    fn byte_length_not_char_count_decides_order() {
        // "日" is 1 char but 3 UTF-8 bytes; "ab" is 2 chars and 2 bytes.
        // Under (byte length, bytes) "ab" sorts first. Under a char count
        // it would not — that is the regression this pins.
        assert_eq!(
            ("ab".len(), "ab".as_bytes()).cmp(&("日".len(), "日".as_bytes())),
            std::cmp::Ordering::Less
        );
        assert_eq!(enc_text("ab").cmp(&enc_text("日")), std::cmp::Ordering::Less);
        assert!("ab".chars().count() > "日".chars().count());
    }
```

- [ ] **Step 2: Run**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && cargo test --release -p secretary-core --lib canonical::value 2>&1 | tail -15
```

Expected: PASS. This test pins existing behaviour, so a green first run is correct — Step 3 is what proves it is not vacuous.

- [ ] **Step 3: Prove the test is not vacuous (mutation check)**

Temporarily change `enc_text`'s length computation from `s.len()` to `s.chars().count()` and re-run. The proptest **must** fail. Restore it. Then temporarily change `CanonicalMap::serialize`'s comparator to use `chars().count()` and confirm `byte_length_not_char_count_decides_order` or the golden-vault test fails. Restore.

Record both mutation results in the commit message. A property test nobody has tried to break is a claim, not a pin — which is the exact defect class this task exists to close.

- [ ] **Step 4: Gates + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all && cargo clippy --release --workspace --tests -- -D warnings
git add core/src/vault/canonical/value.rs
git commit -F - <<'MSG'
test(canonical): pin the (len, bytes) == RFC 8949 4.2.1 key order (#567)

CanonicalMap::serialize sorts text keys on (key.len(), key.as_bytes())
and claims that is exactly RFC 8949 4.2.1 order. That claim is what lets
the sort read straight through the borrowed &strs and materialise no key
buffer — the whole security point, because record field names are
decrypted plaintext.

The claim had been checked twice by exhaustive sweep (184,041 pairwise
comparisons, and 400,000 in an independent reproduction, zero mismatches
both times) and NEITHER sweep was committed. Both lived in prose in a
handoff document; there were zero proptest uses under
core/src/vault/canonical or core/src/cbor.

enc_text is written locally rather than reusing the production encoder,
which would make the test circular.

The golden vault cannot cover this: every key in golden_vault_001 is
ASCII, so a byte-length -> char-count regression produces byte-identical
output for that fixture (#562). A separate explicit test pins the
multi-byte case, because proptest's default String strategy is
ASCII-weighted and would rarely reach it.

Mutation-checked in both directions: changing enc_text to chars().count()
fails the proptest, and changing the production comparator to
chars().count() fails the multi-byte test. A property test nobody has
tried to break is a claim, not a pin.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 8: Documentation

**Files:**
- Modify: `core/src/cbor/secret_tree/mod.rs` — "What this does not claim"
- Modify: `docs/manual/contributors/memory-hygiene-audit-internal.md`
- Modify: `CLAUDE.md` — memory-hygiene section
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/block.rs` — the #519 comment
- Modify: `README.md`, `ROADMAP.md` — **only if** this slice falsifies something in them

**Interfaces:** none. This task describes what shipped, so it runs last.

- [ ] **Step 1: Extend `secret_tree`'s "What this does not claim"**

Add two clauses:

```rust
//! - **The parser's scratch buffer** — `ciborium::de::from_reader` stages
//!   every payload of 4096 bytes or fewer through a `[0u8; 4096]` in its
//!   own stack frame. That is not part of the tree this type wraps, so
//!   `Drop` here never reached it. As of #561 the secret-bearing decode
//!   paths do not use `from_reader` at all — they route through
//!   `super::scratch::from_secret_reader`, which owns that buffer and
//!   wipes it. See that module's doc.
//! - **Reallocation inside the parser's visitor, which is ROUTINE above
//!   4 KiB.** This section previously named that class in one general
//!   clause; the threshold is the part a reader needs. `ciborium`'s
//!   `deserialize_byte_buf` / `deserialize_string` build the final payload
//!   with `Vec::new()` / `String::new()` plus per-chunk
//!   `extend_from_slice`, so a payload larger than
//!   [`super::CBOR_SCRATCH_LEN`] grows by doubling and frees an unwiped
//!   prefix at each step — measured at capacity 131072 grown from 0 for a
//!   100,000-byte `bstr`, roughly 14 reallocations. For an attachment, a
//!   long note or a stored key file this is the normal case, not an edge
//!   case. No public hook exists; tracked as **#570**.
```

- [ ] **Step 2: Correct the #519 comment in the uniffi wrapper**

`ffi/secretary-ffi-uniffi/src/wrappers/block.rs` currently reads *"there is no Rust-side wipe here and cannot be one — the value is lowered across the FFI by UDL-generated code this crate does not own, so there is no local to wrapper-type."* The second clause is wrong. Replace with:

```rust
    /// #519: there is no Rust-side wipe here. The reason is NOT that there
    /// is no local to wrapper-type — the bridge's `expose().to_vec()`
    /// result IS a local this crate owns. There are three copies per call,
    /// and the second is the one that cannot be reached:
    ///
    /// 1. the bridge's `to_vec()` — ours, unwiped;
    /// 2. the `RustBuffer` — `lower_into_rust_buffer`
    ///    (`uniffi_core-0.32.0/src/ffi_converter_traits.rs:265`) builds a
    ///    `Vec<u8>` and hands it to the foreign side, which frees it
    ///    through uniffi's own generated `rustbuffer_free` ->
    ///    `RustBuffer::destroy`. **We never see that free.**
    /// 3. the Swift `Data` / Kotlin `ByteArray` — the caller's documented
    ///    contract.
    ///
    /// `uniffi::custom_type!` does not help: `uniffi_macros-0.32.0/
    /// src/custom.rs:236-247` generates `<Vec<u8> as Lower>::write(
    /// lower_expr, buf)`, so a custom type must still materialise a real
    /// `Vec<u8>` first. Only a hand-authored `unsafe impl Lower` avoids
    /// copy 1 — an `unsafe trait` in a crate that sets
    /// `unsafe_code = "deny"`, requiring a hand-written duplicate of
    /// uniffi's wire format that must stay byte-exact across every uniffi
    /// upgrade. That closes 1 of 3 copies. Copy 2 needs upstream support.
```

Apply the same correction to `expose_bytes`'s "Same #519 caveat" reference if it now points at changed text.

- [ ] **Step 3: Extend the memory-hygiene memo**

In `docs/manual/contributors/memory-hygiene-audit-internal.md`, add a section for this slice covering: the six converted parse sites and the two deliberately excluded; the bundle encode migration and what it eliminates (four long-term secret keys, 2400 B of ML-KEM-768 among them); the encoder return-type change and *why it is stronger than a wrap*; and an explicit **"what this does not claim"** — the >4 KiB realloc class (#570), and the fact that a wipe of freed heap is not observable from safe Rust.

- [ ] **Step 4: Update `CLAUDE.md`**

In the memory-hygiene section, after the existing "foreign serialisation boundary" bullet, add a bullet for the pattern Task 3 established:

```markdown
- **If a function's output is *always* secret** (a canonical encoding of decrypted
  content, an AEAD body) — return the wrapper, don't ask callers to apply one.
  `record::encode` / `block::encode_plaintext` / `encode_manifest` return
  `SecretBytes`, and `encrypt_manifest_body` takes `&SecretBytes` (#558, #565).
  A `SecretBytes::new(f()?)` at a call site is deletable with the whole suite
  green — verified by execution — because the derive gives no observable
  signal. Moving the wrapper into the return type makes the deletion a compile
  error. Note the boundary: this is right where the output is *always* secret,
  and wrong for a general primitive. `aead::encrypt` deliberately still takes
  `&[u8]`, because its plaintext genuinely is not always secret — the RFC-vector
  KATs encrypt literals.
```

- [ ] **Step 5: Check `README.md` and `ROADMAP.md`**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  grep -n "residue\|zeroize\|memory hygiene\|#519\|#561" README.md ROADMAP.md
```

This slice ships no user-visible feature and completes no roadmap phase. Update **only** if a specific sentence is now false. If nothing is falsified, leave both files alone and say so in the commit message — an unnecessary edit to either is churn.

- [ ] **Step 6: Full gate run**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  cargo fmt --all -- --check && \
  cargo build --release --workspace && \
  cargo test --release --workspace && \
  cargo clippy --release --workspace --tests -- -D warnings && \
  cargo clippy --release --workspace -- -D warnings && \
  RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace && \
  uv run core/tests/python/conformance.py && \
  uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py && \
  uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py && \
  bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh && \
  bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh && \
  bash ios/scripts/check-public-log-hygiene.sh --self-test && bash ios/scripts/check-public-log-hygiene.sh && \
  bash android/scripts/check-log-hygiene.sh --self-test && bash android/scripts/check-log-hygiene.sh
```

Then the two must-be-empty diffs:

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout && \
  git diff main... --stat -- core/tests/data/ && echo "^^ MUST BE EMPTY" && \
  git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl && echo "^^ MUST BE EMPTY"
```

`cargo build --release --workspace` is listed **separately from** the test run on purpose: a `test-support`-gated leak is invisible to `cargo test` and to `cargo clippy --tests`, and only the non-test build catches it.

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/cbor-residue-closeout
git add -A
git commit -F - <<'MSG'
docs: record what the residue closeout covers, and what it does not (#570, #519)

secret_tree's "What this does not claim" section gains two clauses. The
parser scratch buffer is now addressed by #561 and cross-referenced. The
reallocation class was already named there in one general clause, but not
its THRESHOLD: ciborium's deserialize_byte_buf / deserialize_string build
payloads with Vec::new() plus per-chunk extend_from_slice, so anything
over 4 KiB grows by doubling and frees an unwiped prefix at each step —
measured at capacity 131072 grown from 0 for a 100,000-byte bstr. For an
attachment, a long note or a stored key file that is the normal case. A
reader previously could not tell.

The #519 comment in the uniffi wrapper is corrected. It justified the gap
as "there is no local to wrapper-type", which is false — the bridge's
to_vec() result is a local this crate owns. The real reason is the
RustBuffer: lower_into_rust_buffer hands it to the foreign side, which
frees it through uniffi's own generated rustbuffer_free, which we never
see. custom_type! cannot close copy 1 either; only a hand-authored
unsafe impl Lower can, in a crate that denies unsafe.

CLAUDE.md gains the "return the wrapper, don't ask callers to apply one"
pattern, WITH its boundary: right where a function's output is always
secret, wrong for a general primitive like aead::encrypt.

README.md and ROADMAP.md deliberately unchanged — no user-visible
feature, no phase completion, nothing falsified.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Post-plan: whole-branch review

After Task 8, run an independent whole-branch review before opening the PR. Specific things to check, drawn from what #560's review actually caught:

1. **Doc comments a change falsified and left standing.** The most repeated defect across that slice's 11 fix rounds. Sweep the whole diff, not just where you edited — and grep for the words *someone else* would have written, not the words you would have.
2. **Counts and enumerations.** Any "the two sites", "all six", "three copies" in a comment or commit message must be re-derived, not carried. Ruling R11 from #560: delete an enumeration rather than correct it a third time.
3. **Weak assertions.** `assert!(x > before)` where an exact count is knowable.
4. **`core/tests/data/` and `.udl` diffs empty.**
5. **Every commit carries the `Co-Authored-By` trailer** — check **per commit**, not over a range (git 2.54's `%(trailers)` never returns empty for a range).
6. **Zero auto-close keywords** in any commit body: `git log main.. --format=%B | grep -inE "(clos|fix|resolv)e[sd]? +#[0-9]+"`
