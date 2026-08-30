# Manifest split + decoder/encoder closeout — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Split `core/src/vault/manifest.rs` into a directory module, then close the four manifest-shaped residues #575 left — the last deletable `SecretBytes` wrap, the last owned-`Value` encode path, the nested duplicate-key gap, and the missing canonicality re-check.

**Architecture:** Task 1 is a pure mechanical split with zero behaviour change, so every later diff is small and readable. Tasks 2–5 then land one issue each into the split module, in dependency order: the encode side first (#571, #569p2), the decode side second (#573 then #572, because #573's precise typed errors must fire before #572's generic check). Task 6 is a one-line `.gitignore` change.

**Tech Stack:** Rust (stable, pinned 1.97.0 via `rust-toolchain.toml`), `ciborium` `=0.2.2`, `zeroize`, `thiserror`, `proptest`. Python tooling via `uv` only — never `pip`.

**Spec:** [docs/superpowers/specs/2026-08-27-manifest-closeout-design.md](../specs/2026-08-27-manifest-closeout-design.md)

## Global Constraints

- **Working directory is the worktree.** `/Users/hherb/src/secretary/.worktrees/manifest-closeout`, branch `feature/manifest-closeout`. Run `pwd && git branch --show-current` before any `cargo` / `git` command. Shell state does NOT persist between Bash tool calls — chain `cd` in the same call or use absolute paths.
- **`#![forbid(unsafe_code)]`** is set workspace-wide. Do not introduce `unsafe`.
- **Clippy must stay clean with `-D warnings`**, both with and without `--tests`.
- **The spec is normative.** `docs/vault-format.md` §4.2 defines the manifest CBOR body. If code and spec disagree, that is a bug to surface, not to silently fix on one side.
- **No on-disk format change.** `git diff main... --stat -- core/tests/data/` and `git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl` must both be EMPTY at every commit.
- **Error payloads are data-free by construction (#474).** Every `&'static str` in an error payload is a compile-time constant. Never interpolate a runtime key name, field name, or value into an error.
- **Assertions of the shape `assert!(counter > before)` are banned.** They pass on any wipe, not the one under test. Assert exact counts with a comment deriving the number. #575 found two pre-existing assertions silently made vacuous by exactly this.
- **Every new mechanism must be pinned by a test that fails when the mechanism is removed, verified by mutation.** Delete the mechanism, run the suite, confirm RED, restore. Report the mutation result in the commit body.
- **Commit trailer**, on every commit:
  ```
  Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
  ```
- **Never write `Closes #N` / `Fixes #N`.** This repo cites fixes as `(#N)`. An auto-close keyword is a plan violation.
- **`cargo` is always `--release`.** The crypto crates are unusably slow in debug.

## Gate command block

Referred to below as **THE GATES**. Run from the worktree root.

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo fmt --all -- --check
cargo build --release --workspace
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo clippy --release --workspace -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace
uv run core/tests/python/conformance.py
uv run scripts/check-error-payload-hygiene.py --self-test && uv run scripts/check-error-payload-hygiene.py
uv run scripts/check-test-support-placement.py --self-test && uv run scripts/check-test-support-placement.py
bash scripts/check-secret-slot-hygiene.sh --self-test && bash scripts/check-secret-slot-hygiene.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
git diff main... --stat -- core/tests/data/
git diff main... -- ffi/secretary-ffi-uniffi/src/secretary.udl
```

Additionally, **once per slice** (Task 7 owns this) — neither is covered by any CI job, and both broke undetected on the #575 branch:

```bash
cargo check --release --features differential-replay --tests -p secretary-core
cd core/fuzz && PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check
```

---

## File Structure

**After Task 1**, `core/src/vault/manifest.rs` no longer exists. In its place:

| File | Responsibility |
|---|---|
| `core/src/vault/manifest/mod.rs` | Module doc, `pub use` re-exports (the whole public surface), §4.2 key constants, version/length constants |
| `core/src/vault/manifest/error.rs` | `ManifestError` and nothing else |
| `core/src/vault/manifest/types.rs` | `KdfParamsRef`, `BlockEntry`, `TrashEntry`, `Manifest` |
| `core/src/vault/manifest/encode.rs` | `encode_manifest` + the private borrow/build helpers |
| `core/src/vault/manifest/decode/mod.rs` | `decode_manifest`, `parse_manifest_map` |
| `core/src/vault/manifest/decode/entries.rs` | The six nested `parse_*` fns |
| `core/src/vault/manifest/decode/extract.rs` | The nine `take_*` fns, `value_to_unknown`, `record_error_to_cbor_fault` |
| `core/src/vault/manifest/header.rs` | `ManifestHeader`, `slice_array`, `encrypt_manifest_body`, `decrypt_manifest_body` |
| `core/src/vault/manifest/file/mod.rs` | `ManifestFile`, `encode_manifest_file`, `decode_manifest_file` |
| `core/src/vault/manifest/file/sign.rs` | `signed_message_bytes`, `sign_manifest`, `verify_manifest`, `is_rollback` |

**Files modified outside the manifest module** (Tasks 2–6 only; Task 1 must touch none):

| File | Task | Change |
|---|---|---|
| `core/src/unlock/bundle.rs` | 2 | `to_canonical_cbor` returns `SecretBytes` |
| `core/src/unlock/mod.rs` | 2 | Delete the deletable wrap at the `bundle_plaintext` site |
| `.gitignore` | 6 | Negated rule for one proptest-regressions path |
| `core/src/vault/canonical/value.rs` | 6 | Comment at the test recording the exemption |
| `core/src/vault/canonical/mod.rs` | 3 | Module-doc paragraph that describes the now-removed manifest clone |
| `docs/manual/contributors/memory-hygiene-audit-internal.md` | 7 | Section for this slice |
| `CLAUDE.md`, `ROADMAP.md` | 7 | Module layout; roadmap bullet |

---

## Task 1: Split `manifest.rs` into a directory module — production code (#564)

**Files:**
- Delete: `core/src/vault/manifest.rs` (4273 lines)
- Create: `core/src/vault/manifest/mod.rs`
- Create: `core/src/vault/manifest/error.rs`
- Create: `core/src/vault/manifest/types.rs`
- Create: `core/src/vault/manifest/encode.rs`
- Create: `core/src/vault/manifest/decode/mod.rs`
- Create: `core/src/vault/manifest/decode/entries.rs`
- Create: `core/src/vault/manifest/decode/extract.rs`
- Create: `core/src/vault/manifest/header.rs`
- Create: `core/src/vault/manifest/file/mod.rs`
- Create: `core/src/vault/manifest/file/sign.rs`
- Create: `core/src/vault/manifest/tests.rs` (ALL tests, verbatim, one file — Task 2 splits them)

**Interfaces:**
- Consumes: nothing.
- Produces: the module path `crate::vault::manifest` with a public surface **byte-identical** to the pre-split one. Everything below must remain reachable at exactly the paths it is reachable at today:
  `ManifestError`, `KdfParamsRef`, `BlockEntry`, `TrashEntry`, `Manifest`, `VectorClockEntry` (re-exported from `super::block`), `MANIFEST_HEADER_LEN`, `ManifestHeader`, `ManifestFile`, `encode_manifest`, `decode_manifest`, `encrypt_manifest_body`, `decrypt_manifest_body`, `encode_manifest_file`, `decode_manifest_file`, `sign_manifest`, `verify_manifest`, `is_rollback`.

### Item inventory — exactly where each item goes

Read these off the CURRENT `core/src/vault/manifest.rs`. Line numbers are a
locator, not a contract; if they have drifted, find the item by name.

**`mod.rs`** — lines 1–126 (module doc + imports + constants) plus the
`pub use super::block::VectorClockEntry;` at line 76, plus the `mod` / `pub use`
wiring. Constants: `KEY_MANIFEST_VERSION`, `KEY_VAULT_UUID`, `KEY_FORMAT_VERSION`,
`KEY_SUITE_ID`, `KEY_OWNER_USER_UUID`, `KEY_VECTOR_CLOCK`, `KEY_BLOCKS`,
`KEY_TRASH`, `KEY_KDF_PARAMS`, `KEY_DEVICE_UUID`, `KEY_COUNTER`, `KEY_BLOCK_UUID`,
`KEY_BLOCK_NAME`, `KEY_FINGERPRINT`, `KEY_RECIPIENTS`, `KEY_VECTOR_CLOCK_SUMMARY`,
`KEY_CREATED_AT_MS`, `KEY_LAST_MOD_MS`, `KEY_TOMBSTONED_AT_MS`, `KEY_TOMBSTONED_BY`,
`KEY_PURGED_AT_MS`, `KEY_MEMORY_KIB`, `KEY_ITERATIONS`, `KEY_PARALLELISM`,
`KEY_SALT`, `UUID_LEN`, `BLOCK_FINGERPRINT_LEN`, `SALT_LEN`, `MANIFEST_VERSION_V1`,
`FORMAT_VERSION_V1`, `SUITE_ID_V1`.

**`error.rs`** — lines 127–373: the `// Errors` banner and `pub enum ManifestError`
with every doc comment intact.

**`types.rs`** — lines 374–472: `KdfParamsRef`, `BlockEntry`, `TrashEntry`, `Manifest`.

**`encode.rs`** — lines 473–806: `encode_manifest`, `manifest_to_entries`,
`vector_clock_to_value`, `blocks_to_value`, `block_entry_to_value`,
`trash_to_value`, `trash_entry_to_value`, `kdf_params_to_value`,
`unknown_value_inner`.

**`decode/mod.rs`** — lines 807–1071: `decode_manifest`, `parse_manifest_map`,
plus `mod entries; mod extract;` and any `use` the two need re-exported.

**`decode/entries.rs`** — lines 1072–1414: `parse_vector_clock`,
`parse_vector_clock_entry`, `parse_blocks`, `parse_block_entry`,
`parse_recipients`, `parse_trash`, `parse_trash_entry`, `parse_kdf_params`.

**`decode/extract.rs`** — lines 1415–1570: `take_text_key`, `take_text`,
`take_fixed_bytes`, `take_u8`, `take_u16`, `take_u32`, `take_u64`,
`take_integer_i128`, `value_to_unknown`, and `record_error_to_cbor_fault`
(currently at line 729 inside the encode section — it has two callers,
`unknown_value_inner` in `encode.rs` and `value_to_unknown` here, so it belongs
with the one that survives Task 4).

**`header.rs`** — lines 1571–1762: `MANIFEST_HEADER_LEN`, its `const _` assert,
`ManifestHeader`, `impl ManifestHeader`, `slice_array`, `encrypt_manifest_body`,
`decrypt_manifest_body`.

**`file/mod.rs`** — lines 1763–2109: the two `const _` asserts,
`IDENTITY_FINGERPRINT_LEN`, `ManifestFile`, `signed_message_bytes`,
`encode_manifest_file`, `decode_manifest_file`, plus `mod sign;`.
Note `signed_message_bytes` is used by BOTH `encode_manifest_file` and
`sign_manifest`; keep it here and make it `pub(super)`.

**`file/sign.rs`** — lines 2110–2273: `sign_manifest`, `verify_manifest`,
`is_rollback`.

**`tests.rs`** — lines 2274–4273, verbatim, wrapped so the existing
`#[cfg(test)] mod tests { ... }` block becomes the file's contents. Every
`use super::*;` inside becomes `use crate::vault::manifest::*;` plus whatever
private items the tests reach; add explicit `use` lines for those rather than
widening any item's visibility beyond what the tests need.

### Visibility rules

- An item used only within its new file stays private.
- An item used by a sibling module gets `pub(super)`, or `pub(crate)` only if a
  module outside `manifest/` needs it (check with grep before widening).
- An item that is `pub` today stays `pub` and is re-exported from `mod.rs`.
- **A blanket `pub(crate)` sweep is a task failure.** The narrowest visibility
  that compiles is the correct one.

### Steps

- [ ] **Step 1: Record the baseline test count**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib 2>&1 | tee /tmp/manifest-split-before.txt | tail -5
grep -c "^test " /tmp/manifest-split-before.txt
```

Write the exact "N passed" line into the commit body later. This number must be
identical after the split; that is the proof no test was lost in the move.

- [ ] **Step 2: Create the directory and move production code**

Create every file listed in the inventory above. Move code **verbatim** — do
not reformat, do not reword a doc comment, do not "improve" a name. The only
edits permitted are:
- `use` lines, adjusted for the new module paths.
- Visibility keywords, per the rules above.
- Intra-doc links that broke because the target moved (e.g. `[`Self::CborEncode`]`
  still resolves inside `error.rs`, but `[`decode_manifest`]` from `error.rs`
  now needs `[`crate::vault::manifest::decode_manifest`]`).

Delete `core/src/vault/manifest.rs` last, after every file is written.

- [ ] **Step 3: Compile and iterate on visibility**

```bash
cargo build --release -p secretary-core 2>&1 | head -60
```

Expected on the first run: a list of `E0603 private module` / `E0433` errors.
Fix each by widening exactly the one item named, to exactly `pub(super)` unless
an out-of-module caller proves `pub(crate)` is needed. Repeat until clean.

- [ ] **Step 4: Run the full test suite and compare counts**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib 2>&1 | tee /tmp/manifest-split-after.txt | tail -5
diff <(grep "^test " /tmp/manifest-split-before.txt | sed 's/ \.\.\..*//' | sort) \
     <(grep "^test " /tmp/manifest-split-after.txt  | sed 's/ \.\.\..*//' | sort)
```

Expected: the `diff` prints test names that changed **module path only**
(`manifest::tests::x` → `manifest::tests::x` should be identical; if the module
path changed, the names differ and you must confirm each difference is a path
change and not a disappearance). The **count** must be identical. A test that
vanished is a task failure.

- [ ] **Step 5: Prove the public surface did not move**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A && git status --short
git diff --cached --stat | grep -v "core/src/vault/manifest" || echo "CLEAN: only manifest paths touched"
```

Expected: `CLEAN: only manifest paths touched`. **Any other file in the diff
means the public surface moved and the split is not pure** — revert that file's
change and re-export from `mod.rs` instead.

- [ ] **Step 6: Check no production file exceeds 500 lines**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
find core/src/vault/manifest -name '*.rs' ! -name 'tests.rs' | xargs wc -l | sort -rn
```

Expected: every file except `tests.rs` under 500. If one is over, split it
further — do not record an exception.

- [ ] **Step 7: Run THE GATES**

All green. `cargo doc` matters here specifically: moving items breaks intra-doc
links, and the #92 gate is `-D warnings`.

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
refactor(core): split manifest.rs into a directory module (#564)

Pure mechanical move, zero behaviour change. 4273 lines -> ten production
files, none over 500, plus tests.rs carrying every test verbatim (split in
the next commit).

Proof the move is pure: the diff touches only core/src/vault/manifest*, and
the lib test count is unchanged at <N> passed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

Replace `<N>` with the number from Step 1. Do not commit until Step 5 printed
CLEAN and Step 4's counts matched.

---

## Task 2: Split the moved tests into per-module files (#564)

**Files:**
- Delete: `core/src/vault/manifest/tests.rs`
- Create: `core/src/vault/manifest/encode/tests.rs` — or `core/src/vault/manifest/encode_tests.rs`; pick ONE convention and apply it to all seven, matching whichever `core/src/cbor/secret_tree/tests.rs` uses
- Create: a test file per production module that has tests
- Modify: each production module, to add its `#[cfg(test)] mod tests;` line

**Interfaces:**
- Consumes: the module layout Task 1 produced.
- Produces: nothing new. This task changes only where test code lives.

### Placement rule

A test goes with the module holding the function it exercises. A test that
spans several modules (e.g. `sign_then_decrypt_round_trips`, which touches
`encode`, `header` and `file/sign`) goes with its **primary subject** — the
function whose behaviour would change if the test broke — and carries a
one-line comment saying which other modules it also covers.

Shared test helpers (fixture builders, `encode_canonical_map`-based
non-canonical-input constructors) go in `core/src/vault/manifest/test_support.rs`
behind `#[cfg(test)]`, imported by the test modules that need them. Do NOT
duplicate a helper into two files.

### Steps

- [ ] **Step 1: Record the baseline**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib 2>&1 | tee /tmp/manifest-tests-before.txt | tail -3
```

- [ ] **Step 2: Distribute the tests**

Move each `#[test] fn` into the file for its module, per the placement rule.
Do not edit a test's body except to fix `use` paths. Do not rename a test. Do
not delete a test you think is redundant — that is a separate decision and not
this task's.

- [ ] **Step 3: Wire the test modules**

Add `#[cfg(test)] mod tests;` to each production module that now has a sibling
test file. Add `#[cfg(test)] mod test_support;` to `mod.rs` if you created one.

- [ ] **Step 4: Run and compare**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib 2>&1 | tee /tmp/manifest-tests-after.txt | tail -3
diff <(grep -o "manifest::.*::[a-z_0-9]*" /tmp/manifest-tests-before.txt | sed 's/.*:://' | sort) \
     <(grep -o "manifest::.*::[a-z_0-9]*" /tmp/manifest-tests-after.txt  | sed 's/.*:://' | sort)
```

Expected: EMPTY diff — the same set of test *function names* exists, only their
module paths changed.

- [ ] **Step 5: Check file sizes**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
find core/src/vault/manifest -name '*.rs' | xargs wc -l | sort -rn
```

Test files may exceed 500 lines where splitting them would separate tests of
one function; if one does, say so explicitly in the commit body with the reason.
Production files must all still be under 500.

- [ ] **Step 6: Run THE GATES**

- [ ] **Step 7: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
refactor(core): distribute manifest tests to their modules (#564)

Same set of test functions, verified by name-set diff against the previous
commit; only module paths changed.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 3: `bundle::to_canonical_cbor` returns `SecretBytes` (#571)

**Files:**
- Modify: `core/src/unlock/bundle.rs` — `IdentityBundle::to_canonical_cbor` signature + doc; `from_canonical_cbor`'s re-encode check (~lines 560–600); ~13 test call sites
- Modify: `core/src/unlock/mod.rs:211` — delete the deletable wrap

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `pub fn to_canonical_cbor(&self) -> Result<SecretBytes, BundleError>` on `IdentityBundle`. `SecretBytes` is `crate::crypto::secret::SecretBytes`; read its bytes with `.expose() -> &[u8]`.

### Why this one

It is the last encoder of the #558 class in `core` still returning `Vec<u8>`,
and its output is the highest-value plaintext buffer in the crate — cleartext
CBOR of the X25519 secret key, the 2400-byte ML-KEM-768 decapsulation key, the
Ed25519 secret key and the ML-DSA-65 seed. Its production caller applies exactly
the `SecretBytes::new(f()?)` shape that is **deletable with the whole suite
green**, verified by execution in #558.

There are exactly **two** production callers of `IdentityBundle::to_canonical_cbor`:
`bundle.rs:562` and `unlock/mod.rs:211`. The other `to_canonical_cbor()` hits in
the tree are on `ContactCard` (`sync/prepare.rs`, `sync/once.rs`,
`sync/commit/write.rs`) and `UnknownValue` (`conflict.rs`) — **do not touch
those**; they are #569 path 3 and out of scope.

### The bonus this unlocks

`from_canonical_cbor`'s canonicality check currently holds `let mut canonical =
bundle.to_canonical_cbor()?;` and hand-wipes it with an explicit
`canonical.zeroize();` inside a block, carrying ~30 lines of comment justifying
the manual wipe. With a `SecretBytes` return, that manual wipe and its block
**are deleted** — `Drop` covers every exit including the `?` above it. This is
the same simplification `re_encoded` took in `record.rs` / `block.rs` under
#565. Keep the parts of the surrounding comment that explain the *other* locals
(`ml_kem_768_sk_bytes` et al.); delete only what justified the now-removed
manual `zeroize()`.

### Steps

- [ ] **Step 1: Write the failing test**

Add to `core/src/unlock/bundle.rs`'s test module:

```rust
/// The `SecretBytes` return type is what makes the wrap non-deletable
/// (#571). A `Vec<u8>` return would let a caller hold cleartext CBOR of
/// all four long-term secret keys with no wipe on drop, which is the
/// `SecretBytes::new(f()?)` shape #558 records as deletable with the
/// whole suite green.
///
/// This test does not observe the wipe — freed heap is not observable
/// from safe Rust. It pins the TYPE, which is what the compiler enforces.
#[test]
fn to_canonical_cbor_returns_a_zeroizing_wrapper() {
    let mut rng = ChaCha20Rng::from_seed([73u8; 32]);
    let bundle = generate("return-type-check", 1_700_000_000_003, &mut rng);
    let encoded: SecretBytes = bundle.to_canonical_cbor().expect("encode");
    // If the return type regressed to Vec<u8>, `.expose()` does not exist
    // and this line fails to compile.
    assert!(!encoded.expose().is_empty());
}
```

`generate(display_name, created_at_ms, &mut rng)` with a seeded
`ChaCha20Rng` is the established fixture shape in this file — see
`canonical_encoding_is_unchanged_by_the_borrowing_mirror` (`bundle.rs:1124`).
Use a seed and timestamp not already used by a neighbouring test.

- [ ] **Step 2: Run it and verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib to_canonical_cbor_returns_a_zeroizing_wrapper 2>&1 | tail -20
```

Expected: FAIL to compile — `no method named 'expose' found for struct 'Vec<u8>'`.

- [ ] **Step 3: Change the signature**

Change `to_canonical_cbor` to return `Result<SecretBytes, BundleError>`, wrapping
its `to_canonical_vec(...)` result. Rewrite the doc comment: delete the "#571,
deliberately deferred" paragraph entirely (the issue is closed by this commit)
and state the new guarantee **with its boundary** — the wrap is compile-enforced,
and the AEAD call still takes `&[u8]` via `.expose()`, exactly as
`record::encode`'s doc does.

- [ ] **Step 4: Fix the two production call sites**

`unlock/mod.rs:211` — `SecretBytes::new(identity.to_canonical_cbor()?)` becomes
`identity.to_canonical_cbor()?`. Update the surrounding comment: it currently
says "wrapped in `SecretBytes` at construction"; it should now say the wrap is
in the return type and cannot be deleted.

`bundle.rs:562` — `let canonical = bundle.to_canonical_cbor()?;` (drop `mut`),
compare with `canonical.expose() == bytes`, and delete the `{ use zeroize::Zeroize as _; ... canonical.zeroize(); }`
block. Keep the comment text about `ml_kem_768_sk_bytes` / `ml_dsa_65_sk_bytes`
and the `Sensitive` move semantics — relocate it to the struct literal it
describes.

- [ ] **Step 5: Fix the test call sites**

~13 sites in `bundle.rs`'s test module. Each is a mechanical
`.as_slice()` → `.expose()` or `&bytes[..]` → `bytes.expose()`. Do not change
what any test asserts.

- [ ] **Step 6: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib unlock:: 2>&1 | tail -10
```

Expected: PASS, including the new test.

- [ ] **Step 7: Mutation-verify**

Revert the return type to `Vec<u8>` locally. Confirm the new test fails to
compile. Restore. Record the result in the commit body.

- [ ] **Step 8: Run THE GATES**

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
refactor(core): move the SecretBytes wrap into to_canonical_cbor's return type (#571)

The last encoder of the #558 class in core still returning Vec<u8>, and the
one whose output matters most — cleartext CBOR of all four long-term secret
keys. Its caller at unlock/mod.rs:211 applied the deletable
SecretBytes::new(f()?) shape; that wrap is now compile-enforced.

from_canonical_cbor's canonicality check drops its hand-written
canonical.zeroize() block with it: Drop now covers every exit, including the
`?` above it. Same simplification re_encoded took under #565.

Mutation-verified: reverting the return type to Vec<u8> fails to compile
to_canonical_cbor_returns_a_zeroizing_wrapper.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 4: `manifest_to_entries` migrates to `CanonicalMap` (#569 path 2)

**Files:**
- Modify: `core/src/vault/manifest/encode.rs` — the whole encode path
- Modify: `core/src/vault/manifest/decode/extract.rs` — `record_error_to_cbor_fault` may lose one of its two callers; keep it (the other caller, `value_to_unknown`, remains)
- Modify: `core/src/vault/canonical/mod.rs` — the module doc paragraph describing the manifest clone this task removes
- Modify: `core/src/vault/manifest/encode/tests.rs` (or wherever Task 2 put the encode tests)

**Interfaces:**
- Consumes: the module layout from Tasks 1–2.
- Produces: `pub(crate) fn manifest_to_canonical(m: &Manifest) -> CanonicalMap<'_>` — **infallible**, returning the borrowed map rather than `Result<Vec<(Value, Value)>, ManifestError>`. `encode_manifest` keeps its signature `pub fn encode_manifest(manifest: &Manifest) -> Result<SecretBytes, ManifestError>`.

### What is wrong today

`manifest_to_entries` builds an owned `Vec<(Value, Value)>`. Every block's
`block_name` — user-authored plaintext, which `BlockEntry::block_name`'s own
doc flags as such — is copied into `Value::Text(entry.block_name.clone())` and
dropped **unwiped** on every manifest write. All four production `sign_manifest`
sites reach it. `canonical_sort_entries` then `pair.clone()`s the whole entry
list, so it is **two** clones of every block name per save.

### The template

`core/src/vault/record.rs`'s `record_to_canonical` / `field_to_canonical` is the
exact pattern. Read it before starting. `core/src/unlock/bundle.rs`'s
`to_canonical_cbor` is the second precedent (#569 path 1).

Types (`core/src/vault/canonical/value.rs`):

```rust
pub(crate) enum CanonicalValue<'a> {
    Text(&'a str),
    Bytes(&'a [u8]),
    Uint(u64),
    Bool(bool),
    Map(CanonicalMap<'a>),
    Array(Vec<CanonicalValue<'a>>),
    Borrowed(&'a Value),
}
pub(crate) struct CanonicalMap<'a>(Vec<(&'a str, CanonicalValue<'a>)>);
impl<'a> CanonicalMap<'a> {
    pub(crate) fn with_capacity(n: usize) -> Self;
    pub(crate) fn push(&mut self, key: &'a str, value: CanonicalValue<'a>);
}
pub(crate) fn to_canonical_vec(map: &CanonicalMap<'_>) -> Result<Vec<u8>, CanonicalError>;
```

`ManifestError` already has `Canonical(#[from] CanonicalError)`, so
`to_canonical_vec(...)?` converts with a bare `?`.

**Push order is irrelevant.** `CanonicalMap`'s `Serialize` imposes RFC 8949
§4.2.1 order recursively at serialise time. Do not sort keys by hand.

**Array sort disciplines are NOT irrelevant** and must be preserved exactly:
`vector_clock` and every `vector_clock_summary` ascending by `device_uuid`;
`blocks` ascending by `block_uuid`; `trash` ascending by `block_uuid`; each
block's `recipients` ascending by 16-byte bytewise compare. Sort a
`Vec<&T>` of borrows, as the current code already does — do not sort owned copies.

### `unknown_value_inner` is deleted

`UnknownValue::as_value()` is already `pub(crate)`, and `record.rs`'s encoder
already does `map.push(k, CanonicalValue::Borrowed(v.as_value()))`. Do the same
here. The current `unknown_value_inner` **encodes an unknown subtree to CBOR
and re-parses it** — an allocation, a `SecretBytes`, and a `from_secret_reader`
call per unknown per manifest write. All of that disappears. Delete the function.

### A test dies with the function

`unknown_value_inner_wipes_the_parser_scratch_buffer` (manifest test module)
exists solely to pin that `unknown_value_inner` routes through
`from_secret_reader`. Deleting the function deletes the only thing that test
can assert, so **delete the test in the same commit** and say so in the commit
body. Do not keep the function alive to keep the test green — the function's
whole cost is what this task removes. Check for any other test that names
`unknown_value_inner` before committing:

```bash
grep -rn "unknown_value_inner" core/src --include='*.rs'
```

The wipe-count assertions in the *neighbouring* scratch-buffer tests
(`decode_manifest_wipes_the_parser_scratch_buffer` and its siblings) may shift
by one, because this commit removes a `from_secret_reader` call from the encode
path. **Re-derive each expected count from the code and update the comment that
explains it** — do not just bump the number until the test passes. #575 found
two assertions silently made vacuous by exactly that kind of drift.

### The integer-equivalence obligation

`Value::Integer(x.into())` → `CanonicalValue::Uint(x)` is the one genuinely
risky substitution and must be justified per field by its declared type, not by
a green test. The affected fields and their types:

| Field | Type | Conversion |
|---|---|---|
| `manifest_version` | `u8` | `CanonicalValue::Uint(u64::from(m.manifest_version))` |
| `format_version` | `u16` | `CanonicalValue::Uint(u64::from(m.format_version))` |
| `suite_id` (manifest and block entry) | `u16` | `CanonicalValue::Uint(u64::from(x))` |
| `counter` | `u64` | `CanonicalValue::Uint(e.counter)` |
| `created_at_ms`, `last_mod_ms` | `u64` | `CanonicalValue::Uint(x)` |
| `tombstoned_at_ms` | `u64` | `CanonicalValue::Uint(x)` |
| `purged_at_ms` | `Option<u64>` | conditional push, `Uint` inside |
| `memory_kib`, `iterations`, `parallelism` | `u32` | `CanonicalValue::Uint(u64::from(x))` |

Every one is unsigned and fits `u64`, so `ciborium`'s big-num arms are
structurally unreachable and equivalence holds over the whole domain. State this
in a comment at the encode entry point, citing the declared types.

**Preserve `Option` semantics exactly.** `TrashEntry::fingerprint` and
`TrashEntry::purged_at_ms` are `Option`; read the current
`trash_entry_to_value` to see whether `None` is absent-on-the-wire or emitted
as something, and reproduce that behaviour. `trash_entry_purged_at_ms_none_roundtrips_byte_identical`
is the existing test that pins it.

### Steps

- [ ] **Step 1: Write the failing test — the ELIMINATION property**

`golden_vault_001_pinned` already backstops output bytes, and would stay green
against a reverted owned-`Value` body. #575's equivalent task shipped its
elimination property pinned by nothing and the review caught it. Pin it here:

```rust
/// #569 path 2: the manifest encode path must BORROW every plaintext
/// value, not copy it. `block_name` is user-authored plaintext inside the
/// encrypted manifest; the pre-#569 path cloned it into an owned
/// `Value::Text` and again inside `canonical_sort_entries`, two unwiped
/// copies per manifest save.
///
/// This pins the borrow structurally: the returned `CanonicalMap` holds a
/// `&str` INTO the `Manifest`, so it cannot outlive it. A body that built
/// owned `Value`s could not satisfy this signature — reverting to one
/// fails to compile, which is the strongest form this property can take.
#[test]
fn manifest_encode_borrows_block_name_rather_than_cloning_it() {
    let m = populated_manifest();
    let canonical = manifest_to_canonical(&m);
    let encoded = to_canonical_vec(&canonical).expect("encode");
    // The block name's bytes must appear in the output...
    let name_bytes = m.blocks[0].block_name.as_bytes();
    assert!(
        encoded.windows(name_bytes.len()).any(|w| w == name_bytes),
        "block_name must reach the wire"
    );
    // ...and the map must borrow from `m`, which this line proves by
    // construction: `canonical` is still alive and `m` is still borrowed.
    assert_eq!(m.blocks[0].block_name.as_bytes(), name_bytes);
}
```

`populated_manifest()` is the existing fixture builder in the manifest test
module (alongside `minimal_manifest()` and `dummy_kdf_params()`). Task 2 moved
it into `test_support.rs`; import it from there.

- [ ] **Step 2: Run it and verify it fails**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib manifest_encode_borrows_block_name 2>&1 | tail -20
```

Expected: FAIL to compile — `manifest_to_canonical` does not exist.

- [ ] **Step 3: Migrate the encode path**

Rewrite `manifest_to_entries` as `manifest_to_canonical(m: &Manifest) -> CanonicalMap<'_>`
and each `*_to_value` helper as a `CanonicalValue<'_>`-returning borrow builder.
Every one becomes **infallible** once `unknown_value_inner` and
`canonical_sort_entries` are gone — drop the `Result` from each helper's return
type. `encode_manifest` becomes:

```rust
pub fn encode_manifest(manifest: &Manifest) -> Result<SecretBytes, ManifestError> {
    Ok(SecretBytes::new(to_canonical_vec(&manifest_to_canonical(
        manifest,
    ))?))
}
```

Delete `unknown_value_inner`. Remove `canonical_sort_entries` and
`encode_canonical_map` from `encode.rs`'s imports if nothing there still uses
them — the test module still does, so keep the import there.

- [ ] **Step 4: Run the full core suite**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core 2>&1 | tail -15
```

Expected: PASS, including `golden_vault_001_pinned`,
`roundtrip_populated_manifest`, `forward_compat_unknown_top_level_key_round_trips`
and `trash_entry_purged_at_ms_none_roundtrips_byte_identical`. **A byte
difference in any of these means the migration changed the on-disk format** —
stop and find out why rather than regenerating a fixture.

- [ ] **Step 5: Prove the format did not move**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git diff main... --stat -- core/tests/data/ && echo "EMPTY = correct"
uv run core/tests/python/conformance.py
```

- [ ] **Step 6: Update `canonical/mod.rs`'s module doc**

Its doc currently says `canonical_sort_entries` "still `pair.clone()`s every
entry" and names `block_entry_to_value`'s `block_name` as a live clone
"deliberately left unmigrated by this slice's own scope decision". That is now
false. Correct it in place, recording what changed rather than deleting the
history — and re-check whether `canonical_sort_entries` has any production
caller left; if it does not, say so precisely rather than claiming it is dead.

- [ ] **Step 7: Mutation-verify**

Revert `manifest_to_canonical` to an owned-`Value` body locally. Confirm the new
test fails (to compile). Restore. Record in the commit body.

- [ ] **Step 8: Run THE GATES**

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
refactor(core): the manifest encode path borrows instead of copying (#569)

Path 2 of #569. Every block_name — user-authored plaintext inside the
encrypted manifest — was cloned into an owned Value::Text and cloned again by
canonical_sort_entries, two unwiped copies per manifest save, on a path all
four production sign_manifest sites reach.

unknown_value_inner is deleted outright rather than migrated: it encoded an
unknown subtree to CBOR and re-parsed it, costing an allocation, a SecretBytes
and a from_secret_reader call per unknown per write. UnknownValue::as_value is
already pub(crate) and record.rs's encoder already borrows through it.

Every *_to_value helper is now infallible; the Result came only from the two
constructs this commit removes.

core/tests/data/ diff EMPTY — no format change. Mutation-verified: an
owned-Value body fails to compile against the borrowing signature.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 5: Nested duplicate-key rejection (#573)

**Files:**
- Modify: `core/src/vault/manifest/decode/entries.rs` — `parse_vector_clock_entry`, `parse_block_entry`, `parse_trash_entry`, `parse_kdf_params`
- Modify: `core/src/vault/manifest/error.rs` — `ManifestError::DuplicateKey`'s doc, which currently says the nested parsers "still silently last-win"
- Modify: `core/src/vault/manifest/decode/mod.rs` — `decode_manifest`'s doc item 11, which currently scopes the check to one level
- Modify: the decode test file from Task 2

**Interfaces:**
- Consumes: the module layout from Tasks 1–2.
- Produces: no new signature. `ManifestError::DuplicateKey { field: &'static str, index: usize }` already exists — **do not add a variant.**

### The pattern to copy

`parse_manifest_map` in `decode/mod.rs` already does this at the top level. Copy
its shape exactly:

```rust
for (index, (k, val)) in entries.iter().enumerate() {
    let key = take_text_key(k)?;
    match key.as_str() {
        KEY_DEVICE_UUID => {
            if device_uuid.is_some() {
                return Err(ManifestError::DuplicateKey {
                    field: KEY_DEVICE_UUID,
                    index,
                });
            }
            device_uuid = Some(take_fixed_bytes::<UUID_LEN>(val, KEY_DEVICE_UUID)?);
        }
        // ... one arm per key, written out
    }
}
```

**Write each check out longhand — do not factor it into a macro or a helper.**
`parse_manifest_map` carries a comment explaining why: every hygiene guard in
this repo reads TEXT, not expanded macros, so an error construction inside a
macro body is invisible to any future rule that inspects one. Nine repetitions
were judged a cheap price there; the same reasoning applies here.

### `field` names the specific nested key

Not the container. A repeated `device_uuid` inside a `vector_clock` entry gives
`field: KEY_DEVICE_UUID`, not `field: KEY_VECTOR_CLOCK`. It is a compile-time
`KEY_*` constant either way, so #474's data-free-by-construction guarantee holds
identically, and the diagnostic is strictly more useful.

A repeated **forward-compat unknown** key gets the literal `"<unknown>"`,
matching `parse_manifest_map`. The repeated key's own text is
attacker-influenced content from inside the encrypted manifest and must never
reach an error payload.

### Per-parser detail

| Parser | Keys needing a check | Unknown bag? |
|---|---|---|
| `parse_vector_clock_entry` | `device_uuid`, `counter` | No — already rejects unknown keys with `WrongType` |
| `parse_kdf_params` | `memory_kib`, `iterations`, `parallelism`, `salt` | No — already rejects unknown keys with `WrongType` |
| `parse_block_entry` | `block_uuid`, `block_name`, `fingerprint`, `recipients`, `vector_clock_summary`, `suite_id`, `created_at_ms`, `last_mod_ms` | **Yes** — a repeated unknown key must give `field: "<unknown>"` |
| `parse_trash_entry` | `block_uuid`, `tombstoned_at_ms`, `tombstoned_by`, `fingerprint`, `purged_at_ms` | **Yes** — same |

The two parsers with no unknown bag already reject anything not in their fixed
key set, so a duplicate of a **known** key is their only silent case.

For the two with unknown bags, detect a repeated unknown key with the
`BTreeMap::insert` return value (`if unknown.insert(key, ..).is_some() { .. }`)
or an explicit `contains_key` check — either is fine; read what
`parse_manifest_map` does and match it.

### Steps

- [ ] **Step 1: Write the failing tests**

One per parser per class. Twelve tests minimum: eight for `parse_block_entry`'s
and `parse_trash_entry`'s known keys is impractical to enumerate exhaustively in
one test each, so use a table-driven test per parser plus one unknown-key test
for the two with bags. Write the table-driven form like this:

```rust
/// #573: every nested manifest map rejects a repeated key. The top level
/// has done this since #568; these four had no check at all and silently
/// last-won.
///
/// `field` names the SPECIFIC repeated key, not the container — a
/// compile-time `KEY_*` constant either way, so the #474 data-free
/// guarantee is unchanged.
#[test]
fn vector_clock_entry_rejects_every_duplicate_key() {
    for repeated in [KEY_DEVICE_UUID, KEY_COUNTER] {
        let v = vector_clock_entry_value_with_duplicate(repeated);
        match parse_vector_clock_entry(&v) {
            Err(ManifestError::DuplicateKey { field, .. }) => assert_eq!(
                field, repeated,
                "DuplicateKey must name the key that was actually repeated"
            ),
            other => panic!("expected DuplicateKey for {repeated}, got {other:?}"),
        }
    }
}
```

`vector_clock_entry_value_with_duplicate` builds a `Value::Map` with the named
key present twice. Three top-level equivalents already exist —
`rejects_duplicate_device_uuid_in_vector_clock`, `rejects_duplicate_block_uuid`
and `rejects_duplicate_trash_uuid`, all built on
`build_manifest_map_with_overrides` — read them and mirror the shape rather
than inventing a new builder.

Also write, for `parse_block_entry` and `parse_trash_entry`:

```rust
/// A repeated forward-compat UNKNOWN key must be rejected with the
/// literal "<unknown>". The repeated key's own text is
/// attacker-influenced content from inside the encrypted manifest and
/// must never reach an error payload (#474).
#[test]
fn block_entry_rejects_duplicate_unknown_key_without_naming_it() {
    let v = block_entry_value_with_duplicate_unknown("v2_extension_field");
    let err = parse_block_entry(&v).expect_err("must reject");
    match &err {
        ManifestError::DuplicateKey { field, .. } => assert_eq!(*field, "<unknown>"),
        other => panic!("expected DuplicateKey, got {other:?}"),
    }
    assert!(
        !format!("{err}").contains("v2_extension_field"),
        "the repeated key's text must never reach the error payload"
    );
}
```

- [ ] **Step 2: Run them and verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib duplicate 2>&1 | tail -30
```

Expected: the new tests FAIL — the parsers currently last-win, so
`parse_*` returns `Ok`.

- [ ] **Step 3: Add the checks**

Longhand, per the pattern above, in all four parsers.

- [ ] **Step 4: Run the tests**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core 2>&1 | tail -10
```

Expected: PASS, including every pre-existing manifest test — a legitimate
manifest has no duplicate keys, so nothing valid may start failing.

- [ ] **Step 5: Correct the two doc comments that now overclaim in reverse**

`ManifestError::DuplicateKey`'s doc says the four nested parsers "still silently
last-win"; `decode_manifest`'s doc item 11 says the check is "scoped to this one
level only". Both are now false. Rewrite them to state what IS still true:

> Neither this check nor the record-level re-encode comparison looks inside a
> forward-compat `unknown` subtree. Those round-trip verbatim, so a duplicate
> key inside one is invisible to both. `UnknownValue`'s only validation is
> `reject_floats_and_tags`.

**Do not let "manifest duplicate keys are handled" stand anywhere in the tree.**
That residual is real and is the single most repeated review finding on the
predecessor slice — documentation claiming more coverage than the code delivers.

- [ ] **Step 6: Mutation-verify**

Delete one parser's duplicate check. Confirm its test fails. Restore. Repeat for
each of the four. Record all four results in the commit body.

- [ ] **Step 7: Run THE GATES**

The error-payload hygiene guard matters here specifically — it is the rule that
would catch a runtime key name reaching a payload.

- [ ] **Step 8: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
fix(core): reject duplicate keys in the four nested manifest parsers (#573)

parse_vector_clock_entry, parse_block_entry, parse_trash_entry and
parse_kdf_params silently last-won on a repeated key; only the top level
checked (#568). No new error variant — ManifestError::DuplicateKey already
exists and is data-free by construction.

`field` names the specific repeated key rather than the container: a
compile-time KEY_* constant either way, so #474's guarantee is unchanged. A
repeated forward-compat unknown key gets the literal "<unknown>"; its own text
never reaches a payload, asserted rather than assumed.

The residual is stated rather than implied: a duplicate INSIDE a forward-compat
unknown subtree round-trips verbatim and is invisible to this check and to the
re-encode comparison alike. Two doc comments that described the old scope are
corrected.

Mutation-verified: deleting each of the four checks individually reds its own
test.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 6: Canonicality re-check in `decode_manifest` (#572)

**Files:**
- Modify: `core/src/vault/manifest/decode/mod.rs` — `decode_manifest`
- Modify: `core/src/vault/manifest/error.rs` — new `NonCanonicalEncoding` variant
- Modify: the decode test file from Task 2

**Interfaces:**
- Consumes: `encode_manifest(&Manifest) -> Result<SecretBytes, ManifestError>` (unchanged by Task 4), and Task 5's duplicate checks.
- Produces: `ManifestError::NonCanonicalEncoding` — a **unit variant**, spelled to match `RecordError::NonCanonicalEncoding` and `BlockError::NonCanonicalEncoding`.

### Why this exists

`record::decode` (`record.rs:684`) and `block::decode_plaintext` (`block.rs:1075`)
each re-encode the parsed struct and compare against the input. `decode_manifest`
has no such check. #575's design spec asserted that it did; the claim travelled
spec → plan → task brief unchecked and was caught only when an implementer read
the code. It is filed as #572 for that reason.

### The forward-compatibility hazard, and why it does not bite

A strict re-encode-and-compare rejects any manifest the decoder cannot reproduce
exactly. That would be a forward-compatibility regression if any **accepted**
manifest were lossily decoded. It is not, and this was verified by reading all
four nested parsers before the spec was written:

- `parse_vector_clock_entry` and `parse_kdf_params` **reject** unknown keys with
  `WrongType`. Nothing is silently dropped.
- `Manifest`, `BlockEntry` and `TrashEntry` each carry an
  `unknown: BTreeMap<String, UnknownValue>` that round-trips verbatim.

If you find a counterexample — a manifest that decodes but does not re-encode
byte-identically — **that is a decoder bug to surface, not a reason to weaken
the check.** Stop and report it.

### Ordering against Task 5

Task 5's checks run during parse; this one runs after. So a nested duplicate
yields the precise `DuplicateKey`, not the generic `NonCanonicalEncoding`. That
ordering is a real property and must be pinned — without a test, a later edit
that moved the re-encode earlier would coarsen every nested duplicate diagnostic
with the suite green.

### The residual

This check does **not** catch a duplicate key inside a forward-compat `unknown`
subtree: those round-trip verbatim, so the re-encode compares equal. State that
at the check site.

### Steps

- [ ] **Step 1: Write the failing tests**

```rust
/// #572: decode_manifest must re-encode the parsed struct and compare,
/// exactly as record::decode and block::decode_plaintext do. Without it,
/// the hybrid signature is the ONLY decoder-level defence against a
/// non-canonical manifest body — there is no second check.
#[test]
fn decode_manifest_rejects_a_non_canonical_body() {
    // Build a valid manifest, encode it, then re-serialise its top-level
    // map with the keys in the WRONG order. Every field is still present
    // and well-typed, so only the canonicality check can reject it.
    let m = populated_manifest();
    let canonical = encode_manifest(&m).expect("encode");
    let scrambled = reorder_top_level_keys(canonical.expose());
    assert!(
        scrambled != canonical.expose(),
        "the fixture must actually differ, or this test is vacuous"
    );
    match decode_manifest(&scrambled) {
        Err(ManifestError::NonCanonicalEncoding) => {}
        other => panic!("expected NonCanonicalEncoding, got {other:?}"),
    }
}

/// Task 5's precise duplicate-key errors must fire BEFORE this check, or
/// every nested duplicate diagnostic silently coarsens to the generic
/// NonCanonicalEncoding. A later edit moving the re-encode earlier would
/// do exactly that with the rest of the suite green.
#[test]
fn duplicate_key_wins_over_non_canonical_encoding() {
    let bytes = manifest_bytes_with_duplicate_nested_key();
    match decode_manifest(&bytes) {
        Err(ManifestError::DuplicateKey { .. }) => {}
        other => panic!("DuplicateKey must precede NonCanonicalEncoding, got {other:?}"),
    }
}

/// The check must reject nothing that is valid today. A v2 manifest
/// carrying unknown keys at all three levels that have an `unknown` bag
/// must still decode — this is the forward-compatibility hazard the
/// design checked against all four nested parsers.
#[test]
fn forward_compat_unknown_keys_survive_the_canonicality_check() {
    let bytes = manifest_bytes_with_unknowns_at_top_level_block_and_trash();
    let m = decode_manifest(&bytes).expect("a forward-compat manifest must still decode");
    assert!(!m.unknown.is_empty(), "top-level unknown preserved");
    assert!(!m.blocks[0].unknown.is_empty(), "block-entry unknown preserved");
    assert!(!m.trash[0].unknown.is_empty(), "trash-entry unknown preserved");
}
```

Build the fixture helpers from `build_manifest_map_with_overrides` and
`parse_to_value_map`, the existing constructors in the manifest test module
that #568's `rejects_duplicate_device_uuid_in_vector_clock` /
`rejects_duplicate_block_uuid` / `rejects_duplicate_trash_uuid` already use.
Read those three tests first; do not hand-write CBOR bytes.

- [ ] **Step 2: Run them and verify they fail**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core --lib non_canonical 2>&1 | tail -30
```

Expected: FAIL to compile — `ManifestError::NonCanonicalEncoding` does not exist.

- [ ] **Step 3: Add the variant**

In `error.rs`, matching `RecordError`'s spelling and doc shape:

```rust
/// The input was not canonical CBOR: re-encoding the parsed manifest did
/// not reproduce the input bytes. Same check `record::decode` and
/// `block::decode_plaintext` apply (#572).
#[error("manifest body is not canonical CBOR")]
NonCanonicalEncoding,
```

The enum is deliberately **not** `#[non_exhaustive]`, so this is a real
compiler-checked surface change. `cargo build --release --workspace` in Step 6
is what confirms it costs nothing downstream.

- [ ] **Step 4: Add the check**

At the end of `decode_manifest`, after `parse_manifest_map` returns:

```rust
    let manifest = parse_manifest_map(entries)?;

    // Re-encode and compare, exactly as `record::decode` and
    // `block::decode_plaintext` do (#572). `encode_manifest` returns
    // `SecretBytes`, so this buffer is wrapped BY CONSTRUCTION — there is
    // no separate `SecretBytes::new` call here for a future edit to drop
    // (#558, #565).
    //
    // What this does NOT catch: a duplicate key inside a forward-compat
    // `unknown` subtree. Those round-trip verbatim, so the comparison is
    // equal. `UnknownValue`'s only validation is `reject_floats_and_tags`,
    // and no decoder in the crate walks inside one (#573's residual).
    let re_encoded = encode_manifest(&manifest)?;
    if re_encoded.expose() != bytes {
        return Err(ManifestError::NonCanonicalEncoding);
    }

    Ok(manifest)
```

Note the borrow ordering: `parse_manifest_map(entries)` borrows from `parsed`,
so `parsed` must still be alive. It is — it lives to the end of the function.

- [ ] **Step 5: Run the full suite**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release -p secretary-core 2>&1 | tail -15
cargo test --release --workspace 2>&1 | tail -15
```

Expected: PASS. Every existing manifest round-trip test, `golden_vault_001_pinned`,
and every orchestrator test that opens a real vault must stay green. **If a
pre-existing test starts failing with `NonCanonicalEncoding`, you have found a
manifest the decoder accepts but cannot reproduce — report it, do not weaken
the check.**

- [ ] **Step 6: Confirm the new variant costs nothing downstream**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo build --release --workspace 2>&1 | tail -20
```

If a bridge or binding fold now fails to compile exhaustively, add the arm there
in this same commit — a half-added variant is not shippable.

- [ ] **Step 7: Mutation-verify**

Delete the `if re_encoded.expose() != bytes` block. Confirm
`decode_manifest_rejects_a_non_canonical_body` fails. Restore. Then move the
re-encode to BEFORE `parse_manifest_map` and confirm
`duplicate_key_wins_over_non_canonical_encoding` fails. Restore. Record both in
the commit body.

- [ ] **Step 8: Run THE GATES**

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
fix(core): decode_manifest re-encodes and compares (#572)

record::decode and block::decode_plaintext have done this since the format
was frozen; decode_manifest never did. #575's design spec asserted otherwise
and the claim travelled spec -> plan -> task brief unchecked, which is why
this is a separate issue rather than a line in that slice.

The forward-compatibility hazard was checked against all four nested parsers
before the change: parse_vector_clock_entry and parse_kdf_params REJECT
unknown keys, and Manifest / BlockEntry / TrashEntry each carry an unknown
bag, so every manifest the decoder accepts is fully representable. A test
pins that a v2 manifest with unknowns at all three levels still decodes.

#573's precise DuplicateKey errors fire before this generic check; a test
pins that ordering, because a later edit moving the re-encode earlier would
coarsen every nested duplicate diagnostic with the suite green.

Does not catch a duplicate inside a forward-compat unknown subtree — those
round-trip verbatim. Stated at the check site.

Mutation-verified both ways: deleting the check reds the rejection test,
moving it before the parse reds the ordering test.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 7: Persist the key-order proptest's counterexamples (#577)

**Files:**
- Modify: `.gitignore` (lines 138–147)
- Modify: `core/src/vault/canonical/value.rs` — a comment at `len_then_bytes_matches_full_cbor_encoding_order`

**Interfaces:**
- Consumes: nothing.
- Produces: nothing. This task changes only which files git tracks.

### Why this one proptest is different

`len_then_bytes_matches_full_cbor_encoding_order` guards `CanonicalMap::serialize`'s
`(byte length, bytes)` key comparator, which must equal RFC 8949 §4.2.1 order.
That is a **format-freezing** property: if it breaks, the on-disk layout of every
record, block and manifest moves silently, and v1 is frozen precisely because
vaults written today must stay readable by clients written decades from now.

It also has the thinnest frozen-anchor coverage in the crate. Verified by
execution during the #575 review: mutating the comparator to `chars().count()`
left `golden_vault_001`, `golden_vault_002`, `conformance_kat` and `revoke_kat`
**all passing**, because every key in those fixtures is ASCII (that blindness is
#562). So a CI failure here currently yields a message and no reproducible seed,
on the one property where reproducing the counterexample matters most — and the
generated input is a `String`, so "just try again" may not re-find it.

Not committing regression files is a deliberate, long-standing project choice.
This task does not argue with it in general — it carves out exactly one path.

### Steps

- [ ] **Step 1: Find out where proptest actually writes, by execution**

Do **not** trust the path the `.gitignore` comment names. Break the comparator
deliberately, run the test, and look:

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
# Temporarily mutate the comparator in core/src/vault/canonical/value.rs
# from byte-length ordering to `chars().count()` ordering.
cargo test --release -p secretary-core --lib len_then_bytes_matches_full_cbor_encoding_order 2>&1 | tail -20
find . -name '*proptest-regressions*' -newermt '-5 minutes' -not -path './target/*'
```

Record the exact path printed. **Then restore the comparator** — do not commit
the mutation. Re-run the test and confirm it passes again before continuing.

- [ ] **Step 2: Add the negated rule**

Append to the existing proptest block in `.gitignore`, using the path Step 1
actually produced:

```
# #577: one exception. `len_then_bytes_matches_full_cbor_encoding_order`
# guards CanonicalMap::serialize's (byte length, bytes) key comparator
# against RFC 8949 §4.2.1. That is a FORMAT-FREEZING property — if it
# breaks, the on-disk layout of every record, block and manifest moves
# silently — and it is the property with the thinnest frozen-anchor
# coverage: mutating the comparator to chars().count() leaves
# golden_vault_001/002, conformance_kat and revoke_kat all green, because
# every key in those fixtures is ASCII (#562). A counterexample here is
# worth committing; the general policy above is unchanged.
!<EXACT PATH FROM STEP 1>
```

Note the git rule this depends on: **a negation cannot re-include a file if a
parent directory is excluded.** `**/proptest-regressions/` excludes the
directory itself, so the negation must un-exclude the directory too, or be
written against a pattern that does not exclude the parent. Verify in Step 3;
if the naive negation does not work, restructure the two existing patterns
rather than adding a third.

- [ ] **Step 3: Verify by execution, not by reading**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
mkdir -p "$(dirname <EXACT PATH FROM STEP 1>)" && touch <EXACT PATH FROM STEP 1>
git check-ignore -v <EXACT PATH FROM STEP 1>; echo "exit=$?"
git status --short | grep proptest
```

Expected: `git check-ignore` exits **1** (not ignored) for this path, and
`git status` shows it as untracked. Then confirm no OTHER proptest path became
un-ignored:

```bash
touch core/proptest-regressions/some/other/module.txt 2>/dev/null || \
  (mkdir -p core/proptest-regressions/some/other && touch core/proptest-regressions/some/other/module.txt)
git check-ignore -v core/proptest-regressions/some/other/module.txt; echo "exit=$? (0 means still ignored — correct)"
rm -rf core/proptest-regressions/some
```

Clean up the probe file from the real path too.

- [ ] **Step 4: Record the reasoning at the test**

Add to `len_then_bytes_matches_full_cbor_encoding_order`'s doc comment:

```rust
/// Counterexamples from this test ARE committed — the one exception to
/// the project's "do not commit proptest regressions" policy, carved out
/// in `.gitignore` (#577). The reason is the paragraph above: this is a
/// format-freezing property whose only other anchors are ASCII-only
/// fixtures (#562), so a CI failure here must yield a replayable seed
/// rather than a message.
```

- [ ] **Step 5: Run THE GATES**

- [ ] **Step 6: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
chore: commit counterexamples for the key-order proptest only (#577)

One carve-out from the project's "do not commit proptest regressions" policy.
len_then_bytes_matches_full_cbor_encoding_order guards CanonicalMap::serialize's
(byte length, bytes) comparator against RFC 8949 §4.2.1 — a format-freezing
property whose only other anchors are ASCII-only fixtures, so a chars().count()
regression leaves golden_vault_001/002, conformance_kat and revoke_kat all green
(#562). A CI failure there must yield a replayable seed, not just a message.

Path verified by execution: the comparator was deliberately broken to observe
where proptest actually writes, and git check-ignore confirms the negation
applies to that path and to no other.

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Task 8: Documentation, slice-level gates, and the handoff

**Files:**
- Modify: `docs/manual/contributors/memory-hygiene-audit-internal.md`
- Modify: `CLAUDE.md`
- Modify: `ROADMAP.md`
- Modify: `README.md` — **only if** something user-visible changed
- Create: `docs/handoffs/2026-08-27-manifest-closeout-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget the symlink)

**Interfaces:**
- Consumes: every preceding task.
- Produces: the baton.

### Steps

- [ ] **Step 1: Run the two gates no CI job covers**

Both broke undetected on the #575 branch because its sweep was scoped to
`--workspace`. `core/fuzz` is `exclude`d from the workspace and
`differential_replay.rs` is feature-gated, so `clippy --tests` builds neither.

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo check --release --features differential-replay --tests -p secretary-core 2>&1 | tail -20
```

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout/core/fuzz && \
  PATH="$HOME/.rustup/toolchains/nightly-2026-04-29-aarch64-apple-darwin/bin:$PATH" cargo check 2>&1 | tail -20
```

Fix anything that broke. Both must be clean.

- [ ] **Step 2: Run the differential-replay suite itself**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
cargo test --release --workspace --features differential-replay 2>&1 | tail -15
```

- [ ] **Step 3: Extend the memory-hygiene memo**

Add a section for this slice covering Tasks 3 and 4 (#571, #569 path 2). It must
include an explicit **"what this does not claim"** paragraph. The two claims to
bound precisely:

- Task 3 pins a TYPE, not a wipe. Freed heap is not observable from safe Rust;
  the guarantee is that the wrap cannot be deleted without a compile error.
- Task 4 ELIMINATES a copy rather than wiping one, which is strictly stronger —
  but it does not touch the `String` that `take_text` clones out of the borrowed
  tree into `BlockEntry::block_name` on the DECODE side. That destination is a
  plain, non-zeroizing `String` and remains so.

Also re-check the memo's existing rows against the code before committing.
#575's review found a row whose line number had been refreshed without
re-verifying the fact it stated, so a stale claim read as freshly confirmed. **Do
not refresh a line number without re-reading what it points at.**

- [ ] **Step 4: Update `CLAUDE.md`**

- The `core/src/vault/manifest/` layout replaces the single-file entry.
- The `unknown`-subtree duplicate-key residual, stated once, precisely.
- If `canonical_sort_entries` lost its last production caller in Task 4, say so
  and say what still calls it (tests do).

- [ ] **Step 5: Update `ROADMAP.md`**

The memory-hygiene bullet records this slice.

- [ ] **Step 6: Decide on `README.md` deliberately**

Nothing in this slice is user-visible. **Unchanged is the correct outcome, not
an omission** — but check rather than assume: grep `README.md` for any sentence
this slice falsified (file counts, module names, issue references). If one
exists, fix that sentence and nothing else.

- [ ] **Step 7: Verify every commit carries the trailer, PER COMMIT**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
for sha in $(git rev-list main..HEAD); do
  git log -1 --format='%H %s' "$sha"
  git log -1 --format='%(trailers:key=Co-Authored-By)' "$sha" | grep -q "Claude Opus 5" || echo "  ^^ MISSING TRAILER"
done
```

Per-commit, not a range query: on git 2.54 a range `%(trailers:…)` audit never
returns empty, so a range check silently always passes.

```bash
git log main..HEAD --format='%B' | grep -iE "closes #|fixes #|resolves #" && echo "AUTO-CLOSE KEYWORD FOUND — fix it" || echo "clean"
```

- [ ] **Step 8: Run THE GATES one final time, from a clean tree**

- [ ] **Step 9: Write the handoff and retarget the symlink**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
ln -snf docs/handoffs/2026-08-27-manifest-closeout-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
```

The handoff must carry: what shipped with commit SHAs; what is next with
concrete acceptance criteria; open decisions and risks; the exact resume
commands. Commit the handoff file and the retargeted symlink together.

- [ ] **Step 10: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/manifest-closeout
git add -A
git commit -F - <<'MSG'
docs: record the manifest split and decoder/encoder closeout

Co-Authored-By: Claude Opus 5 (1M context) <noreply@anthropic.com>
MSG
```

---

## Issue hygiene at slice end

This repo cites fixes as `(#N)` and never `Closes #N`, so an issue outlives its
fix until a human closes it. After the PR merges, these are candidates —
**verify each against the code before closing**, never against this plan's word:

| Issue | Closed by | Verify |
|---|---|---|
| #564 | Tasks 1–2 | `core/src/vault/manifest.rs` gone; no production file in `manifest/` over 500 lines |
| #571 | Task 3 | `to_canonical_cbor` returns `SecretBytes`; no `SecretBytes::new` at `unlock/mod.rs`'s bundle site |
| #573 | Task 5 | All four nested parsers return `DuplicateKey` on a repeat |
| #572 | Task 6 | `decode_manifest` re-encodes and compares |
| #577 | Task 7 | `git check-ignore` exits 1 for the one path, 0 for others |

**#569 does NOT close.** Task 4 closes path 2 only. Path 3 (`card.rs`) remains —
either close it in a later slice or drop it from #569's scope explicitly, but do
not leave it unmentioned, which is what happened to path 2 in the #575 handoff.

Still open and untouched by this slice: **#576** (nothing enforces the
`from_secret_reader` discipline), **#570** (`ciborium`'s decode-side realloc),
**#519** (uniffi secret accessors), **#563** / **#556** (the `block.rs` /
`record.rs` splits), **#562** (golden vaults are ASCII-blind), **#574**.
