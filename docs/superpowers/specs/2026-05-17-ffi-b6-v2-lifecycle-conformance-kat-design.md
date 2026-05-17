# Sub-project B.6 v2 — Cross-language FFI conformance KAT (lifecycle ops)

**Date:** 2026-05-17
**Status:** Design approved (brainstormed 2026-05-17; this doc is the input to writing-plans).
**Predecessor:** [B.6 v1 — read-only conformance KAT](2026-05-15-ffi-b6-conformance-kat-design.md).
**Tracking issue:** [#59](https://github.com/hherb/secretary/issues/59).
**Successor (planned):** Sub-project C kickoff (sync orchestration). v2 closes the B.6 design arc.

## 1. Purpose

B.6 v1 (PR #58, merged 2026-05-15) pinned the **read-only** half of the uniffi FFI surface — `open_vault_with_password`, `open_vault_with_recovery`, `read_block` — into a frozen JSON contract that every binding (Rust bridge, Swift, Kotlin) must match. v2 extends that contract to the **lifecycle** half:

- `save_block` (insert)
- `share_block` (add recipient)
- `trash_block` (move to trash)
- `restore_block` (restore from trash)

Each op gets at least one happy + one error vector per issue #59's acceptance criteria; the chosen error variant in each case is the most likely silent-divergence surface across bindings (`InvalidArgument`, `RecipientAlreadyPresent`, `BlockNotFound`, `BlockNotInTrash`).

The same single JSON file (`core/tests/data/conformance_kat.json`) holds both v1 and v2 vectors; the file's `version` field bumps `1 → 2` and v2 vectors are **appended** to the existing 11 v1 vectors. Replay engines (Rust + Swift + Kotlin) extend their existing replay loops to dispatch the five new operation discriminators.

### 1.1 Cross-language parity reframed (the determinism question)

The headline open question from issue #59 was: **how do we pin `save_block`'s output when AEAD nonces are OS-CSPRNG-driven and the on-disk bytes differ between runs?** Three options were sketched: a `#[cfg(test)]` RNG knob, shape-only assertions, or a `dyn RngCore` parameter on the bridge orchestrator.

The brainstorming session settled this by reframing what "cross-language parity" requires:

> All three host runners (Rust / Swift / Kotlin) delegate to the same `secretary-ffi-bridge` crate via uniffi. They cannot disagree on AEAD nonce bytes — those bytes are produced inside the shared Rust code path, not inside the language-specific binding. Cross-language parity is automatic for any byte the bridge produces.

What the host runners independently produce — and therefore what the KAT must pin — is the **observable surface** of the FFI: the typed Ok/Err discriminator, the variant string for errors, the post-call manifest shape (`block_count`, `find_block(uuid)`, recipient count), and the round-trip plaintext returned by a subsequent `read_block`.

The on-disk encrypted bytes are NOT a cross-language parity concern. They are a Rust-bridge-stability concern, already covered by:

- `core/tests/save_block.rs` round-trip tests (every `cargo test`),
- `core/fuzz/` byte-level corruption harness (manual nightly runs).

**Consequence for v2:** no `#[doc(hidden)] pub fn install_test_rng` on the bridge. No `_with_rng` variant of the lifecycle orchestrators. No bridge code changes at all. The replay engine bears the full complexity by asserting **shape + round-trip**, not bytes.

## 2. Architectural decisions (settled in brainstorming)

| Decision | Choice | Rationale |
|---|---|---|
| Determinism strategy | **Shape + round-trip only.** No on-disk byte pinning. No test-RNG plumbing. No bridge crate changes. | Cross-language parity does not require byte-level determinism (§1.1). Round-trip read after save pins the observable plaintext; counts + variant strings pin the rest. |
| KAT scope (v2) | save_block (happy + invalid input) + share_block (alice happy + `RecipientAlreadyPresent`) + trash_block (happy + unknown uuid) + restore_block (happy + not-in-trash). **8 lifecycle vectors** + 1 writable-open head = 9 new vectors. | Matches issue #59 acceptance floor with one well-chosen error variant per op. Each error variant is the most likely silent-divergence surface across bindings; collectively they exercise the four typed-error paths most exposed to uniffi codegen renames. |
| Writable fixture model | **One `open_vault_with_password_writable` vector at the head of the v2 chain** copies `golden_vault_001/` to a tempdir and opens the copy. All v2 write vectors `after:` that. Replay engines clean up the tempdir at exit via RAII. | Mirrors the existing `fresh_writable_vault()` precedent in `ffi/secretary-ffi-bridge/tests/save_block.rs`. Each replay engine already has the primitives: `tempfile::TempDir` + walkdir in Rust; `FileManager.copyItem` in Swift; `Files.walk` recursive-copy in Kotlin. One tempdir per replay run isolates state from concurrent runs. |
| State evolution | **Linear chain via `after:` (extends v1 model).** Each write vector mutates the cached `OpenVaultOutput` in place; later vectors observe the post-mutation state. Cache value transitions from "read-only after caching" (v1) to "mutated in place across write vectors" (v2). | Models the natural write-order chain (save → share → trash → restore the same block). Independent vectors (e.g. `save_block_invalid_input`) stay independent — they `after:` the writable-open head and don't mutate state. |
| Share-target identity | Use **alice** from `golden_vault_001/contacts/`. Her user_uuid (`7921b6ed8fa8cff2baf61a43f3a66a9f`) is pinned in the KAT as the share recipient. | No new fixture data. `alice.card` is already on disk (the fixture bundles owner + alice + bob; only owner is a recipient of the existing block). Bridge's `share_block` reads contact cards from `<vault>/contacts/`. `RecipientAlreadyPresent` reuses `owner.user_uuid` (already a recipient). |
| Round-trip assertions | After `save_block_insert_happy`, the replay engine calls `read_block(new_uuid)` and asserts the records match the input bit-for-bit (same shape check v1 uses for `read_block_happy`). The pinned post-save records live in `expected.post_state.read_block.records`. | Strongest cross-language guarantee for the save path — catches a bridge regression that writes correctly but reads back garbled records. |
| Manifest-shape assertions | Each write vector pins `expected.post_state.block_count` (post-op) and `expected.post_state.find_block_uuid_hex` (one of: `"<uuid>"` for present, `null` for absent). Share vectors add `expected.post_state.recipient_count`. | Minimum-information snapshot of "did the op observably succeed". Boolean-ish find_block + integer counts are stable across bindings without RNG dependency. |
| KAT versioning | Bump `version: 1 → 2`. Replay engines accept `version <= 2`. v1 vectors remain unchanged. | Single source of truth, no parallel JSON files. A v1-only engine running against a v2 KAT fails loudly on the unknown operation discriminator — that is the desired behavior. |
| Generator regeneration | The existing `#[ignore] fn generate_conformance_kat` extends to also fill `save_block_insert_happy.expected.post_state.read_block.records` placeholders (the only generator-filled field in v2). Workflow matches v1: manual `cargo test -- --ignored generate_conformance_kat --nocapture`; diff is human-reviewed. | Same precedent as v1's `read_block_happy.expected.records`. The placeholder convention `"<filled-in-by-generator>"` makes the regen scope obvious. |
| Tempdir lifecycle | Replay engine creates one tempdir at start, holds it for the full replay run, deletes at the end (success or failure). Rust uses `tempfile::TempDir`; Swift uses `defer { try? FileManager.default.removeItem(at: tmpURL) }`; Kotlin uses `Files.walkFileTree(..., DELETE_ON_EXIT_VISITOR)` or a `try/finally`. | Standard cross-language RAII pattern. Failure path is covered (the test runner exits non-zero but the tempdir is still cleaned up). |
| No bridge changes | `ffi/secretary-ffi-bridge/src/{save,share,trash,restore}/orchestration.rs` are byte-identical pre/post-v2. | Direct consequence of the shape + round-trip determinism choice. Confirmed in §1.1. |

## 3. Module structure

```
core/tests/data/conformance_kat.json
                          EDIT. Bump version 1 → 2; append 9 v2 vectors
                          (writable-open + 8 lifecycle). Existing 11 v1
                          vectors unchanged. Comment field updated to
                          mention v2 scope.

core/tests/conformance_kat.rs
                          EDIT. Extend the replay loop to dispatch the 5
                          new operation discriminators
                          (open_vault_with_password_writable, save_block,
                          share_block, trash_block, restore_block). Extend
                          the cache value to allow in-place mutation by
                          chained write ops. The #[ignore] generator extends
                          to fill save_block_insert_happy's
                          post_state.read_block.records placeholders.
                          ~80 LOC added.

core/tests/conformance_kat_helpers/dispatch.rs
                          EDIT. Add run_open_writable, run_save_block,
                          run_share_block, run_trash_block, run_restore_block
                          + their assert_*_post_state helpers. ~150 LOC added.

core/tests/conformance_kat_helpers/types.rs
                          EDIT. Add PostState struct (block_count,
                          find_block_uuid_hex optional, recipient_count
                          optional, read_block optional) + extend the
                          Operation enum with the 5 new variants. ~30 LOC.

core/tests/conformance_kat_helpers/errors.rs
                          EDIT. Extend variant_name_vault to cover the
                          lifecycle error variants (NotAuthor,
                          RecipientAlreadyPresent, MissingRecipientCard,
                          BlockUuidAlreadyLive, BlockNotInTrash). ~20 LOC.

ffi/secretary-ffi-uniffi/tests/swift/conformance.swift
                          EDIT. Extend dispatch + cache to handle write
                          ops. Add FileManager-based recursive tempdir
                          copy. ~150 LOC added.

ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt
                          EDIT. Same shape as Swift; Files.walk +
                          Files.copy recursive copy. ~150 LOC added.

ROADMAP.md
                          EDIT. Mark B.6 v2 done on PR merge; remove the
                          "next forward chunk" row.

CLAUDE.md
                          NO CHANGE. The two run_conformance.sh invocations
                          listed today already cover v2 (same shell entry
                          points, new vectors).

NO CHANGES to:
  - ffi/secretary-ffi-bridge/src/**     (no orchestrator changes — direct
                                         consequence of the shape + round-trip
                                         determinism choice)
  - ffi/secretary-ffi-uniffi/src/**     (no UDL changes — no new FFI surface)
  - core/src/**                         (no semantic changes — the bridge
                                         crate's lifecycle orchestrators are
                                         already exercised by integration
                                         tests; v2 only freezes their
                                         observable shape in JSON)
  - ffi/secretary-ffi-py/**             (PyO3 binding is out of scope, same
                                         as v1)
```

**Aggregate new code:** roughly 580 LOC (~280 Rust + ~150 Swift + ~150 Kotlin).

## 4. KAT vector format (additions for v2)

### 4.1 New operation discriminators

```
open_vault_with_password_writable   — copy fixture to tempdir, open the copy
save_block                          — insert (update path is v3)
share_block                         — add one recipient
trash_block                         — move block to trash
restore_block                       — restore block from trash
```

### 4.2 New `expected.post_state` sub-object

On `Ok` results for write ops, vectors carry a `post_state` sub-object:

```json
"expected": {
  "kind": "ok",
  "post_state": {
    "block_count": 2,
    "find_block_uuid_hex": "abababababababababababababababab",
    "recipient_count": 2,
    "read_block": {
      "records": [
        {
          "record_uuid_hex": "<filled-in-by-generator>",
          "record_type": "note",
          "tags": [],
          "fields": [
            {"name": "title", "type": "text", "value_utf8": "wifi password"}
          ]
        }
      ]
    }
  }
}
```

Field semantics:

- `block_count` — required on every post_state. Pins the post-op `manifest.block_count()`.
- `find_block_uuid_hex` — optional. `"<hex>"` asserts `manifest.find_block(hex).is_some()`; `null` asserts `is_none()`; absent asserts nothing.
- `recipient_count` — optional, share_block vectors only. Pins the recipient count on the block after the op (host runners observe this via a `read_block` follow-up or a dedicated accessor — see §5.3).
- `read_block` — optional, save_block happy-path vectors only. Triggers a chained `read_block(uuid)` after the op and asserts the returned records match.

`expected.post_state` is **absent** on `Err` vectors (no post-state assertions for failed ops; the in-memory bridge state is byte-identical to pre-call per the FFI invariant).

### 4.3 Vector inventory (9 new vectors)

The vectors are listed in JSON order; each `after:` is given explicitly.

| # | Name | Op | after | Expected | Purpose |
|---|---|---|---|---|---|
| 12 | `open_writable_happy` | `open_vault_with_password_writable` | — | Ok | Head of v2 chain. Copies vault_001 to tempdir, opens the copy. |
| 13 | `save_block_insert_happy` | `save_block` | `open_writable_happy` | Ok + post_state.block_count=2, find=new_uuid, read_block.records match input | Inserts block `0xAB×16` with one record. |
| 14 | `save_block_invalid_input` | `save_block` | `open_writable_happy` | Err `InvalidArgument` (or bridge analogue `SaveCryptoFailure`) | Zero records or invalid uuid → typed error. Does not mutate cache. |
| 15 | `share_block_happy` | `share_block` | `save_block_insert_happy` | Ok + post_state.recipient_count=2 | Shares new block with alice (user_uuid `7921b6ed8fa8cff2baf61a43f3a66a9f`). |
| 16 | `share_block_recipient_already_present` | `share_block` | `share_block_happy` | Err `RecipientAlreadyPresent` | Shares same block with alice again. |
| 17 | `trash_block_happy` | `trash_block` | `share_block_recipient_already_present` | Ok + post_state.block_count=1, find=null | Trashes the new block. |
| 18 | `trash_block_unknown_uuid` | `trash_block` | `trash_block_happy` | Err `BlockNotFound` | Trashes `0x00×16` (never-live uuid). |
| 19 | `restore_block_happy` | `restore_block` | `trash_block_unknown_uuid` | Ok + post_state.block_count=2, find=new_uuid | Restores the trashed block. |
| 20 | `restore_block_not_in_trash` | `restore_block` | `restore_block_happy` | Err `BlockNotInTrash` | Restores the just-restored block. |

Total: v1's 11 + v2's 9 = **20 vectors per host**.

### 4.4 Vector input fields

Beyond the v1 input shapes (`vault_dir`, `password_source`, `block_uuid_hex`, etc.), v2 introduces:

- `save_block` inputs: `block_uuid_hex`, `block_name`, `device_uuid_hex`, `now_ms`, `records: [{record_uuid_hex, record_type, tags[], fields[]}]`. Each field carries `name`, `type` (`"text"` or `"bytes"`), and the corresponding value (`value_utf8` for text, `value_hex` for bytes).
- `share_block` inputs: `block_uuid_hex`, `recipient_user_uuid_hex`, `device_uuid_hex`, `now_ms`.
- `trash_block` inputs: `block_uuid_hex`, `device_uuid_hex`, `now_ms`.
- `restore_block` inputs: `block_uuid_hex`, `device_uuid_hex`, `now_ms`.

All `*_hex` fields are lowercase, no separators (matches v1 + `conflict_kat.json` precedent). `device_uuid_hex` and `now_ms` are pinned in each vector to keep observable manifest state deterministic (the bridge passes both straight into the core's `save_block` etc., which records them in the manifest's per-author clock and the block file's clock vector).

## 5. Replay engine semantics (additions for v2)

Each replay engine — Rust (`core/tests/conformance_kat.rs::replay_conformance_kat`), Swift (`tests/swift/conformance.swift`), Kotlin (`tests/kotlin/Conformance.kt`) — implements the v1 algorithm extended by three changes:

### 5.1 Cache value mutability

v1 cached `OpenVaultOutput` as immutable after the open vector succeeded. v2 needs the cached output to **mutate in place** when a write op runs against it (save_block etc. mutate the in-memory manifest). Implementation per language:

- **Rust:** the cache stays a `HashMap<String, OpenVaultOutput>`. The replay loop takes a mutable borrow when dispatching a write op against a cached predecessor; v1's `OpenVaultOutput::manifest` is already an `OpenVaultManifest` (with internal `Mutex`), so the mutation surface is internal to the cached value. No structural change to the cache type.
- **Swift:** the cache is a `var cache: [String: (UnlockedIdentity, OpenVaultManifest)]` dictionary. Swift's class semantics for `OpenVaultManifest` (uniffi-generated as a Swift class) mean the mutation is in-place by reference; later vectors observe the post-mutation state automatically.
- **Kotlin:** same as Swift, `MutableMap<String, Pair<UnlockedIdentity, OpenVaultManifest>>`. Kotlin's `OpenVaultManifest` is a JNA-backed reference type.

### 5.2 Writable-open dispatch

The `open_vault_with_password_writable` op:

1. Resolves `inputs.vault_dir` against `$SECRETARY_GOLDEN_VAULT_DIR` (matches v1).
2. Recursively copies the source dir to a tempdir owned by the replay engine. The tempdir handle is held until replay exits.
3. Calls the standard `open_vault_with_password` on the tempdir path.
4. Caches the result under the vector's name.

The post-op assertions (`block_count`, `find_block_uuid_hex`) match v1's `open_password_happy` shape — the writable variant just adds the copy step.

### 5.3 Post-state assertions

After a successful write op, the engine asserts:

1. **`block_count`** — read from `manifest.block_count()` on the cached predecessor.
2. **`find_block_uuid_hex`** — `manifest.find_block(uuid).is_some()` or `is_none()` depending on the pinned value. The hex-decoded uuid is used as the lookup key.
3. **`recipient_count`** (share_block only) — read from `manifest.find_block(uuid).recipient_uuids.len()`. The bridge's `BlockSummary` already carries the recipient UUID list as a plaintext header field (Rust `BlockSummary.recipient_uuids: Vec<[u8; 16]>`; Swift `BlockSummary.recipientUuids: [Data]`; Kotlin `BlockSummary.recipientUuids: List<ByteArray>`). The smoke runners already exercise this surface; v2 reuses it. No new bridge accessor needed.
4. **`read_block`** (save_block_insert_happy only) — chained `read_block(uuid)` after the save; records compared field-by-field against `expected.post_state.read_block.records` exactly as v1 does for `read_block_happy.expected.records`.

### 5.4 Error case-name assertion (unchanged semantics; new variants)

v1's `variant_name_vault` mapping table extends to cover the lifecycle error variants:

| Variant on `FfiVaultError` / `VaultError` | Reported string |
|---|---|
| `NotAuthor { author_uuid_hex }` | `"NotAuthor"` |
| `RecipientAlreadyPresent` | `"RecipientAlreadyPresent"` |
| `MissingRecipientCard { recipient_fingerprint_hex }` | `"MissingRecipientCard"` |
| `BlockNotFound { block_uuid_hex }` | `"BlockNotFound"` |
| `BlockUuidAlreadyLive { detail }` | `"BlockUuidAlreadyLive"` |
| `BlockNotInTrash { detail }` | `"BlockNotInTrash"` |
| `InvalidArgument { detail }` | `"InvalidArgument"` |
| `SaveCryptoFailure { detail }` | `"SaveCryptoFailure"` |

Each binding's mapping helper (`case_name(&error)` in Rust, `caseName(_ error:)` in Swift, `caseName(error: VaultException)` in Kotlin) gains the corresponding cases. A binding that renames a variant (e.g. `RecipientAlreadyPresent` → `AlreadyShared`) fails the comparison loudly.

## 6. CI integration

| Surface | New gate | When run |
|---|---|---|
| Rust replay | Subsumed by `cargo test --release --workspace` — the same `replay_conformance_kat` test now iterates 20 vectors internally. **Test count is unchanged** (one `#[test]` runs all vectors). | Every PR |
| Rust generator | `cargo test --release --workspace -- --ignored generate_conformance_kat` — unchanged invocation; the generator now also fills v2 placeholders. | Manual on intentional protocol change |
| Swift conformance | `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` — unchanged invocation; pass count goes 11/11 → 20/20. | Documented in CLAUDE.md gauntlet |
| Kotlin conformance | `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` — unchanged invocation; pass count goes 11/11 → 20/20. | Documented in CLAUDE.md gauntlet |

Final summary line format on each host (unchanged):

```
OK: secretary uniffi <lang> conformance — all 20/20 vectors passed.
```

## 7. Spec / docs updates

| File | Change |
|---|---|
| `docs/superpowers/specs/2026-05-17-ffi-b6-v2-lifecycle-conformance-kat-design.md` | This file. New. |
| `docs/superpowers/specs/2026-05-15-ffi-b6-conformance-kat-design.md` | No change. v1 spec is frozen. v2 is a successor doc, not an amendment. |
| `core/tests/data/conformance_kat.json` `comment` field | Updated to mention both v1 read-only scope AND v2 lifecycle scope, and to point at this design doc alongside the v1 design doc. |
| `ROADMAP.md` | Mark B.6 v2 done on PR merge. Per-binding test counts updated (`20/20` instead of `11/11` for the two run_conformance.sh entries). |
| `CLAUDE.md` Commands section | No change. The run_conformance.sh entries are unchanged; the JSON behind them now has 20 vectors instead of 11. |

**No spec doc changes** to `docs/crypto-design.md` or `docs/vault-format.md` — v2 pins observable behavior of existing FFI surfaces, not a wire-format change.

## 8. Defenses + non-goals

### Designed-against failure modes

| Failure mode | Caught by |
|---|---|
| Binding silently renames `RecipientAlreadyPresent` → `AlreadyShared` | `share_block_recipient_already_present` vector — `case_name(&error)` mapping fails to find the renamed case |
| Binding's `save_block` returns Ok but the write isn't persisted in the manifest | `save_block_insert_happy.expected.post_state.block_count` fails (expected 2, got 1) |
| Binding's `save_block` writes the block file but the round-trip read returns garbled records | `save_block_insert_happy.expected.post_state.read_block.records` fails field-by-field |
| Binding's `trash_block` removes from the live list but doesn't tombstone (the block isn't in the trash) | `restore_block_happy` (which `after:` the trash) fails with `BlockNotInTrash` instead of Ok |
| Binding's `share_block` adds a duplicate recipient instead of returning `RecipientAlreadyPresent` | `share_block_recipient_already_present` returns Ok (with `recipient_count` going past 2) instead of Err |
| Binding's `restore_block` succeeds on a live (never-trashed) block | `restore_block_not_in_trash` returns Ok instead of `BlockNotInTrash` |
| Bridge regression: `save_block` succeeds but `find_block` doesn't return the new uuid | `save_block_insert_happy.expected.post_state.find_block_uuid_hex` fails |
| Bridge regression: `trash_block` keeps the block findable after trashing | `trash_block_happy.expected.post_state.find_block_uuid_hex == null` fails |

### Non-goals (explicitly out of scope for v2)

- **`save_block` update path** (same uuid replaces existing entry). Covered by `core/tests/save_block.rs` and the bridge integration tests; KAT scope expansion would double the v2 vector count for marginal additional coverage. Future v3 candidate.
- **Multi-recipient share.** Today's `share_block` is single-recipient-per-call by design. The v2 vectors share one recipient at a time; multi-recipient is a v3 candidate.
- **`NotAuthor` error path.** Requires a multi-author setup (alice authors a block, owner tries to share). Out of scope for v2.
- **`BlockUuidAlreadyLive` on `restore_block`.** Requires `trash + save-with-same-uuid + restore-trashed` — clashes with the linear chain (would require state branching). Future v3.
- **PyO3 binding parity.** Same scope discipline as v1 — the KAT format is binding-agnostic but PyO3 host runner is a separate future PR.
- **Performance / timing / memory** assertions. The KAT is observable-bytes-only.
- **Sub-project C sync semantics.** Vector clocks, merge KATs, conflict detection are all out of scope.
- **Byte-level on-disk pinning.** Explicitly deferred. Cross-language parity does not require it (§1.1).

## 9. Implementation outline (one PR)

1. **Commit 1 — Rust replay engine + KAT v2 skeleton.** Extend `conformance_kat_helpers/{types,errors,dispatch}.rs` + `conformance_kat.rs` to dispatch the 5 new operations. Bump `conformance_kat.json` `version` to 2 and append the 9 v2 vectors with `"<filled-in-by-generator>"` placeholders for `save_block_insert_happy.expected.post_state.read_block.records`. Run `cargo test --release --workspace replay_conformance_kat` — replay fails on the placeholder; that's expected.
2. **Commit 2 — Generator fill-in.** Run `cargo test --release --workspace -- --ignored generate_conformance_kat --nocapture`. Commit the populated JSON. The diff is human-reviewed — it must scope to the new vectors' generator-filled fields only. Verify `cargo test` now passes.
3. **Commit 3 — Swift host runner.** Extend `ffi/secretary-ffi-uniffi/tests/swift/conformance.swift` with the new dispatch + `FileManager`-based tempdir copy + post_state assertions. Verify `bash …/swift/run_conformance.sh` passes 20/20.
4. **Commit 4 — Kotlin host runner.** Extend `ffi/secretary-ffi-uniffi/tests/kotlin/Conformance.kt` the same way. Verify `bash …/kotlin/run_conformance.sh` passes 20/20.
5. **Commit 5 — Docs + handoff.** ROADMAP.md (mark B.6 v2 done; bump per-binding counts to 20/20), NEXT_SESSION.md + handoff snapshot ride inside this PR per the standing `feedback_next_session_in_pr.md` rule.

Each commit is independently buildable and tested. The PR opens against `main` after step 5.

## 10. Test gauntlet at PR close

```bash
cargo test --release --workspace --no-fail-fast              # Expect: 642 passed + 10 ignored (unchanged — one #[test] runs all vectors)
cargo clippy --release --workspace --tests -- -D warnings    # Expect: clean
cargo fmt --all -- --check                                   # Expect: OK
uv run core/tests/python/conformance.py                      # Expect: PASS (unchanged baseline)
uv run core/tests/python/spec_test_name_freshness.py         # Expect: PASS (96 / 0 / 2 unchanged baseline)
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh             # Expect: OK; ~38 PASS asserts (unchanged)
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh # Expect: 20/20 PASS (was 11/11)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh            # Expect: OK; ~39 PASS asserts (unchanged)
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh # Expect: 20/20 PASS (was 11/11)
```

The cargo test count is **unchanged** (642 + 10) because `replay_conformance_kat` is a single `#[test]` that iterates the vector list internally — adding vectors does not add test entries. Each host runner's PASS-asserts count goes 11 → 20 directly.

## 11. Open questions deferred to writing-plans / implementation

- **`save_block_invalid_input` exact input shape.** The KAT pins an input that maps to `InvalidArgument` (Swift/Kotlin) or `SaveCryptoFailure` (Rust bridge). The specific failure trigger — empty records list vs. invalid uuid length vs. invalid record uuid — is settled in writing-plans by running the bridge tests' existing invalid-input variants and choosing the one that produces the most stable typed error across all three bindings.
- **Swift / Kotlin recursive-copy helper.** Both Swift's `FileManager.copyItem(at:to:)` and Kotlin's `Files.walk(...) + Files.copy(...)` need a small wrapper. Writing-plans decides: inline in `conformance.swift` / `Conformance.kt`, or factor into a shared `copyDirectory` helper at file scope. Recommendation: inline (each is ~15 LOC; factoring is premature DRY).
- **Generator regeneration discipline.** Same question as v1 — whether to gate the regen behind a `SECRETARY_REGEN_KAT=1` env var in addition to `#[ignore]`. The v1 spec deferred this; v2 inherits the deferral. If the writing-plans phase decides to add the gate, it applies to both v1 and v2 placeholders.

These do not change the design. They are implementation-detail decisions that the implementation plan will resolve.

## 12. Acceptance criteria

- `core/tests/data/conformance_kat.json` exists with `"version": 2` and contains the 11 v1 vectors (unchanged) + 9 v2 vectors (1 writable-open + 8 lifecycle).
- `cargo test --release --workspace` passes; the existing `replay_conformance_kat` test now exercises all 20 vectors.
- `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh` exits 0 with `20/20 PASS`.
- `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh` exits 0 with `20/20 PASS`.
- No changes under `ffi/secretary-ffi-bridge/src/`, `ffi/secretary-ffi-uniffi/src/`, or `core/src/`. v2 is replay-side-only.
- ROADMAP.md current-state line marks B.6 v2 done.
- NEXT_SESSION.md + handoff snapshot include the per-binding test counts (`20/20`) and a pointer to this design doc.
- Issue #59 closes via the PR.
