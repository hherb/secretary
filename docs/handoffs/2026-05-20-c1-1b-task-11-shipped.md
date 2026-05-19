# NEXT_SESSION.md

**Session date:** 2026-05-20 (implementation session — C.1.1b Task 11 of 17 shipped; `commit_with_decisions` orchestrator + DraftMerge per-block extension + atomic block-then-manifest write + happy-path integration test + commit.rs → commit/ directory split)
**Status:** PR #97 (Task 10) **MERGED** into `main` as [`d4f2a75`](https://github.com/hherb/secretary/commit/d4f2a75). `feature/c1-1b-sync-merge` reset onto post-merge `main` and now carries Task 11 ([`820b0d0`](https://github.com/hherb/secretary/commit/820b0d0)) — the disk-mutation half of the merge commit path with proactive split into a directory module. 6 tasks remain (12-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`820b0d0`](https://github.com/hherb/secretary/commit/820b0d0) | Task 11 | **Disk-mutation orchestrator + DraftMerge per-block extension.** New public surface: <br/>• `pub fn commit_with_decisions(folder, &SecretBytes, DraftMerge, Vec<VetoDecision>, now_ms) -> Result<SyncState, SyncError>` re-exported from `core/src/sync/mod.rs`. Re-opens the vault (manifest signature + `verify_block_fingerprints` D6 gate), re-hashes the on-disk manifest envelope for TOCTOU freshness against `draft.manifest_hash`, applies decisions via `apply_decisions`, re-encrypts every diverging block with a fresh AEAD nonce (via `OsRng`), BLAKE3-fingerprints the new bytes, builds + signs a new manifest, and atomically writes block-first manifest-last per design §D6 / option (d). Returns `SyncState { vault_uuid, highest_vector_clock_seen: post_merge_clock }`. <br/>• `pub use bundle::compute_manifest_hash` re-export added — consumed by Task 12's `EvidenceStale` integration test for the disk-after-mutation hash check. <br/>**DraftMerge extension:** <br/>• `per_block_clocks: BTreeMap<[u8;16], Vec<VectorClockEntry>>` — the merged per-block clock `prepare_merge` produced for each `block_uuid` in `plan.diverging_blocks`. Empty for the silent-merge case. <br/>• `per_block_records: BTreeMap<[u8;16], Vec<RecordId>>` — record_uuid assignment per block, sorted ascending (matches `BTreeMap::keys()` iteration order). <br/>Both fields are `#[zeroize(skip)]` — values are non-secret framing (vector clock entries + record UUIDs are public material). `prepare_merge` populates both fields after the per-block fold; the existing 3 construction sites (draft.rs test, prepare.rs orchestrator, commit.rs test fixture) updated to match. <br/>**Internal helpers (in `core/src/sync/commit/write.rs`):** <br/>• `struct OwnerKeyBag` — bundle of owner sender + recipient keys derived once per call (Ed25519 SK in `Sensitive`, ML-DSA-65 SK in `MlDsa65Secret`, ML-KEM-768 pre-parsed `MlKem768Public`, `owner_fp`, `pk_bundle`, `x25519_pk`). Drop-time wipe via the inner `Sensitive`/`MlDsa65Secret` `ZeroizeOnDrop` impls. <br/>• `fn rewrite_one_block` — per-block re-encrypt + atomic write. Filters `post_decision_records` by `draft.per_block_records[block_uuid]`, constructs `BlockHeader` (preserving `created_at_ms` from the existing manifest entry, advancing `last_mod_ms` to `now_ms`, setting `vector_clock = draft.per_block_clocks[block_uuid]`), constructs `BlockPlaintext` (with v1 `BLOCK_VERSION_V1` / `SCHEMA_VERSION_V1` constants + `block_name` from existing entry + empty `unknown`), encrypts via `encrypt_block`, encodes via `encode_block_file`, computes BLAKE3 fingerprint, atomic-writes to `blocks/<uuid>.cbor.enc` via `write_atomic`. Returns `NewBlockEntry { fingerprint, vector_clock }` for the manifest-body update pass. <br/>**File layout split:** `commit.rs` reached 661 LOC after Task 11 — above the 500 soft cap and explicitly anticipated by the plan ("If so, plan ahead for a directory module"). Split into a directory module per `feedback_split_files_proactively`: <br/>• `core/src/sync/commit/mod.rs` (35 LOC) — module-level doc + `pub use write::commit_with_decisions` + `pub(crate) use apply::apply_decisions` <br/>• `core/src/sync/commit/apply.rs` (270 LOC) — `apply_decisions` pure helper + 6 table-driven tests (verbatim from Task 10) <br/>• `core/src/sync/commit/write.rs` (389 LOC) — `commit_with_decisions` + `OwnerKeyBag` + `NewBlockEntry` + `rewrite_one_block` <br/>All three files now under the 500-line cap; one concept per file. <br/>**Integration test in `core/tests/sync_merge.rs::commit_with_decisions_empty_vetoes_writes_merged_state`:** two concurrent manifests with no per-block divergence → `sync_once → prepare_merge → commit_with_decisions` returns `SyncState` with both devices' clock entries; subsequent `sync_once` returns `NothingToDo` (closure property). Proves the disk-mutation pipeline end-to-end on the simplest happy path. <br/>**Typed errors consumed:** `SyncError::EvidenceStale` retires its `#[allow(dead_code)]` (consumed by the freshness re-check); `MissingVetoDecision` / `UnknownVetoDecision` propagate from `apply_decisions`. `EmptyDraftWithVetoes` remains a defense-in-depth variant (per Task 10 PR #97 review-fix; documented `Display` test still in `error.rs`). |

**Branch hygiene:** PR #97 (Task 10 + PR-#97 review-fix commits) was squash-merged into `main` as `d4f2a75` at session start. The local `feature/c1-1b-sync-merge` was reset to `origin/main` (`d4f2a75`) to discard the merged commits. Local branch now carries exactly one new commit (`820b0d0`) plus this baton commit.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 11:**

- `cargo test --release --workspace --no-fail-fast` → **766 / 0 / 10** (765 baseline from `d4f2a75` + 1 = 1 new `commit_with_decisions_empty_vetoes_writes_merged_state` integration test in `core/tests/sync_merge.rs`).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed).

## (2) What's next — execute Task 12

### (a) First action next session: execute Task 12 (after PR for Task 11 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 12 — `commit_with_decisions` `EvidenceStale` integration test**. Single integration test in `core/tests/sync_merge.rs`. Setup: write two concurrent manifests, run `sync_once → prepare_merge`, then mutate the canonical manifest on disk between prepare and commit (via `sync_helpers::write_manifest_at` with a new clock). Call `commit_with_decisions` and assert:
1. Returns `Err(SyncError::EvidenceStale)`.
2. The on-disk manifest is byte-identical to its post-mutation state (no commit-side write happened).

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 11's PR merges:
git fetch --prune origin
git reset --hard origin/main                                    # discard merged commits
# THEN open the plan:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 12"
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 12 is a smaller surface than Task 11 — single new test in `core/tests/sync_merge.rs`, no new public API. The `compute_manifest_hash` re-export is already in place (this session, in Task 11) so the test can call it directly without an extra refactor.

### (b) Plan structure at a glance (6 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1-10~~ | ~~Tasks 1-10 shipped~~ ✅ in PRs #84-#97 |
| ~~11~~ | ~~`commit_with_decisions` + DraftMerge per-block + commit/ split + happy-path test~~ ✅ `820b0d0` |
| **12** | **`EvidenceStale` integration test (manifest-hash freshness)** | `core/tests/sync_merge.rs` |
| 13 | Veto-handling 4-test bundle (KeepLocal / AcceptTombstone / Missing / Unknown) — **first per-block-divergent fixture** | `core/tests/sync_merge.rs`, `core/tests/sync_helpers/mod.rs` |
| 14 | Crash-recovery test (partial-write reconverge — D6 proof) | `core/tests/sync_merge.rs` |
| 15 | 4 property tests | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [ ] `cargo test --release --workspace --no-fail-fast` → 766+ / 0 / 10 (765 baseline at `d4f2a75` + ≥1 new test across Tasks 11-16; we're at 766 after Task 11 = 765 + 1 integration test)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5
- [x] `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision` defined with zeroize discipline + module tests ✅ Task 6 (PR #91 merged)
- [x] `tombstone_veto_set` pure helper with 7 table tests covering 4 interesting cases + 3 edges ✅ Task 7 (PR #93 merged)
- [x] `prepare_merge` orchestrator wires decap + iterative fold + veto detection + post_merge_clock; first integration test green ✅ Task 8 (PR #94 merged)
- [x] `rewrite_block_with_records_and_update_manifest` helper exists; post-rewrite vault opens cleanly under D6 ✅ Task 9 (PR #96 merged)
- [x] `apply_decisions` pure helper enforces `vetoes ↔ decisions` bijection; 6 table tests cover missing/unknown/duplicate/KeepLocal/AcceptTombstone/empty edges ✅ Task 10 (PR #97 merged)
- [x] `commit_with_decisions` re-opens vault, freshness-checks manifest hash, applies decisions, re-encrypts diverging blocks, atomic block-first manifest-last write, returns `SyncState`; happy-path test (no per-block divergence) green ✅ Task 11 (`820b0d0`)
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair — proven by the Task 10 unit tests; Task 13's integration coverage closes the disk-side proof
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-10 and confirm each has at least one real consumer in Tasks 11-16. Stale `#[allow(dead_code)]` markers must be removed. **Task 11 retired `apply_decisions`'s `#[allow(dead_code)]` (consumer is `commit_with_decisions`)** and **`EvidenceStale`'s `#[allow(dead_code)]` (consumer is the freshness re-check)**. The Task 9 helper `rewrite_block_with_records_and_update_manifest` carries its own `#[allow(dead_code)]` that gets retired in Task 13 (first integration-test consumer); `EmptyDraftWithVetoes` retains its own dedicated `Display` unit test in `error.rs` (defense-in-depth variant — no longer consumed by `apply_decisions` after PR #97 review-fix); the Task 1 sync_helpers items (`BLOCK_NONCE_F/G`, `SIBLING_NONCE_C/D`, `fresh_vault_four_concurrent_manifests`) are consumed in Tasks 13-14.

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **`commit_with_decisions` takes `&SecretBytes` not `&[u8]`.** Plan's draft used `password: &[u8]`. The actual `Unlocker::Password` variant takes `&SecretBytes`, so the test's `&fixtures::golden_vault_001_password()` (already `&SecretBytes`) flows in directly without an extra `.expose()` call. `&SecretBytes` also keeps the zeroize discipline visible at the API boundary. Reversible if a future cross-crate caller needs the raw-bytes shape.
- **`commit/` directory split happened this PR, not deferred.** Plan said "If so, plan ahead for a directory module"; per `feedback_split_files_proactively` I split now (`commit.rs` was 661 LOC after the Task 11 append, well over the 500 cap). Three small files (35 + 270 + 389) — git tracked the rename `commit.rs → commit/apply.rs` cleanly.
- **`per_block_clocks` / `per_block_records` added to DraftMerge, not a separate "metadata" map.** Plan's draft also mentioned the option of a `per_block_metadata` map for `block_name` / `block_version` / `schema_version` / `unknown`. Shipped the simpler shape: `block_name` is pulled from the existing manifest's `BlockEntry`, version/schema use the v1 constants (`BLOCK_VERSION_V1 = 1`, `SCHEMA_VERSION_V1 = 1`), and the `unknown` forward-compat map defaults to empty (a v1-only client never reads or writes unknown keys on a block plaintext). If a future spec version adds forward-compat fields to `BlockPlaintext`, this is a compat hazard — flag it in the spec doc when that version lands. For v1 it's safe.
- **Used `std::fs::read(manifest_path)` for the freshness re-check, not `read_vault_manifest_full`.** Plan's draft used `read_vault_manifest_full` which re-runs the full AEAD-decrypt + verify pass. Simpler raw read avoids the double-work — `open_vault` already authenticated the on-disk state at step 1. The freshness check only cares about byte-equality (BLAKE3 of envelope bytes), not authenticity. The race between step-1's open and step-2's read is fine: if a concurrent writer swapped the manifest in between, we hash the swapped bytes and fail with `EvidenceStale` (the design's intended path).
- **Explicit `drop(draft)` + `drop(bag)` at end of `commit_with_decisions`.** Pre-cloned `vault_uuid` + `post_merge_clock` so the move into `SyncState::new` doesn't conflict with `DraftMerge`'s `Drop` impl. The explicit drops document the source-order wipe (per CLAUDE.md memory-hygiene: composite types drop secret fields in source order). Reviewer should check that the clone is non-secret material — `vault_uuid: [u8; 16]` and `post_merge_clock: Vec<VectorClockEntry>` are both public-key-style framing.

### Carry-over from earlier PRs

- **Task 1 RNG seeding (in `7dff8da` via `67567c7`)** — `ChaCha20Rng::from_seed(...)` replaced the plan's `DeterministicNonceRng`; `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this; no action for Task 12+.
- **PR #85 helper-signature refactor (`748377d`)** — `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` takes `&OpenVault` because under D6 the helper's previously-internal `open_vault` call fails on the second rewrite of the same fixture. Task 11's `commit_with_decisions` takes `&SecretBytes` and re-opens internally (the test drops `open` before commit) — this works because `commit_with_decisions` only does ONE rewrite per call. The shared-OpenVault pattern is still useful for tests that need multiple rewrites of the same vault folder in the same test (`rewrite_block_with_records_and_update_manifest`).
- **`apply_decisions` is `pub(crate)`, not `pub`.** Kept the minimal surface area from Task 10. `commit_with_decisions` consumes it intra-crate via `pub(crate) use apply::apply_decisions` in `commit/mod.rs`. If a cross-crate consumer (e.g. an FFI binding) needs it, widen then — `pub(crate) → pub` is reversible; the inverse is the breaking change.

### Implementer's-call decisions (live for Tasks 12-13)

1. **`commit_with_decisions` identity argument.** Resolved this PR: takes `&SecretBytes` and re-opens internally. Task 13's veto-fixture tests will need to drop their `open` before calling `commit_with_decisions` (or instantiate a fresh `SecretBytes`). If lifetime gymnastics push, consider widening to also accept `&UnlockedIdentity` in a follow-up — but the current shape works for Tasks 12-14 happy paths.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Frozen this PR. Both are `BTreeMap<[u8; 16], …>`. If Task 13's per-block divergent fixture needs additional per-block metadata (e.g. `block_name` for a renamed block), extend with a third map rather than mutating the existing two. Don't change the existing shape — Task 11's tests pin it.
3. **`extract_vault_uuid` helper duplication (still open).** Task 8 inlined a private `extract_vault_uuid(folder: &Path) -> [u8; 16]` helper in `core/tests/sync_merge.rs`; the same helper lives in `core/tests/sync.rs::extract_golden_vault_uuid`. If Task 12+ integration tests need it again, lift it into `core/tests/fixtures/mod.rs` as `pub fn extract_vault_uuid(folder: &Path) -> [u8; 16]` and delete both duplicates. Out of scope for Task 11.
4. **`sync_helpers/mod.rs` file size (#95 filed).** 743 LOC after Task 9 (unchanged in Tasks 10-11). Natural module boundaries documented in #95. Not in Task 11's scope; revisit at C.1.1b close (Task 17) or as a standalone refactor PR if Tasks 12-16 push it further.
5. **`commit/` directory split (resolved this PR).** Three files at 35 / 270 / 389 LOC. Each is one concept. If Tasks 12-16 grow `commit/write.rs` past 500 (e.g. by adding a per-affected-block metadata extractor or by extending `OwnerKeyBag` with more keys), consider splitting `write.rs` further (`write/{mod,key_bag,block,manifest}.rs`). Not a concern for Task 12 (single integration test, zero new prod code).
6. **`prepare.rs` file size — 869 LOC.** Already over the 500 cap before Task 11; my edit only added ~10 lines (the per-block map population). The baton's earlier "460 LOC after Task 8" estimate was stale. Worth filing a "split prepare.rs into mod.rs + iterative_fold.rs + veto.rs + parent_block_clock.rs" issue at C.1.1b close (Task 17), or as a standalone refactor if Tasks 12-16 push it further.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6 + Task 11 extension. The new `per_block_clocks` + `per_block_records` fields are `#[zeroize(skip)]` (BTreeMap lacks blanket Zeroize; values are non-secret public material). The drop-time wipe of inner `Record`'s secret fields still works through their own `ZeroizeOnDrop` impls on the `merged_records` vec.
- **AEAD nonce per rewrite** — `commit_with_decisions` uses `rand_core::OsRng` directly for production rewrites; per-block re-encrypt generates a fresh nonce via the standard `encrypt_block` step-4 path. The test fixture's pre-existing `BLOCK_NONCE_E/F/G` are still used for `sync_helpers` rewrites; production code does NOT touch those.
- **`tempfile` exact pin** (`=3.27.0`) — unchanged this PR.
- **CRDT proptests must not weaken** — Task 11 shipped no `core/src/vault/conflict.rs` changes. `commit_with_decisions` is a consumer of merge-primitive output, not a producer.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places. No new variants this PR (the four `SyncError` variants needed are all in place from Task 2).
- **File size of `core/src/sync/commit/write.rs`** — 389 LOC after Task 11. Below the 500 cap. Tasks 12-16 are tests-only and shouldn't grow `write.rs` further. If Tasks 14 or 16 do (e.g. partial-write recovery helpers), split per implementer-call #5 above.
- **File size of `core/src/sync/prepare.rs`** — 869 LOC after Task 11 (unchanged shape; Task 11 added ~10 lines). Pre-existing growth — file a tracking issue at C.1.1b close.
- **File size of `core/tests/sync_helpers/mod.rs`** — 743 lines after Task 9 (unchanged this session). See #95 for the planned refactor.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 lines after Task 5's call-site addition. Pre-existing growth, not Task-11 caused; worth filing a `refactor(vault): split orchestrators.rs into per-orchestrator submodules` issue at C.1.1b close.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget. Will be revisited when sizing C.1.1b's per-block proptests in Task 15.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. Not consumed by Task 11's `commit_with_decisions` (uses the existing `OpenVault` not `OpenVaultManifest`). Re-check at Task 13-14.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. Could be closed alongside C.1.1b if `once.rs` surface is touched (Task 12 may not touch it).
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands (C.4 scope).
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 13's veto-fixture helpers may close some of #78 as a side effect — worth re-checking on Task 13 completion.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors (Task 14 of the 1a plan, deferred). Not directly C.1.1b; relisted for tracking.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. Not directly C.1.1b-relevant; tracked for the C.4 doc pass.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader between `core/tests/fixtures/mod.rs` and the lib-internal test helper added in PR #85. Refactor follow-up, scoped to ~30 min.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures. Filed off PR #85 review; current behaviour now ALSO pinned by the renamed FFI `open_vault_missing_block_file_returns_folder_invalid` test (test flips when #88 lands).
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies into one shared helper per crate. Filed off PR #89 review. Cross-crate scope, ~20 min refactor.
- **[#95](https://github.com/hherb/secretary/issues/95)** — split `core/tests/sync_helpers/mod.rs` (~743 LOC) into submodules. Filed at Task 9 close; revisit at Task 17 or as standalone refactor.
- **[#98](https://github.com/hherb/secretary/issues/98)** — `apply_decisions` duplicate-decision tightening (PR #97 review-fix follow-up). Not Task 11/12-blocking.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `820b0d0` (Task 11) on top of `d4f2a75` plus this baton commit. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, 820b0d0, d4f2a75

# Baseline gauntlet (expect 766 / 0 / 10 on this branch before Task 12 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 11's PR merges, reset feature branch + open the plan for Task 12:
git fetch --prune origin
git reset --hard origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 12"
```

## Closing inventory

- **Branch state on close:** `main` at `d4f2a75` (PR #97 squash-merged Task 10 + review-fix commits). `feature/c1-1b-sync-merge` rebased onto `d4f2a75` carrying one new commit: `820b0d0` (Task 11) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 766 passed + 10 ignored (765 baseline from `d4f2a75` + 1 new `commit_with_decisions_empty_vetoes_writes_merged_state` integration test in `core/tests/sync_merge.rs`). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95) / [#98](https://github.com/hherb/secretary/issues/98).
- **Open PRs:** one to be opened at end of this session covering Task 11.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close snapshot (pre-review).
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle snapshot with explicit per-issue disposition.
  - [`docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md) — Task 4 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md) — Task 5 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md) — Task 6 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md) — Task 7 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md) — Task 8 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-9-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-9-shipped.md) — Task 9 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-10-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-10-shipped.md) — Task 10 close snapshot.
  - [`docs/handoffs/2026-05-20-c1-1b-task-11-shipped.md`](docs/handoffs/2026-05-20-c1-1b-task-11-shipped.md) — Task 11 close snapshot (this session).
