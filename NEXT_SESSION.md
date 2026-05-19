# NEXT_SESSION.md

**Session date:** 2026-05-19 (implementation session — C.1.1b Task 10 of 17 shipped; `apply_decisions` pure helper + bijection check + 6 table-driven unit tests)
**Status:** PR #96 (Task 9) **MERGED** into `main` as [`0331057`](https://github.com/hherb/secretary/commit/0331057). `feature/c1-1b-sync-merge` reset onto post-merge `main` and now carries Task 10 ([`db2e02c`](https://github.com/hherb/secretary/commit/db2e02c)) — the new pure helper enforces the `vetoes` ↔ `decisions` bijection via `BTreeSet::difference` and returns the post-decision merged record set. 7 tasks remain (11-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`db2e02c`](https://github.com/hherb/secretary/commit/db2e02c) + review-fix | Task 10 | **`core/src/sync/commit.rs`** new file. New surface: <br/>• `pub(crate) fn apply_decisions(draft: &DraftMerge, decisions: &[VetoDecision]) -> Result<Vec<Record>, SyncError>` — pure-function core of veto-decision application. Two `BTreeSet::difference` passes detect missing/unknown decisions; violations surface as `SyncError::MissingVetoDecision` / `SyncError::UnknownVetoDecision` (defined in Task 2) pointing at the smallest offending `record_id` in canonical sort order. `KeepLocal { record_id }` restores `veto.local_state` over the matching merged record via a `BTreeMap<RecordId, Record>` lookup (O(log n); both lookups are infallible by construction — the bijection check above + `prepare_merge`'s veto-derivation-from-merged-records invariant); `AcceptTombstone` is a no-op (the merge already wrote the death clock). Output is sorted by `record_uuid` to match `prepare_merge`'s shape. Marked `#[allow(dead_code)]` — the allow is retired in Task 11 when `commit_with_decisions` becomes a consumer. <br/>**Six table-driven unit tests** in `sync::commit::tests`: <br/>1. `empty_vetoes_empty_decisions_returns_unchanged_records` — silent merge happy path. <br/>2. `keep_local_overrides_tombstoned_record` — KeepLocal restores the live version over the merged tombstone. <br/>3. `accept_tombstone_is_noop` — AcceptTombstone leaves the merge output untouched. <br/>4. `missing_decision_returns_missing_veto_decision` — 2 vetoes + 1 decision → typed error on the smaller unmatched id. <br/>5. `unknown_decision_returns_unknown_veto_decision` — 1 veto + 2 decisions (one stray) → typed error on the stray id. <br/>6. `duplicate_decisions_for_same_id_treated_as_one` — pins BTreeSet-dedupe semantics (two `KeepLocal` entries for the same id collapse to one decision); typed-error tightening tracked in [issue #98](https://github.com/hherb/secretary/issues/98). <br/>**`core/src/sync/mod.rs`** adds `pub mod commit;` (no public re-export of `apply_decisions` — it's a helper; `commit_with_decisions` re-export lands in Task 11). <br/>**Review-fix on PR #97**: replaced the misleading `.ok_or(SyncError::EmptyDraftWithVetoes)?` on the bijection-proved-unreachable veto lookup with a `BTreeMap::get().expect(...)` carrying the structural invariant in the message; dropped the matching unreachable `else { records.push(...) }` branch on the record lookup; output is now sorted-by-uuid via `BTreeMap::into_values()` instead of `Vec::clone()` (canonical, matches `prepare_merge`); filed [issue #98](https://github.com/hherb/secretary/issues/98) for the deferred duplicate-decision tightening. <br/>**Magic-number discipline**: test fixtures use named consts (`VETO_BLOCK_ID`, `VETO_TOMBSTONER_DEVICE`, `DRAFT_VAULT_UUID`, `DISK_TOMBSTONE_AT_MS`) instead of inline literal arrays. |

**Branch hygiene:** PR #96 (Task 9 + review-fix) was squash-merged into `main` as `0331057` at session start. The local `feature/c1-1b-sync-merge` was reset to `origin/main` to discard the now-redundant Task-9 commits + the PR-#96 review-fix commit (`e60ef5b`). Local branch now carries exactly one new commit (`db2e02c`) plus this baton commit.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 10:**

- `cargo test --release --workspace --no-fail-fast` → **765 / 0 / 10** (759 baseline from `0331057` + 6 = 6 new `sync::commit::tests::*` unit tests, all in the lib target).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean (auto-fix applied to one test case in `commit.rs`).
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed).

## (2) What's next — execute Task 11

### (a) First action next session: execute Task 11 (after PR for Task 10 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 11 — `commit_with_decisions` re-encrypt + manifest re-sign**. The disk-mutation half of the commit path: for each affected block (a block whose merged records changed), re-encrypt with a fresh AEAD nonce, compute the new BLAKE3 fingerprint, write atomically. Build a new manifest body with updated `BlockEntry.fingerprint` + `BlockEntry.vector_clock_summary` + `manifest.vector_clock = draft.post_merge_clock`. Sign hybrid, encode, atomic-write. Return the new `SyncState`. The freshness re-check (`draft.manifest_hash` against on-disk current manifest hash) lives at the top of this function. Bijection is delegated to Task 10's `apply_decisions`. Task 11 retires the `#[allow(dead_code)]` on `apply_decisions` and on the Task 2 `SyncError` variants `EvidenceStale` (consumed by the freshness re-check) + `EmptyDraftWithVetoes` (consumed by the defensive `KeepLocal` branch).

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 10's PR merges:
git fetch --prune origin
git reset --hard origin/main                                    # discard merged commits
# THEN open the plan + design doc:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 11"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 11 is the disk-mutating half — bigger surface than Task 10. Expect:

- One new public function `pub fn commit_with_decisions(folder, &UnlockedIdentity, draft, decisions, now_ms) -> Result<SyncState, SyncError>` (or `&password` if the test pattern wants a re-open) re-exported from `core/src/sync/mod.rs`.
- Helper functions inside `commit.rs` for: (i) per-affected-block AEAD re-encrypt + BLAKE3 re-fingerprint, (ii) manifest body construction with updated `BlockEntry`s, (iii) hybrid sign + encode + atomic-write of the new manifest.
- One integration test in `core/tests/sync_merge.rs::commit_with_decisions_empty_vetoes_writes_merged_state` proving the three-step `sync_once → prepare_merge → commit_with_decisions` happy path against the existing two-concurrent-manifests fixture.
- The freshness re-check at the top of `commit_with_decisions` is the entry point for the `EvidenceStale` test that arrives in Task 12 — no test for it in Task 11 itself, but the typed-error branch must be wired in.

### (b) Plan structure at a glance (7 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1-9~~ | ~~Tasks 1-9 shipped~~ ✅ in PRs #84-#96 |
| ~~10~~ | ~~`apply_decisions` pure helper + 6 bijection unit tests~~ ✅ `db2e02c` |
| **11** | **`commit_with_decisions` — re-encrypt + atomic write + happy-path test** | `core/src/sync/commit.rs`, `core/src/sync/mod.rs`, `core/tests/sync_merge.rs` |
| 12 | `EvidenceStale` integration test (manifest-hash freshness) | `core/tests/sync_merge.rs` |
| 13 | Veto-handling 4-test bundle (KeepLocal / AcceptTombstone / Missing / Unknown) — **first per-block-divergent fixture** | `core/tests/sync_merge.rs`, `core/tests/sync_helpers/mod.rs` |
| 14 | Crash-recovery test (partial-write reconverge — D6 proof) | `core/tests/sync_merge.rs` |
| 15 | 4 property tests | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [ ] `cargo test --release --workspace --no-fail-fast` → 765+ / 0 / 10 (759 baseline at `0331057` + ≥6 new tests across Tasks 10-16; we're at 765 after Task 10 = 759 + 6 lib tests)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5
- [x] `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision` defined with zeroize discipline + module tests ✅ Task 6 (PR #91 merged)
- [x] `tombstone_veto_set` pure helper with 7 table tests covering 4 interesting cases + 3 edges ✅ Task 7 (PR #93 merged)
- [x] `prepare_merge` orchestrator wires decap + iterative fold + veto detection + post_merge_clock; first integration test green ✅ Task 8 (PR #94 merged)
- [x] `rewrite_block_with_records_and_update_manifest` helper exists; post-rewrite vault opens cleanly under D6 ✅ Task 9 (PR #96 merged)
- [x] `apply_decisions` pure helper enforces `vetoes ↔ decisions` bijection; 6 table tests cover missing/unknown/duplicate/KeepLocal/AcceptTombstone/empty edges ✅ Task 10 (`db2e02c`)
- [ ] Three-step `sync_once → prepare_merge → commit_with_decisions` happy-path test green
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair — proven by the Task 10 unit tests; Task 13's integration coverage closes the disk-side proof
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-10 and confirm each has at least one real consumer in Tasks 11-16. Stale `#[allow(dead_code)]` markers must be removed. **Task 10 adds one** (`apply_decisions`) that gets retired in Task 11 (its consumer is `commit_with_decisions`). The Task 9 helper `rewrite_block_with_records_and_update_manifest` carries its own `#[allow(dead_code)]` that gets retired in Task 13 (first integration-test consumer); the Task 2 SyncError variants (`EvidenceStale`, `UnknownVetoDecision`, `MissingVetoDecision`, `EmptyDraftWithVetoes`) — `UnknownVetoDecision` + `MissingVetoDecision` retired by Task 10's unit tests; `EvidenceStale` + `EmptyDraftWithVetoes` retired by Task 11; the Task 1 sync_helpers items (`BLOCK_NONCE_F/G`, `SIBLING_NONCE_C/D`, `fresh_vault_four_concurrent_manifests`) are consumed in Tasks 13-14.

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **No structural deviations.** Task 10's plan provided the exact module shape (impl + 6 tests). Shipped code matches the design intent. The mechanical adjustments:
  - Test fixtures use named consts (`VETO_BLOCK_ID = [0xBB; 16]`, `VETO_TOMBSTONER_DEVICE = [0xCC; 16]`, `DRAFT_VAULT_UUID = [9; 16]`, `DISK_TOMBSTONE_AT_MS = 200`) instead of inline literals so the magic-number discipline holds. Plan's draft inlined these as repeated literals; semantically equivalent, but the const form keeps the fixtures self-documenting.
  - Helper `rec(uuid, last_mod_ms)` uses `created_at_ms: last_mod_ms.saturating_sub(1_000)` (matching the existing pattern in `draft.rs::tests::dummy_record`) rather than the plan's draft `created_at_ms: 0`, so the well-formed-record invariant `created_at_ms ≤ last_mod_ms` reads more naturally and the synthesised records look closer to what production code emits.
- **Marked `apply_decisions` `pub(crate)` not `pub`.** The plan's draft used `pub`; reading downstream Task 11, the only consumer is `commit_with_decisions` in the same crate. Keeping the surface area minimal until there's a cross-crate consumer (which the C.1.1b plan doesn't require) — `pub(crate)` is reversible to `pub` if Task 11 turns out to want it exported, but the inverse (widening then narrowing) is the breaking change. If the design doc actually wants `apply_decisions` on the public surface for tests to drive it directly, Task 11's review will flag and widen.

### Carry-over from earlier PRs

- **Task 1 RNG seeding (in `7dff8da` via `67567c7`)** — `ChaCha20Rng::from_seed(...)` replaced the plan's `DeterministicNonceRng`; `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this; no action for Task 11+.
- **PR #85 helper-signature refactor (`748377d`)** — `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` takes `&OpenVault` because under D6 the helper's previously-internal `open_vault` call fails on the second rewrite of the same fixture. Task 9's `rewrite_block_with_records_and_update_manifest` builds on the same pattern; Task 11's `commit_with_decisions` will need to decide whether to follow this pattern (take `&UnlockedIdentity`) or self-open (take `&password`).

### Implementer's-call decisions (live for Tasks 11-13)

1. **`commit_with_decisions` identity argument.** Plan's Task 11 step-1 draft uses `&password` (the test drops `open` before commit). The design doc's `commit_with_decisions` takes `&UnlockedIdentity`. Pick `&UnlockedIdentity` to match the design doc and avoid the test having to type the password twice — the prepare/commit pair becomes `let draft = prepare_merge(..., &open.identity, ...); let new_state = commit_with_decisions(..., &open.identity, draft, ...);` reusing the same handle. If something blocks (e.g. a lifetime conflict between `&OpenVault` and `&UnlockedIdentity`), fall back to `&password` and re-open inside `commit_with_decisions`.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Tasks 6+8 froze the minimal six-field `DraftMerge` shape; Task 11's `commit_with_decisions` may need to extend it with `per_block_clocks: BTreeMap<[u8; 16], Vec<VectorClockEntry>>` to support per-block re-sign. If added, **MUST preserve the existing `#[derive(Zeroize, ZeroizeOnDrop)]` discipline** — `#[zeroize(skip)]` on the new framing fields with a comment explaining "non-secret, BTreeMap lacks blanket Zeroize" mirrors the existing pattern. Task 10 did NOT need this; pure helper works against the frozen shape.
3. **`extract_vault_uuid` helper duplication (still open).** Task 8 inlined a private `extract_vault_uuid(folder: &Path) -> [u8; 16]` helper in `core/tests/sync_merge.rs`; the same helper lives in `core/tests/sync.rs::extract_golden_vault_uuid`. If Task 11+ integration tests need it, lift it into `core/tests/fixtures/mod.rs` as `pub fn extract_vault_uuid(folder: &Path) -> [u8; 16]` and delete both duplicates. Still out of scope for Task 10.
4. **`sync_helpers/mod.rs` file size (#95 filed).** 680 LOC after Task 9 — natural module boundaries documented in #95. Not in Task 10's scope; revisit at C.1.1b close (Task 17) or as a standalone refactor PR if Tasks 11-16 push it further.
5. **`apply_decisions` visibility (resolved this PR, may revisit in Task 11).** Shipped `pub(crate)`; widen to `pub` only if Task 11 finds a cross-crate consumer.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6. Task 11's `commit_with_decisions` may add fields to `DraftMerge`; if any field carries secret material it MUST derive `Zeroize` or be wrapped in a zeroize-typed container.
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants are in place (now seeded ChaCha20Rng); per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness. Task 11's per-affected-block re-encrypt MUST generate a fresh nonce per block via `OsRng` (production path) — the plan's draft uses `rand_core::OsRng` directly.
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — Task 10 shipped a pure helper with no `core/src/vault/conflict.rs` changes. If implementation friction in Task 11+ requires touching the merge primitives beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places. No new variants in Task 10 or expected in Tasks 11-16 (the four `SyncError` variants needed are all in place from Task 2).
- **File size of `core/src/sync/prepare.rs`** — 460 lines after Task 8 (unchanged in Task 9 + Task 10). Task 11 may push past 500 since `commit_with_decisions` lives in a new module; `commit.rs` is currently 258 lines, and Task 11's append may push it past 500 too. If so, plan ahead for a directory module (`core/src/sync/commit/{mod,apply,write}.rs`) per `feedback_split_files_proactively`.
- **File size of `core/tests/sync_helpers/mod.rs`** — 680 lines after Task 9. See #95 for the planned refactor.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 lines after Task 5's call-site addition. Pre-existing growth, not Task-10 caused; worth filing a `refactor(vault): split orchestrators.rs into per-orchestrator submodules` issue at C.1.1b close.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget. Will be revisited when sizing C.1.1b's per-block proptests in Task 15.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. C.1.1b's `commit_with_decisions` may consume them; re-check at Task 11.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. Could be closed alongside C.1.1b if `once.rs` surface is touched.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands (C.4 scope).
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 13's veto-fixture helpers may close some of #78 as a side effect — worth re-checking on Task 13 completion.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors (Task 14 of the 1a plan, deferred). Not directly C.1.1b; relisted for tracking.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. Not directly C.1.1b-relevant; tracked for the C.4 doc pass.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader between `core/tests/fixtures/mod.rs` and the lib-internal test helper added in PR #85. Refactor follow-up, scoped to ~30 min.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures. Filed off PR #85 review; current behaviour now ALSO pinned by the renamed FFI `open_vault_missing_block_file_returns_folder_invalid` test (test flips when #88 lands).
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies into one shared helper per crate. Filed off PR #89 review. Cross-crate scope, ~20 min refactor.
- **[#95](https://github.com/hherb/secretary/issues/95)** — split `core/tests/sync_helpers/mod.rs` (~680 LOC) into submodules. Filed at Task 9 close; revisit at Task 17 or as standalone refactor.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `db2e02c` (Task 10) on top of `0331057` plus this baton commit. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, db2e02c, 0331057

# Baseline gauntlet (expect 765 / 0 / 10 on this branch before Task 11 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 10's PR merges, reset feature branch + open the plan + design doc for Task 11:
git fetch --prune origin
git reset --hard origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 11"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

## Closing inventory

- **Branch state on close:** `main` at `0331057` (PR #96 squash-merged Task 9 + review-fix commits). `feature/c1-1b-sync-merge` rebased onto `0331057` carrying one new commit: `db2e02c` (Task 10) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 765 passed + 10 ignored (759 baseline from `0331057` + 6 new `sync::commit::tests::*` lib unit tests). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95).
- **Open PRs:** one to be opened at end of this session covering Task 10.
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
  - [`docs/handoffs/2026-05-19-c1-1b-task-10-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-10-shipped.md) — Task 10 close snapshot (this session).
