# NEXT_SESSION.md

**Session date:** 2026-05-23 (implementation session — C.1.1b Task 16 of 17 shipped; 7 new KAT vectors in `core/tests/data/sync_kat.json`).
**Status:** PR to be opened. `feature/c1-1b-task-16` carries 7 commits on top of `43f1214` (post-Task-15 main). 1 task remains (Task 17).

## (1) What we shipped this session

| Commit | Vector | What it adds |
|---|---|---|
| [`2da704e`](https://github.com/hherb/secretary/commit/2da704e) | 16.1 | **`concurrent_disjoint_blocks_no_vetoes_applied`** — schema v1 → v2 (tagged-enum dispatch). Existing 9 vectors gain `"vector_type": "clock_dispatch"`. New family `concurrent_merge_apply_decisions` drives the full three-step merge (sync_once → prepare_merge → commit_with_decisions) on a per-block-divergent fixture built by a scenario-named builder (`no_veto`, `single_veto`, `two_veto`). Vector 1 fixes `scenario = "no_veto"` + both counters = 5 + decisions = []; asserts 0 vetoes, 1 diverging block, post-commit `sync_once → NothingToDo`. Re-uses Task 15's `sync_merge_proptest_helpers/` fixture builders (now flagged shared between proptest and sync_kat binaries — `#[allow(dead_code)]` on items the KAT binary doesn't consume). |
| [`10f433f`](https://github.com/hherb/secretary/commit/10f433f) | 16.2 | **`concurrent_same_block_field_lww_no_vetoes`** — adds fixture builder `build_same_block_field_lww_no_veto_fixture` (canonical + sibling reference SAME `record_uuid` with different `last_mod` timestamps → LWW the "k" field; no tombstones → no vetoes). New optional `expected_post_commit_canonical_records_count` JSON field — distinguishes disjoint-UUID merges (count = 2) from same-UUID-LWW merges (count = 1). Vector 1 gains the assertion-strengthening field too (`= 2`). |
| [`57753f1`](https://github.com/hherb/secretary/commit/57753f1) | 16.3 | **`concurrent_one_tombstone_veto_keep_local`** — scenario = `single_veto` (canonical `RECORD_A` LIVE, sibling `RECORD_A` TOMBSTONED). Decision = `KeepLocal{RECORD_A_UUID}`. Post-commit block holds 1 record (live). Pure additive — scenario arm already wired by Vector 1. |
| [`4c4d572`](https://github.com/hherb/secretary/commit/4c4d572) | 16.4 | **`concurrent_one_tombstone_veto_accept_tombstone`** — same fixture, opposite decision: `AcceptTombstone{RECORD_A_UUID}` → no-op on the merge's tombstoned record. Adds optional `expected_canonical_record_tombstoned` JSON field + assertion arm — distinguishes `KeepLocal` (live, `false`) from `AcceptTombstone` (tombstoned, `true`) at the KAT level. Vector 3's entry gains the explicit `false` value for symmetry. |
| [`fb09d5f`](https://github.com/hherb/secretary/commit/fb09d5f) | 16.5 | **`concurrent_two_tombstone_vetoes_mixed_decisions`** — scenario = `two_veto`. Decisions = `[KeepLocal{A}, AcceptTombstone{B}]`. Post-commit canonical block holds 2 records (A live, B tombstoned). Per-record tombstone-flag distinction left to the Task-15 proptest `prop_commit_associative_under_disjoint_vetoes`; the KAT pins the multi-veto-mixed-decisions scenario shape only. |
| [`f97949c`](https://github.com/hherb/secretary/commit/f97949c) | 16.6 | **`prepare_merge_stale_hash_evidence_stale`** — third vector_type family `evidence_stale`. Drives the commit-time TOCTOU re-check by mutating the canonical manifest between `prepare_merge` (which captures `draft.manifest_hash`) and `commit_with_decisions` (which re-reads the envelope and re-hashes); asserts `SyncError::EvidenceStale` AND zero post-commit disk writes (manifest BLAKE3 byte-identical pre/post). New constant `RACING_DEVICE_UUID = [0x99; 16]` decouples the racing clock from the fixture helpers' private device-UUID constants. The matching integration test (`sync_merge.rs::commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes`) uses a simpler no-per-block-divergence fixture; this KAT widens coverage to the per-block-divergent fixture path. |
| [`08149f9`](https://github.com/hherb/secretary/commit/08149f9) | 16.7 | **`commit_block_fingerprint_mismatch_repair_via_reconverge`** — fourth vector_type family `fingerprint_repair`. Simulates a partial-commit post-condition by flipping a single byte in the canonical block file (manifest still references the OLD fingerprint; on-disk bytes hash to a different value); asserts `open_vault` fires `VaultError::BlockFingerprintMismatch` at open time via Task 5's eager `verify_block_fingerprints` step. Full recovery flow (idempotent reconvergence via re-running the three-step API) is exercised by `sync_merge_crash.rs::partial_commit_recovers_via_idempotent_re_run` (Task 14); this KAT pins the typed-error surface only. |

**Branch hygiene:** This session opened on `feature/c1-1b-task-16` (fresh branch from `43f1214` post-Task-15 main). Local branch carries exactly 7 new commits on top of `43f1214`.

**Gauntlet on `feature/c1-1b-task-16` after Task 16:**

- `cargo test --release --workspace --no-fail-fast` → **800 / 0 / 10** (unchanged from Task 15 baseline — `replay_sync_kat` is one `#[test]` that iterates all 16 vectors internally; the new vectors are absorbed into the existing test loop, matching the design doc's "7 KAT vectors absorbed" growth target).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed).

## (2) What's next — execute Task 17

### (a) First action next session: execute Task 17 (after PR for Task 16 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 17 — README + ROADMAP + NEXT_SESSION updates + final gauntlet + open PR**.

Task 17 closes the C.1.1b loop:
1. **README.md** — Update the Sub-project C row's status: C.1.1b ✅ (currently "C.1.1b will add merge + veto").
2. **ROADMAP.md** — Mark C.1.1b ✅ in the Sub-project C section (line 30); advance the progress bar one tick. Add a C.1.1b row under the C.1.1a row at line 165.
3. **NEXT_SESSION.md** baton — close the C.1.1b track and pivot to whatever's next (C.2 CLI? Another C.1 slice?).
4. **Handoff snapshot** under `docs/handoffs/`.
5. **Final gauntlet** — full workspace test + clippy + fmt + conformance + freshness, all clean.
6. **Open PR** for Task 17's docs commit.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 16's PR merges:
git fetch --prune origin
git checkout -b feature/c1-1b-task-17 origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 17"
```

### (b) Plan structure at a glance (1 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1-10~~ | ~~Tasks 1-10 shipped~~ ✅ in PRs #84-#97 |
| ~~11~~ | ~~`commit_with_decisions` + DraftMerge per-block + commit/ split + happy-path test~~ ✅ PR #99 |
| ~~12~~ | ~~`EvidenceStale` integration test~~ ✅ PR #102 |
| ~~13~~ | ~~Veto handling (KeepLocal / AcceptTombstone / Missing+Unknown bijection)~~ ✅ PR #104 |
| ~~14~~ | ~~Crash-recovery test (partial-write reconverge — D6 proof)~~ ✅ PR #106 |
| ~~15~~ | ~~4 property tests + helpers split~~ ✅ PR #107 |
| ~~16~~ | ~~7 KAT vectors + replay extension~~ ✅ this session (7 commits, PR pending) |
| **17** | **README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR** | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [x] `cargo test --release --workspace --no-fail-fast` → 766+ / 0 / 10 (currently 800 / 0 / 10 — well above the floor)
- [x] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [x] `cargo fmt --all -- --check` → clean
- [x] `uv run core/tests/python/conformance.py` → PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5 (KAT-pinned by Vector 7)
- [x] `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision` defined with zeroize discipline + module tests ✅ Task 6
- [x] `tombstone_veto_set` pure helper with 7 table tests ✅ Task 7
- [x] `prepare_merge` orchestrator wires decap + iterative fold + veto detection + post_merge_clock ✅ Task 8
- [x] `rewrite_block_with_records_and_update_manifest` helper exists; post-rewrite vault opens cleanly under D6 ✅ Task 9
- [x] `apply_decisions` pure helper enforces `vetoes ↔ decisions` bijection ✅ Task 10
- [x] `commit_with_decisions` re-opens vault, freshness-checks manifest hash, applies decisions, re-encrypts diverging blocks, atomic block-first manifest-last write ✅ Task 11
- [x] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes ✅ Task 12 (KAT-pinned by Vector 6)
- [x] **Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair — disk-side proof** ✅ Tasks 13.3 + 13.4
- [x] **`KeepLocal` and `AcceptTombstone` decisions persist correctly to disk** ✅ Tasks 13.1 + 13.2 (KAT-pinned by Vectors 3 + 4)
- [x] **Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit** ✅ Task 14 (typed-error surface KAT-pinned by Vector 7)
- [x] **All four merge-layer proptests pass (post-commit fixpoint, deterministic merge, decision-order independence, bijection enforcement)** ✅ Task 15
- [x] **All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — must not weaken.** Task 16 did not touch `core/src/vault/conflict.rs`. ✅
- [x] **7 new KAT vectors in `core/tests/data/sync_kat.json` (9 → 16); replay extended in `core/tests/sync_kat.rs` via tagged-enum dispatch over `vector_type`** ✅ Task 16
- [ ] **Task 17:** README + ROADMAP + NEXT_SESSION baton updates marking C.1.1b complete; final gauntlet; open C.1.1b cumulative PR. Also: grep every `#[allow(dead_code)]` introduced in Tasks 1-10 / 15 and confirm each has at least one real consumer in Tasks 11-16. `BLOCK_NONCE_G` + `fresh_vault_four_concurrent_manifests` still `#[allow(dead_code)]` — not consumed by Tasks 15 or 16. File as cleanup follow-ups if Task 17 doesn't claim them.

## (3) Open decisions and risks

### Implementer-call decisions from this session

- **Schema v1 → v2 bump.** The existing 9 clock-dispatch vectors gained explicit `"vector_type": "clock_dispatch"` and the new 7 vectors split across three new families (`concurrent_merge_apply_decisions`, `evidence_stale`, `fingerprint_repair`). Reviewer's call: confirm the tagged-enum shape (one struct per variant, `#[serde(flatten)]` for the common `name` field, `#[serde(tag = "vector_type")]` for variant dispatch). The current schema is friendly to additive extension (new vector_type variants append to the enum + dispatcher); breaking field rename within a variant would warrant a schema_version bump to 3.
- **Per-binary helper reuse vs duplication.** Vector 1 reused Task 15's `sync_merge_proptest_helpers/` from the `sync_kat` binary by adding `mod sync_merge_proptest_helpers;` at the binary's crate root. The module's docstring was extended to reflect dual-binary use; `#[allow(dead_code)]` annotations added to items the KAT binary doesn't consume (`PROPTEST_CASES`, `make_decision`). Vector 2 added a new helper `build_same_block_field_lww_no_veto_fixture` in the same shared module. Reviewer's call: confirm shared-helper reuse over a duplicate `sync_kat_helpers/` directory module — this baton's choice prefers shared (DRY) since the helpers are pure, generic, and currently exercised by both binaries.
- **`RACING_DEVICE_UUID = [0x99; 16]`.** The `evidence_stale` vector replaces the canonical manifest's clock with a single-entry `(RACING_DEVICE_UUID, racing_counter)`. Distinct from the fixture helpers' private `CANONICAL_DEVICE_UUID = [0x0A; 16]` / `SIBLING_DEVICE_UUID = [0x0B; 16]`. The decoupling means the KAT binary doesn't need to know the fixture's internal device UUID constants — any well-formed manifest with a different envelope hash forces `EvidenceStale`. The existing `commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes` integration test uses `device_canonical = [0x0A; 16]` with `counter = 99`; both approaches force the same typed error.
- **`expected_post_commit_canonical_records_count` + `expected_canonical_record_tombstoned` schema additions.** Both are `Option<…>` (default `None`). Adding new optional assertion fields is forward-compatible — vectors that don't set them skip the corresponding assertion. Vector 1 (initially shape-only) was retro-strengthened in Vector 2's commit with `expected_post_commit_canonical_records_count: 2`; Vector 3 was retro-strengthened in Vector 4's commit with `expected_canonical_record_tombstoned: false`. The pattern: when a new assertion field is introduced for a NEW vector, prior vectors of the same family may gain the field too if the value is non-ambiguous and forward-only.
- **Vector 5 omits per-record assertions.** The multi-record case (2 records post-merge, one live and one tombstoned) makes `expected_canonical_record_tombstoned` ambiguous (which record's tombstone flag?). A per-uuid-keyed assertion shape would carry more weight but adds JSON complexity; the proptest `prop_commit_associative_under_disjoint_vetoes` already covers per-record decision-application across both decision orderings. Decision: omit the field for Vector 5; the records-count assertion (= 2) + vetoes count (= 2) are enough KAT-level shape distinction.
- **`fingerprint_repair` KAT pins typed-error surface only.** The full recovery flow (idempotent reconvergence via re-running the three-step API on a partial-commit fixture) is the integration test `sync_merge_crash.rs::partial_commit_recovers_via_idempotent_re_run` (Task 14, 327 LOC test body); the KAT pins only the `VaultError::BlockFingerprintMismatch` open-time surface. Doubling the integration test's coverage in JSON would be 100+ LOC of dispatcher code with no semantic gain.

### Carry-over from earlier PRs (still live)

- **PR #99 in-PR refactor (`1193072`)** — `MANIFEST_FILENAME` consolidation already merged.
- **PRs #102, #104, #106, #107** — already merged.
- **Implementer-call decisions from Task 12/13/14/15 batons still live:**
  - #1 `commit_with_decisions` identity argument: stays `&SecretBytes`, re-opens internally.
  - #2 `DraftMerge.per_block_clocks` + `per_block_records` shape: frozen, no change this session.
  - #3 `extract_vault_uuid` helper duplication: closed in PR #104 (`63b32a7`).
  - #4 `sync_helpers/mod.rs` file size: still 1174 LOC, unchanged this session. Track via [#95](https://github.com/hherb/secretary/issues/95).
  - #5 `commit/` directory split (PR #99): no change this session — Task 16 is tests-only, didn't touch `commit/write.rs`.
  - #6 `prepare.rs` file size (~890 LOC post-Task-13): unchanged this session.
  - #7 `sync_merge_vetoes.rs` is a new test binary (Task 13): no change this session.
  - #8 `sync_merge_crash.rs` is a new test binary (Task 14): no change this session.
  - #9 `sync_merge_proptest.rs` + `sync_merge_proptest_helpers/` (Task 15): the helpers module now serves both proptest and sync_kat binaries (`#[allow(dead_code)]` annotations added in Vector 1's commit).

### Implementer's-call decisions (live for Task 17)

1. **`commit_with_decisions` identity argument.** Unchanged.
2. **`DraftMerge` shape.** Unchanged.
3. **Veto-pass iteration source.** Unchanged from Task 13.1.
4. **`sync_helpers/mod.rs` file size.** 1174 LOC. Past the 800 trigger but [#95](https://github.com/hherb/secretary/issues/95) stays the umbrella for the split refactor.
5. **`commit/` directory split.** Unchanged.
6. **`prepare.rs` file size.** ~890 LOC. Still in the "tracking issue at C.1.1b close" bucket.
7. **New test binaries per concern.** Pattern continues — Task 14 = `sync_merge_crash.rs`, Task 15 = `sync_merge_proptest.rs` (+ `sync_merge_proptest_helpers/`), Task 16 extends existing `sync_kat.rs` per the plan (no new binary).
8. **Property file LOC ceiling.** Confirmed in Task 15. Carried forward.
9. **`sync_kat.rs` file size.** ~290 LOC post-Task-16 (was 117 pre-Task-16). Comfortably under the 500-LOC cap; no split needed.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — unchanged this session (no production code touched).
- **AEAD nonce per rewrite** — unchanged. Vector 6's racing manifest uses `SIBLING_NONCE_C` (distinct from canonical's `CANONICAL_NONCE_A`); the helpers' nonce discipline holds.
- **`tempfile` exact pin** (`=3.27.0`) — unchanged this session.
- **CRDT proptests must not weaken** — Task 16's tests do NOT touch `core/src/vault/conflict.rs`. Confirmed via gauntlet: 4 conflict proptests still pass.
- **`SyncOutcome::ConcurrentDetected` is large** — unchanged.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — no new core variants this session.
- **File size of `core/src/sync/commit/write.rs`** — 389 LOC (unchanged). Task 16 is tests-only.
- **File size of `core/src/sync/prepare.rs`** — ~890 LOC (unchanged this session).
- **File size of `core/tests/sync_helpers/mod.rs`** — 1174 LOC. See [#95](https://github.com/hherb/secretary/issues/95).
- **File size of `core/tests/sync_merge_vetoes.rs`** — 499 LOC (unchanged this session).
- **File size of `core/tests/sync_merge_crash.rs`** — 327 LOC (unchanged this session).
- **File size of `core/tests/sync_merge_proptest.rs`** — 391 LOC (unchanged this session).
- **File size of `core/tests/sync_merge_proptest_helpers/mod.rs`** — ~430 LOC post-Task-16 (was 370 LOC post-Task-15, +60 LOC for `build_same_block_field_lww_no_veto_fixture`). Comfortable margin.
- **File size of `core/tests/sync_kat.rs`** — ~290 LOC post-Task-16 (was 117 LOC pre-Task-16). Comfortable margin.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 LOC (unchanged). Pre-existing.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion at Task 17.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's 7 new vectors join when #76 lands. The current Rust-side replay carries the scenario-name + expected-outcome shape; Python will either re-encode the scenarios in code (option B), or the schema bumps to v3 with fully self-describing fixture parameters (option A). Choice deferred to #76.
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures.
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies.
- **[#95](https://github.com/hherb/secretary/issues/95)** — split `core/tests/sync_helpers/mod.rs`.
- **[#98](https://github.com/hherb/secretary/issues/98)** — `apply_decisions` duplicate-decision tightening.
- **[#103](https://github.com/hherb/secretary/issues/103)** — Task 12 follow-on: EvidenceStale abort beats step 5's per-block rewrites on a divergence-bearing fixture. Vector 6 partially exercises this (per-block-divergent fixture → EvidenceStale aborts cleanly with no disk writes); #103 may be closeable at Task 17 review.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-task-16` carries 7 commits + this baton commit on top of `43f1214`. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-task-16 (this session's branch)
git log --oneline -10                                           # last 10: baton + 7 task commits + main HEAD

# Baseline gauntlet (expect 800 / 0 / 10 on this branch BEFORE Task 17 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 16's PR merges, switch to a fresh task branch + open the plan for Task 17:
git fetch --prune origin
git checkout -b feature/c1-1b-task-17 origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 17"
```

## Closing inventory

- **Branch state on close:** `main` at `43f1214` (PR #107 squash-merged Task 15). `feature/c1-1b-task-16` carries 7 new commits on top of `43f1214` (7 vector commits) + this baton commit.
- **Workspace tests on `feature/c1-1b-task-16`:** 800 passed + 10 ignored (no growth from new `#[test]` functions — the 7 vectors absorb into the existing `replay_sync_kat` iteration). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95) / [#98](https://github.com/hherb/secretary/issues/98) / [#103](https://github.com/hherb/secretary/issues/103).
- **Open PRs:** one to be opened at end of this session covering Task 16.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge` (this session's branch lives in the same worktree directory — branch name decoupled from path).
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close.
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle.
  - [`docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md) — Task 4 close.
  - [`docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md) — Task 5 close.
  - [`docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md) — Task 6 close.
  - [`docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md) — Task 7 close.
  - [`docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md) — Task 8 close.
  - [`docs/handoffs/2026-05-19-c1-1b-task-9-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-9-shipped.md) — Task 9 close.
  - [`docs/handoffs/2026-05-19-c1-1b-task-10-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-10-shipped.md) — Task 10 close.
  - [`docs/handoffs/2026-05-20-c1-1b-task-11-shipped.md`](docs/handoffs/2026-05-20-c1-1b-task-11-shipped.md) — Task 11 close.
  - [`docs/handoffs/2026-05-20-c1-1b-task-12-shipped.md`](docs/handoffs/2026-05-20-c1-1b-task-12-shipped.md) — Task 12 close.
  - [`docs/handoffs/2026-05-21-c1-1b-task-13-shipped.md`](docs/handoffs/2026-05-21-c1-1b-task-13-shipped.md) — Task 13 close.
  - [`docs/handoffs/2026-05-22-c1-1b-task-14-shipped.md`](docs/handoffs/2026-05-22-c1-1b-task-14-shipped.md) — Task 14 close.
  - [`docs/handoffs/2026-05-22-c1-1b-task-15-shipped.md`](docs/handoffs/2026-05-22-c1-1b-task-15-shipped.md) — Task 15 close.
  - [`docs/handoffs/2026-05-23-c1-1b-task-16-shipped.md`](docs/handoffs/2026-05-23-c1-1b-task-16-shipped.md) — Task 16 close (this session).
