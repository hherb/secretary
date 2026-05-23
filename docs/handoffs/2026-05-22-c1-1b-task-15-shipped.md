# NEXT_SESSION.md

**Session date:** 2026-05-22 (implementation session — C.1.1b Task 15 of 17 shipped; four `proptest` properties for the merge layer + helpers extraction).
**Status:** PR to be opened. `feature/c1-1b-task-15` carries 5 commits on top of `66ca7d9` (post-Task-14 main) — 4 per-property TDD commits + 1 file-split refactor. 2 tasks remain (16-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`a099749`](https://github.com/hherb/secretary/commit/a099749) | 15 prop 1 | **`prop_commit_then_sync_once_yields_nothing_to_do`** — post-commit fixpoint property. Inputs: canonical + sibling manifest-clock counters via `counter_canonical in 1..1000`, `counter_sibling in 1..1000`. Fixture: per-block-divergent vault with disjoint record UUIDs (no vetoes). Asserts the next `sync_once` after `commit_with_decisions(..., decisions = [])` returns `SyncOutcome::NothingToDo`, proving the commit's `post_merge_clock` is consistent across the returned `SyncState` and the on-disk manifest (so `clock_relation` sees `Equal`). Per-property cap: 16 cases. File initially scaffolded with all four properties' fixture-builder constants + helpers in place (annotated `#[allow(dead_code)]` for items consumed by later props). |
| [`2ae0933`](https://github.com/hherb/secretary/commit/2ae0933) | 15 prop 2 | **`prop_three_step_idempotent_on_repeated_invocation`** — deterministic-merge property. Builds two independent vaults with identical fixture parameters; runs the three-step `sync_once → prepare_merge → commit_with_decisions` on each; asserts: (a) same returned `SyncState`, (b) same decrypted canonical block records, (c) DIFFERENT envelope bytes (AEAD nonces from OsRng per rewrite). The (a)+(b) pair is the idempotence claim; (c) pins the AEAD-nonce-per-rewrite contract at the property level across a different dimension than the crash-recovery integration test's same-vault retry coverage. |
| [`5e51607`](https://github.com/hherb/secretary/commit/5e51607) | 15 prop 3 | **`prop_commit_associative_under_disjoint_vetoes`** — decision-order independence. Builds two equivalent two-veto fixtures; one commits with decisions `[d_a, d_b]`, the other with `[d_b, d_a]`. Asserts same returned `SyncState` AND same decrypted canonical block records. Pins commutativity of `apply_decisions`'s per-decision iteration over the full decision set. Inputs: clock counters + two booleans (`keep_local_a`, `keep_local_b`) covering all four (KeepLocal, AcceptTombstone) × (KeepLocal, AcceptTombstone) pairings. |
| [`bcbcc7b`](https://github.com/hherb/secretary/commit/bcbcc7b) | 15 prop 4 | **`prop_decision_bijection_enforced`** — Missing/Unknown/Ok branch coverage. For a single-veto fixture, constructs decisions from random `(include_match: bool, strays: Vec<u8 != 0xAA>)` and asserts: (a) `!include_match` → `MissingVetoDecision { record_id: RECORD_A_UUID }` (regardless of strays — Missing checked before Unknown); (b) `include_match && !strays.is_empty()` → `UnknownVetoDecision { record_id: [min(strays); 16] }`; (c) `include_match && strays.is_empty()` → `Ok(_)`. Strays exclude `0xAA` via `prop_filter` so they can't coincidentally collapse into the matching `RECORD_A_UUID` via the bijection's set-based dedupe. |
| [`5749158`](https://github.com/hherb/secretary/commit/5749158) | 15 refactor | **`sync_merge_proptest_helpers/mod.rs` split.** All-four-properties file landed at 780 LOC — well over the project's 500-LOC soft cap (per `feedback_split_files_proactively`). Extracted fixture constants, record builders (`live_record`, `tombstoned_record`), fixture builders (`build_no_veto_fixture`, `build_single_veto_fixture`, `build_two_veto_fixture`), `make_decision`, `open_identity`, `drive_sync_once_concurrent`, and `read_canonical_block_records` into a sibling module. Final sizes: `sync_merge_proptest.rs` 391 LOC (four `proptest!` blocks + per-property docstrings only), `sync_merge_proptest_helpers/mod.rs` 370 LOC. Both comfortably under the cap. No behavioural change; gauntlet identical pre / post. |

**Branch hygiene:** This session opened on `feature/c1-1b-task-15` (fresh branch from `66ca7d9` post-Task-14 main), leaving the prior session's `feature/c1-1b-sync-merge` branch untouched on disk (user preference at session start — see implementer-call below). Local branch carries exactly 5 new commits on top of `66ca7d9`.

**Gauntlet on `feature/c1-1b-task-15` after Task 15 + refactor:**

- `cargo test --release --workspace --no-fail-fast` → **795 / 0 / 10** (786 baseline at `66ca7d9` + 4 new proptests + 5 helper_tests cross-binary re-runs from the new `sync_merge_proptest` binary = 9).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed).

## (2) What's next — execute Task 16

### (a) First action next session: execute Task 16 (after PR for Task 15 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 16 — KAT vectors**. Seven new vectors in `core/tests/data/sync_kat.json` (9 → 16) with replay-dispatch extensions in `core/tests/sync_kat.rs`:

1. `concurrent_disjoint_blocks_no_vetoes_applied`
2. `concurrent_same_block_field_lww_no_vetoes`
3. `concurrent_one_tombstone_veto_keep_local`
4. `concurrent_one_tombstone_veto_accept_tombstone`
5. `concurrent_two_tombstone_vetoes_mixed_decisions`
6. `prepare_merge_stale_hash_evidence_stale`
7. `commit_block_fingerprint_mismatch_repair_via_reconverge`

Per `feedback_stay_in_inner_loop`, keep the one-vector-one-commit cadence — seven commits.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 15's PR merges:
git fetch --prune origin
# Choose: reset the existing branch, OR (as this session did) branch a fresh
# feature/c1-1b-task-16 from origin/main. The latter avoids the destructive
# reset and keeps prior task branches available for backreference.
git checkout -b feature/c1-1b-task-16 origin/main
# THEN open the plan:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 16"
```

### (b) Plan structure at a glance (2 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1-10~~ | ~~Tasks 1-10 shipped~~ ✅ in PRs #84-#97 |
| ~~11~~ | ~~`commit_with_decisions` + DraftMerge per-block + commit/ split + happy-path test~~ ✅ PR #99 |
| ~~12~~ | ~~`EvidenceStale` integration test~~ ✅ PR #102 |
| ~~13~~ | ~~Veto handling (KeepLocal / AcceptTombstone / Missing+Unknown bijection)~~ ✅ PR #104 |
| ~~14~~ | ~~Crash-recovery test (partial-write reconverge — D6 proof)~~ ✅ PR #106 |
| ~~15~~ | ~~4 property tests + helpers split~~ ✅ this session (5 commits, PR pending) |
| **16** | **7 KAT vectors + replay extension** | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [x] `cargo test --release --workspace --no-fail-fast` → 766+ / 0 / 10 (currently 795 / 0 / 10 — well above the floor)
- [x] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [x] `cargo fmt --all -- --check` → clean
- [x] `uv run core/tests/python/conformance.py` → PASS
- [x] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5
- [x] `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision` defined with zeroize discipline + module tests ✅ Task 6
- [x] `tombstone_veto_set` pure helper with 7 table tests ✅ Task 7
- [x] `prepare_merge` orchestrator wires decap + iterative fold + veto detection + post_merge_clock ✅ Task 8
- [x] `rewrite_block_with_records_and_update_manifest` helper exists; post-rewrite vault opens cleanly under D6 ✅ Task 9
- [x] `apply_decisions` pure helper enforces `vetoes ↔ decisions` bijection ✅ Task 10
- [x] `commit_with_decisions` re-opens vault, freshness-checks manifest hash, applies decisions, re-encrypts diverging blocks, atomic block-first manifest-last write ✅ Task 11
- [x] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes ✅ Task 12
- [x] **Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair — disk-side proof** ✅ Tasks 13.3 + 13.4
- [x] **`KeepLocal` and `AcceptTombstone` decisions persist correctly to disk** ✅ Tasks 13.1 + 13.2
- [x] **Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit** ✅ Task 14
- [x] **All four merge-layer proptests pass (post-commit fixpoint, deterministic merge, decision-order independence, bijection enforcement)** ✅ Task 15
- [x] **All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — must not weaken.** Task 15 did not touch `core/src/vault/conflict.rs`. ✅
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-10 and confirm each has at least one real consumer in Tasks 11-16. `BLOCK_NONCE_G` + `fresh_vault_four_concurrent_manifests` remain `#[allow(dead_code)]` — neither consumed by Task 15. Task 16 KAT vectors may consume them; if not, file them as cleanup follow-ups.

## (3) Open decisions and risks

### Implementer-call decisions from this session

- **Fresh branch vs reset.** Per `feedback_worktree_location`, the user prefers project-local `.worktrees/` and worktree-per-feature. The prior session's `feature/c1-1b-sync-merge` carried 2 local commits (Task 14 work) that were squash-merged into main as PR #106 — the natural reset is `git reset --hard origin/main`. User chose "fresh branch instead" (auto-mode classifier blocked the `--hard` reset; user authorised the new-branch path). Result: `feature/c1-1b-task-15` is a fresh branch from `66ca7d9`. The prior `feature/c1-1b-sync-merge` branch remains on disk pointing at the (now-squash-merged) Task 14 commits — harmless but worth pruning at the end of C.1.1b if no longer needed.
- **Helpers split into a sibling module.** The four-properties-in-one-file approach landed at 780 LOC. Per `feedback_split_files_proactively`, that's well over the 500-LOC soft cap. The refactor commit moves fixture/driver helpers into `core/tests/sync_merge_proptest_helpers/mod.rs` (a sibling test-module, mirroring the `core/tests/sync_helpers/` pattern). Reviewer: confirm the split shape — fixture builders + drivers in helpers; the proptest file holds only the four `proptest!` blocks + per-property docstrings.
- **Property 4's stray-UUID exclusion.** Random stray UUIDs are built as `[seed; 16]` from `u8` seeds. To prevent a stray from coincidentally landing on `RECORD_A_UUID = [0xAA; 16]` (which would collapse into the matching decision via the bijection's set-based dedupe), the `prop_filter` excludes `seed == 0xAA`. This is the natural way to keep the property's distinction between "matching" and "stray" decisions unambiguous; an alternative (allow the collision and special-case the outcome) would muddle the assertion logic.
- **Cap of 16 cases per property.** Each case opens a vault (Argon2) + encrypts 2 blocks + signs 2 manifests + runs at least one commit (re-encrypt + re-sign). 16 cases keeps the whole file under ~6 seconds. Props 2 + 3 build TWO fixtures per case but still come in well under the budget. Higher cap would not surface much additional coverage — the meaningful dimensions (clock counters, decision kinds, stray seeds) are well-explored at 16.

### Carry-over from earlier PRs (still live)

- **PR #99 in-PR refactor (`1193072`)** — `MANIFEST_FILENAME` consolidation already merged.
- **PRs #102, #104, #106** — already merged.
- **Implementer-call decisions from Task 12/13/14 batons still live:**
  - #1 `commit_with_decisions` identity argument: stays `&SecretBytes`, re-opens internally.
  - #2 `DraftMerge.per_block_clocks` + `per_block_records` shape: frozen, no change this session.
  - #3 `extract_vault_uuid` helper duplication: closed in PR #104 (`63b32a7`).
  - #4 `sync_helpers/mod.rs` file size: still 1174 LOC, unchanged this session. Track via [#95](https://github.com/hherb/secretary/issues/95).
  - #5 `commit/` directory split (PR #99): no change this session — Task 15 is tests-only, didn't touch `commit/write.rs`.
  - #6 `prepare.rs` file size (~890 LOC post-Task-13): unchanged this session.
  - #7 `sync_merge_vetoes.rs` is a new test binary (Task 13): no change this session.
  - #8 `sync_merge_crash.rs` is a new test binary (Task 14): no change this session.

### Implementer's-call decisions (live for Task 16)

1. **`commit_with_decisions` identity argument.** Unchanged.
2. **`DraftMerge` shape.** Unchanged.
3. **Veto-pass iteration source.** Unchanged from Task 13.1.
4. **`sync_helpers/mod.rs` file size.** 1174 LOC. Past the 800 trigger but [#95](https://github.com/hherb/secretary/issues/95) stays the umbrella for the split refactor.
5. **`commit/` directory split.** Unchanged.
6. **`prepare.rs` file size.** ~890 LOC. Still in the "tracking issue at C.1.1b close" bucket.
7. **New test binaries per concern.** Pattern continues — Task 14 = `sync_merge_crash.rs`, Task 15 = `sync_merge_proptest.rs` (+ `sync_merge_proptest_helpers/`). Task 16 (KAT) extends existing `sync_kat.rs` per the plan.
8. **Property file LOC ceiling.** Reviewer's call: confirm `sync_merge_proptest_helpers/` split as the right shape, or consolidate the helpers into the existing `sync_helpers/` module instead. This baton's choice prefers the per-binary helpers (matches the pattern of `conformance_kat_helpers/` next to `conformance_kat.rs`) because the proptest fixture builders carry proptest-specific defaults that wouldn't generalise to the integration tests.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — unchanged this session (no production code touched).
- **AEAD nonce per rewrite** — Property 2 now covers this contract at the proptest level across two-independent-vault dimension. The integration test in `sync_merge_crash.rs` covers the same contract across two-commits-on-same-vault dimension. Both still pass; deterministic-nonce regression would fire on either.
- **`tempfile` exact pin** (`=3.27.0`) — unchanged this session.
- **CRDT proptests must not weaken** — Task 15's tests do NOT touch `core/src/vault/conflict.rs`. Confirmed via gauntlet: 4 conflict proptests still pass.
- **`SyncOutcome::ConcurrentDetected` is large** — unchanged.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — no new core variants this session.
- **File size of `core/src/sync/commit/write.rs`** — 389 LOC (unchanged). Task 15 is tests-only.
- **File size of `core/src/sync/prepare.rs`** — ~890 LOC (unchanged this session).
- **File size of `core/tests/sync_helpers/mod.rs`** — 1174 LOC. See [#95](https://github.com/hherb/secretary/issues/95).
- **File size of `core/tests/sync_merge_vetoes.rs`** — 499 LOC (unchanged this session).
- **File size of `core/tests/sync_merge_crash.rs`** — 327 LOC (unchanged this session).
- **File size of `core/tests/sync_merge_proptest.rs`** — 391 LOC (new this session, post-split). Comfortable margin.
- **File size of `core/tests/sync_merge_proptest_helpers/mod.rs`** — 370 LOC (new this session). Comfortable margin.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 LOC (unchanged). Pre-existing.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands.
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures.
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies.
- **[#95](https://github.com/hherb/secretary/issues/95)** — split `core/tests/sync_helpers/mod.rs`.
- **[#98](https://github.com/hherb/secretary/issues/98)** — `apply_decisions` duplicate-decision tightening.
- **[#103](https://github.com/hherb/secretary/issues/103)** — Task 12 follow-on: EvidenceStale abort beats step 5's per-block rewrites on a divergence-bearing fixture. Could roll into Task 16's KATs.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-task-15` carries 5 commits on top of `66ca7d9`. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-task-15 (this session's branch)
git log --oneline -8                                            # last 8: baton + 5 task commits + main HEAD

# Baseline gauntlet (expect 795 / 0 / 10 on this branch BEFORE Task 16 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 15's PR merges, switch to a fresh task branch + open the plan for Task 16:
git fetch --prune origin
git checkout -b feature/c1-1b-task-16 origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 16"
```

## Closing inventory

- **Branch state on close:** `main` at `66ca7d9` (PR #106 squash-merged Task 14). `feature/c1-1b-task-15` carries 5 new commits on top of `66ca7d9` (4 prop commits + 1 refactor commit) + this baton commit.
- **Workspace tests on `feature/c1-1b-task-15`:** 795 passed + 10 ignored. Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95) / [#98](https://github.com/hherb/secretary/issues/98) / [#103](https://github.com/hherb/secretary/issues/103).
- **Open PRs:** one to be opened at end of this session covering Task 15.
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
  - [`docs/handoffs/2026-05-22-c1-1b-task-15-shipped.md`](docs/handoffs/2026-05-22-c1-1b-task-15-shipped.md) — Task 15 close (this session).
