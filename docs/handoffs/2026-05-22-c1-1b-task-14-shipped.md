# NEXT_SESSION.md

**Session date:** 2026-05-22 (implementation session — C.1.1b Task 14 of 17 shipped; partial-commit crash-recovery via CRDT-idempotent re-run, the D6 / option (d) proof).
**Status:** PR to be opened. `feature/c1-1b-sync-merge` carries 1 commit on top of `8a23f3c` (post-Task-13 main) — a single new test file. 3 tasks remain (15-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`4c3814c`](https://github.com/hherb/secretary/commit/4c3814c) | 14 | **`core/tests/sync_merge_crash.rs::partial_commit_recovers_via_idempotent_re_run`** — the D6 / option (d) crash-recovery proof. Builds a per-block-divergent fixture via `fresh_vault_two_concurrent_blocks` with NON-conflicting records (`[0xAA; 16]` canonical, `[0xBB; 16]` sibling), so the merge produces a clean union with no vetoes — `commit_with_decisions(..., vec![])` succeeds. Flow: (1) capture pre-commit canonical block bytes `b_v0` + manifest bytes `m_v0`; (2) drive `sync_once → prepare_merge → commit_with_decisions` → `state_v1`; (3) capture `b_v1` / `m_v1` / `records_v1`; (4) simulate the crash by rolling the manifest BACK to `m_v0` while leaving the block at `b_v1` — exactly the disk shape produced by a crash between step 5 (per-block re-encrypts) and step 7 (manifest write); (5) assert `open_vault` errs with `VaultError::BlockFingerprintMismatch` naming the rewritten `block_uuid`; (6) recovery — restore the canonical block to `b_v0`; (7) re-run `sync_once → prepare_merge → commit_with_decisions` with the PRE-COMMIT `state_pre` (the caller never persisted `state_v1` because the commit crashed before returning); (8) assert `state_v2 == state_v1` (post-merge vector clocks deterministic in the inputs); (9) assert `records_v2 == records_v1` (merged record set deterministic in the inputs; AEAD nonces differ but plaintext matches); (10) assert `open_vault` succeeds on the recovered vault. **Test non-vacuity verified by perturbation:** commenting out step 6's block-rollback causes the v2 commit to fail with `Vault(BlockFingerprintMismatch { ... })` — exactly the failure mode the recovery prevents. **New test binary:** `sync_merge_crash.rs` rather than extending `sync_merge_vetoes.rs` (already 499 LOC post-Task-13) because crash recovery is a distinct concern from veto handling. File LOC: 313. Test count: 780 → 786 (+1 new + 5 helper_tests cross-binary re-runs in the new test binary). |

**Branch hygiene:** Session opened on `feature/c1-1b-sync-merge` carrying Task 13's 6 commits + baton + 1 review-fix commit (`01d8561` — the smoke-test tightening that landed in PR #104). Per the previous baton's instructions, reset to `origin/main` (`8a23f3c` post-Task-13) at session start. Local branch now carries exactly 1 new commit on top of `8a23f3c`.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 14:**

- `cargo test --release --workspace --no-fail-fast` → **786 / 0 / 10** (780 baseline at `8a23f3c` + 1 new partial-commit-recovery test + 5 helper_tests cross-binary re-runs from the new `sync_merge_crash` binary = 6).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed; the C.1.1b plan + design docs sit outside the script's corpus).

## (2) What's next — execute Task 15

### (a) First action next session: execute Task 15 (after PR for Task 14 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 15 — Property tests**. Four `proptest` properties for the merge layer per the design doc's §"Property tests":

1. **Determinism** — same inputs → same outputs across N runs.
2. **Idempotence** — `merge(a, b) == merge(a, merge(a, b))` at the prepare_merge / commit_with_decisions surface.
3. **Veto bijection well-formedness** — every (vetoes, decisions) bijection produces a typed-error-free commit, every non-bijection produces a typed error.
4. **No data loss without a veto** — every record present in canonical OR sibling appears in the merged output, modulo tombstones-by-clock.

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 15 is property tests in a single file; one commit + one baton commit is the natural shape.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 14's PR merges:
git fetch --prune origin
git reset --hard origin/main                                    # discard merged commits
# THEN open the plan:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 15"
```

### (b) Plan structure at a glance (3 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1-10~~ | ~~Tasks 1-10 shipped~~ ✅ in PRs #84-#97 |
| ~~11~~ | ~~`commit_with_decisions` + DraftMerge per-block + commit/ split + happy-path test~~ ✅ PR #99 (`52093aa`) |
| ~~12~~ | ~~`EvidenceStale` integration test (manifest-hash freshness)~~ ✅ PR #102 (`324c4cb`) |
| ~~13~~ | ~~`fresh_vault_two_concurrent_blocks` helper + 4 veto integration tests + `prepare_merge` veto-pass bug fix~~ ✅ PR #104 (`8a23f3c`) |
| ~~14~~ | ~~Crash-recovery test (partial-write reconverge — D6 proof)~~ ✅ this session (1 commit, PR pending) |
| **15** | **4 property tests** | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [x] `cargo test --release --workspace --no-fail-fast` → 766+ / 0 / 10 (currently 786 / 0 / 10 — well above the floor)
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
- [x] **`prepare_merge`'s veto pass actually fires on per-block-divergent fixtures (was unreachable pre-Task-13.1)** ✅ Task 13.1
- [x] **Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit** ✅ Task 14
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken** (Task 15 adds the merge-layer proptests; Task 14 did not touch `core/src/vault/conflict.rs`)
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-10 and confirm each has at least one real consumer in Tasks 11-16. `BLOCK_NONCE_G` + `SIBLING_NONCE_D` + `fresh_vault_four_concurrent_manifests` remain `#[allow(dead_code)]` — none consumed by Task 14 (single test, single fixture call). Task 15's proptests may consume them.

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **Test binary placement.** Plan §Task 14 cites "Modify: `core/tests/sync_merge.rs` (add 1 test)" but the actual home is the new `core/tests/sync_merge_crash.rs`. Two reasons: (a) `sync_merge.rs` is already at ~500 LOC post-Task-12 and the previous baton's implementer-call #7 left the choice "extend `sync_merge_vetoes.rs` OR open `sync_merge_crash.rs`" open for Task 14's PR-open call; (b) `sync_merge_vetoes.rs` is at 499 LOC post-Task-13.4 — close to the 500 cap, and crash recovery is a distinct concern from veto handling. New binary keeps single-responsibility per file. Reviewer: this is the chosen resolution of the deferred decision; LOC of new file is 313.
- **Non-conflicting record fixture.** Plan §Task 14 step 1 says "reuse Task 13's `fresh_vault_two_concurrent_blocks`", but Task 13's invocation pairs the SAME record UUID on canonical + sibling (LIVE vs TOMBSTONED) to drive a veto. Task 14's test uses distinct UUIDs (`[0xAA]` canonical, `[0xBB]` sibling) so the merge is a clean union with no vetoes — `decisions = vec![]`. Rationale: the property under test is "the commit's block-write happened-before manifest-write contract enables crash recovery via idempotent re-run", NOT "the veto path survives a crash". A non-veto fixture keeps the test minimal and the failure mode (BlockFingerprintMismatch) unambiguous. Reviewer: confirm this scoping; a follow-up Task 14b could repeat the proof with a veto-bearing fixture if reviewers see value.
- **Recovery strategy.** Plan §Task 14 step 7 says "Re-run sync_once → prepare_merge → commit_with_decisions" but does not explicitly say what to do about the crashed-block state first. The test treats recovery as a two-step operator procedure: (a) detect via `BlockFingerprintMismatch`; (b) roll back the affected block to its last-known-good bytes (using whatever backup/snapshot mechanism the platform provides — out of scope for the test, which just calls `std::fs::write`). The plan's "CRDT idempotence guarantees the retried convergence reaches the same final state" then applies once the rollback brings the vault back to a consistent state. Reviewer: confirm this matches the intended D6 recovery story; if the design expects an automatic forward-roll (e.g. re-derive the manifest from the new block bytes), the test scoping needs to widen.

### Carry-over from earlier PRs (still live)

- **`apply_decisions` is `pub(crate)`, not `pub`.** Unchanged this session.
- **PR #99 in-PR refactor (`1193072`)** — `MANIFEST_FILENAME` consolidation already merged.
- **PR #102 (Task 12)** — already merged.
- **PR #104 (Task 13)** — already merged (this session opened on top of it).
- **Implementer-call decisions from Task 12/13 baton still live:**
  - #1 `commit_with_decisions` identity argument: stays `&SecretBytes`, re-opens internally.
  - #2 `DraftMerge.per_block_clocks` + `per_block_records` shape: frozen, no change this session.
  - #3 `extract_vault_uuid` helper duplication: closed in PR #104 (`63b32a7`).
  - #4 `sync_helpers/mod.rs` file size: still open at 1174 LOC (was 1115 at start of this session — the +59 came from Task 13's review-fix commit `01d8561`, not this session). Track via [#95](https://github.com/hherb/secretary/issues/95).
  - #5 `commit/` directory split (PR #99): no change this session — Task 14 is tests-only, didn't grow `write.rs`.
  - #6 `prepare.rs` file size (~890 LOC post-Task-13): unchanged this session. Still pre-existing growth; file a tracking issue at C.1.1b close (Task 17), or split as a standalone refactor if Tasks 15-16 push it further.
  - #7 `sync_merge_vetoes.rs` is a new test binary: resolved this session by adding ANOTHER new binary (`sync_merge_crash.rs`) for Task 14 rather than extending vetoes. The single-responsibility-per-binary pattern is now the convention for new test binaries in this surface.

### Implementer's-call decisions (live for Tasks 15-16)

1. **`commit_with_decisions` identity argument.** Unchanged from earlier batons (`&SecretBytes`).
2. **`DraftMerge` shape.** Unchanged.
3. **Veto-pass iteration source.** Resolved in Task 13.1: walk `canonical_pt.records`, not `acc_records`. If Task 15's proptests add cases where the canonical's record is tombstoned but a peer LIVE record contests the tombstone, the current code's `canonical_rec.tombstone → continue` is the right call (no veto needed because LWW already wins).
4. **`sync_helpers/mod.rs` file size.** 1174 LOC. Past the 800 trigger but [#95](https://github.com/hherb/secretary/issues/95) stays the umbrella for the split refactor.
5. **`commit/` directory split.** Unchanged.
6. **`prepare.rs` file size.** ~890 LOC. Still in the "tracking issue at C.1.1b close" bucket — no urgency from Task 14.
7. **New test binaries per concern.** Pattern: Task 13 = `sync_merge_vetoes.rs`, Task 14 = `sync_merge_crash.rs`. Task 15 (proptests) goes in `sync_merge_proptest.rs` per the plan. Task 16 (KAT) reuses existing `sync_kat.rs` per the plan.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6 + Task 11 extension; unchanged this session.
- **AEAD nonce per rewrite** — Task 14 exercises the rewrite path TWICE (v1 commit + v2 commit on the same vault). `OsRng` drives both, so each commit produces a fresh nonce. The test relies on `assert_ne!(b_v0, b_v1)` to catch a regression where two commits in close succession share a nonce; today this passes (AEAD nonces are 24 bytes of OsRng output, collision probability negligible).
- **`tempfile` exact pin** (`=3.27.0`) — unchanged this session.
- **CRDT proptests must not weaken** — Task 14's test does not touch `core/src/vault/conflict.rs`. Confirmed via gauntlet: 4 conflict proptests still pass.
- **`SyncOutcome::ConcurrentDetected` is large** — unchanged.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — no new core variants this session.
- **File size of `core/src/sync/commit/write.rs`** — 389 LOC (unchanged). Task 14 is tests-only.
- **File size of `core/src/sync/prepare.rs`** — ~890 LOC (unchanged this session). See [#95](https://github.com/hherb/secretary/issues/95)'s pattern.
- **File size of `core/tests/sync_helpers/mod.rs`** — 1174 LOC. See [#95](https://github.com/hherb/secretary/issues/95).
- **File size of `core/tests/sync_merge_vetoes.rs`** — 499 LOC (unchanged this session; Task 14 went into a new file).
- **File size of `core/tests/sync_merge_crash.rs`** — 313 LOC (new this session). Comfortable margin.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 LOC (unchanged). Pre-existing.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. Not consumed by Task 14's crash test.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands.
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 14's crash-recovery fixture may close some of #78 as a side effect — worth re-checking on Task 14 PR merge.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors. Not directly C.1.1b.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. C.4 doc pass.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader. Refactor follow-up.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures.
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies. Cross-crate scope.
- **[#95](https://github.com/hherb/secretary/issues/95)** — split `core/tests/sync_helpers/mod.rs`. Now 1174 LOC; will revisit at Task 17 or as standalone refactor BEFORE Task 15.
- **[#98](https://github.com/hherb/secretary/issues/98)** — `apply_decisions` duplicate-decision tightening.
- **[#103](https://github.com/hherb/secretary/issues/103)** — Task 12 follow-on: prove EvidenceStale abort beats step 5's per-block rewrites on a divergence-bearing fixture. Recommended keep separate from Task 14 (different invariant — Task 14 proves recovery AFTER step 5's rewrites happen; #103 proves abort BEFORE they happen). Could roll into Task 15's proptests or Task 16's KATs.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries 1 commit on top of `8a23f3c` (post-Task-13 main). PR body will reference this baton. Single PR with a single test commit (plus baton commit) is the natural shape for Task 14.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -8                                            # last 8: baton + 1 task commit + main HEAD

# Baseline gauntlet (expect 786 / 0 / 10 on this branch BEFORE Task 15 starts;
# becomes 766+ baseline relative to next session's post-merge main):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 14's PR merges, reset feature branch + open the plan for Task 15:
git fetch --prune origin
git reset --hard origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 15"
```

## Closing inventory

- **Branch state on close:** `main` at `8a23f3c` (PR #104 squash-merged Task 13). `feature/c1-1b-sync-merge` rebased onto `8a23f3c` carrying 1 new commit (`4c3814c` Task 14) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 786 passed + 10 ignored. Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95) / [#98](https://github.com/hherb/secretary/issues/98) / [#103](https://github.com/hherb/secretary/issues/103).
- **Open PRs:** one to be opened at end of this session covering Task 14.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
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
  - [`docs/handoffs/2026-05-22-c1-1b-task-14-shipped.md`](docs/handoffs/2026-05-22-c1-1b-task-14-shipped.md) — Task 14 close (this session).
