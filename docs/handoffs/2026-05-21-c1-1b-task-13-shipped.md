# NEXT_SESSION.md

**Session date:** 2026-05-21 (implementation session — C.1.1b Tasks 13a + 13.1-13.4 of 17 shipped; per-block-divergent veto handling proves through to disk + flushes out a real production bug in `prepare_merge`'s veto pass)
**Status:** PR to be opened. `feature/c1-1b-sync-merge` carries 6 commits on top of `324c4cb` (post-Task-12 main) — one pre-refactor (lift `extract_vault_uuid`), one fixture helper, one bug-fix-plus-test (Task 13.1 + the `prepare_merge` veto-pass canonical-vs-accumulator fix), and three more tests. 4 tasks remain (14-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`63b32a7`](https://github.com/hherb/secretary/commit/63b32a7) | 13a pre-refactor | **`extract_vault_uuid` lifted into `fixtures` helper.** Centralizes the previously-four-times-duplicated `extract_vault_uuid(folder: &Path) -> [u8; 16]` into `core/tests/fixtures/mod.rs::extract_vault_uuid`. Trigger met (the 5th consumer in `sync_merge_vetoes.rs` would have inlined another copy). Removed inline copies from `sync_merge.rs`, `sync_ingest.rs`, `sync_ingest_proptest.rs`. `sync.rs::extract_golden_vault_uuid` kept as a zero-arg adapter that delegates to the lifted helper (its tests use the in-tree pre-built fixture, not a temp copy — preserving the existing call shape). `#[allow(dead_code)]` on the lifted helper because `core/tests/fixtures/mod.rs` is compiled once per `tests/*.rs` binary; binaries that import the module only for `golden_vault_001_password` (e.g. `open_vault.rs`) would otherwise see it as unused under `-D dead_code`. Net: 29 insertions, 31 deletions across 5 files. No test-count change. |
| [`833b981`](https://github.com/hherb/secretary/commit/833b981) | 13a | **`fresh_vault_two_concurrent_blocks` fixture helper.** Per-block-divergent two-manifest fixture: writes canonical block (with caller-supplied `canonical_records`) AND a sibling block file at `blocks/<uuid>.cbor.enc<sibling_block_suffix>` (with `sibling_records`) using distinct AEAD seeds (`BLOCK_NONCE_E` canonical, `BLOCK_NONCE_F` sibling), then re-signs the canonical manifest AND writes a sibling manifest with distinct `BlockEntry.fingerprint` + `BlockEntry.vector_clock_summary` + top-level `vector_clock` per side. The resulting state opens cleanly under D6 (canonical block matches `BlockEntry.fingerprint`) AND drives the C.1.1a ingest layer to emit non-empty `bundle.diverging_blocks` (canonical + sibling `vector_clock_summary` are concurrent). Inner refactor: extracted `encrypt_block_bytes_for_uuid` pure helper (returns `([u8; 32], Vec<u8>) = (fingerprint, bytes)` — no I/O); `rewrite_block_with_records` now calls it; the new fixture helper calls it twice with distinct seeds. Also extracted `write_manifest_with_block_entry` to share manifest re-signing between canonical and sibling. New smoke test pins the helper: `fresh_vault_two_concurrent_blocks_produces_consistent_canonical_with_sibling_on_disk` proves D6 round-trip + both block files present + distinct ciphertexts. Test count: 767 → 771 (+4 from the helper smoke cross-binary, which runs in all 4 test crates that `mod sync_helpers`). **File size:** `core/tests/sync_helpers/mod.rs` is now 1115 LOC, up from 743 at #95 filing. The submodule sketch in #95 still fits; the refactor stays deferred (parallel to merge-layer work). [Comment posted to #95](https://github.com/hherb/secretary/issues/95#issuecomment-4514600227) with the updated LOC. |
| [`7cd8a37`](https://github.com/hherb/secretary/commit/7cd8a37) | 13.1 | **Veto pass canonical-vs-accumulator fix + KeepLocal integration test.** Production-code bug: `prepare_merge`'s per-record veto pass iterated `acc_records.iter()` (post-iterative-fold accumulator) and passed each entry as `local` to `tombstone_veto_set`. Under well-formed inputs this made the integration veto branch UNREACHABLE: when canonical has a LIVE record at `last_mod_ms = L` and a peer has the same record TOMBSTONED at `tombstoned_at_ms = T > L`, `merge_block`'s §11.3 tombstone-wins-by-clock rule writes a tombstoned record into `acc_records`, and the veto pass's `if local_rec.tombstone { continue; }` then skipped the very case the veto is meant to surface. For any other case, the strict-greater inequality `peer.tombstoned_at_ms > merged.last_mod_ms` cannot hold because `merged.last_mod_ms = max(local, all_peers)` (so `merged ≥ peer.tombstoned_at_ms` always). Net: `vetoes.is_empty()` after EVERY `prepare_merge` invocation, regardless of input. Dead code in production — but the helper's own unit tests all passed because they exercise `tombstone_veto_set` in isolation with a canonical-style live record. The bug only surfaced because Task 13.1's integration test was the FIRST test ever to drive `prepare_merge` on a per-block-divergent fixture. **Fix:** walk `canonical_pt.records` (pre-merge) in the veto pass, not `acc_records`. Matches `tombstone_veto_set`'s docstring ("the local (canonical) record"), the design doc §"prepare_merge" step 2, and `commit/apply.rs::keep_local_overrides_tombstoned_record`'s unit-test fixture pattern (vetoes carry LIVE `local_state`, `merged_records` carries TOMBSTONED records — only achievable if vetoes are emitted from canonical). **Test:** `commit_with_decisions_keep_local_overrides_peer_tombstone` in the new `core/tests/sync_merge_vetoes.rs`. Fixture builds canonical LIVE@100 + sibling TOMB@200 → one veto → `KeepLocal { [0xAA; 16] }` decision → post-commit canonical block on disk decrypts to one LIVE record with `last_mod_ms = 100`. Returned `SyncState` carries both manifest devices' clock entries. **Why one commit:** the fix and the test are TDD-coupled (the test is the RED-then-GREEN signal for the fix). Splitting them would either land a failing test (test-first) or a fix with no automated proof (fix-first; bisect points to the test commit, not the fix commit, when a future regression surfaces). Test count: 771 → 777 (+6: +1 KeepLocal in `sync_merge_vetoes` binary + 5 helper_tests cross-binary re-runs in the new test binary). |
| [`262d444`](https://github.com/hherb/secretary/commit/262d444) | 13.2 | **`AcceptTombstone` integration test.** Same fixture as Task 13.1. Decision: `VetoDecision::AcceptTombstone { record_id: [0xAA; 16] }`. `apply_decisions` treats `AcceptTombstone` as a no-op (the merge already wrote the tombstone), the commit re-encrypts the canonical block, and the new on-disk record set holds the TOMBSTONED record (`tombstone=true`, `tombstoned_at_ms=200`). Also pins the §11.5 invariant `tombstoned_at_ms == last_mod_ms` on the post-merge record — catches accidental drift in `merge_record`'s timestamp logic. Test count: 777 → 778. |
| [`ab1c701`](https://github.com/hherb/secretary/commit/ab1c701) | 13.3 | **`MissingVetoDecision` integration test.** Same fixture. Decision: `Vec::new()` — caller fails to adjudicate. Bijection check computes `veto_ids - decision_ids = {[0xAA; 16]}` → typed `SyncError::MissingVetoDecision { record_id: [0xAA; 16] }`. Block-side no-disk-write proof: snapshot canonical block bytes pre-commit, verify byte-identical post-abort. Counterpart to Task 12's manifest-side `EvidenceStale` no-disk-write proof. Test count: 778 → 779. |
| [`8c6149a`](https://github.com/hherb/secretary/commit/8c6149a) | 13.4 | **`UnknownVetoDecision` integration test.** Same fixture. Decision: two entries — one matching (`KeepLocal { [0xAA; 16] }`), one stray (`KeepLocal { [0xFF; 16] }`). Bijection check computes `decision_ids - veto_ids = {[0xFF; 16]}` → typed `SyncError::UnknownVetoDecision { record_id: [0xFF; 16] }`. Same no-disk-write post-condition as Task 13.3. Together with Task 13.3 closes the bijection-violation disk-side proof: any non-bijective `(vetoes, decisions)` pair aborts before block re-encrypt. Test count: 779 → 780. |

**Branch hygiene:** Session opened on `feature/c1-1b-sync-merge` carrying 5 already-merged commits (Task 12's PR #102 squash-merged after the previous session). Per the previous baton's instruction, reset to `origin/main` (`324c4cb`) at session start — the local pre-merge commits' file changes were already on main via the squash, so the reset discarded only duplicates. Local branch now carries exactly 6 new commits on top of `324c4cb`.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 13.4:**

- `cargo test --release --workspace --no-fail-fast` → **780 / 0 / 10** (767 baseline at `324c4cb` + 4 helper_tests cross-binary re-runs from the new `sync_merge_vetoes` binary + 4 new veto tests + 1 helper smoke test = 13).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed; the C.1.1b plan + design docs sit outside the script's corpus).

## (2) What's next — execute Task 14

### (a) First action next session: execute Task 14 (after PR for Task 13 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 14 — Crash-recovery integration test (partial-write reconverge)**. The D6 proof: simulate a crash between step 5's block re-encrypt and step 6's manifest write, then prove the next `sync_once → prepare_merge → commit_with_decisions` reconverges to the same final state via CRDT idempotence.

Plan-cited shape:

1. Fixture: per-block-divergent state (reuse Task 13's `fresh_vault_two_concurrent_blocks`).
2. Drive a partial commit: call `commit_with_decisions` but interrupt it before the manifest write. Strategies tried in the plan:
   - Mock/intercept `write_atomic` to fail on the manifest path. Cleanest, no production-code change needed.
   - OR: manually orchestrate the half-commit by calling `commit_with_decisions`'s individual steps in a test-only harness.
3. The interrupted state on disk: rewritten block + stale manifest (`BlockEntry.fingerprint` references the old block).
4. Next `open_vault` fires `VaultError::BlockFingerprintMismatch` (D6 gate) → caller surfaces, retries.
5. Re-run `sync_once → prepare_merge → commit_with_decisions` — CRDT idempotence guarantees the second pass produces the same final state.

Expected workspace test count after Task 14: 780 → 781 (+1).

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 13's PR merges:
git fetch --prune origin
git reset --hard origin/main                                    # discard merged commits
# THEN open the plan:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 14"
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 14 is a single new test; a single PR with one commit (plus baton commit) is the natural shape.

### (b) Plan structure at a glance (4 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1-10~~ | ~~Tasks 1-10 shipped~~ ✅ in PRs #84-#97 |
| ~~11~~ | ~~`commit_with_decisions` + DraftMerge per-block + commit/ split + happy-path test~~ ✅ PR #99 (`52093aa`) |
| ~~12~~ | ~~`EvidenceStale` integration test (manifest-hash freshness)~~ ✅ PR #102 (`324c4cb`) |
| ~~13a + 13.1-13.4~~ | ~~`fresh_vault_two_concurrent_blocks` helper + 4 veto integration tests + `prepare_merge` veto-pass bug fix~~ ✅ this session (6 commits, PR pending) |
| **14** | **Crash-recovery test (partial-write reconverge — D6 proof)** | `core/tests/sync_merge_vetoes.rs` or new `core/tests/sync_merge_crash.rs` |
| 15 | 4 property tests | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [x] `cargo test --release --workspace --no-fail-fast` → 766+ / 0 / 10 (currently 780 / 0 / 10 — well above the floor)
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
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-10 and confirm each has at least one real consumer in Tasks 11-16. Task 13a retired `BLOCK_NONCE_F`'s and `fresh_vault_two_concurrent_blocks`'s `#[allow(dead_code)]` markers (both now consumed). `BLOCK_NONCE_G` + `SIBLING_NONCE_D` + `fresh_vault_four_concurrent_manifests` remain `#[allow(dead_code)]` — Task 14 (crash recovery) may consume them.

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **`prepare_merge` veto-pass bug fix is a production-code change in a test-driven task.** Task 13 was scoped as "veto integration tests only", but Task 13.1's red signal revealed that `prepare_merge`'s veto pass (line 463 pre-fix) was iterating `acc_records` (post-merge) instead of `canonical_pt.records` (pre-merge), making the integration veto branch UNREACHABLE. Per [[feedback_act_on_issues_dont_mention]] and [[feedback_security_no_assumptions]], fixed in-task rather than filing-and-deferring. The fix is 2 lines + 18 lines of explanatory comment. Reviewer: confirm the design intent matches the helper's docstring ("the local (canonical) record") and the design doc §"prepare_merge" step 2 ("local.is_alive()" with local being canonical).
- **One commit for the fix + the test.** Per the commit body's "Why one commit": the fix and test are TDD-coupled; splitting would either land a RED test (test-first) or a fix with no automated proof (fix-first; bisect would point at the wrong commit). Reviewer: this is the explicit deviation from "step by step, one issue per commit" — the issue here IS "prepare_merge veto branch unreachable; surface it with an integration test and fix the implementation", one issue, one commit.
- **`extract_vault_uuid` lifted pre-Task-13.** Trigger condition met (5th consumer would have inlined another copy). Single refactor PR-resident pre-step.
- **`sync_helpers/mod.rs` grew 743 → 1115 LOC.** Task 13a's `fresh_vault_two_concurrent_blocks` + `encrypt_block_bytes_for_uuid` + `write_manifest_with_block_entry` + smoke test added ~370 LOC. Past the 800 trigger named in the Task 12 baton's implementer-call #4. [Updated #95](https://github.com/hherb/secretary/issues/95#issuecomment-4514600227) with the new LOC; the submodule sketch still fits. **Deferred to a follow-up split PR** (parallel to merge-layer work) rather than expanding Task 13's scope. Plan is to land it as a standalone refactor between Tasks 14 and 17 (or at Task 17 close).
- **`sync_merge_vetoes.rs` is a new test binary, not an extension of `sync_merge.rs`.** Reason: `sync_merge.rs` is already at ~500 LOC after Task 12. Adding 4 new veto tests (~280 LOC) plus the shared `make_veto_fixture` + `live_record` + `tombstoned_record` helpers (~120 LOC) would push it past 900. New binary keeps the veto concern isolated; Task 14 (crash-recovery) can decide whether to extend this file or open `sync_merge_crash.rs`. Per the Task 12 baton's note "if sync_merge.rs crosses 500 BEFORE Task 17, split into `core/tests/sync_merge_*.rs` files".

### Carry-over from earlier PRs

- **`apply_decisions` is `pub(crate)`, not `pub`.** Unchanged this session.
- **PR #99 in-PR refactor (`1193072`)** — `MANIFEST_FILENAME` consolidation already merged.
- **PR #102 (Task 12)** — already merged at session start.
- **Implementer-call decisions from Task 12 baton still live:**
  - #1 `commit_with_decisions` identity argument: stays `&SecretBytes`, re-opens internally. Task 13.1-13.4 tests all use `open_with_password` (standalone identity, no lifetime tie to a vault folder) so no `drop(open)` needed.
  - #2 `DraftMerge.per_block_clocks` + `per_block_records` shape: frozen, no change this session.
  - #3 `extract_vault_uuid` helper duplication: **closed this session** (lifted via `63b32a7`).
  - #4 `sync_helpers/mod.rs` file size: still open, now at 1115 LOC. Track via [#95](https://github.com/hherb/secretary/issues/95).
  - #5 `commit/` directory split (PR #99): no change this session — Task 13.1-13.4 are tests-only, didn't grow `write.rs`.
  - #6 `prepare.rs` file size (869 LOC pre-Task-13.1): now ~890 LOC after the veto-pass fix (+18 lines of explanatory comment). Still pre-existing growth; file a tracking issue at C.1.1b close (Task 17), or split as a standalone refactor if Tasks 14-16 push it further.

### Implementer's-call decisions (live for Tasks 14-16)

1. **`commit_with_decisions` identity argument.** Unchanged from Task 12 baton (`&SecretBytes`).
2. **`DraftMerge` shape.** Unchanged.
3. **Veto-pass iteration source.** Resolved this session: walk `canonical_pt.records`, not `acc_records`. If Task 15's proptests add cases where the canonical's record is tombstoned but a peer LIVE record contests the tombstone, the current code's `canonical_rec.tombstone → continue` is the right call (no veto needed because LWW already wins).
4. **`sync_helpers/mod.rs` file size.** 1115 LOC. Past the 800 trigger but #95 stays the umbrella for the split refactor.
5. **`commit/` directory split.** Unchanged.
6. **`prepare.rs` file size.** ~890 LOC post-fix. Still in the "tracking issue at C.1.1b close" bucket — no urgency from Task 13.
7. **New test binary `sync_merge_vetoes.rs`.** Decided to add Task 13's tests in a new binary rather than extending `sync_merge.rs`. Task 14 can extend `sync_merge_vetoes.rs` OR open `sync_merge_crash.rs` — pick at Task 14 PR-open time based on whether the crash test shares enough fixtures with the veto tests to justify co-location.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6 + Task 11 extension; unchanged this session.
- **AEAD nonce per rewrite** — Task 13.1 + 13.2 EXERCISE the rewrite path for the first time (`commit_with_decisions` re-encrypts the divergent block). `OsRng` drives the rewrite, so each commit produces a fresh nonce. Tasks 13.3 + 13.4 abort before the rewrite; no AEAD exposure there.
- **`tempfile` exact pin** (`=3.27.0`) — unchanged this session.
- **CRDT proptests must not weaken** — Task 13's tests do not touch `core/src/vault/conflict.rs`. `commit_with_decisions` consumes merge-primitive output, not produces it. Confirmed via gauntlet: 4 conflict proptests still pass.
- **`SyncOutcome::ConcurrentDetected` is large** — unchanged.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — no new core variants this session.
- **File size of `core/src/sync/commit/write.rs`** — 389 LOC (unchanged). Task 14 (crash-recovery test) is tests-only; if Task 14 surfaces a need for production-side helpers (e.g. a `commit_one_block` exposed for the test harness), split per the Task 12 baton's implementer-call #5.
- **File size of `core/src/sync/prepare.rs`** — ~890 LOC (+18 from this session). See #95's pattern (file an umbrella issue at C.1.1b close).
- **File size of `core/tests/sync_helpers/mod.rs`** — 1115 LOC. See #95.
- **File size of `core/tests/sync_merge_vetoes.rs`** — 472 LOC after Task 13.4. Comfortably under 500. Task 14 (one crash test, ~100 LOC) would push it to ~570 — close to the cap. If Task 14 lands in this file, consider splitting at Task 14 PR-open time (or open `sync_merge_crash.rs` from the start).
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 LOC (unchanged). Pre-existing.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. Not consumed by Task 13's veto tests.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands.
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 13's veto-fixture work may close some of #78 as a side effect — worth re-checking on Task 13 PR merge.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors. Not directly C.1.1b.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. C.4 doc pass.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader. Refactor follow-up.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures.
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies. Cross-crate scope.
- **[#95](https://github.com/hherb/secretary/issues/95)** — split `core/tests/sync_helpers/mod.rs`. Now 1115 LOC; [comment posted](https://github.com/hherb/secretary/issues/95#issuecomment-4514600227) with the updated LOC. Revisit at Task 17 or as standalone refactor BEFORE Task 14.
- **[#98](https://github.com/hherb/secretary/issues/98)** — `apply_decisions` duplicate-decision tightening.
- **[#103](https://github.com/hherb/secretary/issues/103)** — Task 12 follow-on: prove EvidenceStale abort beats step 5's per-block rewrites on a divergence-bearing fixture. Could be closed alongside Task 13's PR if a small test addition fits, OR roll into Task 14's crash-recovery surface. Recommended: keep separate (Task 14 has its own crash-recovery story; #103 is a narrower EvidenceStale variant).

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries 6 commits on top of `324c4cb` (post-Task-12 main). PR body will reference this baton. Single PR groups all 6 commits because they form a tightly coupled feature (the bug fix + 4 tests + 1 helper + 1 lift-refactor all close the C.1.1b veto-handling surface) — per Task 12's experience that "grouping commits into one PR is fine when they're tightly coupled".

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -8                                            # last 8: baton + 6 task commits + main HEAD

# Baseline gauntlet (expect 780 / 0 / 10 on this branch BEFORE Task 14 starts;
# becomes 766+ baseline relative to next session's post-merge main):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 13's PR merges, reset feature branch + open the plan for Task 14:
git fetch --prune origin
git reset --hard origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 14"
```

## Closing inventory

- **Branch state on close:** `main` at `324c4cb` (PR #102 squash-merged Task 12). `feature/c1-1b-sync-merge` rebased onto `324c4cb` carrying 6 new commits (`63b32a7` lift + `833b981` Task 13a + `7cd8a37` Task 13.1 + fix + `262d444` Task 13.2 + `ab1c701` Task 13.3 + `8c6149a` Task 13.4) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 780 passed + 10 ignored. Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95) / [#98](https://github.com/hherb/secretary/issues/98) / [#103](https://github.com/hherb/secretary/issues/103).
- **Open PRs:** one to be opened at end of this session covering Tasks 13a + 13.1-13.4 + the `prepare_merge` veto-pass fix.
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
  - [`docs/handoffs/2026-05-21-c1-1b-task-13-shipped.md`](docs/handoffs/2026-05-21-c1-1b-task-13-shipped.md) — Task 13 close (this session).
