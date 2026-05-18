# NEXT_SESSION.md

**Session date:** 2026-05-18 (planning session — C.1.1b implementation plan authored, worktree prepared)
**Status:** `main` at `98d8a8a` (PR #83 — the #80 TOCTOU fix — merged earlier today; PRs #77 + #82 already on `main`). New feature branch `feature/c1-1b-sync-merge` created off `main` with the C.1.1b 17-task implementation plan committed. **No PR yet** — next session opens one once the first one or two implementation tasks have shipped (per `feedback_stay_in_inner_loop` — small slices, human review between each).

## (1) What we shipped this session

This was a planning session, not an implementation session. Tasks fanned out:

| Action | Result |
|---|---|
| Cleaned up state (`fix/80-manifest-double-read` worktree+branch removed; `git pull` advanced main to `98d8a8a`) | One stale worktree gone; local main matches origin |
| Read 1b design doc + surveyed C.1.1a code surface (`sync/once.rs`, `sync/bundle.rs`, `sync/outcome.rs`, `vault/conflict.rs`, `vault/orchestrators.rs`, `vault/record.rs`, `tests/sync_helpers/mod.rs`) | Implementation-plan author had ground truth on what's already on `main` post-1a + post-#80 fix |
| Authored 17-task TDD implementation plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) | 5 new files + 8 modified files; expected gauntlet growth 713 → 729 (16 new tests) |
| Created worktree `.worktrees/c1-1b-sync-merge` on new branch `feature/c1-1b-sync-merge` off `main` | Next session resumes there |
| This baton + handoff snapshot, committed on `feature/c1-1b-sync-merge` | Commit SHA assigned on push |

**No code commits this session.** No README / ROADMAP changes — both update at the end of C.1.1b per the plan's Task 17. No PR opened — the plan itself is small enough to live on the branch awaiting the first implementation slice.

## (2) What's next — execute the C.1.1b plan, Task 1 first

### (a) First action next session: execute Task 1

Open the plan and start with **Task 1 — extend `sync_helpers` with a per-block rewrite helper**. The plan's Task 1 is fully self-contained (read existing helper, write failing test, add nonce constants, implement helper, run, commit). Expected time: 60–90 minutes; one commit.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# Plan + design doc are both on this branch already:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Per `feedback_stay_in_inner_loop`, the execution pattern is **subagent-driven-development**: one fresh subagent per task, human-reviews-between-tasks, no overnight pipelines. The plan is structured for it (one task = one subagent invocation = one human review = one commit).

### (b) Plan structure at a glance

| Task | What it builds | New / modified files |
|---|---|---|
| 1 | `sync_helpers` per-block rewrite + new `BLOCK_NONCE_E/F/G` constants | `core/tests/sync_helpers/mod.rs` |
| 2 | 4 new `SyncError` variants (`EvidenceStale` + 3 more) | `core/src/sync/error.rs` |
| 3 | `VaultError::BlockFingerprintMismatch` variant | `core/src/vault/mod.rs` |
| 4 | `verify_block_fingerprints` pure-ish helper + module tests | `core/src/vault/orchestrators.rs` |
| 5 | Wire `verify_block_fingerprints` into `open_vault` + integration test | `core/src/vault/orchestrators.rs`, `core/tests/open_vault.rs` |
| 6 | `draft.rs` — `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision` (zeroize-typed) | `core/src/sync/draft.rs` NEW, `core/src/sync/mod.rs` |
| 7 | `tombstone_veto_set` pure helper + 7 table tests | `core/src/sync/prepare.rs` NEW |
| 8 | `prepare_merge` block decap + iterative N-way merge | `core/src/sync/prepare.rs`, `core/src/sync/mod.rs`, `core/tests/sync_merge.rs` NEW |
| 9 | `rewrite_block_with_records_and_update_manifest` helper + first divergent-block test | `core/tests/sync_helpers/mod.rs`, `core/tests/sync_merge.rs` |
| 10 | `apply_decisions` pure helper + 6 bijection tests | `core/src/sync/commit.rs` NEW, `core/src/sync/mod.rs` |
| 11 | `commit_with_decisions` — re-encrypt + atomic write + happy-path test | `core/src/sync/commit.rs`, `core/src/sync/mod.rs`, `core/tests/sync_merge.rs` |
| 12 | `EvidenceStale` integration test (manifest-hash freshness) | `core/tests/sync_merge.rs` |
| 13 | Veto-handling 4-test bundle (KeepLocal / AcceptTombstone / Missing / Unknown) | `core/tests/sync_merge.rs`, `core/tests/sync_helpers/mod.rs` |
| 14 | Crash-recovery test (partial-write reconverge — D6 proof) | `core/tests/sync_merge.rs` |
| 15 | 4 property tests | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [ ] `cargo test --release --workspace --no-fail-fast` → 729 / 0 / 10 (713 baseline + 16 new tests)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [ ] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch`
- [ ] Three-step `sync_once → prepare_merge → commit_with_decisions` happy-path test green
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**

## (3) Open decisions and risks

### Implementer's-call decisions (deferred from the plan)

1. **`VaultBundle.canonical_owner_card` cache.** Task 8 picks **Path B** (re-load owner card inside `prepare_merge`) to stay self-contained. **Path A** (cache the owner card on the bundle at 1a ingest time) is faster but touches 1a code. Implementer's call when starting Task 8 — if `prepare_merge` shows up in property-test hotpaths, switch to Path A.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Plan's Task 6 defines them as `BTreeMap<[u8; 16], Vec<...>>`. Implementer may prefer a `Vec<DraftMergeBlock>` newtype if iteration order becomes important. Either works — pick one and stick to it across Tasks 6, 8, 11.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — re-read [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) before completing Task 6. The new struct holds plaintext peer-side `Record`s after AEAD decryption. Derive `Zeroize + ZeroizeOnDrop` with `#[zeroize(skip)]` on non-secret fields (precedent: `VaultBundle`).
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants in Task 1; per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness (CLAUDE.md atomic-write section, also called out at design-doc §Risks).
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — this PR consumes `merge_block` / `merge_record` / `merge_vector_clocks` but does NOT modify them. If implementation friction requires touching `core/src/vault/conflict.rs` beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget. May be relevant when sizing C.1.1b's per-block proptests in Task 15.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. C.1.1b's `commit_with_decisions` may consume them; re-check at Task 11.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. Could be closed alongside C.1.1b if `once.rs` surface is touched.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands (C.4 scope).
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 13's veto-fixture helpers may close some of #78 as a side effect — worth re-checking on Task 13 completion.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors (Task 14 of the 1a plan, deferred). Not directly C.1.1b; relisted for tracking.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. Not directly C.1.1b-relevant; tracked for the C.4 doc pass.

### Open PRs at close

**None.** Plan + this baton are on `feature/c1-1b-sync-merge` awaiting execution.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -5

# Baseline gauntlet (expect 713 / 0 / 10 on `main` post-#80-fix):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Open the plan + design doc, then execute Task 1:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Optional but recommended: dispatch via `superpowers:subagent-driven-development` from Task 1 onwards — the plan is structured for it.

## Closing inventory

- **Branch state on close:** `main` at `98d8a8a` (unchanged this session). `feature/c1-1b-sync-merge` at the plan-authored commit (SHA assigned on push).
- **Workspace tests on `main`:** 713 passed + 10 ignored (post-#80 fix baseline). No code changes this session, so no gauntlet was rerun on the feature branch.
- **README.md:** unchanged this session. Updates land at Task 17 of the plan.
- **ROADMAP.md:** unchanged this session. Updates land at Task 17 of the plan.
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81).
- **Open PRs:** none.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshot:** [`docs/handoffs/2026-05-18-c1-1b-plan-authored.md`](docs/handoffs/2026-05-18-c1-1b-plan-authored.md) — exact copy of this file for audit/learning.
