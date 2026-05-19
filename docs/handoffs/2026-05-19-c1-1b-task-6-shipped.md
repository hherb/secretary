# NEXT_SESSION.md

**Session date:** 2026-05-19 (implementation session — C.1.1b Task 6 of 17 shipped; types-only foundation for the merge layer)
**Status:** PR #89 (Task 5) **MERGED** into `main` as `ba969ef` (squashed Task 5 + baton + the `BLOCKS_SUBDIR` / `BLOCK_FILE_EXTENSION` review fix-up). `feature/c1-1b-sync-merge` reset onto post-merge `main` and now carries one new commit: Task 6 ([`85763bd`](https://github.com/hherb/secretary/commit/85763bd)) — `core/src/sync/draft.rs` with `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision` (zeroize-typed), four module tests, and the `pub mod` + `pub use` wire-up in `core/src/sync/mod.rs`. 11 tasks remain (7-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`85763bd`](https://github.com/hherb/secretary/commit/85763bd) | Task 6 | **New file** `core/src/sync/draft.rs` (272 LOC including doc + tests): public-API types `prepare_merge` returns and `commit_with_decisions` consumes. <br/>• `DraftMerge` — `vault_uuid` + `DiffPlan` + `ManifestHash` freshness anchor + `merged_records: Vec<Record>` + `vetoes: Vec<RecordTombstoneVeto>` + `post_merge_clock: Vec<VectorClockEntry>`. <br/>• `RecordTombstoneVeto` — one record where peer would tombstone but local has live; carries `record_id` + `block_id` + plaintext local `Record` + `disk_tombstone_at_ms` + `disk_tombstoner_device`. <br/>• `VetoDecision::{KeepLocal, AcceptTombstone}` with `record_id()` accessor used by the upcoming `commit_with_decisions` bijection check. <br/>• `RecordId` + `BlockId` — `[u8; 16]` aliases for API readability. <br/>**Zeroize discipline** — `DraftMerge` + `RecordTombstoneVeto` derive `Zeroize + ZeroizeOnDrop`; non-secret framing fields (`vault_uuid`, plan, manifest hash, vector clocks) and the contained `Record` (which doesn't derive `Zeroize` itself but wipes its `RecordFieldValue::Text(SecretString)` / `Bytes(SecretBytes)` variants on drop) carry `#[zeroize(skip)]`. Drop-time wipe is the real contract; `.zeroize()` is defense-in-depth. <br/>**Module wire-up** — `core/src/sync/mod.rs` adds `pub mod draft;` and re-exports `BlockId, DraftMerge, RecordId, RecordTombstoneVeto, VetoDecision`. <br/>**Four new module tests** in `sync::draft::tests`: `record_tombstone_veto_zeroize_clears_local_state` (proves the `[u8; 16]` + `u64` fields wipe on `.zeroize()` while `local_state: Record` is `#[zeroize(skip)]`-tolerated), `veto_decision_eq_is_structural`, `veto_decision_record_id_accessor`, `draft_merge_holds_required_fields`. TDD-red was proven by gating the type definitions behind `#[cfg(any())]` and observing `E0432: unresolved imports DraftMerge / RecordTombstoneVeto / VetoDecision` before flipping the gates off. |

**Branch hygiene:** PR #89 (Task 5 + the baton commit + the `BLOCKS_SUBDIR` review fix-up) was squash-merged into `main` as `ba969ef`. The local `feature/c1-1b-sync-merge` was reset to `origin/main` to discard the three now-redundant per-PR commits (`748377d`, `424dbf2`, `57491a9`) before adding Task 6 on top, so the branch contains exactly one new commit and the next PR will be visually clean.

**Working-directory hazard caught and recovered:** The Write tool's first attempt at creating `core/src/sync/draft.rs` accidentally wrote to the main repo (absolute path `/Users/hherb/src/secretary/core/src/sync/draft.rs`) instead of the worktree. Recovered by copying the file across, `git checkout -- core/src/sync/mod.rs` on main, and `rm core/src/sync/draft.rs` from main. Main repo's tree is now clean. **Lesson for next session**: when working inside `.worktrees/c1-1b-sync-merge`, prefer worktree-prefixed absolute paths (`/Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge/...`) or `cd` into the worktree at the top of every shell call to avoid the trap.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 6:**

- `cargo test --release --workspace --no-fail-fast` → **732 / 0 / 10** (728 baseline from `ba969ef` + 4 new = the four `sync::draft::tests::*` lib tests).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed by allowlist).

## (2) What's next — execute Task 7

### (a) First action next session: execute Task 7

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 7 — Add `tombstone_veto_set` pure helper in `prepare.rs`**. Pure-function core of veto detection: given the canonical local `Record` plus the per-copy peer records that share its `record_uuid`, returns `Some(RecordTombstoneVeto)` iff any peer copy has `tombstoned_at_ms > local.last_mod_ms` AND `!local.tombstone`. Table-driven coverage for the four interesting cases (all-tombstones, no-tombstones, local-tombstoned-disk-live, local-live-disk-tombstone), plus the edge cases (no peers, multiple peers picking the latest, tie at `last_mod_ms`).

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 7"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 7 is the last pure-helper foundation before Task 8 wires the iterative N-way merge.

### (b) Plan structure at a glance (11 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1~~ | ~~`sync_helpers` per-block rewrite + new `BLOCK_NONCE_E/F/G` constants~~ ✅ in PR #84 (`7dff8da`) |
| ~~2~~ | ~~4 new `SyncError` variants~~ ✅ in PR #84 (`7dff8da`) |
| ~~3~~ | ~~`VaultError::BlockFingerprintMismatch` variant~~ ✅ in PR #84 (`7dff8da`) |
| ~~4~~ | ~~`verify_block_fingerprints` pure-ish helper + module tests~~ ✅ in PR #85 (`f5b108f`) |
| ~~5~~ | ~~Wire `verify_block_fingerprints` into `open_vault` + integration test~~ ✅ in PR #89 (`ba969ef`) |
| ~~6~~ | ~~`draft.rs` — `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision` (zeroize-typed)~~ ✅ `85763bd` |
| **7** | **`tombstone_veto_set` pure helper + 7 table tests** | `core/src/sync/prepare.rs` NEW |
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

- [ ] `cargo test --release --workspace --no-fail-fast` → 742 / 0 / 10 (728 baseline at `ba969ef` + 14 new tests total across Tasks 6-16; we're at 732 after Task 6 = 728 + 4)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5
- [x] `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision` defined with zeroize discipline + module tests ✅ Task 6
- [ ] Three-step `sync_once → prepare_merge → commit_with_decisions` happy-path test green
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-6 (the four new `SyncError` variants from Task 2 + the seven sync_helpers items from Task 1, including the refactored `rewrite_block_with_records`) and confirm each has at least one real consumer in Tasks 6-16. Stale `#[allow(dead_code)]` markers must be removed (zero in the final PR — they exist only as a per-task TDD-cadence shim). **Tasks 5 + 6 add zero `#[allow(dead_code)]` markers themselves.**

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **None for Task 6.** The new file matches the plan's Step 3 type definitions byte-for-byte; the only adjustment was minor `cargo fmt` reflow of the `VetoDecision` match arm and the test struct literals (formatting-only, no semantic change). I also added one extra module test (`veto_decision_record_id_accessor`) — the plan listed three tests but the `record_id()` accessor warranted its own explicit pin given it's the only behaviour the bijection check in `commit_with_decisions` relies on.

### Working-directory hazard (process, not code)

- **Caught a path-leak between worktree + main repo.** First `Write` of `draft.rs` landed in the main repo's tree (absolute path resolved without the `.worktrees/c1-1b-sync-merge` prefix). Recovered by `cp` + `git checkout -- mod.rs` + `rm draft.rs` in the main repo before re-doing the edits in the worktree. Main repo's tree is now clean (`git status --short` shows nothing). Per `feedback_worktree_location` and CLAUDE.md §"Working directory discipline": next session should always pass worktree-prefixed absolute paths to file-creation tools (or `cd` into the worktree at the top of every shell turn) to avoid the trap.

### Carry-over from earlier PRs

- **Task 1 RNG seeding (in `7dff8da` via `67567c7`)** — `ChaCha20Rng::from_seed(...)` replaced the plan's `DeterministicNonceRng`; `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this; no action for Task 7+.
- **PR #85 helper-signature refactor (`748377d`)** — `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` takes `&OpenVault` because under D6 the helper's previously-internal `open_vault` call fails on the second rewrite of the same fixture. Task 9's `rewrite_block_with_records_and_update_manifest` will compose the primitive with the manifest re-sign step.

### Implementer's-call decisions (live for Tasks 8-11)

1. **`VaultBundle.canonical_owner_card` cache.** Task 8 picks **Path B** (re-load owner card inside `prepare_merge`) to stay self-contained. **Path A** (cache the owner card on the bundle at 1a ingest time) is faster but touches 1a code. Implementer's call when starting Task 8 — if `prepare_merge` shows up in property-test hotpaths, switch to Path A.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** The plan's Task 6 froze the minimal six-field `DraftMerge` shape; Task 8 extends it with `per_block_clocks: BTreeMap<[u8; 16], Vec<VectorClockEntry>>` plus either `per_block_records: BTreeMap<[u8; 16], Vec<[u8; 16]>>` or a `Vec<DraftMergeBlock>` newtype if iteration order becomes important. Pick one and stick to it across Tasks 8, 11. **NOTE**: Task 6 as shipped does NOT yet include these fields — they're a Task 8 extension. Any addition MUST preserve the existing `#[derive(Zeroize, ZeroizeOnDrop)]` discipline.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6 (`#[derive(Zeroize, ZeroizeOnDrop)]` plus `#[zeroize(skip)]` on the non-secret framing fields and the `Record` payload). Extensions in Task 8 (`per_block_clocks` etc.) MUST preserve this discipline.
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants are in place (now seeded ChaCha20Rng — see carry-over above); per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness.
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — this PR consumes `merge_block` / `merge_record` / `merge_vector_clocks` but does NOT modify them. If implementation friction requires touching `core/src/vault/conflict.rs` beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places (`error/vault/mod.rs` + the four orchestrator-specific mappers in `trash/`, `save/`, `restore/`, `share/`). For `BlockFingerprintMismatch` the routing was wired in PR #84; no further matcher edits are needed for Tasks 7-16.
- **File size of `core/src/vault/orchestrators.rs`** — now ~2180 lines after Task 5's call-site addition. Per `feedback_split_files_proactively` the 500-line guideline is for NEW code; this is pre-existing growth. Worth a follow-up issue (`refactor(vault): split orchestrators.rs into per-orchestrator submodules`) when the C.1.1b PR closes — but **out of scope** for the per-task commits.
- **`core/src/sync/draft.rs` size** — 270 lines (well under the 500-line guideline). Task 8's `prepare_merge` will live in `core/src/sync/prepare.rs`, not extend `draft.rs`.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget. May be relevant when sizing C.1.1b's per-block proptests in Task 15.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. C.1.1b's `commit_with_decisions` may consume them; re-check at Task 11.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. Could be closed alongside C.1.1b if `once.rs` surface is touched.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands (C.4 scope).
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 13's veto-fixture helpers may close some of #78 as a side effect — worth re-checking on Task 13 completion.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors (Task 14 of the 1a plan, deferred). Not directly C.1.1b; relisted for tracking.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. Not directly C.1.1b-relevant; tracked for the C.4 doc pass.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader between `core/tests/fixtures/mod.rs` and the lib-internal test helper added in PR #85. Refactor follow-up, scoped to ~30 min.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures. Filed off PR #85 review; current behaviour now ALSO pinned by the renamed FFI `open_vault_missing_block_file_returns_folder_invalid` test (test flips when #88 lands).
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies (two in `core/tests/`, two in `ffi/secretary-ffi-bridge/tests/`) into one shared helper per crate. Filed off PR #89 review. Cross-crate scope, ~20 min refactor.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `85763bd` on top of `ba969ef`. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, 85763bd, ba969ef

# Baseline gauntlet (expect 732 / 0 / 10 on this branch before Task 7 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Open the plan + design doc, then execute Task 7:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

## Closing inventory

- **Branch state on close:** `main` at `ba969ef` (PR #89 squash-merged Tasks 5 + baton sync + review fix-up before this session started). `feature/c1-1b-sync-merge` rebased onto `ba969ef` carrying one new commit: `85763bd` (Task 6) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 732 passed + 10 ignored (728 baseline from `ba969ef` + 4 new from Task 6). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90).
- **Open PRs:** one to be opened at end of this session covering Task 6.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close snapshot (pre-review).
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle snapshot with explicit per-issue disposition (3 fixed in-scope, 2 deferred with rationale).
  - [`docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md) — Task 4 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md) — Task 5 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md) — Task 6 close snapshot (this session).
