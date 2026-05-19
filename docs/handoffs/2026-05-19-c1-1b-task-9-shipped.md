# NEXT_SESSION.md

**Session date:** 2026-05-19 (implementation session — C.1.1b Task 9 of 17 shipped; `rewrite_block_with_records_and_update_manifest` helper + module-level round-trip test + first canonical-block-rewrite integration test)
**Status:** PR #94 (Task 8) **MERGED** into `main` as [`a46c829`](https://github.com/hherb/secretary/commit/a46c829). `feature/c1-1b-sync-merge` reset onto post-merge `main` and now carries Task 9 ([`a85fcb5`](https://github.com/hherb/secretary/commit/a85fcb5)) — the new helper composes [`rewrite_block_with_records`](https://github.com/hherb/secretary/blob/main/core/tests/sync_helpers/mod.rs) with an in-process manifest re-sign (driven by the caller's cached `OpenVault`), so the post-rewrite vault opens cleanly under the C.1.1b D6 fingerprint gate. 8 tasks remain (10-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`a85fcb5`](https://github.com/hherb/secretary/commit/a85fcb5) | Task 9 | **`core/tests/sync_helpers/mod.rs`** grew from 526 → 680 LOC. New surface: <br/>• `pub fn rewrite_block_with_records_and_update_manifest(folder, &OpenVault, block_uuid, new_records, block_seed, manifest_clock, manifest_nonce) -> [u8; 32]` — composes the per-block re-encrypt primitive with an in-process manifest re-sign so the on-disk pair (manifest + block) opens cleanly under [`open_vault`]'s D6 fingerprint gate. Drives the manifest re-sign from the caller's cached `OpenVault` handle (IBK / identity / owner_card), never re-reading disk during the inconsistent window. <br/>• `pub fn write_manifest_at(...)` — visibility widened from `fn` to `pub fn` so merge-layer integration tests can write sibling manifests directly. Docstring records the pre-condition that the on-disk vault must open cleanly, and points to the new combining helper for post-rewrite manifest writes. <br/>**New helper-module test**: `rewrite_block_and_update_manifest_round_trips_through_open_vault` — runs the helper once, then proves a fresh `open_vault` succeeds AND the returned manifest reflects both the new block fingerprint and the new top-level clock. This test runs once per integration-test binary that declares `mod sync_helpers;` (4 binaries: `sync`, `sync_ingest`, `sync_ingest_proptest`, `sync_merge`), so it contributes +4 to the workspace test count. <br/>**New integration test** — `core/tests/sync_merge.rs::prepare_merge_after_canonical_block_rewrite_produces_well_formed_draft` (155 LOC): installs one new record into a canonical block via the new helper, writes a sibling manifest at the Syncthing-convention path `manifest.cbor.enc.sync-conflict-from-device-bb`, opens the vault again to verify the helper produced a consistent state, decrypts the rewritten block to confirm the new record landed, then runs `sync_once → prepare_merge` and asserts the resulting `DraftMerge` is well-formed. Because canonical and sibling reference the same block file with identical per-block `vector_clock_summary`, `bundle.diverging_blocks` is empty (the iterative merge loop runs zero times) — the test asserts empty `vetoes` + empty `merged_records` + `post_merge_clock` includes both manifest-level device entries. Per-block divergence arrives in Task 13. <br/>**TDD discipline**: integration test referenced the helper before it existed → first `cargo build` failed with `E0425: cannot find function rewrite_block_with_records_and_update_manifest`. Implemented helper → green. <br/>**Filed `#95`** during close: 680 LOC in `sync_helpers/mod.rs` exceeds the 500-line guideline; issue documents the natural module boundaries for a follow-up refactor between Task 16 and Task 17 (or bundled into Task 17 if low-risk). |

**Branch hygiene:** PR #94 (Task 8) was squash-merged into `main` as `a46c829` at session start. The local `feature/c1-1b-sync-merge` was reset to `origin/main` to discard the now-redundant Task-8 commits + the two review-fix commits (`6051c93`, `4b39f3a`) that were rolled in. Local branch now carries exactly one new commit (`a85fcb5`) plus this baton commit.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 9:**

- `cargo test --release --workspace --no-fail-fast` → **755 / 0 / 10** (750 baseline from `a46c829` + 5 = 1 new sync_merge integration test + 4 copies of `sync_helpers::helper_tests::rewrite_block_and_update_manifest_round_trips_through_open_vault` which runs once per integration-test target that declares `mod sync_helpers;`).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed).

## (2) What's next — execute Task 10

### (a) First action next session: execute Task 10 (after PR for Task 9 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 10 — `apply_decisions` pure helper in `core/src/sync/commit.rs`**. Introduces the bijection check between a `DraftMerge`'s `vetoes` set and a caller-supplied `VetoDecision` map: every veto must have exactly one decision, every decision must reference a known veto. Wrong cardinality on either side fires `SyncError::MissingVetoDecision` / `UnknownVetoDecision` (variants defined in Task 2). 6 table-driven unit tests cover the bijection cases (4 happy + 2 typed-error). This is a pure function — no I/O, no encryption — so it goes in a new `core/src/sync/commit.rs` module and re-exports via `core/src/sync/mod.rs`.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 9's PR merges:
git fetch --prune origin
git reset --hard origin/main                                    # discard merged commits
# THEN open the plan + design doc:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 10"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 10 is a pure-function task (no integration tests), so the test count delta will be modest (+6 unit tests).

### (b) Plan structure at a glance (8 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1~~ | ~~`sync_helpers` per-block rewrite + new `BLOCK_NONCE_E/F/G` constants~~ ✅ in PR #84 (`7dff8da`) |
| ~~2~~ | ~~4 new `SyncError` variants~~ ✅ in PR #84 (`7dff8da`) |
| ~~3~~ | ~~`VaultError::BlockFingerprintMismatch` variant~~ ✅ in PR #84 (`7dff8da`) |
| ~~4~~ | ~~`verify_block_fingerprints` pure-ish helper + module tests~~ ✅ in PR #85 (`f5b108f`) |
| ~~5~~ | ~~Wire `verify_block_fingerprints` into `open_vault` + integration test~~ ✅ in PR #89 (`ba969ef`) |
| ~~6~~ | ~~`draft.rs` — `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision` (zeroize-typed)~~ ✅ in PR #91 (`7c4dd7f`) |
| ~~7~~ | ~~`tombstone_veto_set` pure helper + 7 table tests~~ ✅ in PR #93 (`0567086`) |
| ~~8~~ | ~~`prepare_merge` block decap + iterative N-way merge + first integration test~~ ✅ in PR #94 (`a46c829`) |
| ~~9~~ | ~~`rewrite_block_with_records_and_update_manifest` helper + helper-module round-trip + first canonical-rewrite integration test~~ ✅ `a85fcb5` |
| **10** | **`apply_decisions` pure helper + 6 bijection unit tests** | `core/src/sync/commit.rs` NEW, `core/src/sync/mod.rs` |
| 11 | `commit_with_decisions` — re-encrypt + atomic write + happy-path test | `core/src/sync/commit.rs`, `core/src/sync/mod.rs`, `core/tests/sync_merge.rs` |
| 12 | `EvidenceStale` integration test (manifest-hash freshness) | `core/tests/sync_merge.rs` |
| 13 | Veto-handling 4-test bundle (KeepLocal / AcceptTombstone / Missing / Unknown) — **first per-block-divergent fixture** | `core/tests/sync_merge.rs`, `core/tests/sync_helpers/mod.rs` |
| 14 | Crash-recovery test (partial-write reconverge — D6 proof) | `core/tests/sync_merge.rs` |
| 15 | 4 property tests | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [ ] `cargo test --release --workspace --no-fail-fast` → 755+ / 0 / 10 (750 baseline at `a46c829` + ≥5 new tests across Tasks 9-16; we're at 755 after Task 9 = 750 + 1 (Task 9 integration) + 4 (Task 9 helper test re-run across 4 sync_helpers consumers))
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5
- [x] `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision` defined with zeroize discipline + module tests ✅ Task 6 (PR #91 merged)
- [x] `tombstone_veto_set` pure helper with 7 table tests covering 4 interesting cases + 3 edges ✅ Task 7 (PR #93 merged)
- [x] `prepare_merge` orchestrator wires decap + iterative fold + veto detection + post_merge_clock; first integration test green ✅ Task 8 (PR #94 merged)
- [x] `rewrite_block_with_records_and_update_manifest` helper exists; post-rewrite vault opens cleanly under D6 ✅ Task 9 (`a85fcb5`)
- [ ] Three-step `sync_once → prepare_merge → commit_with_decisions` happy-path test green
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-7 and confirm each has at least one real consumer in Tasks 8-16. Stale `#[allow(dead_code)]` markers must be removed. **Task 8 retired the two Task-7 prepare.rs shims**; Task 9 adds the new helper with its own `#[allow(dead_code)]` that gets retired in Task 13 (first integration-test consumer); the Task 2 SyncError variants (`EvidenceStale`, `UnknownVetoDecision`, `MissingVetoDecision`, `EmptyDraftWithVetoes`) are consumed in Tasks 10-12; the Task 1 sync_helpers items (`BLOCK_NONCE_F/G`, `SIBLING_NONCE_C/D`, `fresh_vault_four_concurrent_manifests`) are consumed in Tasks 13-14.

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **Signature delta from the plan's draft.** The plan's Task 9 step-3 draft signature for `rewrite_block_with_records_and_update_manifest` took `(folder, block_uuid, new_records, block_nonce, manifest_clock, manifest_nonce)` and called `open_vault` internally AFTER the rewrite. That doesn't work post-C.1.1b D6 — `open_vault` fails with `BlockFingerprintMismatch` on the inconsistent-disk window. Shipped signature instead takes `(folder, &OpenVault, block_uuid, new_records, block_seed, manifest_clock, manifest_nonce)` and drives the manifest re-sign from the caller's cached handle. Same idea as the PR #85 refactor of `rewrite_block_with_records`. Plan was written 2026-05-18; PR #85 landed 2026-05-19 with the signature change — the Task 9 draft was a stale carry-over.
- **`EvidenceStale` integration test deferred to Task 12.** Plan step 5 originally added a stale-manifest test in Task 9, then the plan itself flagged this as a scope error: per D5, `prepare_merge` does NOT re-check the manifest (freshness lives in `commit_with_decisions`). The stale-manifest test belongs in Task 12. Task 9 ships without it.
- **Per-block divergence fixture deferred.** Task 9's integration test uses a fixture where canonical and sibling reference the same block file with identical per-block clocks → `bundle.diverging_blocks` is empty. The plan acknowledged this would be a smoke-level test if forcing per-block divergence required new infrastructure. To actually run `prepare_merge`'s iterative fold path, Task 13 will either extend `rewrite_block_with_records_and_update_manifest` to also write a separate sibling block file with a different per-block clock, OR add a dedicated `write_sibling_with_block_summary` helper. Decision deferred until Task 13.

### Carry-over from earlier PRs

- **Task 1 RNG seeding (in `7dff8da` via `67567c7`)** — `ChaCha20Rng::from_seed(...)` replaced the plan's `DeterministicNonceRng`; `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this; no action for Task 10+.
- **PR #85 helper-signature refactor (`748377d`)** — `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` takes `&OpenVault` because under D6 the helper's previously-internal `open_vault` call fails on the second rewrite of the same fixture. Task 9's `rewrite_block_with_records_and_update_manifest` builds on the same pattern.

### Implementer's-call decisions (live for Tasks 10-13)

1. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Tasks 6+8 froze the minimal six-field `DraftMerge` shape (`vault_uuid`, `manifest_hash`, `plan`, `vetoes`, `merged_records`, `post_merge_clock`); Task 11's `commit_with_decisions` may need to extend it with `per_block_clocks: BTreeMap<[u8; 16], Vec<VectorClockEntry>>` to support per-block re-sign. If added, **MUST preserve the existing `#[derive(Zeroize, ZeroizeOnDrop)]` discipline** — `#[zeroize(skip)]` on the new framing fields with a comment explaining "non-secret, BTreeMap lacks blanket Zeroize" mirrors the existing pattern.
2. **`extract_vault_uuid` helper duplication (still open).** Task 8 inlined a private `extract_vault_uuid(folder: &Path) -> [u8; 16]` helper in `core/tests/sync_merge.rs`; the same helper lives in `core/tests/sync.rs::extract_golden_vault_uuid`. If Task 10+ integration tests need it, lift it into `core/tests/fixtures/mod.rs` as `pub fn extract_vault_uuid(folder: &Path) -> [u8; 16]` and delete both duplicates. Still out of scope for Task 9 (one duplicate is a copy, not a pattern).
3. **`sync_helpers/mod.rs` file size (#95 filed).** 680 LOC after Task 9 — natural module boundaries documented in #95. Not in Task 9's scope; revisit at C.1.1b close (Task 17) or as a standalone refactor PR if Tasks 10-16 push it further.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6. Task 11's `commit_with_decisions` may add fields; if any field carries secret material it MUST derive `Zeroize` or be wrapped in a zeroize-typed container.
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants are in place (now seeded ChaCha20Rng); per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness.
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — Task 9 ships test infrastructure only; no `core/src/vault/conflict.rs` changes. If implementation friction in Task 10+ requires touching the merge primitives beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places. No new variants in Task 9 or expected in Tasks 10-16.
- **File size of `core/src/sync/prepare.rs`** — 460 lines after Task 8 (unchanged in Task 9). Task 10/11 may push it past 500 since `commit_with_decisions` lives in a new module; if so, monitor.
- **File size of `core/tests/sync_helpers/mod.rs`** — 680 lines after Task 9. See #95 for the planned refactor.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 lines after Task 5's call-site addition. Pre-existing growth, not Task-9 caused; worth filing a `refactor(vault): split orchestrators.rs into per-orchestrator submodules` issue at C.1.1b close.

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

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `a85fcb5` (Task 9) on top of `a46c829` plus this baton commit. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, a85fcb5, a46c829

# Baseline gauntlet (expect 755 / 0 / 10 on this branch before Task 10 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 9's PR merges, reset feature branch + open the plan + design doc for Task 10:
git fetch --prune origin
git reset --hard origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 10"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

## Closing inventory

- **Branch state on close:** `main` at `a46c829` (PR #94 squash-merged Task 8 + review-fix commits). `feature/c1-1b-sync-merge` rebased onto `a46c829` carrying one new commit: `a85fcb5` (Task 9) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 755 passed + 10 ignored (750 baseline from `a46c829` + 5 = 1 new sync_merge integration test + 4 helper-test re-runs across the four `sync_helpers`-consuming integration binaries). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95).
- **Open PRs:** one to be opened at end of this session covering Task 9.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close snapshot (pre-review).
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle snapshot with explicit per-issue disposition.
  - [`docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md) — Task 4 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md) — Task 5 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md) — Task 6 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md) — Task 7 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md) — Task 8 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-9-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-9-shipped.md) — Task 9 close snapshot (this session).
