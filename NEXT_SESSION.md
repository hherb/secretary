# NEXT_SESSION.md

**Session date:** 2026-05-20 (implementation session — C.1.1b Task 12 of 17 shipped; `EvidenceStale` TOCTOU freshness integration test in §sync_merge.rs)
**Status:** PR #99 (Task 11) **MERGED** into `main` as [`52093aa`](https://github.com/hherb/secretary/commit/52093aa). `feature/c1-1b-sync-merge` reset onto post-merge `main` and now carries Task 12 ([`2b5b5c8`](https://github.com/hherb/secretary/commit/2b5b5c8)) — the disk-side proof that the D5 freshness re-check inside `commit_with_decisions` fires on a mid-prepare-and-commit manifest mutation AND aborts with zero disk writes. 5 tasks remain (13-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`2b5b5c8`](https://github.com/hherb/secretary/commit/2b5b5c8) | Task 12 | **`EvidenceStale` TOCTOU integration test.** New test in `core/tests/sync_merge.rs::commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes`. Setup reuses the empty-divergence fixture from Task 11's happy-path test (two concurrent manifests referencing the SAME block contents → empty `bundle.diverging_blocks` → commit has zero per-block writes). The race window is opened by `sync_helpers::write_manifest_at` rewriting the canonical manifest with a new clock between `prepare_merge` and `commit_with_decisions` — the rewrite re-signs the manifest properly so step 1 (`open_vault`) inside `commit_with_decisions` still succeeds; the failure MUST fire from step 2's freshness re-check, not from a malformed manifest. <br/>**Assertions:** <br/>• `commit_with_decisions(...)` returns `Err(SyncError::EvidenceStale)`. <br/>• Snapshot the manifest BLAKE3 immediately after the race-window mutation. <br/>• Re-read the manifest after the failed commit. <br/>• `hash_before == hash_after` — proves zero commit-side disk writes. <br/>**Why this test matters:** the EvidenceStale path is the design's intended retry signal — a concurrent writer (another device, another caller, a parallel task) racing between prepare and commit must NOT corrupt the canonical manifest. The proof is two-part: (a) the typed error fires (caller knows to retry from `sync_once`), and (b) no disk write happened (no half-completed state to clean up). Together these match the D5 contract. <br/>**Test count:** 766 → 767 on `feature/c1-1b-sync-merge`. <br/>**No production code change.** All scaffolding (`compute_manifest_hash` re-export, `EvidenceStale` typed variant, `write_manifest_at` helper, `fresh_vault_two_concurrent_manifests` fixture) was in place from Tasks 1-11; Task 12 is the documentation contract for the existing behavior. |

**Branch hygiene:** PR #99 (Task 11 + the in-PR `MANIFEST_FILENAME` consolidation refactor) was squash-merged into `main` as `52093aa` at session start (remote `feature/c1-1b-sync-merge` branch was deleted by the merge). The local `feature/c1-1b-sync-merge` was reset to `origin/main` (`52093aa`) — the local branch's three pre-merge commits (`820b0d0`, `11d436f`, `1193072`) were all already on `main` via the squash (`git diff origin/main..1193072` was empty for all four refactored files), so the reset discarded only the already-merged duplicates with no risk of work loss. Local branch now carries exactly one new commit (`2b5b5c8`) plus this baton commit.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 12:**

- `cargo test --release --workspace --no-fail-fast` → **767 / 0 / 10** (766 baseline from `52093aa` + 1 = 1 new `commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes` integration test in `core/tests/sync_merge.rs`).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed; the freshness corpus scans `crypto-design.md` / `vault-format.md` / `glossary.md` / ADRs only — the C.1.1b plan + design docs are out of scope, so the new test name doesn't appear in the resolver count).

## (2) What's next — execute Task 13

### (a) First action next session: execute Task 13 (after PR for Task 12 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 13 — Veto-handling integration tests (4-test bundle + Task 13a fixture helper)**. The first per-block-divergent fixture in the entire C.1.1b plan.

Task 13's surface is much larger than Task 12 — a 4-test bundle plus the prerequisite `fresh_vault_two_concurrent_blocks` fixture helper in `sync_helpers/mod.rs` (does NOT exist yet — confirmed by `grep -n fresh_vault_two_concurrent_blocks core/tests/sync_helpers/mod.rs` returning nothing). Per the plan: "If the fixture machinery is missing, add it as Task 13a before the 4 tests below." Plan to ship Task 13a as its own commit before the four test commits, following the `feedback_fix_all_review_issues.md` one-issue-one-commit cadence.

The four tests, each its own commit:
1. `commit_with_decisions_keep_local_overrides_peer_tombstone` — fixture has record `[0xAA]` LIVE in canonical at t=100, TOMBSTONED in sibling at t=200; `tombstone_veto_set` fires; caller decides `KeepLocal`; post-commit disk holds the live record.
2. `commit_with_decisions_accept_tombstone_finalizes_peer_delete` — same fixture, decision = `AcceptTombstone`, post-commit disk holds the tombstoned record (`tombstone=true, tombstoned_at_ms=200`).
3. `commit_with_decisions_missing_veto_decision_aborts_with_typed_error` — same fixture, `decisions: Vec::new()`, expect `SyncError::MissingVetoDecision { record_id: [0xAA; 16] }`.
4. `commit_with_decisions_unknown_veto_decision_aborts_with_typed_error` — same fixture, `decisions: vec![VetoDecision::KeepLocal { [0xAA] }, VetoDecision::KeepLocal { [0xFF] }]`, expect `SyncError::UnknownVetoDecision { record_id: [0xFF; 16] }`.

Expected workspace test count after Task 13: 767 → 771 (+1 per test × 4 tests). Task 13a helper itself adds no public test (it's a private `pub(crate)` fixture).

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 12's PR merges:
git fetch --prune origin
git reset --hard origin/main                                    # discard merged commits
# THEN open the plan:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 13"
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 13 may surface as a SINGLE PR with 5 commits (1 helper + 4 tests) or as five PRs — Task 11's experience suggests grouping commits into one PR is fine when they're tightly coupled (the four veto tests share the same fixture). Pick at PR-open time based on file-touch surface.

### (b) Plan structure at a glance (5 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1-10~~ | ~~Tasks 1-10 shipped~~ ✅ in PRs #84-#97 |
| ~~11~~ | ~~`commit_with_decisions` + DraftMerge per-block + commit/ split + happy-path test~~ ✅ PR #99 (`52093aa`) |
| ~~12~~ | ~~`EvidenceStale` integration test (manifest-hash freshness)~~ ✅ `2b5b5c8` |
| **13** | **Veto 4-test bundle (KeepLocal / AcceptTombstone / Missing / Unknown) — first per-block-divergent fixture (Task 13a: `fresh_vault_two_concurrent_blocks` helper)** | `core/tests/sync_merge.rs`, `core/tests/sync_helpers/mod.rs` |
| 14 | Crash-recovery test (partial-write reconverge — D6 proof) | `core/tests/sync_merge.rs` |
| 15 | 4 property tests | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [ ] `cargo test --release --workspace --no-fail-fast` → 766+ / 0 / 10 (766 baseline at `52093aa` + ≥1 new test across Tasks 12-16; we're at 767 after Task 12 = 766 + 1 integration test)
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
- [x] `commit_with_decisions` re-opens vault, freshness-checks manifest hash, applies decisions, re-encrypts diverging blocks, atomic block-first manifest-last write, returns `SyncState`; happy-path test (no per-block divergence) green ✅ Task 11 (PR #99 merged)
- [x] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened ✅ Task 12 (`2b5b5c8`)
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair — proven by the Task 10 unit tests; Task 13's integration coverage closes the disk-side proof
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-10 and confirm each has at least one real consumer in Tasks 11-16. Stale `#[allow(dead_code)]` markers must be removed. Task 11 retired `apply_decisions`'s and `EvidenceStale`'s `#[allow(dead_code)]` markers. The Task 9 helper `rewrite_block_with_records_and_update_manifest` carries its own `#[allow(dead_code)]` that gets retired in Task 13 (first integration-test consumer); `EmptyDraftWithVetoes` retains its own dedicated `Display` unit test in `error.rs` (defense-in-depth variant — no longer consumed by `apply_decisions` after PR #97 review-fix); the Task 1 sync_helpers items (`BLOCK_NONCE_F/G`, `SIBLING_NONCE_D`, `fresh_vault_four_concurrent_manifests`) are consumed in Tasks 13-14 (Task 12 consumed `SIBLING_NONCE_C` for its race-window manifest write — first consumer of `SIBLING_NONCE_C`).

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **Test name slightly longer than the spec citation.** Plan + design doc cite `commit_with_decisions_stale_manifest_hash_aborts`; shipped name is `commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes`. The `_with_no_disk_writes` suffix matches the second half of the assertion (post-condition: byte-identical manifest after EvidenceStale). The spec citation in `docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md` line 407 is a prefix of the shipped name — `spec_test_name_freshness.py` already PASSes; the script's corpus is `crypto-design.md` / `vault-format.md` / `glossary.md` / ADRs only, not the C.1.1b plan + design docs, so neither the shorter prefix nor the longer suffix appears in the resolver count. Reviewer can decide whether to rename the test back to the shorter citation form; current shape favors descriptive name.
- **Used `SyncState::new(vault_uuid, local_clock)` not `SyncState::empty(vault_uuid)`.** Plan's draft uses the struct-literal `SyncState { vault_uuid, highest_vector_clock_seen: Vec::new() }`. Shipped uses `SyncState::new(vault_uuid, local_clock).expect("SyncState::new")` with a third "local" device entry — matches Task 11's existing happy-path test pattern exactly. The local device entry is unrelated to canonical/sibling so the clock relation against the disk manifest is still `Concurrent` (precondition for `sync_once` to produce `ConcurrentDetected`). The plan's empty-clock form would also work (`SyncState::empty` is a public constructor and `new_accepts_empty_clock` is a passing test in `state.rs`); the chosen form was consistency with the test file's existing pattern.
- **Reused `extract_vault_uuid` helper inline (not lifted to fixtures).** The implementer's-call decision from the Task 11 baton (#3 "extract_vault_uuid helper duplication still open") remains live. Task 12 is the second integration test in `sync_merge.rs` consuming `extract_vault_uuid`; the test in `core/tests/sync.rs` also has a copy. **If Task 13 adds another consumer, lift `extract_vault_uuid` into `core/tests/fixtures/mod.rs` as `pub fn extract_vault_uuid(folder: &Path) -> [u8; 16]` and delete both inline copies.** Out of scope for Task 12.

### Carry-over from earlier PRs

- **Task 1 RNG seeding (in `7dff8da` via `67567c7`)** — `ChaCha20Rng::from_seed(...)` replaced the plan's `DeterministicNonceRng`; `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this; no action for Task 13+.
- **PR #85 helper-signature refactor (`748377d`)** — `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` takes `&OpenVault` because under D6 the helper's previously-internal `open_vault` call fails on the second rewrite of the same fixture. Task 11's `commit_with_decisions` takes `&SecretBytes` and re-opens internally (the test drops `open` before commit) — this works because `commit_with_decisions` only does ONE rewrite per call. The shared-OpenVault pattern is still useful for tests that need multiple rewrites of the same vault folder in the same test (`rewrite_block_with_records_and_update_manifest`). Task 13's `fresh_vault_two_concurrent_blocks` helper will compose this pattern.
- **`apply_decisions` is `pub(crate)`, not `pub`.** Kept the minimal surface area from Task 10. `commit_with_decisions` consumes it intra-crate via `pub(crate) use apply::apply_decisions` in `commit/mod.rs`. If a cross-crate consumer (e.g. an FFI binding) needs it, widen then — `pub(crate) → pub` is reversible; the inverse is the breaking change.
- **PR #99 in-PR refactor (`1193072`)** — promoted `vault::orchestrators::MANIFEST_FILENAME` from `const` to `pub(crate) const` so the three sync sites (`commit/write.rs`, `once.rs`, `ingest.rs`) import a single source. Surfaced during PR #99 review when Task 11's `commit/write.rs` would have added the third copy of the literal `"manifest.cbor.enc"`. Now merged into main. No action for Task 13+.

### Implementer's-call decisions (live for Tasks 13-14)

1. **`commit_with_decisions` identity argument.** Resolved in PR #99: takes `&SecretBytes` and re-opens internally. Task 13's veto-fixture tests will need to drop their `open` before calling `commit_with_decisions` (or instantiate a fresh `SecretBytes`). If lifetime gymnastics push, consider widening to also accept `&UnlockedIdentity` in a follow-up — but the current shape works for Tasks 12-14 happy paths. **Confirmed safe in Task 12** — Task 12's test uses `open_with_password` (standalone identity, no lifetime tie to a vault folder) so no `drop(open)` was needed.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Frozen in PR #99. Both are `BTreeMap<[u8; 16], …>`. If Task 13's per-block divergent fixture needs additional per-block metadata (e.g. `block_name` for a renamed block), extend with a third map rather than mutating the existing two. Don't change the existing shape — Task 11's tests pin it.
3. **`extract_vault_uuid` helper duplication (still open).** Task 8 inlined a private `extract_vault_uuid(folder: &Path) -> [u8; 16]` helper in `core/tests/sync_merge.rs`; the same helper lives in `core/tests/sync.rs::extract_golden_vault_uuid`. Task 12 reused the existing inline helper. **If Task 13's per-block-divergent fixture needs another consumer, lift it into `core/tests/fixtures/mod.rs` as `pub fn extract_vault_uuid(folder: &Path) -> [u8; 16]` and delete both inline copies.** Single refactor, ~5 min.
4. **`sync_helpers/mod.rs` file size (#95 filed).** 743 LOC after Task 9 (unchanged in Tasks 10-12). Task 13a's `fresh_vault_two_concurrent_blocks` helper will push it further (estimated +30-60 LOC). If the additional helper pushes past 800, consider splitting per #95's notes BEFORE Task 13's tests land — split first, then add the helper into the appropriate submodule.
5. **`commit/` directory split (resolved in PR #99).** Three files at 35 / 270 / 389 LOC. Each is one concept. Tasks 12-16 are tests-only and shouldn't grow `write.rs` further (Task 12 confirmed: zero production changes). If Tasks 14 or 16 do (e.g. partial-write recovery helpers, KAT-replay-side helpers), split further (`write/{mod,key_bag,block,manifest}.rs`).
6. **`prepare.rs` file size — 869 LOC.** Already over the 500 cap before Task 11; PR #99 added ~10 lines (the per-block map population). Worth filing a "split prepare.rs into mod.rs + iterative_fold.rs + veto.rs + parent_block_clock.rs" issue at C.1.1b close (Task 17), or as a standalone refactor if Tasks 13-16 push it further. Task 13's tests will exercise `prepare_merge` on per-block-divergent fixtures for the FIRST time end-to-end (Task 8's smoke and Task 11's happy-path both used empty `diverging_blocks`); any bugs surfaced should be fixed in prep without expanding the file shape.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6 + Task 11 extension. The `per_block_clocks` + `per_block_records` fields are `#[zeroize(skip)]` (BTreeMap lacks blanket Zeroize; values are non-secret public material). The drop-time wipe of inner `Record`'s secret fields still works through their own `ZeroizeOnDrop` impls on the `merged_records` vec. Task 13's first per-block-divergent fixture exercises this end-to-end for real (Tasks 8/11/12 used empty per-block maps).
- **AEAD nonce per rewrite** — `commit_with_decisions` uses `rand_core::OsRng` directly for production rewrites; per-block re-encrypt generates a fresh nonce via the standard `encrypt_block` step-4 path. Task 12's test does NOT exercise the rewrite path (it aborts at the freshness check before any block re-encrypt). Task 13's first KeepLocal/AcceptTombstone tests WILL exercise it.
- **`tempfile` exact pin** (`=3.27.0`) — unchanged this session.
- **CRDT proptests must not weaken** — Task 12 shipped no `core/src/vault/conflict.rs` changes. `commit_with_decisions` is a consumer of merge-primitive output, not a producer.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places. No new variants this session.
- **File size of `core/src/sync/commit/write.rs`** — 389 LOC (unchanged this session). Below the 500 cap. Tasks 13-16 are tests-only; if Task 14's crash-recovery test surfaces a need for production-side helpers (e.g. a manifest-only re-sign without re-encrypting blocks), split per implementer-call #5 above.
- **File size of `core/src/sync/prepare.rs`** — 869 LOC (unchanged this session). Pre-existing growth — file a tracking issue at C.1.1b close.
- **File size of `core/tests/sync_helpers/mod.rs`** — 743 LOC (unchanged this session). See #95 for the planned refactor. Task 13a's helper addition will push it further; see implementer-call #4 above.
- **File size of `core/tests/sync_merge.rs`** — 393 LOC at session end (was 287 → +113 from Task 12's test, then -7 from `cargo fmt`). Still well under the 500 cap. Task 13's 4 tests + Task 14's 1 test will push it close; if it crosses 500 BEFORE Task 17, split into `core/tests/sync_merge_*.rs` files (one per task's concern: `_happy.rs`, `_evidence.rs`, `_vetoes.rs`, `_crash.rs`) rather than waiting for the doc sweep.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 LOC (unchanged this session). Pre-existing growth, not Task-12 caused; worth filing a `refactor(vault): split orchestrators.rs into per-orchestrator submodules` issue at C.1.1b close.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget. Will be revisited when sizing C.1.1b's per-block proptests in Task 15.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. Not consumed by Task 12's freshness test (which doesn't touch `OpenVaultManifest`). Re-check at Task 13-14.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. Could be closed alongside C.1.1b if `once.rs` surface is touched (Task 13 may not touch it).
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands (C.4 scope).
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 13's veto-fixture helpers may close some of #78 as a side effect — worth re-checking on Task 13 completion.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors (Task 14 of the 1a plan, deferred). Not directly C.1.1b; relisted for tracking.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. Not directly C.1.1b-relevant; tracked for the C.4 doc pass.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader between `core/tests/fixtures/mod.rs` and the lib-internal test helper added in PR #85. Refactor follow-up, scoped to ~30 min.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures. Filed off PR #85 review; current behaviour now ALSO pinned by the renamed FFI `open_vault_missing_block_file_returns_folder_invalid` test (test flips when #88 lands).
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies into one shared helper per crate. Filed off PR #89 review. Cross-crate scope, ~20 min refactor.
- **[#95](https://github.com/hherb/secretary/issues/95)** — split `core/tests/sync_helpers/mod.rs` (~743 LOC) into submodules. Filed at Task 9 close; revisit at Task 17 or as standalone refactor (likely BEFORE Task 13a's helper addition — see implementer-call #4).
- **[#98](https://github.com/hherb/secretary/issues/98)** — `apply_decisions` duplicate-decision tightening (PR #97 review-fix follow-up). Not Task 12/13-blocking.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `2b5b5c8` (Task 12) on top of `52093aa` plus this baton commit. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, 2b5b5c8, 52093aa

# Baseline gauntlet (expect 767 / 0 / 10 on this branch before Task 13 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 12's PR merges, reset feature branch + open the plan for Task 13:
git fetch --prune origin
git reset --hard origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 13"
```

## Closing inventory

- **Branch state on close:** `main` at `52093aa` (PR #99 squash-merged Task 11 + the in-PR `MANIFEST_FILENAME` consolidation refactor). `feature/c1-1b-sync-merge` rebased onto `52093aa` carrying one new commit: `2b5b5c8` (Task 12) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 767 passed + 10 ignored (766 baseline from `52093aa` + 1 new `commit_with_decisions_stale_manifest_hash_aborts_with_no_disk_writes` integration test in `core/tests/sync_merge.rs`). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90) / [#95](https://github.com/hherb/secretary/issues/95) / [#98](https://github.com/hherb/secretary/issues/98).
- **Open PRs:** one to be opened at end of this session covering Task 12.
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
  - [`docs/handoffs/2026-05-20-c1-1b-task-11-shipped.md`](docs/handoffs/2026-05-20-c1-1b-task-11-shipped.md) — Task 11 close snapshot.
  - [`docs/handoffs/2026-05-20-c1-1b-task-12-shipped.md`](docs/handoffs/2026-05-20-c1-1b-task-12-shipped.md) — Task 12 close snapshot (this session).
