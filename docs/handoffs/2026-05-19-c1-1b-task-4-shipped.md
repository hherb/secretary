# NEXT_SESSION.md

**Session date:** 2026-05-19 (implementation session — C.1.1b Task 4 of 17 shipped on top of merged PR #84 scaffolding)
**Status:** PR #84 (Tasks 1-3 + 2 PR-review fix-ups) **MERGED** into `main` as squash commit [`7dff8da`](https://github.com/hherb/secretary/commit/7dff8da). `feature/c1-1b-sync-merge` has been rebased onto post-merge `main` and now carries one commit: Task 4 ([`55b3afe`](https://github.com/hherb/secretary/commit/55b3afe)) — the `verify_block_fingerprints` pure-ish helper plus two module-local tests. 13 tasks remain (5-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`55b3afe`](https://github.com/hherb/secretary/commit/55b3afe) | Task 4 | `core/src/vault/orchestrators.rs`: new `pub(crate) verify_block_fingerprints(folder, manifest) -> Result<(), VaultError>` helper. Walks `manifest.blocks`, reads each `blocks/<uuid>.cbor.enc` file, BLAKE3-256 hashes the bytes, compares against `BlockEntry.fingerprint`. First mismatch surfaces as `VaultError::BlockFingerprintMismatch { block_uuid, expected, got }` (the variant added in Task 3). `#[allow(dead_code)]` as a per-task TDD shim — Task 5 wires the call site into `open_vault` and removes the marker. Plus two module-local tests (`verify_block_fingerprints_ok_on_consistent_vault` + `verify_block_fingerprints_detects_corrupted_block`) and three inline test helpers (`open_golden_vault_manifest_inline` + `read_golden_vault_001_password` + `copy_recursive`) so the lib-internal tests exercise the `pub(crate)` surface without crossing the integration-test boundary. |

**Branch hygiene:** PR #84's squash-merge collapsed Tasks 1-3 + the two PR-review fix-ups into single commit `7dff8da` on main. The local `feature/c1-1b-sync-merge` was reset to `origin/main` and Task 4 cherry-picked on top, so the branch now contains exactly one new commit and a fresh PR will be visually clean.

**Gauntlet:** 726 passed / 0 failed / 10 ignored (724 from PR #84's squash + 2 new from Task 4). Clippy + fmt + Python conformance + spec-citation freshness all clean.

## (2) What's next — execute Task 5

### (a) First action next session: execute Task 5

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 5 — Wire `verify_block_fingerprints` into `open_vault`**. This is the call-site addition that makes Task 4's helper actually do work — partial-commit corruption becomes a typed error at vault-open time. Removes the `#[allow(dead_code)]` shim Task 4 added.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 5"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Tasks 4 + 5 are the natural fingerprint-check pair; Tasks 6-11 are the merge / commit core; Tasks 12-16 are tests; Task 17 is README + ROADMAP + final PR-ready baton.

### (b) Plan structure at a glance (13 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1~~ | ~~`sync_helpers` per-block rewrite + new `BLOCK_NONCE_E/F/G` constants~~ ✅ in PR #84 (`7dff8da`) |
| ~~2~~ | ~~4 new `SyncError` variants~~ ✅ in PR #84 (`7dff8da`) |
| ~~3~~ | ~~`VaultError::BlockFingerprintMismatch` variant~~ ✅ in PR #84 (`7dff8da`) |
| ~~4~~ | ~~`verify_block_fingerprints` pure-ish helper + module tests~~ ✅ `55b3afe` |
| **5** | **Wire `verify_block_fingerprints` into `open_vault` + integration test** | `core/src/vault/orchestrators.rs`, `core/tests/open_vault.rs` |
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

- [ ] `cargo test --release --workspace --no-fail-fast` → 740 / 0 / 10 (724 baseline + 16 new tests total across Tasks 4-16; we're at 726 after Task 4 = 724 + 2)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [ ] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` (**Task 5 closes this; Task 4 has the helper but no production caller yet**)
- [ ] Three-step `sync_once → prepare_merge → commit_with_decisions` happy-path test green
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-4 (the four new `SyncError` variants from Task 2 + the seven sync_helpers items from Task 1 + `verify_block_fingerprints` from Task 4) and confirm each has at least one real consumer in Tasks 5-16. Stale `#[allow(dead_code)]` markers must be removed (zero in the final PR — they exist only as a per-task TDD-cadence shim). Task 5 removes the Task 4 marker.

## (3) Open decisions and risks

### Carry-over from PR #84

- **Task 1 RNG seeding (now in `7dff8da` via `67567c7`)** — replaced the plan's `DeterministicNonceRng` (which would have collapsed BCK + AEAD body nonce to all-zeros across rewrites) with `ChaCha20Rng::from_seed(...)` so each rewrite genuinely uses distinct entropy. `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this deviation; the `distinct_seeds_produce_distinct_ciphertexts` test pins it. No action for Task 5+.

### Implementer's-call decisions (live for Tasks 6-11)

1. **`VaultBundle.canonical_owner_card` cache.** Task 8 picks **Path B** (re-load owner card inside `prepare_merge`) to stay self-contained. **Path A** (cache the owner card on the bundle at 1a ingest time) is faster but touches 1a code. Implementer's call when starting Task 8 — if `prepare_merge` shows up in property-test hotpaths, switch to Path A.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Plan's Task 6 defines them as `BTreeMap<[u8; 16], Vec<...>>`. Implementer may prefer a `Vec<DraftMergeBlock>` newtype if iteration order becomes important. Either works — pick one and stick to it across Tasks 6, 8, 11.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — re-read [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) before completing Task 6. The new struct holds plaintext peer-side `Record`s after AEAD decryption. Derive `Zeroize + ZeroizeOnDrop` with `#[zeroize(skip)]` on non-secret fields (precedent: `VaultBundle`).
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants are in place (now seeded ChaCha20Rng — see carry-over above); per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness.
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — this PR consumes `merge_block` / `merge_record` / `merge_vector_clocks` but does NOT modify them. If implementation friction requires touching `core/src/vault/conflict.rs` beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places (`error/vault/mod.rs` + the four orchestrator-specific mappers in `trash/`, `save/`, `restore/`, `share/`). The pattern is documented in each matcher's comment block (issue #40). For `BlockFingerprintMismatch` the routing was wired in PR #84; no further matcher edits are needed for Task 5.
- **File size of `core/src/vault/orchestrators.rs`** — now at ~2160 lines after Task 4's helper + tests. Per `feedback_split_files_proactively` the 500-line guideline is for NEW code; this is pre-existing growth. Worth a follow-up issue (`refactor(vault): split orchestrators.rs into per-orchestrator submodules`) when the C.1.1b PR closes — but **out of scope** for the per-task commits.

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

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `55b3afe` on top of `7dff8da`. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, 55b3afe, 7dff8da

# Baseline gauntlet (expect 726 / 0 / 10 on this branch):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Open the plan + design doc, then execute Task 5:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

## Closing inventory

- **Branch state on close:** `main` at `7dff8da` (PR #84 squash-merged this session, before Task 4 started). `feature/c1-1b-sync-merge` rebased onto `7dff8da` carrying one new commit: `55b3afe` (Task 4) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 726 passed + 10 ignored (724 baseline from `7dff8da` + 2 new from Task 4). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81).
- **Open PRs:** one to be opened at end of this session covering Task 4.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close snapshot (pre-review).
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle snapshot with explicit per-issue disposition (3 fixed in-scope, 2 deferred with rationale).
  - [`docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md) — Task 4 close snapshot (this session).
