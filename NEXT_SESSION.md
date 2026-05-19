# NEXT_SESSION.md

**Session date:** 2026-05-19 (implementation session — C.1.1b Task 5 of 17 shipped, plus three pre-existing-test contract flips and one helper-signature refactor required by the new D6 invariant)
**Status:** PR #85 (Task 4) + PR #86 (baton sync) **MERGED** into `main` as `f5b108f` + `4881ee1`. `feature/c1-1b-sync-merge` reset to post-merge `main` and now carries one new commit: Task 5 ([`748377d`](https://github.com/hherb/secretary/commit/748377d)) — `verify_block_fingerprints` wired into `open_vault`, plus three pre-existing tests updated to assert the new contract, plus the `rewrite_block_with_records` helper refactored to take `&OpenVault` (mandatory under D6 — see "Plan deviation" below). 12 tasks remain (6-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`748377d`](https://github.com/hherb/secretary/commit/748377d) | Task 5 | **Production wiring**: `core/src/vault/orchestrators.rs` inserts `verify_block_fingerprints(folder, &manifest_body)?` in `open_vault` immediately after `read_and_verify_manifest`. Removes the per-task `#[allow(dead_code)]` shim PR #85 left on the helper and tightens its docstring. **New integration test**: `core/tests/open_vault.rs::open_vault_rejects_corrupted_block_file` — copies golden_vault_001 to a tempdir, flips the last byte of the first on-disk block file, asserts `open_vault` refuses with `VaultError::BlockFingerprintMismatch` (was: silently succeeded pre-D6). TDD-red proven before adding the call site; TDD-green after. **Contract flip on 3 pre-existing tests**: `save_block_then_tampered_block_fails_open` now asserts `open_vault` surfaces `BlockFingerprintMismatch` with the expected `block_uuid` (was: smoke-level out-of-band fingerprint inequality — the test comment had explicitly flagged this as the planned PR-C closure); FFI `read_block_corrupt_block_file_returns_corrupt_vault` → renamed `open_vault_corrupt_block_file_returns_corrupt_vault` (typed surface moved earlier); FFI `read_block_missing_block_file_returns_corrupt_vault` → renamed `open_vault_missing_block_file_returns_folder_invalid` (missing block routes through the guarded `Io { NotFound }` arm → `FolderInvalid`, pinning the Issue #88 baseline). **Helper-signature refactor** (out of plan scope, mandatory under D6): `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` signature changed from `(folder, block_uuid, new_records, aead_nonce)` to `(folder, &OpenVault, block_uuid, new_records, aead_nonce)` — the helper previously opened the vault internally, which after D6 fails on the second rewrite of the same fixture because the first rewrite leaves the manifest fingerprint stale. Both helper-tests updated to open BEFORE the rewrite and pass `&open`. Task 9's `rewrite_block_with_records_and_update_manifest` will compose the primitive with the manifest re-sign step. |

**Branch hygiene:** PR #84 + PR #85 + PR #86 all squash-merged into `main` (`7dff8da` → `f5b108f` → `4881ee1`). The local `feature/c1-1b-sync-merge` was reset to `origin/main` to discard the now-redundant per-PR commits and Task 5 added on top, so the branch contains exactly one new commit and a fresh PR will be visually clean.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 5:**

- `cargo test --release --workspace --no-fail-fast` → **728 / 0 / 10** (727 baseline from `4881ee1` + 1 new = `open_vault_rejects_corrupted_block_file`; the contract-flip on three pre-existing tests is test-count-neutral).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean.
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed by allowlist).

## (2) What's next — execute Task 6

### (a) First action next session: execute Task 6

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 6 — Define `draft.rs`: `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision`**. First new-file task of the merge phase: defines the public-API types `prepare_merge` returns and `commit_with_decisions` consumes, including zeroize discipline for the plaintext `Record`s these types hold after AEAD decryption.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 6"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
$EDITOR docs/manual/contributors/memory-hygiene-audit-internal.md
```

**Critical zeroize contract** — re-read [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) before completing Task 6. The new struct holds plaintext peer-side `Record`s after AEAD decryption. Derive `Zeroize + ZeroizeOnDrop` with `#[zeroize(skip)]` on non-secret fields (precedent: `VaultBundle`).

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Tasks 6 + 7 are the type-and-pure-helper foundation; Tasks 8-11 are the merge / commit core; Tasks 12-16 are tests; Task 17 is README + ROADMAP + final PR-ready baton.

### (b) Plan structure at a glance (12 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1~~ | ~~`sync_helpers` per-block rewrite + new `BLOCK_NONCE_E/F/G` constants~~ ✅ in PR #84 (`7dff8da`) |
| ~~2~~ | ~~4 new `SyncError` variants~~ ✅ in PR #84 (`7dff8da`) |
| ~~3~~ | ~~`VaultError::BlockFingerprintMismatch` variant~~ ✅ in PR #84 (`7dff8da`) |
| ~~4~~ | ~~`verify_block_fingerprints` pure-ish helper + module tests~~ ✅ in PR #85 (`f5b108f`) |
| ~~5~~ | ~~Wire `verify_block_fingerprints` into `open_vault` + integration test~~ ✅ `748377d` |
| **6** | **`draft.rs` — `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision` (zeroize-typed)** | `core/src/sync/draft.rs` NEW, `core/src/sync/mod.rs` |
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

- [ ] `cargo test --release --workspace --no-fail-fast` → 741 / 0 / 10 (727 baseline at `4881ee1` + 14 new tests total across Tasks 5-16; we're at 728 after Task 5 = 727 + 1)
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5
- [ ] Three-step `sync_once → prepare_merge → commit_with_decisions` happy-path test green
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-5 (the four new `SyncError` variants from Task 2 + the seven sync_helpers items from Task 1, including the now-refactored `rewrite_block_with_records`) and confirm each has at least one real consumer in Tasks 6-16. Stale `#[allow(dead_code)]` markers must be removed (zero in the final PR — they exist only as a per-task TDD-cadence shim). **Task 5 already removed the Task 4 `verify_block_fingerprints` marker.**

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **Task 5 helper-signature refactor (`748377d`).** Beyond the plan's "wire one call into `open_vault`" scope, this commit had to refactor `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` to take `&OpenVault` because under D6 the helper's previously-internal `open_vault` call fails on the second rewrite of the same fixture (first rewrite leaves the manifest's `BlockEntry.fingerprint` stale). The alternative — folding Task 9's manifest-update step into the primitive — would have pulled Task 9 work forward; the chosen path keeps the primitive primitive and Task 9 composes it as `rewrite_block_with_records_and_update_manifest`. Both helper-tests updated; the cached `OpenVault` is safe to reuse across rewrites because IBK / identity / owner_card are immune to block-byte changes. **Worth surfacing in the PR review** in case the plan author prefers a different decomposition.
- **Three pre-existing tests' contracts flipped (`748377d`).** `save_block_then_tampered_block_fails_open`'s test comment had already documented the original assertion as a smoke-level placeholder ("Future integration of a load block by uuid path (PR-C) will turn this into a typed-error round-trip"). C.1.1b is that PR; the flip just delivers what the comment promised. The two FFI tests were renamed (`read_block_*` → `open_vault_*`) because the typed surface moved earlier in the call chain. **Worth noting in the PR review** so future grep-by-old-name doesn't get confused.

### Carry-over from PR #84

- **Task 1 RNG seeding (now in `7dff8da` via `67567c7`)** — replaced the plan's `DeterministicNonceRng` (which would have collapsed BCK + AEAD body nonce to all-zeros across rewrites) with `ChaCha20Rng::from_seed(...)` so each rewrite genuinely uses distinct entropy. `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this deviation; the `distinct_seeds_produce_distinct_ciphertexts` test pins it. No action for Task 6+.

### Implementer's-call decisions (live for Tasks 6-11)

1. **`VaultBundle.canonical_owner_card` cache.** Task 8 picks **Path B** (re-load owner card inside `prepare_merge`) to stay self-contained. **Path A** (cache the owner card on the bundle at 1a ingest time) is faster but touches 1a code. Implementer's call when starting Task 8 — if `prepare_merge` shows up in property-test hotpaths, switch to Path A.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Plan's Task 6 defines them as `BTreeMap<[u8; 16], Vec<...>>`. Implementer may prefer a `Vec<DraftMergeBlock>` newtype if iteration order becomes important. Either works — pick one and stick to it across Tasks 6, 8, 11.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — re-read [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) before completing Task 6. The new struct holds plaintext peer-side `Record`s after AEAD decryption. Derive `Zeroize + ZeroizeOnDrop` with `#[zeroize(skip)]` on non-secret fields (precedent: `VaultBundle`).
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants are in place (now seeded ChaCha20Rng — see carry-over above); per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness.
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — this PR consumes `merge_block` / `merge_record` / `merge_vector_clocks` but does NOT modify them. If implementation friction requires touching `core/src/vault/conflict.rs` beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places (`error/vault/mod.rs` + the four orchestrator-specific mappers in `trash/`, `save/`, `restore/`, `share/`). The pattern is documented in each matcher's comment block (issue #40). For `BlockFingerprintMismatch` the routing was wired in PR #84; no further matcher edits are needed for Tasks 6-16.
- **File size of `core/src/vault/orchestrators.rs`** — now ~2180 lines after Task 5's call-site addition. Per `feedback_split_files_proactively` the 500-line guideline is for NEW code; this is pre-existing growth. Worth a follow-up issue (`refactor(vault): split orchestrators.rs into per-orchestrator submodules`) when the C.1.1b PR closes — but **out of scope** for the per-task commits.

### Issues currently open

- **[#37](https://github.com/hherb/secretary/issues/37)** — Sub-project C design discipline umbrella. C.1.1b closes the merge-layer portion.
- **[#38](https://github.com/hherb/secretary/issues/38)** — `save_block` proptest case-count budget. May be relevant when sizing C.1.1b's per-block proptests in Task 15.
- **[#45](https://github.com/hherb/secretary/issues/45)** — three `pub(crate) #[allow(dead_code)]` accessors on `OpenVaultManifest`. C.1.1b's `commit_with_decisions` may consume them; re-check at Task 11.
- **[#75](https://github.com/hherb/secretary/issues/75)** — replace `#[doc(hidden)] pub __test_dispatch` with `pub(crate)` + lib-internal tests. Could be closed alongside C.1.1b if `once.rs` surface is touched.
- **[#76](https://github.com/hherb/secretary/issues/76)** — Python clean-room replay of `sync_kat.json`. Task 16's seven new vectors will join when #76 lands (C.4 scope).
- **[#78](https://github.com/hherb/secretary/issues/78)** — C.1.1a integration-test gaps. Task 13's veto-fixture helpers may close some of #78 as a side effect — worth re-checking on Task 13 completion.
- **[#79](https://github.com/hherb/secretary/issues/79)** — sync_kat.json ingestion vectors (Task 14 of the 1a plan, deferred). Not directly C.1.1b; relisted for tracking.
- **[#81](https://github.com/hherb/secretary/issues/81)** — `MAX_BLOCK_FILE_SIZE` undocumented vs format-max recipient table. Not directly C.1.1b-relevant; tracked for the C.4 doc pass.
- **[#87](https://github.com/hherb/secretary/issues/87)** — dedup `golden_vault_001_password` reader between `core/tests/fixtures/mod.rs` and the lib-internal test helper added in PR #85. Refactor follow-up, scoped to ~30 min. Filed off the back of PR #85 review.
- **[#88](https://github.com/hherb/secretary/issues/88)** — `VaultError::Io` does not carry the failing block UUID on fingerprint-check I/O failures. Filed off the back of PR #85 review; current behaviour now ALSO pinned by the renamed FFI `open_vault_missing_block_file_returns_folder_invalid` test (test flips when #88 lands).
- **[#90](https://github.com/hherb/secretary/issues/90)** — consolidate four `copy_dir_recursive` test-helper copies (two in `core/tests/`, two in `ffi/secretary-ffi-bridge/tests/`) into one shared helper per crate. Filed off the back of PR #89 review. Cross-crate scope, ~20 min refactor.

### PR #89 review fix-ups (subsequent commit on this branch)

- **Single-source `BLOCKS_SUBDIR` / `BLOCK_FILE_EXTENSION`.** Changed both from `pub(crate)` to `#[doc(hidden)] pub` and re-exported from `vault/mod.rs` alongside `format_uuid_hyphenated` (same established cross-target test-hook pattern — see `project_secretary_cfg_test_not_propagated`). The duplicated `const`s in `core/tests/open_vault.rs` were removed.
- **`mod fixtures;` declaration moved** to the top of `core/tests/open_vault.rs` next to the other `use` block (was inlined under the §10 test section).
- **Issue #90 filed** for the cross-crate `copy_dir_recursive` consolidation — broader than this PR's scope.
- Gauntlet after fix-ups: **728 / 0 / 10** (refactor is test-count-neutral; same baseline as the Task 5 commit). Clippy + fmt + Python conformance + spec-citation freshness all clean.

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `748377d` on top of `4881ee1`. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, 748377d, 4881ee1

# Baseline gauntlet (expect 728 / 0 / 10 on this branch before Task 6 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Open the plan + design doc + memory-hygiene memo, then execute Task 6:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
$EDITOR docs/manual/contributors/memory-hygiene-audit-internal.md
```

## Closing inventory

- **Branch state on close:** `main` at `4881ee1` (PR #85 + PR #86 squash-merged before this session started). `feature/c1-1b-sync-merge` rebased onto `4881ee1` carrying one new commit: `748377d` (Task 5) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 728 passed + 10 ignored (727 baseline from `4881ee1` + 1 new from Task 5). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88).
- **Open PRs:** one to be opened at end of this session covering Task 5.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close snapshot (pre-review).
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle snapshot with explicit per-issue disposition (3 fixed in-scope, 2 deferred with rationale).
  - [`docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md) — Task 4 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md) — Task 5 close snapshot (this session).
