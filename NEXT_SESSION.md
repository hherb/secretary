# NEXT_SESSION.md

**Session date:** 2026-05-19 (implementation session — C.1.1b Tasks 1-3 of 17 shipped, two PR-review fix-ups landed)
**Status:** `feature/c1-1b-sync-merge` advanced by 3 task commits + 2 PR-review fix-ups (test helpers + 4 new SyncError variants + new VaultError variant with full FFI-bridge exhaustive-match wiring + seed-padding annotation + `format_uuid_hyphenated` dedup). `main` at `98d8a8a` (unchanged). PR #84 open and tracking; remaining 14 tasks layer on the same branch.

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`67567c7`](https://github.com/hherb/secretary/commit/67567c7) | Task 1 | `core/tests/sync_helpers/mod.rs`: per-block rewrite helper `rewrite_block_with_records`, `decrypt_block_using_open` round-trip helper, `block_file_path` / `golden_vault_001_first_block_uuid` path helpers, three new `BLOCK_NONCE_E/F/G` constants. Two inline helper tests prove wire-format round-trip + AEAD-uniqueness across distinct seeds. **Plan deviation:** the plan's `DeterministicNonceRng` would have collapsed BCK + AEAD body nonce to all-zeros across rewrites (caught by the new `distinct_seeds_produce_distinct_ciphertexts` test); replaced with `ChaCha20Rng::from_seed(...)` so each rewrite genuinely uses distinct entropy. `rand_chacha = "0.3"` was already a workspace dep — no new dependency. |
| [`7fa201b`](https://github.com/hherb/secretary/commit/7fa201b) | Task 2 | `core/src/sync/error.rs`: four new `SyncError` variants — `EvidenceStale`, `UnknownVetoDecision { record_id }`, `MissingVetoDecision { record_id }`, `EmptyDraftWithVetoes`. All wired with stable Display strings + per-variant unit tests; not yet consumed by any call site (Tasks 8-11 wire them). |
| [`dcaed3a`](https://github.com/hherb/secretary/commit/dcaed3a) | Task 3 | `core/src/vault/mod.rs`: new `VaultError::BlockFingerprintMismatch { block_uuid, expected, got }` variant (D6 partial-commit detection). Plus the routing decision propagated into all **five** exhaustive `VaultError → FfiVaultError` matchers in `secretary-ffi-bridge` (per issue #40 these are intentionally exhaustive — adding a new core variant is a compile error). Routing: generic `From<VaultError>` impl folds to `CorruptVault` (the read path that `open_vault?` uses, same semantic as `RestoreVerificationFailed`); trash / save / restore / share orchestrator-specific mappers list in the `SaveCryptoFailure` bucket for exhaustiveness (unreachable because `open_vault` always precedes them). |
| `7633deb` | PR-review fix | `core/tests/sync_helpers/mod.rs`: comment block on `ChaCha20Rng::from_seed` seed construction explaining why the trailing 8 bytes are zero (the BLOCK_NONCE_E/F/G constants are 24-byte AEAD nonces being used as 32-byte seeds; distinct across the first 24 bytes is sufficient for distinct seeds, and injecting randomness would break the determinism the `distinct_seeds_produce_distinct_ciphertexts` invariant depends on). Pure comment; no behaviour change. |
| `acc5085` | PR-review fix | `core/src/vault/{orchestrators.rs,mod.rs}` + `core/tests/sync_helpers/mod.rs`: promote `format_uuid_hyphenated` from `pub(crate)` to `#[doc(hidden)] pub` and re-export from `vault/mod.rs`, mirroring the `__test_dispatch` cross-target test-hook pattern. The duplicate `format_uuid_for_filename` in `sync_helpers` is gone; `block_file_path` now calls the canonical core helper. On-disk filename format is now single-sourced across production code, sync layer, and test helpers. |

**Gauntlet progression:** 713 (baseline) → 719 (+6 helper tests × 3 including crates) → 723 (+4 sync::error) → 724 (+1 vault::tests). Test count unchanged across the two PR-review fix commits (both are non-test refactors). Clippy + fmt + Python conformance + spec-citation freshness all clean at every commit.

## (2) What's next — execute Task 4 first

### (a) First action next session: execute Task 4

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 4 — `verify_block_fingerprints` pure-ish helper**. This is the first task that introduces new observable behavior (BLAKE3-256 re-hashing every on-disk block file at `open_vault` time and surfacing `VaultError::BlockFingerprintMismatch` on disagreement). Tasks 1-3 only added scaffolding; Task 4 is the first that the user will exercise via `open_vault`.

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md  # jump to "Task 4"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Per `feedback_stay_in_inner_loop`, continue the one-task-one-commit-one-review cadence. Tasks 4 + 5 (wiring) form a natural pair; Tasks 6-11 are the merge / commit core; Tasks 12-16 are tests; Task 17 is README + ROADMAP + final PR-ready baton.

### (b) Plan structure at a glance (14 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1~~ | ~~`sync_helpers` per-block rewrite + new `BLOCK_NONCE_E/F/G` constants~~ ✅ `67567c7` | `core/tests/sync_helpers/mod.rs` |
| ~~2~~ | ~~4 new `SyncError` variants~~ ✅ `7fa201b` | `core/src/sync/error.rs` |
| ~~3~~ | ~~`VaultError::BlockFingerprintMismatch` variant~~ ✅ `dcaed3a` | `core/src/vault/mod.rs` + 5 FFI matchers |
| **4** | **`verify_block_fingerprints` pure-ish helper + module tests** | `core/src/vault/orchestrators.rs` |
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
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-3 (`BLOCK_NONCE_E/F/G`, `golden_vault_001_first_block_uuid`, `block_file_path`, `rewrite_block_with_records`, `decrypt_block_using_open`, `fresh_vault_two_concurrent_manifests`, `fresh_vault_four_concurrent_manifests`, `SIBLING_NONCE_C/D`, plus the four new `SyncError` variants: `EvidenceStale`, `UnknownVetoDecision`, `MissingVetoDecision`, `EmptyDraftWithVetoes`) and confirm each has at least one real consumer in Tasks 4-16. Stale `#[allow(dead_code)]` markers must be removed (zero in the final PR — they exist only as a per-task TDD-cadence shim).

## (3) Open decisions and risks

### Plan deviation already in flight (carry into review)

- **Task 1 RNG seeding (`67567c7`)** — the plan's `DeterministicNonceRng` would have collapsed BCK + AEAD body nonce to all-zeros across rewrites; replaced with `ChaCha20Rng::from_seed(...)` so each rewrite genuinely uses distinct entropy. The constant names `BLOCK_NONCE_E/F/G` are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The new `distinct_seeds_produce_distinct_ciphertexts` test pins this fix. **Worth surfacing in the PR review** — if the plan author wants the original literal nonce-as-output behavior, the test would need to flip, but the security argument favors the seeded approach.

### Implementer's-call decisions (carry from prior baton)

1. **`VaultBundle.canonical_owner_card` cache.** Task 8 picks **Path B** (re-load owner card inside `prepare_merge`) to stay self-contained. **Path A** (cache the owner card on the bundle at 1a ingest time) is faster but touches 1a code. Implementer's call when starting Task 8 — if `prepare_merge` shows up in property-test hotpaths, switch to Path A.
2. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** Plan's Task 6 defines them as `BTreeMap<[u8; 16], Vec<...>>`. Implementer may prefer a `Vec<DraftMergeBlock>` newtype if iteration order becomes important. Either works — pick one and stick to it across Tasks 6, 8, 11.

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — re-read [`docs/manual/contributors/memory-hygiene-audit-internal.md`](docs/manual/contributors/memory-hygiene-audit-internal.md) before completing Task 6. The new struct holds plaintext peer-side `Record`s after AEAD decryption. Derive `Zeroize + ZeroizeOnDrop` with `#[zeroize(skip)]` on non-secret fields (precedent: `VaultBundle`).
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants in Task 1 ✅ (now seeded ChaCha20Rng — see plan deviation above); per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness.
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — this PR consumes `merge_block` / `merge_record` / `merge_vector_clocks` but does NOT modify them. If implementation friction requires touching `core/src/vault/conflict.rs` beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places (`error/vault/mod.rs` + the four orchestrator-specific mappers in `trash/`, `save/`, `restore/`, `share/`). The pattern is documented in each matcher's comment block (issue #40). For `BlockFingerprintMismatch` the routing already wires to `CorruptVault` on the read path; no further matcher edits are needed for Task 4/5.

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

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `c925a57` (plan + prior baton) → `67567c7` → `7fa201b` → `dcaed3a` + the updated baton commit. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -10                                           # last 4: this baton, dcaed3a, 7fa201b, 67567c7, c925a57

# Baseline gauntlet (expect 724 / 0 / 10 on this branch):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:"
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# Open the plan + design doc, then execute Task 4:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

## Closing inventory

- **Branch state on close:** `main` at `98d8a8a` (unchanged this session). `feature/c1-1b-sync-merge` advanced 6 commits past the plan-authored `c925a57` baseline: `67567c7` → `7fa201b` → `dcaed3a` → prior baton → `7633deb` → `acc5085` → this baton.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 724 passed + 10 ignored (713 baseline + 11 new across Tasks 1-3; unchanged across the two PR-review fix-ups). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81).
- **Open PRs:** one to be opened at end of this session covering Tasks 1-3.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close snapshot (pre-review).
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle snapshot with explicit per-issue disposition (3 fixed in-scope, 2 deferred with rationale).
