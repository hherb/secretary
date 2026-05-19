# NEXT_SESSION.md

**Session date:** 2026-05-19 (implementation session — C.1.1b Task 8 of 17 shipped; `prepare_merge` orchestrator + first integration test landed)
**Status:** PR #93 (Task 7) **MERGED** into `main` as [`0567086`](https://github.com/hherb/secretary/commit/0567086). `feature/c1-1b-sync-merge` reset onto post-merge `main` and now carries Task 8 ([`6abfc13`](https://github.com/hherb/secretary/commit/6abfc13)) — `prepare_merge` is the orchestrator that turns a `VaultBundle` into a `DraftMerge` by decapping each diverging block envelope, composing pairwise `merge_block` folds, running `tombstone_veto_set` per record, and folding manifest-level vector clocks. Both Task-7 `#[allow(dead_code)]` shims removed (their first real consumer is now wired). 9 tasks remain (9-17).

## (1) What we shipped this session

| Commit | Task | What it adds |
|---|---|---|
| [`6abfc13`](https://github.com/hherb/secretary/commit/6abfc13) | Task 8 | **`core/src/sync/prepare.rs`** grew from 263 → 460 LOC (still well under the 500-line guideline). New surface: <br/>• `pub fn prepare_merge(vault_folder, identity, bundle, plan) -> Result<DraftMerge, SyncError>` — the orchestrator. Iterates `plan.diverging_blocks`; for each, decodes + AEAD-decrypts the canonical envelope and every copy envelope, then composes an iterative pairwise fold via `merge_block` (canonical → +copy_0 → +copy_1 → …). After folding, runs `tombstone_veto_set` across the merged accumulator vs the per-copy plaintexts for each `record_uuid`. Extends a `BTreeMap<record_uuid, Record>` across blocks (outer-level dedup). Final step: `merge_vector_clocks` across canonical + every copy for `post_merge_clock`. <br/>• `struct BlockReaderKeys` — once-per-call owner-card + reader-secret material so the per-block loop doesn't re-encode the owner card or re-parse secret keys. Zeroize discipline: `X25519Secret` (= `Sensitive<[u8; 32]>`) + `MlKem768Secret` zeroize on drop; stack residue from the `x_sk_bytes` move-copy is wiped per `crypto::kem::derive_wrap_key` precedent. <br/>• Private helpers: `derive_block_reader_keys` (one disk read for the owner card via `read_vault_manifest_full`; Path B in the plan, bundle-side caching deferred), `decrypt_block_envelope` (decode + decrypt one envelope under the shared keys), `block_clock_on_manifest` (per-block `vector_clock_summary` lookup with typed `InvalidArgument` on miss). <br/>**Per-copy block-clock pairing**: `bundle.copies[i]` is the parent manifest of `bundle.diverging_blocks[uuid].copy_envelopes[i]` — 1a writes them in matched positional order; Task 8 mirrors that contract. <br/>**First real consumer of `tombstone_veto_set` + `last_modifier_device`** — both `#[allow(dead_code)]` shims removed in this commit (per the Task 17 audit checklist: stale markers die when the consumer lands). <br/>**Public re-export** — `core/src/sync/mod.rs` adds `pub use prepare::prepare_merge;`. <br/>**New integration test** — `core/tests/sync_merge.rs` (123 LOC): `prepare_merge_on_two_concurrent_manifests_returns_draft_with_no_vetoes` pins the empty-divergence case. Sets up two concurrent manifests via `fresh_vault_two_concurrent_manifests` (canonical + Syncthing-style sibling); `bundle.diverging_blocks` is empty (no block was rewritten), so `prepare_merge` runs zero iterations of the per-block loop. Asserts: empty `vetoes`, empty `merged_records`, `draft.vault_uuid` matches `vault.toml`, and `post_merge_clock` includes both canonical and sibling device entries. Tasks 9 + 13 will add the non-empty / veto-bearing cases. <br/>**TDD red-then-green** — committed test against a missing `prepare_merge` export first; compile failed with `E0432: no `prepare_merge` in `sync``. Added impl → green. Iterated once on the sibling filename (initial guess `manifest.conflict-copy.0001.cbor.enc` didn't match `enumerate_manifest_siblings`'s `starts_with("manifest.cbor.enc")` prefix; switched to Syncthing-style suffix per `core/tests/sync_ingest.rs:109`). |

**Branch hygiene:** PR #93 (Task 7) was squash-merged into `main` as `0567086` mid-session-start. The local `feature/c1-1b-sync-merge` was reset to `origin/main` to discard the now-redundant Task-7 commits (`49b8b35`, `0e1e519`, `27da3b2`, `863b7a9`, `10ba16b`) before adding Task 8 on top, so the branch contains exactly one new commit (`6abfc13`) plus this baton commit. Next PR will be visually clean.

**Gauntlet on `feature/c1-1b-sync-merge` after Task 8:**

- `cargo test --release --workspace --no-fail-fast` → **744 / 0 / 10** (741 baseline from `0567086` + 3 = my 1 new integration test + 2 copies of `sync_helpers::helper_tests::{rewrite_block_with_records_round_trips, distinct_seeds_produce_distinct_ciphertexts}` which re-run as part of the new `sync_merge` integration target — Rust treats each integration test file as its own binary, so any `mod sync_helpers;` declaration brings the helper-module tests along).
- `cargo clippy --release --workspace --tests -- -D warnings` → clean (one in-progress nested-list `doc_overindented_list_items` warning surfaced during iteration and was fixed by flattening the nested list in the `# Algorithm` rustdoc section).
- `cargo fmt --all -- --check` → clean.
- `uv run core/tests/python/conformance.py` → PASS.
- `uv run core/tests/python/spec_test_name_freshness.py` → PASS (96 resolved / 0 unresolved / 2 suppressed).

## (2) What's next — execute Task 9

### (a) First action next session: execute Task 9 (after PR for Task 8 merges)

Open the plan at [`docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md`](docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md) → **Task 9 — `prepare_merge` staleness check + block-rewrite fixture**. Task 8's test used two manifests with the SAME block contents (only manifest-level clocks diverged), so `bundle.diverging_blocks` was empty and the iterative merge loop never executed. Task 9 adds a fixture that **rewrites a block file** in the temp dir (composing Task 1's `rewrite_block_with_records` primitive with the manifest re-sign step into the new `rewrite_block_with_records_and_update_manifest` helper) so `bundle.diverging_blocks` is non-empty and the merge loop actually runs end-to-end. Also adds the explicit staleness-check integration test for `SyncError::EvidenceStale` (manifest mutated between `sync_once` and `prepare_merge`).

```bash
cd /Users/hherb/src/secretary/.worktrees/c1-1b-sync-merge
# AFTER Task 8's PR merges:
git fetch --prune origin
git reset --hard origin/main                                    # discard merged commits
# THEN open the plan + design doc:
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 9"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

Per `feedback_stay_in_inner_loop`, keep the one-task-one-commit-one-review cadence. Task 9 introduces the first **non-trivial merge fixture** — expect the integration test to actually exercise the per-block decap + iterative fold path; debug-print the result if anything surprises.

### (b) Plan structure at a glance (9 remaining of 17)

| Task | What it builds | New / modified files |
|---|---|---|
| ~~1~~ | ~~`sync_helpers` per-block rewrite + new `BLOCK_NONCE_E/F/G` constants~~ ✅ in PR #84 (`7dff8da`) |
| ~~2~~ | ~~4 new `SyncError` variants~~ ✅ in PR #84 (`7dff8da`) |
| ~~3~~ | ~~`VaultError::BlockFingerprintMismatch` variant~~ ✅ in PR #84 (`7dff8da`) |
| ~~4~~ | ~~`verify_block_fingerprints` pure-ish helper + module tests~~ ✅ in PR #85 (`f5b108f`) |
| ~~5~~ | ~~Wire `verify_block_fingerprints` into `open_vault` + integration test~~ ✅ in PR #89 (`ba969ef`) |
| ~~6~~ | ~~`draft.rs` — `DraftMerge` + `RecordTombstoneVeto` + `VetoDecision` (zeroize-typed)~~ ✅ in PR #91 (`7c4dd7f`) |
| ~~7~~ | ~~`tombstone_veto_set` pure helper + 7 table tests~~ ✅ in PR #93 (`0567086`) |
| ~~8~~ | ~~`prepare_merge` block decap + iterative N-way merge + first integration test~~ ✅ `6abfc13` |
| **9** | **`rewrite_block_with_records_and_update_manifest` helper + first divergent-block test + EvidenceStale integration test** | `core/tests/sync_helpers/mod.rs`, `core/tests/sync_merge.rs` |
| 10 | `apply_decisions` pure helper + 6 bijection tests | `core/src/sync/commit.rs` NEW, `core/src/sync/mod.rs` |
| 11 | `commit_with_decisions` — re-encrypt + atomic write + happy-path test | `core/src/sync/commit.rs`, `core/src/sync/mod.rs`, `core/tests/sync_merge.rs` |
| 12 | `EvidenceStale` integration test (manifest-hash freshness) — may already land in Task 9 depending on factoring | `core/tests/sync_merge.rs` |
| 13 | Veto-handling 4-test bundle (KeepLocal / AcceptTombstone / Missing / Unknown) | `core/tests/sync_merge.rs`, `core/tests/sync_helpers/mod.rs` |
| 14 | Crash-recovery test (partial-write reconverge — D6 proof) | `core/tests/sync_merge.rs` |
| 15 | 4 property tests | `core/tests/sync_merge_proptest.rs` NEW |
| 16 | 7 KAT vectors + replay extension | `core/tests/data/sync_kat.json`, `core/tests/sync_kat.rs` |
| 17 | README + ROADMAP + NEXT_SESSION baton + handoff snapshot + final gauntlet + open PR | `README.md`, `ROADMAP.md`, `NEXT_SESSION.md`, `docs/handoffs/*` |

### (c) Acceptance criteria for the C.1.1b PR (final)

- [ ] `cargo test --release --workspace --no-fail-fast` → 745+ / 0 / 10 (728 baseline at `ba969ef` + ≥17 new tests across Tasks 6-16; we're at 744 after Task 8 = 728 + 4 (Task 6) + 7 (Task 7 lib) + 2 (PR #93 review-fix) + 1 (Task 8 integration) + 2 (helper_tests re-run in the new sync_merge target))
- [ ] `cargo clippy --release --workspace --tests -- -D warnings` → clean
- [ ] `cargo fmt --all -- --check` → clean
- [ ] `uv run core/tests/python/conformance.py` → PASS
- [ ] `uv run core/tests/python/spec_test_name_freshness.py` → PASS (no unresolved citations)
- [x] `verify_block_fingerprints` runs eagerly in `open_vault`; corrupted-block test fires `VaultError::BlockFingerprintMismatch` ✅ Task 5
- [x] `DraftMerge` / `RecordTombstoneVeto` / `VetoDecision` defined with zeroize discipline + module tests ✅ Task 6 (PR #91 merged)
- [x] `tombstone_veto_set` pure helper with 7 table tests covering 4 interesting cases + 3 edges ✅ Task 7 (PR #93 merged, +2 review-fix)
- [x] `prepare_merge` orchestrator wires decap + iterative fold + veto detection + post_merge_clock; first integration test green ✅ Task 8
- [ ] Three-step `sync_once → prepare_merge → commit_with_decisions` happy-path test green
- [ ] `EvidenceStale` integration test fires on stale manifest_hash + asserts NO disk writes happened
- [ ] Bijection: `MissingVetoDecision` + `UnknownVetoDecision` typed errors fire on every non-bijective `(vetoes, decisions)` pair
- [ ] Crash-recovery test (Task 14) proves CRDT-idempotent reconvergence after partial commit
- [ ] All four CRDT proptests (commutativity, associativity, idempotence, well-formedness) still pass — **must not weaken**
- [ ] **Before merging Task 17:** grep every `#[allow(dead_code)]` introduced in Tasks 1-7 and confirm each has at least one real consumer in Tasks 8-16. Stale `#[allow(dead_code)]` markers must be removed. **Task 8 retired the two Task-7 prepare.rs shims**; the Task 2 SyncError variants (`EvidenceStale`, `UnknownVetoDecision`, `MissingVetoDecision`, `EmptyDraftWithVetoes`) are consumed in Tasks 10-12; the Task 1 sync_helpers items (`BLOCK_NONCE_E/F/G`, `golden_vault_001_first_block_uuid`, `block_file_path`, `decrypt_block_using_open`, `rewrite_block_with_records`) get their first integration-test consumers in Task 9.

## (3) Open decisions and risks

### Plan deviation from this session (carry into PR review)

- **`canonical_owner_card` cache on `VaultBundle` deferred (Path A → Path B).** The plan flagged Path A (cache the owner card on the bundle at 1a ingest time) as the faster option but called out it would require touching 1a code. Task 8 picked **Path B**: re-load the owner card inside `prepare_merge` via `read_vault_manifest_full`. Cost: one extra manifest verify-and-decrypt per `prepare_merge` call (no Argon2id — the IBK is cached on `UnlockedIdentity`). If a property test in Task 15 shows `prepare_merge` in a hot path, switch to Path A then.
- **Sibling filename fixed mid-iteration.** Initial test used `manifest.conflict-copy.0001.cbor.enc` (matching a hypothetical naming convention not in the codebase); `enumerate_manifest_siblings` requires `starts_with("manifest.cbor.enc")` per `core/src/sync/ingest.rs:184`, so the sibling was silently skipped → bundle.copies was empty → `post_merge_clock` missed the sibling device. Switched to `manifest.cbor.enc.sync-conflict-from-device-bb` (Syncthing convention, also used by `core/tests/sync_ingest.rs:109`) and the test went green. **Lesson**: when in doubt about filename heuristics, grep existing 1a integration tests for the discovery pattern.
- **Doc comment nested-list reformat.** Initial Task 8 rustdoc had a nested `a/b/c/d` list under "Algorithm", which clippy's `doc_overindented_list_items` rejected. Flattened into a single paragraph numbered-list step. Kept the prose semantics; lost a level of structure (worth it — clippy `-D warnings` gate).
- **`merging_device` for `merge_block` is the owner's `user_uuid`.** In single-owner v1 there's no separate `device_uuid` field on `IdentityBundle`; `user_uuid` serves both roles. The merge primitive bumps `merging_device`'s component on the post-merge clock — that's the local-owner advance. If multi-device support lands later, the call site here will need a real device_uuid plumbing.

### Carry-over from earlier PRs

- **Task 1 RNG seeding (in `7dff8da` via `67567c7`)** — `ChaCha20Rng::from_seed(...)` replaced the plan's `DeterministicNonceRng`; `BLOCK_NONCE_E/F/G` constants are kept (so subsequent tasks reference what the plan names) but their semantic is now "RNG seed", not "on-disk AEAD nonce". The PR #84 review accepted this; no action for Task 9+.
- **PR #85 helper-signature refactor (`748377d`)** — `core/tests/sync_helpers/mod.rs::rewrite_block_with_records` takes `&OpenVault` because under D6 the helper's previously-internal `open_vault` call fails on the second rewrite of the same fixture. Task 9's `rewrite_block_with_records_and_update_manifest` will compose the primitive with the manifest re-sign step.

### Implementer's-call decisions (live for Tasks 9-11)

1. **`DraftMerge.per_block_clocks` + `per_block_records` shape.** The plan's Task 6 froze the minimal six-field `DraftMerge` shape; Task 9 may need to extend it with `per_block_clocks: BTreeMap<[u8; 16], Vec<VectorClockEntry>>` to support the commit path's per-block re-sign requirement. If added, **MUST preserve the existing `#[derive(Zeroize, ZeroizeOnDrop)]` discipline** — `#[zeroize(skip)]` on the new framing fields with a comment explaining "non-secret, BTreeMap lacks blanket Zeroize" mirrors the existing pattern.
2. **`extract_vault_uuid` helper duplication.** Task 8 inlined a private `extract_vault_uuid(folder: &Path) -> [u8; 16]` helper in `core/tests/sync_merge.rs`; the same helper lives in `core/tests/sync.rs::extract_golden_vault_uuid`. If Task 9 or later integration tests need it too, lift it into `core/tests/fixtures/mod.rs` as `pub fn extract_vault_uuid(folder: &Path) -> [u8; 16]` and delete both duplicates. **Out of scope for Task 8** (one duplicate is a copy, not a pattern).

### Risks (from the design doc, restated for plan execution)

- **`DraftMerge` zeroize discipline** — ✅ in place from Task 6. `prepare_merge` constructs the DraftMerge via struct literal; if any field is added in Task 9+ that holds secret material (e.g. cached plaintext records), it MUST derive `Zeroize` or be wrapped in a zeroize-typed container.
- **AEAD nonce per rewrite** — distinct `BLOCK_NONCE_E/F/G` constants are in place (now seeded ChaCha20Rng); per-test fixtures use distinct values. Sharing key+nonce across rewrites in the same test would violate AEAD uniqueness.
- **`tempfile` exact pin** (`=3.27.0`) — do NOT bump as part of this work.
- **CRDT proptests must not weaken** — Task 8 consumes `merge_block` / `merge_vector_clocks` but does NOT modify them. If implementation friction in Task 9+ requires touching `core/src/vault/conflict.rs` beyond a bug fix, stop and push back.
- **`SyncOutcome::ConcurrentDetected` is large** — variant carries `clippy::large_enum_variant` allow (already in place from 1a). No change needed.
- **Exhaustive `VaultError` matchers in `secretary-ffi-bridge`** — adding a new core variant is a compile error in 5 places. For `BlockFingerprintMismatch` the routing was wired in PR #84; no further matcher edits expected for Tasks 9-16.
- **File size of `core/src/sync/prepare.rs`** — 460 lines after Task 8 (still under 500-line guideline). Task 9 may push it past 500; if so, split veto-detection helpers (`tombstone_veto_set` + `last_modifier_device`) into `core/src/sync/veto.rs` per `feedback_split_files_proactively`.
- **File size of `core/src/vault/orchestrators.rs`** — ~2180 lines after Task 5's call-site addition. Pre-existing growth, not Task-8 caused; worth filing a `refactor(vault): split orchestrators.rs into per-orchestrator submodules` issue at C.1.1b close.

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

### Open PRs at close

**To be opened at end of this session** — `feature/c1-1b-sync-merge` carries `6abfc13` (Task 8) on top of `0567086` plus this baton commit. PR body will reference this baton.

## (4) Exact commands to resume

```bash
cd /Users/hherb/src/secretary
git fetch --prune origin
git status --short                                              # expect: clean
git worktree list                                               # expect: main + .worktrees/c1-1b-sync-merge

cd .worktrees/c1-1b-sync-merge
pwd                                                             # confirm worktree
git branch --show-current                                       # → feature/c1-1b-sync-merge
git log --oneline -3                                            # last 3: this baton, 6abfc13, 0567086

# Baseline gauntlet (expect 744 / 0 / 10 on this branch before Task 9 starts):
cargo test --release --workspace --no-fail-fast 2>&1 | grep -E "^test result:" | awk '{passed+=$4; failed+=$6; ignored+=$8} END {print "PASSED:", passed, "FAILED:", failed, "IGNORED:", ignored}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -3
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -3

# AFTER Task 8's PR merges, reset feature branch + open the plan + design doc for Task 9:
git fetch --prune origin
git reset --hard origin/main
$EDITOR docs/superpowers/plans/2026-05-18-c1-1b-sync-merge.md   # jump to "Task 9"
$EDITOR docs/superpowers/specs/2026-05-18-c1-1b-sync-merge-design.md
```

## Closing inventory

- **Branch state on close:** `main` at `0567086` (PR #93 squash-merged Task 7 + 2 review-fix commits). `feature/c1-1b-sync-merge` rebased onto `0567086` carrying one new commit: `6abfc13` (Task 8) + this baton commit.
- **Workspace tests on `feature/c1-1b-sync-merge`:** 744 passed + 10 ignored (741 baseline from `0567086` + 3 = 1 new sync_merge integration test + 2 helper_tests re-run via new integration target). Clippy + fmt + Python conformance + spec-citation freshness all clean.
- **README.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **ROADMAP.md:** unchanged this session. Per plan Task 17, updates land at end of C.1.1b.
- **CLAUDE.md:** unchanged this session.
- **Open issues:** [#37](https://github.com/hherb/secretary/issues/37) / [#38](https://github.com/hherb/secretary/issues/38) / [#45](https://github.com/hherb/secretary/issues/45) / [#75](https://github.com/hherb/secretary/issues/75) / [#76](https://github.com/hherb/secretary/issues/76) / [#78](https://github.com/hherb/secretary/issues/78) / [#79](https://github.com/hherb/secretary/issues/79) / [#81](https://github.com/hherb/secretary/issues/81) / [#87](https://github.com/hherb/secretary/issues/87) / [#88](https://github.com/hherb/secretary/issues/88) / [#90](https://github.com/hherb/secretary/issues/90).
- **Open PRs:** one to be opened at end of this session covering Task 8.
- **Worktrees on disk:** `main` + `.worktrees/c1-1b-sync-merge`.
- **Frozen baton snapshots:**
  - [`docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md`](docs/handoffs/2026-05-19-c1-1b-tasks-1-3-shipped.md) — Tasks 1-3 close snapshot (pre-review).
  - [`docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md`](docs/handoffs/2026-05-19-c1-1b-pr-84-review-fixes.md) — PR #84 review-fix cycle snapshot with explicit per-issue disposition.
  - [`docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-4-shipped.md) — Task 4 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-5-shipped.md) — Task 5 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-6-shipped.md) — Task 6 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-7-shipped.md) — Task 7 close snapshot.
  - [`docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md`](docs/handoffs/2026-05-19-c1-1b-task-8-shipped.md) — Task 8 close snapshot (this session).
