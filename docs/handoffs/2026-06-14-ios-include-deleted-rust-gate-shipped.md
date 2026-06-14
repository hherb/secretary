# NEXT_SESSION.md — iOS `include_deleted` Rust gate ✅

**Session date:** 2026-06-14. Flow: `/nextsession` → confirmed Slice 2 (#225, iOS vault create/import) merged to `main` (`d59ab59`) + removed the stale `.worktrees/ios-vault-create-import` worktree → brainstormed **iOS `include_deleted` Rust gate** (chose Approach A: unify in the shared bridge `read_block`, single source of truth across all platforms; re-read on toggle) → design doc → 8-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task) → final whole-branch review → full gauntlet green.

**Status:** ✅ **code-complete + all-green** on branch `feature/ios-include-deleted-rust-gate`. PR: see §4. Moves record-level tombstone visibility off the iOS Swift client into the shared Rust bridge `read_block(include_deleted)` — the Rust core is now the **single source of truth** for tombstone visibility across iOS + desktop + Python. **No on-disk-format / crypto / CRDT change** (`git diff main...HEAD --name-only | grep -E 'crypto-design|vault-format|conflict.rs|core/src/vault/record.rs'` → empty; no `core/tests/data/` KAT change).

## (1) What we shipped this session

A withheld (tombstoned, `include_deleted=false`) record now builds **no** `FieldHandle` in the bridge — its secret field bytes never cross the FFI seam. The iOS "Show deleted" toggle **re-reads** the block through the gate (desktop D.1.5 parity) instead of filtering cached records client-side, so the client never holds withheld data. Desktop dropped its now-duplicate `project_block_detail` tombstone filter. Conformance replay passes `include_deleted=true` in all three languages (cross-language parity) — no `read_block` KAT vector carries a tombstone, so no KAT regeneration.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design doc + 8-task TDD plan | `e45a43f` `08b2a4d` |
| **Pure helper** | `record_is_visible(tombstone, include_deleted)` + truth-table test (bridge) | `15fed2a` |
| **Bridge gate (workspace-atomic)** | `read_block` gains `include_deleted`; gate before any `FieldHandle`; UDL + uniffi namespace + pyo3 wrapper + desktop callers + KAT helpers all threaded; `decrypt_block_plaintext` unchanged | `5c25157` |
| **Desktop consolidation** | `project_block_detail` drops its redundant tombstone filter + the param; bridge is sole gate | `dbe2927` |
| **Swift harnesses** | smoke + conformance `readBlock` threaded (`run.sh` + `run_conformance.sh` 27/27) | `112b412` |
| **Kotlin harnesses** | smoke + conformance `readBlock` threaded (`run.sh` + `run_conformance.sh` 27/27) | `68df212` |
| **Python pyo3 tests** | `read_block` threaded (86 pytest pass) | `5f9ec81` |
| **iOS app** | `VaultSession.readBlock(blockUuid:includeDeleted:)`; `VaultBrowseViewModel.showDeleted` re-reads via `didSet`; `visibleRecords` is now a thin accessor (no client-side filter); `FakeVaultSession` models the gate + a `lastIncludeDeleted` spy; SecretaryKit sim gate assertion (both branches, real FFI, temp copy) | `ffac73f` |
| **Final-review fix** | corrected a stale `RecordView` doc comment (untouched file the new seam invalidated) | `f54206d` |
| **Docs** | README new row + corrected 2 now-stale rows; ROADMAP date + progress bar | (this commit) |

Branch from `main` @ `d59ab59`. **Squash-merge collapses to one commit on `main`.**

### Acceptance (green — full gauntlet this session)
```
cargo test --release --workspace                         → green (incl. tombstone_record_hides_from_read_block both branches + conformance KAT)
cargo clippy --release --workspace --tests -- -D warnings → clean
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh + run_conformance.sh   → smoke OK; conformance 27/27
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh + run_conformance.sh  → smoke OK; conformance 27/27
(cd ffi/secretary-ffi-py && maturin develop --release && pytest tests/) → 86 passed
(cd desktop && pnpm test)                                 → 478 passed  [NOTE: desktop uses pnpm, not npm]
(cd ios/SecretaryVaultAccess && swift test)               → 101 tests, 0 failures
bash ios/scripts/run-ios-tests.sh                         → host green; SecretaryKit sim 14/14 (incl. new gate assertion); app BUILD/TEST SUCCEEDED
git diff main...HEAD --name-only | grep -E 'crypto-design|vault-format|conflict.rs|core/src/vault/record.rs'  → empty
git status --short core/tests/data/                       → empty (no KAT drift)
```

## (2) What's next — candidate directions

The iOS app now does select / create / import / unlock / browse / record-CRUD with the deleted-record gate in Rust. Reasonable next slices:
- **#224** — host RootView's route view-models as `@StateObject` so a scenePhase toggle (backgrounding mid-wizard/unlock) doesn't reset state. Cross-cutting RootView refactor; low user impact today. **Acceptance:** backgrounding mid-create returns to the same step with state intact; `.unlock`/`.browse` VMs survive a scenePhase toggle; entering `.create` fresh starts clean.
- **Argon2id off the main actor** — both `UnlockViewModel` and `VaultProvisioningViewModel` block the main actor during the CPU-heavy KDF (documented in-code as accepted). **Acceptance:** the KDF runs on a background executor; the UI stays responsive (no main-actor stall) during open/create; tests prove the VM still transitions correctly.
- **iOS biometric re-auth before a write** (policy decision first — when/what to re-gate).
- **Sync mobile track:** **C.3** (mobile sync adapters) + **C.4** (cross-device convergence conformance) — the next sync milestones after C.2's headless CLI.
- **Rust-core backlog:** **#193** (`pipeline.rs` refactor), **#192** (collision-population test).

**Open follow-up issues:** carried **#224 / #192 / #193 / #186 / #189 / #190 / #161 / #162 / #167**.

## (3) Open decisions and risks

- **Single source of truth is now real**: `read_block(include_deleted)` is the only tombstone-visibility gate; desktop's `project_block_detail` filter is gone. `locate_record` (desktop reveal path) keeps a defensive tombstone skip as defense-in-depth (reveal always passes `include_deleted=false`) — intentional, documented, not double-gating.
- **Re-read on toggle** is deliberate (chosen over caching both result sets) — the client never retains withheld tombstoned records in memory. Cost: one block decrypt per toggle, same cost as selecting a block (accepted; consistent with the existing `@MainActor` VM idiom).
- **Conformance parity**: the cross-language replay pins `include_deleted=true` everywhere so no record is filtered out of the agreement check. Verified no `read_block` KAT vector carries a tombstone, so this is observationally identical to `false` and required no KAT regeneration. If a future vector adds a tombstone, the parity value must stay consistent across Rust/Swift/Kotlin.
- **Process note:** desktop tests run under **pnpm** (`desktop/pnpm-lock.yaml`), not npm. A subagent ran `npm install`/`npm test` (it worked, 478 passed) but created a spurious `desktop/package-lock.json` which was removed before commit. Use `cd desktop && pnpm test` next time.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/ios-include-deleted-rust-gate

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/ios-include-deleted-rust-gate && git branch -D feature/ios-include-deleted-rust-gate
git worktree prune && git worktree list

# 3) Next slice: brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/ios-include-deleted-rust-gate
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh && bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh && bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
( cd ffi/secretary-ffi-py && uv run --with maturin maturin develop --release && uv run --with pytest pytest tests/ -q )
( cd desktop && pnpm test )
( cd ios/SecretaryVaultAccess && swift test ) && bash ios/scripts/run-ios-tests.sh
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `d59ab59`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `d59ab59`; `feature/ios-include-deleted-rust-gate` carries spec + plan + the 8-task implementation + final-review fix + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core`-format / crypto / CRDT change.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; capable-model reviews on the bridge gate + iOS VM + the whole branch). Reviews caught + fixed: premature doc tense (Task 1), redundant pyo3 `#[pyo3(signature)]` + missing wrapper-doc (Task 2), a stale "Mirror project_block_detail" comment (Task 3), and a stale `RecordView` doc comment (final review). No functional defects found in any review — the security property (no `FieldHandle` for withheld records) and cross-language flag consistency verified end-to-end.
- **README.md / ROADMAP.md:** updated — iOS `include_deleted` Rust gate ✅; corrected the two now-stale "filtered client-side" statements.
- **NEXT_SESSION.md:** symlink retargeted to this file.
