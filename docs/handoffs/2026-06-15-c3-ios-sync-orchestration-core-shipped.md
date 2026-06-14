# NEXT_SESSION.md — C.3 iOS sync orchestration core ✅

**Session date:** 2026-06-14→15. Flow: `/nextsession` → confirmed the prior slice (#227, Argon2id off the main actor) was already **squash-merged** to `main` (`4af7ca1`) + removed its stale worktree/branch (and a stale `ios-app-device-unlock` leftover) → asked direction → chose **C.3 mobile sync adapters**, scoped to **iOS only**, **orchestration core only** → brainstormed (Approach A: stateless ports + a thin host-tested `SyncCoordinator`; include `status`; password per-call) → design doc → 4-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/ios-sync-core`. PR: see §4. The iOS app can now run one sync pass and carry a tombstone-veto conflict to resolution, in pure host-testable Swift over the **existing** uniffi sync surface (#187). **iOS-only; no Rust / FFI / on-disk-format / crypto / CRDT change** — `git diff main...HEAD --name-only` touches only `ios/**` + `docs/**` (guardrail greps below empty).

## (1) What we shipped this session

The iOS C.3 work is decoupled from the Rust sync logic: all merge / conflict-detection / freshness-gate logic already lives in `core::sync` and is projected through uniffi as `sync_vault` (inspect / pause-on-conflict) + `sync_commit_decisions` (commit) + `sync_status` (#187). This slice builds only the Swift orchestration layer on top.

Two constraints the code-reading surfaced and the design honours:
- **`sync_vault` / `sync_commit_decisions` re-open the identity from the password → full Argon2id cost.** The real adapter offloads them off the main actor via the `runOffMainActor` helper from #227 (status runs inline — cheap disk read).
- **The conflict flow is a two-call round-trip** threading a 32-byte `manifest_hash` freshness token. The `SyncCoordinator` owns the token privately; the password is passed **per call, never stored**.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design doc + 4-task TDD plan | `b42760b` `02700bc` |
| **Task 1 — pure types** | metadata-only value types (`SyncOutcome`/`SyncStatus`/`SyncVeto`/`SyncCollision`/`SyncVetoDecision`/`PendingConflict`/`DeviceClock`), `VaultSyncPort`, dedicated `VaultSyncError`, `FakeVaultSyncPort` | `354e009` |
| **Task 2 — coordinator** | `SyncCoordinator` actor: inspect→commit round-trip, token stashed privately, password per-call; 7 host tests (TDD) | `baf07c6` |
| **Task 2 — review fixes** | accurate actor-reentrancy doc comment + a `resolve`-re-raises-conflict test (8th) | `707632c` |
| **Task 3 — adapter** | `UniffiVaultSyncPort` (DTO↔value mapping, `runOffMainActor` offload, dedicated `mapVaultSyncError`) + off-main-actor adapter test | `8ce5af0` |
| **Task 3 — review fix** | real spy assertion (replaced a no-op bool) + commit-path off-main-actor coverage | `28ee667` |
| **Docs** | README rows + ROADMAP C.3 slice-1 entry/phase-plan | (this commit) |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `4af7ca1`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live)
- `ios/SecretaryVaultAccess/` (pure, FFI-free): `SyncModels.swift`, `VaultSyncError.swift`, `VaultSyncPort.swift`, `SyncCoordinator.swift`; fake in `…Testing/FakeVaultSyncPort.swift`; tests in `…Tests/Sync{Models,Coordinator}Tests.swift`.
- `ios/SecretaryKit/` (real adapter over uniffi): `VaultAccess/UniffiVaultSyncPort.swift`, `VaultAccess/VaultSyncErrorMapping.swift`; test `…Tests/UniffiVaultSyncPortOffMainActorTests.swift`.
- `VaultSyncError` is a **dedicated** enum (NOT a reuse of `VaultAccessError`) with a **separate** `mapVaultSyncError` — the existing `mapVaultAccessError`'s doc explicitly forbids sync reuse (the sync surface returns a structurally different `VaultError` variant set). Anti-oracle conflation (`wrongPasswordOrCorrupt`) preserved.

### Acceptance (green — full gauntlet this session)
```
cd ios/SecretaryVaultAccess && swift test            → 115 tests, 0 failures
                                                        (incl. 8 SyncCoordinator + 3 SyncModels)
bash ios/scripts/run-ios-tests.sh                    → ** TEST SUCCEEDED ** + ** BUILD SUCCEEDED **
                                                        (SecretaryKit sim suite incl. both
                                                         testMainActorIsFreeWhileSyncing +
                                                         testMainActorIsFreeWhileCommitting; app build OK)
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'                 → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format|conflict.rs|core/tests/data'  → empty
```
NOTE: desktop (`pnpm test`) and Python (`pytest`) suites were **not** re-run — pure iOS Swift slice, those layers unaffected.

## (2) What's next — candidate directions

The iOS app does select / create / import / unlock / browse / record-CRUD, and now can run a sync pass + resolve conflicts **programmatically**. Reasonable next slices:
- **C.3 slice 2 — iOS file-change detection**: `NSFilePresenter` / `NSMetadataQuery` adapter + foreground trigger (per ADR-0003 mobile sync is realistically foreground-only). **Acceptance:** a change to the vault folder (or a sibling conflict-copy appearing) triggers a `SyncCoordinator.runPass`; debounced; no background-watcher assumption. State-dir/app-group path policy is decided here (host tests used a tempdir).
- **C.3 slice 3 — iOS sync UI**: a sync status indicator (uses `SyncStatus`) + a conflict-resolution modal over `PendingConflict` → `resolve(decisions:)` (mirror desktop D.1.15's Keep-mine/Accept-delete). Needs slices 2 (or manual trigger) first.
- **#224** — host RootView's route view-models as `@StateObject` so a scenePhase toggle doesn't reset wizard/unlock state. Low user impact; cross-cutting.
- **iOS biometric re-auth before a write** (policy decision first). Carried since record-CRUD.
- **C.3 Android** (SAF + `WorkManager`) — Android has no app scaffold yet; larger.
- **Rust-core backlog:** **#193** (`pipeline.rs` refactor), **#192** (collision-population test), **#190** (bridge `MergedClean` arm test), **#189** (CI lean-mobile-binding guard).

**Open follow-up issues:** carried **#224 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202(on-device sync smoke, future)**.

## (3) Open decisions and risks

- **Orchestration only — no file events, no UI this slice (intentional).** A real sync today must be triggered programmatically (`coord.runPass` / `coord.resolve`). The value shipped is the host-tested round-trip layer the next two slices sit on.
- **`SyncCoordinator` is an `actor`, but Swift actors are reentrant across `await`.** Two concurrent `runPass`/`resolve` calls can interleave at the suspension point; the *committed* token is captured before the suspension so it's never torn, but the post-await stash can interleave. The design assumes a **single serial driver per vault**; a genuinely concurrent commit is additionally backstopped FFI-side by the per-vault lockfile (`SyncInProgress`) + the `EvidenceStale` freshness gate. Documented in the coordinator's class doc.
- **`status` is `async` but runs inline** (cheap disk read, no KDF) — only `sync`/`commitDecisions` are offloaded. Deliberate; documented in the port + adapter.
- **State-dir / app-group container path is NOT decided yet** — host tests pass a tempdir; the real sandbox path choice rides with C.3 slice 2 (file detection / UI), where it's actually needed.
- **No new Rust test this slice** — the cross-language sync behaviour is already covered by the Rust/bridge/conformance suites; iOS only maps + threads. The DTO→value mapping is compiler-total (no `default` arm in `mapOutcome`).
- **Security invariants preserved** (reviews verified): anti-oracle conflation kept (`wrongPasswordOrCorrupt` not split); password never stored on the coordinator (only the non-secret token + metadata persist); veto value types are metadata-only by construction (field *names*, never values).

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/ios-sync-core

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/ios-sync-core && git branch -D feature/ios-sync-core
git worktree prune && git worktree list

# 3) Next slice: brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/ios-sync-core
( cd ios/SecretaryVaultAccess && swift test )       # 115 host tests
bash ios/scripts/run-ios-tests.sh                   # SecretaryKit sim + app build (slow; cross-compiles xcframework)
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `4af7ca1` == current `main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `4af7ca1`; `feature/ios-sync-core` carries spec + plan + the 4-task implementation (types → coordinator → adapter) + per-task review fixes + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core`-format / crypto / CRDT change.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task). Reviews caught + fixed: a `FakeVaultSyncPort` path-spy gap + an over-stated actor-serialization doc comment + a missing resolve-re-raise test (Tasks 1-2), and a cosmetic responsiveness-test assertion + a missing commit-path off-main-actor test (Task 3). No functional defects found in any review.
- **README.md / ROADMAP.md:** updated — iOS C.3 sync orchestration core ✅.
- **NEXT_SESSION.md:** symlink retargeted to this file.
