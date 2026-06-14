# NEXT_SESSION.md — Argon2id off the main actor ✅

**Session date:** 2026-06-14. Flow: `/nextsession` → confirmed the prior slice (#226, iOS `include_deleted` Rust gate) was already **squash-merged** to `main` (`9d43e7b`) + removed its stale worktree/branch → asked which direction → chose **Argon2id off the main actor** → brainstormed (Approach A: async ports, the `SecretaryKit` adapters own the offload) → design doc → 4-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task) → final whole-branch review → full gauntlet green.

**Status:** ✅ **code-complete + all-green** on branch `feature/argon2id-off-main-actor`. PR: see §4. Moves the CPU-heavy Argon2id **open** and **create** KDF off the iOS main actor so the UI no longer freezes during the ~0.5–1 s derivation. **iOS-only; no Rust / FFI / on-disk-format / crypto / CRDT change** (`git diff main...HEAD --name-only` touches only `ios/**` + docs; no `core/` / `ffi/` / `core/tests/data/` change).

## (1) What we shipped this session

`VaultOpenPort.openWith{Password,Recovery}` and `VaultCreatePort.create` became `async throws`. The real `UniffiVaultOpenPort` / `UniffiVaultCreatePort` adapters offload the synchronous FFI call through a shared `runOffMainActor` helper (`withCheckedThrowingContinuation` + `DispatchQueue.global(qos: .userInitiated)`), so the `@MainActor` `UnlockViewModel` / `VaultProvisioningViewModel` **suspend rather than block** during the KDF. Device unlock is untouched (HKDF, already fast). The pure view-models keep their full state machines (only `await` added); a new `SuspensionGate` test actor lets host tests hold a fake port mid-call and prove the main actor is free.

The offload uses `withCheckedThrowingContinuation` rather than `Task.detached` **on purpose**: `Task<Success>` constrains `Success: Sendable`, but the open adapter returns `any VaultSession` (a non-`Sendable` `AnyObject`), which would emit a Swift-5.9 Sendable warning; the continuation primitive's result type is unconstrained, so the session crosses back cleanly. The gauntlet confirmed **zero Swift Sendable/concurrency warnings**.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design doc + 4-task TDD plan | `e9cf097` `380edf3` |
| **Open path** | `VaultOpenPort` → `async`; `UniffiVaultOpenPort` offload via new `runOffMainActor`; new `SuspensionGate` test actor + unlock responsiveness test; threaded open-path tests | `7ed5c98` |
| **Open path — review fixes** | `SuspensionGate` single-waiter doc + asserts; softened test comment; new `RunOffMainActorTests` (non-`Sendable` return + error propagation) | `727d99e` |
| **Create path** | `VaultCreatePort.create` → `async`; `UniffiVaultCreatePort` body wrapped in `runOffMainActor`; create responsiveness test; threaded create-path tests | `7cfa0e1` |
| **Create path — review nit** | clarified `runOffMainActor` doc (create returns `Sendable` `CreatedVault`, shares helper for consistency) | `2726073` |
| **Docs** | README new row + corrected stale rows; ROADMAP progress bar + dated checklist entry | `1b94b22` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `9d43e7b`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Acceptance (green — full gauntlet this session)
```
cd ios/SecretaryVaultAccess && swift test                 → 103 tests, 0 failures (incl. testMainActorIsFreeWhileOpening + testMainActorIsFreeWhileCreating)
bash ios/scripts/run-ios-tests.sh                         → ** TEST SUCCEEDED ** + ** BUILD SUCCEEDED **
                                                            (SecretaryKit sim suites all 0 failures, incl. RunOffMainActorTests;
                                                             both responsiveness tests pass on sim; app build succeeded)
grep "warning:" gauntlet-log | (not the pre-existing ld SDK-version note)  → none — zero Swift Sendable/concurrency warnings
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'  → empty (only ios/ + docs)
git diff main...HEAD --name-only | grep -E 'crypto-design|vault-format|conflict.rs|core/|ffi/secretary-ffi|core/tests/data'  → empty (no core/ffi/KAT change)
```
NOTE: desktop (`pnpm test`) and Python (`pytest`) suites were **not** re-run — this slice touches no Rust/FFI/desktop/Python code (pure iOS Swift), so those layers are unaffected.

## (2) What's next — candidate directions

The iOS app now does select / create / import / unlock / browse / record-CRUD with the deleted-record gate in Rust **and** a responsive UI during the KDF. Reasonable next slices:
- **#224** — host RootView's route view-models as `@StateObject` so a scenePhase toggle (backgrounding mid-wizard/unlock) doesn't reset state. Cross-cutting RootView refactor; low user impact today. **Acceptance:** backgrounding mid-create returns to the same step with state intact; `.unlock`/`.browse` VMs survive a scenePhase toggle; entering `.create` fresh starts clean.
- **iOS biometric re-auth before a write** (policy decision first — when/what to re-gate). Carried since record-CRUD.
- **Sync mobile track:** **C.3** (mobile sync adapters) + **C.4** (cross-device convergence conformance) — the next sync milestones after C.2's headless CLI.
- **Rust-core backlog:** **#193** (`pipeline.rs` refactor), **#192** (collision-population test).

**Open follow-up issues:** carried **#224 / #192 / #193 / #186 / #189 / #190 / #161 / #162 / #167**.

## (3) Open decisions and risks

- **Offload mechanism is `runOffMainActor`, not `Task.detached`** — deliberate, to avoid a Swift-5.9 Sendable warning on the non-`Sendable` `VaultSession` return; documented in the helper's doc comment and the design doc. If a future Swift-6 strict-concurrency migration happens, revisit whether the gate/helper need `Sendable` annotations (currently fine under the 5.9 language mode).
- **`SuspensionGate` is a single-waiter rendezvous** — at most one `enterAndWait()` and one `waitUntilEntered()` waiter at a time (the responsiveness tests use exactly one of each); `assert` guards catch a violation in test builds. It lives in the shipping `SecretaryVaultAccessTesting` library product (same convention as the existing fakes); not firewalled from release builds — pre-existing pattern, flagged by the final review as a "someday maybe", not a defect.
- **Responsiveness tests hang-on-regression** rather than fail-fast (a synchronous-on-main-actor regression would deadlock the test → XCTest timeout). This is intentional and consistent across both paths; a hung test is still a red CI.
- **Security invariants verified preserved end-to-end** (final whole-branch review): the anti-oracle conflated error still surfaces from inside the offload closure; the create path's persist-before-reveal ordering + `MnemonicOutput.wipe()` lifetime stay entirely on the background thread (the secret is created+wiped inside the closure; only the value-type `CreatedVault`/phrase crosses back); no extra lingering secret copy from the GCD hop.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/argon2id-off-main-actor

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/argon2id-off-main-actor && git branch -D feature/argon2id-off-main-actor
git worktree prune && git worktree list

# 3) Next slice: brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/argon2id-off-main-actor
( cd ios/SecretaryVaultAccess && swift test )       # 103 host tests
bash ios/scripts/run-ios-tests.sh                   # SecretaryKit sim + app build (slow; cross-compiles xcframework)
git diff main...HEAD --name-only | grep -vE '^(ios/|docs/|README.md|ROADMAP.md)'   # expect empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `9d43e7b` == current `main`, confirmed `0/0` vs `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `9d43e7b`; `feature/argon2id-off-main-actor` carries spec + plan + the 4-task implementation (open + create) + per-task review fixes + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — see §1. No `core`-format / crypto / CRDT change.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; final whole-branch review). Reviews caught + fixed: a `SuspensionGate` single-waiter footgun + an over-stated test comment + a missing focused `runOffMainActor` test (Task 1), and a too-narrow `runOffMainActor` doc comment (Task 2). The final review confirmed the security property (anti-oracle conflation + secret-lifetime + persist-before-reveal) preserved end-to-end. No functional defects found in any review.
- **README.md / ROADMAP.md:** updated — iOS Argon2id-off-main-actor ✅.
- **NEXT_SESSION.md:** symlink retargeted to this file.
