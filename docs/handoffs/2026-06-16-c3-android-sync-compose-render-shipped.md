# NEXT_SESSION.md — C.3 Android slice 5: Compose sync render ✅

**Session date:** 2026-06-16. Flow: `/nextsession` → confirmed slice 4 (#243, `190d455`) was squash-merged to `main` after the prior session → removed the stale `feature/c3-android-sync-ui-model` worktree/branch → chose **Android slice 5** (Compose sync render) → brainstormed (scope = `:sync-ui` UI components + ViewModel, no app; harness = instrumented Compose UI tests on emulator; FFI-free over `:vault-access`) → spec → 8-task TDD plan → **subagent-driven execution** (fresh implementer + two-stage spec/quality review per task; all review items fixed in-task) → final whole-branch opus review (READY TO MERGE) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-android-sync-compose` (worktree `.worktrees/c3-android-sync-compose`). PR: see §4 (push/PR is the first resume step — the user reviews/merges, this session does not merge). This slice delivers the **Android mirror of iOS slice 3's rendering layer** — the first Compose UI on Android — over the slice-4 `VaultSyncModel`. `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** render the slice-4 testable heart. A new **FFI-free** `:sync-ui` Compose library (depends on `:vault-access` only — no JNA/uniffi/NDK/`.so` on build or test path) turns `VaultSyncModel`'s StateFlows into a 5-state sync badge, a password sheet, and a metadata-only conflict-resolution sheet. The instrumented Compose UI tests run against a fake-backed model on the emulator, so they need no native library. Real app unlock/lock lifecycle wiring is deferred to a future `:app` module.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | design doc, 8-task TDD plan | `5e7d3b1` `449a139` |
| **Task 1 — scaffold** | `:sync-ui` Compose library module (+ BOM-drift fix) | `18d2e22` `45a9660` |
| **Task 2 — helpers** | `relativeSyncedLabel`/`badgeLabel`/`badgeIcon` (+ explicit clock-skew guard, realistic test clock, boundary tests; dropped material-icons-extended) | `e447610` `20321f3` |
| **Task 3 — ViewModel** | `VaultSyncViewModel` bridge (+ keep-password-sheet-open-on-error fix, zeroing contract, forwarding/resolve tests) | `3145a4e` `e31821f` |
| **Task 4 — badge** | `SyncBadge` + first Compose UI test (+ BOM 2025.05.00 / Espresso 3.7.0 for API-36; a11y semantics merge; split constants; more tests) | `4f6725a` `7992a60` |
| **Task 5 — password sheet** | `SyncPasswordSheet`/`PasswordSheetContent` + `syncErrorLabel` (+ zeroization-ownership clarity, explicit charset, cancel + error-label table tests) | `4d2e634` `491c364` |
| **Task 6 — conflict sheet** | metadata-only `ConflictResolutionSheet` (+ scrollable veto list, anti-oracle rationale docs, cancel/error/multi-veto/collision tests) | `a248968` `e4d6974` |
| **Task 7 — SyncScreen** | wiring + end-to-end UI test (+ zeroize-prior-password-on-retry, intermediate-state assertions, i18n TODO) | `f86b6d1` `3475fec` |
| **Task 8 — docs** | README + ROADMAP slice-5 ✅ (+ flipped 4 stale "Compose UI pending/remaining" refs) | `a410b78` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `190d455`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live — all package `org.secretary.sync.ui`, module `:sync-ui`)
- **`VaultSyncViewModel.kt`** — thin `androidx.lifecycle.ViewModel` over the injected `VaultSyncModel`; re-exposes its 5 StateFlows + owns `passwordSheetVisible`. Launches the model's suspend methods on `viewModelScope`. Deliberately does **not** store or zeroize the password (it's a pass-through; the screen owns the buffer because it's reused for `resolve`). Host JUnit5 tested (`Dispatchers.setMain`).
- **`SyncRenderHelpers.kt`** — pure `relativeSyncedLabel` (named bucket constants, explicit clock-skew guard), `badgeLabel`, `badgeIcon` (material-icons-**core** only), `syncErrorLabel` (exhaustive over `VaultSyncError`, no `else`; anti-oracle conflation preserved). Host-tested.
- **`SyncBadge.kt`** — stateless 5-state badge; spinner while syncing, tap disabled while syncing; `semantics(mergeDescendants=true)` for screen readers.
- **`SyncPasswordSheet.kt`** — `ModalBottomSheet` wrapper + testable `PasswordSheetContent`; password in transient `remember` (never `rememberSaveable`), cleared on every terminal path; stays open on error.
- **`ConflictResolutionSheet.kt`** — `ModalBottomSheet` wrapper + testable `ConflictSheetContent`; one `VetoCard` per veto (Keep mine / Accept delete FilterChips, default Keep mine), read-only collision summary, scrollable. **Metadata-only** — `recordType` · `tags` · `fieldNames` · device-id prefix; never a field value. Decisions via the shared `collectDecisions`.
- **`SyncScreen.kt`** — wires the VM's collected state into the three surfaces; **owns the interactive password** in transient `heldPassword` state, zeroized (`fill(0)`) on every terminal path (clean pass, conflict-resolve, cancel, dismiss, retry-overwrite), reused for the conflict `resolve`.
- **Build:** `android/build.gradle.kts` adds the Compose plugin `apply false`; `android/settings.gradle.kts` includes `:sync-ui`; `:sync-ui/build.gradle.kts` is a Compose Android library with a well-documented `resolutionStrategy` (Compose BOM 2025.05.00, Espresso 3.7.0 force for the API-36 emulator, coroutines 1.8.0 force for the test-only BOM conflict). Scoped to `:sync-ui` — siblings untouched.

### Acceptance (green — full gauntlet this session)
```
cd android && ./gradlew :sync-ui:test :vault-access:test :kit:testDebugUnitTest   → BUILD SUCCESSFUL (host JUnit5)
cd android && PATH=".../platform-tools:.../emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest   → BUILD SUCCESSFUL, 15 Compose UI tests on Medium_Phone_API_36.1 (fake-backed, no .so)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **`:sync-ui` depends on `:vault-access`, not `:kit`** — keeps the UI module FFI-free and the instrumented tests `.so`-free (they render against a `FakeVaultSyncPort`-backed model). Mirrors iOS's pure-UI / thin-conformer split.
- **VM does NOT zeroize the password; `SyncScreen` does.** The same `ByteArray` passed to `submitPassword` is retained as `heldPassword` and reused for the conflict `resolve`; if the VM zeroized after the pass, `resolve` would send an all-zero password. The screen zeroizes on terminal paths (including retry-overwrite). This is the one place to read carefully before touching the password flow.
- **Password sheet stays open on error.** `VaultSyncModel.guardedPass` swallows `VaultSyncError` into `lastError` (never throws), so the VM closes the sheet only when `lastError == null` — wrong-password keeps the sheet open for inline retry (spec/iOS parity).
- **Instrumented (emulator) Compose tests, not Robolectric** — fake-backed so no native lib; the host JUnit5 tests cover the pure helpers + VM forwarding off the emulator. Required Compose BOM 2025.05.00 + Espresso 3.7.0 (Android 16 / API 36 blocks Espresso ≤3.6's `InputManager` reflection).
- **`material-icons-extended` dropped** (~10 MB) — all 5 badge icons resolve from material-icons-core.

## (2) What's next

- **Android `:app` module — runnable walking skeleton + real lifecycle wiring.** The natural next slice: a Compose `:app` (mirror iOS `SecretaryApp`) that builds the real `(VaultSyncModel, ChangeDetectionMonitor)` via `:kit`'s `makeVaultSync`, constructs `VaultSyncViewModel(model)`, hosts `SyncScreen`, and drives the lifecycle: `monitor.start()` + `syncAtUnlock(password)` on unlock, `monitor.stop()` on lock/background, `refreshStatus()` before/after a pass for the "synced N ago" label. **Acceptance:** an unlock → browse → sync flow against a temp copy of `golden_vault_001` ([[feedback_smoke_test_temp_copy_golden_vault]]) on the emulator; an instrumented smoke proving `makeVaultSync` wiring (the one piece this slice left host-untested — it needs `Looper` + the native `.so`). Note the `SyncCoordinator` single-`Mutex` caveat: don't drive a status/badge refresh off the same coordinator while a pass is in flight (read before/after).
- **On-device veto round-trip (later, carried):** the golden vault is single-device → only `AppliedAutomatically`/`NothingToDo`, never `ConflictsPending`. Exercising `resolve`/`commitDecisions` on-device needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]). The conflict path is currently fake-driven in the instrumented suite.
- **Optional WorkManager background detection (deferred since slice 3):** foreground-only per ADR-0003; a background poll would be a second `FolderWatchPort` conformer behind the same seam.

**Other open directions (carried):** iOS biometric re-auth before write; N-device convergence topologies; durability/partition/clock-skew scenarios; Rust-core backlog #193/#192/#190/#189.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session.)

## (3) Open decisions and risks
- **No on-device app/lifecycle coverage this slice** (no `:app` module exists). Expected + matches the project model — the UI surfaces + ViewModel are fully tested (host + 15 instrumented); the real `makeVaultSync` composition is pure wiring over already-tested units. Flagged so it isn't mistaken for on-device-app-proven.
- **`makeVaultSync` has no host test** (needs Android `Looper` + the native `.so`). Deliberate — it composes already-tested units. An instrumented smoke is an `:app`-slice option.
- **Conflict path is fake-driven** in the instrumented suite (single-device golden vault never yields `ConflictsPending`). A real veto round-trip needs a seeded divergent vault (carried).
- **No production change to anything pre-existing.** Purely additive `:sync-ui` + the two single-line root build wirings; `core/`, `ffi/`, `ios/`, on-disk format untouched (both guardrails empty).

## (4) Exact commands to resume

```bash
# 0) FIRST — push the branch + open the PR (the USER reviews/merges; this session does not merge):
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-compose
git push -u origin feature/c3-android-sync-compose
gh pr create --base main --head feature/c3-android-sync-compose \
  --title "C.3 Android slice 5: Compose sync render — :sync-ui (badge, password/conflict sheets, ViewModel)" \
  --body "Android mirror of iOS slice 3's rendering layer — the first Compose UI on Android — over the slice-4 VaultSyncModel. New FFI-free :sync-ui Compose library: VaultSyncViewModel bridge + SyncBadge / SyncPasswordSheet / ConflictResolutionSheet / SyncScreen + pure render helpers. Host JUnit5 for helpers/VM; 15 instrumented Compose UI tests on the emulator (fake-backed, no .so). App lifecycle wiring deferred to a future :app module. Additive only — no core/ffi/ios/format change."

# 1) After review, squash-merge, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-sync-compose && git branch -D feature/c3-android-sync-compose
git worktree prune && git worktree list

# 2) Next direction (Android :app walking skeleton): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch (host + emulator):
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-compose/android && \
  ./gradlew :sync-ui:test :vault-access:test :kit:testDebugUnitTest
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-compose/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :sync-ui:connectedDebugAndroidTest    # 15 tests, emulator must be running
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `190d455` == current `origin/main`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory
- **Branch on close:** `main` @ `190d455`; `feature/c3-android-sync-compose` carries spec + plan + the `:sync-ui` module (6 main sources + helpers, 7 test files across host/androidTest) + build wiring + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — `:sync-ui`/`:vault-access`/`:kit` host suites + 15 instrumented Compose UI tests on `Medium_Phone_API_36.1`; both guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + two-stage spec/quality review per task; all per-task review items fixed in-task; final whole-branch opus review = READY TO MERGE). Reviews caught + fixed real items: password-sheet-stays-open-on-error (T3), coroutines pin mechanism + a11y merge (T4), zeroization-ownership contract (T5), scrollable veto list + multi-veto independence test (T6), zeroize-prior-password-on-retry (T7).
- **README.md / ROADMAP.md:** updated — Android C.3 slice 5 ✅ (Compose sync render); flipped 4 stale "Compose UI pending/remaining" references.
- **NEXT_SESSION.md:** symlink retargeted to this file.
