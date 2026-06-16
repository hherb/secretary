# NEXT_SESSION.md — C.3 Android slice 6: `:app` walking skeleton ✅

**Session date:** 2026-06-17. Flow: `/nextsession` → found the slice-4 baton stale (slice 4 had merged as #243, and slice 5 was already shipped + open as PR #245) → user merged #245 → synced `main` (@ `cbf1adf`) + pruned the merged worktree → chose **Android slice 6** (`:app` walking skeleton) → brainstormed (3 decisions: **sync-only** scope since Android has no open/browse port, `Unlock → SyncScreen` flow, real-FFI `makeVaultSync` smoke as the test bar) → spec → 8-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-slice opus review (one must-fix: secret-zeroize on the error path — fixed) → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-android-app-skeleton` (worktree `.worktrees/c3-android-app-skeleton`). PR: see §4 (push/PR is the first resume step — **the user reviews/merges; this session does not merge**). This slice delivers the **first runnable Android app target** — a Compose `:app` that hosts the slice-5 `SyncScreen` over the **real** `makeVaultSync` lifecycle, closing the one host-untested seam (`makeVaultSync` + `VaultSyncModel.syncAtUnlock` over the real `SyncCoordinator` + native `.so`) with an on-device instrumented smoke. `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** wrap slice-5's rendering layer in a real, runnable app. A new `com.android.application` `:app` module bundles a writable copy of `golden_vault_001` (staged from `core/tests/data`) as a demo vault. A minimal unlock screen takes the vault password → builds `makeVaultSync` on the main thread → runs a silent `syncAtUnlock` → routes to the slice-5 `SyncScreen` (badge + password/conflict sheets). The folder monitor's `start()`/`stop()` is bound to the `Route.Sync` composition; `FLAG_SECURE` blocks screenshots/app-switcher capture. **Sync-only** — record browse/edit is deferred (Android has no vault open/browse FFI port yet; that's a future slice).

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | design doc, 8-task TDD plan | `a88d19f` `5384f22` |
| **Task 1 — scaffold** | `:app` `com.android.application` module + `stageGoldenVaultForApp` asset staging (+ gitignore centralized to match `:kit`) | `8852f9b` `0424f4f` |
| **Task 2 — uuid parse** | pure `parseVaultUuidHex` + 3 host tests | `e05161d` |
| **Task 3 — state dir** | pure `syncStateDir(base)` + host test | `2f6a0d5` |
| **Task 4 — provisioning** | `AppVaultProvisioning` (stage writable copy to `filesDir` + parse pinned uuid) | `c35f3da` |
| **Task 5 — suspend syncAtUnlock** | `VaultSyncViewModel.syncAtUnlock` → `suspend` (so the app awaits before zeroizing) + host test | `37e84ae` |
| **Task 6 — Compose glue** | `UnlockScreen` + `AppRoot` routing/lifecycle + `MainActivity` (FLAG_SECURE) | `82f01f9` |
| **Task 6 — review fix** | bind monitor `start`/`stop` to the `Route.Sync` `DisposableEffect` (closes orphaned-monitor window; drops redundant key) | `690d7c1` |
| **Task 7 — instrumented smoke** | `MakeVaultSyncSmokeTest` (real `.so`: happy → `Synced`, wrong pw → error) + pinned `activity-compose:1.8.2` (latent androidTest-classpath bug) | `782764c` |
| **Task 8 — docs** | README + ROADMAP slice-6 ✅ (+ flipped the stale "lifecycle wiring deferred to a future :app module" slice-5 forward-ref) | `39198e1` |
| **Final-review fix** | zeroize unlock password on **every** exit (incl. early provisioning/factory throw); provisioning failure returns to Unlock instead of an uncaught-coroutine crash | `b1f7cd2` |
| **Handoff** | this file + retargeted `NEXT_SESSION.md` symlink | (this commit) |

Branch from `main` @ `cbf1adf`. **Squash-merge collapses to one commit on `main`** (per-commit SHAs above are pre-squash).

### Architecture (where the pieces live — package `org.secretary.app`, module `:app`)
- **Pure (host-tested JUnit5):** `VaultUuidParsing.kt` (`parseVaultUuidHex` — dashed-hex → 16 bytes, typed rejection of wrong-length/non-hex); `AppSyncStateDir.kt` (`syncStateDir(base) = base/sync-state`).
- **Context-bound (proven by the instrumented smoke):** `AppVaultProvisioning.kt` — `stageGoldenVault(context)` recursively copies `assets/golden_vault_001` → `filesDir/golden_vault_001` (idempotent; never mutates the asset), `goldenVaultUuid(context)` parses the pinned uuid from the bundled inputs JSON via `parseVaultUuidHex`. Mirror of iOS `AppVaultProvisioning.swift` + `:kit`'s `GoldenVaultStaging`.
- **Compose glue:** `UnlockScreen.kt` (masked password field + "Unlock & Sync"); `AppRoot.kt` (`sealed Route { Unlock; Sync(viewModel, monitor) }`; `unlockAndSync` builds `makeVaultSync` on main, awaits `syncAtUnlock`, zeroizes the password in a `finally` wrapping the whole body, `refreshStatus`, routes to Sync; ON_STOP → route = Unlock; monitor lifecycle bound to the `Route.Sync` `DisposableEffect`); `MainActivity.kt` (`ComponentActivity`, `FLAG_SECURE`, `MaterialTheme { Surface { AppRoot() } }`).
- **`:sync-ui` change:** `VaultSyncViewModel.syncAtUnlock` is now `suspend` (was a fire-and-forget slice-5 stub for "a future app") so the app awaits the pass before zeroizing — no use-after-zero race with the async Argon2id re-open. The VM still deliberately does not store/zeroize (the screen/app owns the buffer).
- **Build:** `:app` depends on `:kit` (real `makeVaultSync` + the arm64 `.so`, transitive into the APK — no cargo wiring of its own), `:sync-ui` (SyncScreen/VM), `:vault-access` (model types). Reuses `:sync-ui`'s Compose BOM + Espresso/coroutines force-block; `stageGoldenVaultForApp` Copy task hooks `mergeDebug/ReleaseAssets`. `activity-compose` pinned `1.8.2` (the version the production classpath already resolves; the bare coordinate had no version contributor on the androidTest classpath).

### Acceptance (green — full gauntlet this session)
```
cd android && ./gradlew :app:test :sync-ui:test :vault-access:test :kit:testDebugUnitTest   → BUILD SUCCESSFUL (host JUnit5, no emulator/NDK)
cd android && ./gradlew :app:connectedDebugAndroidTest                                       → BUILD SUCCESSFUL, 2 tests on Medium_Phone_API_36.1 (real .so)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|.gitignore)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'           → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)
- **Sync-only, no browse.** Android has only the sync FFI surface (`syncStatus`/`syncVault`/`syncCommitDecisions`); there is no open/browse port like iOS's `UniffiVaultOpenPort`/`VaultBrowseViewModel`. Building one is a separate, larger effort. The "unlock" here is the sync-password entry, not a session-producing open.
- **`syncAtUnlock` made `suspend`** (not a second method). The silent unlock path drops the password and never reuses it for `resolve`, so the app awaits the pass then zeroizes. The interactive path's buffer hygiene (slice-5 `SyncScreen`) is unchanged.
- **Monitor lifecycle bound to the `Route.Sync` composition**, not to `unlockAndSync` — so a watcher never outlives the on-screen session.
- **`FLAG_SECURE` is the privacy stand-in**; a full iOS-style `PrivacyCover` is deferred with browse (no secret content is on screen in this slice — sync-only, masked password).
- **Compose glue is intentionally not UI-unit-tested** (the slice-5 `SyncScreen` is already covered in `:sync-ui`; the genuinely-novel runtime behavior — real FFI wiring — is what the instrumented smoke proves).

## (2) What's next

- **Android vault open/browse port + browse screen** (the natural next slice; unblocks "browse"). Today Android can sync a vault but cannot open it for record reading. The work: a new uniffi open-vault + read-records binding (mirror iOS `UniffiVaultOpenPort` / `VaultBrowseViewModel`), then a Compose browse screen wired into `:app` after unlock. This likely touches `ffi/` + a thin `:kit`/`:vault-access` port + new `:app` screens — scope it as its own spec (it is larger than a UI slice). **Acceptance:** unlock → list record titles (metadata-only first; reveal-on-tap later) against the staged `golden_vault_001` on the emulator; host tests for the pure port mapper + an instrumented open/read smoke.
- **On-device veto round-trip (carried):** the golden vault is single-device → only `AppliedAutomatically`/`NothingToDo`, never `ConflictsPending`. A real `resolve`/`commitDecisions` exercise needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]). The conflict path stays fake-driven in the instrumented suites.
- **Accepted minor follow-ups (this slice):** (a) background-during-unlock race — if backgrounded while the unlock pass is suspended, the coroutine may still route to Sync and start the monitor; it self-heals on the next ON_STOP and the password is already zeroized (documented in `AppRoot.unlockAndSync` KDoc). (b) The Compose `String`-backed password field lingers until GC (iOS `SecureField` parity); the derived `ByteArray` is zeroized. Neither is worth a fix at skeleton scope.
- **Optional WorkManager background detection (deferred since slice 3):** foreground-only per ADR-0003.

**Other open directions (carried):** iOS biometric re-auth before write; N-device convergence topologies; durability/partition/clock-skew scenarios; Rust-core backlog #193/#192/#190/#189.

**Open follow-up issues:** carried **#224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202**. (No new issues filed this session.)

## (3) Open decisions and risks
- **No on-device app/lifecycle UI coverage** beyond the `makeVaultSync` smoke (no Compose UI test of the unlock screen — approved spec decision). The real FFI wiring is on-device-proven; the unlock-screen routing/lifecycle glue is host-untested. Flagged so it isn't mistaken for full-UI-proven.
- **`arm64-v8a` only** — `armv7`/`x86_64` not cross-built (matches `:kit`); irrelevant on the arm64 emulator/devices used here.
- **No production change to anything pre-existing** except the additive `:sync-ui` `syncAtUnlock` → suspend refactor (under `android/`) and the `activity-compose` pin. `core/`, `ffi/`, `ios/`, on-disk format untouched (both guardrails empty).

## (4) Exact commands to resume

```bash
# 0) FIRST — the branch is already pushed and PR opened by this session (see §below). The USER
#    reviews/merges; this session does NOT merge. If the PR is not yet open, push + open it:
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton
git push -u origin feature/c3-android-app-skeleton
gh pr create --base main --head feature/c3-android-app-skeleton \
  --title "C.3 Android slice 6: :app walking skeleton — Compose unlock → real makeVaultSync → SyncScreen" \
  --body "First runnable Android app. Sync-only Compose :app hosting the slice-5 SyncScreen over the real makeVaultSync lifecycle (unlock → silent syncAtUnlock → badge), bundled golden_vault_001 demo vault, FLAG_SECURE, monitor bound to the Sync composition. Pure host tests (uuid/state-dir) + suspend syncAtUnlock refactor; on-device MakeVaultSyncSmokeTest (real .so: happy → Synced, wrong pw → error). Browse deferred (no Android open port yet). Additive only — no core/ffi/ios/format change."

# 1) After review, squash-merge, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-app-skeleton && git branch -D feature/c3-android-app-skeleton
git worktree prune && git worktree list

# 2) Next direction (Android open/browse port — its own spec): brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this slice's gauntlet on the branch:
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && \
  ./gradlew :app:test :sync-ui:test :vault-access:test :kit:testDebugUnitTest    # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-app-skeleton/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest                                       # 2 tests, emulator must be running
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`cbf1adf`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory
- **Branch on close:** `main` @ `cbf1adf`; `feature/c3-android-app-skeleton` carries spec + plan + the `:app` module (6 main sources + 2 host test files + 1 instrumented test + manifest/strings/build) + the `:sync-ui` suspend refactor + docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — `:app`/`:sync-ui`/`:vault-access`/`:kit` host suites + 2 instrumented `MakeVaultSyncSmokeTest` cases on `Medium_Phone_API_36.1`; both guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task; final whole-slice opus review). Reviews caught + fixed real items: gitignore centralization (T1), orphaned-monitor window (T6), latent `activity-compose` androidTest-classpath bug (T7), and the must-fix **unlock-password not zeroized on the provisioning-error path + uncaught-coroutine crash** (final review).
- **README.md / ROADMAP.md:** updated — Android C.3 slice 6 ✅ (`:app` walking skeleton); flipped the stale slice-5 "lifecycle wiring deferred to a future :app module" forward-ref.
- **NEXT_SESSION.md:** symlink retargeted to this file.
