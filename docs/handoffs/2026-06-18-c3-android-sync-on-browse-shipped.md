# NEXT_SESSION.md — C.3 Android sync-on-browse ✅

**Session date:** 2026-06-18. Flow: `/nextsession` → prior baton said "#254 not yet pushed; push + open PR" but a **parallel session had already pushed + squash-merged #254** (PR #257, `main` @ `e9c51d5`; the `feature/write-action-debounce` branch was byte-identical to `main`) → housekeeping (removed the merged `write-action-debounce` worktree + branch; the two parallel-session worktrees `hardcore-robinson` / `d4-browser-autofill` left untouched) → confirmed README/ROADMAP already carried #254 ✅ → chose **sync-badge re-integration onto the browse screen** → brainstormed (reuse `SyncScreen` stacked above `BrowseScreen`; compose at the `:app` layer, mirroring iOS) → spec → 4-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus, READY-TO-MERGE) → 2 Minor doc fixes → this handoff.

**Status:** ✅ **code-complete + all-green**, on branch `feature/c3-android-sync-on-browse` (worktree `.worktrees/c3-android-sync-on-browse`). **NOT yet pushed / no PR yet** (push + open PR is the immediate next step — see §4). This is the slice that **reunifies the two originally-separate `:app` flows** (sync screen, dropped in slice 7; browse screen) into one. **Android-only — `core` / `ffi` / `ios` / on-disk-format / UDL all untouched; no `:vault-access` / `:browse-ui` / `:sync-ui` library-source edits** (the unification is a pure `:app` composition).

## (1) What we shipped this session

**The central idea:** an unlocked Android user should see a live sync badge and the interactive sync/conflict flow on the *same* screen they browse/edit on — and a sync-at-unlock pass should run automatically without blocking the UI. Achieved by **reusing the existing, fully-tested `SyncScreen` as-is**, stacked above `BrowseScreen` in a new app-level composable. Mirrors iOS, whose unified `VaultBrowseScreen` likewise lives in the **app target** and composes both view-models there.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design doc + 4-task TDD plan | `1d17e54` `95b7b64` |
| **Task 1 — `launchSyncAtUnlock`** | pure host helper: copy-then-zeroize background sync; copy taken synchronously before the caller zeroizes the original (no use-after-zero race); copy zeroized in `finally` on success AND throw. 3 host tests (`runTest`). Added `kotlinx-coroutines-test` to `:app` `testImplementation`. | `74a5156` |
| **Task 2 — `openBrowseWithSync` + `BrowseSession`** | orchestration helper assembling browse VM + sync VM + monitor from the real `.so` (open → `loadBlocks` → `makeVaultSync`); runs on main; does NOT zeroize the password and does NOT launch sync (caller owns both). Instrumented smoke. | `51eac22` |
| **Task 3 — `BrowseWithSyncScreen` + `AppRoot` rewiring** | new app-level `Column { SyncScreen; HorizontalDivider; BrowseScreen }`; `Browse` route carries a `BrowseSession`; `unlockAndOpen` fires background `launchSyncAtUnlock` + zeroizes the original; monitor lifecycle (`start` on entry / `stop`+`browse.lock()` on dispose, failed start non-fatal). Added Compose UI-test deps to `:app`. Instrumented render test proves the badge on BOTH the block-list and record-list views (`waitUntil` on `toggle-show-deleted` proves the view actually swapped). | `632a926` |
| **Task 4 — docs** | README + ROADMAP rows | `a017efb` |
| **Final-review fixes** | corrected the iOS-vs-Android Argon2id framing (both platforms pay a sync-pass Argon2id; the Android delta is it can't reuse the session even for the vault UUID) across README/ROADMAP/spec; added the background-scope rationale comment at the `launchSyncAtUnlock` call site | `161759a` |

Branch from `main` @ `e9c51d5`. **Squash-merge collapses to one commit on `main`** (per-task SHAs above are pre-squash; Task 1 and Task 3 each had review-fix commits folded in via `--amend`).

### Architecture (where the pieces live, all in `:app`)

- `android/app/.../SyncAtUnlock.kt` — `launchSyncAtUnlock(scope, password, suspend (ByteArray)->Unit): Job`. Sole owner of the password COPY's lifetime.
- `android/app/.../BrowseSession.kt` — `data class BrowseSession(browse, sync, monitor)` + `suspend fun openBrowseWithSync(openPort, folder, stateDir, vaultUuid, password): BrowseSession` (main-thread; no zeroize, no sync-launch).
- `android/app/.../BrowseWithSyncScreen.kt` — stateless `Column { SyncScreen(sync); HorizontalDivider(); BrowseScreen(browse) }`.
- `android/app/.../AppRoot.kt` — `Route.Browse(session: BrowseSession)`; `unlockAndOpen(context, scope, password)` assembles + fires background sync + zeroizes original; `DisposableEffect(r.session)` runs `monitor.start()` (try/catch-log) on entry and `monitor.stop()` + `browse.lock()` on dispose.

### Acceptance (green this session)

```
cd android && ./gradlew :app:testDebugUnitTest :vault-access:test :browse-ui:test                → BUILD SUCCESSFUL (host)
cd android && ./gradlew :app:connectedDebugAndroidTest                                            → :app 10/10 on Medium_Phone_API_36.1 (+ a real device NX809J in one run)
cd android && ./gradlew :browse-ui:connectedDebugAndroidTest :sync-ui:connectedDebugAndroidTest   → 8/8 + 15/15 (neighbour libs unchanged)
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                → empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' → empty  (NO ios/ this slice)
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Reuse `SyncScreen` unchanged, compose at `:app`** — not embedding sync into `:browse-ui`. Keeps `:browse-ui` and `:sync-ui` decoupled siblings (no new inter-library dependency) and matches iOS's actual layering (unified screen lives in the app target). The 15 `:sync-ui` + 8 `:browse-ui` instrumented tests stay valid and untouched.
- **Sync-at-unlock runs in the BACKGROUND** (`launchSyncAtUnlock` on the app scope, fire-and-forget) — browse renders immediately; the sync-pass Argon2id never blocks the UI. Mirrors iOS's `Task { await syncAtUnlock() }`.
- **The background sync pass deliberately outlives Browse disposal** — it opens its own independent vault handle from the password COPY and never touches the (wiped) browse session. Binding it to the Browse composition scope would cancel the in-flight Argon2id on background. Documented at the call site.
- **Both platforms pay a sync-pass Argon2id** — the `SyncCoordinator` opens the vault with the password per sync call on iOS and Android alike. The genuine Android delta is it can't reuse the open session even to read the vault UUID (so it provisions `goldenVaultUuid` separately). Mitigated by background execution. Restructuring `:kit` to avoid a separate sync-pass open is out of scope (it would touch the FFI surface). *(This framing was corrected from an earlier overstatement in `161759a` after the final review dug into iOS's `makeVaultSync(session:)`.)*
- **The unlock password is NOT retained for conflict resolution** — the silent sync-at-unlock path drops the copy; a conflict only raises the review badge. The interactive path (badge tap) re-prompts fresh via `SyncScreen`'s own `heldPassword`. No new long-lived secret buffer.

## (2) What's next

- **Recovery-phrase + device-secret open paths on Android** — every slice so far is password-only; `open_with_recovery` (mnemonic) / `open_with_device_secret` (per-device wrap slot) already exist on the uniffi surface. **Acceptance:** open the golden vault on-device via the recovery mnemonic, and via a per-device wrap slot; both reach the same `BrowseWithSyncScreen`.
- **Block create/rename + record move-between-blocks** — the next CRUD tier (slices 9–10 + sync-on-browse manage records *within* a block / sync, not block lifecycle). **Acceptance:** create a block, rename it, move a record across blocks, all re-read-verified on-device.
- **iOS biometric re-auth before a write** — separate follow-up (ROADMAP C.3 remaining).
- **On-device sync veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]) — the sync-on-browse flow now has a UI surface to exercise it.
- Optional `WorkManager` background detection (deferred from slice 3); `NSMetadataQuery` iCloud-download detection on iOS (deferred).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202 / #251 / #252 / #255. **Closed this session:** none filed for this slice (no GitHub issue existed for sync-on-browse — commits carry no issue suffix; file one at PR time if desired).

## (3) Open decisions and risks

- **`ios/` is NOT in this slice's diff** — the standard "no `ios/` change" guardrail re-applies (it did NOT apply to #254, which was cross-platform). Both guardrails verified empty (§1).
- **No host test of the inline `AppRoot.unlockAndOpen` happy/failure route-assembly** — it depends on the FFI (real ports + `makeVaultSync`), so it is covered by the instrumented `OpenBrowseWithSyncSmokeTest` rather than a host test. The plan made this tradeoff deliberately; the genuinely pure logic (`launchSyncAtUnlock` copy/zeroize) IS host-tested.
- **Final review verdict (opus):** READY-TO-MERGE; 0 Critical/Important; all 7 cross-cutting invariants verified against actual code (password copy-then-zeroize, always-run `monitor.stop()`+`browse.lock()` on dispose, main-thread `makeVaultSync`, zero library/core/ffi/ios edits, coherent helper consumption, non-tautological UI test). The 2 Minor findings (doc-accuracy + a clarifying comment) were fixed in `161759a`.
- **Per-task Minor adjudications** (recorded, no-action): the `golden_vault_001` literal cleanup path matches the sibling `OpenBrowseSmokeTest`/`MakeVaultSyncSmokeTest` pattern; class-level `@OptIn` is acceptable.

## (4) Exact commands to resume

```bash
# 0) THIS BRANCH IS NOT YET PUSHED. Immediate next step: push + open the PR.
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-on-browse
git push -u origin feature/c3-android-sync-on-browse
gh pr create --repo hherb/secretary \
  --title "C.3 Android: sync badge + sync-at-unlock on the browse screen (sync-on-browse)" \
  --body "<summary>"
#    Then the user reviews + squash-merges (this session does not merge).

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-sync-on-browse && git branch -D feature/c3-android-sync-on-browse
git worktree prune && git worktree list

# 2) Next direction (recovery/device-secret open OR block CRUD — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on this branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-on-browse/android && \
  ./gradlew :app:testDebugUnitTest :vault-access:test :browse-ui:test                  # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-on-browse/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest :browse-ui:connectedDebugAndroidTest :sync-ui:connectedDebugAndroidTest
# NOTE: connectedAndroidTest rejects --tests; use -Pandroid.testInstrumentationRunnerArguments.class=<FQN> for one test.

# Guardrails (core/ffi/format AND ios/ all empty this slice):
cd /Users/hherb/src/secretary/.worktrees/c3-android-sync-on-browse
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                       # empty
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'     # empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`e9c51d5`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `e9c51d5`; `feature/c3-android-sync-on-browse` carries spec + plan + 4 task commits + docs + 1 final-fix commit + this handoff commit. Squash-merge → one commit on `main`. **Not yet pushed; no PR yet.**
- **Acceptance:** green — `:app`/`:vault-access`/`:browse-ui` host suites + `:app` connected 10/10 + `:browse-ui` 8/8 + `:sync-ui` 15/15 on `Medium_Phone_API_36.1`; both guardrails empty (incl. no `ios/`). See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task — Task 1 caught a committed-red test + JUnit5 assertion-order bugs in the plan's example code; Task 3's nav assertion was strengthened to prove the view-swap). Final whole-branch review (opus) = READY-TO-MERGE; 2 Minor doc fixes applied.
- **README.md / ROADMAP.md:** updated — sync badge + sync-at-unlock on the Android browse screen ✅ (C.3 sync-on-browse).
- **NEXT_SESSION.md:** symlink retargeted to this file.
