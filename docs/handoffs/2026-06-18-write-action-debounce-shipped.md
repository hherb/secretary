# NEXT_SESSION.md — Write-action in-flight guard (#254) ✅

**Session date:** 2026-06-18. Flow: `/nextsession` → slice-10 baton said "push + open PR" but a **parallel session had already merged slice 10** (PR #256, `main` @ `7c1a6ed`; feature branch was byte-identical to `main`) → housekeeping (removed the merged `c3-android-record-edit` worktree/branch; two parallel-session worktrees `hardcore-robinson` / `d4-browser-autofill` left untouched) → confirmed README/ROADMAP already carried slice-10 ✅ → chose **#254 (write-action debounce)** → brainstormed (model-level re-entrancy guard + UI disable; Android + iOS parity) → spec → 6-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-branch review (opus) → fixed the 3 review findings → this handoff.

**Status:** ✅ **code-complete + all-green**, on branch `feature/write-action-debounce` (worktree `.worktrees/write-action-debounce`). **NOT yet pushed / no PR yet** (push + open PR is the immediate next step — see §4). This is the **first cross-platform Android+iOS slice** in the C.3 run — it closes #254 by guarding every write action against concurrent / rapid-repeat taps. **No `core` / `ffi` / on-disk-format / UDL change; `ios/` IS intentionally touched this slice** (so the prior "no `ios/`" guardrail does NOT apply — see §3).

## (1) What we shipped this session

**The central idea:** a write action (record Add/Edit `commit`, list Delete/Restore) must never execute twice. The **host-tested model owns a re-entrancy guard flag**; the UI just disables the button by reading it. Android `commit()` was `suspend` (two taps = two concurrent coroutines both calling the FFI writer → Add appends twice); the fix guards on `inFlight` (concurrent coroutine) AND `committed` (post-success re-tap in the render gap before the form clears). iOS `commit()` is synchronous on `@MainActor` — its only window is that same render-gap re-tap, closed by the `committed` guard; an `isWriting` flag drives the button-disable for UX parity.

| Layer | What landed | Commit |
|---|---|---|
| **Spec + plan** | design doc + 6-task TDD plan | `81c6b02` `f23bfd1` |
| **Task 1 — Android RecordEditModel** | `inFlight` StateFlow + 3-flag `commit()` guard (`inFlight`/`committed`/`loadFailed`), `finally`-reset on every exit; host fake gains `writeGate: CompletableDeferred<Unit>?` | `3143d37` |
| **Task 2 — Android VaultBrowseModel** | global `writing` flag guarding `commitThenReload` (delete+restore), reset in `finally` + `lock()` | `7c6f669` |
| **Task 3 — Android :browse-ui** | `VaultBrowseViewModel.writing` pass-through; Save `!loadFailed && !inFlight`; Delete/Restore/Add `!writing`; androidTest fake gate + 2 instrumented disable tests | `400fd7c` |
| **Task 4 — iOS RecordEditViewModel** | `isWriting` + `guard !committed, !isWriting, !loadFailed`, `defer`-reset; keystone test: 2nd commit after success → still 1 append | `1d293dc` |
| **Task 5 — iOS VaultBrowseViewModel + SwiftUI** | `isWriting` guard in `commitThenReload`; `.disabled` on Save + 4 browse buttons | `adecf76` |
| **Task 6 — docs** | README/ROADMAP rows | `7ae9f29` |
| **Final-review fixes** | doc minimal androidTest fake; assert error on failed-write test; relocate `isWriting`/`showDeleted` doc-comments | `a0949ed` `c4b5ddf` |

Branch from `main` @ `7c1a6ed`. **Squash-merge collapses to one commit on `main`** (per-task SHAs above are pre-squash).

### Architecture (where the pieces live)

- **Android `:vault-access` (host-tested JUnit5):**
  - `RecordEditModel.kt` — `inFlight: StateFlow<Boolean>`; `commit()` short-circuits on `inFlight || committed || loadFailed`, sets `inFlight=true`, `try { build→validate→append/edit } finally { inFlight=false }` (resets on hex/validation early-return, typed error, raw throwable, and after re-throwing `CancellationException`).
  - `VaultBrowseModel.kt` — `writing: StateFlow<Boolean>`; `commitThenReload` guards `if (writing) return; writing=true; try {…} finally { writing=false }`; `lock()` resets it. Re-read on success only (failed write leaves the list intact).
  - `FakeVaultBrowse.kt` (host fake `FakeVaultSession`) — `writeGate: CompletableDeferred<Unit>? = null` (default null = backward-compatible); each write `await`s the gate first, enabling a deterministic concurrent-race test.
- **Android `:browse-ui` (FFI-free Compose):**
  - `VaultBrowseViewModel.kt` — `val writing = model.writing` (one-line pass-through).
  - `RecordEditForm.kt` — Save `enabled = !loadFailed && !inFlight`.
  - `BrowseScreen.kt` — `writing` threaded into `RecordRow`; Delete/Restore/Add `enabled = !writing`.
  - `androidTest/.../FakeVaultSession.kt` — separate minimal instrumented fake; gained its own `writeGate` (doc-commented as a deliberate subset).
- **iOS `SecretaryVaultAccess` (SwiftPM, host-tested via `swift test`):**
  - `RecordEditViewModel.swift` — `isWriting`; `commit()` guards `!committed, !isWriting, !loadFailed`, `defer { isWriting = false }`.
  - `VaultBrowseViewModel.swift` — `isWriting`; `commitThenReload` guards + `defer`-reset.
- **iOS `SecretaryApp` (XcodeGen target — see §3 caveat):**
  - `RecordEditScreen.swift` — Save `.disabled(loadFailed || committed || isWriting)`.
  - `VaultBrowseScreen.swift` — `.disabled(isWriting)` on dialog-Delete, swipe-Restore, swipe-Delete, Add.

### Acceptance (green this session)

```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test   → BUILD SUCCESSFUL
cd android && ./gradlew :browse-ui:connectedDebugAndroidTest                                   → 8/8 (incl. 2 new disable tests) on Medium_Phone_API_36.1
cd ios/SecretaryVaultAccess && swift test                                                       → 172/172 ; swift build clean
bash ios/scripts/run-ios-tests.sh                                                               → exit 0 (pure tests + XCFramework + SecretaryKit sim XCTest + SecretaryApp build-app.sh ** BUILD SUCCEEDED **)
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'              → empty
git diff main...HEAD --name-only | grep -vE '^(android/|ios/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Guard lives in the host-tested model, not the UI** — the button-disable is UX; the model re-entrancy guard is the correctness fix (a UI that forgets to disable still must not double-write). Proven by the keystone gated-concurrency host test (two `commit()`s → one `appendRecord`).
- **Android needs BOTH `inFlight` and `committed`** — `inFlight` blocks the concurrent-coroutine case; `committed` blocks the post-success re-tap in the render gap before `LaunchedEffect(committed)` clears `editing`. Dropping either reopens a double-write.
- **iOS delete/restore `isWriting` is UX parity, NOT a race fix** — those paths are synchronous on `@MainActor` and cannot truly re-enter; the real iOS double-write (Add) is fixed by the `committed` guard. Documented in the VM doc-comment; don't "strengthen" it expecting a race.
- **Global `writing` flag (all rows), not per-row** — writes serialize under the session lock; allowing a second different-row write to start (and queue) could still double-act, so a global disable is the correct "no concurrent writes" posture.
- **No new error variant** — validation reuses `InvalidArgument`; FFI reuses existing arms. Keeps the workspace-wide exhaustive-match + Swift/Kotlin conformance-harness obligation untriggered ([[project_secretary_ffivaulterror_workspace_match]]).

## (2) What's next

- **Sync-badge re-integration onto `BrowseScreen`** — unify browse/edit with the slice-5 sync flow into one screen (`AppSyncStateDir` retained in `:app`). Acceptance: the browse/edit screen shows the sync badge and can sync-at-unlock without a separate screen.
- **Recovery-phrase + device-secret open paths on Android** — every slice so far is password-only; `open_with_recovery` / `open_with_device_secret` already exist on the uniffi surface. Acceptance: open the golden vault on-device via the recovery mnemonic, and via a per-device wrap slot.
- **Block create/rename + record move-between-blocks** — the next CRUD tier (#254 + slice 10 manage record existence/content within a block, not block lifecycle). Acceptance: create a block, rename it, move a record across blocks, all re-read-verified on-device.
- **iOS biometric re-auth before a write** — a separate follow-up (ROADMAP C.3 remaining).
- **On-device veto round-trip** still needs a seeded concurrent state ([[project_secretary_sync_veto_needs_seeded_state]]).
- Optional `WorkManager` background detection (deferred from slice 3).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202 / #251 / #252 / #255. **Closed this session:** **#254** (write-action debounce — both Android and iOS halves; the error-banner-detail half was already fixed in PR #256).

## (3) Open decisions and risks

- **`SecretaryApp` SwiftUI views compiled clean on the simulator.** The 5 `.disabled(...)` edits are additive modifier lines on already-tested `@Published` flags. `bash ios/scripts/run-ios-tests.sh` ran end-to-end (exit 0): pure `swift test` (172/172), XCFramework build, `SecretaryKit` simulator XCTest, **and Step 5 `build-app.sh` (XcodeGen + simulator compile of the `SecretaryApp` target = `** BUILD SUCCEEDED **`)** — so the view edits are genuinely compiled, not just inspected. (Earlier in the session I'd mis-judged this as "disproportionate / xcframework not prebuilt"; `run-ios-tests.sh` builds the xcframework itself, so the full compile proof was cheap enough and was run.)
- **`ios/` is intentionally in this slice's diff** — unlike every prior Android-only C.3 slice. The standard "no `ios/` change" guardrail does NOT apply here; the `core/`/`ffi/`/format guardrail still does and is empty.
- **iOS `VaultBrowseViewModel.lock()` does not reset `isWriting`** — sound, because iOS writes are synchronous so `isWriting` is never observably true outside one synchronous call; a `lock()` can't interleave with it. (Android `lock()` DOES reset `writing` as defense-in-depth, since Android writes are `suspend`.)
- **Final review verdict:** CHANGES REQUESTED with one borderline-Minor (androidTest fake parity doc) + two cosmetic Minors (a test could assert `error` set; an iOS doc-comment was misplaced). **All three fixed** (`a0949ed`; the comment-relocation was re-fixed in `c4b5ddf` after the first attempt orphaned `showDeleted`'s comment). No Critical/Important correctness findings.

## (4) Exact commands to resume

```bash
# 0) THIS BRANCH IS NOT YET PUSHED. Immediate next step: push + open the PR.
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git push -u origin feature/write-action-debounce
gh pr create --repo hherb/secretary \
  --title "Write-action in-flight guard (#254): no double-write on concurrent/rapid taps (Android + iOS)" \
  --body "<summary>"
#    Then the user reviews + squash-merges (this session does not merge).

# 1) After the PR merges, housekeeping (from the MAIN checkout, not this worktree):
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/write-action-debounce && git branch -D feature/write-action-debounce
git worktree prune && git worktree list

# 2) Next direction (sync-badge re-integration OR recovery/device-secret open OR block CRUD — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on this branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test        # host green
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :browse-ui:connectedDebugAndroidTest                                       # 8/8, emulator running
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce/ios/SecretaryVaultAccess && swift test  # 172/172

# Guardrails (core/ffi/format empty; ios/ IS allowed this slice):
cd /Users/hherb/src/secretary/.worktrees/write-action-debounce
git diff main...HEAD --name-only | grep -E 'core/|ffi/|crypto-design|vault-format'                       # empty
git diff main...HEAD --name-only | grep -vE '^(android/|ios/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)' # empty
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`7c1a6ed`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `7c1a6ed`; `feature/write-action-debounce` carries spec + plan + 6 task commits + docs + 2 fix commits + this handoff commit. Squash-merge → one commit on `main`. **Not yet pushed; no PR yet.**
- **Acceptance:** green — `:vault-access`/`:kit`/`:browse-ui`/`:app` host suites + `:browse-ui` connected 8/8 on `Medium_Phone_API_36.1` + iOS `swift test` 172/172 + full `run-ios-tests.sh` (XCFramework + `SecretaryKit` sim XCTest + `SecretaryApp` simulator compile proof, exit 0); both guardrails empty. See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task). Final whole-branch review (opus) = READY-TO-MERGE-after-fixes; 6 cross-cutting invariants verified (guard semantics both platforms, `writing` reset on every exit, no flag stuck across `lock()`, all UI sites wired, cross-commit coherence, iOS caveat honestly scoped); 0 Critical/Important; the 3 Minor findings all fixed.
- **README.md / ROADMAP.md:** updated — Write-action debounce ✅ (Android + iOS, #254).
- **NEXT_SESSION.md:** symlink retargeted to this file.
