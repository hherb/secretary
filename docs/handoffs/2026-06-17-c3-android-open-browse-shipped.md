# NEXT_SESSION.md — C.3 Android slice 7: vault open/browse ✅

**Session date:** 2026-06-17. Flow: `/nextsession` → found the slice-6 baton (PR #248 merged, `main` @ `965fbd7`) → chose **Android slice 7** (vault open/browse) → brainstormed (4 decisions: metadata-only, browse-only post-unlock flow, new `:browse-ui` module, lock-on-background) → spec → 8-task TDD plan → **subagent-driven execution** (fresh implementer + spec/quality review per task; all review items fixed in-task) → final whole-slice review → docs + this handoff.

**Status:** ✅ **code-complete + all-green** on branch `feature/c3-android-open-browse` (worktree `.worktrees/c3-android-open-browse`). PR: see §4 (push/PR is the first resume step — **the user reviews/merges; this session does not merge**). This slice delivers the **first Android slice that opens a vault** — real `open_vault_with_password`, Argon2id on IO, metadata-only `BrowseScreen`, lock-on-background. `git diff main...HEAD --name-only` touches only `android/**` + `docs/**` + `README.md` + `ROADMAP.md` (both guardrail greps below empty — no `core/`/`ffi/`/`ios/`/format change).

## (1) What we shipped this session

**The central idea:** first Android slice that OPENS a vault (not just syncs). Unlock → real `open_vault_with_password` (Argon2id on IO inside the port) → metadata-only Compose `BrowseScreen`: lists blocks → a selected block's record titles/types/tags/field-NAMES. **No secret value is ever read** (`RecordSummaryView` has no value field; the adapter never calls `expose_*` and closes the decrypted `BlockReadOutput` immediately). New FFI-free `:browse-ui` module. Lock-on-background wipes the session (returns to Unlock; re-entry re-opens). **No `core`/`ffi`/`ios`/on-disk-format change** — the open/read uniffi surface already existed; pure Kotlin-port + Compose-UI slice. The prior sync flow (`:sync-ui`, `makeVaultSync`, `SyncScreen`, `MakeVaultSyncSmokeTest`) stays in the repo, just not wired into `:app`'s route.

| Layer | What landed | Commit(s) |
|---|---|---|
| **Spec + plan** | slice-7 design doc + 8-task implementation plan + spec error-type fix | `271d987` `f81a687` |
| **Task 1 — browse view types** | `BlockSummaryView`, `RecordSummaryView`, `VaultBrowseError`, `hexOfBytes` helper in `:vault-access` | `f0af993` |
| **Task 2 — VaultOpenPort/VaultSession seam** | `VaultOpenPort` / `VaultSession` interfaces + host fakes in `:vault-access` | `5c679eb` |
| **Task 3 — VaultBrowseModel** | `VaultBrowseModel` coordinator + coroutine-based host tests in `:vault-access` | `8aa53d0` |
| **Task 4 — :kit mappers** | browse error + block-summary mappers + host tests in `:kit` | `617d8bd` |
| **Task 5 — :kit adapters** | `UniffiVaultOpenPort` + `UniffiVaultSession` + `uniffiVaultOpenPort()` factory in `:kit` | `9a64bcf` |
| **Task 6 — :browse-ui module** | new `:browse-ui` module + `VaultBrowseViewModel` + render helpers | `d4dff79` |
| **Task 7 — BrowseScreen** | `BrowseScreen` metadata-only Compose UI in `:browse-ui` | `2f7e811` |
| **Task 8 — :app wiring + smoke** | `:app` route unlock→`BrowseScreen` (lock-on-background) + on-device `OpenBrowseSmokeTest` | `1d7bc9e` |
| **Docs** | README + ROADMAP slice-7 ✅ + this handoff | (this commit) |

Branch from `main` @ `965fbd7`. **Squash-merge collapses to one commit on `main`** (per-task SHAs above are pre-squash).

### Architecture (where the pieces live)

- **`:vault-access` (package `org.secretary.browse`) — pure, host-tested JUnit5:**
  - `BlockSummaryView` / `RecordSummaryView` — metadata-only value types; `RecordSummaryView` has no value field by design.
  - `hexOfBytes(ByteArray): String` — pure hex formatter.
  - `VaultBrowseError` — sealed class throwable hierarchy (`OpenFailed`, `ReadFailed`, `SessionWiped`).
  - `VaultOpenPort` / `VaultSession` — seam interfaces; `VaultSession.readBlock` is a plain (non-suspend) call (cheap in-memory manifest metadata; iOS does the same).
  - `VaultBrowseModel` — coordinator: `loadBlocks(port, folder, password)` suspend, `selectBlock(block)` suspend, `clearSelection()`, `lock()`.
  - `FakeVaultOpenPort` / `FakeVaultSession` — host fakes for testing.

- **`:kit` (package `org.secretary.kit`) — FFI adapters, host-tested:**
  - `mapVaultBrowseError(VaultException): VaultBrowseError` — typed mapper.
  - `mapBlockSummary(BlockSummary): BlockSummaryView` — DTO→domain mapper.
  - `UniffiVaultOpenPort` — calls `open_vault_with_password` on `Dispatchers.IO`; wraps `VaultException` → `VaultBrowseError.OpenFailed`.
  - `UniffiVaultSession` — wraps `OpenVaultOutput`; `blockSummaries()` maps each `BlockSummary`; `readBlock` opens + reads + closes immediately (no `expose_*`); `wipe()` closes the output handle.
  - `uniffiVaultOpenPort()` — factory function returning `UniffiVaultOpenPort`.

- **`:browse-ui` (new module, package `org.secretary.browse.ui`) — FFI-free Compose:**
  - `VaultBrowseViewModel` — thin `androidx.lifecycle.ViewModel` wrapping `VaultBrowseModel`; exposes `uiState: StateFlow<BrowseUiState>` and `selectBlock`/`back`/`lock` entry points.
  - `BrowseScreen` — Compose UI: block list → selected block's records (metadata-only: title from field names or record-type, type, tags, field names). Lock-on-background via `LifecycleObserver`.
  - Render helpers (`recordTitle`, `recordTypeLabel`, `tagChips`, etc.) — host-testable pure functions.

- **`:app` changes:**
  - Route changed from `Route.Sync(viewModel, monitor)` to `Route.Browse(viewModel)`.
  - `unlockAndBrowse` opens the vault via `uniffiVaultOpenPort()`, builds `VaultBrowseModel`, creates `VaultBrowseViewModel`, routes to `BrowseScreen`. Password zeroized in `finally`.
  - `ON_STOP` wipes the session and returns to `Route.Unlock`.
  - `MakeVaultSyncSmokeTest` (the 2 existing instrumented smoke tests) stays and still passes; new `OpenBrowseSmokeTest` (2 cases: happy-path reads block list, wrong-password surfaces `OpenFailed`) adds 2 more.

### Acceptance (green — full gauntlet this session)

```
cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test   → BUILD SUCCESSFUL (host JUnit5)
cd android && ./gradlew :app:connectedDebugAndroidTest                                         → BUILD SUCCESSFUL, 4/4 on Medium_Phone_API_36.1 (real .so)
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'   → empty
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'               → empty
```

### Deliberate design decisions (so a future reader doesn't "fix" them)

- **Metadata-only browse.** `RecordSummaryView` has no value field. The adapter never calls `expose_text`/`expose_bytes` and closes `BlockReadOutput` immediately. Reveal-on-tap is the next slice.
- **Browse-only post-unlock (no sync at unlock).** Unlock → `open_vault_with_password` → `BrowseScreen`. One Argon2id at unlock. The sync flow (`:sync-ui`, `makeVaultSync`) stays in the repo but is not wired into `:app`'s route this slice; sync-badge re-integration onto `BrowseScreen` is deferred.
- **`VaultSession.readBlock` is non-suspend.** The call is cheap in-memory manifest metadata; iOS does the same; no need to offload.
- **Lock-on-background** wipes the session immediately on `ON_STOP` (not on `ON_PAUSE`). Re-entry requires the password again. `FLAG_SECURE` is already set by the activity.
- **`AppSyncStateDir` is retained in `:app` but unused** until the sync-badge re-integration lands.
- **`OpenBrowseSmokeTest @After` hard-codes the staged subpath** (`golden_vault_001`) — flagged as a minor carry-forward (see §3).

## (2) What's next

- **Reveal-on-tap** (the natural next slice; mirrors iOS browse). Per-field `expose_text`/`expose_bytes` behind a tap gesture; hide/auto-hide; background redaction of exposed values. Acceptance: tap a text field on `BrowseScreen` → value shown; background → value hidden; session wipe → no value retained.
- **Sync-badge re-integration onto `BrowseScreen`** — unify browse + the existing sync flow into one screen. `AppSyncStateDir` is retained in `:app` for this purpose.
- Recovery-phrase + device-secret open paths (this slice is password-only).
- Show-deleted toggle, swipe delete/restore/edit (iOS browse parity).
- On-device veto round-trip (the golden vault is single-device → only `AppliedAutomatically`/`NothingToDo`; needs a seeded concurrent state — see [[project_secretary_sync_veto_needs_seeded_state]]).
- Optional `WorkManager` background detection (deferred from slice 3).

**Open follow-up issues (carried):** #224 / #234 / #192 / #193 / #190 / #189 / #186 / #161 / #162 / #167 / #202. No new issues filed this session.

## (3) Open decisions and risks

- **No Compose UI test of the browse glue.** `BrowseScreen` is not covered by instrumented Compose UI tests (the instrumented smoke only checks the ViewModel layer + real FFI wiring). The same deliberate choice as `:app`'s unlock screen (slice 6) — the novel runtime behaviour is what the instrumented smoke proves; the Compose render itself is simpler than `:sync-ui`'s 15-test harness. Flagged so it isn't mistaken for full-UI-proven.
- **`BlockSummaryView.uuidHex` is a recomputed `get()`** (could be made eager). Minor — the field is only accessed on selection.
- **A few untested-but-correct paths:** `VaultBrowseViewModel.lock()` forwarding; tombstone + blank-type `recordTitle`; error-path `selectedBlock` assertion on `SessionWiped`.
- **`UniffiVaultSession.blockSummaries()/vaultUuidHex()` run on the caller thread** — cheap in-memory metadata; iOS does the same. Not a risk but noted.
- **`OpenBrowseSmokeTest @After` hard-codes the staged subpath** (`golden_vault_001`). Works correctly but is a minor brittle point; the final review should triage.
- **`arm64-v8a` only** — matches `:kit`; irrelevant on the arm64 emulator/devices used here.
- **No production change to anything pre-existing** except the `:app` route (from Sync to Browse). `core/`, `ffi/`, `ios/`, on-disk format untouched (both guardrails empty).

## (4) Exact commands to resume

```bash
# 0) The branch is ready to push and open a PR. Push + open it (or verify it's already open):
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse
git push -u origin feature/c3-android-open-browse
gh pr create --base main --head feature/c3-android-open-browse \
  --title "C.3 Android slice 7: vault open/browse — open_vault_with_password + BrowseScreen" \
  --body "First Android slice that opens a vault. Unlock → real open_vault_with_password (Argon2id on IO) → metadata-only BrowseScreen (block list → record titles/types/tags/field-names). No secret value crosses the adapter. New :browse-ui module, lock-on-background. Host-tested throughout; 4/4 on-device (OpenBrowseSmokeTest x2 + MakeVaultSyncSmokeTest x2). Pure Kotlin-port + Compose-UI — no core/ffi/ios/format change."

# 1) After review, squash-merge, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/c3-android-open-browse && git branch -D feature/c3-android-open-browse
git worktree prune && git worktree list

# 2) Next direction (reveal-on-tap slice — spec first):
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run the gauntlet on the branch (emulator must be running for connected tests):
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse/android && \
  ./gradlew :vault-access:test :kit:testDebugUnitTest :browse-ui:test :app:test    # host green
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse/android && \
  PATH="$HOME/Library/Android/sdk/platform-tools:$HOME/Library/Android/sdk/emulator:$PATH" \
  ./gradlew :app:connectedDebugAndroidTest                                         # 4 tests, emulator running

# Guardrail greps (both must be empty):
cd /Users/hherb/src/secretary/.worktrees/c3-android-open-browse
git diff main...HEAD --name-only | grep -vE '^(android/|docs/|README.md|ROADMAP.md|NEXT_SESSION.md)'
git diff main...HEAD --name-only | grep -E 'core/|ffi/|ios/|crypto-design|vault-format'
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session relative to the branch point (`965fbd7`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]). If you resume this branch for fixups, first `git fetch origin && git merge origin/main` (branch-version-wins on the handoff path) before editing — closes the add/add gap ([[feedback_next_session_main_authoritative]]).

## Closing inventory

- **Branch on close:** `main` @ `965fbd7`; `feature/c3-android-open-browse` carries spec + plan + 10 commits (spec/plan × 2 + 8 task commits) + this docs/handoff commit. Squash-merge → one commit on `main`.
- **Acceptance:** green — `:vault-access`/`:kit`/`:browse-ui`/`:app` host suites + 4/4 instrumented tests (`OpenBrowseSmokeTest` × 2 + `MakeVaultSyncSmokeTest` × 2) on `Medium_Phone_API_36.1`; both guardrails clean. See §1.
- **Process note:** subagent-driven (fresh implementer + spec/quality review per task; all per-task review items fixed in-task). Final review flagged the minor items listed in §3 — none are blockers; carried to next review.
- **README.md / ROADMAP.md:** updated — Android C.3 slice 7 ✅ (vault open/browse); slice-6 "sync-only, browse deferred" phrasing updated to match reality.
- **NEXT_SESSION.md:** symlink retargeted to this file.
