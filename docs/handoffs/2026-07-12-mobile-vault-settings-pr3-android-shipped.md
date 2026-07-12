# NEXT_SESSION.md — Mobile per-vault settings · PR 3 (Android Settings screen) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-12, resuming from `main` @ `25b8b652` after #419 (PR 2: iOS Settings screen) merged. This session built **PR 3 — the final piece of the 3-PR mobile-settings slice** — the native Jetpack Compose Android Settings screen, over the frozen PR-1 FFI surface (#418) and mirroring the shipped iOS #419. **With this PR the retention-window + re-auth-grace per-vault settings are feature-complete on desktop + iOS + Android.** Branch `feature/mobile-settings-android` cut from `main` @ `25b8b652`; worktree `.worktrees/mobile-settings-android/`. Executed plan-first (a PR-3 plan doc grounded in the existing Android gate/Trash/port patterns + the *shipped* iOS VM), TDD host-first, with a Phase-1 security review + fix pass and a whole-branch review.

PR 3 is **Android-only, over the existing FFI**: no `core` / crypto / on-disk-format / `manifest_version` change, **no new `FfiVaultError`/`VaultBrowseError` variant**, `#![forbid(unsafe_code)]` intact. The only shipped-code touch outside the new files is one **additive** gate method + the composition root. Spec: [docs/superpowers/specs/2026-07-12-mobile-vault-settings-design.md](../superpowers/specs/2026-07-12-mobile-vault-settings-design.md) (Components D + E, Android half). Plan: [docs/superpowers/plans/2026-07-12-mobile-vault-settings-pr3-android.md](../superpowers/plans/2026-07-12-mobile-vault-settings-pr3-android.md).

## (0) Design decisions locked this session (user-approved)

- **Effective re-auth grace default → 2 min on Android** (was 30 s: `ReauthWindow.V1_DEFAULT_MS`), honored from **persisted** settings at open across the local + cloud paths. Same user-approved 30 s→2 min weakening iOS got (a longer unattended-write window) — matches the schema/iOS/desktop. `ReauthWindow.V1_DEFAULT_MS` (30 s, its own tests) is untouched; the composition passes the settings-derived window explicitly, and it remains the cloud placeholder-retarget fallback window.
- **Separate "Vault settings" entry.** Android's browse shell already surfaces a **"Device settings"** entry (biometric enrollment) via `testTag("open-settings")` + `Route.Browse.showSettings`. The new per-vault Settings screen got its **own** distinct entry (`open-vault-settings`), route flag (`showVaultSettings`), and back tag — the existing device-settings screen/route is untouched.

## (1) What we shipped this session (PR 3)

A native Compose **Vault settings** screen (its own browse entry) with two per-vault controls — **retention window** (days, 1–3650, default 90) and **re-auth grace** (minutes, 0–60, default 2):

- **FFI-free layer** (`:vault-access`, `org.secretary.browse`): `SettingsPort` (`readSettings`/`writeSettings`/`settingsBounds`) + `VaultSettings` / `SettingsBounds` / `SettingsBanner` value types + pure `retentionDaysFromMs`/`graceMinutesFromMs`/… conversions + clamps (reusing `MS_PER_DAY`/`msToDays` from `TrashFormatting`; new `MS_PER_MINUTE`).
- **Gate primitive** (`:vault-access`): an **additive** `RetargetableReauthGate.retargetWindow(newGate, nowMs)` — swap to a fresh gate for a new grace window **seeded at now** (mirror of iOS `retarget(window:)`); the existing `retarget`/`seed`/`reset` (cloud UUID-retarget ordering-independence) are untouched.
- **Model** (`:vault-access`): `SettingsModel` — host-tested, `StateFlow` state, mirror of `TrashBrowseModel.guardedWrite` + the *shipped* iOS `SettingsViewModel`: load, clamp against projected bounds, a `suspend` gated `save()` (re-auth → **re-read** → merge only retention+grace → write → retarget), and a `TrashBrowseModel` gaining an optional `SettingsPort` so its 3 frozen-default retention reads become the per-vault window.
- **FFI adapter** (`:kit`): `UniffiVaultSession : … , SettingsPort` **in-class** over PR-1's `read_settings`/`write_settings` + six bound readers, reusing the session's `sessionLock`/`wiped`/`mapErrors`/`write{}`/`deviceUuid()` helpers; `readSettings` throws on wiped, `writeSettings` is IO-offloaded, ULong↔Long at the boundary.
- **UI + composition** (`:browse-ui` + `:app`): a `SettingsBrowseViewModel` (thin VM) + `SettingsScreen.kt`; a "Vault settings" browse entry + `Route.Browse.showVaultSettings` + render branch in `AppRoot`; `openBrowseWithSync` gains a `makeGraceGate` factory, reads persisted grace at open and installs it on the **shared** `RetargetableReauthGate` via `retargetWindow`, and builds the `SettingsModel`/VM + a settings-aware `TrashBrowseModel` from `(session as? SettingsPort)`. The **local** path switched its plain `GraceWindowReauthGate` to the shared `RetargetableReauthGate`; the **cloud** path threads the persisted window through `cloudGateForResolvedVault`.
- **Testing fakes**: `FakeSettingsPort` (+ a `previewWindows` spy on `FakeTrashPort`).

**Two load-bearing invariants, both test-pinned (identical to iOS #419):**
- **Retarget-after-save ordering (security):** the save is gated against the **current (pre-save)** grace window; the gate retargets to the new window **strictly after** a successful write, and **only when the grace value changed** — so a user outside the current grace window cannot widen it to self-authorize the widening. Pinned by a `writtenAtAuthorize==[0]` / `writtenAtRetarget==[1]` ordering test.
- **Field preservation + TOCTOU:** `save()` re-reads `readSettings()` **after** the gate and merges only retention+grace onto the freshly-read `autoLockTimeoutMs`/`requirePasswordBeforeEdits`, so a partial write never clobbers them (and closes the load→save TOCTOU). Pinned at the VM level + a save-before-load test.

### Branch commits (off `main` @ `25b8b652`, in order)
- `0b02d474` PR-3 plan doc
- `f689ec89` Tasks 1–2 (SettingsPort + value types + conversions + `FakeSettingsPort`)
- `15c829a4` Task 3 (`retargetWindow` seed-at-now gate primitive)
- `6fbe9220` Task 4 (`SettingsModel` — gated save + retarget-after-save ordering)
- `d0a55a03` Task 5 (Trash per-vault retention integration)
- `201374a9` Task 6 (`UniffiVaultSession: SettingsPort` in-class adapter)
- `3f207013` Phase-1 **review hardening** (narrow the Trash retention catch; +CancellationException-propagation + save-before-load tests)
- `fc254875` Tasks 7–8 (`SettingsScreen` + VM + composition wiring + separate entry)
- `a062a021` README + ROADMAP feature-complete flip
- `0c0daca8` whole-branch **review fix** (clear a stale save banner on Settings re-entry)
- `<this handoff commit>` handoff doc + symlink retarget

### Acceptance (all verified green this session, from the worktree)
```bash
( cd android && ./gradlew :vault-access:test )                                                    # host: SettingsModel 14 · Retargetable 7 · TrashBrowse 18 · conversions 9 · fake 5, 0 failures
( cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :kit:lintDebug \
    :browse-ui:compileDebugKotlin :app:assembleDebug )                                            # full gate: BUILD SUCCESSFUL
```
PR 3 is Android-only (no `.rs` / desktop / iOS change), so the Rust/desktop/iOS gates do not apply.

**Reviews:** Phase-1 focused review — **all six load-bearing invariants CONFIRMED enforced, tests non-vacuous, "no changes for merge"**; applied its 3 optional sub-threshold items anyway (`3f207013`). Whole-branch review (opus) — **security posture SOUND, no defects at/above threshold**: shared-gate identity end-to-end (browse+trash+settings retarget the *same* `RetargetableReauthGate` instance), grace-seeding correct on both open paths (the bounds-default fallback can't fail the unlock; the cloud `learnedVaultId` is populated before `makeGraceGate` runs; un-enrolled → NOOP handled), retarget-after-save intact through the VM chain, no regression to device-settings/trash/session-lifecycle, `:kit` adapter handle-safe. Its one sub-threshold UX nit (stale save banner on re-entry) is fixed (`0c0daca8`).

## (2) What's next — the mobile-settings slice is COMPLETE

There is **no PR 4** for this feature. Pick the next slice from [ROADMAP.md](../../ROADMAP.md) / [README.md](../../README.md). Concrete candidates surfaced during this work:

- **Mobile Settings/Trash screen render tests** ([#417](https://github.com/hherb/secretary/issues/417)) — the iOS + Android settings/trash *screens* stay host-untested (only the VMs/models are). The `testTag`/`accessibilityIdentifier` hooks are in place (`open-vault-settings`, `settings-retention-days`, `settings-grace-minutes`, `settings-save`, `settings-notice`, `settings-error`, `vault-settings-back`) for a future Compose/instrumented assertion.
- **Desktop OS-biometric + presence proof for password-only sessions** — the remaining "configurable grace-window settings + presence proof" roadmap item (ROADMAP D.1 status line); mobile grace-window config now shipped, desktop OS-biometric still open.
- Any user-prioritized slice.

## (3) Open decisions and risks

- **30 s → 2 min effective grace default on Android (accepted, user-approved).** User-visible weakening; called out in the PR body + README/ROADMAP. Now consistent with iOS/desktop.
- **Seed-at-now on `retargetWindow` (accepted, mirrors iOS #419 §3).** A grace-changing save reseeds presence to `now`; a retention-only save does **not** retarget (guarded), so a non-grace edit never slides the unattended-write window. Bounded by the grace window's inherent trust; deliberate ("a successful gated save means the user is present now").
- **Cloud grace-window seeding is compile-verified but not runtime-tested here** (no emulator + SAF in this session). The change is minimal and conservative: the existing `onVaultUuidLearned` placeholder-retarget stays as a robust fallback, and `openBrowseWithSync` re-installs the persisted window over it via `makeGraceGate` (which reads the resolved `learnedVaultId` at call time). The whole-branch review confirmed the ordering and the no-write-before-install property from the code. If a future change reorders cloud open, re-verify the placeholder→persisted-window install sequence.
- **Mobile screen render stays host-untested** (existing gap #417); the `testTag` hooks are in place.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After PR 3 merges, drop the branch + worktree (squash-merge leaves it "not fully merged"):
#   git worktree remove .worktrees/mobile-settings-android && git branch -D feature/mobile-settings-android
git worktree list && git status -s
# Re-run PR-3 gates any time the branch is live (from the worktree root .worktrees/mobile-settings-android):
#   ( cd android && ./gradlew :vault-access:test )
#   ( cd android && ./gradlew :vault-access:test :kit:testDebugUnitTest :kit:lintDebug :browse-ui:compileDebugKotlin :app:assembleDebug )
# NOTE: a cold :kit daemon triggers a multi-minute silent Rust→JNI build — warm once, run backgrounded with log-poll.
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; the symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). The handoff rides inside the PR — do **not** sync to `main` during the pause window ([[feedback_next_session_main_authoritative]]). If resuming this branch for fixups, first `git fetch origin && git merge origin/main` (branch version wins on this doc) before editing.

## Closing inventory
- **State on close:** PR 3 opening on `feature/mobile-settings-android` (worktree `.worktrees/mobile-settings-android`). 10 branch commits (1 plan + 6 task/adapter + 1 phase-1-fix + 1 docs + 1 whole-branch-fix) + this handoff = 11.
- **Acceptance:** `:vault-access` host tests (SettingsModel 14 incl. the ordering + field-preservation + CancellationException + banner-clear pins) + `:kit`/`:browse-ui`/`:app` build + `:kit:lintDebug` → BUILD SUCCESSFUL. Both reviews clean (Phase-1 CONFIRMED non-vacuous; whole-branch SOUND); the two nits addressed.
- **Next:** the mobile per-vault settings feature is **complete on all three platforms** — pick the next slice from ROADMAP/README (#417 render tests, desktop OS-biometric, or user priority).
- **README / ROADMAP:** updated — Android Settings row added; ROADMAP flipped to "feature-complete on desktop + iOS + Android".
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-12-mobile-vault-settings-pr3-android-shipped.md`.
