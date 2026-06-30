# NEXT_SESSION.md — Android unsynced-create warning banner (#329) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-01. Surfaced `PendingFlushNotPersisted` (an offline-created cloud vault that could neither sync nor persist its pending-flush marker) as a **persistent warning banner on the Unlock screen**, instead of only a logcat line. Issue [#329](https://github.com/hherb/secretary/issues/329). Executed subagent-driven (fresh implementer per task → spec+quality review per task → whole-branch opus review) in worktree `.worktrees/android-unsynced-create-banner-329`, branch `feature/android-unsynced-create-banner-329` (cut from `main` @ `be84775`). **`android/app` Kotlin/Compose only — no `:vault-access`/`:kit`, no `core`/`ffi`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change.**

## (1) What we shipped this session

**The feature.** The signal already existed: `cloudOpenFailureRoute` returns `CloudOpenFailure(target, createdButNotSynced)` (host-tested), but `createdButNotSynced` only ever chose between two `Log.w` lines — both failure branches returned the identical `Route.Unlock(cloudTarget = failure.target)`, so a user whose freshly-created vault lives **only** in the local working copy saw the same Unlock screen as an ordinary retry. The integrity protection (the `VaultMirror.materialize` no-clobber guard + `isCreate`-preserved push-before-pull retry, #327) already protected the data — this session adds **only** the missing user-facing warning.

- **Pure projection** — `unsyncedCreateRoute(failure: CloudOpenFailure): Route.Unlock` in [CloudVaultOpen.kt](android/app/src/main/kotlin/org/secretary/app/CloudVaultOpen.kt), Context-free + host-testable, threads `failure.createdButNotSynced` onto the new `Route.Unlock.unsyncedCreateWarning: Boolean = false` field. `openCloudTarget`'s failure branch now returns `unsyncedCreateRoute(failure)`; **both `Log.w` branches untouched.**
- **Banner** — `UnlockScreen` gains a last/defaulted `unsyncedCreateWarning: Boolean = false` param; when true it renders a `Text` at the top of the Column (`testTag("unsynced-create-warning")`, `colorScheme.error`), following the existing `wizard-error`/`device-error` plain-`Text` convention (no Card/Surface). `AppRoot` passes `r.unsyncedCreateWarning`.
- **Clearing semantics (opus-verified at source, design §3):** the banner rides the **failed-attempt flag** on the route, not durable state — by construction `PendingFlushNotPersisted` means the marker *couldn't* persist, so there is nothing durable to read. Success → `Route.Browse` clears it; an ordinary retry failure sets `false` (correct — the vault is now marked, push-before-pull protects it); backgrounding (ON_STOP → `Route.Unlock(null)`) drops it (documented limitation; data still protected; warning re-raises on the next failed create-open). Merely being on the create-then-open Unlock screen does **not** show the banner (create-wizard routes with the flag defaulted `false`).

**Verification.** Full host gate green (run by the controller post-merge-review): `:app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin` → BUILD SUCCESSFUL. Host: `CloudCreateErrorRoutingTest` 4/4 (2 existing + 2 new — projection true/false + target identity). Instrumented `UnsyncedCreateWarningUiTest` 2/2 on `emulator-5554` (`Medium_Phone_API_36.1`, `ANDROID_SERIAL` pinned so the flaky RedMagic was untouched): banner shown for `true`, absent for `false`. Whole-branch review (opus): **Ready to merge: Yes, 0 Critical / 0 Important** — all six invariants (additive/no-weaker, both `Log.w` preserved, defaulted additions safe across all 6 `Route.Unlock` + the `UnlockScreen` call sites, clearing semantics, real-behavior tests, scope) verified at source.

**Branch commits** (off `main` @ `be84775`):
| SHA | What |
|---|---|
| `d88f51a` | docs: design |
| `218aec4` | docs: implementation plan |
| `79aa14a` | Task 1 — `Route.Unlock.unsyncedCreateWarning` + pure `unsyncedCreateRoute` helper + host test (4/4) |
| `e0f34f9` | Task 2 — `UnlockScreen` banner param + `AppRoot` wiring |
| `4f56a12` | Task 3 — instrumented `UnsyncedCreateWarningUiTest` (2/2 emulator-5554) |
| `ff9e41b` | Task 4 — README + ROADMAP |
| (+ handoff) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-unsynced-create-banner-329/android
./gradlew :app:testDebugUnitTest :kit:testDebugUnitTest :vault-access:test \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin              # full host gate green
# Instrumented (emulator-5554 online; pin the serial so the RedMagic is skipped):
ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.secretary.app.UnsyncedCreateWarningUiTest   # 2/2
```

## (2) What's next
#329 is complete. Remaining cloud follow-ups (pick at brainstorm):

1. **`security` [#340](https://github.com/hherb/secretary/issues/340) — write-reauth gate is NOOP on the first biometric/password open of a remembered cloud vault** (vault UUID not yet known until first open, so `cloudReauthRoute` selects NOOP). *Highest-priority of the open set — it's a security label.* *Acceptance:* the grace-window/reauth gate is armed (not NOOP) on the first open of a remembered cloud vault whose UUID is learned during that open.
2. **[#341](https://github.com/hherb/secretary/issues/341) — biometric unlock surfaces no feedback on a non-cancel `DeviceUnlockError`** (demo + cloud paths). *Acceptance:* a non-cancel failure (e.g. `wrappedSecretCorrupt`, enclave error) surfaces a typed message, not a silent return to Unlock.
3. **On-device biometric cloud-*open* proof ([#338](https://github.com/hherb/secretary/issues/338)).** Manual on-device walkthrough on the RedMagic 11 Pro over a real Google Drive folder; no code change expected.
4. **Picker can't grant local/non-GDrive SAF tree on custom ROMs ([#331](https://github.com/hherb/secretary/issues/331)).** In-app guidance and/or an app-managed local vault location.
5. **Settings-screen enroll/disenroll toggle for cloud vaults** (#333 is opt-in-at-open only).
6. **Native cloud-provider integration epic ([#334](https://github.com/hherb/secretary/issues/334)).** **Gated on an ADR + threat-model review FIRST** — an embedded OAuth client secret in the secrets process changes the in-process attack surface vs OS-mediated SAF.

## (3) Open decisions and risks
- **Banner is transient-by-construction, not durable.** It rides the failed-attempt `Route.Unlock` flag; a process restart or backgrounding drops it. This is inherent to `PendingFlushNotPersisted` (no durable marker exists for that case). Data is still protected by the materialize no-clobber guard; the warning re-raises on the next failed create-open. If a future slice introduces a durable "vault exists only locally" marker, re-source the banner from it (forward note, out of scope here).
- **Cloud open failure message stays generic.** The cloud path's existing "couldn't open the cloud vault" Toast is still shown on failure *in addition* to the persistent banner; the typed `unlockFailureMessage` re-plumbing remains out of scope (consistent with #332/#333; tracked for the cloud path by #341).
- **`:app` Compose-UI instrumented tests can fail on the RedMagic** ("No compose hierarchies found") — pre-existing, device-specific; the merge gate is the host suite + emulator-5554 (`ANDROID_SERIAL` pin).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/android-unsynced-create-banner-329 && \
#   git branch -D feature/android-unsynced-create-banner-329
git worktree list && git status -s
# Pick a next item (see §2; #340 is the security-labelled one). Android toolchain on this machine:
# emulator-5554 + a real RedMagic 11 Pro (serial 912607710061); adb/emulator need absolute paths
# (~/Library/Android/sdk/platform-tools/adb); logcat is blocked on the RedMagic.
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-unsynced-create-banner-329` (6 work/docs commits + handoff). Worktree `.worktrees/android-unsynced-create-banner-329`. Feature complete; #329 resolved.
- **Acceptance:** full host gate green; host `CloudCreateErrorRoutingTest` 4/4; instrumented `UnsyncedCreateWarningUiTest` 2/2 on emulator-5554; whole-branch opus review Ready-to-merge (Yes, 0 Critical / 0 Important).
- **README.md / ROADMAP.md:** updated (Unlock-screen unsynced-create warning banner). **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-01-android-unsynced-create-banner-329-shipped.md`.
