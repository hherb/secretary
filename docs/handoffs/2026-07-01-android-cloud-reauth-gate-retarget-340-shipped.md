# NEXT_SESSION.md — Android cloud write-reauth gate re-target (#340) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-01. Fixed a `security`-labelled defense-in-depth gap: the write-reauth gate was selected as `NOOP` on the **first** biometric/password open of a remembered SAF cloud vault, because the gate was chosen from the pre-open `location.vaultUuidHex` — empty (`""`) for a SAF-picked vault until its UUID is learned during open. Issue [#340](https://github.com/hherb/secretary/issues/340) (Android analog of iOS [#284](https://github.com/hherb/secretary/issues/284)). Executed subagent-driven (fresh implementer per task → spec+quality review per task → whole-branch opus review) in worktree `.worktrees/android-cloud-reauth-gate-retarget-340`, branch `feature/android-cloud-reauth-gate-retarget-340` (cut from `main` @ `da5a21c`). **`:vault-access` (one new pure class + test) + `:app` (`CloudVaultOpen.kt` + `CloudReauthRouteTest`) — no `core`/`ffi`, no on-disk-format / spec / `conformance.py` / conflict-KAT / observable-byte / FFI-surface change. Not a sealed-type arm → no cross-module exhaustive-`when` impact.**

## (1) What we shipped this session

**The bug (verified at source).** For a remembered SAF cloud vault opened the first time, `location.vaultUuidHex == ""`. `openCloudBrowse` built the gate at the top from that empty `vaultId` → `cloudReauthRoute("", enrolled=true, meta) == NOOP` (and a `CoordinatorBiometricAuthorizer` would be bound to `""`). The real UUID is only learned at `BrowseSession.kt::openBrowseWithSync` (`session.vaultUuidHex()` → `onVaultUuidLearned`), **after** the gate was already built, handed to `VaultBrowseModel`, and seeded — so that first session's writes ran ungated through `NoopReauthGate`. **The open itself was always correctly authorized against the enrollment metadata; only the write-reauth gate was missing — a defense-in-depth gap, not a weaker open.**

**The fix.**
- **New pure decorator** — `RetargetableReauthGate` (`android/vault-access/src/main/kotlin/org/secretary/browse/RetargetableReauthGate.kt`), a `WriteReauthGate` whose delegate is swappable (initial delegate `NoopReauthGate`). `seed(n)` records `n` **and** forwards; `reset()` clears the recorded instant **and** forwards; `authorizeWrite` forwards to the current delegate; `retarget(g)` swaps the delegate and re-seeds `g` with the recorded instant if the wrapper was already seeded — so the grace window opens at the unlock instant **regardless of whether `seed()` or `retarget()` ran first** (a local invariant, not reliant on call ordering). NOT thread-safe (single main-dispatcher caller, like `GraceWindowReauthGate`).
- **Cloud path re-wire** — `openCloudBrowse` now hands a `RetargetableReauthGate()` placeholder to `openBrowseWithSync` and, inside the existing `onVaultUuidLearned` callback, calls `gate.retarget(cloudGateForResolvedVault(deviceUnlock, resolvedHex, clock))`. The new private helper `cloudGateForResolvedVault` runs `cloudReauthRoute(enclaveEnrolled, resolvedHex, metadataVaultId)` and builds `GraceWindowReauthGate(CoordinatorBiometricAuthorizer(coordinator, resolvedHex), clock)` or `NoopReauthGate`. Because the gate is always rebuilt from the **resolved** UUID, the create path (UUID known up front) and the open path are handled uniformly — no empty-vs-known special-casing; un-enrolled/stale enrollment still yields `NOOP`.
- **Untouched:** `openBrowseWithSync`, the demo path (`AppRoot.kt`, empty diff), `learnedVaultId` logic, both `Log.w` branches, the zeroize `finally`, and the device-enroll flow — all verified intact at source by the final review.

**Verification.** Full host gate green (implementer, Task 2): `:vault-access:test :app:testDebugUnitTest :kit:testDebugUnitTest :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin` → BUILD SUCCESSFUL (2m 5s). Host: `RetargetableReauthGateTest` 5/5 (default authorizes; seed→retarget and retarget→seed both seed the new delegate; authorizeWrite forwards; reset clears+forwards), `CloudReauthRouteTest` 8/8 (7 pre-existing + 1 new boundary: `cloudReauthRoute("", enrolled=true, meta) == NOOP`). No instrumented test added — `openCloudBrowse` is Context/FragmentActivity-bound and the biometric release can't run host-side, so the two pure units carry the coverage (matching how `cloudReauthRoute` is already host-tested while `openCloudBrowse` is not). Per-task reviews: both clean, 0 findings. **Whole-branch review (opus): Ready to merge — Yes, 0 Critical / 0 Important** (2 Minor, both "no action required" — they confirm intended behavior); all six security invariants (resolved-UUID binding of both `cloudReauthRoute` and the authorizer, seed/retarget ordering for both orders, monotonic clock, the four must-not-touch items, no open-path weakening, no sealed-arm impact) verified at source against the pre-fix `da5a21c` version.

**Branch commits** (off `main` @ `da5a21c`):
| SHA | What |
|---|---|
| `9e5fa92` | docs: design |
| `79a08b8` | docs: implementation plan |
| `475b9c2` | Task 1 — `RetargetableReauthGate` + host test (5/5) |
| `a16bde2` | Task 2 — cloud open re-target wiring + `cloudGateForResolvedVault` + boundary test (8/8) |
| `c839e26` | Task 3 — README + ROADMAP |
| (+ handoff) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/android-cloud-reauth-gate-retarget-340/android
./gradlew :vault-access:test :app:testDebugUnitTest :kit:testDebugUnitTest \
  :app:compileDebugKotlin :app:compileDebugAndroidTestKotlin              # full host gate green
# Focused: RetargetableReauthGateTest 5/5, CloudReauthRouteTest 8/8
```

## (2) What's next
#340 is complete. Remaining cloud follow-ups from the open set (pick at brainstorm):

1. **[#341](https://github.com/hherb/secretary/issues/341) — biometric unlock surfaces no feedback on a non-cancel `DeviceUnlockError`** (demo + cloud paths). *Acceptance:* a non-cancel failure (e.g. `wrappedSecretCorrupt`, enclave error) surfaces a typed message, not a silent return to Unlock.
2. **[#342](https://github.com/hherb/secretary/issues/342) — "Remember this device" checkbox state carries across vaults on the Unlock screen** (no reset on route entry). *Acceptance:* the checkbox resets on Unlock-screen route entry so it doesn't carry a prior vault's choice.
3. **On-device biometric cloud-*open* proof ([#338](https://github.com/hherb/secretary/issues/338)).** Manual on-device walkthrough on the RedMagic 11 Pro over a real Google Drive folder; no code change expected.
4. **Picker can't grant local/non-GDrive SAF tree on custom ROMs ([#331](https://github.com/hherb/secretary/issues/331)).** In-app guidance and/or an app-managed local vault location.
5. **Settings-screen enroll/disenroll toggle for cloud vaults** (#333 is opt-in-at-open only).
6. **Native cloud-provider integration epic ([#334](https://github.com/hherb/secretary/issues/334)).** **Gated on an ADR + threat-model review FIRST** — an embedded OAuth client secret in the secrets process changes the in-process attack surface vs OS-mediated SAF.

Also worth considering: **iOS #284** is the mirror of this fix and remains open — the same "seed the write-reauth gate from the biometric device-unlock route once the UUID is known" shape applies there.

## (3) Open decisions and risks
- **Enroll-during-this-open still arms on the *next* open** (explicit non-goal). The retarget reads pre-open enrollment state (`deviceUnlock.enclaveEnrolled` at callback time, before `cloudEnrollThisDevice` runs later in `openCloudBrowse`), identical to the demo path. #340 concerns a vault enrolled on a *prior* session; enroll-then-write in the same session is out of scope and consistent with existing behavior.
- **No instrumented coverage of the retarget-in-callback glue.** `openCloudBrowse` is Context-bound and the biometric release can't run host-side, so the wiring is covered by the two pure unit tests (`RetargetableReauthGate` ordering + the `cloudReauthRoute` boundary) plus reading. If a future slice makes an instrumentable seam available, an on-device write-reauth-after-first-cloud-open test would close the last gap.
- **`:app` Compose-UI instrumented tests can fail on the RedMagic** ("No compose hierarchies found") — pre-existing, device-specific; unaffected here (no instrumented test added).

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/android-cloud-reauth-gate-retarget-340 && \
#   git branch -D feature/android-cloud-reauth-gate-retarget-340
git worktree list && git status -s
# Pick a next item (see §2). Android toolchain on this machine:
# emulator-5554 + a real RedMagic 11 Pro (serial 912607710061); adb/emulator need absolute paths
# (~/Library/Android/sdk/platform-tools/adb); logcat is blocked on the RedMagic.
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/android-cloud-reauth-gate-retarget-340` (5 work/docs commits + handoff). Worktree `.worktrees/android-cloud-reauth-gate-retarget-340`. Feature complete; #340 resolved.
- **Acceptance:** full host gate green; `RetargetableReauthGateTest` 5/5; `CloudReauthRouteTest` 8/8; both per-task reviews clean; whole-branch opus review Ready-to-merge (Yes, 0 Critical / 0 Important).
- **README.md / ROADMAP.md:** updated (cloud write-reauth gate re-target row + ROADMAP bullet + summary bars). **CLAUDE.md:** unchanged.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-01-android-cloud-reauth-gate-retarget-340-shipped.md`.
