# NEXT_SESSION.md — iOS biometric device-unlock → browse (#284) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-01. Built the iOS analog of Android's demo/local biometric device-unlock flow and, as its final wire, **seeded the write-reauth grace window from the biometric-unlock instant — closing [#284](https://github.com/hherb/secretary/issues/284)**. #284 as filed was a one-liner, but its precondition ("when the biometric device-unlock → browse route is connected") was **unmet on iOS**: the app's Unlock screen was password/recovery only, and `DeviceUnlockScreen` was a standalone #202 walking-skeleton wired into nothing. So this session built the enabling integration. Executed subagent-driven (fresh implementer per task → spec+quality review per task → opus whole-branch review → opus-flagged fix wave) in worktree `.worktrees/ios-device-unlock-browse-284`, branch `feature/ios-device-unlock-browse-284` (cut from `main` @ `42c1311`). **iOS only — `SecretaryDeviceUnlock` / `SecretaryVaultAccess` / `SecretaryKit` / `SecretaryApp`; no `core`/`ffi` Rust, no on-disk-format / spec / `conformance.py` / conflict-KAT / FFI-surface change** (the B.2 `open_with_device_secret` / device-slot FFI already existed and is consumed).

## (1) What we shipped this session

**The gap (verified at source).** The app `Route` enum had only `select`/`create`/`unlock`/`browse`; the `.unlock` screen used `UnlockViewModel.Mode = {password, recovery}` and built `GraceWindowReauthGate` with no `initialAuthAt` (correct — neither proves biometric presence). There was no live biometric-unlock→browse path to seed. `openWithDeviceSecret` (B.2 FFI) already returns the same `OpenVaultOutput` the password path wraps, so a full browse session was one constructor away — only the app wiring was missing.

**The build (mirrors Android's demo/local path).**
- **Layering (Android parity).** The pure, FFI-free `SecretaryDeviceUnlock` coordinator yields a **`DeviceSecretCredential`** (`releaseCredential(reason:)`); `unlock()` was refactored to compose on that single primitive (walking-skeleton unchanged). `VaultOpenPort` gained a **`openWithDeviceSecret(...) -> VaultSession`** arm (+ folded `VaultAccessError.wrongDeviceSecretOrCorrupt`); the real `UniffiVaultOpenPort` conformer opens via the **same B.2 `open_with_device_secret` manifest verify-before-decrypt** and wraps the identical `UniffiVaultSession` as the password path (proven by a real-FFI round-trip on a temp golden-vault copy).
- **#284 seeding.** New pure host-tested `reauthInitialAuthAt(biometricUnlock:now:)` returns `now` for a biometric open, `nil` otherwise. The app builds the gate with `initialAuthAt: MonotonicInstant.now()` on the biometric path **only**; password/recovery stay `nil` (no biometric-presence oracle). Authorizer unchanged (`EnclaveBiometricAuthorizer`).
- **App wiring (no new route).** "Unlock with Face ID" button on the existing Unlock screen when enrolled → `DeviceUnlockOpen.open` (release → `openWithDeviceSecret` → **verify opened UUID == enrolled UUID, else `wipe()` + typed error** → seeded gate → `.browse`). Secret zeroized on every exit path.
- **#341 (folded proactively).** Pure exhaustive classifier `deviceUnlockFailureDisplay`: only `.userCancelled` is silent; every other `DeviceUnlockError` surfaces a typed message (no silent non-cancel return).
- **#342-safe.** "Remember this device" checkbox (Password mode, when not enrolled) enrolls after a successful password open — **offloaded off the main actor**, non-fatal — and `rememberDevice`/`biometricError` are parent-owned `@State` **reset on every `.unlock` route entry**.

**Verification.** `bash ios/scripts/run-ios-tests.sh` green end-to-end at each app-touching task and after the fix wave: pure host packages (`SecretaryDeviceUnlock`, `SecretaryVaultAccess`), simulator `SecretaryKit` XCTest (incl. the device-secret round-trip + the new error-mapping test), and the `SecretaryApp` compile (`** TEST SUCCEEDED **` + `** BUILD SUCCEEDED **`, no `error:` lines). Per-task reviews all Approved. **Opus whole-branch review: Ready to merge — With fixes, 0 Critical**, all 8 security invariants verified at source (no weaker open, #284 seeding asymmetry, zeroize on all exit paths, wrong-vault wipe, exhaustive #341 classifier, anti-oracle fold, Swift 6 Sendable capture, FFI-free pure package). The two Important findings + one parity Minor were **fixed** in `c205a18` (below) and controller-verified at source.

**Branch commits** (off `main` @ `42c1311`):
| SHA | What |
|---|---|
| `fc7140d` | docs: design |
| `17f0011` | docs: implementation plan |
| `bdd7df1` | T1 — `DeviceSecretCredential` + `releaseCredential`; `unlock` refactor (host tests) |
| `32bd8b6` | T2 — `VaultOpenPort.openWithDeviceSecret` arm + fake + folded error case |
| `6829fdb` | T3 — real `UniffiVaultOpenPort` conformer + real-FFI round-trip |
| `f6d1989` | T4 — `reauthInitialAuthAt` (#284 seeding decision, host-tested) |
| `49d0910` | T5 — exhaustive `deviceUnlockFailureDisplay` (#341, host-tested) |
| `90e6748` | T6 — biometric button + release→open→verify→**seeded gate**→browse (#284, #341) |
| `b519d9d` | T7 — "Remember this device" enroll-at-unlock (#342-safe) |
| `2c85f7a` | T7 fix — offload enroll off the main actor (review) |
| `2f25081` | T8 — README + ROADMAP |
| `c205a18` | Final fix wave — map device-slot open errors + zeroize device-secret boundary copy + biometric-path log parity (review) |
| (+ handoff) | this baton + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-device-unlock-browse-284
bash ios/scripts/run-ios-tests.sh          # host packages + simulator SecretaryKit + app compile, all green
# Fast pure-package iteration:
#   (cd ios/SecretaryDeviceUnlock && swift test) ; (cd ios/SecretaryVaultAccess && swift test)
```

## (2) What's next
#284 is complete (pending on-device proof). Concrete follow-ups:

1. **On-device Face ID acceptance (iPhone 13 Pro Max), the plan's manual checklist — no code expected.** *Acceptance:* enroll via the "Remember this device" checkbox on a password open → background/foreground → "Unlock with Face ID" → lands in browse; **first write within 30 s does NOT re-prompt** (#284 seeding); a write after the window re-prompts; a cancelled Face ID prompt returns to Unlock **silently** (#341). If it passes, flip the "on-device Face ID acceptance pending" note in README/ROADMAP to ✅.
2. **Android [#341](https://github.com/hherb/secretary/issues/341) / [#342](https://github.com/hherb/secretary/issues/342)** remain open — this session folded the **iOS-side** equivalents in proactively, but the Android bugs (non-cancel `DeviceUnlockError` feedback; "Remember this device" checkbox carry-over) are still to do. *Acceptance:* Android non-cancel failure surfaces a typed message; Android checkbox resets on Unlock-screen route entry.
3. **Android cloud follow-ups from the #340 baton:** on-device biometric cloud-*open* proof ([#338](https://github.com/hherb/secretary/issues/338)); local/non-GDrive SAF on custom ROMs ([#331](https://github.com/hherb/secretary/issues/331)); settings enroll/disenroll toggle (#333 is opt-in-at-open only); native cloud-provider epic ([#334](https://github.com/hherb/secretary/issues/334), **ADR + threat-model first**).

## (3) Open decisions and risks
- **No automated coverage of the Context/biometric-bound app wiring** (`DeviceUnlockOpen`, the Unlock-screen glue, the enroll offload) — compile + on-device only, the same accepted limitation as every biometric path in this repo. The decidable logic is host-tested pure (`reauthInitialAuthAt`, `deviceUnlockFailureDisplay`, `releaseCredential`, the round-trip). The one remaining gap closes with item (1)'s on-device walkthrough.
- **Enroll-during-this-open arms on the *next* biometric unlock** (explicit non-goal; the current session is already open via password). Consistent with Android's demo path.
- **Accepted benign Minors** (no action needed; recorded in `.superpowers/sdd/progress.md`): double `metadata.load()` in `unlock` (pure read); weak `vaultUuidHex.count` round-trip assertion; `biometricUnlock: Bool` vs enum; user-facing messages interpolate error-taxonomy strings (no secret content); `runOffMainActor` idiom duplicated in the app target (module-visibility — promote to `public` only if a 3rd site appears); `coordinator` name shadow in two disjoint closures.
- **Process note:** the multi-minute Rust `Secretary.xcframework` build trips a subagent's 600 s no-output watchdog. Warm-build it once (`bash ios/scripts/build-xcframework.sh`; Swift-only changes don't invalidate it), and have simulator/app-build subagents run `run-ios-tests.sh` via a backgrounded Bash + log-poll. Two fix subagents also flaked by "waiting" on a backgrounded build instead of polling; an imperative "execute the edits and commit before replying" retry worked.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/ios-device-unlock-browse-284 && \
#   git branch -D feature/ios-device-unlock-browse-284
git worktree list && git status -s
# iOS toolchain is available on this machine (Xcode + simulators; Apple-dev signing works).
# On-device Face ID needs the physical iPhone 13 Pro Max (manual steps).
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/ios-device-unlock-browse-284` (12 work/docs commits + handoff). Worktree `.worktrees/ios-device-unlock-browse-284`. Feature complete; #284 resolved (on-device proof pending).
- **Acceptance:** `run-ios-tests.sh` green (host + simulator + app compile); all per-task reviews Approved; opus whole-branch review Ready-to-merge-with-fixes (0 Critical) → the 2 Important + 1 parity Minor fixed in `c205a18` and source-verified.
- **README.md / ROADMAP.md:** updated (iOS status row + ROADMAP progress-bar + phase-plan bullet; #284 marked done, on-device Face ID acceptance noted pending; Android #340 cross-ref updated). **CLAUDE.md:** unchanged (the existing B.3 iOS paragraph + device-open FFI arm description remain accurate; the new wiring is a UI integration, not a new grep-invisible invariant).
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-01-ios-device-unlock-browse-284-shipped.md`.
