# NEXT_SESSION.md — iOS app walking-skeleton + #202 on-device biometric proof ✅

**Session date:** 2026-06-11. Flow: `/nextsession` → found B.3 (#214) already merged + clean → re-reviewed PR #214 at the user's request (found + fixed 2 issues: an auth-vs-tamper `mapDecryptError` mislabel `751d542`, and a `clear()` strand `facf676`; merged) → brainstormed the next slice → spec → 9-task TDD plan → subagent-driven implementation (fresh implementer + spec & code-quality review per task) → final whole-branch review (APPROVE) → **on-device #202 proof on a physical iPhone 13 Pro Max**.

**Status:** ✅ code-complete on branch `feature/ios-app-device-unlock`; **#202 PROVEN ON DEVICE.** PR: see §4.

## (1) What we shipped this session

**The first runnable iOS app — a SwiftUI walking-skeleton — and the on-device proof that closes #202.** A pure, host-testable `DeviceUnlockViewModel` drives the real B.3 device-unlock flow (enroll / unlock / disenroll) through the real `DeviceUnlockCoordinator` (real Secure Enclave + uniffi port + Keychain); the app deployed to a real iPhone and Face ID released the device secret + opened the vault.

| Layer | What landed | Key commits |
|---|---|---|
| **Diagnostic plumbing** (pure pkg) | `lastReleaseDiagnostic` on the `DeviceSecretEnclave` protocol (default-nil ext) + coordinator passthrough + injectable on the fake; host-tested | `e57c5d6` |
| **UI core** (pure pkg) | New `SecretaryDeviceUnlockUI` SPM product: `DeviceUnlockState`/`Activity` enums + `@MainActor DeviceUnlockViewModel` (status/enroll/unlock/disenroll), **fully host-tested with the in-memory fakes** (34 `swift test` total) | `79a120d` `d828e44` `2e9b46e` |
| **App** | `ios/SecretaryApp/` — an **XcodeGen** app target (`project.yml` committed; generated `.xcodeproj` gitignored), thin `DeviceUnlockScreen` + `AppVaultProvisioning` (stages a writable golden-vault copy) + `@main` wiring the real coordinator; `scripts/build-app.sh` (stage fixture → xcodegen → simulator build, auto-builds the xcframework if absent) | `eb1787a` `ee0166b` `f24debf` |
| **SE store** | Real `SecureEnclaveDeviceSecretStore` records the raw `domain`+`code` diagnostic (every `mapDecryptError` branch) — **typed mapping unchanged**, only diagnostic capture added | `b1f1693` |
| **CI + docs** | `build-app.sh` wired into `run-ios-tests.sh`; README/ROADMAP/ios-README updates | `7880ffb` `a7a4ef4` |
| **On-device codesign fix** | A bundled folder literally named `Resources/` breaks on-device codesign — staged the demo vault under `Fixtures/` instead (loaded via `Bundle subdirectory:`) | `f83c326` |
| **#202 proven** | docs marked ✅ across README/ROADMAP/ios-README/CLAUDE; `.swiftpm/` gitignored | `677c1a2` `73c3b6c` |

Branch from `main` @ `49b615e`: spec `e923f06` + plan `9194c99` + the above. **Squash-merge collapses to one commit on `main`.**

### The #202 on-device proof (iPhone 13 Pro Max, real SE + Face ID)

| Step | Result |
|---|---|
| Enroll (golden password) → mints slot, SE-wraps the secret | ✅ enrolled |
| **Unlock → match Face ID** → SE releases secret → `open_with_device_secret` | ✅ **unlocked; `vault_uuid` matched the pinned golden fixture** |
| Unlock → cancel the prompt | `domain=com.apple.LocalAuthentication code=-2 mappedTo=userCancelled` |
| Unlock → non-matching face | same — `LAError.userCancel` → `userCancelled` |
| Unlock → repeated failures | no distinct lockout; Face ID stops + offers cancel → again `LAError.userCancel` |
| Disenroll | ✅ not enrolled |

**Findings (folded into the docs):**
- The happy path works on **real hardware** — non-exportable SE P-256 key, biometric gate, secret release, vault open. This is #202's core deliverable. ✅
- The `SecKeyCreateDecryptedData`-triggered biometric eval funnels cancel / non-match / exhausted-attempts into **`LAError.userCancel` (code −2)** — it does **not** surface distinct `authenticationFailed` / `biometryLockout` codes (those are more a direct-`LAContext.evaluatePolicy` thing), and it does **not** use `NSOSStatusErrorDomain` on this device/iOS.
- **No failure produced `.wrappedSecretCorrupt`** → the "never mislabel an auth failure as tamper" property (hardened in #214's `751d542`) held on hardware. **No `mapDecryptError` change needed.** The `NSOSStatusErrorDomain` branch + the `authenticationFailed`/`biometryLockout` LAError cases remain correct **defensive** handling (untriggered on this path, but right to keep).

### Acceptance (all green)
```
cd ios/SecretaryDeviceUnlock && swift test                 → 34 passed (host: VM + diagnostic + state + prior 24)
bash ios/scripts/run-ios-tests.sh                          → host 34 + simulator XCTest 3/3 + app BUILD SUCCEEDED
# device: Xcode → Secretary target → Signing (Team) → Run on iPhone 13 Pro Max → proof table above
git diff main..HEAD --name-only | grep -E '\.rs$'          → (empty — no Rust touched)
```

## (2) What's next

**No single forced headline.** The B-chain + iOS device-unlock arc (B.1 core → B.2 FFI → B.3 SE conformer → app + #202 proof) is **complete**. Candidate next slices (pick with the user):
- **iOS app — grow beyond the skeleton:** password/recovery unlock UI, vault create/import, record browse/edit — i.e. start the iOS analogue of the desktop D.1.x arc. (Largest; all Swift.)
- **Rust-core backlog (Rust-learning):** **#193** (`pipeline.rs` refactor), **#192** (collision-population test).
- **Desktop/sync deferred:** background auto-sync (Tauri), reveal-to-decide; manual GUI smoke **#161**.

**Acceptance for the iOS-app-growth path** would mirror the desktop walking skeleton: unlock-an-existing-vault (password) + a real block list, host-tested view models + a simulator integration test, on-device manual smoke.

**Open follow-up issues:** carried **#192/#193/#186/#189/#190/#161/#162/#167** (#202 closes with this PR).

## (3) Open decisions and risks

- **`@MainActor` ViewModel blocks on the password KDF.** `enroll` awaits the synchronous, CPU-heavy Argon2id open on the main actor (brief UI freeze). Documented, accepted for the skeleton; a background-offload refinement is the noted follow-up (needs Sendable plumbing of the coordinator/ports, or an actor).
- **Signing-team friction:** the committed `project.yml` is team-agnostic (`DEVELOPMENT_TEAM = $(DEVELOPMENT_TEAM)`), so regenerating the project resets the team you picked in Xcode — reselect it (one click) on each device build. CI uses the simulator (no signing). A local untracked xcconfig could pin it if this becomes annoying.
- **`Resources/`-name codesign trap (now documented):** never bundle a folder literally named `Resources/` in a flat iOS `.app` — codesign fails with the misleading "code object is not signed at all / embedded.mobileprovision". We stage under `Fixtures/`. (Isolated empirically: any other folder name signs cleanly.)
- **Carried B.3 risks unchanged:** `device_uuid` bound structurally not in AEAD AAD; anti-rollback `None` on the device path at parity with password; best-effort zeroization under Swift value/COW semantics.

## (4) Exact commands to resume

```bash
# 1) PR (opened this session — confirm / review / merge):
cd /Users/hherb/src/secretary && gh pr list --head feature/ios-app-device-unlock

# 2) Merge (squash) once reviewed, then housekeeping:
git fetch --prune origin && git checkout main && git pull --ff-only origin main
git worktree remove .worktrees/ios-app-device-unlock && git branch -D feature/ios-app-device-unlock
git worktree prune && git worktree list

# 3) Next slice: brainstorm → plan → execute
git worktree add .worktrees/<slug> -b feature/<slug> main

# Re-run this session's gauntlet on the branch (macOS + Xcode + simulators):
cd /Users/hherb/src/secretary/.worktrees/ios-app-device-unlock/ios/SecretaryDeviceUnlock && swift test   # 34
bash /Users/hherb/src/secretary/.worktrees/ios-app-device-unlock/ios/scripts/run-ios-tests.sh            # host + sim + app build
# device re-proof: open ios/SecretaryApp/Secretary.xcodeproj in Xcode, set the Team, Run on a Face ID device
```

## (5) Handoff file model

`NEXT_SESSION.md` is a **relative symlink** to the latest file in `docs/handoffs/` (this file). Authored once; the symlink is the pointer. `main` did NOT move during this session (branch point == `origin/main` == `49b615e`), so the symlink retarget merges cleanly. Both this handoff + the retargeted symlink are committed on the feature branch ([[feedback_next_session_in_pr]]).

## Closing inventory

- **Branch on close:** `main` @ `49b615e`; `feature/ios-app-device-unlock` carries spec + plan + the 9-task implementation (each with its review fixes) + the on-device codesign fix + the #202-proven docs + this handoff/symlink. Squash-merge → one commit on `main`.
- **Acceptance:** green — host `swift test` 34/34, simulator XCTest 3/3, app BUILD SUCCEEDED, on-device proof passed (§1). No Rust / frozen-format / FFI-surface change (`git diff main..HEAD` is `ios/` + docs only).
- **Final whole-branch review:** APPROVE (all 8 cross-cutting properties hold; no weaker open; mapping byte-identical; #202 not overclaimed pre-proof).
- **README.md / ROADMAP.md / ios/README.md / CLAUDE.md:** updated — iOS app walking-skeleton ✅ + #202 on-device biometric proof ✅; CLAUDE records the `Resources/`→`Fixtures/` codesign gotcha.
- **#202 closes with this PR** (real SE + Face ID proven on an iPhone 13 Pro Max).
- **NEXT_SESSION.md:** symlink retargeted to this file.
