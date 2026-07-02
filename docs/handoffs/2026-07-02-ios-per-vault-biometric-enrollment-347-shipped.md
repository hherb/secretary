# NEXT_SESSION.md — iOS per-vault-keyed biometric enrollment (#347) ✅ SHIPPED (PR opening)

**Session date:** 2026-07-02. Shipped the **iOS** fix for [#347](https://github.com/hherb/secretary/issues/347): "Unlock with Face ID" was shown **vault-agnostically**, firing a doomed biometric prompt for a vault this device wasn't enrolled for (a UX wart surfaced by the #346/#284 review — it failed gracefully via the post-open UUID check, no data loss). Chosen scope: **full Android-parity per-vault enrollment** — the Secure-Enclave key **and** the enrollment-metadata Keychain entries are namespaced by `vaultKey = SHA-256(vault path)`, mirroring Android's `cloudVaultKey`. Worktree `.worktrees/ios-per-vault-biometric-347`, branch `feature/ios-per-vault-biometric-enrollment-347` (cut from `main` @ `34980e5`). **iOS only — `SecretaryDeviceUnlock` (pure derivation) + `SecretaryKit` (factory) + `SecretaryApp` (rewire). No `core`/`ffi` Rust, no on-disk-format / spec / conformance / FFI-surface change; no change to `DeviceEnrollment` / coordinator / enclave protocol APIs — per-vault-ness lives in the Keychain storage keys, not the struct.**

Also at session start: the previous session's #341/#342 work (PR #348) was confirmed merged to `main` (`34980e5`); its remote branch was already deleted and the local worktree + branch `feature/android-biometric-feedback-341-342` were cleaned up.

## (1) What we shipped this session

Built via **subagent-driven development** (fresh implementer + task reviewer per task; opus whole-branch review at the end).

- **Task 1 — pure derivation** (`98addd1`): `vaultKey(fromPath: Data) -> String` (lowercase SHA-256 hex, named `sha256HexLength = 64`) + `perVaultDeviceUnlockIdentifiers(vaultPath:) -> PerVaultDeviceUnlockIdentifiers` in the FFI-free `SecretaryDeviceUnlock` package. Identifier scheme: `seKeyTag = com.secretary.deviceSecret.seKey.<vaultKey>`, `blobAccount = wrappedDeviceSecret.<vaultKey>`, `enrollmentAccount = deviceEnrollment.<vaultKey>`; the two **services stay stable** (all Secretary items grouped under one service, per-vault key rides in the account/tag). Host-tested (determinism, distinctness, hex shape, pinned KAT `SHA-256("secretary") = a814…8369`, identifier prefixes) — 6 tests, runs in `run-ios-tests.sh` Step 1 (fast host `swift test`, no simulator).
- **Task 2 — factory** (`24e8a45`): `makePerVaultDeviceUnlock(vaultPath:) -> PerVaultDeviceUnlock {coordinator, enclave}` in `SecretaryKit`, reusing the existing `SecureEnclaveDeviceSecretStore(keyTag:blobService:blobAccount:)` / `KeychainEnrollmentMetadataStore(service:account:)` constructor params (no new adapter params). Returns the **same-keyed enclave** alongside the coordinator (the reauth gate's authorizer needs this vault's key).
- **Task 3 — rewire** (`c0c812f`): all six app device-unlock construction sites routed through the factory (`SecretaryApp.swift` ×5 + `DeviceUnlockOpen.swift` ×1); device-global `localCoordinator()` deleted; **both** write-reauth grace-gate sites build their `EnclaveBiometricAuthorizer` with the same-keyed `.enclave`. Behavior-preserving otherwise (#342 resets, off-main-actor enroll, #284 `initialAuthAt` all intact).

**Why it's correct:** `coordinator.isEnrolled` becomes correct-by-construction — a vault-B-keyed coordinator queries vault-B's Keychain items, so it returns false when only vault A is enrolled and the button hides. The cross-vault doomed prompt is **unreachable**, not merely guarded. The pre-prompt `vaultId` guard (`DeviceUnlockCoordinator.unlock`) and post-open `session.vaultUuidHex == cred.enrolledVaultId` check remain as defense-in-depth; the device open still goes through the same `open_with_device_secret` manifest verify-before-decrypt (not a weaker open).

**Verification.** Full `bash ios/scripts/run-ios-tests.sh` — **green**: host pure-package tests (incl. the 6 new), `SecretaryKitTests` **41/41** on the simulator, app **BUILD SUCCEEDED**; grep confirmed no `localCoordinator` and no bare `SecureEnclaveDeviceSecretStore()` remain in the app target. **Opus whole-branch review: Ready to merge = YES** — 0 Critical/Important, 2 cosmetic Minors (both marked do-not-change); every security invariant (per-vault key isolation, same-keyed enclave at both gates, both defense-in-depth guards intact, crypto core untouched, Sendable) verified directly against the checkout.

**Branch commits** (off `main` @ `34980e5`):
| SHA | What |
|---|---|
| `0bd4185` | docs: design |
| `c67fadf` | docs: implementation plan |
| `98addd1` | feat — Task 1 pure `vaultKey` + identifier derivation |
| `24e8a45` | feat — Task 2 `makePerVaultDeviceUnlock` factory |
| `c0c812f` | feat — Task 3 rewire six construction sites (+ delete `localCoordinator`) |
| (+ docs) | README + ROADMAP + this handoff + retargeted `NEXT_SESSION.md` symlink |

### Acceptance (verified this session)
```bash
cd /Users/hherb/src/secretary/.worktrees/ios-per-vault-biometric-347
bash ios/scripts/run-ios-tests.sh          # host pure tests + SecretaryKit 41/41 + app build — GREEN
# Confirm no device-global construction remains:
grep -rn "localCoordinator\|SecureEnclaveDeviceSecretStore()" ios/SecretaryApp ios/SecretaryKit/Sources
# (expected: only the parameterized SecureEnclaveDeviceSecretStore(keyTag:...) inside the factory; no bare "()" and no localCoordinator)
```

## (2) What's next
#347 is complete. Follow-ups:

1. **iOS on-device Face ID acceptance (#284)** — still pending the physical iPhone 13 Pro Max manual walkthrough (no code). With #347 in, the walkthrough should also spot-check the **multi-vault** case: enroll vault A, then open vault B and confirm the Face ID button is **absent** for B (and present for A). If it passes, flip the "on-device Face ID acceptance pending" note in README/ROADMAP to ✅.
2. **Instrumented UI assertions for #341/#342 (Android, emulator, optional)** — the pure classifier is host-tested; the Compose Toast/reset wiring is compile-covered only (carried over from the #341/#342 baton).
3. **Android analog of #347's data-model consideration** — Android is *already* per-vault keyed on its cloud path via `cloudVaultKey(treeUri)` (#333), so #347 was iOS-specific. But note: Android's **local/demo** path is still device-global (single `DEFAULT_ALIAS`); iOS is now uniformly per-vault (incl. the demo). If a future change unifies the Android demo path to per-vault too, mirror this iOS shape.
4. **Android cloud follow-ups (from the #340 baton):** on-device biometric cloud-*open* proof ([#338](https://github.com/hherb/secretary/issues/338)); local/non-GDrive SAF on custom ROMs ([#331](https://github.com/hherb/secretary/issues/331)); settings enroll/disenroll toggle; native cloud-provider epic ([#334](https://github.com/hherb/secretary/issues/334), **ADR + threat-model first**).

## (3) Open decisions and risks
- **Write-reauth grace gate is now per-vault (behavior change, improvement).** It touches the #284 path: previously any enrollment armed the gate for every vault; now it's armed only for the enrolled vault. An unenrolled vault had no gate before either, so this is more correct, not a regression — but it is called out for reviewers (the opus review confirmed no bug).
- **Path-hash stability (accepted limitation).** If a vault file moves (iCloud relocation), its resolved path changes → `vaultKey` changes → enrollment appears lost → button hides → user re-enrolls. No data loss (password unlock always works; post-open UUID check is authoritative). Same class of concern as Android keying on `treeUri`. The vault UUID would be stabler but is unknown pre-open, so the path is the only pre-open key. Worth a one-line note in the eventual migration/settings story.
- **No migration of old device-global Keychain items** (pre-release app; nobody holds a durable enrollment). Old items become orphaned but harmless (never queried again). No cleanup pass.
- **Redundant factory calls** on the `.select`/`openDemo` `isEnrolled` snapshot paths (each build-and-discards a cheap wrapper) — the stores touch the Keychain only on method calls, not at init, so this is stateless and cheap; flagged Minor, do-not-change.

## (4) Exact commands to resume
```bash
cd /Users/hherb/src/secretary
git fetch --prune origin && git checkout main && git pull --ff-only origin main
# After this PR merges, remove the worktree + branch:
#   git worktree remove .worktrees/ios-per-vault-biometric-347 && \
#   git branch -D feature/ios-per-vault-biometric-enrollment-347
git worktree list && git status -s
# iOS: full acceptance is `bash ios/scripts/run-ios-tests.sh` (host tests fast; then the multi-minute
# xcframework build + simulator XCTest + app build). Xcode + simulators are available on this machine.
```

## (5) Handoff file model
`NEXT_SESSION.md` is a **relative symlink** to this file in `docs/handoffs/`. Authored once here; symlink retargeted in the same commit on the feature branch (new path → no add/add conflict; `main` updates cleanly on merge). Per [[feedback_next_session_in_pr]] / [[feedback_next_session_main_authoritative]] the baton rides inside the PR — do **not** sync to `main` during the pause window.

## Closing inventory
- **State on close:** PR opening on `feature/ios-per-vault-biometric-enrollment-347` (2 docs + 3 feat commits + this docs/handoff commit). Worktree `.worktrees/ios-per-vault-biometric-347`. Feature complete; #347 resolved.
- **Acceptance:** `run-ios-tests.sh` green (host pure tests incl. 6 new, SecretaryKit 41/41, app build); opus whole-branch review clean (0 Critical/Important; all security invariants source-verified).
- **README.md / ROADMAP.md:** updated (new iOS status row; ROADMAP `[x]` checklist item + progress-bar enumeration). **CLAUDE.md:** unchanged — the existing "iOS device unlock (B.3)" paragraph remains accurate; the per-vault keying is a composition detail (factory + storage-key namespacing), not a new grep-invisible crypto invariant.
- **NEXT_SESSION.md:** symlink → `docs/handoffs/2026-07-02-ios-per-vault-biometric-enrollment-347-shipped.md`.
