# Design — iOS biometric device-unlock → browse integration (unblocks #284)

**Issue:** [#284](https://github.com/hherb/secretary/issues/284) — seed the write-reauth gate's `initialAuthAt` from the biometric device-unlock route. The fix as written is a one-liner, but its stated precondition ("when the biometric device-unlock → browse route is connected") is **unmet on iOS**: that route does not exist in the app. This design builds the enabling integration (the iOS analog of Android's demo/local biometric-open flow) and seeds the gate as its final wire, closing #284.

**Scope:**
- `ios/SecretaryDeviceUnlock` (pure): a `DeviceSecretCredential` value type + a `releaseCredential` primitive on `DeviceUnlockCoordinator`; the existing `unlock() -> OpenedVault` refactored to compose on it.
- `ios/SecretaryVaultAccess` (pure): a `openWithDeviceSecret` arm on `VaultOpenPort`.
- `ios/SecretaryKit`: the real `openWithDeviceSecret` conformer over the existing B.2 FFI.
- `ios/SecretaryApp`: a biometric-unlock button on the Unlock screen, enrollment surfacing, a "Remember this device" enroll-at-unlock checkbox, and an extracted open helper that builds the `GraceWindowReauthGate` with `initialAuthAt` on the biometric path.

**Not in scope / unchanged:** `core`/`ffi` Rust, on-disk format, spec (`docs/`), `conformance.py`, conflict KATs, FFI surface (the B.2 `open_with_device_secret` / device-slot functions already exist and are consumed), and the cloud path. No new FFI functions.

**Reference:** mirrors the Android demo/local path — `AppRoot.kt` (biometric button on the Unlock screen, `unlockAndOpen`, `BrowseSession`), `DeviceUnlockCoordinator.kt` (returns `UnlockCredential.DeviceSecret`), `GraceWindowReauthGate` seeded at the unlock instant.

---

## 1. Problem (verified at source)

The iOS app route ([SecretaryApp.swift:25-30](../../../ios/SecretaryApp/Sources/SecretaryApp.swift)) has exactly four cases — `select`, `create`, `unlock`, `browse` — **no device-unlock route**. The production unlock flow is password/recovery only (`UnlockViewModel.Mode = { password, recovery }`). The gate is built at [SecretaryApp.swift:106-109](../../../ios/SecretaryApp/Sources/SecretaryApp.swift) with no `initialAuthAt`, which is currently *correct*: neither password nor recovery proves biometric presence, so seeding would be wrong.

`DeviceUnlockScreen.swift` / `DeviceUnlockViewModel` exist as the #202/#275 walking-skeleton (standalone enroll/unlock/disenroll diagnostic), but are referenced nowhere in the app route. `DeviceUnlockViewModel.unlock` ([DeviceUnlockViewModel.swift:39-59](../../../ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockViewModel.swift)) opens the vault and immediately `wipe()`s it — it never hands a browse-capable session anywhere.

So there is no live "first write after biometric unlock" path to seed. #284 is blocked on this route.

**Enabling fact:** the B.2 FFI `openWithDeviceSecret` returns the **same** `OpenVaultOutput` the password path wraps ([UniffiVaultDeviceSlotPort.swift:29-38](../../../ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/UniffiVaultDeviceSlotPort.swift); [UniffiVaultOpenPort.swift:10-22](../../../ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift)). Today the device path erases it to the minimal `OpenedVault` boundary ([OpenVaultOutput+OpenedVault.swift](../../../ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/OpenVaultOutput+OpenedVault.swift)). A full browse session (`UniffiVaultSession(output:)`) is one constructor away — the crypto path is proven; only the app wiring is missing.

## 2. Architecture — biometric as a button on the Unlock screen

No new route (mirrors Android). Biometric unlock is an action on the existing `.unlock` screen, shown when this device is enrolled. Password-unlock and biometric-unlock both terminate in `.browse` through **one shared open helper**, extracted out of `SecretaryApp.body` into a small host-testable file (`ios/SecretaryApp/Sources/DeviceUnlockOpen.swift`, the analog of Android's `unlockAndOpen`/`BrowseSession`). `SecretaryApp.swift`'s `.unlock` closure is already dense; keeping the new logic in a focused file preserves the <500-line discipline and makes the branch logic unit-testable.

## 3. The layering bridge

The pure `SecretaryDeviceUnlock` package has **zero dependencies** ([Package.swift](../../../ios/SecretaryDeviceUnlock/Package.swift)) and must not name `VaultSession`. Following Android, the coordinator yields a **credential**; a shared open pipeline builds the session.

### 3.1 `SecretaryDeviceUnlock` (pure)

New value type (own file, `DeviceSecretCredential.swift`):

```swift
/// The biometric-released device secret + the slot it opens, plus the vault the
/// enrollment is bound to. `secret` is a `var` so the consumer can zeroize its
/// canonical copy after opening. Not `Sendable`-derived automatically — it carries
/// raw secret bytes; it is created and consumed on the same actor within a single
/// open, never stored.
public struct DeviceSecretCredential {
    public let deviceUuid: [UInt8]
    public var secret: [UInt8]
    public let enrolledVaultId: String   // metadata's vaultId, for a post-open match check
}
```

New coordinator primitive:

```swift
/// Biometric-release the device secret for the enrolled vault. Metadata guard runs
/// BEFORE the enclave prompt (no prompt when not enrolled). Does NOT open the vault
/// — returns the credential for a session-producing open port to consume.
public func releaseCredential(reason: String) async throws -> DeviceSecretCredential {
    guard let enrollment = try metadata.load() else { throw DeviceUnlockError.notEnrolled }
    var secret = try await enclave.release(reason: reason)     // throws DeviceUnlockError
    // caller zeroizes credential.secret after the open; do not zeroize `secret` here.
    return DeviceSecretCredential(deviceUuid: enrollment.deviceUuid,
                                  secret: secret,
                                  enrolledVaultId: enrollment.vaultId)
}
```

The existing `unlock(vaultPath:vaultId:reason:) -> OpenedVault` is refactored to compose on `releaseCredential` + `slotPort.openWithDeviceSecret`, preserving its current behavior and its tests, so there is a **single** biometric-release primitive (the `vaultId == enrollment.vaultId` guard stays in `unlock`). The walking-skeleton VM is unchanged.

### 3.2 `SecretaryVaultAccess` (pure)

Add a device-secret arm to `VaultOpenPort` ([VaultOpenPort.swift](../../../ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultOpenPort.swift)):

```swift
func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                          deviceSecret: [UInt8]) async throws -> VaultSession
```

`async` for parity with the password/recovery arms (device open is not itself Argon2id-heavy, but the port contract is uniform and the conformer offloads for consistency). Throws `VaultAccessError`.

### 3.3 `SecretaryKit` (real conformer)

Implement the new arm in `UniffiVaultOpenPort` over the existing FFI:

```swift
public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                                 deviceSecret: [UInt8]) async throws -> VaultSession {
    try await runOffMainActor {
        do {
            let out = try SecretaryKit.openWithDeviceSecret(
                folderPath: vaultPath, deviceUuid: Data(deviceUuid), deviceSecret: Data(deviceSecret))
            return UniffiVaultSession(output: out)   // same session type as the password path
        } catch let e as VaultError { throw mapVaultAccessError(e) }
    }
}
```

This is the ONLY new use of the B.2 open FFI that keeps the `OpenVaultOutput` alive as a full session (the existing `UniffiVaultDeviceSlotPort.openWithDeviceSecret -> OpenedVault` is left intact for the walking-skeleton). Both call the identical FFI; they differ only in which boundary type they project.

### 3.4 App composition (`DeviceUnlockOpen.swift`)

```
releaseCredential(reason)                       // biometric prompt
  → openWithDeviceSecret(path, uuid, secret)    // full VaultSession
  → zeroize credential.secret
  → verify session.vaultUuidHex == credential.enrolledVaultId
        else { session.wipe(); throw wrongVault }   // "picked folder B, enrolled for A"
  → build GraceWindowReauthGate(authorizer, clock, initialAuthAt: unlockInstant)   // #284
  → route = .browse(VaultBrowseViewModel(session:gate:), sync, monitor, scoped)
```

The post-open UUID check is why the coordinator need not know the vault UUID before opening (iOS can't cheaply learn it pre-open from a folder path); it is defense-in-depth on top of the crypto (a wrong device secret would already fail the open with `wrongDeviceSecretOrCorrupt`).

## 4. #284 — gate seeding (the closing wire)

The gate authorizer stays the existing `EnclaveBiometricAuthorizer` ([SecretaryApp.swift:107-108](../../../ios/SecretaryApp/Sources/SecretaryApp.swift)) — no Android-style `CoordinatorBiometricAuthorizer` is needed on iOS. The only change at the gate-construction site:

- **Biometric device-unlock path:** `GraceWindowReauthGate(authorizer:…, clock: MonotonicInstant.now, initialAuthAt: unlockInstant)` where `unlockInstant = MonotonicInstant.now()` captured at gate construction (shares the gate's monotonic base, per the type's contract). The just-proven biometric presence covers the first write inside the grace window.
- **Password / recovery path:** unchanged — `initialAuthAt` stays `nil` (no biometric presence to credit).

`GraceWindowReauthGate` already accepts `initialAuthAt` and is covered by `testInitialAuthAtSeedsGrace` ([GraceWindowReauthGateTests.swift](../../../ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/GraceWindowReauthGateTests.swift)); the pure layer needs no change.

## 5. Enrollment surfacing + "Remember this device"

- **Surfacing:** on entering `.unlock`, a prompt-free `coordinator.isEnrolled` read drives whether the **"Unlock with Face ID"** button shows. Single-slot enrollment (one `DeviceEnrollment` in the Keychain metadata store); the vault match is verified post-open (§3.4), so surfacing needs no pre-open UUID.
- **Enroll-at-unlock:** a "Remember this device" checkbox in Password mode, shown when `!isEnrolled`. After a successful **password** open, if checked, `coordinator.enroll(vaultPath:, vaultId: session.vaultUuidHex, password:)` runs (password bytes are available in the unlock closure). Enroll failure is **non-fatal** — the password open already succeeded; log + surface a non-blocking message, still route to `.browse`. Mirrors Android `unlockAndOpen`'s enroll-after-open.
- **#342 avoided proactively:** the checkbox resets on `.unlock` route entry, so it never carries a prior vault's choice (the bug open against Android).

## 6. Error handling (folds in the iOS analog of #341)

- Biometric **cancel** (`LAError.userCancel`, incl. the non-match/cancel funnel documented in CLAUDE.md) → silent return to Unlock; no error surfaced.
- **Non-cancel** `DeviceUnlockError` (enclave error, `wrappedSecretCorrupt`) → surface a **typed** message (never a silent return). This is the iOS analog of Android #341, handled correctly from the start.
- Post-open **UUID mismatch** → `session.wipe()` + typed "wrong vault" error.
- **Enroll** failure → non-fatal, logged + non-blocking surface.

## 7. Testing (TDD)

- **Pure (`SecretaryDeviceUnlock` host tests):** `releaseCredential` — not-enrolled guard throws before any release; happy path returns `{deviceUuid, secret, enrolledVaultId}` from the fakes. The refactored `unlock` still passes its existing tests (behavior-preserving).
- **`openWithDeviceSecret`:** a `FakeVaultOpenPort` unit test for the new arm, plus a real round-trip integration test (BlockCrud-style, alongside `BlockCrudRoundTripIntegrationTests`) proving a device-secret open yields a working, **writable** session.
- **Gate seeding (#284):** a decision/composition unit test asserting the biometric path builds the gate **with** `initialAuthAt` and the password path **without**; the existing `testInitialAuthAtSeedsGrace` covers the pure grace behavior.
- **Open-helper branch logic:** unit tests over `DeviceUnlockOpen` — cancel → no error / stay on Unlock; non-cancel `DeviceUnlockError` → typed error; post-open UUID mismatch → wipe + typed error.
- **Manual on-device proof** (iPhone 13 Pro Max, Face ID): enroll via the checkbox → background/foreground → "Unlock with Face ID" → browse → first write is free within the grace window → a write after the window (30 s default) prompts. The Context/biometric-bound glue can't run host-side (same precedent as the walking-skeleton and Android `openCloudBrowse`), so the pure units + reading carry the automated coverage and the device walkthrough closes the loop.

## 8. Execution (subagent-driven, one branch/PR)

1. **Slice 1 — layering primitives:** `DeviceSecretCredential` + `releaseCredential` (+ `unlock` refactor) in `SecretaryDeviceUnlock`; `VaultOpenPort.openWithDeviceSecret` in `SecretaryVaultAccess`; the real conformer in `SecretaryKit`. All host-tested. No app change yet.
2. **Slice 2 — Unlock UX + open + seeded gate (#284):** biometric button + enrollment surfacing on the Unlock screen; the extracted `DeviceUnlockOpen` helper (release → open → verify → seeded gate → `.browse`); #341-style typed-error handling. #284 is closed here.
3. **Slice 3 — enroll-at-unlock:** "Remember this device" checkbox (Password mode, reset on route entry), enroll-after-password-open, non-fatal failure.

Spec + quality review per slice; whole-branch review before opening the PR. README/ROADMAP updated in a final docs slice.

## 9. Open decisions / risks

- **Coordinator has two release-adjacent methods during the refactor.** Mitigated by making `unlock` *compose* on `releaseCredential` (single primitive), not duplicate it. If the walking-skeleton is retired in a later cleanup, `unlock`/`OpenedVault` can go with it — out of scope here.
- **No host coverage of the Context/biometric-bound wiring.** Same limitation as every biometric path in this repo; covered by pure units + the on-device walkthrough.
- **Enroll-during-this-open arms on the *next* biometric unlock**, not the current session (the current session is already open via password). Consistent with Android's demo path and an explicit non-goal.
- **`async` on `openWithDeviceSecret`** is contract-uniformity, not a KDF need; the conformer offloads for consistency with the password/recovery arms.
