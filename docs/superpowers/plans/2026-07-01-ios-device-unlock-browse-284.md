# iOS biometric device-unlock → browse integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire a biometric device-unlock → browse path into the iOS app (mirroring Android's demo/local flow) and seed the write-reauth grace window from the unlock instant, closing #284.

**Architecture:** Biometric unlock is a button on the existing `.unlock` screen (no new route); password- and biometric-unlock both terminate in `.browse` through a shared open helper. The pure `SecretaryDeviceUnlock` coordinator yields a `DeviceSecretCredential`; a new `VaultOpenPort.openWithDeviceSecret` arm builds the same `UniffiVaultSession` the password path produces; the app captures `MonotonicInstant.now()` at the biometric open and passes it as `GraceWindowReauthGate.initialAuthAt`.

**Tech Stack:** Swift 6 (strict concurrency), SwiftPM packages (`SecretaryDeviceUnlock`, `SecretaryVaultAccess`, `SecretaryKit`), XcodeGen app target (`SecretaryApp`), XCTest, uniffi B.2 FFI (`openWithDeviceSecret`, `addDeviceSlot`).

## Global Constraints

- **Swift 6 language mode** — a non-`Sendable` value crossing an actor/`@MainActor` boundary is a hard compile error (#231). New value types carrying secret bytes are created + consumed on one actor within a single open and never stored/sent.
- **Pure packages have no FFI dependency.** `SecretaryDeviceUnlock` has **zero** deps and must not name `VaultSession`/FFI types. `SecretaryVaultAccess` names `VaultSession` but not FFI.
- **Anti-oracle:** never split `wrongPasswordOrCorrupt` / `wrongDeviceSecretOrCorrupt` into "wrong credential" vs "corrupt" (see [VaultAccessError.swift](../../../ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift)).
- **Zeroize discipline:** any released 32-byte device secret is zeroized after the open consumes it (`zeroize(&…)` on the canonical copy).
- **Both-halves verify / no weaker open:** the device open goes through the same B.2 `open_with_device_secret` (manifest verify-before-decrypt) as password/recovery — do not add a bypass.
- **File size:** keep new files focused and well under 500 lines; extract app orchestration out of `SecretaryApp.body`.
- **Test runner:** pure packages via `swift test` (fast, host); full acceptance via `bash ios/scripts/run-ios-tests.sh` (host packages → xcframework build → simulator XCTest → app compile). Commit messages end with the `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` trailer.
- **Anti-oracle for cancel (#341):** only `DeviceUnlockError.userCancelled` is a silent dismissal; every other case surfaces a typed message. Never silently swallow a non-cancel failure.

---

## Slice 1 — Layering primitives (pure + real conformer, host/simulator tested)

### Task 1: `DeviceSecretCredential` + `releaseCredential` primitive; refactor `unlock` to compose on it

**Files:**
- Create: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceSecretCredential.swift`
- Modify: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift` (add `releaseCredential`; rewrite `unlock` to compose on it)
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift` (add `releaseCredential` cases; existing `unlock` tests must stay green)

**Interfaces:**
- Produces: `struct DeviceSecretCredential { let deviceUuid: [UInt8]; var secret: [UInt8]; let enrolledVaultId: String }`; `func releaseCredential(reason: String) async throws -> DeviceSecretCredential` on `DeviceUnlockCoordinator`.
- Consumes: existing `metadata.load()`, `enclave.release(reason:)`, `mapSlotErrors`, `zeroize`.

- [ ] **Step 1: Write the failing tests**

Append to `DeviceUnlockCoordinatorTests.swift` (before the final `}`):

```swift
    // MARK: releaseCredential

    func testReleaseCredentialNotEnrolledWhenNoMetadata() async {
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort())
        await assertThrowsDeviceUnlock(.notEnrolled) {
            _ = try await coord.releaseCredential(reason: "x")
        }
    }

    func testReleaseCredentialHappyPathReturnsSlotAndVaultId() async throws {
        let enclave = InMemoryDeviceSecretEnclave(); try enclave.store(secret: secret)
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort(), enclave: enclave,
                                    metadata: enrolledMetadata(vaultId: "v1"))
        let cred = try await coord.releaseCredential(reason: "Unlock")
        XCTAssertEqual(cred.deviceUuid, uuid)
        XCTAssertEqual(cred.secret, secret)
        XCTAssertEqual(cred.enrolledVaultId, "v1")
    }

    func testReleaseCredentialPropagatesBiometricError() async {
        let enclave = InMemoryDeviceSecretEnclave(); try! enclave.store(secret: secret)
        enclave.releaseError = .userCancelled
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort(), enclave: enclave,
                                    metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.userCancelled) {
            _ = try await coord.releaseCredential(reason: "x")
        }
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockCoordinatorTests`
Expected: FAIL — `value of type 'DeviceUnlockCoordinator' has no member 'releaseCredential'`.

- [ ] **Step 3: Create `DeviceSecretCredential.swift`**

```swift
/// The biometric-released device secret + the slot it opens, plus the vault the
/// enrollment is bound to. Returned by `DeviceUnlockCoordinator.releaseCredential`
/// so a session-producing open port (outside this FFI-free package) can open the
/// vault — this package never names `VaultSession`.
///
/// `secret` is a `var` so the consumer can zeroize its canonical copy after the
/// open. Deliberately NOT `Sendable`: it carries raw secret bytes and is created
/// and consumed on the same actor within a single open; it is never stored or
/// sent across an actor boundary.
public struct DeviceSecretCredential {
    public let deviceUuid: [UInt8]
    public var secret: [UInt8]
    public let enrolledVaultId: String

    public init(deviceUuid: [UInt8], secret: [UInt8], enrolledVaultId: String) {
        self.deviceUuid = deviceUuid
        self.secret = secret
        self.enrolledVaultId = enrolledVaultId
    }
}
```

- [ ] **Step 4: Add `releaseCredential` and rewrite `unlock` to compose on it**

In `DeviceUnlockCoordinator.swift`, replace the existing `unlock(vaultPath:vaultId:reason:)` method with:

```swift
    /// Biometric-release the device secret for the enrolled vault WITHOUT opening
    /// the vault. Metadata guard runs BEFORE the enclave prompt (no prompt when
    /// not enrolled). The caller zeroizes `credential.secret` after the open.
    public func releaseCredential(reason: String) async throws -> DeviceSecretCredential {
        guard let enrollment = try metadata.load() else { throw DeviceUnlockError.notEnrolled }
        let secret = try await enclave.release(reason: reason) // throws DeviceUnlockError
        return DeviceSecretCredential(deviceUuid: enrollment.deviceUuid,
                                      secret: secret,
                                      enrolledVaultId: enrollment.vaultId)
    }

    /// Unlock: biometric-release the secret (via `releaseCredential`), then open
    /// the vault with it. Retains the `vaultId` guard so a stale enrollment for a
    /// different vault fails BEFORE the biometric prompt.
    public func unlock(vaultPath: Data, vaultId: String, reason: String) async throws -> OpenedVault {
        guard let enrollment = try metadata.load() else { throw DeviceUnlockError.notEnrolled }
        guard enrollment.vaultId == vaultId else { throw DeviceUnlockError.vaultSlotMismatch }

        var cred = try await releaseCredential(reason: reason)
        defer { zeroize(&cred.secret) }

        return try mapSlotErrors {
            try slotPort.openWithDeviceSecret(vaultPath: vaultPath,
                                              deviceUuid: cred.deviceUuid,
                                              deviceSecret: cred.secret)
        }
    }
```

- [ ] **Step 5: Run tests to verify all pass (new + existing `unlock` suite)**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockCoordinatorTests`
Expected: PASS — the three new `releaseCredential` tests plus every pre-existing `unlock`/`enroll`/`disenroll` test (behavior-preserving refactor).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceSecretCredential.swift \
        ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift \
        ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift
git commit -m "feat(ios): DeviceUnlockCoordinator.releaseCredential primitive (#284)"
```

---

### Task 2: `VaultOpenPort.openWithDeviceSecret` protocol arm + `FakeVaultOpenPort` conformance

**Files:**
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultOpenPort.swift` (add arm)
- Modify: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultOpenPort.swift` (conform + spy; defaulted init param so existing call sites compile)
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/FakeVaultOpenPortDeviceSecretTests.swift` (new)

**Interfaces:**
- Produces: `func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) async throws -> VaultSession` on `VaultOpenPort`; `FakeVaultOpenPort.lastDeviceOpen: (deviceUuid: [UInt8], secret: [UInt8])?` spy + `deviceSecretResult` init param (defaulted).
- Consumes: `VaultSession`, `VaultAccessError` (existing).

- [ ] **Step 1: Write the failing test**

Create `FakeVaultOpenPortDeviceSecretTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeVaultOpenPortDeviceSecretTests: XCTestCase {
    private final class StubSession: VaultSession, @unchecked Sendable {
        let vaultUuidHex = "abc123"
        func blockSummaries() -> [BlockSummary] { [] }
        func readBlock(blockUuid: [UInt8], includeDeleted: Bool) throws -> [RecordView] { [] }
        func appendRecord(blockUuid: [UInt8], content: RecordContentInput) throws -> [UInt8] { [] }
        func editRecord(blockUuid: [UInt8], recordUuid: [UInt8], content: RecordContentInput) throws {}
        func tombstoneRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {}
        func resurrectRecord(blockUuid: [UInt8], recordUuid: [UInt8]) throws {}
        func createBlock(blockName: String) throws -> [UInt8] { [] }
        func renameBlock(blockUuid: [UInt8], newName: String) throws {}
        func moveRecord(sourceBlockUuid: [UInt8], targetBlockUuid: [UInt8],
                        sourceRecordUuid: [UInt8]) throws -> [UInt8] { [] }
        func wipe() {}
    }

    func testDeviceSecretArmForwardsBytesAndReturnsSession() async throws {
        let session = StubSession()
        let port = FakeVaultOpenPort(
            passwordResult: .failure(.other("n/a")),
            recoveryResult: .failure(.other("n/a")),
            deviceSecretResult: .success(session))
        let uuid = [UInt8](repeating: 0x01, count: 16)
        let secret = [UInt8](repeating: 0x02, count: 32)

        let out = try await port.openWithDeviceSecret(
            vaultPath: Data("/tmp/v".utf8), deviceUuid: uuid, deviceSecret: secret)

        XCTAssertTrue(out === session)
        XCTAssertEqual(port.lastDeviceOpen?.deviceUuid, uuid)
        XCTAssertEqual(port.lastDeviceOpen?.secret, secret)
    }

    func testDeviceSecretArmPropagatesError() async {
        let port = FakeVaultOpenPort(
            passwordResult: .failure(.other("n/a")),
            recoveryResult: .failure(.other("n/a")),
            deviceSecretResult: .failure(.wrongDeviceSecretOrCorrupt))
        do {
            _ = try await port.openWithDeviceSecret(
                vaultPath: Data(), deviceUuid: [], deviceSecret: [])
            XCTFail("expected throw")
        } catch let e as VaultAccessError {
            XCTAssertEqual(e, .wrongDeviceSecretOrCorrupt)
        } catch { XCTFail("wrong error \(error)") }
    }
}
```

Note: this test references `VaultAccessError.wrongDeviceSecretOrCorrupt` — add that case in Step 3 (it does not exist yet).

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter FakeVaultOpenPortDeviceSecretTests`
Expected: FAIL — `VaultOpenPort` has no `openWithDeviceSecret`; `FakeVaultOpenPort` has no `deviceSecretResult`; `VaultAccessError` has no `wrongDeviceSecretOrCorrupt`.

- [ ] **Step 3: Add the protocol arm + the error case**

In `VaultOpenPort.swift`, add to the protocol:

```swift
    /// Open a vault with a biometric-released device secret (B.2 device slot),
    /// producing the SAME `VaultSession` type as the password/recovery arms.
    /// `async` for contract uniformity; conformers offload for consistency.
    func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                              deviceSecret: [UInt8]) async throws -> VaultSession
```

In `VaultAccessError.swift`, add (mirrors the anti-oracle "…OrCorrupt" folding):

```swift
    /// Device-secret open failed: wrong device secret OR vault corruption
    /// (indistinguishable), OR the slot/uuid is inconsistent. Folded like the
    /// password/recovery "…OrCorrupt" cases — do NOT split.
    case wrongDeviceSecretOrCorrupt
```

- [ ] **Step 4: Conform `FakeVaultOpenPort`**

In `FakeVaultOpenPort.swift`, add the stored result + spy and the method, and extend `init` with a defaulted param:

```swift
    private let deviceSecretResult: Result<VaultSession, VaultAccessError>
    public private(set) var lastDeviceOpen: (deviceUuid: [UInt8], secret: [UInt8])?
```

Change the initializer signature to (keep the existing body, add the new assignment):

```swift
    public init(passwordResult: Result<VaultSession, VaultAccessError>,
                recoveryResult: Result<VaultSession, VaultAccessError>,
                deviceSecretResult: Result<VaultSession, VaultAccessError> = .failure(.other("device-secret open not stubbed"))) {
        self.passwordResult = passwordResult
        self.recoveryResult = recoveryResult
        self.deviceSecretResult = deviceSecretResult
    }
```

Add the method:

```swift
    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                                     deviceSecret: [UInt8]) async throws -> VaultSession {
        lastDeviceOpen = (deviceUuid, deviceSecret)
        await gate?.enterAndWait()
        return try deviceSecretResult.get()
    }
```

- [ ] **Step 5: Run tests to verify pass (and the existing vault-access suite still compiles)**

Run: `cd ios/SecretaryVaultAccess && swift test`
Expected: PASS — the two new tests plus the full existing suite (the defaulted `deviceSecretResult` keeps every `FakeVaultOpenPort(...)` call site compiling).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultOpenPort.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccess/VaultAccessError.swift \
        ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessTesting/FakeVaultOpenPort.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/FakeVaultOpenPortDeviceSecretTests.swift
git commit -m "feat(ios): VaultOpenPort.openWithDeviceSecret arm + fake (#284)"
```

---

### Task 3: `UniffiVaultOpenPort.openWithDeviceSecret` real conformer + real-FFI round-trip

**Files:**
- Modify: `ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift` (implement arm)
- Test: `ios/SecretaryKit/Tests/SecretaryKitTests/DeviceSecretOpenRoundTripTests.swift` (new; real FFI, simulator)

**Interfaces:**
- Consumes: `SecretaryKit.openWithDeviceSecret(folderPath: Data, deviceUuid: Data, deviceSecret: Data) throws -> OpenVaultOutput`, `SecretaryKit.addDeviceSlot(folderPath:password:) -> DeviceSecretOutput`, `UniffiVaultSession(output:)`, `mapVaultAccessError`.
- Produces: real `VaultSession` from a device-secret open.

- [ ] **Step 1: Write the failing test** (real FFI: enroll a slot on a temp golden vault, then open with the released secret and write through the session)

Create `DeviceSecretOpenRoundTripTests.swift`:

```swift
import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryDeviceUnlockTesting

/// Real-FFI: mint a device slot on a TEMP COPY of golden_vault_001, then open
/// the vault with `UniffiVaultOpenPort.openWithDeviceSecret` and confirm the
/// resulting session is browse-capable (lists blocks) — proving the device open
/// yields the SAME session shape as the password path.
final class DeviceSecretOpenRoundTripTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-devopen-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy {
            try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent())
        }
    }

    private var path: Data { Data(vaultCopy.path.utf8) }

    func testOpenWithDeviceSecretYieldsBrowseCapableSession() async throws {
        // Mint a device slot via the real slot port (returns uuid + secret).
        let slotPort = UniffiVaultDeviceSlotPort()
        let slot = try slotPort.addDeviceSlot(vaultPath: path, password: Array(goldenPassword.utf8))

        // Open with the device secret through the port under test.
        let port = UniffiVaultOpenPort()
        let session = try await port.openWithDeviceSecret(
            vaultPath: path, deviceUuid: slot.deviceUuid, deviceSecret: slot.deviceSecret)
        defer { session.wipe() }

        // Browse-capable: it exposes the manifest's blocks (golden vault has ≥1).
        XCTAssertFalse(session.blockSummaries().isEmpty,
                       "device-secret session must list golden-vault blocks")
        XCTAssertEqual(session.vaultUuidHex.count, 32, "vault uuid hex is 16 bytes")
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `bash ios/scripts/run-ios-tests.sh` (or a scoped `xcodebuild test -scheme SecretaryKit -destination 'platform=iOS Simulator,name=iPhone 17' -only-testing:SecretaryKitTests/DeviceSecretOpenRoundTripTests`)
Expected: FAIL — `UniffiVaultOpenPort` has no `openWithDeviceSecret`.

- [ ] **Step 3: Implement the conformer arm**

In `UniffiVaultOpenPort.swift`, add:

```swift
    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8],
                                     deviceSecret: [UInt8]) async throws -> VaultSession {
        try await runOffMainActor {
            do {
                let out = try SecretaryKit.openWithDeviceSecret(
                    folderPath: vaultPath,
                    deviceUuid: Data(deviceUuid),
                    deviceSecret: Data(deviceSecret))
                return UniffiVaultSession(output: out)
            } catch let e as VaultError {
                throw mapVaultAccessError(e)
            }
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: PASS — the round-trip lists golden-vault blocks through a device-secret-opened session; all pre-existing SecretaryKit tests still pass.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/VaultAccess/UniffiVaultOpenPort.swift \
        ios/SecretaryKit/Tests/SecretaryKitTests/DeviceSecretOpenRoundTripTests.swift
git commit -m "feat(ios): UniffiVaultOpenPort.openWithDeviceSecret real conformer + round-trip (#284)"
```

---

## Slice 2 — Unlock UX + open + seeded gate (#284) + typed errors (#341)

### Task 4: Pure gate-seeding decision (`reauthInitialAuthAt`) — the #284 decision, host-tested

**Files:**
- Create: `ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/ReauthSeeding.swift`
- Test: `ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/ReauthSeedingTests.swift` (new)

**Interfaces:**
- Produces: `func reauthInitialAuthAt(biometricUnlock: Bool, now: MonotonicInstant) -> MonotonicInstant?` — returns `now` for a biometric unlock (seed the grace window with the just-proven presence), `nil` otherwise (password/recovery prove no biometric presence).

- [ ] **Step 1: Write the failing test**

Create `ReauthSeedingTests.swift`:

```swift
import XCTest
import SecretaryVaultAccess
@testable import SecretaryVaultAccessUI

final class ReauthSeedingTests: XCTestCase {
    func testBiometricUnlockSeedsWithNow() {
        let now = MonotonicInstant(nanoseconds: 42)
        XCTAssertEqual(reauthInitialAuthAt(biometricUnlock: true, now: now), now)
    }

    func testPasswordOrRecoveryDoesNotSeed() {
        let now = MonotonicInstant(nanoseconds: 42)
        XCTAssertNil(reauthInitialAuthAt(biometricUnlock: false, now: now))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ReauthSeedingTests`
Expected: FAIL — `reauthInitialAuthAt` not defined.

- [ ] **Step 3: Implement**

Create `ReauthSeeding.swift`:

```swift
import SecretaryVaultAccess

/// The `initialAuthAt` to seed `GraceWindowReauthGate` with, given how the vault
/// was just opened. A biometric device-unlock proves biometric presence at
/// `now`, so the first write within the grace window is free (#284). A password
/// or recovery open proves NO biometric presence, so the gate must NOT be
/// pre-seeded (the first write should prompt if the device is enrolled).
///
/// Pure: the caller supplies `now` from `MonotonicInstant.now()` (SecretaryKit),
/// sharing the gate's monotonic base.
public func reauthInitialAuthAt(biometricUnlock: Bool, now: MonotonicInstant) -> MonotonicInstant? {
    biometricUnlock ? now : nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryVaultAccess && swift test --filter ReauthSeedingTests`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryVaultAccess/Sources/SecretaryVaultAccessUI/ReauthSeeding.swift \
        ios/SecretaryVaultAccess/Tests/SecretaryVaultAccessUITests/ReauthSeedingTests.swift
git commit -m "feat(ios): reauthInitialAuthAt — seed grace window on biometric unlock (#284)"
```

---

### Task 5: Pure biometric-failure classifier (`deviceUnlockFailureDisplay`) — #341, host-tested

**Files:**
- Create: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockFailureDisplay.swift`
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockFailureDisplayTests.swift` (new)

**Interfaces:**
- Produces: `enum DeviceUnlockFailureDisplay: Equatable { case silent; case message(String) }`; `func deviceUnlockFailureDisplay(_ error: DeviceUnlockError) -> DeviceUnlockFailureDisplay` — `.userCancelled` → `.silent`; every other case → `.message(<short label>)`.

- [ ] **Step 1: Write the failing test**

Create `DeviceUnlockFailureDisplayTests.swift`:

```swift
import XCTest
import SecretaryDeviceUnlock
@testable import SecretaryDeviceUnlockUI

final class DeviceUnlockFailureDisplayTests: XCTestCase {
    func testUserCancelledIsSilent() {
        XCTAssertEqual(deviceUnlockFailureDisplay(.userCancelled), .silent)
    }

    func testNonCancelFailuresSurfaceAMessage() {
        // Every non-cancel case must produce a non-empty message — never silent.
        let nonCancel: [DeviceUnlockError] = [
            .biometryUnavailable, .biometryNotEnrolled, .biometryLockout,
            .authenticationFailed, .notEnrolled, .vaultSlotMismatch,
            .wrappedSecretCorrupt, .wrongDeviceSecretOrCorrupt,
            .vault(.other("x")), .enclave("domain=… code=…"),
        ]
        for err in nonCancel {
            guard case let .message(text) = deviceUnlockFailureDisplay(err) else {
                return XCTFail("\(err) must surface a message, not be silent")
            }
            XCTAssertFalse(text.isEmpty, "\(err) produced an empty message")
        }
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockFailureDisplayTests`
Expected: FAIL — `deviceUnlockFailureDisplay` not defined.

- [ ] **Step 3: Implement**

Create `DeviceUnlockFailureDisplay.swift`:

```swift
import SecretaryDeviceUnlock

/// How a failed biometric unlock should be presented on the Unlock screen.
public enum DeviceUnlockFailureDisplay: Equatable {
    /// User cancelled / dismissed the biometric prompt — return to Unlock quietly.
    case silent
    /// A real failure — surface this short, user-facing message (#341: a
    /// non-cancel failure must never silently return to Unlock).
    case message(String)
}

/// Classify a `DeviceUnlockError` for the Unlock screen. ONLY `.userCancelled`
/// is silent; every other case surfaces a typed message. (#341)
public func deviceUnlockFailureDisplay(_ error: DeviceUnlockError) -> DeviceUnlockFailureDisplay {
    switch error {
    case .userCancelled:
        return .silent
    case .biometryUnavailable:
        return .message("Biometric unlock is unavailable on this device.")
    case .biometryNotEnrolled:
        return .message("No biometrics are enrolled on this device.")
    case .biometryLockout:
        return .message("Biometrics are locked out. Use your passcode, then try again.")
    case .authenticationFailed:
        return .message("Biometric authentication failed. Try again or use your password.")
    case .notEnrolled:
        return .message("This device isn’t set up for biometric unlock of this vault.")
    case .vaultSlotMismatch:
        return .message("This device’s biometric enrollment is for a different vault.")
    case .wrappedSecretCorrupt, .wrongDeviceSecretOrCorrupt:
        return .message("The device key couldn’t be used. Unlock with your password.")
    case .vault(let e):
        return .message("Couldn’t open the vault (\(e)). Unlock with your password.")
    case .enclave(let detail):
        return .message("Secure Enclave error. Unlock with your password. (\(detail))")
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockFailureDisplayTests`
Expected: PASS. (The `switch` is exhaustive, so a future new `DeviceUnlockError` case forces a decision here — no silent default.)

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlockUI/DeviceUnlockFailureDisplay.swift \
        ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockUITests/DeviceUnlockFailureDisplayTests.swift
git commit -m "feat(ios): typed biometric-failure display classifier (#341)"
```

---

### Task 6: App wiring — biometric button on UnlockScreen + release→open→verify→seeded gate→browse

**Files:**
- Create: `ios/SecretaryApp/Sources/DeviceUnlockOpen.swift` (orchestration extracted out of `SecretaryApp.body`)
- Modify: `ios/SecretaryApp/Sources/UnlockScreen.swift` (biometric button, shown when enrolled; `onBiometricUnlock` callback; surface a typed failure message)
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift` (build the demo/local `DeviceUnlockCoordinator`; prompt-free `isEnrolled` on `.unlock` entry; pass `onBiometricUnlock`; on success route to `.browse` with a gate seeded via `reauthInitialAuthAt`)

**Interfaces:**
- Consumes: `DeviceUnlockCoordinator(slotPort:enclave:metadata:)` with real adapters `UniffiVaultDeviceSlotPort()`, `SecureEnclaveDeviceSecretStore()`, `KeychainEnrollmentMetadataStore()`; `coordinator.releaseCredential` (Task 1); `UniffiVaultOpenPort().openWithDeviceSecret` (Task 3); `reauthInitialAuthAt` (Task 4); `deviceUnlockFailureDisplay` (Task 5); `GraceWindowReauthGate(authorizer:clock:initialAuthAt:)`; `EnclaveBiometricAuthorizer`; `MonotonicInstant.now()`.
- Produces: `DeviceUnlockOpen.open(...)` async orchestration returning a typed outcome the app maps to `.browse` or an Unlock-screen message.

**Note on testing:** this task is app-target code (Context/biometric-bound), compile-verified via `build-app.sh` and exercised by the on-device walkthrough — the decidable logic it depends on (#284 seeding, #341 classification) is already host-tested in Tasks 4–5, and `DeviceUnlockOpen` is a thin translation over them (per the design's accepted "no host coverage of Context-bound wiring" risk).

- [ ] **Step 1: Create `DeviceUnlockOpen.swift` (the orchestration)**

```swift
import Foundation
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

/// Outcome of a biometric device-unlock open attempt.
enum DeviceUnlockOpenResult {
    /// Opened successfully; `gate` is already seeded with the unlock instant (#284).
    case opened(VaultSession, gate: GraceWindowReauthGate)
    /// User cancelled the biometric prompt — return to Unlock quietly (#341).
    case cancelled
    /// A real failure — surface this typed message on the Unlock screen (#341).
    case failed(String)
}

/// Release the device secret behind a biometric prompt, open the vault with it,
/// verify the opened vault matches the enrollment, and build a grace-window gate
/// seeded at the unlock instant. Extracted out of `SecretaryApp.body` to keep
/// that view small and this flow readable.
enum DeviceUnlockOpen {
    static func open(
        coordinator: DeviceUnlockCoordinator,
        openPort: VaultOpenPort,
        vaultPath: Data,
        reason: String
    ) async -> DeviceUnlockOpenResult {
        do {
            var cred = try await coordinator.releaseCredential(reason: reason)
            let session: VaultSession
            do {
                session = try await openPort.openWithDeviceSecret(
                    vaultPath: vaultPath, deviceUuid: cred.deviceUuid, deviceSecret: cred.secret)
            } catch {
                cred.secret.resetBytes(in: 0..<cred.secret.count)
                // A device-secret open failure is not a biometric cancel; surface it.
                let display = (error as? VaultAccessError).map(vaultAccessFailureMessage)
                    ?? "Couldn’t open the vault. Unlock with your password."
                return .failed(display)
            }
            cred.secret.resetBytes(in: 0..<cred.secret.count)

            // Defense-in-depth: the opened vault must be the enrolled one.
            guard session.vaultUuidHex == cred.enrolledVaultId else {
                session.wipe()
                return .failed("This device’s biometric enrollment is for a different vault.")
            }

            let gate = GraceWindowReauthGate(
                authorizer: EnclaveBiometricAuthorizer(enclave: SecureEnclaveDeviceSecretStore()),
                clock: MonotonicInstant.now,
                initialAuthAt: reauthInitialAuthAt(biometricUnlock: true, now: MonotonicInstant.now()))
            return .opened(session, gate: gate)
        } catch let e as DeviceUnlockError {
            switch deviceUnlockFailureDisplay(e) {
            case .silent:            return .cancelled
            case .message(let text): return .failed(text)
            }
        } catch {
            return .failed("Biometric unlock failed. Unlock with your password.")
        }
    }
}

/// A short user-facing message for a device-secret open failure (anti-oracle:
/// wrong-secret and corruption are folded — do not distinguish).
private func vaultAccessFailureMessage(_ e: VaultAccessError) -> String {
    switch e {
    case .wrongDeviceSecretOrCorrupt:
        return "The device key couldn’t open this vault. Unlock with your password."
    case .folderInvalid:
        return "The vault folder is missing or unreadable."
    default:
        return "Couldn’t open the vault. Unlock with your password."
    }
}
```

- [ ] **Step 2: Add the biometric button + failure surface to `UnlockScreen.swift`**

Add stored properties near the existing `onUnlocked` (respect the file's current init pattern):

```swift
    /// Shown only when this device is enrolled for biometric unlock of a vault.
    let biometricEnrolled: Bool
    /// Invoked when the user taps "Unlock with Face ID".
    let onBiometricUnlock: () -> Void
```

Thread both through `init` (add parameters with the others). In the form body, above the password `Section`, add:

```swift
                if biometricEnrolled {
                    Section {
                        Button("Unlock with Face ID") { onBiometricUnlock() }
                    }
                }
```

Add a parent-owned error binding and an error section (surface the typed message from `DeviceUnlockOpen`). The parent (`SecretaryApp`) owns the state so it resets cleanly on route entry (avoids the Android #342 carry-over shape for the error too):

```swift
    @Binding var biometricError: String?
```

```swift
                if let biometricError {
                    Section("Couldn’t unlock") {
                        Text(biometricError).foregroundStyle(.red)
                    }
                }
```

Reset `biometricError = nil` inside `onBiometricUnlock` before the attempt (wired from the parent in Step 3).

- [ ] **Step 3: Wire `SecretaryApp.swift` — coordinator, enrollment surfacing, biometric route to `.browse`**

In the `SecretaryApp` view, add a demo/local coordinator factory and enrollment state:

```swift
    private func localCoordinator() -> DeviceUnlockCoordinator {
        DeviceUnlockCoordinator(
            slotPort: UniffiVaultDeviceSlotPort(),
            enclave: SecureEnclaveDeviceSecretStore(),
            metadata: KeychainEnrollmentMetadataStore())
    }
```

In the `.unlock(let scoped)` case, compute `biometricEnrolled` prompt-free and pass the new params to `UnlockScreen`:

```swift
                case .unlock(let scoped):
                    let coordinator = localCoordinator()
                    UnlockScreen(
                        viewModel: UnlockViewModel(port: UniffiVaultOpenPort(),
                                                   vaultPath: scoped.pathData),
                        biometricEnrolled: coordinator.isEnrolled,
                        biometricError: $biometricUnlockError,
                        onBiometricUnlock: {
                            biometricUnlockError = nil
                            Task {
                                let result = await DeviceUnlockOpen.open(
                                    coordinator: coordinator,
                                    openPort: UniffiVaultOpenPort(),
                                    vaultPath: scoped.pathData,
                                    reason: "Unlock your Secretary vault")
                                await handleBiometricResult(result, scoped: scoped)
                            }
                        },
                        onUnlocked: { session, password in
                            // …existing password/recovery path unchanged…
                            let gate = GraceWindowReauthGate(
                                authorizer: EnclaveBiometricAuthorizer(
                                    enclave: SecureEnclaveDeviceSecretStore()),
                                clock: MonotonicInstant.now)   // initialAuthAt stays nil (#284)
                            route = .browse(VaultBrowseViewModel(session: session, gate: gate),
                                            syncVM, monitor, scoped)
                        })
```

Add the biometric-result handler (builds sync + monitor exactly like the password path, then routes with the pre-seeded gate):

```swift
    @MainActor
    private func handleBiometricResult(_ result: DeviceUnlockOpenResult,
                                       scoped: ScopedVaultPath) async {
        switch result {
        case .cancelled:
            return                                   // stay on Unlock, quietly (#341)
        case .failed(let message):
            biometricUnlockError = message           // surface typed message (#341)
        case .opened(let session, let gate):
            let folder = URL(fileURLWithPath:
                String(decoding: scoped.pathData, as: UTF8.self))
            let stateDir = (try? defaultSyncStateDir()) ?? FileManager.default.temporaryDirectory
            let (syncVM, monitor) = makeVaultSync(session: session, folder: folder, stateDir: stateDir)
            try? monitor.start()
            Task { await syncVM.refreshStatus() }    // no sync password on the device path
            route = .browse(VaultBrowseViewModel(session: session, gate: gate),
                            syncVM, monitor, scoped)
        }
    }
```

Add the `@State private var biometricUnlockError: String?` on the app view and pass it into `UnlockScreen` (binding) so the message renders; reset it to `nil` on `.unlock` route entry.

- [ ] **Step 4: Build the app (compile proof) + run the full host/simulator gate**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: PASS — pure packages (Tasks 1,2,4,5) green, SecretaryKit simulator tests (Task 3) green, and `build-app.sh` compiles the app with the new UnlockScreen + `DeviceUnlockOpen` + `SecretaryApp` wiring (no route added; button on Unlock).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryApp/Sources/DeviceUnlockOpen.swift \
        ios/SecretaryApp/Sources/UnlockScreen.swift \
        ios/SecretaryApp/Sources/SecretaryApp.swift
git commit -m "feat(ios): biometric device-unlock → browse; seed grace window at unlock (#284, #341)"
```

---

## Slice 3 — Enroll-at-unlock ("Remember this device"), #342-safe

### Task 7: "Remember this device" checkbox + enroll-after-password-open (non-fatal), reset on route entry

**Files:**
- Modify: `ios/SecretaryApp/Sources/UnlockScreen.swift` (checkbox in Password mode when `!biometricEnrolled`; controlled by parent; reset on appear)
- Modify: `ios/SecretaryApp/Sources/SecretaryApp.swift` (own `rememberDevice` state, reset on `.unlock` entry; after a successful password open, if checked, `coordinator.enroll(...)`; non-fatal on failure)

**Interfaces:**
- Consumes: `coordinator.enroll(vaultPath:vaultId:password:)`; `session.vaultUuidHex` (the `vaultId`); `rememberDevice` bool state.

**Note on testing:** app-target UI + Context-bound enroll — compile-verified via `build-app.sh` + on-device walkthrough. The enroll transaction + rollback are already host-tested in `DeviceUnlockCoordinatorTests` (Task 1's file); no new pure logic is introduced here.

- [ ] **Step 1: Add the checkbox to `UnlockScreen.swift`**

Add stored props (controlled by the parent, so state resets cleanly on route entry — avoids the Android #342 carry-over):

```swift
    @Binding var rememberDevice: Bool
```

In the body, inside the Password-mode section (shown only when not already enrolled):

```swift
                if !biometricEnrolled && mode == .password {
                    Toggle("Remember this device with Face ID", isOn: $rememberDevice)
                }
```

- [ ] **Step 2: Wire enroll-after-open in `SecretaryApp.swift`**

Add `@State private var rememberDevice = false`. Reset it on entering `.unlock` (alongside the biometric-error reset from Task 6). Pass `rememberDevice: $rememberDevice` to `UnlockScreen`.

In the existing password `onUnlocked` closure, AFTER building the session but BEFORE routing to `.browse`, add (password is still live here):

```swift
                            if rememberDevice, let password {
                                do {
                                    try localCoordinator().enroll(
                                        vaultPath: scoped.pathData,
                                        vaultId: session.vaultUuidHex,
                                        password: password)
                                } catch {
                                    // Non-fatal: the password open already succeeded.
                                    appLog.error("device enroll failed: \(error.localizedDescription, privacy: .public)")
                                    biometricUnlockError = "Couldn’t enable biometric unlock. You can try again later."
                                }
                            }
```

- [ ] **Step 3: Build the app (compile proof) + full gate**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: PASS — app compiles with the checkbox + enroll wiring; all pure + simulator tests still green.

- [ ] **Step 4: Commit**

```bash
git add ios/SecretaryApp/Sources/UnlockScreen.swift ios/SecretaryApp/Sources/SecretaryApp.swift
git commit -m "feat(ios): 'Remember this device' enroll-at-unlock, reset on route entry (#342-safe)"
```

---

## Slice 4 — Docs

### Task 8: README + ROADMAP

**Files:**
- Modify: `README.md` (iOS status: biometric device-unlock → browse now wired; #284 closed)
- Modify: `ROADMAP.md` (mark the iOS device-unlock integration / #284 done)

- [ ] **Step 1: Update README iOS status**

Add a concise bullet under the iOS section noting biometric device-unlock → browse is wired (enroll-at-unlock + biometric open + write-reauth grace seeded at the unlock instant), keeping the house dot-point style (no test-count walls).

- [ ] **Step 2: Update ROADMAP**

Mark the iOS biometric device-unlock browse integration (and #284) complete in the relevant D.x / iOS device-unlock line.

- [ ] **Step 3: Commit**

```bash
git add README.md ROADMAP.md
git commit -m "docs: iOS biometric device-unlock → browse shipped (#284)"
```

---

## Post-merge manual acceptance (not a code task)

On the iPhone 13 Pro Max (Face ID), per the design §7:
1. Open the demo vault by password with "Remember this device" checked → enroll succeeds.
2. Background → foreground the app → return to Unlock.
3. Tap "Unlock with Face ID" → Face ID → lands in browse.
4. First write within the grace window (30 s default) does NOT re-prompt (#284 seeding).
5. A write after the window re-prompts for Face ID.
6. Cancel the Face ID prompt → returns to Unlock with no error (#341 silent cancel).

---

## Self-Review

**1. Spec coverage:**
- Design §2 (button on Unlock, no new route) → Task 6. ✓
- §3.1 credential + `releaseCredential` + `unlock` refactor → Task 1. ✓
- §3.2 `VaultOpenPort` arm → Task 2. ✓
- §3.3 real conformer → Task 3. ✓
- §3.4 app composition (release→open→verify→gate→browse) → Task 6. ✓
- §4 gate seeding (#284) → Task 4 (decision) + Task 6 (wiring). ✓
- §5 enrollment surfacing + "Remember this device" (#342-safe) → Task 6 (surfacing) + Task 7 (checkbox/enroll). ✓
- §6 error handling (#341 cancel-vs-typed; UUID mismatch wipe) → Task 5 (classifier) + Task 6 (wiring/UUID guard). ✓
- §7 testing → Tasks 1–5 host tests + Task 3 simulator round-trip + manual acceptance. ✓

**2. Placeholder scan:** No TBD/TODO; every code step shows full code. ✓

**3. Type consistency:** `DeviceSecretCredential {deviceUuid, secret, enrolledVaultId}` produced in Task 1, consumed in Task 6. `reauthInitialAuthAt(biometricUnlock:now:)` (Task 4) called in Task 6. `deviceUnlockFailureDisplay` → `DeviceUnlockFailureDisplay {silent, message}` (Task 5) consumed in Task 6. `VaultAccessError.wrongDeviceSecretOrCorrupt` added in Task 2, used in Tasks 3/5/6. `FakeVaultOpenPort` gains `deviceSecretResult` (defaulted) + `lastDeviceOpen` in Task 2. `openWithDeviceSecret(vaultPath:deviceUuid:deviceSecret:)` signature identical across protocol (Task 2), fake (Task 2), and real conformer (Task 3). ✓

**Risk noted:** the `SecretaryDeviceUnlockUITests` test target must exist for Task 5; if the package has no `SecretaryDeviceUnlockUITests` target yet, add it to `Package.swift` (it already declares `SecretaryDeviceUnlockUI` + a `SecretaryDeviceUnlockUITests` test target per the package manifest) — the executing agent verifies before Step 1.
