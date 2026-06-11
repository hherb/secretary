# B.3 — iOS Secure Enclave / biometric release of the device secret — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Protect the per-device `device_secret` with the iOS Secure Enclave behind a biometric gate and drive vault unlock through it, as a protocol-boundary slice with a real-but-device-deferred SE conformer.

**Architecture:** A new FFI-free Swift package `ios/SecretaryDeviceUnlock` holds the pure orchestration (`DeviceUnlockCoordinator` over three injected ports + a typed error), exercised entirely by host `swift test`. The iOS-bound adapters (real uniffi port, the Secure Enclave conformer, a Keychain metadata store) live in the existing `SecretaryKit` package, with one simulator integration test driving the real B.2 FFI against a staged `golden_vault_001` copy using a fake enclave.

**Tech Stack:** Swift 5.9, SwiftPM, XCTest, Foundation; `Security`/`LocalAuthentication` (iOS) for the SE conformer; the B.2 uniffi bindings (`addDeviceSlot`/`openWithDeviceSecret`/`removeDeviceSlot`).

**Spec:** [docs/superpowers/specs/2026-06-11-b3-ios-secure-enclave-design.md](../specs/2026-06-11-b3-ios-secure-enclave-design.md)

### Planning refinements over the spec (intentional, noted for honesty)

1. **`VaultSlotError` (pure mirror).** The spec's `DeviceUnlockError.vault(VaultError)` can't hold the uniffi `VaultError` — that type lives in the `SecretaryKit` module, invisible to the FFI-free package. The `VaultDeviceSlotPort` therefore throws a pure `VaultSlotError` mirror; the real adapter maps `VaultError → VaultSlotError`; the coordinator maps `VaultSlotError → DeviceUnlockError`. So `DeviceUnlockError.vault` carries `VaultSlotError`, not `VaultError`.
2. **`DeviceSecretEnclave` throws `DeviceUnlockError` directly.** The enclave conformer owns the `LAError`/`OSStatus` → `DeviceUnlockError` mapping; the coordinator propagates those unchanged. Fakes throw injected `DeviceUnlockError`.
3. **`zeroize(_ bytes: inout [UInt8])`** is the implementable form of the spec's `withZeroizing` (an `inout` overwrite is the only form Swift can honor against COW). `EnrolledSlot.deviceSecret` is a `var` so the coordinator can zeroize its canonical copy.
4. **`OpenedVault` gains `wipe()`** alongside `vaultUuid` so callers release the manifest/identity through the protocol.
5. Metadata-store I/O errors propagate as their underlying `Error` (Swift throws are untyped); the documented `DeviceUnlockError` taxonomy covers the *semantic* failure modes. Absent enrollment is `load() -> nil`, not a throw.

---

## File structure

**New pure package `ios/SecretaryDeviceUnlock/`** (zero iOS-binary deps, host `swift test`):

| File | Responsibility |
|---|---|
| `Package.swift` | 3 targets: `SecretaryDeviceUnlock` (lib), `SecretaryDeviceUnlockTesting` (fakes lib), `SecretaryDeviceUnlockTests` (host tests) |
| `Sources/SecretaryDeviceUnlock/Zeroizing.swift` | `zeroize(_:)` |
| `Sources/SecretaryDeviceUnlock/OpenedVault.swift` | `OpenedVault` protocol |
| `Sources/SecretaryDeviceUnlock/VaultSlotError.swift` | pure mirror of the device-slot FFI errors |
| `Sources/SecretaryDeviceUnlock/VaultDeviceSlotPort.swift` | `VaultDeviceSlotPort` protocol + `EnrolledSlot` |
| `Sources/SecretaryDeviceUnlock/DeviceSecretEnclave.swift` | `DeviceSecretEnclave` protocol |
| `Sources/SecretaryDeviceUnlock/DeviceEnrollment.swift` | `DeviceEnrollment` + `DeviceEnrollmentMetadataStore` protocol |
| `Sources/SecretaryDeviceUnlock/DeviceUnlockError.swift` | `DeviceUnlockError` enum |
| `Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift` | the orchestration |
| `Sources/SecretaryDeviceUnlockTesting/*.swift` | `InMemoryDeviceSecretEnclave`, `FakeVaultDeviceSlotPort`, `InMemoryEnrollmentMetadataStore`, `FakeOpenedVault` |
| `Tests/SecretaryDeviceUnlockTests/*.swift` | `ZeroizingTests`, `FakesTests`, `DeviceUnlockCoordinatorTests` |

**Existing package `ios/SecretaryKit/`** (iOS-bound adapters):

| File | Responsibility |
|---|---|
| `Package.swift` (modify) | add `.package(path: "../SecretaryDeviceUnlock")`; wire products into lib + test targets |
| `Sources/SecretaryKit/DeviceUnlock/UniffiVaultDeviceSlotPort.swift` | real port over the 3 B.2 funcs; consumes the one-shot `DeviceSecretOutput` |
| `Sources/SecretaryKit/DeviceUnlock/OpenVaultOutput+OpenedVault.swift` | `OpenVaultOutput: OpenedVault` conformance |
| `Sources/SecretaryKit/DeviceUnlock/SecureEnclaveDeviceSecretStore.swift` | real SE conformer (compiles; device-verified later) |
| `Sources/SecretaryKit/DeviceUnlock/KeychainEnrollmentMetadataStore.swift` | real Keychain metadata store |
| `Tests/SecretaryKitTests/DeviceUnlockIntegrationTests.swift` | Tier-2 simulator round-trip |

**Docs:** `ios/README.md`, root `README.md`, `ROADMAP.md`, `CLAUDE.md`.

---

## Task 1: Scaffold the pure package + `zeroize`

**Files:**
- Create: `ios/SecretaryDeviceUnlock/Package.swift`
- Create: `ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/Zeroizing.swift`
- Test: `ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/ZeroizingTests.swift`

- [ ] **Step 1: Write `Package.swift`**

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecretaryDeviceUnlock",
    platforms: [.macOS(.v13), .iOS(.v17)],
    products: [
        .library(name: "SecretaryDeviceUnlock", targets: ["SecretaryDeviceUnlock"]),
        .library(name: "SecretaryDeviceUnlockTesting", targets: ["SecretaryDeviceUnlockTesting"]),
    ],
    targets: [
        .target(name: "SecretaryDeviceUnlock"),
        .target(name: "SecretaryDeviceUnlockTesting", dependencies: ["SecretaryDeviceUnlock"]),
        .testTarget(
            name: "SecretaryDeviceUnlockTests",
            dependencies: ["SecretaryDeviceUnlock", "SecretaryDeviceUnlockTesting"]
        ),
    ]
)
```

- [ ] **Step 2: Write the failing test** `Tests/SecretaryDeviceUnlockTests/ZeroizingTests.swift`

```swift
import XCTest
@testable import SecretaryDeviceUnlock

final class ZeroizingTests: XCTestCase {
    func testZeroizeOverwritesBuffer() {
        var bytes: [UInt8] = [1, 2, 3, 4, 255]
        zeroize(&bytes)
        XCTAssertEqual(bytes, [0, 0, 0, 0, 0])
    }

    func testZeroizeEmptyBufferIsNoop() {
        var empty: [UInt8] = []
        zeroize(&empty) // must not trap on a zero-length buffer
        XCTAssertEqual(empty, [])
    }
}
```

- [ ] **Step 3: Run it to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test`
Expected: FAIL — `cannot find 'zeroize' in scope`.

- [ ] **Step 4: Write `Sources/SecretaryDeviceUnlock/Zeroizing.swift`**

```swift
import Foundation

/// Overwrite `bytes` with zeros in place. Best-effort secret hygiene: it clears
/// only this array's backing buffer, so any *other* copies a caller made (e.g.
/// passed across the FFI) are out of reach. Swift's value-copy semantics make
/// full guarantees impossible — see the spec's zeroization note.
public func zeroize(_ bytes: inout [UInt8]) {
    bytes.withUnsafeMutableBytes { raw in
        guard let base = raw.baseAddress, raw.count > 0 else { return }
        memset_s(base, raw.count, 0, raw.count)
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd ios/SecretaryDeviceUnlock && swift test`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Package.swift \
        ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/Zeroizing.swift \
        ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/ZeroizingTests.swift
git commit -m "feat(b3): scaffold pure SecretaryDeviceUnlock package + zeroize helper"
```

---

## Task 2: Ports, value types, error type, and the fakes

This task defines all the protocols/types (no behavior of their own) plus the fakes
(which DO have behavior) and tests the fakes.

**Files:**
- Create: `Sources/SecretaryDeviceUnlock/OpenedVault.swift`
- Create: `Sources/SecretaryDeviceUnlock/VaultSlotError.swift`
- Create: `Sources/SecretaryDeviceUnlock/VaultDeviceSlotPort.swift`
- Create: `Sources/SecretaryDeviceUnlock/DeviceSecretEnclave.swift`
- Create: `Sources/SecretaryDeviceUnlock/DeviceEnrollment.swift`
- Create: `Sources/SecretaryDeviceUnlock/DeviceUnlockError.swift`
- Create: `Sources/SecretaryDeviceUnlockTesting/FakeOpenedVault.swift`
- Create: `Sources/SecretaryDeviceUnlockTesting/FakeVaultDeviceSlotPort.swift`
- Create: `Sources/SecretaryDeviceUnlockTesting/InMemoryDeviceSecretEnclave.swift`
- Create: `Sources/SecretaryDeviceUnlockTesting/InMemoryEnrollmentMetadataStore.swift`
- Test: `Tests/SecretaryDeviceUnlockTests/FakesTests.swift`

- [ ] **Step 1: Write the protocol/type files**

`OpenedVault.swift`:
```swift
import Foundation

/// An opened vault, abstracted so the pure package never names the uniffi
/// `OpenVaultOutput`. The real adapter conforms `OpenVaultOutput` to this.
public protocol OpenedVault {
    var vaultUuid: [UInt8] { get }
    /// Release the manifest/identity secret material held by the opened vault.
    func wipe()
}
```

`VaultSlotError.swift`:
```swift
/// Pure mirror of the device-slot FFI error surface. The real adapter maps the
/// uniffi `VaultError` onto these so the FFI-free package can pattern-match.
public enum VaultSlotError: Error, Equatable {
    case deviceSlotNotFound
    case wrongDeviceSecretOrCorrupt
    case deviceUuidMismatch(String)
    case invalidArgument(String)
    /// Any other `VaultError`, carried as its display string.
    case other(String)
}
```

`VaultDeviceSlotPort.swift`:
```swift
import Foundation

/// The 32-byte device secret + 16-byte device uuid returned by enrollment.
/// `deviceSecret` is a `var` so the coordinator can `zeroize` its canonical copy.
public struct EnrolledSlot {
    public let deviceUuid: [UInt8]
    public var deviceSecret: [UInt8]
    public init(deviceUuid: [UInt8], deviceSecret: [UInt8]) {
        self.deviceUuid = deviceUuid
        self.deviceSecret = deviceSecret
    }
}

/// Thin port over the three B.2 device-slot uniffi functions. Throws `VaultSlotError`.
public protocol VaultDeviceSlotPort {
    func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot
    func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault
    func removeDeviceSlot(vaultPath: Data, deviceUuid: [UInt8]) throws
}
```

`DeviceSecretEnclave.swift`:
```swift
/// A biometric-gated store for one 32-byte device secret. Conformers throw
/// `DeviceUnlockError` for every failure (biometric, corruption, OS errors).
public protocol DeviceSecretEnclave {
    var isEnrolled: Bool { get }
    /// Generate the hardware key if needed, wrap `secret`, persist the blob.
    /// Replaces any existing enrollment.
    func store(secret: [UInt8]) throws
    /// Biometric-gate, then release the secret. `async` because the real
    /// conformer drives an `LAContext` evaluation.
    func release(reason: String) async throws -> [UInt8]
    /// Delete the key + wrapped blob.
    func clear() throws
}
```

`DeviceEnrollment.swift`:
```swift
/// Non-secret enrollment metadata. `vaultId` is a caller-supplied opaque token
/// identifying the vault, used to detect a stale enrollment.
public struct DeviceEnrollment: Equatable {
    public let vaultId: String
    public let deviceUuid: [UInt8]
    public init(vaultId: String, deviceUuid: [UInt8]) {
        self.vaultId = vaultId
        self.deviceUuid = deviceUuid
    }
}

public protocol DeviceEnrollmentMetadataStore {
    func load() throws -> DeviceEnrollment?
    func save(_ enrollment: DeviceEnrollment) throws
    func clear() throws
}
```

`DeviceUnlockError.swift`:
```swift
/// Typed failures surfaced by `DeviceUnlockCoordinator`. The enclave conformer
/// produces the biometric/enclave cases; the coordinator produces the
/// orchestration cases from `VaultSlotError` and metadata state.
public enum DeviceUnlockError: Error, Equatable {
    case biometryUnavailable
    case biometryNotEnrolled
    case biometryLockout
    case userCancelled
    case authenticationFailed
    case notEnrolled
    case vaultSlotMismatch
    case wrappedSecretCorrupt
    case wrongDeviceSecretOrCorrupt
    case vault(VaultSlotError)
    /// Unexpected Security.framework / OSStatus error, carried as its string.
    case enclave(String)
}
```

- [ ] **Step 2: Write the fakes**

`FakeOpenedVault.swift`:
```swift
import SecretaryDeviceUnlock

public final class FakeOpenedVault: OpenedVault {
    public let vaultUuid: [UInt8]
    public private(set) var wipeCount = 0
    public init(vaultUuid: [UInt8]) { self.vaultUuid = vaultUuid }
    public func wipe() { wipeCount += 1 }
}
```

`FakeVaultDeviceSlotPort.swift`:
```swift
import Foundation
import SecretaryDeviceUnlock

/// In-memory `VaultDeviceSlotPort`. Records calls and supports error injection
/// so the coordinator's every branch is reachable without the real FFI.
public final class FakeVaultDeviceSlotPort: VaultDeviceSlotPort {
    // Canned outputs / injected errors.
    public var addResult: Result<EnrolledSlot, VaultSlotError>
    public var openResult: Result<OpenedVault, VaultSlotError>
    public var removeError: VaultSlotError?

    // Call recorders.
    public private(set) var addCalls = 0
    public private(set) var openedWith: (deviceUuid: [UInt8], deviceSecret: [UInt8])?
    public private(set) var removedUuids: [[UInt8]] = []

    public init(
        addResult: Result<EnrolledSlot, VaultSlotError> =
            .success(EnrolledSlot(deviceUuid: Array(repeating: 0xAB, count: 16),
                                  deviceSecret: Array(repeating: 0xCD, count: 32))),
        openResult: Result<OpenedVault, VaultSlotError> =
            .success(FakeOpenedVault(vaultUuid: Array(repeating: 0xEF, count: 16))),
        removeError: VaultSlotError? = nil
    ) {
        self.addResult = addResult
        self.openResult = openResult
        self.removeError = removeError
    }

    public func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot {
        addCalls += 1
        return try addResult.get()
    }

    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault {
        openedWith = (deviceUuid, deviceSecret)
        return try openResult.get()
    }

    public func removeDeviceSlot(vaultPath: Data, deviceUuid: [UInt8]) throws {
        removedUuids.append(deviceUuid)
        if let removeError { throw removeError }
    }
}
```

`InMemoryDeviceSecretEnclave.swift`:
```swift
import SecretaryDeviceUnlock

/// In-memory `DeviceSecretEnclave`. Holds the bytes (no real crypto); supports
/// injecting a `DeviceUnlockError` from `store`/`release` to simulate biometric
/// failures. Reusable by the SecretaryKit Tier-2 integration test.
public final class InMemoryDeviceSecretEnclave: DeviceSecretEnclave {
    private var secret: [UInt8]?
    public var storeError: DeviceUnlockError?
    public var releaseError: DeviceUnlockError?
    public private(set) var clearCount = 0

    public init() {}

    public var isEnrolled: Bool { secret != nil }

    public func store(secret: [UInt8]) throws {
        if let storeError { throw storeError }
        self.secret = secret
    }

    public func release(reason: String) async throws -> [UInt8] {
        if let releaseError { throw releaseError }
        guard let secret else { throw DeviceUnlockError.notEnrolled }
        return secret
    }

    public func clear() throws {
        clearCount += 1
        secret = nil
    }
}
```

`InMemoryEnrollmentMetadataStore.swift`:
```swift
import SecretaryDeviceUnlock

public final class InMemoryEnrollmentMetadataStore: DeviceEnrollmentMetadataStore {
    private var enrollment: DeviceEnrollment?
    public var saveError: Error?
    public private(set) var clearCount = 0

    public init(enrollment: DeviceEnrollment? = nil) { self.enrollment = enrollment }

    public func load() throws -> DeviceEnrollment? { enrollment }

    public func save(_ enrollment: DeviceEnrollment) throws {
        if let saveError { throw saveError }
        self.enrollment = enrollment
    }

    public func clear() throws {
        clearCount += 1
        enrollment = nil
    }
}
```

- [ ] **Step 3: Write the failing test** `Tests/SecretaryDeviceUnlockTests/FakesTests.swift`

```swift
import XCTest
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

final class FakesTests: XCTestCase {
    func testInMemoryEnclaveStoreReleaseClearRoundTrip() async throws {
        let enclave = InMemoryDeviceSecretEnclave()
        XCTAssertFalse(enclave.isEnrolled)
        try enclave.store(secret: [1, 2, 3])
        XCTAssertTrue(enclave.isEnrolled)
        let out = try await enclave.release(reason: "test")
        XCTAssertEqual(out, [1, 2, 3])
        try enclave.clear()
        XCTAssertFalse(enclave.isEnrolled)
        XCTAssertEqual(enclave.clearCount, 1)
    }

    func testInMemoryEnclaveInjectedReleaseError() async {
        let enclave = InMemoryDeviceSecretEnclave()
        try? enclave.store(secret: [9])
        enclave.releaseError = .biometryLockout
        do {
            _ = try await enclave.release(reason: "test")
            XCTFail("expected throw")
        } catch let e as DeviceUnlockError {
            XCTAssertEqual(e, .biometryLockout)
        } catch { XCTFail("wrong error type: \(error)") }
    }

    func testFakePortRecordsAndInjects() throws {
        let port = FakeVaultDeviceSlotPort(removeError: .deviceSlotNotFound)
        _ = try port.addDeviceSlot(vaultPath: Data(), password: [])
        XCTAssertEqual(port.addCalls, 1)
        XCTAssertThrowsError(try port.removeDeviceSlot(vaultPath: Data(), deviceUuid: [1])) { err in
            XCTAssertEqual(err as? VaultSlotError, .deviceSlotNotFound)
        }
        XCTAssertEqual(port.removedUuids, [[1]])
    }

    func testInMemoryMetadataStore() throws {
        let store = InMemoryEnrollmentMetadataStore()
        XCTAssertNil(try store.load())
        let e = DeviceEnrollment(vaultId: "v1", deviceUuid: [7])
        try store.save(e)
        XCTAssertEqual(try store.load(), e)
        try store.clear()
        XCTAssertNil(try store.load())
        XCTAssertEqual(store.clearCount, 1)
    }
}
```

- [ ] **Step 4: Run to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter FakesTests`
Expected: FAIL — types not yet defined / compile error until Steps 1–2 files exist. (If you wrote Steps 1–2 first, it should compile and PASS — that's fine; the point is the suite is green after this task.)

- [ ] **Step 5: Run the full suite to verify it passes**

Run: `cd ios/SecretaryDeviceUnlock && swift test`
Expected: PASS (ZeroizingTests + FakesTests).

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Sources ios/SecretaryDeviceUnlock/Tests
git commit -m "feat(b3): device-unlock ports, value types, typed error, and in-memory fakes"
```

---

## Task 3: `DeviceUnlockCoordinator.enroll` (happy + rollback)

**Files:**
- Create: `Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift`
- Test: `Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift`

- [ ] **Step 1: Write the failing tests** (create the test file with the enroll cases)

```swift
import XCTest
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

final class DeviceUnlockCoordinatorTests: XCTestCase {
    private let vaultPath = Data("/tmp/vault".utf8)
    private let uuid: [UInt8] = Array(repeating: 0x11, count: 16)
    private let secret: [UInt8] = Array(repeating: 0x22, count: 32)

    private func makeCoordinator(
        port: FakeVaultDeviceSlotPort,
        enclave: InMemoryDeviceSecretEnclave = InMemoryDeviceSecretEnclave(),
        metadata: InMemoryEnrollmentMetadataStore = InMemoryEnrollmentMetadataStore()
    ) -> DeviceUnlockCoordinator {
        DeviceUnlockCoordinator(slotPort: port, enclave: enclave, metadata: metadata)
    }

    func testEnrollHappyPathStoresSecretAndSavesMetadata() throws {
        let port = FakeVaultDeviceSlotPort(
            addResult: .success(EnrolledSlot(deviceUuid: uuid, deviceSecret: secret)))
        let enclave = InMemoryDeviceSecretEnclave()
        let metadata = InMemoryEnrollmentMetadataStore()
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: metadata)

        try coord.enroll(vaultPath: vaultPath, vaultId: "v1", password: [0x50])

        XCTAssertEqual(port.addCalls, 1)
        XCTAssertTrue(enclave.isEnrolled)
        XCTAssertEqual(try metadata.load(), DeviceEnrollment(vaultId: "v1", deviceUuid: uuid))
        XCTAssertTrue(port.removedUuids.isEmpty, "no rollback on success")
    }

    func testEnrollRollsBackSlotWhenEnclaveStoreFails() throws {
        let port = FakeVaultDeviceSlotPort(
            addResult: .success(EnrolledSlot(deviceUuid: uuid, deviceSecret: secret)))
        let enclave = InMemoryDeviceSecretEnclave()
        enclave.storeError = .enclave("simulated SE failure")
        let metadata = InMemoryEnrollmentMetadataStore()
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: metadata)

        XCTAssertThrowsError(try coord.enroll(vaultPath: vaultPath, vaultId: "v1", password: [0x50])) { err in
            XCTAssertEqual(err as? DeviceUnlockError, .enclave("simulated SE failure"))
        }
        XCTAssertEqual(port.removedUuids, [uuid], "slot must be removed to avoid an orphan wrap file")
        XCTAssertNil(try metadata.load())
    }

    func testEnrollRollsBackBothWhenMetadataSaveFails() throws {
        struct SaveFailed: Error {}
        let port = FakeVaultDeviceSlotPort(
            addResult: .success(EnrolledSlot(deviceUuid: uuid, deviceSecret: secret)))
        let enclave = InMemoryDeviceSecretEnclave()
        let metadata = InMemoryEnrollmentMetadataStore()
        metadata.saveError = SaveFailed()
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: metadata)

        XCTAssertThrowsError(try coord.enroll(vaultPath: vaultPath, vaultId: "v1", password: [0x50]))
        XCTAssertEqual(enclave.clearCount, 1, "enclave must be cleared on metadata failure")
        XCTAssertEqual(port.removedUuids, [uuid], "slot must be removed on metadata failure")
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockCoordinatorTests`
Expected: FAIL — `cannot find 'DeviceUnlockCoordinator' in scope`.

- [ ] **Step 3: Write `DeviceUnlockCoordinator.swift` (enroll only for now)**

```swift
import Foundation

/// Pure orchestration over three injected ports. No I/O of its own.
public struct DeviceUnlockCoordinator {
    let slotPort: VaultDeviceSlotPort
    let enclave: DeviceSecretEnclave
    let metadata: DeviceEnrollmentMetadataStore

    public init(slotPort: VaultDeviceSlotPort,
                enclave: DeviceSecretEnclave,
                metadata: DeviceEnrollmentMetadataStore) {
        self.slotPort = slotPort
        self.enclave = enclave
        self.metadata = metadata
    }

    /// Enroll this device: password-open + mint a slot, SE-wrap the secret,
    /// persist metadata. Transactional: any mid-flow failure rolls back so no
    /// orphan wrap file or enclave key survives.
    public func enroll(vaultPath: Data, vaultId: String, password: [UInt8]) throws {
        var slot = try mapSlotErrors { try slotPort.addDeviceSlot(vaultPath: vaultPath, password: password) }
        defer { zeroize(&slot.deviceSecret) }

        do {
            try enclave.store(secret: slot.deviceSecret)
        } catch {
            try? slotPort.removeDeviceSlot(vaultPath: vaultPath, deviceUuid: slot.deviceUuid)
            throw error
        }

        do {
            try metadata.save(DeviceEnrollment(vaultId: vaultId, deviceUuid: slot.deviceUuid))
        } catch {
            try? enclave.clear()
            try? slotPort.removeDeviceSlot(vaultPath: vaultPath, deviceUuid: slot.deviceUuid)
            throw error
        }
    }
}

/// Run a port call, translating `VaultSlotError` into the coordinator's typed
/// `DeviceUnlockError` semantics. (Used by unlock; enroll's add path re-throws
/// the mapped error directly.)
func mapSlotErrors<R>(_ body: () throws -> R) throws -> R {
    do {
        return try body()
    } catch let e as VaultSlotError {
        switch e {
        case .deviceSlotNotFound:          throw DeviceUnlockError.vaultSlotMismatch
        case .wrongDeviceSecretOrCorrupt:  throw DeviceUnlockError.wrongDeviceSecretOrCorrupt
        default:                           throw DeviceUnlockError.vault(e)
        }
    }
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockCoordinatorTests`
Expected: PASS (3 enroll tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift \
        ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift
git commit -m "feat(b3): DeviceUnlockCoordinator.enroll with transactional rollback"
```

---

## Task 4: `DeviceUnlockCoordinator.unlock` (happy + every error branch)

**Files:**
- Modify: `Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift`
- Modify: `Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift`

- [ ] **Step 1: Add the failing unlock tests** (append to the test class)

```swift
    // MARK: unlock

    private func enrolledMetadata(vaultId: String = "v1") -> InMemoryEnrollmentMetadataStore {
        InMemoryEnrollmentMetadataStore(enrollment: DeviceEnrollment(vaultId: vaultId, deviceUuid: uuid))
    }

    func testUnlockHappyPathOpensVaultAndZeroizes() async throws {
        let opened = FakeOpenedVault(vaultUuid: Array(repeating: 0x33, count: 16))
        let port = FakeVaultDeviceSlotPort(openResult: .success(opened))
        let enclave = InMemoryDeviceSecretEnclave()
        try enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())

        let out = try await coord.unlock(vaultPath: vaultPath, vaultId: "v1", reason: "Unlock")

        XCTAssertEqual(out.vaultUuid, Array(repeating: 0x33, count: 16))
        XCTAssertEqual(port.openedWith?.deviceUuid, uuid)
        XCTAssertEqual(port.openedWith?.deviceSecret, secret)
    }

    func testUnlockNotEnrolledWhenNoMetadata() async {
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort())
        await assertThrowsDeviceUnlock(.notEnrolled) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockVaultSlotMismatchOnWrongVaultId() async {
        let enclave = InMemoryDeviceSecretEnclave(); try? enclave.store(secret: secret)
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort(), enclave: enclave,
                                    metadata: enrolledMetadata(vaultId: "v1"))
        await assertThrowsDeviceUnlock(.vaultSlotMismatch) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "DIFFERENT", reason: "x")
        }
    }

    func testUnlockMapsDeviceSlotNotFoundToMismatch() async {
        let port = FakeVaultDeviceSlotPort(openResult: .failure(.deviceSlotNotFound))
        let enclave = InMemoryDeviceSecretEnclave(); try? enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.vaultSlotMismatch) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockSurfacesWrongDeviceSecretOrCorrupt() async {
        let port = FakeVaultDeviceSlotPort(openResult: .failure(.wrongDeviceSecretOrCorrupt))
        let enclave = InMemoryDeviceSecretEnclave(); try? enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.wrongDeviceSecretOrCorrupt) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockPassesThroughOtherVaultError() async {
        let port = FakeVaultDeviceSlotPort(openResult: .failure(.other("disk gone")))
        let enclave = InMemoryDeviceSecretEnclave(); try? enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.vault(.other("disk gone"))) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockPropagatesBiometricError() async {
        let enclave = InMemoryDeviceSecretEnclave(); try? enclave.store(secret: secret)
        enclave.releaseError = .biometryLockout
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort(), enclave: enclave,
                                    metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.biometryLockout) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    /// Helper: assert an async throwing block throws a specific DeviceUnlockError.
    private func assertThrowsDeviceUnlock(
        _ expected: DeviceUnlockError,
        _ body: () async throws -> Void,
        file: StaticString = #filePath, line: UInt = #line
    ) async {
        do {
            try await body()
            XCTFail("expected \(expected) but no error thrown", file: file, line: line)
        } catch let e as DeviceUnlockError {
            XCTAssertEqual(e, expected, file: file, line: line)
        } catch {
            XCTFail("expected DeviceUnlockError.\(expected), got \(error)", file: file, line: line)
        }
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockCoordinatorTests`
Expected: FAIL — `value of type 'DeviceUnlockCoordinator' has no member 'unlock'`.

- [ ] **Step 3: Add `unlock` to `DeviceUnlockCoordinator.swift`** (insert after `enroll`)

```swift
    /// Unlock: biometric-release the secret, then open the vault with it.
    public func unlock(vaultPath: Data, vaultId: String, reason: String) async throws -> OpenedVault {
        guard let enrollment = try metadata.load() else { throw DeviceUnlockError.notEnrolled }
        guard enrollment.vaultId == vaultId else { throw DeviceUnlockError.vaultSlotMismatch }

        var secret = try await enclave.release(reason: reason) // throws DeviceUnlockError
        defer { zeroize(&secret) }

        return try mapSlotErrors {
            try slotPort.openWithDeviceSecret(vaultPath: vaultPath,
                                              deviceUuid: enrollment.deviceUuid,
                                              deviceSecret: secret)
        }
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockCoordinatorTests`
Expected: PASS (enroll + all unlock tests).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift \
        ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift
git commit -m "feat(b3): DeviceUnlockCoordinator.unlock with full error-branch coverage"
```

---

## Task 5: `disenroll` + `isEnrolled`

**Files:**
- Modify: `Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift`
- Modify: `Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift`

- [ ] **Step 1: Add the failing tests** (append to the test class)

```swift
    // MARK: disenroll + isEnrolled

    func testDisenrollRemovesSlotClearsEnclaveAndMetadata() throws {
        let port = FakeVaultDeviceSlotPort()
        let enclave = InMemoryDeviceSecretEnclave(); try enclave.store(secret: secret)
        let metadata = enrolledMetadata()
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: metadata)

        try coord.disenroll(vaultPath: vaultPath)

        XCTAssertEqual(port.removedUuids, [uuid])
        XCTAssertEqual(enclave.clearCount, 1)
        XCTAssertEqual(metadata.clearCount, 1)
        XCTAssertNil(try metadata.load())
    }

    func testDisenrollToleratesAlreadyRemovedSlot() throws {
        let port = FakeVaultDeviceSlotPort(removeError: .deviceSlotNotFound)
        let enclave = InMemoryDeviceSecretEnclave(); try enclave.store(secret: secret)
        let metadata = enrolledMetadata()
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: metadata)

        try coord.disenroll(vaultPath: vaultPath) // must NOT throw

        XCTAssertEqual(enclave.clearCount, 1, "enclave still cleared even when slot was already gone")
        XCTAssertEqual(metadata.clearCount, 1)
    }

    func testDisenrollWhenNotEnrolledIsNoop() throws {
        let port = FakeVaultDeviceSlotPort()
        let coord = makeCoordinator(port: port) // empty metadata + enclave
        try coord.disenroll(vaultPath: vaultPath)
        XCTAssertTrue(port.removedUuids.isEmpty)
    }

    func testIsEnrolledRequiresBothEnclaveAndMetadata() throws {
        let enclave = InMemoryDeviceSecretEnclave()
        let metadata = InMemoryEnrollmentMetadataStore()
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort(), enclave: enclave, metadata: metadata)
        XCTAssertFalse(coord.isEnrolled)

        try enclave.store(secret: secret)
        XCTAssertFalse(coord.isEnrolled, "enclave-only is not enrolled")

        try metadata.save(DeviceEnrollment(vaultId: "v1", deviceUuid: uuid))
        XCTAssertTrue(coord.isEnrolled)
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ios/SecretaryDeviceUnlock && swift test --filter DeviceUnlockCoordinatorTests`
Expected: FAIL — no member `disenroll` / `isEnrolled`.

- [ ] **Step 3: Add `disenroll` + `isEnrolled`** (insert into `DeviceUnlockCoordinator`)

```swift
    /// True iff both the enclave holds a secret AND enrollment metadata exists.
    public var isEnrolled: Bool {
        enclave.isEnrolled && ((try? metadata.load()) ?? nil) != nil
    }

    /// Disenroll this device: remove the vault slot (tolerating an already-gone
    /// slot), then clear the enclave key and metadata so no orphan survives.
    public func disenroll(vaultPath: Data) throws {
        if let enrollment = try metadata.load() {
            do {
                try slotPort.removeDeviceSlot(vaultPath: vaultPath, deviceUuid: enrollment.deviceUuid)
            } catch VaultSlotError.deviceSlotNotFound {
                // already gone — fine
            }
        }
        try enclave.clear()
        try metadata.clear()
    }
```

- [ ] **Step 4: Run to verify it passes**

Run: `cd ios/SecretaryDeviceUnlock && swift test`
Expected: PASS (all suites).

- [ ] **Step 5: Commit**

```bash
git add ios/SecretaryDeviceUnlock/Sources/SecretaryDeviceUnlock/DeviceUnlockCoordinator.swift \
        ios/SecretaryDeviceUnlock/Tests/SecretaryDeviceUnlockTests/DeviceUnlockCoordinatorTests.swift
git commit -m "feat(b3): DeviceUnlockCoordinator.disenroll + isEnrolled"
```

---

## Task 6: Wire SecretaryKit to the pure package + the real uniffi port adapter

The pure logic is done and host-green. Now the iOS-bound adapters. From here,
verification needs macOS + Xcode + the XCFramework (via `bash ios/scripts/run-ios-tests.sh`).

**Files:**
- Modify: `ios/SecretaryKit/Package.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/OpenVaultOutput+OpenedVault.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/UniffiVaultDeviceSlotPort.swift`

- [ ] **Step 1: Confirm the generated B.2 Swift signatures** (do this before writing the adapter)

```bash
bash ios/scripts/build-xcframework.sh
grep -nE 'func (addDeviceSlot|openWithDeviceSecret|removeDeviceSlot)|class DeviceSecretOutput|struct DeviceEnrollOutput|func takeSecret|func vaultUuid' \
    ios/SecretaryKit/Sources/SecretaryKit/secretary.swift
```
Expected (adapt the adapter below if names differ): `addDeviceSlot(folderPath: Data, password: Data) throws -> DeviceEnrollOutput`; `openWithDeviceSecret(folderPath: Data, deviceUuid: Data, deviceSecret: Data) throws -> OpenVaultOutput`; `removeDeviceSlot(folderPath: Data, deviceUuid: Data) throws`; `DeviceEnrollOutput { deviceUuid: Data; deviceSecret: DeviceSecretOutput }`; `DeviceSecretOutput.takeSecret() -> [UInt8]?` + `.wipe()`; `OpenVaultOutput { manifest; identity }` with `manifest.vaultUuid() -> Data`.

- [ ] **Step 2: Modify `ios/SecretaryKit/Package.swift`** to depend on the pure package

```swift
// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecretaryKit",
    platforms: [.iOS(.v17)],
    products: [
        .library(name: "SecretaryKit", targets: ["SecretaryKit"]),
    ],
    dependencies: [
        .package(path: "../SecretaryDeviceUnlock"),
    ],
    targets: [
        .binaryTarget(name: "SecretaryFFI", path: "../Secretary.xcframework"),
        .target(
            name: "SecretaryKit",
            dependencies: [
                "SecretaryFFI",
                .product(name: "SecretaryDeviceUnlock", package: "SecretaryDeviceUnlock"),
            ]
        ),
        .testTarget(
            name: "SecretaryKitTests",
            dependencies: [
                "SecretaryKit",
                .product(name: "SecretaryDeviceUnlockTesting", package: "SecretaryDeviceUnlock"),
            ],
            resources: [
                .copy("Resources/golden_vault_001"),
                .copy("Resources/golden_vault_001_inputs.json"),
            ]
        ),
    ]
)
```

- [ ] **Step 3: Write `OpenVaultOutput+OpenedVault.swift`**

```swift
import Foundation
import SecretaryDeviceUnlock

/// Bridge the uniffi `OpenVaultOutput` to the pure `OpenedVault` boundary type.
extension OpenVaultOutput: OpenedVault {
    public var vaultUuid: [UInt8] { [UInt8](manifest.vaultUuid()) }
    public func wipe() { manifest.wipe(); identity.wipe() }
}
```

- [ ] **Step 4: Write `UniffiVaultDeviceSlotPort.swift`**

```swift
import Foundation
import SecretaryDeviceUnlock

/// Real `VaultDeviceSlotPort` over the B.2 uniffi functions. This is the ONLY
/// place that touches the one-shot `DeviceSecretOutput`.
public struct UniffiVaultDeviceSlotPort: VaultDeviceSlotPort {
    public init() {}

    public func addDeviceSlot(vaultPath: Data, password: [UInt8]) throws -> EnrolledSlot {
        do {
            let out = try SecretaryKit.addDeviceSlot(folderPath: vaultPath, password: Data(password))
            guard let secret = out.deviceSecret.takeSecret() else {
                // One-shot already consumed — should never happen on a fresh handle.
                throw VaultSlotError.other("device secret handle was empty")
            }
            out.deviceSecret.wipe()
            return EnrolledSlot(deviceUuid: [UInt8](out.deviceUuid), deviceSecret: secret)
        } catch let e as VaultError {
            throw mapVaultError(e)
        }
    }

    public func openWithDeviceSecret(vaultPath: Data, deviceUuid: [UInt8], deviceSecret: [UInt8]) throws -> OpenedVault {
        do {
            return try SecretaryKit.openWithDeviceSecret(
                folderPath: vaultPath,
                deviceUuid: Data(deviceUuid),
                deviceSecret: Data(deviceSecret))
        } catch let e as VaultError {
            throw mapVaultError(e)
        }
    }

    public func removeDeviceSlot(vaultPath: Data, deviceUuid: [UInt8]) throws {
        do {
            try SecretaryKit.removeDeviceSlot(folderPath: vaultPath, deviceUuid: Data(deviceUuid))
        } catch let e as VaultError {
            throw mapVaultError(e)
        }
    }
}

/// Map the uniffi `VaultError` onto the pure `VaultSlotError` mirror.
func mapVaultError(_ e: VaultError) -> VaultSlotError {
    switch e {
    case .DeviceSlotNotFound:         return .deviceSlotNotFound
    case .WrongDeviceSecretOrCorrupt: return .wrongDeviceSecretOrCorrupt
    case .DeviceUuidMismatch(let d):  return .deviceUuidMismatch(d)
    case .InvalidArgument(let d):     return .invalidArgument(d)
    default:                          return .other(String(describing: e))
    }
}
```

- [ ] **Step 5: Build to verify it compiles** (the integration test in Task 8 exercises it)

Run: `cd ios/SecretaryKit && swift build`
Expected: builds (note: `swift build` for an iOS-only binaryTarget may require `xcodebuild`; if `swift build` cannot resolve the XCFramework on this host, defer compile-verification to Task 8's `run-ios-tests.sh`, which builds for the simulator). If `mapVaultError`'s `case` labels don't match the generated `VaultError`, fix them per the grep in Step 1.

- [ ] **Step 6: Commit**

```bash
git add ios/SecretaryKit/Package.swift ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/
git commit -m "feat(b3): wire SecretaryKit to SecretaryDeviceUnlock + real uniffi port adapter"
```

---

## Task 7: The real Secure Enclave conformer + Keychain metadata store (compile-only)

These are the real platform conformers. They compile against the iOS SDK but are
**not** asserted by an automated test here — real biometrics need a device (the #202
follow-up). Keep them complete and idiomatic.

**Files:**
- Create: `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/SecureEnclaveDeviceSecretStore.swift`
- Create: `ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/KeychainEnrollmentMetadataStore.swift`

- [ ] **Step 1: Write `SecureEnclaveDeviceSecretStore.swift`**

```swift
import Foundation
import Security
import LocalAuthentication
import SecretaryDeviceUnlock

/// Real `DeviceSecretEnclave`: a non-exportable Secure Enclave P-256 key with a
/// biometry-bound access control wraps the 32-byte device secret via ECIES; the
/// SE private key never leaves the enclave. NOT covered by an automated test —
/// real Face ID / Touch ID needs a device (the #202 follow-up's manual proof).
public final class SecureEnclaveDeviceSecretStore: DeviceSecretEnclave {
    private let keyTag: Data
    private let blobService: String
    private let blobAccount: String
    private let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM

    public init(keyTag: String = "com.secretary.deviceSecret.seKey",
                blobService: String = "com.secretary.deviceSecret",
                blobAccount: String = "wrappedDeviceSecret") {
        self.keyTag = Data(keyTag.utf8)
        self.blobService = blobService
        self.blobAccount = blobAccount
    }

    public var isEnrolled: Bool { loadKey() != nil && ((try? loadBlob()) ?? nil) != nil }

    public func store(secret: [UInt8]) throws {
        let key = try ensureKey()
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw DeviceUnlockError.enclave("no public key for SE private key")
        }
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            throw DeviceUnlockError.enclave("ECIES algorithm unsupported")
        }
        var error: Unmanaged<CFError>?
        guard let cipher = SecKeyCreateEncryptedData(
            publicKey, algorithm, Data(secret) as CFData, &error) as Data? else {
            throw DeviceUnlockError.enclave(cfErrorString(error))
        }
        try saveBlob(cipher)
    }

    public func release(reason: String) async throws -> [UInt8] {
        guard let blob = try loadBlob() else { throw DeviceUnlockError.notEnrolled }
        let context = LAContext()
        context.localizedReason = reason
        guard let key = loadKey(context: context) else { throw DeviceUnlockError.notEnrolled }

        return try await withCheckedThrowingContinuation { continuation in
            // SecKeyCreateDecryptedData on an SE key triggers the biometric prompt.
            var error: Unmanaged<CFError>?
            guard let plain = SecKeyCreateDecryptedData(key, algorithm, blob as CFData, &error) as Data? else {
                continuation.resume(throwing: mapDecryptError(error))
                return
            }
            continuation.resume(returning: [UInt8](plain))
        }
    }

    public func clear() throws {
        // Delete the SE key.
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
        ]
        let keyStatus = SecItemDelete(keyQuery as CFDictionary)
        guard keyStatus == errSecSuccess || keyStatus == errSecItemNotFound else {
            throw DeviceUnlockError.enclave("SecItemDelete(key) failed: \(keyStatus)")
        }
        // Delete the wrapped blob.
        let blobStatus = SecItemDelete(blobQuery() as CFDictionary)
        guard blobStatus == errSecSuccess || blobStatus == errSecItemNotFound else {
            throw DeviceUnlockError.enclave("SecItemDelete(blob) failed: \(blobStatus)")
        }
    }

    // MARK: - Key management

    private func ensureKey() throws -> SecKey {
        if let existing = loadKey() { return existing }

        var acError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &acError) else {
            throw DeviceUnlockError.enclave(cfErrorString(acError))
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: keyTag,
                kSecAttrAccessControl as String: access,
            ],
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw DeviceUnlockError.enclave(cfErrorString(error))
        }
        return key
    }

    private func loadKey(context: LAContext? = nil) -> SecKey? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyTag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        guard SecItemCopyMatching(query as CFDictionary, &item) == errSecSuccess else { return nil }
        // SecKey is a CF type; force-cast is the documented retrieval idiom.
        return (item as! SecKey)
    }

    // MARK: - Blob persistence (the ciphertext is already SE-encrypted)

    private func blobQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: blobService,
            kSecAttrAccount as String: blobAccount,
        ]
    }

    private func saveBlob(_ blob: Data) throws {
        SecItemDelete(blobQuery() as CFDictionary) // replace any existing
        var attrs = blobQuery()
        attrs[kSecValueData as String] = blob
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw DeviceUnlockError.enclave("SecItemAdd(blob) failed: \(status)")
        }
    }

    private func loadBlob() throws -> Data? {
        var query = blobQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:      return item as? Data
        case errSecItemNotFound: return nil
        default:                 throw DeviceUnlockError.enclave("SecItemCopyMatching(blob) failed: \(status)")
        }
    }

    // MARK: - Error mapping

    private func mapDecryptError(_ error: Unmanaged<CFError>?) -> DeviceUnlockError {
        guard let cf = error?.takeRetainedValue() else { return .wrappedSecretCorrupt }
        let nsError = cf as Error as NSError
        if nsError.domain == LAError.errorDomain, let code = LAError.Code(rawValue: nsError.code) {
            switch code {
            case .biometryNotAvailable:                 return .biometryUnavailable
            case .biometryNotEnrolled:                  return .biometryNotEnrolled
            case .biometryLockout:                      return .biometryLockout
            case .userCancel, .appCancel, .systemCancel: return .userCancelled
            case .authenticationFailed:                 return .authenticationFailed
            default:                                    return .enclave(nsError.localizedDescription)
            }
        }
        // A decryption/auth failure that is not an LAError ⇒ corrupt or tampered blob.
        return .wrappedSecretCorrupt
    }

    private func cfErrorString(_ error: Unmanaged<CFError>?) -> String {
        guard let cf = error?.takeRetainedValue() else { return "unknown Security.framework error" }
        return (cf as Error).localizedDescription
    }
}
```

- [ ] **Step 2: Write `KeychainEnrollmentMetadataStore.swift`**

```swift
import Foundation
import Security
import SecretaryDeviceUnlock

/// Real `DeviceEnrollmentMetadataStore`: persists the NON-secret enrollment
/// metadata (vaultId + 16-byte device uuid) in the Keychain as a generic
/// password item, this-device-only, with NO biometric gate (it is not secret).
public struct KeychainEnrollmentMetadataStore: DeviceEnrollmentMetadataStore {
    private let service: String
    private let account: String

    public init(service: String = "com.secretary.enrollment",
                account: String = "deviceEnrollment") {
        self.service = service
        self.account = account
    }

    private func baseQuery() -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    public func load() throws -> DeviceEnrollment? {
        var query = baseQuery()
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data else { return nil }
            return try decode(data)
        case errSecItemNotFound:
            return nil
        default:
            throw NSError(domain: "KeychainEnrollmentMetadataStore", code: Int(status))
        }
    }

    public func save(_ enrollment: DeviceEnrollment) throws {
        let data = try encode(enrollment)
        SecItemDelete(baseQuery() as CFDictionary)
        var attrs = baseQuery()
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(attrs as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: "KeychainEnrollmentMetadataStore", code: Int(status))
        }
    }

    public func clear() throws {
        let status = SecItemDelete(baseQuery() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw NSError(domain: "KeychainEnrollmentMetadataStore", code: Int(status))
        }
    }

    // Codable JSON wire form (the device uuid as a hex string).
    private struct Wire: Codable { let vaultId: String; let deviceUuidHex: String }

    private func encode(_ e: DeviceEnrollment) throws -> Data {
        let hex = e.deviceUuid.map { String(format: "%02x", $0) }.joined()
        return try JSONEncoder().encode(Wire(vaultId: e.vaultId, deviceUuidHex: hex))
    }

    private func decode(_ data: Data) throws -> DeviceEnrollment {
        let wire = try JSONDecoder().decode(Wire.self, from: data)
        var bytes = [UInt8]()
        var i = wire.deviceUuidHex.startIndex
        while i < wire.deviceUuidHex.endIndex {
            let j = wire.deviceUuidHex.index(i, offsetBy: 2)
            bytes.append(UInt8(wire.deviceUuidHex[i..<j], radix: 16) ?? 0)
            i = j
        }
        return DeviceEnrollment(vaultId: wire.vaultId, deviceUuid: bytes)
    }
}
```

- [ ] **Step 3: Build to verify it compiles** (on the simulator build via the next task; or `swift build` if the host resolves the binaryTarget)

Run: `bash ios/scripts/build-xcframework.sh && cd ios/SecretaryKit && xcodebuild build -scheme SecretaryKit -destination 'generic/platform=iOS Simulator'`
Expected: BUILD SUCCEEDED. Fix any SDK-name mismatches (e.g. `LAError.Code` cases) revealed by the compiler.

- [ ] **Step 4: Commit**

```bash
git add ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/SecureEnclaveDeviceSecretStore.swift \
        ios/SecretaryKit/Sources/SecretaryKit/DeviceUnlock/KeychainEnrollmentMetadataStore.swift
git commit -m "feat(b3): real Secure Enclave conformer + Keychain metadata store (compile-only; device-deferred)"
```

---

## Task 8: Tier-2 simulator integration test (real FFI + fake enclave)

**Files:**
- Create: `ios/SecretaryKit/Tests/SecretaryKitTests/DeviceUnlockIntegrationTests.swift`

- [ ] **Step 1: Write the integration test**

```swift
import XCTest
@testable import SecretaryKit
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

/// Drives the FULL B.3 orchestration through the REAL B.2 FFI on a simulator,
/// using a fake enclave (so no biometric hardware is needed) against a writable
/// copy of golden_vault_001. Proves enroll → (fake) SE-wrap → release → real
/// open_with_device_secret actually opens the vault, and that disenroll removes
/// the on-disk wrap file.
final class DeviceUnlockIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-b3-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }

    func testEnrollUnlockDisenrollAgainstRealFFI() async throws {
        let path = Data(vaultCopy.path.utf8)
        let port = UniffiVaultDeviceSlotPort()
        let enclave = InMemoryDeviceSecretEnclave()
        let metadata = InMemoryEnrollmentMetadataStore()
        let coord = DeviceUnlockCoordinator(slotPort: port, enclave: enclave, metadata: metadata)

        // Enroll with the real password → real device slot minted + wrapped (fake enclave).
        try coord.enroll(vaultPath: path, vaultId: "golden", password: [UInt8](goldenPassword.utf8))
        XCTAssertTrue(coord.isEnrolled)

        // Unlock via the device secret → real open_with_device_secret.
        let opened = try await coord.unlock(vaultPath: path, vaultId: "golden", reason: "Unlock")
        defer { opened.wipe() }
        let expected = try pinnedVaultUuid()
        XCTAssertEqual(opened.vaultUuid, [UInt8](expected),
                       "device-secret open must yield the pinned golden vault UUID")

        // Capture the enrolled uuid for the direct-port probe BEFORE disenroll clears metadata.
        let enrolledUuid = try XCTUnwrap(try metadata.load()).deviceUuid

        // Disenroll → slot deleted, enclave + metadata cleared.
        try coord.disenroll(vaultPath: path)
        XCTAssertFalse(coord.isEnrolled)

        // (a) A subsequent coordinator unlock is .notEnrolled (metadata cleared).
        do {
            _ = try await coord.unlock(vaultPath: path, vaultId: "golden", reason: "Unlock")
            XCTFail("expected .notEnrolled after disenroll")
        } catch let e as DeviceUnlockError {
            XCTAssertEqual(e, .notEnrolled)
        }

        // (b) The wrap file is actually gone: the real port now throws DeviceSlotNotFound.
        XCTAssertThrowsError(
            try port.openWithDeviceSecret(vaultPath: path, deviceUuid: enrolledUuid,
                                          deviceSecret: Array(repeating: 0, count: 32))
        ) { err in
            XCTAssertEqual(err as? VaultSlotError, .deviceSlotNotFound,
                           "devices/<uuid>.wrap must be deleted from disk by disenroll")
        }
    }

    /// Pinned vault_uuid from the bundled inputs JSON → 16 bytes (no hardcoded array).
    private func pinnedVaultUuid() throws -> Data {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001_inputs", withExtension: "json"))
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let dict = try XCTUnwrap(json as? [String: Any])
        let dashed = try XCTUnwrap(dict["vault_uuid"] as? String)
        let hex = dashed.replacingOccurrences(of: "-", with: "")
        var bytes = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            let j = try XCTUnwrap(hex.index(i, offsetBy: 2, limitedBy: hex.endIndex))
            bytes.append(try XCTUnwrap(UInt8(hex[i..<j], radix: 16)))
            i = j
        }
        XCTAssertEqual(bytes.count, 16)
        return Data(bytes)
    }
}
```

- [ ] **Step 2: Run the full simulator suite**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: all SecretaryKitTests PASS — `OpenVaultLinkTests` (existing) + `DeviceUnlockIntegrationTests` (new). If the enrolled-secret open fails, re-check that `UniffiVaultDeviceSlotPort.addDeviceSlot` consumes `takeSecret()` exactly once and passes those bytes to `openWithDeviceSecret`.

- [ ] **Step 3: Commit**

```bash
git add ios/SecretaryKit/Tests/SecretaryKitTests/DeviceUnlockIntegrationTests.swift
git commit -m "test(b3): simulator integration test — real B.2 FFI round-trip with fake enclave"
```

---

## Task 9: Test-runner wiring + docs

**Files:**
- Modify: `ios/scripts/run-ios-tests.sh`
- Modify: `ios/README.md`
- Modify: `README.md`
- Modify: `ROADMAP.md`
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add a host-test pre-step to `run-ios-tests.sh`** (after the `build-xcframework.sh` call, before the simulator resolve)

```bash
# --- Step 1b: host-run the pure SecretaryDeviceUnlock package (fast, no simulator) ---
echo "==> swift test (pure SecretaryDeviceUnlock — host)"
( cd "$IOS_DIR/SecretaryDeviceUnlock" && swift test )
```

- [ ] **Step 2: Run the combined script to verify both tiers**

Run: `bash ios/scripts/run-ios-tests.sh`
Expected: the host `swift test` passes first, then the simulator XCTest passes.

- [ ] **Step 3: Update `ios/README.md`** — replace the "no Keychain/Secure-Enclave key storage yet" sentence and add a B.3 status block

```markdown
## Status — D.3 slice 1 ✅ + B.3 (Secure Enclave device unlock) ✅

The first slice established the iOS build pipeline and proves the core runs
on-device. B.3 adds biometric-gated, Secure-Enclave-backed release of the
per-device secret (ADR 0009 slot → unlock).

- `SecretaryDeviceUnlock/` — a pure, FFI-free Swift package: the orchestration
  (`DeviceUnlockCoordinator` over three injected ports + a typed
  `DeviceUnlockError`), fully covered by host `swift test`.
- `SecretaryKit/DeviceUnlock/` — the iOS adapters: the real uniffi port, the
  Secure Enclave conformer (non-exportable P-256 + biometric `SecAccessControl`,
  ECIES wrap), and a Keychain metadata store. The SE conformer compiles and is
  exercised on the simulator with a fake enclave; real Face ID / Touch ID
  verification on a device is the #202 follow-up.

```bash
bash ios/scripts/run-ios-tests.sh   # host swift test + simulator XCTest
```
```

- [ ] **Step 4: Update `README.md`** — add a one-line note to the iOS/mobile status (match the existing brief, dot-point style; no test-count walls)

Find the mobile/iOS status area and add:
```markdown
- iOS: Secure-Enclave-backed, biometric-gated device unlock (B.3) — pure
  orchestration host-tested; SE conformer device-verification deferred.
```

- [ ] **Step 5: Update `ROADMAP.md`** — mark B.3 done

Change the B.3 line to `✅ 2026-06-11` (mirror the B.2 entry's format), noting
the device-verification follow-up under #202.

- [ ] **Step 6: Update `CLAUDE.md`** — add a crypto-layering bullet after the B.2 device-slot paragraph

```markdown
- **iOS device unlock (B.3)** lives in `ios/`: a pure, FFI-free `SecretaryDeviceUnlock`
  package (`DeviceUnlockCoordinator` over `VaultDeviceSlotPort` / `DeviceSecretEnclave`
  / `DeviceEnrollmentMetadataStore`, typed `DeviceUnlockError`) host-tested via
  `swift test`, plus iOS adapters in `SecretaryKit/DeviceUnlock/` (real uniffi port,
  the non-exportable Secure-Enclave P-256 conformer behind a biometric
  `SecAccessControl`, Keychain metadata). The SE conformer is compile-verified on the
  simulator with a fake enclave; real biometric release on a device is the #202 follow-up.
  The coordinator's `unlock` funnels through the same B.2 `open_with_device_secret`
  (hence the same manifest verify-before-decrypt) — it is not a weaker open.
```

- [ ] **Step 7: Commit**

```bash
git add ios/scripts/run-ios-tests.sh ios/README.md README.md ROADMAP.md CLAUDE.md
git commit -m "docs(b3): wire host swift-test into the iOS runner; README/ROADMAP/CLAUDE updates"
```

---

## Final verification (run before opening the PR)

- [ ] **Host pure tests:** `cd ios/SecretaryDeviceUnlock && swift test` → all pass.
- [ ] **Full iOS gauntlet:** `bash ios/scripts/run-ios-tests.sh` → host tests + simulator `OpenVaultLinkTests` + `DeviceUnlockIntegrationTests` all pass.
- [ ] **No core regressions** (sanity — B.3 touches no Rust): `cargo test --release --workspace` → 0 failed.
- [ ] **Frozen-format untouched:** `git diff main..HEAD -- core/ docs/vault-format.md docs/crypto-design.md` shows no format/spec changes (B.3 is additive Swift only).
- [ ] Update the NEXT_SESSION baton (handoff doc + symlink) on this branch per the `/nextsession` workflow, then open the PR.

---

## Self-review notes (planner)

- **Spec coverage:** §3 module split → Tasks 1, 6 (Package wiring). §4 protocols/types → Tasks 1–2. §5 coordinator (enroll/unlock/disenroll) → Tasks 3–5. §6 error taxonomy → Task 2 (`DeviceUnlockError`) + reached in Tasks 4–5 + mapped in Tasks 3 (`mapSlotErrors`) and 6 (`mapVaultError`/`mapDecryptError`). §7 Tier-1 → Tasks 1–5; Tier-2 → Task 8; runner wiring → Task 9. §8 acceptance → SE conformer Task 7; enroll/unlock/disenroll Tasks 3–5/8; typed failures Task 2; zeroize Task 1. §9 risks reflected in Task 7's "compile-only" framing and the zeroize caveat.
- **Type consistency:** `EnrolledSlot.deviceSecret` is `var` (zeroized in Tasks 3/4). `VaultDeviceSlotPort` throws `VaultSlotError` everywhere (Tasks 2/3/4/6/8). `DeviceSecretEnclave` throws `DeviceUnlockError` (Tasks 2/4/7). `OpenedVault` = `{ vaultUuid: [UInt8]; wipe() }` (Tasks 2/6/8). `mapSlotErrors` (coordinator) vs `mapVaultError` (adapter) are distinct and both used.
- **Known soft spot:** the exact generated Swift API names (`VaultError` case labels, `manifest.vaultUuid()`) are confirmed by the Task-6 Step-1 grep before the adapter is written; the adapter notes to adjust if uniffi names differ. This is a verification step, not a placeholder.
```
