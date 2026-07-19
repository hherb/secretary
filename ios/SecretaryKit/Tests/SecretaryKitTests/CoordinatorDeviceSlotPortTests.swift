import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockTesting

/// Host tests for `CoordinatorDeviceSlotPort` — the SecretaryKit adapter behind
/// the D.5.5 "Forget This Mac" flow. The coordinator it wraps is covered by
/// `DeviceUnlockCoordinatorTests` in its own package; what is pinned HERE is the
/// adapter's own contract, previously compile-proven only: the
/// `VaultSlotError` → `VaultAccessError` translation, and the two-predicate
/// `isEnrolled` conjunction that the `DeviceSlotViewModel` lock discriminator's
/// soundness argument rests on.
final class CoordinatorDeviceSlotPortTests: XCTestCase {

    private let vaultPath = Data("fixtures/vault".utf8)
    private let deviceUuid = [UInt8](repeating: 0xAB, count: 16)

    /// Enrolled-state fixture: the enclave holds a secret AND metadata holds the
    /// slot's enrollment — the state `disenroll` exists to tear down.
    private func makeEnrolled(
        slotPort: FakeVaultDeviceSlotPort = FakeVaultDeviceSlotPort()
    ) throws -> (port: CoordinatorDeviceSlotPort,
                 slotPort: FakeVaultDeviceSlotPort,
                 enclave: InMemoryDeviceSecretEnclave,
                 metadata: InMemoryEnrollmentMetadataStore) {
        let enclave = InMemoryDeviceSecretEnclave()
        try enclave.store(secret: [UInt8](repeating: 7, count: 32))
        let metadata = InMemoryEnrollmentMetadataStore(
            enrollment: DeviceEnrollment(vaultId: "vault-1", deviceUuid: deviceUuid))
        let coordinator = DeviceUnlockCoordinator(
            slotPort: slotPort, enclave: enclave, metadata: metadata)
        return (CoordinatorDeviceSlotPort(coordinator: coordinator, vaultPath: vaultPath),
                slotPort, enclave, metadata)
    }

    // MARK: isEnrolled — the port-side predicate of the lock discriminator

    /// The port predicate is `enclave.isEnrolled && metadata != nil` while the
    /// write-reauth gate's is `enclave.isEnrolled` alone — so port-enrolled ⟹
    /// gate-live, the implication that makes `DeviceSlotViewModel.forget()`'s
    /// "`!port.isEnrolled` ⇒ lock" discriminator sound (no false negative in the
    /// dangerous direction). Pinning the conjunction pins that implication.
    func testIsEnrolledRequiresBothEnclaveSecretAndMetadata() throws {
        let both = try makeEnrolled()
        XCTAssertTrue(both.port.isEnrolled)

        // Secret but no metadata: the gate would still be live; port reads false
        // (the deliberately loose converse — over-locks, fail-safe).
        let enclaveOnly = InMemoryDeviceSecretEnclave()
        try enclaveOnly.store(secret: [UInt8](repeating: 7, count: 32))
        let noMetadata = CoordinatorDeviceSlotPort(
            coordinator: DeviceUnlockCoordinator(
                slotPort: FakeVaultDeviceSlotPort(),
                enclave: enclaveOnly,
                metadata: InMemoryEnrollmentMetadataStore()),
            vaultPath: vaultPath)
        XCTAssertFalse(noMetadata.isEnrolled)

        // Metadata but no secret — the exact post-partial-failure state (blob
        // already torn down before `disenroll` threw) that the VM locks on.
        let metadataOnly = CoordinatorDeviceSlotPort(
            coordinator: DeviceUnlockCoordinator(
                slotPort: FakeVaultDeviceSlotPort(),
                enclave: InMemoryDeviceSecretEnclave(),
                metadata: InMemoryEnrollmentMetadataStore(
                    enrollment: DeviceEnrollment(vaultId: "vault-1", deviceUuid: deviceUuid))),
            vaultPath: vaultPath)
        XCTAssertFalse(metadataOnly.isEnrolled)
    }

    // MARK: happy path

    func testForgetRemovesSlotThenClearsEnclaveAndMetadata() throws {
        let t = try makeEnrolled()

        try t.port.forgetThisDevice()

        XCTAssertEqual(t.slotPort.removedUuids, [deviceUuid])
        XCTAssertEqual(t.enclave.clearCount, 1)
        XCTAssertFalse(t.enclave.isEnrolled)
        XCTAssertEqual(t.metadata.clearCount, 1)
        XCTAssertNil(try t.metadata.load())
    }

    /// `.deviceSlotNotFound` from the vault means already-gone, not failure: the
    /// coordinator swallows it and still clears local state (the adapter's
    /// mapping arm for it is defensive only, per its comment). A cross-device
    /// race — the slot revoked elsewhere while this Mac still holds a local
    /// credential — must land here as success, or Forget could never converge.
    func testAlreadyGoneSlotIsToleratedAndStillClearsLocalState() throws {
        let t = try makeEnrolled(
            slotPort: FakeVaultDeviceSlotPort(removeError: .deviceSlotNotFound))

        try t.port.forgetThisDevice()   // must not throw

        XCTAssertFalse(t.enclave.isEnrolled)
        XCTAssertNil(try t.metadata.load())
    }

    // MARK: error mapping — the adapter's own translation table

    /// Every propagating `VaultSlotError` variant maps to its typed
    /// `VaultAccessError` (`.deviceSlotNotFound` never propagates — above). A
    /// slot-removal failure aborts BEFORE local teardown, so the credential must
    /// read intact afterwards — the "no lock" half of the VM's discriminator.
    func testSlotErrorsMapToTypedVaultAccessErrors() throws {
        let cases: [(thrown: VaultSlotError, expected: VaultAccessError)] = [
            (.wrongDeviceSecretOrCorrupt, .wrongDeviceSecretOrCorrupt),
            (.deviceUuidMismatch("uuid-detail"), .other("uuid-detail")),
            (.invalidArgument("arg-detail"), .invalidArgument("arg-detail")),
            (.other("io-detail"), .other("io-detail")),
        ]
        for c in cases {
            let t = try makeEnrolled(
                slotPort: FakeVaultDeviceSlotPort(removeError: c.thrown))

            XCTAssertThrowsError(try t.port.forgetThisDevice(), "for \(c.thrown)") {
                XCTAssertEqual($0 as? VaultAccessError, c.expected, "for \(c.thrown)")
            }
            XCTAssertTrue(t.port.isEnrolled,
                          "credential must survive a failed removal (\(c.thrown))")
        }
    }

    /// A non-`VaultSlotError` (here the enclave's `DeviceUnlockError` from
    /// `clear()`) falls through to the adapter's untyped `.other` arm rather
    /// than escaping as a foreign error type.
    func testNonSlotErrorFallsBackToOther() throws {
        let coordinator = DeviceUnlockCoordinator(
            slotPort: FakeVaultDeviceSlotPort(),
            enclave: ThrowingClearEnclave(),
            metadata: InMemoryEnrollmentMetadataStore(
                enrollment: DeviceEnrollment(vaultId: "vault-1", deviceUuid: deviceUuid)))
        let port = CoordinatorDeviceSlotPort(coordinator: coordinator, vaultPath: vaultPath)

        XCTAssertThrowsError(try port.forgetThisDevice()) {
            XCTAssertEqual(
                $0 as? VaultAccessError,
                .other(String(describing: DeviceUnlockError.enclave("clear failed"))))
        }
    }

    /// Minimal enclave whose `clear()` throws — `InMemoryDeviceSecretEnclave`
    /// has no clear-error injection, and the real store's clear CAN fail
    /// (`SecItemDelete`), so the fallback arm is a reachable path, not theory.
    private struct ThrowingClearEnclave: DeviceSecretEnclave {
        var isEnrolled: Bool { true }
        func store(secret: [UInt8]) throws {}
        func release(reason: String) async throws -> [UInt8] { [] }
        func clear() throws { throw DeviceUnlockError.enclave("clear failed") }
    }
}
