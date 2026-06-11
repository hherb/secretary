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

    func testEnrollMapsAddSlotErrorAndDoesNotRollBack() throws {
        // When minting the slot itself fails, there is nothing to roll back
        // (no slot, no stored secret) and the VaultSlotError is mapped to a
        // typed DeviceUnlockError through `mapSlotErrors`.
        let port = FakeVaultDeviceSlotPort(addResult: .failure(.invalidArgument("bad path")))
        let enclave = InMemoryDeviceSecretEnclave()
        let metadata = InMemoryEnrollmentMetadataStore()
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: metadata)

        XCTAssertThrowsError(try coord.enroll(vaultPath: vaultPath, vaultId: "v1", password: [0x50])) { err in
            XCTAssertEqual(err as? DeviceUnlockError, .vault(.invalidArgument("bad path")))
        }
        XCTAssertTrue(port.removedUuids.isEmpty, "nothing to roll back when add itself fails")
        XCTAssertFalse(enclave.isEnrolled)
        XCTAssertNil(try metadata.load())
    }

    // MARK: unlock

    private func enrolledMetadata(vaultId: String = "v1") -> InMemoryEnrollmentMetadataStore {
        InMemoryEnrollmentMetadataStore(enrollment: DeviceEnrollment(vaultId: vaultId, deviceUuid: uuid))
    }

    // NB: zeroization of the released secret is not asserted here — the fake
    // port records a *value copy* of deviceSecret, so the coordinator's
    // best-effort `defer { zeroize(&secret) }` of its own local is not
    // observable at this boundary. The defer is guaranteed to run on every exit
    // by construction; we assert the right bytes reached the port, not the wipe.
    func testUnlockHappyPathOpensVault() async throws {
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
        let enclave = InMemoryDeviceSecretEnclave(); try! enclave.store(secret: secret)
        let coord = makeCoordinator(port: FakeVaultDeviceSlotPort(), enclave: enclave,
                                    metadata: enrolledMetadata(vaultId: "v1"))
        await assertThrowsDeviceUnlock(.vaultSlotMismatch) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "DIFFERENT", reason: "x")
        }
    }

    func testUnlockMapsDeviceSlotNotFoundToMismatch() async {
        let port = FakeVaultDeviceSlotPort(openResult: .failure(.deviceSlotNotFound))
        let enclave = InMemoryDeviceSecretEnclave(); try! enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.vaultSlotMismatch) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockSurfacesWrongDeviceSecretOrCorrupt() async {
        let port = FakeVaultDeviceSlotPort(openResult: .failure(.wrongDeviceSecretOrCorrupt))
        let enclave = InMemoryDeviceSecretEnclave(); try! enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.wrongDeviceSecretOrCorrupt) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockPassesThroughOtherVaultError() async {
        let port = FakeVaultDeviceSlotPort(openResult: .failure(.other("disk gone")))
        let enclave = InMemoryDeviceSecretEnclave(); try! enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.vault(.other("disk gone"))) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockSurfacesDeviceUuidMismatchAsVault() async {
        // A header/filename uuid mismatch from the FFI must be surfaced honestly
        // (as .vault), not swallowed — it can signal a tampered/relabelled wrap.
        let port = FakeVaultDeviceSlotPort(openResult: .failure(.deviceUuidMismatch("hdr!=name")))
        let enclave = InMemoryDeviceSecretEnclave(); try! enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())
        await assertThrowsDeviceUnlock(.vault(.deviceUuidMismatch("hdr!=name"))) {
            _ = try await coord.unlock(vaultPath: self.vaultPath, vaultId: "v1", reason: "x")
        }
    }

    func testUnlockPropagatesBiometricError() async {
        let enclave = InMemoryDeviceSecretEnclave(); try! enclave.store(secret: secret)
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

    func testDisenrollPropagatesNonNotFoundRemoveError() throws {
        // The catch is intentionally narrow: only deviceSlotNotFound is tolerated.
        // Any other remove failure must propagate, NOT be swallowed (guards against
        // a future `catch { }` that would hide a real revocation failure).
        let port = FakeVaultDeviceSlotPort(removeError: .other("disk full"))
        let enclave = InMemoryDeviceSecretEnclave(); try enclave.store(secret: secret)
        let coord = makeCoordinator(port: port, enclave: enclave, metadata: enrolledMetadata())

        XCTAssertThrowsError(try coord.disenroll(vaultPath: vaultPath)) { err in
            XCTAssertEqual(err as? VaultSlotError, .other("disk full"))
        }
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
}
