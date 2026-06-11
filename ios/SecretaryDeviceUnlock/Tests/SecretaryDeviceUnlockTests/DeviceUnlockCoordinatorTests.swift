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
