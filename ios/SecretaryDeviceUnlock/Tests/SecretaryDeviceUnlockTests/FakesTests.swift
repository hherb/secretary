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
        _ = try port.addDeviceSlot(vaultPath: Data("/v".utf8), password: [0x70])
        XCTAssertEqual(port.addCalls, 1)
        XCTAssertEqual(port.addCalledWith?.vaultPath, Data("/v".utf8))
        XCTAssertEqual(port.addCalledWith?.password, [0x70])
        XCTAssertThrowsError(try port.removeDeviceSlot(vaultPath: Data(), deviceUuid: [1])) { err in
            XCTAssertEqual(err as? VaultSlotError, .deviceSlotNotFound)
        }
        XCTAssertEqual(port.removedUuids, [[1]])
    }

    func testFakeOpenedVaultCountsWipes() {
        let opened = FakeOpenedVault(vaultUuid: [0xAA, 0xBB])
        XCTAssertEqual(opened.vaultUuid, [0xAA, 0xBB])
        XCTAssertEqual(opened.wipeCount, 0)
        opened.wipe()
        opened.wipe()
        XCTAssertEqual(opened.wipeCount, 2)
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
