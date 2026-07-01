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
