import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakesTests: XCTestCase {
    func testFakeSessionCountsReadsAndWipesAndDefersReveal() throws {
        var revealCalls = 0
        let field = FieldView(name: "password", kind: .text) {
            revealCalls += 1
            return .text("s3cret")
        }
        let rec = RecordView(uuid: Array(repeating: 1, count: 16),
                             type: "login", tags: [], fields: [field])
        let session = FakeVaultSession(
            vaultUuidHex: "ab",
            blocks: [BlockSummary(uuid: [9], name: "B", createdAtMs: 0, lastModMs: 0)],
            recordsByBlock: [[9]: [rec]])

        XCTAssertEqual(session.blockSummaries().count, 1)
        // Reveal closure must NOT have fired just by reading the block.
        let records = try session.readBlock(blockUuid: [9], includeDeleted: false)
        XCTAssertEqual(session.readCount, 1)
        XCTAssertEqual(revealCalls, 0, "reveal must be on-demand only")
        // Firing reveal explicitly works and is counted by the closure.
        XCTAssertEqual(try records[0].fields[0].reveal(), .text("s3cret"))
        XCTAssertEqual(revealCalls, 1)

        session.wipe()
        session.wipe()
        XCTAssertEqual(session.wipeCount, 2)
    }

    func testFakeSessionReadUnknownBlockThrows() {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        XCTAssertThrowsError(try session.readBlock(blockUuid: [0xde], includeDeleted: false)) { err in
            XCTAssertEqual(err as? VaultAccessError, .blockNotFound("de"))
        }
    }

    func testFakeOpenPortRoutesPasswordAndRecovery() async throws {
        let session = FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
        let port = FakeVaultOpenPort(passwordResult: .success(session),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        let opened = try await port.openWithPassword(vaultPath: Data(), password: [1])
        XCTAssertTrue(opened === session)
        do {
            _ = try await port.openWithRecovery(vaultPath: Data(), phrase: [1])
            XCTFail("expected recovery to throw")
        } catch {
            XCTAssertEqual(error as? VaultAccessError, .wrongMnemonicOrCorrupt)
        }
    }
}
