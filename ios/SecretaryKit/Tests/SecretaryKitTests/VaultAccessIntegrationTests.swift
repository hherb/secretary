import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Drives the real folder-in open + read_block FFI on a simulator against a
/// writable copy of golden_vault_001. Asserts the open yields the pinned vault
/// UUID, blocks enumerate, a block reads, a text field reveals non-empty
/// plaintext ONLY when asked, recovery opens the same vault, and a wrong
/// password surfaces the conflated `.wrongPasswordOrCorrupt`.
final class VaultAccessIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private let goldenRecovery = "wall annual clay zebra cost cricket choose light small neck mimic season fix situate love asset dismiss online island disease turkey grab dish that"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-va-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }

    private var path: Data { Data(vaultCopy.path.utf8) }

    func testPasswordOpenBrowseAndRevealOnDemand() throws {
        let port = UniffiVaultOpenPort()
        let session = try port.openWithPassword(vaultPath: path, password: [UInt8](goldenPassword.utf8))
        defer { session.wipe() }

        XCTAssertEqual(session.vaultUuidHex, try goldenPinnedVaultUuidHex())

        let blocks = session.blockSummaries()
        XCTAssertFalse(blocks.isEmpty, "golden vault has at least one block")

        let records = try session.readBlock(blockUuid: blocks[0].uuid, includeDeleted: false)
        XCTAssertFalse(records.isEmpty, "the first block has at least one record")

        let textField = try XCTUnwrap(
            records.flatMap(\.fields).first(where: { $0.kind == .text }),
            "expected at least one text field in the login record")
        guard case .text(let plaintext) = try textField.reveal() else {
            return XCTFail("text field did not reveal text")
        }
        XCTAssertFalse(plaintext.isEmpty)
    }

    func testRecoveryOpensSameVault() throws {
        let port = UniffiVaultOpenPort()
        let session = try port.openWithRecovery(vaultPath: path, phrase: [UInt8](goldenRecovery.utf8))
        defer { session.wipe() }
        XCTAssertEqual(session.vaultUuidHex, try goldenPinnedVaultUuidHex())
    }

    func testWrongPasswordSurfacesConflatedVariant() {
        let port = UniffiVaultOpenPort()
        XCTAssertThrowsError(
            try port.openWithPassword(vaultPath: path, password: [UInt8]("definitely wrong".utf8))
        ) { err in
            XCTAssertEqual(err as? VaultAccessError, .wrongPasswordOrCorrupt,
                           "wrong password must be indistinguishable from corruption (anti-oracle)")
        }
    }
}
