import XCTest
import SecretaryVaultAccess
@testable import SecretaryKit

/// #251: navigating to another block must evict the prior block's decrypted
/// plaintext (a stale reveal closure must stop yielding plaintext), and
/// re-selecting the same block must not accumulate. Reads the single golden
/// block twice — proves eviction + dedup together.
final class RevealResidencyIntegrationTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        let tmp = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("res-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent())
    }

    func testNavigatingAwayEvictsPriorBlockPlaintext() async throws {
        let port = UniffiVaultOpenPort()
        let path = Data(vaultCopy.path.utf8)
        let session = try await port.openWithPassword(
            vaultPath: path, password: [UInt8](goldenPassword.utf8))
        defer { session.wipe() }

        let blocks = session.blockSummaries()
        let blockUuid = try XCTUnwrap(blocks.first?.uuid, "golden vault has one block")

        // First read: capture a reveal closure from this block's first revealable field.
        let firstRecords = try session.readBlock(blockUuid: blockUuid, includeDeleted: false)
        let staleField = try XCTUnwrap(
            firstRecords.flatMap(\.fields).first, "block has at least one field")
        _ = try staleField.reveal()  // sanity: reveals before we navigate away

        // Navigate (re-read the same block — the only one). The fix wipes the prior
        // BlockReadOutput, which cascades to the captured FieldHandle.
        _ = try session.readBlock(blockUuid: blockUuid, includeDeleted: false)

        // Pre-fix: the prior block stays in `openBlocks`, so this still yields plaintext.
        // Post-fix: the prior block was wiped, so reveal() throws.
        XCTAssertThrowsError(try staleField.reveal(),
            "stale reveal closure must fail after navigating away (block evicted)")
    }
}
