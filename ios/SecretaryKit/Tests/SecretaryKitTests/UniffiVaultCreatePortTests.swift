import XCTest
import SecretaryVaultAccess
@testable import SecretaryKit

final class UniffiVaultCreatePortTests: XCTestCase {
    /// Create a vault in a fresh tempdir parent, then open it by password and
    /// assert the display name round-trips. NEVER touches the bundled golden
    /// fixture — a unique tempdir, not even a copy.
    func testCreateThenOpenRoundTrips() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }

        let port = UniffiVaultCreatePort()
        let password = Array("create-test-pw".utf8)
        var created = try port.create(parent: parent,
                                      vaultName: "v1",
                                      password: password,
                                      displayName: "Sim-Owner")
        defer { created.phrase.replaceSubrange(created.phrase.indices, with: repeatElement(0, count: created.phrase.count)) }

        // 24-word recovery phrase.
        let words = String(decoding: created.phrase, as: UTF8.self)
            .split(whereSeparator: { $0.isWhitespace })
        XCTAssertEqual(words.count, 24)

        // Re-open the created folder by password → display name round-trips.
        let folder = parent.appendingPathComponent("v1", isDirectory: true)
        let out = try SecretaryKit.openVaultWithPassword(
            folderPath: Data(folder.path.utf8), password: Data(password))
        defer { out.identity.wipe() }
        defer { out.manifest.wipe() }
        XCTAssertEqual(out.identity.displayName(), "Sim-Owner")
    }

    func testCreateIntoExistingNonEmptyNameThrowsFolderNotEmpty() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("create-collide-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }
        // Pre-create the subfolder so the port's mkdir hits an existing dir.
        try FileManager.default.createDirectory(
            at: parent.appendingPathComponent("v1", isDirectory: true),
            withIntermediateDirectories: false)

        XCTAssertThrowsError(try UniffiVaultCreatePort().create(
            parent: parent, vaultName: "v1", password: [1, 2, 3], displayName: "X")) {
            XCTAssertEqual($0 as? VaultProvisioningError, .folderNotEmpty)
        }
    }

    func testShapeProbeDetectsVault() throws {
        let parent = FileManager.default.temporaryDirectory
            .appendingPathComponent("probe-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: parent) }

        let probe = FileManagerVaultShapeProbe()
        XCTAssertFalse(try probe.looksLikeVault(parent))             // empty → not a vault
        let folder = parent.appendingPathComponent("v1", isDirectory: true)
        _ = try UniffiVaultCreatePort().create(
            parent: parent, vaultName: "v1", password: Array("pw".utf8), displayName: "O")
        XCTAssertTrue(try probe.looksLikeVault(folder))              // now has vault.toml
    }
}
