import XCTest
@testable import SecretaryKit

/// Proves `secretary-core` runs through the uniffi bindings on an iOS
/// simulator: opens the golden vault with its known password and asserts the
/// returned vault UUID matches the value pinned in the fixture's inputs JSON.
final class OpenVaultLinkTests: XCTestCase {
    /// golden_vault_001's password (see core/tests/data/golden_vault_001_inputs.json).
    private let goldenPassword = "correct horse battery staple"

    /// A writable per-test copy of the read-only golden-vault fixture.
    /// Opening a vault may write vault-stored settings, so we never open the
    /// bundled fixture in place.
    private var vaultCopy: URL!

    override func setUpWithError() throws {
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh"
        )
        let tmp = FileManager.default.temporaryDirectory
            .appendingPathComponent("gv-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        vaultCopy = tmp.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultCopy)
    }

    override func tearDownWithError() throws {
        if let vaultCopy { try? FileManager.default.removeItem(at: vaultCopy.deletingLastPathComponent()) }
    }

    /// Happy path: full on-device crypto+FFI round-trip.
    func testOpenGoldenVaultOnDevice() throws {
        let folderPath = Data(vaultCopy.path.utf8)
        let out = try openVaultWithPassword(folderPath: folderPath,
                                            password: Data(goldenPassword.utf8))
        defer { out.manifest.wipe(); out.identity.wipe() }

        let expected = try pinnedVaultUuid()
        XCTAssertEqual(out.manifest.vaultUuid(), expected,
                       "on-device vault UUID must match the pinned fixture value")
        XCTAssertGreaterThan(out.manifest.blockCount(), 0,
                             "golden_vault_001 has at least one block")
    }

    /// Negative: a wrong password surfaces the typed error across the FFI.
    func testWrongPasswordSurfacesTypedError() throws {
        let folderPath = Data(vaultCopy.path.utf8)
        XCTAssertThrowsError(
            try openVaultWithPassword(folderPath: folderPath,
                                      password: Data("definitely wrong".utf8))
        ) { error in
            guard case VaultError.WrongPasswordOrCorrupt = error else {
                return XCTFail("expected VaultError.WrongPasswordOrCorrupt, got \(error)")
            }
        }
    }

    /// Read the pinned `vault_uuid` from the bundled inputs JSON and decode the
    /// dashed hex string to 16 bytes. Keeps core/tests/data the single source
    /// of truth (no hardcoded byte array).
    private func pinnedVaultUuid() throws -> Data {
        let url = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001_inputs", withExtension: "json")
        )
        let json = try JSONSerialization.jsonObject(with: Data(contentsOf: url))
        let dict = try XCTUnwrap(json as? [String: Any])
        let dashed = try XCTUnwrap(dict["vault_uuid"] as? String)
        let hex = dashed.replacingOccurrences(of: "-", with: "")
        var bytes = [UInt8]()
        var i = hex.startIndex
        while i < hex.endIndex {
            // `limitedBy:` returns nil (→ a clean XCTUnwrap failure) on an
            // odd-length string rather than trapping past endIndex.
            let j = try XCTUnwrap(hex.index(i, offsetBy: 2, limitedBy: hex.endIndex),
                                  "vault_uuid hex must have an even number of digits")
            bytes.append(try XCTUnwrap(UInt8(hex[i..<j], radix: 16)))
            i = j
        }
        XCTAssertEqual(bytes.count, 16, "vault UUID must decode to 16 bytes")
        return Data(bytes)
    }
}
