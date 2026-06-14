import XCTest
@testable import SecretaryKit
import SecretaryVaultAccess

/// Exercises the REAL Foundation bookmark + security-scope round-trip on a
/// simulator, then proves a *bookmarked* path opens the golden vault identically
/// to a staged path. Uses an ephemeral UserDefaults suite so it never touches the
/// app's real defaults.
final class BookmarkVaultLocationStoreTests: XCTestCase {
    private let goldenPassword = "correct horse battery staple"
    private var suiteName: String!
    private var defaults: UserDefaults!
    private var tmpRoot: URL!
    private var vaultURL: URL!

    override func setUpWithError() throws {
        suiteName = "test.bookmarkstore.\(UUID().uuidString)"
        defaults = try XCTUnwrap(UserDefaults(suiteName: suiteName))
        let bundled = try XCTUnwrap(
            Bundle.module.url(forResource: "golden_vault_001", withExtension: nil),
            "golden_vault_001 not bundled — run ios/scripts/build-xcframework.sh")
        tmpRoot = FileManager.default.temporaryDirectory
            .appendingPathComponent("bm-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: tmpRoot, withIntermediateDirectories: true)
        vaultURL = tmpRoot.appendingPathComponent("golden_vault_001", isDirectory: true)
        try FileManager.default.copyItem(at: bundled, to: vaultURL)
    }

    override func tearDownWithError() throws {
        defaults.removePersistentDomain(forName: suiteName)
        if let tmpRoot { try? FileManager.default.removeItem(at: tmpRoot) }
    }

    private func makeStore() -> BookmarkVaultLocationStore {
        BookmarkVaultLocationStore(defaults: defaults)
    }

    func testLoadNilWhenNothingPersisted() {
        XCTAssertNil(makeStore().load())
    }

    func testPersistLoadClearRoundTrip() throws {
        let store = makeStore()
        let bookmark = try vaultURL.bookmarkData()
        let loc = VaultLocation(displayName: "golden_vault_001", bookmark: bookmark)
        store.persist(loc)
        XCTAssertEqual(store.load(), loc)
        store.clear()
        XCTAssertNil(store.load())
    }

    func testBeginAccessResolvesToFolderAndOpensGoldenVault() async throws {
        let store = makeStore()
        let bookmark = try vaultURL.bookmarkData()
        store.persist(VaultLocation(displayName: "golden_vault_001", bookmark: bookmark))

        let scoped = try store.beginAccess(XCTUnwrap(store.load()))
        defer { scoped.end() }

        let resolvedPath = String(decoding: scoped.pathData, as: UTF8.self)
        XCTAssertTrue(resolvedPath.hasSuffix("golden_vault_001"),
                      "resolved \(resolvedPath)")

        let port = UniffiVaultOpenPort()
        let session = try await port.openWithPassword(
            vaultPath: scoped.pathData, password: [UInt8](goldenPassword.utf8))
        defer { session.wipe() }
        XCTAssertEqual(session.vaultUuidHex, try goldenPinnedVaultUuidHex())
    }

    func testBeginAccessUnresolvableBookmarkThrowsLocationUnavailable() {
        let store = makeStore()
        let garbage = VaultLocation(displayName: "x", bookmark: Data([0x00, 0x01, 0x02, 0x03]))
        XCTAssertThrowsError(try store.beginAccess(garbage)) { err in
            guard case VaultSelectionError.locationUnavailable = err else {
                return XCTFail("expected .locationUnavailable, got \(err)")
            }
        }
    }
}
