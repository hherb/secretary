import XCTest
@testable import SecretaryVaultAccess

final class FileVaultLocationStoreTests: XCTestCase {
    /// Each test gets an isolated UserDefaults suite so nothing touches `.standard`.
    private func makeStore() -> FileVaultLocationStore {
        let suite = "test.filevaultstore.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        return FileVaultLocationStore(defaults: defaults)
    }

    func testLoadReturnsNilWhenEmpty() {
        XCTAssertNil(makeStore().load())
    }

    func testPersistThenLoadRoundTrips() {
        let store = makeStore()
        let loc = VaultLocation(displayName: "Personal", bookmark: Data("/vaults/personal".utf8))
        store.persist(loc)
        let loaded = store.load()
        XCTAssertEqual(loaded?.displayName, "Personal")
        XCTAssertEqual(loaded.map { String(decoding: $0.bookmark, as: UTF8.self) }, "/vaults/personal")
    }

    func testPersistReplacesPriorLocation() {
        let store = makeStore()
        store.persist(VaultLocation(displayName: "A", bookmark: Data("/a".utf8)))
        store.persist(VaultLocation(displayName: "B", bookmark: Data("/b".utf8)))
        XCTAssertEqual(store.load()?.displayName, "B")
        XCTAssertEqual(store.load().map { String(decoding: $0.bookmark, as: UTF8.self) }, "/b")
    }

    func testClearForgetsLocation() {
        let store = makeStore()
        store.persist(VaultLocation(displayName: "A", bookmark: Data("/a".utf8)))
        store.clear()
        XCTAssertNil(store.load())
    }

    func testBeginAccessReturnsNoOpScopedPath() throws {
        let store = makeStore()
        let loc = VaultLocation(displayName: "A", bookmark: Data("/some/vault".utf8))
        let scoped = try store.beginAccess(loc)
        XCTAssertEqual(String(decoding: scoped.pathData, as: UTF8.self), "/some/vault")
        // No-op scope: end() must be safe and idempotent (no crash on double-end).
        scoped.end()
        scoped.end()
    }
}
