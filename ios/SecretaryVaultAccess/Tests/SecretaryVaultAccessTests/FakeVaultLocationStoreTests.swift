import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeVaultLocationStoreTests: XCTestCase {
    func testPersistLoadClearRoundTrip() {
        let store = FakeVaultLocationStore()
        XCTAssertNil(store.load())
        let loc = VaultLocation(displayName: "V", bookmark: Data([0x01]))
        store.persist(loc)
        XCTAssertEqual(store.load(), loc)
        store.clear()
        XCTAssertNil(store.load())
    }

    func testBeginAccessCountsStartAndScopedEndCountsStop() throws {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data([0x01])),
            pathDataToReturn: Data("/fake/v".utf8))
        let scoped = try store.beginAccess(store.load()!)  // stored set in init — unwrap is safe
        XCTAssertEqual(scoped.pathData, Data("/fake/v".utf8))
        XCTAssertEqual(store.started, 1)
        XCTAssertEqual(store.stopped, 0)
        XCTAssertEqual(store.liveScopes, 1)
        scoped.end()
        scoped.end() // idempotent
        XCTAssertEqual(store.stopped, 1)
        XCTAssertEqual(store.liveScopes, 0)
    }

    func testBeginAccessThrowsSeededError() {
        let store = FakeVaultLocationStore(
            stored: VaultLocation(displayName: "V", bookmark: Data()))
        store.beginAccessError = .locationUnavailable("gone")
        XCTAssertThrowsError(try store.beginAccess(store.load()!)) { err in  // stored set in init
            XCTAssertEqual(err as? VaultSelectionError, .locationUnavailable("gone"))
        }
        XCTAssertEqual(store.started, 0, "a thrown beginAccess must not count a start")
    }
}
