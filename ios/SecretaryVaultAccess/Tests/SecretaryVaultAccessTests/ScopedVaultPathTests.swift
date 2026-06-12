import XCTest
import SecretaryVaultAccess

final class ScopedVaultPathTests: XCTestCase {
    func testExposesPathData() {
        let scoped = ScopedVaultPath(pathData: Data("/vaults/v1".utf8), onEnd: {})
        XCTAssertEqual(scoped.pathData, Data("/vaults/v1".utf8))
    }

    func testEndReleasesExactlyOnce() {
        var releases = 0
        let scoped = ScopedVaultPath(pathData: Data(), onEnd: { releases += 1 })
        scoped.end()
        scoped.end() // idempotent — must not double-release
        XCTAssertEqual(releases, 1)
    }

    func testDeinitReleasesWhenEndNotCalled() {
        var releases = 0
        do {
            _ = ScopedVaultPath(pathData: Data(), onEnd: { releases += 1 })
        } // handle dropped here without end()
        XCTAssertEqual(releases, 1, "deinit must release a scope whose end() was never called")
    }

    func testExplicitEndThenDeinitReleasesExactlyOnce() {
        var releases = 0
        do {
            let scoped = ScopedVaultPath(pathData: Data(), onEnd: { releases += 1 })
            scoped.end()
        } // deinit runs here; must NOT release again
        XCTAssertEqual(releases, 1)
    }
}
