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

    func testErrorIsEquatable() {
        XCTAssertEqual(VaultSelectionError.noVaultSelected, .noVaultSelected)
        XCTAssertEqual(VaultSelectionError.locationUnavailable("x"),
                       .locationUnavailable("x"))
        XCTAssertNotEqual(VaultSelectionError.locationUnavailable("x"),
                          .locationUnavailable("y"))
    }
}
