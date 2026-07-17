import XCTest
import SecretaryVaultAccess

final class VaultSelectionErrorTests: XCTestCase {
    func testErrorIsEquatable() {
        XCTAssertEqual(VaultSelectionError.noVaultSelected, .noVaultSelected)
        XCTAssertEqual(VaultSelectionError.locationUnavailable("x"),
                       .locationUnavailable("x"))
        XCTAssertNotEqual(VaultSelectionError.locationUnavailable("x"),
                          .locationUnavailable("y"))
    }

    private static let oneOfEachCase: [VaultSelectionError] = [
        .noVaultSelected, .locationUnavailable("/moved"),
    ]

    // #454: friendly, non-nil `errorDescription` per case so `localizedDescription`
    // never falls back to the raw case name or the Foundation default. See the
    // matching VaultAccessError tests for the `as? LocalizedError` RED rationale.
    func testEveryCaseSurfacesAFriendlyDescription() {
        for e in Self.oneOfEachCase {
            let desc = (e as? LocalizedError)?.errorDescription
            XCTAssertNotNil(desc, "case \(e) must have a friendly errorDescription")
            guard let desc else { continue }
            XCTAssertFalse(desc.isEmpty, "case \(e) description must not be empty")
            XCTAssertFalse(desc.contains("locationUnavailable"), "case \(e) leaks a raw case name")
            XCTAssertFalse(desc.contains("VaultSelectionError"), "case \(e) leaks the type name")
        }
    }

    func testLocalizedDescriptionUsesErrorDescription() {
        for e in Self.oneOfEachCase {
            XCTAssertEqual(e.localizedDescription, (e as? LocalizedError)?.errorDescription,
                           "localizedDescription must delegate to errorDescription for \(e)")
        }
    }
}
