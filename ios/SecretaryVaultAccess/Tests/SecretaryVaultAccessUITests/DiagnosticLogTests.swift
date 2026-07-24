import XCTest
@testable import SecretaryVaultAccessUI

/// An error whose `String(describing:)` is an exact, known sentinel — so the
/// formatter's output can be asserted byte-for-byte (proving no other content,
/// e.g. `.localizedDescription`, leaks into the logged line).
private struct SentinelError: Error, CustomStringConvertible {
    let description: String
}

final class DiagnosticLogTests: XCTestCase {
    func testDiagnosticIncludesUnderlyingDescription() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "UNDERLYING-BOOM"),
            fileID: "F.swift", function: "f()", line: 1
        )
        XCTAssertTrue(out.contains("UNDERLYING-BOOM"))
    }

    func testDiagnosticIncludesSite() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "x"),
            fileID: "Foo.swift", function: "bar()", line: 99
        )
        XCTAssertTrue(out.contains("Foo.swift"))
        XCTAssertTrue(out.contains("99"))
        XCTAssertTrue(out.contains("bar()"))
    }

    /// SECURITY (#456): the formatted line contains ONLY the site identifiers and
    /// `String(describing: underlying)` — nothing else. Byte-exact equality is the
    /// enforcement that the logged content stays diagnostic-only.
    func testDiagnosticIsSiteAndDescriptionOnly() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "DIAG-SENTINEL-9F3A"),
            fileID: "MyFile.swift", function: "myFunc()", line: 42
        )
        XCTAssertEqual(out, "[MyFile.swift:42 myFunc()] DIAG-SENTINEL-9F3A")
    }
}
