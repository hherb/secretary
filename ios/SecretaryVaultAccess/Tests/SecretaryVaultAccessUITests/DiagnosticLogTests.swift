import XCTest
import SecretaryVaultAccess
@testable import SecretaryVaultAccessUI

/// A CONFORMING error whose `String(describing:)` is an exact sentinel — so the
/// formatter's output can be asserted byte-for-byte (proving no other content,
/// e.g. `.localizedDescription`, leaks into the logged line).
private struct SentinelError: SecretFreeError, CustomStringConvertible {
    let description: String
}

/// A NON-conforming, secret-bearing error — proves the fold seam inherits the
/// default-deny policy rather than re-implementing its own rendering.
private struct UnreviewedSecretBearing: Error, CustomStringConvertible {
    let secret: String
    var description: String { "UnreviewedSecretBearing(secret: \(secret))" }
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
    /// the gated detail — nothing else. Byte-exact equality is the enforcement
    /// that the logged content stays diagnostic-only.
    func testDiagnosticIsSiteAndDetailOnly() {
        let out = foldedErrorDiagnostic(
            underlying: SentinelError(description: "DIAG-SENTINEL-9F3A"),
            fileID: "MyFile.swift", function: "myFunc()", line: 42
        )
        XCTAssertEqual(out, "[MyFile.swift:42 myFunc()] DIAG-SENTINEL-9F3A")
    }

    /// SECURITY (#467): the formatter renders through `diagnosticDetail`, so an
    /// unreviewed type is not described here either. The seam does NOT get its
    /// own rendering policy.
    func testFormatterAppliesDefaultDeny() {
        let out = foldedErrorDiagnostic(
            underlying: UnreviewedSecretBearing(secret: "SECRET-2D77"),
            fileID: "F.swift", function: "f()", line: 7
        )
        XCTAssertFalse(out.contains("SECRET-2D77"))
        XCTAssertTrue(out.contains("<undisclosed UnreviewedSecretBearing "))
    }

    /// SECURITY (#467): `foldDiagnostic` returns the SAME gated string it logs,
    /// which is what makes the log line and the carried payload unable to
    /// disagree at a fold site.
    func testFoldDiagnosticReturnsTheGatedDetail() {
        let returned = foldDiagnostic(UnreviewedSecretBearing(secret: "SECRET-5E19"))
        XCTAssertFalse(returned.contains("SECRET-5E19"))
        XCTAssertTrue(returned.contains("<undisclosed UnreviewedSecretBearing "))
    }

    /// A conformer round-trips its description through `foldDiagnostic` unchanged
    /// (the site prefix is on the LOG line, not on the returned payload).
    func testFoldDiagnosticReturnsDescriptionForConformer() {
        XCTAssertEqual(foldDiagnostic(SentinelError(description: "OK-1B4C")), "OK-1B4C")
    }
}
