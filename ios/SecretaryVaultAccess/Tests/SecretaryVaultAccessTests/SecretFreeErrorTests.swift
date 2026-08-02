import XCTest
@testable import SecretaryVaultAccess

/// Conforming, wholly safe: its `String(describing:)` is a known sentinel so the
/// DEFAULT rendering can be asserted byte-exactly.
private struct SafeSentinel: SecretFreeError, CustomStringConvertible {
    let description: String
}

/// Conforming but REDACTING at source: `String(describing:)` would expose the
/// secret; `diagnosticDescription` must not. This is the case that distinguishes
/// a rendering protocol from a bare marker.
private struct PartiallySafe: SecretFreeError, CustomStringConvertible {
    let secret: String
    var description: String { "PartiallySafe(secret: \(secret))" }
    var diagnosticDescription: String { "PartiallySafe(secret: <redacted>)" }
}

/// NON-conforming and secret-bearing — the exact case #467 exists to stop.
private struct UnreviewedSecretBearing: Error, CustomStringConvertible {
    let secret: String
    var description: String { "UnreviewedSecretBearing(secret: \(secret))" }
}

final class SecretFreeErrorTests: XCTestCase {
    /// A conformer with no override renders its full Swift description.
    func testConformerRendersFullDescriptionByDefault() {
        XCTAssertEqual(diagnosticDetail(SafeSentinel(description: "SAFE-7C1D")), "SAFE-7C1D")
    }

    /// SECURITY (#467): an explicit `diagnosticDescription` WINS over
    /// `String(describing:)`. Without this, sanitize-at-source would be
    /// decorative and the protocol would be a bare marker.
    func testCustomDiagnosticDescriptionWinsOverDescription() {
        let e = PartiallySafe(secret: "SECRET-4B2E")
        XCTAssertEqual(diagnosticDetail(e), "PartiallySafe(secret: <redacted>)")
        XCTAssertFalse(diagnosticDetail(e).contains("SECRET-4B2E"))
    }

    /// SECURITY (#467): the core leak assertion. An unreviewed type is NEVER
    /// described, so a future secret-bearing error cannot reach a `.public` line.
    func testUnreviewedErrorIsNeverDescribed() {
        let out = diagnosticDetail(UnreviewedSecretBearing(secret: "SECRET-9A03"))
        XCTAssertFalse(out.contains("SECRET-9A03"))
        XCTAssertTrue(out.hasPrefix("<undisclosed UnreviewedSecretBearing "),
                      "expected the default-deny marker, got: \(out)")
    }

    /// SECURITY (#467): `userInfo` is never read — it is the only part of an
    /// `NSError` that can carry arbitrary caller-supplied content. `domain` and
    /// `code` ARE emitted so the marker stays actionable.
    func testNSErrorUserInfoIsNotRendered() {
        let e = NSError(domain: "TestDomain", code: 42,
                        userInfo: ["leak": "SECRET-USERINFO-11B7"])
        let out = diagnosticDetail(e)
        XCTAssertFalse(out.contains("SECRET-USERINFO-11B7"))
        XCTAssertTrue(out.contains("domain=TestDomain"))
        XCTAssertTrue(out.contains("code=42"))
    }

    /// The five in-package conformances. A conformance silently removed would
    /// degrade every log line for that type to `<undisclosed …>` — safe, but a
    /// diagnostic regression nobody would notice without this test.
    func testInPackageConformancesHold() {
        XCTAssertTrue(VaultAccessError.other("x") is SecretFreeError)
        XCTAssertTrue(VaultSyncError.inProgress is SecretFreeError)
        XCTAssertTrue(VaultSelectionError.noVaultSelected is SecretFreeError)
        XCTAssertTrue(DeviceUuidStoreError.corruptLength(3) is SecretFreeError)
        XCTAssertTrue(CancellationError() is SecretFreeError)
    }
}
