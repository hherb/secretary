import XCTest
@testable import SecretaryVaultAccess

final class VaultAccessErrorTests: XCTestCase {
    // The two credential-or-corrupt cases are DISTINCT cases per credential type
    // but neither distinguishes "wrong credential" from "corrupt vault" — that
    // conflation is the anti-oracle property and must NOT be split further.
    func testCredentialOrCorruptCasesAreEquatableAndDistinct() {
        XCTAssertEqual(VaultAccessError.wrongPasswordOrCorrupt, .wrongPasswordOrCorrupt)
        XCTAssertEqual(VaultAccessError.wrongMnemonicOrCorrupt, .wrongMnemonicOrCorrupt)
        XCTAssertNotEqual(VaultAccessError.wrongPasswordOrCorrupt, .wrongMnemonicOrCorrupt)
    }

    func testAssociatedValueCasesCarryDetail() {
        XCTAssertEqual(VaultAccessError.corruptVault("x"), .corruptVault("x"))
        XCTAssertNotEqual(VaultAccessError.blockNotFound("a"), .blockNotFound("b"))
    }

    func testDifferentCasesWithSameDetailAreNotEqual() {
        // Two distinct cases carrying identical detail must differ — the case
        // discriminant is part of equality, not just the associated value.
        XCTAssertNotEqual(VaultAccessError.invalidMnemonic("bad"), .corruptVault("bad"))
        XCTAssertNotEqual(VaultAccessError.blockNotFound("x"), .invalidArgument("x"))
        XCTAssertNotEqual(VaultAccessError.folderInvalid("y"), .other("y"))
    }

    // One representative value per case — the single source the description tests
    // iterate over. Keeping it exhaustive means a newly-added case that forgets a
    // friendly description is caught here (add its sample and the loop asserts it).
    private static let oneOfEachCase: [VaultAccessError] = [
        .wrongPasswordOrCorrupt, .wrongMnemonicOrCorrupt, .invalidMnemonic("bad words"),
        .wrongDeviceSecretOrCorrupt, .vaultMismatch, .corruptVault("blk"),
        .blockNotFound("blk"), .recordNotFound("rec"), .invalidArgument("arg"),
        .folderInvalid("/path"), .reauthFailed("cancelled"), .other("boom"),
    ]

    // #454: every case must surface a friendly, non-nil `errorDescription`, so a
    // user-facing `localizedDescription` never falls back to the raw enum-case name
    // (`String(describing:)`) or the "The operation couldn't be completed" default.
    // `as? LocalizedError` compiles before the conformance exists (yielding nil at
    // runtime → a clean RED), then resolves to the real description once it does.
    func testEveryCaseSurfacesAFriendlyDescription() {
        for e in Self.oneOfEachCase {
            let desc = (e as? LocalizedError)?.errorDescription
            XCTAssertNotNil(desc, "case \(e) must have a friendly errorDescription")
            guard let desc else { continue }
            XCTAssertFalse(desc.isEmpty, "case \(e) description must not be empty")
            // Never leak a raw Swift case identifier to the user.
            XCTAssertFalse(desc.contains("OrCorrupt"), "case \(e) leaks a raw case name")
            XCTAssertFalse(desc.contains("VaultAccessError"), "case \(e) leaks the type name")
        }
    }

    // The bridged `localizedDescription` must resolve to our `errorDescription`,
    // not the Foundation default — this is what proves the `LocalizedError`
    // conformance is actually wired, not merely a stray `errorDescription` property.
    func testLocalizedDescriptionUsesErrorDescription() {
        for e in Self.oneOfEachCase {
            XCTAssertEqual(e.localizedDescription, (e as? LocalizedError)?.errorDescription,
                           "localizedDescription must delegate to errorDescription for \(e)")
        }
    }

    // Anti-oracle invariant (crypto-design): the three folded "…OrCorrupt" cases must
    // NEVER present the credential as definitively wrong — the vault-damage possibility
    // stays visible in every one, so the message can never be read as a wrong-credential
    // oracle. Standardised on the word "damaged" across all three.
    func testFoldedCasesAlwaysSurfaceTheDamagePossibility() {
        for e in [VaultAccessError.wrongPasswordOrCorrupt, .wrongMnemonicOrCorrupt,
                  .wrongDeviceSecretOrCorrupt] {
            let desc = ((e as? LocalizedError)?.errorDescription ?? "").lowercased()
            XCTAssertTrue(desc.contains("damaged"),
                          "folded case \(e) must keep the corruption possibility visible")
        }
    }
}
