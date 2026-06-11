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
}
