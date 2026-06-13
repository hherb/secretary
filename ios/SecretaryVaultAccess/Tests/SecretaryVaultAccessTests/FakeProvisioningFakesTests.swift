import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeProvisioningFakesTests: XCTestCase {
    func testCreatePortReturnsSeededResultAndSpiesInputs() throws {
        let loc = VaultLocation(displayName: "v1", bookmark: Data("bm".utf8))
        let port = FakeVaultCreatePort(result: .success(
            CreatedVault(location: loc, phrase: Array("word1 word2".utf8))))
        let out = try port.create(parent: URL(fileURLWithPath: "/p"),
                                  vaultName: "v1",
                                  password: Array("pw".utf8),
                                  displayName: "Owner")
        XCTAssertEqual(out.location, loc)
        XCTAssertEqual(port.lastVaultName, "v1")
        XCTAssertEqual(port.lastPassword, Array("pw".utf8))
        XCTAssertEqual(port.lastDisplayName, "Owner")
    }

    func testCreatePortThrowsSeededError() {
        let port = FakeVaultCreatePort(result: .failure(.folderNotEmpty))
        XCTAssertThrowsError(try port.create(parent: URL(fileURLWithPath: "/p"),
                                             vaultName: "v",
                                             password: [1],
                                             displayName: "d")) {
            XCTAssertEqual($0 as? VaultProvisioningError, .folderNotEmpty)
        }
    }

    func testShapeProbeReturnsSeededAnswer() throws {
        XCTAssertTrue(try FakeVaultShapeProbe(answer: .success(true))
            .looksLikeVault(URL(fileURLWithPath: "/p")))
        XCTAssertFalse(try FakeVaultShapeProbe(answer: .success(false))
            .looksLikeVault(URL(fileURLWithPath: "/p")))
    }
}
