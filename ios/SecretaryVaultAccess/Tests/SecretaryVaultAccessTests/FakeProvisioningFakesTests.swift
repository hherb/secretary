import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting

final class FakeProvisioningFakesTests: XCTestCase {
    func testCreatePortReturnsSeededResultAndSpiesInputs() async throws {
        let loc = VaultLocation(displayName: "v1", bookmark: Data("bm".utf8))
        let port = FakeVaultCreatePort(result: .success(
            CreatedVault(location: loc, phrase: Array("word1 word2".utf8))))
        let out = try await port.create(parent: URL(fileURLWithPath: "/p"),
                                  vaultName: "v1",
                                  password: Array("pw".utf8),
                                  displayName: "Owner")
        XCTAssertEqual(out.location, loc)
        XCTAssertEqual(out.phrase, Array("word1 word2".utf8))
        XCTAssertEqual(port.lastParent, URL(fileURLWithPath: "/p"))
        XCTAssertEqual(port.lastVaultName, "v1")
        XCTAssertEqual(port.lastPassword, Array("pw".utf8))
        XCTAssertEqual(port.lastDisplayName, "Owner")
    }

    func testCreatePortThrowsSeededError() async {
        let port = FakeVaultCreatePort(result: .failure(.folderNotEmpty))
        do {
            _ = try await port.create(parent: URL(fileURLWithPath: "/p"),
                                      vaultName: "v",
                                      password: [1],
                                      displayName: "d")
            XCTFail("expected create to throw")
        } catch {
            XCTAssertEqual(error as? VaultProvisioningError, .folderNotEmpty)
        }
        XCTAssertEqual(port.lastVaultName, "v")
        XCTAssertEqual(port.lastPassword, [1])
        XCTAssertEqual(port.lastDisplayName, "d")
    }

    func testShapeProbeReturnsSeededAnswer() throws {
        let yes = FakeVaultShapeProbe(answer: .success(true))
        XCTAssertTrue(try yes.looksLikeVault(URL(fileURLWithPath: "/p")))
        XCTAssertEqual(yes.lastFolder, URL(fileURLWithPath: "/p"))
        XCTAssertFalse(try FakeVaultShapeProbe(answer: .success(false))
            .looksLikeVault(URL(fileURLWithPath: "/q")))
    }

    func testShapeProbeThrowsSeededError() {
        struct Boom: Error {}
        let probe = FakeVaultShapeProbe(answer: .failure(Boom()))
        XCTAssertThrowsError(try probe.looksLikeVault(URL(fileURLWithPath: "/p")))
    }
}
