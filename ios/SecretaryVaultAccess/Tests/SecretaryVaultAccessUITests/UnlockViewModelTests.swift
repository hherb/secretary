import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class UnlockViewModelTests: XCTestCase {
    private func session(_ hex: String = "ab") -> FakeVaultSession {
        FakeVaultSession(vaultUuidHex: hex, blocks: [], recordsByBlock: [:])
    }

    func testPasswordUnlockSuccessPublishesSession() async {
        let s = session("cd")
        let port = FakeVaultOpenPort(passwordResult: .success(s),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .password
        await vm.unlock(secret: Array("pw".utf8))
        guard case .unlocked(let opened) = vm.state else { return XCTFail("expected unlocked") }
        XCTAssertTrue(opened === s)
        XCTAssertEqual(port.lastPassword, Array("pw".utf8))
    }

    func testRecoveryUnlockSuccessUsesRecoveryPath() async {
        let s = session("ef")
        let port = FakeVaultOpenPort(passwordResult: .failure(.wrongPasswordOrCorrupt),
                                     recoveryResult: .success(s))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .recovery
        await vm.unlock(secret: Array("phrase".utf8))
        guard case .unlocked(let opened) = vm.state else { return XCTFail("expected unlocked") }
        XCTAssertTrue(opened === s)
        XCTAssertEqual(port.lastPhrase, Array("phrase".utf8))
    }

    func testWrongPasswordSurfacesConflatedVariant() async {
        let port = FakeVaultOpenPort(passwordResult: .failure(.wrongPasswordOrCorrupt),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .password
        await vm.unlock(secret: Array("bad".utf8))
        guard case .failed(let err) = vm.state else { return XCTFail("expected failed") }
        // Anti-oracle: a wrong password is NOT distinguishable from corruption.
        XCTAssertEqual(err, .wrongPasswordOrCorrupt)
    }
}
