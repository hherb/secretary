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

    func testMainActorIsFreeWhileOpening() async {
        let s = session("cd")
        let gate = SuspensionGate()
        let port = FakeVaultOpenPort(passwordResult: .success(s),
                                     recoveryResult: .failure(.wrongMnemonicOrCorrupt))
        port.gate = gate
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .password

        let task = Task { await vm.unlock(secret: Array("pw".utf8)) }

        // Suspends THIS (main-actor) test until the fake is mid-call. Reaching the
        // next line proves `unlock` yielded the main actor at a suspension point
        // mid-open: if it had run the open synchronously on the main actor, this
        // `Task`'s body could not interleave with the test's await and
        // `waitUntilEntered()` would never resume (the test would time out).
        await gate.waitUntilEntered()
        guard case .busy = vm.state else {
            return XCTFail("expected .busy while the port is in flight")
        }

        await gate.release()
        await task.value
        guard case .unlocked(let opened) = vm.state else {
            return XCTFail("expected unlocked")
        }
        XCTAssertTrue(opened === s)
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

    func testDefaultModeIsPassword() {
        let vm = UnlockViewModel(
            port: FakeVaultOpenPort(passwordResult: .success(session()),
                                    recoveryResult: .failure(.wrongMnemonicOrCorrupt)),
            vaultPath: Data("p".utf8))
        XCTAssertEqual(vm.mode, .password)
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

    // MARK: - Rollback reset (#746)

    private func rollbackPort(reset: Result<VaultSession, VaultAccessError>) -> FakeVaultOpenPort {
        FakeVaultOpenPort(passwordResult: .failure(.rollbackDetected),
                          recoveryResult: .failure(.wrongMnemonicOrCorrupt),
                          resetResult: reset)
    }

    func testPasswordRollbackShowsResetPrompt() async {
        let port = rollbackPort(reset: .success(session()))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        await vm.unlock(secret: Array("pw".utf8))
        guard case .rollbackResetPrompt = vm.state else { return XCTFail("expected prompt, got \(vm.state)") }
        XCTAssertNil(port.lastResetPassword, "the reset must never run without confirmation")
    }

    func testRecoveryRollbackIsAPlainFailureWithoutPrompt() async {
        // The reset needs the master password, so a recovery open is not offered it.
        let port = FakeVaultOpenPort(passwordResult: .failure(.wrongPasswordOrCorrupt),
                                     recoveryResult: .failure(.rollbackDetected),
                                     resetResult: .success(session()))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        vm.mode = .recovery
        await vm.unlock(secret: Array("phrase".utf8))
        guard case .failed(let err) = vm.state else { return XCTFail("expected failed") }
        XCTAssertEqual(err, .rollbackDetected)
    }

    func testCancelRollbackResetClearsPromptWithoutResetting() async {
        let port = rollbackPort(reset: .success(session()))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        await vm.unlock(secret: Array("pw".utf8))
        vm.cancelRollbackReset()
        guard case .idle = vm.state else { return XCTFail("expected idle, got \(vm.state)") }
        XCTAssertNil(port.lastResetPassword)
    }

    func testConfirmRollbackResetCallsResetWithPasswordAndUnlocks() async {
        let s = session("12")
        let port = rollbackPort(reset: .success(s))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        await vm.unlock(secret: Array("pw".utf8))
        await vm.confirmRollbackReset(secret: Array("pw".utf8))
        guard case .unlocked(let opened) = vm.state else { return XCTFail("expected unlocked, got \(vm.state)") }
        XCTAssertTrue(opened === s)
        XCTAssertEqual(port.lastResetPassword, Array("pw".utf8))
    }

    func testConfirmRollbackResetFailureIsSurfaced() async {
        let port = rollbackPort(reset: .failure(.wrongPasswordOrCorrupt))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        await vm.unlock(secret: Array("pw".utf8))
        await vm.confirmRollbackReset(secret: Array("pw".utf8))
        guard case .failed(let err) = vm.state else { return XCTFail("expected failed, got \(vm.state)") }
        XCTAssertEqual(err, .wrongPasswordOrCorrupt)
    }

    func testConfirmWithoutPromptDoesNothing() async {
        // The reset is user-confirmed recovery only: never reachable except from the prompt.
        let port = rollbackPort(reset: .success(session()))
        let vm = UnlockViewModel(port: port, vaultPath: Data("p".utf8))
        await vm.confirmRollbackReset(secret: Array("pw".utf8))
        guard case .idle = vm.state else { return XCTFail("expected idle, got \(vm.state)") }
        XCTAssertNil(port.lastResetPassword)
    }

    func testRollbackResetCopyIsVerbatim() {
        // Shared verbatim with desktop and Android (#746).
        XCTAssertEqual(RollbackResetCopy.title, "This vault looks older than expected")
        XCTAssertEqual(RollbackResetCopy.body,
                       "This device last saw a newer version of this vault. That can happen after restoring a backup, but it can also mean your storage provider is serving an old copy. Only continue if you restored this vault from a backup or are sure this copy is current.")
        XCTAssertEqual(RollbackResetCopy.confirm, "Reset and open")
        XCTAssertEqual(RollbackResetCopy.cancel, "Cancel")
    }
}
