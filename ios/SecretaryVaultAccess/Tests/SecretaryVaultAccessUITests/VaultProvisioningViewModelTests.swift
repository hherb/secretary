import XCTest
import Combine
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultProvisioningViewModelTests: XCTestCase {
    private func makeVM(
        createResult: Result<CreatedVault, VaultProvisioningError>
    ) -> (VaultProvisioningViewModel, FakeVaultCreatePort, FakeVaultLocationStore) {
        let port = FakeVaultCreatePort(result: createResult)
        let store = FakeVaultLocationStore()
        return (VaultProvisioningViewModel(createPort: port, store: store), port, store)
    }

    private func okResult(name: String = "v1") -> Result<CreatedVault, VaultProvisioningError> {
        .success(CreatedVault(
            location: VaultLocation(displayName: name, bookmark: Data("bm".utf8)),
            phrase: Array((1...24).map { "w\($0)" }.joined(separator: " ").utf8)))
    }

    func testFolderStepRejectsInvalidName() {
        let (vm, _, _) = makeVM(createResult: okResult())
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "a/b")
        XCTAssertEqual(vm.step, .folder)
        XCTAssertEqual(vm.nameError, .containsSeparator)
    }

    func testFolderStepAdvancesOnValidName() {
        let (vm, _, _) = makeVM(createResult: okResult())
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "  My Vault  ")
        XCTAssertEqual(vm.step, .credentials(parent: URL(fileURLWithPath: "/p"), vaultName: "My Vault"))
        XCTAssertNil(vm.nameError)
    }

    func testPasswordMismatchBlocksCreate() async {
        let (vm, port, _) = makeVM(createResult: okResult())
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("a".utf8), confirm: Array("b".utf8))
        XCTAssertEqual(vm.error, .passwordMismatch)
        XCTAssertNil(port.lastPassword)             // never reached the port
        if case .mnemonic = vm.step { XCTFail("must not advance") }
    }

    func testHappyPathPersistsThenShowsMnemonic() async {
        let (vm, port, store) = makeVM(createResult: okResult(name: "v1"))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        XCTAssertEqual(port.lastVaultName, "v1")
        XCTAssertEqual(port.lastDisplayName, "Owner")
        XCTAssertEqual(store.stored?.displayName, "v1")   // persisted BEFORE mnemonic
        XCTAssertEqual(vm.step, .mnemonic)
        XCTAssertEqual(vm.mnemonicRows?.count, 24)
    }

    func testMainActorIsFreeWhileCreating() async {
        let (vm, port, _) = makeVM(createResult: okResult(name: "v1"))
        let gate = SuspensionGate()
        port.gate = gate
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")

        let task = Task {
            await vm.create(displayName: "Owner",
                            password: Array("pw".utf8), confirm: Array("pw".utf8))
        }

        // Reaching past this await proves `create` yielded the main actor at a
        // suspension point mid-create: if it had run the create synchronously on
        // the main actor, this `Task`'s body could not interleave with the test's
        // await and `waitUntilEntered()` would never resume (the test would time out).
        await gate.waitUntilEntered()
        XCTAssertEqual(port.lastVaultName, "v1")        // reached the port
        if case .mnemonic = vm.step { XCTFail("must not advance until port returns") }

        await gate.release()
        await task.value
        XCTAssertEqual(vm.step, .mnemonic)
        XCTAssertEqual(vm.mnemonicRows?.count, 24)
    }

    func testFolderNotEmptyErrorSurfaces() async {
        let (vm, _, store) = makeVM(createResult: .failure(.folderNotEmpty))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        XCTAssertEqual(vm.error, .folderNotEmpty)
        XCTAssertNil(store.stored)                        // nothing persisted on failure
        XCTAssertEqual(vm.step, .credentials(parent: URL(fileURLWithPath: "/p"), vaultName: "v1"))
    }

    func testAcknowledgeClearsPhraseAndCompletes() async {
        let (vm, _, _) = makeVM(createResult: okResult(name: "v1"))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        vm.acknowledgeMnemonic()
        XCTAssertNil(vm.mnemonicRows)                     // display cleared
        guard case .done(let loc) = vm.step else { return XCTFail("expected .done") }
        XCTAssertEqual(loc.displayName, "v1")
    }

    func testAcknowledgeWithLostLocationSurfacesError() async {
        let (vm, _, store) = makeVM(createResult: okResult(name: "v1"))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        // Simulate the store losing the just-persisted location before ack.
        store.clear()
        vm.acknowledgeMnemonic()
        XCTAssertNil(vm.mnemonicRows)                 // phrase display still wiped (security)
        XCTAssertEqual(vm.error, .createFailed("vault location unavailable after create"))
        if case .done = vm.step { XCTFail("must not complete without a location") }
    }

    func testCancelClearsMnemonicRows() async {
        let (vm, _, _) = makeVM(createResult: okResult(name: "v1"))
        vm.chooseParent(URL(fileURLWithPath: "/p"), vaultName: "v1")
        await vm.create(displayName: "Owner",
                        password: Array("pw".utf8), confirm: Array("pw".utf8))
        XCTAssertNotNil(vm.mnemonicRows)          // shown after create
        vm.cancel()
        XCTAssertNil(vm.mnemonicRows)             // cleared on cancel
    }
}
