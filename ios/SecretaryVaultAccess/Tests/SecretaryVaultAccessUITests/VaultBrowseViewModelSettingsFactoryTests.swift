import XCTest
import SecretaryVaultAccess
import SecretaryVaultAccessTesting
@testable import SecretaryVaultAccessUI

@MainActor
final class VaultBrowseViewModelSettingsFactoryTests: XCTestCase {
    private func session() -> FakeVaultSession {
        FakeVaultSession(vaultUuidHex: "ab", blocks: [], recordsByBlock: [:])
    }

    private func retargetable() -> RetargetableReauthGate {
        let t0 = MonotonicInstant(nanoseconds: 1)
        return RetargetableReauthGate(window: .seconds(120), initialAuthAt: nil,
                                      clock: { t0 }) { _, _ in FakeWriteReauthGate() }
    }

    func testMakeSettingsViewModelNilWithoutSettingsPort() {
        let vm = VaultBrowseViewModel(session: session(), gate: retargetable())
        XCTAssertNil(vm.makeSettingsViewModel(), "no settings port → no settings VM")
    }

    func testMakeSettingsViewModelNilWhenGateNotRetargetable() {
        // A pass-through gate (not a RetargetableReauthGate) can't be retargeted,
        // so no Settings VM is built even with a settings port.
        let vm = VaultBrowseViewModel(session: session(), gate: FakeWriteReauthGate(),
                                      settingsPort: FakeSettingsPort())
        XCTAssertNil(vm.makeSettingsViewModel())
    }

    func testMakeSettingsViewModelBuiltWhenWired() {
        let vm = VaultBrowseViewModel(session: session(), gate: retargetable(),
                                      settingsPort: FakeSettingsPort())
        XCTAssertNotNil(vm.makeSettingsViewModel(), "settings port + retargetable gate → settings VM")
    }

    func testMakeTrashViewModelThreadsSettingsPortForPerVaultRetention() throws {
        let trash = FakeTrashPort(defaultWindowMs: 90 * 86_400_000)
        let settings = FakeSettingsPort(settings: VaultSettings(
            autoLockTimeoutMs: 600_000, requirePasswordBeforeEdits: true,
            reauthGraceWindowMs: 120_000, retentionWindowMs: 15 * 86_400_000))
        let vm = VaultBrowseViewModel(session: session(), gate: FakeWriteReauthGate(),
                                      trashPort: trash, settingsPort: settings)
        let trashVM = try XCTUnwrap(vm.makeTrashViewModel())
        trashVM.load()
        XCTAssertEqual(trashVM.retentionWindowMs, 15 * 86_400_000,
                       "browse VM threads the settings port into the Trash VM")
    }
}
