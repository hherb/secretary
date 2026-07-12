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

    func testMakeSettingsViewModelNilWithoutPortOrGate() {
        let vm = VaultBrowseViewModel(session: session(), gate: FakeWriteReauthGate())
        XCTAssertNil(vm.makeSettingsViewModel(), "no settings port/gate → no settings VM")
    }

    func testMakeSettingsViewModelBuiltWhenWired() {
        let gate = retargetable()
        let vm = VaultBrowseViewModel(session: session(), gate: gate,
                                      settingsPort: FakeSettingsPort(), settingsGate: gate)
        XCTAssertNotNil(vm.makeSettingsViewModel())
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
