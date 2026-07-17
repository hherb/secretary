import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

/// Routes select → unlock → browse for the macOS client. A user-selected vault's
/// (no-op, pre-sandbox) scope is held by the `ScopedVaultPath` for the whole session
/// and released on lock, returning to selection (which still shows the remembered
/// vault — one click re-opens).
@MainActor
struct MacRootView: View {
    private enum Route {
        case select
        case unlock(ScopedVaultPath)
        case browse(VaultBrowseViewModel, ScopedVaultPath)
    }

    private let store: VaultLocationStore
    @StateObject private var selectionVM: VaultSelectionViewModel
    @State private var route: Route = .select
    @State private var biometricEnrolled = false
    @State private var biometricError: String?
    @State private var rememberDevice = false

    init() {
        let store = FileVaultLocationStore()
        self.store = store
        _selectionVM = StateObject(wrappedValue: VaultSelectionViewModel(
            store: store, probe: FileManagerVaultShapeProbe()))
    }

    var body: some View {
        switch route {
        case .select:
            MacVaultSelectionView(
                viewModel: selectionVM,
                onOpen: { enterUnlock($0) },
                onOpenDemo: { try openDemo() })
        case .unlock(let scoped):
            MacUnlockView(
                viewModel: UnlockViewModel(port: UniffiVaultOpenPort(), vaultPath: scoped.pathData),
                vaultPath: scoped.pathData,
                biometricEnrolled: biometricEnrolled,
                biometricError: $biometricError,
                rememberDevice: $rememberDevice,
                onOpened: { session, gate in enterBrowse(session, gate: gate, scoped: scoped) })
        case .browse:
            // TEMPORARY stub until Task 5 adds MacBrowseView.
            Text("Browse route (stub)").padding(24)
        }
    }

    private func enterUnlock(_ scoped: ScopedVaultPath) {
        biometricError = nil
        rememberDevice = false
        biometricEnrolled = makePerVaultDeviceUnlock(vaultPath: scoped.pathData).coordinator.isEnrolled
        route = .unlock(scoped)
    }

    private func enterBrowse(_ session: VaultSession, gate: RetargetableReauthGate,
                             scoped: ScopedVaultPath) {
        let vm = VaultBrowseViewModel(session: session, gate: gate,
                                      trashPort: session as? TrashPort,
                                      settingsPort: session as? SettingsPort)
        route = .browse(vm, scoped)
    }

    /// Stage + open the bundled golden vault behind an explicit opt-in (SKELETON
    /// ONLY). The demo path is transient — not persisted to the store.
    private func openDemo() throws {
        let url = try MacVaultProvisioning.stageGoldenVault()
        enterUnlock(ScopedVaultPath(pathData: Data(url.path.utf8), onEnd: {}))
    }
}
