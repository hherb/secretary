import SwiftUI
import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

@main
struct SecretaryApp: App {
    var body: some Scene {
        WindowGroup { RootView() }
    }
}

/// Routes `select → unlock → browse`. A user-selected vault's security scope is
/// held by the `ScopedVaultPath` for the whole session (lazy block reads) and
/// released on lock/background, which returns to the selection screen showing the
/// still-remembered vault (one tap re-opens — no re-pick). The demo vault reuses
/// the same unlock/browse flow with a no-op scope over its staged path.
private struct RootView: View {
    private enum Route {
        case select
        case create
        case unlock(ScopedVaultPath)
        case browse(VaultBrowseViewModel, ScopedVaultPath)
    }

    /// One shared location store backs BOTH the selection VM and the create
    /// wizard's provisioning VM, so a vault created in the wizard is visible to
    /// `selectionVM.loadPersisted()` immediately after `onCreated`.
    private let store: BookmarkVaultLocationStore
    @StateObject private var selectionVM: VaultSelectionViewModel
    @State private var route: Route = .select
    @Environment(\.scenePhase) private var scenePhase

    init() {
        let store = BookmarkVaultLocationStore()
        self.store = store
        _selectionVM = StateObject(
            wrappedValue: VaultSelectionViewModel(store: store,
                                                  probe: FileManagerVaultShapeProbe()))
    }

    var body: some View {
        Group {
            switch route {
            case .select:
                VaultSelectionScreen(
                    viewModel: selectionVM,
                    onOpen: { scoped in route = .unlock(scoped) },
                    onOpenDemo: { try openDemo() },
                    onCreateNew: { route = .create })
            case .create:
                CreateVaultWizardView(
                    viewModel: VaultProvisioningViewModel(
                        createPort: UniffiVaultCreatePort(), store: store),
                    onCreated: { _ in
                        selectionVM.loadPersisted()          // pick up the new location
                        route = .select                      // back to select → "Open" → unlock
                    },
                    onCancel: { route = .select })
            case .unlock(let scoped):
                UnlockScreen(
                    viewModel: UnlockViewModel(port: UniffiVaultOpenPort(),
                                               vaultPath: scoped.pathData),
                    onUnlocked: { session in
                        route = .browse(VaultBrowseViewModel(session: session), scoped)
                    })
            case .browse(let browseModel, _):
                VaultBrowseScreen(viewModel: browseModel)
            }
        }
        // Lock on background: wipe + drop reveals, release the held scope, and
        // return to the selection screen (which still shows the remembered vault).
        .onChange(of: scenePhase) { _, phase in
            guard phase == .background else { return }
            switch route {
            case .browse(let browseModel, let scoped):
                browseModel.lock()
                scoped.end()
                route = .select
            case .unlock(let scoped):
                scoped.end()
                route = .select
            case .select, .create:
                break
            }
        }
    }

    /// Stage + open the bundled golden vault behind an explicit opt-in. The demo
    /// path is in-sandbox, so its `ScopedVaultPath` holds no real scope (no-op end).
    /// A staging failure is rethrown so `VaultSelectionScreen` surfaces it in its
    /// Error section — the button never silently no-ops.
    private func openDemo() throws {
        let url = try AppVaultProvisioning.stageGoldenVault()
        let scoped = ScopedVaultPath(pathData: Data(url.path.utf8), onEnd: {})
        route = .unlock(scoped)
    }
}
