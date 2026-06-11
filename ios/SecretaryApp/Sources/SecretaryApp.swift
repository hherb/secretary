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

/// Routes between the unlock screen and the browse screen, and LOCKS (wipes the
/// session) when the app backgrounds — re-unlock is required on return. Builds
/// the real `UniffiVaultOpenPort` over a staged writable copy of golden_vault_001.
private struct RootView: View {
    private enum Route {
        case unlock
        /// Carries the live browse VM (not just the session) so backgrounding can
        /// route teardown through its authoritative `lock()` (drop reveals + wipe).
        case browse(VaultBrowseViewModel)
    }

    @State private var route: Route = .unlock
    @State private var staged: Result<Data, Error> = RootView.stageVaultPath()
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        Group {
            switch staged {
            case .failure(let error):
                Text("Setup failed: \(error.localizedDescription)").padding()
            case .success(let vaultPath):
                switch route {
                case .unlock:
                    UnlockScreen(
                        viewModel: UnlockViewModel(port: UniffiVaultOpenPort(), vaultPath: vaultPath),
                        onUnlocked: { session in route = .browse(VaultBrowseViewModel(session: session)) })
                case .browse(let browseModel):
                    VaultBrowseScreen(viewModel: browseModel)
                }
            }
        }
        // Lock on background: the VM's lock() drops all revealed plaintext AND
        // wipes the session in one authoritative step; then return to unlock.
        .onChange(of: scenePhase) { _, phase in
            if phase == .background, case .browse(let browseModel) = route {
                browseModel.lock()
                route = .unlock
            }
        }
    }

    /// Computed once as a `@State` default: SwiftUI keeps the FIRST stored value
    /// across `RootView` re-creations, so the staging runs effectively once. The
    /// default expression may re-run on a later init (SwiftUI discards the extra
    /// results), which is harmless because `stageGoldenVault` is idempotent.
    private static func stageVaultPath() -> Result<Data, Error> {
        do {
            let url = try AppVaultProvisioning.stageGoldenVault()
            return .success(Data(url.path.utf8))
        } catch {
            return .failure(error)
        }
    }
}
