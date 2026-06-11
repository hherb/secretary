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
        case browse(VaultSession)
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
                        onUnlocked: { session in route = .browse(session) })
                case .browse(let session):
                    VaultBrowseScreen(viewModel: VaultBrowseViewModel(session: session))
                }
            }
        }
        // Lock on background: wipe the live session and return to unlock.
        .onChange(of: scenePhase) { _, phase in
            if phase == .background, case .browse(let session) = route {
                session.wipe()
                route = .unlock
            }
        }
    }

    private static func stageVaultPath() -> Result<Data, Error> {
        do {
            let url = try AppVaultProvisioning.stageGoldenVault()
            return .success(Data(url.path.utf8))
        } catch {
            return .failure(error)
        }
    }
}
