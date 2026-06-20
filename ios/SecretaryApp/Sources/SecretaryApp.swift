import SwiftUI
import os
import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// App-level breadcrumbs for the best-effort sync wiring (folder watcher start +
/// sync-state-dir resolution). Both paths degrade gracefully rather than failing
/// the unlock, so a log line is the only signal that detection went advisory-blind.
private let appLog = Logger(subsystem: "com.secretary.app", category: "sync-wiring")

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
        case browse(VaultBrowseViewModel, VaultSyncViewModel, ChangeDetectionMonitor, ScopedVaultPath)
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
        ZStack {
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
                            // `loadPersisted()` early-returns while the selection VM
                            // is `.unavailable`, so it would NOT surface the new
                            // vault from that state. This is safe only because the
                            // Create entry point lives exclusively in the `.empty`
                            // selectSection (unreachable from `.unavailable` without
                            // `chooseDifferent()` → `.empty` first). If a future
                            // change adds a Create button to another section, surface
                            // the location directly instead of relying on this.
                            selectionVM.loadPersisted()          // pick up the new location
                            route = .select                      // back to select → "Open" → unlock
                        },
                        onCancel: { route = .select })
                case .unlock(let scoped):
                    UnlockScreen(
                        viewModel: UnlockViewModel(port: UniffiVaultOpenPort(),
                                                   vaultPath: scoped.pathData),
                        onUnlocked: { session, password in
                            let folder = URL(fileURLWithPath:
                                String(decoding: scoped.pathData, as: UTF8.self))
                            // App-sandbox dir creation effectively never fails; if it
                            // does, fall back to a (ephemeral) temp dir so unlock still
                            // proceeds — sync state just won't persist across launches.
                            let stateDir: URL
                            do {
                                stateDir = try defaultSyncStateDir()
                            } catch {
                                stateDir = FileManager.default.temporaryDirectory
                                appLog.error("sync state dir unavailable, using temp: \(error.localizedDescription, privacy: .public)")
                            }
                            let (syncVM, monitor) = makeVaultSync(
                                session: session, folder: folder, stateDir: stateDir)
                            // A failed watcher start leaves detection advisory-blind
                            // (the badge falls back to manual "Sync now"); not fatal.
                            do {
                                try monitor.start()
                            } catch {
                                appLog.error("folder-change monitor failed to start: \(error.localizedDescription, privacy: .public)")
                            }
                            if let password {
                                Task { await syncVM.syncAtUnlock(password: password) }
                            } else {
                                Task { await syncVM.refreshStatus() }
                            }
                            let gate = GraceWindowReauthGate(
                                authorizer: EnclaveBiometricAuthorizer(
                                    enclave: SecureEnclaveDeviceSecretStore()))
                            route = .browse(VaultBrowseViewModel(session: session, gate: gate),
                                            syncVM, monitor, scoped)
                        })
                case .browse(let browseModel, let syncVM, let monitor, _):
                    VaultBrowseScreen(viewModel: browseModel, syncModel: syncVM)
                        .onDisappear { monitor.stop() }
                }
            }
            // Privacy cover for the app-switcher snapshot. iOS renders the snapshot
            // at the `.inactive` transition (BEFORE `.background`), so secret content
            // on screen — most acutely the create wizard's 24-word recovery phrase,
            // but also browse-screen reveals — would otherwise be captured. An opaque
            // cover whenever the scene is not `.active` keeps the snapshot blank. A
            // brief interruption (notification banner, incoming call) goes
            // `.inactive → .active` without `.background`, so the cover lifts and the
            // wizard resumes; only a full `.background` scrubs (see below).
            if scenePhase != .active {
                PrivacyCover()
            }
        }
        // Lock on background: wipe + drop reveals, release the held scope, and
        // return to the selection screen (which still shows the remembered vault).
        .onChange(of: scenePhase) { _, phase in
            guard phase == .background else { return }
            switch route {
            case .browse(let browseModel, _, let monitor, let scoped):
                monitor.stop()
                browseModel.lock()
                scoped.end()
                route = .select
            case .unlock(let scoped):
                scoped.end()
                route = .select
            case .create:
                // The mnemonic step holds the recovery phrase in memory; routing to
                // `.select` drops the inline-constructed `VaultProvisioningViewModel`,
                // whose `deinit` scrubs the retained phrase. The vault was already
                // created + persisted by this point, so the user simply re-opens it.
                route = .select
            case .select:
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

/// Opaque full-screen cover shown whenever the scene is not `.active`, so the
/// iOS app-switcher snapshot never captures on-screen secret content (recovery
/// phrase, revealed fields). Deliberately content-free — just the app chrome.
private struct PrivacyCover: View {
    var body: some View {
        ZStack {
            Color(.systemBackground).ignoresSafeArea()
            Image(systemName: "lock.fill")
                .font(.largeTitle)
                .foregroundStyle(.secondary)
        }
    }
}
