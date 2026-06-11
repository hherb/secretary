import SwiftUI
import SecretaryKit
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI

@main
struct SecretaryApp: App {
    var body: some Scene {
        WindowGroup { RootView() }
    }
}

/// Builds the REAL coordinator (Secure Enclave + uniffi port + Keychain) over a
/// staged writable copy of golden_vault_001, or shows a provisioning error.
private struct RootView: View {
    /// SwiftUI keeps the FIRST stored `@State` value across `RootView`
    /// re-creations, so the coordinator + ViewModel the views observe are
    /// effectively built once. (The default expression itself can re-run on a
    /// later `RootView` init — SwiftUI discards those extra results — which is
    /// harmless here because `build`'s only side effect, `stageGoldenVault`, is
    /// idempotent.)
    @State private var built = build()

    var body: some View {
        switch built {
        case .success(let (vm, pinned)):
            DeviceUnlockScreen(viewModel: vm, pinnedVaultUuidHex: pinned)
        case .failure(let error):
            Text("Setup failed: \(error.localizedDescription)").padding()
        }
    }

    private static func build() -> Result<(DeviceUnlockViewModel, String?), Error> {
        do {
            let vaultURL = try AppVaultProvisioning.stageGoldenVault()
            let pinned = try? AppVaultProvisioning.pinnedVaultUuidHex()
            let coordinator = DeviceUnlockCoordinator(
                slotPort: UniffiVaultDeviceSlotPort(),
                enclave: SecureEnclaveDeviceSecretStore(),
                metadata: KeychainEnrollmentMetadataStore())
            let vm = DeviceUnlockViewModel(
                coordinator: coordinator,
                vaultPath: Data(vaultURL.path.utf8),
                vaultId: "golden")
            return .success((vm, pinned))
        } catch {
            return .failure(error)
        }
    }
}
