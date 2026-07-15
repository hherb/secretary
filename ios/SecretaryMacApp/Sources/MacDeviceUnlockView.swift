import SwiftUI
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI
import SecretaryKit

/// Owns the one-time provisioning of the device-unlock bundle. Running this from
/// a `.task` (not `View.init`) keeps the file I/O off the synchronous
/// view-construction path and, unlike an `init`, does not re-run on every SwiftUI
/// re-init. A provisioning failure becomes a first-class `.failed` phase rather
/// than a placeholder view model over a bogus vault path.
@MainActor
final class MacUnlockSetup: ObservableObject {
    enum Phase {
        case provisioning
        case ready(DeviceUnlockViewModel)
        case failed(String)
    }

    @Published private(set) var phase: Phase = .provisioning

    /// Idempotent: provisions once, then no-ops on any later `.task` re-entry.
    func provision() async {
        guard case .provisioning = phase else { return }
        do {
            let vaultURL = try MacVaultProvisioning.stageGoldenVault()
            let vaultPath = Data(vaultURL.path.utf8)   // matches SecretaryApp: Data(url.path.utf8)
            let vaultId = try MacVaultProvisioning.pinnedVaultUuidHex()
            let bundle = makePerVaultDeviceUnlock(vaultPath: vaultPath)
            let model = DeviceUnlockViewModel(
                coordinator: bundle.coordinator, vaultPath: vaultPath, vaultId: vaultId)
            model.refreshStatus()
            phase = .ready(model)
        } catch {
            phase = .failed(error.localizedDescription)
        }
    }
}

struct MacDeviceUnlockView: View {
    @StateObject private var setup = MacUnlockSetup()

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Secretary — macOS device unlock (D.5.1)").font(.headline)
            switch setup.phase {
            case .provisioning:
                Text("Provisioning demo vault…")
                    .font(.system(.body, design: .monospaced))
            case .failed(let message):
                Text("Setup error: \(message)").foregroundColor(.red)
            case .ready(let model):
                MacUnlockControls(model: model)
            }
        }
        .padding(24)
        .frame(minWidth: 440, minHeight: 260)
        .task { await setup.provision() }
    }
}

/// The interactive controls, shown only once provisioning has produced the real,
/// vault-backed view model — so `model` is never a placeholder.
private struct MacUnlockControls: View {
    @ObservedObject var model: DeviceUnlockViewModel
    @State private var password: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("State: \(String(describing: model.state))")
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)

            SecureField("Vault password (to enroll)", text: $password)
                .frame(maxWidth: 320)

            HStack(spacing: 12) {
                Button("Enroll device slot") {
                    Task { await model.enroll(password: Array(password.utf8)); password = "" }
                }.disabled(password.isEmpty)

                Button("Unlock with Touch ID") {
                    Task { await model.unlock(reason: "Unlock your Secretary vault") }
                }
            }

            Button("Refresh status") { model.refreshStatus() }
        }
    }
}
