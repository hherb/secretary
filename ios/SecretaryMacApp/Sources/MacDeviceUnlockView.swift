import SwiftUI
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI
import SecretaryKit

struct MacDeviceUnlockView: View {
    @StateObject private var model: DeviceUnlockViewModel
    @State private var password: String = ""
    private let setupError: String?

    init() {
        // Build the real per-vault device-unlock bundle over a staged vault.
        do {
            let vaultURL = try MacVaultProvisioning.stageGoldenVault()
            let vaultPath = Data(vaultURL.path.utf8)                    // same as SecretaryApp.swift:247
            let vaultId = try MacVaultProvisioning.pinnedVaultUuidHex()
            let bundle = makePerVaultDeviceUnlock(vaultPath: vaultPath)
            _model = StateObject(wrappedValue: DeviceUnlockViewModel(
                coordinator: bundle.coordinator, vaultPath: vaultPath, vaultId: vaultId))
            self.setupError = nil
        } catch {
            // Provisioning failed — show the error; VM is a harmless placeholder.
            let vaultPath = Data("<unprovisioned>".utf8)
            let bundle = makePerVaultDeviceUnlock(vaultPath: vaultPath)
            _model = StateObject(wrappedValue: DeviceUnlockViewModel(
                coordinator: bundle.coordinator, vaultPath: vaultPath, vaultId: "0"))
            self.setupError = error.localizedDescription
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Secretary — macOS device unlock (D.5.1)").font(.headline)
            if let setupError {
                Text("Setup error: \(setupError)").foregroundColor(.red)
            }
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
        .padding(24)
        .frame(minWidth: 440, minHeight: 260)
        .onAppear { model.refreshStatus() }
    }
}
