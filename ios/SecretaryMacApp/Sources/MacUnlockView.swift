import SwiftUI
import os
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

private let macUnlockLog = Logger(subsystem: "com.secretary.macapp", category: "unlock")

/// Password + Touch ID unlock (macOS). Owns gate construction so `MacRootView`
/// receives a fully-opened `(session, gate)` regardless of which tier was used.
@MainActor
struct MacUnlockView: View {
    @StateObject private var viewModel: UnlockViewModel
    let vaultPath: Data
    let biometricEnrolled: Bool
    @Binding var biometricError: String?
    @Binding var rememberDevice: Bool
    let onOpened: (VaultSession, RetargetableReauthGate) -> Void

    @State private var password: String = ""
    @State private var lastPasswordSecret: [UInt8]?

    init(viewModel: UnlockViewModel, vaultPath: Data, biometricEnrolled: Bool,
         biometricError: Binding<String?>, rememberDevice: Binding<Bool>,
         onOpened: @escaping (VaultSession, RetargetableReauthGate) -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.vaultPath = vaultPath
        self.biometricEnrolled = biometricEnrolled
        _biometricError = biometricError
        _rememberDevice = rememberDevice
        self.onOpened = onOpened
    }

    private var isBusy: Bool { if case .busy = viewModel.state { return true } else { return false } }
    private var stateIsUnlocked: Bool { if case .unlocked = viewModel.state { return true } else { return false } }

    var body: some View {
        Form {
            if biometricEnrolled {
                Section("Touch ID") {
                    Button("Unlock with Touch ID") { biometricUnlock() }.disabled(isBusy)
                }
            }
            Section("Master password") {
                SecureField("Password", text: $password)
                Toggle("Remember this Mac with Touch ID", isOn: $rememberDevice)
            }
            Section {
                Button("Unlock") { passwordUnlock() }.disabled(isBusy || password.isEmpty)
            }
            if case .failed(let err) = viewModel.state {
                Section("Error") { Text(String(describing: err)).foregroundStyle(.red) }
            }
            if let biometricError {
                Section("Couldn’t unlock") { Text(biometricError).foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, minHeight: 320)
        .overlay { if isBusy { ProgressView() } }
        // Single-param overload (macOS 11+): the app's deploymentTarget is
        // macOS 13.0, below the macOS 14.0 floor for the two-param
        // `onChange(of:initial:_:)` used elsewhere on iOS 17+.
        .onChange(of: stateIsUnlocked) { unlocked in
            guard unlocked, case .unlocked(let session) = viewModel.state else { return }
            let password = lastPasswordSecret
            lastPasswordSecret = nil
            let gate = makeRetargetableReauthGate(session: session, vaultPath: vaultPath,
                                                  biometricUnlock: false)
            if rememberDevice, let password { enrollDevice(session: session, secret: password) }
            onOpened(session, gate)
        }
    }

    private func passwordUnlock() {
        viewModel.mode = .password
        let secret = Array(password.utf8)
        lastPasswordSecret = secret
        Task { await viewModel.unlock(secret: secret) }
    }

    private func biometricUnlock() {
        biometricError = nil
        let coordinator = makePerVaultDeviceUnlock(vaultPath: vaultPath).coordinator
        Task {
            let result = await DeviceUnlockOpen.open(
                coordinator: coordinator, openPort: UniffiVaultOpenPort(),
                vaultPath: vaultPath, reason: "Unlock your Secretary vault")
            switch result {
            case .cancelled: break                              // stay on unlock, quietly
            case .failed(let message): biometricError = message
            case .opened(let session, let gate): onOpened(session, gate)
            }
        }
    }

    /// Best-effort device-slot enrollment on password unlock (mirrors iOS): a second
    /// Argon2id open, hopped onto a background queue so the route transition is never
    /// blocked. Non-fatal — the password open already succeeded.
    private func enrollDevice(session: VaultSession, secret: [UInt8]) {
        let coordinator = makePerVaultDeviceUnlock(vaultPath: vaultPath).coordinator
        let vaultPath = self.vaultPath
        let vaultId = session.vaultUuidHex
        Task {
            do {
                try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
                    DispatchQueue.global(qos: .userInitiated).async {
                        do { try coordinator.enroll(vaultPath: vaultPath, vaultId: vaultId, password: secret); c.resume() }
                        catch { c.resume(throwing: error) }
                    }
                }
            } catch {
                macUnlockLog.error("device enroll failed: \(error.localizedDescription, privacy: .public)")
                await MainActor.run { biometricError = "Couldn’t enable Touch ID unlock. You can try again later." }
            }
        }
    }
}
