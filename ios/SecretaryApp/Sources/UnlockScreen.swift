import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Password / recovery-phrase unlock. Thin shell: renders `viewModel.state` and
/// forwards the entered secret. On `.unlocked` it calls `onUnlocked(session, password)`
/// where `password` is non-nil only for `.password` mode (recovery has no usable sync password).
struct UnlockScreen: View {
    @StateObject private var viewModel: UnlockViewModel
    /// Shown only when this device is enrolled for biometric unlock of a vault.
    let biometricEnrolled: Bool
    /// Parent-owned so it resets cleanly on route entry (avoids the Android
    /// #342 carry-over shape for the error).
    @Binding var biometricError: String?
    /// Parent-owned so it resets cleanly on route entry — same #342-safe shape
    /// as `biometricError` — rather than a local `@State` that could carry a
    /// prior vault's choice across route re-entry.
    @Binding var rememberDevice: Bool
    /// Invoked when the user taps "Unlock with Face ID".
    let onBiometricUnlock: () -> Void
    let onUnlocked: (VaultSession, _ password: [UInt8]?) -> Void

    @State private var mode: UnlockViewModel.Mode = .password
    @State private var password: String = ""
    @State private var phrase: String = ""
    @State private var lastPasswordSecret: [UInt8]?

    init(viewModel: UnlockViewModel,
         biometricEnrolled: Bool = false,
         biometricError: Binding<String?> = .constant(nil),
         rememberDevice: Binding<Bool> = .constant(false),
         onBiometricUnlock: @escaping () -> Void = {},
         onUnlocked: @escaping (VaultSession, _ password: [UInt8]?) -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.biometricEnrolled = biometricEnrolled
        self._biometricError = biometricError
        self._rememberDevice = rememberDevice
        self.onBiometricUnlock = onBiometricUnlock
        self.onUnlocked = onUnlocked
    }

    private var isBusy: Bool { if case .busy = viewModel.state { return true } else { return false } }

    var body: some View {
        NavigationStack {
            Form {
                Picker("Unlock with", selection: $mode) {
                    Text("Password").tag(UnlockViewModel.Mode.password)
                    Text("Recovery phrase").tag(UnlockViewModel.Mode.recovery)
                }
                .pickerStyle(.segmented)

                if biometricEnrolled {
                    Section {
                        Button("Unlock with Face ID") { onBiometricUnlock() }
                    }
                }

                switch mode {
                case .password:
                    Section("Master password") {
                        SecureField("password", text: $password)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                    }
                    if !biometricEnrolled {
                        Toggle("Remember this device with Face ID", isOn: $rememberDevice)
                    }
                case .recovery:
                    Section("24-word recovery phrase") {
                        TextField("word word word …", text: $phrase, axis: .vertical)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
                            .lineLimit(3...6)
                    }
                }

                Section {
                    Button("Unlock") {
                        viewModel.mode = mode
                        let secret: [UInt8] = mode == .password
                            ? Array(password.utf8)
                            : Array(RecoveryPhrase.normalize(phrase).utf8)
                        lastPasswordSecret = (mode == .password) ? secret : nil
                        Task { await viewModel.unlock(secret: secret) }
                    }
                }
                .disabled(isBusy)

                if case .failed(let err) = viewModel.state {
                    Section("Error") {
                        Text(String(describing: err)).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }

                if let biometricError {
                    Section("Couldn’t unlock") {
                        Text(biometricError).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Unlock vault")
            .overlay { if isBusy { ProgressView() } }
            .onChange(of: stateIsUnlocked) { _, unlocked in
                if unlocked, case .unlocked(let session) = viewModel.state {
                    onUnlocked(session, lastPasswordSecret)
                    lastPasswordSecret = nil       // drop our copy
                }
            }
        }
    }

    // A Bool projection so `.onChange` fires exactly when we transition to unlocked.
    private var stateIsUnlocked: Bool {
        if case .unlocked = viewModel.state { return true } else { return false }
    }
}
