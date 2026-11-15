import SwiftUI
import SecretaryDeviceUnlock
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Password / recovery-phrase unlock. Thin shell: renders `viewModel.state` and
/// forwards the entered secret. On `.unlocked` it calls `onUnlocked(session, password)`
/// where `password` is non-nil only for `.password` mode; it is used only for the
/// optional "remember this device" enrollment (sync needs no password, #101).
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
                Section {
                    SecretaryBrandHeader(
                        title: "Welcome back",
                        subtitle: "Unlock locally. Your vault remains encrypted at rest.")
                }
                .listRowBackground(Color.clear)

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
                            .secretaryVaultPasswordInput()
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
                        let isPassword = mode == .password
                        submit(isPassword ? Array(password.utf8) : Array(RecoveryPhrase.normalize(phrase).utf8),
                               isPassword: isPassword) { await viewModel.unlock(secret: $0) }
                    }
                    .buttonStyle(.borderedProminent)
                }
                .disabled(isBusy)

                if case .rollbackResetPrompt = viewModel.state {
                    RollbackResetSection(
                        onConfirm: {
                            submit(Array(password.utf8), isPassword: true) {
                                await viewModel.confirmRollbackReset(secret: $0)
                            }
                        },
                        onCancel: { viewModel.cancelRollbackReset() })
                }

                if case .failed(let err) = viewModel.state {
                    Section("Error") {
                        Text(err.localizedDescription).font(.footnote).foregroundStyle(.red)
                    }
                }

                if let biometricError {
                    Section("Couldn’t unlock") {
                        Text(biometricError).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Unlock vault")
            .secretaryScreenChrome()
            .overlay { if isBusy { ProgressView() } }
            .onChange(of: stateIsUnlocked) { _, unlocked in
                if unlocked, case .unlocked(let session) = viewModel.state {
                    onUnlocked(session, lastPasswordSecret)
                    lastPasswordSecret = nil       // drop our copy
                }
            }
        }
    }

    /// Run one open attempt with `secret`, retaining a password copy for the
    /// `onUnlocked` hand-off. If the attempt does not unlock (a failure, or the
    /// rollback prompt, which takes the password again on confirm) the secret is
    /// never handed off, so drop + wipe our retained copy now instead of holding
    /// it until the next attempt. Nil the `@State` reference FIRST so `secret`
    /// becomes uniquely referenced, then `zeroize` overwrites the real backing
    /// buffer — a still-shared `[UInt8]` would only COW-clear a throwaway copy.
    /// Best-effort: the SwiftUI `password`/`phrase` Strings and any bytes already
    /// copied across the FFI are out of reach (see `zeroize`). On success the
    /// buffer is deliberately kept for sync/enroll and released by `onChange`.
    private func submit(_ secretIn: [UInt8], isPassword: Bool,
                        _ attempt: @escaping ([UInt8]) async -> Void) {
        var secret = secretIn
        lastPasswordSecret = isPassword ? secret : nil
        Task {
            await attempt(secret)
            if !stateIsUnlocked {
                lastPasswordSecret = nil
                zeroize(&secret)
            }
        }
    }

    // A Bool projection so `.onChange` fires exactly when we transition to unlocked.
    private var stateIsUnlocked: Bool {
        if case .unlocked = viewModel.state { return true } else { return false }
    }
}

/// The rollback-reset prompt (#746): the explanation plus explicit confirm and
/// cancel. A separate view so `UnlockScreen.body` stays under the type-checker's
/// time limit.
private struct RollbackResetSection: View {
    let onConfirm: () -> Void
    let onCancel: () -> Void

    var body: some View {
        Section(RollbackResetCopy.title) {
            Text(RollbackResetCopy.body).font(.footnote)
            Button(RollbackResetCopy.confirm, role: .destructive, action: onConfirm)
            Button(RollbackResetCopy.cancel, role: .cancel, action: onCancel)
        }
    }
}
