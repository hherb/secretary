import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Password / recovery-phrase unlock. Thin shell: renders `viewModel.state` and
/// forwards the entered secret. On `.unlocked` it calls `onUnlocked(session)`.
struct UnlockScreen: View {
    @StateObject private var viewModel: UnlockViewModel
    let onUnlocked: (VaultSession) -> Void

    @State private var mode: UnlockViewModel.Mode = .password
    // Demo convenience ONLY: the app stages the golden demo vault, so prefilling
    // its fixture password saves typing. MUST be removed when real vault
    // selection/import lands — never ship a prefilled credential into a build
    // that opens a user's real vault.
    @State private var password: String = "correct horse battery staple"
    @State private var phrase: String = ""

    init(viewModel: UnlockViewModel, onUnlocked: @escaping (VaultSession) -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
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

                switch mode {
                case .password:
                    Section("Master password") {
                        SecureField("password", text: $password)
                            .textInputAutocapitalization(.never)
                            .autocorrectionDisabled()
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
                        Task { await viewModel.unlock(secret: secret) }
                    }
                }
                .disabled(isBusy)

                if case .failed(let err) = viewModel.state {
                    Section("Error") {
                        Text(String(describing: err)).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Unlock vault")
            .overlay { if isBusy { ProgressView() } }
            .onChange(of: stateIsUnlocked) { _, unlocked in
                if unlocked, case .unlocked(let session) = viewModel.state { onUnlocked(session) }
            }
        }
    }

    // A Bool projection so `.onChange` fires exactly when we transition to unlocked.
    private var stateIsUnlocked: Bool {
        if case .unlocked = viewModel.state { return true } else { return false }
    }
}
