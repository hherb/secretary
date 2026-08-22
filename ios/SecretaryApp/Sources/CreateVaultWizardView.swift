import SwiftUI
import UniformTypeIdentifiers
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Three-step create wizard (folder → credentials → mnemonic) over a
/// `VaultProvisioningViewModel`. On completion, calls `onCreated` with the
/// persisted `VaultLocation` so the host can route to the unlock screen
/// (re-enter password — desktop D.1.3 parity, no auto-open).
struct CreateVaultWizardView: View {
    @ObservedObject var viewModel: VaultProvisioningViewModel
    let onCreated: (VaultLocation) -> Void
    let onCancel: () -> Void

    @State private var pickingParent = false
    @State private var parentURL: URL?
    @State private var vaultName = ""
    @State private var displayName = ""
    @State private var password = ""
    @State private var confirm = ""

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    SecretaryBrandHeader(
                        title: "Create a new vault",
                        subtitle: stepSubtitle)
                }
                .listRowBackground(Color.clear)

                switch viewModel.step {
                case .folder:        folderStep
                case .credentials:   credentialsStep
                case .mnemonic:      mnemonicStep
                case .done(let loc): Color.clear.onAppear { onCreated(loc) }
                }
            }
            .navigationTitle("Create vault")
            .secretaryScreenChrome()
            .toolbar { ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { viewModel.cancel(); onCancel() }
            } }
            .fileImporter(isPresented: $pickingParent,
                          allowedContentTypes: [.folder]) { result in
                if case .success(let url) = result { parentURL = url }
            }
        }
    }

    private var folderStep: some View {
        Section("Location") {
            Button("Choose parent folder…") { pickingParent = true }
            if let parentURL { Text(parentURL.lastPathComponent).font(.footnote.monospaced()) }
            TextField("Vault name", text: $vaultName)
            if let e = viewModel.nameError { Text(message(for: e)).foregroundStyle(.red).font(.footnote) }
            Button("Continue") {
                if let parentURL { viewModel.chooseParent(parentURL, vaultName: vaultName) }
            }
            .buttonStyle(.borderedProminent)
            .disabled(parentURL == nil || vaultName.isEmpty)
        }
    }

    private var credentialsStep: some View {
        Section("Credentials") {
            TextField("Display name", text: $displayName)
            SecureField("Master password", text: $password)
                .secretaryVaultPasswordInput()
            SecureField("Confirm password", text: $confirm)
                .secretaryVaultPasswordInput()
            if viewModel.error == .passwordMismatch {
                Text("Passwords do not match").foregroundStyle(.red).font(.footnote)
            } else if let e = viewModel.error {
                Text(message(for: e)).foregroundStyle(.red).font(.footnote)
            }
            Button("Create vault") {
                Task {
                    var pw = Array(password.utf8); var cf = Array(confirm.utf8)
                    await viewModel.create(displayName: displayName, password: pw, confirm: cf)
                    for i in pw.indices { pw[i] = 0 }; for i in cf.indices { cf[i] = 0 }
                    password = ""; confirm = ""
                }
            }
            .buttonStyle(.borderedProminent)
            .disabled(displayName.isEmpty || password.isEmpty || confirm.isEmpty
                      || viewModel.isCreating)
            if viewModel.isCreating { ProgressView("Creating vault…") }
        }
    }

    private var mnemonicStep: some View {
        Section("Recovery phrase") {
            Text("Write these 24 words down and keep them safe. This is the only way to recover your vault if you forget the password.")
                .font(.footnote).foregroundStyle(.secondary)
            ForEach(viewModel.mnemonicRows ?? [], id: \.number) { w in
                Text("\(w.number). \(w.word)").font(.body.monospaced())
            }
            Button("I have written down my recovery phrase") {
                viewModel.acknowledgeMnemonic()
            }
            .buttonStyle(.borderedProminent)
        }
    }

    private var stepSubtitle: String {
        switch viewModel.step {
        case .folder: return "Step 1 of 3 · Choose where your encrypted vault lives."
        case .credentials: return "Step 2 of 3 · Protect it with a strong master password."
        case .mnemonic: return "Step 3 of 3 · Save your recovery phrase offline."
        case .done: return "Your encrypted vault is ready."
        }
    }

    private func message(for e: VaultNameError) -> String {
        switch e {
        case .empty: return "Enter a vault name"
        case .containsSeparator: return "Name can't contain “/”"
        case .reservedName: return "Choose a different name"
        }
    }

    private func message(for e: VaultProvisioningError) -> String {
        switch e {
        case .folderNotEmpty: return "A folder with that name already exists — choose another"
        case .folderInvalid: return "That location can't be used"
        case .passwordMismatch: return "Passwords do not match"
        case .createFailed(let d): return "Couldn't create the vault (\(d))"
        }
    }
}
