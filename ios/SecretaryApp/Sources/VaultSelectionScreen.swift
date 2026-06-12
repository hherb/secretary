import SwiftUI
import UniformTypeIdentifiers
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// First screen: pick a vault folder (system file importer) or open the remembered
/// one. Also offers an explicit, opt-in "Try the demo vault" (no prefilled
/// password). Calls `onOpen` with a held `ScopedVaultPath` once a vault is ready to
/// unlock; `onOpenDemo` stages + opens the bundled golden vault.
struct VaultSelectionScreen: View {
    @ObservedObject var viewModel: VaultSelectionViewModel
    let onOpen: (ScopedVaultPath) -> Void
    let onOpenDemo: () -> Void

    @State private var importing = false
    @State private var errorText: String?

    var body: some View {
        NavigationStack {
            Form {
                switch viewModel.state {
                case .empty:
                    selectSection
                case .located(let name):
                    Section("Remembered vault") {
                        Text(name).font(.body.monospaced())
                        Button("Open") { open() }
                        Button("Choose a different vault") { viewModel.chooseDifferent() }
                    }
                case .unavailable(let reason):
                    Section("Vault unavailable") {
                        Text(reason).font(.footnote).foregroundStyle(.secondary)
                        Button("Select a vault…") { importing = true }
                        Button("Choose a different vault") { viewModel.chooseDifferent() }
                    }
                }

                Section {
                    Button("Try the demo vault") { onOpenDemo() }
                }

                if let errorText {
                    Section("Error") {
                        Text(errorText).font(.footnote.monospaced()).foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle("Choose vault")
            .onAppear { viewModel.loadPersisted() }
            .fileImporter(isPresented: $importing,
                          allowedContentTypes: [.folder]) { result in
                handleImport(result)
            }
        }
    }

    private var selectSection: some View {
        Section("Open a vault") {
            Button("Select a vault…") { importing = true }
        }
    }

    private func open() {
        errorText = nil
        do {
            let scoped = try viewModel.beginAccess()
            onOpen(scoped)
        } catch {
            // If the VM already reflects the failure (.unavailable carries the
            // reason), don't also show a redundant Error line; otherwise surface it.
            if case .unavailable = viewModel.state {
                errorText = nil
            } else {
                errorText = String(describing: error)
            }
        }
    }

    private func handleImport(_ result: Result<URL, Error>) {
        errorText = nil
        switch result {
        case .failure(let error):
            errorText = String(describing: error)
        case .success(let url):
            // Create the bookmark while access is briefly held (iOS requirement).
            let didAccess = url.startAccessingSecurityScopedResource()
            defer { if didAccess { url.stopAccessingSecurityScopedResource() } }
            do {
                let bookmark = try url.bookmarkData()
                viewModel.recordSelection(bookmark: bookmark,
                                          displayName: url.lastPathComponent)
            } catch {
                errorText = String(describing: error)
            }
        }
    }
}
