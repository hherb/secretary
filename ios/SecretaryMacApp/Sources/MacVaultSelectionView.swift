import SwiftUI
import AppKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI
import SecretaryKit

/// Vault selection (macOS): shows the one remembered vault (if any), an "Open
/// other…" folder picker (`NSOpenPanel`), and the SKELETON-ONLY demo vault. On
/// macOS the "bookmark" handed to `considerImport` is the UTF-8 folder path (see
/// `FileVaultLocationStore`), not a security-scoped bookmark.
@MainActor
struct MacVaultSelectionView: View {
    @ObservedObject var viewModel: VaultSelectionViewModel
    let onOpen: (ScopedVaultPath) -> Void
    let onOpenDemo: () throws -> Void

    @State private var errorText: String?

    var body: some View {
        Form {
            switch viewModel.state {
            case .empty:
                Section("No vault selected") {
                    Button("Open other…") { pickFolder() }
                }
            case .located(let name):
                Section("Vault") {
                    Text(name)
                    Button("Open") { open() }
                    Button("Choose a different vault") { viewModel.chooseDifferent() }
                }
            case .unavailable(let reason):
                Section("Vault unavailable") {
                    Text(reason).foregroundStyle(.secondary)
                    Button("Choose a different vault") { viewModel.chooseDifferent() }
                }
            }

            Section("Demo") {
                Button("Open demo vault") {
                    do { try onOpenDemo() } catch { errorText = error.localizedDescription }
                }
            }

            if let errorText {
                Section("Error") { Text(errorText).foregroundStyle(.red) }
            }
        }
        .formStyle(.grouped)
        .frame(minWidth: 460, minHeight: 320)
        .onAppear { viewModel.loadPersisted() }
    }

    private func open() {
        do { onOpen(try viewModel.beginAccess()) }
        catch { errorText = error.localizedDescription }
    }

    /// macOS folder picker. The picked folder's UTF-8 path is the "bookmark".
    private func pickFolder() {
        errorText = nil
        let panel = NSOpenPanel()
        panel.canChooseDirectories = true
        panel.canChooseFiles = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Open Vault"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let outcome = viewModel.considerImport(url: url,
                                               bookmark: Data(url.path.utf8),
                                               displayName: url.lastPathComponent)
        switch outcome {
        case .opened:
            open()
        case .notAVault:
            errorText = "That folder is not a Secretary vault (no vault.toml)."
        case .unavailable(let reason):
            errorText = reason
        }
    }
}
