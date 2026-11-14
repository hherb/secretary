import SwiftUI
import SecretaryKit
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// The Mac copy for a write refused as `.vaultChangedOnDisk` (#101). The shared
/// copy says "Sync", and the Mac app has no sync yet, so it says Reload instead.
let macVaultChangedOnDiskMessage = "This vault changed on another device. Reload, then try again."

/// Shown wherever a Mac write surface would render `.vaultChangedOnDisk`: the
/// browse overlay and every sheet that owns its own error (record edit, move,
/// block name, trash, settings). Reload re-reads the manifest into the OWNING
/// browse view model's session, which every sheet's view model shares, then
/// calls `onReloaded` (a sheet dismisses itself there).
///
/// The failure text is view-local state, so it disappears with the notice as
/// soon as the error stops being `.vaultChangedOnDisk`; it cannot stick to a
/// later, unrelated error.
@MainActor
struct MacReloadNotice: View {
    @ObservedObject var browseViewModel: VaultBrowseViewModel
    var onReloaded: () -> Void = {}
    @State private var failure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(failure ?? macVaultChangedOnDiskMessage)
                .font(.footnote)
                .foregroundStyle(.red)
            // Interim until the Mac sync slice lands; remove this button then (#101).
            Button("Reload") {
                do {
                    browseViewModel.reloadFromDisk(stateDir: try defaultSyncStateDir().path)
                    onReloaded()
                } catch {
                    failure = "Could not locate the sync state folder."
                }
            }
        }
    }
}
