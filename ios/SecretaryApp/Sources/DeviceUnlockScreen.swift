import SwiftUI
import SecretaryDeviceUnlock
import SecretaryDeviceUnlockUI

/// Thin shell: renders `viewModel.state` and forwards button taps. No logic.
struct DeviceUnlockScreen: View {
    @StateObject private var viewModel: DeviceUnlockViewModel
    /// Pinned uuid for the happy-path match readout (nil if unavailable).
    let pinnedVaultUuidHex: String?
    @State private var password: String = "correct horse battery staple"

    init(viewModel: DeviceUnlockViewModel, pinnedVaultUuidHex: String?) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.pinnedVaultUuidHex = pinnedVaultUuidHex
    }

    private var isBusy: Bool { if case .busy = viewModel.state { return true } else { return false } }

    var body: some View {
        NavigationStack {
            Form {
                Section("Status") { Text(statusText).font(.callout.monospaced()) }

                Section("Demo vault password (enroll)") {
                    SecureField("password", text: $password)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }

                Section {
                    Button("Enroll") { Task { await viewModel.enroll(password: Array(password.utf8)) } }
                    Button("Unlock (Face ID)") { Task { await viewModel.unlock(reason: "Unlock your Secretary vault") } }
                    Button("Disenroll", role: .destructive) { Task { await viewModel.disenroll() } }
                }
                .disabled(isBusy)

                if let detail = failureDetail {
                    Section("Last error detail (raw domain+code)") {
                        Text(detail).font(.footnote.monospaced()).foregroundStyle(.secondary)
                    }
                }
            }
            .navigationTitle("Secretary")
            .overlay { if isBusy { ProgressView() } }
            .onAppear { viewModel.refreshStatus() }
        }
    }

    private var statusText: String {
        switch viewModel.state {
        case .idle:               return "…"
        case .notEnrolled:        return "not enrolled"
        case .enrolled:           return "enrolled — ready to unlock"
        case .busy(let a):        return "busy: \(a)"
        case .unlocked(let hex):
            let match = pinnedVaultUuidHex.map { $0 == hex ? " ✅ matches pinned" : " ❌ MISMATCH" } ?? ""
            return "unlocked\nvault_uuid=\(hex)\(match)"
        case .failed(let err, _): return "failed: \(err)"
        }
    }

    private var failureDetail: String? {
        if case .failed(_, let detail) = viewModel.state { return detail }
        return nil
    }
}
