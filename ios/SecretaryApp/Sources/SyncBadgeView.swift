// SyncBadgeView.swift
import SwiftUI
import SecretaryVaultAccess

/// Toolbar badge rendering `SyncBadgeState`. Tapping (when not syncing) starts an
/// interactive sync. The "synced … ago" label is computed from the state's epoch
/// millis against `nowMs` supplied by the parent.
struct SyncBadgeView: View {
    let state: SyncBadgeState
    let nowMs: UInt64
    let onTap: () -> Void

    var body: some View {
        Button(action: onTap) {
            switch state {
            case .syncing:
                HStack(spacing: 4) { ProgressView(); Text("Syncing…") }
            case .reviewNeeded:
                Label("Review needed", systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            case .changesDetected:
                Label("Changes detected", systemImage: "arrow.triangle.2.circlepath")
            case .synced(let sinceMs):
                Label(Self.syncedLabel(sinceMs: sinceMs, nowMs: nowMs),
                      systemImage: "checkmark.circle")
                    .foregroundStyle(.secondary)
            case .neverSynced:
                Label("Sync now", systemImage: "arrow.triangle.2.circlepath")
            }
        }
        .disabled(state == .syncing)
        .font(.footnote)
    }

    /// "Synced just now / Nm ago / Nh ago". Defends against a future-dated stamp.
    static func syncedLabel(sinceMs: UInt64, nowMs: UInt64) -> String {
        let deltaMs = nowMs > sinceMs ? nowMs - sinceMs : 0
        let seconds = deltaMs / 1_000
        if seconds < 60 { return "Synced just now" }
        let minutes = seconds / 60
        if minutes < 60 { return "Synced \(minutes)m ago" }
        return "Synced \(minutes / 60)h ago"
    }
}
