import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Trash browser sheet (macOS): lists trashed blocks with per-row Restore /
/// Delete-forever via a context menu (the D.5.3 idiom — NOT swipe), plus Empty
/// trash and Run-retention-now in a bottom bar. Mirrors iOS `TrashScreen` over the
/// shared, host-tested `TrashViewModel`; every destructive op routes through the
/// VM's re-auth write gate. macOS diffs from the iOS screen: context menus instead
/// of swipe actions, and a bottom button bar instead of a NavigationStack toolbar.
@MainActor
struct MacTrashView: View {
    @StateObject private var viewModel: TrashViewModel
    let onDone: () -> Void

    @State private var pendingPurge: TrashedBlockInfo?
    @State private var pendingEmpty = false
    @State private var showRetention = false

    init(viewModel: TrashViewModel, onDone: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.onDone = onDone
    }

    var body: some View {
        VStack(spacing: 0) {
            if let notice = viewModel.purgeNotice {
                Text(notice.text)
                    .font(.footnote)
                    .foregroundStyle(notice.severity == .warning ? Color.orange : Color.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal).padding(.vertical, 8)
            }
            List {
                if viewModel.entries.isEmpty {
                    Text("Trash is empty.").foregroundStyle(.secondary)
                }
                ForEach(viewModel.entries, id: \.uuidHex) { block in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(block.blockName.isEmpty ? "block" : block.blockName)
                            .font(.headline)
                        Text("trashed \(formatTrashedWhen(block.tombstonedAtMs, timeZone: .current, locale: .current))")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    .contextMenu {
                        Button {
                            Task { await viewModel.restore(uuid: block.blockUuid) }
                        } label: {
                            Label("Restore", systemImage: "arrow.uturn.backward")
                        }
                        .disabled(viewModel.isWriting)
                        Button(role: .destructive) {
                            pendingPurge = block
                        } label: {
                            Label("Delete forever", systemImage: "trash")
                        }
                        .disabled(viewModel.isWriting)
                    }
                }
            }
            if let error = viewModel.error {
                Text(error.localizedDescription)
                    .font(.footnote).foregroundStyle(.red)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.horizontal)
            }
            Divider()
            HStack {
                Button("Done") { onDone() }
                Spacer()
                Button {
                    showRetention = true
                } label: {
                    Label("Run retention now", systemImage: "clock.arrow.circlepath")
                }
                .disabled(viewModel.isWriting)
                if !viewModel.entries.isEmpty {
                    Button(role: .destructive) { pendingEmpty = true } label: { Text("Empty trash") }
                        .disabled(viewModel.isWriting)
                }
            }
            .padding()
        }
        .frame(minWidth: 440, minHeight: 440)
        .navigationTitle("Trash")
        .onAppear { viewModel.load() }
        .confirmationDialog("Delete forever?",
            isPresented: Binding(get: { pendingPurge != nil },
                                 set: { if !$0 { pendingPurge = nil } }),
            titleVisibility: .visible) {
            if let block = pendingPurge {
                Button("Delete forever", role: .destructive) {
                    Task { await viewModel.purge(uuid: block.blockUuid) }
                    pendingPurge = nil
                }.disabled(viewModel.isWriting)
            }
            Button("Cancel", role: .cancel) { pendingPurge = nil }
        } message: {
            if let block = pendingPurge {
                Text("\"\(block.blockName)\" will be permanently deleted. This cannot be undone.")
            }
        }
        .confirmationDialog("Empty trash?",
            isPresented: $pendingEmpty, titleVisibility: .visible) {
            Button("Empty trash", role: .destructive) {
                Task { await viewModel.emptyTrash() }
                pendingEmpty = false
            }.disabled(viewModel.isWriting)
            Button("Cancel", role: .cancel) { pendingEmpty = false }
        } message: {
            Text(emptyTrashConfirmBody(count: viewModel.entries.count))
        }
        .sheet(isPresented: $showRetention) {
            MacRetentionSheet(viewModel: viewModel, isPresented: $showRetention)
        }
    }
}

/// Retention preview + purge, nested within the Trash sheet. Mirrors iOS
/// `RetentionSheet`; macOS uses a bottom button bar instead of a NavigationStack.
@MainActor
private struct MacRetentionSheet: View {
    @ObservedObject var viewModel: TrashViewModel
    @Binding var isPresented: Bool

    var body: some View {
        VStack(spacing: 20) {
            Text("Run retention").font(.headline)
            if let preview = viewModel.preview {
                Text(retentionSummary(entries: preview, windowMs: viewModel.retentionWindowMs))
                    .multilineTextAlignment(.center)
                if !preview.isEmpty {
                    Button(role: .destructive) {
                        Task { await viewModel.runRetention(); isPresented = false }
                    } label: { Text("Purge \(preview.count) items") }
                    .disabled(viewModel.isWriting)
                }
            } else {
                ProgressView("Checking trash…")
            }
            Spacer()
            Divider()
            HStack {
                Button("Close") { isPresented = false }
                Spacer()
            }
        }
        .padding()
        .frame(minWidth: 360, minHeight: 220)
        .onAppear { viewModel.previewRetention() }
        .onDisappear { viewModel.clearPreview() }
    }
}
