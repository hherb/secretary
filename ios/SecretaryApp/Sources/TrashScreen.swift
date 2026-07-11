import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

struct TrashScreen: View {
    @StateObject private var viewModel: TrashViewModel
    @State private var pendingPurge: TrashedBlockInfo?
    @State private var pendingEmpty = false
    @State private var showRetention = false

    init(viewModel: TrashViewModel) {
        self._viewModel = StateObject(wrappedValue: viewModel)
    }

    var body: some View {
        List {
            if viewModel.entries.isEmpty {
                Text("Trash is empty.").foregroundStyle(.secondary)
            }
            ForEach(viewModel.entries, id: \.uuidHex) { block in
                VStack(alignment: .leading, spacing: 2) {
                    Text(block.blockName.isEmpty ? "block" : block.blockName)
                        .font(.headline)
                    Text("trashed \(formatTrashedWhen(block.tombstonedAtMs))")
                        .font(.caption).foregroundStyle(.secondary)
                }
                .swipeActions(edge: .trailing) {
                    Button(role: .destructive) { pendingPurge = block } label: {
                        Label("Delete forever", systemImage: "trash")
                    }
                    .disabled(viewModel.isWriting)
                    Button {
                        Task { await viewModel.restore(uuid: block.blockUuid) }
                    } label: { Label("Restore", systemImage: "arrow.uturn.backward") }
                    .tint(.blue)
                    .disabled(viewModel.isWriting)
                }
            }
        }
        .navigationTitle("Trash")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { showRetention = true } label: {
                    Label("Run retention now", systemImage: "clock.arrow.circlepath")
                }
                .disabled(viewModel.isWriting)
            }
            if !viewModel.entries.isEmpty {
                ToolbarItem(placement: .bottomBar) {
                    Button(role: .destructive) { pendingEmpty = true } label: {
                        Text("Empty trash")
                    }
                    .disabled(viewModel.isWriting)
                    .accessibilityIdentifier("empty-trash")
                }
            }
        }
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
            RetentionSheet(viewModel: viewModel, isPresented: $showRetention)
        }
    }
}

private struct RetentionSheet: View {
    @ObservedObject var viewModel: TrashViewModel
    @Binding var isPresented: Bool

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let preview = viewModel.preview {
                    Text(retentionSummary(entries: preview,
                                          windowMs: viewModel.retentionWindowMs))
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
            }
            .padding()
            .navigationTitle("Run retention")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Close") { isPresented = false }
                }
            }
            .onAppear { viewModel.previewRetention() }
            .onDisappear { viewModel.clearPreview() }
        }
    }
}
