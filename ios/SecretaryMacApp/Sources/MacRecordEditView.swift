import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Add / edit a record on macOS. A sheet over the shared, host-tested
/// `RecordEditViewModel` (the same VM the iOS `RecordEditScreen` uses). Renders
/// editable type / tags / field rows and forwards Save; on `committed` it calls
/// `onDone`, which dismisses the sheet and re-reads the block in the browse VM.
///
/// macOS differences from the iOS screen: no `.textInputAutocapitalization`
/// (iOS-only); no `.onDelete` swipe (macOS Forms have no List edit mode) — a
/// field row carries an explicit delete button (identity-safe, keyed on the
/// `EditableField.id`). Tags are plain strings with no identity, so an emptied
/// tag row is simply dropped on save (the VM already filters empty tags in
/// `buildContent`); clearing a tag's text is how you remove it.
@MainActor
struct MacRecordEditView: View {
    @StateObject private var viewModel: RecordEditViewModel
    let title: String
    let onDone: () -> Void
    let onCancel: () -> Void

    init(viewModel: RecordEditViewModel, title: String,
         onDone: @escaping () -> Void, onCancel: @escaping () -> Void) {
        _viewModel = StateObject(wrappedValue: viewModel)
        self.title = title
        self.onDone = onDone
        self.onCancel = onCancel
    }

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section("Type") {
                    TextField("record type (e.g. login)", text: $viewModel.recordType)
                }
                Section("Tags") {
                    ForEach(viewModel.tags.indices, id: \.self) { i in
                        TextField("tag (clear to remove)", text: $viewModel.tags[i])
                    }
                    Button("Add tag") { viewModel.tags.append("") }
                }
                Section("Fields") {
                    ForEach($viewModel.fields) { $field in
                        VStack(alignment: .leading, spacing: 6) {
                            HStack {
                                TextField("name", text: $field.name)
                                Button {
                                    viewModel.fields.removeAll { $0.id == field.id }
                                } label: {
                                    Image(systemName: "minus.circle")
                                }
                                .buttonStyle(.borderless)
                                .help("Remove this field")
                            }
                            Picker("kind", selection: $field.kind) {
                                Text("Text").tag(FieldContentValue.Kind.text)
                                Text("Bytes (hex)").tag(FieldContentValue.Kind.bytes)
                            }
                            .pickerStyle(.segmented)
                            if field.kind == .text {
                                SecureField("value", text: $field.rawText)
                            } else {
                                TextField("hex bytes", text: $field.rawText)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    Button("Add field") { viewModel.addField() }
                }
                if let err = viewModel.error {
                    Section("Error") {
                        Text(err.localizedDescription)
                            .font(.footnote)
                            .foregroundStyle(.red)
                    }
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Button("Cancel", role: .cancel) { onCancel() }
                Spacer()
                Button("Save") { Task { await viewModel.commit() } }
                    .keyboardShortcut(.defaultAction)
                    .disabled(viewModel.loadFailed || viewModel.committed || viewModel.isWriting)
            }
            .padding()
        }
        .frame(minWidth: 440, minHeight: 480)
        .navigationTitle(title)
        // Single-param overload (macOS 13 floor; see MacBrowseView).
        .onChange(of: viewModel.committed) { done in
            if done { onDone() }
        }
    }
}
