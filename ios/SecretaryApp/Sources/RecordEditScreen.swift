// ios/SecretaryApp/Sources/RecordEditScreen.swift
import SwiftUI
import SecretaryVaultAccess
import SecretaryVaultAccessUI

/// Add / edit a record. Thin shell over `RecordEditViewModel`: renders the
/// editable field rows and forwards Save. On `committed` it calls `onDone`,
/// which dismisses the sheet and re-reads the block in the browse VM.
struct RecordEditScreen: View {
    @StateObject private var viewModel: RecordEditViewModel
    let title: String
    let onDone: () -> Void

    init(viewModel: RecordEditViewModel, title: String, onDone: @escaping () -> Void) {
        self._viewModel = StateObject(wrappedValue: viewModel)
        self.title = title
        self.onDone = onDone
    }

    var body: some View {
        NavigationStack {
            Form {
                Section("Type") {
                    TextField("record type (e.g. login)", text: $viewModel.recordType)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                }
                Section("Tags") {
                    ForEach(viewModel.tags.indices, id: \.self) { i in
                        TextField("tag", text: $viewModel.tags[i])
                            .textInputAutocapitalization(.never).autocorrectionDisabled()
                    }
                    .onDelete { viewModel.tags.remove(atOffsets: $0) }
                    Button("Add tag") { viewModel.tags.append("") }
                }
                Section("Fields") {
                    ForEach($viewModel.fields) { $field in
                        VStack(alignment: .leading, spacing: 6) {
                            TextField("name", text: $field.name)
                                .textInputAutocapitalization(.never)
                                .autocorrectionDisabled()
                            Picker("kind", selection: $field.kind) {
                                Text("Text").tag(FieldContentValue.Kind.text)
                                Text("Bytes (hex)").tag(FieldContentValue.Kind.bytes)
                            }
                            .pickerStyle(.segmented)
                            if field.kind == .text {
                                SecureField("value", text: $field.rawText)
                            } else {
                                TextField("hex bytes", text: $field.rawText)
                                    .textInputAutocapitalization(.never)
                                    .autocorrectionDisabled()
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    .onDelete { viewModel.fields.remove(atOffsets: $0) }
                    Button("Add field") { viewModel.addField() }
                }
                Section {
                    Button("Save") { Task { await viewModel.commit() } }
                        .disabled(viewModel.loadFailed || viewModel.committed || viewModel.isWriting)
                }
                if let err = viewModel.error {
                    Section("Error") {
                        Text(String(describing: err))
                            .font(.footnote.monospaced())
                            .foregroundStyle(.red)
                    }
                }
            }
            .navigationTitle(title)
            .onChange(of: viewModel.committed) { _, done in
                if done { onDone() }
            }
        }
    }
}
