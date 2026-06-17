package org.secretary.browse

import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordContent

/**
 * Pure [RecordContentInput] → generated [RecordContent] mapping for the record edit/add write path.
 * The FFI bridge wraps both payloads in zeroize-on-drop SecretString / SecretBytes; the foreign-side
 * String / ByteArray are the caller's to clear (the edit form drops them on cancel/commit/lock).
 * Mirror of iOS `UniffiVaultSession.toFfi`.
 */
internal fun toFfi(content: RecordContentInput): RecordContent =
    RecordContent(
        recordType = content.recordType,
        tags = content.tags,
        fields = content.fields.map { f ->
            FieldInput(
                name = f.name,
                value = when (val v = f.value) {
                    is FieldContentValue.Text -> FieldInputValue.Text(v.value)
                    is FieldContentValue.Bytes -> FieldInputValue.Bytes(v.value)
                },
            )
        },
    )
