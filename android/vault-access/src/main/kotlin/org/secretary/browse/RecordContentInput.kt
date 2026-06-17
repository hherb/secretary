package org.secretary.browse

/**
 * A field's plaintext value to write. [Text] is keyboard plaintext; [Bytes] is raw bytes (the edit
 * UI enters/edits these as hex). Mirrors the FFI `FieldInputValue` without naming it, keeping this
 * package FFI-free. Mirror of iOS `FieldContentValue`.
 *
 * [Bytes] defines structural equality via `contentEquals` (a data class over a [ByteArray] gives
 * referential equals/hashCode, which would break test assertions) — same caveat as [RevealedValue.Bytes].
 */
sealed interface FieldContentValue {
    data class Text(val value: String) : FieldContentValue

    class Bytes(val value: ByteArray) : FieldContentValue {
        override fun equals(other: Any?): Boolean =
            this === other || (other is Bytes && value.contentEquals(other.value))

        override fun hashCode(): Int = value.contentHashCode()
    }
}

/** One field to write: a non-secret [name] + a [value]. Mirrors FFI `FieldInput`. */
data class FieldContentInput(val name: String, val value: FieldContentValue)

/**
 * Full desired content of a record to add or edit. Mirrors FFI `RecordContent`. `record_uuid`,
 * `created_at_ms`, per-field clocks and forward-compat `unknown` maps are intentionally NOT here —
 * the bridge edit primitives own those (mint-on-add / preserve-on-edit). Mirror of iOS
 * `RecordContentInput`.
 */
data class RecordContentInput(
    val recordType: String,
    val tags: List<String>,
    val fields: List<FieldContentInput>,
) {
    /**
     * Pure pre-commit validation. `null` == valid. Field names must be non-blank and unique (the
     * bridge diffs fields by name on edit, so two same-named fields would alias). Record type and
     * tags are unconstrained; empty [fields] is allowed.
     */
    fun validate(): RecordContentInputError? {
        val seen = HashSet<String>()
        for (f in fields) {
            if (f.name.isBlank()) return RecordContentInputError.EmptyFieldName
            if (!seen.add(f.name)) return RecordContentInputError.DuplicateFieldName(f.name)
        }
        return null
    }
}

/** Why a [RecordContentInput] is not writable. Surfaced inline in the edit UI. */
sealed interface RecordContentInputError {
    data object EmptyFieldName : RecordContentInputError
    data class DuplicateFieldName(val name: String) : RecordContentInputError
}
