package org.secretary.browse

/**
 * A revealed (decrypted) field value. Holds plaintext — callers must drop it promptly (see
 * [VaultBrowseModel], which clears it on hide / reload / lock). Mirror of iOS `RevealedValue`.
 *
 * [Bytes] defines structural equality via `contentEquals`: a `data class` over a [ByteArray] gives
 * referential equals/hashCode (Kotlin caveat), which would break test assertions and dedup.
 */
sealed interface RevealedValue {
    data class Text(val value: String) : RevealedValue

    class Bytes(val value: ByteArray) : RevealedValue {
        override fun equals(other: Any?): Boolean =
            this === other || (other is Bytes && value.contentEquals(other.value))

        override fun hashCode(): Int = value.contentHashCode()
    }
}

/** Whether a field's payload is text or raw bytes. Mirror of iOS `FieldView.Kind`. */
enum class FieldKind { Text, Bytes }

/**
 * One field of a record. [name] and [kind] are non-secret metadata; [reveal] materializes the
 * plaintext ON DEMAND only — the real adapter wires it to the FFI `expose_text`/`expose_bytes`, so
 * plaintext is never eagerly decrypted. NOT a data class (it holds a closure). Mirror of iOS
 * `FieldView`.
 */
class RevealableField(
    val name: String,
    val kind: FieldKind,
    val reveal: () -> RevealedValue,
)

/**
 * Policy constants for revealing secret field values. Auto-hide is driven by the Compose layer
 * (`BrowseScreen` attaches a `LaunchedEffect` that delays this interval then calls the view model's
 * `hide`). A named constant — never a magic number in the view. Mirror of iOS `RevealPolicy`.
 */
object RevealPolicy {
    /** How long a revealed value stays visible before the UI auto-hides it. */
    const val autoHideSeconds: Long = 30
}
