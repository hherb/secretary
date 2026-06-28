package org.secretary.browse

/** Upper bound on a typed vault name (it becomes a folder name + a display label). */
const val MAX_VAULT_NAME_LENGTH = 64

/** Outcome of validating a typed vault name. */
sealed interface VaultNameValidation {
    data class Valid(val name: String) : VaultNameValidation
    data class Invalid(val error: VaultNameError) : VaultNameValidation
}

/**
 * Why a typed vault name was rejected, with user-safe copy. Throwable to match the other
 * `:vault-access` error families, though it is normally consumed as a value via [VaultNameValidation].
 */
sealed class VaultNameError(message: String) : Exception(message) {
    data object Blank : VaultNameError("Enter a name for the vault.")
    data object TooLong : VaultNameError("That name is too long.")
    data object IllegalCharacters :
        VaultNameError("A vault name can't contain / or \\, control characters, or be just \".\" or \"..\".")
}

/**
 * Validate a typed vault name for use as both a folder name and a display label. Trims surrounding
 * whitespace, then rejects blank, over-[MAX_VAULT_NAME_LENGTH], path separators (`/` `\`), the
 * dot-only names (`.` `..`, which would collide with directory entries), and control / NUL chars.
 * Pure — no side effects. Mirror of iOS `validateVaultName`.
 */
fun validateVaultName(raw: String): VaultNameValidation {
    val name = raw.trim()
    if (name.isEmpty()) return VaultNameValidation.Invalid(VaultNameError.Blank)
    if (name.length > MAX_VAULT_NAME_LENGTH) return VaultNameValidation.Invalid(VaultNameError.TooLong)
    val illegal = name == "." || name == ".." ||
        name.any { it == '/' || it == '\\' || it.code < 0x20 || it.code == 0x7F }
    if (illegal) return VaultNameValidation.Invalid(VaultNameError.IllegalCharacters)
    return VaultNameValidation.Valid(name)
}
