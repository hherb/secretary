package org.secretary.browse

/**
 * Normalizes a user-typed BIP-39 recovery phrase before it is handed to the FFI: lowercases,
 * splits on any whitespace run, drops empty tokens, and rejoins single-spaced. The canonical
 * BIP-39 word list is all-lowercase and single-space-joined, so this removes the most common
 * copy/paste and keyboard auto-capitalization noise without altering the words themselves.
 * Pure — no side effects. Mirror of iOS `RecoveryPhrase.normalize`.
 */
object RecoveryPhrase {
    fun normalize(raw: String): String =
        raw.lowercase()
            .split(Regex("\\s+"))
            .filter { it.isNotEmpty() }
            .joinToString(" ")
}
