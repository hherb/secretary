package org.secretary.browse

/** One numbered word of a recovery phrase, for on-screen display. [word] is an un-zeroizable
 *  String — the accepted best-effort tradeoff for showing a phrase the user must read. */
data class MnemonicWord(val index: Int, val word: String)

/**
 * Number the words of a UTF-8 recovery [phrase] for display (1-based). Splits on any whitespace run
 * and drops empties — the canonical BIP-39 phrase is single-space-joined, this tolerates display
 * noise. Pure: the input [phrase] `ByteArray` is read, never mutated (its zeroize lifetime is owned
 * by the caller — `VaultProvisioningViewModel`). Note that decoding to a `String` copies the bytes
 * into an un-zeroizable buffer; that is the documented display tradeoff.
 */
fun groupMnemonic(phrase: ByteArray): List<MnemonicWord> =
    String(phrase, Charsets.UTF_8)
        .split(Regex("\\s+"))
        .filter { it.isNotEmpty() }
        .mapIndexed { i, w -> MnemonicWord(index = i + 1, word = w) }
