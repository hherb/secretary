package org.secretary.browse

private const val HEX_DIGITS = "0123456789abcdef"

/**
 * Lowercase hex encoding of [bytes] (two chars per byte, zero-padded). Pure; used to derive the
 * stable string identity of a block/record UUID for UI keys and equality (raw [ByteArray] has
 * referential equals/hashCode, so hex is the safe identity).
 */
fun hexOfBytes(bytes: ByteArray): String {
    val sb = StringBuilder(bytes.size * 2)
    for (b in bytes) {
        val v = b.toInt() and 0xff
        sb.append(HEX_DIGITS[v ushr 4]).append(HEX_DIGITS[v and 0x0f])
    }
    return sb.toString()
}

/**
 * Parse an even-length lowercase hex string to its raw bytes. Inverse of [hexOfBytes].
 * Trusted-input only: callers pass [RecordSummaryView.uuidHex] / [BlockSummaryView.uuidHex], which
 * the adapter produces via [hexOfBytes], so length/charset are guaranteed. Malformed input throws an
 * unmapped `NumberFormatException` — do not feed it user-supplied strings.
 */
internal fun hexToBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

/**
 * Parse a hex string to bytes, leniently: whitespace is stripped (so users can paste spaced hex)
 * and digits are case-insensitive. Returns `null` if the cleaned string has odd length or any
 * non-hex character. Inverse of [hexOfBytes] for the byte-field edit affordance; mirror of iOS
 * `RecordEditViewModel.parseHex`. Unlike [hexToBytes] (trusted, throwing), this is for USER input.
 */
fun parseHexLenient(s: String): ByteArray? {
    val cleaned = s.filterNot { it.isWhitespace() }
    if (cleaned.length % 2 != 0) return null
    val out = ByteArray(cleaned.length / 2)
    for (i in out.indices) {
        val hi = Character.digit(cleaned[i * 2], 16)
        val lo = Character.digit(cleaned[i * 2 + 1], 16)
        if (hi < 0 || lo < 0) return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
