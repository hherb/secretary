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

/** Parse a 32-char lowercase hex string to its raw bytes. Inverse of [hexOfBytes]. */
internal fun hexToBytes(hex: String): ByteArray =
    ByteArray(hex.length / 2) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
