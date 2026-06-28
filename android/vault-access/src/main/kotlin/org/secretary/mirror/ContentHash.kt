package org.secretary.mirror

import java.security.MessageDigest
import java.util.HexFormat

/**
 * Lowercase-hex SHA-256 of [bytes]. [VaultMirror] uses it to decide whether a working-copy
 * file and its cloud-folder counterpart hold identical content: every block rewrite
 * re-encrypts with a fresh nonce, so equal byte *length* does not imply equal content, and a
 * content hash is the only reliable same-or-different signal. Pure + deterministic
 * (`MessageDigest` is JVM-standard), so fully host-testable with no Android dependency.
 */
fun sha256Hex(bytes: ByteArray): String =
    HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes))
