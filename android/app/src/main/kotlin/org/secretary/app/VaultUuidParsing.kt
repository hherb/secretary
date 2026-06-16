package org.secretary.app

private const val UUID_BYTES = 16

/**
 * Parses a vault UUID from its canonical dashed-hex form (e.g.
 * "00112233-4455-6677-8899-aabbccddeeff") into the 16 raw bytes the sync FFI expects.
 *
 * Pure (no Android dependency) so it is host-testable. The single source of truth for the
 * golden vault's UUID is the bundled `golden_vault_001_inputs.json`; AppVaultProvisioning
 * reads that JSON and calls this to decode it — there is no hardcoded UUID constant.
 *
 * @throws IllegalArgumentException if, after removing dashes, the string is not exactly 32
 *   hex digits.
 */
fun parseVaultUuidHex(dashedHex: String): ByteArray {
    val hex = dashedHex.replace("-", "")
    require(hex.length == UUID_BYTES * 2) {
        "vault UUID must be $UUID_BYTES bytes (32 hex digits), got ${hex.length} digits"
    }
    return ByteArray(UUID_BYTES) { i ->
        val byteHex = hex.substring(i * 2, i * 2 + 2)
        byteHex.toIntOrNull(16)?.toByte()
            ?: throw IllegalArgumentException("vault UUID contains non-hex characters: '$byteHex'")
    }
}
