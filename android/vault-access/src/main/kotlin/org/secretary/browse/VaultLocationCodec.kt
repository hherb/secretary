package org.secretary.browse

/**
 * Pure encoding of a [VaultLocation] to/from a single persisted string (one atomic
 * SharedPreferences value, so a location can never half-persist with a URI but no name).
 * The encoding is reversible for any location with a non-empty tree URI — the only domain
 * that ever reaches the codec in practice, since a real location comes from the SAF picker.
 * Free functions, no Android dependency → fully host-testable.
 *
 * **v2 format (current):**
 * `"v2:<nameLen>:<uuidLen>:<name><uuid><treeUri>"`
 * Two length prefixes (UTF-16 code units, matching `String.length` / `String.substring`):
 * the display name length and the uuid-hex length. Both fields may contain any character,
 * including `:`, with no escaping. The treeUri is the remainder after the two prefixed
 * segments.
 *
 * **v1 format (tolerant decode only):**
 * `"v1:<nameLen>:<name><treeUri>"`
 * Produced by Slice-4 and earlier. Decoded to `vaultUuidHex = ""` — never null — so
 * that a pre-Slice-5 persisted location remains readable without prompting a new pick.
 */

/** Codec format version; bump when the encoding changes in a non-backward-compatible way. */
internal const val VAULT_LOCATION_CODEC_VERSION = "v2"

/** Encode [location] to its persisted string form. */
fun encodeVaultLocation(location: VaultLocation): String =
    "$VAULT_LOCATION_CODEC_VERSION:${location.displayName.length}:${location.vaultUuidHex.length}:" +
        "${location.displayName}${location.vaultUuidHex}${location.treeUri}"

/**
 * Decode a string produced by [encodeVaultLocation]. Returns null for anything malformed
 * — empty tree URI, wrong/absent version tag, missing length delimiter, non-numeric or
 * negative length, or a payload shorter than the declared field lengths.
 * A v1 blob (no uuid segment) decodes with `vaultUuidHex = ""` (tolerant).
 * Never throws.
 */
fun decodeVaultLocation(encoded: String): VaultLocation? {
    if (encoded.startsWith("v2:")) return decodeV2(encoded.substring(3))
    if (encoded.startsWith("v1:")) return decodeV1(encoded.substring(3))
    return null
}

private fun decodeV2(rest: String): VaultLocation? {
    val c1 = rest.indexOf(':')
    if (c1 < 0) return null
    val nameLen = rest.substring(0, c1).toIntOrNull()?.takeIf { it >= 0 } ?: return null
    val afterName = rest.substring(c1 + 1)
    val c2 = afterName.indexOf(':')
    if (c2 < 0) return null
    val uuidLen = afterName.substring(0, c2).toIntOrNull()?.takeIf { it >= 0 } ?: return null
    val payload = afterName.substring(c2 + 1)
    if (payload.length < nameLen + uuidLen) return null
    val name = payload.substring(0, nameLen)
    val uuid = payload.substring(nameLen, nameLen + uuidLen)
    val treeUri = payload.substring(nameLen + uuidLen)
    // An empty SAF tree URI is never valid — conservative under-report.
    if (treeUri.isEmpty()) return null
    return VaultLocation(name, treeUri, uuid)
}

private fun decodeV1(rest: String): VaultLocation? {
    val colon = rest.indexOf(':')
    if (colon < 0) return null
    val nameLen = rest.substring(0, colon).toIntOrNull()?.takeIf { it >= 0 } ?: return null
    val payload = rest.substring(colon + 1)
    if (payload.length < nameLen) return null
    val name = payload.substring(0, nameLen)
    val treeUri = payload.substring(nameLen)
    // An empty SAF tree URI is never valid — conservative under-report.
    if (treeUri.isEmpty()) return null
    return VaultLocation(name, treeUri, "")
}
