package org.secretary.browse

/**
 * Pure encoding of a [VaultLocation] to/from a single persisted string (one atomic
 * SharedPreferences value, so a location can never half-persist with a URI but no name).
 * The encoding is reversible for any location with a non-empty tree URI — the only domain
 * that ever reaches the codec in practice, since a real location comes from the SAF picker.
 * Free functions, no Android dependency → fully host-testable.
 *
 * Format: `"<VERSION>:<displayName.length>:<displayName><treeUri>"`. The display name is
 * length-prefixed (UTF-16 code units, matching `String.length` / `String.substring`) so
 * it needs no escaping and may contain any character — including the `:` delimiter. The
 * only structural delimiters are the version tag and the single colon after the length
 * digits.
 */

/** Codec format version; bump when the encoding changes so old blobs decode to null. */
internal const val VAULT_LOCATION_CODEC_VERSION = "v1"

/** Encode [location] to its persisted string form. */
fun encodeVaultLocation(location: VaultLocation): String =
    "$VAULT_LOCATION_CODEC_VERSION:${location.displayName.length}:${location.displayName}${location.treeUri}"

/**
 * Decode a string produced by [encodeVaultLocation]. Returns null for anything malformed
 * — empty tree URI, wrong/absent version tag, missing length delimiter, non-numeric or
 * negative length, or a payload shorter than the declared name length — a conservative
 * under-report mirroring `FileDeviceEnrollmentMetadataStore.load`. Never throws.
 */
fun decodeVaultLocation(encoded: String): VaultLocation? {
    val prefix = "$VAULT_LOCATION_CODEC_VERSION:"
    if (!encoded.startsWith(prefix)) return null
    val rest = encoded.substring(prefix.length)
    val colon = rest.indexOf(':')
    if (colon < 0) return null
    val nameLen = rest.substring(0, colon).toIntOrNull() ?: return null
    if (nameLen < 0) return null
    val payload = rest.substring(colon + 1)
    if (payload.length < nameLen) return null
    val displayName = payload.substring(0, nameLen)
    val treeUri = payload.substring(nameLen)
    // An empty SAF tree URI is never valid — conservative under-report, same as other malformed cases.
    if (treeUri.isEmpty()) return null
    return VaultLocation(displayName, treeUri)
}
