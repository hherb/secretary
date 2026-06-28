package org.secretary.mirror

/**
 * androidTest staging helpers for [CloudWorkingCopyLifecycleInstrumentedTest].
 *
 * Kept minimal: the production lifecycle types ([VaultWorkingCopyCoordinator],
 * [VaultMirrorWorkingCopy], [VaultMirror], [FilePendingFlushMarker]) and the real SAF port
 * ([safCloudFolderPort]) are wired directly in the test. The only thing missing from the
 * production surface for this test is a bytes → hex helper for the vault uuid: `org.secretary.browse`
 * exposes `hexToBytesPublic` (hex → bytes) but no public bytes → hex, so we provide it here.
 */

/** Lowercase hex of [bytes] (e.g. a 16-byte vault uuid → 32 hex chars). No separators. */
fun bytesToHex(bytes: ByteArray): String =
    bytes.joinToString(separator = "") { "%02x".format(it) }

/**
 * Canonical hyphenated lowercase UUID of a 16-byte [uuid] (8-4-4-4-12), matching the on-disk block
 * filename core's `format_uuid_hyphenated` writes (`blocks/<uuid>.cbor.enc`). Used by
 * [TwoWorkingCopiesConflictInstrumentedTest] to address the canonical block file + place its
 * conflict-copy sibling. Requires exactly 16 bytes.
 */
fun formatUuidHyphenated(uuid: ByteArray): String {
    require(uuid.size == 16) { "uuid must be 16 bytes, got ${uuid.size}" }
    val hex = bytesToHex(uuid)
    return "${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-" +
        "${hex.substring(16, 20)}-${hex.substring(20, 32)}"
}
