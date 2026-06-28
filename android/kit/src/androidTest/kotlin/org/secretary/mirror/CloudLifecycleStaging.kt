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
