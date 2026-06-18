package org.secretary.browse

/**
 * Errors raised by the vault open/browse surface. Throwable (mirrors [org.secretary.sync.VaultSyncError])
 * so the coordinator can `catch (e: VaultBrowseError)`. Deliberately SEPARATE from `VaultSyncError`:
 * the open/read FFI returns a different `VaultException` arm set; folding them would misattribute errors.
 *
 * [WrongPasswordOrCorrupt] is intentionally conflated (wrong password vs. corruption) per the threat
 * model's anti-oracle rule (§13). Do NOT split it.
 */
sealed class VaultBrowseError(message: String? = null) : Exception(message) {
    /** Open failed: wrong password OR corrupt vault. Conflated on purpose (§13). */
    data object WrongPasswordOrCorrupt : VaultBrowseError()

    /** Recovery open failed: wrong phrase OR corrupt vault. Conflated on purpose (§13). */
    data object WrongRecoveryOrCorrupt : VaultBrowseError()

    /** The recovery phrase was malformed (bad word / wrong length / invalid UTF-8) — a format
     *  error, distinct from the conflated [WrongRecoveryOrCorrupt]. Safe to surface to the user. */
    data class InvalidRecoveryPhrase(val detail: String) : VaultBrowseError(detail)

    /** The opened folder is a different vault than expected. */
    data object VaultMismatch : VaultBrowseError()

    /** The vault on disk is structurally corrupt. */
    data class CorruptVault(val detail: String) : VaultBrowseError(detail)

    /** The supplied folder path is not a readable vault folder. */
    data class FolderInvalid(val detail: String) : VaultBrowseError(detail)

    /** No block with the requested UUID exists in the manifest. */
    data class BlockNotFound(val uuidHex: String) : VaultBrowseError(uuidHex)

    /** A caller argument was malformed (e.g. wrong-length UUID). */
    data class InvalidArgument(val detail: String) : VaultBrowseError(detail)

    /** A write targeted a record that does not exist in the requested state (e.g. a peer already
     *  deleted it). Surfaced by tombstone/resurrect/edit. */
    data class RecordNotFound(val uuidHex: String) : VaultBrowseError(uuidHex)

    /** The save tail (atomic manifest + block rewrite) failed during a write. */
    data class SaveCryptoFailure(val detail: String) : VaultBrowseError(detail)

    /** Any other open/read/write failure: the mapper's else-fold, plus the device-uuid resolve
     *  failure and the no-provider (read-only session) write attempt. */
    data class Failed(val detail: String) : VaultBrowseError(detail)
}
