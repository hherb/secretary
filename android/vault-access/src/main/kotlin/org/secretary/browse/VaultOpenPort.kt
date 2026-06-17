package org.secretary.browse

/**
 * Opens a vault folder, producing a [VaultSession]. The pure seam mirrors iOS `VaultOpenPort`; the
 * real implementation (`:kit` `UniffiVaultOpenPort`) runs Argon2id off the main thread. The
 * [password] is forwarded per call and never retained by the port.
 */
interface VaultOpenPort {
    suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession
}

/**
 * An opened vault. The single owner of the decrypted manifest + identity handles. [blockSummaries]
 * is in-memory manifest metadata (no decryption); [readBlock] decrypts ONE block and returns
 * metadata-only [RecordSummaryView]s (it never exposes a secret value). [wipe] zeroizes/releases the
 * underlying handles and is idempotent. Mirror of iOS `VaultSession`.
 */
interface VaultSession {
    fun vaultUuidHex(): String
    fun blockSummaries(): List<BlockSummaryView>
    suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView>
    fun wipe()
}
