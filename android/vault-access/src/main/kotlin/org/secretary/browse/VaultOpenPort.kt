package org.secretary.browse

/**
 * Opens a vault folder, producing a [VaultSession]. The pure seam mirrors iOS `VaultOpenPort`; the
 * real implementation (`:kit` `UniffiVaultOpenPort`) runs Argon2id off the main thread. The
 * [password] is forwarded per call and never retained by the port.
 */
interface VaultOpenPort {
    suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession

    /**
     * Opens a vault folder with its 24-word BIP-39 recovery phrase. [phrase] is the UTF-8 bytes of
     * the (normalized) phrase, forwarded per call and never retained. The real impl runs Argon2id
     * off the main thread, like [openWithPassword]. Mirror of iOS `VaultOpenPort.openWithRecovery`.
     */
    suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession

    /**
     * Opens a vault folder with a per-device wrap slot. [deviceUuid] is the 16-byte device identifier
     * and [deviceSecret] is the 32-byte wrapped key (derived from Secure Enclave or Keystore storage).
     * Both are forwarded per call and never retained. Mirror of iOS `VaultOpenPort.openWithDeviceSecret`.
     */
    suspend fun openWithDeviceSecret(vaultFolder: String, deviceUuid: ByteArray, deviceSecret: ByteArray): VaultSession
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

    /** Soft-delete one live record (tombstone). Device-uuid + now-ms are resolved inside the impl. */
    suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray)

    /** Restore one tombstoned record (resurrect). Device-uuid + now-ms are resolved inside the impl. */
    suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray)

    /**
     * Append a new record built from [content] to the block; returns the freshly-minted 16-byte
     * record UUID. The UUID is minted INSIDE the impl (SecureRandom in the real adapter) so the pure
     * model stays deterministic. Device-uuid + now-ms are resolved inside the impl.
     */
    suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray

    /**
     * Replace one live record's editable part (type / tags / fields) with [content]. `record_uuid`,
     * `created_at_ms`, per-field clocks and `unknown` maps are preserved by the bridge. Device-uuid +
     * now-ms are resolved inside the impl. `RecordNotFound` if no live record with [recordUuid].
     */
    suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput)

    /**
     * Create a new (empty) block named [blockName]; mints (SecureRandom in the real adapter) and
     * returns its fresh 16-byte UUID. Device-uuid + now-ms are resolved inside the impl.
     */
    suspend fun createBlock(blockName: String): ByteArray

    /**
     * Rename the block identified by [blockUuid] to [newName]. `BlockNotFound` if no such block.
     * Device-uuid + now-ms are resolved inside the impl.
     */
    suspend fun renameBlock(blockUuid: ByteArray, newName: String)

    /**
     * Move the live record [sourceRecordUuid] from [sourceBlockUuid] into [targetBlockUuid], minting
     * (SecureRandom) and returning the fresh target record UUID. Copy-to-target then tombstone-in-
     * source. Caller guarantees source != target. Device-uuid + now-ms resolved inside the impl.
     */
    suspend fun moveRecord(
        sourceBlockUuid: ByteArray,
        targetBlockUuid: ByteArray,
        sourceRecordUuid: ByteArray,
    ): ByteArray

    fun wipe()
}
