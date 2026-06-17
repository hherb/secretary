package org.secretary.browse

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.OpenVaultManifest
import uniffi.secretary.OpenVaultOutput
import uniffi.secretary.Record
import uniffi.secretary.UnlockedIdentity
import uniffi.secretary.VaultException
import uniffi.secretary.openVaultWithPassword
import uniffi.secretary.readBlock as ffiReadBlock

/**
 * The real [VaultOpenPort] over the generated `uniffi.secretary` open call. The only browse code
 * (with [UniffiVaultSession]) that invokes the bindings. Kotlin mirror of iOS `UniffiVaultOpenPort`.
 *
 * [openWithPassword] re-derives the vault key with Argon2id, so it runs on [ioDispatcher]
 * (default [Dispatchers.IO]) to keep the caller responsive. The password [ByteArray] is forwarded
 * per call (UTF-8 path + raw password bytes) and never retained. The open function is an injectable
 * seam defaulting to the real binding.
 */
class UniffiVaultOpenPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val openFn: (ByteArray, ByteArray) -> OpenVaultOutput = ::openVaultWithPassword,
) : VaultOpenPort {
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors { openFn(vaultFolder.toByteArray(Charsets.UTF_8), password) }
            UniffiVaultSession(output, ioDispatcher)
        }
}

/**
 * The real [VaultSession]: owns the decrypted [OpenVaultManifest] + [UnlockedIdentity] handles.
 * [blockSummaries] reads in-memory manifest metadata. [readBlock] decrypts ONE block on
 * [ioDispatcher], maps each [Record]'s metadata + field NAMES to a [RecordSummaryView], and closes
 * the block output immediately — it NEVER calls `exposeText`/`exposeBytes`, so no secret value is
 * materialized while browsing. [wipe] zeroizes the manifest + identity (idempotent).
 */
class UniffiVaultSession(
    output: OpenVaultOutput,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : VaultSession {
    private val identity: UnlockedIdentity = output.identity
    private val manifest: OpenVaultManifest = output.manifest

    override fun vaultUuidHex(): String = hexOfBytes(manifest.vaultUuid())

    override fun blockSummaries(): List<BlockSummaryView> =
        // In-memory manifest metadata (no decryption), but route through mapErrors so any
        // VaultException surfaces as a typed VaultBrowseError rather than a raw FFI throwable.
        mapErrors { manifest.blockSummaries().map(::mapBlockSummary) }

    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> =
        withContext(ioDispatcher) {
            mapErrors {
                // `.use` closes (and zeroizes) the decrypted block output as soon as we have copied
                // the metadata out — no decrypted record handle outlives this call.
                ffiReadBlock(identity, manifest, blockUuid, includeDeleted).use { block ->
                    val count = block.recordCount().toInt()
                    (0 until count).mapNotNull { i ->
                        block.recordAt(i.toULong())?.use(::toRecordSummaryView)
                    }
                }
            }
        }

    override fun wipe() {
        // Idempotent zeroize-now of both long-lived handles (mirrors iOS UniffiVaultSession.wipe).
        manifest.wipe()
        identity.wipe()
    }
}

/** Map one decrypted [Record] handle to a metadata-only view. NEVER reads a field value. */
private fun toRecordSummaryView(record: Record): RecordSummaryView =
    RecordSummaryView(
        uuidHex = hexOfBytes(record.recordUuid()),
        type = record.recordType(),
        tags = record.tags(),
        createdAtMs = record.createdAtMs(),
        lastModMs = record.lastModMs(),
        tombstone = record.tombstone(),
        fieldNames = record.fieldNames(),
    )

/** Run an FFI call, translating any [VaultException] into the domain [VaultBrowseError]. */
private inline fun <T> mapErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultBrowseError(e)
    }

/** Production factory for the real open port (defaults to the live bindings + IO dispatcher). */
fun uniffiVaultOpenPort(): VaultOpenPort = UniffiVaultOpenPort()
