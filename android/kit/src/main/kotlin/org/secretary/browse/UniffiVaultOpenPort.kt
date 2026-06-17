package org.secretary.browse

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.secretary.BlockReadOutput
import uniffi.secretary.FieldHandle
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
 * The real [VaultSession]: owns the decrypted [OpenVaultManifest] + [UnlockedIdentity] handles,
 * plus every [BlockReadOutput] retained from [readBlock]. [blockSummaries] reads in-memory manifest
 * metadata. [readBlock] decrypts ONE block, retains it in [openBlocks] (NO `.use{}`), and builds
 * one [RevealableField] per field whose `reveal` lambda calls `expose_text`/`expose_bytes` ON DEMAND
 * — no secret value is materialized until the user taps. [wipe] zeroizes blocks → manifest →
 * identity in that order (mirrors iOS UniffiVaultSession). Kotlin mirror of iOS `UniffiVaultSession`.
 */
class UniffiVaultSession(
    output: OpenVaultOutput,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : VaultSession {
    private val identity: UnlockedIdentity = output.identity
    private val manifest: OpenVaultManifest = output.manifest

    /** Decrypted blocks retained so the per-field reveal closures (which capture a FieldHandle)
     *  stay valid until wipe(). Mirror of iOS UniffiVaultSession.openBlocks. */
    private val openBlocks: MutableList<BlockReadOutput> = mutableListOf()

    override fun vaultUuidHex(): String = hexOfBytes(manifest.vaultUuid())

    override fun blockSummaries(): List<BlockSummaryView> =
        // In-memory manifest metadata (no decryption), but route through mapErrors so any
        // VaultException surfaces as a typed VaultBrowseError rather than a raw FFI throwable.
        mapErrors { manifest.blockSummaries().map(::mapBlockSummary) }

    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> =
        withContext(ioDispatcher) {
            mapErrors {
                val block = ffiReadBlock(identity, manifest, blockUuid, includeDeleted)
                openBlocks += block   // retained (NO .use{}) — reveal closures depend on it
                val count = block.recordCount().toInt()
                (0 until count).map { i ->
                    val rec = block.recordAt(i.toULong())
                        ?: throw VaultBrowseError.CorruptVault("recordAt($i) returned null on an open block")
                    toRecordView(rec)
                }
            }
        }

    /** Map one decrypted [Record] handle to a view whose fields reveal plaintext ON DEMAND.
     *  The ONLY place expose_text/expose_bytes is called (inside each field's reveal lambda). */
    private fun toRecordView(record: Record): RecordSummaryView {
        val fieldCount = record.fieldCount().toInt()
        val fields = (0 until fieldCount).map { j ->
            val handle = record.fieldAt(j.toULong())
                ?: throw VaultBrowseError.CorruptVault("fieldAt($j) returned null on an open record")
            buildRevealableField(handle)
        }
        return RecordSummaryView(
            uuidHex = hexOfBytes(record.recordUuid()),
            type = record.recordType(),
            tags = record.tags(),
            createdAtMs = record.createdAtMs(),
            lastModMs = record.lastModMs(),
            tombstone = record.tombstone(),
            fields = fields,
        )
    }

    /** The secret-pull boundary: captures [handle]; calls expose_* only when reveal() is invoked. */
    private fun buildRevealableField(handle: FieldHandle): RevealableField {
        val kind = fieldKindOf(handle.isText())
        return RevealableField(name = handle.name(), kind = kind) {
            when (kind) {
                FieldKind.Text -> RevealedValue.Text(
                    handle.exposeText() ?: throw VaultBrowseError.CorruptVault("text field could not be exposed"))
                FieldKind.Bytes -> RevealedValue.Bytes(
                    handle.exposeBytes() ?: throw VaultBrowseError.CorruptVault("bytes field could not be exposed"))
            }
        }
    }

    override fun wipe() {
        // Order mirrors iOS: blocks (cascade zeroize to records + fields) → manifest → identity.
        openBlocks.forEach { it.wipe() }
        openBlocks.clear()
        manifest.wipe()
        identity.wipe()
    }
}

/** Run an FFI call, translating any [VaultException] into the domain [VaultBrowseError]. */
private inline fun <T> mapErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultBrowseError(e)
    }

/** Production factory for the real open port (defaults to the live bindings + IO dispatcher). */
fun uniffiVaultOpenPort(): VaultOpenPort = UniffiVaultOpenPort()
