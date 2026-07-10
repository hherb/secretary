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
import uniffi.secretary.openVaultWithRecovery
import uniffi.secretary.openWithDeviceSecret as ffiOpenWithDeviceSecret
import uniffi.secretary.readBlock as ffiReadBlock
import uniffi.secretary.resurrectRecord as ffiResurrectRecord
import uniffi.secretary.tombstoneRecord as ffiTombstoneRecord
import uniffi.secretary.appendRecord as ffiAppendRecord
import uniffi.secretary.editRecord as ffiEditRecord
import uniffi.secretary.createBlock as ffiCreateBlock
import uniffi.secretary.renameBlock as ffiRenameBlock
import uniffi.secretary.moveRecord as ffiMoveRecord
import java.security.SecureRandom

/**
 * The real [VaultOpenPort] over the generated `uniffi.secretary` open call. The only browse code
 * (with [UniffiVaultSession]) that invokes the bindings. Kotlin mirror of iOS `UniffiVaultOpenPort`.
 *
 * [openWithPassword] re-derives the vault key with Argon2id, so it runs on [ioDispatcher]
 * (default [Dispatchers.IO]) to keep the caller responsive. The password [ByteArray] is forwarded
 * per call (UTF-8 path + raw password bytes) and never retained. [openWithRecovery] behaves
 * identically — it also runs on [ioDispatcher] (Argon2id) and forwards the phrase bytes per call
 * without retaining them. [openWithDeviceSecret] behaves identically — it runs on [ioDispatcher]
 * and forwards the 16-byte device UUID + 32-byte device secret per call without retaining them,
 * opening via the per-device wrap slot. The open function is an injectable seam defaulting to the real binding.
 *
 * The secret argument crosses the FFI as a direct [java.nio.ByteBuffer] minted (and scrubbed) per
 * call by [withDirectSecret] — uniffi 0.32's `[ByRef] bytes` zero-copy path (#307).
 */
class UniffiVaultOpenPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val deviceUuids: DeviceUuidProvider? = null,
    private val openFn: (ByteArray, java.nio.ByteBuffer) -> OpenVaultOutput = ::openVaultWithPassword,
    private val recoveryFn: (ByteArray, java.nio.ByteBuffer) -> OpenVaultOutput = ::openVaultWithRecovery,
    private val deviceSecretFn: (ByteArray, ByteArray, java.nio.ByteBuffer) -> OpenVaultOutput = ::ffiOpenWithDeviceSecret,
) : VaultOpenPort {
    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors {
                withDirectSecret(password) { pw ->
                    openFn(vaultFolder.toByteArray(Charsets.UTF_8), pw)
                }
            }
            UniffiVaultSession(output, ioDispatcher, deviceUuids)
        }

    override suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors {
                withDirectSecret(phrase) { p ->
                    recoveryFn(vaultFolder.toByteArray(Charsets.UTF_8), p)
                }
            }
            UniffiVaultSession(output, ioDispatcher, deviceUuids)
        }

    override suspend fun openWithDeviceSecret(
        vaultFolder: String,
        deviceUuid: ByteArray,
        deviceSecret: ByteArray,
    ): VaultSession =
        withContext(ioDispatcher) {
            val output = mapErrors {
                withDirectSecret(deviceSecret) { secret ->
                    deviceSecretFn(vaultFolder.toByteArray(Charsets.UTF_8), deviceUuid, secret)
                }
            }
            UniffiVaultSession(output, ioDispatcher, deviceUuids)
        }
}

/**
 * The real [VaultSession]: owns the decrypted [OpenVaultManifest] + [UnlockedIdentity] handles,
 * plus the single on-screen [BlockReadOutput] retained from [readBlock] (at most one at a time).
 * [blockSummaries] reads in-memory manifest metadata. [readBlock] decrypts ONE block, evicts the
 * prior [currentBlock], retains the new one (NO `.use{}`), and builds one [RevealableField] per
 * field whose `reveal` lambda calls `expose_text`/`expose_bytes` ON DEMAND — no secret value is
 * materialized until the user taps. [wipe] zeroizes the current block → manifest → identity in
 * that order (mirrors iOS UniffiVaultSession). Kotlin mirror of iOS `UniffiVaultSession`.
 *
 * Thread-safety: unlike iOS (whose `readBlock` is synchronous), Android runs [readBlock] on
 * [ioDispatcher] while [wipe] runs on the main thread (the slice-7 `ON_STOP` lock-on-background).
 * Every touch of the shared FFI state — the `identity`/`manifest` handles and [currentBlock] —
 * is therefore serialized under [sessionLock], and a [wiped] flag makes a read that loses
 * the race to a concurrent [wipe] zeroize its just-decrypted block instead of leaving plaintext
 * resident after a lock the caller believed cleared everything.
 */
class UniffiVaultSession(
    output: OpenVaultOutput,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val deviceUuids: DeviceUuidProvider? = null,
) : VaultSession {
    private val identity: UnlockedIdentity = output.identity
    private val manifest: OpenVaultManifest = output.manifest

    /** The vault UUID is immutable for the session's life, so it is snapshotted to hex at
     *  construction (while the manifest handle is valid). [vaultUuidHex] returns this stored
     *  value and never touches the FFI handle, so it stays correct after [wipe] zeroizes the
     *  manifest — a post-wipe read pre-fix returned the bridge's all-zero default (#252). */
    private val vaultUuidHexValue: String = hexOfBytes(manifest.vaultUuid())

    /** Serializes all access to the FFI handles + [currentBlock] across the IO dispatcher (reads)
     *  and the main thread (wipe). The held section spans the block decrypt, so a concurrent
     *  [wipe] waits for an in-flight read (bounded — one block decrypt is milliseconds). */
    private val sessionLock = Any()

    /** Set true by [wipe]; a read that observes it must not retain its block. */
    private var wiped: Boolean = false

    /** Resolved once per session (first write) so every write stamps the same device UUID. */
    private var cachedDeviceUuid: ByteArray? = null

    /** The single retained decrypted block — the on-screen one. Bounding to one block (not a
     *  growing list) makes "≤1 block resident" a type-level invariant and dedups re-selection.
     *  The VM clears the reveal map on selectBlock, so no live reveal closure references a prior
     *  block when we evict it here. Mirror of iOS UniffiVaultSession.currentBlock (#251). */
    private var currentBlock: BlockReadOutput? = null

    override fun vaultUuidHex(): String = vaultUuidHexValue

    override fun blockSummaries(): List<BlockSummaryView> =
        synchronized(sessionLock) {
            // After wipe() the session is closed: return no blocks without touching the zeroized
            // manifest handle (mirrors readBlock's lost-race empty return + the write-path guard).
            // The bridge also returns empty for a wiped handle, but the session enforces its own
            // contract rather than relying on that cross-crate default. In-memory manifest metadata
            // (no decryption), routed through mapErrors so any VaultException surfaces as a typed
            // VaultBrowseError rather than a raw FFI throwable.
            if (wiped) emptyList()
            else mapErrors { manifest.blockSummaries().map(::mapBlockSummary) }
        }

    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> =
        withContext(ioDispatcher) {
            mapErrors {
                synchronized(sessionLock) {
                    val block = ffiReadBlock(identity, manifest, blockUuid, includeDeleted)
                    if (wiped) {
                        // Lost the race to a concurrent wipe(): the session is closed. Zeroize the
                        // block we just decrypted rather than retain plaintext past the lock.
                        block.wipe()
                        return@synchronized emptyList<RecordSummaryView>()
                    }
                    // Decrypt-first ordering: `block` is decoded above; a thrown read left the
                    // prior block retained. Evict it before retaining the new one (NO .use{} —
                    // reveal closures depend on currentBlock until wipe()).
                    currentBlock?.wipe()
                    currentBlock = block
                    val count = block.recordCount().toInt()
                    (0 until count).map { i ->
                        // Record is a transient Kotlin wrapper; the FieldHandle secrets it
                        // yields are zeroized via the BlockReadOutput.wipe() cascade in wipe(),
                        // not via this handle.
                        val rec = block.recordAt(i.toULong())
                            ?: throw VaultBrowseError.CorruptVault("recordAt($i) returned null on an open block")
                        toRecordView(rec)
                    }
                }
            }
        }

    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        write { dev, now -> ffiTombstoneRecord(identity, manifest, blockUuid, recordUuid, dev, now) }

    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) =
        write { dev, now -> ffiResurrectRecord(identity, manifest, blockUuid, recordUuid, dev, now) }

    /** Mint a fresh 16-byte record UUID (SecureRandom — never in the pure model), append, return it. */
    override suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray =
        write { dev, now ->
            val recordUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
            ffiAppendRecord(identity, manifest, blockUuid, recordUuid, toFfi(content), dev, now)
            recordUuid
        }

    override suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput) =
        write { dev, now -> ffiEditRecord(identity, manifest, blockUuid, recordUuid, toFfi(content), dev, now) }

    override suspend fun createBlock(blockName: String): ByteArray =
        write { dev, now ->
            val blockUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
            ffiCreateBlock(identity, manifest, blockUuid, blockName, dev, now)
            blockUuid
        }

    override suspend fun renameBlock(blockUuid: ByteArray, newName: String) =
        write { dev, now -> ffiRenameBlock(identity, manifest, blockUuid, newName, dev, now) }

    override suspend fun moveRecord(
        sourceBlockUuid: ByteArray,
        targetBlockUuid: ByteArray,
        sourceRecordUuid: ByteArray,
    ): ByteArray =
        write { dev, now ->
            val newRecordUuid = ByteArray(16).also { SecureRandom().nextBytes(it) }
            ffiMoveRecord(
                identity, manifest, sourceBlockUuid, targetBlockUuid,
                sourceRecordUuid, newRecordUuid, dev, now,
            )
            newRecordUuid
        }

    /**
     * Resolve (device-uuid, now-ms), run the FFI write under [sessionLock] + the [wiped] guard, and
     * map errors. A write that loses the race to a concurrent wipe() must not touch zeroized handles.
     * Generic so [appendRecord] can return the minted UUID; [tombstoneRecord]/[resurrectRecord] infer T=Unit.
     */
    private suspend fun <T> write(body: (deviceUuid: ByteArray, nowMs: ULong) -> T): T =
        withContext(ioDispatcher) {
            mapErrors {
                synchronized(sessionLock) {
                    if (wiped) throw VaultBrowseError.Failed("write on a wiped session")
                    val dev = deviceUuid()
                    body(dev, System.currentTimeMillis().toULong())
                }
            }
        }

    /** Resolve + cache the per-vault device UUID; surface a store failure as a typed error. */
    private fun deviceUuid(): ByteArray {
        cachedDeviceUuid?.let { return it }
        val provider = deviceUuids
            ?: throw VaultBrowseError.Failed("read-only session: no device-uuid provider configured")
        val d = try {
            provider.deviceUuid(vaultUuidHex())
        } catch (e: DeviceUuidException) {
            throw VaultBrowseError.Failed("device-uuid resolve failed: ${e.message}")
        }
        cachedDeviceUuid = d
        return d
    }

    /** Map one decrypted [Record] handle to a view whose fields reveal plaintext ON DEMAND. */
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
        // Under sessionLock so an in-flight readBlock either completes before we zeroize the
        // handles or observes `wiped` and zeroizes its own block (idempotent — wipe may be called
        // repeatedly, e.g. ON_STOP then explicit lock).
        synchronized(sessionLock) {
            wiped = true
            currentBlock?.wipe()
            currentBlock = null
            manifest.wipe()
            identity.wipe()
        }
    }
}

/** Run an FFI call, translating any [VaultException] into the domain [VaultBrowseError]. */
internal inline fun <T> mapErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultBrowseError(e)
    }

/** Production factory for the real open port (defaults to the live bindings + IO dispatcher). */
fun uniffiVaultOpenPort(): VaultOpenPort = UniffiVaultOpenPort()

/** Production factory that supports writes (delete/restore/edit): inject a device-uuid provider. */
fun uniffiVaultOpenPort(deviceUuids: DeviceUuidProvider): VaultOpenPort =
    UniffiVaultOpenPort(deviceUuids = deviceUuids)
