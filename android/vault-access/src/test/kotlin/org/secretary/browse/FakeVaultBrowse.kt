package org.secretary.browse

import kotlinx.coroutines.CompletableDeferred

/** Build a text field whose reveal returns a canned value (host tests only). */
fun textField(name: String, value: String): RevealableField =
    RevealableField(name, FieldKind.Text) { RevealedValue.Text(value) }

/** In-memory [VaultSession] for host tests. Records whether it was wiped; keyed by block uuidHex. */
class FakeVaultSession(
    private val vaultUuidHex: String,
    private val blocks: List<BlockSummaryView>,
    recordsByBlockHex: Map<String, List<RecordSummaryView>> = emptyMap(),
    private val readError: VaultBrowseError? = null,
    private val blocksError: VaultBrowseError? = null,
    private val writeError: VaultBrowseError? = null,
    /** A non-[VaultBrowseError] throwable a write raises raw — models a uniffi InternalException
     *  (Rust panic) that mapErrors does NOT translate, so callers must fold it themselves. */
    private val rawWriteThrowable: Throwable? = null,
    /** When set, every write suspends on this gate before recording — lets a test hold a write
     *  in flight while a second call hits the model's re-entrancy guard (a faithful race, not a sleep). */
    private val writeGate: CompletableDeferred<Unit>? = null,
) : VaultSession {
    var wiped: Boolean = false
        private set
    /** The `includeDeleted` arg of the most recent readBlock call (null until first read). */
    var lastIncludeDeleted: Boolean? = null
        private set
    /** (blockHex, recordUuidHex) of each tombstone/resurrect call, in order. */
    val tombstoned: MutableList<Pair<String, String>> = mutableListOf()
    val resurrected: MutableList<Pair<String, String>> = mutableListOf()
    /** (blockHex, content) of each appendRecord call, in order. */
    val appended: MutableList<Pair<String, RecordContentInput>> = mutableListOf()
    /** (blockHex, recordHex, content) of each editRecord call, in order. */
    val edited: MutableList<Triple<String, String, RecordContentInput>> = mutableListOf()
    private var nextFakeUuidByte: Int = 0xA0

    private val records: MutableMap<String, MutableList<RecordSummaryView>> =
        recordsByBlockHex.mapValues { it.value.toMutableList() }.toMutableMap()

    override fun vaultUuidHex(): String = vaultUuidHex
    override fun blockSummaries(): List<BlockSummaryView> {
        blocksError?.let { throw it }
        return blocks
    }
    override suspend fun readBlock(blockUuid: ByteArray, includeDeleted: Boolean): List<RecordSummaryView> {
        lastIncludeDeleted = includeDeleted
        readError?.let { throw it }
        val all = records[hexOfBytes(blockUuid)] ?: return emptyList()
        return if (includeDeleted) all.toList() else all.filter { !it.tombstone }
    }
    override suspend fun tombstoneRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeGate?.await()
        writeError?.let { throw it }
        tombstoned += hexOfBytes(blockUuid) to hexOfBytes(recordUuid)
        flipTombstone(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = true)
    }
    override suspend fun resurrectRecord(blockUuid: ByteArray, recordUuid: ByteArray) {
        writeGate?.await()
        writeError?.let { throw it }
        resurrected += hexOfBytes(blockUuid) to hexOfBytes(recordUuid)
        flipTombstone(hexOfBytes(blockUuid), hexOfBytes(recordUuid), tombstone = false)
    }
    override suspend fun appendRecord(blockUuid: ByteArray, content: RecordContentInput): ByteArray {
        writeGate?.await()
        writeError?.let { throw it }
        rawWriteThrowable?.let { throw it }
        val blockHex = hexOfBytes(blockUuid)
        appended += blockHex to content
        // Mint a deterministic distinct uuid for the fake (real adapter uses SecureRandom).
        val uuid = ByteArray(16).also { it[15] = (nextFakeUuidByte and 0xff).toByte() }
        nextFakeUuidByte += 1
        val list = records.getOrPut(blockHex) { mutableListOf() }
        list += RecordSummaryView(
            uuidHex = hexOfBytes(uuid),
            type = content.recordType,
            tags = content.tags,
            createdAtMs = 0u,
            lastModMs = 0u,
            tombstone = false,
            fields = content.fields.map { it.toRevealableField() },
        )
        return uuid
    }

    override suspend fun editRecord(blockUuid: ByteArray, recordUuid: ByteArray, content: RecordContentInput) {
        writeGate?.await()
        writeError?.let { throw it }
        rawWriteThrowable?.let { throw it }
        val blockHex = hexOfBytes(blockUuid)
        val recordHex = hexOfBytes(recordUuid)
        edited += Triple(blockHex, recordHex, content)
        val list = records[blockHex]
        val i = list?.indexOfFirst { it.uuidHex == recordHex } ?: -1
        if (i < 0) throw VaultBrowseError.RecordNotFound(recordHex)
        list!![i] = list[i].copy(
            type = content.recordType,
            tags = content.tags,
            fields = content.fields.map { it.toRevealableField() },
        )
    }

    override fun wipe() { wiped = true }

    private fun flipTombstone(blockHex: String, recordHex: String, tombstone: Boolean) {
        val list = records[blockHex] ?: return
        val i = list.indexOfFirst { it.uuidHex == recordHex }
        if (i >= 0) list[i] = list[i].copy(tombstone = tombstone)
    }
}

/** Turn an input field into a canned RevealableField for the fake's re-read. */
private fun FieldContentInput.toRevealableField(): RevealableField = when (val v = value) {
    is FieldContentValue.Text -> RevealableField(name, FieldKind.Text) { RevealedValue.Text(v.value) }
    is FieldContentValue.Bytes -> RevealableField(name, FieldKind.Bytes) { RevealedValue.Bytes(v.value) }
}

/**
 * Scriptable [VaultOpenPort]: returns [session] or throws the matching error; records every open by
 * credential kind so dispatch tests can assert which path fired with which bytes.
 */
class FakeVaultOpenPort(
    private val session: VaultSession = FakeVaultSession("00", emptyList()),
    private val openError: VaultBrowseError? = null,
    private val recoveryError: VaultBrowseError? = null,
) : VaultOpenPort {
    val openedFolders: MutableList<String> = mutableListOf()
    /** Copies of the password bytes seen by each openWithPassword call, in order. */
    val openedWithPassword: MutableList<ByteArray> = mutableListOf()
    /** Copies of the phrase bytes seen by each openWithRecovery call, in order. */
    val openedWithRecovery: MutableList<ByteArray> = mutableListOf()
    /** Copies of the (deviceUuid, deviceSecret) pairs seen by each openWithDeviceSecret call, in order. */
    val openedWithDeviceSecret: MutableList<Pair<ByteArray, ByteArray>> = mutableListOf()

    override suspend fun openWithPassword(vaultFolder: String, password: ByteArray): VaultSession {
        openedFolders += vaultFolder
        openedWithPassword += password.copyOf()
        openError?.let { throw it }
        return session
    }

    override suspend fun openWithRecovery(vaultFolder: String, phrase: ByteArray): VaultSession {
        openedFolders += vaultFolder
        openedWithRecovery += phrase.copyOf()
        recoveryError?.let { throw it }
        return session
    }

    override suspend fun openWithDeviceSecret(vaultFolder: String, deviceUuid: ByteArray, deviceSecret: ByteArray): VaultSession {
        openedFolders += vaultFolder
        openedWithDeviceSecret += deviceUuid.copyOf() to deviceSecret.copyOf()
        return session
    }
}
