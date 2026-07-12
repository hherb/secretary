package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Host-tested Trash browser model — Kotlin mirror of iOS `TrashViewModel`, following the
 * [VaultBrowseModel.guardedWrite] discipline: [_writing] is set BEFORE the gate await; a
 * `UserCancelled` re-auth aborts silently (no write, no error, list intact); a typed op failure
 * surfaces via [error] and skips the reload. Destructive-op reports are surfaced via [notice]
 * (#411) after the reload.
 *
 * Main-thread-confined like [VaultBrowseModel] (the injected [WriteReauthGate] is not thread-safe).
 * Writes are `suspend` because the real [TrashPort] offloads the FFI write to IO.
 */
class TrashBrowseModel(
    private val port: TrashPort,
    private val gate: WriteReauthGate = NoopReauthGate,
) {
    private val _entries = MutableStateFlow<List<TrashedBlockInfo>>(emptyList())
    val entries: StateFlow<List<TrashedBlockInfo>> = _entries.asStateFlow()

    private val _error = MutableStateFlow<VaultBrowseError?>(null)
    val error: StateFlow<VaultBrowseError?> = _error.asStateFlow()

    private val _writing = MutableStateFlow(false)
    /** True while a destructive write is in flight — disables all trash write buttons. */
    val writing: StateFlow<Boolean> = _writing.asStateFlow()

    private val _preview = MutableStateFlow<List<ExpiredEntryInfo>?>(null)
    /** Populated by [previewRetention]; drives the retention sheet summary. Null = not yet previewed. */
    val preview: StateFlow<List<ExpiredEntryInfo>?> = _preview.asStateFlow()

    private val _notice = MutableStateFlow<PurgeNotice?>(null)
    /** The last destructive op's outcome for the inline banner (#411). Cleared at the start of any
     * new write; set on a successful op. */
    val notice: StateFlow<PurgeNotice?> = _notice.asStateFlow()

    /** The frozen 90-day default retention window (no per-vault setting yet). */
    val retentionWindowMs: Long get() = port.defaultRetentionWindowMs()

    /** List trashed blocks (newest-first). A typed failure surfaces via [error]; entries cleared. */
    fun load() {
        _error.value = null
        try {
            _entries.value = sortTrashed(port.listTrashedBlocks())
        } catch (e: VaultBrowseError) {
            _error.value = e
            _entries.value = emptyList()
        }
    }

    /** Ungated retention preview against the fixed default window. */
    fun previewRetention() {
        _preview.value = port.expiredTrashEntries(port.defaultRetentionWindowMs())
    }

    /** Drop the cached preview so a reopened retention sheet shows its loading state (no stale flash). */
    fun clearPreview() {
        _preview.value = null
    }

    suspend fun restore(uuid: ByteArray) {
        guardedWrite("Confirm restoring this block") { port.restoreBlock(uuid) }
    }

    suspend fun purge(uuid: ByteArray) {
        val result = guardedWrite("Confirm permanently deleting this block") { port.purgeBlock(uuid) }
        if (result != null) _notice.value = formatPurgeNotice(PurgeOutcome.SinglePurge)
    }

    suspend fun emptyTrash() {
        val report = guardedWrite("Confirm permanently deleting all trashed blocks") { port.emptyTrash() }
        if (report != null) {
            _notice.value = formatPurgeNotice(PurgeOutcome.EmptyTrash(report.purgedCount, report.filesFailed))
        }
    }

    suspend fun runRetention() {
        val window = port.defaultRetentionWindowMs()
        val report = guardedWrite("Confirm permanently deleting expired trash") { port.autoPurgeExpired(window) }
        if (report != null) {
            _notice.value = formatPurgeNotice(PurgeOutcome.Retention(report.purgedCount, report.filesFailed))
        }
    }

    /**
     * Re-auth, run a guarded destructive op, then reload on success. [_writing] set before the gate
     * await so a second action during the prompt is rejected. Mirror of [VaultBrowseModel.guardedWrite]:
     * `UserCancelled` → silent; other `DeviceUnlockError` → [error]; op failure → [error], no reload.
     * Returns the op's result (report DTO) so the caller can build a [notice].
     */
    private suspend fun <T> guardedWrite(reason: String, op: suspend () -> T): T? {
        if (_writing.value) return null
        _writing.value = true
        _notice.value = null
        try {
            // CancellationException is NOT caught here — it propagates past these DeviceUnlockError
            // catches so coroutine cancellation is never swallowed. Do NOT widen to catch (Exception).
            try {
                gate.authorizeWrite(reason)
            } catch (e: DeviceUnlockError.UserCancelled) {
                return null // silent: no write, no error
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(reauthFailedMessage(e))
                return null
            }
            val result = try {
                op()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return null
            }
            load()
            return result
        } finally {
            _writing.value = false
        }
    }
}
