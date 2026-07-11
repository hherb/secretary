package org.secretary.browse

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Host-tested Trash browser model — Kotlin mirror of iOS `TrashViewModel`, following the
 * [VaultBrowseModel.guardedWrite] discipline: [_writing] is set BEFORE the gate await; a
 * `UserCancelled` re-auth aborts silently (no write, no error, list intact); a typed op failure
 * surfaces via [error] and skips the reload. Destructive-op reports are DISCARDED — the reloaded
 * list is the success signal (parity with iOS/desktop; #411 surfaces counts later).
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

    suspend fun restore(uuid: ByteArray) =
        guardedWrite("Confirm restoring this block") { port.restoreBlock(uuid) }

    suspend fun purge(uuid: ByteArray) =
        guardedWrite("Confirm permanently deleting this block") { port.purgeBlock(uuid) }

    suspend fun emptyTrash() =
        guardedWrite("Confirm permanently deleting all trashed blocks") { port.emptyTrash() }

    suspend fun runRetention() {
        val window = port.defaultRetentionWindowMs()
        guardedWrite("Confirm permanently deleting expired trash") { port.autoPurgeExpired(window) }
    }

    /**
     * Re-auth, run a guarded destructive op, then reload on success. [_writing] set before the gate
     * await so a second action during the prompt is rejected. Mirror of [VaultBrowseModel.guardedWrite]:
     * `UserCancelled` → silent; other `DeviceUnlockError` → [error]; op failure → [error], no reload.
     * The op's return value (report DTO) is discarded.
     */
    private suspend fun guardedWrite(reason: String, op: suspend () -> Unit) {
        if (_writing.value) return
        _writing.value = true
        try {
            // CancellationException is NOT caught here — it propagates past these DeviceUnlockError
            // catches so coroutine cancellation is never swallowed. Do NOT widen to catch (Exception).
            try {
                gate.authorizeWrite(reason)
            } catch (e: DeviceUnlockError.UserCancelled) {
                return // silent: no write, no error
            } catch (e: DeviceUnlockError) {
                _error.value = VaultBrowseError.ReauthFailed(reauthFailedMessage(e))
                return
            }
            try {
                op()
            } catch (e: VaultBrowseError) {
                _error.value = e
                return
            }
            load()
        } finally {
            _writing.value = false
        }
    }
}
