package org.secretary.sync

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.secretary.browse.withDirectSecret
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VaultException
import uniffi.secretary.VetoDecisionDto
import uniffi.secretary.syncCommitDecisions
import uniffi.secretary.syncStatus
import uniffi.secretary.syncVault

/**
 * The real [VaultSyncPort] over the generated `uniffi.secretary` sync calls. This is the only
 * [VaultSyncPort] implementation that invokes the bindings (the pure DTO/error mappers reference
 * the generated types too, but only as translators). A faithful Kotlin mirror of iOS
 * `UniffiVaultSyncPort.swift`.
 *
 * [sync] and [commitDecisions] re-open the vault from the password (full Argon2id), so they run
 * on [ioDispatcher] (default [Dispatchers.IO]) to keep the caller responsive; [status] is a cheap
 * disk read and runs inline. The password [ByteArray] is forwarded per call and never retained.
 *
 * The three FFI functions are injectable seams defaulting to the real bindings, so the adapter's
 * wiring is host-testable with fakes (no native library loaded). Production code uses all defaults.
 */
class UniffiVaultSyncPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val statusFn: (String, ByteArray) -> SyncStatusDto = ::syncStatus,
    private val syncFn: (String, String, java.nio.ByteBuffer, ULong) -> SyncOutcomeDto = ::syncVault,
    // (stateDir, vaultFolder, password, decisions, manifestHash, nowMs) -> outcome
    private val commitFn: (String, String, java.nio.ByteBuffer, List<VetoDecisionDto>, ByteArray, ULong) -> SyncOutcomeDto =
        ::syncCommitDecisions,
    // Re-reads the open session after a pass (#101); null when there is no session to refresh.
    private val refreshSession: ((String) -> Unit)? = null,
) : VaultSyncPort {

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        mapStatus(callMappingErrors { statusFn(stateDir, vaultUuid) })

    override suspend fun sync(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = withContext(ioDispatcher) {
        mapOutcome(callMappingErrors {
            withDirectSecret(password) { pw -> syncFn(stateDir, vaultFolder, pw, nowMs) }
        }.also { refreshIfNeeded(stateDir, it) })
    }

    override suspend fun commitDecisions(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = withContext(ioDispatcher) {
        val dtoDecisions = decisions.map(::toVetoDecisionDto)
        mapOutcome(callMappingErrors {
            withDirectSecret(password) { pw ->
                commitFn(stateDir, vaultFolder, pw, dtoDecisions, manifestHash, nowMs)
            }
        }.also { refreshIfNeeded(stateDir, it) })
    }

    // Not after SilentMerge: the password pass persists a clock that always dominates the disk
    // (#730), so a refresh there would fail as a rollback. Not after Rollback/Conflicts: nothing written.
    private fun refreshIfNeeded(stateDir: String, outcome: SyncOutcomeDto) {
        val refresh = refreshSession ?: return
        if (outcome == SyncOutcomeDto.NothingToDo ||
            outcome == SyncOutcomeDto.AppliedAutomatically ||
            outcome == SyncOutcomeDto.MergedClean
        ) callMappingErrors { refresh(stateDir) }
    }
}

/** Run an FFI call, translating any [VaultException] into the domain [VaultSyncError]. */
private inline fun <T> callMappingErrors(block: () -> T): T =
    try {
        block()
    } catch (e: VaultException) {
        throw mapVaultSyncError(e)
    }

private fun toVetoDecisionDto(d: SyncVetoDecision): VetoDecisionDto =
    VetoDecisionDto(recordUuidHex = d.recordUuidHex, keepLocal = d.keepLocal)
