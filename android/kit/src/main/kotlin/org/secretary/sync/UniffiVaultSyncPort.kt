package org.secretary.sync

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
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
    private val syncFn: (String, String, ByteArray, ULong) -> SyncOutcomeDto = ::syncVault,
    // (stateDir, vaultFolder, password, decisions, manifestHash, nowMs) -> outcome
    private val commitFn: (String, String, ByteArray, List<VetoDecisionDto>, ByteArray, ULong) -> SyncOutcomeDto =
        ::syncCommitDecisions,
) : VaultSyncPort {

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        mapStatus(callMappingErrors { statusFn(stateDir, vaultUuid) })

    override suspend fun sync(
        stateDir: String,
        vaultFolder: String,
        password: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = withContext(ioDispatcher) {
        mapOutcome(callMappingErrors { syncFn(stateDir, vaultFolder, password, nowMs) })
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
            commitFn(stateDir, vaultFolder, password, dtoDecisions, manifestHash, nowMs)
        })
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
