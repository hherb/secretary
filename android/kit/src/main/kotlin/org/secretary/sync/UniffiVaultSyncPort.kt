package org.secretary.sync

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.secretary.browse.UniffiVaultSession
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VaultException
import uniffi.secretary.VetoDecisionDto
import uniffi.secretary.syncStatus

/**
 * The real [VaultSyncPort] over the generated `uniffi.secretary` sync calls. This is the only
 * [VaultSyncPort] implementation that invokes the bindings (the pure DTO/error mappers reference
 * the generated types too, but only as translators). Every pass runs through the open session
 * (#733, as iOS since #101): no password, and the bridge refreshes the session's manifest handle
 * itself, so a write after any pass is not refused as stale.
 *
 * [sync] and [commitDecisions] do disk I/O and crypto, so they run on [ioDispatcher] (default
 * [Dispatchers.IO]); [status] is a cheap disk read and runs inline.
 *
 * The three calls (one FFI function, two session methods) are injectable seams so the adapter's
 * wiring is host-testable with fakes (no native library loaded). Production builds it from a
 * session with the secondary constructor.
 */
class UniffiVaultSyncPort(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val statusFn: (String, ByteArray) -> SyncStatusDto = ::syncStatus,
    private val syncFn: (String, ULong) -> SyncOutcomeDto,
    // (stateDir, decisions, manifestHash, nowMs) -> outcome
    private val commitFn: (String, List<VetoDecisionDto>, ByteArray, ULong) -> SyncOutcomeDto,
) : VaultSyncPort {

    /** The production port: syncs through [session]'s handles. */
    constructor(session: UniffiVaultSession) : this(
        syncFn = session::syncThroughSession,
        commitFn = session::commitDecisionsThroughSession,
    )

    override suspend fun status(stateDir: String, vaultUuid: ByteArray): SyncStatus =
        mapStatus(callMappingErrors { statusFn(stateDir, vaultUuid) })

    override suspend fun sync(stateDir: String, nowMs: ULong): SyncOutcome = withContext(ioDispatcher) {
        mapOutcome(callMappingErrors { syncFn(stateDir, nowMs) })
    }

    override suspend fun commitDecisions(
        stateDir: String,
        decisions: List<SyncVetoDecision>,
        manifestHash: ByteArray,
        nowMs: ULong,
    ): SyncOutcome = withContext(ioDispatcher) {
        val dtoDecisions = decisions.map(::toVetoDecisionDto)
        mapOutcome(callMappingErrors { commitFn(stateDir, dtoDecisions, manifestHash, nowMs) })
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
