package org.secretary.sync

import uniffi.secretary.CollisionDto
import uniffi.secretary.DeviceClockDto
import uniffi.secretary.SyncOutcomeDto
import uniffi.secretary.SyncStatusDto
import uniffi.secretary.VetoDto

/**
 * Pure DTO→domain mappers for the uniffi sync surface. The arms map 1:1 to the
 * `SyncOutcomeDto` definition in `ffi/secretary-ffi-uniffi/src/secretary.udl`; if that
 * surface changes, update both these functions and the `SyncOutcome` domain arms.
 * A faithful transcription of iOS `UniffiVaultSyncPort.swift`'s `mapOutcome`/`mapStatus`.
 */
internal fun mapOutcome(dto: SyncOutcomeDto): SyncOutcome = when (dto) {
    is SyncOutcomeDto.NothingToDo -> SyncOutcome.NothingToDo
    is SyncOutcomeDto.AppliedAutomatically -> SyncOutcome.AppliedAutomatically
    is SyncOutcomeDto.SilentMerge -> SyncOutcome.SilentMerge
    is SyncOutcomeDto.MergedClean -> SyncOutcome.MergedClean
    is SyncOutcomeDto.RollbackRejected -> SyncOutcome.RollbackRejected
    is SyncOutcomeDto.ConflictsPending -> SyncOutcome.ConflictsPending(
        vetoes = dto.vetoes.map(::mapVeto),
        collisions = dto.collisions.map(::mapCollision),
        manifestHash = dto.manifestHash,
    )
}

internal fun mapStatus(dto: SyncStatusDto): SyncStatus = SyncStatus(
    hasState = dto.hasState,
    deviceClocks = dto.deviceClocks.map(::mapDeviceClock),
    lastStateWriteMs = dto.lastStateWriteMs,
)

internal fun mapVeto(dto: VetoDto): SyncVeto = SyncVeto(
    recordUuidHex = dto.recordUuidHex,
    recordType = dto.recordType,
    tags = dto.tags,
    fieldNames = dto.fieldNames,
    localLastModMs = dto.localLastModMs,
    peerTombstonedAtMs = dto.peerTombstonedAtMs,
    peerDeviceHex = dto.peerDeviceHex,
)

internal fun mapCollision(dto: CollisionDto): SyncCollision = SyncCollision(
    recordUuidHex = dto.recordUuidHex,
    fieldNames = dto.fieldNames,
)

private fun mapDeviceClock(dto: DeviceClockDto): DeviceClock = DeviceClock(
    deviceUuidHex = dto.deviceUuidHex,
    counter = dto.counter,
)
