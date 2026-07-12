package org.secretary.browse

import uniffi.secretary.Settings as FfiSettings

/**
 * Pure projections between the generated uniffi [FfiSettings] and the FFI-free [VaultSettings], the
 * one numeric boundary where the settings fields cross `:kit`. Extracted from
 * [UniffiVaultSession.readSettings]/[UniffiVaultSession.writeSettings] so the `ULong`↔`Long`
 * conversion is host-testable (the generated record type constructs without loading the native lib,
 * like every other `:kit` mapping — see [toFfi]/[mapBlockSummary]). No record plaintext crosses here.
 */
internal fun FfiSettings.toVaultSettings(): VaultSettings =
    VaultSettings(
        autoLockTimeoutMs = autoLockTimeoutMs.toLong(),
        requirePasswordBeforeEdits = requirePasswordBeforeEdits,
        reauthGraceWindowMs = reauthGraceWindowMs.toLong(),
        retentionWindowMs = retentionWindowMs.toLong(),
    )

/** Inverse of [toVaultSettings] (`Long`→`ULong` at the FFI boundary). */
internal fun VaultSettings.toFfiSettings(): FfiSettings =
    FfiSettings(
        autoLockTimeoutMs = autoLockTimeoutMs.toULong(),
        requirePasswordBeforeEdits = requirePasswordBeforeEdits,
        reauthGraceWindowMs = reauthGraceWindowMs.toULong(),
        retentionWindowMs = retentionWindowMs.toULong(),
    )
