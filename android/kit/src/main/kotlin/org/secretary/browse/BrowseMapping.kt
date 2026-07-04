package org.secretary.browse

import uniffi.secretary.BlockSummary
import uniffi.secretary.VaultException

/**
 * Pure `VaultException` → [VaultBrowseError] mapper for the open/read path. Maps only the
 * open-relevant arms; every other arm folds into [VaultBrowseError.Failed] carrying the variant
 * name (mirrors `:kit`'s `mapVaultSyncError` else-fold).
 *
 * [VaultException.WrongPasswordOrCorrupt] stays conflated per the threat model (§13) — do NOT split.
 *
 * MAINTAINER WARNING: the `else` fold silently swallows any FUTURE open-relevant arm into
 * [VaultBrowseError.Failed] (the `when` is non-exhaustive by design over a ~30-arm sealed type). If
 * the open/read FFI surface gains a new arm, add an explicit branch above `else` and a matching
 * [VaultBrowseError] case. The Kotlin compiler will not flag it.
 */
internal fun mapVaultBrowseError(e: VaultException): VaultBrowseError = when (e) {
    is VaultException.WrongPasswordOrCorrupt -> VaultBrowseError.WrongPasswordOrCorrupt
    is VaultException.VaultMismatch -> VaultBrowseError.VaultMismatch
    is VaultException.CorruptVault -> VaultBrowseError.CorruptVault(e.detail)
    is VaultException.FolderInvalid -> VaultBrowseError.FolderInvalid(e.detail)
    is VaultException.BlockNotFound -> VaultBrowseError.BlockNotFound(e.uuidHex)
    is VaultException.InvalidArgument -> VaultBrowseError.InvalidArgument(e.detail)
    is VaultException.RecordNotFound -> VaultBrowseError.RecordNotFound(e.uuidHex)
    is VaultException.SaveCryptoFailure -> VaultBrowseError.SaveCryptoFailure(e.detail)
    is VaultException.WrongMnemonicOrCorrupt -> VaultBrowseError.WrongRecoveryOrCorrupt
    is VaultException.InvalidMnemonic -> VaultBrowseError.InvalidRecoveryPhrase(e.detail)
    is VaultException.WrongDeviceSecretOrCorrupt -> VaultBrowseError.WrongDeviceSecretOrCorrupt
    is VaultException.DeviceSlotNotFound -> VaultBrowseError.DeviceSlotNotFound
    is VaultException.DeviceUuidMismatch -> VaultBrowseError.DeviceUuidMismatch(e.detail)
    // #374: the open path now promotes crash-residue (`BlockFingerprintMismatch`)
    // out of `CorruptVault` into these two dedicated arms. Android ships no
    // repair UI yet, so both map back to `CorruptVault` — the same domain
    // classification the pre-#374 `CorruptVault` fold produced — rather than
    // silently degrading into the generic `else -> Failed` bucket (per this
    // file's MAINTAINER WARNING: a new open-relevant arm gets an explicit branch).
    is VaultException.VaultNeedsRepair ->
        VaultBrowseError.CorruptVault("crash residue in block ${e.blockUuidHex}")
    is VaultException.RepairRejected ->
        VaultBrowseError.CorruptVault("repair refused for block ${e.blockUuidHex}: ${e.detail}")
    else -> VaultBrowseError.Failed(e.toString())
}

/** Pure uniffi `BlockSummary` → [BlockSummaryView] (metadata only; recipient list dropped). */
internal fun mapBlockSummary(s: BlockSummary): BlockSummaryView =
    BlockSummaryView(
        uuid = s.blockUuid,
        name = s.blockName,
        createdAtMs = s.createdAtMs,
        lastModifiedMs = s.lastModifiedMs,
    )
