package org.secretary.browse

import org.secretary.diagnostics.SecretFreeThrowable

/**
 * Errors raised by the vault open/browse surface. Throwable (mirrors [org.secretary.sync.VaultSyncError])
 * so the coordinator can `catch (e: VaultBrowseError)`. Deliberately SEPARATE from `VaultSyncError`:
 * the open/read FFI returns a different `VaultException` arm set; folding them would misattribute errors.
 *
 * [WrongPasswordOrCorrupt] is intentionally conflated (wrong password vs. corruption) per the threat
 * model's anti-oracle rule (§13). Do NOT split it.
 */
sealed class VaultBrowseError(message: String? = null) : Exception(message), SecretFreeThrowable {
    /**
     * Secret-free rendering for logcat (#472). Three arms are redacted AT SOURCE.
     *
     * PAYLOAD-ORIGIN AUDIT — each `render` verdict below is a security claim,
     * established by tracing the payload to its construction site. An arm whose
     * origin cannot be established is redacted, not assumed safe.
     *
     * REDACTED:
     * - [CorruptVault]: a Rust-authored `VaultError` Display passed through
     *   verbatim. Its fold includes `VaultError::Record(_)`, which renders as
     *   `"record CBOR error: {0}"` over `RecordError::DuplicateKey { key }`
     *   (`core/src/vault/record.rs:660`) — and `key` is the DECRYPTED CBOR field
     *   name. We do not author these strings, so their content cannot be
     *   reviewed here; that is the "unreviewed content" class this interface
     *   exists to deny. Tracked at the Rust root as #474.
     * - [SaveCryptoFailure]: the SAME plaintext, one arm over. The bridge's
     *   `map_core_vault_error_*` folds `VaultError::Record(_)` and
     *   `VaultError::Block(_)` into `FfiVaultError::SaveCryptoFailure { detail:
     *   format!("{e}") }` (`ffi/.../retention/orchestration.rs:205` plus five
     *   siblings in revoke/trash/purge/restore/save). iOS is NOT exposed here
     *   only because `VaultAccessError` has no `.saveCryptoFailure` case, so the
     *   arm falls to `VaultErrorMapping.swift:53`'s gated
     *   `default -> .other(diagnosticDetail(e))`. Our `BrowseMapping.kt` maps it
     *   EXPLICITLY and carries the raw detail, so the redaction is load-bearing
     *   here in a way it is not there. Do not "align with iOS" by removing it.
     * - [InvalidArgument]: Kotlin-side. `RecordEditModel` interpolates a
     *   decrypted record field name (`"field '<name>' is not valid hex"`,
     *   `"duplicate field name: <name>"`). Redacted regardless of which site
     *   renders it — do NOT rely on catch-arm ordering to keep it out of a log.
     *
     * RENDERED IN FULL, with the evidence:
     * - [InvalidRecoveryPhrase]: `MnemonicError` Display emits a word INDEX
     *   (`core/src/unlock/mnemonic.rs:54`), a word count (`:46`), or the fixed
     *   `"BIP-39 checksum failed"` (`:59`) — never the word itself.
     * - [FolderInvalid]: `format!("{context}: {source}")` — a filesystem path
     *   plus an errno. The threat model already treats paths as disclosed.
     * - [DeviceUuidMismatch]: device UUIDs, a public per-device fingerprint.
     * - [BlockNotFound] / [RecordNotFound]: hex-encoded UUIDs. The
     *   `BlockNotInTrash` / `BlockPurged` folds also `hex::encode`
     *   (`ffi/.../purge/orchestration.rs:153`), so no block NAME reaches them.
     * - [ReauthFailed]: built Android-side at the biometric gate from fixed
     *   labels.
     * - [Failed]: gated at construction — every producer passes
     *   `diagnosticDetail` output. Scoped to `VaultBrowseError.Failed` ONLY.
     *   [org.secretary.sync.VaultSyncError] has its own arm of the same name
     *   ([org.secretary.sync.VaultSyncError.Failed]) that this verdict does
     *   NOT cover — one of ITS two producers is a raw, ungated pass-through,
     *   safe by traced Rust content rather than by construction. See that
     *   class's own payload-origin audit; a shared arm name across two
     *   sealed types is not a shared verdict.
     *
     * NOTE: this audit is a point-in-time claim. An arm's payload can change
     * from an edit in the Rust core with NO Kotlin diff at all, which is exactly
     * how [SaveCryptoFailure] came to carry plaintext. Re-check when the bridge's
     * error folds change.
     */
    override val diagnosticDescription: String
        get() = when (this) {
            is CorruptVault -> "CorruptVault(<redacted>)"
            is SaveCryptoFailure -> "SaveCryptoFailure(<redacted>)"
            is InvalidArgument -> "InvalidArgument(<redacted>)"
            else -> toString()
        }

    /** Open failed: wrong password OR corrupt vault. Conflated on purpose (§13). */
    data object WrongPasswordOrCorrupt : VaultBrowseError()

    /** Recovery open failed: wrong phrase OR corrupt vault. Conflated on purpose (§13). */
    data object WrongRecoveryOrCorrupt : VaultBrowseError()

    /** The recovery phrase was malformed (bad word / wrong length / invalid UTF-8) — a format
     *  error, distinct from the conflated [WrongRecoveryOrCorrupt]. Safe to surface to the user. */
    data class InvalidRecoveryPhrase(val detail: String) : VaultBrowseError(detail)

    /** Device-secret open failed: wrong device secret OR corrupt wrap/vault. Conflated on purpose (§13). */
    data object WrongDeviceSecretOrCorrupt : VaultBrowseError()

    /** No `devices/<uuid>.wrap` slot for the requested device UUID (benign "no such device"). */
    data object DeviceSlotNotFound : VaultBrowseError()

    /** The wrap file's header device_uuid ≠ the lookup UUID (§3a relabel-integrity check). A
     *  structural-integrity signal, safe to surface. */
    data class DeviceUuidMismatch(val detail: String) : VaultBrowseError(detail)

    /** The opened folder is a different vault than expected. */
    data object VaultMismatch : VaultBrowseError()

    /** The vault on disk is structurally corrupt. */
    data class CorruptVault(val detail: String) : VaultBrowseError(detail)

    /** The supplied folder path is not a readable vault folder. */
    data class FolderInvalid(val detail: String) : VaultBrowseError(detail)

    /** No block with the requested UUID exists in the manifest. */
    data class BlockNotFound(val uuidHex: String) : VaultBrowseError(uuidHex)

    /** A caller argument was malformed (e.g. wrong-length UUID). */
    data class InvalidArgument(val detail: String) : VaultBrowseError(detail)

    /** A write targeted a record that does not exist in the requested state (e.g. a peer already
     *  deleted it). Surfaced by tombstone/resurrect/edit. */
    data class RecordNotFound(val uuidHex: String) : VaultBrowseError(uuidHex)

    /** The save tail (atomic manifest + block rewrite) failed during a write. */
    data class SaveCryptoFailure(val detail: String) : VaultBrowseError(detail)

    /** A mutating write was refused because the biometric presence proof failed (lockout / hardware
     *  unavailable / not-a-match). Distinct from [Failed]; safe to surface. A user *cancel* is NOT
     *  this — cancel aborts silently and leaves the originating dialog open. */
    data class ReauthFailed(val detail: String) : VaultBrowseError(detail)

    /** Any other open/read/write failure: the mapper's else-fold, plus the device-uuid resolve
     *  failure and the no-provider (read-only session) write attempt. */
    data class Failed(val detail: String) : VaultBrowseError(detail)
}
