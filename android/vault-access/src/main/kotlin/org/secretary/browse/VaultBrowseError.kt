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
     * Secret-free rendering for logcat (#472). One arm is redacted AT SOURCE.
     *
     * PAYLOAD-ORIGIN AUDIT — each `render` verdict below is a security claim,
     * established by tracing the payload to its construction site. An arm whose
     * origin cannot be established is redacted, not assumed safe.
     *
     * REDACTED:
     * - [InvalidArgument]: Kotlin-side. `RecordEditModel` interpolates a
     *   decrypted record field name (`"field '<name>' is not valid hex"`,
     *   `"duplicate field name: <name>"`). Redacted regardless of which site
     *   renders it — do NOT rely on catch-arm ordering to keep it out of a log.
     *   This is NOT covered by the #474 guarantee below: its payload is
     *   Kotlin-authored, not `core`-authored, a different class entirely. No
     *   issue tracks that payload class itself; #476 tracks the separate
     *   question of these carried diagnostics being rendered as on-screen
     *   copy.
     *
     * RENDERED IN FULL, with the evidence:
     * - [CorruptVault] / [SaveCryptoFailure]: as of #474, every plaintext-bearing
     *   `core` error payload is data-free BY CONSTRUCTION rather than by review —
     *   it carries a `&'static str` hint plus an ordinal, never interpolated
     *   runtime content. `RecordError::DuplicateKey`'s decrypted CBOR field name
     *   (the original leak, `core/src/vault/record.rs`) is gone: the `ciborium`
     *   codec message it came from is discarded at the boundary in
     *   `core/src/cbor.rs`, which classifies the failure into a fieldless
     *   `CborErrorKind` instead of stringifying it. `scripts/check-error-payload-
     *   hygiene.py` fails CI if a future `core` variant reintroduces a runtime
     *   `String` into an `#[error(...)]` message, so this is enforced, not just
     *   claimed. Both arms are therefore no longer redacted here.
     *   The guard scans everything under `core/src/` ONLY — `ffi/secretary-ffi-bridge`
     *   builds its own `format!` detail strings for [SaveCryptoFailure] and is
     *   NOT scanned; see #478.
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
     * - [Failed]: gated at construction — every producer passes `diagnosticDetail`
     *   output, a fixed Kotlin string literal, or both (never raw Rust/JDK content).
     *   Nine producers: four gated (`BrowseMapping.kt:48, RecordEditModel.kt:117,162,
     *   VaultBrowseModel.kt:113`); four literals (`UniffiVaultOpenPort.kt:238,249,377,
     *   UniffiVaultDeviceSlotPort.kt:34`); one hybrid, fixed prefix plus `diagnosticDetail`
     *   (`UniffiVaultOpenPort.kt:253`). Scoped to `VaultBrowseError.Failed` ONLY.
     *   [org.secretary.sync.VaultSyncError] has its own arm of the same name
     *   ([org.secretary.sync.VaultSyncError.Failed]) that this verdict does
     *   NOT cover — one of ITS two producers is a raw, ungated pass-through,
     *   safe by traced Rust content rather than by construction. See that
     *   class's own payload-origin audit; a shared arm name across two
     *   sealed types is not a shared verdict.
     */
    override val diagnosticDescription: String
        get() = when (this) {
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
