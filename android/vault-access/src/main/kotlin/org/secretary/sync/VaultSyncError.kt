package org.secretary.sync

import org.secretary.diagnostics.SecretFreeThrowable

/**
 * Errors raised by the sync surface. Deliberately SEPARATE from any future
 * `VaultAccessError`: the sync FFI returns a different `FfiVaultError`/`VaultException`
 * variant set, and folding the two would misattribute errors.
 *
 * [WrongPasswordOrCorrupt] is intentionally conflated (wrong password vs. vault corruption)
 * per the threat model's anti-oracle rule (§13). Do NOT split it.
 *
 * The singleton (`data object`) arms share a single instance and therefore a single captured
 * stack trace; rely on the arm type, not the stack trace, for diagnosis.
 *
 * PAYLOAD-ORIGIN AUDIT (#472) — no arm here is redacted; every `detail`-carrying arm is
 * safe to render in full, but for TWO DIFFERENT reasons that must not be conflated with
 * [org.secretary.browse.VaultBrowseError]'s audit despite the shared arm name [Failed]:
 *
 * - [Failed] has TWO producers, not one. `VaultSyncErrorMapping.kt`'s `else`-fold (any
 *   sync-relevant `VaultException` arm this file does not name) is GATED AT CONSTRUCTION —
 *   it passes `diagnosticDetail(e)`, which default-denies an unconformed type. But the
 *   explicit `is VaultException.SyncFailed -> VaultSyncError.Failed(e.detail)` arm
 *   (`VaultSyncErrorMapping.kt`) is a RAW pass-through — it is NOT gated. It is safe only
 *   because every Rust construction site of `FfiVaultError::SyncFailed` was traced and
 *   confirmed to emit a fixed literal, a `std::io::Error` Display, or a `SyncError`
 *   internal-consistency-guard Display over an argument-shape description — NEVER a fold of
 *   an arbitrary `VaultError` (contrast [org.secretary.browse.VaultBrowseError.CorruptVault],
 *   which DOES fold an arbitrary `VaultError` and is redacted for exactly that reason).
 *   Traced sites:
 *     - `ffi/secretary-ffi-bridge/src/sync/orchestration.rs:38,144` — fixed literal
 *       ("no platform data directory available…").
 *     - `ffi/secretary-ffi-bridge/src/sync/orchestration.rs:173-177,238-240` — fixed
 *       literals (the `manifest_hash`-length guard; the internal "commit unexpectedly
 *       returned ConflictsPending" guard).
 *     - `ffi/secretary-ffi-bridge/src/sync/orchestration.rs:249-280` (`map_sync_error`,
 *       matched EXHAUSTIVELY — no `_` catch-all): folds `SyncError::InvalidArgument` /
 *       `ConflictCopyScanIoFailed` / `EmptyDraftWithVetoes`. Their Displays
 *       (`core/src/sync/error.rs:27-28,35-39,67-68`) are an argument-shape description, an
 *       `io::Error` (path + errno — already disclosed per the threat model), and a fixed
 *       literal, respectively.
 *     - `ffi/secretary-ffi-bridge/src/sync/status.rs:89-91` — `StateError::Io` Display
 *       (`io::Error`).
 *     - `ffi/secretary-ffi-bridge/src/sync/dto.rs:97,100` — hex-decode / fixed-length-
 *       conversion failures on caller-supplied bytes.
 *   THIS IS A CONTENT-TRACED CLAIM, NOT A STRUCTURAL ONE: unlike `VaultBrowseError`, this
 *   type has NO `diagnosticDescription` override, so nothing stops a future Rust edit from
 *   routing unreviewed content into `SyncFailed.detail` with zero Kotlin diff — exactly the
 *   class of drift that made [org.secretary.browse.VaultBrowseError.SaveCryptoFailure]
 *   unsafe. That is the honest residual risk; re-check this claim whenever
 *   `map_sync_error`/`map_state_error` or a `SyncFailed` construction site changes.
 * - [StateCorrupt]: `FfiVaultError::SyncStateCorrupt`
 *   (`ffi/secretary-ffi-bridge/src/sync/status.rs:85-87`) wraps `StateError::Decode`/`Encode`
 *   (`cli/src/state.rs:59-62`), a CBOR (de)serialization error over the LOCAL sync-state
 *   cache — vector clocks and device UUIDs only. `status.rs`'s own file header states "No
 *   secrets" (line 2). Never vault plaintext.
 * - [InvalidArgument]: the FFI's generic argument-SHAPE error
 *   (`VaultError::InvalidArgument(detail)`, `ffi/secretary-ffi-uniffi/src/secretary.udl:481`)
 *   — e.g. a wrong-length UUID. Unlike its browse-surface namesake
 *   ([org.secretary.browse.VaultBrowseError.InvalidArgument], REDACTED because
 *   `RecordEditModel` ALSO constructs it there with a decrypted field name), the sync
 *   surface has exactly ONE producer (`VaultSyncErrorMapping.kt`'s explicit
 *   `VaultException.InvalidArgument` arm) and no Kotlin-side interpolation site. Do not
 *   assume the two `InvalidArgument` arms share a verdict just because they share a name.
 *
 * NOTE: like [org.secretary.browse.VaultBrowseError]'s audit, this is a point-in-time claim
 * re-verified by tracing, not guaranteed by any type in the sync surface. See that class's
 * `[Failed]` entry: its "gated at construction" verdict is scoped to
 * `VaultBrowseError.Failed` ONLY — do not read it as covering this class's [Failed] too.
 */
sealed class VaultSyncError(message: String? = null) : Exception(message), SecretFreeThrowable {
    /** Re-open failed: wrong password OR corrupt vault. Conflated on purpose (§13). */
    data object WrongPasswordOrCorrupt : VaultSyncError()

    /** Another sync is already running for this vault (per-vault FFI lockfile held). */
    data object InProgress : VaultSyncError()

    /** The sync-state cache belongs to a different vault. */
    data object StateVaultMismatch : VaultSyncError()

    /** The sync-state cache is corrupt. */
    data class StateCorrupt(val detail: String) : VaultSyncError(detail)

    /** The vault changed on disk mid-pass; the TOCTOU freshness gate tripped. Retry. */
    data object EvidenceStale : VaultSyncError()

    /** The supplied decisions did not cover the pending conflicts. */
    data object DecisionsIncomplete : VaultSyncError()

    /** A caller argument was malformed (e.g. wrong-length UUID/hash). */
    data class InvalidArgument(val detail: String) : VaultSyncError(detail)

    /** Any other sync failure. */
    data class Failed(val detail: String) : VaultSyncError(detail)

    /** Coordinator guard: `resolve` was called with no paused conflict stashed. */
    data object NoPendingConflict : VaultSyncError()
}
