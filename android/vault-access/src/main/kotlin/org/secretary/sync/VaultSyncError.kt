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
 * PAYLOAD-ORIGIN AUDIT (#472, structural as of #480) — no arm here is redacted; every
 * `detail`-carrying arm is safe to render in full, and as of #480 every one of them is
 * safe for the SAME reason: gated at construction, not by traced content. That collapses
 * the distinction this audit used to draw against [org.secretary.browse.VaultBrowseError]
 * (whose [Failed] is gated at construction while its [CorruptVault] is not) — every arm
 * below is gated the same way [org.secretary.browse.VaultBrowseError.CorruptVault] now is.
 *
 * - [Failed]'s `detail` is gated at construction (#480, closing #478): every
 *   `FfiVaultError::SyncFailed` producer under `ffi/secretary-ffi-bridge/src/sync/`
 *   passes a string literal or a `detail::gated(&e)` call into
 *   `ffi/secretary-ffi-bridge/src/error/detail.rs` (rules E2/E3/E4), CI-enforced via
 *   `scripts/check-error-payload-hygiene.py` — a producer that instead hand-rolls a
 *   `format!` into `detail` now fails in the Rust author's own PR. `VaultSyncErrorMapping.kt`
 *   still has two producers (the explicit `is VaultException.SyncFailed -> ...` pass-through,
 *   and the `else`-fold's `diagnosticDetail(e)`), but both now carry a construction-gated
 *   string rather than one gated arm and one traced-content arm.
 *   That claim is about the CONSTRUCTION-SITE shape, not about every value any
 *   `impl GatedDetail` could ever render: the guard's own documented limits (an `io::Error`
 *   minted from a runtime string before reaching a gated field, #487; three syntactic
 *   re-wrap shapes needing dataflow analysis to catch, #488) are real, but neither shape
 *   appears on today's `SyncFailed` path — every current producer is a literal or
 *   `detail::gated(&e)`, verified by reading `orchestration.rs`, `status.rs`, and `dto.rs`.
 * - [StateCorrupt]: `FfiVaultError::SyncStateCorrupt`'s `detail` is gated the same way —
 *   `ffi/secretary-ffi-bridge/src/sync/status.rs` constructs it only via `detail::gated(&e)`
 *   into `error/detail.rs` (rules E2/E3/E4, CI-enforced, #480). It wraps
 *   `StateError::Decode`/`Encode` (`cli/src/state.rs`), a CBOR (de)serialization error over
 *   the LOCAL sync-state cache — vector clocks and device UUIDs only, never vault plaintext.
 * - [InvalidArgument]: the FFI's generic argument-SHAPE error
 *   (`VaultError::InvalidArgument(detail)`, `ffi/secretary-ffi-uniffi/src/secretary.udl:481`)
 *   — e.g. a wrong-length UUID. Unlike its browse-surface namesake
 *   ([org.secretary.browse.VaultBrowseError.InvalidArgument], REDACTED because
 *   `RecordEditModel` ALSO constructs it there with a decrypted field name), the sync
 *   surface has exactly ONE producer (`VaultSyncErrorMapping.kt`'s explicit
 *   `VaultException.InvalidArgument` arm) and no Kotlin-side interpolation site. Do not
 *   assume the two `InvalidArgument` arms share a verdict just because they share a name.
 *
 * NOTE: unlike the pre-#480 state of this audit, [Failed] here no longer needs its own
 * traced-content justification separate from
 * [org.secretary.browse.VaultBrowseError.Failed] — both are gated at construction by the
 * same guard, via different files under `ffi/secretary-ffi-bridge/src/`. Re-verify this
 * claim whenever a `SyncFailed`/`SyncStateCorrupt` construction site changes to something
 * other than a literal or a `detail::gated(&e)` call.
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
