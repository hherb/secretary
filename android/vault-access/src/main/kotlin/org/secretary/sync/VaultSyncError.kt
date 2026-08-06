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
 * PAYLOAD-ORIGIN AUDIT (#472, partly structural as of #480) — no arm here is redacted, but
 * NOT for one shared reason: [Failed] and [StateCorrupt] are gated at their Rust construction
 * site; [InvalidArgument] is not, and stays safe only by producer trace. Do not flatten these
 * into one claim — see each bullet:
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
 * - [StateCorrupt]: `FfiVaultError::SyncStateCorrupt`'s `detail` is gated the same way — TWO
 *   Rust producers, both `detail::gated(&e)` calls into `error/detail.rs` (rules E2/E3/E4,
 *   CI-enforced, #480): `ffi/secretary-ffi-bridge/src/sync/status.rs:86` (wraps
 *   `StateError::Decode`/`Encode`) and `.../sync/orchestration.rs:249-254` (`map_sync_error`,
 *   wraps `SyncError::StateDecodeFailed`/`StateEncodeFailed`). Both ultimately trace back to
 *   `core/src/sync/state.rs`'s CBOR (de)serialization over the LOCAL sync-state cache — vector
 *   clocks and device UUIDs only, never vault plaintext. `cli/src/state.rs`'s `StateError` is
 *   a thin wrapper: it carries the core `SyncError` unchanged and adds the file-I/O side (the
 *   `<state-dir>/<vault_uuid_hex>.state.cbor` read/write), not any of the CBOR codec itself.
 * - [InvalidArgument] is NOT #480-gated. Rules E2/E3/E4 stop at everything under
 *   `ffi/secretary-ffi-bridge/src/`; this arm's sole producer,
 *   `ffi/secretary-ffi-uniffi/src/namespace/sync.rs:22`, calls the WRAPPER crate's own
 *   `uuid_from_vec` helper (`namespace/mod.rs:672-675`), which builds `detail` with
 *   `format!("{field} must be 16 bytes, got {}", bytes.len())` — a hand-rolled `format!` in a
 *   crate this guard does not scan at all (#486). It is safe TODAY by PRODUCER TRACE, not by
 *   construction: THIS arm's sole call site passes `uuid_from_vec` the fixed literal
 *   `"vault_uuid"` as `field` (never decrypted content), and `bytes.len()` is a length, never
 *   content. That is a claim about `sync.rs:22` specifically, not about `uuid_from_vec` in
 *   general — `field` is NOT always a literal across its callers: `namespace/repair.rs:52,65`
 *   pass `format!("approvals[{idx}].block_uuid")` (a safe loop index, not a fixed literal),
 *   though that is a different arm's producer, not this one's. Nothing enforces that a future
 *   producer of THIS arm keeps `field` a literal, unlike [Failed]/[StateCorrupt] above.
 *   `VaultSyncErrorMapping.kt`'s Kotlin side adds no further risk on top: exactly ONE
 *   producer, no Kotlin-side interpolation. Unlike its browse-surface namesake
 *   ([org.secretary.browse.VaultBrowseError.InvalidArgument], REDACTED because
 *   `RecordEditModel` interpolates a decrypted field name into it), this arm stays RENDERED
 *   because its one producer's content is provably a parameter-name literal plus a length —
 *   but that is a TRACED claim about `uuid_from_vec`'s current callers, not a guard
 *   guarantee. Do not assume the two `InvalidArgument` arms share a verdict just because they
 *   share a name, and do not assume this arm shares [Failed]'s or [StateCorrupt]'s CI
 *   enforcement either.
 *
 * NOTE: [Failed] and [StateCorrupt] no longer need their own traced-content justification
 * separate from [org.secretary.browse.VaultBrowseError.Failed] IN KIND — both are now "gated
 * at construction, not by tracing" — but NOT via the same guard, and NOT via the same files.
 * `VaultBrowseError.Failed`'s nine producers are all KOTLIN (`BrowseMapping.kt`,
 * `RecordEditModel.kt`, `VaultBrowseModel.kt`, `UniffiVaultOpenPort.kt`,
 * `UniffiVaultDeviceSlotPort.kt`), gated by the `diagnosticDetail`/fixed-literal CONVENTION
 * from #472 — a Kotlin-side, review-plus-lint discipline with no Rust guard behind it. This
 * class's [Failed]/[StateCorrupt] are instead gated by the PYTHON guard
 * (`scripts/check-error-payload-hygiene.py`, rules E2/E3/E4, #480) at their RUST construction
 * sites under `ffi/secretary-ffi-bridge/src/sync/`. Same PATTERN, different GUARD, different
 * LAYER — conflating them was a real mistake in an earlier draft of this KDoc; do not repeat
 * it. Re-verify [Failed]/[StateCorrupt] whenever a `SyncFailed`/`SyncStateCorrupt`
 * construction site changes to something other than a literal or a `detail::gated(&e)` call;
 * re-verify [InvalidArgument] whenever `uuid_from_vec` or its callers change.
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
