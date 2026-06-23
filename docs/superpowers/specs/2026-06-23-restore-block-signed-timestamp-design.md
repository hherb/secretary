# Design: Bind `restore_block` selection to the signed `tombstoned_at_ms` (#205)

**Date:** 2026-06-23
**Issue:** [#205](https://github.com/hherb/secretary/issues/205) — *restore_block trusts attacker-controlled trash filename suffix → authentic-but-stale block rollback* (severity: Medium, security)
**Branch:** `feature/restore-block-signed-timestamp`

## Problem

`restore_block` selects which trashed block file to restore using the **attacker-controlled filename suffix** (`matches.last()` — largest suffix wins) and never binds that suffix to the signed `TrashEntry.tombstoned_at_ms`. The signed manifest entry is consulted only for *existence*, never for *value*.

```rust
// core/src/vault/orchestrators.rs:2043-2044 (before)
matches.sort_by_key(|(ts, _)| *ts);
let (_restore_ts, restore_path) = matches.last().cloned().expect("non-empty checked above");
```

A malicious cloud-folder host (in scope per `docs/threat-model.md` §2.1) retains every historical byte. For a block the owner trashed at `T_recent` (the value in the signed `TrashEntry`), the attacker drops a previously-retained older-but-owner-signed version of the same `block_uuid` named `<uuid>.cbor.enc.<N>` with `N > T_recent`. On the next user-initiated restore, `restore_block` picks the attacker's file, it passes the §6.1 hybrid verify (it *is* genuinely owner-signed — authenticity ≠ freshness), becomes live, and step 7 best-effort-purges the smaller-suffix legitimate copy. Result: undetectable resurrection of a stale secret (e.g. a rotated password), and no later CRDT merge can self-heal because the legitimate copy is gone and the restored block's `vector_clock_summary` is copied verbatim from the planted file.

This violates `docs/threat-model.md`:60, which requires a restored backup to be "authentic and **current** (or detectably stale)."

### Why the suffix is unauthenticated

`trash_block` moves the file with a plain `std::fs::rename` (`orchestrators.rs:1853`) and the signed block payload runs "magic … through end of vector_clock_entries" (`block.rs:653`) — it contains **no** trash timestamp. So the filename suffix is unauthenticated metadata an attacker with write access to the synced folder can freely rename.

### The load-bearing invariant

`trash_block` writes, in the same operation:
- the file `trash/<uuid>.cbor.enc.<now_ms>` (`orchestrators.rs:1852`), and
- the signed `TrashEntry { block_uuid, tombstoned_at_ms: now_ms, … }` into the manifest (`orchestrators.rs:1867-1872`).

So **the authentic trashed file's suffix equals the signed `TrashEntry.tombstoned_at_ms` by construction.** The fix is to select on that equality instead of on "largest suffix."

The manifest carries only the **most-recent** `tombstoned_at_ms` (per `vault-format.md`:456 — older tombstone times are not tracked). Equality (not `>=`) is required: a multi-cycle trash→restore→re-trash history with the legitimate copy purged could otherwise still mis-select an older or planted file.

## Design

### 1. Core selection change (`core/src/vault/orchestrators.rs`)

Replace the "largest suffix" selection (steps 2-3, ~lines 2022-2050) with equality-to-signed-timestamp selection:

- Look up the `TrashEntry` itself (not just `.any(...)` existence) to obtain the authoritative `tombstoned_at_ms`.
- Select the file whose canonical suffix **equals** `tombstoned_at_ms`. At most one file can match — the suffix ↔ filename mapping is 1:1 (same UUID + same canonical suffix = same filename).
- Purge targets = every other match (older stale copies **and** larger-suffix attacker plants).

Error precedence (first match wins):

| Condition | Error |
|---|---|
| `!trash_entry_present` (no signed `TrashEntry`) | `BlockNotInTrash` (**unchanged**) |
| `trash_entry_present` but **no** trash files at all (`matches.is_empty()`) | `BlockNotInTrash` (**unchanged** — preserves the "entry without file" semantics and existing tests) |
| `trash_entry_present`, files present, but **none** has suffix == `tombstoned_at_ms` | `RestoreTargetMissing` (**new**) |

The new error fires only when the authentic file (suffix == signed timestamp) is **absent** and only stale/forged copies remain — i.e. the attacker removed or renamed the authentic file. The simpler attack from the issue (plant a larger-suffix forgery while the authentic file is *still present*) now resolves correctly and silently: equality picks the authentic file and the forgery becomes a purge target.

### 2. New core `VaultError` variant (`core/src/vault/mod.rs`)

Added after `RestoreVerificationFailed`:

```rust
/// `restore_block`: a signed `TrashEntry` exists for this `block_uuid`,
/// and one or more `trash/<uuid>.cbor.enc.*` files are present, but NONE
/// has a suffix equal to the entry's `tombstoned_at_ms`. The authentic-
/// current trashed file (whose suffix MUST equal the signed timestamp by
/// the trash_block construction) is absent — it was removed or renamed,
/// leaving only stale or attacker-planted copies. Restoring any of those
/// would resurrect authentic-but-stale content (#205), so restore halts;
/// the manifest is NOT modified and `trash/` is NOT modified.
#[error(
    "restore target for block {block_uuid:?} is missing: no trashed file's \
     suffix matches the signed tombstoned_at_ms {expected_tombstoned_at_ms}"
)]
RestoreTargetMissing {
    block_uuid: [u8; 16],
    expected_tombstoned_at_ms: u64,
},
```

The user chose a distinct typed variant (over reusing `BlockNotInTrash`) so the core layer carries a forensic "tampering / authentic-file-missing" signal distinct from "nothing was ever trashed."

### 3. FFI projection (`ffi/secretary-ffi-bridge/src/error/vault/mod.rs`)

The `From<core::VaultError> for FfiVaultError` match has **no `_ =>` catchall** (issue #40 made the drift surface explicit), so adding a core variant is a forced compile error there. Route the new variant to the existing **`FfiVaultError::CorruptVault`** bucket, mirroring `RestoreVerificationFailed` — both are "signed data ↔ on-disk bytes disagree" integrity failures, deliberately conflated at the FFI boundary per the §13 anti-oracle granularity policy.

```rust
VE::RestoreTargetMissing { block_uuid, expected_tombstoned_at_ms } => FfiVaultError::CorruptVault {
    detail: format!(
        "restore target for block {} is missing (expected tombstoned_at_ms {expected_tombstoned_at_ms})",
        hex::encode(block_uuid),
    ),
},
```

**Consequence: no new `FfiVaultError` variant.** Therefore no `.udl` change, no pyo3 `errors.rs` change, and no Swift/Kotlin `ConformanceErrors.{swift,kt}` churn (those harnesses enumerate `FfiVaultError` variants; `CorruptVault` already exists). The distinct signal lives at the core layer and in the core tests.

Any *other* exhaustive `core::VaultError` match without a catchall will surface as a compile error and be threaded as the compiler enumerates them; `cargo build --workspace` is the authority.

### 4. Spec lockstep (`docs/vault-format.md` §7.1)

Steps 1-3 currently normatively mandate "pick the file with the **largest** suffix." Rewrite to mandate equality to the signed `TrashEntry.tombstoned_at_ms`:

- **Step 1** (scan): unchanged grammar/skip rules, but the closing "Correctness is still gated by the §6.1 hybrid verify … on the largest-canonical-timestamp file" reference updates to "on the file whose suffix equals the signed `tombstoned_at_ms`."
- **Step 2** (selection): "Pick the file whose suffix **equals** the manifest's signed `TrashEntry.tombstoned_at_ms` as the *restore target*. All other matching files are *purge targets*. If no file's suffix equals the signed timestamp, restore fails — the authentic-current trashed file is missing (removed or renamed); only stale or planted copies remain. The largest-suffix file is **not** trusted: the suffix is unauthenticated filename metadata, and binding selection to the signed timestamp is what prevents an attacker-planted larger-suffix copy from being restored (#205)."
- **Step 3** (verify): "largest-canonical-timestamp file" → "selected restore-target file."

`core/tests/python/conformance.py` does **not** exercise trash/restore (verified by grep) — no clean-room change required.

### 5. Tests (TDD — written first, `core/tests/trash_restore.rs`)

1. **`restore_block_selects_signed_timestamp_not_largest_suffix`** (the regression that fails on `main` today): trash a block at `T`; plant a valid, owner-signed block file with **different content** for the same `block_uuid` at suffix `T+N` (`N > 0`); restore; assert the restored live block decrypts to the **`T`-file content** (not the planted content), and the planted `T+N` file has been purged.
2. **`restore_block_missing_signed_target_rejected`**: trash a block at `T`; remove/rename the authentic `T` file, leaving only a larger-suffix copy; restore; assert `Err(VaultError::RestoreTargetMissing { expected_tombstoned_at_ms: T, .. })`.

Both follow the existing `trash_restore.rs` fixture patterns. Crypto values are generated at runtime via the existing helpers (no hardcoded key/nonce literals — `feedback_test_crypto_random_not_hardcoded`).

## Non-goals / out of scope

- No change to `trash_block` (it already writes the file suffix == signed timestamp).
- No change to the §6.1 hybrid-verify, recipient-resolution, or atomic-write steps.
- No re-signing of the trash filename into the block payload (a heavier format change; equality-to-`TrashEntry` closes the *suffix-selection* gap within the frozen v1 format).
- No new `FfiVaultError` variant (folds to `CorruptVault`).
- **No content-freshness binding** — see the residual gap in Risk below (tracked as #293). This fix scopes to the suffix-selection vector only.

## Risk

- Behavior change is narrow: the only externally-observable change for honest vaults is nil (the authentic file's suffix already equals `tombstoned_at_ms`, so equality selects the same file "largest" did in the single-trash case). The change bites only when extra files are present.
- The new error path is reachable by a tampered/partially-purged trash dir; folding to `CorruptVault` at the FFI boundary matches existing operator expectations for integrity failures.
- **Residual gap (tracked as #293):** this fix narrows but does **not** fully eliminate authentic-but-stale rollback. An attacker who *overwrites the suffix-matching file in place* — writing a previously-retained, genuinely owner-signed *older* copy of the same `block_uuid` to `trash/<uuid>.cbor.enc.<T_recent>` where `T_recent` is the signed `tombstoned_at_ms` — defeats equality selection (it is the only match) and passes hybrid-verify (authenticity ≠ currency). Closing this requires binding a *content* commitment (e.g. a hash or the trashed `vector_clock_summary`) into the signed `TrashEntry` and verifying it post-decrypt; that binding is what suffix-equality approximates but cannot provide. Deliberately out of scope here (frozen-v1 format consideration) — #293 tracks it.
