# Design — `restore_block` content commitment (#293, #205 residual)

**Date:** 2026-06-23
**Issue:** #293 — *restore_block: in-place overwrite of the signed-suffix trash file still allows authentic-but-stale rollback*
**Status:** Approved design, pre-implementation.
**Branch:** `feature/trash-content-commitment` (worktree `.worktrees/trash-content-commitment`, off `main` @ `77656a31`).

## Problem

PR #292 (#205) bound `restore_block` *selection* to the signed `TrashEntry.tombstoned_at_ms` (equality, not largest suffix), closing two rollback vectors: the larger-suffix plant, and the authentic-file-removed case (`RestoreTargetMissing`).

A third vector survives. An attacker with write access to the synced `trash/` folder (threat-model §2.1) can **overwrite the suffix-matching file in place** with a *previously-retained, genuinely owner-signed, older* copy of the same `block_uuid`, named at the exact signed suffix `trash/<uuid>.cbor.enc.<tombstoned_at_ms>`. At restore:

- equality selection picks that file (it is the only suffix match),
- §6.1 hybrid-verify **passes** (the content is genuinely owner-signed — *authenticity is not currency*),
- the stale block goes live with the older content's `vector_clock_summary`.

Result: an authentic-but-stale rollback (e.g. a rotated password reverts), achieved by overwriting rather than out-suffixing the authentic file.

### Root cause

`TrashEntry` (`core/src/vault/manifest.rs`) carries `block_uuid` / `tombstoned_at_ms` / `tombstoned_by` — **no commitment to the trashed block's *content***. The suffix-equality fix binds the *filename* to the signed timestamp and verifies *authenticity*, but nothing binds the restored content's *freshness* to the signed manifest.

## Approach

Bind the restored block's content to the signed manifest by carrying the block's existing BLAKE3-256 fingerprint through the trash→restore lifecycle.

`BlockEntry` already commits to `fingerprint: [u8; 32]` (BLAKE3-256 of the complete block file bytes, `BLOCK_FINGERPRINT_LEN = 32`), and `open_vault` verifies every on-disk block file against it (`verify_block_fingerprints`). We extend that same commitment to tombstoned blocks.

### 1. `TrashEntry` gains an optional content commitment

```rust
pub struct TrashEntry {
    pub block_uuid: [u8; UUID_LEN],
    pub tombstoned_at_ms: u64,
    pub tombstoned_by: [u8; UUID_LEN],
    /// BLAKE3-256 of the trashed block file bytes, captured at trash time
    /// (the value the live `BlockEntry.fingerprint` committed to). `None`
    /// for entries written before this field existed (legacy vaults).
    pub fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]>,
    pub unknown: BTreeMap<String, UnknownValue>,
}
```

- **Encoder** (`trash_entry_to_value`): emit key `"fingerprint"` **only when `Some`**. Legacy-shaped entries (no commitment) stay byte-identical → no `format_version` / `manifest_version` bump.
- **Decoder** (`parse_trash_entry`): add a typed arm for `KEY_TRASH_FINGERPRINT = "fingerprint"` → `Some(take_fixed_bytes::<BLOCK_FINGERPRINT_LEN>(..))`; absent → `None`. Any *other* unknown key still routes to `unknown` (forward-compat unchanged).
- All `TrashEntry { .. }` literals across the workspace gain the new field (test fixtures, conflict/merge sites if any).

### 2. `trash_block` populates it

The `BlockEntry` being removed already carries a verified `fingerprint` (authenticated at the most recent `open_vault`; the file is *moved* by `rename`, not rewritten, so the bytes — and thus the hash — are unchanged). Copy it directly:

```rust
open.manifest.trash.push(TrashEntry {
    block_uuid,
    tombstoned_at_ms: now_ms,
    tombstoned_by: device_uuid,
    fingerprint: Some(entry_fingerprint), // = removed BlockEntry.fingerprint
    unknown: BTreeMap::new(),
});
```

No re-hashing at trash time — the value is already trustworthy and binding it to a fresh read would only widen the trust surface.

### 3. `restore_block` verifies it

After reading the selected file's bytes (existing step 4, **before** the point-of-no-return rename at step 6):

```rust
if let Some(committed) = trash_entry_fingerprint {
    let got = *blake3_hash(&bytes).as_bytes();
    if got != committed {
        return Err(VaultError::RestoreVerificationFailed {
            block_uuid,
            detail: "content commitment mismatch: trashed file bytes do not \
                     match the signed TrashEntry.fingerprint".into(),
        });
    }
}
```

- The BLAKE3-256 of the restored bytes is already computed downstream for the new `BlockEntry.fingerprint`; this hoists/duplicates it so the check happens before any filesystem mutation. The manifest and `trash/` are untouched on the reject path (same guarantee as the existing hybrid-verify failure).
- `None` (legacy entry) → the current #205 suffix-equality + §6.1 hybrid-verify path is unchanged.

## Decisions (confirmed with user)

| Decision | Choice | Rationale |
|---|---|---|
| Storage shape | **Typed `Option<[u8;32]>` field** | Backward-compatible (old clients route the key to `unknown`, preserve + re-sign on round-trip); forward-compatible; legacy entries byte-identical; no version bump. Cleaner than overloading `unknown` with a field this client depends on. |
| Legacy fallback | **Graceful** — `None` → existing #205 behavior | A missing commitment cannot break restore of blocks trashed before this lands. New trash always carries the commitment. |
| Error surface | **Reuse `RestoreVerificationFailed`** | A commitment mismatch *is* a signed-data ↔ on-disk-bytes integrity failure — exactly this variant's meaning. Folds to `FfiVaultError::CorruptVault`: **no new FFI variant, no `.udl`/pyo3/Swift/Kotlin conformance churn**. Distinguished by `detail`. Consistent with #205. |

## Security properties

- **No downgrade-strip attack.** `TrashEntry` lives inside the AEAD'd, hybrid-signed manifest body. An attacker who strips the `fingerprint` field to force the legacy path invalidates the manifest signature → `open_vault` fails before restore is reachable. The fallback path is reachable **only** for genuinely legacy entries written by a pre-change client, never attacker-induced.
- **Closes the in-place-overwrite vector for newly-trashed blocks.** The commitment binds the *exact* bytes; an older copy (different bytes) has a different BLAKE3 → mismatch → reject, regardless of how genuinely it was once owner-signed.
- **Residual (documented, not closed):** blocks trashed by a pre-change client carry no commitment and remain exposed to the #293 vector until re-trashed by an updated client. This is the deliberate cost of graceful fallback; an attacker cannot *induce* this state (see downgrade-strip above).

## Testing (TDD)

New tests in `core/tests/trash_restore.rs`:

1. **`restore_block_rejects_in_place_overwrite_with_stale_signed_copy`** — the #293 teeth test. Trash an authentic block (commitment captured). Produce a *different, genuinely-signed, validly-decoding* copy of the same `block_uuid` and overwrite the suffix-matching trash file in place with its bytes, leaving the signed manifest (and its committed fingerprint) intact. Restore must reject with `RestoreVerificationFailed`; manifest + `trash/` untouched. **Fails on `main`** (no commitment → hybrid-verify passes → stale block goes live).
2. **`restore_block_legacy_entry_without_fingerprint_falls_back`** — construct a `TrashEntry` with `fingerprint: None` (re-sign the manifest), confirm restore succeeds via suffix-equality. Guards the fallback path and proves legacy vaults still restore.
3. **Happy-path assertion** — a normal trash→restore carries the commitment: after `trash_block`, assert the new `TrashEntry.fingerprint == Some(live BlockEntry.fingerprint)`; after `restore_block`, the round-trip succeeds and the restored `BlockEntry.fingerprint` equals the committed value.

Plus the full gate: `cargo test --release --workspace`, `cargo clippy --release --workspace --tests -- -D warnings`, `uv run core/tests/python/conformance.py`, `uv run core/tests/python/spec_test_name_freshness.py`.

## Docs to update in lockstep

- **`docs/vault-format.md`** §4.2 (trash-entry field list gains optional `fingerprint`) and §7/§7.1 (restore gains the content-commitment verification step; note the legacy-`None` fallback).
- **`docs/threat-model.md`** §2.1 — note the in-place-overwrite vector is closed for committed entries.
- **`README.md`** B.5 row — restore now verifies a content commitment, not only the signed selection.
- **`conformance.py`** — **no change** (it decodes the golden *block file* + KAT merges, not manifest trash entries; the golden vault has no trash entries). Verified at design time.

## Scope guard

Stays inside frozen v1 — the field is optional and unknown-routed, so no `format_version` bump and no v2 manifest discussion. The issue's `vector_clock_summary`-as-commitment alternative is rejected: BLAKE3-of-bytes is strictly stronger (binds exact content) and reuses the existing `BlockEntry.fingerprint` / `verify_block_fingerprints` machinery.
