# Design: purge / empty-trash operation (#399)

**Date:** 2026-07-08
**Issue:** #399 — *Design a purge / empty-trash operation (crypto-shred vs best-effort overwrite)*
**Refs:** #376 (observable trash relocation — split this out), #350 (manifest-first `trash_block` + repair), #293 (signed content commitment), #205 (restore signed-timestamp binding)
**Scope (this slice):** Rust `core` (orchestrators + `docs/vault-format.md` §7 + tests + `conformance.py`) **and** the FFI bridge projection (`secretary-ffi-bridge` → pyo3 + uniffi). Platform UIs (desktop / iOS / Android) are described here but deferred to per-platform follow-up issues.

## Problem

`trash_block` moves a block `blocks/ → trash/`; this is **organizational**, not a security boundary — the trashed ciphertext is equally decryptable in `trash/` as in `blocks/` (same bytes, same recipient wraps). There is currently **no** operation that permanently removes a trashed block. §7 step 5 mentions a 90-day retention window after which trash files "are physically removed", but no code implements it and no explicit user-initiated purge verb exists. #376 deliberately excluded "secure overwrite" because it belongs to a purge operation, not to trash.

Two honest caveats constrain any purge design:

1. **Filesystem-level secure erase is unreliable on modern storage.** Zero-then-unlink does not dependably destroy data on SSDs (wear-leveling remaps writes), CoW/journaling filesystems (btrfs/APFS/ZFS keep the old extent until GC), or snapshotted volumes. A best-effort overwrite is defense-in-depth hygiene, **not** an erasure guarantee.
2. **The load-bearing erasure property is cryptographic.** A block's plaintext is recoverable only via its per-block **Block Content Key (BCK)**, which exists *only* wrapped per-recipient inside the block file itself (the §6.2 recipient table) — there is no separate key store. Consequences:
   - For an **owner-only, never-shared** block, deleting the local ciphertext file *is* the crypto-shred: the owner can unwrap the BCK only from that file; once it is gone the plaintext is unrecoverable. There is no distinct "destroy the key but keep the ciphertext" mechanism to build.
   - For a **shared/synced** block, any recipient with a copy of the ciphertext can still decrypt it. Purge cannot reach their copies. Purge of a shared block is inherently **local cleanup**, not global forgetting.

## Decisions (resolved during brainstorming)

1. **One erasure mechanism + honest classification.** Purge deletes every local `trash/` copy of the block (`fs::remove_file`). "Owner-only vs shared" is computed from the §6.2 recipient table **only to drive honest reporting/UX copy**, never as a second code path.
2. **Keep the tombstone, mark it purged.** The `TrashEntry` is retained in the signed manifest (it is the resurrection guard against a lagging peer that still holds the block live) and marked purged via a new additive optional field `purged_at_ms`. This mirrors the existing §7 retention asymmetry (files GC'd, tombstone persists).
3. **Unlink only — no overwrite pass in v1.** FS-level secure erase is unachievable (caveat 1); the bytes are already ciphertext and unlinking destroys the only local copy of the wrapped BCK (caveat 2). No overwrite theater. Documented plainly. Can be added later if a concrete threat model demands it.
4. **Two explicit user-initiated verbs:** `purge_block(uuid)` and `empty_trash()`. Retention auto-purge (§7 step 5, auto-delete on open past a window) is a distinct security-sensitive design (auto-deletes without user action) and is deferred to its own issue.
5. **Add a dedicated `BlockPurged` typed error** so restore of a purged block yields a clean "permanently purged" signal, distinct from `BlockNotInTrash` / an integrity failure. Accepted cost: the workspace-wide exhaustive-match obligation for a new `FfiVaultError` variant (uniffi/pyo3/core-KAT + the Swift/Kotlin conformance harnesses).

## Manifest change — `TrashEntry.purged_at_ms`

`core/src/vault/manifest.rs` `TrashEntry` today:

```rust
pub struct TrashEntry {
    pub block_uuid: [u8; UUID_LEN],
    pub tombstoned_at_ms: u64,
    pub tombstoned_by: [u8; UUID_LEN],
    pub fingerprint: Option<[u8; BLOCK_FINGERPRINT_LEN]>,
    pub unknown: BTreeMap<String, UnknownValue>,
}
```

Add:

```rust
    /// `Some(t)` = this block has been purged: its local ciphertext was
    /// permanently removed at unix-millis `t`. Terminal and monotonic — a
    /// purged entry never un-purges. `None` = a still-restorable trash entry.
    /// Additive optional field: old clients preserve it verbatim through the
    /// §6.3.2 `unknown` map, exactly as `fingerprint` was introduced.
    pub purged_at_ms: Option<u64>,
```

**Format-freeze compliance.** This follows the *exact* forward-compat precedent already set by `fingerprint: Option<…>`: a new CBOR map key that old clients round-trip verbatim via `unknown` (§6.3.2) and new clients read as a known field. The decoder gains one optional-key read; encode is symmetric. No wire-format break, no `manifest_version` bump. `fingerprint` is left untouched by purge — `purged_at_ms.is_some()` is the sole purged signal (so it is unambiguously distinct from the legacy `fingerprint == None` case).

The CBOR map key is `"purged_at_ms"` (snake_case, matching sibling keys). Absent key decodes to `None` (round-trips to absent, not to an explicit null) so pre-purge manifests re-encode byte-identically.

## Operations

### `purge_block(open, block_uuid)`

Manifest-first, mirroring `trash_block`'s ordering (§8: "for deletion, manifest-first — never persist a manifest state that references block bytes that are not on disk"; purge inverts this — mark unrestorable *before* removing bytes, so the manifest never advertises a restorable block whose bytes are mid-deletion).

1. **Preconditions.**
   - `uuid` MUST have a `TrashEntry` in `manifest.trash`, else `VaultError::BlockNotInTrash`. (A `uuid` in `manifest.trash` is not in `manifest.blocks` by construction — the two lists are mutually exclusive — so no separate "already live" precondition is needed on the trash side; the "not live" property is nonetheless re-asserted as the *file-deletion gate* in step 4, defensively matching the sweep, so a corrupt both-live-and-trashed manifest can never have its live block's file deleted.)
   - If the `TrashEntry` is already purged (`purged_at_ms.is_some()`), purge is an **idempotent no-op success**: return a report with `files_removed = <any residual files cleaned>` and the recorded classification if still derivable, without re-signing. (Re-purge must never fail.)
2. **Classify (reporting only).** Locate the restore-target trash file for `uuid` (the file whose suffix equals the signed `tombstoned_at_ms`, per §7.1 step 2). Decode its §6.2 recipient table; `was_shared = recipients != {owner_fingerprint}`; `recipient_count = recipients.len()`. If the file is already absent (crash residue / prior partial purge), classification is unavailable → report `was_shared = None` (the honest "unknown" — we do not fabricate it).
3. **Commit point.** Re-sign + atomically write the manifest with the matching `TrashEntry.purged_at_ms = now_ms`. From here the block is purged regardless of what happens to the physical files.
4. **Best-effort file removal** (gated on `uuid` not live in `manifest.blocks`, matching the sweep — a no-op on a well-formed manifest, load-bearing only against a corrupt both-live-and-trashed one). `fs::remove_file` every `trash/<uuid>.cbor.enc.*` copy (restore-target *and* any stale siblings). Individual failures are logged (`tracing::warn!`, reusing the #376 observability pattern) and swallowed — a crash between 3 and 4 leaves a purged-marked entry plus a lingering file, which is a benign orphan: restore refuses it via the marker, and the open-time purge-cleanup sweep (below) removes it on a later open.

Returns `PurgeReport { block_uuid, was_shared: Option<bool>, recipient_count: Option<u16>, files_removed: usize }`.

### `empty_trash(open)`

Bulk purge of every non-purged `TrashEntry`:

1. Collect all `TrashEntry` where `purged_at_ms.is_none()` and `block_uuid` not live in `manifest.blocks`.
2. Classify each (step 2 above), best-effort — an undecodable/absent file yields `was_shared = None` for that entry and does not abort the batch.
3. **Single commit point.** Re-sign + atomically write the manifest once, marking *all* collected entries purged with a shared `now_ms`. (One re-sign for the batch, not N.)
4. Best-effort remove all their files.

Returns `EmptyTrashReport { purged_count, shared_count, owner_only_count, unknown_count, files_removed, files_failed }`. Per-entry failure never aborts the batch (mirrors `restore_block` step 6's best-effort purge of stale copies).

### Restore interaction

`restore_block` gains a fail-fast precondition: if the matching `TrashEntry.purged_at_ms.is_some()`, return **`VaultError::BlockPurged { block_uuid }`** *before* any trash-file scan — the content is intentionally gone, distinct from `BlockNotInTrash` (no signed record) and `RestoreVerificationFailed` (integrity failure). Because `TrashEntry` is inside the signed manifest, an attacker cannot strip the purged marker without invalidating the signature.

## CRDT / cross-device propagation

The signed manifest is the synced artifact, so the purged marker propagates to the owner's other devices. Two additions make purge meaningful across replicas without weakening any existing guarantee:

- **Merge monotonicity.** When two manifests carry a `TrashEntry` for the same `block_uuid`, the merged `purged_at_ms` is purged if *either* side is purged (take the `Some` with the max millis; `None` loses to any `Some`). Purge is terminal — a merge never un-purges. This is a pure metadata monotone join on an already-dead tombstone; it introduces **no** new resurrection semantics.
- **Open-time purge-cleanup sweep.** On each successful open, for every `TrashEntry` with `purged_at_ms.is_some()` whose local `trash/` file still exists **and whose `block_uuid` is not live in `manifest.blocks`**, delete the file (best-effort, rename-free, no manifest change). This is a direct mirror of the existing §7 relocation sweep (`repair/sweep.rs::complete_pending_trash_renames`) and reuses its "not live in `manifest.blocks`" gate.

**Concurrent restore is safe by construction.** If, concurrent with a purge on device A, device B restores the block (removing the `TrashEntry`, adding a live `BlockEntry`), the merged manifest resolves the block's liveness by the *existing* trash/restore + block-vector-clock rules — purge adds nothing to that decision. The purge-cleanup sweep's "not live in `manifest.blocks`" gate means: if a restore won, the block is live, and the sweep leaves its file untouched. Purge therefore can never delete the ciphertext of a block that is live in the merged manifest.

## FFI surface (bridge → pyo3 + uniffi)

New in `secretary-ffi-bridge`:

- `pub fn purge_block(handle, block_uuid: &[u8; 16]) -> Result<PurgeReport, FfiVaultError>`
- `pub fn empty_trash(handle) -> Result<EmptyTrashReport, FfiVaultError>`
- `pub struct PurgeReport { block_uuid, was_shared: Option<bool>, recipient_count: Option<u16>, files_removed: u32 }`
- `pub struct EmptyTrashReport { purged_count, shared_count, owner_only_count, unknown_count, files_removed, files_failed: u32 }`
- New `FfiVaultError::BlockPurged { block_uuid }`, mapped from `VaultError::BlockPurged`. Input `block_uuid` length validated at the binding wrapper (`&[u8; 16]`), per [[project_secretary_input_validation_at_binding_wrapper]].

Placed under a new `purge/` module in the bridge (mirroring `trash/`, `restore/`). Exposed on both pyo3 and uniffi. Platform UIs ("Delete forever" / "Empty Trash") consume this surface and are deferred.

## Testing (TDD — tests first)

**Core unit / integration (`core/tests/`):**
- `purge_block` happy path: owner-only block → report `was_shared = Some(false)`, files gone, `TrashEntry.purged_at_ms = Some(_)`, `BlockEntry` still absent.
- Shared block → `was_shared = Some(true)`, `recipient_count` correct.
- Idempotent re-purge → no-op success, no second re-sign (assert manifest bytes unchanged on the second call).
- `BlockNotInTrash` for an unknown UUID; `BlockUuidAlreadyLive` for a live UUID.
- Crash residue: manifest marked purged but file present → open-time sweep removes it; sweep skips a purged entry whose UUID is live (concurrent-restore safety).
- `restore_block` on a purged entry → `BlockPurged` (fail-fast, before any file scan).
- `empty_trash`: mixed owner-only + shared + already-purged → aggregate report correct, single re-sign, one failure does not abort.
- Merge monotonicity: purged ∨ non-purged → purged; take max millis; `None` loses to `Some`.
- `purged_at_ms` CBOR round-trip: `None` re-encodes byte-identically (absent key); `Some` round-trips; an old-client `unknown`-map round-trip preserves it.

**Conformance (`core/tests/python/conformance.py`):** add a purge scenario proving the manifest marker + merge-monotonicity are reproducible clean-room from `docs/` alone; extend the merge-KAT set with a purged-tombstone case (`conflict_kat.json`).

**FFI conformance:** `purge_block` / `empty_trash` / restore-of-purged replayed through the Swift + Kotlin uniffi harnesses (`run_conformance.sh`), asserting the same observable output as the Rust bridge replay; thread `BlockPurged` through `ConformanceErrors.{swift,kt}` ([[project_secretary_ffivaulterror_workspace_match]]).

## Non-goals / guardrails

- **No overwrite pass, no secure-erase claim.** Document the honest limitation in §7.2 and in the FFI doc comments.
- **No retention auto-purge** (§7 step 5 auto-delete on open) — separate future issue.
- **No new crypto.** No `crypto-design.md` change; purge introduces no new primitive, KEM, or signature site.
- **No `manifest_version` bump.** `purged_at_ms` is an additive optional field via the established `unknown`-map forward-compat mechanism.
- **No platform-UI code** this slice.
- **Never delete a live block's file.** The purge-cleanup sweep's "not live in `manifest.blocks`" gate is load-bearing and must be preserved (guard comment at the sweep site).

## Acceptance

```bash
cd /Users/hherb/src/secretary
cargo test --release --workspace                                  # full suite green
cargo test --release -p secretary-core purge                      # new purge tests pass
cargo test --release --workspace --features differential-replay   # cross-language replay green
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all --check                                           # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
uv run core/tests/python/conformance.py                           # purge scenario passes
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh      # BlockPurged threaded
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```

Close #399 on merge with a comment recording the deliberate non-actions: overwrite (decision 3), retention auto-purge (decision 4 — deferred to a new issue).
