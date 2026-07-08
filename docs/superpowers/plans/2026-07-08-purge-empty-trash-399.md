# Purge / Empty-Trash (#399) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a permanent purge lifecycle verb (`purge_block` + `empty_trash`) that deletes a trashed block's local ciphertext and marks its manifest tombstone purged, projected through the FFI bridge to pyo3 + uniffi.

**Architecture:** Purge is manifest-first (mirroring `trash_block`): mark the `TrashEntry` purged via a new additive optional `purged_at_ms` field, re-sign + atomic-write the manifest (commit point), then best-effort delete the local `trash/` files. Owner-only vs shared is classified from the §6.2 recipient table for honest reporting only — one erasure mechanism, no overwrite. An open-time sweep propagates purges across the owner's devices via manifest file sync.

**Tech Stack:** Rust (stable) `secretary-core`; `secretary-ffi-bridge` → PyO3 + uniffi (Swift/Kotlin); CBOR (`ciborium`); BLAKE3; hybrid Ed25519 ∧ ML-DSA-65 manifest signing.

**Design doc:** [docs/superpowers/specs/2026-07-08-purge-empty-trash-399-design.md](../specs/2026-07-08-purge-empty-trash-399-design.md)

## Global Constraints

- Workspace lints: `#![forbid(unsafe_code)]`; clippy must stay clean with `-D warnings` (lib + tests); `cargo fmt --all --check` clean; `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace` clean.
- Tests run `--release` (crypto crates are slow in debug). Python is `uv` only — never pip.
- Spec is normative: `docs/vault-format.md` changes ship *with* the code that implements them; `conformance.py` must keep agreeing with the Rust bytes.
- Frozen v1 format: `purged_at_ms` is an **additive optional** CBOR map key via the existing `unknown`-map forward-compat mechanism — **no `manifest_version` bump**, no wire break. Absent key ⇒ `None` ⇒ re-encodes byte-identically.
- No new crypto primitive, KEM, or signature site. No overwrite pass. No platform-UI code. No retention auto-purge. No conflict-copy trash-merge (deferred follow-up).
- Secret hygiene: any decoded block plaintext is dropped/zeroized at end of scope; classification reads only the cleartext §6.2 recipient fingerprints (no plaintext needed).
- `FfiVaultError` variant additions are a workspace-wide exhaustive-match obligation: uniffi + pyo3 + core-KAT matches AND the Swift/Kotlin `ConformanceErrors.{swift,kt}` harnesses (which cargo/clippy cannot see — only `run_conformance.sh` does).

**Working directory / branch:** Work on branch `feature/purge-empty-trash-399` (already cut off `main` @ `ca01b3a`; design commits `d113c3b`, `7a8bd02`). Verify before path-sensitive commands: `pwd && git branch --show-current`.

---

## File Structure

**Core (`secretary-core`):**
- `core/src/vault/manifest.rs` — MODIFY: add `TrashEntry.purged_at_ms` field + CBOR encode/decode + `KEY_PURGED_AT_MS` const.
- `core/src/vault/mod.rs` — MODIFY: add `VaultError::BlockPurged`; register `pub mod purge;` (or `pub(crate)` + re-export, matching sibling verbs).
- `core/src/vault/orchestrators.rs` — MODIFY: `restore_block` fail-fast `BlockPurged` guard; wire the new sweep at the open-time call site (line ~600).
- `core/src/vault/purge.rs` — CREATE: `purge_block`, `empty_trash`, `PurgeReport`, `EmptyTrashReport`, the pure `classify_recipients` helper, and the `remove_trash_files` / `classify_trash_target` I/O helpers. (New module — keeps `orchestrators.rs` from growing past its already-large size.)
- `core/src/vault/repair/sweep.rs` — MODIFY: add `sweep_purged_trash_files`; `core/src/vault/repair/mod.rs` re-export.
- `docs/vault-format.md` — MODIFY: §7.2 "Purging a block" + `purged_at_ms` in the manifest schema.
- `core/tests/purge.rs` — CREATE: integration tests for the orchestrators + sweep.
- `core/tests/python/conformance.py` — MODIFY: purge scenario.

**FFI (`secretary-ffi-bridge` + bindings):**
- `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` — MODIFY: `FfiVaultError::BlockPurged` + `VaultError` mapping.
- `ffi/secretary-ffi-bridge/src/purge/` — CREATE: `mod.rs`, `orchestration.rs` (`purge_block`, `empty_trash`, `PurgeReport`, `EmptyTrashReport`), mirroring `trash/`.
- `ffi/secretary-ffi-bridge/src/lib.rs` — MODIFY: register + re-export `purge` module.
- `ffi/secretary-ffi-bridge/src/trash/list.rs` — MODIFY: `list_trashed_blocks` skips purged entries.
- `ffi/secretary-ffi-py/…`, `ffi/secretary-ffi-uniffi/…` — MODIFY: project the new fns/types + `BlockPurged`.
- `ffi/secretary-ffi-uniffi/tests/{swift,kotlin}/…ConformanceErrors.{swift,kt}` + conformance runners — MODIFY.

---

## Task 1: `TrashEntry.purged_at_ms` field + CBOR round-trip

**Files:**
- Modify: `core/src/vault/manifest.rs` (struct `TrashEntry` ~line 362; `trash_entry_to_value` ~line 1989 region; the trash-entry decoder; add a `KEY_PURGED_AT_MS` const beside the other `KEY_*` consts)
- Test: `core/src/vault/manifest.rs` `#[cfg(test)]`

**Interfaces:**
- Produces: `TrashEntry { block_uuid, tombstoned_at_ms, tombstoned_by, fingerprint, purged_at_ms: Option<u64>, unknown }`.

- [ ] **Step 1: Write the failing round-trip tests**

Add to the manifest tests module (mirror the existing `fingerprint` round-trip tests near line 1961–1997):

```rust
#[test]
fn trash_entry_purged_at_ms_none_roundtrips_byte_identical() {
    let mut m = sample_manifest_with_one_trash_entry(); // existing helper used by fingerprint tests
    m.trash[0].purged_at_ms = None;
    let v1 = trash_entry_to_value(&m.trash[0]).unwrap();
    let bytes1 = to_canonical_cbor_value(&v1);
    let decoded = decode_trash_entry(&v1).unwrap();
    assert_eq!(decoded.purged_at_ms, None, "None must round-trip");
    // absent key, not explicit null: re-encode is byte-identical to a pre-purge entry
    let v2 = trash_entry_to_value(&decoded).unwrap();
    assert_eq!(bytes1, to_canonical_cbor_value(&v2));
}

#[test]
fn trash_entry_purged_at_ms_some_roundtrips() {
    let mut m = sample_manifest_with_one_trash_entry();
    m.trash[0].purged_at_ms = Some(1_724_000_000_123);
    let v = trash_entry_to_value(&m.trash[0]).unwrap();
    let decoded = decode_trash_entry(&v).unwrap();
    assert_eq!(decoded.purged_at_ms, Some(1_724_000_000_123));
}
```

If exact helper names (`sample_manifest_with_one_trash_entry`, `to_canonical_cbor_value`, `decode_trash_entry`) differ, match the ones the existing `fingerprint` round-trip tests use in this module (read lines 1955–2000 first).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-core --lib manifest::tests::trash_entry_purged`
Expected: FAIL — `purged_at_ms` field does not exist / not decoded.

- [ ] **Step 3: Add the field**

In `struct TrashEntry` (after `fingerprint`), add:

```rust
    /// `Some(t)` = this block has been purged: its local ciphertext was
    /// permanently removed at unix-millis `t`. Terminal and monotonic — a
    /// purged entry never un-purges. `None` = a still-restorable trash entry.
    /// Additive optional field (§6.3.2 forward-compat), same shape as
    /// `fingerprint`; absent key decodes to `None` and re-encodes to absent.
    pub purged_at_ms: Option<u64>,
```

Add the key constant beside the sibling `KEY_*` consts:

```rust
const KEY_PURGED_AT_MS: &str = "purged_at_ms";
```

- [ ] **Step 4: Encode + decode**

In `trash_entry_to_value`, after the `fingerprint` key emission, mirror its optional pattern:

```rust
    if let Some(purged_at_ms) = entry.purged_at_ms {
        map.push((
            Value::Text(KEY_PURGED_AT_MS.into()),
            Value::Integer(purged_at_ms.into()),
        ));
    }
```

In the trash-entry decoder, read the optional key exactly as `fingerprint` is read (absent ⇒ `None`), integer ⇒ `u64` (reject negative / overflow with the module's existing typed decode error), and **ensure `purged_at_ms` is removed from the `unknown` map** it would otherwise land in (match how `fingerprint` is excluded).

Fix every other `TrashEntry { … }` literal in the crate to add `purged_at_ms: None` (compile will point them out — e.g. `trash_block` in orchestrators.rs, block.rs test fixtures ~1893/2029, sync test helpers).

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --release -p secretary-core --lib manifest`
Expected: PASS. Then `cargo build --release -p secretary-core` to confirm all `TrashEntry` literals updated.

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/manifest.rs core/src/vault/orchestrators.rs core/src/vault/block.rs core/src/sync
git commit -m "feat(core): add TrashEntry.purged_at_ms (additive optional, #399)"
```

---

## Task 2: `VaultError::BlockPurged` + `restore_block` fail-fast guard

**Files:**
- Modify: `core/src/vault/mod.rs` (enum `VaultError` ~line 82; add variant near `BlockNotInTrash` ~301)
- Modify: `core/src/vault/orchestrators.rs` (`restore_block`, at the `TrashEntry` lookup ~line 2412–2420)
- Test: `core/tests/purge.rs` (CREATE)

**Interfaces:**
- Produces: `VaultError::BlockPurged { block_uuid: [u8; 16] }`.
- Consumes: Task 1's `purged_at_ms`.

- [ ] **Step 1: Write the failing test**

Create `core/tests/purge.rs`. Use the existing trash/restore integration-test scaffolding (copy the vault-setup helper pattern from `core/tests/crash_recovery.rs` or the restore tests — a temp copy of a golden vault, unlock, save a block, trash it). Then:

```rust
#[test]
fn restore_of_purged_block_returns_block_purged() {
    let (folder, mut open, device, mut rng) = setup_vault_with_trashed_block();
    let uuid = /* the trashed block uuid */;
    // Mark it purged directly through purge_block once Task 3 lands; for now,
    // hand-set the manifest marker to isolate the restore guard:
    let idx = open.manifest.trash.iter().position(|t| t.block_uuid == uuid).unwrap();
    open.manifest.trash[idx].purged_at_ms = Some(42);

    let err = secretary_core::vault::restore_block(&folder, &mut open, uuid, device, 1000, &mut rng)
        .unwrap_err();
    assert!(matches!(err, secretary_core::vault::VaultError::BlockPurged { .. }));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-core --test purge restore_of_purged_block`
Expected: FAIL — `BlockPurged` does not exist (compile error).

- [ ] **Step 3: Add the variant**

In `VaultError` (near `BlockNotInTrash`):

```rust
    /// `restore_block`: the block's `TrashEntry` is marked purged
    /// (`purged_at_ms.is_some()`) — the ciphertext was permanently removed
    /// and cannot be restored. Distinct from `BlockNotInTrash` (no signed
    /// tombstone at all) and `RestoreVerificationFailed` (integrity failure).
    #[error("block {block_uuid:02x?} has been purged and cannot be restored")]
    BlockPurged { block_uuid: [u8; 16] },
```

- [ ] **Step 4: Add the guard**

In `restore_block`, at the `TrashEntry` match (~2412), fail fast before any file scan is used:

```rust
    let (expected_ts, committed_fp) = match open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == block_uuid)
    {
        Some(entry) if entry.purged_at_ms.is_some() => {
            return Err(VaultError::BlockPurged { block_uuid });
        }
        Some(entry) => (entry.tombstoned_at_ms, entry.fingerprint),
        None => return Err(VaultError::BlockNotInTrash { block_uuid }),
    };
```

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --release -p secretary-core --test purge restore_of_purged_block`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/mod.rs core/src/vault/orchestrators.rs core/tests/purge.rs
git commit -m "feat(core): VaultError::BlockPurged + restore_block guard (#399)"
```

---

## Task 3: core `purge.rs` — classify + `purge_block` + `PurgeReport`

**Files:**
- Create: `core/src/vault/purge.rs`
- Modify: `core/src/vault/mod.rs` (register module + re-export `purge_block`, `PurgeReport`)
- Test: `core/tests/purge.rs`

**Interfaces:**
- Consumes: `resign_and_write_manifest`, `tick_clock`, `format_uuid_hyphenated`, `TRASH_SUBDIR`, `BLOCK_FILE_EXTENSION` (all `pub(crate)` in `orchestrators`); `block::decode_block_file`, `block::RecipientWrap`; `crate::crypto::…::fingerprint`; `TrashEntry.purged_at_ms`.
- Produces:
  - `pub struct PurgeReport { pub block_uuid: [u8;16], pub was_shared: Option<bool>, pub recipient_count: Option<u16>, pub files_removed: usize }`
  - `pub fn purge_block(folder: &Path, open: &mut OpenVault, block_uuid: [u8;16], device_uuid: [u8;16], now_ms: u64, rng: &mut (impl RngCore + CryptoRng)) -> Result<PurgeReport, VaultError>`
  - `pub(crate) fn classify_recipients(recipients: &[RecipientWrap], owner_fp: &[u8;16]) -> (bool, u16)` (pure)

- [ ] **Step 1: Write the failing pure-classify unit test**

In `core/src/vault/purge.rs` `#[cfg(test)]`:

```rust
#[test]
fn classify_owner_only_is_not_shared() {
    let owner = [0xAA; 16];
    let recips = vec![wrap_with_fp(owner)];
    assert_eq!(classify_recipients(&recips, &owner), (false, 1));
}

#[test]
fn classify_owner_plus_other_is_shared() {
    let owner = [0xAA; 16];
    let recips = vec![wrap_with_fp(owner), wrap_with_fp([0xBB; 16])];
    assert_eq!(classify_recipients(&recips, &owner), (true, 2));
}
```

`wrap_with_fp` builds a `RecipientWrap` with the given `recipient_fingerprint` and dummy wrap bytes (mirror the block.rs test builders).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-core --lib purge::tests::classify`
Expected: FAIL — module/function missing.

- [ ] **Step 3: Implement the pure helper + module skeleton**

```rust
//! Permanent purge of trashed blocks (#399). Manifest-first: mark the
//! `TrashEntry` purged (commit point = manifest write), then best-effort
//! delete the local `trash/` ciphertext. One erasure mechanism; owner-only
//! vs shared is classified from the §6.2 recipient table for honest
//! reporting only. No overwrite (FS secure-erase is unachievable on
//! SSD/CoW; the bytes are already ciphertext, and unlinking destroys the
//! only local copy of the wrapped Block Content Key).
use std::path::Path;
use rand_core::{CryptoRng, RngCore};
use crate::vault::block::{self, RecipientWrap};
use crate::vault::orchestrators::{
    format_uuid_hyphenated, resign_and_write_manifest, tick_clock,
    BLOCK_FILE_EXTENSION, TRASH_SUBDIR,
};
use crate::vault::{OpenVault, VaultError};

/// Pure classification: `(was_shared, recipient_count)`. Owner-only ⇒ no
/// recipient fingerprint other than the owner's ⇒ `was_shared == false`.
pub(crate) fn classify_recipients(recipients: &[RecipientWrap], owner_fp: &[u8; 16]) -> (bool, u16) {
    let count = recipients.len() as u16;
    let was_shared = recipients.iter().any(|r| &r.recipient_fingerprint != owner_fp);
    (was_shared, count)
}
```

- [ ] **Step 4: Run to verify the pure test passes**

Run: `cargo test --release -p secretary-core --lib purge::tests::classify`
Expected: PASS.

- [ ] **Step 5: Add the I/O helpers + `purge_block` + `PurgeReport`**

```rust
#[derive(Debug, Clone)]
pub struct PurgeReport {
    pub block_uuid: [u8; 16],
    pub was_shared: Option<bool>,
    pub recipient_count: Option<u16>,
    pub files_removed: usize,
}

/// Best-effort removal of every `trash/<uuid>.cbor.enc.*` file. Returns the
/// count removed. Individual failures are logged (`tracing::warn!`) and
/// tolerated — a lingering file is a benign orphan the open-time sweep
/// removes later. Caller MUST have already established the uuid is not live
/// in `manifest.blocks` (true by construction for a trash entry).
fn remove_trash_files(folder: &Path, block_uuid: &[u8; 16]) -> usize {
    let trash_dir = folder.join(TRASH_SUBDIR);
    let uuid_hex = format_uuid_hyphenated(block_uuid);
    let prefix = format!("{uuid_hex}{BLOCK_FILE_EXTENSION}.");
    let mut removed = 0usize;
    let Ok(rd) = std::fs::read_dir(&trash_dir) else { return 0 };
    for entry in rd.flatten() {
        let path = entry.path();
        let is_match = path.file_name().and_then(|s| s.to_str())
            .map(|n| n.starts_with(&prefix)).unwrap_or(false);
        if !is_match { continue; }
        match std::fs::remove_file(&path) {
            Ok(()) => removed += 1,
            Err(e) => tracing::warn!(
                block_uuid = %uuid_hex, error = %e,
                "purge: failed to remove trash file; benign orphan remains"),
        }
    }
    removed
}

/// Best-effort classification of the restore-target trash file
/// (`suffix == tombstoned_at_ms`). Reads only the cleartext §6.2 recipient
/// fingerprints — no plaintext decrypt. `None` when the file is absent /
/// undecodable (honest "unknown", never fabricated).
fn classify_trash_target(
    folder: &Path,
    block_uuid: &[u8; 16],
    tombstoned_at_ms: u64,
    owner_card: &crate::vault::ContactCard,
) -> Option<(bool, u16)> {
    let uuid_hex = format_uuid_hyphenated(block_uuid);
    let path = folder.join(TRASH_SUBDIR)
        .join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}.{tombstoned_at_ms}"));
    let bytes = std::fs::read(&path).ok()?;
    let block_file = block::decode_block_file(&bytes).ok()?;
    let owner_fp = crate::crypto::hash::fingerprint(&owner_card.to_canonical_cbor().ok()?);
    Some(classify_recipients(&block_file.recipients, &owner_fp))
}

pub fn purge_block(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<PurgeReport, VaultError> {
    // Step 1: find the TrashEntry (BlockNotInTrash otherwise).
    let idx = open.manifest.trash.iter()
        .position(|t| t.block_uuid == block_uuid)
        .ok_or(VaultError::BlockNotInTrash { block_uuid })?;

    // Idempotent re-purge: already purged ⇒ no-op success, no re-sign.
    // Still best-effort clean any residual file (crash residue).
    if open.manifest.trash[idx].purged_at_ms.is_some() {
        let files_removed = remove_trash_files(folder, &block_uuid);
        return Ok(PurgeReport { block_uuid, was_shared: None, recipient_count: None, files_removed });
    }

    let tombstoned_at_ms = open.manifest.trash[idx].tombstoned_at_ms;

    // Step 2: classify (reporting only), best-effort.
    let (was_shared, recipient_count) =
        match classify_trash_target(folder, &block_uuid, tombstoned_at_ms, &open.owner_card) {
            Some((s, c)) => (Some(s), Some(c)),
            None => (None, None),
        };

    // Step 3: stage purged marker + tick vault clock; write = commit point.
    let mut staged = open.manifest.clone();
    staged.trash[idx].purged_at_ms = Some(now_ms);
    tick_clock(&mut staged.vector_clock, &device_uuid)?;
    let new_manifest_file = resign_and_write_manifest(
        folder, &staged, &open.identity, &open.identity_block_key,
        &open.manifest_file.header, now_ms, open.manifest_file.author_fingerprint, rng,
        "purge_block: failed to write manifest.cbor.enc",
    )?;
    open.manifest = staged;
    open.manifest_file = new_manifest_file;

    // Step 4: best-effort file removal (uuid is a trash entry ⇒ not live).
    let files_removed = remove_trash_files(folder, &block_uuid);
    Ok(PurgeReport { block_uuid, was_shared, recipient_count, files_removed })
}
```

Confirm the exact path of `fingerprint` (grep `pub fn fingerprint` under `core/src/crypto/`) and `ContactCard` re-export; adjust imports to what compiles. Register in `mod.rs`: `pub mod purge;` and `pub use purge::{purge_block, PurgeReport};` beside the trash/restore re-exports.

- [ ] **Step 6: Write the integration tests**

In `core/tests/purge.rs`:

```rust
#[test]
fn purge_owner_only_block_reports_not_shared_and_removes_file() {
    let (folder, mut open, device, mut rng) = setup_vault_with_trashed_block(); // owner-only
    let uuid = /* trashed uuid */;
    let report = secretary_core::vault::purge_block(&folder, &mut open, uuid, device, 5000, &mut rng).unwrap();
    assert_eq!(report.was_shared, Some(false));
    assert_eq!(report.recipient_count, Some(1));
    assert!(report.files_removed >= 1);
    let idx = open.manifest.trash.iter().position(|t| t.block_uuid == uuid).unwrap();
    assert!(open.manifest.trash[idx].purged_at_ms.is_some());
    assert!(!open.manifest.blocks.iter().any(|b| b.block_uuid == uuid)); // still not live
    // no trash file remains
    assert!(trash_files_for(&folder, &uuid).is_empty());
}

#[test]
fn purge_unknown_uuid_is_block_not_in_trash() {
    let (folder, mut open, device, mut rng) = setup_vault_with_trashed_block();
    let err = secretary_core::vault::purge_block(&folder, &mut open, [0x99;16], device, 5000, &mut rng).unwrap_err();
    assert!(matches!(err, secretary_core::vault::VaultError::BlockNotInTrash { .. }));
}

#[test]
fn re_purge_is_idempotent_no_second_resign() {
    let (folder, mut open, device, mut rng) = setup_vault_with_trashed_block();
    let uuid = /* trashed uuid */;
    secretary_core::vault::purge_block(&folder, &mut open, uuid, device, 5000, &mut rng).unwrap();
    let manifest_bytes_before = open.manifest_file_bytes(); // or clone open.manifest_file
    let report = secretary_core::vault::purge_block(&folder, &mut open, uuid, device, 6000, &mut rng).unwrap();
    assert_eq!(report.was_shared, None, "already-purged ⇒ unknown classification");
    assert_eq!(open.manifest_file_bytes(), manifest_bytes_before, "no re-sign on re-purge");
}
```

Add a shared-block variant test if the harness can mint a second recipient (mirror the share tests; `was_shared == Some(true)`, `recipient_count == Some(2)`). Provide the `setup_vault_with_trashed_block` / `trash_files_for` helpers at the top of the test file.

- [ ] **Step 7: Run to verify pass**

Run: `cargo test --release -p secretary-core --test purge`
Expected: PASS (all purge_block tests).

- [ ] **Step 8: Commit**

```bash
git add core/src/vault/purge.rs core/src/vault/mod.rs core/tests/purge.rs
git commit -m "feat(core): purge_block + PurgeReport, one-mechanism erase (#399)"
```

---

## Task 4: open-time purge-cleanup sweep

**Files:**
- Modify: `core/src/vault/repair/sweep.rs` (add `sweep_purged_trash_files`)
- Modify: `core/src/vault/repair/mod.rs` (re-export)
- Modify: `core/src/vault/orchestrators.rs` (call at open-time, ~line 600, beside `complete_pending_trash_renames`)
- Test: `core/tests/purge.rs`

**Interfaces:**
- Produces: `pub(crate) fn sweep_purged_trash_files(folder: &Path, manifest: &Manifest)`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn sweep_removes_purged_file_and_keeps_live_and_unpurged() {
    // Build a folder + manifest with three trash entries:
    //  A: purged, file present, uuid NOT live   → file removed
    //  B: purged, file present, uuid IS live    → file kept (concurrent restore)
    //  C: not purged, file present              → file kept
    let (folder, manifest) = build_sweep_fixture();
    secretary_core::vault::repair::sweep_purged_trash_files_for_test(&folder, &manifest); // doc(hidden) test hook or via open_vault
    assert!(!file_a_exists(&folder));
    assert!(file_b_exists(&folder));
    assert!(file_c_exists(&folder));
}
```

Since `sweep_purged_trash_files` is `pub(crate)`, drive it through a `#[doc(hidden)] pub` test hook (see [[project_secretary_cfg_test_not_propagated]]) or assert via a full `open_vault` round-trip that leaves the purged file gone. Prefer the `open_vault` route if a fixture exists.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-core --test purge sweep_removes_purged`
Expected: FAIL — function missing.

- [ ] **Step 3: Implement the sweep (mirror `complete_pending_trash_renames`)**

In `sweep.rs`:

```rust
/// Best-effort removal of local `trash/` files for entries the signed
/// manifest marks purged (#399). For every `TrashEntry` with
/// `purged_at_ms.is_some()` whose `block_uuid` is **not live** in
/// `manifest.blocks`, delete every `trash/<uuid>.cbor.enc.*` file. The
/// "not live" gate makes a concurrent restore win safely: a restored block
/// is live, so its file is left untouched. No manifest mutation, no signing;
/// idempotent; failures logged and tolerated. This is what propagates a
/// purge across the owner's devices via manifest file sync.
pub(crate) fn sweep_purged_trash_files(folder: &Path, manifest: &Manifest) {
    let trash_dir = folder.join(TRASH_SUBDIR);
    for entry in &manifest.trash {
        if entry.purged_at_ms.is_none() {
            continue;
        }
        // Live-and-trashed: never delete a live block's file.
        if manifest.blocks.iter().any(|b| b.block_uuid == entry.block_uuid) {
            continue;
        }
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let prefix = format!("{uuid_hex}{BLOCK_FILE_EXTENSION}.");
        let Ok(rd) = std::fs::read_dir(&trash_dir) else { continue };
        for de in rd.flatten() {
            let path = de.path();
            let is_match = path.file_name().and_then(|s| s.to_str())
                .map(|n| n.starts_with(&prefix)).unwrap_or(false);
            if !is_match { continue; }
            if let Err(e) = std::fs::remove_file(&path) {
                tracing::warn!(block_uuid = %uuid_hex, error = %e,
                    "purge sweep: failed to remove purged trash file; benign orphan remains");
            }
        }
    }
}
```

Re-export in `repair/mod.rs`: `pub(crate) use sweep::sweep_purged_trash_files;`.

- [ ] **Step 4: Wire into open-time**

In `orchestrators.rs` at ~line 600, after `super::repair::complete_pending_trash_renames(folder, &manifest_body);` add:

```rust
    super::repair::sweep_purged_trash_files(folder, &manifest_body);
```

Also add it at the two `repair/orchestration.rs` sites (~276, ~306) beside `complete_pending_trash_renames`, for parity.

- [ ] **Step 5: Run to verify pass**

Run: `cargo test --release -p secretary-core --test purge sweep`
Expected: PASS. Also `cargo test --release -p secretary-core --test crash_recovery` (existing relocation sweep untouched).

- [ ] **Step 6: Commit**

```bash
git add core/src/vault/repair/sweep.rs core/src/vault/repair/mod.rs core/src/vault/orchestrators.rs core/tests/purge.rs
git commit -m "feat(core): open-time purge-cleanup sweep, cross-device propagation (#399)"
```

---

## Task 5: core `empty_trash` + `EmptyTrashReport`

**Files:**
- Modify: `core/src/vault/purge.rs`
- Modify: `core/src/vault/mod.rs` (re-export)
- Test: `core/tests/purge.rs`

**Interfaces:**
- Produces:
  - `pub struct EmptyTrashReport { pub purged_count: usize, pub shared_count: usize, pub owner_only_count: usize, pub unknown_count: usize, pub files_removed: usize, pub files_failed: usize }`
  - `pub fn empty_trash(folder, open: &mut OpenVault, device_uuid, now_ms, rng) -> Result<EmptyTrashReport, VaultError>`
- Consumes: Task 3's `classify_trash_target`, `remove_trash_files`, `resign_and_write_manifest`, `tick_clock`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn empty_trash_purges_all_unpurged_in_single_resign() {
    // Vault with: 1 owner-only trashed, 1 shared trashed, 1 already-purged.
    let (folder, mut open, device, mut rng) = setup_vault_with_mixed_trash();
    let report = secretary_core::vault::empty_trash(&folder, &mut open, device, 7000, &mut rng).unwrap();
    assert_eq!(report.purged_count, 2, "already-purged is skipped");
    assert_eq!(report.owner_only_count, 1);
    assert_eq!(report.shared_count, 1);
    // all trash entries now purged
    assert!(open.manifest.trash.iter().all(|t| t.purged_at_ms.is_some()));
    // single new signed manifest (all share one now_ms)
    let purged_stamps: std::collections::HashSet<_> =
        open.manifest.trash.iter().filter_map(|t| t.purged_at_ms).collect();
    // the two freshly-purged share now_ms=7000; the pre-purged keeps its own
    assert!(purged_stamps.contains(&7000));
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-core --test purge empty_trash`
Expected: FAIL — `empty_trash` missing.

- [ ] **Step 3: Implement**

```rust
#[derive(Debug, Clone, Default)]
pub struct EmptyTrashReport {
    pub purged_count: usize,
    pub shared_count: usize,
    pub owner_only_count: usize,
    pub unknown_count: usize,
    pub files_removed: usize,
    pub files_failed: usize,
}

pub fn empty_trash(
    folder: &Path,
    open: &mut OpenVault,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<EmptyTrashReport, VaultError> {
    // Collect indices of not-yet-purged entries whose uuid is not live.
    let targets: Vec<usize> = open.manifest.trash.iter().enumerate()
        .filter(|(_, t)| t.purged_at_ms.is_none()
            && !open.manifest.blocks.iter().any(|b| b.block_uuid == t.block_uuid))
        .map(|(i, _)| i)
        .collect();
    if targets.is_empty() {
        return Ok(EmptyTrashReport::default());
    }

    let mut report = EmptyTrashReport::default();
    // Classify each BEFORE the write (files still present).
    let mut per_uuid: Vec<[u8; 16]> = Vec::with_capacity(targets.len());
    for &i in &targets {
        let uuid = open.manifest.trash[i].block_uuid;
        let ts = open.manifest.trash[i].tombstoned_at_ms;
        match classify_trash_target(folder, &uuid, ts, &open.owner_card) {
            Some((true, _)) => report.shared_count += 1,
            Some((false, _)) => report.owner_only_count += 1,
            None => report.unknown_count += 1,
        }
        per_uuid.push(uuid);
    }

    // Single commit point: mark all purged + one clock tick + one write.
    let mut staged = open.manifest.clone();
    for &i in &targets {
        staged.trash[i].purged_at_ms = Some(now_ms);
    }
    tick_clock(&mut staged.vector_clock, &device_uuid)?;
    let new_manifest_file = resign_and_write_manifest(
        folder, &staged, &open.identity, &open.identity_block_key,
        &open.manifest_file.header, now_ms, open.manifest_file.author_fingerprint, rng,
        "empty_trash: failed to write manifest.cbor.enc",
    )?;
    open.manifest = staged;
    open.manifest_file = new_manifest_file;
    report.purged_count = targets.len();

    // Best-effort remove all files (per-file failure never aborts).
    for uuid in &per_uuid {
        report.files_removed += remove_trash_files(folder, uuid);
    }
    Ok(report)
}
```

(`files_failed` is incremented inside a variant of `remove_trash_files` that returns `(removed, failed)`; either extend that helper to return both counts and update Task 3's call site, or track failures here. Pick one and keep it DRY — extending `remove_trash_files` to return `(usize, usize)` is cleaner; update `purge_block` accordingly.)

Re-export `empty_trash`, `EmptyTrashReport` in `mod.rs`.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --release -p secretary-core --test purge`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add core/src/vault/purge.rs core/src/vault/mod.rs core/tests/purge.rs
git commit -m "feat(core): empty_trash single-resign batch purge (#399)"
```

---

## Task 6: `docs/vault-format.md` §7.2 + manifest schema

**Files:**
- Modify: `docs/vault-format.md` (§7 area ~lines 452–470; manifest schema `"trash"` block ~lines 222–229)

- [ ] **Step 1: Add `purged_at_ms` to the manifest schema**

In the `"trash"` entry schema (~line 227), after the `"fingerprint"` line, add:

```
      "purged_at_ms":   <uint, optional>           ; unix-millis the block was purged
                                                    ; (local ciphertext permanently removed).
                                                    ; Terminal + monotonic. Absent = still restorable.
                                                    ; Additive optional key (§6.3.2 forward-compat).
```

- [ ] **Step 2: Add §7.2 "Purging a block"**

After §7.1, add a normative §7.2 covering: purge = mark `TrashEntry.purged_at_ms` (manifest-first commit) + best-effort delete every `trash/<uuid>.cbor.enc.*`; one erasure mechanism (no overwrite — state the SSD/CoW honesty caveat and that unlinking destroys the only local copy of the wrapped BCK); owner-only vs shared is reporting-only; restore of a purged entry fails with a purged error before any file scan; the open-time purge-cleanup sweep deletes local files for purged entries gated on "not live in `manifest.blocks`"; `empty_trash` = single-resign batch. Note the deferred conflict-copy merge-monotonicity as a documented limitation.

- [ ] **Step 3: Verify doc builds clean**

Run: `RUSTDOCFLAGS="-D warnings" cargo doc --no-deps -p secretary-core`
Expected: clean (no intra-doc link breakage from any `[…]` you add).

- [ ] **Step 4: Commit**

```bash
git add docs/vault-format.md
git commit -m "docs(spec): vault-format §7.2 purge + purged_at_ms schema (#399)"
```

---

## Task 7: `conformance.py` purge scenario

**Files:**
- Modify: `core/tests/python/conformance.py`

- [ ] **Step 1: Add a purge scenario**

Add a clean-room check that, from `docs/` alone: (a) a manifest `TrashEntry` with `purged_at_ms` present decodes and re-encodes consistently (marker round-trip), and (b) the documented rule "restore refuses a purged entry" is expressible — i.e. given a manifest trash entry carrying `purged_at_ms`, the verifier classifies it as non-restorable. Mirror how existing scenarios read `core/tests/data/*` fixtures. If a golden fixture is needed, generate it via the ignored KAT generator (see CLAUDE.md `generate_conformance_kat`) and human-review the diff (scoped to the new purge fixture only).

- [ ] **Step 2: Run conformance**

Run: `uv run core/tests/python/conformance.py`
Expected: PASS including the new purge scenario.

- [ ] **Step 3: Full differential replay**

Run: `cargo test --release --workspace --features differential-replay`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add core/tests/python/conformance.py core/tests/data
git commit -m "test(core): conformance purge scenario proves docs sufficiency (#399)"
```

---

## Task 8: `FfiVaultError::BlockPurged` threaded through all bindings

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (variant + `From<VaultError>` mapping ~line 486)
- Modify: every exhaustive match on `FfiVaultError` / `VaultError` in `secretary-ffi-{bridge,py,uniffi}` (compiler will list them)
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/…ConformanceErrors.swift`, `…/kotlin/…ConformanceErrors.kt`

**Interfaces:**
- Produces: `FfiVaultError::BlockPurged { block_uuid: [u8;16] }` (or the binding's UUID projection type — match `BlockNotInTrash`'s shape exactly).

- [ ] **Step 1: Write the failing bridge mapping test**

In the bridge error tests, assert `FfiVaultError::from(VaultError::BlockPurged { block_uuid: [7;16] })` matches `FfiVaultError::BlockPurged { .. }` with the same uuid (mirror the `BlockNotInTrash` mapping test).

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-ffi-bridge block_purged`
Expected: FAIL — variant missing.

- [ ] **Step 3: Add the variant + mapping**

Add `BlockPurged` to `FfiVaultError` (copy `BlockNotInTrash`'s attributes/uniffi derives exactly, ~line 265) and its arm in `From<VaultError>` (~line 486):

```rust
    VE::BlockPurged { block_uuid } => FfiVaultError::BlockPurged {
        block_uuid: block_uuid.to_vec(), // match BlockNotInTrash's uuid projection
    },
```

Thread through every other exhaustive match the compiler flags. Add `BlockPurged` to `ConformanceErrors.swift` and `ConformanceErrors.kt` (grep for `blockNotInTrash` / `BlockNotInTrash` in those files and mirror every site — cargo/clippy cannot see these).

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --release -p secretary-ffi-bridge block_purged` then `cargo build --release -p secretary-ffi-py -p secretary-ffi-uniffi`
Expected: PASS + clean build (all matches exhaustive).

- [ ] **Step 5: Commit**

```bash
git add ffi/
git commit -m "feat(ffi): FfiVaultError::BlockPurged threaded through all bindings (#399)"
```

---

## Task 9: bridge `purge_block` + `PurgeReport`

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/purge/mod.rs`, `ffi/secretary-ffi-bridge/src/purge/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (register + re-export)
- Modify: pyo3 + uniffi projection files (mirror how `trash_block` is exposed)

**Interfaces:**
- Produces:
  - `pub struct PurgeReport { block_uuid: [u8;16], was_shared: Option<bool>, recipient_count: Option<u16>, files_removed: u32 }`
  - `pub fn purge_block(identity, manifest, block_uuid, device_uuid, now_ms) -> Result<PurgeReport, FfiVaultError>`

- [ ] **Step 1: Write the failing bridge test**

Mirror the bridge trash test: build handles, trash a block, then `purge_block`, assert `Ok(report)` with `was_shared == Some(false)`, `files_removed >= 1`, and a follow-up `restore_block` returns `FfiVaultError::BlockPurged`.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-ffi-bridge purge_block`
Expected: FAIL — function missing.

- [ ] **Step 3: Implement (mirror `trash/orchestration.rs`)**

Copy `trash/orchestration.rs`'s snapshot → build `OpenVault` → call core → write-back pattern verbatim, calling `secretary_core::vault::purge_block` and mapping its `PurgeReport` into the bridge `PurgeReport` (with `files_removed as u32`). `OsRng` for the rng arg. Register `pub mod purge;` in `lib.rs` and `pub use purge::{purge_block, PurgeReport};`. Project `PurgeReport` + `purge_block` on pyo3 and uniffi exactly as `TrashedBlock` / `trash_block` are projected (uniffi `Record`/`dictionary`; pyo3 `#[pyclass]`/`#[pyfunction]`) — follow the sibling's derive/attribute set to satisfy [[project_secretary_pyo3_028_fromtopyobject_deprecation]] and [[project_secretary_uniffi_codegen_renames]].

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --release -p secretary-ffi-bridge purge` and `cargo build --release -p secretary-ffi-py -p secretary-ffi-uniffi`
Expected: PASS + clean.

- [ ] **Step 5: Commit**

```bash
git add ffi/
git commit -m "feat(ffi): bridge purge_block + PurgeReport on pyo3 + uniffi (#399)"
```

---

## Task 10: bridge `empty_trash` + `EmptyTrashReport` + `list_trashed_blocks` skips purged

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/purge/orchestration.rs`
- Modify: `ffi/secretary-ffi-bridge/src/trash/list.rs` (skip purged entries)
- Modify: pyo3 + uniffi projections

**Interfaces:**
- Produces: `EmptyTrashReport { purged_count, shared_count, owner_only_count, unknown_count, files_removed, files_failed: u32 }`; `pub fn empty_trash(identity, manifest, device_uuid, now_ms) -> Result<EmptyTrashReport, FfiVaultError>`.

- [ ] **Step 1: Write the failing tests**

(a) `empty_trash` over a mixed trash returns the expected aggregate. (b) **Regression:** `list_trashed_blocks` after purging a block does **not** error and does **not** list the purged block (before the fix it would raise `CorruptVault` on the missing file).

```rust
#[test]
fn list_trashed_skips_purged_entries() {
    // trash two blocks, purge one
    let listed = list_trashed_blocks(&identity, &manifest).unwrap();
    assert_eq!(listed.len(), 1, "purged block is not listed and does not error");
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --release -p secretary-ffi-bridge empty_trash list_trashed_skips_purged`
Expected: FAIL — `empty_trash` missing; list test errors with `CorruptVault`.

- [ ] **Step 3: Implement**

`empty_trash` mirrors Task 9's orchestration, calling `secretary_core::vault::empty_trash`. In `list_trashed_blocks` (`trash/list.rs`), skip entries where `entry.purged_at_ms.is_some()` **before** the "no file ⇒ integrity error" check — a purged entry legitimately has no file:

```rust
    for entry in &manifest_body.trash {
        if entry.purged_at_ms.is_some() {
            continue; // purged: ciphertext intentionally gone, not an integrity violation
        }
        // …existing per-entry decrypt/project…
    }
```

Project `EmptyTrashReport` + `empty_trash` on pyo3 + uniffi.

- [ ] **Step 4: Run to verify pass**

Run: `cargo test --release -p secretary-ffi-bridge` and `cargo build --release -p secretary-ffi-py -p secretary-ffi-uniffi`
Expected: PASS + clean.

- [ ] **Step 5: Commit**

```bash
git add ffi/
git commit -m "feat(ffi): bridge empty_trash + list skips purged entries (#399)"
```

---

## Task 11: uniffi Swift/Kotlin + pyo3 conformance for purge

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/…`, `ffi/secretary-ffi-uniffi/tests/kotlin/…` (conformance runners)
- Modify: pyo3 pytest suite

- [ ] **Step 1: Add the conformance assertions**

Extend the Swift + Kotlin conformance runners to replay: trash → `purge_block` (assert report shape) → `restore_block` yields `BlockPurged`; and `empty_trash` over a seeded trash → aggregate matches the Rust bridge replay. Add the equivalent pyo3 pytest (mind the maturin/uv editable cache: rebuild + nuke cache if the `.so` looks stale, per [[project_secretary_maturin_uv_cache]]).

- [ ] **Step 2: Run the conformance harnesses**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: PASS (both), including the `BlockPurged` error surface threaded in Task 8.

- [ ] **Step 3: Build the mobile `:kit` consumers**

Per [[project_secretary_conformance_scripts_dont_compile_kit]] a uniffi return-shape change can pass the conformance runner yet break the Gradle `:kit`/`:app` modules. Build them:
```bash
cd android && ./gradlew :kit:assemble :app:assembleDebug
```
Expected: clean (the new `PurgeReport`/`EmptyTrashReport`/`BlockPurged` types compile in the Kotlin consumers).

- [ ] **Step 4: pyo3 pytest**

Run the purge pytest (path per the existing FFI-py test layout).
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add ffi/ android/
git commit -m "test(ffi): swift+kotlin+pyo3 conformance for purge/empty_trash (#399)"
```

---

## Final verification (before PR)

```bash
cd /Users/hherb/src/secretary
cargo test --release --workspace                                  # full suite green
cargo test --release --workspace --features differential-replay   # cross-language replay green
cargo clippy --release --workspace --tests -- -D warnings         # clean
cargo fmt --all --check                                           # clean
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --workspace        # clean
uv run core/tests/python/conformance.py                           # purge scenario passes
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
bash ffi/scripts/check-lean-binding.sh --self-test && bash ffi/scripts/check-lean-binding.sh
```

Open the follow-up issue for **conflict-copy trash-list reconciliation (purged-marker merge monotonicity)** — a pre-existing durability-only gap in `sync/commit/write.rs` (the merged manifest is `open.manifest.clone()`, so peer trash entries are never unioned). Close #399 on merge with a comment recording the deliberate non-actions: no overwrite (decision 3), retention auto-purge deferred, merge monotonicity deferred to the new issue.

## Self-Review Notes (author)

- **Spec coverage:** field (T1), BlockPurged+restore (T2), purge_block+classify+report (T3), sweep+propagation (T4), empty_trash (T5), vault-format §7.2 (T6), conformance (T7), FFI error (T8), FFI purge (T9), FFI empty_trash+list-skip (T10), cross-language conformance (T11). Deferred items (overwrite, retention, merge monotonicity) are explicitly out of scope.
- **Type consistency:** `PurgeReport`/`EmptyTrashReport` field names identical in core and bridge (bridge uses `u32` for counts vs core `usize` — an intentional FFI projection, noted at each site). `classify_recipients` signature stable across T3/T5. `BlockPurged { block_uuid }` shape mirrors `BlockNotInTrash` everywhere.
- **Placeholder scan:** test-body `/* trashed uuid */` markers are the one value each harness must fill from its own setup helper — the surrounding assertions are concrete. Every new function has full code.
