# Block CRUD tier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add three first-class uniffi write ops — `create_block`, `rename_block`, `move_record` — over the existing bridge `BlockPlaintext` round-trip, with full forward-compat `unknown` preservation and correct cross-block CRDT behaviour.

**Architecture:** FFI-surface only. New bridge primitives (`edit/rename.rs`, `edit/move_record.rs`) compose the existing `core::vault::save_block` via the shared `save_plaintext` tail; `create_block` already exists in the bridge and is only newly *exposed*. uniffi wrappers in a new `namespace/block_crud.rs` length-validate UUIDs and map errors. `core/` and the on-disk format / crypto spec are untouched.

**Tech Stack:** Rust (stable, `--release`), uniffi 0.31 (UDL → generated Swift/Kotlin), Swift + Kotlin host smoke runners, cargo + clippy.

## Global Constraints

- `#![forbid(unsafe_code)]` workspace-wide — no `unsafe`.
- `cargo clippy --release --workspace --tests -- -D warnings` must stay clean.
- **No `core/` change**; guardrail `git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format'` must be empty.
- **No new `FfiVaultError` / `VaultError` variant** — reuse `BlockNotFound` / `RecordNotFound` / `InvalidArgument` / `CorruptVault`. (A new variant is a workspace-wide exhaustive-match + Swift/Kotlin `ConformanceErrors` obligation.)
- Caller-mints all UUIDs; every write op returns `void` / `Result<(), VaultError>`.
- Preserve forward-compat `unknown` at block/record/field level on every round-trip (the `edit_record` keystone principle).
- Files stay under ~500 lines; new primitives go in their own files (`edit/mod.rs` is already ~585 lines).
- All cargo commands run from the worktree root `/Users/hherb/src/secretary/.worktrees/block-record-crud` (verify with `pwd && git branch --show-current` first).
- Tests must generate any crypto values at runtime (none needed here — these ops carry no key material; UUIDs are fixed test constants, which is fine).

---

### Task 1: Bridge `rename_block` primitive

Changes only `block_name`; preserves all records + every `unknown`. Decrypt → set name → `save_plaintext`.

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/edit/rename.rs`
- Create: `ffi/secretary-ffi-bridge/src/edit/test_support.rs` (shared `#[cfg(test)]` fixture helper for the two new files)
- Modify: `ffi/secretary-ffi-bridge/src/edit/mod.rs` (declare + re-export the new submodule and test_support)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs:135-137` (re-export `rename_block`)

**Interfaces:**
- Consumes: `super::save_plaintext` (private fn in `edit/mod.rs`), `crate::record::orchestration::decrypt_block_plaintext`, `crate::error::FfiVaultError`, `crate::identity::UnlockedIdentity`, `crate::vault::OpenVaultManifest`.
- Produces: `pub fn rename_block(identity: &UnlockedIdentity, manifest: &OpenVaultManifest, block_uuid: [u8; 16], new_block_name: String, device_uuid: [u8; 16], now_ms: u64) -> Result<(), FfiVaultError>`.
- Produces (test_support): `#[cfg(test)] pub(super) fn open_writable_golden_001() -> (tempfile::TempDir, crate::OpenVaultOutput)`.

- [ ] **Step 1: Add the shared test-support helper**

Create `ffi/secretary-ffi-bridge/src/edit/test_support.rs`:

```rust
//! Shared `#[cfg(test)]` fixtures for the block-CRUD edit primitives
//! (`rename.rs`, `move_record.rs`). Mirrors the per-file helper used by
//! `mod.rs` / `tombstone.rs`; factored out here because two new files need it.
#![cfg(test)]

use std::path::{Path, PathBuf};

use crate::{open_vault_with_password, OpenVaultOutput};

pub(super) const VAULT_001_PASSWORD: &[u8] = b"correct horse battery staple";

fn fixture_folder(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../core/tests/data")
        .join(name)
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir_recursive(&from, &to);
        } else {
            std::fs::copy(&from, &to).unwrap();
        }
    }
}

/// Open a writable copy of golden_vault_001 in a fresh tempdir. The tempdir
/// is returned so the caller keeps it alive for the test.
pub(super) fn open_writable_golden_001() -> (tempfile::TempDir, OpenVaultOutput) {
    let src = fixture_folder("golden_vault_001");
    let tmp = tempfile::tempdir().expect("tempdir");
    copy_dir_recursive(&src, tmp.path());
    let out = open_vault_with_password(tmp.path(), VAULT_001_PASSWORD)
        .expect("open writable copy of golden_vault_001");
    (tmp, out)
}
```

- [ ] **Step 2: Wire the new submodules into `edit/mod.rs`**

In `ffi/secretary-ffi-bridge/src/edit/mod.rs`, after the existing `mod tombstone;` / `pub use tombstone::{...}` block (around line 17-18), add:

```rust
#[cfg(test)]
mod test_support;

mod rename;
pub use rename::rename_block;

mod move_record;
pub use move_record::move_record;
```

(`move_record` lands in Task 2; declaring it now keeps one mod block. If running Task 1 in isolation, temporarily omit the `move_record` lines and add them in Task 2.)

- [ ] **Step 3: Write the failing test for `rename_block`**

Create `ffi/secretary-ffi-bridge/src/edit/rename.rs` with ONLY the test module first (so it fails to compile / fails on the missing fn):

```rust
//! Block-rename primitive: change only `block_name`, preserving every
//! record and all forward-compat `unknown` maps (block/record/field).
//! Decrypt → set name → re-encrypt through the shared `save_plaintext`
//! tail (which ticks the block clock, bumps `last_mod_ms`, re-signs the
//! manifest, and updates the manifest `BlockEntry.block_name` as a side
//! effect).

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::vault::OpenVaultManifest;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use secretary_core::crypto::secret::SecretString;
    use secretary_core::vault::block::BlockPlaintext;
    use secretary_core::vault::record::{Record, RecordField, RecordFieldValue, UnknownValue};

    use super::super::test_support::open_writable_golden_001;
    use super::super::{BLOCK_VERSION_V1, SCHEMA_VERSION_V1};
    use super::rename_block;
    use crate::record::orchestration::decrypt_block_plaintext;

    const DEVICE_UUID: [u8; 16] = [0x07; 16];

    /// Rename must change ONLY block_name; records + block/record/field
    /// `unknown` survive byte-faithfully and `last_mod_ms` of the block
    /// is bumped (proven indirectly: the record's stored data is intact).
    #[test]
    fn rename_block_changes_only_name_preserving_records_and_unknown() {
        let (_tmp, opened) = open_writable_golden_001();
        let block_uuid = [0x61u8; 16];
        let record_uuid = [0x62u8; 16];

        let mk = || UnknownValue::from_canonical_cbor(&[0x01]).expect("canonical cbor unknown");

        let mut block_unknown = BTreeMap::new();
        block_unknown.insert("x_block".to_string(), mk());
        let mut record_unknown = BTreeMap::new();
        record_unknown.insert("x_rec".to_string(), mk());
        let mut field_unknown = BTreeMap::new();
        field_unknown.insert("x_fld".to_string(), mk());

        let mut fields = BTreeMap::new();
        fields.insert(
            "user".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from("alice")),
                last_mod: 1_000,
                device_uuid: DEVICE_UUID,
                unknown: field_unknown,
            },
        );

        let plaintext = BlockPlaintext {
            block_version: BLOCK_VERSION_V1,
            block_uuid,
            block_name: "Before".to_string(),
            schema_version: SCHEMA_VERSION_V1,
            records: vec![Record {
                record_uuid,
                record_type: "login".to_string(),
                fields,
                tags: vec!["work".to_string()],
                created_at_ms: 1_000,
                last_mod_ms: 1_000,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: record_unknown,
            }],
            unknown: block_unknown,
        };
        super::super::save_plaintext(&opened.identity, &opened.manifest, plaintext, DEVICE_UUID, 1_000)
            .expect("seed plaintext");

        rename_block(&opened.identity, &opened.manifest, block_uuid, "After".to_string(), DEVICE_UUID, 2_000)
            .expect("rename_block");

        let after = decrypt_block_plaintext(&opened.identity, &opened.manifest, &block_uuid)
            .expect("decrypt after rename");
        assert_eq!(after.block_name, "After", "block_name updated");
        assert!(after.unknown.contains_key("x_block"), "block-level unknown survives");
        assert_eq!(after.records.len(), 1, "record preserved");
        let rec = &after.records[0];
        assert_eq!(rec.record_uuid, record_uuid);
        assert!(rec.unknown.contains_key("x_rec"), "record-level unknown survives");
        let user = rec.fields.get("user").expect("field preserved");
        assert!(user.unknown.contains_key("x_fld"), "field-level unknown survives");
        match &user.value {
            RecordFieldValue::Text(s) => assert_eq!(*s, SecretString::from("alice")),
            other => panic!("expected Text, got {other:?}"),
        }
    }

    /// Renaming a block whose UUID is absent from the manifest is a
    /// `BlockNotFound`, not a silent insert.
    #[test]
    fn rename_block_absent_uuid_is_block_not_found() {
        let (_tmp, opened) = open_writable_golden_001();
        let err = rename_block(&opened.identity, &opened.manifest, [0xEEu8; 16], "x".to_string(), DEVICE_UUID, 2_000)
            .expect_err("absent block must error");
        assert!(matches!(err, FfiVaultError::BlockNotFound { .. }), "got {err:?}");
    }
}
```

- [ ] **Step 4: Run the test to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge rename_block`
Expected: FAIL — `cannot find function rename_block in this scope` (the fn isn't defined yet).

- [ ] **Step 5: Implement `rename_block`**

In `ffi/secretary-ffi-bridge/src/edit/rename.rs`, add above the `#[cfg(test)] mod tests` block:

```rust
/// Rename a block: replace only `block_name`, preserving every record and
/// all `unknown` maps. Re-encrypts through the shared `save_plaintext`
/// tail; `core::save_block` ticks the block clock + re-signs the manifest,
/// and the manifest `BlockEntry.block_name` updates as a save side effect.
///
/// Empty `new_block_name` is allowed (the spec permits empty block names).
///
/// # Errors
///
/// [`FfiVaultError::BlockNotFound`] (block UUID not in the manifest),
/// [`FfiVaultError::CorruptVault`] (decrypt failure / wiped handle), or the
/// save-tail error surface ([`FfiVaultError::FolderInvalid`] /
/// [`FfiVaultError::SaveCryptoFailure`]).
pub fn rename_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    new_block_name: String,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    plaintext.block_name = new_block_name;
    super::save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --release -p secretary-ffi-bridge rename_block`
Expected: PASS — both `rename_block_changes_only_name_preserving_records_and_unknown` and `rename_block_absent_uuid_is_block_not_found`.

- [ ] **Step 7: Re-export `rename_block` from the bridge crate root**

In `ffi/secretary-ffi-bridge/src/lib.rs`, extend the `pub use edit::{...}` list (currently `append_record, create_block, edit_record, resurrect_record, tombstone_record, RecordContent`) to add `rename_block` (alphabetical: after `resurrect_record`, or anywhere in the braces):

```rust
pub use edit::{
    append_record, create_block, edit_record, rename_block, resurrect_record, tombstone_record,
    RecordContent,
    // ... keep any other existing items on the following lines unchanged
};
```

Verify the exact current contents of lines 135-137 first and insert `rename_block` without dropping existing items.

- [ ] **Step 8: Lint + commit**

Run: `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings`
Expected: clean.

```bash
git add ffi/secretary-ffi-bridge/src/edit/rename.rs \
        ffi/secretary-ffi-bridge/src/edit/test_support.rs \
        ffi/secretary-ffi-bridge/src/edit/mod.rs \
        ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(bridge): rename_block primitive (preserve records + unknown)"
```

---

### Task 2: Bridge `move_record` primitive

Copy a live record into the target block under a fresh UUID (preserving values + `unknown`), then tombstone the source. Copy-before-delete ordering; decrypt-target-before-write so a missing target leaves the source untouched.

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/edit/move_record.rs`
- Modify: `ffi/secretary-ffi-bridge/src/edit/mod.rs` (already declared in Task 1 Step 2)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (re-export `move_record`)

**Interfaces:**
- Consumes: `super::save_plaintext`, `super::tombstone::tombstone_record`, `decrypt_block_plaintext`, `secretary_core::vault::record::{Record, RecordField}`.
- Produces: `pub fn move_record(identity: &UnlockedIdentity, manifest: &OpenVaultManifest, source_block_uuid: [u8; 16], target_block_uuid: [u8; 16], source_record_uuid: [u8; 16], new_record_uuid: [u8; 16], device_uuid: [u8; 16], now_ms: u64) -> Result<(), FfiVaultError>`.

- [ ] **Step 1: Write the failing tests for `move_record`**

Create `ffi/secretary-ffi-bridge/src/edit/move_record.rs` with the test module first:

```rust
//! Cross-block record move: copy a live record into the target block under
//! a FRESH `record_uuid` (preserving secret values + every `unknown`), then
//! tombstone the source record. A fresh target UUID keeps each block's CRDT
//! self-contained (the merge layer in `core/src/vault/conflict.rs` is
//! record-level WITHIN a block — no cross-block identity), so the same UUID
//! can never be live in two blocks. Copy-before-delete ordering: the target
//! is decrypted before any write (a missing target leaves the source
//! untouched) and saved before the source tombstone (a crash mid-move yields
//! a recoverable transient duplicate, never data loss).

use secretary_core::vault::record::{Record, RecordField};

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::vault::OpenVaultManifest;

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use secretary_core::crypto::secret::SecretString;
    use secretary_core::vault::block::BlockPlaintext;
    use secretary_core::vault::record::{Record, RecordField, RecordFieldValue, UnknownValue};

    use super::super::test_support::open_writable_golden_001;
    use super::super::{BLOCK_VERSION_V1, SCHEMA_VERSION_V1};
    use super::move_record;
    use crate::error::FfiVaultError;
    use crate::record::orchestration::decrypt_block_plaintext;

    const DEVICE_UUID: [u8; 16] = [0x07; 16];

    /// Seed a block with one live record carrying record-level + field-level
    /// `unknown`. Returns nothing; the block is persisted into `opened`.
    fn seed_source(
        opened: &crate::OpenVaultOutput,
        block_uuid: [u8; 16],
        record_uuid: [u8; 16],
    ) {
        let mk = || UnknownValue::from_canonical_cbor(&[0x01]).expect("canonical cbor unknown");
        let mut record_unknown = BTreeMap::new();
        record_unknown.insert("x_rec".to_string(), mk());
        let mut field_unknown = BTreeMap::new();
        field_unknown.insert("x_fld".to_string(), mk());
        let mut fields = BTreeMap::new();
        fields.insert(
            "user".to_string(),
            RecordField {
                value: RecordFieldValue::Text(SecretString::from("alice")),
                last_mod: 1_000,
                device_uuid: DEVICE_UUID,
                unknown: field_unknown,
            },
        );
        let plaintext = BlockPlaintext {
            block_version: BLOCK_VERSION_V1,
            block_uuid,
            block_name: "Source".to_string(),
            schema_version: SCHEMA_VERSION_V1,
            records: vec![Record {
                record_uuid,
                record_type: "login".to_string(),
                fields,
                tags: vec!["work".to_string()],
                created_at_ms: 1_000,
                last_mod_ms: 1_000,
                tombstone: false,
                tombstoned_at_ms: 0,
                unknown: record_unknown,
            }],
            unknown: BTreeMap::new(),
        };
        super::super::save_plaintext(&opened.identity, &opened.manifest, plaintext, DEVICE_UUID, 1_000)
            .expect("seed source block");
    }

    fn seed_empty_target(opened: &crate::OpenVaultOutput, block_uuid: [u8; 16]) {
        super::super::create_block(
            &opened.identity,
            &opened.manifest,
            block_uuid,
            "Target".to_string(),
            DEVICE_UUID,
            1_000,
        )
        .expect("seed empty target block");
    }

    /// Happy path: the target gains a record with the NEW uuid, copied value,
    /// preserved record-level + field-level `unknown`, and fresh
    /// `created_at_ms`; the source record is tombstoned at `now_ms`.
    #[test]
    fn move_record_copies_with_fresh_uuid_and_tombstones_source() {
        let (_tmp, opened) = open_writable_golden_001();
        let source_block = [0x81u8; 16];
        let target_block = [0x82u8; 16];
        let source_record = [0x83u8; 16];
        let new_record = [0x84u8; 16];

        seed_source(&opened, source_block, source_record);
        seed_empty_target(&opened, target_block);

        move_record(
            &opened.identity, &opened.manifest,
            source_block, target_block, source_record, new_record,
            DEVICE_UUID, 5_000,
        )
        .expect("move_record");

        // Target: new record present with copied value + preserved unknowns + fresh clock.
        let target = decrypt_block_plaintext(&opened.identity, &opened.manifest, &target_block)
            .expect("decrypt target");
        assert_eq!(target.records.len(), 1, "target gained exactly one record");
        let moved = &target.records[0];
        assert_eq!(moved.record_uuid, new_record, "target copy uses the fresh uuid");
        assert!(!moved.tombstone, "target copy is live");
        assert_eq!(moved.created_at_ms, 5_000, "target copy created_at is fresh");
        assert_eq!(moved.record_type, "login");
        assert_eq!(moved.tags, vec!["work".to_string()]);
        assert!(moved.unknown.contains_key("x_rec"), "record-level unknown carried to target");
        let user = moved.fields.get("user").expect("field copied");
        assert!(user.unknown.contains_key("x_fld"), "field-level unknown carried to target");
        assert_eq!(user.last_mod, 5_000, "field clock reset to now_ms on copy");
        assert_eq!(user.device_uuid, DEVICE_UUID, "field authoring device is the moving device");
        match &user.value {
            RecordFieldValue::Text(s) => assert_eq!(*s, SecretString::from("alice")),
            other => panic!("expected Text, got {other:?}"),
        }

        // Source: original record tombstoned at now_ms.
        let source = decrypt_block_plaintext(&opened.identity, &opened.manifest, &source_block)
            .expect("decrypt source");
        let orig = source.records.iter().find(|r| r.record_uuid == source_record)
            .expect("source record still present (tombstoned)");
        assert!(orig.tombstone, "source record tombstoned after move");
        assert_eq!(orig.tombstoned_at_ms, 5_000, "death clock set to now_ms");
    }

    /// source == target is rejected (a no-op/nonsense move) with InvalidArgument.
    #[test]
    fn move_record_same_block_is_invalid_argument() {
        let (_tmp, opened) = open_writable_golden_001();
        let block = [0x85u8; 16];
        let rec = [0x86u8; 16];
        seed_source(&opened, block, rec);
        let err = move_record(
            &opened.identity, &opened.manifest, block, block, rec, [0x87u8; 16], DEVICE_UUID, 5_000,
        )
        .expect_err("same-block move must error");
        assert!(matches!(err, FfiVaultError::InvalidArgument { .. }), "got {err:?}");
    }

    /// A missing target block fails as BlockNotFound and leaves the SOURCE
    /// record untouched (copy-before-delete: decrypt target before any write).
    #[test]
    fn move_record_missing_target_leaves_source_untouched() {
        let (_tmp, opened) = open_writable_golden_001();
        let source_block = [0x88u8; 16];
        let source_record = [0x89u8; 16];
        seed_source(&opened, source_block, source_record);

        let err = move_record(
            &opened.identity, &opened.manifest,
            source_block, [0x8Au8; 16] /* absent target */, source_record, [0x8Bu8; 16],
            DEVICE_UUID, 5_000,
        )
        .expect_err("missing target must error");
        assert!(matches!(err, FfiVaultError::BlockNotFound { .. }), "got {err:?}");

        let source = decrypt_block_plaintext(&opened.identity, &opened.manifest, &source_block)
            .expect("decrypt source");
        let orig = source.records.iter().find(|r| r.record_uuid == source_record)
            .expect("source record present");
        assert!(!orig.tombstone, "source record must remain LIVE when the move fails before any write");
    }

    /// Moving an absent / already-tombstoned source record is RecordNotFound.
    #[test]
    fn move_record_absent_source_record_is_record_not_found() {
        let (_tmp, opened) = open_writable_golden_001();
        let source_block = [0x8Cu8; 16];
        let target_block = [0x8Du8; 16];
        seed_source(&opened, source_block, [0x8Eu8; 16]);
        seed_empty_target(&opened, target_block);
        let err = move_record(
            &opened.identity, &opened.manifest,
            source_block, target_block, [0xAAu8; 16] /* absent record */, [0x8Fu8; 16],
            DEVICE_UUID, 5_000,
        )
        .expect_err("absent source record must error");
        assert!(matches!(err, FfiVaultError::RecordNotFound { .. }), "got {err:?}");
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test --release -p secretary-ffi-bridge move_record`
Expected: FAIL — `cannot find function move_record in this scope`.

- [ ] **Step 3: Implement `move_record` + the copy helper**

In `ffi/secretary-ffi-bridge/src/edit/move_record.rs`, add above the `#[cfg(test)] mod tests` block:

```rust
/// Move a live record from `source_block_uuid` to `target_block_uuid`:
/// copy it into the target under `new_record_uuid` (preserving secret values
/// and every forward-compat `unknown`), then tombstone the source record.
///
/// The target copy gets a FRESH uuid + fresh clocks (a new authorship event
/// under a new identity); this keeps each block's CRDT self-contained, since
/// `core`'s merge reconciles records only WITHIN a block. Order of effects is
/// copy-before-delete:
///
/// 1. reject `source == target` (`InvalidArgument`);
/// 2. decrypt source, locate the LIVE record (`RecordNotFound` otherwise);
/// 3. decrypt the target BEFORE any write (`BlockNotFound` otherwise → the
///    source stays live);
/// 4. save the target copy FIRST;
/// 5. tombstone the source SECOND (reusing `tombstone_record`).
///
/// A crash between steps 4 and 5 leaves a recoverable transient duplicate,
/// never data loss.
///
/// # Errors
///
/// [`FfiVaultError::InvalidArgument`] (source == target),
/// [`FfiVaultError::RecordNotFound`] (no live source record),
/// [`FfiVaultError::BlockNotFound`] (source or target block absent),
/// [`FfiVaultError::CorruptVault`], or the save-tail error surface.
#[allow(clippy::too_many_arguments)]
pub fn move_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    source_block_uuid: [u8; 16],
    target_block_uuid: [u8; 16],
    source_record_uuid: [u8; 16],
    new_record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    // 1. A move into the same block is a no-op/nonsense — reject explicitly.
    if source_block_uuid == target_block_uuid {
        return Err(FfiVaultError::InvalidArgument {
            detail: "source_block_uuid and target_block_uuid must differ".into(),
        });
    }

    // 2. Decrypt source; locate the LIVE record and build its target copy.
    let source_plaintext = decrypt_block_plaintext(identity, manifest, &source_block_uuid)?;
    let source_record = source_plaintext
        .records
        .iter()
        .find(|r| r.record_uuid == source_record_uuid && !r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound {
            uuid_hex: hex::encode(source_record_uuid),
        })?;
    let copy = copy_record_into_target(source_record, new_record_uuid, device_uuid, now_ms);

    // 3. Decrypt the target BEFORE any write: a missing target fails here
    //    with the source record still live (copy-before-delete safety).
    let mut target_plaintext = decrypt_block_plaintext(identity, manifest, &target_block_uuid)?;
    target_plaintext.records.push(copy);

    // Release the source secret material before the write tail / re-decrypt.
    drop(source_plaintext);

    // 4. Save the target copy FIRST.
    super::save_plaintext(identity, manifest, target_plaintext, device_uuid, now_ms)?;

    // 5. Tombstone the source SECOND (re-decrypts source from the now-updated
    //    manifest; reuses the death-clock-correct primitive).
    super::tombstone::tombstone_record(
        identity,
        manifest,
        source_block_uuid,
        source_record_uuid,
        device_uuid,
        now_ms,
    )
}

/// Build the target-block copy of a moved record: a fresh `record_uuid`, a
/// fresh `created_at_ms` / `last_mod_ms`, and fresh per-field clocks (the
/// move is a new authorship event), while preserving the secret field
/// values and every forward-compat `unknown` map (record-level and
/// per-field) so a move never silently drops data a future schema added.
fn copy_record_into_target(
    source: &Record,
    new_record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Record {
    let fields = source
        .fields
        .iter()
        .map(|(name, f)| {
            (
                name.clone(),
                RecordField {
                    value: f.value.clone(),
                    last_mod: f.last_mod,          // faithful move: preserve per-field authorship
                    device_uuid: f.device_uuid,    // faithful move: preserve authoring device
                    unknown: f.unknown.clone(),
                },
            )
        })
        .collect();
    Record {
        record_uuid: new_record_uuid,
        record_type: source.record_type.clone(),
        fields,
        tags: source.tags.clone(),
        created_at_ms: source.created_at_ms,       // faithful move: preserve the secret's age
        last_mod_ms: now_ms,
        tombstone: false,
        tombstoned_at_ms: 0,
        unknown: source.unknown.clone(),
    }
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test --release -p secretary-ffi-bridge move_record`
Expected: PASS — all four `move_record_*` tests.

- [ ] **Step 5: Re-export `move_record` from the bridge crate root**

In `ffi/secretary-ffi-bridge/src/lib.rs`, add `move_record` to the `pub use edit::{...}` list (now includes `append_record, create_block, edit_record, move_record, rename_block, resurrect_record, tombstone_record, RecordContent`).

- [ ] **Step 6: Lint + commit**

Run: `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings`
Expected: clean.

```bash
git add ffi/secretary-ffi-bridge/src/edit/move_record.rs \
        ffi/secretary-ffi-bridge/src/edit/mod.rs \
        ffi/secretary-ffi-bridge/src/lib.rs
git commit -m "feat(bridge): move_record primitive (fresh-uuid copy + tombstone source)"
```

---

### Task 3: uniffi surface — UDL + namespace wrappers

Expose `create_block`, `rename_block`, `move_record` on the uniffi namespace with UUID-length validation → `InvalidArgument`.

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/namespace/block_crud.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (declare + re-export)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs:69-73` (add the three fns to the `use crate::namespace::{...}` import that the generated scaffolding resolves)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (three function declarations)

**Interfaces:**
- Consumes: `secretary_ffi_bridge::{create_block, rename_block, move_record}`, `super::uuid_from_vec`, `crate::errors::VaultError`, `crate::wrappers::identity::UnlockedIdentity`, `crate::wrappers::vault::OpenVaultManifest`.
- Produces (Rust, matched by UDL): `create_block`, `rename_block`, `move_record` namespace fns returning `Result<(), VaultError>` and taking `Arc<UnlockedIdentity>` / `Arc<OpenVaultManifest>` + `Vec<u8>` uuids.

- [ ] **Step 1: Add the UDL declarations**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside the `namespace secretary { ... }` block, after the `resurrect_record(...)` declaration (line 199) and before the `add_device_slot` block (line 201), add:

```idl
    /// Create a brand-new empty block. (block-CRUD slice)
    /// `block_uuid` / `device_uuid` must each be 16 bytes (otherwise
    /// [`VaultError::InvalidArgument`]). Caller mints `block_uuid` (CSPRNG);
    /// a same-uuid call updates the existing block in place (insert-or-update
    /// by `block_uuid`, as for `save_block`).
    [Throws=VaultError]
    void create_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        string block_name,
        bytes device_uuid,
        u64 now_ms
    );

    /// Rename a block: change ONLY `block_name`, preserving every record and
    /// all `unknown`. (block-CRUD slice) `BlockNotFound` if the UUID is
    /// absent; same uuid-length contract as `create_block`. Empty name allowed.
    [Throws=VaultError]
    void rename_block(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        string new_block_name,
        bytes device_uuid,
        u64 now_ms
    );

    /// Move a live record between blocks: copy it into `target_block_uuid`
    /// under the caller-minted `new_record_uuid` (preserving values + every
    /// `unknown`), then tombstone the source record. (block-CRUD slice)
    /// The four uuids must each be 16 bytes (otherwise
    /// [`VaultError::InvalidArgument`]); `source_block_uuid` must differ from
    /// `target_block_uuid` (else `InvalidArgument`). `BlockNotFound` if either
    /// block is absent; `RecordNotFound` if no live source record. Copy is
    /// committed before the source tombstone (copy-before-delete).
    [Throws=VaultError]
    void move_record(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes source_block_uuid,
        bytes target_block_uuid,
        bytes source_record_uuid,
        bytes new_record_uuid,
        bytes device_uuid,
        u64 now_ms
    );
```

- [ ] **Step 2: Write the namespace wrappers**

Create `ffi/secretary-ffi-uniffi/src/namespace/block_crud.rs`:

```rust
//! uniffi namespace projection of the bridge's block-CRUD primitives.
//!
//! Three thin wrappers over `secretary_ffi_bridge::{create_block,
//! rename_block, move_record}`. Each length-validates its uuid arguments
//! (16 bytes each → otherwise [`VaultError::InvalidArgument`], mirroring
//! `save_block` / record-edit) and maps `FfiVaultError` via the existing
//! `From` impl on [`VaultError`]. All CRDT / unknown-preservation semantics
//! live in the bridge primitives; this layer adds only input validation.

use std::sync::Arc;

use super::uuid_from_vec;
use crate::errors::VaultError;
use crate::wrappers::identity::UnlockedIdentity;
use crate::wrappers::vault::OpenVaultManifest;

/// Create a brand-new empty block. (block-CRUD slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::CorruptVault`] — wiped handle.
/// - save-tail surface ([`VaultError::FolderInvalid`] / [`VaultError::SaveCryptoFailure`]).
pub fn create_block(
    identity: Arc<UnlockedIdentity>,
    manifest: Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    block_name: String,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::create_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        block_name,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Rename a block (change only `block_name`). (block-CRUD slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::BlockNotFound`] — `block_uuid` not in the manifest.
/// - [`VaultError::CorruptVault`] / save-tail surface.
pub fn rename_block(
    identity: Arc<UnlockedIdentity>,
    manifest: Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    new_block_name: String,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::rename_block(
        &identity.0,
        &manifest.0,
        block_uuid,
        new_block_name,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Move a live record between blocks (fresh-uuid copy + tombstone source).
/// (block-CRUD slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid OR source == target block.
/// - [`VaultError::BlockNotFound`] — source or target block absent.
/// - [`VaultError::RecordNotFound`] — no live source record.
/// - [`VaultError::CorruptVault`] / save-tail surface.
#[allow(clippy::too_many_arguments)]
pub fn move_record(
    identity: Arc<UnlockedIdentity>,
    manifest: Arc<OpenVaultManifest>,
    source_block_uuid: Vec<u8>,
    target_block_uuid: Vec<u8>,
    source_record_uuid: Vec<u8>,
    new_record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let source_block_uuid = uuid_from_vec(&source_block_uuid, "source_block_uuid")?;
    let target_block_uuid = uuid_from_vec(&target_block_uuid, "target_block_uuid")?;
    let source_record_uuid = uuid_from_vec(&source_record_uuid, "source_record_uuid")?;
    let new_record_uuid = uuid_from_vec(&new_record_uuid, "new_record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::move_record(
        &identity.0,
        &manifest.0,
        source_block_uuid,
        target_block_uuid,
        source_record_uuid,
        new_record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}
```

- [ ] **Step 3: Declare + re-export the wrappers in `namespace/mod.rs`**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, after the `mod record_edit; pub use record_edit::{...}` block (line 14-15), add:

```rust
mod block_crud;
pub use block_crud::{create_block, move_record, rename_block};
```

- [ ] **Step 4: Add the fns to the scaffolding import in `lib.rs`**

In `ffi/secretary-ffi-uniffi/src/lib.rs`, the `use crate::namespace::{...}` block (lines ~69-73) brings every namespace fn into scope so `uniffi::include_scaffolding!` can resolve the UDL declarations. Add `block_crud`'s three fns: insert `create_block`, `move_record`, `rename_block` into that import list (keep the existing items). After editing, the list contains (among others) `append_record, create_block, create_vault, ..., move_record, ..., rename_block, ...`.

- [ ] **Step 5: Build to verify the UDL ↔ Rust scaffolding agree**

Run: `cargo build --release -p secretary-ffi-uniffi`
Expected: builds clean. A mismatch (missing fn, wrong arity/type) fails here with a scaffolding type error naming the offending fn.

- [ ] **Step 6: Run the uniffi crate tests + lint**

Run: `cargo test --release -p secretary-ffi-uniffi`
Run: `cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings`
Expected: PASS / clean.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/namespace/block_crud.rs \
        ffi/secretary-ffi-uniffi/src/namespace/mod.rs \
        ffi/secretary-ffi-uniffi/src/lib.rs \
        ffi/secretary-ffi-uniffi/src/secretary.udl
git commit -m "feat(uniffi): expose create_block / rename_block / move_record"
```

---

### Task 4: Swift + Kotlin smoke harness (create → move → read-back)

Exercise the three ops through the REAL generated bindings on both languages.

**Files:**
- Create: `ffi/secretary-ffi-uniffi/tests/swift/SmokeBlockCrud.swift`
- Create: `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeBlockCrud.kt`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift` (register `runBlockCrudAsserts`)
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` (register `runBlockCrudAsserts`)

**Interfaces:**
- Consumes: the generated `createBlock` / `renameBlock` / `moveRecord` / `appendRecord` / `readBlock` wrappers, `SmokeEnv` + `freshWritableVault` (from `SmokeHelpers`), the `assert*` helpers used by sibling smoke files.
- Produces: `fun runBlockCrudAsserts(env: SmokeEnv)` (Kotlin) / `func runBlockCrudAsserts(env: SmokeEnv)` (Swift).

- [ ] **Step 1: Write the Kotlin smoke assertions**

Create `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeBlockCrud.kt`. Mirror `SmokeRecordEdit.kt`'s structure (per-assertion `freshWritableVault`, `.use { }` handle scoping, the shared `assert*`/`failures` helpers from `SmokeHelpers.kt`):

```kotlin
// Block-CRUD slice assertions for the Kotlin smoke runner.
//
// Kotlin mirror of tests/swift/SmokeBlockCrud.swift. create_block /
// rename_block / move_record mutate the on-disk vault, so each assertion
// seeds into a fresh per-test temp copy of golden_vault_001 via
// freshWritableVault (the read-only fixture is never touched).

import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordContent
import uniffi.secretary.VaultException
import uniffi.secretary.appendRecord
import uniffi.secretary.createBlock
import uniffi.secretary.moveRecord
import uniffi.secretary.readBlock
import uniffi.secretary.renameBlock

private val CRUD_DEVICE = ByteArray(16) { 0x07 }
private fun uuid(b: Int) = ByteArray(16) { b.toByte() }

fun runBlockCrudAsserts(env: SmokeEnv) {
    // create_block → read-back: empty block with the given name.
    run {
        val (out, t) = freshWritableVault(env)
        try {
            out.identity.use { id -> out.manifest.use { mf ->
                val block = uuid(0xC1)
                createBlock(id, mf, block, "Imported", CRUD_DEVICE, 1_000UL)
                readBlock(id, mf, block, false).use { rb ->
                    assertEq("create_block name", "Imported", rb.blockName())
                    assertEq("create_block empty", 0UL, rb.recordCount())
                }
            } }
        } finally { t?.let { java.nio.file.Files.walk(it).sorted(Comparator.reverseOrder()).forEach { p -> p.toFile().delete() } } }
    }

    // rename_block → read-back: name changes, record survives.
    run {
        val (out, t) = freshWritableVault(env)
        try {
            out.identity.use { id -> out.manifest.use { mf ->
                val block = uuid(0xC2)
                createBlock(id, mf, block, "Before", CRUD_DEVICE, 1_000UL)
                appendRecord(id, mf, block, uuid(0xC3),
                    RecordContent("login", listOf("work"), listOf(FieldInput("user", FieldInputValue.Text("alice")))),
                    CRUD_DEVICE, 2_000UL)
                renameBlock(id, mf, block, "After", CRUD_DEVICE, 3_000UL)
                readBlock(id, mf, block, false).use { rb ->
                    assertEq("rename_block name", "After", rb.blockName())
                    assertEq("rename_block record survives", 1UL, rb.recordCount())
                }
            } }
        } finally { t?.let { java.nio.file.Files.walk(it).sorted(Comparator.reverseOrder()).forEach { p -> p.toFile().delete() } } }
    }

    // move_record → read-back: target gains the record (new uuid), source loses it.
    run {
        val (out, t) = freshWritableVault(env)
        try {
            out.identity.use { id -> out.manifest.use { mf ->
                val src = uuid(0xC4); val dst = uuid(0xC5)
                val srcRec = uuid(0xC6); val newRec = uuid(0xC7)
                createBlock(id, mf, src, "Source", CRUD_DEVICE, 1_000UL)
                createBlock(id, mf, dst, "Target", CRUD_DEVICE, 1_000UL)
                appendRecord(id, mf, src, srcRec,
                    RecordContent("login", listOf(), listOf(FieldInput("user", FieldInputValue.Text("alice")))),
                    CRUD_DEVICE, 2_000UL)
                moveRecord(id, mf, src, dst, srcRec, newRec, CRUD_DEVICE, 5_000UL)
                readBlock(id, mf, dst, false).use { rb ->
                    assertEq("move target record count", 1UL, rb.recordCount())
                    assertEq("move target record uuid", newRec.toList(), rb.recordAt(0UL)!!.recordUuid().toList())
                }
                readBlock(id, mf, src, false).use { rb ->
                    assertEq("move source live count", 0UL, rb.recordCount())
                }
            } }
        } finally { t?.let { java.nio.file.Files.walk(it).sorted(Comparator.reverseOrder()).forEach { p -> p.toFile().delete() } } }
    }

    // move_record same block → InvalidArgument.
    run {
        val (out, t) = freshWritableVault(env)
        try {
            out.identity.use { id -> out.manifest.use { mf ->
                val block = uuid(0xC8); val rec = uuid(0xC9)
                createBlock(id, mf, block, "B", CRUD_DEVICE, 1_000UL)
                appendRecord(id, mf, block, rec,
                    RecordContent("login", listOf(), listOf(FieldInput("user", FieldInputValue.Text("x")))),
                    CRUD_DEVICE, 2_000UL)
                try {
                    moveRecord(id, mf, block, block, rec, uuid(0xCA), CRUD_DEVICE, 5_000UL)
                    fail("move_record same block should throw InvalidArgument")
                } catch (e: VaultException.InvalidArgument) { pass("move_record same block → InvalidArgument") }
            } }
        } finally { t?.let { java.nio.file.Files.walk(it).sorted(Comparator.reverseOrder()).forEach { p -> p.toFile().delete() } } }
    }
}
```

NOTE: confirm the exact helper names by reading `tests/kotlin/SmokeHelpers.kt` and an existing sibling (`SmokeRecordEdit.kt`) before writing — use the SAME assertion helpers (`assertEq` / `pass` / `fail` or whatever the file actually exposes) and the SAME `freshWritableVault` return-shape and tempdir-cleanup idiom. Match them exactly rather than inventing new helpers.

- [ ] **Step 2: Write the Swift smoke assertions**

Create `ffi/secretary-ffi-uniffi/tests/swift/SmokeBlockCrud.swift` mirroring the Kotlin file exactly (same UUIDs, same four assertions), using the Swift smoke helpers from `SmokeHelpers.swift` and the `createBlock` / `renameBlock` / `moveRecord` generated Swift wrappers. Read `tests/swift/SmokeRecordEdit.swift` first and match its idioms (e.g. `freshWritableVault(env:)`, `defer` cleanup, the Swift `assert*` helpers, `do/catch VaultError.InvalidArgument`).

- [ ] **Step 3: Register the new group in both runners**

In `tests/kotlin/Main.kt`, add `runBlockCrudAsserts(env)` after `runRecordEditAsserts(env)`.
In `tests/swift/main.swift`, add `runBlockCrudAsserts(env: env)` after `runRecordEditAsserts(env: env)`.

- [ ] **Step 4: Run both smoke runners**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh`
Expected: `OK: secretary uniffi Swift smoke runner — all assertions passed.`
Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`
Expected: `OK: secretary uniffi Kotlin smoke runner — all assertions passed.`

(If a generated-wrapper name differs — e.g. `moveRecord` vs `move_record` — fix the call site to match the uniffi-generated camelCase and re-run. Kotlin/Swift uniffi codegen camelCases UDL snake_case fns.)

- [ ] **Step 5: Run the conformance runners (no KAT change expected)**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh`
Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh`
Expected: both pass with their existing assertion counts (these ops are not in `conformance_kat.json`; the runners must still build + pass against the regenerated bindings).

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/SmokeBlockCrud.swift \
        ffi/secretary-ffi-uniffi/tests/kotlin/SmokeBlockCrud.kt \
        ffi/secretary-ffi-uniffi/tests/swift/main.swift \
        ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt
git commit -m "test(uniffi): Swift+Kotlin smoke for create/rename/move block CRUD"
```

---

### Task 5: Docs + full gauntlet + handoff

**Files:**
- Modify: `ROADMAP.md` (Block CRUD tier row)
- Modify: `README.md` (only if a user-facing surface note is warranted — likely no change)
- Create: `docs/handoffs/2026-06-19-block-record-crud-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget symlink)

- [ ] **Step 1: Run the full acceptance gauntlet**

Run, from the worktree root:

```bash
cargo test --release -p secretary-ffi-bridge -p secretary-ffi-uniffi
cargo clippy --release --workspace --tests -- -D warnings
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
( cd android && ./gradlew :kit:test )
bash ios/scripts/run-ios-tests.sh
# Guardrail (core/spec untouched):
git diff main...HEAD --name-only | grep -E 'core/|crypto-design|vault-format'   # must print nothing
```

Expected: all green; the guardrail grep prints nothing.

- [ ] **Step 2: Update ROADMAP.md**

Add a row under the FFI/write-surface section recording the Block CRUD tier (create/rename block + move record between blocks, uniffi surface, host-tested). Match the existing ROADMAP row style (read it first; keep it a single dot-point line per the brief-docs convention).

- [ ] **Step 3: README check**

Read `README.md`'s status section. The block-CRUD ops are an FFI-surface addition; only add a line if the README enumerates the write surface (it likely does not — keep it unchanged if so, per the brief-README convention). Make the call explicitly and note it in the handoff.

- [ ] **Step 4: Write the handoff + retarget the NEXT_SESSION symlink**

Author `docs/handoffs/2026-06-19-block-record-crud-shipped.md` capturing: (1) what shipped + commit SHAs, (2) what's next with acceptance criteria, (3) open decisions/risks, (4) exact resume commands, (5) the symlink note. Then:

```bash
ln -snf docs/handoffs/2026-06-19-block-record-crud-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows -> target
head -3 NEXT_SESSION.md  # reads handoff content transparently
```

- [ ] **Step 5: Commit docs + handoff, push, open PR**

```bash
git add ROADMAP.md README.md docs/handoffs/2026-06-19-block-record-crud-shipped.md NEXT_SESSION.md
git commit -m "docs: ROADMAP + handoff for block CRUD tier"
git push -u origin feature/block-record-crud
gh pr create --title "Block CRUD tier: create/rename block + move record between blocks" --body "..."
```

---

## Self-Review

**1. Spec coverage:**
- create_block (expose existing bridge) → Task 3 (UDL + wrapper) + Task 4 smoke. ✓
- rename_block (preserve records + unknown) → Task 1. ✓
- move_record (fresh uuid, copy-before-delete, preserve unknown, tombstone source) → Task 2. ✓
- Error reuse (no new variant) → enforced in Tasks 1-3 (only existing `FfiVaultError`/`VaultError` variants used). ✓
- Caller-mints UUIDs, void returns → Task 3 signatures. ✓
- Forward-compat unknown preservation → keystone assertions in Tasks 1 & 2. ✓
- Host-only acceptance bar (cargo + Swift/Kotlin conformance + smoke + android :kit + iOS XCTest) → Task 5 Step 1. ✓
- Guardrail core/spec untouched → Task 5 Step 1. ✓
- Spec's "CRDT-merge / convergence check": **covered structurally, not as a new merge test.** The cross-block convergence claim reduces to per-block convergence (already proven by `core`'s four conflict proptests) because the target copy carries a FRESH uuid — there is no cross-block identity to reconcile. The testable safety property (copy-before-delete ordering) is covered by `move_record_missing_target_leaves_source_untouched` (Task 2). A new bridge-level merge proptest would re-test `core` and is intentionally out of scope. (Noted so this is a deliberate decision, not a gap.)

**2. Placeholder scan:** No "TBD"/"implement later"/"add error handling" placeholders. The only deferred specifics are the handoff/PR body text (Task 5) and the instruction to match existing smoke-helper names by reading the sibling files first (Task 4) — both are concrete actions, not vague code placeholders.

**3. Type consistency:** Bridge fn names `rename_block` / `move_record` / `create_block` and `copy_record_into_target` are used consistently across tasks. uniffi wrappers take `Arc<UnlockedIdentity>` / `Arc<OpenVaultManifest>` + `Vec<u8>` and call `&identity.0` / `&manifest.0` (matching `record_edit.rs`). Generated foreign wrappers are camelCase (`createBlock` / `renameBlock` / `moveRecord`) — flagged in Task 4. `RecordContent(record_type, tags, fields)` positional constructor matches `SmokeRecordEdit.kt` usage.
