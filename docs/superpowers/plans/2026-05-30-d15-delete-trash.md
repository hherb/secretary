# D.1.5 Delete (record tombstone/resurrect + block trash/restore) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user with an unlocked vault soft-delete (tombstone) a record, reveal+resurrect tombstoned records, trash a whole block, list trashed blocks by name, and restore a trashed block — all from the desktop app, with forward-compat `unknown` preserved byte-faithfully across tombstone/resurrect, and Rust gating tombstoned-record visibility.

**Architecture:** Record delete/resurrect route through TWO NEW native-`BlockPlaintext` bridge primitives (`tombstone_record` / `resurrect_record`) that reuse the D.1.4 `decrypt_block_plaintext` + `save_plaintext` machinery — they flip exactly one flag (`tombstone` + clocks), preserving siblings and all three `unknown` levels. Block trash/restore reuse the ALREADY-EXISTING bridge primitives `trash_block`/`restore_block` (built in the B-phase, `ffi/secretary-ffi-bridge/src/{trash,restore}/`); D.1.5 only wires them to the desktop. One more NEW bridge primitive, `list_trashed_blocks`, decrypts each trashed block file (owner is sender+reader in v1) just enough to project its name. The desktop adds five IPC commands, two typed errors, a `TrashedBlockDto`, a `tombstoned: bool` on `RecordDto`, and an `include_deleted: bool` gate on the block-detail read (Rust decides what crosses the seam). The frontend adds delete/resurrect/trash/restore actions, a "Show deleted" toggle that re-reads with `include_deleted=true`, and a Trash view.

**Tech Stack:** Rust (bridge primitives over `secretary-core` `decrypt_block`/`save_block`/`trash_block`/`restore_block`; Tauri 2 commands + `*_impl` split; `serde` DTOs; `thiserror` `AppError`), `secretary-core` (`BlockPlaintext`/`Record`/`RecordField`/`Manifest.trash`/`TrashEntry`), `hex`, `zeroize`, Svelte 5 runes + TypeScript (Vitest).

**Spec:** `docs/superpowers/specs/2026-05-30-d15-delete-trash-design.md`

---

## Ground-truth facts the plan relies on (verified)

- **Bridge `trash_block`/`restore_block` ALREADY EXIST** and are re-exported in `ffi/secretary-ffi-bridge/src/lib.rs` (`pub use trash::trash_block;`, `pub use restore::restore_block;`). Signatures (both): `pub fn NAME(identity: &UnlockedIdentity, manifest: &OpenVaultManifest, block_uuid: [u8; 16], device_uuid: [u8; 16], now_ms: u64) -> Result<(), FfiVaultError>`. D.1.5 does NOT reimplement them.
- **Bridge `FfiVaultError` already has** `BlockUuidAlreadyLive { detail: String }` and `BlockNotInTrash { detail: String }` (`detail` = `hex::encode(block_uuid)`), plus `BlockNotFound { uuid_hex }` and `RecordNotFound { uuid_hex }`.
- **`decrypt_block_plaintext`** lives at `ffi/secretary-ffi-bridge/src/record/orchestration.rs:111` (`pub(crate)`); it binds the manifest `BlockEntry` as `_entry` (unused for decryption — decryption uses only `owner_card` + identity reader keys + the block-file bytes). **It uses `uuid_hyphenated(block_uuid)` for the file name** and pins `drop(reader_x_sk); drop(reader_pq_sk);` before returning.
- **`save_plaintext`** is a private `fn` in `ffi/secretary-ffi-bridge/src/edit/mod.rs:221`. A child module of `edit` (e.g. `edit::tombstone`) can call it via `super::save_plaintext` (Rust lets descendant modules access ancestor private items).
- **`Record`** (`core/src/vault/record.rs:330`) fields: `record_uuid: [u8;16]`, `record_type: String`, `fields: BTreeMap<String, RecordField>`, `tags: Vec<String>`, `created_at_ms: u64`, `last_mod_ms: u64`, `tombstone: bool`, `tombstoned_at_ms: u64`, `unknown: BTreeMap<String, UnknownValue>`. Resurrection invariant: `tombstone==true ⇒ tombstoned_at_ms==last_mod_ms`; resurrect (live edit at `T>tombstoned_at_ms`): `tombstone=false`, `last_mod_ms=T`, `tombstoned_at_ms` preserved.
- **`Manifest.trash: Vec<TrashEntry>`** (direct field); `TrashEntry { block_uuid: [u8;16], tombstoned_at_ms: u64, tombstoned_by: [u8;16], unknown }` (`core/src/vault/manifest.rs:356`). Trashed files live at `trash/<uuid_hyphenated>.cbor.enc.<ts>`; multiple may exist per uuid (restore picks newest).
- **Desktop `read_block_impl`** (`desktop/src-tauri/src/commands/browse.rs:28`) calls `project_block_detail(block_uuid_hex.to_string(), &output)` (`desktop/src-tauri/src/reveal.rs:17`), which skips tombstoned records (`if record.tombstone() { continue; }`).
- **Desktop `map_ffi_error`** (`desktop/src-tauri/src/errors.rs:188`) currently folds `BlockUuidAlreadyLive | BlockNotInTrash` to `Internal`; D.1.5 splits them into typed variants.
- **`session.with_unlocked(|u| ...)`** gives `&UnlockedSession { identity, manifest, device_uuid, .. }`; `parse_uuid_16` is in `commands/shared.rs`.

---

## File Structure

### Bridge (Rust) — `ffi/secretary-ffi-bridge/`

| File | Status | Responsibility |
|---|---|---|
| `src/record/orchestration.rs` | Modify | Extract `pub(crate) fn decrypt_block_file_bytes(identity, owner_card, bytes) -> Result<BlockPlaintext, FfiVaultError>` (decode + owner-keys decrypt + the `drop(reader_*_sk)` wipe). `decrypt_block_plaintext` calls it after resolving the live-block path. The trash-list primitive calls it on trash-file bytes. |
| `src/edit/tombstone.rs` | **Create** | `tombstone_record` / `resurrect_record` over native `BlockPlaintext` (flip the flag + clocks, preserve everything else) + the `unknown`-preservation keystone test. |
| `src/edit/mod.rs` | Modify | `mod tombstone; pub use tombstone::{resurrect_record, tombstone_record};` |
| `src/trash/list.rs` | **Create** | `pub struct TrashedBlock { block_uuid, block_name, tombstoned_at_ms, tombstoned_by }`; `pub fn list_trashed_blocks(identity, manifest) -> Result<Vec<TrashedBlock>, FfiVaultError>` (per `TrashEntry`: find newest trash file, decrypt for name). |
| `src/trash/mod.rs` | Modify | `mod list; pub use list::{list_trashed_blocks, TrashedBlock};` |
| `src/lib.rs` | Modify | Re-export `resurrect_record`, `tombstone_record`, `list_trashed_blocks`, `TrashedBlock`. (`trash_block`/`restore_block` already re-exported.) |

> The new primitives are **NOT** mirrored on uniffi/pyo3 (no mobile/Python consumer yet) — tracked by #167. No conformance-KAT change is expected (tombstone/resurrect use existing wire fields).

### Desktop (Rust) — `desktop/src-tauri/`

| File | Status | Responsibility |
|---|---|---|
| `src/errors.rs` | Modify | Add `BlockRestoreConflict { block_uuid_hex }` + `TrashEntryNotFound { block_uuid_hex }`; route `FfiVaultError::BlockUuidAlreadyLive`/`BlockNotInTrash` to them in `map_ffi_error`. |
| `src/dtos/trash.rs` | **Create** | `Serialize TrashedBlockDto { block_uuid_hex, block_name, tombstoned_at_ms, tombstoned_by_hex }` (camelCase; redacted `Debug`). |
| `src/dtos/browse.rs` | Modify | `RecordDto` gains `pub tombstoned: bool`. |
| `src/dtos/mod.rs` | Modify | Declare `mod trash;` + re-export `TrashedBlockDto`. |
| `src/reveal.rs` | Modify | `project_block_detail` + `project_record` take `include_deleted: bool`; emit tombstoned records (flagged) only when set. |
| `src/commands/browse.rs` | Modify | `read_block` + `read_block_impl` gain `include_deleted: bool`, threaded into `project_block_detail`. |
| `src/commands/delete.rs` | **Create** | `tombstone_record` / `resurrect_record` / `trash_block` / `restore_block` / `list_trashed_blocks` thin commands + `*_impl`. |
| `src/commands/mod.rs` | Modify | `pub mod delete;` |
| `src/main.rs` | Modify | Register the five new commands. |
| `tests/ipc_integration.rs` | Modify | L3: tombstone hides by default / shows-flagged with `include_deleted`; resurrect; trash→list-by-name→restore; `BlockRestoreConflict`/`TrashEntryNotFound`/`RecordNotFound`. |

### Frontend (Svelte + TS) — `desktop/`

| File | Status | Responsibility |
|---|---|---|
| `src/lib/ipc.ts` | Modify | `readBlock(blockUuidHex, includeDeleted?)`; `RecordDto` gains `tombstoned?: boolean`; `TrashedBlockDto`; `tombstoneRecord`/`resurrectRecord`/`trashBlock`/`restoreBlock`/`listTrashedBlocks`. |
| `src/lib/errors.ts` | Modify | Add `block_restore_conflict` + `trash_entry_not_found` codes/union/messages. |
| `src/lib/browse.ts` | Modify | `BrowseNav` gains `{ level: 'trash' }`; `openTrash()`; `back()` pops it. |
| `src/lib/trash.ts` | **Create** | Pure helpers: `sortTrashed(dtos)`, `formatTrashedWhen(ms)`. |
| `src/components/delete/ConfirmDialog.svelte` | **Create** | Reusable confirm (title/body/confirm/cancel), modeled on `SettingsDialog`. |
| `src/components/delete/TrashView.svelte` | **Create** | Fetches `listTrashedBlocks` on mount; lists `TrashedBlockRow`s; Restore wiring; back button. |
| `src/components/delete/TrashedBlockRow.svelte` | **Create** | One trashed-block row: name + when + Restore. |
| `src/components/RecordList.svelte` | Modify | "Show deleted" toggle (re-reads with `includeDeleted`); per-row Delete (confirm → tombstone); tombstoned rows greyed + Restore (resurrect). |
| `src/components/RecordRow.svelte` | Modify | `deleted` prop → `.record-row--deleted`; Delete / Restore action buttons (dispatch up). |
| `src/components/BlockCard.svelte` | Modify | Trash action button (dispatch up; confirm in Vault). |
| `src/routes/Vault.svelte` | Modify | Add the `trash` pane + "🗑 Trash" entry; host confirm dialogs; `refreshManifest` after trash/restore. |
| `src/theme.css` | Modify | `.confirm-dialog*`, `.trash-view*`, `.trashed-row*`, `.record-row--deleted`, row action buttons (Vite-6 preprocessCSS workaround, #153). |

### Frontend tests — `desktop/tests/`

| File | Status | Covers |
|---|---|---|
| `tests/trash.test.ts` | **Create** | `sortTrashed` (newest-first), `formatTrashedWhen`. |
| `tests/browseTrash.test.ts` | **Create** | `openTrash`/`back` transitions. |
| `tests/ipcTrash.test.ts` | **Create** | 5 new wrappers + `readBlock` `includeDeleted` arg (invoke mocks). |
| `tests/errors.test.ts` | Modify | Two new code messages. |
| `tests/ConfirmDialog.test.ts` | **Create** | Confirm/cancel events; Esc/backdrop. |
| `tests/TrashView.test.ts` | **Create** | Lists rows from mocked `listTrashedBlocks`; Restore dispatch; empty state. |
| `tests/RecordListDelete.test.ts` | **Create** | Show-deleted toggle re-reads with `includeDeleted=true`; delete confirm → tombstone; resurrect. |

### Modified docs (Task 8 / ship)

- `README.md` — D-row advances to "D.1.5 (delete/trash) shipped; D.1.6 (share) next".
- `ROADMAP.md` — D.1.5 ✅, D.1.6 ⏳ (note: share split out of D.1.5).
- `docs/handoffs/2026-05-31-d15-delete-trash-shipped.md` + retarget `NEXT_SESSION.md` symlink.

---

## Task 1: Bridge — record `tombstone_record` / `resurrect_record` primitives (+ `unknown` keystone)

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/edit/tombstone.rs`
- Modify: `ffi/secretary-ffi-bridge/src/edit/mod.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`
- Test: `ffi/secretary-ffi-bridge/tests/edit.rs` (round-trips) + `src/edit/tombstone.rs` `#[cfg(test)]` (the `unknown` keystone)

- [ ] **Step 1: Write the failing round-trip tests**

Append to `ffi/secretary-ffi-bridge/tests/edit.rs` (reuse that file's existing `open_writable_golden_001` / `create_block` / `append_record` helpers — check the top of the file for the exact helper names and match them):

```rust
#[test]
fn tombstone_record_hides_from_read_block() {
    use secretary_ffi_bridge::{
        append_record, create_block, read_block, tombstone_record, FieldInput, FieldInputValue,
        RecordContent,
    };
    use secretary_core::crypto::secret::SecretString;

    let opened = open_writable_golden_001();
    let block_uuid = [0x51u8; 16];
    create_block(&opened.identity, &opened.manifest, block_uuid, "Logins".into(), [0x07u8; 16], 1_000)
        .expect("create_block");
    let rec = [0x52u8; 16];
    append_record(
        &opened.identity, &opened.manifest, block_uuid, rec,
        RecordContent {
            record_type: "login".into(),
            tags: vec![],
            fields: vec![FieldInput { name: "user".into(), value: FieldInputValue::Text(SecretString::from("alice")) }],
        },
        [0x07u8; 16], 2_000,
    ).expect("append_record");

    tombstone_record(&opened.identity, &opened.manifest, block_uuid, rec, [0x07u8; 16], 3_000)
        .expect("tombstone_record");

    // read_block lowers to handles; the record is still present in the block
    // file (CRDT), but its handle reports tombstone() == true.
    let out = read_block(&opened.identity, &opened.manifest, &block_uuid).expect("read");
    let found = (0..out.record_count())
        .filter_map(|i| out.record_at(i))
        .find(|r| r.record_uuid() == rec)
        .expect("record present in block file");
    assert!(found.tombstone(), "record must be tombstoned after tombstone_record");
    out.wipe();
}

#[test]
fn resurrect_record_clears_tombstone_and_keeps_fields() {
    use secretary_ffi_bridge::{
        append_record, create_block, read_block, resurrect_record, tombstone_record, FieldInput,
        FieldInputValue, RecordContent,
    };
    use secretary_core::crypto::secret::SecretString;

    let opened = open_writable_golden_001();
    let block_uuid = [0x61u8; 16];
    create_block(&opened.identity, &opened.manifest, block_uuid, "B".into(), [0x07u8; 16], 1_000).unwrap();
    let rec = [0x62u8; 16];
    append_record(
        &opened.identity, &opened.manifest, block_uuid, rec,
        RecordContent { record_type: "login".into(), tags: vec![], fields: vec![FieldInput { name: "user".into(), value: FieldInputValue::Text(SecretString::from("alice")) }] },
        [0x07u8; 16], 2_000,
    ).unwrap();
    tombstone_record(&opened.identity, &opened.manifest, block_uuid, rec, [0x07u8; 16], 3_000).unwrap();

    resurrect_record(&opened.identity, &opened.manifest, block_uuid, rec, [0x07u8; 16], 4_000)
        .expect("resurrect_record");

    let out = read_block(&opened.identity, &opened.manifest, &block_uuid).unwrap();
    let r = (0..out.record_count()).filter_map(|i| out.record_at(i)).find(|r| r.record_uuid() == rec).unwrap();
    assert!(!r.tombstone(), "resurrect must clear the tombstone flag");
    assert_eq!(r.field_at(0).unwrap().expose_text().unwrap(), "alice", "fields survive resurrect");
    out.wipe();
}

#[test]
fn tombstone_record_errors_on_absent_or_already_tombstoned() {
    use secretary_ffi_bridge::{create_block, tombstone_record, FfiVaultError};
    let opened = open_writable_golden_001();
    let block_uuid = [0x71u8; 16];
    create_block(&opened.identity, &opened.manifest, block_uuid, "B".into(), [0x07u8; 16], 1_000).unwrap();
    let missing = [0x99u8; 16];
    let err = tombstone_record(&opened.identity, &opened.manifest, block_uuid, missing, [0x07u8; 16], 2_000)
        .expect_err("absent record must error");
    assert!(matches!(err, FfiVaultError::RecordNotFound { .. }));
}
```

- [ ] **Step 2: Run to confirm they fail (primitives not found)**

Run: `cargo test --release -p secretary-ffi-bridge --test edit tombstone 2>&1 | tail -20`
Expected: FAIL — `tombstone_record` / `resurrect_record` not found.

- [ ] **Step 3: Create `edit/tombstone.rs`**

Create `ffi/secretary-ffi-bridge/src/edit/tombstone.rs`:

```rust
//! D.1.5 record-level soft delete. `tombstone_record` flips a LIVE record's
//! `tombstone` flag on (setting the death-clock); `resurrect_record` clears it
//! at a newer clock. Both reuse the D.1.4 native-`BlockPlaintext` round-trip
//! (`decrypt_block_plaintext` + `super::save_plaintext`), so untouched sibling
//! records — and every `unknown` map at block / record / field level — survive
//! byte-faithfully. Fields are NOT cleared on tombstone: the record stays
//! resurrectable with its data intact.

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::decrypt_block_plaintext;
use crate::vault::OpenVaultManifest;

/// Tombstone (soft-delete) one LIVE record. Sets `tombstone = true`,
/// `tombstoned_at_ms = now_ms`, `last_mod_ms = now_ms` (preserving the
/// `tombstone ⇒ tombstoned_at_ms == last_mod_ms` invariant). `record_uuid`,
/// `created_at_ms`, fields, tags, and all `unknown` maps are preserved.
/// Errors `RecordNotFound` if the record is absent or already tombstoned.
pub fn tombstone_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    let idx = plaintext
        .records
        .iter()
        .position(|r| r.record_uuid == record_uuid && !r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound { uuid_hex: hex::encode(record_uuid) })?;
    let r = &mut plaintext.records[idx];
    r.tombstone = true;
    r.tombstoned_at_ms = now_ms;
    r.last_mod_ms = now_ms;
    super::save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}

/// Resurrect one TOMBSTONED record. Sets `tombstone = false`,
/// `last_mod_ms = now_ms` (`now_ms` must exceed the prior `tombstoned_at_ms`),
/// and PRESERVES `tombstoned_at_ms` (the death-clock high-water mark, per the
/// core merge invariant). Errors `RecordNotFound` if absent or already live.
pub fn resurrect_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    record_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let mut plaintext = decrypt_block_plaintext(identity, manifest, &block_uuid)?;
    let idx = plaintext
        .records
        .iter()
        .position(|r| r.record_uuid == record_uuid && r.tombstone)
        .ok_or_else(|| FfiVaultError::RecordNotFound { uuid_hex: hex::encode(record_uuid) })?;
    let r = &mut plaintext.records[idx];
    r.tombstone = false;
    r.last_mod_ms = now_ms;
    // tombstoned_at_ms intentionally preserved (death-clock high-water mark).
    super::save_plaintext(identity, manifest, plaintext, device_uuid, now_ms)
}
```

> `super::save_plaintext` resolves to the private `save_plaintext` in `edit/mod.rs` (a child module can call an ancestor's private fn). If the compiler rejects the visibility, change `fn save_plaintext` to `pub(super) fn save_plaintext` in `edit/mod.rs` — nothing else references it.

- [ ] **Step 4: Wire the module + re-exports**

In `ffi/secretary-ffi-bridge/src/edit/mod.rs`, after the existing `mod content; pub use content::RecordContent;`:

```rust
mod tombstone;
pub use tombstone::{resurrect_record, tombstone_record};
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, extend the existing edit re-export line:

```rust
pub use edit::{
    append_record, create_block, edit_record, resurrect_record, tombstone_record, RecordContent,
};
```

- [ ] **Step 5: Run the round-trip tests**

Run: `cargo test --release -p secretary-ffi-bridge --test edit tombstone 2>&1 | tail -20` then `... resurrect ...`
Expected: PASS (3 tests: hide, resurrect-keeps-fields, error-on-absent).

- [ ] **Step 6: Write + run the `unknown` keystone test (in-crate, needs `decrypt_block_plaintext`)**

Add a `#[cfg(test)] mod tests` to `ffi/secretary-ffi-bridge/src/edit/tombstone.rs`. Mirror the D.1.4 keystone in `edit/mod.rs` (open its `#[cfg(test)]` module and copy its setup: how it builds a native `BlockPlaintext` with synthetic `unknown` via `secretary_core::vault::record::UnknownValue::from_canonical_cbor(&[0x01])`, saves it through the same `OpenVault` path, then asserts via `decrypt_block_plaintext`). The test:

```rust
#[cfg(test)]
mod tests {
    // Build a block with one record R that carries unknowns at all three levels:
    //   block.unknown["x_block"], R.unknown["x_rec"], R.fields["user"].unknown["x_fld"].
    // Save it via the same path the primitives use.
    // 1. tombstone_record(R) → decrypt_block_plaintext → assert R.tombstone == true,
    //    R.tombstoned_at_ms == now, AND all three unknowns still present, AND
    //    R.fields["user"] still present (fields NOT cleared).
    // 2. resurrect_record(R) at a newer now → assert R.tombstone == false,
    //    R.tombstoned_at_ms UNCHANGED, all three unknowns STILL present.
    // This is the slice's correctness contract — do not stub it.
}
```

> Reproduce the D.1.4 keystone's exact construction helpers (it is the proven template). Use `UnknownValue::from_canonical_cbor(&[0x01])` for the synthetic values, and the same `OpenVault` save path `save_plaintext` uses to seed the block.

Run: `cargo test --release -p secretary-ffi-bridge tombstone::tests 2>&1 | tail -20`
Expected: PASS — three-level `unknown` survives BOTH tombstone and resurrect.

- [ ] **Step 7: Bridge gauntlet + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
cargo test --release --workspace 2>&1 | grep "^test result:" | tail -8
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all && cargo fmt --all -- --check
git add ffi/secretary-ffi-bridge/src/edit/ ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/edit.rs
git commit -m "feat(d15): record tombstone_record / resurrect_record bridge primitives

Native-BlockPlaintext flip-one-flag primitives over the D.1.4 round-trip:
tombstone sets tombstone+death-clock (fields kept, resurrectable); resurrect
clears the flag at a newer clock and preserves tombstoned_at_ms. Siblings and
all three unknown levels survive byte-faithfully (keystone test).

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Bridge — `list_trashed_blocks` (decrypt trashed blocks for names)

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/record/orchestration.rs` (extract `decrypt_block_file_bytes`)
- Create: `ffi/secretary-ffi-bridge/src/trash/list.rs`
- Modify: `ffi/secretary-ffi-bridge/src/trash/mod.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`
- Test: `ffi/secretary-ffi-bridge/tests/trash_list.rs` (new)

- [ ] **Step 1: Extract `decrypt_block_file_bytes` from `decrypt_block_plaintext` (behaviour-preserving refactor)**

In `ffi/secretary-ffi-bridge/src/record/orchestration.rs`, factor the part of `decrypt_block_plaintext` from `decode_block_file` through the decrypt + the `drop(reader_x_sk); drop(reader_pq_sk);` wipe into a crate-internal helper that takes already-read bytes + the owner card. The secret-key drop stays INSIDE the helper (preserving the exact wipe timing the memory-hygiene audit pins):

```rust
/// Decode + hybrid-verify + AEAD-decrypt one block file's bytes as the vault
/// OWNER (v1 single-author: owner == sender == reader). Shared by
/// `decrypt_block_plaintext` (live blocks, path from the manifest BlockEntry)
/// and `crate::trash::list_trashed_blocks` (trashed blocks, path under
/// `trash/`). The reader secret keys are dropped (zeroized) inside this fn,
/// immediately after `decrypt_block` returns and before the plaintext is
/// handed back — the timing the memory-hygiene audit relies on.
pub(crate) fn decrypt_block_file_bytes(
    identity: &UnlockedIdentity,
    owner_card: &ContactCard, // use the actual owner-card type the surrounding code uses
    bytes: &[u8],
) -> Result<secretary_core::vault::BlockPlaintext, FfiVaultError> {
    // MOVE here verbatim from decrypt_block_plaintext:
    //   block::decode_block_file(bytes) -> CorruptVault on error,
    //   owner_canonical / owner_fp / owner_pk_bundle / owner_pq_pk derivation,
    //   identity.reader_secret_keys() match,
    //   block::decrypt_block(...) call,
    //   drop(reader_x_sk); drop(reader_pq_sk);
    //   Ok(plaintext)
}
```

Then rewrite `decrypt_block_plaintext`'s tail to call it:

```rust
    // (unchanged: snapshot_for_read_block, BlockEntry lookup -> BlockNotFound,
    //  path build with uuid_hyphenated, std::fs::read with the NotFound ->
    //  CorruptVault / other -> FolderInvalid mapping)
    decrypt_block_file_bytes(identity, &owner_card, &bytes)
```

> Match the exact owner-card type and `use` imports already in the file (`ContactCard`, `fingerprint`, `MlDsa65Public`, `ReaderSecretKeysError`, `block`). This is a pure extraction — no behaviour change.

- [ ] **Step 2: Run existing read_block tests to confirm the refactor is behaviour-preserving**

Run: `cargo test --release -p secretary-ffi-bridge read_block 2>&1 | tail -20`
Expected: PASS (all pre-existing read_block tests).

- [ ] **Step 3: Write the failing trash-list test**

Create `ffi/secretary-ffi-bridge/tests/trash_list.rs`:

```rust
//! D.1.5 list_trashed_blocks: after trashing a named block, the trash list
//! must surface it BY NAME (decrypted from the trash file), with the
//! tombstoned_at metadata. Hermetic writable golden-001 copy.

mod common; // reuse the golden-001 open helpers used by edit.rs / save_block.rs
use common::open_writable_golden_001;

use secretary_ffi_bridge::{create_block, list_trashed_blocks, trash_block};

#[test]
fn trashed_block_appears_in_list_by_name() {
    let opened = open_writable_golden_001();
    let block_uuid = [0x81u8; 16];
    create_block(&opened.identity, &opened.manifest, block_uuid, "Bank logins".into(), [0x07u8; 16], 1_000)
        .expect("create_block");

    trash_block(&opened.identity, &opened.manifest, block_uuid, [0x07u8; 16], 2_000)
        .expect("trash_block");

    let trashed = list_trashed_blocks(&opened.identity, &opened.manifest).expect("list");
    let entry = trashed.iter().find(|t| t.block_uuid == block_uuid).expect("trashed block present");
    assert_eq!(entry.block_name, "Bank logins", "name must be decrypted from the trash file");
    assert_eq!(entry.tombstoned_at_ms, 2_000);
}

#[test]
fn list_trashed_blocks_empty_when_nothing_trashed() {
    let opened = open_writable_golden_001();
    let trashed = list_trashed_blocks(&opened.identity, &opened.manifest).expect("list");
    // golden_vault_001 ships with no trashed blocks.
    assert!(trashed.iter().all(|t| t.block_name != "Bank logins"));
}
```

> If `common` isn't already a shared test module, copy the `open_writable_golden_001` helper from `tests/edit.rs` (or wherever it lives) following that file's pattern.

Run: `cargo test --release -p secretary-ffi-bridge --test trash_list 2>&1 | tail -20`
Expected: FAIL — `list_trashed_blocks` not found.

- [ ] **Step 4: Implement `trash/list.rs`**

Create `ffi/secretary-ffi-bridge/src/trash/list.rs`:

```rust
//! D.1.5 `list_trashed_blocks` — project the manifest's trash table into
//! name-bearing entries. The `TrashEntry` carries no name (it lives inside the
//! encrypted block), so each trashed file is decrypted (owner == reader, v1)
//! just enough to read its name. Record plaintext is decoded but never
//! lowered to a handle / never returned — only the block name + metadata
//! cross out. Whole-block plaintext drops (zeroizes) per entry.

use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::record::orchestration::{decrypt_block_file_bytes, uuid_hyphenated};
use crate::vault::OpenVaultManifest;

/// One trashed block, identified by name for the restore UI.
#[derive(Clone, Debug)]
pub struct TrashedBlock {
    pub block_uuid: [u8; 16],
    pub block_name: String,
    pub tombstoned_at_ms: u64,
    pub tombstoned_by: [u8; 16],
}

/// List trashed blocks, decrypting each for its name. Newest trash file wins
/// when a uuid has more than one (mirrors `restore_block`'s newest-wins).
pub fn list_trashed_blocks(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<Vec<TrashedBlock>, FfiVaultError> {
    let (manifest_body, owner_card, vault_folder) = manifest
        .snapshot_for_read_block()
        .ok_or_else(|| FfiVaultError::CorruptVault {
            detail: "vault manifest handle has been closed".into(),
        })?;

    let trash_dir = vault_folder.join("trash");
    let mut out = Vec::with_capacity(manifest_body.trash.len());
    for entry in &manifest_body.trash {
        let path = newest_trash_file(&trash_dir, &entry.block_uuid)?.ok_or_else(|| {
            FfiVaultError::CorruptVault {
                detail: format!("trash entry {} has no file", hex::encode(entry.block_uuid)),
            }
        })?;
        let bytes = std::fs::read(&path).map_err(|e| FfiVaultError::FolderInvalid {
            detail: format!("failed to read trash file: {e}"),
        })?;
        let plaintext = decrypt_block_file_bytes(identity, &owner_card, &bytes)?;
        out.push(TrashedBlock {
            block_uuid: entry.block_uuid,
            block_name: plaintext.block_name.clone(),
            tombstoned_at_ms: entry.tombstoned_at_ms,
            tombstoned_by: entry.tombstoned_by,
        });
        // plaintext drops (zeroizes) here.
    }
    Ok(out)
}

/// Find `trash/<uuid_hyphenated>.cbor.enc.<ts>` with the highest `<ts>`.
fn newest_trash_file(
    trash_dir: &std::path::Path,
    block_uuid: &[u8; 16],
) -> Result<Option<std::path::PathBuf>, FfiVaultError> {
    let prefix = format!("{}.cbor.enc.", uuid_hyphenated(block_uuid));
    let read_dir = match std::fs::read_dir(trash_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(FfiVaultError::FolderInvalid { detail: format!("read trash dir: {e}") }),
    };
    let mut best: Option<(u64, std::path::PathBuf)> = None;
    for de in read_dir {
        let de = de.map_err(|e| FfiVaultError::FolderInvalid { detail: format!("trash entry: {e}") })?;
        let name = de.file_name();
        let name = name.to_string_lossy();
        if let Some(ts_str) = name.strip_prefix(&prefix) {
            if let Ok(ts) = ts_str.parse::<u64>() {
                if best.as_ref().is_none_or(|(b, _)| ts > *b) {
                    best = Some((ts, de.path()));
                }
            }
        }
    }
    Ok(best.map(|(_, p)| p))
}
```

> Confirm `uuid_hyphenated` is reachable (it's used inside `decrypt_block_plaintext` in `record/orchestration.rs`); if it's private there, make it `pub(crate)`. Confirm `snapshot_for_read_block` returns `(manifest_body, owner_card, vault_folder)` in that order (it does in `decrypt_block_plaintext`). If `is_none_or` is unavailable on the toolchain, use `best.as_ref().map_or(true, |(b, _)| ts > *b)`.

- [ ] **Step 5: Wire the module + re-exports**

In `ffi/secretary-ffi-bridge/src/trash/mod.rs`, add:

```rust
mod list;
pub use list::{list_trashed_blocks, TrashedBlock};
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, extend the trash re-export:

```rust
pub use trash::{list_trashed_blocks, trash_block, TrashedBlock};
```

- [ ] **Step 6: Run the trash-list tests**

Run: `cargo test --release -p secretary-ffi-bridge --test trash_list 2>&1 | tail -20`
Expected: PASS (2 tests).

- [ ] **Step 7: Bridge gauntlet + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
cargo test --release --workspace 2>&1 | grep "^test result:" | tail -8
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
git add ffi/secretary-ffi-bridge/src/record/orchestration.rs ffi/secretary-ffi-bridge/src/trash/ \
        ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/trash_list.rs
git commit -m "feat(d15): list_trashed_blocks bridge primitive (decrypt for name)

Extract decrypt_block_file_bytes (decode + owner-keys decrypt + secret-key
wipe) shared by decrypt_block_plaintext and the new trash list. list_trashed_blocks
projects manifest.trash by decrypting each trashed file (newest-wins) for its
name; record plaintext is never returned. Secret-wipe timing preserved.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Desktop — typed `AppError::BlockRestoreConflict` + `TrashEntryNotFound` + map routing

**Files:**
- Modify: `desktop/src-tauri/src/errors.rs` (enum + `map_ffi_error` + test module)

- [ ] **Step 1: Write failing wire-format tests**

Add to the `#[cfg(test)] mod tests` in `desktop/src-tauri/src/errors.rs` (after the existing `record_not_found_carries_hex`-style tests; reuse the `round_trip` helper):

```rust
    #[test]
    fn block_restore_conflict_carries_hex() {
        let v = round_trip(&AppError::BlockRestoreConflict { block_uuid_hex: "ab12".into() });
        assert_eq!(v["code"], "block_restore_conflict");
        assert_eq!(v["block_uuid_hex"], "ab12");
    }

    #[test]
    fn trash_entry_not_found_carries_hex() {
        let v = round_trip(&AppError::TrashEntryNotFound { block_uuid_hex: "cd34".into() });
        assert_eq!(v["code"], "trash_entry_not_found");
        assert_eq!(v["block_uuid_hex"], "cd34");
    }

    #[test]
    fn ffi_block_uuid_already_live_maps_to_restore_conflict() {
        let mapped = map_ffi_error(secretary_ffi_bridge::FfiVaultError::BlockUuidAlreadyLive {
            detail: "abcd".into(),
        });
        assert!(matches!(mapped, AppError::BlockRestoreConflict { block_uuid_hex } if block_uuid_hex == "abcd"));
    }

    #[test]
    fn ffi_block_not_in_trash_maps_to_trash_entry_not_found() {
        let mapped = map_ffi_error(secretary_ffi_bridge::FfiVaultError::BlockNotInTrash {
            detail: "ef01".into(),
        });
        assert!(matches!(mapped, AppError::TrashEntryNotFound { block_uuid_hex } if block_uuid_hex == "ef01"));
    }
```

- [ ] **Step 2: Run to confirm they fail**

Run: `cd desktop/src-tauri && cargo test --release errors 2>&1 | tail -20`
Expected: FAIL — `no variant ... BlockRestoreConflict`.

- [ ] **Step 3: Add the two variants**

In `desktop/src-tauri/src/errors.rs`, inside `pub enum AppError` (after `RecordSaveFailed`):

```rust
    #[error("Cannot restore: a block with this id is already live")]
    BlockRestoreConflict { block_uuid_hex: String },

    #[error("That trashed block is no longer available")]
    TrashEntryNotFound { block_uuid_hex: String },
```

- [ ] **Step 4: Route the bridge variants in `map_ffi_error`**

In `desktop/src-tauri/src/errors.rs`, the current catch-all arm folds `BlockUuidAlreadyLive | BlockNotInTrash` into `Internal`. Split them out (the bridge `detail` is `hex::encode(block_uuid)`, so map it straight to `block_uuid_hex`):

```rust
        FfiVaultError::BlockUuidAlreadyLive { detail } => {
            AppError::BlockRestoreConflict { block_uuid_hex: detail }
        }
        FfiVaultError::BlockNotInTrash { detail } => {
            AppError::TrashEntryNotFound { block_uuid_hex: detail }
        }
        // share-only variants remain folded to Internal (D.1.6):
        other @ (FfiVaultError::NotAuthor { .. }
        | FfiVaultError::RecipientAlreadyPresent
        | FfiVaultError::MissingRecipientCard { .. }) => AppError::Internal {
            detail: format!("{other:?}"),
        },
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cd desktop/src-tauri && cargo test --release errors 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Clippy + fmt + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
git add desktop/src-tauri/src/errors.rs
git commit -m "feat(d15): typed AppError::BlockRestoreConflict + TrashEntryNotFound

Route the bridge BlockUuidAlreadyLive / BlockNotInTrash (previously folded to
Internal) to typed variants carrying block_uuid_hex, so restore conflicts and
missing trash targets surface precise messages. Wire + mapping tests pin both.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Desktop — `TrashedBlockDto` + `RecordDto.tombstoned` + `include_deleted` projection gate

**Files:**
- Create: `desktop/src-tauri/src/dtos/trash.rs`
- Modify: `desktop/src-tauri/src/dtos/browse.rs` (RecordDto + its test)
- Modify: `desktop/src-tauri/src/dtos/mod.rs`
- Modify: `desktop/src-tauri/src/reveal.rs` (projection gate)
- Modify: `desktop/src-tauri/src/commands/browse.rs` (read_block param)

- [ ] **Step 1: Write failing tests for `TrashedBlockDto` + `RecordDto.tombstoned` + the projection gate**

Create `desktop/src-tauri/src/dtos/trash.rs`:

```rust
//! D.1.5 trash-view DTO. `block_name` is a category label (not a secret field
//! value), but `Debug` is redacted for parity with the secret-boundary
//! discipline (a block name can still be sensitive).

/// One trashed block, identified by name for the restore UI.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashedBlockDto {
    pub block_uuid_hex: String,
    pub block_name: String,
    pub tombstoned_at_ms: u64,
    pub tombstoned_by_hex: String,
}

impl std::fmt::Debug for TrashedBlockDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrashedBlockDto")
            .field("block_uuid_hex", &self.block_uuid_hex)
            .field("block_name", &"<redacted>")
            .field("tombstoned_at_ms", &self.tombstoned_at_ms)
            .field("tombstoned_by_hex", &self.tombstoned_by_hex)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn trashed_block_dto_camel_case() {
        let v: Value = serde_json::from_str(
            &serde_json::to_string(&TrashedBlockDto {
                block_uuid_hex: "ab".into(),
                block_name: "Bank".into(),
                tombstoned_at_ms: 42,
                tombstoned_by_hex: "cd".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(v["blockUuidHex"], "ab");
        assert_eq!(v["blockName"], "Bank");
        assert_eq!(v["tombstonedAtMs"], 42);
        assert_eq!(v["tombstonedByHex"], "cd");
    }

    #[test]
    fn trashed_block_dto_debug_redacts_name() {
        let dbg = format!(
            "{:?}",
            TrashedBlockDto {
                block_uuid_hex: "ab".into(),
                block_name: "Secret Category".into(),
                tombstoned_at_ms: 1,
                tombstoned_by_hex: "cd".into(),
            }
        );
        assert!(!dbg.contains("Secret Category"));
        assert!(dbg.contains("redacted"));
    }
}
```

In `desktop/src-tauri/src/dtos/browse.rs`, add `tombstoned` to `RecordDto` and update its serde test to assert the new field. Add to the struct:

```rust
    /// `true` when the record is tombstoned. Only ever `true` in a projection
    /// the caller requested with `include_deleted` (the read gate is Rust's).
    pub tombstoned: bool,
```

Extend the existing `RecordDto` serde test (e.g. `record_dto_camel_case_with_hex_uuid_and_field_count`) to set `tombstoned: false` in the literal and assert `v["tombstoned"] == false`.

- [ ] **Step 2: Run to confirm failures (missing field / module)**

Run: `cd desktop/src-tauri && cargo test --release dtos 2>&1 | tail -20`
Expected: FAIL — `dtos/trash.rs` not declared; `RecordDto` literal missing `tombstoned`.

- [ ] **Step 3: Declare + re-export the trash DTO; add the projection gate**

In `desktop/src-tauri/src/dtos/mod.rs`, add `mod trash;` and re-export:

```rust
mod browse;
mod create;
mod edit;
mod manifest;
mod trash;

pub use browse::{BlockDetailDto, FieldMetaDto, RecordDto, RevealedFieldDto};
pub use create::{CreateTargetProbeDto, CreateVaultDto};
pub use edit::{
    FieldInputDto, FieldValueDto, RecordInputDto, RecordRefDto, RecordRevealDto,
    RevealedFieldWithNameDto,
};
pub use manifest::{BlockSummaryDto, ManifestDto, SettingsDto, SettingsInput};
pub use trash::TrashedBlockDto;
```

In `desktop/src-tauri/src/reveal.rs`, thread `include_deleted` and emit `tombstoned`. Replace `project_block_detail` + `project_record`:

```rust
/// Project a decrypted [`BlockReadOutput`] into a [`BlockDetailDto`]. When
/// `include_deleted` is false (default) tombstoned records are filtered out
/// (the historical behaviour); when true they are emitted with
/// `tombstoned: true`. Rust is the gatekeeper — the caller sees a tombstoned
/// record only by asking. Carries only plaintext metadata (no field values).
pub fn project_block_detail(
    block_uuid_hex: String,
    output: &BlockReadOutput,
    include_deleted: bool,
) -> BlockDetailDto {
    let mut records = Vec::with_capacity(output.record_count());
    for i in 0..output.record_count() {
        let Some(record) = output.record_at(i) else {
            continue;
        };
        if record.tombstone() && !include_deleted {
            continue;
        }
        records.push(project_record(&record));
    }
    BlockDetailDto {
        block_uuid_hex,
        block_name: output.block_name(),
        records,
    }
}

fn project_record(record: &Record) -> RecordDto {
    let field_count = record.field_count();
    let mut fields = Vec::with_capacity(field_count);
    for i in 0..field_count {
        if let Some(handle) = record.field_at(i) {
            fields.push(project_field_meta(&handle));
        }
    }
    RecordDto {
        record_uuid_hex: hex::encode(record.record_uuid()),
        record_type: record.record_type(),
        tags: record.tags(),
        created_at_ms: record.created_at_ms(),
        last_mod_ms: record.last_mod_ms(),
        field_count: fields.len() as u64,
        fields,
        tombstoned: record.tombstone(),
    }
}
```

> `locate_record` (used by `reveal_record`) must KEEP skipping tombstoned records — do not add `include_deleted` there; you cannot reveal a deleted record's secrets (only `resurrect_record` reads it, in the bridge).

In `desktop/src-tauri/src/commands/browse.rs`, thread the param through the command + impl:

```rust
#[tauri::command]
pub async fn read_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    include_deleted: bool,
) -> Result<BlockDetailDto, AppError> {
    read_block_impl(state.inner(), &block_uuid_hex, include_deleted)
}

pub fn read_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    include_deleted: bool,
) -> Result<BlockDetailDto, AppError> {
    let uuid = parse_uuid_16(block_uuid_hex)?;
    let session = state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })?;
    session.with_unlocked(|u| {
        let output = bridge_read_block(&u.identity, &u.manifest, &uuid).map_err(|e| match e {
            FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound {
                block_uuid_hex: uuid_hex,
            },
            other => AppError::from(other),
        })?;
        let dto = project_block_detail(block_uuid_hex.to_string(), &output, include_deleted);
        output.wipe();
        Ok(dto)
    })
}
```

> Update existing `read_block_impl` call sites in `tests/ipc_integration.rs` to pass `false` (the D.1.4 tests don't want deleted records).

- [ ] **Step 4: Run the DTO + projection tests**

Run: `cd desktop/src-tauri && cargo test --release dtos 2>&1 | tail -20` then `cargo test --release reveal 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 5: Clippy + fmt + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
git add desktop/src-tauri/src/dtos/ desktop/src-tauri/src/reveal.rs desktop/src-tauri/src/commands/browse.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(d15): TrashedBlockDto + RecordDto.tombstoned + include_deleted read gate

read_block gains include_deleted (default false); the projection emits
tombstoned records (flagged) only when set — Rust gates visibility. TrashedBlockDto
(redacted Debug) carries the decrypted name for the restore UI.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Desktop — `commands/delete.rs` (5 commands + `*_impl`) + register + L3 tests

**Files:**
- Create: `desktop/src-tauri/src/commands/delete.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs`
- Modify: `desktop/src-tauri/src/main.rs`
- Modify: `desktop/src-tauri/tests/ipc_integration.rs`

- [ ] **Step 1: Write the failing L3 integration tests**

Add to `desktop/src-tauri/tests/ipc_integration.rs`. Imports (alongside the existing `use secretary_desktop::commands::{...}`):

```rust
use secretary_desktop::commands::delete;
```

Append a module (reuse the existing `unlocked_session_over_new_vault()`, `text_field(...)`, and `browse::read_block_impl` helpers):

```rust
mod delete_path {
    use super::*;

    #[test]
    fn tombstone_hides_by_default_and_shows_with_include_deleted() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Logins").unwrap();
        let rec = edit::save_record_impl(
            &state,
            &block.block_uuid_hex,
            RecordInputDto { record_type: "login".into(), tags: vec![], fields: vec![text_field("user", "alice")] },
        )
        .unwrap();

        delete::tombstone_record_impl(&state, &block.block_uuid_hex, &rec.record_uuid_hex).unwrap();

        // Default read: hidden.
        let live = browse::read_block_impl(&state, &block.block_uuid_hex, false).unwrap();
        assert!(live.records.is_empty(), "tombstoned record hidden by default");

        // include_deleted: present and flagged.
        let all = browse::read_block_impl(&state, &block.block_uuid_hex, true).unwrap();
        assert_eq!(all.records.len(), 1);
        assert!(all.records[0].tombstoned);
    }

    #[test]
    fn resurrect_returns_record_to_live_view() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Logins").unwrap();
        let rec = edit::save_record_impl(
            &state, &block.block_uuid_hex,
            RecordInputDto { record_type: "login".into(), tags: vec![], fields: vec![text_field("user", "alice")] },
        ).unwrap();
        delete::tombstone_record_impl(&state, &block.block_uuid_hex, &rec.record_uuid_hex).unwrap();
        delete::resurrect_record_impl(&state, &block.block_uuid_hex, &rec.record_uuid_hex).unwrap();

        let live = browse::read_block_impl(&state, &block.block_uuid_hex, false).unwrap();
        assert_eq!(live.records.len(), 1, "resurrected record back in live view");
        assert!(!live.records[0].tombstoned);
    }

    #[test]
    fn trash_then_list_by_name_then_restore() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "Bank logins").unwrap();

        delete::trash_block_impl(&state, &block.block_uuid_hex).unwrap();

        let trashed = delete::list_trashed_blocks_impl(&state).unwrap();
        let entry = trashed.iter().find(|t| t.block_uuid_hex == block.block_uuid_hex).expect("in trash");
        assert_eq!(entry.block_name, "Bank logins", "listed by decrypted name");

        let restored = delete::restore_block_impl(&state, &block.block_uuid_hex).unwrap();
        assert_eq!(restored.block_uuid_hex, block.block_uuid_hex);

        let trashed_after = delete::list_trashed_blocks_impl(&state).unwrap();
        assert!(trashed_after.iter().all(|t| t.block_uuid_hex != block.block_uuid_hex), "no longer trashed");
    }

    #[test]
    fn restore_into_live_uuid_is_conflict() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "B").unwrap();
        // Restoring a live (never-trashed) block id => TrashEntryNotFound
        // (no trash entry). The conflict variant is exercised at the bridge
        // level; here assert the typed not-found maps through.
        let err = delete::restore_block_impl(&state, &block.block_uuid_hex).unwrap_err();
        assert!(matches!(err, AppError::TrashEntryNotFound { .. }));
    }

    #[test]
    fn tombstone_absent_record_is_record_not_found() {
        let (state, _dir, _pw) = unlocked_session_over_new_vault();
        let block = edit::create_block_impl(&state, "B").unwrap();
        let err = delete::tombstone_record_impl(&state, &block.block_uuid_hex, &hex::encode([0x99u8; 16])).unwrap_err();
        assert!(matches!(err, AppError::RecordNotFound { .. }));
    }
}
```

> Confirm `text_field` / `unlocked_session_over_new_vault` exist (they back the D.1.4 edit tests). If a `restore_block` of a live-and-trashed uuid is needed to hit `BlockRestoreConflict` specifically, that path is covered by the bridge/core tests; the desktop test above asserts the not-found mapping, which is the reachable desktop case for a never-trashed block.

- [ ] **Step 2: Run to confirm failures (commands not found)**

Run: `cd desktop/src-tauri && cargo test --release delete_path 2>&1 | tail -20`
Expected: FAIL — `delete::tombstone_record_impl` not found.

- [ ] **Step 3: Create `commands/delete.rs`**

Create `desktop/src-tauri/src/commands/delete.rs`:

```rust
//! D.1.5 delete/trash IPC commands. Thin `#[tauri::command]` shells + testable
//! `*_impl`. Record tombstone/resurrect go through the bridge native-plaintext
//! primitives; block trash/restore through the existing bridge orchestrators;
//! list_trashed_blocks projects names (decrypted in the bridge, never field
//! values). All errors are typed via `map_ffi_error`.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::{
    list_trashed_blocks as bridge_list_trashed_blocks, resurrect_record as bridge_resurrect_record,
    restore_block as bridge_restore_block, tombstone_record as bridge_tombstone_record,
    trash_block as bridge_trash_block, FfiVaultError,
};

use crate::commands::shared::parse_uuid_16;
use crate::dtos::{BlockSummaryDto, RecordRefDto, TrashedBlockDto};
use crate::errors::{map_ffi_error, AppError};
use crate::session::VaultSession;
use crate::time::now_ms; // use the same now_ms() source edit.rs uses

/// Map a bridge error from a record write to a typed AppError (block/record
/// not-found stay typed; else RecordSaveFailed). Mirrors edit::map_save_error.
fn map_record_delete_error(e: FfiVaultError) -> AppError {
    match e {
        FfiVaultError::BlockNotFound { uuid_hex } => AppError::BlockNotFound { block_uuid_hex: uuid_hex },
        FfiVaultError::RecordNotFound { uuid_hex } => AppError::RecordNotFound { record_uuid_hex: uuid_hex },
        other => {
            tracing::warn!(?other, "record tombstone/resurrect failed");
            AppError::RecordSaveFailed { detail: format!("{other:?}") }
        }
    }
}

#[tauri::command]
pub async fn tombstone_record(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record_uuid_hex: String,
) -> Result<RecordRefDto, AppError> {
    tombstone_record_impl(state.inner(), &block_uuid_hex, &record_uuid_hex)
}

pub fn tombstone_record_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record_uuid_hex: &str,
) -> Result<RecordRefDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let record_uuid = parse_uuid_16(record_uuid_hex)?;
    let session = state.lock().map_err(|e| AppError::Internal { detail: format!("session mutex poisoned: {e}") })?;
    session.with_unlocked(|u| {
        bridge_tombstone_record(&u.identity, &u.manifest, block_uuid, record_uuid, u.device_uuid, now_ms())
            .map_err(map_record_delete_error)?;
        Ok(RecordRefDto { block_uuid_hex: block_uuid_hex.to_string(), record_uuid_hex: record_uuid_hex.to_string() })
    })
}

#[tauri::command]
pub async fn resurrect_record(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    record_uuid_hex: String,
) -> Result<RecordRefDto, AppError> {
    resurrect_record_impl(state.inner(), &block_uuid_hex, &record_uuid_hex)
}

pub fn resurrect_record_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    record_uuid_hex: &str,
) -> Result<RecordRefDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let record_uuid = parse_uuid_16(record_uuid_hex)?;
    let session = state.lock().map_err(|e| AppError::Internal { detail: format!("session mutex poisoned: {e}") })?;
    session.with_unlocked(|u| {
        bridge_resurrect_record(&u.identity, &u.manifest, block_uuid, record_uuid, u.device_uuid, now_ms())
            .map_err(map_record_delete_error)?;
        Ok(RecordRefDto { block_uuid_hex: block_uuid_hex.to_string(), record_uuid_hex: record_uuid_hex.to_string() })
    })
}

#[tauri::command]
pub async fn trash_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<(), AppError> {
    trash_block_impl(state.inner(), &block_uuid_hex)
}

pub fn trash_block_impl(state: &Mutex<VaultSession>, block_uuid_hex: &str) -> Result<(), AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = state.lock().map_err(|e| AppError::Internal { detail: format!("session mutex poisoned: {e}") })?;
    session.with_unlocked(|u| {
        bridge_trash_block(&u.identity, &u.manifest, block_uuid, u.device_uuid, now_ms()).map_err(map_ffi_error)
    })
}

#[tauri::command]
pub async fn restore_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
) -> Result<BlockSummaryDto, AppError> {
    restore_block_impl(state.inner(), &block_uuid_hex)
}

pub fn restore_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
) -> Result<BlockSummaryDto, AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let session = state.lock().map_err(|e| AppError::Internal { detail: format!("session mutex poisoned: {e}") })?;
    session.with_unlocked(|u| {
        bridge_restore_block(&u.identity, &u.manifest, block_uuid, u.device_uuid, now_ms()).map_err(map_ffi_error)?;
        // After restore, the block is live again in the manifest; project its
        // summary the same way list_blocks does (find by uuid in the manifest).
        crate::commands::vault::block_summary_for(&u.manifest, block_uuid)
            .ok_or_else(|| AppError::Internal { detail: "restored block missing from manifest".into() })
    })
}

#[tauri::command]
pub async fn list_trashed_blocks(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<Vec<TrashedBlockDto>, AppError> {
    list_trashed_blocks_impl(state.inner())
}

pub fn list_trashed_blocks_impl(state: &Mutex<VaultSession>) -> Result<Vec<TrashedBlockDto>, AppError> {
    let session = state.lock().map_err(|e| AppError::Internal { detail: format!("session mutex poisoned: {e}") })?;
    session.with_unlocked(|u| {
        let trashed = bridge_list_trashed_blocks(&u.identity, &u.manifest).map_err(map_ffi_error)?;
        Ok(trashed
            .into_iter()
            .map(|t| TrashedBlockDto {
                block_uuid_hex: hex::encode(t.block_uuid),
                block_name: t.block_name,
                tombstoned_at_ms: t.tombstoned_at_ms,
                tombstoned_by_hex: hex::encode(t.tombstoned_by),
            })
            .collect())
    })
}
```

> Two call-outs to confirm against the real code:
> 1. **`now_ms()` source** — `commands/edit.rs` imports it; reuse the same path (likely `crate::time::now_ms` or a `commands::shared` helper). Match it exactly.
> 2. **`block_summary_for`** — `restore_block_impl` needs a `BlockSummaryDto` for the restored block. `commands/vault.rs::list_blocks` already builds `BlockSummaryDto`s from the manifest; extract a `pub(crate) fn block_summary_for(manifest, block_uuid) -> Option<BlockSummaryDto>` there and reuse it (or, if simpler, return `()` from `restore_block` and have the frontend `refreshManifest()` + `listBlocks()` to repaint — but the spec specifies `BlockSummaryDto`, so prefer the accessor). If extracting is non-trivial, build the DTO inline from the manifest `BlockEntry` (block_uuid/block_name/created_at_ms/last_mod_ms) the same way `list_blocks` does.

- [ ] **Step 4: Declare + register the module**

In `desktop/src-tauri/src/commands/mod.rs`, add `pub mod delete;` (alphabetical: after `create`, before `lock`).

In `desktop/src-tauri/src/main.rs`, add to the `tauri::generate_handler![...]` list (after the `edit::*` entries):

```rust
            delete::tombstone_record,
            delete::resurrect_record,
            delete::trash_block,
            delete::restore_block,
            delete::list_trashed_blocks,
```

Add `use secretary_desktop::commands::delete;` if the handler list references modules via `use` (match how `edit` is referenced — it uses `edit::create_block`, so `delete::...` works if `delete` is in scope the same way).

- [ ] **Step 5: Run the L3 tests + full desktop tests**

Run: `cd desktop/src-tauri && cargo test --release delete_path 2>&1 | tail -25`
Expected: PASS (5 tests).

- [ ] **Step 6: Clippy + fmt + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
cargo test --release --workspace 2>&1 | grep "^test result:" | tail -8
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
git add desktop/src-tauri/src/commands/ desktop/src-tauri/src/main.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(d15): delete/trash IPC commands (tombstone/resurrect/trash/restore/list)

Five thin commands + *_impl over the bridge primitives, typed errors via
map_ffi_error / map_record_delete_error. L3 tests over ephemeral tempdir vaults:
tombstone hides-by-default/shows-with-include_deleted, resurrect, trash→list-by-
name→restore, and the typed not-found path.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Frontend — pure `trash.ts` + ipc wrappers + error codes + browse `trash` level

**Files:**
- Create: `desktop/src/lib/trash.ts`
- Modify: `desktop/src/lib/ipc.ts`
- Modify: `desktop/src/lib/errors.ts`
- Modify: `desktop/src/lib/browse.ts`
- Test: `desktop/tests/trash.test.ts`, `tests/ipcTrash.test.ts`, `tests/browseTrash.test.ts`, `tests/errors.test.ts` (modify)

- [ ] **Step 1: Write failing pure-model tests**

Create `desktop/tests/trash.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { sortTrashed, formatTrashedWhen, type TrashedBlockDto } from '../src/lib/trash';

const mk = (hex: string, ms: number): TrashedBlockDto => ({
  blockUuidHex: hex,
  blockName: `b-${hex}`,
  tombstonedAtMs: ms,
  tombstonedByHex: 'dev'
});

describe('sortTrashed', () => {
  it('orders newest-first by tombstonedAtMs', () => {
    const out = sortTrashed([mk('a', 100), mk('b', 300), mk('c', 200)]);
    expect(out.map((t) => t.blockUuidHex)).toEqual(['b', 'c', 'a']);
  });
  it('does not mutate the input array', () => {
    const input = [mk('a', 100), mk('b', 300)];
    sortTrashed(input);
    expect(input.map((t) => t.blockUuidHex)).toEqual(['a', 'b']);
  });
});

describe('formatTrashedWhen', () => {
  it('returns a non-empty label for a timestamp', () => {
    expect(formatTrashedWhen(1_700_000_000_000).length).toBeGreaterThan(0);
  });
});
```

> Re-export `TrashedBlockDto` from `trash.ts` for tests, or import it from `ipc.ts` — pick one and be consistent. Recommended: define the interface in `ipc.ts` (Step 3) and `import type` it in `trash.ts`.

- [ ] **Step 2: Run to confirm failure**

Run: `cd desktop && pnpm test trash 2>&1 | tail -20`
Expected: FAIL — `../src/lib/trash` not found.

- [ ] **Step 3: Implement `trash.ts`, ipc wrappers, error codes, browse level**

Create `desktop/src/lib/trash.ts`:

```typescript
import type { TrashedBlockDto } from './ipc';

/** Order trashed blocks newest-first. Pure (returns a new array). */
export function sortTrashed(dtos: TrashedBlockDto[]): TrashedBlockDto[] {
  return [...dtos].sort((a, b) => b.tombstonedAtMs - a.tombstonedAtMs);
}

/** Human label for when a block was trashed. Reuses the shared date format. */
export function formatTrashedWhen(ms: number): string {
  // Mirror lib/format.ts (formatShortDate) so the trash view matches the rest
  // of the app; import it rather than re-implementing.
  return formatShortDate(ms);
}
```

> Import `formatShortDate` from `./format` at the top (the same helper `RecordRow`/`BlockCard` use). If `formatTrashedWhen` is just a passthrough, the test still pins the contract and a future relative-time tweak has one home.

In `desktop/src/lib/ipc.ts`: add the `includeDeleted` arg to `readBlock`, the `tombstoned` field to `RecordDto`, the `TrashedBlockDto` interface, and the five wrappers:

```typescript
export interface RecordDto {
  recordUuidHex: string;
  recordType: string;
  tags: string[];
  createdAtMs: number;
  lastModMs: number;
  fieldCount: number;
  fields: FieldMetaDto[];
  tombstoned?: boolean;
}

export interface TrashedBlockDto {
  blockUuidHex: string;
  blockName: string;
  tombstonedAtMs: number;
  tombstonedByHex: string;
}

export async function readBlock(blockUuidHex: string, includeDeleted = false): Promise<BlockDetailDto> {
  return call<BlockDetailDto>('read_block', { blockUuidHex, includeDeleted });
}

export async function tombstoneRecord(blockUuidHex: string, recordUuidHex: string): Promise<RecordRefDto> {
  return call<RecordRefDto>('tombstone_record', { blockUuidHex, recordUuidHex });
}

export async function resurrectRecord(blockUuidHex: string, recordUuidHex: string): Promise<RecordRefDto> {
  return call<RecordRefDto>('resurrect_record', { blockUuidHex, recordUuidHex });
}

export async function trashBlock(blockUuidHex: string): Promise<void> {
  return call<void>('trash_block', { blockUuidHex });
}

export async function restoreBlock(blockUuidHex: string): Promise<BlockSummaryDto> {
  return call<BlockSummaryDto>('restore_block', { blockUuidHex });
}

export async function listTrashedBlocks(): Promise<TrashedBlockDto[]> {
  return call<TrashedBlockDto[]>('list_trashed_blocks', {});
}
```

> Replace the existing `readBlock` definition (don't add a second). Existing `readBlock(x)` callers keep working because `includeDeleted` defaults to `false`.

In `desktop/src/lib/errors.ts`: add the two codes to `APP_ERROR_CODES`, the union, and `userMessageFor`:

```typescript
// in APP_ERROR_CODES (before 'internal'):
  'block_restore_conflict',
  'trash_entry_not_found',

// in the AppError union:
  | { code: 'block_restore_conflict'; block_uuid_hex: string }
  | { code: 'trash_entry_not_found'; block_uuid_hex: string }

// in userMessageFor switch:
    case 'block_restore_conflict':
      return {
        title: 'Already restored',
        actionHint: 'A block with this id is already live — it may have been restored elsewhere.'
      };
    case 'trash_entry_not_found':
      return { title: 'Not in trash', actionHint: 'That trashed block is no longer available.' };
```

In `desktop/src/lib/browse.ts`: add the `trash` level + transition:

```typescript
export type BrowseNav =
  | { level: 'blocks' }
  | { level: 'records'; block: BlockSummaryDto }
  | { level: 'fields'; block: BlockSummaryDto; record: RecordDto }
  | { level: 'newBlock' }
  | { level: 'newRecord'; block: BlockSummaryDto }
  | { level: 'editRecord'; block: BlockSummaryDto; record: RecordDto }
  | { level: 'trash' };

export function openTrash(): void {
  store.set({ level: 'trash' });
}
```

And in `back()`, add the pop arm:

```typescript
    if (s.level === 'trash') return { level: 'blocks' };
```

- [ ] **Step 4: Write + run the ipc + browse + error tests**

Create `desktop/tests/ipcTrash.test.ts` (mirror `ipcEdit.test.ts`'s `vi.hoisted` + `vi.mock('@tauri-apps/api/core')` pattern):

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));

import { readBlock, tombstoneRecord, resurrectRecord, trashBlock, restoreBlock, listTrashedBlocks } from '../src/lib/ipc';

describe('trash/delete IPC wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('readBlock forwards includeDeleted=false by default', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'B', records: [] });
    await readBlock('ab');
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false });
  });

  it('readBlock forwards includeDeleted=true when asked', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'B', records: [] });
    await readBlock('ab', true);
    expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: true });
  });

  it('tombstoneRecord forwards both hex ids', async () => {
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', recordUuidHex: 'cd' });
    await tombstoneRecord('ab', 'cd');
    expect(invokeMock).toHaveBeenCalledWith('tombstone_record', { blockUuidHex: 'ab', recordUuidHex: 'cd' });
  });

  it('listTrashedBlocks invokes with no args', async () => {
    invokeMock.mockResolvedValueOnce([]);
    await listTrashedBlocks();
    expect(invokeMock).toHaveBeenCalledWith('list_trashed_blocks', {});
  });

  // + resurrectRecord, trashBlock, restoreBlock analogous
});
```

Create `desktop/tests/browseTrash.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { get } from 'svelte/store';
import { browseNav, openTrash, back } from '../src/lib/browse';

describe('browse trash level', () => {
  it('openTrash sets level trash; back pops to blocks', () => {
    openTrash();
    expect(get(browseNav).level).toBe('trash');
    back();
    expect(get(browseNav).level).toBe('blocks');
  });
});
```

Add two cases to `desktop/tests/errors.test.ts` for the new codes (mirror the existing message assertions).

Run: `cd desktop && pnpm test trash browseTrash ipcTrash errors 2>&1 | tail -25`
Expected: PASS.

- [ ] **Step 5: typecheck + commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete/desktop
pnpm typecheck && pnpm lint
cd /Users/hherb/src/secretary/.worktrees/d15-delete
git add desktop/src/lib/ desktop/tests/trash.test.ts desktop/tests/ipcTrash.test.ts desktop/tests/browseTrash.test.ts desktop/tests/errors.test.ts
git commit -m "feat(d15): frontend trash model + ipc wrappers + error codes + browse level

Pure trash.ts (sortTrashed/formatTrashedWhen); 5 ipc wrappers + readBlock
includeDeleted arg + RecordDto.tombstoned + TrashedBlockDto; two new error
codes/messages; BrowseNav 'trash' level + openTrash. Vitest covers each.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Frontend — components (ConfirmDialog, TrashView, RecordList/RecordRow/BlockCard mods) + Vault routing + styles

**Files:**
- Create: `desktop/src/components/delete/ConfirmDialog.svelte`, `TrashView.svelte`, `TrashedBlockRow.svelte`
- Modify: `desktop/src/components/RecordList.svelte`, `RecordRow.svelte`, `BlockCard.svelte`, `desktop/src/routes/Vault.svelte`, `desktop/src/theme.css`
- Test: `desktop/tests/ConfirmDialog.test.ts`, `TrashView.test.ts`, `RecordListDelete.test.ts`

- [ ] **Step 1: Write failing component tests**

Create `desktop/tests/ConfirmDialog.test.ts` (mirror `RecordEditor.test.ts`'s render pattern):

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import ConfirmDialog from '../src/components/delete/ConfirmDialog.svelte';

describe('ConfirmDialog', () => {
  it('fires onConfirm when the confirm button is clicked', async () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const { getByRole } = render(ConfirmDialog, {
      props: { title: 'Delete this record?', body: 'It can be restored.', confirmLabel: 'Delete', onConfirm, onCancel }
    });
    await fireEvent.click(getByRole('button', { name: 'Delete' }));
    expect(onConfirm).toHaveBeenCalledOnce();
  });

  it('fires onCancel when the cancel button is clicked', async () => {
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    const { getByRole } = render(ConfirmDialog, {
      props: { title: 't', body: 'b', confirmLabel: 'Delete', onConfirm, onCancel }
    });
    await fireEvent.click(getByRole('button', { name: 'Cancel' }));
    expect(onCancel).toHaveBeenCalledOnce();
  });
});
```

Create `desktop/tests/TrashView.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor, fireEvent } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import TrashView from '../src/components/delete/TrashView.svelte';

describe('TrashView', () => {
  beforeEach(() => invokeMock.mockReset());

  it('lists trashed blocks by name', async () => {
    invokeMock.mockResolvedValueOnce([
      { blockUuidHex: 'ab', blockName: 'Bank logins', tombstonedAtMs: 2, tombstonedByHex: 'd' }
    ]);
    const { getByText } = render(TrashView, { props: {} });
    await waitFor(() => expect(getByText('Bank logins')).toBeTruthy());
  });

  it('shows empty state when nothing is trashed', async () => {
    invokeMock.mockResolvedValueOnce([]);
    const { getByText } = render(TrashView, { props: {} });
    await waitFor(() => expect(getByText(/empty/i)).toBeTruthy());
  });
});
```

Create `desktop/tests/RecordListDelete.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import RecordList from '../src/components/RecordList.svelte';

const block = { blockUuidHex: 'ab', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 1 };

describe('RecordList show-deleted toggle', () => {
  beforeEach(() => invokeMock.mockReset());

  it('re-reads with includeDeleted=true when the toggle is turned on', async () => {
    // initial mount read (live only)
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Logins', records: [] });
    const { getByLabelText } = render(RecordList, { props: { block } });
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: false }));

    // toggle on → re-read with includeDeleted=true
    invokeMock.mockResolvedValueOnce({ blockUuidHex: 'ab', blockName: 'Logins', records: [] });
    await fireEvent.click(getByLabelText(/show deleted/i));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('read_block', { blockUuidHex: 'ab', includeDeleted: true }));
  });
});
```

- [ ] **Step 2: Run to confirm failures**

Run: `cd desktop && pnpm test ConfirmDialog TrashView RecordListDelete 2>&1 | tail -20`
Expected: FAIL — components not found / toggle not present.

- [ ] **Step 3: Implement `ConfirmDialog.svelte`**

Create `desktop/src/components/delete/ConfirmDialog.svelte` (modeled on `SettingsDialog`; uses a native `<dialog>` for backdrop + Esc):

```svelte
<script lang="ts">
  type Props = {
    title: string;
    body: string;
    confirmLabel: string;
    onConfirm: () => void;
    onCancel: () => void;
  };
  let { title, body, confirmLabel, onConfirm, onCancel }: Props = $props();

  let dialog = $state<HTMLDialogElement | null>(null);
  $effect(() => {
    dialog?.showModal();
  });
</script>

<dialog
  bind:this={dialog}
  class="confirm-dialog"
  onclose={() => onCancel()}
  oncancel={(e) => { e.preventDefault(); onCancel(); }}
>
  <h2 class="confirm-dialog__title">{title}</h2>
  <p class="confirm-dialog__body">{body}</p>
  <div class="confirm-dialog__actions">
    <button type="button" class="confirm-dialog__button" onclick={() => onCancel()}>Cancel</button>
    <button type="button" class="confirm-dialog__button confirm-dialog__button--danger" onclick={() => onConfirm()}>
      {confirmLabel}
    </button>
  </div>
</dialog>
```

- [ ] **Step 4: Implement `TrashedBlockRow.svelte` + `TrashView.svelte`**

Create `desktop/src/components/delete/TrashedBlockRow.svelte`:

```svelte
<script lang="ts">
  import type { TrashedBlockDto } from '../../lib/ipc';
  import { formatTrashedWhen } from '../../lib/trash';

  type Props = { entry: TrashedBlockDto; onRestore: (entry: TrashedBlockDto) => void };
  let { entry, onRestore }: Props = $props();
</script>

<div class="trashed-row">
  <span class="trashed-row__name">{entry.blockName}</span>
  <span class="trashed-row__when">trashed {formatTrashedWhen(entry.tombstonedAtMs)}</span>
  <button type="button" class="trashed-row__restore" onclick={() => onRestore(entry)}>Restore</button>
</div>
```

Create `desktop/src/components/delete/TrashView.svelte`:

```svelte
<script lang="ts">
  import { listTrashedBlocks, restoreBlock, isAppError, type TrashedBlockDto } from '../../lib/ipc';
  import { sortTrashed } from '../../lib/trash';
  import { back } from '../../lib/browse';
  import { refreshManifest } from '../../lib/stores';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import TrashedBlockRow from './TrashedBlockRow.svelte';

  let entries = $state<TrashedBlockDto[] | null>(null);
  let error = $state<AppError | null>(null);

  async function load() {
    entries = null;
    error = null;
    try {
      entries = sortTrashed(await listTrashedBlocks());
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
  $effect(() => { load(); });

  async function onRestore(entry: TrashedBlockDto) {
    try {
      await restoreBlock(entry.blockUuidHex);
      await refreshManifest();
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
</script>

<section class="trash-view">
  <button type="button" class="trash-view__back" onclick={() => back()}>← Trash</button>
  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="trash-view__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if entries === null}
    <p class="trash-view__loading">Loading…</p>
  {:else if entries.length === 0}
    <p class="trash-view__empty">Trash is empty.</p>
  {:else}
    {#each entries as entry (entry.blockUuidHex)}
      <TrashedBlockRow {entry} {onRestore} />
    {/each}
  {/if}
</section>
```

- [ ] **Step 5: Modify `RecordRow.svelte`, `RecordList.svelte`, `BlockCard.svelte`**

`RecordRow.svelte` — add a `deleted` prop + Delete/Restore actions (dispatched up). Keep the row click for live rows only:

```svelte
<script lang="ts">
  import type { RecordDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';

  type Props = {
    record: RecordDto;
    onClick: (record: RecordDto) => void;
    onDelete?: (record: RecordDto) => void;
    onRestore?: (record: RecordDto) => void;
  };
  let { record, onClick, onDelete, onRestore }: Props = $props();
  let deleted = $derived(record.tombstoned === true);
  let countLabel = $derived(`${record.fieldCount} field${record.fieldCount === 1 ? '' : 's'}`);
</script>

<div class="record-row-wrap" class:record-row--deleted={deleted}>
  <button type="button" class="record-row" disabled={deleted} onclick={() => onClick(record)}>
    <span class="record-row__type">{record.recordType}</span>
    {#each record.tags as tag (tag)}<span class="record-row__tag">{tag}</span>{/each}
    <span class="record-row__meta">{countLabel} · modified {formatShortDate(record.lastModMs)}</span>
  </button>
  {#if deleted && onRestore}
    <button type="button" class="record-row__restore" onclick={() => onRestore(record)}>Restore</button>
  {:else if !deleted && onDelete}
    <button type="button" class="record-row__delete" aria-label="Delete record" onclick={() => onDelete(record)}>Delete</button>
  {/if}
</div>
```

`RecordList.svelte` — add the toggle, thread `includeDeleted`, wire delete (confirm) + resurrect:

```svelte
<script lang="ts">
  import { readBlock, tombstoneRecord, resurrectRecord, isAppError, type BlockSummaryDto, type RecordDto } from '../lib/ipc';
  import { openRecord, openNewRecord, back } from '../lib/browse';
  import { userMessageFor, type AppError } from '../lib/errors';
  import RecordRow from './RecordRow.svelte';
  import ConfirmDialog from './delete/ConfirmDialog.svelte';

  type Props = { block: BlockSummaryDto };
  let { block }: Props = $props();

  let records = $state<RecordDto[] | null>(null);
  let error = $state<AppError | null>(null);
  let showDeleted = $state(false);
  let pendingDelete = $state<RecordDto | null>(null);

  async function load() {
    records = null;
    error = null;
    try {
      const dto = await readBlock(block.blockUuidHex, showDeleted);
      records = dto.records;
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
  // Re-load whenever the block or the showDeleted toggle changes.
  $effect(() => {
    void block.blockUuidHex;
    void showDeleted;
    load();
  });

  async function confirmDelete() {
    const rec = pendingDelete;
    pendingDelete = null;
    if (!rec) return;
    try {
      await tombstoneRecord(block.blockUuidHex, rec.recordUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  async function onRestore(rec: RecordDto) {
    try {
      await resurrectRecord(block.blockUuidHex, rec.recordUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
</script>

<section class="record-list">
  <button type="button" class="record-list__back" onclick={() => back()}>← {block.blockName}</button>
  <button type="button" class="record-list__add" onclick={() => openNewRecord(block)}>+ Add record</button>
  <label class="record-list__show-deleted">
    <input type="checkbox" bind:checked={showDeleted} /> Show deleted
  </label>

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="record-list__error" role="alert">{msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}</p>
  {:else if records === null}
    <p class="record-list__loading">Loading…</p>
  {:else if records.length === 0}
    <p class="record-list__empty">No records.</p>
  {:else}
    {#each records as record (record.recordUuidHex)}
      <RecordRow {record} onClick={openRecord} onDelete={(r) => (pendingDelete = r)} {onRestore} />
    {/each}
  {/if}
</section>

{#if pendingDelete}
  <ConfirmDialog
    title="Delete this record?"
    body="It's removed from view but can be restored from “Show deleted”."
    confirmLabel="Delete"
    onConfirm={confirmDelete}
    onCancel={() => (pendingDelete = null)}
  />
{/if}
```

> `$effect` reads `block.blockUuidHex` and `showDeleted` so it re-runs on either change. The `void` reads register the dependencies explicitly (svelte-check may warn `state_referenced_locally` — if so, document it inline as intentional, matching the three accepted warnings noted in the D.1.4 handoff).

`BlockCard.svelte` — add a Trash action (dispatched up; confirm handled by Vault):

```svelte
<script lang="ts">
  import type { BlockSummaryDto } from '../lib/ipc';
  import { formatShortDate } from '../lib/format';

  type Props = {
    block: BlockSummaryDto;
    onClick: (block: BlockSummaryDto) => void;
    onTrash?: (block: BlockSummaryDto) => void;
  };
  let { block, onClick, onTrash }: Props = $props();
</script>

<div class="block-card-wrap">
  <button type="button" class="block-card" onclick={() => onClick(block)}>
    <div class="block-card__name">{block.blockName}</div>
    <div class="block-card__meta">modified {formatShortDate(block.lastModifiedMs)}</div>
  </button>
  {#if onTrash}
    <button type="button" class="block-card__trash" aria-label="Trash block" onclick={() => onTrash(block)}>Trash</button>
  {/if}
</div>
```

- [ ] **Step 6: Wire `Vault.svelte` — trash pane, Trash entry, block trash confirm**

In `desktop/src/routes/Vault.svelte`: import `openTrash`, `TrashView`, `ConfirmDialog`, `trashBlock`, `refreshManifest`; add a "🗑 Trash" button on the blocks pane; pass `onTrash` to `BlockCard`; host a block-trash confirm; add the `trash` routing arm:

```svelte
<!-- blocks pane: add the Trash entry + onTrash on each card -->
{#if $browseNav.level === 'blocks'}
  <button type="button" class="vault__new-block" onclick={() => openNewBlock()}>+ New block</button>
  <button type="button" class="vault__trash-entry" onclick={() => openTrash()}>🗑 Trash</button>
  <div class="vault__block-count">{manifest.blockCount} block{manifest.blockCount === 1 ? '' : 's'}</div>
  <div class="vault__block-list">
    {#each manifest.blockSummaries as block (block.blockUuidHex)}
      <BlockCard {block} onClick={openBlock} onTrash={(b) => (pendingTrash = b)} />
    {/each}
  </div>
{:else if $browseNav.level === 'records'}
  <RecordList block={$browseNav.block} />
{:else if $browseNav.level === 'fields'}
  <FieldViewer block={$browseNav.block} record={$browseNav.record} />
{:else if $browseNav.level === 'trash'}
  <TrashView />
{:else if $browseNav.level === 'newBlock'}
  <!-- unchanged -->
{:else if $browseNav.level === 'newRecord'}
  <!-- unchanged -->
{:else}
  <!-- editRecord unchanged -->
{/if}

{#if pendingTrash}
  <ConfirmDialog
    title="Move this block to Trash?"
    body="You can restore it from the Trash view."
    confirmLabel="Trash"
    onConfirm={confirmTrash}
    onCancel={() => (pendingTrash = null)}
  />
{/if}
```

In the `<script>`, add the state + handler:

```typescript
  let pendingTrash = $state<BlockSummaryDto | null>(null);
  async function confirmTrash() {
    const b = pendingTrash;
    pendingTrash = null;
    if (!b) return;
    try {
      await trashBlock(b.blockUuidHex);
      await refreshManifest();
    } catch (e) {
      // surface via the existing toast/error channel Vault uses
    }
  }
```

> Match Vault.svelte's existing error-surfacing pattern (it already shows toasts/errors for other flows) instead of swallowing — fill the catch with the same channel the create/edit flows use.

- [ ] **Step 7: Add styles to `theme.css`**

Append to `desktop/src/theme.css` (mirror the `.settings-dialog`, `.block-card`, `.record-row` patterns; use existing tokens):

```css
/* D.1.5 confirm dialog (mirrors .settings-dialog) */
.confirm-dialog { border: 1px solid var(--color-border); border-radius: var(--radius-lg); background: var(--color-bg-elevated); color: var(--color-text); padding: var(--space-5); min-width: 360px; box-shadow: var(--shadow-lg); }
.confirm-dialog::backdrop { background: rgba(0, 0, 0, 0.4); }
.confirm-dialog__title { margin: 0 0 var(--space-2); font-size: var(--font-size-lg); }
.confirm-dialog__body { margin: 0; color: var(--color-text-muted); }
.confirm-dialog__actions { margin-top: var(--space-5); display: flex; justify-content: flex-end; gap: var(--space-2); }
.confirm-dialog__button { padding: var(--space-2) var(--space-4); border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-bg-elevated); color: var(--color-text); cursor: pointer; font-size: var(--font-size-sm); }
.confirm-dialog__button--danger { background: var(--color-danger, #c0392b); border-color: var(--color-danger, #c0392b); color: white; }

/* D.1.5 trash view + trashed rows */
.trash-view { display: flex; flex-direction: column; gap: var(--space-2); }
.trashed-row { display: flex; align-items: baseline; gap: var(--space-2); padding: var(--space-3) var(--space-4); border: 1px solid var(--color-border); border-radius: var(--radius-md); background: var(--color-bg-elevated); }
.trashed-row__name { font-weight: 600; }
.trashed-row__when { margin-left: auto; font-size: var(--font-size-xs); color: var(--color-text-muted); }
.trashed-row__restore, .record-row__restore, .record-row__delete, .block-card__trash { padding: var(--space-1) var(--space-3); border: 1px solid var(--color-border); border-radius: var(--radius-sm); background: var(--color-bg-elevated); color: var(--color-text); cursor: pointer; font-size: var(--font-size-xs); }

/* D.1.5 tombstoned record row */
.record-row--deleted { opacity: 0.55; }
.record-row-wrap, .block-card-wrap { display: flex; align-items: center; gap: var(--space-2); }
.record-row-wrap .record-row, .block-card-wrap .block-card { flex: 1; }
```

> If a `--color-danger` token doesn't exist, add one to the `:root`/dark blocks alongside the existing color tokens, or reuse an existing accent. Confirm the token names against the top of `theme.css`.

- [ ] **Step 8: Run the component tests + the full frontend gauntlet**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete/desktop
pnpm test 2>&1 | grep -E "Test Files|Tests " | tail -4
pnpm typecheck
pnpm svelte-check 2>&1 | tail -5
pnpm lint
```
Expected: all new tests pass; typecheck clean; svelte-check 0 errors (document any intentional `state_referenced_locally` warning); lint clean.

- [ ] **Step 9: Commit**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
git add desktop/src/components/ desktop/src/routes/Vault.svelte desktop/src/theme.css desktop/tests/ConfirmDialog.test.ts desktop/tests/TrashView.test.ts desktop/tests/RecordListDelete.test.ts
git commit -m "feat(d15): delete/trash UI — confirm dialog, trash view, show-deleted, actions

ConfirmDialog (shared), TrashView + TrashedBlockRow, RecordList show-deleted
toggle (re-reads with includeDeleted) + per-row delete/restore, BlockCard trash
action, Vault trash pane + entry. Component tests cover confirm, trash list,
empty state, and the toggle re-read.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 8: Ship — README + ROADMAP + handoff + full gauntlet

**Files:**
- Modify: `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-05-31-d15-delete-trash-shipped.md`
- Modify: `NEXT_SESSION.md` (retarget symlink)

- [ ] **Step 1: Run the full automated gauntlet on the branch**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust totals → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -2
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -2
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -3
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -3
cd desktop && pnpm test 2>&1 | grep -E "Test Files|Tests " | tail -3 && pnpm typecheck && pnpm svelte-check 2>&1 | tail -3 && pnpm lint && cd ..
```
Expected: Rust PASSED rises above the 1102 baseline; clippy/fmt clean; conformance + spec-freshness PASS; swift/kotlin 22/22 (record if toolchains absent); Vitest rises above 303; typecheck/svelte-check/lint clean. **No conformance-KAT regeneration expected** (tombstone/resurrect use existing wire fields) — if `conformance.py` flags a diff, STOP and investigate (it would mean an unintended format change).

- [ ] **Step 2: Update README + ROADMAP**

`README.md` — advance the D-row note to "D.1.5 (delete/trash) shipped; D.1.6 (share) next" (brief, per the README style — dot points, no test-count walls).

`ROADMAP.md` — mark D.1.5 ✅; add D.1.6 ⏳ (share + contacts subsystem), noting share was split out of the original D.1.5 bundle.

- [ ] **Step 3: Author the handoff + retarget the symlink**

Author `docs/handoffs/2026-05-31-d15-delete-trash-shipped.md` capturing: (1) what shipped + commit SHAs, (2) D.1.6 (share) next with acceptance criteria + the contacts-subsystem note, (3) open decisions/risks (manual smoke gate; #167 deferred-FFI now also covers tombstone/resurrect/list_trashed; carry-forwards #153/#154/#161/#162/#164), (4) exact resume commands. Then:

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
ln -snf docs/handoffs/2026-05-31-d15-delete-trash-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md   # shows the -> target
head -3 NEXT_SESSION.md  # reads the handoff transparently
git add README.md ROADMAP.md docs/handoffs/2026-05-31-d15-delete-trash-shipped.md NEXT_SESSION.md
git commit -m "ship(d15): D.1.5 delete/trash complete — README/ROADMAP/handoff

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Push + open the PR (manual GUI smoke is the pre-merge gate)**

```bash
cd /Users/hherb/src/secretary/.worktrees/d15-delete
git push -u origin feature/d15-delete
gh pr create --base main --title "D.1.5 — delete: record tombstone/resurrect + block trash/restore" --body "<summary + the §15 manual smoke checklist + automated gauntlet results>"
```

Manual GUI smoke (spec §15), against a **tempdir vault copy** ([[feedback_smoke_test_temp_copy_golden_vault]]): unlock → delete a record (confirm) → it disappears → "Show deleted" → it appears greyed → Restore → back in live list → trash a block (confirm) → leaves blocks list → "🗑 Trash" → appears by name → Restore → back in blocks list → reopen vault, confirm persistence. This is the user's pre-merge gate.

---

## Self-Review

**Spec coverage (§ → task):**
- §1/§6.1 tombstone, §6.2 resurrect → Task 1. §6.5 list_trashed_blocks → Task 2. §6.3 trash_block / §6.4 restore_block → bridge already exists; wired in Task 5.
- §3 `include_deleted` gate, §5 RecordDto.tombstoned + reveal projection → Task 4. §9 errors → Task 3.
- §5 TrashedBlockDto → Task 4. Five IPC commands → Task 5.
- §5/§7 frontend model + nav + ipc + errors → Task 6. §7/§8/§12 components + Vault routing + styles → Task 7.
- §10 testing distributed across tasks (L1 bridge in 1/2; L1 desktop in 3/4; L3 in 5; L2 in 6/7). §14 docs + §15 acceptance → Task 8.

**Placeholder scan:** No "TBD"/"implement later". The two `// MOVE here verbatim` blocks (Task 2 Step 1 extraction; Task 1 Step 6 keystone) reference an exact existing function to copy from, with the invariant to preserve named — these are extraction/clone instructions, not unfilled gaps.

**Type consistency:** `RecordRefDto`/`BlockSummaryDto`/`TrashedBlockDto` names match across bridge (`TrashedBlock`) → desktop DTO (`TrashedBlockDto`) → TS (`TrashedBlockDto`). `include_deleted` (Rust snake) ↔ `includeDeleted` (TS camel, via serde rename) consistent. `tombstone_record`/`resurrect_record`/`trash_block`/`restore_block`/`list_trashed_blocks` names identical bridge↔desktop↔command-registration. `map_ffi_error` (block trash/restore) vs `map_record_delete_error` (record tombstone/resurrect) used consistently per call site.

**Open confirmations for the implementer (flagged inline, not gaps):** (a) `now_ms()` import path (match `commands/edit.rs`); (b) `block_summary_for` accessor extraction in `commands/vault.rs`; (c) `uuid_hyphenated` visibility; (d) `--color-danger` token existence; (e) exact `open_writable_golden_001`/`text_field` helper names.
