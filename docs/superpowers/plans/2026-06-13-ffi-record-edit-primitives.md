# FFI record-edit primitives projection — Implementation Plan (Slice 1)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Project the Rust bridge's four CRDT-correct record-edit primitives (`append_record`, `edit_record`, `tombstone_record`, `resurrect_record`) onto the uniffi (Swift) and pyo3 (Python) bindings, with smoke + pytest coverage. No UI.

**Architecture:** Pure FFI-glue projection mirroring the existing `save_block`/`trash_block` pattern exactly. Each binding gets a new value type `RecordContent` (reusing the existing `FieldInput`/`FieldInputValue`) and four thin namespace functions that length-validate the uuid args, convert to the bridge type, call the bridge primitive, and map `FfiVaultError` to the binding's error type. No new `FfiVaultError` variants (`BlockNotFound`/`RecordNotFound` already exist). No on-disk-format / Rust-core change.

**Tech Stack:** Rust (uniffi 0.31 UDL, PyO3 0.29), Swift + Kotlin smoke runners, pytest via `uv`.

**Spec:** [docs/superpowers/specs/2026-06-13-ffi-record-edit-primitives-design.md](../specs/2026-06-13-ffi-record-edit-primitives-design.md)

**Working dir:** `/Users/hherb/src/secretary/.worktrees/ffi-record-edit-primitives` on branch `feature/ffi-record-edit-primitives`. Verify before each path-sensitive command: `pwd && git branch --show-current`.

**Bridge reference (already exists — do NOT modify):**
- `append_record(identity, manifest, block_uuid:[u8;16], record_uuid:[u8;16], content: RecordContent, device_uuid:[u8;16], now_ms:u64) -> Result<(), FfiVaultError>`
- `edit_record(...)` — same shape as `append_record`.
- `tombstone_record(identity, manifest, block_uuid:[u8;16], record_uuid:[u8;16], device_uuid:[u8;16], now_ms:u64) -> Result<(), FfiVaultError>`
- `resurrect_record(...)` — same shape as `tombstone_record`.
- `secretary_ffi_bridge::RecordContent { record_type: String, tags: Vec<String>, fields: Vec<FieldInput> }` — re-exported from `secretary_ffi_bridge` (lib.rs:136).

---

## Task 1: uniffi — `RecordContent` value type + UDL dictionary

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/src/wrappers/save.rs` (append `RecordContent` struct)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs:77` (re-export `RecordContent`)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (add `dictionary RecordContent`)

- [ ] **Step 1: Add the `RecordContent` Rust struct to `wrappers/save.rs`**

Append to `ffi/secretary-ffi-uniffi/src/wrappers/save.rs` (after the `BlockInput` struct, ~line 81):

```rust
/// The editable delta for one record on an edit/append. (record-edit slice)
///
/// Mirrors [`secretary_ffi_bridge::RecordContent`]: it carries only the
/// editable part — `record_type`, `tags`, `fields`. The `record_uuid`,
/// `created_at_ms`, and every `unknown` map are owned by the bridge edit
/// primitives (preserve-on-edit / mint-on-add), NOT supplied here. Reuses
/// the same zeroize-typed [`FieldInput`] / [`FieldInputValue`] as the
/// `save_block` path, so a `RecordContent` zeroizes its secrets on drop.
pub struct RecordContent {
    /// Open-ended record-type discriminator (e.g. "login"). Empty allowed.
    pub record_type: String,
    /// Cross-cutting tags.
    pub tags: Vec<String>,
    /// Ordered list of fields (name + zeroize-typed text/bytes value).
    pub fields: Vec<FieldInput>,
}
```

- [ ] **Step 2: Re-export `RecordContent` at crate root**

In `ffi/secretary-ffi-uniffi/src/lib.rs`, modify line 77:

```rust
pub use wrappers::save::{BlockInput, FieldInput, FieldInputValue, RecordContent, RecordInput};
```

- [ ] **Step 3: Add the UDL `dictionary RecordContent`**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, after the `dictionary BlockInput { ... };` block (~line 455), add:

```
/// The editable delta for one record on append/edit. (record-edit slice)
/// `record_uuid` / `created_at_ms` / `unknown` are NOT here — the edit
/// primitives own those (preserve-on-edit / mint-on-add). Reuses the
/// same zeroize-typed FieldInput / FieldInputValue as save_block.
dictionary RecordContent {
    /// Open-ended record-type discriminator (e.g. "login"). Empty allowed.
    string record_type;
    /// Cross-cutting tags.
    sequence<string> tags;
    /// Ordered list of fields.
    sequence<FieldInput> fields;
};
```

- [ ] **Step 4: Build to verify the type + UDL agree**

Run: `cd /Users/hherb/src/secretary/.worktrees/ffi-record-edit-primitives && cargo build --release -p secretary-ffi-uniffi`
Expected: BUILD SUCCEEDS. (No behavior yet — `RecordContent` is consumed in Task 2. uniffi only fails if a UDL dictionary has no matching crate-root Rust struct of the same name/shape; this step proves they match.)

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/wrappers/save.rs ffi/secretary-ffi-uniffi/src/lib.rs ffi/secretary-ffi-uniffi/src/secretary.udl
git commit -m "feat(ffi-uniffi): RecordContent value type + UDL dictionary"
```

---

## Task 2: uniffi — four record-edit namespace functions

**Files:**
- Create: `ffi/secretary-ffi-uniffi/src/namespace/record_edit.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/namespace/mod.rs` (add `mod record_edit; pub use record_edit::*;` and make `uuid_from_vec` reachable)
- Modify: `ffi/secretary-ffi-uniffi/src/lib.rs:68-73` (re-export the 4 fns)
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl` (declare the 4 fns)

- [ ] **Step 1: Create `namespace/record_edit.rs` with the four fns + the converter**

Create `ffi/secretary-ffi-uniffi/src/namespace/record_edit.rs`:

```rust
//! uniffi namespace projection of the bridge's record-edit primitives.
//!
//! Four thin wrappers over `secretary_ffi_bridge::{append_record,
//! edit_record, tombstone_record, resurrect_record}`. Each length-validates
//! its uuid arguments (16 bytes each → otherwise [`VaultError::InvalidArgument`],
//! mirroring `save_block`/`trash_block`), converts the flat `RecordContent`
//! into the bridge type (wrapping payloads in zeroize-on-drop carriers), and
//! maps `FfiVaultError` via the existing `From` impl on [`VaultError`].
//!
//! The bridge primitives own all CRDT semantics (preserve per-field clocks
//! on unchanged fields, freeze `tombstoned_at_ms`, carry forward `unknown`
//! maps); this layer adds none of its own.

use super::uuid_from_vec;
use crate::errors::VaultError;
use crate::wrappers::identity::UnlockedIdentity;
use crate::wrappers::vault::OpenVaultManifest;

/// Convert a uniffi-side [`crate::RecordContent`] into a bridge-side
/// [`secretary_ffi_bridge::RecordContent`], wrapping each field payload in
/// the appropriate zeroize-on-drop secret carrier (`SecretString` /
/// `SecretBytes`).
fn convert_record_content(c: crate::RecordContent) -> secretary_ffi_bridge::RecordContent {
    use secretary_core::crypto::secret::{SecretBytes, SecretString};

    let fields = c
        .fields
        .into_iter()
        .map(|f| secretary_ffi_bridge::FieldInput {
            name: f.name,
            value: match f.value {
                crate::FieldInputValue::Text { text } => {
                    secretary_ffi_bridge::FieldInputValue::Text(SecretString::from(text))
                }
                crate::FieldInputValue::Bytes { data } => {
                    secretary_ffi_bridge::FieldInputValue::Bytes(SecretBytes::from(data))
                }
            },
        })
        .collect();

    secretary_ffi_bridge::RecordContent {
        record_type: c.record_type,
        tags: c.tags,
        fields,
    }
}

/// Append a new record to an existing block. (record-edit slice)
///
/// `block_uuid`, `record_uuid`, and `device_uuid` must each be exactly 16
/// bytes; otherwise returns [`VaultError::InvalidArgument`]. Routes to
/// [`secretary_ffi_bridge::append_record`], which preserves every sibling
/// record and all `unknown` maps natively.
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::BlockNotFound`] — `block_uuid` not in the manifest.
/// - [`VaultError::CorruptVault`] — decrypt failure / wiped handle.
/// - save-tail surface ([`VaultError::FolderInvalid`] / [`VaultError::SaveCryptoFailure`]).
pub fn append_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: crate::RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    let content = convert_record_content(content);
    secretary_ffi_bridge::append_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        content,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Replace one live record's editable part (type / tags / fields),
/// preserving its `record_uuid`, `created_at_ms`, `tombstoned_at_ms`, and
/// every `unknown` map; untouched fields keep their prior clock /
/// `device_uuid`. (record-edit slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::RecordNotFound`] — no live record with this UUID in the block.
/// - [`VaultError::BlockNotFound`] / [`VaultError::CorruptVault`] / save-tail surface.
pub fn edit_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: crate::RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    let content = convert_record_content(content);
    secretary_ffi_bridge::edit_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        content,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Soft-delete one live record (set tombstone + death clock). (record-edit slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::RecordNotFound`] — no LIVE record with this UUID.
/// - [`VaultError::BlockNotFound`] / [`VaultError::CorruptVault`] / save-tail surface.
pub fn tombstone_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::tombstone_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}

/// Resurrect one tombstoned record (clear tombstone, preserve
/// `tombstoned_at_ms`). (record-edit slice)
///
/// # Errors
///
/// - [`VaultError::InvalidArgument`] — wrong-length uuid.
/// - [`VaultError::RecordNotFound`] — no TOMBSTONED record with this UUID.
/// - [`VaultError::BlockNotFound`] / [`VaultError::CorruptVault`] / save-tail surface.
pub fn resurrect_record(
    identity: std::sync::Arc<UnlockedIdentity>,
    manifest: std::sync::Arc<OpenVaultManifest>,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> Result<(), VaultError> {
    let block_uuid = uuid_from_vec(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_from_vec(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_from_vec(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::resurrect_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(VaultError::from)
}
```

> Note: confirm the `UnlockedIdentity`/`OpenVaultManifest` import paths against `namespace/mod.rs` lines 8-11 (it imports `crate::wrappers::identity::UnlockedIdentity` and `crate::wrappers::vault::OpenVaultManifest`). The `.0` field access mirrors `save_block` (`&identity.0`, `&manifest.0`).

- [ ] **Step 2: Wire the submodule into `namespace/mod.rs`**

In `ffi/secretary-ffi-uniffi/src/namespace/mod.rs`, after the existing `mod sync; pub use sync::{...};` (lines 14-15), add:

```rust
mod record_edit;
pub use record_edit::{append_record, edit_record, resurrect_record, tombstone_record};
```

Then ensure `uuid_from_vec` is reachable from the submodule: it is already declared `pub(super)` (line 531), so `use super::uuid_from_vec;` in `record_edit.rs` resolves. No change needed if it is `pub(super)`; if the build complains it is private, widen it to `pub(super)`.

- [ ] **Step 3: Re-export the 4 fns at crate root**

In `ffi/secretary-ffi-uniffi/src/lib.rs`, extend the `pub use namespace::{ ... }` block (lines 68-73) to include the four names (keep alphabetical-ish ordering consistent with the file):

```rust
pub use namespace::{
    add_device_slot, append_record, create_vault, edit_record, open_vault_with_password,
    open_vault_with_recovery, open_with_device_secret, open_with_password, open_with_recovery,
    read_block, remove_device_slot, restore_block, resurrect_record, save_block, share_block,
    sync_commit_decisions, sync_status, sync_vault, tombstone_record, trash_block,
};
```

- [ ] **Step 4: Declare the 4 fns in the UDL**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, inside the `namespace secretary { ... }` block, after the `restore_block(...)` declaration (~line 128), add:

```
    /// Append a new record to an existing block. (record-edit slice)
    /// `block_uuid` / `record_uuid` / `device_uuid` must each be 16 bytes
    /// (otherwise [`VaultError::InvalidArgument`]). Preserves every sibling
    /// record + all `unknown` maps natively. `BlockNotFound` if the block
    /// UUID is absent.
    [Throws=VaultError]
    void append_record(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        bytes record_uuid,
        RecordContent content,
        bytes device_uuid,
        u64 now_ms
    );

    /// Replace one live record's editable part (type / tags / fields).
    /// (record-edit slice) Preserves `record_uuid` / `created_at_ms` /
    /// `tombstoned_at_ms` / every `unknown`; untouched fields keep their
    /// prior per-field clock. `RecordNotFound` if no live record with this
    /// UUID; same uuid-length contract as `append_record`.
    [Throws=VaultError]
    void edit_record(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        bytes record_uuid,
        RecordContent content,
        bytes device_uuid,
        u64 now_ms
    );

    /// Soft-delete one live record (set tombstone + death clock).
    /// (record-edit slice) Fields are NOT cleared (resurrectable).
    /// `RecordNotFound` if no LIVE record with this UUID; same
    /// uuid-length contract as `append_record`.
    [Throws=VaultError]
    void tombstone_record(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        bytes record_uuid,
        bytes device_uuid,
        u64 now_ms
    );

    /// Resurrect one tombstoned record (clear tombstone, preserve
    /// `tombstoned_at_ms`). (record-edit slice) `RecordNotFound` if no
    /// TOMBSTONED record with this UUID; same uuid-length contract as
    /// `append_record`.
    [Throws=VaultError]
    void resurrect_record(
        UnlockedIdentity identity,
        OpenVaultManifest manifest,
        bytes block_uuid,
        bytes record_uuid,
        bytes device_uuid,
        u64 now_ms
    );
```

- [ ] **Step 5: Build + clippy + fmt**

Run: `cargo build --release -p secretary-ffi-uniffi && cargo clippy --release -p secretary-ffi-uniffi --tests -- -D warnings && cargo fmt --all`
Expected: clean build, no clippy warnings. (If uniffi complains a UDL fn has no matching Rust fn, the signature in the UDL and `record_edit.rs` disagree — reconcile exactly, including arg order/types.)

- [ ] **Step 6: Workspace test (no regressions)**

Run: `cargo test --release --workspace`
Expected: PASS (no behavior change to existing surface; the new fns are not yet exercised by Rust tests — that happens in Tasks 3/4/6).

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-uniffi/src/namespace/record_edit.rs ffi/secretary-ffi-uniffi/src/namespace/mod.rs ffi/secretary-ffi-uniffi/src/lib.rs ffi/secretary-ffi-uniffi/src/secretary.udl
git commit -m "feat(ffi-uniffi): project append/edit/tombstone/resurrect record primitives"
```

---

## Task 3: Swift smoke — `SmokeRecordEdit.swift` (TDD at the binding boundary)

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/SmokeHelpers.swift` (add shared uuid constants)
- Create: `ffi/secretary-ffi-uniffi/tests/swift/SmokeRecordEdit.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/run.sh` (add the new file to swiftc list)
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/main.swift` (call `runRecordEditAsserts`)

- [ ] **Step 1: Add shared constants to `SmokeHelpers.swift`**

After the existing `saveBlock*` constants (lines 67-69), add:

```swift
let recordEditBlockUuid = Data(repeating: 0xB1, count: 16)
let recordEditRecordUuid = Data(repeating: 0xC2, count: 16)
let recordEditDeviceUuid = Data(repeating: 0x07, count: 16)
```

- [ ] **Step 2: Write the failing smoke runner `SmokeRecordEdit.swift`**

Create `ffi/secretary-ffi-uniffi/tests/swift/SmokeRecordEdit.swift`. (Boilerplate — `_freshWritableVault`, `check`, `defer wipe` — mirrors `SmokeSaveBlock.swift`.)

```swift
// record-edit slice assertions for the Swift smoke runner.
//
// append/edit/tombstone/resurrect mutate the on-disk vault — each assert
// copies golden_vault_001 into a per-test tempdir via _freshWritableVault.

import Foundation

func runRecordEditAsserts(env: SmokeEnv) {
    // Helper: save a one-record, two-field block to edit against.
    func seedBlock(_ identity: UnlockedIdentity, _ manifest: OpenVaultManifest) throws {
        let input = BlockInput(
            blockUuid: recordEditBlockUuid,
            blockName: "Logins",
            records: [
                RecordInput(
                    recordUuid: recordEditRecordUuid,
                    recordType: "login",
                    tags: ["work"],
                    fields: [
                        FieldInput(name: "user", value: .text(text: "alice")),
                        FieldInput(name: "pass", value: .text(text: "hunter2")),
                    ]
                ),
            ]
        )
        try saveBlock(
            identity: identity, manifest: manifest, input: input,
            deviceUuid: recordEditDeviceUuid, nowMs: 1_000
        )
    }

    // Assert: append_record adds a second live record, read_block sees both.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe(); manifest.wipe(); try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        let secondUuid = Data(repeating: 0xD3, count: 16)
        try appendRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: secondUuid,
            content: RecordContent(
                recordType: "note", tags: [],
                fields: [FieldInput(name: "body", value: .text(text: "remember"))]
            ),
            deviceUuid: recordEditDeviceUuid, nowMs: 2_000
        )
        let block = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        defer { block.wipe() }
        check(block.recordCount() == 2, "append_record → read_block sees 2 records (got \(block.recordCount()))")
    } catch {
        check(false, "append_record round-trip threw \(error)")
    }

    // Assert: edit_record changes "pass" but leaves "user" untouched — the
    // untouched field keeps its prior device_uuid (per-field-clock proof).
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe(); manifest.wipe(); try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        // First save stamped both fields with recordEditDeviceUuid. Edit with
        // a DIFFERENT device, changing only "pass".
        let editDevice = Data(repeating: 0x09, count: 16)
        try editRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
            content: RecordContent(
                recordType: "login", tags: ["work"],
                fields: [
                    FieldInput(name: "user", value: .text(text: "alice")),   // unchanged
                    FieldInput(name: "pass", value: .text(text: "s3cret!")), // changed
                ]
            ),
            deviceUuid: editDevice, nowMs: 3_000
        )
        let block = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        defer { block.wipe() }
        let record = block.recordAt(idx: 0)
        let pass = record?.fieldByName(name: "pass")?.exposeText()
        let userDevice = record?.fieldByName(name: "user")?.deviceUuid()
        let passDevice = record?.fieldByName(name: "pass")?.deviceUuid()
        check(
            pass == "s3cret!"
                && userDevice == recordEditDeviceUuid   // untouched: prior device preserved
                && passDevice == editDevice,             // changed: new device stamped
            "edit_record preserves untouched field clock (pass=\(pass ?? "<nil>"))"
        )
    } catch {
        check(false, "edit_record round-trip threw \(error)")
    }

    // Assert: tombstone_record drops the record from the live read; resurrect brings it back.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe(); manifest.wipe(); try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        try tombstoneRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
            deviceUuid: recordEditDeviceUuid, nowMs: 4_000
        )
        let afterTombstone = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        let goneCount = afterTombstone.recordCount()
        afterTombstone.wipe()
        try resurrectRecord(
            identity: identity, manifest: manifest,
            blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
            deviceUuid: recordEditDeviceUuid, nowMs: 5_000
        )
        let afterResurrect = try readBlock(identity: identity, manifest: manifest, blockUuid: recordEditBlockUuid)
        let backCount = afterResurrect.recordCount()
        afterResurrect.wipe()
        check(goneCount == 0 && backCount == 1, "tombstone→hidden(\(goneCount)) then resurrect→back(\(backCount))")
    } catch {
        check(false, "tombstone/resurrect round-trip threw \(error)")
    }

    // Assert: editing an unknown record uuid → VaultError.RecordNotFound.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe(); manifest.wipe(); try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        do {
            try editRecord(
                identity: identity, manifest: manifest,
                blockUuid: recordEditBlockUuid, recordUuid: Data(repeating: 0xFF, count: 16),
                content: RecordContent(recordType: "x", tags: [], fields: []),
                deviceUuid: recordEditDeviceUuid, nowMs: 6_000
            )
            check(false, "edit_record on unknown uuid should have thrown RecordNotFound")
        } catch let e as VaultError {
            if case .RecordNotFound = e { check(true, "edit_record unknown uuid → RecordNotFound") }
            else { check(false, "edit_record unknown uuid threw wrong variant: \(e)") }
        }
    } catch {
        check(false, "edit_record unknown-uuid setup threw \(error)")
    }

    // Assert: wrong-length device_uuid → VaultError.InvalidArgument.
    do {
        let (identity, manifest, tmp) = try _freshWritableVault(env: env)
        defer { identity.wipe(); manifest.wipe(); try? FileManager.default.removeItem(at: tmp) }
        try seedBlock(identity, manifest)
        do {
            try tombstoneRecord(
                identity: identity, manifest: manifest,
                blockUuid: recordEditBlockUuid, recordUuid: recordEditRecordUuid,
                deviceUuid: Data([0x07, 0x07]), nowMs: 7_000
            )
            check(false, "tombstone_record wrong-length device_uuid should have thrown InvalidArgument")
        } catch let e as VaultError {
            if case .InvalidArgument = e { check(true, "tombstone_record wrong-length → InvalidArgument") }
            else { check(false, "wrong-length threw wrong variant: \(e)") }
        }
    } catch {
        check(false, "wrong-length setup threw \(error)")
    }
}
```

> Note: the generated Swift names are camelCase (`appendRecord`, `editRecord`, `tombstoneRecord`, `resurrectRecord`, `RecordContent`, `FieldHandle.deviceUuid()`). Confirm `FieldHandle` exposes `deviceUuid()` in the generated `secretary.swift` after the Task 2 build (UDL line ~532 declares `bytes device_uuid();`). If the record handle accessor differs (`recordAt(idx:)?.fieldByName(name:)`), match the names used in `SmokeReadBlock.swift`.

- [ ] **Step 3: Add the file to the swiftc list in `run.sh`**

In `ffi/secretary-ffi-uniffi/tests/swift/run.sh`, add the new source between `SmokeSaveBlock.swift` and `SmokeShareBlock.swift` in the `swiftc` invocation (~line 82):

```
    "$SCRIPT_DIR/SmokeSaveBlock.swift" \
    "$SCRIPT_DIR/SmokeRecordEdit.swift" \
    "$SCRIPT_DIR/SmokeShareBlock.swift" \
```

- [ ] **Step 4: Call the runner from `main.swift`**

In `ffi/secretary-ffi-uniffi/tests/swift/main.swift`, after `runSaveBlockAsserts(env: env)` (line 26):

```swift
runRecordEditAsserts(env: env)
```

- [ ] **Step 5: Run the Swift smoke suite**

Run: `bash ffi/secretary-ffi-uniffi/tests/swift/run.sh`
Expected: compiles, runs, and every assert (including the new record-edit ones) prints PASS; the script exits 0. A FAIL line names the failing assert.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/swift/SmokeRecordEdit.swift ffi/secretary-ffi-uniffi/tests/swift/SmokeHelpers.swift ffi/secretary-ffi-uniffi/tests/swift/run.sh ffi/secretary-ffi-uniffi/tests/swift/main.swift
git commit -m "test(ffi-uniffi/swift): record-edit smoke (append/edit/tombstone/resurrect + clock proof)"
```

---

## Task 4: Kotlin smoke — `SmokeRecordEdit.kt`

**Files:**
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeHelpers.kt` (add shared uuid constants)
- Create: `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeRecordEdit.kt`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh` (add file to kotlinc list)
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt` (call `runRecordEditAsserts`)

- [ ] **Step 1: Add shared constants to `SmokeHelpers.kt`**

Find the existing `SAVE_BLOCK_*` constants in `SmokeHelpers.kt` and add alongside them:

```kotlin
val RECORD_EDIT_BLOCK_UUID = ByteArray(16) { 0xB1.toByte() }
val RECORD_EDIT_RECORD_UUID = ByteArray(16) { 0xC2.toByte() }
val RECORD_EDIT_DEVICE_UUID = ByteArray(16) { 0x07.toByte() }
```

- [ ] **Step 2: Write `SmokeRecordEdit.kt` (mirror of the Swift runner)**

Create `ffi/secretary-ffi-uniffi/tests/kotlin/SmokeRecordEdit.kt`. Mirror the five Swift asserts from Task 3 in Kotlin, using the `out.identity.use { id -> out.manifest.use { mf -> ... } }` handle pattern and `freshWritableVault(env)` exactly as `SmokeSaveBlock.kt` does. Imports:

```kotlin
import uniffi.secretary.BlockInput
import uniffi.secretary.FieldInput
import uniffi.secretary.FieldInputValue
import uniffi.secretary.RecordContent
import uniffi.secretary.RecordInput
import uniffi.secretary.VaultException
import uniffi.secretary.appendRecord
import uniffi.secretary.editRecord
import uniffi.secretary.readBlock
import uniffi.secretary.resurrectRecord
import uniffi.secretary.saveBlock
import uniffi.secretary.tombstoneRecord

fun seedBlock(id: UnlockedIdentity, mf: OpenVaultManifest) {
    val input = BlockInput(
        blockUuid = RECORD_EDIT_BLOCK_UUID,
        blockName = "Logins",
        records = listOf(
            RecordInput(
                recordUuid = RECORD_EDIT_RECORD_UUID,
                recordType = "login",
                tags = listOf("work"),
                fields = listOf(
                    FieldInput("user", FieldInputValue.Text("alice")),
                    FieldInput("pass", FieldInputValue.Text("hunter2")),
                ),
            ),
        ),
    )
    saveBlock(id, mf, input, RECORD_EDIT_DEVICE_UUID, 1_000uL)
}

fun runRecordEditAsserts(env: SmokeEnv) {
    // Assert 1 (fully written; mirror this idiom for the remaining four):
    // appendRecord adds a second live record → readBlock sees both.
    var tmp1: java.nio.file.Path? = null
    try {
        val (out, tmp) = freshWritableVault(env)
        tmp1 = tmp
        out.identity.use { id ->
            out.manifest.use { mf ->
                seedBlock(id, mf)
                val second = ByteArray(16) { 0xD3.toByte() }
                appendRecord(
                    id, mf, RECORD_EDIT_BLOCK_UUID, second,
                    RecordContent(
                        recordType = "note", tags = emptyList(),
                        fields = listOf(FieldInput("body", FieldInputValue.Text("remember"))),
                    ),
                    RECORD_EDIT_DEVICE_UUID, 2_000uL,
                )
                readBlock(id, mf, RECORD_EDIT_BLOCK_UUID).use { block ->
                    check(block.recordCount() == 2uL, "appendRecord → readBlock sees 2 records")
                }
            }
        }
    } finally {
        tmp1?.let { org.apache.commons.io.FileUtils.deleteQuietly(it.toFile()) }
    }

    // Assert 2: editRecord changes "pass" but leaves "user" untouched — the
    //   untouched field keeps its prior deviceUuid (per-field-clock proof).
    //   Edit with a DIFFERENT device (ByteArray(16){0x09}); after readBlock,
    //   record.fieldByName("user")?.deviceUuid()?.contentEquals(RECORD_EDIT_DEVICE_UUID) == true
    //   and ...("pass")?.deviceUuid()?.contentEquals(editDevice) == true,
    //   and ...("pass")?.exposeText() == "s3cret!".
    // Assert 3: tombstoneRecord → readBlock recordCount() == 0uL; then
    //   resurrectRecord → readBlock recordCount() == 1uL.
    // Assert 4: editRecord with unknown record uuid (ByteArray(16){0xFF}) →
    //   try { ... ; check(false, ...) } catch (e: VaultException.RecordNotFound) { check(true, ...) }.
    // Assert 5: tombstoneRecord with wrong-length deviceUuid (byteArrayOf(0x07,0x07)) →
    //   catch (e: VaultException.InvalidArgument) { check(true, ...) }.
    // Match the temp-dir cleanup idiom used in SmokeSaveBlock.kt (it tracks a
    // nullable Path and deletes in finally); reuse whatever helper that file
    // uses rather than the commons-io call sketched above if it differs.
}
```

> The cleanup line above is illustrative — use the **same** tempdir-deletion approach `SmokeSaveBlock.kt` already uses (check that file; it may use `tmp.toFile().deleteRecursively()` or a helper). Do not introduce a new dependency.

> Kotlin error catches use `VaultException.RecordNotFound` / `VaultException.InvalidArgument` (uniffi 0.31 Kotlin error class naming; see how `SmokeSaveBlock.kt` catches `VaultException`). Field clock accessor is `record?.fieldByName("user")?.deviceUuid()` returning `ByteArray?`; compare with `.contentEquals(RECORD_EDIT_DEVICE_UUID)`.

- [ ] **Step 3: Add to kotlinc list in `run.sh`**

In `ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`, add between `SmokeSaveBlock.kt` and `SmokeShareBlock.kt` (~line 171):

```
    "$SCRIPT_DIR/SmokeSaveBlock.kt" \
    "$SCRIPT_DIR/SmokeRecordEdit.kt" \
    "$SCRIPT_DIR/SmokeShareBlock.kt" \
```

- [ ] **Step 4: Call the runner from `Main.kt`**

In `ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt`, after `runSaveBlockAsserts(env)`:

```kotlin
runRecordEditAsserts(env)
```

- [ ] **Step 5: Run the Kotlin smoke suite**

Run: `bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh`
Expected: compiles, runs, all asserts PASS, exit 0. (Requires a Kotlin/JVM toolchain; if unavailable on this machine, note it and rely on Swift + pyo3 coverage, but the Kotlin file must still compile-match the binding — flag any skip explicitly.)

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-uniffi/tests/kotlin/SmokeRecordEdit.kt ffi/secretary-ffi-uniffi/tests/kotlin/SmokeHelpers.kt ffi/secretary-ffi-uniffi/tests/kotlin/run.sh ffi/secretary-ffi-uniffi/tests/kotlin/Main.kt
git commit -m "test(ffi-uniffi/kotlin): record-edit smoke parity with Swift"
```

---

## Task 5: pyo3 — `RecordContent` pyclass + four pyfunctions

**Files:**
- Create: `ffi/secretary-ffi-py/src/record_edit.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs` (mod + use + register pyclass and 4 fns)

- [ ] **Step 1: Add a `to_bridge()` accessor to the `save.rs` `FieldInput` (keeps `inner` private)**

The pyo3 `FieldInput` (in `save.rs`) holds `value: FieldInputValue`, and `FieldInputValue` wraps a **private** `inner: BridgeFieldInputValue`. The record-edit converter needs the bridge field without exposing `inner`. In `ffi/secretary-ffi-py/src/save.rs`, add a plain Rust `impl` (NOT `#[pymethods]`) next to the existing `FieldInput`:

```rust
impl FieldInput {
    /// Clone this field into the bridge-side `FieldInput` (name +
    /// zeroize-typed value) for the record-edit projection. Brief
    /// secret-doubling, same tradeoff as `save_block`'s record clone.
    pub(crate) fn to_bridge(&self) -> secretary_ffi_bridge::FieldInput {
        secretary_ffi_bridge::FieldInput {
            name: self.name.clone(),
            value: self.value.inner.clone(),
        }
    }
}
```

(`self.value.inner` is reachable here because this `impl` lives in `save.rs`, the same module that declares the private field.)

- [ ] **Step 2: Create `record_edit.rs` with the pyclass + four pyfunctions**

Create `ffi/secretary-ffi-py/src/record_edit.rs`:

```rust
//! Record-edit entry points (record-edit slice): `append_record`,
//! `edit_record`, `tombstone_record`, `resurrect_record`, plus the
//! `RecordContent` input pyclass.
//!
//! `RecordContent` projects the bridge's `RecordContent` 1:1, reusing the
//! same `FieldInput` pyclass as `save_block`. Zeroize discipline matches
//! `save.rs`: text/bytes land in `SecretString`/`SecretBytes` as soon as
//! the `FieldInputValue` constructor fires; the Python str/bytes remain
//! caller-owned.

use pyo3::prelude::*;
use secretary_ffi_bridge::RecordContent as BridgeRecordContent;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};
use crate::identity::UnlockedIdentity;
use crate::save::FieldInput;
use crate::vault::OpenVaultManifest;

/// The editable delta for one record on append/edit. Construct with
/// `RecordContent(record_type=..., tags=[...], fields=[FieldInput(...)])`.
/// `record_uuid` / `created_at_ms` / `unknown` are owned by the edit
/// primitives, not supplied here.
#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct RecordContent {
    /// Open-ended record-type discriminator. Empty allowed.
    #[pyo3(get, set)]
    pub record_type: String,
    /// Cross-cutting tags.
    #[pyo3(get, set)]
    pub tags: Vec<String>,
    /// Ordered list of fields.
    pub fields: Vec<FieldInput>,
}

#[pymethods]
impl RecordContent {
    /// Construct a record-content delta. `record_type` defaults to "" and
    /// `tags` to [] for ergonomic 1-arg construction.
    #[new]
    #[pyo3(signature = (fields, record_type=String::new(), tags=Vec::new()))]
    fn new(fields: Vec<FieldInput>, record_type: String, tags: Vec<String>) -> Self {
        Self {
            record_type,
            tags,
            fields,
        }
    }
}

/// Convert the pyclass `RecordContent` into the bridge type, cloning the
/// (zeroize-on-drop) secret carriers via `FieldInput::to_bridge`. Same
/// brief-doubling tradeoff as `save_block`'s record clone.
fn to_bridge_content(c: &RecordContent) -> BridgeRecordContent {
    BridgeRecordContent {
        record_type: c.record_type.clone(),
        tags: c.tags.clone(),
        fields: c.fields.iter().map(FieldInput::to_bridge).collect(),
    }
}

/// Append a new record to an existing block. `block_uuid` / `record_uuid`
/// / `device_uuid` must each be 16 bytes (else `ValueError`). Raises
/// `VaultBlockNotFound` for an unknown block; `VaultCorruptVault` on a
/// wiped handle.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn append_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: &RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::append_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        to_bridge_content(content),
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Replace one live record's editable part. Raises `VaultRecordNotFound`
/// if no live record with this UUID; same uuid-length contract as
/// `append_record`.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn edit_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    content: &RecordContent,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::edit_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        to_bridge_content(content),
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Soft-delete one live record. Raises `VaultRecordNotFound` if no LIVE
/// record with this UUID.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn tombstone_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::tombstone_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}

/// Resurrect one tombstoned record (preserve `tombstoned_at_ms`). Raises
/// `VaultRecordNotFound` if no TOMBSTONED record with this UUID.
#[pyfunction]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn resurrect_record(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: Vec<u8>,
    record_uuid: Vec<u8>,
    device_uuid: Vec<u8>,
    now_ms: u64,
) -> PyResult<()> {
    let block_uuid = uuid_array_or_value_error(&block_uuid, "block_uuid")?;
    let record_uuid = uuid_array_or_value_error(&record_uuid, "record_uuid")?;
    let device_uuid = uuid_array_or_value_error(&device_uuid, "device_uuid")?;
    secretary_ffi_bridge::resurrect_record(
        &identity.0,
        &manifest.0,
        block_uuid,
        record_uuid,
        device_uuid,
        now_ms,
    )
    .map_err(ffi_vault_error_to_pyerr)
}
```

- [ ] **Step 3: Register the module + pyclass + four fns in `lib.rs`**

In `ffi/secretary-ffi-py/src/lib.rs`:
- Add `mod record_edit;` alongside the other `mod` lines (after `mod record;`, ~line 53).
- Add the import after the `save::{...}` use (~line 81):
  ```rust
  use record_edit::{append_record, edit_record, resurrect_record, tombstone_record, RecordContent};
  ```
- In the module-init fn, after the `save_block` registration (line 193), add:
  ```rust
  m.add_class::<RecordContent>()?;
  m.add_function(wrap_pyfunction!(append_record, m)?)?;
  m.add_function(wrap_pyfunction!(edit_record, m)?)?;
  m.add_function(wrap_pyfunction!(tombstone_record, m)?)?;
  m.add_function(wrap_pyfunction!(resurrect_record, m)?)?;
  ```

- [ ] **Step 4: Build the pyo3 extension + clippy**

Run: `cargo build --release -p secretary-ffi-py && cargo clippy --release -p secretary-ffi-py --tests -- -D warnings`
Expected: clean. (If `FieldInputValue.inner` access errors as private, the `to_bridge()` accessor from Step 1 is missing or in the wrong module — it must live in `save.rs`.)

- [ ] **Step 5: Commit**

```bash
git add ffi/secretary-ffi-py/src/record_edit.rs ffi/secretary-ffi-py/src/lib.rs ffi/secretary-ffi-py/src/save.rs
git commit -m "feat(ffi-py): project append/edit/tombstone/resurrect record primitives"
```

---

## Task 6: pyo3 pytest — `test_record_edit.py` (TDD round-trips)

**Files:**
- Create: `ffi/secretary-ffi-py/tests/test_record_edit.py`

- [ ] **Step 1: Write the failing pytest suite**

Create `ffi/secretary-ffi-py/tests/test_record_edit.py` (mirrors `test_trash_restore.py`'s fixture pattern — fresh temp copy of golden_vault_001 per test):

```python
"""record-edit slice pytest — append/edit/tombstone/resurrect end-to-end.

Each test gets its own writable copy of golden_vault_001 in pytest's
``tmp_path`` so the read-only on-disk fixture is never touched.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import secretary_ffi_py
from secretary_ffi_py import (
    FieldInput,
    FieldInputValue,
    RecordContent,
    VaultRecordNotFound,
)

VAULT_001_PASSWORD = b"correct horse battery staple"
BLOCK_UUID = bytes([0xB1] * 16)
RECORD_UUID = bytes([0xC2] * 16)
DEVICE_UUID = bytes([0x07] * 16)
NOW_MS_BASE = 1_715_000_000_000


def _golden_vault_path(n: int) -> Path:
    return (
        Path(__file__).resolve().parents[3]
        / "core" / "tests" / "data" / f"golden_vault_{n:03d}"
    )


def _fresh_writable_vault(tmp_path: Path):
    dst = tmp_path / "vault001"
    shutil.copytree(_golden_vault_path(1), dst)
    return secretary_ffi_py.open_vault_with_password(str(dst), VAULT_001_PASSWORD), dst


def _seed_block(identity, manifest) -> None:
    """Save a one-record, two-field block to edit against."""
    inp = secretary_ffi_py.BlockInput(
        block_uuid=BLOCK_UUID,
        block_name="Logins",
        records=[
            secretary_ffi_py.RecordInput(
                record_uuid=RECORD_UUID,
                fields=[
                    FieldInput("user", FieldInputValue.text("alice")),
                    FieldInput("pass", FieldInputValue.text("hunter2")),
                ],
                record_type="login",
                tags=["work"],
            ),
        ],
    )
    secretary_ffi_py.save_block(identity, manifest, inp, DEVICE_UUID, NOW_MS_BASE)


def test_append_record_adds_live_record(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            second = bytes([0xD3] * 16)
            secretary_ffi_py.append_record(
                identity, manifest, BLOCK_UUID, second,
                RecordContent([FieldInput("body", FieldInputValue.text("remember"))], "note", []),
                DEVICE_UUID, NOW_MS_BASE + 1_000,
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID) as block:
                assert block.record_count() == 2


def test_edit_record_changes_value_and_preserves_untouched_field_clock(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            edit_device = bytes([0x09] * 16)
            secretary_ffi_py.edit_record(
                identity, manifest, BLOCK_UUID, RECORD_UUID,
                RecordContent(
                    [
                        FieldInput("user", FieldInputValue.text("alice")),    # unchanged
                        FieldInput("pass", FieldInputValue.text("s3cret!")),  # changed
                    ],
                    "login", ["work"],
                ),
                edit_device, NOW_MS_BASE + 2_000,
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID) as block:
                record = block.record_at(0)
                assert record.field_by_name("pass").expose_text() == "s3cret!"
                # Untouched field keeps its prior device_uuid; changed field gets the new one.
                assert bytes(record.field_by_name("user").device_uuid()) == DEVICE_UUID
                assert bytes(record.field_by_name("pass").device_uuid()) == edit_device


def test_tombstone_then_resurrect_round_trip(tmp_path: Path) -> None:
    # NOTE: read_block surfaces ALL records (it does not hide tombstoned
    # ones) and exposes deletion via the per-record tombstone() flag —
    # filtering live-vs-deleted is the consumer's job. So we assert the
    # flag flips, not a record_count change.
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            secretary_ffi_py.tombstone_record(
                identity, manifest, BLOCK_UUID, RECORD_UUID, DEVICE_UUID, NOW_MS_BASE + 1_000
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID) as block:
                assert block.record_count() == 1
                assert block.record_at(0).tombstone() is True
            secretary_ffi_py.resurrect_record(
                identity, manifest, BLOCK_UUID, RECORD_UUID, DEVICE_UUID, NOW_MS_BASE + 2_000
            )
            with secretary_ffi_py.read_block(identity, manifest, BLOCK_UUID) as block:
                assert block.record_at(0).tombstone() is False


def test_edit_unknown_record_raises_record_not_found(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            with pytest.raises(VaultRecordNotFound):
                secretary_ffi_py.edit_record(
                    identity, manifest, BLOCK_UUID, b"\xff" * 16,
                    RecordContent([], "x", []), DEVICE_UUID, NOW_MS_BASE + 1_000,
                )


def test_tombstone_wrong_length_device_uuid_raises_value_error(tmp_path: Path) -> None:
    out, _dst = _fresh_writable_vault(tmp_path)
    with out as vault:
        with vault.identity as identity, vault.manifest as manifest:
            _seed_block(identity, manifest)
            with pytest.raises(ValueError):
                secretary_ffi_py.tombstone_record(
                    identity, manifest, BLOCK_UUID, RECORD_UUID, b"\x07\x07", NOW_MS_BASE + 1_000
                )
```

- [ ] **Step 2: Run it to verify it fails before the module is rebuilt/installed**

Run: `cd ffi/secretary-ffi-py && uv run --with pytest pytest tests/test_record_edit.py -v`
Expected: FAIL or ImportError (`cannot import name 'RecordContent'`) until the extension is rebuilt into the venv. (If the venv already has a stale build, this proves the test is wired.)

- [ ] **Step 3: Build the extension into the venv (maturin develop)**

Run: `cd ffi/secretary-ffi-py && uv run maturin develop --release`
Expected: builds and installs `secretary_ffi_py` into the active venv.

> If a later pytest run still raises `ImportError: cannot import name 'RecordContent'` after a successful `maturin develop`, you hit the uv editable-cache stickiness: remove the venv + `uv` cache and re-run `maturin develop --release`. Do not trust a stale-`.so` failure.

- [ ] **Step 4: Run the suite to green**

Run: `cd ffi/secretary-ffi-py && uv run --with pytest pytest tests/test_record_edit.py -v`
Expected: all 5 tests PASS.

- [ ] **Step 5: Run the full pyo3 pytest suite (no regressions)**

Run: `cd ffi/secretary-ffi-py && uv run --with pytest pytest -v`
Expected: existing suites (`test_smoke`, `test_trash_restore`, `test_sync`, `test_device_slot`) + the new one all PASS.

- [ ] **Step 6: Commit**

```bash
git add ffi/secretary-ffi-py/tests/test_record_edit.py
git commit -m "test(ffi-py): record-edit pytest round-trips + error contracts"
```

---

## Task 7: Full gauntlet, conformance proof, docs, handoff

**Files:**
- Modify (if needed): `README.md`, `ROADMAP.md`
- Modify: `docs/handoffs/<date>-...-shipped.md` + retarget `NEXT_SESSION.md` symlink

- [ ] **Step 1: Workspace test + clippy + fmt**

Run:
```bash
cargo test --release --workspace
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all --check
```
Expected: all green, no warnings, no fmt diff.

- [ ] **Step 2: Prove no conformance / variant drift**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh
```
Expected: both PASS unchanged — this proves the projection added **no** `FfiVaultError` variant and did not perturb the KAT replay surface. (If either fails, a new variant or an observable-format change slipped in — stop and reconcile per the spec's "disagreement is Rust bug / Python bug / spec ambiguity" rule.)

- [ ] **Step 3: Re-run both smoke runners end-to-end**

Run:
```bash
bash ffi/secretary-ffi-uniffi/tests/swift/run.sh
bash ffi/secretary-ffi-uniffi/tests/kotlin/run.sh
```
Expected: both exit 0 with the record-edit asserts PASS.

- [ ] **Step 4: Docs check**

Review `README.md` and `ROADMAP.md`. If either enumerates the FFI write surface or per-binding capabilities, add record-edit (append/edit/tombstone/resurrect) to the uniffi + pyo3 surface. Keep README status terse (dot points). If neither references the FFI surface at that granularity, make no change and note "no doc change needed" in the handoff.

- [ ] **Step 5: Write the handoff + retarget the symlink**

Author `docs/handoffs/2026-06-13-ffi-record-edit-primitives-shipped.md` capturing: (1) what shipped with commit SHAs, (2) Slice 2 (iOS UI) as the concrete next step with acceptance criteria, (3) open risks, (4) exact resume commands, (5) the symlink note. Then:
```bash
ln -snf docs/handoffs/2026-06-13-ffi-record-edit-primitives-shipped.md NEXT_SESSION.md
git add docs/handoffs/2026-06-13-ffi-record-edit-primitives-shipped.md NEXT_SESSION.md README.md ROADMAP.md
git commit -m "docs: record-edit FFI projection shipped — handoff + symlink"
```

- [ ] **Step 6: Push + open PR**

```bash
git push -u origin feature/ffi-record-edit-primitives
gh pr create --title "FFI projection of record-edit primitives (Slice 1 of iOS record CRUD)" --body "<summary + test evidence>"
```

---

## Self-review notes (for the executor)

- **Per-field-clock preservation** is asserted at the binding boundary in both Swift smoke (`deviceUuid()`) and pyo3 pytest (`device_uuid()`) — not merely trusted from the bridge. This is the CRDT-correctness proof the whole slice exists for.
- **No new `FfiVaultError` variant** — verified structurally (only `BlockNotFound`/`RecordNotFound`/`InvalidArgument` used, all pre-existing) and proven by the unchanged conformance scripts in Task 7 Step 2.
- **File-size discipline:** the new code lives in dedicated `record_edit.rs` files on both bindings; `namespace/mod.rs` is not extended (it is already 637 lines).
- **Encapsulation:** the pyo3 `FieldInputValue.inner` stays private; cross-module access goes through a `to_bridge()` accessor on `FieldInput`.
- **No hardcoded crypto values** — the tests use record/field *plaintext* and fixed UUIDs/timestamps (not key material); the golden vault's keys come from the fixture, never literals. This stays within the project's "no hardcoded cryptographic value" rule (UUIDs and now_ms are not crypto secrets).
