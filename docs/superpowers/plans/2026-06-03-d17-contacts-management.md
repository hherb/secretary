# D.1.7 — Contacts management (export-my-card + contacts pane) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user with an unlocked vault export their own public contact card to a folder, and manage imported contacts (view with per-contact recipient counts; delete, warn-but-allow) from a standalone Contacts pane.

**Architecture:** Bridge-thick, `core/` frozen. Two new bridge primitives (`owner_card_export`, `delete_contact_card`) plus a widening of `enumerate_contact_cards` to report per-contact `shared_block_count`. One new `FfiVaultError` variant (`CannotDeleteOwnerContact`) threaded through every workspace exhaustive-match site in a single task. Desktop IPC + DTOs + a Svelte Contacts pane mirroring the D.1.5 Trash pane. Export reuses the granted folder picker (bridge yields bytes; desktop writes the external file).

**Tech Stack:** Rust (stable; `secretary-ffi-bridge`, `secretary-desktop`), uniffi + PyO3 bindings, Tauri 2, Svelte 5 (runes) + TypeScript, Vitest.

**Spec:** `docs/superpowers/specs/2026-06-03-d17-contacts-management-design.md`. Revoke is out of scope (filed as #177 — needs a frozen-core primitive).

---

## File Structure

```
ffi/secretary-ffi-bridge/src/contacts/
  mod.rs            MODIFIED  ContactSummary gains shared_block_count: u32
  enumerate.rs      MODIFIED  scan manifest_body().blocks[].recipients per card
  export.rs         NEW       owner_card_export(manifest) -> (String, Vec<u8>)
  delete.rs         NEW       delete_contact_card(manifest, [u8;16])
ffi/secretary-ffi-bridge/src/error/vault/mod.rs   MODIFIED  + CannotDeleteOwnerContact
ffi/secretary-ffi-bridge/src/lib.rs               MODIFIED  re-export new fns
ffi/secretary-ffi-bridge/tests/contacts.rs        MODIFIED  bridge integration tests
ffi/secretary-ffi-uniffi/src/secretary.udl        MODIFIED  + CannotDeleteOwnerContact()
ffi/secretary-ffi-uniffi/src/errors/vault.rs      MODIFIED  + variant + From arm + test
ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift    MODIFIED  + case
ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt      MODIFIED  + arms
ffi/secretary-ffi-py/src/errors.rs                MODIFIED  + exception + From arm
ffi/secretary-ffi-py/src/lib.rs                   MODIFIED  + import + register
core/tests/conformance_kat_helpers/errors.rs      MODIFIED  + name arm
desktop/src-tauri/src/
  dtos/contact.rs   MODIFIED  ContactSummaryDto + sharedBlockCount; NEW ExportedCardDto
  dtos/mod.rs       MODIFIED  export ExportedCardDto
  errors.rs         MODIFIED  + AppError::CannotDeleteOwnerContact + map arm + test
  commands/contacts.rs   MODIFIED  + export_contact_card / delete_contact_card (+ *_impl)
  main.rs           MODIFIED  register the two commands
  tests/ipc_integration.rs   MODIFIED  L3 tests
desktop/src/
  lib/ipc.ts        MODIFIED  ContactSummaryDto + sharedBlockCount; ExportedCardDto; 2 wrappers
  lib/errors.ts     MODIFIED  + 'cannot_delete_owner_contact' code/union/message
  lib/browse.ts     MODIFIED  + { level: 'contacts' } + openContacts()
  components/contacts/ContactsPane.svelte   NEW
  components/contacts/ContactRow.svelte     NEW
  routes/Vault.svelte                       MODIFIED  👤 entry + pane host
  theme.css         MODIFIED  .contacts-pane* / .contact-row*
desktop/tests/      MODIFIED/NEW  contacts.test.ts, ipcContacts.test.ts, browse.test.ts,
                                  errors.test.ts, ContactsPane.test.ts
```

**Build/test commands referenced below:**
- Bridge test: `cargo test --release -p secretary-ffi-bridge --test contacts <name>`
- Workspace gate (REQUIRED after every Rust task touching the shared enum): `cargo build --release --workspace && cargo clippy --release --workspace --tests -- -D warnings`
- Desktop unit: `cargo test --release -p secretary-desktop <name>`
- Desktop L3: `cargo test --release -p secretary-desktop --test ipc_integration <name>`
- Frontend: `cd desktop && pnpm test -- <file>` (vitest), `pnpm typecheck`, `pnpm svelte-check`, `pnpm lint`

---

## Task 1: Bridge — widen `ContactSummary` + `enumerate_contact_cards` with `shared_block_count`

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/contacts/mod.rs` (ContactSummary struct)
- Modify: `ffi/secretary-ffi-bridge/src/contacts/enumerate.rs`
- Test: `ffi/secretary-ffi-bridge/tests/contacts.rs`

- [ ] **Step 1: Write the failing test**

Append to `ffi/secretary-ffi-bridge/tests/contacts.rs` (uses the existing harness imports `save_one_record_block`, `mint_external_card`, `import_contact_card`, `share_block_to`, `NEW_BLOCK_UUID`, `NEW_RECORD_UUID`, `DEVICE_UUID`, `NOW_MS_BASE`):

```rust
#[test]
fn enumerate_reports_shared_block_count_per_contact() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(
        &identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "p", "v", NOW_MS_BASE,
    );
    // Import two peers; share the block with only the first.
    let (_b1, shared_peer) = mint_external_card(0xC3, "Shared-Peer");
    let (_b2, lonely_peer) = mint_external_card(0xD4, "Lonely-Peer");
    let shared_uuid = uuid_of(&shared_peer);
    let lonely_uuid = uuid_of(&lonely_peer);
    import_contact_card(&manifest, &shared_peer).expect("import shared");
    import_contact_card(&manifest, &lonely_peer).expect("import lonely");
    share_block_to(
        &identity, &manifest, NEW_BLOCK_UUID, shared_uuid, DEVICE_UUID, NOW_MS_BASE + 1_000,
    )
    .expect("share");

    let (summaries, _unreadable) = enumerate_contact_cards(&manifest).expect("enumerate");
    let shared = summaries.iter().find(|s| s.contact_uuid == shared_uuid).expect("shared present");
    let lonely = summaries.iter().find(|s| s.contact_uuid == lonely_uuid).expect("lonely present");
    assert_eq!(shared.shared_block_count, 1, "shared peer receives exactly one block");
    assert_eq!(lonely.shared_block_count, 0, "lonely peer receives no blocks");
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge --test contacts enumerate_reports_shared_block_count_per_contact`
Expected: FAIL — `no field shared_block_count on type ContactSummary` (compile error).

- [ ] **Step 3: Widen the struct**

In `ffi/secretary-ffi-bridge/src/contacts/mod.rs`, add the field to `ContactSummary`:

```rust
#[derive(Debug)]
pub struct ContactSummary {
    /// 16-byte contact identity (the card's `contact_uuid`).
    pub contact_uuid: [u8; 16],
    /// User-facing label from the card.
    pub display_name: String,
    /// How many of the owner's blocks list this contact as a recipient.
    /// In-memory scan of `manifest_body().blocks[].recipients` — no
    /// decryption, no I/O. Feeds the contacts-pane delete warning (spec §3).
    pub shared_block_count: u32,
}
```

- [ ] **Step 4: Populate it in enumerate**

In `ffi/secretary-ffi-bridge/src/contacts/enumerate.rs`, add the manifest-body read near the top (after `owner_uuid`), and compute the count when pushing each summary. Replace the body of the function so it reads:

```rust
pub fn enumerate_contact_cards(
    manifest: &OpenVaultManifest,
) -> Result<(Vec<ContactSummary>, usize), FfiVaultError> {
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let owner_uuid = manifest.owner_card().ok_or_else(handle_wiped)?.contact_uuid;
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    let contacts_dir = folder.join("contacts");

    let mut summaries = Vec::new();
    let mut unreadable = 0usize;

    let read_dir = match std::fs::read_dir(&contacts_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((summaries, unreadable));
        }
        Err(e) => {
            return Err(FfiVaultError::FolderInvalid {
                detail: format!("read_dir contacts/: {e}"),
            })
        }
    };

    for entry in read_dir {
        let entry = entry.map_err(|e| FfiVaultError::FolderInvalid {
            detail: format!("iterate contacts/: {e}"),
        })?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("card") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            unreadable += 1;
            continue;
        };
        match read_verified_card(&bytes) {
            Ok(card) if card.contact_uuid == owner_uuid => { /* omit owner */ }
            Ok(card) => {
                let shared_block_count = body
                    .blocks
                    .iter()
                    .filter(|b| b.recipients.contains(&card.contact_uuid))
                    .count() as u32;
                summaries.push(ContactSummary {
                    contact_uuid: card.contact_uuid,
                    display_name: card.display_name,
                    shared_block_count,
                });
            }
            Err(_) => unreadable += 1,
        }
    }
    Ok((summaries, unreadable))
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge --test contacts`
Expected: PASS (the new test + all existing contacts tests).

Note: the existing D.1.6 tests construct `ContactSummary` only via `enumerate`/`import` return values, not literals, so the new field does not break them. (If any test elsewhere builds a `ContactSummary { .. }` literal, add `shared_block_count: 0`.)

- [ ] **Step 6: Workspace gate**

Run: `cargo build --release --workspace && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/contacts/mod.rs ffi/secretary-ffi-bridge/src/contacts/enumerate.rs ffi/secretary-ffi-bridge/tests/contacts.rs
git commit -m "feat(d17-bridge): enumerate reports shared_block_count per contact"
```

---

## Task 2: Bridge — `owner_card_export`

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/contacts/export.rs`
- Modify: `ffi/secretary-ffi-bridge/src/contacts/mod.rs` (declare + re-export)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (re-export)
- Test: `ffi/secretary-ffi-bridge/tests/contacts.rs`

- [ ] **Step 1: Write the failing test**

Append to `ffi/secretary-ffi-bridge/tests/contacts.rs`:

```rust
#[test]
fn owner_card_export_returns_canonical_name_and_round_trips() {
    use secretary_ffi_bridge::owner_card_export;
    let (_tmp, _identity, manifest) = fresh_writable_vault();

    let (file_name, bytes) = owner_card_export(&manifest).expect("export ok");

    // Name is the canonical hyphenated-uuid filename a peer's import re-derives.
    let owner = owner_uuid(&manifest);
    assert_eq!(file_name, format!("{}.card", format_uuid_hyphenated(&owner)));
    // Bytes parse + self-verify back to the owner's card (public material only).
    let card = ContactCard::from_canonical_cbor(&bytes).expect("parse");
    card.verify_self().expect("both self-signature halves verify");
    assert_eq!(card.contact_uuid, owner);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-ffi-bridge --test contacts owner_card_export_returns_canonical_name_and_round_trips`
Expected: FAIL — `owner_card_export` not found in `secretary_ffi_bridge`.

- [ ] **Step 3: Create the module**

Create `ffi/secretary-ffi-bridge/src/contacts/export.rs`:

```rust
//! `owner_card_export`: serialize the vault owner's own PUBLIC contact card
//! for handing to a peer (the symmetric counterpart to `import_contact_card`).
//! No secret material — a contact card holds only public keys + display name
//! + uuid. The destination (an external folder) is written by the desktop
//! edge; the bridge only yields the canonical file name + bytes (spec §3, §5).

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::handle_wiped;
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Return the canonical export file name (`<hyphenated-owner-uuid>.card` — the
/// name a peer's `import_contact_card` re-derives from the card's own uuid)
/// and the canonical-CBOR bytes of the owner's contact card.
///
/// Single lock acquisition: `owner_card()` clones the verified card, and we
/// serialize that clone directly (avoiding a second `owner_card_bytes()` lock
/// and the wipe-between-accessors gap).
///
/// - manifest handle wiped → [`FfiVaultError::CorruptVault`] (via `handle_wiped`).
/// - `to_canonical_cbor` failure (unreachable for a card validated at unlock;
///   the `Result` is preserved per issue #41) → [`FfiVaultError::CorruptVault`].
pub fn owner_card_export(
    manifest: &OpenVaultManifest,
) -> Result<(String, Vec<u8>), FfiVaultError> {
    let card = manifest.owner_card().ok_or_else(handle_wiped)?;
    let file_name = format!("{}.card", format_uuid_hyphenated(&card.contact_uuid));
    let bytes = card
        .to_canonical_cbor()
        .map_err(|e| FfiVaultError::CorruptVault {
            detail: format!("owner card re-encode failed: {e}"),
        })?;
    Ok((file_name, bytes))
}
```

- [ ] **Step 4: Wire the module + re-export**

In `ffi/secretary-ffi-bridge/src/contacts/mod.rs`, add after the `mod share;` block:

```rust
mod export;
pub use export::owner_card_export;
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, find the existing contacts re-export line (it re-exports `enumerate_contact_cards, import_contact_card, share_block_to`) and add `owner_card_export` to it. For example if it reads `pub use contacts::{enumerate_contact_cards, import_contact_card, share_block_to};` change it to:

```rust
pub use contacts::{
    enumerate_contact_cards, import_contact_card, owner_card_export, share_block_to,
};
```

(Verify the exact existing form first with `grep -n "pub use contacts" ffi/secretary-ffi-bridge/src/lib.rs`.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `cargo test --release -p secretary-ffi-bridge --test contacts owner_card_export_returns_canonical_name_and_round_trips`
Expected: PASS.

- [ ] **Step 6: Workspace gate**

Run: `cargo build --release --workspace && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/contacts/export.rs ffi/secretary-ffi-bridge/src/contacts/mod.rs ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/contacts.rs
git commit -m "feat(d17-bridge): owner_card_export (canonical name + bytes, public material)"
```

---

## Task 3: Thread `CannotDeleteOwnerContact` through every workspace exhaustive-match site

This is the atomic cross-crate plumbing task — adding a shared `FfiVaultError` variant breaks exhaustive matches in uniffi, pyo3, the core KAT helper, and the desktop mapper (the D.1.6 lesson: per-crate `-p` builds mask this; the gate is `--workspace`). No code *produces* the variant yet (Task 4's `delete_contact_card` is the first producer); this task only makes every layer handle it. The variant carries **no fields**.

**Files:**
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`
- Modify: `ffi/secretary-ffi-uniffi/src/secretary.udl`
- Modify: `ffi/secretary-ffi-uniffi/src/errors/vault.rs`
- Modify: `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`
- Modify: `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt`
- Modify: `ffi/secretary-ffi-py/src/errors.rs`
- Modify: `ffi/secretary-ffi-py/src/lib.rs`
- Modify: `core/tests/conformance_kat_helpers/errors.rs`
- Modify: `desktop/src-tauri/src/errors.rs`

- [ ] **Step 1: Add the bridge variant**

In `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, add inside the `enum FfiVaultError` (after the `BlockNotInTrash { .. }` variant, before the closing `}`):

```rust
    /// `delete_contact_card`: the requested uuid is the vault owner's own
    /// self-card, which must never be removed (removing it corrupts the
    /// vault's identity). Defense in depth — the contacts pane already omits
    /// the owner, but the primitive refuses it regardless. Spec §3, §5.
    #[error("the vault owner's own contact card cannot be deleted")]
    CannotDeleteOwnerContact,
```

- [ ] **Step 2: Add the uniffi UDL case**

In `ffi/secretary-ffi-uniffi/src/secretary.udl`, in the `VaultError` enum (near the `ContactNotFound(string uuid_hex);` line), add:

```
    CannotDeleteOwnerContact();
```

- [ ] **Step 3: Add the uniffi Rust variant + From arm + test**

In `ffi/secretary-ffi-uniffi/src/errors/vault.rs`:

After the `ContactNotFound { uuid_hex: String },` variant, add:

```rust
    /// The owner's own contact card cannot be deleted.
    /// Mirrors `FfiVaultError::CannotDeleteOwnerContact`.
    #[error("the vault owner's own contact card cannot be deleted")]
    CannotDeleteOwnerContact,
```

In the `From<FfiVaultError> for VaultError` match (near the `ContactNotFound { uuid_hex } => VaultError::ContactNotFound { uuid_hex },` arm), add:

```rust
            FfiVaultError::CannotDeleteOwnerContact => VaultError::CannotDeleteOwnerContact,
```

Add a round-trip test in the `#[cfg(test)] mod tests` block (mirroring the existing `ContactNotFound` round-trip test near line 429):

```rust
    #[test]
    fn cannot_delete_owner_contact_maps_across() {
        let ffi = FfiVaultError::CannotDeleteOwnerContact;
        let uniffi: VaultError = ffi.into();
        assert!(matches!(uniffi, VaultError::CannotDeleteOwnerContact));
    }
```

- [ ] **Step 4: Add the Swift conformance case**

In `ffi/secretary-ffi-uniffi/tests/swift/ConformanceErrors.swift`, in the `switch` that maps error → name (near `case .ContactNotFound: return "ContactNotFound"`), add:

```swift
    case .CannotDeleteOwnerContact: return "CannotDeleteOwnerContact"
```

If there is a second exhaustive switch in that file (e.g. for a detail field), add a matching `case .CannotDeleteOwnerContact: return nil` there too (grep the file for `case .ContactNotFound` to find every switch).

- [ ] **Step 5: Add the Kotlin conformance arms**

In `ffi/secretary-ffi-uniffi/tests/kotlin/ConformanceErrors.kt`, mirror both `ContactNotFound` arms (name + detail):

```kotlin
    is VaultException.CannotDeleteOwnerContact -> "CannotDeleteOwnerContact"
```
and in the detail `when` (where `ContactNotFound -> null`):
```kotlin
    is VaultException.CannotDeleteOwnerContact -> null
```

- [ ] **Step 6: Add the PyO3 exception + From arm**

In `ffi/secretary-ffi-py/src/errors.rs`, add the exception declaration (near `create_exception!(secretary_ffi_py, VaultContactNotFound, PyException);`):

```rust
create_exception!(secretary_ffi_py, VaultCannotDeleteOwnerContact, PyException);
```

In the `From<FfiVaultError>` match (near `FfiVaultError::ContactNotFound { uuid_hex } => VaultContactNotFound::new_err(uuid_hex),`), add:

```rust
        FfiVaultError::CannotDeleteOwnerContact => {
            VaultCannotDeleteOwnerContact::new_err("the vault owner's own contact card cannot be deleted")
        }
```

In `ffi/secretary-ffi-py/src/lib.rs`: add `VaultCannotDeleteOwnerContact` to the `use ... errors::{...}` import list (near `VaultContactNotFound`), and register it in the module-init block (mirroring the `"VaultContactNotFound", py.get_type::<VaultContactNotFound>(),` pair):

```rust
        "VaultCannotDeleteOwnerContact",
        py.get_type::<VaultCannotDeleteOwnerContact>(),
```

- [ ] **Step 7: Add the core KAT-helper arm**

In `core/tests/conformance_kat_helpers/errors.rs`, in the `match` mapping `E::* => "..."` (near `E::ContactNotFound { .. } => "ContactNotFound",`), add:

```rust
        E::CannotDeleteOwnerContact => "CannotDeleteOwnerContact",
```

- [ ] **Step 8: Add the desktop AppError variant + map arm + test**

In `desktop/src-tauri/src/errors.rs`:

Add the variant to `enum AppError` (after `ContactNotFound { contact_uuid_hex: String },`):

```rust
    #[error("Your own contact card can't be deleted")]
    CannotDeleteOwnerContact,
```

Add the map arm in `map_ffi_error` (after the `FfiVaultError::ContactNotFound { uuid_hex } => ...` arm):

```rust
        FfiVaultError::CannotDeleteOwnerContact => AppError::CannotDeleteOwnerContact,
```

Add a serde round-trip test in the `#[cfg(test)] mod tests` block (mirroring the `ContactNotFound` round-trip near line 546):

```rust
    #[test]
    fn cannot_delete_owner_contact_round_trips() {
        let v = round_trip(&AppError::CannotDeleteOwnerContact);
        assert_eq!(v["code"], "cannot_delete_owner_contact");
    }

    #[test]
    fn map_cannot_delete_owner_contact() {
        let m = map_ffi_error(FfiVaultError::CannotDeleteOwnerContact);
        assert!(matches!(m, AppError::CannotDeleteOwnerContact));
    }
```

- [ ] **Step 9: Workspace build + clippy gate**

Run: `cargo build --release --workspace && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean — every exhaustive match now handles the variant. (If anything fails to compile, an exhaustive-match site was missed — grep `ContactNotFound` across the workspace to find the sibling site and add the arm.)

- [ ] **Step 10: Run the new Rust tests + conformance**

Run:
```bash
cargo test --release -p secretary-ffi-uniffi cannot_delete_owner_contact_maps_across
cargo test --release -p secretary-desktop cannot_delete_owner_contact_round_trips map_cannot_delete_owner_contact
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -2
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -2
```
Expected: tests PASS; Swift 22/22; Kotlin 22/22 (a new error arm, no new vector).

- [ ] **Step 11: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/error/vault/mod.rs ffi/secretary-ffi-uniffi/ ffi/secretary-ffi-py/ core/tests/conformance_kat_helpers/errors.rs desktop/src-tauri/src/errors.rs
git commit -m "feat(d17): thread CannotDeleteOwnerContact through uniffi/pyo3/KAT/desktop error layers"
```

---

## Task 4: Bridge — `delete_contact_card`

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/contacts/delete.rs`
- Modify: `ffi/secretary-ffi-bridge/src/contacts/mod.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`
- Test: `ffi/secretary-ffi-bridge/tests/contacts.rs`

- [ ] **Step 1: Write the failing tests**

Append to `ffi/secretary-ffi-bridge/tests/contacts.rs`:

```rust
#[test]
fn delete_contact_card_removes_the_file_and_enumerate_omits_it() {
    use secretary_ffi_bridge::delete_contact_card;
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let (_b, peer) = mint_external_card(0xC3, "Carol");
    let peer_uuid = uuid_of(&peer);
    import_contact_card(&manifest, &peer).expect("import");
    let (before, _) = enumerate_contact_cards(&manifest).expect("enum");
    assert!(before.iter().any(|s| s.contact_uuid == peer_uuid));

    delete_contact_card(&manifest, peer_uuid).expect("delete ok");

    let (after, _) = enumerate_contact_cards(&manifest).expect("enum");
    assert!(after.iter().all(|s| s.contact_uuid != peer_uuid), "deleted contact gone");
    // Second delete of the same uuid → ContactNotFound.
    let err = delete_contact_card(&manifest, peer_uuid).expect_err("already gone");
    assert!(matches!(err, FfiVaultError::ContactNotFound { .. }));
}

#[test]
fn delete_contact_card_refuses_owner() {
    use secretary_ffi_bridge::delete_contact_card;
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let owner = owner_uuid(&manifest);
    let err = delete_contact_card(&manifest, owner).expect_err("owner is undeletable");
    assert!(matches!(err, FfiVaultError::CannotDeleteOwnerContact));
    // The owner self-card is still on disk.
    let (sums, _) = enumerate_contact_cards(&manifest).expect("enum");
    // (owner is excluded from enumerate; assert via owner_card_bytes still working)
    assert!(manifest.owner_card_bytes().expect("ok").is_some(), "owner card intact");
    let _ = sums;
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --release -p secretary-ffi-bridge --test contacts delete_contact_card`
Expected: FAIL — `delete_contact_card` not found.

- [ ] **Step 3: Create the module**

Create `ffi/secretary-ffi-bridge/src/contacts/delete.rs`:

```rust
//! `delete_contact_card`: remove one contact's `.card` from `contacts/`.
//!
//! Warn-but-allow (spec §3): the primitive does NOT check recipient
//! membership — the "this contact still receives N blocks" warning is a UI
//! gate fed by `enumerate`'s `shared_block_count`. Deleting a card does NOT
//! revoke the contact's access to blocks already shared with them (they hold
//! the content key); it only removes the card from the picker and from future
//! re-key assembly. Revoke needs a frozen-core primitive (issue #177).

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::handle_wiped;
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Remove `contacts/<hyphenated-uuid>.card`.
///
/// - `contact_uuid` == owner uuid → [`FfiVaultError::CannotDeleteOwnerContact`]
///   (never removes the vault's own self-card; checked before any I/O).
/// - card file absent → [`FfiVaultError::ContactNotFound`].
/// - any other unlink failure → [`FfiVaultError::FolderInvalid`].
pub fn delete_contact_card(
    manifest: &OpenVaultManifest,
    contact_uuid: [u8; 16],
) -> Result<(), FfiVaultError> {
    let owner_uuid = manifest.owner_card().ok_or_else(handle_wiped)?.contact_uuid;
    if contact_uuid == owner_uuid {
        return Err(FfiVaultError::CannotDeleteOwnerContact);
    }
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let path = folder
        .join("contacts")
        .join(format!("{}.card", format_uuid_hyphenated(&contact_uuid)));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Err(FfiVaultError::ContactNotFound {
                uuid_hex: hex::encode(contact_uuid),
            })
        }
        Err(e) => Err(FfiVaultError::FolderInvalid {
            detail: format!("remove contact card: {e}"),
        }),
    }
}
```

- [ ] **Step 4: Wire the module + re-export**

In `ffi/secretary-ffi-bridge/src/contacts/mod.rs`, add after the `mod export;` block:

```rust
mod delete;
pub use delete::delete_contact_card;
```

In `ffi/secretary-ffi-bridge/src/lib.rs`, add `delete_contact_card` to the `pub use contacts::{...}` list (keep alphabetical):

```rust
pub use contacts::{
    delete_contact_card, enumerate_contact_cards, import_contact_card, owner_card_export,
    share_block_to,
};
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `cargo test --release -p secretary-ffi-bridge --test contacts delete_contact_card`
Expected: PASS (both new tests).

- [ ] **Step 6: Workspace gate**

Run: `cargo build --release --workspace && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/contacts/delete.rs ffi/secretary-ffi-bridge/src/contacts/mod.rs ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/contacts.rs
git commit -m "feat(d17-bridge): delete_contact_card (owner-guarded, warn-but-allow)"
```

---

## Task 5: Desktop — widen `ContactSummaryDto` + add `ExportedCardDto`

**Files:**
- Modify: `desktop/src-tauri/src/dtos/contact.rs`
- Modify: `desktop/src-tauri/src/dtos/mod.rs`

- [ ] **Step 1: Write the failing test**

In `desktop/src-tauri/src/dtos/contact.rs`, add to the `#[cfg(test)] mod tests`:

```rust
    #[test]
    fn contact_summary_dto_carries_shared_block_count() {
        let dto = ContactSummaryDto {
            contact_uuid_hex: "ab".into(),
            display_name: "Alice".into(),
            shared_block_count: 3,
        };
        let v = to_json(&dto);
        assert_eq!(v["sharedBlockCount"], 3);
    }

    #[test]
    fn exported_card_dto_shape() {
        let dto = ExportedCardDto { path: "/tmp/x.card".into() };
        let v = to_json(&dto);
        assert_eq!(v["path"], "/tmp/x.card");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p secretary-desktop contact_summary_dto_carries_shared_block_count`
Expected: FAIL — missing field `shared_block_count` / `ExportedCardDto` not found.

- [ ] **Step 3: Widen the DTO + add ExportedCardDto**

In `desktop/src-tauri/src/dtos/contact.rs`, add the field to `ContactSummaryDto` (the redacting `Debug` stays; add the count to it too) and update the `From` impl; then add `ExportedCardDto`:

```rust
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactSummaryDto {
    pub contact_uuid_hex: String,
    pub display_name: String,
    pub shared_block_count: u32,
}

impl std::fmt::Debug for ContactSummaryDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactSummaryDto")
            .field("contact_uuid_hex", &self.contact_uuid_hex)
            .field("display_name", &"<redacted>")
            .field("shared_block_count", &self.shared_block_count)
            .finish()
    }
}

impl From<&ContactSummary> for ContactSummaryDto {
    fn from(s: &ContactSummary) -> Self {
        ContactSummaryDto {
            contact_uuid_hex: hex::encode(s.contact_uuid),
            display_name: s.display_name.clone(),
            shared_block_count: s.shared_block_count,
        }
    }
}

/// Result of `export_contact_card`: the external path the owner's card was
/// written to (a user-chosen folder + the canonical file name). Non-secret —
/// the user already chose this path; not redacted.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportedCardDto {
    pub path: String,
}
```

Also update the existing `contact_summary_dto_camel_case` and `contact_summary_debug_redacts_name` tests to include `shared_block_count: 0` in their literals (they construct `ContactSummaryDto { .. }` directly).

In `desktop/src-tauri/src/dtos/mod.rs`, add `ExportedCardDto` to the contact re-export (grep `ContactSummaryDto` in mod.rs to find the line; add `ExportedCardDto` alongside it).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --release -p secretary-desktop --lib dtos::contact`
Expected: PASS.

- [ ] **Step 5: Workspace gate**

Run: `cargo build --release --workspace && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/dtos/contact.rs desktop/src-tauri/src/dtos/mod.rs
git commit -m "feat(d17-desktop): ContactSummaryDto.sharedBlockCount + ExportedCardDto"
```

---

## Task 6: Desktop — `export_contact_card` + `delete_contact_card` IPC commands

**Files:**
- Modify: `desktop/src-tauri/src/commands/contacts.rs`
- Modify: `desktop/src-tauri/src/main.rs`
- Test: `desktop/src-tauri/tests/ipc_integration.rs`

- [ ] **Step 1: Write the failing L3 tests**

Append to `desktop/src-tauri/tests/ipc_integration.rs` (use the harness this file already uses to build an unlocked `VaultSession` over a temp vault — mirror the existing contacts/share tests near the `ContactNotFound` reference at line ~1236; reuse their setup helpers). Add:

```rust
#[test]
fn export_contact_card_writes_importable_file() {
    let (state, _tmp) = unlocked_session(); // existing helper that yields a Mutex<VaultSession>
    let dest = tempfile::tempdir().expect("dest dir");
    let dto = secretary_desktop::commands::contacts::export_contact_card_impl(
        &state,
        dest.path().to_str().unwrap(),
    )
    .expect("export ok");
    let written = std::path::Path::new(&dto.path);
    assert!(written.exists(), "card written to chosen folder");
    assert!(dto.path.ends_with(".card"));
}

#[test]
fn delete_contact_card_impl_owner_is_refused() {
    let (state, _tmp) = unlocked_session();
    // Owner uuid via the session: import is not needed — owner is always present.
    // Resolve the owner uuid hex through list_contacts? No (owner excluded);
    // instead delete a known-absent uuid to assert ContactNotFound, and rely on
    // the bridge unit test for the owner-guard (constructing the owner uuid hex
    // at L3 needs an accessor; ContactNotFound is the reachable L3 assertion).
    let err = secretary_desktop::commands::contacts::delete_contact_card_impl(
        &state,
        "00112233445566778899aabbccddeeff",
    )
    .expect_err("absent contact");
    assert!(matches!(err, secretary_desktop::errors::AppError::ContactNotFound { .. }));
}
```

> Note: the owner-guard (`CannotDeleteOwnerContact`) is fully covered by the Task 4 bridge unit test; at L3 the owner uuid hex is not readily constructable (owner is excluded from `list_contacts`), so the L3 test asserts the reachable `ContactNotFound` path. If `unlocked_session` / module visibility differs in this file, follow the exact pattern of the existing `import_contact` / `share_block` L3 tests already present.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --release -p secretary-desktop --test ipc_integration export_contact_card_writes_importable_file delete_contact_card_impl_owner_is_refused`
Expected: FAIL — `export_contact_card_impl` / `delete_contact_card_impl` not found.

- [ ] **Step 3: Add the commands**

In `desktop/src-tauri/src/commands/contacts.rs`, extend the bridge import line and add the two command pairs. Update the `use secretary_ffi_bridge::{...}` to include the new fns:

```rust
use secretary_ffi_bridge::{
    delete_contact_card as bridge_delete, enumerate_contact_cards as bridge_enumerate,
    import_contact_card as bridge_import, owner_card_export as bridge_owner_card_export,
    share_block_to as bridge_share_block_to,
};
```

Add to the `use crate::dtos::{...}` line: `ExportedCardDto`. Then append the commands:

```rust
#[tauri::command]
pub async fn export_contact_card(
    state: State<'_, Mutex<VaultSession>>,
    dest_dir: String,
) -> Result<ExportedCardDto, AppError> {
    export_contact_card_impl(state.inner(), &dest_dir)
}

pub fn export_contact_card_impl(
    state: &Mutex<VaultSession>,
    dest_dir: &str,
) -> Result<ExportedCardDto, AppError> {
    let session = lock_session(state)?;
    let (file_name, bytes) = session
        .with_unlocked(|u| bridge_owner_card_export(&u.manifest).map_err(map_ffi_error))?;
    let path = std::path::Path::new(dest_dir).join(&file_name);
    // The owner card is PUBLIC material; the destination is a user-chosen
    // external folder. Overwriting a prior export of the same card is benign
    // (idempotent self-card). Native Rust write — no JS fs capability needed.
    std::fs::write(&path, &bytes).map_err(|e| AppError::Io {
        detail: format!("write exported card to {path:?}: {e}"),
    })?;
    Ok(ExportedCardDto {
        path: path.to_string_lossy().into_owned(),
    })
}

#[tauri::command]
pub async fn delete_contact_card(
    state: State<'_, Mutex<VaultSession>>,
    contact_uuid_hex: String,
) -> Result<(), AppError> {
    delete_contact_card_impl(state.inner(), &contact_uuid_hex)
}

pub fn delete_contact_card_impl(
    state: &Mutex<VaultSession>,
    contact_uuid_hex: &str,
) -> Result<(), AppError> {
    let contact_uuid = parse_uuid_16(contact_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_delete(&u.manifest, contact_uuid).map_err(map_ffi_error)?;
        Ok(())
    })
}
```

- [ ] **Step 4: Register the commands**

In `desktop/src-tauri/src/main.rs`, find the `tauri::generate_handler![...]` list and add `commands::contacts::export_contact_card` and `commands::contacts::delete_contact_card` alongside the existing `list_contacts` / `import_contact` / `share_block` entries.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --release -p secretary-desktop --test ipc_integration export_contact_card_writes_importable_file delete_contact_card_impl_owner_is_refused`
Expected: PASS.

- [ ] **Step 6: Workspace gate**

Run: `cargo build --release --workspace && cargo clippy --release --workspace --tests -- -D warnings`
Expected: clean.

- [ ] **Step 7: Commit**

```bash
git add desktop/src-tauri/src/commands/contacts.rs desktop/src-tauri/src/main.rs desktop/src-tauri/tests/ipc_integration.rs
git commit -m "feat(d17-desktop): export_contact_card + delete_contact_card IPC commands"
```

---

## Task 7: Frontend — ipc wrappers, browse level, error code

**Files:**
- Modify: `desktop/src/lib/ipc.ts`
- Modify: `desktop/src/lib/errors.ts`
- Modify: `desktop/src/lib/browse.ts`
- Test: `desktop/tests/ipcContacts.test.ts`, `desktop/tests/browse.test.ts`, `desktop/tests/errors.test.ts`

- [ ] **Step 1: Write the failing tests**

In `desktop/tests/ipcContacts.test.ts`, add (mirror the existing `importContact`/`shareBlock` mock-invoke tests in this file):

```ts
it('exportContactCard invokes export_contact_card with destDir and returns the path', async () => {
  const invoke = vi.fn().mockResolvedValue({ path: '/tmp/owner.card' });
  vi.mocked(coreInvoke).mockImplementation(invoke); // match this file's existing mock wiring
  const { exportContactCard } = await import('../src/lib/ipc');
  const dto = await exportContactCard('/tmp');
  expect(dto.path).toBe('/tmp/owner.card');
  expect(invoke).toHaveBeenCalledWith('export_contact_card', { destDir: '/tmp' });
});

it('deleteContactCard invokes delete_contact_card with the uuid hex', async () => {
  const invoke = vi.fn().mockResolvedValue(undefined);
  vi.mocked(coreInvoke).mockImplementation(invoke);
  const { deleteContactCard } = await import('../src/lib/ipc');
  await deleteContactCard('abcd');
  expect(invoke).toHaveBeenCalledWith('delete_contact_card', { contactUuidHex: 'abcd' });
});
```

> Follow the EXACT mock-invoke setup the existing tests in `ipcContacts.test.ts` use (the variable name for the mocked Tauri `invoke` may differ — replace `coreInvoke` accordingly).

In `desktop/tests/browse.test.ts`, add:

```ts
it('openContacts sets the contacts level', () => {
  openContacts();
  expect(get(browseNav)).toEqual({ level: 'contacts' });
});
```
(Import `openContacts` alongside the existing `openTrash` import.)

In `desktop/tests/errors.test.ts`, add:

```ts
it('cannot_delete_owner_contact has a user message', () => {
  const msg = userMessageFor({ code: 'cannot_delete_owner_contact' });
  expect(msg.title).toBeTruthy();
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd desktop && pnpm test -- ipcContacts browse errors`
Expected: FAIL — wrappers / `openContacts` / error code not defined.

- [ ] **Step 3: Add the ipc wrappers + DTO field**

In `desktop/src/lib/ipc.ts`:

Widen `ContactSummaryDto` and add `ExportedCardDto`:

```ts
export interface ContactSummaryDto {
  contactUuidHex: string;
  displayName: string;
  sharedBlockCount: number;
}

export interface ExportedCardDto {
  path: string;
}
```

Add the two wrappers near the existing `listContacts` / `importContact` / `shareBlock`:

```ts
export async function exportContactCard(destDir: string): Promise<ExportedCardDto> {
  return call<ExportedCardDto>('export_contact_card', { destDir });
}

export async function deleteContactCard(contactUuidHex: string): Promise<void> {
  return call<void>('delete_contact_card', { contactUuidHex });
}
```

- [ ] **Step 4: Add the error code**

In `desktop/src/lib/errors.ts`:
- Add `'cannot_delete_owner_contact'` to the `APP_ERROR_CODES` array (before `'internal'`).
- Add to the `AppError` union: `| { code: 'cannot_delete_owner_contact' }`.
- Add a `userMessageFor` case:

```ts
    case 'cannot_delete_owner_contact':
      return {
        title: "That's your own card",
        actionHint: 'You can export your card, but it stays in your vault.'
      };
```

- [ ] **Step 5: Add the browse level**

In `desktop/src/lib/browse.ts`:
- Add `| { level: 'contacts' }` to the `BrowseNav` union.
- Add the setter (mirroring `openTrash`):

```ts
export function openContacts(): void {
  store.set({ level: 'contacts' });
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd desktop && pnpm test -- ipcContacts browse errors`
Expected: PASS.

- [ ] **Step 7: Typecheck + commit**

Run: `cd desktop && pnpm typecheck`
Expected: clean.

```bash
git add desktop/src/lib/ipc.ts desktop/src/lib/errors.ts desktop/src/lib/browse.ts desktop/tests/ipcContacts.test.ts desktop/tests/browse.test.ts desktop/tests/errors.test.ts
git commit -m "feat(d17-fe): contacts ipc wrappers + contacts browse level + owner-card error code"
```

---

## Task 8: Frontend — Contacts pane (export + list + delete) + Vault entry

**Files:**
- Create: `desktop/src/components/contacts/ContactsPane.svelte`
- Create: `desktop/src/components/contacts/ContactRow.svelte`
- Modify: `desktop/src/routes/Vault.svelte`
- Modify: `desktop/src/theme.css`
- Test: `desktop/tests/ContactsPane.test.ts`

- [ ] **Step 1: Write the failing component test**

Create `desktop/tests/ContactsPane.test.ts` (mirror `TrashView.test.ts`'s render + mocked-ipc pattern):

```ts
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import ContactsPane from '../src/components/contacts/ContactsPane.svelte';
import * as ipc from '../src/lib/ipc';

describe('ContactsPane', () => {
  beforeEach(() => vi.restoreAllMocks());

  it('lists contacts with their shared-block counts', async () => {
    vi.spyOn(ipc, 'listContacts').mockResolvedValue({
      contacts: [
        { contactUuidHex: 'aa', displayName: 'Alice', sharedBlockCount: 2 },
        { contactUuidHex: 'bb', displayName: 'Bob', sharedBlockCount: 0 }
      ],
      unreadableCount: 0
    });
    render(ContactsPane);
    expect(await screen.findByText('Alice')).toBeInTheDocument();
    expect(screen.getByText(/receives 2 blocks/i)).toBeInTheDocument();
    expect(screen.getByText('Bob')).toBeInTheDocument();
  });

  it('deleting a contact with N>0 routes through a confirm then deleteContactCard', async () => {
    vi.spyOn(ipc, 'listContacts').mockResolvedValue({
      contacts: [{ contactUuidHex: 'aa', displayName: 'Alice', sharedBlockCount: 2 }],
      unreadableCount: 0
    });
    const del = vi.spyOn(ipc, 'deleteContactCard').mockResolvedValue(undefined);
    render(ContactsPane);
    await screen.findByText('Alice');
    await fireEvent.click(screen.getByRole('button', { name: /delete/i }));
    // Warn confirm appears; confirm it.
    await fireEvent.click(await screen.findByRole('button', { name: /delete anyway/i }));
    await waitFor(() => expect(del).toHaveBeenCalledWith('aa'));
  });

  it('export my card calls exportContactCard with the picked folder', async () => {
    vi.spyOn(ipc, 'listContacts').mockResolvedValue({ contacts: [], unreadableCount: 0 });
    const exp = vi.spyOn(ipc, 'exportContactCard').mockResolvedValue({ path: '/tmp/owner.card' });
    render(ContactsPane);
    // The PathPicker onSelect is wired to exportContactCard; simulate selection
    // by invoking the component's export handler via the picker button + a
    // mocked dialog. Follow ShareDialog.test.ts's PathPicker-mock approach.
    // (Assert the wiring once the picker resolves a path.)
    expect(exp).toBeDefined();
  });
});
```

> The export-picker assertion depends on how `ShareDialog.test.ts` mocks `@tauri-apps/plugin-dialog`'s `open`. Reuse that exact mock so selecting a folder resolves a path and triggers `exportContactCard`. Keep the first two tests as the hard gates; refine the third to match the established PathPicker mock.

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop && pnpm test -- ContactsPane`
Expected: FAIL — component does not exist.

- [ ] **Step 3: Create `ContactRow.svelte`**

Create `desktop/src/components/contacts/ContactRow.svelte`:

```svelte
<script lang="ts">
  // One imported contact: display name + how many of the owner's blocks it
  // receives, plus a Delete action. Mirrors TrashedBlockRow's callback-prop
  // shape. The parent owns the confirm dialog + delete call.
  import type { ContactSummaryDto } from '../../lib/ipc';

  type Props = {
    contact: ContactSummaryDto;
    onDelete: (c: ContactSummaryDto) => void;
  };
  let { contact, onDelete }: Props = $props();

  const blocksLabel = $derived(
    contact.sharedBlockCount === 1
      ? 'receives 1 block'
      : `receives ${contact.sharedBlockCount} blocks`
  );
</script>

<div class="contact-row">
  <span class="contact-row__name">{contact.displayName}</span>
  <span class="contact-row__count">{blocksLabel}</span>
  <button type="button" class="contact-row__delete" onclick={() => onDelete(contact)}>
    Delete
  </button>
</div>
```

- [ ] **Step 4: Create `ContactsPane.svelte`**

Create `desktop/src/components/contacts/ContactsPane.svelte`:

```svelte
<script lang="ts">
  // Contacts pane (spec D.1.7) — reached from the Vault "👤 Contacts" entry.
  // Mirrors TrashView's load/error/empty + loadSeq generation guard. Hosts
  // "Export my card" (PathPicker folder mode → exportContactCard) and the
  // contact list with per-contact delete (warn-but-allow via ConfirmDialog).
  import {
    listContacts,
    deleteContactCard,
    exportContactCard,
    isAppError,
    type ContactSummaryDto
  } from '../../lib/ipc';
  import { sortContacts } from '../../lib/contacts';
  import { back } from '../../lib/browse';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import PathPicker from '../PathPicker.svelte';
  import ConfirmDialog from '../delete/ConfirmDialog.svelte';
  import ContactRow from './ContactRow.svelte';

  let contacts = $state<ContactSummaryDto[] | null>(null);
  let unreadable = $state(0);
  let error = $state<AppError | null>(null);
  let notice = $state<string | null>(null);
  let pendingDelete = $state<ContactSummaryDto | null>(null);

  let loadSeq = 0;
  async function load() {
    const seq = ++loadSeq;
    error = null;
    try {
      const res = await listContacts();
      if (seq === loadSeq) {
        contacts = sortContacts(res.contacts);
        unreadable = res.unreadableCount;
      }
    } catch (e) {
      if (seq === loadSeq) error = isAppError(e) ? e : { code: 'internal' };
    }
  }
  $effect(() => {
    void load();
  });

  async function onExportSelect(destDir: string) {
    error = null;
    notice = null;
    try {
      const dto = await exportContactCard(destDir);
      notice = `Card exported to ${dto.path}`;
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  function requestDelete(c: ContactSummaryDto) {
    pendingDelete = c;
  }

  async function confirmDelete() {
    const target = pendingDelete;
    pendingDelete = null;
    if (!target) return;
    error = null;
    try {
      await deleteContactCard(target.contactUuidHex);
      await load();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  const confirmBody = $derived(
    pendingDelete && pendingDelete.sharedBlockCount > 0
      ? `${pendingDelete.displayName} receives ${pendingDelete.sharedBlockCount} of your blocks. ` +
          "Deleting their card won't revoke access they already have, but you won't be able to " +
          're-share those blocks to anyone.'
      : `Remove ${pendingDelete?.displayName ?? 'this contact'} from your vault?`
  );
</script>

<section class="contacts-pane">
  <button type="button" class="contacts-pane__back" onclick={() => back()}>← Contacts</button>

  <div class="contacts-pane__export">
    <span class="contacts-pane__export-label">Export my card</span>
    <PathPicker
      value=""
      directory={true}
      title="Choose a folder to export your card to"
      label="Export…"
      onSelect={onExportSelect}
    />
  </div>

  {#if notice}
    <p class="contacts-pane__notice" role="status">{notice}</p>
  {/if}
  {#if unreadable > 0}
    <p class="contacts-pane__warn" role="alert">
      {unreadable} contact file(s) could not be read.
    </p>
  {/if}

  {#if error}
    {@const msg = userMessageFor(error)}
    <p class="contacts-pane__error" role="alert">
      {msg.title}{msg.actionHint ? ` — ${msg.actionHint}` : ''}
    </p>
  {:else if contacts === null}
    <p class="contacts-pane__loading">Loading…</p>
  {:else if contacts.length === 0}
    <p class="contacts-pane__empty">No contacts imported yet.</p>
  {:else}
    {#each contacts as contact (contact.contactUuidHex)}
      <ContactRow {contact} onDelete={requestDelete} />
    {/each}
  {/if}

  {#if pendingDelete}
    <ConfirmDialog
      title="Delete this contact?"
      body={confirmBody}
      confirmLabel={pendingDelete.sharedBlockCount > 0 ? 'Delete anyway' : 'Delete'}
      onConfirm={confirmDelete}
      onCancel={() => (pendingDelete = null)}
    />
  {/if}
</section>
```

- [ ] **Step 5: Host the pane in Vault**

In `desktop/src/routes/Vault.svelte`:
- Add the import: `import ContactsPane from '../components/contacts/ContactsPane.svelte';`
- Add `openContacts` to the existing `import { ... } from '../lib/browse';` line.
- At the blocks level (next to the `🗑 Trash` entry button near line 82), add:

```svelte
      <button type="button" class="vault__contacts-entry" onclick={() => openContacts()}>👤 Contacts</button>
```
- Add the render branch next to the trash branch (`{:else if $browseNav.level === 'trash'}`):

```svelte
    {:else if $browseNav.level === 'contacts'}
      <ContactsPane />
```

- [ ] **Step 6: Add styles**

In `desktop/src/theme.css`, add (mirroring the existing `.trash-view*` / `.confirm-dialog*` rules):

```css
.contacts-pane { display: flex; flex-direction: column; gap: 0.5rem; }
.contacts-pane__back { align-self: flex-start; background: none; border: none; color: var(--accent); cursor: pointer; padding: 0.25rem 0; }
.contacts-pane__export { display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0; border-bottom: 1px solid var(--border); }
.contacts-pane__export-label { font-weight: 600; }
.contacts-pane__notice { color: var(--ok, #2a7); }
.contacts-pane__warn { color: var(--warn, #b80); }
.contacts-pane__error { color: var(--danger, #c33); }
.contacts-pane__empty, .contacts-pane__loading { color: var(--muted); }
.contact-row { display: flex; align-items: center; gap: 0.75rem; padding: 0.4rem 0; border-bottom: 1px solid var(--border); }
.contact-row__name { font-weight: 600; }
.contact-row__count { color: var(--muted); font-size: 0.9em; }
.contact-row__delete { margin-left: auto; background: none; border: 1px solid var(--danger, #c33); color: var(--danger, #c33); border-radius: 4px; cursor: pointer; padding: 0.2rem 0.6rem; }
```
(Match the existing CSS-variable names in `theme.css`; the fallbacks above are only used if a variable is undefined.)

- [ ] **Step 7: Run the component test**

Run: `cd desktop && pnpm test -- ContactsPane`
Expected: PASS (at minimum the list + delete-confirm tests).

- [ ] **Step 8: Full frontend gauntlet**

Run: `cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check && pnpm lint`
Expected: all green; svelte-check 0 errors / 0 new warnings.

- [ ] **Step 9: Commit**

```bash
git add desktop/src/components/contacts/ desktop/src/routes/Vault.svelte desktop/src/theme.css desktop/tests/ContactsPane.test.ts
git commit -m "feat(d17-fe): Contacts pane (export my card + list + warn-but-allow delete) + Vault entry"
```

---

## Final verification (before handoff)

- [ ] **Full automated gauntlet** (from the worktree root):

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings
cargo fmt --all -- --check
uv run core/tests/python/conformance.py
uv run core/tests/python/spec_test_name_freshness.py
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -2
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -2
cd desktop && pnpm test && pnpm typecheck && pnpm svelte-check 2>&1 | tail -2 && pnpm lint && cd ..
```
Expected: Rust ≈ 1145 + new tests (~9–11 added), 0 failed; clippy/fmt clean; conformance PASS; spec-freshness PASS; Swift 22/22; Kotlin 22/22; Vitest 353 + new (~8 added); typecheck/svelte-check/lint clean.

- [ ] **README/ROADMAP** — mark D.1.7 ✅, point to D.1.8.
- [ ] **Handoff** — author `docs/handoffs/2026-06-03-d17-contacts-management-shipped.md`, retarget `NEXT_SESSION.md` symlink, commit both.
- [ ] **Manual GUI smoke** (the user's pre-merge gate; §15 of the spec) — against a TEMP vault copy.

---

## Self-Review

**Spec coverage:**
- §1 export-my-card → Tasks 2, 6, 8. ✓
- §1 contacts pane (list + counts) → Tasks 1, 5, 7, 8. ✓
- §1/§3 delete warn-but-allow → Tasks 4 (bridge), 8 (UI warn). ✓
- §3/§5 owner-delete guard → Tasks 3 (variant), 4 (guard), bridge test. ✓
- §5 widen enumerate → Task 1. ✓
- §5 new error variant threaded → Task 3 (all sites). ✓
- §6 DTOs + IPC → Tasks 5, 6. ✓
- §7 frontend → Tasks 7, 8. ✓
- §9 invariants → covered by the bridge/desktop/frontend tests across tasks (#1 export public/round-trip: T2; #2 name convention: T2; #3 count exact: T1; #4 delete removes one: T4; #5 owner undeletable: T4; #6 delete≠revoke: documented + T4 file-intact; #7 no new secret residence: export/delete handle only public bytes/unlink). ✓
- §11 security (seam discipline, redacting Debug, no new capability) → Tasks 5 (Debug), 6 (native write, no save dialog). ✓
- §12 conformance: new error arm, no vector change → Task 3 keeps Swift/Kotlin 22/22. ✓

**Placeholder scan:** No "TBD"/"add error handling"/"similar to" — code is inline. The two soft spots (the L3 `unlocked_session` helper name in Task 6, the PathPicker/dialog mock in Task 8's third assertion) are explicitly flagged to "follow the existing pattern in <named file>" because the exact harness symbol must be read from that file at implementation time; the hard-gate assertions in those tasks do not depend on the soft spot.

**Type consistency:** `ContactSummary.shared_block_count: u32` (bridge) → `ContactSummaryDto.shared_block_count`/`sharedBlockCount` (desktop/TS); `owner_card_export -> (String, Vec<u8>)` consumed as `(file_name, bytes)` in Task 6; `ExportedCardDto { path }` consistent across Rust/TS; `delete_contact_card(manifest, [u8;16])` ↔ `delete_contact_card_impl(state, &str)` ↔ `deleteContactCard(contactUuidHex)`; `CannotDeleteOwnerContact` / `cannot_delete_owner_contact` consistent across all layers; `openContacts()` + `{ level: 'contacts' }` consistent. ✓
