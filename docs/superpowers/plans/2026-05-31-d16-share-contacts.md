# D.1.6 Share a block + desktop contacts subsystem — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a user with an unlocked vault import a peer's contact card, pick that contact in a share dialog, and share an owner-authored block with them — wiring the already-existing `core::share_block` through three new bridge primitives → IPC → UI, with card bytes/public keys never crossing the IPC seam.

**Architecture:** Bridge-thick. Three NEW bridge primitives own all `contacts/` I/O: `enumerate_contact_cards` (parse + `verify_self` every `contacts/*.card`, omit the owner's own card, count unreadable), `import_contact_card` (TOFU: parse + `verify_self` + dedup-reject + atomic write), and `share_block_to` (read the block's recipient UUIDs from the manifest, load every existing card + the new card from `contacts/`, delegate to the EXISTING `share::share_block` wrapper). The desktop adds three thin IPC commands, five typed `AppError` variants, a `ContactSummaryDto`/`ListContactsDto`, and reads the user-chosen `.card` file's bytes at the command edge. The frontend adds `lib/contacts.ts`, three ipc wrappers, five error codes, and a `ShareDialog` (picker + inline import) opened from a `BlockCard` 🔗 action.

**Tech Stack:** Rust (bridge primitives over `secretary-core` `ContactCard`/`share_block`/`io::write_atomic`/`format_uuid_hyphenated`; Tauri 2 commands + `*_impl` split; `serde` DTOs; `thiserror` `AppError`), Svelte 5 runes + TypeScript (Vitest, `@testing-library/svelte`, `@tauri-apps/plugin-dialog`).

**Spec:** `docs/superpowers/specs/2026-05-31-d16-share-contacts-design.md`

---

## Ground-truth facts the plan relies on (verified against the tree)

- **`core::share_block` + the bridge wrapper already exist.** Bridge `share_block(identity, manifest, block_uuid, existing_recipient_cards: &[Vec<u8>], new_recipient: &[u8], device_uuid, now_ms) -> Result<(), FfiVaultError>` lives at `ffi/secretary-ffi-bridge/src/share/orchestration.rs:56`, re-exported `pub use share::share_block;` in `lib.rs`. It snapshots via `manifest.snapshot_for_save_block()`, decodes the supplied CBOR cards, calls `secretary_core::vault::share_block`, and writes back. **D.1.6 does NOT reimplement it — `share_block_to` assembles card bytes and calls it.**
- **`ContactCard::from_canonical_cbor` PARSES ONLY.** It ends `Ok(card)` (`core/src/identity/card.rs:397`) with no signature check. The both-halves gate is the **separate** `card.verify_self()` (`card.rs:418`, "Returns `Ok(())` only if both Ed25519 and ML-DSA-65 verify"). `core::vault::restore_block` (`orchestrators.rs:1852+`) establishes the canonical scan: `from_canonical_cbor` THEN `verify_self()`, `continue`-ing past any card that fails either. **Import + enumerate MUST do the same.**
- **Filename convention:** `contacts/<format_uuid_hyphenated(contact_uuid)>.card` — lowercase 8-4-4-4-12 **hyphenated** (NOT `hex::encode`). `format_uuid_hyphenated(&[u8;16]) -> String` is re-exported at `secretary_core::vault::format_uuid_hyphenated` (`core/src/vault/mod.rs:62`). `create_vault` writes `contacts/{format_uuid_hyphenated(owner_uuid)}.card` (`orchestrators.rs:352-353`); `share_block` writes the new recipient card the same way (`orchestrators.rs:1444-1445`). **Error fields use `hex::encode` (32 hex, no hyphens) per existing `BlockNotFound { uuid_hex }`; FILE names use `format_uuid_hyphenated`. Do not conflate them.**
- **Manifest recipients:** `core::vault::BlockEntry.recipients: Vec<[u8; 16]>` ("Contact UUIDs of each recipient (always includes owner)"). Read by `body.blocks.iter().find(|b| b.block_uuid == uuid)`. Bridge `OpenVaultManifest` exposes `pub(crate) fn manifest_body(&self) -> Option<Manifest>` and `pub(crate) fn vault_folder(&self) -> Option<PathBuf>` and `pub(crate) fn owner_card(&self) -> Option<ContactCard>` (`ffi/secretary-ffi-bridge/src/vault/manifest.rs`).
- **Atomic write:** `secretary_core::vault::io::write_atomic(path: &Path, bytes: &[u8]) -> io::Result<()>` (rename(2) semantics; the §9 atomicity contract). Reachable from the bridge.
- **`FfiVaultError`** (`ffi/secretary-ffi-bridge/src/error/vault/mod.rs:35`, `#[derive(Debug, Error)]`) ALREADY has `NotAuthor { expected_fingerprint_hex, got_fingerprint_hex }`, `RecipientAlreadyPresent`, `MissingRecipientCard { recipient_fingerprint_hex }`, `CardDecodeFailure { detail }`, `BlockNotFound { uuid_hex }`. D.1.6 adds `ContactAlreadyExists { uuid_hex }`, `ContactNotFound { uuid_hex }` (bridge-internal — not produced by `From<VaultError>`).
- **Desktop `map_ffi_error`** (`desktop/src-tauri/src/errors.rs:194`) currently folds `NotAuthor | RecipientAlreadyPresent | MissingRecipientCard` to `Internal` (the arm at `errors.rs:271-275`). Adding two FfiVaultError variants makes this match non-exhaustive → compile error until Task 4 routes them.
- **Desktop command pattern** (`commands/delete.rs`): `#[tauri::command] async fn NAME(state: State<'_, Mutex<VaultSession>>, args…) -> Result<Dto, AppError>` → `NAME_impl(state.inner(), …)`; `*_impl` does `parse_uuid_16` (`commands/shared.rs`) → `lock_session` → `session.with_unlocked(|u| { … u.identity, u.manifest, u.device_uuid … })`; `now_ms()` from `crate::auto_lock`.
- **Bridge share test harness** (`ffi/secretary-ffi-bridge/tests/share_block_helpers/mod.rs`): `fresh_writable_vault() -> (TempDir, UnlockedIdentity, OpenVaultManifest)`; `mint_external_card(seed: u8, display_name: &str) -> (IdentityBundle, Vec<u8>)` (self-signed card + canonical CBOR bytes); `save_one_record_block(&identity, &manifest, block_uuid, record_uuid, field_name, field_value, now_ms)`; consts `DEVICE_UUID`, `NEW_BLOCK_UUID`, `NEW_RECORD_UUID`, `NOW_MS_BASE`; `manifest.find_block(&uuid).recipient_uuids`.
- **Desktop L3 harness** (`desktop/src-tauri/tests/ipc_integration.rs`): `unlocked_state()` (golden, read-only), `ephemeral_golden_copy() -> (TempDir, PathBuf)`, `create::create_vault_impl(folder_path, display_name, &SecretBytes, created_at_ms, &mut rng) -> Result<CreateVaultDto, AppError>` (called at `:597`, `:624`, `:730`, `:930`). Golden owner-authored block: `GOLDEN_BLOCK_UUID_HEX = "112233445566778899aabbccddeeff00"`.

---

## File Structure

### Bridge (Rust) — `ffi/secretary-ffi-bridge/`

| File | Status | Responsibility |
|---|---|---|
| `src/contacts/mod.rs` | **Create** | `pub struct ContactSummary { contact_uuid: [u8;16], display_name: String }`; `mod enumerate/import/share`; re-exports; a shared `pub(crate) fn read_verified_card(bytes: &[u8]) -> Result<ContactCard, FfiVaultError>` (parse + `verify_self`). |
| `src/contacts/enumerate.rs` | **Create** | `enumerate_contact_cards(manifest) -> Result<(Vec<ContactSummary>, usize), FfiVaultError>` — scan `contacts/*.card`, parse+verify, omit owner, count failures. |
| `src/contacts/import.rs` | **Create** | `import_contact_card(manifest, card_bytes) -> Result<ContactSummary, FfiVaultError>` — verify → dedup-reject → `write_atomic`. |
| `src/contacts/share.rs` | **Create** | `share_block_to(identity, manifest, block_uuid, new_recipient_uuid, device_uuid, now_ms) -> Result<(), FfiVaultError>` — assemble existing+new card bytes from `contacts/`, delegate to `crate::share::share_block`. |
| `src/error/vault/mod.rs` | Modify | Add `ContactAlreadyExists { uuid_hex }`, `ContactNotFound { uuid_hex }`. |
| `src/lib.rs` | Modify | `pub mod contacts;` + `pub use contacts::{enumerate_contact_cards, import_contact_card, share_block_to, ContactSummary};` |
| `tests/contacts.rs` | **Create** | Integration tests (reuse `mod share_block_helpers`). |

> NOT mirrored on uniffi/pyo3 (no mobile/Python consumer) — tracked by #167. No conformance-KAT change (existing card + share wire only).

### Desktop (Rust) — `desktop/src-tauri/`

| File | Status | Responsibility |
|---|---|---|
| `src/errors.rs` | Modify | Add typed `NotAuthor`, `RecipientAlreadyPresent`, `MissingRecipientCard`, `ContactAlreadyExists { contact_uuid_hex }`, `ContactNotFound { contact_uuid_hex }`; route the matching `FfiVaultError` variants in `map_ffi_error`. |
| `src/dtos/contact.rs` | **Create** | `ContactSummaryDto { contact_uuid_hex, display_name }` (camelCase; redacting `Debug`) + `ListContactsDto { contacts, unreadable_count }`. |
| `src/dtos/mod.rs` | Modify | `mod contact;` + re-export. |
| `src/commands/contacts.rs` | **Create** | `list_contacts` / `import_contact` / `share_block` thin commands + `*_impl`. `import_contact` reads the chosen `.card` file bytes via `std::fs::read`. |
| `src/commands/mod.rs` | Modify | `pub mod contacts;` |
| `src/main.rs` | Modify | Register the three commands. |
| `tests/ipc_integration.rs` | Modify | L3: list/import/share over an ephemeral vault + a created peer vault's card file; typed-error paths. |

### Frontend (Svelte + TS) — `desktop/`

| File | Status | Responsibility |
|---|---|---|
| `src/lib/contacts.ts` | **Create** | Pure `sortContacts(dtos)` (by `displayName`). |
| `src/lib/ipc.ts` | Modify | `ContactSummaryDto`/`ListContactsDto` interfaces; `listContacts()` / `importContact(cardPath)` / `shareBlock(blockUuidHex, recipientUuidHex)`. |
| `src/lib/errors.ts` | Modify | Five new codes + union members + `userMessageFor` cases. |
| `src/components/share/ShareDialog.svelte` | **Create** | Picker (sorted) + "Import a contact…" (file PathPicker) + Share; typed-error rendering; `unreadableCount` warning. |
| `src/components/PathPicker.svelte` | Modify | Optional `directory`/`filters` props so it can pick a `.card` FILE (default stays folder). |
| `src/components/BlockCard.svelte` | Modify | Optional `onShare?` → 🔗 button. |
| `src/routes/Vault.svelte` | Modify | Host `ShareDialog`; wire `onShare`. |
| `src/theme.css` | Modify | `.share-dialog*`, `.block-card__share`, `.contact-row*` (Vite-6 preprocessCSS workaround, #153). |

### Frontend tests — `desktop/tests/`

| File | Status | Covers |
|---|---|---|
| `tests/contacts.test.ts` | **Create** | `sortContacts`. |
| `tests/ipcContacts.test.ts` | **Create** | `listContacts`/`importContact`/`shareBlock` invoke shapes. |
| `tests/ShareDialog.test.ts` | **Create** | empty→import→populated→share; warning line; typed-error render. |

---

## Task 1: Bridge — `enumerate_contact_cards` + `ContactSummary` + module scaffold

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/contacts/mod.rs`
- Create: `ffi/secretary-ffi-bridge/src/contacts/enumerate.rs`
- Create: `ffi/secretary-ffi-bridge/tests/contacts.rs`
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs`

- [ ] **Step 1: Write the failing test** — append to a NEW `ffi/secretary-ffi-bridge/tests/contacts.rs`:

```rust
//! Integration tests for the D.1.6 contacts subsystem. Reuse the share
//! test harness (writable golden copy + runtime-minted external cards).
mod share_block_helpers;

use secretary_core::identity::card::ContactCard;
use secretary_core::vault::format_uuid_hyphenated;
use secretary_ffi_bridge::{enumerate_contact_cards, FfiVaultError};
use share_block_helpers::{fresh_writable_vault, mint_external_card};
use std::fs;

/// Write raw card bytes into the vault's contacts/ dir under the canonical
/// hyphenated filename. Returns the card's contact_uuid.
fn place_card(folder: &std::path::Path, card_bytes: &[u8]) -> [u8; 16] {
    let card = ContactCard::from_canonical_cbor(card_bytes).expect("valid card");
    let path = folder
        .join("contacts")
        .join(format!("{}.card", format_uuid_hyphenated(&card.contact_uuid)));
    fs::write(&path, card_bytes).expect("write card");
    card.contact_uuid
}

#[test]
fn enumerate_returns_placed_cards_excluding_owner() {
    let (tmp, _identity, manifest) = fresh_writable_vault();
    let folder = tmp.path();
    let (_b1, alice) = mint_external_card(0xA1, "Alice");
    let (_b2, bob) = mint_external_card(0xB2, "Bob");
    place_card(folder, &alice);
    place_card(folder, &bob);

    let (summaries, unreadable) = enumerate_contact_cards(&manifest).expect("enumerate ok");

    assert_eq!(unreadable, 0, "all placed cards are valid");
    let names: Vec<&str> = summaries.iter().map(|s| s.display_name.as_str()).collect();
    assert!(names.contains(&"Alice") && names.contains(&"Bob"));
    // The owner's own self-card (written by create_vault) is omitted.
    assert_eq!(summaries.len(), 2, "owner card excluded, 2 peers placed");
}

#[test]
fn enumerate_counts_unreadable_and_unverified() {
    let (tmp, _identity, manifest) = fresh_writable_vault();
    let folder = tmp.path();
    let (_b1, alice) = mint_external_card(0xA1, "Alice");
    place_card(folder, &alice);
    // Garbage .card → parse failure.
    fs::write(folder.join("contacts").join("garbage.card"), b"not cbor").unwrap();
    // Tampered card → parse OK but verify_self fails (flip a signature byte).
    let mut tampered = alice.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    fs::write(folder.join("contacts").join("11111111-1111-1111-1111-111111111111.card"), &tampered).unwrap();

    let (summaries, unreadable) = enumerate_contact_cards(&manifest).expect("enumerate ok");
    assert_eq!(summaries.len(), 1, "only the intact Alice card is valid");
    assert_eq!(unreadable, 2, "garbage + tampered both counted");
}
```

- [ ] **Step 2: Run to verify it fails (no such symbol)**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test contacts 2>&1 | tail -20`
Expected: FAIL — `cannot find function enumerate_contact_cards`.

- [ ] **Step 3: Create the module scaffold** — `ffi/secretary-ffi-bridge/src/contacts/mod.rs`:

```rust
//! D.1.6 contacts subsystem: enumerate / import contact cards and share a
//! block by recipient UUID. All `contacts/` directory I/O lives here so the
//! desktop layer never learns the on-disk vault layout (spec §3).
//!
//! Trust model: TOFU. Cards are PARSED with `ContactCard::from_canonical_cbor`
//! then cryptographically self-verified with `verify_self()` (both Ed25519 ∧
//! ML-DSA-65 halves) before being trusted — mirroring `core::vault::restore_block`.

mod enumerate;
mod import;
mod share;

pub use enumerate::enumerate_contact_cards;
pub use import::import_contact_card;
pub use share::share_block_to;

use secretary_core::identity::card::ContactCard;

use crate::error::FfiVaultError;

/// Secret-free projection of one contact card — the only contact data that
/// crosses the IPC seam (spec §3: card bytes + public keys stay server-side).
pub struct ContactSummary {
    /// 16-byte contact identity (the card's `contact_uuid`).
    pub contact_uuid: [u8; 16],
    /// User-facing label from the card.
    pub display_name: String,
}

/// Parse + cryptographically self-verify one contact card. `from_canonical_cbor`
/// only parses; `verify_self()` is the both-halves gate. Either failure →
/// `CardDecodeFailure` (the caller decides skip-and-count vs. reject).
pub(crate) fn read_verified_card(bytes: &[u8]) -> Result<ContactCard, FfiVaultError> {
    let card = ContactCard::from_canonical_cbor(bytes).map_err(|e| {
        FfiVaultError::CardDecodeFailure { detail: e.to_string() }
    })?;
    card.verify_self().map_err(|e| FfiVaultError::CardDecodeFailure {
        detail: format!("contact card self-signature verification failed: {e:?}"),
    })?;
    Ok(card)
}
```

- [ ] **Step 4: Implement `enumerate.rs`** — `ffi/secretary-ffi-bridge/src/contacts/enumerate.rs`:

```rust
//! `enumerate_contact_cards`: list every OTHER party's verified contact card
//! in `contacts/`, omitting the owner's own self-card, counting unreadable /
//! unverifiable files rather than silently dropping them (spec §3, §9.5).

use crate::contacts::{read_verified_card, ContactSummary};
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Returns `(verified non-owner summaries, count of unreadable/unverifiable
/// .card files)`. The owner's own card is omitted (the owner is implicitly the
/// author/recipient of their own blocks and is never a share target).
pub fn enumerate_contact_cards(
    manifest: &OpenVaultManifest,
) -> Result<(Vec<ContactSummary>, usize), FfiVaultError> {
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let owner_uuid = manifest.owner_card().ok_or_else(handle_wiped)?.contact_uuid;
    let contacts_dir = folder.join("contacts");

    let mut summaries = Vec::new();
    let mut unreadable = 0usize;

    let read_dir = match std::fs::read_dir(&contacts_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((summaries, unreadable)); // no contacts/ yet → empty
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
            Ok(card) => summaries.push(ContactSummary {
                contact_uuid: card.contact_uuid,
                display_name: card.display_name,
            }),
            Err(_) => unreadable += 1,
        }
    }
    Ok((summaries, unreadable))
}

fn handle_wiped() -> FfiVaultError {
    FfiVaultError::CorruptVault {
        detail: "vault manifest handle has been wiped".to_string(),
    }
}
```

- [ ] **Step 5: Wire `lib.rs`** — add after the existing `pub mod` lines and re-export block:

```rust
pub mod contacts;
```
and in the `pub use` block:
```rust
pub use contacts::{enumerate_contact_cards, import_contact_card, share_block_to, ContactSummary};
```

> Note: `import_contact_card` / `share_block_to` don't exist until Tasks 2–3. To keep Task 1 compiling, add only `pub use contacts::{enumerate_contact_cards, ContactSummary};` now, and extend the re-export in Tasks 2 and 3. (`contacts/mod.rs` already `mod import; mod share;` — so create minimal stubs `import.rs`/`share.rs` with the function signatures `todo!()`-free by implementing them in their own tasks; for Task 1, create `import.rs` and `share.rs` as empty `//! placeholder` files with NO public fn, and DO NOT `pub use` them yet. Adjust `mod.rs` to only `pub use enumerate::enumerate_contact_cards;` in Task 1.)

To avoid a broken intermediate, for **Task 1 only** make `contacts/mod.rs` declare just:
```rust
mod enumerate;
pub use enumerate::enumerate_contact_cards;
```
plus the `ContactSummary` struct + `read_verified_card`. Add `mod import; pub use …` in Task 2 and `mod share; pub use …` in Task 3.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test contacts 2>&1 | tail -20`
Expected: both `enumerate_*` tests PASS.

- [ ] **Step 7: Lint + commit**

Run: `cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings 2>&1 | tail -3`
```bash
git add ffi/secretary-ffi-bridge/src/contacts/ ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/contacts.rs
git commit -m "feat(d16-bridge): enumerate_contact_cards (parse+verify_self, omit owner, count unreadable)"
```

---

## Task 2: Bridge — `import_contact_card` + `ContactAlreadyExists`

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/contacts/import.rs`
- Modify: `ffi/secretary-ffi-bridge/src/contacts/mod.rs` (add `mod import; pub use import::import_contact_card;`)
- Modify: `ffi/secretary-ffi-bridge/src/error/vault/mod.rs` (add `ContactAlreadyExists`)
- Modify: `ffi/secretary-ffi-bridge/src/lib.rs` (extend re-export)
- Modify: `ffi/secretary-ffi-bridge/tests/contacts.rs`

- [ ] **Step 1: Write the failing test** — append to `tests/contacts.rs`:

```rust
use secretary_ffi_bridge::import_contact_card;

#[test]
fn import_writes_card_and_returns_summary() {
    let (tmp, _identity, manifest) = fresh_writable_vault();
    let (_b, alice) = mint_external_card(0xA1, "Alice");

    let summary = import_contact_card(&manifest, &alice).expect("import ok");
    assert_eq!(summary.display_name, "Alice");

    // File landed under the canonical hyphenated name.
    let path = tmp.path().join("contacts").join(format!(
        "{}.card",
        format_uuid_hyphenated(&summary.contact_uuid)
    ));
    assert!(path.exists(), "imported card written to contacts/");
}

#[test]
fn import_rejects_duplicate_uuid() {
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let (_b, alice) = mint_external_card(0xA1, "Alice");
    import_contact_card(&manifest, &alice).expect("first import ok");
    let err = import_contact_card(&manifest, &alice).expect_err("dup must reject");
    assert!(matches!(err, FfiVaultError::ContactAlreadyExists { .. }));
}

#[test]
fn import_rejects_tampered_card() {
    let (_tmp, _identity, manifest) = fresh_writable_vault();
    let (_b, alice) = mint_external_card(0xA1, "Alice");
    let mut tampered = alice.clone();
    let n = tampered.len();
    tampered[n - 1] ^= 0xFF;
    let err = import_contact_card(&manifest, &tampered).expect_err("tampered must reject");
    assert!(matches!(err, FfiVaultError::CardDecodeFailure { .. }));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test contacts 2>&1 | tail -20`
Expected: FAIL — `cannot find function import_contact_card` / `no variant ContactAlreadyExists`.

- [ ] **Step 3: Add the error variant** — in `ffi/secretary-ffi-bridge/src/error/vault/mod.rs`, after `CardDecodeFailure`:

```rust
    /// A contact card with this `contact_uuid` is already present in the
    /// vault's `contacts/` directory. Import refuses to overwrite a trusted
    /// card (TOFU substitution guard, spec §3).
    #[error("contact already exists in vault: {uuid_hex}")]
    ContactAlreadyExists {
        /// 32-char lowercase hex of the contact UUID.
        uuid_hex: String,
    },
```

- [ ] **Step 4: Implement `import.rs`**:

```rust
//! `import_contact_card`: TOFU import of a peer's card. Parse + `verify_self`,
//! dedup-reject (never overwrite a trusted card), atomic write (spec §3, §5).

use secretary_core::vault::{format_uuid_hyphenated, io::write_atomic};

use crate::contacts::{read_verified_card, ContactSummary};
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Import one contact card from raw canonical-CBOR bytes. Verifies BOTH
/// self-signature halves, rejects a duplicate `contact_uuid`, and writes
/// `contacts/<hyphenated-uuid>.card` atomically. Returns the imported summary.
pub fn import_contact_card(
    manifest: &OpenVaultManifest,
    card_bytes: &[u8],
) -> Result<ContactSummary, FfiVaultError> {
    let card = read_verified_card(card_bytes)?;
    let folder = manifest.vault_folder().ok_or_else(|| FfiVaultError::CorruptVault {
        detail: "vault manifest handle has been wiped".to_string(),
    })?;
    let contacts_dir = folder.join("contacts");
    std::fs::create_dir_all(&contacts_dir).map_err(|e| FfiVaultError::FolderInvalid {
        detail: format!("ensure contacts/: {e}"),
    })?;
    let path = contacts_dir.join(format!("{}.card", format_uuid_hyphenated(&card.contact_uuid)));
    if path.exists() {
        return Err(FfiVaultError::ContactAlreadyExists {
            uuid_hex: hex::encode(card.contact_uuid),
        });
    }
    write_atomic(&path, card_bytes).map_err(|e| FfiVaultError::FolderInvalid {
        detail: format!("write contact card: {e}"),
    })?;
    Ok(ContactSummary {
        contact_uuid: card.contact_uuid,
        display_name: card.display_name,
    })
}
```

- [ ] **Step 5: Wire `mod.rs` + `lib.rs`** — in `contacts/mod.rs` add `mod import;` and `pub use import::import_contact_card;`. In `lib.rs` extend the re-export to `pub use contacts::{enumerate_contact_cards, import_contact_card, ContactSummary};`.

- [ ] **Step 6: Run tests + clippy**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test contacts 2>&1 | tail -20 && cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings 2>&1 | tail -3`
Expected: all import tests PASS; clippy clean.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/contacts/ ffi/secretary-ffi-bridge/src/error/vault/mod.rs ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/contacts.rs
git commit -m "feat(d16-bridge): import_contact_card (TOFU verify_self + dedup-reject + atomic write)"
```

---

## Task 3: Bridge — `share_block_to` + `ContactNotFound`

**Files:**
- Create: `ffi/secretary-ffi-bridge/src/contacts/share.rs`
- Modify: `ffi/secretary-ffi-bridge/src/contacts/mod.rs`, `src/error/vault/mod.rs`, `src/lib.rs`, `tests/contacts.rs`

- [ ] **Step 1: Write the failing test** — append to `tests/contacts.rs`:

```rust
use secretary_ffi_bridge::share_block_to;
use share_block_helpers::{save_one_record_block, DEVICE_UUID, NEW_BLOCK_UUID, NEW_RECORD_UUID, NOW_MS_BASE};

fn uuid_of(card_bytes: &[u8]) -> [u8; 16] {
    ContactCard::from_canonical_cbor(card_bytes).unwrap().contact_uuid
}

#[test]
fn share_block_to_appends_recipient() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(&identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "password", "hunter2", NOW_MS_BASE);
    let (_b, alice) = mint_external_card(0xA1, "Alice");
    let alice_uuid = uuid_of(&alice);
    import_contact_card(&manifest, &alice).expect("import alice");

    share_block_to(&identity, &manifest, NEW_BLOCK_UUID, alice_uuid, DEVICE_UUID, NOW_MS_BASE + 1_000)
        .expect("share_block_to ok");

    let entry = manifest.find_block(&NEW_BLOCK_UUID).expect("block findable");
    assert_eq!(entry.recipient_uuids.len(), 2, "owner + Alice");
    assert!(entry.recipient_uuids.iter().any(|u| *u == alice_uuid));
}

#[test]
fn share_block_to_unknown_recipient_card_is_contact_not_found() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(&identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "p", "v", NOW_MS_BASE);
    let err = share_block_to(&identity, &manifest, NEW_BLOCK_UUID, [0x99; 16], DEVICE_UUID, NOW_MS_BASE + 1)
        .expect_err("no card on disk");
    assert!(matches!(err, FfiVaultError::ContactNotFound { .. }));
}

#[test]
fn share_block_to_unknown_block_is_block_not_found() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    let (_b, alice) = mint_external_card(0xA1, "Alice");
    let alice_uuid = uuid_of(&alice);
    import_contact_card(&manifest, &alice).unwrap();
    let err = share_block_to(&identity, &manifest, [0x77; 16], alice_uuid, DEVICE_UUID, NOW_MS_BASE + 1)
        .expect_err("unknown block");
    assert!(matches!(err, FfiVaultError::BlockNotFound { .. }));
}

#[test]
fn share_block_to_twice_is_recipient_already_present() {
    let (_tmp, identity, manifest) = fresh_writable_vault();
    save_one_record_block(&identity, &manifest, NEW_BLOCK_UUID, NEW_RECORD_UUID, "p", "v", NOW_MS_BASE);
    let (_b, alice) = mint_external_card(0xA1, "Alice");
    let alice_uuid = uuid_of(&alice);
    import_contact_card(&manifest, &alice).unwrap();
    share_block_to(&identity, &manifest, NEW_BLOCK_UUID, alice_uuid, DEVICE_UUID, NOW_MS_BASE + 1).unwrap();
    let err = share_block_to(&identity, &manifest, NEW_BLOCK_UUID, alice_uuid, DEVICE_UUID, NOW_MS_BASE + 2)
        .expect_err("already a recipient");
    assert!(matches!(err, FfiVaultError::RecipientAlreadyPresent));
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test contacts 2>&1 | tail -20`
Expected: FAIL — `cannot find function share_block_to` / `no variant ContactNotFound`.

- [ ] **Step 3: Add the error variant** — in `src/error/vault/mod.rs`, after `ContactAlreadyExists`:

```rust
    /// A contact card referenced by a share operation (an existing recipient
    /// listed in the manifest, or the new recipient) has no `.card` file in
    /// `contacts/`. Spec §5, §9.3.
    #[error("contact not found in vault: {uuid_hex}")]
    ContactNotFound {
        /// 32-char lowercase hex of the contact UUID.
        uuid_hex: String,
    },
```

- [ ] **Step 4: Implement `share.rs`**:

```rust
//! `share_block_to`: share a block by recipient UUID. Reads the block's
//! current recipient set from the manifest, loads every existing card + the
//! new card from `contacts/`, and delegates to the existing `share::share_block`
//! wrapper (which owns the snapshot/zeroize/write-back machinery). Spec §5, §8.

use secretary_core::vault::format_uuid_hyphenated;

use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;
use crate::identity::UnlockedIdentity;

/// Append one new recipient (by `contact_uuid`) to a block the owner authored.
/// `existing_recipient_cards` are assembled from the manifest's
/// `BlockEntry.recipients` (always includes the owner). Card bytes loaded here
/// were self-verified at import time. NotAuthor / RecipientAlreadyPresent /
/// MissingRecipientCard surface unchanged from the underlying `share_block`.
pub fn share_block_to(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: [u8; 16],
    new_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let contacts_dir = folder.join("contacts");

    let entry = body
        .blocks
        .iter()
        .find(|b| b.block_uuid == block_uuid)
        .ok_or_else(|| FfiVaultError::BlockNotFound {
            uuid_hex: hex::encode(block_uuid),
        })?;

    // Existing recipient cards (file name = hyphenated; error field = hex).
    let mut existing: Vec<Vec<u8>> = Vec::with_capacity(entry.recipients.len());
    for r in &entry.recipients {
        existing.push(load_card_bytes(&contacts_dir, r)?);
    }
    let new_bytes = load_card_bytes(&contacts_dir, &new_recipient_uuid)?;

    crate::share::share_block(
        identity,
        manifest,
        block_uuid,
        &existing,
        &new_bytes,
        device_uuid,
        now_ms,
    )
}

fn load_card_bytes(contacts_dir: &std::path::Path, uuid: &[u8; 16]) -> Result<Vec<u8>, FfiVaultError> {
    let path = contacts_dir.join(format!("{}.card", format_uuid_hyphenated(uuid)));
    std::fs::read(&path).map_err(|_| FfiVaultError::ContactNotFound {
        uuid_hex: hex::encode(uuid),
    })
}

fn handle_wiped() -> FfiVaultError {
    FfiVaultError::CorruptVault {
        detail: "vault manifest handle has been wiped".to_string(),
    }
}
```

- [ ] **Step 5: Wire `mod.rs` + `lib.rs`** — `contacts/mod.rs`: `mod share; pub use share::share_block_to;`. `lib.rs`: re-export becomes `pub use contacts::{enumerate_contact_cards, import_contact_card, share_block_to, ContactSummary};`.

- [ ] **Step 6: Run the full bridge test bin + clippy**

Run: `cd ffi/secretary-ffi-bridge && cargo test --release --test contacts 2>&1 | tail -20 && cargo clippy --release -p secretary-ffi-bridge --tests -- -D warnings 2>&1 | tail -3`
Expected: all `share_block_to_*` tests PASS; clippy clean.

- [ ] **Step 7: Commit**

```bash
git add ffi/secretary-ffi-bridge/src/contacts/ ffi/secretary-ffi-bridge/src/error/vault/mod.rs ffi/secretary-ffi-bridge/src/lib.rs ffi/secretary-ffi-bridge/tests/contacts.rs
git commit -m "feat(d16-bridge): share_block_to (assemble recipient cards from contacts/, delegate to share_block)"
```

---

## Task 4: Desktop — typed `AppError` variants + `map_ffi_error` routing

**Files:**
- Modify: `desktop/src-tauri/src/errors.rs`

- [ ] **Step 1: Write the failing tests** — in the `#[cfg(test)] mod tests` of `errors.rs`:

```rust
    #[test]
    fn share_errors_serialize_typed() {
        assert_eq!(round_trip(&AppError::NotAuthor)["code"], "not_author");
        assert_eq!(round_trip(&AppError::RecipientAlreadyPresent)["code"], "recipient_already_present");
        assert_eq!(round_trip(&AppError::MissingRecipientCard)["code"], "missing_recipient_card");
        let v = round_trip(&AppError::ContactAlreadyExists { contact_uuid_hex: "ab".into() });
        assert_eq!(v["code"], "contact_already_exists");
        assert_eq!(v["contact_uuid_hex"], "ab");
        let v = round_trip(&AppError::ContactNotFound { contact_uuid_hex: "cd".into() });
        assert_eq!(v["code"], "contact_not_found");
        assert_eq!(v["contact_uuid_hex"], "cd");
    }

    #[test]
    fn ffi_share_variants_route_to_typed_app_errors() {
        let m: AppError = map_ffi_error(FfiVaultError::RecipientAlreadyPresent);
        assert_eq!(round_trip(&m)["code"], "recipient_already_present");
        let m = map_ffi_error(FfiVaultError::ContactAlreadyExists { uuid_hex: "ab".into() });
        assert_eq!(round_trip(&m)["contact_uuid_hex"], "ab");
        let m = map_ffi_error(FfiVaultError::ContactNotFound { uuid_hex: "cd".into() });
        assert_eq!(round_trip(&m)["contact_uuid_hex"], "cd");
        let m = map_ffi_error(FfiVaultError::NotAuthor {
            expected_fingerprint_hex: "x".into(),
            got_fingerprint_hex: "y".into(),
        });
        assert_eq!(round_trip(&m)["code"], "not_author");
    }
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-desktop --lib errors 2>&1 | tail -20`
Expected: FAIL — `no variant or associated item NotAuthor` (and non-exhaustive `map_ffi_error`).

- [ ] **Step 3: Add the variants** — in the `AppError` enum (after `TrashEntryNotFound`):

```rust
    #[error("Only the block's author can share it")]
    NotAuthor,

    #[error("This block is already shared with that contact")]
    RecipientAlreadyPresent,

    #[error("A recipient's contact card is missing")]
    MissingRecipientCard,

    #[error("That contact is already in your vault")]
    ContactAlreadyExists { contact_uuid_hex: String },

    #[error("That contact is not in your vault")]
    ContactNotFound { contact_uuid_hex: String },
```

- [ ] **Step 4: Route them in `map_ffi_error`** — replace the existing `other @ (FfiVaultError::NotAuthor { .. } | …) => Internal` arm with:

```rust
        FfiVaultError::NotAuthor { .. } => AppError::NotAuthor,
        FfiVaultError::RecipientAlreadyPresent => AppError::RecipientAlreadyPresent,
        FfiVaultError::MissingRecipientCard { .. } => AppError::MissingRecipientCard,
        FfiVaultError::ContactAlreadyExists { uuid_hex } => {
            AppError::ContactAlreadyExists { contact_uuid_hex: uuid_hex }
        }
        FfiVaultError::ContactNotFound { uuid_hex } => {
            AppError::ContactNotFound { contact_uuid_hex: uuid_hex }
        }
```

- [ ] **Step 5: Run tests + clippy**

Run: `cargo test --release -p secretary-desktop --lib errors 2>&1 | tail -20 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -3`
Expected: PASS; clippy clean (the `match` is now exhaustive again).

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/errors.rs
git commit -m "feat(d16-desktop): typed AppError share/contact variants + map_ffi_error routing"
```

---

## Task 5: Desktop — `ContactSummaryDto` + `ListContactsDto`

**Files:**
- Create: `desktop/src-tauri/src/dtos/contact.rs`
- Modify: `desktop/src-tauri/src/dtos/mod.rs`

- [ ] **Step 1: Write the failing test** — in `dtos/contact.rs` (new file, with the impl below); test module:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("ser")).expect("parse")
    }

    #[test]
    fn contact_summary_dto_camel_case() {
        let dto = ContactSummaryDto {
            contact_uuid_hex: "00112233445566778899aabbccddeeff".into(),
            display_name: "Alice".into(),
        };
        let v = to_json(&dto);
        assert_eq!(v["contactUuidHex"], "00112233445566778899aabbccddeeff");
        assert_eq!(v["displayName"], "Alice");
        assert!(v.get("contact_uuid_hex").is_none());
    }

    #[test]
    fn contact_summary_debug_redacts_name() {
        let dto = ContactSummaryDto {
            contact_uuid_hex: "ab".into(),
            display_name: "SecretName".into(),
        };
        let dbg = format!("{dto:?}");
        assert!(!dbg.contains("SecretName"));
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn list_contacts_dto_shape() {
        let dto = ListContactsDto {
            contacts: vec![],
            unreadable_count: 3,
        };
        let v = to_json(&dto);
        assert_eq!(v["unreadableCount"], 3);
        assert!(v["contacts"].is_array());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-desktop --lib dtos::contact 2>&1 | tail -20`
Expected: FAIL — module/types don't exist.

- [ ] **Step 3: Implement `dtos/contact.rs`** (above the test module):

```rust
//! D.1.6 contacts DTOs. `ContactSummaryDto` carries the decrypted contact
//! display name (a secret-boundary value); its `Debug` redacts it. Card bytes
//! and public keys never appear in any DTO (spec §3).

use secretary_ffi_bridge::ContactSummary;

/// One contact surfaced to the picker. Card bytes/public keys are NOT here.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactSummaryDto {
    pub contact_uuid_hex: String,
    pub display_name: String,
}

impl std::fmt::Debug for ContactSummaryDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContactSummaryDto")
            .field("contact_uuid_hex", &self.contact_uuid_hex)
            .field("display_name", &"<redacted>")
            .finish()
    }
}

impl From<&ContactSummary> for ContactSummaryDto {
    fn from(s: &ContactSummary) -> Self {
        ContactSummaryDto {
            contact_uuid_hex: hex::encode(s.contact_uuid),
            display_name: s.display_name.clone(),
        }
    }
}

/// Result of `list_contacts`: the picker rows + a count of unreadable/
/// unverifiable `.card` files (surfaced, never hidden — spec §3).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ListContactsDto {
    pub contacts: Vec<ContactSummaryDto>,
    pub unreadable_count: u32,
}
```

- [ ] **Step 4: Wire `dtos/mod.rs`** — add `mod contact;` and `pub use contact::{ContactSummaryDto, ListContactsDto};`.

- [ ] **Step 5: Run tests**

Run: `cargo test --release -p secretary-desktop --lib dtos::contact 2>&1 | tail -20`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/dtos/
git commit -m "feat(d16-desktop): ContactSummaryDto (redacting Debug) + ListContactsDto"
```

---

## Task 6: Desktop — `commands/contacts.rs` + registration

**Files:**
- Create: `desktop/src-tauri/src/commands/contacts.rs`
- Modify: `desktop/src-tauri/src/commands/mod.rs`, `desktop/src-tauri/src/main.rs`

- [ ] **Step 1: Write the failing L3-lite test stub** — the real L3 tests land in Task 7; here, add a compile-smoke unit test at the bottom of `contacts.rs` that the impls exist and `list_contacts_impl` errors when locked:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use crate::session::VaultSession;

    #[test]
    fn list_contacts_locked_session_is_not_unlocked() {
        let state = Mutex::new(VaultSession::new(std::env::temp_dir()));
        let err = list_contacts_impl(&state).expect_err("locked");
        assert!(matches!(err, AppError::NotUnlocked));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-desktop --lib commands::contacts 2>&1 | tail -20`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement `commands/contacts.rs`**:

```rust
//! D.1.6 contacts IPC commands: list_contacts / import_contact / share_block.
//! Thin shells over the bridge primitives (spec §6). `import_contact` reads the
//! user-chosen `.card` file at the desktop edge; the bridge takes bytes.

use std::sync::Mutex;

use tauri::State;

use secretary_ffi_bridge::{
    enumerate_contact_cards as bridge_enumerate, import_contact_card as bridge_import,
    share_block_to as bridge_share_block_to,
};

use crate::auto_lock::now_ms;
use crate::commands::shared::parse_uuid_16;
use crate::dtos::{ContactSummaryDto, ListContactsDto};
use crate::errors::{map_ffi_error, AppError};
use crate::session::VaultSession;

fn lock_session(
    state: &Mutex<VaultSession>,
) -> Result<std::sync::MutexGuard<'_, VaultSession>, AppError> {
    state.lock().map_err(|e| AppError::Internal {
        detail: format!("session mutex poisoned: {e}"),
    })
}

#[tauri::command]
pub async fn list_contacts(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<ListContactsDto, AppError> {
    list_contacts_impl(state.inner())
}

pub fn list_contacts_impl(state: &Mutex<VaultSession>) -> Result<ListContactsDto, AppError> {
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let (summaries, unreadable) = bridge_enumerate(&u.manifest).map_err(map_ffi_error)?;
        Ok(ListContactsDto {
            contacts: summaries.iter().map(ContactSummaryDto::from).collect(),
            unreadable_count: unreadable as u32,
        })
    })
}

#[tauri::command]
pub async fn import_contact(
    state: State<'_, Mutex<VaultSession>>,
    card_path: String,
) -> Result<ContactSummaryDto, AppError> {
    import_contact_impl(state.inner(), &card_path)
}

pub fn import_contact_impl(
    state: &Mutex<VaultSession>,
    card_path: &str,
) -> Result<ContactSummaryDto, AppError> {
    let bytes = std::fs::read(card_path).map_err(|e| AppError::Io {
        detail: format!("read contact card file {card_path:?}: {e}"),
    })?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        let summary = bridge_import(&u.manifest, &bytes).map_err(map_ffi_error)?;
        Ok(ContactSummaryDto::from(&summary))
    })
}

#[tauri::command]
pub async fn share_block(
    state: State<'_, Mutex<VaultSession>>,
    block_uuid_hex: String,
    recipient_uuid_hex: String,
) -> Result<(), AppError> {
    share_block_impl(state.inner(), &block_uuid_hex, &recipient_uuid_hex)
}

pub fn share_block_impl(
    state: &Mutex<VaultSession>,
    block_uuid_hex: &str,
    recipient_uuid_hex: &str,
) -> Result<(), AppError> {
    let block_uuid = parse_uuid_16(block_uuid_hex)?;
    let recipient_uuid = parse_uuid_16(recipient_uuid_hex)?;
    let session = lock_session(state)?;
    session.with_unlocked(|u| {
        bridge_share_block_to(
            &u.identity,
            &u.manifest,
            block_uuid,
            recipient_uuid,
            u.device_uuid,
            now_ms(),
        )
        .map_err(map_ffi_error)?;
        Ok(())
    })
}
```

- [ ] **Step 4: Register** — `commands/mod.rs`: add `pub mod contacts;`. `main.rs`: add `contacts` to the `use …commands::{…}` import list, and add to `generate_handler![…]`:

```rust
            contacts::list_contacts,
            contacts::import_contact,
            contacts::share_block,
```

- [ ] **Step 5: Run tests + clippy + build**

Run: `cargo test --release -p secretary-desktop --lib commands::contacts 2>&1 | tail -20 && cargo clippy --release -p secretary-desktop --tests -- -D warnings 2>&1 | tail -3`
Expected: PASS; clippy clean.

- [ ] **Step 6: Commit**

```bash
git add desktop/src-tauri/src/commands/ desktop/src-tauri/src/main.rs
git commit -m "feat(d16-desktop): list_contacts/import_contact/share_block IPC commands"
```

---

## Task 7: Desktop — L3 integration tests

**Files:**
- Modify: `desktop/src-tauri/tests/ipc_integration.rs`

- [ ] **Step 1: Write the failing tests** — add a helper + tests. The peer card file is sourced from a freshly-created second vault (its single `contacts/*.card` is the owner's self-signed card):

```rust
/// Create a throwaway vault in a tempdir and return (tempdir, path to its
/// owner contact card file). Used as a valid, self-signed peer card to import.
fn peer_card_file() -> (TempDir, PathBuf) {
    use secretary_core::crypto::secret::SecretBytes;
    let dir = tempfile::tempdir().expect("peer vault tempdir");
    let mut rng = rand_core::OsRng;
    create::create_vault_impl(
        dir.path().to_str().expect("utf8"),
        "Peer",
        &SecretBytes::from(b"peer-password-123".to_vec()),
        1_700_000_000_000,
        &mut rng,
    )
    .expect("create peer vault");
    let contacts = dir.path().join("contacts");
    let card = std::fs::read_dir(&contacts)
        .expect("read contacts/")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .find(|p| p.extension().and_then(|s| s.to_str()) == Some("card"))
        .expect("owner card present");
    (dir, card)
}

/// Unlocked session over a WRITABLE ephemeral copy of the golden vault.
fn unlocked_ephemeral() -> (Mutex<VaultSession>, TempDir, TempDir) {
    let (vault_dir, vault_path) = ephemeral_golden_copy();
    let (state, device_dir) = fresh_state();
    unlock::unlock_with_password_impl(
        &state,
        vault_path.to_str().expect("utf8"),
        GOLDEN_VAULT_PASSWORD.as_bytes(),
    )
    .expect("unlock ephemeral golden copy");
    (state, vault_dir, device_dir)
}

#[test]
fn list_contacts_excludes_owner_then_shows_imported_peer() {
    let (state, _vault_dir, _dev) = unlocked_ephemeral();
    let before = contacts::list_contacts_impl(&state).expect("list ok");
    assert_eq!(before.contacts.len(), 0, "fresh golden: only owner, which is excluded");
    assert_eq!(before.unreadable_count, 0);

    let (_peer_dir, card_path) = peer_card_file();
    let imported = contacts::import_contact_impl(&state, card_path.to_str().unwrap()).expect("import ok");
    assert_eq!(imported.display_name, "Peer");

    let after = contacts::list_contacts_impl(&state).expect("list ok");
    assert_eq!(after.contacts.len(), 1);
    assert_eq!(after.contacts[0].display_name, "Peer");
}

#[test]
fn import_contact_duplicate_is_typed_error() {
    let (state, _vault_dir, _dev) = unlocked_ephemeral();
    let (_peer_dir, card_path) = peer_card_file();
    contacts::import_contact_impl(&state, card_path.to_str().unwrap()).expect("first ok");
    let err = contacts::import_contact_impl(&state, card_path.to_str().unwrap()).expect_err("dup");
    assert!(matches!(err, AppError::ContactAlreadyExists { .. }));
}

#[test]
fn share_block_happy_and_typed_errors() {
    let (state, _vault_dir, _dev) = unlocked_ephemeral();
    let (_peer_dir, card_path) = peer_card_file();
    let peer = contacts::import_contact_impl(&state, card_path.to_str().unwrap()).expect("import");

    // Happy: golden block is owner-authored.
    contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex).expect("share ok");

    // Re-share same peer → RecipientAlreadyPresent.
    let err = contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, &peer.contact_uuid_hex).expect_err("dup recip");
    assert!(matches!(err, AppError::RecipientAlreadyPresent));

    // Unknown recipient (no card on disk) → ContactNotFound.
    let err = contacts::share_block_impl(&state, GOLDEN_BLOCK_UUID_HEX, "99999999999999999999999999999999").expect_err("no card");
    assert!(matches!(err, AppError::ContactNotFound { .. }));
}
```

> Add `use secretary_desktop::commands::contacts;` to the test imports if not already covered by the existing glob. If `rand_core` / `secretary_core` are not already dev-deps of `desktop/src-tauri`, add them under `[dev-dependencies]` in `desktop/src-tauri/Cargo.toml` (they are transitive runtime deps; the existing create-vault tests already construct `SecretBytes` and an `OsRng`, so confirm the pattern at `ipc_integration.rs:597` and mirror its imports rather than adding new deps).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test --release -p secretary-desktop --test ipc_integration contacts 2>&1 | tail -25`
Expected: FAIL (or compile error) until Tasks 4–6 are in (they are) — then assertion failures only if logic is wrong. Since Tasks 4–6 landed, expect PASS; if a dev-dep is missing, fix per the note.

- [ ] **Step 3: (no new impl)** — these exercise Task 6 code. If `peer_card_file` needs a dep tweak, make the minimal `Cargo.toml` dev-dep addition and re-run.

- [ ] **Step 4: Run + commit**

Run: `cargo test --release -p secretary-desktop --test ipc_integration 2>&1 | grep "test result:"`
Expected: all green.
```bash
git add desktop/src-tauri/tests/ipc_integration.rs desktop/src-tauri/Cargo.toml
git commit -m "test(d16-desktop): L3 list/import/share over ephemeral vault + peer card"
```

---

## Task 8: Frontend — `lib/contacts.ts` + ipc wrappers + error codes

**Files:**
- Create: `desktop/src/lib/contacts.ts`
- Modify: `desktop/src/lib/ipc.ts`, `desktop/src/lib/errors.ts`
- Create: `desktop/tests/contacts.test.ts`, `desktop/tests/ipcContacts.test.ts`

- [ ] **Step 1: Write the failing tests** — `desktop/tests/contacts.test.ts`:

```typescript
import { describe, it, expect } from 'vitest';
import { sortContacts } from '../src/lib/contacts';
import type { ContactSummaryDto } from '../src/lib/ipc';

const c = (displayName: string): ContactSummaryDto => ({ contactUuidHex: displayName, displayName });

describe('sortContacts', () => {
  it('orders case-insensitively by displayName, returns a new array', () => {
    const input = [c('bob'), c('Alice'), c('charlie')];
    const out = sortContacts(input);
    expect(out.map((x) => x.displayName)).toEqual(['Alice', 'bob', 'charlie']);
    expect(out).not.toBe(input);
  });
});
```

`desktop/tests/ipcContacts.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
import { listContacts, importContact, shareBlock } from '../src/lib/ipc';

describe('contacts IPC wrappers', () => {
  beforeEach(() => invokeMock.mockReset());

  it('listContacts invokes with empty args', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 });
    await listContacts();
    expect(invokeMock).toHaveBeenCalledWith('list_contacts', {});
  });
  it('importContact forwards cardPath', async () => {
    invokeMock.mockResolvedValueOnce({ contactUuidHex: 'ab', displayName: 'A' });
    await importContact('/tmp/a.card');
    expect(invokeMock).toHaveBeenCalledWith('import_contact', { cardPath: '/tmp/a.card' });
  });
  it('shareBlock forwards both uuids', async () => {
    invokeMock.mockResolvedValueOnce(undefined);
    await shareBlock('blk', 'rcp');
    expect(invokeMock).toHaveBeenCalledWith('share_block', { blockUuidHex: 'blk', recipientUuidHex: 'rcp' });
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test -- contacts ipcContacts 2>&1 | tail -20`
Expected: FAIL — symbols not exported.

- [ ] **Step 3: Implement** — `desktop/src/lib/contacts.ts`:

```typescript
// Pure contact-list helpers (D.1.6). No IPC / DOM. IPC wrappers live in ipc.ts.
import type { ContactSummaryDto } from './ipc';

/** Order contacts case-insensitively by displayName. Pure (new array). */
export function sortContacts(dtos: ContactSummaryDto[]): ContactSummaryDto[] {
  return [...dtos].sort((a, b) =>
    a.displayName.localeCompare(b.displayName, undefined, { sensitivity: 'base' })
  );
}
```

In `ipc.ts`, add the interfaces + wrappers (after the existing DTO/wrapper blocks):

```typescript
export interface ContactSummaryDto {
  contactUuidHex: string;
  displayName: string;
}
export interface ListContactsDto {
  contacts: ContactSummaryDto[];
  unreadableCount: number;
}

export async function listContacts(): Promise<ListContactsDto> {
  return call<ListContactsDto>('list_contacts', {});
}
export async function importContact(cardPath: string): Promise<ContactSummaryDto> {
  return call<ContactSummaryDto>('import_contact', { cardPath });
}
export async function shareBlock(blockUuidHex: string, recipientUuidHex: string): Promise<void> {
  return call<void>('share_block', { blockUuidHex, recipientUuidHex });
}
```

In `errors.ts`: add the codes to `APP_ERROR_CODES` (`'not_author'`, `'recipient_already_present'`, `'missing_recipient_card'`, `'contact_already_exists'`, `'contact_not_found'`), add union members:

```typescript
  | { code: 'not_author' }
  | { code: 'recipient_already_present' }
  | { code: 'missing_recipient_card' }
  | { code: 'contact_already_exists'; contact_uuid_hex: string }
  | { code: 'contact_not_found'; contact_uuid_hex: string }
```

and `userMessageFor` cases:

```typescript
    case 'not_author':
      return { title: "You can't share this block", actionHint: 'Only the block author can share it.' };
    case 'recipient_already_present':
      return { title: 'Already shared', actionHint: 'This block is already shared with that contact.' };
    case 'missing_recipient_card':
      return { title: 'Recipient card missing', actionHint: 'A recipient on this block has no contact card. Re-import it.' };
    case 'contact_already_exists':
      return { title: 'Contact already imported', actionHint: 'That contact is already in your vault.' };
    case 'contact_not_found':
      return { title: 'Contact not found', actionHint: 'That contact is no longer in your vault. Refresh the list.' };
```

- [ ] **Step 4: Run tests + typecheck**

Run: `cd desktop && pnpm test -- contacts ipcContacts 2>&1 | tail -10 && pnpm typecheck 2>&1 | tail -3`
Expected: PASS; typecheck clean.

- [ ] **Step 5: Commit**

```bash
git add desktop/src/lib/contacts.ts desktop/src/lib/ipc.ts desktop/src/lib/errors.ts desktop/tests/contacts.test.ts desktop/tests/ipcContacts.test.ts
git commit -m "feat(d16-fe): contacts lib + ipc wrappers + five share/contact error codes"
```

---

## Task 9: Frontend — `ShareDialog` + `BlockCard` action + hosting + styles

**Files:**
- Create: `desktop/src/components/share/ShareDialog.svelte`
- Modify: `desktop/src/components/PathPicker.svelte`, `desktop/src/components/BlockCard.svelte`, `desktop/src/routes/Vault.svelte`, `desktop/src/theme.css`
- Create: `desktop/tests/ShareDialog.test.ts`

- [ ] **Step 1: Write the failing test** — `desktop/tests/ShareDialog.test.ts`:

```typescript
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/svelte';
const { invokeMock } = vi.hoisted(() => ({ invokeMock: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: invokeMock }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
import ShareDialog from '../src/components/share/ShareDialog.svelte';
import type { BlockSummaryDto } from '../src/lib/ipc';

const BLOCK: BlockSummaryDto = { blockUuidHex: 'blk', blockName: 'Logins', createdAtMs: 1, lastModifiedMs: 2 };

describe('ShareDialog.svelte', () => {
  beforeEach(() => invokeMock.mockReset());

  it('shows the empty state with an import affordance when no contacts', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 0 }); // list_contacts
    const { getByText } = render(ShareDialog, { props: { block: BLOCK, onClose: vi.fn() } });
    await waitFor(() => expect(getByText(/Import a contact/i)).toBeTruthy());
  });

  it('lists contacts and shares the selected one', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [{ contactUuidHex: 'rcp', displayName: 'Alice' }], unreadableCount: 0 });
    const onClose = vi.fn();
    const { getByText, getByRole } = render(ShareDialog, { props: { block: BLOCK, onClose } });
    await waitFor(() => expect(getByText('Alice')).toBeTruthy());
    await fireEvent.click(getByText('Alice'));
    invokeMock.mockResolvedValueOnce(undefined); // share_block
    await fireEvent.click(getByRole('button', { name: /^Share$/ }));
    await waitFor(() => expect(invokeMock).toHaveBeenCalledWith('share_block', { blockUuidHex: 'blk', recipientUuidHex: 'rcp' }));
  });

  it('warns when some cards are unreadable', async () => {
    invokeMock.mockResolvedValueOnce({ contacts: [], unreadableCount: 2 });
    const { getByText } = render(ShareDialog, { props: { block: BLOCK, onClose: vi.fn() } });
    await waitFor(() => expect(getByText(/2 .*unreadable/i)).toBeTruthy());
  });
});
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd desktop && pnpm test -- ShareDialog 2>&1 | tail -20`
Expected: FAIL — component missing.

- [ ] **Step 3: Make `PathPicker` file-capable** — add optional props (default preserves folder behaviour):

```svelte
  type Props = {
    value?: string;
    onSelect: (path: string) => void;
    disabled?: boolean;
    directory?: boolean;
    filters?: { name: string; extensions: string[] }[];
    title?: string;
    label?: string;
  };
  let {
    value = '',
    onSelect,
    disabled = false,
    directory = true,
    filters,
    title = 'Choose vault folder',
    label = 'Choose…'
  }: Props = $props();

  async function pick(): Promise<void> {
    if (disabled) return;
    const selected = await openDialog({ directory, multiple: false, filters, title });
    if (typeof selected === 'string') onSelect(selected);
  }
```
(Update the button text to `{label}`.)

- [ ] **Step 4: Implement `ShareDialog.svelte`**:

```svelte
<script lang="ts">
  import { listContacts, importContact, shareBlock, isAppError, type BlockSummaryDto, type ContactSummaryDto } from '../../lib/ipc';
  import { sortContacts } from '../../lib/contacts';
  import { userMessageFor, type AppError } from '../../lib/errors';
  import PathPicker from '../PathPicker.svelte';

  type Props = { block: BlockSummaryDto; onClose: () => void };
  let { block, onClose }: Props = $props();

  let contacts = $state<ContactSummaryDto[]>([]);
  let unreadable = $state(0);
  let selected = $state<string | null>(null);
  let busy = $state(false);
  let error = $state<AppError | null>(null);
  let dialogEl: HTMLDialogElement | undefined = $state();

  $effect(() => {
    if (dialogEl && !dialogEl.hasAttribute('open')) dialogEl.showModal();
  });

  async function refresh() {
    try {
      const dto = await listContacts();
      contacts = sortContacts(dto.contacts);
      unreadable = dto.unreadableCount;
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }
  $effect(() => { void refresh(); });

  async function onImport(path: string) {
    error = null;
    try {
      await importContact(path);
      await refresh();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    }
  }

  async function doShare() {
    if (!selected) return;
    busy = true; error = null;
    try {
      await shareBlock(block.blockUuidHex, selected);
      onClose();
    } catch (e) {
      error = isAppError(e) ? e : { code: 'internal' };
    } finally {
      busy = false;
    }
  }
</script>

<dialog bind:this={dialogEl} class="share-dialog" oncancel={(e) => { e.preventDefault(); onClose(); }}>
  <h2 class="share-dialog__title">Share “{block.blockName}”</h2>

  {#if unreadable > 0}
    <p class="share-dialog__warn">{unreadable} contact card(s) are unreadable and were skipped.</p>
  {/if}

  {#if contacts.length === 0}
    <p class="share-dialog__empty">No contacts yet.</p>
  {:else}
    <ul class="contact-list">
      {#each contacts as contact (contact.contactUuidHex)}
        <li>
          <button
            type="button"
            class="contact-row"
            class:contact-row--selected={selected === contact.contactUuidHex}
            onclick={() => (selected = contact.contactUuidHex)}
          >{contact.displayName}</button>
        </li>
      {/each}
    </ul>
  {/if}

  <PathPicker
    onSelect={onImport}
    directory={false}
    filters={[{ name: 'Contact card', extensions: ['card'] }]}
    title="Import a contact card"
    label="Import a contact…"
  />

  {#if error}
    <p class="share-dialog__error">{userMessageFor(error).title} — {userMessageFor(error).actionHint}</p>
  {/if}

  <div class="share-dialog__actions">
    <button type="button" onclick={onClose}>Cancel</button>
    <button type="button" disabled={!selected || busy} onclick={doShare}>Share</button>
  </div>
</dialog>
```

- [ ] **Step 5: Wire `BlockCard` + `Vault`** — `BlockCard.svelte`: add `onShare?: (block: BlockSummaryDto) => void;` to Props and a button mirroring the trash one:

```svelte
{#if onShare}
  <button type="button" class="block-card__share" aria-label="Share block" onclick={() => onShare(block)}>🔗</button>
{/if}
```

`Vault.svelte`: import `ShareDialog`; add `let blockToShare = $state<BlockSummaryDto | null>(null);`; pass `onShare={(b) => (blockToShare = b)}` on `<BlockCard>`; mount:

```svelte
{#if blockToShare}
  <ShareDialog block={blockToShare} onClose={() => { blockToShare = null; refreshManifest(); }} />
{/if}
```

- [ ] **Step 6: Styles** — append to `theme.css`: `.share-dialog`, `.share-dialog__title/__warn/__empty/__error/__actions`, `.contact-list`, `.contact-row`, `.contact-row--selected`, `.block-card__share` (mirror `.block-card__trash`). Keep parity with existing dialog styling.

- [ ] **Step 7: Run the frontend gauntlet**

Run: `cd desktop && pnpm test 2>&1 | grep -E "Test Files|Tests " && pnpm typecheck 2>&1 | tail -2 && pnpm svelte-check 2>&1 | tail -2 && pnpm lint 2>&1 | tail -2`
Expected: all green; svelte-check 0 errors / 0 new warnings; lint clean.

- [ ] **Step 8: Commit**

```bash
git add desktop/src/components/ desktop/src/routes/Vault.svelte desktop/src/theme.css desktop/tests/ShareDialog.test.ts
git commit -m "feat(d16-fe): ShareDialog (picker + inline import) + BlockCard share action"
```

---

## Task 10: Ship — full gauntlet, README/ROADMAP, handoff

**Files:**
- Modify: `README.md`, `ROADMAP.md`
- Create: `docs/handoffs/2026-05-31-d16-share-contacts-shipped.md`
- Retarget: `NEXT_SESSION.md` symlink

- [ ] **Step 1: Run the FULL automated gauntlet** (from repo root of the worktree):

```bash
cargo test --release --workspace --no-fail-fast 2>&1 | grep "^test result:" | awk '$3=="ok." {p+=$4; f+=$6; i+=$8} END {printf "Rust → PASSED %d FAILED %d IGNORED %d\n", p, f, i}'
cargo clippy --release --workspace --tests -- -D warnings 2>&1 | tail -3
cargo fmt --all -- --check
uv run core/tests/python/conformance.py 2>&1 | tail -2
uv run core/tests/python/spec_test_name_freshness.py 2>&1 | tail -2
bash ffi/secretary-ffi-uniffi/tests/swift/run_conformance.sh 2>&1 | tail -2
bash ffi/secretary-ffi-uniffi/tests/kotlin/run_conformance.sh 2>&1 | tail -2
cd desktop && pnpm test 2>&1 | grep -E "Test Files|Tests " && pnpm typecheck && pnpm svelte-check 2>&1 | tail -2 && pnpm lint && cd ..
```
Expected: Rust PASSED ≥ 1121 + the new tests; everything green; conformance + KAT UNCHANGED (Swift/Kotlin 22/22).

- [ ] **Step 2: Update `README.md` + `ROADMAP.md`** — mark D.1.6 ✅ (share + contacts import); note D.1.7 next (export-my-card / contacts-pane / revoke per spec §13). Keep the status section brief (dot points) per the README style.

- [ ] **Step 3: Author the handoff** at `docs/handoffs/2026-05-31-d16-share-contacts-shipped.md` capturing: (1) shipped + commit SHAs, (2) next (D.1.7 candidates w/ acceptance criteria), (3) open risks (manual smoke gate; #167 now also covers contacts primitives), (4) resume commands, (5) the symlink model. Mirror the D.1.5 handoff structure.

- [ ] **Step 4: Retarget the symlink + commit on the branch**

```bash
ln -snf docs/handoffs/2026-05-31-d16-share-contacts-shipped.md NEXT_SESSION.md
ls -la NEXT_SESSION.md && head -3 NEXT_SESSION.md
git add README.md ROADMAP.md docs/handoffs/2026-05-31-d16-share-contacts-shipped.md NEXT_SESSION.md
git commit -m "docs(d16): README/ROADMAP ✅ + handoff + symlink retarget"
```

- [ ] **Step 5: Push + open the PR** (the manual GUI smoke per spec §15 is the user's pre-merge gate).

```bash
git push -u origin feature/d16-share
gh pr create --base main --title "D.1.6 — share a block + desktop contacts subsystem" --body "<summary + smoke checklist + 🤖 footer>"
```

---

## Self-review (run after writing; fix inline)

**Spec coverage** — §3 architecture (bridge-thick) → Tasks 1-3,6; §5 bridge surface → Tasks 1-3; §6 desktop → Tasks 4-6; §7 frontend → Tasks 8-9; §9 invariants: (1) only summaries cross IPC → DTOs (Task 5) carry no bytes/keys; (2) verify_self both halves → Task 1/2 `read_verified_card`; (3) recipient-set assembly + ContactNotFound → Task 3; (4) drop timing reused via delegation → Task 3 (calls existing wrapper); (5) unreadableCount → Tasks 1,5,9; (6) owner excluded + NotAuthor typed → Tasks 1,4. §10 testing → Tasks 1-3,7,8,9. §12 no-KAT-change → Task 10 verifies. §13 deferrals → not built. §15 smoke → Task 10 PR gate. **No gaps.**

**Type consistency** — `ContactSummary` (bridge) → `ContactSummaryDto { contactUuidHex, displayName }` (desktop camelCase) → `ContactSummaryDto` (TS) align. Error fields: bridge `uuid_hex` → desktop `contact_uuid_hex` (snake, matches existing AppError convention + TS union `contact_uuid_hex`). Filenames use `format_uuid_hyphenated`; error/DTO hex uses `hex::encode` — called out explicitly in Task 3.

**Placeholder scan** — Task 1 Step 5 contains a deliberate sequencing note (build `import`/`share` modules in their own tasks) — this is a real instruction, not a TODO; each module is fully implemented in its task.
