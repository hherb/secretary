//! FFI-friendly facade of `secretary-core`.
//!
//! This crate is the **single source of code truth** for the FFI surface
//! shared between [`secretary-ffi-py`](../../secretary-ffi-py/) (PyO3 →
//! Python) and [`secretary-ffi-uniffi`](../../secretary-ffi-uniffi/) (uniffi
//! → Swift / Kotlin). Both binding-flavor crates depend on this one and
//! project these types through their respective binding macros — drift
//! between the two foreign-language APIs is impossible at compile time.
//!
//! # Surface
//!
//! ## Errors
//!
//! - [`FfiUnlockError`] — thinned 5-variant error type for the **bytes-in**
//!   unlock entry points ([`open_with_password`], [`open_with_recovery`])
//!   and the bytes-out [`create_vault`]. See [`error`] module docs.
//! - [`FfiVaultError`] — thinned 7-variant error type for the **folder-in**
//!   vault entry points ([`open_vault_with_password`],
//!   [`open_vault_with_recovery`], [`read_block`]). Mirrors
//!   [`FfiUnlockError`]'s 5 unlock-class variants byte-identically
//!   (variant name + Display string) plus [`FfiVaultError::FolderInvalid`]
//!   for missing or inaccessible vault folders, plus
//!   [`FfiVaultError::BlockNotFound`] for read-time block-UUID lookups
//!   that miss the manifest's live blocks list. See [`error`] module
//!   docs.
//!
//! ## Handles
//!
//! - [`UnlockedIdentity`] — opaque handle wrapping a successfully-unlocked
//!   `core::UnlockedIdentity`. Returned by every unlock or open path
//!   ([`open_with_password`], [`open_with_recovery`], [`create_vault`],
//!   [`open_vault_with_password`], [`open_vault_with_recovery`]). See
//!   [`identity`] module docs.
//! - [`MnemonicOutput`] — one-shot opaque handle for the freshly-generated
//!   24-word BIP-39 recovery mnemonic returned by [`create_vault`]. See
//!   [`create`] module docs.
//! - [`OpenVaultManifest`] — opaque handle for the decrypted manifest
//!   returned by the folder-in open paths. Holds the IBK + manifest body
//!   + manifest envelope + verified owner card internally; B.4a exposes
//!     only read-only block-list accessors. See [`vault`] module docs.
//!     Also borrowed by [`read_block`] to drive block decryption (B.4b).
//! - [`BlockReadOutput`] — opaque handle for one block's decrypted
//!   records. Returned by [`read_block`]. Holds owned [`Record`]s;
//!   [`BlockReadOutput::wipe`] cascades wipe to every contained record
//!   + field. See [`record`] module docs.
//! - [`Record`] — per-record handle. Wraps non-secret metadata
//!   (record_uuid, record_type, tags, timestamps, tombstone) plus an
//!   ordered list of [`FieldHandle`]s. `Arc<Mutex<Option<...>>>` so
//!   foreign callers can store cheap clones that share the same wiped
//!   state.
//! - [`FieldHandle`] — per-field handle. Holds the secret-payload
//!   [`secretary_core::vault::record::RecordFieldValue`] (text or bytes);
//!   explicit [`FieldHandle::expose_text`] / [`FieldHandle::expose_bytes`]
//!   boundary for surfacing the secret to the foreign caller.
//!
//! ## Entry points
//!
//! Bytes-in (B.2 / B.3a / B.3b):
//! - [`open_with_password`] — fallible bytes-in unlock by master password.
//! - [`open_with_recovery`] — fallible bytes-in unlock by 24-word phrase.
//! - [`create_vault`] — fallible bytes-out vault creation using OS CSPRNG +
//!   `Argon2idParams::V1_DEFAULT`.
//!
//! Folder-in (B.4a):
//! - [`open_vault_with_password`] — fallible folder-in vault open by
//!   master password. Reads `vault.toml` + `identity.bundle.enc` +
//!   `manifest.cbor.enc` + owner contact card from the folder via
//!   `core::vault::open_vault`. Returns [`OpenVaultOutput`] with the
//!   live identity and the read-only manifest handle.
//! - [`open_vault_with_recovery`] — same as above but using a 24-word
//!   BIP-39 recovery phrase. Mnemonic input is UTF-8 bytes (`&[u8]`).
//!
//! Read (B.4b):
//! - [`read_block`] — fallible decrypt of one block's records given
//!   an open vault and a 16-byte block UUID. Borrows
//!   [`UnlockedIdentity`] + [`OpenVaultManifest`]. Returns
//!   [`BlockReadOutput`] with the decrypted records on success;
//!   [`FfiVaultError::BlockNotFound`] / [`FfiVaultError::CorruptVault`]
//!   on lookup or decryption failure.
//!
//! ## Output shapes
//!
//! - [`CreateVaultOutput`] — return type from [`create_vault`]: byte
//!   artifacts to persist + live identity + one-shot mnemonic.
//! - [`OpenVaultOutput`] — return type from the folder-in open paths:
//!   live identity + read-only manifest handle.
//! - [`BlockSummary`] — read-only metadata projection of one
//!   `core::BlockEntry`. Five plaintext-in-the-manifest fields.
//!
//! # Invariants
//!
//! - Pure-safe Rust. The workspace's `#![forbid(unsafe_code)]` applies
//!   without carve-out (the binding-flavor crates carry the FFI-macro
//!   `unsafe_code = "deny"` carve-outs locally).
//! - The `From<core::unlock::UnlockError>` impl in [`error`] uses explicit
//!   match arms with no wildcard so future core variants force a compile
//!   error instead of silently mapping to a default. The
//!   `From<core::vault::VaultError>` impl delegates to the unlock-class
//!   translation through a private `From<FfiUnlockError>` arm so renames
//!   on `FfiUnlockError` propagate automatically.
//! - The 5 unlock-class variants of `FfiUnlockError` and `FfiVaultError`
//!   share **byte-identical** Display strings — pinned by a tripwire
//!   test in [`error`].

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod contacts;
pub mod create;
pub mod edit;
pub mod error;
pub mod identity;
pub mod record;
pub mod restore;
pub mod revoke;
pub mod save;
pub mod share;
pub mod sync;
mod sync_helpers;
pub mod trash;
pub mod unlock;
pub mod vault;

pub use contacts::{
    block_recipients, contact_blocks, delete_contact_card, enumerate_contact_cards,
    import_contact_card, owner_card_export, revoke_block_from, share_block_to, ContactSummary,
    RecipientKind, RecipientSummary,
};
pub use create::{create_vault, CreateVaultOutput, MnemonicOutput};
pub use edit::{
    append_record, create_block, edit_record, resurrect_record, tombstone_record, RecordContent,
};
pub use error::{FfiUnlockError, FfiVaultError};
pub use identity::UnlockedIdentity;
pub use record::{read_block, BlockReadOutput, FieldHandle, Record};
pub use restore::restore_block;
pub use revoke::revoke_block;
pub use save::{save_block, BlockInput, FieldInput, FieldInputValue, RecordInput};
pub use share::share_block;
pub use sync::{
    sync_status, sync_vault, CollisionDto, DeviceClockDto, SyncOutcomeDto, SyncStatusDto,
    VetoDecisionDto, VetoDto,
};
pub use trash::{list_trashed_blocks, trash_block, TrashedBlock};
pub use unlock::{open_with_password, open_with_recovery};
pub use vault::{
    open_vault_with_password, open_vault_with_recovery, BlockSummary, OpenVaultManifest,
    OpenVaultOutput,
};
