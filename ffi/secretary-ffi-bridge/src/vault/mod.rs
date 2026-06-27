//! Folder-based vault entry points (B.4a). The first folder-IO surface on
//! the bridge — bytes-in unlock paths (B.2 / B.3a) and bytes-in
//! create_vault (B.3b) all stay unchanged.
//!
//! # IO model
//!
//! Foreign caller passes a folder path; Rust core reads `vault.toml`,
//! `identity.bundle.enc`, `manifest.cbor.enc`, and the owner contact card
//! from disk via `secretary_core::vault::open_vault`. This is a deliberate
//! transition from the bytes-in discipline: the §9 atomicity guarantee
//! depends on `tempfile::persist` for `rename(2)` semantics, and B.4c's
//! eventual `save_block` will need that contract owned by Rust core.
//! B.4a establishes the IO model that B.4b/c/d inherit.
//!
//! # Output handles
//!
//! Two opaque handles:
//! - [`crate::identity::UnlockedIdentity`] — re-used unchanged from
//!   B.2 / B.3a / B.3b. Wraps `core::IdentityBundle` (display_name,
//!   user_uuid, secret keys).
//! - [`OpenVaultManifest`] — NEW. Wraps the rest of `core::vault::OpenVault`:
//!   the IBK (Sensitive on the Rust side, kept for B.4b's read_block),
//!   the decrypted manifest body (block list + vault-level vector clock),
//!   the manifest envelope (kept for B.4c's re-sign), and the verified
//!   owner contact card (kept for B.4c/d signature operations; not yet
//!   exposed through accessors).
//!
//! # Error type
//!
//! Returns [`crate::error::FfiVaultError`] (NEW; see [`crate::error`]
//! module docs). Six flat variants — 5 mirrored byte-identically from
//! [`crate::error::FfiUnlockError`] and 1 new `FolderInvalid` for IO
//! problems. `local_highest_clock` is always `None`; rollback detection
//! deferred to Sub-project C.
//!
//! # Submodule layout
//!
//! - `inner` — `OpenVaultManifestInner` + [`BlockSummary`].
//! - `manifest` — [`OpenVaultManifest`] + accessors + write-back +
//!   `ReplaceManifestError`.
//! - [`orchestration`] — [`OpenVaultOutput`] + [`open_vault_with_password`] +
//!   [`open_vault_with_recovery`] + the `core::vault::OpenVault`-to-handles
//!   splitter.

pub(crate) mod inner;
pub(crate) mod manifest;
pub mod orchestration;

pub use inner::BlockSummary;
pub use manifest::OpenVaultManifest;
pub use orchestration::{open_vault_with_password, open_vault_with_recovery, OpenVaultOutput};

#[cfg(test)]
mod tests;
