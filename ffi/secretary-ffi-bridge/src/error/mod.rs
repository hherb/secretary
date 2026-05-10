//! Thinned FFI-friendly error types for the bridge layer.
//!
//! [`FfiUnlockError`] — 5-variant thinned error for the **bytes-in** unlock
//! entry points (`open_with_password`, `open_with_recovery`, `create_vault`).
//! [`FfiVaultError`] — 11-variant **folder-in** error type. Mirrors
//! `FfiUnlockError`'s 5 unlock-class variants byte-identically (variant
//! name + Display string) plus folder-in / save-time / share-time variants.
//! Returned by `open_vault_with_password` / `open_vault_with_recovery` /
//! `read_block` / `save_block` / `share_block`.
//!
//! # Why thinned (FfiUnlockError rationale)
//!
//! `core::unlock::UnlockError` has 7 variants reachable from
//! `open_with_password`, three of which wrap inner enums with their own
//! variant counts (`MalformedVaultToml(VaultTomlError)`, etc.). Mirroring
//! exactly to the foreign side either re-exposes ~15 inner types per
//! language (huge surface, churns on every internal refactor) or collapses
//! inners to strings (anti-pattern; foreign callers parse strings to
//! understand failure causes).
//!
//! [`FfiUnlockError`] thins to 5 variants expressing **user-actionable
//! intent** rather than mirroring the core enum's structural shape:
//!
//! - [`FfiUnlockError::WrongPasswordOrCorrupt`] — "your password is wrong,
//!   try again". Returned by `open_with_password`. **Deliberately conflates
//!   wrong-password and corruption** per `docs/threat-model.md` §13's
//!   anti-oracle property; this MUST NOT be split into separate variants.
//! - [`FfiUnlockError::WrongMnemonicOrCorrupt`] — parallel to the above for
//!   the `open_with_recovery` path. Same anti-oracle conflation under
//!   `recovery_kek`.
//! - [`FfiUnlockError::InvalidMnemonic`] — pre-decryption: the input does
//!   not validate as a 24-word BIP-39 phrase (wrong word count, unknown
//!   word, bad checksum, or invalid UTF-8). NOT a security oracle.
//! - [`FfiUnlockError::VaultMismatch`] — "vault.toml and identity.bundle.enc
//!   reference different vaults; re-pair from backups".
//! - [`FfiUnlockError::CorruptVault`] — collapses
//!   `{core::CorruptVault, all MalformedX, KdfFailure, WeakKdfParams}`.
//!   Carries a diagnostic `detail: String` for debugging; structured
//!   pattern-matching on the inner cause is intentionally not supported.
//!   Display text is path-neutral (`"vault data integrity failure"`)
//!   so the variant reads correctly on BOTH the open path (where it
//!   fires when a vault file is malformed) AND the create path (where
//!   it fires on rare system-level failures during vault production).
//!
//! # Why a separate FfiVaultError (mirror property)
//!
//! The bytes-in unlock paths cannot raise IO errors — they take owned byte
//! slices, not paths. The folder-in vault paths read four files from disk
//! (`vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`,
//! `contacts/<owner_uuid>.card`) and need a way to surface "your path is
//! wrong" distinctly from "your data is corrupt". The 5 overlapping
//! variants share **byte-identical** Display strings with their
//! `FfiUnlockError` counterparts — pinned by a tripwire test in the
//! [`conversions`] submodule. The drift-resistance comes from
//! `From<core::vault::VaultError>` delegating unlock-class translation
//! through a private `From<FfiUnlockError>` arm; if a future change adds
//! a 6th variant to `FfiUnlockError`, the new variant automatically picks
//! up the right `FfiVaultError` mapping via the delegation.
//!
//! # Submodule layout
//!
//! - [`unlock`] — [`FfiUnlockError`] + `From<core::UnlockError>`.
//! - [`vault`] — [`FfiVaultError`] + `From<core::VaultError>`.
//! - [`conversions`] — `From<FfiUnlockError> for FfiVaultError` + the
//!   byte-identical-mirror tripwire test.

pub mod conversions;
pub mod unlock;
pub mod vault;

pub use unlock::FfiUnlockError;
pub use vault::FfiVaultError;
