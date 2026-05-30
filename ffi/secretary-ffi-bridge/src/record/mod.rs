//! Bridge surface for `read_block` (Sub-project B.4b).
//!
//! Exposes the free function [`read_block`] and the three opaque handle
//! types that carry the decrypted records out to PyO3 / uniffi:
//! [`BlockReadOutput`], [`Record`], [`FieldHandle`].
//!
//! # Hybrid Record projection
//!
//! Foreign-language `Record` carries non-secret metadata as plain
//! accessors (record_uuid, record_type, tags, timestamps, tombstone)
//! plus an ordered list of [`FieldHandle`]s. Each [`FieldHandle`]
//! carries name + last_mod + device_uuid as plain accessors, and
//! `expose_text()` / `expose_bytes()` for the secret payload. The
//! foreign caller must opt-in per-field to surfacing the secret —
//! there is no eager copy-out at `read_block` time.
//!
//! # Lifecycle
//!
//! [`BlockReadOutput::wipe`] cascades to every contained [`Record`]
//! and [`FieldHandle`], which themselves cascade to the underlying
//! [`secretary_core::vault::record::RecordFieldValue`]'s [`zeroize`]
//! impl. Wipe is idempotent everywhere; foreign callers using the
//! context-manager / `defer` / `use` idiom get full cleanup
//! automatically.
//!
//! `Record` and `FieldHandle` use `Arc<Mutex<Option<Inner>>>` so
//! accessors can hand out cheap clones the foreign caller can store.
//! `BlockReadOutput` uses the simpler `Mutex<Option<Inner>>` (no
//! shared-clone access pattern). The Arc clone shares the same
//! `Option::take()` slot — wiping any clone wipes them all
//! immediately.
//!
//! # Single-author block reading (v1)
//!
//! B.4b assumes the block author = vault owner (the v1 single-author
//! case covered by `golden_vault_001`). The bridge takes
//! `manifest.owner_card` as both the sender and reader card when
//! calling `core::block::decrypt_block`. If the on-disk block's
//! `author_fingerprint` doesn't match `fingerprint(owner_card)`,
//! `decrypt_block` returns `BlockError::AuthorFingerprintMismatch`
//! which folds into [`FfiVaultError::CorruptVault`]. B.4d's
//! `share_block` flow will add `contacts/<author_uuid>.card`
//! discovery + the multi-author read path.
//!
//! [`zeroize`]: https://docs.rs/zeroize
//! [`FfiVaultError::CorruptVault`]: crate::error::FfiVaultError::CorruptVault

mod field;
mod handle;
pub(crate) mod orchestration;
mod output;

pub use field::FieldHandle;
pub use handle::Record;
pub use orchestration::read_block;
pub use output::BlockReadOutput;
