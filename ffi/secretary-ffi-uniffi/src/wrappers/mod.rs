//! uniffi-side opaque-handle wrappers around bridge-crate handle types.
//!
//! Each submodule wraps one logical group of handles:
//! - [`identity`] — `UnlockedIdentity`, `MnemonicOutput`, `CreateVaultOutput`
//! - [`vault`] — `OpenVaultManifest`, `OpenVaultOutput`, `BlockSummary`
//! - [`block`] — `BlockReadOutput`, `Record`, `FieldHandle`
//! - [`save`] — `BlockInput`, `RecordInput`, `FieldInput`, `FieldInputValue`
//! - [`contacts`] — `ContactSummary`
//!
//! The wrappers are newtype-around-bridge-type with thin forwarder methods.
//! All the actual logic lives in `secretary-ffi-bridge`; this layer exists
//! purely so uniffi's scaffolding can reach the types via crate-root paths
//! that match the UDL declarations.

pub mod block;
pub mod contacts;
pub mod device;
pub mod identity;
pub mod save;
pub mod sync;
pub mod vault;

pub use contacts::ContactSummary;
