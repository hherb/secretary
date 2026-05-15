//! uniffi-side error types and bridge-to-uniffi error translations.
//!
//! Both `UnlockError` and `VaultError` mirror the bridge crate's
//! `FfiUnlockError` / `FfiVaultError` shape. uniffi auto-marshals these to
//! Swift `enum ...: Error` and Kotlin `sealed class ...`. The structured
//! field is named `detail` rather than `message` because uniffi 0.31's
//! Kotlin codegen produces an "overload resolution ambiguity" between
//! `Throwable.message` and a user-defined `message` field.
//!
//! `VaultError` carries one extra variant (`InvalidArgument`) that has no
//! counterpart in the bridge's `FfiVaultError` — it's uniffi-side only
//! because uniffi 0.31 has no native `ValueError` equivalent at the
//! namespace-fn level, so wrong-length / malformed FFI inputs need to ride
//! inside `VaultError`. Pythoning out wrong-length inputs as `ValueError`
//! is the parallel pattern in `secretary-ffi-py`.
//!
//! # Module layout
//!
//! - [`unlock`] — `UnlockError` enum + `From<FfiUnlockError>` translation.
//! - [`vault`] — `VaultError` enum + `From<FfiVaultError>` translation
//!   plus the uniffi-only `InvalidArgument` variant.
//!
//! The types are re-exported at this module's root so `lib.rs`'s
//! `pub use errors::{UnlockError, VaultError};` line (which feeds uniffi
//! scaffolding's `crate::TypeName` path) keeps working unchanged.

pub mod unlock;
pub mod vault;

pub use unlock::UnlockError;
pub use vault::VaultError;
