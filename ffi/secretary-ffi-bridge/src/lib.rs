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
//! - [`FfiUnlockError`] — thinned 5-variant error type expressing
//!   user-actionable intent rather than mirroring `core::UnlockError`'s
//!   internal enum structure. Two variants per unlock path
//!   (`WrongPasswordOrCorrupt` / `WrongMnemonicOrCorrupt`) plus a
//!   pre-decryption `InvalidMnemonic { detail }` for BIP-39 validation
//!   failures, plus the cross-path `VaultMismatch` and `CorruptVault { detail }`.
//!   See [`error`] module docs.
//! - [`UnlockedIdentity`] — opaque handle wrapping a successfully-unlocked
//!   `core::UnlockedIdentity`. Foreign callers hold a refcount and read
//!   non-secret fields via accessor methods; the secret keys stay Rust-
//!   side and zeroize on drop. Both unlock entry points return this same
//!   shape (the §3/§4 dual-KEK design produces byte-identical secret state).
//!   See [`identity`] module docs.
//! - [`open_with_password`] — fallible, secret-bearing operation: vault
//!   unlock by master password. See [`unlock`] module docs.
//! - [`open_with_recovery`] — fallible, secret-bearing operation: vault
//!   unlock by 24-word BIP-39 recovery phrase. Mnemonic input is UTF-8
//!   bytes (`&[u8]`), parallel to the password input shape. See [`unlock`]
//!   module docs.
//!
//! # Invariants
//!
//! - Pure-safe Rust. The workspace's `#![forbid(unsafe_code)]` applies
//!   without carve-out (the binding-flavor crates carry the FFI-macro
//!   `unsafe_code = "deny"` carve-outs locally).
//! - The `From<core::unlock::UnlockError>` impl in [`error`] uses explicit
//!   match arms with no wildcard so future core variants force a compile
//!   error instead of silently mapping to a default.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod error;
pub mod identity;
pub mod unlock;

pub use error::FfiUnlockError;
pub use identity::UnlockedIdentity;
pub use unlock::{open_with_password, open_with_recovery};
