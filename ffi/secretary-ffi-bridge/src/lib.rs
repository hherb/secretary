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
//! - [`FfiUnlockError`] — thinned 3-variant error type expressing
//!   user-actionable intent rather than mirroring `core::UnlockError`'s
//!   internal enum structure. See [`error`] module docs.
//! - [`UnlockedIdentity`] — opaque handle wrapping a successfully-unlocked
//!   `core::UnlockedIdentity`. Foreign callers hold a refcount and read
//!   non-secret fields via accessor methods; the secret keys stay Rust-
//!   side and zeroize on drop. See [`identity`] module docs.
//! - [`open_with_password`] — fallible, secret-bearing operation: vault
//!   unlock by master password. See [`unlock`] module docs.
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

pub use error::FfiUnlockError; // uncommented in Task 4
pub use identity::UnlockedIdentity; // uncommented in Task 5
pub use unlock::open_with_password; // uncommented in Task 6
