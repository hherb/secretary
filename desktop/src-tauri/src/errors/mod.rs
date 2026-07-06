//! `AppError` + `AppWarning` types crossing the Tauri IPC boundary.
//!
//! See spec §9 for the full mapping rules. Key disciplines:
//!
//! - Every variant `#[serde(tag = "code", rename_all = "snake_case")]` so
//!   the wire format is `{ "code": "wrong_password", ... }`.
//! - Developer-facing `detail` fields are `#[serde(skip_serializing)]` — they're
//!   logged via `tracing` on the Rust side but NEVER cross the IPC seam.
//! - The mapping from `FfiVaultError` is split into a pure [`map_ffi_error`]
//!   function (no side effects, exhaustive match) and an `impl From` that
//!   logs at `warn` before delegating. The side effect is visible at the
//!   call site rather than buried inside the `From` body.
//! - `WrongPassword` collapse rule: anything decryption-failure-shaped becomes
//!   `WrongPassword` (info-leak prevention per `docs/threat-model.md` §13).
//!
//! # Variant coverage versus FfiVaultError
//!
//! The `map_ffi_error` match is exhaustive (no `_` catch-all) so every new
//! bridge variant forces a deliberate UI-mapping choice rather than silently
//! folding to `Internal`. Most bridge variants now route to a typed
//! `AppError` — including the D.1.5 trash/restore preconditions and the
//! D.1.6 block-share + contacts variants (`NotAuthor`,
//! `RecipientAlreadyPresent`, `RecipientNotPresent`, `CannotRevokeOwner`,
//! `MissingRecipientCard`, `ContactAlreadyExists`, `ContactNotFound`). A
//! residual few that should never fire on a reachable
//! UI path (e.g. a stale block UUID into `read_block`) fold to
//! `Internal { detail }` so a regression surfaces as a clear "this is a bug"
//! rather than a silent miscategorisation.
//!
//! Note: the bridge already collapses `WeakKdfParams` into `CorruptVault`
//! (post-unlock detail string). `AppError::KdfTooWeak` therefore has no
//! producer in this `From` impl — it survives as a typed variant for the
//! future where the bridge exposes the parameter pair structurally, and
//! its serialization shape is pinned by `kdf_too_weak_carries_payload`.
//!
//! # Internal layout
//!
//! Split across private siblings — callers see a single flat `errors::*`
//! surface:
//!
//! - `types` — the `AppError` / `AppWarning` enum definitions (the
//!   wire-format schema).
//! - `mapping` — the `FfiVaultError` → `AppError` bridge mapping
//!   ([`map_ffi_error`] + `impl From`).
//! - `tests` — the serde round-trip + mapping-routing suite that pins the
//!   IPC contract.

mod mapping;
mod types;

pub use mapping::map_ffi_error;
pub use types::{AppError, AppWarning};

#[cfg(test)]
mod tests;
