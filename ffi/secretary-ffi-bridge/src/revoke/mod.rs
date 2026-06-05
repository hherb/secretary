//! `revoke_block` orchestrator. Mirrors `share/`'s structure: this module
//! holds the free-function entry point that removes one recipient from an
//! existing block and re-keys for the remainder. v1 single-author: only the
//! vault owner can revoke from blocks they authored.
//!
//! The near-exact inverse of `share/`. See the orchestration module docs.

pub mod orchestration;

pub use orchestration::revoke_block;
