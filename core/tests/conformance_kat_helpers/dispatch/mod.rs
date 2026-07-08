//! Per-operation dispatch + Ok-payload assertion helpers.
//!
//! `run_*` invoke the bridge crate; `assert_*` check the observable
//! output against the pinned expectation. Split into one file per op
//! family (issue #67) to stay under the 500-LOC guideline:
//!
//! - [`open`] — `open_vault_with_password` / `open_vault_with_recovery`
//!   / `open_vault_with_password_writable` and `assert_open_ok`.
//! - [`read`] — `read_block` plus its record-shape assertions.
//! - [`lifecycle`] — v2 write ops (`save_block`, `share_block`,
//!   `trash_block`, `restore_block`) plus `assert_post_state`, and the
//!   #399 purge ops (`purge_block`, `empty_trash`) plus their report
//!   assertions (Task 11a).
//! - [`inputs`] — JSON-input → typed-value helpers shared by all
//!   v2 write-op dispatchers (`uuid_from_inputs` /
//!   `block_input_from_inputs` / `now_ms_from_inputs`).
//!
//! `mod.rs` re-exports the entry-test surface so callers keep importing
//! `conformance_kat_helpers::dispatch::{run_*, assert_*}` unchanged.

pub mod inputs;
pub mod lifecycle;
pub mod open;
pub mod read;

pub use lifecycle::{
    assert_empty_trash_report, assert_post_state, assert_purge_report, run_empty_trash,
    run_purge_block, run_restore_block, run_save_block, run_share_block, run_trash_block,
};
pub use open::{
    assert_open_ok, run_open_device_secret, run_open_password, run_open_recovery, run_open_writable,
};
pub use read::{assert_read_block_ok, run_read_block};
