//! `expired_trash_entries` / `auto_purge_expired` orchestrators — the #402
//! retention-window counterpart to [`crate::purge`]. Minimal
//! `orchestration.rs` carrying the free-function entry points, the
//! bridge-side [`ExpiredEntry`] / [`RetentionPurgeReport`] projections, and
//! the core-error mapper.

pub mod orchestration;

pub use orchestration::{
    auto_purge_expired, expired_trash_entries, ExpiredEntry, RetentionPurgeReport,
};
