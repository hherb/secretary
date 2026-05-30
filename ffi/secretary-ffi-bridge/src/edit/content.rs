//! `RecordContent` — the editable delta the desktop sends for one record.
//! Reuses the zeroize-typed [`FieldInput`](crate::save::input::FieldInput) /
//! [`FieldInputValue`](crate::save::input::FieldInputValue) from
//! `crate::save::input`. Unlike `RecordInput` (the from-scratch save path),
//! `RecordContent` is APPLIED to a record that may already exist, so the
//! edit primitives carry forward that record's `unknown` (and the block's
//! and every sibling's) — see [`crate::edit`].

use crate::save::input::FieldInput;

/// The editable part of a record: its open-ended type, tags, and fields.
///
/// `record_uuid`, `created_at_ms`, record-level `unknown`, and per-field
/// `unknown` are NOT here — the edit primitives own those
/// (preserve-on-edit / mint-on-add). The secret-bearing field values live
/// inside [`FieldInput`]'s zeroize-typed
/// [`FieldInputValue`](crate::save::input::FieldInputValue); a
/// `RecordContent` therefore zeroizes its secrets when it drops, and the
/// edit primitives never stash it past the call.
#[derive(Clone, Debug)]
pub struct RecordContent {
    /// Open-ended record-type discriminator (e.g. `"login"`). Empty allowed.
    pub record_type: String,
    /// Cross-cutting tags.
    pub tags: Vec<String>,
    /// Fields (name + zeroize-typed text/bytes value).
    pub fields: Vec<FieldInput>,
}
