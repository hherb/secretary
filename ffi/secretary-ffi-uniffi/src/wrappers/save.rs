//! uniffi-side projection types for the `save_block` input shape.
//!
//! These are pure value types with the same shape as the UDL dictionaries —
//! uniffi's UDL-driven scaffolding emits scaffolding code that names them at
//! crate-root scope (e.g. `crate::BlockInput`), so each UDL declaration
//! requires a matching Rust struct / enum re-exported from `lib.rs`.
//!
//! The conversion to the bridge crate's [`secretary_ffi_bridge::BlockInput`]
//! family lives in [`crate::namespace::save_block`], which wraps text /
//! bytes payloads in zeroize-on-drop secret carriers
//! (`SecretString` / `SecretBytes`).
//!
//! # Why a separate module?
//!
//! Mirrors the per-domain organization of the other wrapper modules:
//! `block.rs` (block-read output), `identity.rs` (identity / mnemonic /
//! create-vault output), `vault.rs` (open-vault output + manifest +
//! summary). `save.rs` carries the save-block input domain.

/// Tagged value for a single field on save. (B.4c)
///
/// uniffi codegen produces a Kotlin sealed class / Swift enum on the
/// foreign side. The bridge wraps `Text` payloads in `SecretString` and
/// `Bytes` payloads in `SecretBytes` (both `Zeroize, ZeroizeOnDrop`);
/// the foreign-side `String` / `Vec<u8>` values are caller-owned and
/// must be cleared by the caller after use.
pub enum FieldInputValue {
    /// UTF-8 text payload.
    Text {
        /// UTF-8 plaintext (caller-zeroize after passing to `save_block`).
        text: String,
    },
    /// Raw bytes payload.
    Bytes {
        /// Caller-owned bytes (caller-zeroize after passing to `save_block`).
        data: Vec<u8>,
    },
}

/// One field on a record being saved. (B.4c)
///
/// `name` is plaintext (CBOR map keys at the wire level are plaintext —
/// secrets live in the value, not the key).
pub struct FieldInput {
    /// Field name (plaintext).
    pub name: String,
    /// Tagged value with text or bytes payload.
    pub value: FieldInputValue,
}

/// One record being saved. (B.4c)
///
/// `record_uuid` must be exactly 16 bytes; wrong-length input surfaces as
/// [`crate::VaultError::InvalidArgument`] from
/// [`crate::namespace::save_block`]. Duplicate field names inside `fields`
/// collapse to last-write-wins per the bridge's `into_core_record` helper.
pub struct RecordInput {
    /// 16-byte record UUID (validated as length-16 by the namespace fn).
    pub record_uuid: Vec<u8>,
    /// Ordered list of fields.
    pub fields: Vec<FieldInput>,
}

/// One block being saved. (B.4c)
///
/// `block_uuid` must be exactly 16 bytes. Empty `records` is allowed.
/// Same `block_uuid` on a subsequent save replaces the existing manifest
/// entry in-place; new UUID appends.
pub struct BlockInput {
    /// 16-byte block UUID (validated as length-16 by the namespace fn).
    pub block_uuid: Vec<u8>,
    /// User-visible block name (plaintext within the encrypted manifest).
    pub block_name: String,
    /// Records to save in this block.
    pub records: Vec<RecordInput>,
}
