//! Manifest CBOR body schema and codec (`docs/vault-format.md` §4.2).
//!
//! The manifest is the top-level vault index: it enumerates blocks, their
//! fingerprints and recipients, the vault-level vector clock, the trash
//! list, and a copy of the KDF params (mirrored from `vault.toml` so the
//! manifest signature attests to them — §4.2 line 205).
//!
//! This module ships **only the CBOR body**: types, canonical encode,
//! canonical decode, and the layer-local error enum. The surrounding
//! binary file header (§4.1), AEAD encrypt/decrypt, hybrid signature
//! suffix (§8), rollback resistance (§10), and orchestrators land in
//! subsequent build-sequence steps.
//!
//! ## Canonical CBOR
//!
//! Same profile as [`record`](super::record) and [`block`](super::block):
//!
//! 1. Map keys sorted bytewise lexicographically by their canonical
//!    encoded form (RFC 8949 §4.2.1, length-then-bytewise).
//! 2. Definite-length encoding for every map, array, and byte/text string.
//! 3. Shortest-form integer and length prefixes.
//! 4. **No tags, no floats, no indefinite-length items** anywhere.
//! 5. Duplicate map keys forbidden (RFC 8949 §5.4).
//!
//! Arrays additionally have explicit sort disciplines:
//!
//! - `vector_clock` and every `vector_clock_summary`: ascending by
//!   `device_uuid` (16-byte bytewise compare).
//! - `blocks`: ascending by `block_uuid`.
//! - `trash`: ascending by `block_uuid`.
//! - per-block `recipients`: ascending by 16-byte contact_uuid.
//!
//! ## Forward compatibility
//!
//! Mirrors [`record`](super::record)'s discipline, with two deliberate
//! exceptions. [`Manifest`], [`BlockEntry`] and [`TrashEntry`] each carry
//! an `unknown`
//! [`BTreeMap<String, UnknownValue>`](std::collections::BTreeMap)
//! that captures unrecognised keys on decode and round-trips them
//! verbatim on encode. A v1 client receiving a v2 manifest preserves the
//! v2 material so a v2 device that subsequently reads the file still sees
//! its extra fields.
//!
//! **[`KdfParamsRef`] and [`VectorClockEntry`] have no such bag and reject
//! an unrecognised key outright** (`WrongType`) — both are fixed-shape
//! sub-maps in v1 with no extension surface, so nothing is silently
//! absorbed there. The consequence is worth stating: a v2 client that adds
//! a field to either sub-map produces a manifest a v1 client cannot open
//! at all. This paragraph said "every struct that maps to a CBOR object"
//! until the #584 review, which was false of both.
//!
//! ## Pure-function API
//!
//! [`encode_manifest`] and [`decode_manifest`] are free functions, not
//! methods, per the codebase convention (pure functions in reusable
//! modules; structs hold state but do not own their own serialisation).

#![forbid(unsafe_code)]

mod decode;
mod encode;
mod error;
mod file;
mod header;
mod types;

#[cfg(test)]
mod test_support;

pub use decode::decode_manifest;
pub use encode::encode_manifest;
pub use error::ManifestError;
pub use file::{
    decode_manifest_file, encode_manifest_file, is_rollback, sign_manifest, verify_manifest,
    ManifestFile,
};
pub use header::{
    decrypt_manifest_body, encrypt_manifest_body, ManifestHeader, MANIFEST_HEADER_LEN,
};
pub use types::{BlockEntry, KdfParamsRef, Manifest, TrashEntry};

// Re-use the block-layer VectorClockEntry: §4.2's vector_clock entries are
// byte-identical in shape and purpose to a block's vector_clock entries.
// See block.rs::VectorClockEntry — same `device_uuid: [u8; 16]` +
// `counter: u64`, same `Eq + Clone + PartialEq`. Re-using is the right
// call: one canonical type for vector clocks across the format.
pub use super::block::VectorClockEntry;

// ---------------------------------------------------------------------------
// Constants — manifest-level CBOR keys (§4.2)
// ---------------------------------------------------------------------------

const KEY_MANIFEST_VERSION: &str = "manifest_version";
const KEY_VAULT_UUID: &str = "vault_uuid";
const KEY_FORMAT_VERSION: &str = "format_version";
const KEY_SUITE_ID: &str = "suite_id";
const KEY_OWNER_USER_UUID: &str = "owner_user_uuid";
const KEY_VECTOR_CLOCK: &str = "vector_clock";
const KEY_BLOCKS: &str = "blocks";
const KEY_TRASH: &str = "trash";
const KEY_KDF_PARAMS: &str = "kdf_params";

// Vector-clock entry keys
const KEY_DEVICE_UUID: &str = "device_uuid";
const KEY_COUNTER: &str = "counter";

// Block-entry keys
const KEY_BLOCK_UUID: &str = "block_uuid";
const KEY_BLOCK_NAME: &str = "block_name";
const KEY_FINGERPRINT: &str = "fingerprint";
const KEY_RECIPIENTS: &str = "recipients";
const KEY_VECTOR_CLOCK_SUMMARY: &str = "vector_clock_summary";
const KEY_CREATED_AT_MS: &str = "created_at_ms";
const KEY_LAST_MOD_MS: &str = "last_mod_ms";

// Trash-entry keys
const KEY_TOMBSTONED_AT_MS: &str = "tombstoned_at_ms";
const KEY_TOMBSTONED_BY: &str = "tombstoned_by";
const KEY_PURGED_AT_MS: &str = "purged_at_ms";

// kdf_params keys
const KEY_MEMORY_KIB: &str = "memory_kib";
const KEY_ITERATIONS: &str = "iterations";
const KEY_PARALLELISM: &str = "parallelism";
const KEY_SALT: &str = "salt";

// Byte lengths for the §4.2 `bstr N` fields.
const UUID_LEN: usize = 16;
const BLOCK_FINGERPRINT_LEN: usize = 32;
const SALT_LEN: usize = 32;

// v1 sentinels.
const MANIFEST_VERSION_V1: u8 = 1;
const FORMAT_VERSION_V1: u16 = crate::version::FORMAT_VERSION;
const SUITE_ID_V1: u16 = crate::version::SUITE_ID;
