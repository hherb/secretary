//! KAT vector deserialization types and the bridge-or-synthetic error wrapper.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Kat {
    pub version: u32,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    pub comment: String,
    pub vectors: Vec<Vector>,
}

#[derive(Debug, Deserialize)]
pub struct Vector {
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)] // documentation field; the replay does not read it.
    pub description: String,
    pub operation: Operation,
    pub inputs: serde_json::Value,
    #[serde(default)]
    pub after: Option<String>,
    pub expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    OpenVaultWithPassword,
    OpenVaultWithRecovery,
    // Device-slot open path — ADR 0009 / B.2.
    OpenWithDeviceSecret,
    ReadBlock,
    // v2 lifecycle ops — issue #59.
    OpenVaultWithPasswordWritable,
    SaveBlock,
    ShareBlock,
    TrashBlock,
    RestoreBlock,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Expected {
    Ok(OkPayload),
    Err {
        variant: String,
        #[serde(default)]
        detail_contains: Option<String>,
    },
}

#[derive(Debug, Deserialize, Default)]
pub struct OkPayload {
    // Open ops:
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub block_count: Option<u64>,
    #[serde(default)]
    pub block_uuid_hex: Option<String>,
    // read_block records:
    #[serde(default)]
    pub records: Option<Vec<ExpectedRecord>>,
    // v2 lifecycle ops:
    #[serde(default)]
    pub post_state: Option<PostState>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedRecord {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub fields: Vec<ExpectedField>,
}

#[derive(Debug, Deserialize)]
pub struct ExpectedField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String, // "text" or "bytes"
    #[serde(default)]
    pub value_utf8: Option<String>,
    #[serde(default)]
    pub value_hex: Option<String>,
}

/// Post-call manifest-shape assertions for v2 write ops. All fields
/// optional; the replay engine asserts only what the vector pins.
#[derive(Debug, Deserialize, Default)]
pub struct PostState {
    /// Required on every v2 Ok post_state. Pins `manifest.block_count()`.
    #[serde(default)]
    pub block_count: Option<u64>,
    /// `"<hex>"` asserts `manifest.find_block(hex).is_some()` and
    /// hex-equals the returned summary's `block_uuid`. Absent / JSON null
    /// asserts nothing — absence-after-trash is already covered by
    /// `block_count` (e.g. trash_block_happy pins block_count 2→1; the
    /// only way to reach block_count==1 is for find_block(new_uuid) to
    /// be None).
    #[serde(default)]
    pub find_block_uuid_hex: Option<String>,
    /// share_block only. Pins `manifest.find_block(uuid).recipient_uuids.len()`.
    #[serde(default)]
    pub recipient_count: Option<u64>,
    /// save_block_*_happy only. Triggers a chained `read_block(uuid)`
    /// after the op and asserts records bit-for-bit.
    #[serde(default)]
    pub read_block: Option<ExpectedReadBlock>,
}

/// The round-trip read_block payload pinned post-save. Same `records`
/// shape that v1's `OkPayload::records` carries.
#[derive(Debug, Deserialize)]
pub struct ExpectedReadBlock {
    pub records: Vec<ExpectedRecord>,
}

/// Internal wrapper letting `run_read_block` surface either a real
/// `FfiVaultError` (from the bridge) OR a synthesized "InvalidArgument"
/// case-name when the input fails the wrong-length pre-check (the
/// bridge's `read_block` signature is `&[u8; 16]` so wrong-length is
/// rejected at the binding layer in production, not in core).
///
/// Synthesis rationale: see design doc §11 (B.6 v1).
#[derive(Debug)]
pub enum BridgeOrSyntheticErr {
    Bridge(secretary_ffi_bridge::error::FfiVaultError),
    Synthetic {
        variant: &'static str,
        detail: String,
    },
}
