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
    ReadBlock,
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
