//! JSON-input → typed-value helpers shared by v2 write-op dispatchers
//! (`save_block`, `share_block`, `trash_block`, `restore_block`).
//!
//! Wrong-length UUID inputs synthesize
//! `BridgeOrSyntheticErr::Synthetic { variant: "InvalidArgument" }`
//! symmetrically with the uniffi namespace-layer `uuid_from_vec`
//! length check on Swift / Kotlin (the bridge's `[u8; 16]` parameters
//! are type-bounded so wrong-length never reaches the bridge directly).

use secretary_core::crypto::secret::{SecretBytes, SecretString};
use secretary_ffi_bridge::{BlockInput, FieldInput, FieldInputValue, RecordInput};

use super::super::types::BridgeOrSyntheticErr;

/// Parse a `*_hex` or `*_bytes_hex` input field into a `[u8; 16]`.
/// Returns `Err(BridgeOrSyntheticErr::Synthetic{"InvalidArgument"})`
/// for any non-16-byte input — matches the uniffi-layer
/// `uuid_from_vec` behavior so Swift/Kotlin get a real
/// VaultError.InvalidArgument while Rust gets the synthesized analogue.
pub(super) fn uuid_from_inputs(
    inputs: &serde_json::Value,
    primary_field: &str,
    bytes_field: &str,
    label: &str,
) -> Result<[u8; 16], BridgeOrSyntheticErr> {
    let raw = inputs
        .get(primary_field)
        .or_else(|| inputs.get(bytes_field))
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| {
            panic!("inputs need {primary_field} or {bytes_field} (vector dispatch error)")
        });
    let bytes =
        hex::decode(raw).unwrap_or_else(|e| panic!("{label}: {primary_field} hex decode: {e}"));
    if bytes.len() != 16 {
        return Err(BridgeOrSyntheticErr::Synthetic {
            variant: "InvalidArgument",
            detail: format!("{label} must be exactly 16 bytes, got {}", bytes.len()),
        });
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Build a `BlockInput` from the JSON `inputs.records` array. Each
/// record has `record_uuid_hex` + `fields[]`; each field has `name`,
/// `type` (`"text"` or `"bytes"`), and a value (`value_utf8` or
/// `value_hex`). The bridge's `RecordInput` does not carry `record_type`
/// or `tags` (both default to empty inside `into_core_record`).
///
/// Wrong-length `block_uuid_*` or `record_uuid_*` inputs synthesize
/// `BridgeOrSyntheticErr::Synthetic { variant: "InvalidArgument" }`
/// symmetrically with `uuid_from_inputs` — this is the surface that
/// matches the uniffi namespace-layer `uuid_from_vec` length check
/// on Swift / Kotlin, where the bridge's `[u8; 16]` parameters are
/// type-bounded so wrong-length never reaches the bridge.
pub(super) fn block_input_from_inputs(
    inputs: &serde_json::Value,
) -> Result<BlockInput, BridgeOrSyntheticErr> {
    let block_uuid = uuid_from_inputs(
        inputs,
        "block_uuid_hex",
        "block_uuid_bytes_hex",
        "input.block_uuid",
    )?;

    let block_name = inputs
        .get("block_name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let records: Vec<RecordInput> =
        if let Some(arr) = inputs.get("records").and_then(|v| v.as_array()) {
            arr.iter()
                .map(|rec| -> Result<RecordInput, BridgeOrSyntheticErr> {
                    let record_uuid = uuid_from_inputs(
                        rec,
                        "record_uuid_hex",
                        "record_uuid_bytes_hex",
                        "record.record_uuid",
                    )?;
                    let fields: Vec<FieldInput> = rec
                        .get("fields")
                        .and_then(|v| v.as_array())
                        .map(|fs| {
                            fs.iter()
                                .map(|f| {
                                    let name = f
                                        .get("name")
                                        .and_then(|v| v.as_str())
                                        .expect("field needs name")
                                        .to_string();
                                    let ftype = f
                                        .get("type")
                                        .and_then(|v| v.as_str())
                                        .expect("field needs type");
                                    let value = match ftype {
                                        "text" => FieldInputValue::Text(SecretString::from(
                                            f.get("value_utf8")
                                                .and_then(|v| v.as_str())
                                                .expect("text field needs value_utf8")
                                                .to_string(),
                                        )),
                                        "bytes" => FieldInputValue::Bytes(SecretBytes::from(
                                            hex::decode(
                                                f.get("value_hex")
                                                    .and_then(|v| v.as_str())
                                                    .expect("bytes field needs value_hex"),
                                            )
                                            .expect("value_hex decode"),
                                        )),
                                        other => panic!("unknown field type {other}"),
                                    };
                                    FieldInput { name, value }
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    Ok(RecordInput {
                        record_uuid,
                        fields,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?
        } else {
            Vec::new()
        };

    Ok(BlockInput {
        block_uuid,
        block_name,
        records,
    })
}

/// Extract `now_ms` (required for all v2 write ops).
pub(super) fn now_ms_from_inputs(inputs: &serde_json::Value) -> u64 {
    inputs
        .get("now_ms")
        .and_then(|v| v.as_u64())
        .expect("v2 write-op vector needs now_ms")
}
