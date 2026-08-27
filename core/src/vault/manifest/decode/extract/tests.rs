//! Unit tests for the manifest typed-extract helpers.
//!
//! Moved verbatim out of the pre-split `manifest/tests.rs` (#564); shared
//! fixtures live in [`crate::vault::manifest::test_support`].
//!
//! Each test below drives `decode::decode_manifest` end to end, but the
//! function whose behaviour it pins — and which would have to change for
//! the test to break — is the extract helper its doc comment names.

use crate::vault::canonical::encode_canonical_map;
use crate::vault::manifest::test_support::dummy_kdf_params_value;
use crate::vault::manifest::{
    decode_manifest, FORMAT_VERSION_V1, KEY_BLOCKS, KEY_FORMAT_VERSION, KEY_KDF_PARAMS,
    KEY_MANIFEST_VERSION, KEY_OWNER_USER_UUID, KEY_SUITE_ID, KEY_TRASH, KEY_VAULT_UUID,
    KEY_VECTOR_CLOCK, MANIFEST_VERSION_V1, SUITE_ID_V1, UUID_LEN,
};

use super::*;

// (Group B) Hand-crafted decode negatives — pin every typed
// ManifestError variant that's reachable from real input but lacked a
// dedicated negative. Mirrors the style of the
// `rejects_unsupported_manifest_version` test in `decode`'s own `tests`
// and the `rejects_duplicate_*` ones in `decode::entries`'s (they read
// "above" here until #564 split this file out). Catches the regression
// where a refactor of `decode_manifest` collapses a typed variant into a
// generic CBOR error.

/// Regression: ensures `decode_manifest` rejects a top-level map whose
/// keys aren't all text strings. §4.2 fixes every map key as `tstr`.
#[test]
fn rejects_non_text_map_key() {
    // Build a hand-crafted top-level map with one integer key
    // alongside the text-string keys. The integer key fires
    // `take_text_key` → `NonTextKey` before any field-specific
    // dispatch.
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_KDF_PARAMS.into()), dummy_kdf_params_value()),
        // Integer key — illegal under §4.2 ("all map keys are tstr").
        (Value::Integer(0u64.into()), Value::Integer(0u64.into())),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("integer map key must reject");
    assert!(
        matches!(err, ManifestError::NonTextKey),
        "expected NonTextKey, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` rejects a known field with the
/// wrong CBOR type. Field is `vault_uuid` (declared as `bstr 16`); we
/// hand-encode it as a text string so `take_fixed_bytes` fires the
/// `WrongType { expected: "byte string" }` arm.
#[test]
fn rejects_wrong_type_for_vault_uuid() {
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        // vault_uuid declared as text — wrong type.
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Text("01010101-0101-0101-0101-010101010101".into()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_KDF_PARAMS.into()), dummy_kdf_params_value()),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("text vault_uuid must reject");
    assert!(
        matches!(
            err,
            ManifestError::WrongType {
                field: KEY_VAULT_UUID,
                expected: "byte string",
            }
        ),
        "expected WrongType {{ field: vault_uuid, expected: byte string }}, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` rejects a fixed-length `bstr`
/// field whose byte count is wrong. `vault_uuid` is `bstr 16`; here we
/// supply 15 bytes so `take_fixed_bytes::<16>` fails its
/// `<[u8; N]>::try_from` conversion (#547 Task 7b: was `Vec::try_into`
/// before the borrow conversion — same failure, different spelling).
#[test]
fn rejects_invalid_byte_length_for_vault_uuid() {
    let entries: Vec<(Value, Value)> = vec![
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(u64::from(MANIFEST_VERSION_V1).into()),
        ),
        // 15 bytes — short by one of the §4.2 declared 16.
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes(vec![0x01; UUID_LEN - 1]),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_KDF_PARAMS.into()), dummy_kdf_params_value()),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("15-byte vault_uuid must reject");
    assert!(
        matches!(
            err,
            ManifestError::InvalidByteLength {
                field: KEY_VAULT_UUID,
                expected: UUID_LEN,
                length: 15,
            }
        ),
        "expected InvalidByteLength {{ field: vault_uuid, expected: 16, length: 15 }}, got {err:?}"
    );
}

/// Regression: ensures `decode_manifest` rejects an integer field that
/// exceeds its declared range. `manifest_version` is declared `u8`;
/// here we encode a CBOR negative integer (major type 1) so
/// `take_u8`'s `0..=u8::MAX` range check fires `IntegerOutOfRange`.
#[test]
fn rejects_integer_out_of_range_for_manifest_version() {
    let entries: Vec<(Value, Value)> = vec![
        // -1 — outside [0, 255]. ciborium represents this as
        // major-type-1 integer; `take_integer_i128` returns -1 and
        // `take_u8`'s contains check fails.
        (
            Value::Text(KEY_MANIFEST_VERSION.into()),
            Value::Integer(ciborium::value::Integer::from(-1i64)),
        ),
        (
            Value::Text(KEY_VAULT_UUID.into()),
            Value::Bytes([0x01; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_FORMAT_VERSION.into()),
            Value::Integer(u64::from(FORMAT_VERSION_V1).into()),
        ),
        (
            Value::Text(KEY_SUITE_ID.into()),
            Value::Integer(u64::from(SUITE_ID_V1).into()),
        ),
        (
            Value::Text(KEY_OWNER_USER_UUID.into()),
            Value::Bytes([0x02; UUID_LEN].to_vec()),
        ),
        (
            Value::Text(KEY_VECTOR_CLOCK.into()),
            Value::Array(Vec::new()),
        ),
        (Value::Text(KEY_BLOCKS.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_TRASH.into()), Value::Array(Vec::new())),
        (Value::Text(KEY_KDF_PARAMS.into()), dummy_kdf_params_value()),
    ];
    let bytes = encode_canonical_map(&entries).expect("encode_canonical_map");

    let err = decode_manifest(&bytes).expect_err("negative manifest_version must reject");
    assert!(
        matches!(
            err,
            ManifestError::IntegerOutOfRange {
                field: KEY_MANIFEST_VERSION,
                value: -1,
            }
        ),
        "expected IntegerOutOfRange {{ field: manifest_version, value: -1 }}, got {err:?}"
    );
}
