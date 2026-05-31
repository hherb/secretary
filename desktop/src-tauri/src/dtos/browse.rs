//! D.1.2 browse-path DTOs. `BlockDetailDto` / `RecordDto` / `FieldMetaDto`
//! carry NO secret payload — only plaintext metadata (names, types, tags,
//! timestamps). `RevealedFieldDto` is the single DTO that carries a secret
//! (`value`), produced only by `reveal_field` on an explicit reveal click.

/// Read projection of one decrypted block: name + the (tombstone-filtered)
/// records. No secret values — field *values* are fetched separately via
/// `reveal_field`.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDetailDto {
    pub block_uuid_hex: String,
    pub block_name: String,
    pub records: Vec<RecordDto>,
}

/// One record's plaintext metadata + its field metadata list.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
    pub field_count: u64,
    pub fields: Vec<FieldMetaDto>,
    /// `true` when the record is tombstoned. Only ever `true` in a projection
    /// the caller requested with `include_deleted` (the read gate is Rust's).
    pub tombstoned: bool,
}

/// One field's plaintext metadata. The value is NOT here — it crosses only
/// via `reveal_field` → `RevealedFieldDto`.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldMetaDto {
    pub name: String,
    pub last_mod_ms: u64,
    pub is_text: bool,
    pub is_bytes: bool,
}

/// The single secret-bearing DTO. `value` is plaintext for a text field or
/// base64 for a bytes field; `is_text` disambiguates. Produced only by
/// `reveal_field` on explicit reveal; the frontend holds it briefly and
/// drops it on re-mask / navigate / lock (it cannot be zeroized in JS).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedFieldDto {
    pub is_text: bool,
    pub value: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SAMPLE_UUID_HEX: &str = "00112233445566778899aabbccddeeff";

    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("serialize")).expect("parse")
    }

    #[test]
    fn field_meta_dto_camel_case_no_value_field() {
        let dto = FieldMetaDto {
            name: "password".to_string(),
            last_mod_ms: 2_000_000_000_000,
            is_text: true,
            is_bytes: false,
        };
        let v = to_json(&dto);
        assert_eq!(v["name"], "password");
        assert_eq!(v["lastModMs"], 2_000_000_000_000_u64);
        assert_eq!(v["isText"], true);
        assert_eq!(v["isBytes"], false);
        assert!(v.get("value").is_none());
        assert!(v.get("last_mod_ms").is_none());
    }

    #[test]
    fn record_dto_camel_case_with_hex_uuid_and_field_count() {
        let dto = RecordDto {
            record_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            record_type: "login".to_string(),
            tags: vec!["work".to_string()],
            created_at_ms: 100,
            last_mod_ms: 200,
            field_count: 2,
            fields: vec![],
            tombstoned: false,
        };
        let v = to_json(&dto);
        assert_eq!(v["recordUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["recordType"], "login");
        assert_eq!(v["tags"][0], "work");
        assert_eq!(v["fieldCount"], 2);
        assert_eq!(v["tombstoned"], false);
        assert!(v.get("record_uuid_hex").is_none());
    }

    #[test]
    fn block_detail_dto_camel_case() {
        let dto = BlockDetailDto {
            block_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            block_name: "Personal logins".to_string(),
            records: vec![],
        };
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["blockName"], "Personal logins");
        assert_eq!(v["records"], serde_json::json!([]));
    }

    #[test]
    fn revealed_field_dto_carries_value_and_is_text_flag() {
        let dto = RevealedFieldDto {
            is_text: true,
            value: "hunter2".to_string(),
        };
        let v = to_json(&dto);
        assert_eq!(v["isText"], true);
        assert_eq!(v["value"], "hunter2");
    }
}
