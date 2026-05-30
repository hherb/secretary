//! D.1.4 edit-path DTOs.
//!
//! `RecordInputDto` is the single secret-bearing INBOUND payload (the field
//! values being saved). Its `Debug` is hand-redacted (mirrors D.1.3's
//! `CreateVaultDto`). Honest limitation (spec §8 / §13, same as D.1.3's
//! `Password`): the `Deserialize` zeroizes nothing of `serde_json`'s own
//! parse buffer — a bounded boundary, not an end-to-end guarantee. The
//! secret strings live only transiently in the command `*_impl` before
//! being moved into the bridge's zeroize-typed `RecordContent`.
//!
//! `RecordRefDto` / `RecordRevealDto` are OUTBOUND. `RecordRevealDto` carries
//! one record's field values (text plaintext / base64 bytes) for edit
//! prefill — the same single-record exposure as D.1.2 reveal.

/// One field-value on the wire: text or base64-encoded bytes.
#[derive(serde::Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum FieldValueDto {
    Text { text: String },
    Bytes { base64: String },
}

/// One field being saved.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FieldInputDto {
    pub name: String,
    pub value: FieldValueDto,
}

/// The editable delta for one record. Secret-bearing → redacted `Debug`.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordInputDto {
    pub record_type: String,
    pub tags: Vec<String>,
    pub fields: Vec<FieldInputDto>,
}

impl std::fmt::Debug for RecordInputDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact: field NAMES are arguably non-secret, but values are; redact
        // the whole field list to a count so a stray {:?} can never leak a value.
        f.debug_struct("RecordInputDto")
            .field("record_type", &self.record_type)
            .field("tags", &self.tags)
            .field("fields", &format_args!("<{} redacted>", self.fields.len()))
            .finish()
    }
}

/// Identifies a just-saved record so the frontend can re-navigate/refresh.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordRefDto {
    pub block_uuid_hex: String,
    pub record_uuid_hex: String,
}

/// One revealed field for edit prefill: name + is_text + value (plaintext or
/// base64). Secret-bearing OUTBOUND — the frontend holds it only in the
/// editor draft and clears it after save.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedFieldWithNameDto {
    pub name: String,
    pub is_text: bool,
    pub value: String,
}

impl std::fmt::Debug for RevealedFieldWithNameDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealedFieldWithNameDto")
            .field("name", &self.name)
            .field("is_text", &self.is_text)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// All of one record's fields, revealed for editing.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordRevealDto {
    pub fields: Vec<RevealedFieldWithNameDto>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn record_input_dto_deserializes_camel_case_and_tagged_value() {
        let json = r#"{
            "recordType": "login",
            "tags": ["work"],
            "fields": [
                { "name": "user", "value": { "kind": "text", "text": "alice" } },
                { "name": "seed", "value": { "kind": "bytes", "base64": "aGVsbG8=" } }
            ]
        }"#;
        let dto: RecordInputDto = serde_json::from_str(json).expect("deserialize");
        assert_eq!(dto.record_type, "login");
        assert_eq!(dto.tags, vec!["work".to_string()]);
        assert_eq!(dto.fields.len(), 2);
        assert_eq!(dto.fields[0].name, "user");
        assert!(matches!(dto.fields[0].value, FieldValueDto::Text { .. }));
        assert!(matches!(dto.fields[1].value, FieldValueDto::Bytes { .. }));
    }

    #[test]
    fn record_input_dto_debug_is_redacted() {
        let dto = RecordInputDto {
            record_type: "login".into(),
            tags: vec![],
            fields: vec![FieldInputDto {
                name: "password".into(),
                value: FieldValueDto::Text {
                    text: "hunter2".into(),
                },
            }],
        };
        let dbg = format!("{dto:?}");
        assert!(
            !dbg.contains("hunter2"),
            "field value must not appear in Debug"
        );
        assert!(dbg.contains("redacted"));
    }

    #[test]
    fn record_ref_dto_uses_camel_case_hex() {
        let v: Value = serde_json::from_str(
            &serde_json::to_string(&RecordRefDto {
                block_uuid_hex: "ab".into(),
                record_uuid_hex: "cd".into(),
            })
            .unwrap(),
        )
        .unwrap();
        assert_eq!(v["blockUuidHex"], "ab");
        assert_eq!(v["recordUuidHex"], "cd");
    }
}
