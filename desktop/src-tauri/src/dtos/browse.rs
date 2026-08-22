//! D.1.2 browse-path DTOs.
//!
//! # What carries a decrypted field value
//!
//! Two DTOs do, and both hand-roll a redacted [`std::fmt::Debug`] rather than
//! deriving one — the same discipline `dtos::edit`'s `RecordInputDto` and
//! `dtos::create` already apply, for the same reason: a stray `{:?}` at any
//! `tracing` site would otherwise print the value.
//!
//! - [`RevealedFieldDto`] — `value`, produced only by `reveal_field` on an
//!   explicit reveal click. Auto-hides in the frontend.
//! - [`RecordDto`] — `title` / `subtitle`, derived by [`crate::record_title`]
//!   from a **decrypted** field value behind that module's allowlist (#526).
//!   Unlike a revealed field these do NOT auto-hide: they are on screen for as
//!   long as the record list is. Before #526 the browse path never called
//!   `expose_text` at all, and this module's doc claimed no browse DTO carried
//!   a secret; that claim is what stopped being true.
//!
//! Everything else here is plaintext metadata the threat model already treats
//! as visible at this layer: block/field names, record type, tags, timestamps,
//! counts. [`BlockDetailDto`] and [`FieldMetaDto`] therefore still derive
//! `Debug` — `BlockDetailDto` safely, because its only secret-adjacent content
//! is the `RecordDto`s whose own `Debug` redacts.

/// Read projection of one decrypted block: name + the (tombstone-filtered)
/// records. Field *values* are fetched separately via `reveal_field`; the
/// per-record row labels are the one decrypted-value exception (see
/// [`RecordDto`]).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockDetailDto {
    pub block_uuid_hex: String,
    pub block_name: String,
    pub records: Vec<RecordDto>,
}

/// One record's metadata + its field metadata list.
///
/// Secret-bearing → redacted `Debug`: `title` / `subtitle` are derived from a
/// decrypted field value (see the module doc).
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    /// Human-readable row label, derived by `crate::record_title` behind an
    /// allowlist of field names. Falls back to `record_type`. Never carries a
    /// non-allowlisted field's plaintext.
    pub title: String,
    /// Secondary row label, `"<field name>: <value>"`, same allowlist.
    pub subtitle: Option<String>,
    pub tags: Vec<String>,
    pub created_at_ms: u64,
    pub last_mod_ms: u64,
    pub field_count: u64,
    pub fields: Vec<FieldMetaDto>,
    /// `true` when the record is tombstoned. Only ever `true` in a projection
    /// the caller requested with `include_deleted` (the read gate is Rust's).
    pub tombstoned: bool,
}

impl std::fmt::Debug for RecordDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact the two derived row labels — they hold a decrypted field
        // value. Everything else is metadata this layer already treats as
        // visible. `subtitle` reports presence only, so a `{:?}` still tells
        // you whether the second label was derived.
        f.debug_struct("RecordDto")
            .field("record_uuid_hex", &self.record_uuid_hex)
            .field("record_type", &self.record_type)
            .field("title", &format_args!("<redacted>"))
            .field(
                "subtitle",
                &format_args!(
                    "{}",
                    if self.subtitle.is_some() {
                        "<redacted>"
                    } else {
                        "None"
                    }
                ),
            )
            .field("tags", &self.tags)
            .field("created_at_ms", &self.created_at_ms)
            .field("last_mod_ms", &self.last_mod_ms)
            .field("field_count", &self.field_count)
            .field("fields", &self.fields)
            .field("tombstoned", &self.tombstoned)
            .finish()
    }
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

/// The explicitly-revealed field value. `value` is plaintext for a text field
/// or base64 for a bytes field; `is_text` disambiguates. Produced only by
/// `reveal_field` on explicit reveal; the frontend holds it briefly and
/// drops it on re-mask / navigate / lock (it cannot be zeroized in JS).
///
/// Secret-bearing → redacted `Debug`.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RevealedFieldDto {
    pub is_text: bool,
    pub value: String,
}

impl std::fmt::Debug for RevealedFieldDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RevealedFieldDto")
            .field("is_text", &self.is_text)
            .field("value", &format_args!("<redacted>"))
            .finish()
    }
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
            title: "login".to_string(),
            subtitle: None,
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
        assert_eq!(v["title"], "login");
        assert!(v["subtitle"].is_null());
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

    // ---- redacted Debug (#526 review) ----
    //
    // These two DTOs carry a decrypted field value. `Debug` is hand-rolled so
    // a stray `{:?}` at a tracing site cannot print it; without a test, a
    // future `#[derive(Debug)]` would silently undo that. Asserting on the
    // rendered string is the only way to observe the impl.

    #[test]
    fn record_dto_debug_redacts_the_derived_row_labels() {
        let dto = RecordDto {
            record_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            record_type: "login".to_string(),
            title: "owner@example.test".to_string(),
            subtitle: Some("url: https://admin@router.local".to_string()),
            tags: vec!["work".to_string()],
            created_at_ms: 100,
            last_mod_ms: 200,
            field_count: 2,
            fields: vec![],
            tombstoned: false,
        };
        let rendered = format!("{dto:?}");
        assert!(
            !rendered.contains("owner@example.test"),
            "title plaintext reached Debug: {rendered}"
        );
        assert!(
            !rendered.contains("router.local"),
            "subtitle plaintext reached Debug: {rendered}"
        );
        // Metadata still renders, so the redaction has not cost diagnosability.
        assert!(rendered.contains(SAMPLE_UUID_HEX));
        assert!(rendered.contains("login"));
    }

    #[test]
    fn record_dto_debug_distinguishes_absent_from_redacted_subtitle() {
        let base = RecordDto {
            record_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            record_type: "login".to_string(),
            title: "T".to_string(),
            subtitle: None,
            tags: vec![],
            created_at_ms: 0,
            last_mod_ms: 0,
            field_count: 0,
            fields: vec![],
            tombstoned: false,
        };
        assert!(format!("{base:?}").contains("subtitle: None"));

        let with_subtitle = RecordDto {
            subtitle: Some("name: Ada".to_string()),
            ..base
        };
        let rendered = format!("{with_subtitle:?}");
        assert!(!rendered.contains("Ada"), "{rendered}");
        assert!(rendered.contains("subtitle: <redacted>"), "{rendered}");
    }

    #[test]
    fn revealed_field_dto_debug_redacts_the_value() {
        let dto = RevealedFieldDto {
            is_text: true,
            value: "hunter2".to_string(),
        };
        let rendered = format!("{dto:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("is_text: true"), "{rendered}");
    }

    #[test]
    fn block_detail_dto_debug_inherits_record_redaction() {
        // BlockDetailDto still DERIVES Debug; that is only sound because the
        // RecordDto it nests redacts its own labels. Pin the composition.
        let dto = BlockDetailDto {
            block_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            block_name: "Personal logins".to_string(),
            records: vec![RecordDto {
                record_uuid_hex: SAMPLE_UUID_HEX.to_string(),
                record_type: "login".to_string(),
                title: "owner@example.test".to_string(),
                subtitle: None,
                tags: vec![],
                created_at_ms: 0,
                last_mod_ms: 0,
                field_count: 0,
                fields: vec![],
                tombstoned: false,
            }],
        };
        let rendered = format!("{dto:?}");
        assert!(!rendered.contains("owner@example.test"), "{rendered}");
        assert!(rendered.contains("Personal logins"), "{rendered}");
    }
}
