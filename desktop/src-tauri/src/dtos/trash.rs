//! D.1.5 trash-path DTO. `TrashedBlockDto` carries the decrypted block name
//! (a secret-boundary value) for the restore UI, plus the record-level death
//! clock fields. The `Debug` impl is hand-written to redact `block_name` —
//! parity with the secret-boundary discipline applied across the DTO layer.

/// Read projection of one tombstoned block surfaced to the restore UI. The
/// `block_name` is decrypted plaintext; `Debug` redacts it.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrashedBlockDto {
    pub block_uuid_hex: String,
    pub block_name: String,
    pub tombstoned_at_ms: u64,
    pub tombstoned_by_hex: String,
}

impl std::fmt::Debug for TrashedBlockDto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrashedBlockDto")
            .field("block_uuid_hex", &self.block_uuid_hex)
            .field("block_name", &"<redacted>")
            .field("tombstoned_at_ms", &self.tombstoned_at_ms)
            .field("tombstoned_by_hex", &self.tombstoned_by_hex)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SAMPLE_UUID_HEX: &str = "00112233445566778899aabbccddeeff";
    const SAMPLE_BY_HEX: &str = "ffeeddccbbaa99887766554433221100";

    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("serialize")).expect("parse")
    }

    #[test]
    fn trashed_block_dto_camel_case() {
        let dto = TrashedBlockDto {
            block_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            block_name: "Old logins".to_string(),
            tombstoned_at_ms: 1_700_000_000_000,
            tombstoned_by_hex: SAMPLE_BY_HEX.to_string(),
        };
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["blockName"], "Old logins");
        assert_eq!(v["tombstonedAtMs"], 1_700_000_000_000_u64);
        assert_eq!(v["tombstonedByHex"], SAMPLE_BY_HEX);
        // snake_case keys must not leak.
        assert!(v.get("block_uuid_hex").is_none());
        assert!(v.get("tombstoned_at_ms").is_none());
    }

    #[test]
    fn trashed_block_dto_debug_redacts_name() {
        let dto = TrashedBlockDto {
            block_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            block_name: "TopSecretName".to_string(),
            tombstoned_at_ms: 1_700_000_000_000,
            tombstoned_by_hex: SAMPLE_BY_HEX.to_string(),
        };
        let dbg = format!("{dto:?}");
        assert!(!dbg.contains("TopSecretName"), "name must be redacted");
        assert!(dbg.contains("redacted"), "redaction marker must be present");
        // Non-secret fields remain visible.
        assert!(dbg.contains(SAMPLE_UUID_HEX));
        assert!(dbg.contains(SAMPLE_BY_HEX));
    }
}
