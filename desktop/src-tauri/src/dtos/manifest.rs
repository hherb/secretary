use secretary_ffi_bridge::vault::{BlockSummary, OpenVaultManifest};

use crate::errors::AppWarning;
use crate::settings::Settings;

/// Plaintext metadata projection of one vault block. All four fields are
/// already plaintext in the encrypted manifest (see [`BlockSummary`] in
/// the bridge crate) — no secret material crosses through this DTO.
///
/// D.1.1 omits `recipient_uuids`: the walking skeleton has no sharing UI
/// and the recipient list is always `[owner]`. The frontend ignores
/// unknown fields, so D.1.2 can add `recipient_uuids_hex` without a wire
/// break.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BlockSummaryDto {
    pub block_uuid_hex: String,
    pub block_name: String,
    pub created_at_ms: u64,
    pub last_modified_ms: u64,
}

impl From<&BlockSummary> for BlockSummaryDto {
    fn from(b: &BlockSummary) -> Self {
        Self {
            block_uuid_hex: hex::encode(b.block_uuid),
            block_name: b.block_name.clone(),
            created_at_ms: b.created_at_ms,
            last_modified_ms: b.last_modified_ms,
        }
    }
}

/// Top-level read projection of an unlocked vault. Returned by
/// `unlock_with_password` and `get_manifest`. The `warnings` vec carries
/// any non-fatal settings-load issues surfaced during unlock — Task 3's
/// `UnlockedSession::pending_warnings` is the source of truth.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestDto {
    pub vault_uuid_hex: String,
    pub owner_user_uuid_hex: String,
    pub block_count: u64,
    pub block_summaries: Vec<BlockSummaryDto>,
    pub warnings: Vec<AppWarning>,
}

impl ManifestDto {
    /// Build the DTO by walking the bridge handle's opaque accessors.
    /// `warnings` is taken as a parameter because the bridge does not
    /// track them; the unlock command threads `UnlockedSession::pending_warnings`
    /// here. Callers that don't need warnings (e.g. `get_manifest`) pass
    /// an empty vec.
    pub fn from_manifest_with_warnings(
        manifest: &OpenVaultManifest,
        warnings: Vec<AppWarning>,
    ) -> Self {
        let summaries = manifest.block_summaries();
        Self {
            vault_uuid_hex: hex::encode(manifest.vault_uuid()),
            owner_user_uuid_hex: hex::encode(manifest.owner_user_uuid()),
            block_count: manifest.block_count(),
            block_summaries: summaries.iter().map(BlockSummaryDto::from).collect(),
            warnings,
        }
    }
}

/// Serializable mirror of [`Settings`]. Identical shape today — the
/// indirection exists so Task 6's TS pin can rename a wire-format field
/// (e.g. for unit suffixes like `auto_lock_timeout_seconds`) without
/// breaking the Rust struct that the rest of the backend uses.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsDto {
    pub auto_lock_timeout_ms: u64,
}

impl From<&Settings> for SettingsDto {
    fn from(s: &Settings) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
        }
    }
}

/// Deserializable input for `set_settings`. Separate type from
/// [`SettingsDto`] because:
/// 1. The Serialize / Deserialize derives have different requirements
///    (Serialize lives on the read DTO; Deserialize lives here so the
///    Tauri command macro can pick it up).
/// 2. Future read-only DTO fields (e.g. computed clamped values, schema
///    version) shouldn't appear in the writable input shape.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsInput {
    pub auto_lock_timeout_ms: u64,
}

impl From<&SettingsInput> for Settings {
    fn from(s: &SettingsInput) -> Self {
        Self {
            auto_lock_timeout_ms: s.auto_lock_timeout_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    //! DTO wire-format tests. Pin every field name + casing + type so a
    //! frontend break surfaces at Rust compile / test time rather than at
    //! Svelte runtime. Task 6's TS discriminated union will mirror these
    //! shapes; mismatches here are mismatches there.

    use super::*;
    use serde_json::Value;

    /// Sample SHA-256-derived 16-byte UUID. Hex value chosen so each byte
    /// pair is distinct — catches off-by-one slicing bugs in `hex::encode`
    /// that a `[0u8; 16]` literal would mask.
    const SAMPLE_UUID_HEX: &str = "00112233445566778899aabbccddeeff";
    const SAMPLE_UUID_BYTES: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn to_json_value<T: serde::Serialize>(value: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(value).expect("serialize"))
            .expect("re-parse as Value")
    }

    #[test]
    fn block_summary_dto_serializes_as_camel_case_with_hex_uuid() {
        let dto = BlockSummaryDto {
            block_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            block_name: "Banking".to_string(),
            created_at_ms: 1_700_000_000_000,
            last_modified_ms: 1_700_086_400_000,
        };
        let v = to_json_value(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["blockName"], "Banking");
        assert_eq!(v["createdAtMs"], 1_700_000_000_000_u64);
        assert_eq!(v["lastModifiedMs"], 1_700_086_400_000_u64);
        // Snake-case names must NOT leak through.
        assert!(v.get("block_uuid_hex").is_none());
        assert!(v.get("block_name").is_none());
    }

    #[test]
    fn block_summary_from_bridge_round_trips_uuid_bytes_to_hex() {
        let summary = BlockSummary {
            block_uuid: SAMPLE_UUID_BYTES,
            block_name: "Personal".to_string(),
            created_at_ms: 100,
            last_modified_ms: 200,
            recipient_uuids: vec![SAMPLE_UUID_BYTES],
        };
        let dto = BlockSummaryDto::from(&summary);
        assert_eq!(dto.block_uuid_hex, SAMPLE_UUID_HEX);
        assert_eq!(dto.block_name, "Personal");
        assert_eq!(dto.created_at_ms, 100);
        assert_eq!(dto.last_modified_ms, 200);
        // recipient_uuids is intentionally NOT projected for D.1.1.
    }

    #[test]
    fn settings_dto_serializes_as_camel_case() {
        let dto = SettingsDto::from(&Settings {
            auto_lock_timeout_ms: 600_000,
        });
        let v = to_json_value(&dto);
        assert_eq!(v["autoLockTimeoutMs"], 600_000_u64);
        assert!(v.get("auto_lock_timeout_ms").is_none());
    }

    #[test]
    fn settings_input_deserializes_from_camel_case() {
        let input: SettingsInput =
            serde_json::from_str(r#"{"autoLockTimeoutMs":900000}"#).expect("deserialize");
        assert_eq!(input.auto_lock_timeout_ms, 900_000);

        let settings = Settings::from(&input);
        assert_eq!(settings.auto_lock_timeout_ms, 900_000);
    }

    #[test]
    fn settings_input_rejects_snake_case_payload() {
        // Lock down that the TS frontend MUST send camelCase — a serde
        // round-trip from snake_case must fail so a Task 6 TS-pin
        // regression surfaces immediately at the boundary rather than
        // silently overwriting the field with the type's default.
        let result: Result<SettingsInput, _> =
            serde_json::from_str(r#"{"auto_lock_timeout_ms":900000}"#);
        assert!(
            result.is_err(),
            "snake_case input must fail to deserialize (got Ok)"
        );
    }

    #[test]
    fn manifest_dto_empty_warnings_round_trip() {
        // Construct a ManifestDto directly (the bridge handle path is
        // covered by the integration tests against the golden vault).
        let dto = ManifestDto {
            vault_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            owner_user_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            block_count: 0,
            block_summaries: vec![],
            warnings: vec![],
        };
        let v = to_json_value(&dto);
        assert_eq!(v["vaultUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["ownerUserUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["blockCount"], 0);
        assert_eq!(v["blockSummaries"], serde_json::json!([]));
        assert_eq!(v["warnings"], serde_json::json!([]));
    }

    #[test]
    fn manifest_dto_passes_warnings_through() {
        let dto = ManifestDto {
            vault_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            owner_user_uuid_hex: SAMPLE_UUID_HEX.to_string(),
            block_count: 0,
            block_summaries: vec![],
            warnings: vec![AppWarning::SettingsClamped {
                original_ms: 30_000,
                clamped_ms: 60_000,
            }],
        };
        let v = to_json_value(&dto);
        // AppWarning is `#[serde(tag = "code", rename_all = "snake_case")]`,
        // so the inner shape stays snake_case — its on-wire schema was pinned
        // by `errors::tests::settings_clamped_warning_carries_both_values`.
        assert_eq!(v["warnings"][0]["code"], "settings_clamped");
        assert_eq!(v["warnings"][0]["original_ms"], 30_000_u64);
        assert_eq!(v["warnings"][0]["clamped_ms"], 60_000_u64);
    }
}
