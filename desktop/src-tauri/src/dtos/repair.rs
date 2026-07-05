//! Repair-preview DTOs (#374 Task 9). `preview_repair` returns
//! [`RepairPreviewDto`] — a read-only projection of every consent-eligible
//! recipient widening the bridge's `preview_repair_with_password` found in
//! crash residue. `ApprovedWideningArg` is the inverse: the frontend echoes
//! back exactly the fields it was shown (verbatim, no reformatting) once the
//! user consents, and `commands::repair` decodes it into a
//! `secretary_ffi_bridge::FfiApprovedWidening` for the `repair_vault_with_*`
//! call.
//!
//! Unlike the rest of this module's DTOs (which re-hex `[u8; 16]` /
//! `Vec<u8>` fields via `hex::encode`), every hex field here is the bridge's
//! OWN hex string, passed through unchanged: `block_uuid_hex` / `uuid_hex`
//! are the bridge's lowercase-hyphenated `format_uuid_hyphenated` output
//! (36 chars), NOT the plain 32-hex-char form the rest of this crate's DTOs
//! use (e.g. `BlockSummaryDto::block_uuid_hex`). Reformatting here would risk
//! silently diverging from the exact bytes the user was shown at consent
//! time, since the whole point of the file-fingerprint bind (see
//! `WideningReportDto::file_fingerprint_hex`) is that the approval echoes
//! back precisely what was previewed.

use secretary_ffi_bridge::FfiRepairPreview;

/// One recipient a consent-eligible widening would add, for display in an
/// informed-consent prompt.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AddedRecipientDto {
    /// Lowercase hyphenated UUID of the contact this widening would add —
    /// verbatim from `FfiAddedRecipient::uuid_hex`.
    pub uuid_hex: String,
    /// The contact's verified `display_name`.
    pub display_name: String,
    /// 32 lowercase hex chars — the contact card's identity fingerprint.
    /// NOT the block content fingerprint (see
    /// [`WideningReportDto::file_fingerprint_hex`]).
    pub card_fingerprint_hex: String,
}

/// One block whose crash residue is a consent-eligible recipient widening.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WideningReportDto {
    /// Lowercase hyphenated UUID of the affected block — verbatim from
    /// `FfiWideningReport::block_uuid_hex`.
    pub block_uuid_hex: String,
    /// The block's plaintext name, for display.
    pub block_name: String,
    /// 64 lowercase hex chars — BLAKE3-256 of the on-disk block file bytes
    /// previewed here. An `ApprovedWideningArg` built from this value binds
    /// the eventual `repair_vault` call to exactly these bytes; a file
    /// swapped between preview and repair fails that bind as stale consent.
    pub file_fingerprint_hex: String,
    /// The exact recipients this widening would add, in no particular order.
    pub added: Vec<AddedRecipientDto>,
}

/// The read-only result of `preview_repair`: every consent-eligible
/// recipient widening found in the vault's crash residue. Producing this
/// value writes nothing to disk.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepairPreviewDto {
    /// One entry per affected block.
    pub widenings: Vec<WideningReportDto>,
}

impl From<FfiRepairPreview> for RepairPreviewDto {
    fn from(preview: FfiRepairPreview) -> Self {
        Self {
            widenings: preview
                .widenings
                .into_iter()
                .map(|w| WideningReportDto {
                    block_uuid_hex: w.block_uuid_hex,
                    block_name: w.block_name,
                    file_fingerprint_hex: w.file_fingerprint_hex,
                    added: w
                        .added
                        .into_iter()
                        .map(|a| AddedRecipientDto {
                            uuid_hex: a.uuid_hex,
                            display_name: a.display_name,
                            card_fingerprint_hex: a.card_fingerprint_hex,
                        })
                        .collect(),
                })
                .collect(),
        }
    }
}

/// One user-approved crash-repair recipient widening, deserialized from the
/// frontend's consent decision. `commands::repair` decodes the hex fields
/// (via its local `parse_hyphenated_uuid` / `parse_plain_hex` helpers) into
/// a `secretary_ffi_bridge::FfiApprovedWidening`, folding bad hex/length to
/// `AppError::InvalidArgument` — this DTO carries the wire strings only, no
/// validation.
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovedWideningArg {
    /// Must equal a `WideningReportDto::block_uuid_hex` the user was shown.
    pub block_uuid_hex: String,
    /// Must equal the `WideningReportDto::file_fingerprint_hex` the user
    /// consented to — the stale-consent bind.
    pub file_fingerprint_hex: String,
    /// The exact set of `AddedRecipientDto::uuid_hex` values the user
    /// approved adding.
    pub added_uuids_hex: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use secretary_ffi_bridge::{FfiAddedRecipient, FfiWideningReport};
    use serde_json::Value;

    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("serialize")).expect("parse")
    }

    const SAMPLE_BLOCK_UUID_HEX: &str = "01234567-89ab-cdef-0123-456789abcdef";
    const SAMPLE_RECIPIENT_UUID_HEX: &str = "fedcba98-7654-3210-fedc-ba9876543210";
    const SAMPLE_FILE_FINGERPRINT_HEX: &str =
        "0011223344556677001122334455667700112233445566770011223344556677";
    const SAMPLE_CARD_FINGERPRINT_HEX: &str = "00112233445566778899aabbccddeeff";

    #[test]
    fn added_recipient_dto_camel_case() {
        let dto = AddedRecipientDto {
            uuid_hex: SAMPLE_RECIPIENT_UUID_HEX.to_string(),
            display_name: "Alice".to_string(),
            card_fingerprint_hex: SAMPLE_CARD_FINGERPRINT_HEX.to_string(),
        };
        let v = to_json(&dto);
        assert_eq!(v["uuidHex"], SAMPLE_RECIPIENT_UUID_HEX);
        assert_eq!(v["displayName"], "Alice");
        assert_eq!(v["cardFingerprintHex"], SAMPLE_CARD_FINGERPRINT_HEX);
        assert!(v.get("uuid_hex").is_none());
    }

    #[test]
    fn widening_report_dto_camel_case() {
        let dto = WideningReportDto {
            block_uuid_hex: SAMPLE_BLOCK_UUID_HEX.to_string(),
            block_name: "Banking".to_string(),
            file_fingerprint_hex: SAMPLE_FILE_FINGERPRINT_HEX.to_string(),
            added: vec![],
        };
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_BLOCK_UUID_HEX);
        assert_eq!(v["blockName"], "Banking");
        assert_eq!(v["fileFingerprintHex"], SAMPLE_FILE_FINGERPRINT_HEX);
        assert_eq!(v["added"], serde_json::json!([]));
        assert!(v.get("block_uuid_hex").is_none());
        assert!(v.get("file_fingerprint_hex").is_none());
    }

    #[test]
    fn repair_preview_dto_from_bridge_type_passes_hex_verbatim() {
        let bridge_preview = FfiRepairPreview {
            widenings: vec![FfiWideningReport {
                block_uuid_hex: SAMPLE_BLOCK_UUID_HEX.to_string(),
                block_name: "Banking".to_string(),
                file_fingerprint_hex: SAMPLE_FILE_FINGERPRINT_HEX.to_string(),
                added: vec![FfiAddedRecipient {
                    uuid_hex: SAMPLE_RECIPIENT_UUID_HEX.to_string(),
                    display_name: "Alice".to_string(),
                    card_fingerprint_hex: SAMPLE_CARD_FINGERPRINT_HEX.to_string(),
                }],
            }],
        };
        let dto = RepairPreviewDto::from(bridge_preview);
        assert_eq!(dto.widenings.len(), 1);
        let w = &dto.widenings[0];
        // Every hex field must be byte-for-byte identical to the bridge's
        // own string — no re-encoding, no case change.
        assert_eq!(w.block_uuid_hex, SAMPLE_BLOCK_UUID_HEX);
        assert_eq!(w.file_fingerprint_hex, SAMPLE_FILE_FINGERPRINT_HEX);
        assert_eq!(w.added[0].uuid_hex, SAMPLE_RECIPIENT_UUID_HEX);
        assert_eq!(w.added[0].card_fingerprint_hex, SAMPLE_CARD_FINGERPRINT_HEX);
    }

    #[test]
    fn repair_preview_dto_camel_case_round_trip() {
        let dto = RepairPreviewDto {
            widenings: vec![WideningReportDto {
                block_uuid_hex: SAMPLE_BLOCK_UUID_HEX.to_string(),
                block_name: "Banking".to_string(),
                file_fingerprint_hex: SAMPLE_FILE_FINGERPRINT_HEX.to_string(),
                added: vec![],
            }],
        };
        let v = to_json(&dto);
        assert_eq!(v["widenings"][0]["blockUuidHex"], SAMPLE_BLOCK_UUID_HEX);
    }

    #[test]
    fn approved_widening_arg_deserializes_from_camel_case() {
        let json = format!(
            r#"{{"blockUuidHex":"{SAMPLE_BLOCK_UUID_HEX}","fileFingerprintHex":"{SAMPLE_FILE_FINGERPRINT_HEX}","addedUuidsHex":["{SAMPLE_RECIPIENT_UUID_HEX}"]}}"#
        );
        let arg: ApprovedWideningArg = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(arg.block_uuid_hex, SAMPLE_BLOCK_UUID_HEX);
        assert_eq!(arg.file_fingerprint_hex, SAMPLE_FILE_FINGERPRINT_HEX);
        assert_eq!(
            arg.added_uuids_hex,
            vec![SAMPLE_RECIPIENT_UUID_HEX.to_string()]
        );
    }

    #[test]
    fn approved_widening_arg_rejects_snake_case_payload() {
        let json = format!(
            r#"{{"block_uuid_hex":"{SAMPLE_BLOCK_UUID_HEX}","file_fingerprint_hex":"{SAMPLE_FILE_FINGERPRINT_HEX}","added_uuids_hex":[]}}"#
        );
        let result: Result<ApprovedWideningArg, _> = serde_json::from_str(&json);
        assert!(result.is_err(), "snake_case input must fail to deserialize");
    }
}
