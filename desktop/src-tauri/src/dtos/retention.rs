//! Retention/purge read DTOs. Project the bridge's retention + purge report
//! types onto camelCase wire shapes: `block_uuid: [u8;16]` is hex-encoded
//! (parity with `TrashedBlockDto`); `u32` counts serialize as JSON numbers.
//! None of these fields is secret material.

use secretary_ffi_bridge::{EmptyTrashReport, ExpiredEntry, PurgeReport, RetentionPurgeReport};

/// One trashed block that is past the retention window (preview only).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpiredEntryDto {
    pub block_uuid_hex: String,
    pub tombstoned_at_ms: u64,
    pub age_ms: u64,
}

impl From<&ExpiredEntry> for ExpiredEntryDto {
    fn from(e: &ExpiredEntry) -> Self {
        Self {
            block_uuid_hex: hex::encode(e.block_uuid),
            tombstoned_at_ms: e.tombstoned_at_ms,
            age_ms: e.age_ms,
        }
    }
}

/// Preview payload: the expired entries plus the window they were computed
/// against (so the UI shows "> N days" consistently with the commit).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionPreviewDto {
    pub entries: Vec<ExpiredEntryDto>,
    pub window_ms: u64,
}

impl RetentionPreviewDto {
    pub fn from_entries(entries: Vec<ExpiredEntry>, window_ms: u64) -> Self {
        Self {
            entries: entries.iter().map(ExpiredEntryDto::from).collect(),
            window_ms,
        }
    }
}

/// Report from a committed retention purge.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionReportDto {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
    pub window_ms: u64,
}

impl From<&RetentionPurgeReport> for RetentionReportDto {
    fn from(r: &RetentionPurgeReport) -> Self {
        Self {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
            window_ms: r.window_ms,
        }
    }
}

/// Report from an `empty_trash` batch purge. Aggregate counts only —
/// no per-block UUID, no window, no plaintext (parity with the security
/// contract of `RetentionReportDto`; nothing secret is projected).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EmptyTrashReportDto {
    pub purged_count: u32,
    pub shared_count: u32,
    pub owner_only_count: u32,
    pub unknown_count: u32,
    pub files_removed: u32,
    pub files_failed: u32,
}

impl From<&EmptyTrashReport> for EmptyTrashReportDto {
    fn from(r: &EmptyTrashReport) -> Self {
        Self {
            purged_count: r.purged_count,
            shared_count: r.shared_count,
            owner_only_count: r.owner_only_count,
            unknown_count: r.unknown_count,
            files_removed: r.files_removed,
            files_failed: r.files_failed,
        }
    }
}

/// Report from a single per-block purge.
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PurgeReportDto {
    pub block_uuid_hex: String,
    pub was_shared: Option<bool>,
    pub recipient_count: Option<u16>,
    pub files_removed: u32,
}

impl From<&PurgeReport> for PurgeReportDto {
    fn from(r: &PurgeReport) -> Self {
        Self {
            block_uuid_hex: hex::encode(r.block_uuid),
            was_shared: r.was_shared,
            recipient_count: r.recipient_count,
            files_removed: r.files_removed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const SAMPLE_UUID_HEX: &str = "00112233445566778899aabbccddeeff";
    const SAMPLE_UUID_BYTES: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];

    fn to_json<T: serde::Serialize>(v: &T) -> Value {
        serde_json::from_str(&serde_json::to_string(v).expect("serialize")).expect("parse")
    }

    #[test]
    fn expired_entry_dto_hex_and_camel_case() {
        let dto = ExpiredEntryDto::from(&secretary_ffi_bridge::ExpiredEntry {
            block_uuid: SAMPLE_UUID_BYTES,
            tombstoned_at_ms: 1_700_000_000_000,
            age_ms: 99,
        });
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["tombstonedAtMs"], 1_700_000_000_000_u64);
        assert_eq!(v["ageMs"], 99);
        assert!(v.get("block_uuid").is_none());
    }

    #[test]
    fn retention_preview_dto_carries_window_and_entries() {
        let preview = RetentionPreviewDto::from_entries(
            vec![secretary_ffi_bridge::ExpiredEntry {
                block_uuid: SAMPLE_UUID_BYTES,
                tombstoned_at_ms: 1,
                age_ms: 2,
            }],
            7_776_000_000,
        );
        let v = to_json(&preview);
        assert_eq!(v["windowMs"], 7_776_000_000_u64);
        assert_eq!(v["entries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn retention_report_dto_camel_case() {
        let dto = RetentionReportDto::from(&secretary_ffi_bridge::RetentionPurgeReport {
            purged_count: 3,
            shared_count: 1,
            owner_only_count: 2,
            unknown_count: 0,
            files_removed: 3,
            files_failed: 0,
            window_ms: 7_776_000_000,
        });
        let v = to_json(&dto);
        assert_eq!(v["purgedCount"], 3);
        assert_eq!(v["filesFailed"], 0);
        assert_eq!(v["windowMs"], 7_776_000_000_u64);
    }

    #[test]
    fn empty_trash_report_dto_camel_case() {
        let dto = EmptyTrashReportDto::from(&secretary_ffi_bridge::EmptyTrashReport {
            purged_count: 4,
            shared_count: 1,
            owner_only_count: 3,
            unknown_count: 0,
            files_removed: 4,
            files_failed: 0,
        });
        let v = to_json(&dto);
        assert_eq!(v["purgedCount"], 4);
        assert_eq!(v["sharedCount"], 1);
        assert_eq!(v["ownerOnlyCount"], 3);
        assert_eq!(v["unknownCount"], 0);
        assert_eq!(v["filesRemoved"], 4);
        assert_eq!(v["filesFailed"], 0);
        // No snake_case / UUID / window leakage.
        assert!(v.get("purged_count").is_none());
        assert!(v.get("blockUuidHex").is_none());
        assert!(v.get("windowMs").is_none());
    }

    #[test]
    fn purge_report_dto_camel_case() {
        let dto = PurgeReportDto::from(&secretary_ffi_bridge::PurgeReport {
            block_uuid: SAMPLE_UUID_BYTES,
            was_shared: Some(true),
            recipient_count: Some(2),
            files_removed: 1,
        });
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert_eq!(v["wasShared"], true);
        assert_eq!(v["recipientCount"], 2);
        assert_eq!(v["filesRemoved"], 1);
    }

    #[test]
    fn purge_report_dto_none_serializes_to_null() {
        let dto = PurgeReportDto::from(&secretary_ffi_bridge::PurgeReport {
            block_uuid: SAMPLE_UUID_BYTES,
            was_shared: None,
            recipient_count: None,
            files_removed: 5,
        });
        let v = to_json(&dto);
        assert_eq!(v["blockUuidHex"], SAMPLE_UUID_HEX);
        assert!(v["wasShared"].is_null());
        assert!(v["recipientCount"].is_null());
        assert_eq!(v["filesRemoved"], 5);
    }
}
