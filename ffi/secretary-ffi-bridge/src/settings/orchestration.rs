//! Vault I/O for the settings record: `read_settings` (find-block → read →
//! parse) and `write_settings` (find-or-create block → serialize → save).
//! Composed from the bridge's own `read_block` / `save_block`; no direct core
//! access. Warnings are returned to the (Rust) caller — desktop surfaces them;
//! the FFI wrappers drop them (mobile does not consume them).

use secretary_core::crypto::secret::SecretString;

use super::parse::{parse_settings_fields, serialize_settings, SettingsWarning};
use super::schema::{deterministic_uuid_16, Settings, SETTINGS_BLOCK_NAME, SETTINGS_RECORD_TYPE};
use crate::error::FfiVaultError;
use crate::identity::UnlockedIdentity;
use crate::save::{save_block, BlockInput, FieldInput, FieldInputValue, RecordInput};
use crate::vault::OpenVaultManifest;
use crate::{read_block, BlockReadOutput};

/// Look up the settings block UUID by name. Uses the on-disk `block_uuid`
/// (authoritative — a pre-spec vault that minted a random UUID keeps working).
fn find_settings_block_uuid(manifest: &OpenVaultManifest) -> Option<[u8; 16]> {
    manifest
        .block_summaries()
        .into_iter()
        .find(|bs| bs.block_name == SETTINGS_BLOCK_NAME)
        .map(|bs| bs.block_uuid)
}

/// Read the settings record from an unlocked vault. Returns
/// `(Settings::default(), [])` when no settings block exists (the happy path
/// for a vault whose owner never opened Settings). Lenient on record shape: a
/// non-text or payload-missing field is a warning, not a hard error. Likewise,
/// an unparseable record (unknown version, non-integer/non-bool field text)
/// falls back to `(Settings::default(), [SettingsWarning::Corrupt { .. }])`
/// rather than erroring — a broken settings record must never block vault
/// access.
///
/// # Errors
/// Propagates `read_block`'s errors: `CorruptVault` on a wiped handle,
/// `FolderInvalid` / `SaveCryptoFailure` on read failure.
pub fn read_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(Settings, Vec<SettingsWarning>), FfiVaultError> {
    let Some(block_uuid) = find_settings_block_uuid(manifest) else {
        return Ok((Settings::default(), Vec::new()));
    };

    let block: BlockReadOutput = read_block(identity, manifest, &block_uuid, false)?;

    if block.record_count() != 1 {
        return Ok((
            Settings::default(),
            vec![SettingsWarning::Corrupt {
                detail: format!(
                    "settings block has {} records (expected 1)",
                    block.record_count()
                ),
            }],
        ));
    }
    let record = block
        .record_at(0)
        .expect("record_count==1 ⇒ record_at(0) is Some");

    let mut field_pairs: Vec<(String, String)> = Vec::new();
    let mut shape_warnings: Vec<SettingsWarning> = Vec::new();
    for i in 0..record.field_count() {
        let field = record.field_at(i).expect("i < field_count ⇒ Some");
        if !field.is_text() {
            shape_warnings.push(SettingsWarning::Corrupt {
                detail: format!("settings field '{}' is not text-typed", field.name()),
            });
            continue;
        }
        let Some(text) = field.expose_text() else {
            shape_warnings.push(SettingsWarning::Corrupt {
                detail: "settings field text payload missing".to_string(),
            });
            continue;
        };
        field_pairs.push((field.name(), text));
    }

    // Empty record_type maps to v1 (records written before #141); any other
    // value flows to parse, which surfaces UnknownVersion for a future v2.
    let stored = record.record_type();
    let effective = if stored.is_empty() {
        SETTINGS_RECORD_TYPE.to_string()
    } else {
        stored
    };

    match parse_settings_fields(&effective, &field_pairs) {
        Ok((settings, mut parse_warnings)) => {
            let mut warnings = shape_warnings;
            warnings.append(&mut parse_warnings);
            Ok((settings, warnings))
        }
        // A malformed record must not block vault access: fall back to
        // defaults + a corruption warning (mirrors desktop's lenient load).
        Err(e) => Ok((
            Settings::default(),
            vec![SettingsWarning::Corrupt {
                detail: format!("settings record unparseable: {e:?}"),
            }],
        )),
    }
}

/// Persist the settings record. Creates the settings block on first write
/// (lazy creation; `deterministic_uuid_16(SETTINGS_BLOCK_NAME)` fallback),
/// replaces it in-place on subsequent writes (same `block_uuid`). Serializes
/// **all four** fields, so a partial update never drops a field.
///
/// Bounds are the CALLER's responsibility (uniffi/pyo3 wrappers and desktop
/// call `validate_save_settings` first); an out-of-range value here clamps on
/// next load and is not a security surface.
///
/// # Errors
/// Propagates `save_block`'s errors (`CorruptVault` on a wiped handle,
/// `FolderInvalid` on I/O, `SaveCryptoFailure` on crypto/encoding).
pub fn write_settings(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    settings: &Settings,
    device_uuid: [u8; 16],
    now_ms: u64,
) -> Result<(), FfiVaultError> {
    let block_uuid = find_settings_block_uuid(manifest)
        .unwrap_or_else(|| deterministic_uuid_16(SETTINGS_BLOCK_NAME));
    let record_uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);

    let fields: Vec<FieldInput> = serialize_settings(settings)
        .into_iter()
        .map(|(name, value_text)| FieldInput {
            name,
            value: FieldInputValue::Text(SecretString::from(value_text)),
        })
        .collect();

    let input = BlockInput {
        block_uuid,
        block_name: SETTINGS_BLOCK_NAME.to_string(),
        records: vec![RecordInput {
            record_uuid,
            record_type: SETTINGS_RECORD_TYPE.to_string(),
            tags: Vec::new(),
            fields,
        }],
    };

    save_block(identity, manifest, input, device_uuid, now_ms)
}
