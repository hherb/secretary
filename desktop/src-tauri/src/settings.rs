//! Settings record schema + parse/serialize. The vault I/O facade
//! (`load_from_vault`, `save_to_vault`) lands in Task 3 along with
//! `VaultSession`.
//!
//! See spec §8 for the full schema rationale (record_type, deterministic
//! UUIDs, lazy creation, validation bounds, version handling).

use crate::constants::{
    AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
    SETTINGS_RECORD_TYPE,
};
use crate::errors::{AppError, AppWarning};

/// Parsed app settings — pure value type with no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
        }
    }
}

/// Result of parsing a settings record from the vault.
///
/// The `Ok((Settings, Vec<AppWarning>))` shape lets parse succeed with
/// non-fatal warnings (e.g. clamped-on-load when an older client wrote
/// a too-small value), which the frontend renders as a banner alongside
/// the manifest.
pub type ParseResult = Result<(Settings, Vec<AppWarning>), AppError>;

/// Parse one field-name / field-value pair into a `Settings`. Returns the
/// parsed settings + any warnings (clamp on out-of-range, unknown version,
/// etc.).
///
/// `record_type` is the record's record_type string. `field_name` is the
/// field's name. `field_value_text` is the field's text value (settings
/// fields are always text per spec §8). Bytes-typed fields are rejected by
/// the caller, before reaching this pure parser.
pub fn parse_settings_field(
    record_type: &str,
    field_name: &str,
    field_value_text: &str,
) -> ParseResult {
    if record_type != SETTINGS_RECORD_TYPE {
        return Err(AppError::SettingsUnknownVersion {
            version: record_type.to_string(),
        });
    }

    if field_name != SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS {
        return Err(AppError::SettingsCorrupt {
            detail: format!("unknown field name: {field_name}"),
        });
    }

    let parsed: u64 = field_value_text
        .parse()
        .map_err(|e| AppError::SettingsCorrupt {
            detail: format!("auto_lock_timeout_ms parse failure: {e}"),
        })?;

    let (final_value, warnings) = clamp_with_warning(parsed);
    Ok((
        Settings {
            auto_lock_timeout_ms: final_value,
        },
        warnings,
    ))
}

/// Apply bounds-clamping + emit a warning if clamped. Used by the load path.
/// The save path uses `validate_save_value` instead — clamping silently on
/// save would mask user intent.
fn clamp_with_warning(value: u64) -> (u64, Vec<AppWarning>) {
    if value < AUTO_LOCK_MIN_MS {
        (
            AUTO_LOCK_MIN_MS,
            vec![AppWarning::SettingsClamped {
                original_ms: value,
                clamped_ms: AUTO_LOCK_MIN_MS,
            }],
        )
    } else if value > AUTO_LOCK_MAX_MS {
        (
            AUTO_LOCK_MAX_MS,
            vec![AppWarning::SettingsClamped {
                original_ms: value,
                clamped_ms: AUTO_LOCK_MAX_MS,
            }],
        )
    } else {
        (value, vec![])
    }
}

/// Validate a settings value before saving (frontend-supplied value path).
/// Rejects out-of-range with `SettingsOutOfRange` rather than clamping —
/// the frontend dialog also validates client-side; this round-trips only
/// on adversarial input.
pub fn validate_save_value(value: u64) -> Result<(), AppError> {
    if (AUTO_LOCK_MIN_MS..=AUTO_LOCK_MAX_MS).contains(&value) {
        Ok(())
    } else {
        Err(AppError::SettingsOutOfRange {
            min: AUTO_LOCK_MIN_MS,
            max: AUTO_LOCK_MAX_MS,
        })
    }
}

/// Serialize a `Settings` into the (record_type, field_name, field_value_text)
/// triple expected by the vault save path. Pure function — the save call
/// itself (which packages this into a `BlockInput` and calls
/// `secretary_ffi_bridge::save_block`) lives in Task 3.
pub fn serialize_settings(s: &Settings) -> (String, String, String) {
    (
        SETTINGS_RECORD_TYPE.to_string(),
        SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
        s.auto_lock_timeout_ms.to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_uses_constant() {
        assert_eq!(
            Settings::default().auto_lock_timeout_ms,
            AUTO_LOCK_DEFAULT_MS
        );
    }

    #[test]
    fn parse_happy_path_no_warnings() {
        let (s, warnings) = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "300000",
        )
        .expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, 300_000);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_below_min_clamps_with_warning() {
        let (s, warnings) = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "30000",
        )
        .expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, AUTO_LOCK_MIN_MS);
        assert_eq!(warnings.len(), 1);
        match &warnings[0] {
            AppWarning::SettingsClamped {
                original_ms,
                clamped_ms,
            } => {
                assert_eq!(*original_ms, 30_000);
                assert_eq!(*clamped_ms, AUTO_LOCK_MIN_MS);
            }
            other => panic!("expected SettingsClamped, got {other:?}"),
        }
    }

    #[test]
    fn parse_above_max_clamps_with_warning() {
        let oversized = AUTO_LOCK_MAX_MS + 1;
        let (s, warnings) = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            &oversized.to_string(),
        )
        .expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, AUTO_LOCK_MAX_MS);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn parse_unknown_version_errors() {
        let err = parse_settings_field(
            "secretary.settings.v99",
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "600000",
        )
        .expect_err("must error");
        match err {
            AppError::SettingsUnknownVersion { version } => {
                assert_eq!(version, "secretary.settings.v99");
            }
            other => panic!("expected SettingsUnknownVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_field_name_errors() {
        let err = parse_settings_field(SETTINGS_RECORD_TYPE, "unknown_field", "x")
            .expect_err("must error");
        match err {
            AppError::SettingsCorrupt { .. } => {}
            other => panic!("expected SettingsCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn parse_non_integer_errors() {
        let err = parse_settings_field(
            SETTINGS_RECORD_TYPE,
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
            "not-a-number",
        )
        .expect_err("must error");
        match err {
            AppError::SettingsCorrupt { .. } => {}
            other => panic!("expected SettingsCorrupt, got {other:?}"),
        }
    }

    #[test]
    fn validate_save_accepts_default() {
        assert!(validate_save_value(AUTO_LOCK_DEFAULT_MS).is_ok());
    }

    #[test]
    fn validate_save_rejects_below_min() {
        let err = validate_save_value(AUTO_LOCK_MIN_MS - 1).expect_err("must error");
        match err {
            AppError::SettingsOutOfRange { min, max } => {
                assert_eq!(min, AUTO_LOCK_MIN_MS);
                assert_eq!(max, AUTO_LOCK_MAX_MS);
            }
            other => panic!("expected SettingsOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn validate_save_rejects_above_max() {
        let err = validate_save_value(AUTO_LOCK_MAX_MS + 1).expect_err("must error");
        match err {
            AppError::SettingsOutOfRange { .. } => {}
            other => panic!("expected SettingsOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn serialize_round_trips_through_parse() {
        let original = Settings {
            auto_lock_timeout_ms: 900_000,
        };
        let (record_type, field_name, field_value) = serialize_settings(&original);
        let (parsed, warnings) =
            parse_settings_field(&record_type, &field_name, &field_value).expect("parse");
        assert_eq!(parsed, original);
        assert!(warnings.is_empty());
    }

    #[test]
    fn validate_save_accepts_min_and_max_inclusive() {
        // The bounds are inclusive — pin that to prevent a sneaky off-by-one
        // refactor that would reject the exact min/max user-picked values.
        assert!(validate_save_value(AUTO_LOCK_MIN_MS).is_ok());
        assert!(validate_save_value(AUTO_LOCK_MAX_MS).is_ok());
    }
}

// ============================================================================
// Vault I/O facade — load + save settings against an unlocked vault
// ============================================================================
//
// These functions sit between `VaultSession` (which owns the unlocked
// identity + manifest handles) and the pure parse/serialize layer above.
// Free functions, not methods on `VaultSession`, so they stay unit-testable
// without spinning up a real session.

use std::path::{Path, PathBuf};

use rand::rngs::OsRng;
use rand::TryRngCore;
use secretary_core::crypto::secret::SecretString;
use secretary_ffi_bridge::{
    read_block, save_block, BlockInput, FieldInput, FieldInputValue, OpenVaultManifest,
    RecordInput, UnlockedIdentity,
};

use crate::auto_lock::now_ms;
use crate::constants::{deterministic_uuid_16, SETTINGS_BLOCK_NAME};
// SETTINGS_RECORD_TYPE is already imported at the top of the file via the
// shared `use crate::constants::{...}` block; reusing the same binding here
// keeps the import surface single-source.

/// Look up the settings block UUID in the manifest by name. Returns `None`
/// if no block matches — the happy path for vaults whose owner never opened
/// the Settings dialog.
///
/// Uses the on-disk `block_uuid` rather than recomputing
/// `deterministic_uuid_16(SETTINGS_BLOCK_NAME)`: the on-disk value is the
/// authoritative one, and a vault created by an older client that minted a
/// random `block_uuid` (pre-spec) keeps working.
fn find_settings_block_uuid(manifest: &OpenVaultManifest) -> Option<[u8; 16]> {
    manifest
        .block_summaries()
        .into_iter()
        .find(|bs| bs.block_name == SETTINGS_BLOCK_NAME)
        .map(|bs| bs.block_uuid)
}

/// Load settings from an unlocked vault. Returns the settings + any non-fatal
/// warnings (clamped on load, unknown version, corrupt record).
///
/// Returns `(Settings::default(), vec![])` if no settings block exists.
pub fn load_from_vault(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
) -> Result<(Settings, Vec<AppWarning>), AppError> {
    let Some(block_uuid) = find_settings_block_uuid(manifest) else {
        return Ok((Settings::default(), Vec::new()));
    };

    let block = read_block(identity, manifest, &block_uuid).map_err(AppError::from)?;

    if block.record_count() != 1 {
        return Ok((
            Settings::default(),
            vec![AppWarning::SettingsCorrupt {
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

    if record.field_count() != 1 {
        return Ok((
            Settings::default(),
            vec![AppWarning::SettingsCorrupt {
                detail: format!(
                    "settings record has {} fields (expected 1)",
                    record.field_count()
                ),
            }],
        ));
    }
    let field = record
        .field_at(0)
        .expect("field_count==1 ⇒ field_at(0) is Some");

    // Both shape-checks fall through to defaults+warning rather than an
    // `AppError` for the same reason `record_count != 1` and
    // `field_count != 1` do: a settings record that's shaped wrong on
    // disk must not block vault access, since the user's only recourse
    // is the Settings dialog itself. Severity is uniform across all four
    // "settings record disagrees with v1 shape" cases.
    if !field.is_text() {
        return Ok((
            Settings::default(),
            vec![AppWarning::SettingsCorrupt {
                detail: format!("settings field '{}' is not text-typed", field.name()),
            }],
        ));
    }
    let Some(field_text) = field.expose_text() else {
        return Ok((
            Settings::default(),
            vec![AppWarning::SettingsCorrupt {
                detail: "settings field text payload missing".to_string(),
            }],
        ));
    };

    // HACK(#141): the bridge's `RecordInput` has no `record_type` field —
    // `save::input::RecordInput::into_core_record` hardcodes
    // `record_type: String::new()`. So records this client wrote arrive back
    // with `record.record_type() == ""`. Until issue #141 lands, treat empty
    // as v1 so the round-trip succeeds; pass the original value through
    // otherwise so a future v2 record from a newer client surfaces
    // `SettingsUnknownVersion` correctly.
    let stored_record_type = record.record_type();
    let effective_record_type = if stored_record_type.is_empty() {
        SETTINGS_RECORD_TYPE
    } else {
        stored_record_type.as_str()
    };

    parse_settings_field(effective_record_type, &field.name(), &field_text)
}

/// Save settings to the vault. Creates the settings block on first call
/// (lazy creation per spec §8); updates it in-place on subsequent calls
/// (the bridge's `save_block` semantics: same `block_uuid` replaces the
/// existing manifest entry).
///
/// Validates bounds via `validate_save_value` before constructing the
/// `BlockInput` — adversarial in-bounds-on-frontend / out-of-bounds-on-IPC
/// inputs are rejected here with `SettingsOutOfRange`. (Clamping is
/// load-side only per spec §8; silently clamping on save would mask user
/// intent.)
pub fn save_to_vault(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    device_uuid: [u8; 16],
    new_settings: &Settings,
) -> Result<(), AppError> {
    validate_save_value(new_settings.auto_lock_timeout_ms)?;

    // Re-use the on-disk block_uuid if a settings block already exists; fall
    // back to the deterministic UUID for first-save. The deterministic value
    // is also what other Secretary clients would mint, so two devices
    // creating the settings block independently produce the same UUID and
    // the CRDT merge layer treats them as concurrent updates of one block.
    let block_uuid = find_settings_block_uuid(manifest)
        .unwrap_or_else(|| deterministic_uuid_16(SETTINGS_BLOCK_NAME));
    let record_uuid = deterministic_uuid_16(SETTINGS_RECORD_TYPE);

    let (_record_type, field_name, field_value_text) = serialize_settings(new_settings);

    // NOTE(#141): see HACK in `load_from_vault` — `RecordInput` doesn't
    // expose a `record_type` field, so the SETTINGS_RECORD_TYPE component
    // of the tuple is discarded here. The matching workaround on load
    // treats the empty `record_type` as v1.
    let block_input = BlockInput {
        block_uuid,
        block_name: SETTINGS_BLOCK_NAME.to_string(),
        records: vec![RecordInput {
            record_uuid,
            fields: vec![FieldInput {
                name: field_name,
                value: FieldInputValue::Text(SecretString::from(field_value_text)),
            }],
        }],
    };

    save_block(identity, manifest, block_input, device_uuid, now_ms()).map_err(AppError::from)?;
    Ok(())
}

// ============================================================================
// Per-vault device UUID — persisted file under the platform data_dir
// ============================================================================

/// Subdirectory under `dirs::data_dir()` that holds one `<vault_uuid_hex>.dev`
/// file per vault. Named after the binary so multiple Secretary installs on
/// the same machine don't collide.
const DEVICE_FILES_SUBDIR: &str = "secretary-desktop/devices";

/// File extension for the per-vault device UUID files. Plain `.dev` so a
/// user inspecting the data directory recognises them as Secretary device
/// fingerprints, not random data.
const DEVICE_FILE_EXTENSION: &str = "dev";

/// Number of bytes in a device UUID file. 16 bytes = 128 bits, matching the
/// vault format's UUID width everywhere else.
const DEVICE_UUID_BYTE_LEN: usize = 16;

/// Resolve the per-vault device UUID file path under `data_dir`. The `_in`
/// suffix marks this as the explicit-dir variant; callers that need the
/// platform-default location use [`load_or_create_device_uuid`] which
/// threads `dirs::data_dir()` for them.
///
/// Pulled out as a free function (not a method on a Paths struct) so tests
/// can inject a `TempDir` rather than polluting the actual user data_dir.
pub fn device_uuid_path_in(data_dir: &Path, vault_uuid: &[u8]) -> PathBuf {
    data_dir.join(DEVICE_FILES_SUBDIR).join(format!(
        "{}.{}",
        hex::encode(vault_uuid),
        DEVICE_FILE_EXTENSION
    ))
}

/// Persistent per-vault device UUID accessor. On first call for a given
/// `vault_uuid`, generates 16 `OsRng` bytes, atomically persists them via
/// `tempfile::NamedTempFile::persist_noclobber`, and returns them. On
/// subsequent calls for the same vault, reads the file back and returns it.
///
/// The vector-clock layer (Sub-project C) needs a stable per-vault device
/// identifier; we cannot derive it from the user identity (a single user
/// across two machines must have two device UUIDs) or from a hardware
/// fingerprint (privacy, plus brittle across OS reinstalls). Random +
/// persisted is the simplest reliable approach.
///
/// Race semantics: two processes opening the same vault concurrently for
/// the first time would each see `path.exists() == false` and each generate
/// their own UUID. `persist_noclobber` makes the rename TOCTOU-free — the
/// race-winner's bytes land on disk; the race-loser's `persist_noclobber`
/// returns `ErrorKind::AlreadyExists`, at which point we re-read the
/// winner's file and return *those* bytes (not the in-memory ones we just
/// generated). Both processes converge on a single device UUID, preserving
/// the vector-clock invariant that one device == one fingerprint.
///
/// The `_in` variant takes an explicit `data_dir` so integration tests can
/// drive a tempdir; production callers use [`load_or_create_device_uuid`].
pub fn load_or_create_device_uuid_in(
    data_dir: &Path,
    vault_uuid: &[u8],
) -> Result<[u8; DEVICE_UUID_BYTE_LEN], AppError> {
    use std::fs;
    use std::io;

    let path = device_uuid_path_in(data_dir, vault_uuid);

    if path.exists() {
        return read_device_uuid_file(&path);
    }

    // First-call path: generate + atomically persist.
    let parent = path.parent().expect("device_uuid path always has a parent");
    fs::create_dir_all(parent).map_err(|e| AppError::Io {
        detail: format!("mkdir -p {}: {}", parent.display(), e),
    })?;

    let mut uuid = [0u8; DEVICE_UUID_BYTE_LEN];
    OsRng.try_fill_bytes(&mut uuid).map_err(|e| AppError::Io {
        detail: format!("OS entropy for device UUID: {e}"),
    })?;

    // `tempfile::NamedTempFile::new_in(parent)` + `persist_noclobber(path)`
    // performs the same `rename(2)` / `MoveFileExW` atomic-rename semantics
    // as `core/src/vault/io.rs::write_atomic`, but refuses to overwrite an
    // existing target. This closes the TOCTOU between the `path.exists()`
    // check above and the rename below: if a parallel process wrote the
    // file in between, `persist_noclobber` returns `AlreadyExists` and we
    // read the persisted bytes instead of stomping them.
    let temp_file = tempfile::NamedTempFile::new_in(parent).map_err(|e| AppError::Io {
        detail: format!("tempfile new_in {}: {}", parent.display(), e),
    })?;
    fs::write(temp_file.path(), uuid).map_err(|e| AppError::Io {
        detail: format!(
            "write {} (tempfile for {}): {}",
            temp_file.path().display(),
            path.display(),
            e
        ),
    })?;
    match temp_file.persist_noclobber(&path) {
        Ok(_) => Ok(uuid),
        Err(persist_err) if persist_err.error.kind() == io::ErrorKind::AlreadyExists => {
            // Race lost: another process persisted first. Read its bytes
            // and discard our own — both sides converge on one UUID.
            read_device_uuid_file(&path)
        }
        Err(persist_err) => Err(AppError::Io {
            detail: format!(
                "atomic persist of device_uuid file {}: {}",
                path.display(),
                persist_err.error
            ),
        }),
    }
}

/// Read a device-UUID file and validate its length. Shared between the
/// fast-path (file already exists) and the race-loser path (concurrent
/// first-unlock) of [`load_or_create_device_uuid_in`].
fn read_device_uuid_file(path: &Path) -> Result<[u8; DEVICE_UUID_BYTE_LEN], AppError> {
    let bytes = std::fs::read(path).map_err(|e| AppError::Io {
        detail: format!("read device_uuid file {}: {}", path.display(), e),
    })?;
    if bytes.len() != DEVICE_UUID_BYTE_LEN {
        return Err(AppError::Io {
            detail: format!(
                "device_uuid file {} has {} bytes (expected {})",
                path.display(),
                bytes.len(),
                DEVICE_UUID_BYTE_LEN,
            ),
        });
    }
    let mut uuid = [0u8; DEVICE_UUID_BYTE_LEN];
    uuid.copy_from_slice(&bytes);
    Ok(uuid)
}

/// Convenience wrapper around [`load_or_create_device_uuid_in`] that uses
/// `dirs::data_dir()` as the parent. Returns `AppError::Io` if the OS has
/// no platform `data_dir` (vanishingly rare on the platforms we ship to;
/// Windows is not a primary target).
pub fn load_or_create_device_uuid(
    vault_uuid: &[u8],
) -> Result<[u8; DEVICE_UUID_BYTE_LEN], AppError> {
    let data_dir = dirs::data_dir().ok_or_else(|| AppError::Io {
        detail: "platform has no data_dir (unsupported environment)".to_string(),
    })?;
    load_or_create_device_uuid_in(&data_dir, vault_uuid)
}

#[cfg(test)]
mod io_tests {
    use super::*;

    /// The path encoder includes the vault_uuid as lowercase hex and uses
    /// the `.dev` extension under the `secretary-desktop/devices/` subdir.
    /// Pinning this prevents an accidental refactor that would orphan
    /// existing on-disk device files.
    #[test]
    fn device_uuid_path_uses_hex_vault_uuid_and_dev_extension() {
        let data_dir = std::path::Path::new("/tmp/secretary-test-data");
        let uuid = [0xAB; 16];
        let path = device_uuid_path_in(data_dir, &uuid);
        let s = path.to_string_lossy();
        assert!(
            s.contains("secretary-desktop/devices"),
            "path {s} must include the secretary-desktop/devices/ subdir",
        );
        assert!(
            s.contains("abababababababababababababababab.dev"),
            "path {s} must use hex(vault_uuid).dev as the filename",
        );
    }

    /// First call generates and persists; second call reads the persisted
    /// bytes. Both calls return the same UUID. Tempdir keeps the test
    /// hermetic — no pollution of the user's real data_dir.
    #[test]
    fn load_or_create_round_trips_for_fresh_vault_uuid() {
        let dir = tempfile::tempdir().expect("tempdir");

        let mut fresh_uuid = [0u8; 16];
        rand::rngs::OsRng
            .try_fill_bytes(&mut fresh_uuid)
            .expect("OS entropy in test");

        let first = load_or_create_device_uuid_in(dir.path(), &fresh_uuid)
            .expect("first call must succeed");
        let second = load_or_create_device_uuid_in(dir.path(), &fresh_uuid)
            .expect("second call must succeed");

        assert_eq!(first, second, "second call must return persisted bytes");
        assert_ne!(first, [0u8; 16], "device UUID must be randomly generated");
        assert!(
            device_uuid_path_in(dir.path(), &fresh_uuid).exists(),
            "first call must have created the persisted file"
        );
    }

    /// A file with the wrong byte length surfaces as `AppError::Io` rather
    /// than truncating or panicking. Defensive check: a partial write or
    /// manual edit could leave the file in this state.
    #[test]
    fn load_or_create_rejects_wrong_length_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_uuid = [0xCD; 16];
        let path = device_uuid_path_in(dir.path(), &vault_uuid);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, b"short").expect("seed wrong-length file");

        let err = load_or_create_device_uuid_in(dir.path(), &vault_uuid)
            .expect_err("must reject wrong-length file");
        match err {
            AppError::Io { detail } => {
                assert!(
                    detail.contains("5 bytes (expected 16)"),
                    "detail must surface the actual+expected lengths: {detail}",
                );
            }
            other => panic!("expected AppError::Io, got {other:?}"),
        }
    }

    /// Two different vault UUIDs get two different files and two different
    /// device UUIDs. Pins the per-vault isolation invariant the vector-clock
    /// layer relies on.
    #[test]
    fn distinct_vault_uuids_yield_distinct_device_uuids() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = load_or_create_device_uuid_in(dir.path(), &[0x01; 16]).expect("vault a");
        let b = load_or_create_device_uuid_in(dir.path(), &[0x02; 16]).expect("vault b");
        assert_ne!(a, b, "different vaults must get different device UUIDs");
    }

    /// Stress the race-loser path: many threads call
    /// `load_or_create_device_uuid_in` concurrently for the same fresh
    /// vault_uuid. Without the `persist_noclobber` guard the race-loser
    /// would persist its own UUID *over* the winner's, and the threads
    /// would diverge on the in-memory return value vs the on-disk bytes.
    /// With the guard, all threads converge on a single UUID — whichever
    /// reached `persist_noclobber` first.
    ///
    /// 16 threads against a fresh tempdir reliably forces multiple racers
    /// to see `path.exists() == false` and contend on the rename. The test
    /// is non-flaky in the sense that the *convergence* assertion holds
    /// regardless of which thread wins; a TOCTOU regression would surface
    /// as divergent returned UUIDs, not a timing-dependent failure.
    #[test]
    fn concurrent_first_unlock_converges_on_single_device_uuid() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = Arc::new(tempfile::tempdir().expect("tempdir"));
        let vault_uuid = [0xEF; 16];
        let thread_count = 16;
        let barrier = Arc::new(Barrier::new(thread_count));

        let handles: Vec<_> = (0..thread_count)
            .map(|_| {
                let dir = Arc::clone(&dir);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    // Synchronise the start so threads actually contend on
                    // the rename rather than serialising via thread spawn.
                    barrier.wait();
                    load_or_create_device_uuid_in(dir.path(), &vault_uuid)
                        .expect("concurrent caller must succeed")
                })
            })
            .collect();

        let results: Vec<_> = handles
            .into_iter()
            .map(|h| h.join().expect("thread panic"))
            .collect();

        let winner = results[0];
        assert_ne!(winner, [0u8; 16], "winner UUID must be RNG-generated");
        for (i, r) in results.iter().enumerate() {
            assert_eq!(
                *r, winner,
                "thread {i} diverged from the on-disk winner — TOCTOU regression: \
                 got {r:?}, expected {winner:?}",
            );
        }

        // Sanity: re-reading the persisted file matches the convergence value.
        let on_disk = load_or_create_device_uuid_in(dir.path(), &vault_uuid)
            .expect("post-race read must succeed");
        assert_eq!(
            on_disk, winner,
            "on-disk bytes must match the value returned to every thread"
        );
    }
}
