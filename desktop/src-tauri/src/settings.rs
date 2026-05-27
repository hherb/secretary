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
