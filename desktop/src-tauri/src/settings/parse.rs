//! Settings record schema + parse/serialize. Pure value-type layer — every
//! input is a `&str`, every output is owned data, no filesystem or vault
//! handles are touched. The vault I/O facade lives in the sibling
//! [`super::io`] module.
//!
//! See spec §8 for the full schema rationale (record_type, deterministic
//! UUIDs, lazy creation, validation bounds, version handling).

use crate::constants::{
    AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS, REAUTH_WINDOW_DEFAULT_MS,
    REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS, REQUIRE_PASSWORD_DEFAULT,
    SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS, SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS,
    SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS, SETTINGS_RECORD_TYPE,
};
use crate::errors::{AppError, AppWarning};

/// Parsed app settings — pure value type, no secret material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    pub auto_lock_timeout_ms: u64,
    pub require_password_before_edits: bool,
    pub reauth_grace_window_ms: u64,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
            require_password_before_edits: REQUIRE_PASSWORD_DEFAULT,
            reauth_grace_window_ms: REAUTH_WINDOW_DEFAULT_MS,
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

/// Parse a settings record's `(field_name, field_value_text)` list into a
/// `Settings`. Unknown record_type → `SettingsUnknownVersion`. Missing known
/// fields fall back to `Settings::default()` values with no warning (forward-
/// compat: an older-client record never wrote the new field). An unknown
/// *extra* field name produces a non-fatal `SettingsCorrupt` warning so that
/// a newer-client write doesn't break this client. Numeric fields clamp-on-
/// load with a `SettingsClamped` warning; the save path rejects out-of-range
/// rather than clamping (see `validate_save_settings`).
pub fn parse_settings_fields(record_type: &str, fields: &[(String, String)]) -> ParseResult {
    if record_type != SETTINGS_RECORD_TYPE {
        return Err(AppError::SettingsUnknownVersion {
            version: record_type.to_string(),
        });
    }

    let mut settings = Settings::default();
    let mut warnings = Vec::new();

    for (name, value) in fields {
        match name.as_str() {
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS => {
                let raw: u64 = value.parse().map_err(|e| AppError::SettingsCorrupt {
                    detail: format!("auto_lock_timeout_ms parse failure: {e}"),
                })?;
                let (v, mut w) = clamp_ms_with_warning(raw, AUTO_LOCK_MIN_MS, AUTO_LOCK_MAX_MS);
                settings.auto_lock_timeout_ms = v;
                warnings.append(&mut w);
            }
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS => {
                let raw: u64 = value.parse().map_err(|e| AppError::SettingsCorrupt {
                    detail: format!("reauth_grace_window_ms parse failure: {e}"),
                })?;
                let (v, mut w) =
                    clamp_ms_with_warning(raw, REAUTH_WINDOW_MIN_MS, REAUTH_WINDOW_MAX_MS);
                settings.reauth_grace_window_ms = v;
                warnings.append(&mut w);
            }
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS => {
                settings.require_password_before_edits =
                    value.parse().map_err(|e| AppError::SettingsCorrupt {
                        detail: format!("require_password_before_edits parse failure: {e}"),
                    })?;
            }
            other => {
                // Forward-compat: a field this build doesn't know about is a
                // warning, not a hard error — a newer client may have written
                // it, and we must still load the fields we DO understand.
                warnings.push(AppWarning::SettingsCorrupt {
                    detail: format!("unknown settings field ignored: {other}"),
                });
            }
        }
    }

    Ok((settings, warnings))
}

/// Clamp a millisecond value into `[min, max]`, emitting a `SettingsClamped`
/// warning when clamped. Load-path only — the save path rejects out-of-range
/// rather than clamping (see `validate_save_settings`).
fn clamp_ms_with_warning(value: u64, min: u64, max: u64) -> (u64, Vec<AppWarning>) {
    if value < min {
        (
            min,
            vec![AppWarning::SettingsClamped {
                original_ms: value,
                clamped_ms: min,
            }],
        )
    } else if value > max {
        (
            max,
            vec![AppWarning::SettingsClamped {
                original_ms: value,
                clamped_ms: max,
            }],
        )
    } else {
        (value, vec![])
    }
}

/// Validate settings before saving (frontend-supplied path). Rejects
/// out-of-range numeric values with `SettingsOutOfRange` rather than clamping
/// — the dialog also validates client-side; this catches adversarial IPC.
pub fn validate_save_settings(s: &Settings) -> Result<(), AppError> {
    if !(AUTO_LOCK_MIN_MS..=AUTO_LOCK_MAX_MS).contains(&s.auto_lock_timeout_ms) {
        return Err(AppError::SettingsOutOfRange {
            min: AUTO_LOCK_MIN_MS,
            max: AUTO_LOCK_MAX_MS,
        });
    }
    if !(REAUTH_WINDOW_MIN_MS..=REAUTH_WINDOW_MAX_MS).contains(&s.reauth_grace_window_ms) {
        return Err(AppError::SettingsOutOfRange {
            min: REAUTH_WINDOW_MIN_MS,
            max: REAUTH_WINDOW_MAX_MS,
        });
    }
    Ok(())
}

/// Serialize a `Settings` into one `(record_type, field_name, field_value_text)`
/// triple per field. All triples share `SETTINGS_RECORD_TYPE` as element 0.
/// The save call (which packages these into a `BlockInput` and calls
/// `secretary_ffi_bridge::save_block`) lives in [`super::io::save_to_vault`].
pub fn serialize_settings(s: &Settings) -> Vec<(String, String, String)> {
    vec![
        (
            SETTINGS_RECORD_TYPE.to_string(),
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            s.auto_lock_timeout_ms.to_string(),
        ),
        (
            SETTINGS_RECORD_TYPE.to_string(),
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS.to_string(),
            s.require_password_before_edits.to_string(),
        ),
        (
            SETTINGS_RECORD_TYPE.to_string(),
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS.to_string(),
            s.reauth_grace_window_ms.to_string(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS, REQUIRE_PASSWORD_DEFAULT,
        SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS, SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS,
        SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS, SETTINGS_RECORD_TYPE,
    };

    // =========================================================================
    // Default / struct shape
    // =========================================================================

    #[test]
    fn default_uses_constant() {
        assert_eq!(
            Settings::default().auto_lock_timeout_ms,
            AUTO_LOCK_DEFAULT_MS
        );
    }

    #[test]
    fn default_includes_reauth_fields() {
        let d = Settings::default();
        assert_eq!(d.require_password_before_edits, REQUIRE_PASSWORD_DEFAULT);
        assert_eq!(d.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
    }

    // =========================================================================
    // parse_settings_fields — happy paths
    // =========================================================================

    #[test]
    fn parse_happy_path_no_warnings() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "300000".to_string(),
        )];
        let (s, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, 300_000);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_all_three_fields_round_trips() {
        let original = Settings {
            auto_lock_timeout_ms: 900_000,
            require_password_before_edits: false,
            reauth_grace_window_ms: 30_000,
        };
        let triples = serialize_settings(&original);
        let fields: Vec<(String, String)> = triples
            .iter()
            .map(|(_, name, value)| (name.clone(), value.clone()))
            .collect();
        let record_type = &triples[0].0;
        let (parsed, warnings) = parse_settings_fields(record_type, &fields).expect("parse");
        assert_eq!(parsed, original);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_missing_new_fields_defaults_them_no_warning() {
        // Older-client record: only the auto-lock field present.
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "600000".to_string(),
        )];
        let (parsed, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(parsed.auto_lock_timeout_ms, 600_000);
        assert_eq!(parsed.require_password_before_edits, REQUIRE_PASSWORD_DEFAULT);
        assert_eq!(parsed.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
        assert!(warnings.is_empty(), "missing-but-defaulted fields are not a warning");
    }

    #[test]
    fn parse_require_password_accepts_bool_text() {
        for (text, expected) in [("true", true), ("false", false)] {
            let fields = vec![
                (SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(), "600000".to_string()),
                (
                    SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS.to_string(),
                    text.to_string(),
                ),
            ];
            let (parsed, _) =
                parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
            assert_eq!(parsed.require_password_before_edits, expected);
        }
    }

    // =========================================================================
    // parse_settings_fields — clamp-on-load
    // =========================================================================

    #[test]
    fn parse_below_min_clamps_with_warning() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "30000".to_string(),
        )];
        let (s, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
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
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            oversized.to_string(),
        )];
        let (s, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, AUTO_LOCK_MAX_MS);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn parse_window_above_max_clamps_with_warning() {
        let fields = vec![
            (SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(), "600000".to_string()),
            (
                SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS.to_string(),
                (REAUTH_WINDOW_MAX_MS + 1).to_string(),
            ),
        ];
        let (parsed, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(parsed.reauth_grace_window_ms, REAUTH_WINDOW_MAX_MS);
        assert_eq!(warnings.len(), 1);
    }

    // =========================================================================
    // parse_settings_fields — error / warning cases
    // =========================================================================

    #[test]
    fn parse_unknown_version_errors() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "600000".to_string(),
        )];
        let err =
            parse_settings_fields("secretary.settings.v99", &fields).expect_err("must error");
        match err {
            AppError::SettingsUnknownVersion { version } => {
                assert_eq!(version, "secretary.settings.v99");
            }
            other => panic!("expected SettingsUnknownVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_extra_field_warns_not_errors() {
        let fields = vec![
            (SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(), "600000".to_string()),
            ("some_future_field".to_string(), "x".to_string()),
        ];
        let (parsed, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields)
            .expect("unknown field must not be a hard error");
        assert_eq!(parsed.auto_lock_timeout_ms, 600_000);
        assert_eq!(warnings.len(), 1);
        matches!(warnings[0], AppWarning::SettingsCorrupt { .. });
    }

    #[test]
    fn parse_non_integer_errors() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "not-a-number".to_string(),
        )];
        let err =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect_err("must error");
        match err {
            AppError::SettingsCorrupt { .. } => {}
            other => panic!("expected SettingsCorrupt, got {other:?}"),
        }
    }

    // =========================================================================
    // validate_save_settings
    // =========================================================================

    #[test]
    fn validate_save_accepts_default() {
        assert!(validate_save_settings(&Settings::default()).is_ok());
    }

    #[test]
    fn validate_save_accepts_min_and_max_inclusive() {
        // The bounds are inclusive — pin that to prevent a sneaky off-by-one
        // refactor that would reject the exact min/max user-picked values.
        let min_settings = Settings {
            auto_lock_timeout_ms: AUTO_LOCK_MIN_MS,
            ..Default::default()
        };
        let max_settings = Settings {
            auto_lock_timeout_ms: AUTO_LOCK_MAX_MS,
            ..Default::default()
        };
        assert!(validate_save_settings(&min_settings).is_ok());
        assert!(validate_save_settings(&max_settings).is_ok());
    }

    #[test]
    fn validate_save_rejects_below_min() {
        let s = Settings {
            auto_lock_timeout_ms: AUTO_LOCK_MIN_MS - 1,
            ..Default::default()
        };
        let err = validate_save_settings(&s).expect_err("must error");
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
        let s = Settings {
            auto_lock_timeout_ms: AUTO_LOCK_MAX_MS + 1,
            ..Default::default()
        };
        let err = validate_save_settings(&s).expect_err("must error");
        match err {
            AppError::SettingsOutOfRange { .. } => {}
            other => panic!("expected SettingsOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn validate_save_rejects_window_above_max() {
        let s = Settings {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
            require_password_before_edits: true,
            reauth_grace_window_ms: REAUTH_WINDOW_MAX_MS + 1,
        };
        let err = validate_save_settings(&s).expect_err("must reject");
        matches!(err, AppError::SettingsOutOfRange { .. });
    }

    // =========================================================================
    // serialize_settings
    // =========================================================================

    #[test]
    fn serialize_round_trips_through_parse() {
        let original = Settings {
            auto_lock_timeout_ms: 900_000,
            require_password_before_edits: false,
            reauth_grace_window_ms: 30_000,
        };
        let triples = serialize_settings(&original);
        // The auto-lock triple is always first.
        assert_eq!(&triples[0].1, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS);
        let fields: Vec<(String, String)> = triples
            .iter()
            .map(|(_, name, value)| (name.clone(), value.clone()))
            .collect();
        let record_type = &triples[0].0;
        let (parsed, warnings) = parse_settings_fields(record_type, &fields).expect("parse");
        assert_eq!(parsed, original);
        assert!(warnings.is_empty());
    }
}
