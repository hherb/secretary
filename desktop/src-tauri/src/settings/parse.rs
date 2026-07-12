//! Settings record schema + parse/serialize adapter over the shared
//! [`secretary_ffi_bridge::settings`] module. The pure schema, bounds, and
//! (de)serialization logic itself lives in the bridge crate (Task 1/2 of the
//! mobile-vault-settings epic) so desktop and mobile share one Rust
//! definition of the on-disk settings schema; this module's job is solely
//! to map the bridge's crate-native `SettingsWarning` / `SettingsParseError`
//! / `SettingsBoundsError` types onto the desktop `AppError` / `AppWarning`
//! IPC wire-types. The vault I/O facade lives in the sibling [`super::io`]
//! module.
//!
//! See spec §8 for the full schema rationale (record_type, deterministic
//! UUIDs, lazy creation, validation bounds, version handling).

use secretary_ffi_bridge::{
    parse_settings_fields as bridge_parse, validate_save_settings as bridge_validate,
    SettingsBoundsError, SettingsParseError, SettingsWarning,
};
pub use secretary_ffi_bridge::{serialize_settings, Settings};

use crate::errors::{AppError, AppWarning};

/// Result of parsing a settings record from the vault.
///
/// The `Ok((Settings, Vec<AppWarning>))` shape lets parse succeed with
/// non-fatal warnings (e.g. clamped-on-load when an older client wrote
/// a too-small value), which the frontend renders as a banner alongside
/// the manifest.
pub type ParseResult = Result<(Settings, Vec<AppWarning>), AppError>;

/// Map a bridge load warning to the desktop IPC warning wire-type. `pub(crate)`
/// so [`super::io`] can reuse it for [`secretary_ffi_bridge::read_settings`]'s
/// warnings without duplicating the match.
pub(crate) fn map_warning(w: SettingsWarning) -> AppWarning {
    match w {
        SettingsWarning::Clamped {
            original_ms,
            clamped_ms,
        } => AppWarning::SettingsClamped {
            original_ms,
            clamped_ms,
        },
        SettingsWarning::Corrupt { detail } => AppWarning::SettingsCorrupt { detail },
    }
}

/// Parse a settings record's `(field_name, field_value_text)` list into a
/// `Settings`, delegating the pure logic to the shared bridge and mapping its
/// warnings/errors onto the desktop IPC wire-types. Unknown record_type →
/// `SettingsUnknownVersion`. Missing known fields fall back to
/// `Settings::default()` values with no warning (forward-compat: an
/// older-client record never wrote the new field). An unknown *extra* field
/// name produces a non-fatal `SettingsCorrupt` warning so that a newer-client
/// write doesn't break this client. Numeric fields clamp-on-load with a
/// `SettingsClamped` warning; the save path rejects out-of-range rather than
/// clamping (see `validate_save_settings`).
///
/// This adapter maps the bridge parser's errors/warnings onto `AppError` /
/// `AppWarning` for callers that already have a decoded `(name, value)` field
/// list. The live vault-load path does not call this directly — it goes
/// through `secretary_ffi_bridge::read_settings`, which is lenient: a
/// malformed settings record yields `(Settings::default(), [warning])`
/// rather than an `AppError`, so a broken record never blocks vault access.
pub fn parse_settings_fields(record_type: &str, fields: &[(String, String)]) -> ParseResult {
    match bridge_parse(record_type, fields) {
        Ok((settings, warnings)) => Ok((settings, warnings.into_iter().map(map_warning).collect())),
        Err(SettingsParseError::UnknownVersion { version }) => {
            Err(AppError::SettingsUnknownVersion { version })
        }
        Err(SettingsParseError::Corrupt { detail }) => Err(AppError::SettingsCorrupt { detail }),
    }
}

/// Validate settings before saving (frontend-supplied path), delegating to
/// the shared bridge and mapping its bounds error onto the desktop IPC
/// wire-type. Rejects out-of-range numeric values with `SettingsOutOfRange`
/// rather than clamping — the dialog also validates client-side; this
/// catches adversarial IPC.
pub fn validate_save_settings(s: &Settings) -> Result<(), AppError> {
    bridge_validate(s)
        .map_err(|SettingsBoundsError { min, max }| AppError::SettingsOutOfRange { min, max })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{
        REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS, REQUIRE_PASSWORD_DEFAULT,
        RETENTION_WINDOW_MIN_MS, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
        SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS, SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
        SETTINGS_FIELD_RETENTION_WINDOW_MS, SETTINGS_RECORD_TYPE,
    };

    // =========================================================================
    // Default / struct shape
    // =========================================================================

    #[test]
    fn default_uses_constant() {
        assert_eq!(
            Settings::default().auto_lock_timeout_ms,
            crate::constants::AUTO_LOCK_DEFAULT_MS
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
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, 300_000);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_all_three_fields_round_trips() {
        let original = Settings {
            auto_lock_timeout_ms: 900_000,
            require_password_before_edits: false,
            reauth_grace_window_ms: 30_000,
            ..Settings::default()
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
        assert_eq!(
            parsed.require_password_before_edits,
            REQUIRE_PASSWORD_DEFAULT
        );
        assert_eq!(parsed.reauth_grace_window_ms, REAUTH_WINDOW_DEFAULT_MS);
        assert!(
            warnings.is_empty(),
            "missing-but-defaulted fields are not a warning"
        );
    }

    #[test]
    fn parse_require_password_accepts_bool_text() {
        for (text, expected) in [("true", true), ("false", false)] {
            let fields = vec![
                (
                    SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
                    "600000".to_string(),
                ),
                (
                    SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS.to_string(),
                    text.to_string(),
                ),
            ];
            let (parsed, _) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
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
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, crate::constants::AUTO_LOCK_MIN_MS);
        assert_eq!(warnings.len(), 1);
        match &warnings[0] {
            AppWarning::SettingsClamped {
                original_ms,
                clamped_ms,
            } => {
                assert_eq!(*original_ms, 30_000);
                assert_eq!(*clamped_ms, crate::constants::AUTO_LOCK_MIN_MS);
            }
            other => panic!("expected SettingsClamped, got {other:?}"),
        }
    }

    #[test]
    fn parse_above_max_clamps_with_warning() {
        let oversized = crate::constants::AUTO_LOCK_MAX_MS + 1;
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            oversized.to_string(),
        )];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, crate::constants::AUTO_LOCK_MAX_MS);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn parse_window_above_max_clamps_with_warning() {
        let fields = vec![
            (
                SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
                "600000".to_string(),
            ),
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
        let err = parse_settings_fields("secretary.settings.v99", &fields).expect_err("must error");
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
            (
                SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
                "600000".to_string(),
            ),
            ("some_future_field".to_string(), "x".to_string()),
        ];
        let (parsed, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields)
            .expect("unknown field must not be a hard error");
        assert_eq!(parsed.auto_lock_timeout_ms, 600_000);
        assert_eq!(warnings.len(), 1);
        assert!(matches!(warnings[0], AppWarning::SettingsCorrupt { .. }));
    }

    #[test]
    fn parse_non_integer_errors() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "not-a-number".to_string(),
        )];
        let err = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect_err("must error");
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
            auto_lock_timeout_ms: crate::constants::AUTO_LOCK_MIN_MS,
            ..Default::default()
        };
        let max_settings = Settings {
            auto_lock_timeout_ms: crate::constants::AUTO_LOCK_MAX_MS,
            ..Default::default()
        };
        assert!(validate_save_settings(&min_settings).is_ok());
        assert!(validate_save_settings(&max_settings).is_ok());
    }

    #[test]
    fn validate_save_rejects_below_min() {
        let s = Settings {
            auto_lock_timeout_ms: crate::constants::AUTO_LOCK_MIN_MS - 1,
            ..Default::default()
        };
        let err = validate_save_settings(&s).expect_err("must error");
        match err {
            AppError::SettingsOutOfRange { min, max } => {
                assert_eq!(min, crate::constants::AUTO_LOCK_MIN_MS);
                assert_eq!(max, crate::constants::AUTO_LOCK_MAX_MS);
            }
            other => panic!("expected SettingsOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn validate_save_rejects_above_max() {
        let s = Settings {
            auto_lock_timeout_ms: crate::constants::AUTO_LOCK_MAX_MS + 1,
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
            auto_lock_timeout_ms: crate::constants::AUTO_LOCK_DEFAULT_MS,
            require_password_before_edits: true,
            reauth_grace_window_ms: REAUTH_WINDOW_MAX_MS + 1,
            ..Settings::default()
        };
        let err = validate_save_settings(&s).expect_err("must reject");
        assert!(matches!(err, AppError::SettingsOutOfRange { .. }));
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
            ..Settings::default()
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

    // =========================================================================
    // retention_window_ms
    // =========================================================================

    #[test]
    fn default_includes_retention_window() {
        assert_eq!(
            Settings::default().retention_window_ms,
            crate::constants::RETENTION_WINDOW_DEFAULT_MS
        );
    }

    #[test]
    fn parse_retention_window_field() {
        let fields = vec![(
            SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(),
            (30 * crate::constants::MS_PER_DAY).to_string(),
        )];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.retention_window_ms, 30 * crate::constants::MS_PER_DAY);
        assert!(warnings.is_empty());
    }

    #[test]
    fn parse_retention_window_clamps_below_min() {
        let fields = vec![(
            SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(),
            "1000".to_string(),
        )];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.retention_window_ms, RETENTION_WINDOW_MIN_MS);
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn validate_save_rejects_out_of_range_retention() {
        let s = Settings {
            retention_window_ms: 999,
            ..Settings::default()
        };
        assert!(matches!(
            validate_save_settings(&s),
            Err(AppError::SettingsOutOfRange { .. })
        ));
    }

    #[test]
    fn serialize_round_trips_retention_window() {
        let s = Settings {
            retention_window_ms: 45 * crate::constants::MS_PER_DAY,
            ..Settings::default()
        };
        let triples = serialize_settings(&s);
        assert!(triples
            .iter()
            .any(|(_, name, val)| name == SETTINGS_FIELD_RETENTION_WINDOW_MS
                && val == &(45 * crate::constants::MS_PER_DAY).to_string()));
    }
}
