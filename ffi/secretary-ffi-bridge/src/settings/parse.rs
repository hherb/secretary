//! Pure settings schema parse/serialize/validate. Every input is a `&str`,
//! every output is owned data — no filesystem, no vault handles. Lifted from
//! `desktop/src-tauri/src/settings/parse.rs`; the desktop-specific
//! `AppError`/`AppWarning` were replaced by the bridge-native types below.

use super::schema::{
    Settings, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS, REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS,
    RETENTION_WINDOW_MAX_MS, RETENTION_WINDOW_MIN_MS, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
    SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS, SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
    SETTINGS_FIELD_RETENTION_WINDOW_MS, SETTINGS_RECORD_TYPE,
};

/// A non-fatal condition surfaced while loading a settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsWarning {
    /// A numeric value out of bounds on load was clamped into range.
    Clamped {
        /// The out-of-range value as read from the record.
        original_ms: u64,
        /// The bound the value was clamped to.
        clamped_ms: u64,
    },
    /// A field was malformed / unknown / wrong-shaped and skipped.
    Corrupt {
        /// Human-readable detail about what was wrong with the field.
        detail: String,
    },
}

/// A fatal condition parsing a settings record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsParseError {
    /// `record_type` is not `secretary.settings.v1`.
    UnknownVersion {
        /// The unrecognized `record_type` value.
        version: String,
    },
    /// A known field failed to parse (integer or boolean).
    Corrupt {
        /// Human-readable detail about the parse failure.
        detail: String,
    },
}

/// Bounds violation from `validate_save_settings` (the save path rejects
/// out-of-range rather than clamping).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SettingsBoundsError {
    /// Lower bound of the violated field, inclusive.
    pub min: u64,
    /// Upper bound of the violated field, inclusive.
    pub max: u64,
}

/// Parse a settings record's `(field_name, field_value_text)` list into a
/// `Settings`. Unknown record_type → `UnknownVersion`. Missing known
/// fields fall back to `Settings::default()` values with no warning (forward-
/// compat: an older-client record never wrote the new field). An unknown
/// *extra* field name produces a non-fatal `Corrupt` warning so that
/// a newer-client write doesn't break this client. Numeric fields clamp-on-
/// load with a `Clamped` warning; the save path rejects out-of-range
/// rather than clamping (see `validate_save_settings`).
pub fn parse_settings_fields(
    record_type: &str,
    fields: &[(String, String)],
) -> Result<(Settings, Vec<SettingsWarning>), SettingsParseError> {
    if record_type != SETTINGS_RECORD_TYPE {
        return Err(SettingsParseError::UnknownVersion {
            version: record_type.to_string(),
        });
    }

    let mut settings = Settings::default();
    let mut warnings = Vec::new();

    for (name, value) in fields {
        match name.as_str() {
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS => {
                let raw: u64 = value.parse().map_err(|e| SettingsParseError::Corrupt {
                    detail: format!("auto_lock_timeout_ms parse failure: {e}"),
                })?;
                let (v, mut w) = clamp_ms_with_warning(raw, AUTO_LOCK_MIN_MS, AUTO_LOCK_MAX_MS);
                settings.auto_lock_timeout_ms = v;
                warnings.append(&mut w);
            }
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS => {
                let raw: u64 = value.parse().map_err(|e| SettingsParseError::Corrupt {
                    detail: format!("reauth_grace_window_ms parse failure: {e}"),
                })?;
                let (v, mut w) =
                    clamp_ms_with_warning(raw, REAUTH_WINDOW_MIN_MS, REAUTH_WINDOW_MAX_MS);
                settings.reauth_grace_window_ms = v;
                warnings.append(&mut w);
            }
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS => {
                settings.require_password_before_edits =
                    value.parse().map_err(|e| SettingsParseError::Corrupt {
                        detail: format!("require_password_before_edits parse failure: {e}"),
                    })?;
            }
            SETTINGS_FIELD_RETENTION_WINDOW_MS => {
                let raw: u64 = value.parse().map_err(|e| SettingsParseError::Corrupt {
                    detail: format!("retention_window_ms parse failure: {e}"),
                })?;
                let (v, mut w) =
                    clamp_ms_with_warning(raw, RETENTION_WINDOW_MIN_MS, RETENTION_WINDOW_MAX_MS);
                settings.retention_window_ms = v;
                warnings.append(&mut w);
            }
            other => {
                // Forward-compat: a field this build doesn't know about is a
                // warning, not a hard error — a newer client may have written
                // it, and we must still load the fields we DO understand.
                warnings.push(SettingsWarning::Corrupt {
                    detail: format!("unknown settings field ignored: {other}"),
                });
            }
        }
    }

    Ok((settings, warnings))
}

/// Clamp a millisecond value into `[min, max]`, emitting a `Clamped`
/// warning when clamped. Load-path only — the save path rejects out-of-range
/// rather than clamping (see `validate_save_settings`).
fn clamp_ms_with_warning(value: u64, min: u64, max: u64) -> (u64, Vec<SettingsWarning>) {
    if value < min {
        (
            min,
            vec![SettingsWarning::Clamped {
                original_ms: value,
                clamped_ms: min,
            }],
        )
    } else if value > max {
        (
            max,
            vec![SettingsWarning::Clamped {
                original_ms: value,
                clamped_ms: max,
            }],
        )
    } else {
        (value, vec![])
    }
}

/// Validate settings before saving (frontend-supplied path). Rejects
/// out-of-range numeric values with `SettingsBoundsError` rather than
/// clamping — the dialog also validates client-side; this catches
/// adversarial IPC.
pub fn validate_save_settings(s: &Settings) -> Result<(), SettingsBoundsError> {
    if !(AUTO_LOCK_MIN_MS..=AUTO_LOCK_MAX_MS).contains(&s.auto_lock_timeout_ms) {
        return Err(SettingsBoundsError {
            min: AUTO_LOCK_MIN_MS,
            max: AUTO_LOCK_MAX_MS,
        });
    }
    if !(REAUTH_WINDOW_MIN_MS..=REAUTH_WINDOW_MAX_MS).contains(&s.reauth_grace_window_ms) {
        return Err(SettingsBoundsError {
            min: REAUTH_WINDOW_MIN_MS,
            max: REAUTH_WINDOW_MAX_MS,
        });
    }
    if !(RETENTION_WINDOW_MIN_MS..=RETENTION_WINDOW_MAX_MS).contains(&s.retention_window_ms) {
        return Err(SettingsBoundsError {
            min: RETENTION_WINDOW_MIN_MS,
            max: RETENTION_WINDOW_MAX_MS,
        });
    }
    Ok(())
}

/// Serialize a `Settings` into one `(field_name, field_value_text)` pair per
/// field. Every pair belongs to a single `SETTINGS_RECORD_TYPE` record; the
/// caller supplies that record type (it is constant, so it is not repeated
/// per field). The pair order is stable, auto-lock first.
pub fn serialize_settings(s: &Settings) -> Vec<(String, String)> {
    vec![
        (
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            s.auto_lock_timeout_ms.to_string(),
        ),
        (
            SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS.to_string(),
            s.require_password_before_edits.to_string(),
        ),
        (
            SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS.to_string(),
            s.reauth_grace_window_ms.to_string(),
        ),
        (
            SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(),
            s.retention_window_ms.to_string(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::schema::*;

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
        let fields = serialize_settings(&original);
        let (parsed, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
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
            SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(),
            "1000".to_string(),
        )];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.retention_window_ms, RETENTION_WINDOW_MIN_MS);
        assert_eq!(
            warnings,
            vec![SettingsWarning::Clamped {
                original_ms: 1000,
                clamped_ms: RETENTION_WINDOW_MIN_MS
            }]
        );
    }

    #[test]
    fn parse_auto_lock_below_min_clamps_with_warning() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "30000".to_string(),
        )];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, AUTO_LOCK_MIN_MS);
        assert_eq!(warnings.len(), 1);
        match &warnings[0] {
            SettingsWarning::Clamped {
                original_ms,
                clamped_ms,
            } => {
                assert_eq!(*original_ms, 30_000);
                assert_eq!(*clamped_ms, AUTO_LOCK_MIN_MS);
            }
            other => panic!("expected Clamped, got {other:?}"),
        }
    }

    #[test]
    fn parse_above_max_clamps_with_warning() {
        let oversized = AUTO_LOCK_MAX_MS + 1;
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            oversized.to_string(),
        )];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.auto_lock_timeout_ms, AUTO_LOCK_MAX_MS);
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

    #[test]
    fn parse_retention_window_field() {
        let fields = vec![(
            SETTINGS_FIELD_RETENTION_WINDOW_MS.to_string(),
            (30 * MS_PER_DAY).to_string(),
        )];
        let (s, warnings) = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(s.retention_window_ms, 30 * MS_PER_DAY);
        assert!(warnings.is_empty());
    }

    // (retention clamp-below-min is covered by `parse_below_min_clamps_with_warning`
    // above, which asserts the exact clamped value + warning.)

    // =========================================================================
    // parse_settings_fields — error / warning cases
    // =========================================================================

    #[test]
    fn parse_unknown_version_errors() {
        let err = parse_settings_fields("secretary.settings.v99", &[]).expect_err("must error");
        assert_eq!(
            err,
            SettingsParseError::UnknownVersion {
                version: "secretary.settings.v99".into()
            }
        );
    }

    #[test]
    fn parse_unknown_version_errors_with_fields_present() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "600000".to_string(),
        )];
        let err = parse_settings_fields("secretary.settings.v99", &fields).expect_err("must error");
        match err {
            SettingsParseError::UnknownVersion { version } => {
                assert_eq!(version, "secretary.settings.v99");
            }
            other => panic!("expected UnknownVersion, got {other:?}"),
        }
    }

    #[test]
    fn parse_unknown_extra_field_warns_not_errors() {
        let fields = vec![("some_future_field".to_string(), "x".to_string())];
        let (_s, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("must not hard-error");
        assert_eq!(warnings.len(), 1);
        assert!(matches!(warnings[0], SettingsWarning::Corrupt { .. }));
    }

    #[test]
    fn parse_unknown_extra_field_warns_not_errors_with_known_field_present() {
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
        assert!(matches!(warnings[0], SettingsWarning::Corrupt { .. }));
    }

    #[test]
    fn parse_non_integer_errors() {
        let fields = vec![(
            SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS.to_string(),
            "not-a-number".to_string(),
        )];
        let err = parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect_err("must error");
        match err {
            SettingsParseError::Corrupt { .. } => {}
            other => panic!("expected Corrupt, got {other:?}"),
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
        assert_eq!(
            err,
            SettingsBoundsError {
                min: AUTO_LOCK_MIN_MS,
                max: AUTO_LOCK_MAX_MS
            }
        );
    }

    #[test]
    fn validate_save_rejects_above_max() {
        let s = Settings {
            auto_lock_timeout_ms: AUTO_LOCK_MAX_MS + 1,
            ..Default::default()
        };
        assert!(validate_save_settings(&s).is_err());
    }

    #[test]
    fn validate_save_rejects_window_above_max() {
        let s = Settings {
            auto_lock_timeout_ms: AUTO_LOCK_DEFAULT_MS,
            require_password_before_edits: true,
            reauth_grace_window_ms: REAUTH_WINDOW_MAX_MS + 1,
            ..Settings::default()
        };
        let err = validate_save_settings(&s).expect_err("must reject");
        assert_eq!(
            err,
            SettingsBoundsError {
                min: REAUTH_WINDOW_MIN_MS,
                max: REAUTH_WINDOW_MAX_MS
            }
        );
    }

    #[test]
    fn validate_rejects_out_of_range_retention() {
        let s = Settings {
            retention_window_ms: 999,
            ..Settings::default()
        };
        assert_eq!(
            validate_save_settings(&s),
            Err(SettingsBoundsError {
                min: RETENTION_WINDOW_MIN_MS,
                max: RETENTION_WINDOW_MAX_MS
            })
        );
    }

    // (out-of-range retention is covered by `validate_rejects_out_of_range_retention`
    // above, which asserts the exact min/max in the returned error.)

    // =========================================================================
    // serialize_settings
    // =========================================================================

    #[test]
    fn serialize_round_trips_through_parse() {
        let original = Settings {
            auto_lock_timeout_ms: 900_000,
            require_password_before_edits: false,
            reauth_grace_window_ms: 30_000,
            retention_window_ms: 45 * MS_PER_DAY,
        };
        let fields = serialize_settings(&original);
        let (parsed, warnings) =
            parse_settings_fields(SETTINGS_RECORD_TYPE, &fields).expect("parse");
        assert_eq!(parsed, original);
        assert!(warnings.is_empty());
    }

    #[test]
    fn serialize_first_pair_is_auto_lock_field() {
        let original = Settings {
            auto_lock_timeout_ms: 900_000,
            require_password_before_edits: false,
            reauth_grace_window_ms: 30_000,
            ..Settings::default()
        };
        let pairs = serialize_settings(&original);
        // The auto-lock field is always first.
        assert_eq!(&pairs[0].0, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS);
    }

    // =========================================================================
    // retention_window_ms
    // =========================================================================

    #[test]
    fn serialize_round_trips_retention_window() {
        let s = Settings {
            retention_window_ms: 45 * MS_PER_DAY,
            ..Settings::default()
        };
        let pairs = serialize_settings(&s);
        assert!(pairs
            .iter()
            .any(|(name, val)| name == SETTINGS_FIELD_RETENTION_WINDOW_MS
                && val == &(45 * MS_PER_DAY).to_string()));
    }
}
