//! Vault-settings schema + parse/serialize + read/write orchestrators — the
//! single source of truth for the `secretary.settings.v1` record consumed by
//! desktop (directly) and mobile (via uniffi). Split: `schema` (value type +
//! constants + deterministic UUIDs), `parse` (pure string↔struct + bounds),
//! `orchestration` (vault I/O over `read_block` / `save_block`).
//!
//! Task 1 wired `schema`; Task 2 adds `parse`; `orchestration` lands in Task 3.

pub mod parse;
pub mod schema;

pub use parse::{
    parse_settings_fields, serialize_settings, validate_save_settings, SettingsBoundsError,
    SettingsParseError, SettingsWarning,
};
pub use schema::{
    deterministic_uuid_16, Settings, AUTO_LOCK_DEFAULT_MS, AUTO_LOCK_MAX_MS, AUTO_LOCK_MIN_MS,
    MS_PER_DAY, REAUTH_WINDOW_DEFAULT_MS, REAUTH_WINDOW_MAX_MS, REAUTH_WINDOW_MIN_MS,
    REQUIRE_PASSWORD_DEFAULT, RETENTION_WINDOW_DEFAULT_MS, RETENTION_WINDOW_MAX_MS,
    RETENTION_WINDOW_MIN_MS, SETTINGS_BLOCK_NAME, SETTINGS_FIELD_AUTO_LOCK_TIMEOUT_MS,
    SETTINGS_FIELD_REAUTH_GRACE_WINDOW_MS, SETTINGS_FIELD_REQUIRE_PASSWORD_BEFORE_EDITS,
    SETTINGS_FIELD_RETENTION_WINDOW_MS, SETTINGS_RECORD_TYPE,
};
