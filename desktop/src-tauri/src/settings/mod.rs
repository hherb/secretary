//! Settings module — schema + parse/serialize + vault I/O facade.
//!
//! Internally split across two private siblings:
//!
//! - [`parse`] holds the Task-2 pure value types and string→struct
//!   conversions (`Settings`, `parse_settings_field`, `serialize_settings`,
//!   `validate_save_value`). No filesystem or vault touching — every input
//!   is a `&str` and every output is owned data.
//! - [`io`] holds the Task-3 vault I/O facade (`load_from_vault`,
//!   `save_to_vault`) and per-vault device-UUID persistence
//!   (`load_or_create_device_uuid`, `device_uuid_path_in`). These reach
//!   into the bridge's `UnlockedIdentity` / `OpenVaultManifest` handles
//!   and touch the platform `data_dir`.
//!
//! Callers see a single flat `settings::*` surface — the split is purely
//! internal organisation. See spec §8 for the schema rationale.

mod io;
mod parse;

pub use io::{
    device_uuid_path_in, load_from_vault, load_or_create_device_uuid,
    load_or_create_device_uuid_in, save_to_vault,
};
pub use parse::{
    parse_settings_fields, serialize_settings, validate_save_settings, ParseResult, Settings,
};
