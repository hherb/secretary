//! Data Transfer Objects crossing the Tauri IPC boundary.
//!
//! Discipline (spec §5 "IPC boundary"):
//!
//! - Hex-encode all `[u8; 16]` / `Vec<u8>` UUIDs as `String` fields with a
//!   `_hex` suffix so the wire format is JSON-native.
//! - Never serialize zeroize-typed values. `read_block`'s DTOs carry no
//!   secret payload; only `reveal_field`'s `RevealedFieldDto.value` does,
//!   produced lazily on explicit reveal.
//! - `From<&BridgeType>` impls live next to the DTO.
//! - All DTOs `#[serde(rename_all = "camelCase")]`.
//!
//! Submodules: [`manifest`] (D.1.1 manifest/summary/settings DTOs) and
//! [`browse`] (D.1.2 block-detail / record / field / revealed-field DTOs).

mod browse;
mod create;
mod edit;
mod manifest;
mod trash;

pub use browse::{BlockDetailDto, FieldMetaDto, RecordDto, RevealedFieldDto};
pub use create::{CreateTargetProbeDto, CreateVaultDto};
pub use edit::{
    FieldInputDto, FieldValueDto, RecordInputDto, RecordRefDto, RecordRevealDto,
    RevealedFieldWithNameDto,
};
pub use manifest::{BlockSummaryDto, ManifestDto, SettingsDto, SettingsInput};
pub use trash::TrashedBlockDto;
