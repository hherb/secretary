//! PyO3 sync surface (#187): the three sync functions + their DTOs,
//! mirroring `secretary_ffi_bridge::sync`. Output DTOs are frozen read-only
//! pyclasses; `SyncOutcomeDto` exposes a `kind` discriminant + payload
//! getters (populated only for the ConflictsPending arm) — matching the
//! TS tagged-union shape. `VetoDecisionDto` is the one input pyclass.
//!
//! Every function takes an explicit `state_dir` (mobile sandbox path /
//! hermetic tests). `password` is wrapped in `SecretBytes` immediately.

use std::path::PathBuf;

use pyo3::prelude::*;
use secretary_core::crypto::secret::SecretBytes;

use crate::errors::{ffi_vault_error_to_pyerr, uuid_array_or_value_error};

// `Clone` is required because this DTO is nested inside a `get_all` `Vec`
// getter (`SyncStatusDto.device_clocks`), which hands Python a clone of the
// field. `skip_from_py_object` opts out of the (now deprecated) auto
// `FromPyObject` derive for `Clone` pyclasses — this is an output-only DTO,
// never extracted from Python.
#[pyclass(frozen, get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct DeviceClockDto {
    pub device_uuid_hex: String,
    pub counter: u64,
}

#[pyclass(frozen, get_all)]
pub struct SyncStatusDto {
    pub has_state: bool,
    pub device_clocks: Vec<DeviceClockDto>,
    pub last_state_write_ms: Option<u64>,
}

// `Clone` + `skip_from_py_object`: nested inside `SyncOutcomeDto.vetoes`
// (a `get_all` `Vec` getter); output-only, never extracted from Python.
#[pyclass(frozen, get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct VetoDto {
    pub record_uuid_hex: String,
    pub record_type: String,
    pub tags: Vec<String>,
    pub field_names: Vec<String>,
    pub local_last_mod_ms: u64,
    pub peer_tombstoned_at_ms: u64,
    pub peer_device_hex: String,
}

// `Clone` + `skip_from_py_object`: nested inside `SyncOutcomeDto.collisions`
// (a `get_all` `Vec` getter); output-only, never extracted from Python.
#[pyclass(frozen, get_all, skip_from_py_object)]
#[derive(Clone)]
pub struct CollisionDto {
    pub record_uuid_hex: String,
    pub field_names: Vec<String>,
}

/// Result of one sync pass. `kind` is one of `"NothingToDo"`,
/// `"AppliedAutomatically"`, `"SilentMerge"`, `"MergedClean"`,
/// `"ConflictsPending"`, `"RollbackRejected"`. `vetoes` / `collisions` /
/// `manifest_hash` are populated only when `kind == "ConflictsPending"`
/// (empty / `None` otherwise).
#[pyclass(frozen, get_all)]
pub struct SyncOutcomeDto {
    pub kind: String,
    pub vetoes: Vec<VetoDto>,
    pub collisions: Vec<CollisionDto>,
    pub manifest_hash: Option<Vec<u8>>,
}

#[pyclass(from_py_object)]
#[derive(Clone)]
pub struct VetoDecisionDto {
    pub record_uuid_hex: String,
    pub keep_local: bool,
}

#[pymethods]
impl VetoDecisionDto {
    #[new]
    fn new(record_uuid_hex: String, keep_local: bool) -> Self {
        Self {
            record_uuid_hex,
            keep_local,
        }
    }
}

fn outcome_from_bridge(o: secretary_ffi_bridge::SyncOutcomeDto) -> SyncOutcomeDto {
    use secretary_ffi_bridge::SyncOutcomeDto as B;
    let kind = match &o {
        B::NothingToDo => "NothingToDo",
        B::AppliedAutomatically => "AppliedAutomatically",
        B::SilentMerge => "SilentMerge",
        B::MergedClean => "MergedClean",
        B::ConflictsPending { .. } => "ConflictsPending",
        B::RollbackRejected => "RollbackRejected",
    }
    .to_string();
    match o {
        B::ConflictsPending {
            vetoes,
            collisions,
            manifest_hash,
        } => SyncOutcomeDto {
            kind,
            vetoes: vetoes
                .into_iter()
                .map(|v| VetoDto {
                    record_uuid_hex: v.record_uuid_hex,
                    record_type: v.record_type,
                    tags: v.tags,
                    field_names: v.field_names,
                    local_last_mod_ms: v.local_last_mod_ms,
                    peer_tombstoned_at_ms: v.peer_tombstoned_at_ms,
                    peer_device_hex: v.peer_device_hex,
                })
                .collect(),
            collisions: collisions
                .into_iter()
                .map(|c| CollisionDto {
                    record_uuid_hex: c.record_uuid_hex,
                    field_names: c.field_names,
                })
                .collect(),
            manifest_hash: Some(manifest_hash),
        },
        _ => SyncOutcomeDto {
            kind,
            vetoes: Vec::new(),
            collisions: Vec::new(),
            manifest_hash: None,
        },
    }
}

#[pyfunction]
pub(crate) fn sync_status(state_dir: PathBuf, vault_uuid: Vec<u8>) -> PyResult<SyncStatusDto> {
    let vault_uuid = uuid_array_or_value_error(&vault_uuid, "vault_uuid")?;
    let s = secretary_ffi_bridge::sync_status_in(&state_dir, vault_uuid)
        .map_err(ffi_vault_error_to_pyerr)?;
    Ok(SyncStatusDto {
        has_state: s.has_state,
        device_clocks: s
            .device_clocks
            .into_iter()
            .map(|c| DeviceClockDto {
                device_uuid_hex: c.device_uuid_hex,
                counter: c.counter,
            })
            .collect(),
        last_state_write_ms: s.last_state_write_ms,
    })
}

#[pyfunction]
pub(crate) fn sync_vault(
    state_dir: PathBuf,
    vault_folder: PathBuf,
    password: Vec<u8>,
    now_ms: u64,
) -> PyResult<SyncOutcomeDto> {
    secretary_ffi_bridge::sync_vault_in(
        &state_dir,
        &vault_folder,
        SecretBytes::new(password),
        now_ms,
    )
    .map(outcome_from_bridge)
    .map_err(ffi_vault_error_to_pyerr)
}

#[pyfunction]
pub(crate) fn sync_commit_decisions(
    state_dir: PathBuf,
    vault_folder: PathBuf,
    password: Vec<u8>,
    decisions: Vec<VetoDecisionDto>,
    manifest_hash: Vec<u8>,
    now_ms: u64,
) -> PyResult<SyncOutcomeDto> {
    let bridge_decisions = decisions
        .into_iter()
        .map(|d| secretary_ffi_bridge::VetoDecisionDto {
            record_uuid_hex: d.record_uuid_hex,
            keep_local: d.keep_local,
        })
        .collect();
    secretary_ffi_bridge::sync_commit_decisions_in(
        &state_dir,
        &vault_folder,
        SecretBytes::new(password),
        bridge_decisions,
        manifest_hash,
        now_ms,
    )
    .map(outcome_from_bridge)
    .map_err(ffi_vault_error_to_pyerr)
}
