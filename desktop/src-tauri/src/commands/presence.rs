//! `authenticate_presence` — macOS Touch ID write-reauth presence proof.
//!
//! Vault-independent (presence ≠ crypto): it takes no session handle and
//! touches no key material. The live objc2 evaluation is injected through a
//! `PresenceProvider` seam so the command core is host-testable with a fake.
//!
//! `read_presence_pref` / `write_presence_pref` (#277) are the desktop-local,
//! per-vault preference commands: whether Touch ID may satisfy write re-auth
//! on THIS machine. Unlike `authenticate_presence`, these DO need the open
//! vault's UUID (to key the pref file) so they require an unlocked session.

use std::path::PathBuf;
use std::sync::Mutex;

use tauri::State;

use secretary_desktop_presence::{
    availability as real_availability, evaluate as real_evaluate, PresenceAvailability,
    PresenceOutcome,
};

use crate::commands::shared::lock_session;
use crate::errors::AppError;
use crate::presence_pref::{load_pref_in, save_pref_in, PresencePref};
use crate::session::VaultSession;

/// Wire form of `PresenceOutcome`. `#[serde(tag = "kind")]` → `{ "kind": "authenticated" }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum PresenceOutcomeDto {
    Authenticated,
    Fallback,
    Unavailable,
    Cancelled,
}

impl From<PresenceOutcome> for PresenceOutcomeDto {
    fn from(o: PresenceOutcome) -> Self {
        match o {
            PresenceOutcome::Authenticated => Self::Authenticated,
            PresenceOutcome::Fallback => Self::Fallback,
            PresenceOutcome::Unavailable => Self::Unavailable,
            PresenceOutcome::Cancelled => Self::Cancelled,
        }
    }
}

/// Wire form of `PresenceAvailability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum PresenceAvailabilityDto {
    Available,
    NotEnrolled,
    NotAvailable,
    Unsupported,
}

impl From<PresenceAvailability> for PresenceAvailabilityDto {
    fn from(a: PresenceAvailability) -> Self {
        match a {
            PresenceAvailability::Available => Self::Available,
            PresenceAvailability::NotEnrolled => Self::NotEnrolled,
            PresenceAvailability::NotAvailable => Self::NotAvailable,
            PresenceAvailability::Unsupported => Self::Unsupported,
        }
    }
}

/// Injectable biometric provider. Production delegates to the presence crate;
/// tests inject a fake (the live sheet can't run in `cargo test`).
pub trait PresenceProvider {
    fn availability(&self) -> PresenceAvailability;
    fn evaluate(&self, reason: &str) -> PresenceOutcome;
}

/// Production provider — thin delegate to `secretary_desktop_presence`.
pub struct RealPresenceProvider;

impl PresenceProvider for RealPresenceProvider {
    fn availability(&self) -> PresenceAvailability {
        real_availability()
    }
    fn evaluate(&self, reason: &str) -> PresenceOutcome {
        real_evaluate(reason)
    }
}

/// Testable core. Never returns `AppError` for a normal outcome — cancel /
/// fallback / unavailable are control-flow returned as `Ok`. `AppError` is
/// reserved for genuine faults (none today; the seam is infallible, but the
/// signature keeps room for a future transport error).
pub fn authenticate_presence_impl(
    provider: &dyn PresenceProvider,
    reason: &str,
) -> Result<PresenceOutcomeDto, AppError> {
    Ok(provider.evaluate(reason).into())
}

#[tauri::command]
pub async fn authenticate_presence(reason: String) -> Result<PresenceOutcomeDto, AppError> {
    // `evaluate` presents the Touch ID sheet and blocks the calling thread
    // until the user answers it — running that inline in an async command
    // handler would tie up a Tauri async-runtime worker for the duration.
    // `spawn_blocking` moves it onto the blocking thread pool instead.
    tauri::async_runtime::spawn_blocking(move || {
        authenticate_presence_impl(&RealPresenceProvider, &reason)
    })
    .await
    .map_err(|e| AppError::Internal {
        detail: format!("presence eval join error: {e}"),
    })?
}

// ============================================================================
// read_presence_pref / write_presence_pref (#277)
// ============================================================================

/// Wire form of the presence preference read: the stored toggle plus the
/// current hardware availability (so the UI can hide the toggle off macOS or
/// where Touch ID isn't enrolled).
#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PresencePrefDto {
    pub biometric_enabled: bool,
    pub availability: PresenceAvailabilityDto,
}

/// Resolve `(data_dir, vault_uuid_hex)` for the open vault, or `NotUnlocked`.
fn open_vault_pref_key(session: &VaultSession) -> Result<(PathBuf, String), AppError> {
    let uuid = session.vault_uuid().ok_or(AppError::NotUnlocked)?;
    Ok((session.device_data_dir_clone(), hex::encode(uuid)))
}

#[tauri::command]
pub async fn read_presence_pref(
    state: State<'_, Mutex<VaultSession>>,
) -> Result<PresencePrefDto, AppError> {
    read_presence_pref_impl(state.inner())
}

#[tauri::command]
pub async fn write_presence_pref(
    state: State<'_, Mutex<VaultSession>>,
    enabled: bool,
) -> Result<(), AppError> {
    write_presence_pref_impl(state.inner(), enabled)
}

/// Testable core for `read_presence_pref`. `NotUnlocked` when locked (no
/// vault UUID to key the pref file). The session mutex is released before
/// the file read, mirroring the mutex-early-release pattern in
/// `verify_password_impl`.
pub fn read_presence_pref_impl(state: &Mutex<VaultSession>) -> Result<PresencePrefDto, AppError> {
    let (data_dir, uuid_hex) = {
        let session = lock_session(state)?;
        open_vault_pref_key(&session)?
    };
    let pref = load_pref_in(&data_dir, &uuid_hex);
    Ok(PresencePrefDto {
        biometric_enabled: pref.biometric_reauth_enabled,
        availability: RealPresenceProvider.availability().into(),
    })
}

/// Testable core for `write_presence_pref`. `NotUnlocked` when locked.
pub fn write_presence_pref_impl(
    state: &Mutex<VaultSession>,
    enabled: bool,
) -> Result<(), AppError> {
    let (data_dir, uuid_hex) = {
        let session = lock_session(state)?;
        open_vault_pref_key(&session)?
    };
    save_pref_in(
        &data_dir,
        &uuid_hex,
        &PresencePref {
            biometric_reauth_enabled: enabled,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeProvider(PresenceOutcome);
    impl PresenceProvider for FakeProvider {
        fn availability(&self) -> PresenceAvailability {
            PresenceAvailability::Available
        }
        fn evaluate(&self, _reason: &str) -> PresenceOutcome {
            self.0
        }
    }

    #[test]
    fn each_outcome_passes_through() {
        let cases = [
            (
                PresenceOutcome::Authenticated,
                PresenceOutcomeDto::Authenticated,
            ),
            (PresenceOutcome::Fallback, PresenceOutcomeDto::Fallback),
            (
                PresenceOutcome::Unavailable,
                PresenceOutcomeDto::Unavailable,
            ),
            (PresenceOutcome::Cancelled, PresenceOutcomeDto::Cancelled),
        ];
        for (outcome, expected) in cases {
            let got = authenticate_presence_impl(&FakeProvider(outcome), "test").unwrap();
            assert_eq!(got, expected);
        }
    }

    #[test]
    fn outcome_dto_serializes_tagged() {
        let json = serde_json::to_string(&PresenceOutcomeDto::Authenticated).unwrap();
        assert_eq!(json, r#"{"kind":"authenticated"}"#);
    }

    #[test]
    fn read_presence_pref_impl_while_locked_returns_not_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(dir.path().to_path_buf()));
        let err = read_presence_pref_impl(&state).expect_err("locked must reject");
        assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
    }

    #[test]
    fn write_presence_pref_impl_while_locked_returns_not_unlocked() {
        let dir = tempfile::tempdir().unwrap();
        let state = Mutex::new(VaultSession::new(dir.path().to_path_buf()));
        let err = write_presence_pref_impl(&state, false).expect_err("locked must reject");
        assert!(matches!(err, AppError::NotUnlocked), "got {err:?}");
    }

    /// Pins the wire format Task 5's TS `PresencePrefDto` relies on:
    /// `{ biometricEnabled: boolean; availability: 'available' | ... }`.
    #[test]
    fn presence_pref_dto_serializes_camel_case() {
        let dto = PresencePrefDto {
            biometric_enabled: true,
            availability: PresenceAvailabilityDto::NotEnrolled,
        };
        let json = serde_json::to_string(&dto).unwrap();
        assert_eq!(
            json,
            r#"{"biometricEnabled":true,"availability":"notEnrolled"}"#
        );
    }
}
