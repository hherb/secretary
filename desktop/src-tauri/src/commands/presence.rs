//! `authenticate_presence` — macOS Touch ID write-reauth presence proof.
//!
//! Vault-independent (presence ≠ crypto): it takes no session handle and
//! touches no key material. The live objc2 evaluation is injected through a
//! `PresenceProvider` seam so the command core is host-testable with a fake.

use secretary_desktop_presence::{
    availability as real_availability, evaluate as real_evaluate, PresenceAvailability,
    PresenceOutcome,
};

use crate::errors::AppError;

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
}
