//! macOS Touch ID via LocalAuthentication. STUB (Task 1) — the real objc2
//! `evaluate`/`availability` land in Task 2. The pure `crate::classify` this
//! shell will delegate to is already fully tested.

use crate::{PresenceAvailability, PresenceOutcome};

pub(crate) fn availability() -> PresenceAvailability {
    // Task 2 replaces this with LAContext.canEvaluatePolicy.
    PresenceAvailability::NotAvailable
}

pub(crate) fn evaluate(_reason: &str) -> PresenceOutcome {
    // Task 2 replaces the hardcoded code with the real LAContext.evaluatePolicy
    // result; the stub already routes through the real mapping path
    // (crate::classify) so nothing in the crate is dead on macOS.
    crate::classify(Err(crate::LA_ERROR_BIOMETRY_NOT_AVAILABLE))
}
