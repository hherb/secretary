//! Non-macOS providers are not implemented in this release (#277 is macOS-only).
//! Returning `Unsupported`/`Unavailable` keeps the crate compiling on Linux CI
//! and makes the frontend fall back to the password path everywhere else.

use crate::{PresenceAvailability, PresenceOutcome};

pub(crate) fn availability() -> PresenceAvailability {
    PresenceAvailability::Unsupported
}

pub(crate) fn evaluate(_reason: &str) -> PresenceOutcome {
    PresenceOutcome::Unavailable
}
