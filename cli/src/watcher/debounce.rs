//! Debounce state machine — collapses a burst of `notify` events into
//! a single `SyncCandidate` per `--debounce-ms` window.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D3 (events + debounce + optional poll).
//!
//! **Pure** — [`step`] takes `(now, pending_since, window)` and returns
//! a `(decision, new_pending_since)` tuple. The daemon loop owns the
//! actual [`Instant`] and translates `decision` into either:
//!
//! - arming/extending a `recv_timeout` deadline (on
//!   [`DebounceDecision::Schedule`] / [`DebounceDecision::Reschedule`]),
//!   or
//! - emitting [`super::WatcherEvent::SyncCandidate`] when the deadline
//!   fires.
//!
//! Semantics: **trailing-edge** debounce. Each new event extends the
//! window — the sync attempt fires after the operator has been quiet
//! for one full window. Mirrors the user-facing expectation that the
//! daemon waits for the burst to end before reacting (matches
//! `notify`'s recommended pattern + `--debounce-ms` flag intent).

use std::time::{Duration, Instant};

/// Decision returned by [`step`] for the current event.
///
/// Both variants carry the **same** `delay` (= `window`); the driver
/// uses the variant to log/telemeter "scheduled fresh" vs "extended
/// due to burst" while applying the deadline identically.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebounceDecision {
    /// No pending schedule existed (or the previous one had already
    /// elapsed) — start a new debounce window from `now`. Driver
    /// arms a deadline `delay` from now.
    Schedule {
        /// How long until the schedule fires.
        delay: Duration,
    },
    /// A pending schedule was still in-window — reset its deadline
    /// to `delay` from `now`. Driver replaces the existing deadline.
    Reschedule {
        /// How long until the (now reset) schedule fires.
        delay: Duration,
    },
}

/// Pure debounce step.
///
/// Inputs:
/// - `now` — the wall-clock instant at which the event arrived.
/// - `pending_since` — `Some(t)` if a previous event set a debounce
///   timer at `t`; `None` if no timer is currently armed.
/// - `window` — the debounce window (typically `--debounce-ms`).
///
/// Returns `(decision, new_pending_since)`:
/// - `decision` tells the driver what to do (schedule / reschedule);
/// - `new_pending_since = Some(now)` — the caller stores this so the
///   next call sees the latest reset point.
///
/// The function is **pure**: same inputs → same outputs, no I/O, no
/// global state. The driver loop's responsibility is to drive the
/// `Instant`s and apply the decision.
#[must_use]
pub fn step(
    now: Instant,
    pending_since: Option<Instant>,
    window: Duration,
) -> (DebounceDecision, Option<Instant>) {
    let decision = match pending_since {
        // No pending timer — fresh schedule.
        None => DebounceDecision::Schedule { delay: window },
        // Previous timer is conceptually expired (deadline has passed
        // before this event arrived) — treat as a fresh schedule.
        // Boundary semantics: `>=` (equal-to-window counts as expired).
        Some(prev) if now.duration_since(prev) >= window => {
            DebounceDecision::Schedule { delay: window }
        }
        // Previous timer is still in-window — reset the deadline.
        Some(_) => DebounceDecision::Reschedule { delay: window },
    };
    (decision, Some(now))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Debounce window used across this module's tests. One named
    /// constant keeps each test focused on the timing scenario rather
    /// than the duration literal (avoids "magic-numbers" drift).
    const WINDOW: Duration = Duration::from_millis(500);

    /// In-window event arrival — well below `WINDOW` so the reschedule
    /// path is unambiguously exercised.
    const WITHIN_WINDOW: Duration = Duration::from_millis(100);

    /// Past-window event arrival — well above `WINDOW` so the fresh-
    /// schedule path is unambiguously exercised.
    const PAST_WINDOW: Duration = Duration::from_millis(600);

    #[test]
    fn first_event_schedules_fresh() {
        let now = Instant::now();
        let (decision, pending) = step(now, None, WINDOW);
        assert_eq!(decision, DebounceDecision::Schedule { delay: WINDOW });
        assert_eq!(pending, Some(now));
    }

    #[test]
    fn second_event_within_window_reschedules() {
        let t0 = Instant::now();
        let t1 = t0 + WITHIN_WINDOW;
        let (decision, pending) = step(t1, Some(t0), WINDOW);
        assert_eq!(decision, DebounceDecision::Reschedule { delay: WINDOW });
        assert_eq!(pending, Some(t1));
    }

    #[test]
    fn event_after_window_schedules_fresh() {
        // Previous timer logically expired (PAST_WINDOW > WINDOW) —
        // covers both the "post-deadline-emit" boundary and the
        // "reset-on-new-event-after-emit" acceptance criterion.
        let t0 = Instant::now();
        let t1 = t0 + PAST_WINDOW;
        let (decision, pending) = step(t1, Some(t0), WINDOW);
        assert_eq!(decision, DebounceDecision::Schedule { delay: WINDOW });
        assert_eq!(pending, Some(t1));
    }

    #[test]
    fn equal_to_window_treated_as_after() {
        // Boundary: `duration_since(prev) == window` returns Schedule
        // (not Reschedule). Pins the `>=` predicate against drift.
        let t0 = Instant::now();
        let t1 = t0 + WINDOW;
        let (decision, pending) = step(t1, Some(t0), WINDOW);
        assert_eq!(decision, DebounceDecision::Schedule { delay: WINDOW });
        assert_eq!(pending, Some(t1));
    }

    #[test]
    fn burst_of_three_events_collapses_into_single_reschedule_chain() {
        // First event arms; second + third (each WITHIN_WINDOW after
        // the previous) extend the window. Pins burst-collapse — three
        // events do NOT produce two separate sync attempts.
        let t0 = Instant::now();
        let (d0, p0) = step(t0, None, WINDOW);
        assert_eq!(d0, DebounceDecision::Schedule { delay: WINDOW });

        let t1 = t0 + WITHIN_WINDOW;
        let (d1, p1) = step(t1, p0, WINDOW);
        assert_eq!(d1, DebounceDecision::Reschedule { delay: WINDOW });

        let t2 = t1 + WITHIN_WINDOW;
        let (d2, p2) = step(t2, p1, WINDOW);
        assert_eq!(d2, DebounceDecision::Reschedule { delay: WINDOW });

        // The final `pending_since` is the latest event time (t2).
        assert_eq!(p2, Some(t2));
    }
}
