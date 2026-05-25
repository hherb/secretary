//! Veto-decision UX for `RecordTombstoneVeto` adjudication.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D4 (default `KeepLocal` veto policy in non-interactive mode).
//!
//! Two impls ship together (both tiny) so the upcoming `pipeline.rs`
//! (Task 5) can wire either one behind a `&mut dyn VetoUx` without
//! ordering churn:
//!
//! - [`noninteractive::AutoKeepLocalVetoUx`] — auto-resolves every veto
//!   to [`VetoDecision::KeepLocal`]. Used by `--non-interactive`.
//! - [`interactive::TtyVetoUx`] — per-record `y`/`n` prompt over a
//!   generic `BufRead` + `Write` pair (production wires
//!   `stdin().lock()` + `stderr().lock()`; tests wire `Cursor`s).

use secretary_core::sync::{RecordTombstoneVeto, VetoDecision};

pub mod interactive;
pub mod noninteractive;

#[cfg(test)]
pub(crate) mod test_util;

/// Strategy for converting a slice of [`RecordTombstoneVeto`] into the
/// `Vec<VetoDecision>` that [`secretary_core::sync::commit_with_decisions`]
/// requires.
///
/// Implementations are stateless and side-effect-free except for the
/// actual UX layer (which reads from a [`std::io::Read`] + writes to a
/// [`std::io::Write`]). The trait is intentionally object-safe so the
/// pipeline picks the impl at runtime behind a `&mut dyn VetoUx`
/// without monomorphisation — see [`crate::pipeline::run_one`].
pub trait VetoUx {
    /// Produce one [`VetoDecision`] per input veto, **preserving order**.
    ///
    /// Each returned decision's `record_id` MUST match the corresponding
    /// veto's `record_id` — `commit_with_decisions` enforces the
    /// `vetoes ↔ decisions` bijection and rejects mismatches with a
    /// typed error (see spec §"Public surface" exit code 1 / generic).
    fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision>;
}
