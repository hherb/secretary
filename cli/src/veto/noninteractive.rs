//! Auto-`KeepLocal` veto UX for `--non-interactive` mode.
//!
//! Spec: [`docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md`](../../../docs/superpowers/specs/2026-05-23-c2-headless-sync-cli-design.md)
//! §D4 — the safe default for headless mode (no silent record
//! deletion; every veto becomes `KeepLocal`).

use secretary_core::sync::{RecordTombstoneVeto, VetoDecision};

use super::VetoUx;

/// Auto-resolves every veto to [`VetoDecision::KeepLocal`]. Stateless
/// unit struct; instantiation is free.
///
/// Order is preserved one-to-one with the input slice so the bijection
/// check in `commit_with_decisions` is trivially satisfied. Consumed
/// by [`crate::pipeline::run_one`] when the operator passes
/// `--non-interactive`.
pub struct AutoKeepLocalVetoUx;

impl VetoUx for AutoKeepLocalVetoUx {
    fn decide(&mut self, vetoes: &[RecordTombstoneVeto]) -> Vec<VetoDecision> {
        vetoes
            .iter()
            .map(|v| VetoDecision::KeepLocal {
                record_id: v.record_id,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::test_util::dummy_veto;
    use super::*;

    #[test]
    fn empty_input_returns_empty() {
        let mut ux = AutoKeepLocalVetoUx;
        let decisions = ux.decide(&[]);
        assert!(decisions.is_empty());
    }

    #[test]
    fn every_veto_becomes_keep_local_preserving_order() {
        let mut ux = AutoKeepLocalVetoUx;
        let vetoes = vec![dummy_veto(1), dummy_veto(2), dummy_veto(3)];
        let decisions = ux.decide(&vetoes);
        assert_eq!(decisions.len(), 3);
        for (d, v) in decisions.iter().zip(vetoes.iter()) {
            match d {
                VetoDecision::KeepLocal { record_id } => assert_eq!(*record_id, v.record_id),
                other => panic!("expected KeepLocal, got {other:?}"),
            }
        }
    }
}
