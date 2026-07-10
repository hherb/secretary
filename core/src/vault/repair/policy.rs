//! Consent policy for the repair path (#374 part 3). The default is
//! fail-closed; `AdoptApproved` licenses ONLY the crashed-share shape
//! (`Equal` clock ∧ strict superset) and only where the approval matches
//! the on-disk file fingerprint AND the exact added-recipient set —
//! consent is bound to exactly what the user was shown (spec §3.1–3.3).

use std::collections::BTreeSet;

/// How `repair_vault` treats a consent-eligible recipient widening.
#[derive(Debug, Clone)]
pub enum RepairPolicy {
    /// Any recipient widening refuses the repair (pre-#374-part-3 behavior).
    FailClosed,
    /// Adopt a widening ONLY if it matches one of these approvals exactly;
    /// any mismatch (or any non-consent-eligible widening shape) still
    /// refuses. An empty vec behaves like `FailClosed`.
    AdoptApproved(Vec<ApprovedWidening>),
}

/// One user-approved widening, bound to exactly what the preview showed.
///
/// **Mint fresh from a [`super::preview_repair`] run; never persist.**
/// The three binds below make an approval structurally single-use (#391):
/// beyond the on-disk file bytes and the added-recipient delta, an
/// approval also carries the COMMITTED manifest fingerprint the preview
/// diffed against, and `repair_vault` refuses when the committed entry
/// has since changed. This closes the replay window even against a
/// non-conforming client that persists approvals: a persisted approval
/// replayed after an intervening revocation of the same recipient
/// exactly matches a re-planted copy of the previously-approved file on
/// the first two binds, but the revocation's re-key changed the
/// committed fingerprint, so the third bind refuses (stale consent)
/// rather than re-granting access without fresh consent (normative:
/// vault-format.md §6.5 consent scoping).
#[derive(Debug, Clone)]
pub struct ApprovedWidening {
    /// The block whose widening the user approved.
    pub block_uuid: [u8; 16],
    /// BLAKE3-256 of the on-disk block file the user was shown. A file
    /// swapped between preview and repair fails this bind (stale consent).
    pub file_fingerprint: [u8; 32],
    /// The committed manifest `BlockEntry.fingerprint` the preview diffed
    /// the residue against (from
    /// [`super::WideningReport::committed_fingerprint`]). Any committed
    /// write to the block between preview and repair fails this bind
    /// (stale consent) — the approval is scoped in time by construction,
    /// not merely by client discipline (#391).
    pub committed_fingerprint: [u8; 32],
    /// The exact added-recipient set (contact UUIDs) the user approved.
    /// Compared with set equality — never subset/superset.
    pub added_recipients: BTreeSet<[u8; 16]>,
}
