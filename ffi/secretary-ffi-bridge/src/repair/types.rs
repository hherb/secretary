//! FFI-seam type for consented crash-repair recipient-widening adoption
//! (#374 part 3). Projects `secretary_core::vault::ApprovedWidening`
//! across the FFI boundary; see `super::orchestration` module docs for
//! how the three repair arms map a slice of these into a
//! `secretary_core::vault::RepairPolicy`.

/// One user-approved crash-repair recipient widening, projected across the
/// FFI seam.
///
/// **Mint fresh from a `preview_repair_with_*` run; never persist.**
/// vault-format.md §6.5 scopes an approval to the immediately-following
/// repair invocation: the fingerprint/delta bind deliberately does not
/// cover the committed manifest state, so a persisted approval replayed
/// after an intervening revocation of the same recipient would re-license
/// a re-planted copy of the previously-approved file without fresh consent.
///
/// `block_uuid` / `file_fingerprint` are fixed-size arrays, so there is no
/// length to validate — wrong-length raw byte buffers on the foreign side
/// are the BINDING layer's job to reject before constructing this type
/// (uniffi/pyo3 wrappers), per the established rule that FFI input
/// validation lives at the binding wrapper, not the bridge; the bridge
/// trusts its caller here exactly as it does for the existing
/// `[u8; 16]`/`[u8; 32]` device-slot parameters.
///
/// `added_recipients` is a `Vec` here — not a `BTreeSet` — because
/// uniffi/PyO3 do not project `BTreeSet` cleanly across the FFI boundary.
/// The arm that consumes this (`repair_vault_with_*_in`) converts it to a
/// `BTreeSet<[u8; 16]>` when building
/// [`secretary_core::vault::RepairPolicy::AdoptApproved`]; core's
/// `ApprovedWidening::added_recipients` is compared by set equality, so
/// duplicate entries or ordering at this seam are immaterial.
#[derive(Debug, Clone)]
pub struct FfiApprovedWidening {
    /// The block whose widening the user approved.
    pub block_uuid: [u8; 16],
    /// BLAKE3-256 of the on-disk block file the user was shown when they
    /// approved (from `preview_repair`). A file swapped between preview
    /// and repair fails this bind — core surfaces the mismatch as
    /// [`crate::error::FfiVaultError::RepairRejected`] with a detail
    /// naming it stale consent.
    pub file_fingerprint: [u8; 32],
    /// The exact added-recipient set (contact UUIDs) the user approved.
    /// Compared with set equality by core — never subset/superset.
    pub added_recipients: Vec<[u8; 16]>,
}
