//! Vault on-disk format: blocks, manifest, recipients, conflict resolution.
//!
//! The on-disk format is normatively specified in `docs/vault-format.md`.
//! This module currently exposes the §6.3 record types ([`record`]),
//! the §6.1 / §6.2 / §6.3 block layer ([`block`] — binary header,
//! recipient table, AEAD body, the trailing §8 hybrid signature suffix,
//! plus the canonical-CBOR plaintext body and the
//! [`block::encrypt_block`] / [`block::decrypt_block`] orchestrators
//! which sign on encrypt and verify on decrypt), and the manifest layer
//! ([`manifest`] — §4 binary header / CBOR body, §8 hybrid signature,
//! §10 rollback resistance check). The recipients layer (§7) lands in a
//! subsequent build-sequence step and will plug into the [`VaultError`]
//! umbrella below via an additional `#[from]` variant.
//!
//! ## PR-B orchestrators
//!
//! The PR-B orchestrators ([`create_vault`], [`open_vault`],
//! [`save_block`], [`share_block`]) compose the lower pure-function
//! layers into a single side-effecting entry point per user-visible
//! operation. They live in [`orchestrators`] (re-exported here so the
//! public API stays `secretary_core::vault::create_vault`, etc.).

pub mod block;
pub(crate) mod canonical;
pub mod conflict;
pub mod device_slot;
pub(crate) mod io;
pub mod manifest;
pub(crate) mod orchestrators;
pub mod record;

pub use block::{
    decode_block_file, decrypt_block, encode_block_file, encrypt_block, verify_block_signature,
    BlockError, BlockFile, BlockHeader, BlockPlaintext, RecipientPublicKeys, RecipientWrap,
    VectorClockEntry, FILE_KIND_BLOCK, RECIPIENT_ENTRY_LEN,
};
pub use conflict::{
    clock_relation, merge_block, merge_record, merge_vector_clocks, ClockRelation, ConflictError,
    FieldCollision, MergedBlock, MergedRecord, RecordCollision,
};
pub use manifest::{
    decode_manifest, decode_manifest_file, decrypt_manifest_body, encode_manifest,
    encode_manifest_file, encrypt_manifest_body, sign_manifest, verify_manifest, BlockEntry,
    KdfParamsRef, Manifest, ManifestError, ManifestFile, ManifestHeader, TrashEntry,
    MANIFEST_HEADER_LEN,
};
// NOTE: VectorClockEntry is re-used from block.rs by manifest.rs (re-exported
// there via `pub use super::block::VectorClockEntry`). Do NOT add a second
// re-export here — the type is already re-exported above via block.rs.
pub use orchestrators::{
    create_vault, open_vault, read_vault_manifest, restore_block, revoke_block_recipient,
    save_block, share_block, trash_block, OpenVault, Unlocker,
};
// Cross-target test-hook re-exports: integration tests in `tests/*.rs`
// (and the C.1.1a conflict-copy scanner internally) reuse the
// canonical UUID-to-filename formatter and the blocks-subdir / block
// file-extension constants so on-disk filename format stays
// single-sourced. `#[doc(hidden)]` keeps them out of the rendered
// public API. See the docstring on `format_uuid_hyphenated` /
// `BLOCKS_SUBDIR` for the full rationale, and
// `crate::sync::__test_dispatch` for the same pattern.
#[doc(hidden)]
pub use orchestrators::{format_uuid_hyphenated, BLOCKS_SUBDIR, BLOCK_FILE_EXTENSION};
pub use record::{Record, RecordError, RecordField, RecordFieldValue, UnknownValue};

/// Umbrella error type for the vault format layer.
///
/// Aggregates [`RecordError`], [`BlockError`], and [`ManifestError`].
/// Future build-sequence steps add a `Recipients` variant (§7) — `#[from]`
/// so per-layer code paths can use `?` to propagate without hand-mapping.
/// Single-layer surface today, expandable surface tomorrow, with no
/// breaking change at the call sites that already match on this enum.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// Record-level CBOR encode / decode failure (§6.3).
    #[error("record CBOR error: {0}")]
    Record(#[from] RecordError),

    /// Block-level encode / decode failure: binary header (§6.1) or
    /// canonical-CBOR plaintext (§6.3).
    #[error("block error: {0}")]
    Block(#[from] BlockError),

    /// Manifest-level encode / decode / sign / verify failure (§4 / §8).
    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),

    /// CRDT merge primitive failure (`docs/crypto-design.md` §11).
    /// Reachable from [`merge_block`] — the only fallible merge call —
    /// when the two block plaintexts have mismatched `block_uuid`s
    /// (a programmer error per §11.2) or when the merging device's
    /// vector-clock counter would overflow `u64::MAX`. `#[from]`
    /// propagates from [`ConflictError`] through `?`.
    #[error("conflict error: {0}")]
    Conflict(#[from] ConflictError),

    /// Rollback resistance check (§10) rejected an incoming manifest:
    /// its vector clock is *strictly dominated* by the local "highest
    /// clock seen for this vault" — every per-device counter is ≤ the
    /// local counterpart and at least one is strictly less. The UI
    /// SHOULD offer an explicit "I am restoring from a backup; accept
    /// anyway" override before bypassing this guard.
    ///
    /// `local_clock` is the per-vault highest-seen clock (OS keystore
    /// concern; out of scope for this module to compute or store).
    /// `incoming_clock` is the clock from the manifest under load.
    #[error("incoming manifest is dominated by local highest-seen vector clock (rollback)")]
    Rollback {
        local_clock: Vec<VectorClockEntry>,
        incoming_clock: Vec<VectorClockEntry>,
    },

    /// Unlock-layer failure surfaced by the PR-B orchestrators (§3 / §4 /
    /// §5): KDF params below the v1 floor, a malformed `vault.toml` that
    /// the orchestrator round-trips through, an `IdentityBundle` with a
    /// rejected ML-DSA-65 seed, etc. `#[from]` propagates from
    /// [`crate::unlock::UnlockError`] through `?`.
    #[error("unlock error: {0}")]
    Unlock(#[from] crate::unlock::UnlockError),

    /// Contact-card encode / sign failure surfaced by the PR-B
    /// orchestrators when minting the owner's self-signed card.
    /// `#[from]` propagates from [`crate::identity::card::CardError`]
    /// through `?`.
    #[error("contact-card error: {0}")]
    Card(#[from] crate::identity::card::CardError),

    /// Cryptographic-signature primitive failure surfaced by the PR-B
    /// orchestrators when reconstructing typed key/sig objects from the
    /// `IdentityBundle`'s raw byte fields. `#[from]` propagates from
    /// [`crate::crypto::sig::SigError`] through `?`.
    #[error("signature primitive error: {0}")]
    Sig(#[from] crate::crypto::sig::SigError),

    /// Filesystem I/O failure during a §9 atomic write or directory
    /// validation in a PR-B orchestrator. The wrapped
    /// [`std::io::Error`] carries the underlying OS error;
    /// `context` describes which orchestrator step produced it (e.g.
    /// `"vault folder is not empty"`).
    #[error("vault I/O error ({context}): {source}")]
    Io {
        context: &'static str,
        #[source]
        source: std::io::Error,
    },

    /// Sanity check failed during [`open_vault`]: the owner contact
    /// card's `contact_uuid` (or the manifest body's `owner_user_uuid`)
    /// does not match the unlocked identity bundle's `user_uuid`.
    /// Indicates a vault assembled from mismatched parts (e.g. an owner
    /// card from another vault was dropped into `contacts/`) or a swap
    /// attack against the cleartext metadata. The two UUIDs are
    /// included so a UI can show the user exactly which sides
    /// disagree.
    #[error("owner UUID mismatch: vault identity has {vault:?}, found {found:?}")]
    OwnerUuidMismatch { vault: [u8; 16], found: [u8; 16] },

    /// Sanity check failed during [`open_vault`]: the manifest file's
    /// `author_fingerprint` does not match the fingerprint computed
    /// from the loaded owner contact card. The manifest signature
    /// itself verifies under the owner card's public keys (so the
    /// signature path is sound), but the wire-level author hint points
    /// at a different card — typically a sign of a mis-assembled vault
    /// folder rather than an active attack, but rejected loudly so the
    /// inconsistency does not slip past silently.
    #[error("manifest author_fingerprint does not match owner card fingerprint")]
    ManifestAuthorMismatch,

    /// `docs/vault-format.md` §4.3 step 5 cross-check failed: the
    /// `vault_uuid` inside the encrypted+signed manifest body does not
    /// match the `vault_uuid` in the (AAD-bound) binary header. The
    /// AEAD AAD already binds the header to the body, so a successful
    /// decrypt implies the AAD-as-encrypted matches; this explicit
    /// equality check defends a v2/multi-suite migration where AAD
    /// could legitimately decouple from header layout, and surfaces
    /// the disagreement loudly when both UUIDs round-trip but disagree.
    #[error("manifest vault_uuid mismatch: header has {header:?}, body has {body:?}")]
    ManifestVaultUuidMismatch { header: [u8; 16], body: [u8; 16] },

    /// `docs/vault-format.md` §4.3 step 6 cross-check failed: the
    /// `kdf_params` in the (signed) manifest body do not equal the
    /// `[kdf]` block in the (cleartext) `vault.toml`. The duplication
    /// is the load-bearing tamper-detection surface for `vault.toml`:
    /// per §4.2 line 205, "a modified vault.toml cannot trick a reader
    /// into deriving a wrong master_kek without also producing an
    /// invalid manifest signature". Without this comparison a
    /// malicious cloud host could swap memory_kib for a DoS or
    /// swap the salt to confuse the user; the manifest signature
    /// attests to the real params, but only this check actually
    /// rejects the swap.
    #[error("manifest kdf_params do not match vault.toml [kdf]")]
    KdfParamsMismatch,

    /// A vector-clock per-device counter would overflow `u64::MAX` on
    /// `tick_clock`. The §10 rollback-resistance check is order-only
    /// on per-device counters; a `saturating_add` would silently
    /// freeze a maxed-out counter and `is_rollback` would then declare
    /// two distinct writes "Equal". Practical reachability is zero
    /// (~10¹¹ years at one write/ns) but a typed surface keeps the
    /// invariant explicit.
    #[error("vector-clock overflow on device {device_uuid:?}")]
    ClockOverflow { device_uuid: [u8; 16] },

    /// [`share_block`] precondition: the caller is not the block's
    /// original author. PR-B's share_block is "author-only re-sign" —
    /// adding a recipient extends the §6.2 recipient table, which is
    /// inside the §6.1 signed range, so the new block file must carry
    /// a fresh author signature. Re-signing with a different identity
    /// would silently change `author_fingerprint`; rejecting up-front
    /// keeps that boundary explicit. The "share-as-fork" path
    /// (decrypt → mint a new author block) is a future PR.
    #[error("share_block: caller is not the block author. expected {expected:?}, got {got:?}")]
    NotAuthor {
        expected: crate::identity::fingerprint::Fingerprint,
        got: crate::identity::fingerprint::Fingerprint,
    },

    /// [`share_block`] precondition: no manifest entry for the
    /// requested `block_uuid`. Catches typos and stale UUIDs from a
    /// caller that read the manifest and then dropped the matching
    /// entry between read and call.
    #[error("share_block: block {block_uuid:?} not found in manifest")]
    BlockNotFound { block_uuid: [u8; 16] },

    /// [`share_block`] precondition: the new recipient's contact-card
    /// fingerprint already appears in the block's recipient table.
    /// Re-issuing a wrap for the same recipient would either no-op or
    /// silently rotate their wrap; the orchestrator refuses both and
    /// surfaces this distinct error so the caller can treat it as a UI
    /// affordance ("they already have access") rather than a generic
    /// error.
    #[error("share_block: recipient is already in the block's recipient list")]
    RecipientAlreadyPresent,

    /// The caller asked to revoke a recipient that is not currently a
    /// recipient of the block (absent from the §6.2 wire table / the
    /// manifest `BlockEntry.recipients`). Symmetric with
    /// [`Self::RecipientAlreadyPresent`]. Surfaced by `revoke_block_recipient`.
    #[error("recipient is not present on the block")]
    RecipientNotPresent,

    /// The caller asked to revoke the block owner/author. The owner is
    /// always a recipient of a shareable block (`share_block` decrypts
    /// under the author's reader identity, `NotARecipient` otherwise),
    /// so re-keying without them would brick the block — no
    /// future decrypt-as-author for re-key / re-share. Surfaced by
    /// `revoke_block_recipient`, which rejects this up-front.
    #[error("cannot revoke the block owner")]
    CannotRevokeOwner,

    /// [`share_block`] precondition: the supplied `existing_recipients`
    /// list does not include a card whose fingerprint matches a wrap
    /// in the block. The orchestrator rebuilds the new block by re-
    /// encrypting under the union of existing + new recipient cards;
    /// it cannot reconstruct a wrap for a recipient whose card it has
    /// not been given. The caller is expected to source recipient
    /// cards from the manifest's `BlockEntry.recipients` list
    /// (contact UUIDs) → the on-disk `contacts/<uuid>.card` files; the
    /// orchestrator does not read them itself today (Task 13 scope).
    #[error("share_block: existing recipient with fingerprint {fingerprint:?} is missing from the supplied recipient cards list")]
    MissingRecipientCard {
        fingerprint: crate::identity::fingerprint::Fingerprint,
    },

    /// trash_block / restore_block precondition: the requested
    /// `block_uuid` exists in `manifest.trash` but also exists in
    /// `manifest.blocks`. Restore would produce a duplicate entry. The
    /// caller MUST trash the live copy first, then restore the trashed
    /// one. See `docs/vault-format.md` §7.1 "Restoring a block".
    #[error(
        "block {block_uuid:?} is currently live and trashed; trash the live copy before restoring"
    )]
    BlockUuidAlreadyLive { block_uuid: [u8; 16] },

    /// `restore_block` precondition: no file matching
    /// `trash/<uuid>.cbor.enc.*` was found AND no `TrashEntry` exists in
    /// `manifest.trash` for this UUID. (Both conditions are required —
    /// the spec keeps the file and the manifest entry paired; one
    /// without the other is also a `BlockNotInTrash`.)
    #[error("block {block_uuid:?} is not in trash")]
    BlockNotInTrash { block_uuid: [u8; 16] },

    /// `restore_block` step 3: the trashed block file failed §6.1 hybrid
    /// signature verification or AEAD decrypt. An attacker with write
    /// access to `trash/` planted a corrupt or forged file. The
    /// manifest is NOT modified and `trash/` is NOT modified — the
    /// caller can decide between purge-without-restore and forensic
    /// capture.
    #[error("trashed block {block_uuid:?} failed verification: {detail}")]
    RestoreVerificationFailed {
        block_uuid: [u8; 16],
        detail: String,
    },

    /// No `devices/<device-uuid>.wrap` file found for the requested device
    /// (ADR 0009 / vault-format §3a). Returned by
    /// [`device_slot::open_identity_with_device_secret`] and
    /// [`device_slot::remove_device_slot`] when the wrap file is absent.
    /// Distinct from a generic I/O error so callers can distinguish
    /// "device never enrolled / already revoked" from "disk failure".
    #[error("device slot not found")]
    DeviceSlotNotFound,

    /// Added in C.1.1b: per-block fingerprint check inside
    /// [`open_vault`] detected that an on-disk block file's bytes do
    /// not BLAKE3-256-hash to the value committed in the manifest's
    /// `BlockEntry.fingerprint`. The manifest's own hybrid signature
    /// has already verified by the time this fires, so the disagreement
    /// is between the (signed) manifest and the (unsigned-at-the-
    /// envelope-level) block file.
    ///
    /// The most common cause is a crash between the block-file write
    /// and the manifest write inside `commit_with_decisions` (a partial
    /// commit). Recovery: re-run the three-step
    /// `sync_once → prepare_merge → commit_with_decisions` flow; CRDT
    /// idempotence guarantees the same final state once both writes
    /// land. The less-common cause is tamper / on-disk corruption — in
    /// either case the error is loud rather than silent.
    #[error(
        "block {block_uuid:02x?} fingerprint mismatch: manifest expected {expected:02x?}, \
         disk has {got:02x?}"
    )]
    BlockFingerprintMismatch {
        block_uuid: [u8; 16],
        expected: [u8; 32],
        got: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_fingerprint_mismatch_display_is_stable() {
        let err = VaultError::BlockFingerprintMismatch {
            block_uuid: [0x01; 16],
            expected: [0x02; 32],
            got: [0x03; 32],
        };
        let s = format!("{err}");
        // Tag the substrings we want long-term consumers (logs, CLIs) to
        // be able to grep for. Avoid pinning the exact concatenation so
        // a future cosmetic tweak of the message body does not turn
        // into a breaking API change.
        assert!(s.contains("fingerprint mismatch"));
        assert!(s.contains("01"));
        assert!(s.contains("02"));
        assert!(s.contains("03"));
    }
}
