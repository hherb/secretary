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
pub(crate) mod io;
pub mod manifest;
mod orchestrators;
pub mod record;

pub use block::{
    decode_block_file, decrypt_block, encode_block_file, encrypt_block, BlockError, BlockFile,
    BlockHeader, BlockPlaintext, RecipientPublicKeys, RecipientWrap, VectorClockEntry,
    FILE_KIND_BLOCK, RECIPIENT_ENTRY_LEN,
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
pub use orchestrators::{create_vault, open_vault, save_block, share_block, OpenVault, Unlocker};
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
    OwnerUuidMismatch {
        vault: [u8; 16],
        found: [u8; 16],
    },

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
    ManifestVaultUuidMismatch {
        header: [u8; 16],
        body: [u8; 16],
    },

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
}
