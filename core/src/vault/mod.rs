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
//! The PR-B orchestrators ([`create_vault`] today; `open_vault`,
//! `save_block`, `share_block` in subsequent tasks) compose the lower
//! pure-function layers into a single side-effecting entry point per
//! user-visible operation. They live inline at the bottom of this
//! module rather than in a sub-file because the four-function total is
//! small enough to keep navigation easy. If `mod.rs` grows past
//! ~600 LoC, split into `vault/orchestrators.rs`.

pub mod block;
pub(crate) mod canonical;
pub(crate) mod io;
pub mod manifest;
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

// ---------------------------------------------------------------------------
// PR-B orchestrators
// ---------------------------------------------------------------------------
//
// These functions compose `unlock::*`, `manifest::*`, `block::*`,
// `identity::card::*`, and `vault::io::*` into the four user-visible
// vault operations. They are the only place inside the crate where:
//   1. Multiple lower-layer steps are sequenced under a single error
//      type ([`VaultError`]); and
//   2. Disk I/O happens in support of the format. Unit-level pure
//      functions never touch the filesystem; orchestrators do.
//
// Discipline: each orchestrator is a free function (no hidden state),
// takes a `&mut (impl RngCore + CryptoRng)` for any randomness it
// needs, and returns its result by value. Atomic-write semantics are
// inherited from [`io::write_atomic`].

use std::path::Path;

use rand_core::{CryptoRng, RngCore};

use crate::crypto::aead::AEAD_TAG_LEN;
use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::kdf::Argon2idParams;
use crate::crypto::kem::MlKem768Public;
use crate::crypto::secret::{SecretBytes, Sensitive};
use crate::crypto::sig::{Ed25519Secret, MlDsa65Public, MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN};
use crate::identity::card::{ContactCard, CARD_VERSION_V1};
use crate::identity::fingerprint::fingerprint;
use crate::unlock::{self, bundle::IdentityBundle, mnemonic::Mnemonic, vault_toml};

/// Filename of the cleartext metadata file (§2 / vault-format.md §1).
const VAULT_TOML_FILENAME: &str = "vault.toml";

/// Filename of the encrypted dual-wrapped identity bundle file
/// (§3 / vault-format.md §1).
const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";

/// Filename of the encrypted, signed manifest (§4 / vault-format.md §1).
const MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// Subdirectory holding imported / owner contact cards
/// (vault-format.md §1, §5).
const CONTACTS_SUBDIR: &str = "contacts";

/// Subdirectory holding encrypted block files
/// (vault-format.md §1, §6.1).
const BLOCKS_SUBDIR: &str = "blocks";

/// Format a 16-byte UUID as canonical lowercase 8-4-4-4-12 hex
/// (`docs/vault-format.md` §1).
///
/// Pure helper; no allocation other than the returned `String`. The
/// dashed grouping is normative for `<contact-uuid>.card` and
/// `<block-uuid>.cbor.enc` filenames.
fn format_uuid_hyphenated(uuid: &[u8; 16]) -> String {
    let mut s = String::with_capacity(36);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in uuid.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Validate that `folder` exists, is a directory, and contains no
/// entries — the precondition for [`create_vault`]. Returns the canonical
/// `VaultError::Io` on any check failure.
///
/// The "empty" check protects the user from accidentally aiming
/// [`create_vault`] at a directory that already holds unrelated files
/// (or worse, a different vault). It does NOT examine `..`/`.` —
/// `read_dir` filters those.
fn ensure_empty_directory(folder: &Path) -> Result<(), VaultError> {
    let meta = std::fs::metadata(folder).map_err(|e| VaultError::Io {
        context: "vault folder does not exist or is unreadable",
        source: e,
    })?;
    if !meta.is_dir() {
        return Err(VaultError::Io {
            context: "vault folder path is not a directory",
            source: std::io::Error::new(
                std::io::ErrorKind::NotADirectory,
                "expected an empty directory",
            ),
        });
    }
    let mut entries = std::fs::read_dir(folder).map_err(|e| VaultError::Io {
        context: "failed to read vault folder",
        source: e,
    })?;
    if entries.next().is_some() {
        return Err(VaultError::Io {
            context: "vault folder is not empty",
            source: std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "expected an empty directory",
            ),
        });
    }
    Ok(())
}

/// Build, sign, and canonical-encode the owner's [`ContactCard`] from a
/// freshly-generated [`unlock::bundle::IdentityBundle`].
///
/// The card embeds the four public keys plus the user UUID, display
/// name, and creation timestamp; the §6 self-signature is produced
/// with the bundle's matching secret keys. Returns the canonical-CBOR
/// bytes ready to write to `contacts/<owner-uuid>.card`.
///
/// Pure-ish: takes a `&IdentityBundle`, returns `(card, bytes)`. No
/// I/O. The caller is responsible for placing the bytes on disk.
fn build_owner_card_from_bundle(
    identity: &unlock::bundle::IdentityBundle,
) -> Result<(ContactCard, Vec<u8>), VaultError> {
    // Reconstruct the typed PQ secret-key wrapper from the bundle's
    // raw seed bytes. `MlDsa65Secret::from_bytes` validates the length
    // (32 B for the seed) and surfaces SigError on mismatch — the
    // bundle invariant guarantees the right size, but the typed wrap
    // is what `card.sign` accepts.
    let pq_sk = MlDsa65Secret::from_bytes(identity.ml_dsa_65_sk.expose())?;

    let mut card = ContactCard {
        card_version: CARD_VERSION_V1,
        contact_uuid: identity.user_uuid,
        display_name: identity.display_name.clone(),
        x25519_pk: identity.x25519_pk,
        ml_kem_768_pk: identity.ml_kem_768_pk.clone(),
        ed25519_pk: identity.ed25519_pk,
        ml_dsa_65_pk: identity.ml_dsa_65_pk.clone(),
        created_at_ms: identity.created_at_ms,
        // Placeholders until `card.sign(...)` overwrites them. The
        // pre-sig `signed_bytes()` view does not look at these fields,
        // so the placeholder values are irrelevant to the signed
        // message.
        self_sig_ed: [0u8; ED25519_SIG_LEN],
        self_sig_pq: vec![0u8; ML_DSA_65_SIG_LEN],
    };
    card.sign(&identity.ed25519_sk, &pq_sk)?;
    let bytes = card.to_canonical_cbor()?;
    Ok((card, bytes))
}

/// Create a brand-new vault on disk in `folder`.
///
/// `folder` MUST already exist as an empty directory. The function
/// errors if the directory is missing, is not a directory, or contains
/// any entries. (The empty-directory precondition keeps the
/// orchestrator from clobbering an unrelated folder; the caller is the
/// right layer to choose between "create the directory if it doesn't
/// exist" and "fail loudly".)
///
/// On success, the four canonical files of an empty vault are written
/// atomically (per `docs/vault-format.md` §9):
///
/// - `vault.toml`            — cleartext §2 metadata
/// - `identity.bundle.enc`   — encrypted, dual-wrapped identity (§3)
/// - `manifest.cbor.enc`     — encrypted, signed empty manifest (§4)
/// - `contacts/<owner-uuid-hyphenated>.card` — owner's self-signed
///   contact card (§5)
///
/// The `contacts/` subdirectory is created if it does not exist.
///
/// Returns the freshly-generated 24-word recovery mnemonic. It is the
/// user's only recovery path if the password is lost — the caller is
/// responsible for displaying it to the user once and never persisting
/// it. The mnemonic's [`Drop`] impl zeroes its in-memory phrase when
/// the value is dropped.
///
/// `kdf_params` is checked against the v1 floor by [`unlock::create_vault`]:
/// sub-floor parameters return [`VaultError::Unlock`] wrapping
/// [`unlock::UnlockError::WeakKdfParams`]. Tests that need fast Argon2id
/// can call [`unlock::create_vault_unchecked`] directly through their
/// own ad-hoc orchestrator; this function is the production entry
/// point and refuses weak parameters.
pub fn create_vault(
    folder: &Path,
    password: &SecretBytes,
    display_name: &str,
    kdf_params: Argon2idParams,
    created_at_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Mnemonic, VaultError> {
    // Step 1: validate the destination folder. Doing this before any
    // crypto means a bad path is rejected without burning an Argon2id
    // run.
    ensure_empty_directory(folder)?;

    // Step 2: run the §3/§4/§5 unlock orchestrator. This generates
    // identifiers, runs Argon2id, derives the IBK, and emits
    // canonical bytes for `vault.toml` and `identity.bundle.enc`. We
    // route through the v1-floor-enforcing entry point on purpose;
    // tests that need fast KDF call `unlock::create_vault_unchecked`
    // by hand.
    let created =
        unlock::create_vault(password, display_name, created_at_ms, kdf_params, rng)?;

    // Step 3: re-parse vault.toml to recover `vault_uuid` and the
    // 32-byte Argon2id `salt`. Both are needed for the manifest's
    // `kdf_params` mirror (§4.2 line 205) and the manifest header
    // (§4.1). We do not thread these through `CreatedVault`'s API to
    // keep that struct's surface stable across PR-B; parsing the
    // 8-field TOML once is cheap. Any malformed-TOML failure here is
    // a bug in `unlock::create_vault`, not user input — but using the
    // `?` chain through `VaultError::Unlock` keeps the diagnostic
    // path uniform.
    let vt_str = std::str::from_utf8(&created.vault_toml_bytes).map_err(|_| {
        VaultError::Unlock(crate::unlock::UnlockError::MalformedVaultToml(
            crate::unlock::vault_toml::VaultTomlError::MalformedToml(
                "internal: emitted vault.toml is not UTF-8".to_string(),
            ),
        ))
    })?;
    let vt = vault_toml::decode(vt_str).map_err(crate::unlock::UnlockError::from)?;

    // Step 4: build the owner's self-signed contact card and compute
    // its 16-byte fingerprint. The fingerprint is the manifest's
    // `author_fingerprint` field (§4.1) — the manifest signature
    // attests that the owner authored the (empty) initial state.
    let (_owner_card, owner_card_bytes) = build_owner_card_from_bundle(&created.identity)?;
    let author_fingerprint = fingerprint(&owner_card_bytes);

    // Step 5: build an empty Manifest (§4.2). All the per-vault
    // identifiers come from the vault.toml we just emitted; the
    // KdfParamsRef mirrors the Argon2id parameters so the manifest
    // signature attests to them.
    let manifest = Manifest {
        manifest_version: 1,
        vault_uuid: vt.vault_uuid,
        format_version: crate::version::FORMAT_VERSION,
        suite_id: crate::version::SUITE_ID,
        owner_user_uuid: created.identity.user_uuid,
        vector_clock: Vec::new(),
        blocks: Vec::new(),
        trash: Vec::new(),
        kdf_params: KdfParamsRef {
            memory_kib: vt.kdf.memory_kib,
            iterations: vt.kdf.iterations,
            parallelism: vt.kdf.parallelism,
            salt: vt.kdf.salt,
        },
        unknown: std::collections::BTreeMap::new(),
    };

    // Step 6: build the manifest binary header. `last_mod_ms` equals
    // `created_at_ms` because no edits exist yet — the moment of
    // creation is also the moment of the last (only) modification.
    let manifest_header = ManifestHeader {
        vault_uuid: vt.vault_uuid,
        created_at_ms,
        last_mod_ms: created_at_ms,
    };

    // Step 7: fresh 24-byte AEAD nonce for the manifest body. Drawn
    // from the same RNG `unlock::create_vault` consumed; tests pin
    // determinism via a seeded ChaCha20Rng so this nonce is stable
    // across re-runs of the same seed.
    let mut aead_nonce = [0u8; 24];
    rng.fill_bytes(&mut aead_nonce);

    // Step 8: reconstruct the typed ML-DSA-65 secret-key wrapper for
    // signing. `card.sign` and `sign_manifest` both consume the
    // typed form rather than raw seed bytes. Length validation is
    // enforced by `from_bytes`.
    let pq_sk = MlDsa65Secret::from_bytes(created.identity.ml_dsa_65_sk.expose())?;

    // Step 9: hybrid-sign the manifest. `sign_manifest` canonical-
    // encodes the body, AEAD-encrypts it under the IBK with the
    // header AAD, and produces both Ed25519 and ML-DSA-65 signatures
    // (§8 step 6).
    let manifest_file = manifest::sign_manifest(
        manifest_header,
        &manifest,
        &created.identity_block_key,
        &aead_nonce,
        author_fingerprint,
        &created.identity.ed25519_sk,
        &pq_sk,
    )?;

    // Step 10: encode the on-disk manifest envelope (§4.1).
    let manifest_file_bytes = manifest::encode_manifest_file(&manifest_file)?;

    // Step 11: ensure `contacts/` exists, then atomically write all
    // four files. Order does not affect correctness (each write is
    // atomic in isolation), but writing the manifest last mirrors the
    // PR-B convention: blocks first, manifest second, so a crash mid-
    // sequence leaves a stale manifest pointing at a fresh block —
    // the recovery direction we want.
    let contacts_dir = folder.join(CONTACTS_SUBDIR);
    std::fs::create_dir_all(&contacts_dir).map_err(|e| VaultError::Io {
        context: "failed to create contacts/ subdirectory",
        source: e,
    })?;
    let owner_uuid_hex = format_uuid_hyphenated(&created.identity.user_uuid);
    let owner_card_path = contacts_dir.join(format!("{owner_uuid_hex}.card"));
    let vault_toml_path = folder.join(VAULT_TOML_FILENAME);
    let identity_bundle_path = folder.join(IDENTITY_BUNDLE_FILENAME);
    let manifest_path = folder.join(MANIFEST_FILENAME);

    io::write_atomic(&vault_toml_path, &created.vault_toml_bytes).map_err(|e| {
        VaultError::Io {
            context: "failed to write vault.toml",
            source: e,
        }
    })?;
    io::write_atomic(&identity_bundle_path, &created.identity_bundle_bytes).map_err(|e| {
        VaultError::Io {
            context: "failed to write identity.bundle.enc",
            source: e,
        }
    })?;
    io::write_atomic(&owner_card_path, &owner_card_bytes).map_err(|e| VaultError::Io {
        context: "failed to write owner contact card",
        source: e,
    })?;
    io::write_atomic(&manifest_path, &manifest_file_bytes).map_err(|e| VaultError::Io {
        context: "failed to write manifest.cbor.enc",
        source: e,
    })?;

    Ok(created.recovery_mnemonic)
}

// ---------------------------------------------------------------------------
// open_vault — Task 11
// ---------------------------------------------------------------------------

/// Caller's choice of unlock path for [`open_vault`].
///
/// The two variants mirror the two §3 / §4 unlock entry points in the
/// `unlock` module. `Password` is the day-to-day path; `Recovery` is
/// the lost-password path that derives the same Identity Block Key
/// from the 24-word BIP-39 mnemonic returned by [`create_vault`].
///
/// The variants borrow rather than own — `open_vault` is a one-shot
/// call and the caller already holds the secrets (a `SecretBytes`
/// password or a stack-allocated `String` mnemonic). Avoiding moves
/// lets the caller keep the values for retry or logging without
/// cloning.
pub enum Unlocker<'a> {
    /// User-supplied master password. Routes through
    /// [`unlock::open_with_password`].
    Password(&'a SecretBytes),
    /// 24-word BIP-39 recovery mnemonic. Routes through
    /// [`unlock::open_with_recovery`]. The string is whitespace-
    /// tolerant — [`unlock::mnemonic::parse`] splits on ASCII
    /// whitespace.
    Recovery(&'a str),
}

/// Live, in-memory state after a successful [`open_vault`].
///
/// The handle owns the Identity Block Key (sensitive; zeroized on
/// drop), the [`IdentityBundle`] (carries owner-side secret keys —
/// also zeroized on drop), the verified owner [`ContactCard`], the
/// decrypted [`Manifest`] body, and the on-disk
/// [`ManifestFile`] envelope. The latter two are kept so that
/// `save_block` (Task 12) and `share_block` (Task 13) can extend the
/// existing manifest without re-reading the file.
///
/// `open_vault` is a plain handle — no I/O is hidden behind it. Once
/// returned, the caller has everything needed to either inspect the
/// manifest or hand the handle to the next orchestrator.
pub struct OpenVault {
    /// 32-byte Identity Block Key. Same `Sensitive<[u8; 32]>` type
    /// that [`unlock::UnlockedIdentity`] returns; dropping the
    /// `OpenVault` zeroizes the wrapped bytes.
    pub identity_block_key: Sensitive<[u8; 32]>,
    /// Owner-side identity bundle (carries the four secret keys).
    pub identity: IdentityBundle,
    /// Owner's self-signed contact card, loaded from
    /// `contacts/<owner_uuid>.card` and self-verified before use.
    pub owner_card: ContactCard,
    /// Decrypted manifest body (§4.2).
    pub manifest: Manifest,
    /// On-disk manifest envelope (§4.1) — header, AEAD nonce, AEAD
    /// ct/tag, author fingerprint, and the §8 hybrid signature. Kept
    /// so subsequent orchestrators can re-sign on update.
    pub manifest_file: ManifestFile,
}

/// Redacted Debug for [`OpenVault`] — mirrors the no-leak-via-Debug
/// policy used by [`unlock::UnlockedIdentity`]. The IBK is the
/// symmetric root secret; the [`IdentityBundle`] carries the four
/// secret keys (its own Debug already redacts). `owner_card`,
/// `manifest`, and `manifest_file` are public material and printed
/// normally.
impl std::fmt::Debug for OpenVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenVault")
            .field("identity_block_key", &"<redacted>")
            .field("identity", &self.identity)
            .field("owner_card", &self.owner_card)
            .field("manifest", &self.manifest)
            .field("manifest_file", &self.manifest_file)
            .finish()
    }
}

/// Open an existing vault at `folder`.
///
/// Sequence (mirrors `docs/vault-format.md` §1 read order):
/// 1. Read `vault.toml` and `identity.bundle.enc` from `folder`.
/// 2. Unlock via `unlocker` — either [`unlock::open_with_password`]
///    or [`unlock::open_with_recovery`]. Both surface as
///    [`VaultError::Unlock`] on failure.
/// 3. Read `manifest.cbor.enc`.
/// 4. Decode the §4.1 envelope via [`manifest::decode_manifest_file`].
/// 5. Load the owner contact card from
///    `contacts/<owner_uuid_hyphenated>.card` (lowercase 8-4-4-4-12
///    hex; matches [`create_vault`]'s output). Self-verify the card
///    via [`ContactCard::verify_self`] — defence-in-depth, since the
///    card is a self-signed structure and its embedded public keys
///    drive step 6.
/// 6. **Verify before decrypt.** Verify the §8 hybrid signature on
///    the manifest envelope using the owner card's `ed25519_pk` and
///    `ml_dsa_65_pk`. Catches a tampered ciphertext / tag / header
///    *before* we reveal anything to the AEAD primitive.
/// 7. AEAD-decrypt the manifest body via
///    [`manifest::decrypt_manifest_body`] using the unlocked Identity
///    Block Key.
/// 8. If `local_highest_clock` is `Some`, run [`manifest::is_rollback`]
///    against the decrypted manifest's `vector_clock`. Returns
///    [`VaultError::Rollback`] when the incoming clock is strictly
///    dominated. Pass `None` to skip the check (e.g. on a fresh
///    install where no highest-seen clock exists yet — the OS-keystore
///    layer is responsible for tracking it; out of scope for this
///    function).
///
/// Sanity checks:
/// - The owner card's `contact_uuid` must equal
///   `identity.user_uuid`. Mismatch → [`VaultError::OwnerUuidMismatch`].
/// - The manifest envelope's `author_fingerprint` must equal the
///   fingerprint of the loaded owner card. Mismatch →
///   [`VaultError::ManifestAuthorMismatch`].
/// - The decrypted manifest's `owner_user_uuid` must equal
///   `identity.user_uuid`. Mismatch → [`VaultError::OwnerUuidMismatch`].
///
/// On success, returns an [`OpenVault`] handle. The handle owns
/// sensitive material; drop it once the caller is done so the
/// zeroizing destructors run.
pub fn open_vault(
    folder: &Path,
    unlocker: Unlocker<'_>,
    local_highest_clock: Option<&[VectorClockEntry]>,
) -> Result<OpenVault, VaultError> {
    // Step 1: read vault.toml + identity.bundle.enc
    let vault_toml_path = folder.join(VAULT_TOML_FILENAME);
    let identity_bundle_path = folder.join(IDENTITY_BUNDLE_FILENAME);
    let vault_toml_bytes = std::fs::read(&vault_toml_path).map_err(|e| VaultError::Io {
        context: "failed to read vault.toml",
        source: e,
    })?;
    let identity_bundle_bytes =
        std::fs::read(&identity_bundle_path).map_err(|e| VaultError::Io {
            context: "failed to read identity.bundle.enc",
            source: e,
        })?;

    // Step 2: unlock the identity bundle. Either path produces an
    // UnlockedIdentity carrying the IBK (Sensitive<[u8;32]>) and the
    // owner-side IdentityBundle. Errors propagate via VaultError::Unlock.
    let unlocked = match unlocker {
        Unlocker::Password(p) => {
            unlock::open_with_password(&vault_toml_bytes, &identity_bundle_bytes, p)?
        }
        Unlocker::Recovery(words) => {
            unlock::open_with_recovery(&vault_toml_bytes, &identity_bundle_bytes, words)?
        }
    };

    // Step 3-4: read + decode the §4.1 manifest envelope.
    let manifest_path = folder.join(MANIFEST_FILENAME);
    let manifest_file_bytes = std::fs::read(&manifest_path).map_err(|e| VaultError::Io {
        context: "failed to read manifest.cbor.enc",
        source: e,
    })?;
    let manifest_file = manifest::decode_manifest_file(&manifest_file_bytes)?;

    // Step 5: load + self-verify the owner contact card. The owner
    // UUID lives inside the IdentityBundle (which we have from step
    // 2); using it here avoids a chicken-and-egg with the still-
    // encrypted manifest body.
    let owner_uuid_hex = format_uuid_hyphenated(&unlocked.identity.user_uuid);
    let owner_card_path = folder
        .join(CONTACTS_SUBDIR)
        .join(format!("{owner_uuid_hex}.card"));
    let owner_card_bytes = std::fs::read(&owner_card_path).map_err(|e| VaultError::Io {
        context: "failed to read owner contact card",
        source: e,
    })?;
    let owner_card = ContactCard::from_canonical_cbor(&owner_card_bytes)?;
    owner_card.verify_self()?;

    // Sanity: owner card's UUID matches the IdentityBundle. The
    // filename uses the same UUID, so a mismatch here would only fire
    // on a deliberately-mis-named card placed in `contacts/`.
    if owner_card.contact_uuid != unlocked.identity.user_uuid {
        return Err(VaultError::OwnerUuidMismatch {
            vault: unlocked.identity.user_uuid,
            found: owner_card.contact_uuid,
        });
    }

    // Sanity: manifest envelope's author_fingerprint matches the
    // computed fingerprint of the loaded owner card. The manifest
    // signature verifies under the card's public keys (next step), but
    // a successful verify against a *different* card whose keys
    // happened to match would still leave this guard firing — and the
    // common-case failure is a folder assembled from mismatched
    // pieces, which we want to flag loudly.
    let owner_fp = fingerprint(&owner_card_bytes);
    if manifest_file.author_fingerprint != owner_fp {
        return Err(VaultError::ManifestAuthorMismatch);
    }

    // Step 6: verify-then-decrypt. Verify the §8 hybrid signature on
    // the envelope using the owner card's two public keys. If this
    // rejects, we bail without attempting AEAD decrypt — the security
    // discipline is "verify before decrypt" so a tampered ciphertext
    // never reaches the primitive.
    let pk_pq = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)?;
    manifest::verify_manifest(&manifest_file, &owner_card.ed25519_pk, &pk_pq)?;

    // Step 7: AEAD-decrypt the manifest body. Reassemble (ct || tag)
    // from the split fields in the on-disk envelope; that's the wire
    // shape decrypt_manifest_body expects.
    let mut ct_with_tag =
        Vec::with_capacity(manifest_file.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&manifest_file.aead_ct);
    ct_with_tag.extend_from_slice(&manifest_file.aead_tag);
    let manifest_body = manifest::decrypt_manifest_body(
        &manifest_file.header,
        &ct_with_tag,
        &unlocked.identity_block_key,
        &manifest_file.aead_nonce,
    )?;

    // Sanity: manifest body's owner_user_uuid matches the unlocked
    // identity. The signature already commits to the body, so this is
    // belt-and-braces against a pathological key reuse where two
    // identities accidentally produced verifying signatures over
    // different bodies — but it costs one comparison and removes a
    // class of "looked OK to crypto, but is not this user's vault"
    // surprises at higher layers.
    if manifest_body.owner_user_uuid != unlocked.identity.user_uuid {
        return Err(VaultError::OwnerUuidMismatch {
            vault: unlocked.identity.user_uuid,
            found: manifest_body.owner_user_uuid,
        });
    }

    // §4.3 step 5 cross-check: the encrypted body's vault_uuid must
    // equal the (AAD-bound) header's vault_uuid. AEAD AAD already
    // binds the header to the body, so a successful decrypt implies
    // the AAD-as-encrypted equals the header bytes we passed; this
    // explicit equality is defence-in-depth for a future v2 layout
    // that could decouple AAD from header.
    if manifest_body.vault_uuid != manifest_file.header.vault_uuid {
        return Err(VaultError::ManifestVaultUuidMismatch {
            header: manifest_file.header.vault_uuid,
            body: manifest_body.vault_uuid,
        });
    }

    // §4.3 step 6 cross-check: the manifest body carries a duplicate
    // copy of vault.toml's [kdf] block precisely so the manifest
    // signature attests to the parameters used to derive master_kek
    // (§4.2 line 205). Without this comparison a malicious cloud host
    // could swap memory_kib (DoS), iterations, parallelism, or salt in
    // vault.toml and the user would derive a different — but
    // signature-valid — manifest with no warning. Re-parse vault.toml
    // here rather than threading the parsed form through unlock to
    // keep the check local and unambiguous.
    let vt_str = std::str::from_utf8(&vault_toml_bytes).map_err(|_| VaultError::Unlock(
        crate::unlock::UnlockError::MalformedVaultToml(
            crate::unlock::vault_toml::VaultTomlError::MalformedToml(
                "vault.toml is not valid UTF-8".to_string(),
            ),
        ),
    ))?;
    let vt = vault_toml::decode(vt_str).map_err(|e| {
        VaultError::Unlock(crate::unlock::UnlockError::MalformedVaultToml(e))
    })?;
    if manifest_body.kdf_params.memory_kib != vt.kdf.memory_kib
        || manifest_body.kdf_params.iterations != vt.kdf.iterations
        || manifest_body.kdf_params.parallelism != vt.kdf.parallelism
        || manifest_body.kdf_params.salt != vt.kdf.salt
    {
        return Err(VaultError::KdfParamsMismatch);
    }

    // Step 8: §10 rollback resistance. The OS-keystore layer holds the
    // per-vault highest-seen clock; this function is agnostic about
    // where it comes from. Pass `None` to skip the check (no clock
    // recorded yet).
    if let Some(local) = local_highest_clock {
        if manifest::is_rollback(local, &manifest_body.vector_clock) {
            return Err(VaultError::Rollback {
                local_clock: local.to_vec(),
                incoming_clock: manifest_body.vector_clock.clone(),
            });
        }
    }

    Ok(OpenVault {
        identity_block_key: unlocked.identity_block_key,
        identity: unlocked.identity,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    })
}

// ---------------------------------------------------------------------------
// save_block — Task 12
// ---------------------------------------------------------------------------

/// Tick a vector clock for `device_uuid`: increment its existing counter, or
/// insert a new entry at counter 1 if absent. Pure helper shared by both the
/// block-level and manifest-level clocks. The output is left unsorted; the
/// canonical-CBOR encoders sort on emit so in-memory order doesn't matter.
fn tick_clock(clock: &mut Vec<VectorClockEntry>, device_uuid: &[u8; 16]) {
    if let Some(entry) = clock.iter_mut().find(|e| &e.device_uuid == device_uuid) {
        entry.counter = entry.counter.saturating_add(1);
    } else {
        clock.push(VectorClockEntry {
            device_uuid: *device_uuid,
            counter: 1,
        });
    }
}

/// Encrypt and persist a new (or updated) block in the vault.
///
/// Updates the in-memory `OpenVault.manifest` and `OpenVault.manifest_file`,
/// then re-writes both `blocks/<uuid>.cbor.enc` and `manifest.cbor.enc`
/// atomically. The block file is written FIRST and the manifest SECOND
/// (`docs/vault-format.md` §9 line 430): a crash between leaves a fresh
/// orphan block plus a stale manifest — recoverable on next open by either
/// retrying the save or trimming the orphan.
///
/// Recipients are public-key holders who can decrypt the block. The
/// caller's own owner card is NOT automatically included — pass it
/// explicitly if the caller should be a recipient (this matches the
/// "send-only mode" semantics where the owner can encrypt for others
/// without keeping a copy themselves). [`encrypt_block`] rejects an empty
/// recipient list with [`BlockError::EmptyRecipientList`].
///
/// `device_uuid` identifies the writing device. This device's counter in
/// both the block's vector clock AND the manifest's vault-level vector
/// clock is incremented by 1 (or inserted at 1 if previously absent).
///
/// The block's `block_uuid` is taken from `plaintext.block_uuid` — the
/// caller is responsible for generating it. If a block with the same
/// `block_uuid` already exists in the manifest, this call replaces it
/// in-place (same UUID = update); otherwise a new entry is appended.
/// The block's `created_at_ms` is preserved across updates from the
/// existing manifest entry; for a brand-new block, `now_ms` is used.
///
/// `now_ms` stamps:
/// - The new `BlockEntry.last_mod_ms`,
/// - The new `BlockEntry.created_at_ms` (only on first save),
/// - The manifest header's `last_mod_ms`,
/// - The block header's `last_mod_ms` (the block-level header is rebuilt
///   in full from `plaintext`'s metadata; `created_at_ms` carries the
///   block-entry value).
///
/// `rng` is consumed for: the block's BCK, every per-recipient KEM encap,
/// the block's body AEAD nonce, and the manifest's body AEAD nonce. Pass
/// `rand_core::OsRng` in production.
pub fn save_block(
    folder: &Path,
    open: &mut OpenVault,
    plaintext: BlockPlaintext,
    recipients: &[ContactCard],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    // Determine whether this is an update (preserve created_at_ms and
    // continue the per-block clock from the existing manifest entry) or
    // a fresh insert (created_at_ms = now_ms, empty starting clock).
    let existing_idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == plaintext.block_uuid);
    let (block_created_at_ms, mut block_clock) = match existing_idx {
        Some(i) => (
            open.manifest.blocks[i].created_at_ms,
            open.manifest.blocks[i].vector_clock_summary.clone(),
        ),
        None => (now_ms, Vec::new()),
    };

    // Step 1: tick the block-level vector clock for this device.
    tick_clock(&mut block_clock, &device_uuid);

    // Step 2: build the §6.1 block header. The header's vector_clock
    // mirrors the block-entry summary so a single-author write produces
    // identical clocks at both layers.
    let header = BlockHeader {
        magic: crate::version::MAGIC,
        format_version: crate::version::FORMAT_VERSION,
        suite_id: crate::version::SUITE_ID,
        file_kind: block::FILE_KIND_BLOCK,
        vault_uuid: open.manifest.vault_uuid,
        block_uuid: plaintext.block_uuid,
        created_at_ms: block_created_at_ms,
        last_mod_ms: now_ms,
        vector_clock: block_clock.clone(),
    };

    // Step 3: translate &[ContactCard] → Vec<RecipientPublicKeys>.
    // We materialise the pk_bundle bytes and the typed ML-KEM-768 public
    // key once per recipient, then borrow into RecipientPublicKeys for
    // encrypt_block. Owned buffers live in `bundles` / `pq_pks`; the
    // borrowed `RecipientPublicKeys` references them.
    let mut bundles: Vec<Vec<u8>> = Vec::with_capacity(recipients.len());
    let mut pq_pks: Vec<MlKem768Public> = Vec::with_capacity(recipients.len());
    for r in recipients {
        bundles.push(r.pk_bundle_bytes()?);
        pq_pks.push(
            MlKem768Public::from_bytes(&r.ml_kem_768_pk).map_err(block::BlockError::from)?,
        );
    }
    // Each recipient's fingerprint is the 16-byte identity fingerprint
    // over the canonical-CBOR signed contact card bytes (§6.1). This is
    // what lands in the §6.2 recipient table on the wire.
    let mut recipient_fps: Vec<[u8; 16]> = Vec::with_capacity(recipients.len());
    for r in recipients {
        recipient_fps.push(fingerprint(&r.to_canonical_cbor()?));
    }
    let recipient_keys: Vec<RecipientPublicKeys<'_>> = recipients
        .iter()
        .enumerate()
        .map(|(i, r)| RecipientPublicKeys {
            fingerprint: recipient_fps[i],
            pk_bundle: &bundles[i],
            x25519_pk: &r.x25519_pk,
            ml_kem_768_pk: &pq_pks[i],
        })
        .collect();

    // Owner-side sender keys. Re-wrap the bundle's raw seed bytes into the
    // typed ML-DSA-65 / Ed25519 secret-key holders that encrypt_block
    // expects. Ed25519Secret is a Sensitive<[u8; 32]> alias — we allocate a
    // fresh Sensitive to keep the bundle's owner copy intact.
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes()?;
    let owner_fp = fingerprint(&open.owner_card.to_canonical_cbor()?);
    let owner_ed_sk: Ed25519Secret = Sensitive::new(*open.identity.ed25519_sk.expose());
    let owner_pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose())?;

    // Step 4: encrypt_block (signs internally, §6.5 step 7).
    let block_file = block::encrypt_block(
        rng,
        &header,
        &plaintext,
        &owner_fp,
        &owner_pk_bundle,
        &owner_ed_sk,
        &owner_pq_sk,
        &recipient_keys,
    )?;

    // Step 5: encode the block file to its on-disk byte form.
    let block_file_bytes = block::encode_block_file(&block_file)?;

    // Step 6: BLAKE3-256 fingerprint of the on-disk bytes — this is the
    // value the manifest's BlockEntry.fingerprint commits to.
    let block_fp: [u8; 32] = *blake3_hash(&block_file_bytes).as_bytes();

    // Step 7: atomic-write the block file. blocks/ subdirectory is created
    // if missing; filename is the lowercase hyphenated UUID + ".cbor.enc"
    // (mirrors Task 10's contacts/<uuid>.card pattern).
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    std::fs::create_dir_all(&blocks_dir).map_err(|e| VaultError::Io {
        context: "failed to create blocks/ subdirectory",
        source: e,
    })?;
    let block_uuid_hex = format_uuid_hyphenated(&plaintext.block_uuid);
    let block_path = blocks_dir.join(format!("{block_uuid_hex}.cbor.enc"));
    io::write_atomic(&block_path, &block_file_bytes).map_err(|e| VaultError::Io {
        context: "failed to write block file",
        source: e,
    })?;

    // Step 8: build the new BlockEntry. recipients[i].contact_uuid drives
    // the §4.2 BlockEntry.recipients list. The encoder sorts on emit so
    // in-memory order is irrelevant; we keep insertion order for clarity.
    let new_entry = BlockEntry {
        block_uuid: plaintext.block_uuid,
        block_name: plaintext.block_name.clone(),
        fingerprint: block_fp,
        recipients: recipients.iter().map(|r| r.contact_uuid).collect(),
        vector_clock_summary: block_clock,
        suite_id: crate::version::SUITE_ID,
        created_at_ms: block_created_at_ms,
        last_mod_ms: now_ms,
        unknown: std::collections::BTreeMap::new(),
    };

    // Step 9: replace existing entry or append. Same-UUID = update.
    match existing_idx {
        Some(i) => open.manifest.blocks[i] = new_entry,
        None => open.manifest.blocks.push(new_entry),
    }

    // Step 10: tick the manifest-level (vault-level) vector clock.
    tick_clock(&mut open.manifest.vector_clock, &device_uuid);

    // Step 11: refresh the manifest header — vault_uuid and created_at_ms
    // are preserved from the existing on-disk envelope; only last_mod_ms
    // moves forward.
    let new_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };

    // Step 12: fresh AEAD nonce + re-sign the manifest. `sign_manifest`
    // canonical-encodes the body, AEAD-encrypts with the IBK (header AAD),
    // and produces both halves of the §8 hybrid signature.
    let mut aead_nonce = [0u8; 24];
    rng.fill_bytes(&mut aead_nonce);
    let new_manifest_file = manifest::sign_manifest(
        new_header,
        &open.manifest,
        &open.identity_block_key,
        &aead_nonce,
        owner_fp,
        &owner_ed_sk,
        &owner_pq_sk,
    )?;
    let manifest_bytes = manifest::encode_manifest_file(&new_manifest_file)?;

    // Step 13: atomic-write the manifest. Block-first-then-manifest
    // ordering is preserved by step 7 → step 13.
    let manifest_path = folder.join(MANIFEST_FILENAME);
    io::write_atomic(&manifest_path, &manifest_bytes).map_err(|e| VaultError::Io {
        context: "failed to write manifest.cbor.enc",
        source: e,
    })?;

    // Step 14: refresh the in-memory manifest envelope so subsequent
    // saves chain off the new clock and the new author signature.
    open.manifest_file = new_manifest_file;

    Ok(())
}

// ---------------------------------------------------------------------------
// share_block — Task 13
// ---------------------------------------------------------------------------

/// Add a new recipient to an existing block — author-only re-sign.
///
/// `share_block` is the mechanism for granting an additional party
/// access to an already-encrypted block. Conceptually:
///
/// 1. The §6.2 recipient table is part of the §6.1 *signed range*
///    (the §6.1 hybrid signature covers `magic..aead_tag`, which
///    contains `recipient_entries`). Adding an entry therefore
///    invalidates the existing signature and requires a fresh one.
/// 2. Producing a fresh signature requires the original author's
///    secret keys — anyone else's signature would silently change
///    `author_fingerprint` and break attribution. PR-B's `share_block`
///    is consequently **author-only**: the caller MUST hold the
///    matching `author_sk_ed` / `author_sk_pq`, and the function
///    cross-checks them against the block's `author_fingerprint`
///    before doing any work. Mismatch → [`VaultError::NotAuthor`].
///
/// The "share-as-fork" path (decrypt the block as a recipient, mint a
/// fresh authored block under the caller's own identity) is NOT
/// implemented in PR-B. That path produces a different
/// `author_fingerprint` and a different `block_uuid`, which is a
/// distinct user-visible operation; deferring it keeps Task 13's
/// surface focused on the "owner extends access" case.
///
/// **Operational restriction.** Because `share_block` rotates the
/// block content key (BCK) and re-encrypts the body, the author must
/// also be a *current recipient* of the block — the BCK lives
/// exclusively inside per-recipient wraps and is otherwise
/// unrecoverable. An author who deliberately omitted themselves at
/// `save_block` time (the "send-only" mode where the author encrypts
/// for others without keeping a copy) cannot later call `share_block`
/// on that same block; the decrypt step in §6.4 surfaces as
/// [`BlockError::NotARecipient`] propagated through
/// [`VaultError::Block`]. This restriction is intentional: the
/// alternative would mean retaining the BCK in some side channel,
/// which is exactly the property send-only mode opts out of.
///
/// Wire-level effect:
///
/// - The block file at `blocks/<block_uuid>.cbor.enc` is rewritten
///   atomically (§9). A fresh BCK, fresh AEAD nonce, fresh
///   per-recipient hybrid-KEM wraps for everyone (existing + new),
///   and a fresh §6.1 hybrid signature are produced. The
///   `block_uuid`, `created_at_ms`, and the block-level vector clock
///   are preserved verbatim — the block's *content* did not change,
///   so its per-block clock is not ticked.
/// - The manifest's `BlockEntry` for this block is updated:
///   `recipients` extends with the new contact UUID, `fingerprint`
///   reflects the new on-disk BLAKE3, and `last_mod_ms` advances to
///   `now_ms`.
/// - The manifest-level vector clock is ticked for `device_uuid`
///   (the manifest's *content* did change — its recipient list and
///   block fingerprint moved). The manifest header's `last_mod_ms`
///   advances to `now_ms`.
/// - `open.manifest` and `open.manifest_file` are refreshed in place
///   so subsequent calls chain off the new state.
///
/// Atomic-write ordering matches `save_block`: block first, manifest
/// second, mirroring `docs/vault-format.md` §9 line 430. A crash
/// between leaves a fresh block whose recipients exceed the manifest's
/// view — recoverable on next open by trimming the orphan or retrying
/// the share.
///
/// Parameter notes:
///
/// - `author_card`: the author's full [`ContactCard`]. Required so
///   the orchestrator can recompute the author's fingerprint from
///   canonical bytes (rather than from the public-key tuple — the
///   spec-aligned identity is "the fingerprint of the canonical
///   contact card", §6). PR-B's `share_block` is restricted to the
///   single-owner case: `author_card.contact_uuid` must equal
///   `open.identity.user_uuid`, else [`VaultError::NotAuthor`]. A
///   future "share-as-fork" PR lifts this restriction. There is no
///   SK↔PK pre-flight cross-check today (`crypto::sig` does not
///   expose "derive PK from SK" entry points); a mismatched
///   (author_card, author_sk_*) tuple surfaces on the next
///   `open_vault` as a hybrid-signature verification failure.
///
/// - `existing_recipient_cards`: the contact cards for every
///   recipient currently in the block's recipient table, **including
///   the author if the author is also a recipient**. The orchestrator
///   uses these cards to rebuild the per-recipient
///   [`RecipientPublicKeys`] inputs to `encrypt_block`. Today this
///   list is the caller's responsibility to assemble — the orchestrator
///   does not read `contacts/<uuid>.card` files automatically. (When a
///   future PR adds a generic "load contact card by UUID" path, this
///   parameter can be inferred from `BlockEntry.recipients` instead.)
///   Any wrap whose fingerprint cannot be matched against the supplied
///   list surfaces as [`VaultError::MissingRecipientCard`].
///
/// - `new_recipient`: the contact card to grant access. Its
///   fingerprint must NOT already appear in the block's recipient
///   table; duplicate sharing surfaces as
///   [`VaultError::RecipientAlreadyPresent`]. The card is also written
///   to `contacts/<uuid>.card` so future reads (`open_vault`,
///   `decrypt_block` callers) can locate the public keys without the
///   share path's caller-supplied list.
///
/// - `device_uuid`: the writing device. Ticks the manifest-level
///   vector clock; the *block's* per-block clock is NOT ticked
///   (sharing didn't change content).
///
/// - `now_ms`: stamps `BlockEntry.last_mod_ms` and the manifest
///   header's `last_mod_ms`.
///
/// - `rng`: consumed for the new BCK, every per-recipient encap, the
///   new block AEAD nonce, and the manifest's body AEAD nonce.
#[allow(clippy::too_many_arguments)]
pub fn share_block(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    author_card: &ContactCard,
    author_sk_ed: &Ed25519Secret,
    author_sk_pq: &MlDsa65Secret,
    existing_recipient_cards: &[ContactCard],
    new_recipient: &ContactCard,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    // Step 1: locate the manifest BlockEntry. Bail before any I/O if
    // the caller is asking about an unknown block.
    let entry_idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .ok_or(VaultError::BlockNotFound { block_uuid })?;

    // Step 2: read the on-disk block file and decode the §6.1 envelope.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = blocks_dir.join(format!("{block_uuid_hex}.cbor.enc"));
    let block_file_bytes = std::fs::read(&block_path).map_err(|e| VaultError::Io {
        context: "failed to read block file for share_block",
        source: e,
    })?;
    let block_file = block::decode_block_file(&block_file_bytes)?;

    // Step 3: author check. The on-disk `author_fingerprint` is the
    // BLAKE3-derived 16-byte fingerprint of the author's canonical
    // contact-card bytes (§6). We re-derive it from the supplied
    // `author_card` and compare. Mismatch → NotAuthor.
    let author_card_bytes = author_card.to_canonical_cbor()?;
    let author_fp = fingerprint(&author_card_bytes);
    if author_fp != block_file.author_fingerprint {
        return Err(VaultError::NotAuthor {
            expected: block_file.author_fingerprint,
            got: author_fp,
        });
    }

    // Step 4: PR-B single-owner restriction. The decrypt path at step
    // 7 below uses `open.identity.{x25519_sk, ml_kem_768_sk}` as the
    // reader-side decap material while passing `author_fp` as the
    // reader-side fingerprint into `decrypt_block`. That pairing is
    // sound only when the calling owner IS the author. A mismatched
    // (open.identity, author_card) tuple would yield a cryptic
    // KemError or AeadFailure deep in the decrypt path; surfacing
    // `NotAuthor` up-front keeps the failure mode unambiguous. The
    // "share-as-fork" path (decrypt-as-non-author-recipient → mint a
    // fresh authored block) is a future PR that lifts this restriction.
    if author_card.contact_uuid != open.identity.user_uuid {
        return Err(VaultError::NotAuthor {
            expected: block_file.author_fingerprint,
            got: author_fp,
        });
    }

    // (No SK→PK cross-check today: the crypto::sig module does not
    // expose "derive PK from SK" entry points, and ML-DSA-65's PK is
    // not a trivial scalarmult of the SK seed. A mismatched
    // (author_card, author_sk_*) tuple would surface on the next
    // `open_vault` as a hybrid-signature verification failure
    // ([`VaultError::Manifest`] / [`VaultError::Block`]). Adding a
    // pre-flight cross-check is a future enhancement gated on
    // crypto::sig growing the relevant accessors.)

    // Step 5: duplicate-recipient check. The new recipient's
    // fingerprint must not already appear in the wire-level recipient
    // table. Linear scan: the table is small (handful of recipients in
    // the typical case).
    let new_recipient_card_bytes = new_recipient.to_canonical_cbor()?;
    let new_recipient_fp = fingerprint(&new_recipient_card_bytes);
    if block_file
        .recipients
        .iter()
        .any(|w| w.recipient_fingerprint == new_recipient_fp)
    {
        return Err(VaultError::RecipientAlreadyPresent);
    }

    // Step 6: resolve every existing wrap to its supplying card. We
    // build a (fingerprint → card) lookup once and walk the wrap list
    // in wire order so the new recipient set preserves the existing
    // order with the new recipient appended (the encoder sorts on
    // emit, so in-memory order doesn't affect the on-disk bytes — but
    // it keeps the in-memory shape stable across debug prints).
    //
    // The caller is responsible for assembling `existing_recipient_cards`
    // to cover every recipient currently in the block's wire-level
    // recipient table — INCLUDING the author if the author is also a
    // recipient. The orchestrator does NOT implicitly add `author_card`:
    // a wrap whose fingerprint isn't matched by the supplied list
    // surfaces as `VaultError::MissingRecipientCard` (loud, typed). The
    // shape mirrors `save_block` where the caller passes the recipient
    // list verbatim.
    let mut card_lookup: Vec<(crate::identity::fingerprint::Fingerprint, &ContactCard)> =
        Vec::with_capacity(existing_recipient_cards.len());
    for c in existing_recipient_cards {
        let fp = fingerprint(&c.to_canonical_cbor()?);
        card_lookup.push((fp, c));
    }
    // Resolve each on-wire wrap to a supplying card.
    let mut existing_cards_in_order: Vec<&ContactCard> =
        Vec::with_capacity(block_file.recipients.len());
    for wrap in &block_file.recipients {
        let card = card_lookup
            .iter()
            .find(|(fp, _)| *fp == wrap.recipient_fingerprint)
            .map(|(_, c)| *c)
            .ok_or(VaultError::MissingRecipientCard {
                fingerprint: wrap.recipient_fingerprint,
            })?;
        existing_cards_in_order.push(card);
    }

    // Step 7: decrypt the existing block under the author's reader
    // identity. The author MUST be a current recipient (operational
    // restriction documented above) — `decrypt_block` returns
    // `NotARecipient` otherwise, which propagates as
    // `VaultError::Block`.
    //
    // We pass author = sender = reader: the §6.4 author cross-check
    // (sender_card_fingerprint vs block.author_fingerprint) was
    // already validated by step 3, so this re-check is a tautology
    // here, but the API forces us to thread it.
    let author_pk_bundle = author_card.pk_bundle_bytes()?;
    let reader_x_sk: crate::crypto::kem::X25519Secret =
        Sensitive::new(*open.identity.x25519_sk.expose());
    let reader_pq_sk =
        crate::crypto::kem::MlKem768Secret::from_bytes(open.identity.ml_kem_768_sk.expose())
            .map_err(block::BlockError::from)?;
    let author_pq_pk = MlDsa65Public::from_bytes(&author_card.ml_dsa_65_pk)?;
    let plaintext = block::decrypt_block(
        &block_file,
        &author_fp,
        &author_pk_bundle,
        &author_card.ed25519_pk,
        &author_pq_pk,
        &author_fp,
        &author_pk_bundle,
        &reader_x_sk,
        &reader_pq_sk,
    )?;

    // Step 8: build the new recipient set: existing in wire order +
    // the new recipient at the tail. Materialise owned buffers
    // (pk-bundles, parsed ML-KEM-768 PKs, fingerprints) before
    // building the borrow-laden `RecipientPublicKeys` view, mirroring
    // `save_block`'s shape.
    let mut new_recipients: Vec<&ContactCard> = existing_cards_in_order;
    new_recipients.push(new_recipient);

    let mut bundles: Vec<Vec<u8>> = Vec::with_capacity(new_recipients.len());
    let mut pq_pks: Vec<MlKem768Public> = Vec::with_capacity(new_recipients.len());
    let mut recipient_fps: Vec<crate::identity::fingerprint::Fingerprint> =
        Vec::with_capacity(new_recipients.len());
    for r in &new_recipients {
        bundles.push(r.pk_bundle_bytes()?);
        pq_pks.push(
            MlKem768Public::from_bytes(&r.ml_kem_768_pk).map_err(block::BlockError::from)?,
        );
        recipient_fps.push(fingerprint(&r.to_canonical_cbor()?));
    }
    let recipient_keys: Vec<RecipientPublicKeys<'_>> = new_recipients
        .iter()
        .enumerate()
        .map(|(i, r)| RecipientPublicKeys {
            fingerprint: recipient_fps[i],
            pk_bundle: &bundles[i],
            x25519_pk: &r.x25519_pk,
            ml_kem_768_pk: &pq_pks[i],
        })
        .collect();

    // Step 9: rebuild the §6.1 block header. Preserve `block_uuid`,
    // `created_at_ms`, and the existing per-block vector clock — the
    // *content* didn't change, so neither does its clock. `last_mod_ms`
    // advances to `now_ms` (the block's wire-level state moved even
    // if the plaintext didn't).
    let new_header = BlockHeader {
        magic: crate::version::MAGIC,
        format_version: crate::version::FORMAT_VERSION,
        suite_id: crate::version::SUITE_ID,
        file_kind: block::FILE_KIND_BLOCK,
        vault_uuid: block_file.header.vault_uuid,
        block_uuid: block_file.header.block_uuid,
        created_at_ms: block_file.header.created_at_ms,
        last_mod_ms: now_ms,
        vector_clock: block_file.header.vector_clock.clone(),
    };

    // Step 10: re-encrypt with the new recipient set. encrypt_block
    // rotates the BCK, draws a fresh AEAD nonce, and produces a fresh
    // §6.1 hybrid signature under the author's SKs.
    let new_block_file = block::encrypt_block(
        rng,
        &new_header,
        &plaintext,
        &author_fp,
        &author_pk_bundle,
        author_sk_ed,
        author_sk_pq,
        &recipient_keys,
    )?;
    let new_block_file_bytes = block::encode_block_file(&new_block_file)?;
    let new_block_fp: [u8; 32] = *blake3_hash(&new_block_file_bytes).as_bytes();

    // Step 11: atomic-write the rotated block file. blocks/ already
    // exists (the file we read from was inside it) but defensively
    // ensure it.
    std::fs::create_dir_all(&blocks_dir).map_err(|e| VaultError::Io {
        context: "failed to ensure blocks/ subdirectory",
        source: e,
    })?;
    io::write_atomic(&block_path, &new_block_file_bytes).map_err(|e| VaultError::Io {
        context: "failed to re-write block file",
        source: e,
    })?;

    // Step 12: persist the new recipient's contact card to
    // `contacts/<uuid>.card` so future readers can decrypt without
    // the caller threading the card. Idempotent: if the file already
    // exists (e.g. because the caller imported the card before
    // calling share_block), we overwrite with the same canonical
    // bytes — no semantic difference.
    let contacts_dir = folder.join(CONTACTS_SUBDIR);
    std::fs::create_dir_all(&contacts_dir).map_err(|e| VaultError::Io {
        context: "failed to ensure contacts/ subdirectory",
        source: e,
    })?;
    let new_recipient_uuid_hex = format_uuid_hyphenated(&new_recipient.contact_uuid);
    let new_recipient_card_path =
        contacts_dir.join(format!("{new_recipient_uuid_hex}.card"));
    io::write_atomic(&new_recipient_card_path, &new_recipient_card_bytes).map_err(|e| {
        VaultError::Io {
            context: "failed to write new recipient contact card",
            source: e,
        }
    })?;

    // Step 13: update the manifest's BlockEntry. `recipients` extends
    // with the new contact_uuid; `fingerprint` reflects the new
    // on-disk BLAKE3; `last_mod_ms` advances. `vector_clock_summary`
    // is preserved (block clock did not tick). `block_name` and
    // `created_at_ms` are unchanged.
    let updated_entry = {
        let old = &open.manifest.blocks[entry_idx];
        let mut new_recipients_uuids = old.recipients.clone();
        new_recipients_uuids.push(new_recipient.contact_uuid);
        BlockEntry {
            block_uuid: old.block_uuid,
            block_name: old.block_name.clone(),
            fingerprint: new_block_fp,
            recipients: new_recipients_uuids,
            vector_clock_summary: old.vector_clock_summary.clone(),
            suite_id: old.suite_id,
            created_at_ms: old.created_at_ms,
            last_mod_ms: now_ms,
            unknown: old.unknown.clone(),
        }
    };
    open.manifest.blocks[entry_idx] = updated_entry;

    // Step 14: tick the manifest-level vector clock for this device.
    // Sharing changes the manifest's content (recipient list +
    // block-fingerprint), so the vault-level clock advances.
    tick_clock(&mut open.manifest.vector_clock, &device_uuid);

    // Step 15: refresh manifest header. vault_uuid + created_at_ms
    // are preserved; only last_mod_ms advances.
    let new_manifest_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };

    // Step 16: re-sign manifest with the author's SKs. The manifest's
    // `author_fingerprint` is unchanged (the manifest author is the
    // same identity that authored the block — for a single-owner
    // vault these are the same key pair). The manifest's IBK is
    // unchanged; we draw a fresh AEAD nonce.
    let mut manifest_aead_nonce = [0u8; 24];
    rng.fill_bytes(&mut manifest_aead_nonce);
    let new_manifest_file = manifest::sign_manifest(
        new_manifest_header,
        &open.manifest,
        &open.identity_block_key,
        &manifest_aead_nonce,
        open.manifest_file.author_fingerprint,
        author_sk_ed,
        author_sk_pq,
    )?;
    let manifest_bytes = manifest::encode_manifest_file(&new_manifest_file)?;

    // Step 17: atomic-write manifest (block-first → manifest-second
    // ordering matches save_block + §9 line 430).
    let manifest_path = folder.join(MANIFEST_FILENAME);
    io::write_atomic(&manifest_path, &manifest_bytes).map_err(|e| VaultError::Io {
        context: "failed to write manifest.cbor.enc after share_block",
        source: e,
    })?;

    // Step 18: refresh the in-memory manifest envelope.
    open.manifest_file = new_manifest_file;

    Ok(())
}

#[cfg(test)]
mod orchestrator_tests {
    //! Crate-internal smoke tests for the orchestrator's helpers.
    //! End-to-end coverage lives in `core/tests/create_vault.rs` —
    //! these tests pin the helper invariants that don't need a real
    //! filesystem to exercise.

    use super::*;

    #[test]
    fn format_uuid_hyphenated_zero() {
        let uuid = [0u8; 16];
        assert_eq!(
            format_uuid_hyphenated(&uuid),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    #[test]
    fn format_uuid_hyphenated_known_pattern() {
        // 0x1f 0x3a 0x4b 0x2c | 0x9d 0x8e | 0x4f 0x7a |
        // 0xb6 0xc5 | 0x1a 0x2b 0x3c 0x4d 0x5e 0x6f
        let uuid = [
            0x1f, 0x3a, 0x4b, 0x2c, 0x9d, 0x8e, 0x4f, 0x7a, 0xb6, 0xc5, 0x1a, 0x2b, 0x3c, 0x4d,
            0x5e, 0x6f,
        ];
        assert_eq!(
            format_uuid_hyphenated(&uuid),
            "1f3a4b2c-9d8e-4f7a-b6c5-1a2b3c4d5e6f"
        );
    }

    #[test]
    fn ensure_empty_directory_rejects_nonexistent_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let err = ensure_empty_directory(&missing).expect_err("missing dir must error");
        assert!(matches!(err, VaultError::Io { .. }));
    }

    #[test]
    fn ensure_empty_directory_rejects_nonempty_path() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("junk"), b"hi").unwrap();
        let err = ensure_empty_directory(dir.path()).expect_err("nonempty dir must error");
        assert!(matches!(err, VaultError::Io { context, .. } if context.contains("not empty")));
    }

    #[test]
    fn ensure_empty_directory_rejects_file_path() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("a-regular-file");
        std::fs::write(&file, b"x").unwrap();
        let err = ensure_empty_directory(&file).expect_err("file path must error");
        assert!(matches!(err, VaultError::Io { context, .. } if context.contains("not a directory")));
    }

    #[test]
    fn ensure_empty_directory_accepts_empty_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        ensure_empty_directory(dir.path()).expect("empty tempdir must succeed");
    }
}
