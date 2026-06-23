//! PR-B orchestrators (`create_vault`, `open_vault`, `save_block`, `share_block`).
//!
//! These functions compose `unlock::*`, `manifest::*`, `block::*`,
//! `identity::card::*`, and `vault::io::*` into the four user-visible
//! vault operations. They are the only place inside the crate where:
//!   1. Multiple lower-layer steps are sequenced under a single error
//!      type ([`VaultError`]); and
//!   2. Disk I/O happens in support of the format. Unit-level pure
//!      functions never touch the filesystem; orchestrators do.
//!
//! Discipline: each orchestrator is a free function (no hidden state),
//! takes a `&mut (impl RngCore + CryptoRng)` for any randomness it
//! needs, and returns its result by value. Atomic-write semantics are
//! inherited from [`super::io::write_atomic`].
//!
//! Split out of `vault/mod.rs` per the review on PR #5: keeping the
//! orchestrator surface in its own file lets `mod.rs` stay focused on
//! module wiring and the [`VaultError`] umbrella.

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use rand_core::{CryptoRng, RngCore};

use zeroize::Zeroize as _;

use crate::crypto::aead::{self, AEAD_TAG_LEN};
use crate::crypto::hash::hash as blake3_hash;
use crate::crypto::kdf::Argon2idParams;
use crate::crypto::kem::{self, MlKem768Public, MlKem768Secret};
use crate::crypto::secret::{SecretBytes, Sensitive};
use crate::crypto::sig::{
    Ed25519Secret, MlDsa65Public, MlDsa65Secret, ED25519_SIG_LEN, ML_DSA_65_SIG_LEN,
};
use crate::identity::card::{ContactCard, CARD_VERSION_V1};
use crate::identity::fingerprint::fingerprint;
use crate::unlock::{
    self, bundle::IdentityBundle, mnemonic::Mnemonic, vault_toml, UnlockedIdentity,
};

use super::{block, io, manifest};
use super::{
    BlockEntry, BlockHeader, BlockPlaintext, KdfParamsRef, Manifest, ManifestFile, ManifestHeader,
    RecipientPublicKeys, TrashEntry, VaultError, VectorClockEntry,
};

/// Filename of the cleartext metadata file (§2 / vault-format.md §1).
/// `pub(crate)` so sibling folder ops (`device_slot`) share the single source.
pub(crate) const VAULT_TOML_FILENAME: &str = "vault.toml";

/// Filename of the encrypted dual-wrapped identity bundle file
/// (§3 / vault-format.md §1). `pub(crate)` — see [`VAULT_TOML_FILENAME`].
pub(crate) const IDENTITY_BUNDLE_FILENAME: &str = "identity.bundle.enc";

/// Filename of the encrypted, signed manifest (§4 / vault-format.md §1).
/// `pub(crate)` so the sync-orchestration layer
/// (`crate::sync::{ingest, once, commit::write}`) can address the
/// canonical manifest path without re-declaring the literal in three
/// places. `pub(crate)` keeps it invisible to integration tests and
/// external crates — those continue to use the documented filename
/// literal directly.
pub(crate) const MANIFEST_FILENAME: &str = "manifest.cbor.enc";

/// Subdirectory holding imported / owner contact cards
/// (vault-format.md §1, §5).
const CONTACTS_SUBDIR: &str = "contacts";

/// Subdirectory holding encrypted block files
/// (vault-format.md §1, §6.1). `#[doc(hidden)] pub` (re-exported from
/// `vault/mod.rs`) so:
///
/// - The C.1.1a conflict-copy scanner
///   (`crate::sync::ingest::enumerate_block_siblings`) can address
///   the same path without re-declaring the string.
/// - Integration tests in `tests/*.rs` can address the blocks subdir
///   without duplicating a `const` (`pub(crate)` is invisible to
///   integration tests; `#[doc(hidden)] pub` is the established
///   cross-target test-hook pattern — see [`format_uuid_hyphenated`]
///   and `crate::sync::__test_dispatch`).
#[doc(hidden)]
pub const BLOCKS_SUBDIR: &str = "blocks";

/// Filename extension for block envelopes on disk: every block file
/// is `<uuid-hyphenated>.cbor.enc`. `#[doc(hidden)] pub` re-exported
/// from `vault/mod.rs` for the same reason as [`BLOCKS_SUBDIR`].
#[doc(hidden)]
pub const BLOCK_FILE_EXTENSION: &str = ".cbor.enc";

/// Format a 16-byte UUID as canonical lowercase 8-4-4-4-12 hex
/// (`docs/vault-format.md` §1).
///
/// Pure helper; no allocation other than the returned `String`. The
/// dashed grouping is normative for `<contact-uuid>.card` and
/// `<block-uuid>.cbor.enc` filenames.
///
/// `#[doc(hidden)] pub` (re-exported from `vault/mod.rs`) so:
///
/// - The C.1.1a conflict-copy scanner
///   (`crate::sync::ingest::enumerate_block_siblings`) can derive
///   canonical block filenames from a `block_uuid` without
///   re-implementing.
/// - Integration tests in `tests/sync_helpers/mod.rs` can reuse the
///   same formatter without copying the body (`#[cfg(test)]` items on
///   the lib are invisible to `tests/*.rs`; `#[doc(hidden)] pub` is
///   the established cross-target test-hook pattern — see
///   `__test_dispatch` in `crate::sync::once`).
///
/// Keeps the on-disk filename format pinned to a single source of
/// truth across production code, sync layer, and test helpers.
#[doc(hidden)]
pub fn format_uuid_hyphenated(uuid: &[u8; 16]) -> String {
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
    let created = unlock::create_vault(password, display_name, created_at_ms, kdf_params, rng)?;

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
    let aead_nonce = aead::random_nonce(rng);

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

    io::write_atomic(&vault_toml_path, &created.vault_toml_bytes).map_err(|e| VaultError::Io {
        context: "failed to write vault.toml",
        source: e,
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
    /// Per-device wrap secret (ADR 0009 / §5a). Recovers the IBK from
    /// `devices/<device_uuid>.wrap` via `unlock::device::open_with_device_secret`.
    /// `device_uuid` locates the wrap file AND is the §3a structural check
    /// (header device_uuid must equal it). The 32-byte secret is what B.3's
    /// Secure Enclave releases after a biometric check.
    DeviceSecret {
        /// 16-byte device UUID — the `devices/<uuid>.wrap` filename + §3a header check.
        device_uuid: &'a [u8; 16],
        /// 32-byte device secret (high-entropy random; not password-derived).
        secret: &'a SecretBytes,
    },
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
        Unlocker::DeviceSecret {
            device_uuid,
            secret,
        } => {
            let wrap_bytes =
                crate::vault::device_slot::read_device_wrap_bytes(folder, device_uuid)?;
            unlock::device::open_with_device_secret(
                &vault_toml_bytes,
                &wrap_bytes,
                &identity_bundle_bytes,
                device_uuid,
                secret,
            )?
        }
    };

    // Steps 3-8: read manifest envelope, load + verify owner card,
    // verify + decrypt manifest, sanity-check body↔envelope and
    // body↔vault.toml, optional rollback check. Shared with
    // `read_vault_manifest` so a caller that already holds an
    // UnlockedIdentity does not re-run Argon2 just to inspect the
    // manifest body.
    //
    // `_manifest_envelope_bytes` (raw on-disk bytes of `manifest.cbor.enc`)
    // is discarded here — `open_vault` doesn't need them. The C.1.1a
    // sync_once Concurrent path uses them via `read_vault_manifest_full`
    // to compute the freshness `ManifestHash` without re-reading the file
    // (see #80).
    let (owner_card, manifest_body, manifest_file, _manifest_envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, &unlocked, local_highest_clock)?;

    // C.1.1b D6: verify each on-disk block file's BLAKE3 fingerprint
    // matches `BlockEntry.fingerprint` in the (now-authenticated)
    // manifest. Closes the partial-commit window where a
    // `commit_with_decisions` crash between block writes and the
    // manifest write would leave a mismatched on-disk state. The
    // mismatch surfaces as `VaultError::BlockFingerprintMismatch` —
    // recovery is to re-run `sync_once → prepare_merge →
    // commit_with_decisions`, which is convergent under CRDT
    // idempotence.
    verify_block_fingerprints(folder, &manifest_body)?;

    Ok(OpenVault {
        identity_block_key: unlocked.identity_block_key,
        identity: unlocked.identity,
        owner_card,
        manifest: manifest_body,
        manifest_file,
    })
}

/// Read, verify, and decrypt the vault manifest using a caller-held
/// `UnlockedIdentity`. Returns just the decrypted [`Manifest`] body —
/// the caller retains ownership of the identity (no `IdentityBundle`
/// clone is performed, consistent with the bundle's no-Clone safety
/// policy).
///
/// The entry point used by [`core::sync::sync_once`] so a sync poll
/// runs in milliseconds (file read + signature verify + AEAD decrypt)
/// rather than seconds (Argon2id derivation + bundle unwrap).
///
/// Performs the same verify-then-decrypt + cross-checks as
/// [`open_vault`] — owner card sanity, manifest signature verify, AEAD
/// decrypt, body↔envelope vault_uuid match, KDF params match, optional
/// §10 rollback check.
///
/// [`core::sync::sync_once`]: crate::sync::sync_once
pub fn read_vault_manifest(
    folder: &Path,
    identity: &UnlockedIdentity,
    local_highest_clock: Option<&[VectorClockEntry]>,
) -> Result<Manifest, VaultError> {
    let vault_toml_path = folder.join(VAULT_TOML_FILENAME);
    let vault_toml_bytes = std::fs::read(&vault_toml_path).map_err(|e| VaultError::Io {
        context: "failed to read vault.toml",
        source: e,
    })?;
    let (_owner_card, manifest_body, _manifest_file, _manifest_envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, identity, local_highest_clock)?;
    Ok(manifest_body)
}

/// Like [`read_vault_manifest`] but returns the verified owner contact
/// card AND the raw manifest envelope bytes alongside the decrypted
/// manifest body.
///
/// `pub(crate)` because the C.1.1a Concurrent dispatch path
/// ([`crate::sync::sync_once`]) needs the owner card (for owner
/// fingerprint + Ed25519/ML-DSA-65 public keys to authenticate
/// conflict-copies) AND the envelope bytes (for the BLAKE3
/// [`crate::sync::ManifestHash`] freshness anchor consumed by
/// C.1.1b's commit path). Returning both from one call closes the
/// previous double-read TOCTOU window where a concurrent writer could
/// rewrite `manifest.cbor.enc` between the verify-decrypt read and a
/// follow-up hash read (issue #80). Doing this from outside the
/// orchestrators module would require duplicating the load + self-
/// verify + AEAD-decrypt + cross-checks already performed once by
/// `read_and_verify_manifest`.
///
/// The returned bytes are the on-disk envelope as read — no
/// canonicalisation — so callers can BLAKE3 them directly to obtain
/// the same value the verifier saw.
pub(crate) fn read_vault_manifest_full(
    folder: &Path,
    identity: &UnlockedIdentity,
    local_highest_clock: Option<&[VectorClockEntry]>,
) -> Result<(ContactCard, Manifest, Vec<u8>), VaultError> {
    let vault_toml_path = folder.join(VAULT_TOML_FILENAME);
    let vault_toml_bytes = std::fs::read(&vault_toml_path).map_err(|e| VaultError::Io {
        context: "failed to read vault.toml",
        source: e,
    })?;
    let (owner_card, manifest, _envelope, manifest_envelope_bytes) =
        read_and_verify_manifest(folder, &vault_toml_bytes, identity, local_highest_clock)?;
    Ok((owner_card, manifest, manifest_envelope_bytes))
}

/// Verify each on-disk block file's BLAKE3-256 fingerprint matches the
/// value committed in the manifest's [`BlockEntry::fingerprint`].
///
/// Returns `Ok(())` if every block matches. The first mismatch fires
/// [`VaultError::BlockFingerprintMismatch`] with the failing
/// `block_uuid` plus both fingerprints (the manifest's `expected` and
/// the on-disk-bytes `got`). The mismatch is a typed signal that a
/// partial commit (e.g. a crash between block writes and the manifest
/// write inside `commit_with_decisions`) corrupted the vault — caller
/// recovery is to re-run `sync_once → prepare_merge →
/// commit_with_decisions`, which is convergent under CRDT idempotence.
///
/// Reads one block file per `manifest.blocks` entry; the per-file read
/// buffer dominates allocation (the per-entry `PathBuf` / `String`
/// construction is `O(1)` per block by comparison). The manifest must
/// already be authenticated (envelope signature verified) — this
/// helper does not re-verify it.
///
/// On the I/O failure path (e.g. a `blocks/<uuid>.cbor.enc` file is
/// missing or unreadable) this surfaces a generic [`VaultError::Io`]
/// with a static context string that does not carry the failing
/// block's UUID. See [Issue #88] for the planned debuggability
/// improvement.
///
/// [Issue #88]: https://github.com/hherb/secretary/issues/88
///
/// `pub(crate)` because it is only invoked from [`open_vault`];
/// external callers go via `open_vault`'s typed error surface.
pub(crate) fn verify_block_fingerprints(
    folder: &Path,
    manifest: &Manifest,
) -> Result<(), VaultError> {
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    for entry in &manifest.blocks {
        let uuid_hex = format_uuid_hyphenated(&entry.block_uuid);
        let block_path = blocks_dir.join(format!("{uuid_hex}{BLOCK_FILE_EXTENSION}"));
        let bytes = std::fs::read(&block_path).map_err(|e| VaultError::Io {
            context: "failed to read block file for fingerprint check",
            source: e,
        })?;
        let got = *blake3_hash(&bytes).as_bytes();
        if got != entry.fingerprint {
            return Err(VaultError::BlockFingerprintMismatch {
                block_uuid: entry.block_uuid,
                expected: entry.fingerprint,
                got,
            });
        }
    }
    Ok(())
}

/// Shared helper for [`open_vault`] and [`read_vault_manifest`].
///
/// Inputs: the vault folder, pre-read `vault.toml` bytes, the unlocked
/// identity (by reference — no ownership transfer), and an optional
/// `local_highest_clock` for §10 rollback resistance.
///
/// Performs §1 read-order steps 3-8 of `docs/vault-format.md`:
///   - Read + decode the §4.1 manifest envelope.
///   - Load + self-verify the owner contact card; cross-check its
///     `contact_uuid` against the unlocked identity, and the manifest
///     envelope's `author_fingerprint` against the loaded card.
///   - Verify-then-decrypt: §8 hybrid signature on the envelope under
///     the owner card's keys; AEAD-decrypt the manifest body using the
///     caller's Identity Block Key.
///   - Cross-check the body's `owner_user_uuid`, `vault_uuid`, and
///     `kdf_params` against the unlocked identity, the envelope header,
///     and the parsed `vault.toml` respectively.
///   - Optional §10 rollback check against `local_highest_clock`.
///
/// Returns the
/// `(owner_card, manifest_body, manifest_file, manifest_envelope_bytes)`
/// 4-tuple. The trailing `Vec<u8>` is the raw on-disk envelope bytes
/// of `manifest.cbor.enc` as read for decode + verify — callers that
/// need a hash of the verified-on-disk manifest (e.g. C.1.1a's
/// sync_once Concurrent path computing a `ManifestHash` freshness
/// anchor) consume them without re-reading the file. Closing this
/// double-read window prevents a TOCTOU race where a concurrent writer
/// could rewrite the manifest between the verify-decrypt read and a
/// follow-up hash read (issue #80). [`open_vault`] and
/// [`read_vault_manifest`] discard the bytes.
fn read_and_verify_manifest(
    folder: &Path,
    vault_toml_bytes: &[u8],
    unlocked: &UnlockedIdentity,
    local_highest_clock: Option<&[VectorClockEntry]>,
) -> Result<(ContactCard, Manifest, ManifestFile, Vec<u8>), VaultError> {
    // Step 3-4: read + decode the §4.1 manifest envelope.
    let manifest_path = folder.join(MANIFEST_FILENAME);
    let manifest_file_bytes = std::fs::read(&manifest_path).map_err(|e| VaultError::Io {
        context: "failed to read manifest.cbor.enc",
        source: e,
    })?;
    let manifest_file = manifest::decode_manifest_file(&manifest_file_bytes)?;

    // Step 5: load + self-verify the owner contact card. The owner
    // UUID lives inside the IdentityBundle (which the caller already
    // has); using it here avoids a chicken-and-egg with the still-
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

    // Sanity: owner card's UUID matches the IdentityBundle.
    if owner_card.contact_uuid != unlocked.identity.user_uuid {
        return Err(VaultError::OwnerUuidMismatch {
            vault: unlocked.identity.user_uuid,
            found: owner_card.contact_uuid,
        });
    }

    // Sanity: manifest envelope's author_fingerprint matches the
    // computed fingerprint of the loaded owner card.
    let owner_fp = fingerprint(&owner_card_bytes);
    if manifest_file.author_fingerprint != owner_fp {
        return Err(VaultError::ManifestAuthorMismatch);
    }

    // Step 6: verify-then-decrypt.
    let pk_pq = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk)?;
    manifest::verify_manifest(&manifest_file, &owner_card.ed25519_pk, &pk_pq)?;

    // Step 7: AEAD-decrypt the manifest body.
    let mut ct_with_tag = Vec::with_capacity(manifest_file.aead_ct.len() + AEAD_TAG_LEN);
    ct_with_tag.extend_from_slice(&manifest_file.aead_ct);
    ct_with_tag.extend_from_slice(&manifest_file.aead_tag);
    let manifest_body = manifest::decrypt_manifest_body(
        &manifest_file.header,
        &ct_with_tag,
        &unlocked.identity_block_key,
        &manifest_file.aead_nonce,
    )?;

    // Sanity: manifest body's owner_user_uuid matches the unlocked
    // identity.
    if manifest_body.owner_user_uuid != unlocked.identity.user_uuid {
        return Err(VaultError::OwnerUuidMismatch {
            vault: unlocked.identity.user_uuid,
            found: manifest_body.owner_user_uuid,
        });
    }

    // §4.3 step 5 cross-check: body.vault_uuid == header.vault_uuid.
    if manifest_body.vault_uuid != manifest_file.header.vault_uuid {
        return Err(VaultError::ManifestVaultUuidMismatch {
            header: manifest_file.header.vault_uuid,
            body: manifest_body.vault_uuid,
        });
    }

    // §4.3 step 6 cross-check: body.kdf_params == vault.toml [kdf].
    let vt_str = std::str::from_utf8(vault_toml_bytes).map_err(|_| {
        VaultError::Unlock(crate::unlock::UnlockError::MalformedVaultToml(
            crate::unlock::vault_toml::VaultTomlError::MalformedToml(
                "vault.toml is not valid UTF-8".to_string(),
            ),
        ))
    })?;
    let vt = vault_toml::decode(vt_str)
        .map_err(|e| VaultError::Unlock(crate::unlock::UnlockError::MalformedVaultToml(e)))?;
    let expected_kdf = manifest::KdfParamsRef {
        memory_kib: vt.kdf.memory_kib,
        iterations: vt.kdf.iterations,
        parallelism: vt.kdf.parallelism,
        salt: vt.kdf.salt,
    };
    if manifest_body.kdf_params != expected_kdf {
        return Err(VaultError::KdfParamsMismatch);
    }

    // Step 8: §10 rollback resistance.
    if let Some(local) = local_highest_clock {
        if manifest::is_rollback(local, &manifest_body.vector_clock) {
            return Err(VaultError::Rollback {
                local_clock: local.to_vec(),
                incoming_clock: manifest_body.vector_clock.clone(),
            });
        }
    }

    Ok((
        owner_card,
        manifest_body,
        manifest_file,
        manifest_file_bytes,
    ))
}

// ---------------------------------------------------------------------------
// save_block — Task 12
// ---------------------------------------------------------------------------

/// Tick a vector clock for `device_uuid`: increment its existing counter, or
/// insert a new entry at counter 1 if absent. Pure helper shared by both the
/// block-level and manifest-level clocks. The output is left unsorted; the
/// canonical-CBOR encoders sort on emit so in-memory order doesn't matter.
///
/// Returns [`VaultError::ClockOverflow`] if the per-device counter is already
/// at `u64::MAX`. The §10 rollback-resistance check is order-only on
/// per-device counters; a frozen counter would silently break that property
/// (a non-incrementing tick makes two writes look like one and `is_rollback`
/// would declare them "Equal"). Practical reachability is essentially zero
/// (~10¹¹ years at one write/ns) but a typed surface beats a silent freeze.
fn tick_clock(clock: &mut Vec<VectorClockEntry>, device_uuid: &[u8; 16]) -> Result<(), VaultError> {
    if let Some(entry) = clock.iter_mut().find(|e| &e.device_uuid == device_uuid) {
        entry.counter = entry
            .counter
            .checked_add(1)
            .ok_or(VaultError::ClockOverflow {
                device_uuid: *device_uuid,
            })?;
    } else {
        clock.push(VectorClockEntry {
            device_uuid: *device_uuid,
            counter: 1,
        });
    }
    Ok(())
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
    tick_clock(&mut block_clock, &device_uuid)?;

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
        pq_pks.push(MlKem768Public::from_bytes(&r.ml_kem_768_pk).map_err(block::BlockError::from)?);
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
    // fresh Sensitive to keep the bundle's owner copy intact. The
    // intermediate `ed_sk_bytes` is a stack copy of the owner's Ed25519 SK;
    // bind it explicitly so we can zeroize it after the move.
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes()?;
    let owner_fp = fingerprint(&open.owner_card.to_canonical_cbor()?);
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
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
    tick_clock(&mut open.manifest.vector_clock, &device_uuid)?;

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
    let aead_nonce = aead::random_nonce(rng);
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
// rewrite_block_with_recipients — shared re-key engine
// ---------------------------------------------------------------------------

/// Re-key a block for a given final recipient set and re-sign the manifest.
///
/// Shared crypto engine behind both `share_block` (final set = existing ++ new)
/// and `revoke_block_recipient` (final set = existing \ target). Performs §6.4
/// decrypt-as-author → fresh-BCK §6.5 re-encrypt → atomic block write → optional
/// recipient-card persist → manifest BlockEntry update → vault clock tick →
/// manifest re-sign (Ed25519 ∧ ML-DSA-65) → atomic manifest write, preserving the
/// block-first → manifest-second ordering of §9.
///
/// Callers perform steps 1–6 (locate entry, read+decode block, author check,
/// single-owner check, wire-table resolution) and pass the results in.
#[allow(clippy::too_many_arguments)]
fn rewrite_block_with_recipients(
    folder: &Path,
    open: &mut OpenVault,
    block_file: &block::BlockFile,
    entry_idx: usize,
    author_card: &ContactCard,
    author_fp: crate::identity::fingerprint::Fingerprint,
    author_sk_ed: &Ed25519Secret,
    author_sk_pq: &MlDsa65Secret,
    final_recipient_cards: &[&ContactCard],
    final_recipient_uuids: Vec<[u8; 16]>,
    card_to_persist: Option<(&[u8], [u8; 16])>,
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    // Recompute the block path from the block UUID (callers read the block
    // from this same location in step 2).
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let block_uuid_hex = format_uuid_hyphenated(&block_file.header.block_uuid);
    let block_path = blocks_dir.join(format!("{block_uuid_hex}.cbor.enc"));

    // Step 7: decrypt the existing block under the author's reader
    // identity. The author MUST be a current recipient (operational
    // restriction documented at the `share_block` /
    // `revoke_block_recipient` call sites) — `decrypt_block` returns
    // `NotARecipient` otherwise, which propagates as
    // `VaultError::Block`.
    //
    // We pass author = sender = reader: the §6.4 author cross-check
    // (sender_card_fingerprint vs block.author_fingerprint) was
    // already validated by step 3, so this re-check is a tautology
    // here, but the API forces us to thread it.
    //
    // TODO(share-as-fork): the reader-side arguments below
    // (`&author_fp`, `&author_pk_bundle`, `&reader_x_sk`,
    // `&reader_pq_sk`) are the second touchpoint of the single-owner
    // restriction pinned at the `contact_uuid == user_uuid` guard at
    // the `share_block` / `revoke_block_recipient` call sites. When
    // share-as-fork lands, the reader fingerprint /
    // pk-bundle pair must come from `open.owner_card` (the calling
    // owner) rather than from the original author, and the reader
    // secret-keys already do come from `open.identity` — the pairing
    // (author-fp, owner-secret-keys) is what makes the current
    // arrangement only valid when caller == author. Grep for
    // `share-as-fork` to find the matching guard.
    let author_pk_bundle = author_card.pk_bundle_bytes()?;
    let mut x_sk_bytes = *open.identity.x25519_sk.expose();
    let reader_x_sk: crate::crypto::kem::X25519Secret = Sensitive::new(x_sk_bytes);
    x_sk_bytes.zeroize();
    let reader_pq_sk =
        crate::crypto::kem::MlKem768Secret::from_bytes(open.identity.ml_kem_768_sk.expose())
            .map_err(block::BlockError::from)?;
    let author_pq_pk = MlDsa65Public::from_bytes(&author_card.ml_dsa_65_pk)?;
    let plaintext = block::decrypt_block(
        block_file,
        &author_fp,
        &author_pk_bundle,
        &author_card.ed25519_pk,
        &author_pq_pk,
        &author_fp,
        &author_pk_bundle,
        &reader_x_sk,
        &reader_pq_sk,
    )?;

    // Step 8: build the final recipient set (supplied by the caller in
    // wire order). Materialise owned buffers (pk-bundles, parsed
    // ML-KEM-768 PKs, fingerprints) before building the borrow-laden
    // `RecipientPublicKeys` view, mirroring `save_block`'s shape.
    let mut bundles: Vec<Vec<u8>> = Vec::with_capacity(final_recipient_cards.len());
    let mut pq_pks: Vec<MlKem768Public> = Vec::with_capacity(final_recipient_cards.len());
    let mut recipient_fps: Vec<crate::identity::fingerprint::Fingerprint> =
        Vec::with_capacity(final_recipient_cards.len());
    for r in final_recipient_cards {
        bundles.push(r.pk_bundle_bytes()?);
        pq_pks.push(MlKem768Public::from_bytes(&r.ml_kem_768_pk).map_err(block::BlockError::from)?);
        recipient_fps.push(fingerprint(&r.to_canonical_cbor()?));
    }
    let recipient_keys: Vec<RecipientPublicKeys<'_>> = final_recipient_cards
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

    // Step 12: optionally persist a recipient's contact card to
    // `contacts/<uuid>.card` so future readers can decrypt without
    // the caller threading the card. Idempotent: if the file already
    // exists (e.g. because the caller imported the card before
    // calling share_block), we overwrite with the same canonical
    // bytes — no semantic difference. `revoke_block_recipient` passes
    // `None` (no new card is granted access).
    if let Some((card_bytes, card_uuid)) = card_to_persist {
        let contacts_dir = folder.join(CONTACTS_SUBDIR);
        std::fs::create_dir_all(&contacts_dir).map_err(|e| VaultError::Io {
            context: "failed to ensure contacts/ subdirectory",
            source: e,
        })?;
        let recipient_uuid_hex = format_uuid_hyphenated(&card_uuid);
        let recipient_card_path = contacts_dir.join(format!("{recipient_uuid_hex}.card"));
        io::write_atomic(&recipient_card_path, card_bytes).map_err(|e| VaultError::Io {
            context: "failed to write new recipient contact card",
            source: e,
        })?;
    }

    // Step 13: update the manifest's BlockEntry. `recipients` becomes
    // the caller-supplied final set; `fingerprint` reflects the new
    // on-disk BLAKE3; `last_mod_ms` advances. `vector_clock_summary`
    // is preserved (block clock did not tick). `block_name` and
    // `created_at_ms` are unchanged.
    let updated_entry = {
        let old = &open.manifest.blocks[entry_idx];
        BlockEntry {
            block_uuid: old.block_uuid,
            block_name: old.block_name.clone(),
            fingerprint: new_block_fp,
            recipients: final_recipient_uuids,
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
    tick_clock(&mut open.manifest.vector_clock, &device_uuid)?;

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
    let manifest_aead_nonce = aead::random_nonce(rng);
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
        context: "failed to write manifest.cbor.enc after block re-key",
        source: e,
    })?;

    // Step 18: refresh the in-memory manifest envelope.
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
    // `NotAuthor` up-front keeps the failure mode unambiguous.
    //
    // TODO(share-as-fork): the "share-as-fork" path (decrypt-as-non-
    // author-recipient → mint a fresh authored block under the caller's
    // own identity) is a future PR that lifts this restriction. When
    // that PR lands, the reader-side fingerprint passed into
    // `decrypt_block` at step 7 must change from `author_fp` to the
    // calling owner's fingerprint (the fingerprint of `open.owner_card`),
    // and this `contact_uuid == user_uuid` guard must be replaced with a
    // path-selector argument distinguishing "extend recipients in place"
    // (current behaviour) from "fork into a new authored block" (new
    // behaviour). Grep for `share-as-fork` to find the touchpoints.
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

    // Steps 7–18: build the final recipient set (existing in wire order +
    // the new recipient appended) and delegate to the shared re-key engine.
    let mut final_uuids = open.manifest.blocks[entry_idx].recipients.clone();
    final_uuids.push(new_recipient.contact_uuid);

    let mut final_cards: Vec<&ContactCard> = existing_cards_in_order;
    final_cards.push(new_recipient);

    rewrite_block_with_recipients(
        folder,
        open,
        &block_file,
        entry_idx,
        author_card,
        author_fp,
        author_sk_ed,
        author_sk_pq,
        &final_cards,
        final_uuids,
        Some((&new_recipient_card_bytes, new_recipient.contact_uuid)),
        device_uuid,
        now_ms,
        rng,
    )
}

// ---------------------------------------------------------------------------
// revoke_block_recipient — D.1.10 revoke / unshare primitive
// ---------------------------------------------------------------------------

/// Revoke a recipient from a shared block (§6 revoke / unshare primitive).
///
/// The inverse of [`share_block`]: rotates the block content key, re-wraps for
/// the remaining recipients only, drops `revoked_recipient_uuid` from the
/// manifest `BlockEntry.recipients`, ticks the manifest clock, re-signs
/// (Ed25519 ∧ ML-DSA-65) and writes atomically (block then manifest).
///
/// Author-only (single-owner, like `share_block`). `existing_recipient_cards`
/// must cover every recipient currently in the §6.2 wire table, INCLUDING the
/// revoke target (needed to resolve the table). The revoked contact's card is
/// left in `contacts/` untouched — card deletion is a separate concern.
///
/// Mirrors `share_block`'s validation (locate → read+decode → author check)
/// but adds a fail-fast owner-revoke guard and inverts share's duplicate-
/// recipient check into a require-present + split. Where `share_block` rejects
/// an *already-present* recipient ([`VaultError::RecipientAlreadyPresent`]),
/// revoke instead requires the target *be* present
/// ([`VaultError::RecipientNotPresent`] otherwise) and splits the resolved
/// cards into the "keep" set vs the revoked one. The shared re-key engine
/// ([`rewrite_block_with_recipients`]) is then invoked with
/// `card_to_persist = None` — revoke grants no new access, so no contact card
/// is written.
///
/// Body step numbering follows the design spec
/// (`docs/superpowers/specs/2026-06-04-d110-revoke-block-recipient-design.md`
/// §4.2): (1) locate entry, (2) read + decode, (3) author check, (4) owner-
/// revoke guard, (5) resolve wraps → cards, (6) target-present check, (7) build
/// the final recipient set, (8) delegate to the re-key engine.
///
/// # Errors
/// - [`VaultError::BlockNotFound`] — `block_uuid` absent from the manifest.
/// - [`VaultError::NotAuthor`] — caller is not the block's single-owner author.
/// - [`VaultError::CannotRevokeOwner`] — `revoked_recipient_uuid` is the owner;
///   the owner is always a recipient and must remain one (rejected up-front,
///   before any re-key).
/// - [`VaultError::MissingRecipientCard`] — a current wrap has no supplying card.
/// - [`VaultError::RecipientNotPresent`] — `revoked_recipient_uuid` is not a
///   current recipient.
///
/// # Forward secrecy
/// Revocation protects FUTURE block-versions only. The revoked party may retain
/// plaintext/keys already seen; `core` cannot un-see them. See `docs/`.
#[allow(clippy::too_many_arguments)]
pub fn revoke_block_recipient(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    author_card: &ContactCard,
    author_sk_ed: &Ed25519Secret,
    author_sk_pq: &MlDsa65Secret,
    existing_recipient_cards: &[ContactCard],
    revoked_recipient_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    // Step 1: locate the manifest BlockEntry (mirror share_block step 1).
    let entry_idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .ok_or(VaultError::BlockNotFound { block_uuid })?;

    // Step 2: read the on-disk block file and decode the §6.1 envelope
    // (mirror share_block step 2, revoke-specific Io context string).
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    let block_uuid_hex = format_uuid_hyphenated(&block_uuid);
    let block_path = blocks_dir.join(format!("{block_uuid_hex}.cbor.enc"));
    let block_file_bytes = std::fs::read(&block_path).map_err(|e| VaultError::Io {
        context: "failed to read block file for revoke_block_recipient",
        source: e,
    })?;
    let block_file = block::decode_block_file(&block_file_bytes)?;

    // Step 3 (author check, part 1 of 2): re-derive author fingerprint,
    // compare to the on-disk `author_fingerprint` (mirror share_block's
    // fingerprint check).
    let author_card_bytes = author_card.to_canonical_cbor()?;
    let author_fp = fingerprint(&author_card_bytes);
    if author_fp != block_file.author_fingerprint {
        return Err(VaultError::NotAuthor {
            expected: block_file.author_fingerprint,
            got: author_fp,
        });
    }

    // Step 3 (author check, part 2 of 2): PR-B single-owner restriction
    // (mirror share_block's single-owner check). The §6.4 decrypt inside
    // the helper pairs `open.identity` reader secret-keys with
    // `author_fp`; that pairing is sound only when caller == author. See
    // the matching `share-as-fork` TODO at the `share_block` call site.
    if author_card.contact_uuid != open.identity.user_uuid {
        return Err(VaultError::NotAuthor {
            expected: block_file.author_fingerprint,
            got: author_fp,
        });
    }

    // Step 4 (owner-revoke guard): the owner/author is ALWAYS a recipient
    // and must remain one — re-keying without them would brick the block
    // (no future decrypt-as-author for re-key/re-share). Reject up-front,
    // before any re-key. This is the guard that has no `share_block`
    // analogue, hence the spec numbering diverges from share here.
    if revoked_recipient_uuid == open.identity.user_uuid {
        return Err(VaultError::CannotRevokeOwner);
    }

    // Steps 5 + 6: resolve every wrap to a supplying card (step 5, the
    // same resolve as share's wrap-resolution) AND locate the revoke
    // target (step 6). Build the (fingerprint → card) lookup, walk the
    // wire table, and split resolved cards into the final "keep" set vs
    // the single revoked card. The split is the INVERSION of share's
    // duplicate-recipient check: share rejects a present recipient, revoke
    // requires one. The target MUST be present, else `RecipientNotPresent`.
    let mut card_lookup: Vec<(crate::identity::fingerprint::Fingerprint, &ContactCard)> =
        Vec::with_capacity(existing_recipient_cards.len());
    for c in existing_recipient_cards {
        let fp = fingerprint(&c.to_canonical_cbor()?);
        card_lookup.push((fp, c));
    }
    let mut final_cards: Vec<&ContactCard> = Vec::with_capacity(block_file.recipients.len());
    let mut found_target = false;
    for wrap in &block_file.recipients {
        let card = card_lookup
            .iter()
            .find(|(fp, _)| *fp == wrap.recipient_fingerprint)
            .map(|(_, c)| *c)
            .ok_or(VaultError::MissingRecipientCard {
                fingerprint: wrap.recipient_fingerprint,
            })?;
        if card.contact_uuid == revoked_recipient_uuid {
            found_target = true; // drop from the final set
        } else {
            final_cards.push(card);
        }
    }
    if !found_target {
        return Err(VaultError::RecipientNotPresent);
    }

    // Step 7: final manifest recipient uuids = current minus the target.
    // This list is built from `manifest.recipients` (manifest order),
    // whereas `final_cards` above is built from `block_file.recipients`
    // (wire-table order). The two orderings need not match — the manifest
    // `recipients` list is SET-semantics (a UUID set for enumeration), not
    // positionally aligned with the §6.2 wire table. Correctness depends
    // only on both describing the same recipient *set*; the re-key uses
    // `final_cards` (wire order) and the manifest stores `final_uuids`.
    let final_uuids: Vec<[u8; 16]> = open.manifest.blocks[entry_idx]
        .recipients
        .iter()
        .copied()
        .filter(|u| *u != revoked_recipient_uuid)
        .collect();

    // Steps 8–18: delegate to the shared re-key engine. `card_to_persist`
    // is `None` — revoke grants no new access, so no contact card is
    // written or deleted.
    rewrite_block_with_recipients(
        folder,
        open,
        &block_file,
        entry_idx,
        author_card,
        author_fp,
        author_sk_ed,
        author_sk_pq,
        &final_cards,
        final_uuids,
        None,
        device_uuid,
        now_ms,
        rng,
    )
}

// ---------------------------------------------------------------------------
// trash_block — B.5 lifecycle pair (with restore_block below)
// ---------------------------------------------------------------------------

/// Subdirectory holding tombstoned block files (vault-format.md §7).
/// Created lazily on first `trash_block` call.
const TRASH_SUBDIR: &str = "trash";

/// Move a live block into trash. `docs/vault-format.md` §7 deletion sequence.
///
/// Sequence:
///
/// 1. Find the block in `open.manifest.blocks`; surfaces
///    [`VaultError::BlockNotFound`] if absent. Lookup is by `block_uuid`.
/// 2. Ensure `folder/trash/` exists (lazy mkdir, mirroring `save_block`'s
///    `blocks/` create).
/// 3. `std::fs::rename(blocks/<uuid>.cbor.enc, trash/<uuid>.cbor.enc.<now_ms>)`
///    — atomic per POSIX `rename(2)` within a single filesystem. Cross-
///    filesystem (`EXDEV`) surfaces as [`VaultError::Io`].
/// 4. Remove the matching [`BlockEntry`] from `open.manifest.blocks`.
/// 5. Append a [`TrashEntry`] `{ block_uuid, tombstoned_at_ms: now_ms,
///    tombstoned_by: device_uuid }` to `open.manifest.trash`.
/// 6. Tick `open.manifest.vector_clock` for `device_uuid`. The per-block
///    clock is NOT ticked — the block's *content* did not change.
/// 7. Re-sign the manifest with a fresh AEAD nonce; atomic-write per §9.
///    Mirrors `save_block` steps 11–14.
/// 8. Refresh `open.manifest_file` in place.
///
/// On `Err`: `open.manifest` and `open.manifest_file` are NOT modified.
/// The filesystem MAY have a partial move (block file in `trash/`, manifest
/// still pointing at `blocks/`) which is harmless because `open_vault`
/// reads only entries listed in the manifest — the trashed file is then
/// detectable as an orphan and the operation can be retried.
pub fn trash_block(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    // Step 1: locate the block.
    let entry_idx = open
        .manifest
        .blocks
        .iter()
        .position(|b| b.block_uuid == block_uuid)
        .ok_or(VaultError::BlockNotFound { block_uuid })?;
    // #293: capture the live content commitment before removing the entry.
    // The file is moved (rename) unchanged into trash/, so this BLAKE3-256
    // (authenticated at the most recent open_vault) is exactly the hash of
    // the trashed bytes restore will recompute and check.
    let content_fingerprint = open.manifest.blocks[entry_idx].fingerprint;

    // Step 2: lazy mkdir for trash/.
    let trash_dir = folder.join(TRASH_SUBDIR);
    std::fs::create_dir_all(&trash_dir).map_err(|e| VaultError::Io {
        context: "trash_block: failed to create trash/ subdirectory",
        source: e,
    })?;

    // Step 3: rename blocks/<uuid>.cbor.enc → trash/<uuid>.cbor.enc.<now_ms>.
    // POSIX rename(2) is atomic within a single filesystem; EXDEV (cross-FS)
    // surfaces here as a typed Io error so the caller knows the vault is
    // mis-configured rather than the block being half-trashed.
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let src = folder
        .join(BLOCKS_SUBDIR)
        .join(format!("{uuid_hex}.cbor.enc"));
    let dst = trash_dir.join(format!("{uuid_hex}.cbor.enc.{now_ms}"));
    std::fs::rename(&src, &dst).map_err(|e| VaultError::Io {
        context: "trash_block: rename blocks/ → trash/",
        source: e,
    })?;

    // Step 4: drop the BlockEntry. The manifest encoder re-sorts on emit,
    // so order-preserving `remove` and order-shuffling `swap_remove` are
    // both correct; pick `remove` for clearer intent.
    open.manifest.blocks.remove(entry_idx);

    // Step 5: append the TrashEntry. The spec's §7.1 "Restoring" path
    // matches on (block_uuid, tombstoned_at_ms) so older tombstones —
    // surviving as files but not in the manifest — never collide with
    // a fresh trash event for the same UUID.
    open.manifest.trash.push(TrashEntry {
        block_uuid,
        tombstoned_at_ms: now_ms,
        tombstoned_by: device_uuid,
        fingerprint: Some(content_fingerprint),
        unknown: std::collections::BTreeMap::new(),
    });

    // Step 6: tick the manifest-level (vault-level) vector clock. The
    // per-block clock is NOT touched — the block's *content* did not
    // change, only its life-cycle state.
    tick_clock(&mut open.manifest.vector_clock, &device_uuid)?;

    // Step 7: refresh manifest header → fresh AEAD nonce → re-sign →
    // atomic-write. Mirrors `save_block` steps 11-13. Owner secret keys
    // are re-wrapped from the bundle's raw seeds into the typed
    // Ed25519Secret / MlDsa65Secret holders that `sign_manifest`
    // expects; the intermediate stack copy is zeroized before sign.
    let new_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose())?;
    let aead_nonce = aead::random_nonce(rng);
    let new_manifest_file = manifest::sign_manifest(
        new_header,
        &open.manifest,
        &open.identity_block_key,
        &aead_nonce,
        open.manifest_file.author_fingerprint,
        &owner_ed_sk,
        &owner_pq_sk,
    )?;
    let manifest_bytes = manifest::encode_manifest_file(&new_manifest_file)?;
    let manifest_path = folder.join(MANIFEST_FILENAME);
    io::write_atomic(&manifest_path, &manifest_bytes).map_err(|e| VaultError::Io {
        context: "trash_block: failed to write manifest.cbor.enc",
        source: e,
    })?;

    // Step 8: refresh the in-memory envelope so subsequent operations
    // chain off the new clock + new signature.
    open.manifest_file = new_manifest_file;

    Ok(())
}

// ---------------------------------------------------------------------------
// restore_block — B.5 lifecycle pair
// ---------------------------------------------------------------------------

/// Restore the most recent trashed copy of a block; purge older copies.
///
/// See `docs/vault-format.md` §7.1 "Restoring a block" for the normative
/// sequence. Mirrors that flow:
///
/// 1. Reject if `block_uuid` is live in `manifest.blocks` →
///    [`VaultError::BlockUuidAlreadyLive`].
/// 2. Scan `trash/` for files matching `<uuid>.cbor.enc.<unix-millis>`.
///    Parse each suffix as `u64`; reject ill-formed suffixes as
///    integrity failures.
/// 3. Pick the file whose suffix **equals** the signed
///    `TrashEntry.tombstoned_at_ms` as the *restore target* (#205 — the
///    suffix is unauthenticated filename metadata, so selection must
///    bind to the signed value, not the largest suffix); all other
///    matches are *purge targets*. No matching `TrashEntry`, or an empty
///    match list → [`VaultError::BlockNotInTrash`]; a `TrashEntry`
///    present with files but none matching its `tombstoned_at_ms` →
///    [`VaultError::RestoreTargetMissing`].
/// 4. Read the restore target's bytes; decode + AEAD-decrypt +
///    hybrid-verify against the owner's pubkeys + IBK + owner reader
///    keys. Failure → [`VaultError::RestoreVerificationFailed`]. The
///    manifest and `trash/` are NOT modified on this path.
/// 5. Resolve `recipient_fingerprint` → `contact_uuid` for every wrap
///    in the file's recipient table by matching against the owner's
///    fingerprint first, then scanning `contacts/*.card` for the
///    rest. Unresolved → [`VaultError::MissingRecipientCard`]. Trash
///    file and manifest still untouched.
/// 6. `rename(2)` the restore target to `blocks/<uuid>.cbor.enc`.
///    Point of no easy return.
/// 7. Best-effort `remove_file` every purge target. Individual
///    failures are swallowed — the block is already live.
/// 8. Build the new [`BlockEntry`] from the decrypted file + resolved
///    contact_uuids. `vector_clock_summary` is preserved verbatim
///    (sync correctness). `last_mod_ms` = `now_ms`.
/// 9. Append the new entry to `open.manifest.blocks`; drop the
///    matching `TrashEntry` from `open.manifest.trash`.
/// 10. Tick `open.manifest.vector_clock` for `device_uuid`.
/// 11. Re-sign manifest with a fresh AEAD nonce; atomic-write.
/// 12. Refresh `open.manifest_file` in place.
pub fn restore_block(
    folder: &Path,
    open: &mut OpenVault,
    block_uuid: [u8; 16],
    device_uuid: [u8; 16],
    now_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(), VaultError> {
    use std::collections::HashMap;

    // Step 1: live-collision check. Restore on a UUID that is currently
    // live in manifest.blocks would produce a duplicate entry; the
    // caller MUST trash the live copy first.
    if open
        .manifest
        .blocks
        .iter()
        .any(|b| b.block_uuid == block_uuid)
    {
        return Err(VaultError::BlockUuidAlreadyLive { block_uuid });
    }

    // Step 2: scan trash/ for matches of `<uuid>.cbor.enc.<u64>`.
    let trash_dir = folder.join(TRASH_SUBDIR);
    let uuid_hex = format_uuid_hyphenated(&block_uuid);
    let prefix = format!("{uuid_hex}.cbor.enc.");
    let mut matches: Vec<(u64, PathBuf)> = Vec::new();
    if trash_dir.exists() {
        for entry in std::fs::read_dir(&trash_dir).map_err(|e| VaultError::Io {
            context: "restore_block: failed to read_dir trash/",
            source: e,
        })? {
            let entry = entry.map_err(|e| VaultError::Io {
                context: "restore_block: failed to iterate trash/ entry",
                source: e,
            })?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(suffix) = name.strip_prefix(&prefix) else {
                continue;
            };
            // Spec §7 grammar: `<unix-millis>` is the canonical decimal
            // ASCII representation of a u64 (no leading `+`, no leading
            // zeros except for `0` itself). We `continue` rather than
            // error on non-canonical entries so a single junk filename
            // alongside a valid one cannot wedge restore (DoS
            // resistance — a buggy peer client or filesystem cruft on a
            // shared sync folder must not deny the legitimate
            // restore). Correctness is still gated by the §6.1 hybrid
            // verify on the file whose suffix equals the signed
            // `TrashEntry.tombstoned_at_ms` (selected in step 3, verified
            // in step 4).
            //
            // Note: `u64::from_str` already rejects `+`-prefixed and
            // sign-bearing forms, but accepts leading-zero forms
            // (`"007"` → 7). The `to_string() == suffix` check pins
            // canonical decimal form.
            let Ok(ts) = suffix.parse::<u64>() else {
                continue;
            };
            if ts.to_string() != suffix {
                continue;
            }
            matches.push((ts, path));
        }
    }
    // Step 3: bind selection to the signed TrashEntry.tombstoned_at_ms.
    // The authentic trashed file's filename suffix EQUALS this signed
    // value by construction — trash_block writes the file
    // `<uuid>.cbor.enc.<now_ms>` and the TrashEntry {tombstoned_at_ms:
    // now_ms} in the same operation. The suffix alone is unauthenticated
    // filename metadata an attacker with write access to trash/ can forge;
    // selecting the largest suffix would let a planted older-but-owner-
    // signed copy with a larger suffix be restored (authentic-but-stale
    // rollback, #205). We therefore select by EQUALITY to the signed
    // timestamp, not by largest suffix.
    //
    // The §7.1 contract pairs the file and the manifest entry; a
    // disagreement is an integrity failure. Error precedence:
    //   - no signed TrashEntry            → BlockNotInTrash (as before)
    //   - signed entry, but no trash file → BlockNotInTrash (as before)
    //   - signed entry, files present, but none with suffix == signed ts
    //                                     → RestoreTargetMissing (#205)
    //
    // The §6.1 hybrid-verify at step 4 still independently rejects a
    // tampered selected file; this step adds the freshness binding that
    // verification alone cannot provide (an authentic-but-stale file
    // verifies fine — authenticity is not currency).
    let (expected_ts, committed_fp) = match open
        .manifest
        .trash
        .iter()
        .find(|t| t.block_uuid == block_uuid)
    {
        Some(entry) => (entry.tombstoned_at_ms, entry.fingerprint),
        None => return Err(VaultError::BlockNotInTrash { block_uuid }),
    };
    if matches.is_empty() {
        return Err(VaultError::BlockNotInTrash { block_uuid });
    }
    // At most one file can match — suffix ↔ filename is 1:1.
    let Some(restore_path) = matches
        .iter()
        .find(|(ts, _)| *ts == expected_ts)
        .map(|(_, p)| p.clone())
    else {
        return Err(VaultError::RestoreTargetMissing {
            block_uuid,
            expected_tombstoned_at_ms: expected_ts,
        });
    };
    // Purge targets = every other match (older stale copies AND larger-
    // suffix attacker plants).
    let purge_targets: Vec<PathBuf> = matches
        .iter()
        .filter(|(ts, _)| *ts != expected_ts)
        .map(|(_, p)| p.clone())
        .collect();

    // Step 4: read + decode + AEAD-decrypt + hybrid-verify. Defense in
    // depth: if an attacker with write access to trash/ planted a
    // tampered file, we want to reject before any manifest mutation.
    let bytes = std::fs::read(&restore_path).map_err(|e| VaultError::Io {
        context: "restore_block: failed to read trash file",
        source: e,
    })?;

    // #293: content-freshness binding. If the signed TrashEntry commits to a
    // BLAKE3-256 of the trashed bytes (captured at trash_block), the selected
    // file's bytes MUST hash to it. This rejects an in-place overwrite of the
    // suffix-matching file with a genuinely-owner-signed but OLDER copy —
    // authenticity is not currency, so the §6.1 hybrid-verify below cannot
    // catch it, and #205's suffix-equality does not defend it. The check runs
    // before any rename/purge, so the manifest and trash/ stay untouched on
    // reject. `None` = legacy entry (pre-#293) → fall through to the existing
    // suffix-equality + hybrid-verify path.
    if let Some(committed_fp) = committed_fp {
        let got = *blake3_hash(&bytes).as_bytes();
        if got != committed_fp {
            return Err(VaultError::RestoreVerificationFailed {
                block_uuid,
                detail: "content commitment mismatch: trashed file bytes do not \
                         match the signed TrashEntry.fingerprint"
                    .to_string(),
            });
        }
    }

    let block_file =
        block::decode_block_file(&bytes).map_err(|e| VaultError::RestoreVerificationFailed {
            block_uuid,
            detail: format!("decode: {e}"),
        })?;

    // Owner-side reader + sender keys. The vault owner is always the
    // block author in v1 (save_block is owner-only), and the restorer
    // is always the owner — so sender_* and reader_* both reference
    // the owner card / owner identity.
    let owner_pk_bundle = open.owner_card.pk_bundle_bytes()?;
    let owner_fp = fingerprint(&open.owner_card.to_canonical_cbor()?);
    // Owner's *own* keys, not trashed-file bytes — internal-state parse
    // failure routes via `VaultError::Sig` / `VaultError::Block(BlockError::Kem(..))`,
    // not `RestoreVerificationFailed` (which would mislead operators to inspect the file).
    let owner_pq_pk = MlDsa65Public::from_bytes(&open.owner_card.ml_dsa_65_pk)?;
    let mut x_sk_bytes = *open.identity.x25519_sk.expose();
    let owner_x_sk: kem::X25519Secret = Sensitive::new(x_sk_bytes);
    x_sk_bytes.zeroize();
    let owner_pq_sk_reader = MlKem768Secret::from_bytes(open.identity.ml_kem_768_sk.expose())
        .map_err(block::BlockError::from)?;
    let plaintext = block::decrypt_block(
        &block_file,
        &owner_fp,
        &owner_pk_bundle,
        &open.owner_card.ed25519_pk,
        &owner_pq_pk,
        &owner_fp,
        &owner_pk_bundle,
        &owner_x_sk,
        &owner_pq_sk_reader,
    )
    .map_err(|e| VaultError::RestoreVerificationFailed {
        block_uuid,
        detail: format!("decrypt/verify: {e}"),
    })?;

    // Cross-check the file header's block_uuid against the requested
    // uuid: filename ↔ payload mismatch is an integrity failure.
    if block_file.header.block_uuid != block_uuid {
        return Err(VaultError::RestoreVerificationFailed {
            block_uuid,
            detail: format!(
                "file header block_uuid {:?} does not match requested {:?}",
                block_file.header.block_uuid, block_uuid
            ),
        });
    }

    // Step 5: resolve recipient_fingerprint → contact_uuid for every
    // entry in the block file's §6.2 recipient table.
    //   - Owner fingerprint resolves to open.owner_card.contact_uuid.
    //   - Non-owner fingerprints require a contacts/*.card scan;
    //     we hash each card and look up its fingerprint.
    let mut fp_to_uuid: HashMap<[u8; 16], [u8; 16]> = HashMap::new();
    fp_to_uuid.insert(owner_fp, open.owner_card.contact_uuid);
    let needs_scan = block_file
        .recipients
        .iter()
        .any(|w| w.recipient_fingerprint != owner_fp);
    if needs_scan {
        let contacts_dir = folder.join(CONTACTS_SUBDIR);
        if contacts_dir.exists() {
            for entry in std::fs::read_dir(&contacts_dir).map_err(|e| VaultError::Io {
                context: "restore_block: failed to read_dir contacts/",
                source: e,
            })? {
                let entry = entry.map_err(|e| VaultError::Io {
                    context: "restore_block: failed to iterate contacts/ entry",
                    source: e,
                })?;
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("card") {
                    continue;
                }
                let card_bytes = std::fs::read(&path).map_err(|e| VaultError::Io {
                    context: "restore_block: failed to read contact card",
                    source: e,
                })?;
                let Ok(card) = ContactCard::from_canonical_cbor(&card_bytes) else {
                    continue;
                };
                // Self-signature verification is REQUIRED before we trust
                // the card's `contact_uuid` for the manifest's recipient
                // table. `from_canonical_cbor` only parses; it does not
                // verify the embedded Ed25519 ∧ ML-DSA-65 self-signature
                // (see card.rs::verify_self). Without this check, an
                // attacker with write access to `contacts/` could plant a
                // forged card matching a wrap's fingerprint and mint a
                // `contact_uuid` of their choice into the manifest. The
                // block plaintext is still gated by the §6.1 hybrid
                // verify on the trashed file itself, but the manifest's
                // `BlockEntry.recipients` is load-bearing for share /
                // sync logic and must not carry un-attested UUIDs.
                //
                // We `continue` past an unverifiable card rather than
                // hard-failing so a single corrupt or malicious card in
                // `contacts/` cannot wedge restore for every block — the
                // legitimate cards alongside it still resolve. If no
                // verified card matches a given fingerprint, the loop
                // at step 5's wrap-resolution surfaces
                // `MissingRecipientCard` and the manifest stays
                // untouched.
                if card.verify_self().is_err() {
                    continue;
                }
                let fp = fingerprint(&card.to_canonical_cbor()?);
                fp_to_uuid.insert(fp, card.contact_uuid);
            }
        }
    }
    let mut recipients_uuids: Vec<[u8; 16]> = Vec::with_capacity(block_file.recipients.len());
    for wrap in &block_file.recipients {
        match fp_to_uuid.get(&wrap.recipient_fingerprint) {
            Some(uuid) => recipients_uuids.push(*uuid),
            None => {
                return Err(VaultError::MissingRecipientCard {
                    fingerprint: wrap.recipient_fingerprint,
                });
            }
        }
    }

    // Step 6: rename trash/<uuid>.cbor.enc.<ts> → blocks/<uuid>.cbor.enc.
    // Point of no easy return — from here on, all errors are best-effort
    // recovery: the block is on disk live, and the manifest update is the
    // last step.
    let blocks_dir = folder.join(BLOCKS_SUBDIR);
    std::fs::create_dir_all(&blocks_dir).map_err(|e| VaultError::Io {
        context: "restore_block: failed to create blocks/ subdirectory",
        source: e,
    })?;
    let target = blocks_dir.join(format!("{uuid_hex}.cbor.enc"));
    std::fs::rename(&restore_path, &target).map_err(|e| VaultError::Io {
        context: "restore_block: rename trash/ → blocks/",
        source: e,
    })?;

    // Step 7: best-effort purge of older trashed copies. Individual
    // failures are swallowed — the restore already succeeded; a left-
    // over older copy is only a retention-window cleanup item.
    for p in &purge_targets {
        let _ = std::fs::remove_file(p);
    }

    // Step 8: build the new BlockEntry. fingerprint is BLAKE3-256 of
    // the bytes we just verified (and which match the on-disk file
    // after rename, since rename is a move not a rewrite).
    //
    // `unknown` is reset to empty. This is intentional but not
    // free-of-tradeoff: the project's CBOR "unknown-keys" forward-
    // compat invariant says decoders preserve unrecognized keys on
    // round-trip — yet on restore we have no source of unknown keys
    // to preserve. The trashed-block side carries nothing into
    // `TrashEntry` (which is a fixed-shape tombstone, not a BlockEntry
    // archive), and we cannot reconstruct the pre-trash
    // `BlockEntry.unknown` from the encrypted block file alone (the
    // block file does not duplicate the manifest's BlockEntry
    // fields). A future v2 client that wrote signed-metadata unknowns
    // onto BlockEntry would see those unknowns lost across a v1
    // trash → restore cycle — acceptable for v1 because v1 does not
    // populate this map in any code path, and the spec explicitly
    // documents trash → restore as a continuation of the block's
    // *content* lineage, not of its manifest-side metadata.
    let block_fp: [u8; 32] = *blake3_hash(&bytes).as_bytes();
    let new_entry = BlockEntry {
        block_uuid,
        block_name: plaintext.block_name.clone(),
        fingerprint: block_fp,
        recipients: recipients_uuids,
        vector_clock_summary: block_file.header.vector_clock.clone(),
        suite_id: block_file.header.suite_id,
        created_at_ms: block_file.header.created_at_ms,
        last_mod_ms: now_ms,
        unknown: std::collections::BTreeMap::new(),
    };

    // Step 9: append + drop the TrashEntry. retain keeps order stable
    // for the unaffected entries.
    open.manifest.blocks.push(new_entry);
    open.manifest.trash.retain(|t| t.block_uuid != block_uuid);

    // Step 10: tick the manifest-level vector clock. The per-block
    // clock is NOT touched — that's the whole point of preserving
    // vector_clock_summary in step 8 (sync correctness).
    tick_clock(&mut open.manifest.vector_clock, &device_uuid)?;

    // Step 11: re-sign manifest with fresh AEAD nonce + atomic-write.
    // Mirrors trash_block / save_block.
    let new_header = ManifestHeader {
        vault_uuid: open.manifest_file.header.vault_uuid,
        created_at_ms: open.manifest_file.header.created_at_ms,
        last_mod_ms: now_ms,
    };
    let mut ed_sk_bytes = *open.identity.ed25519_sk.expose();
    let owner_ed_sk: Ed25519Secret = Sensitive::new(ed_sk_bytes);
    ed_sk_bytes.zeroize();
    let owner_pq_sk = MlDsa65Secret::from_bytes(open.identity.ml_dsa_65_sk.expose())?;
    let aead_nonce = aead::random_nonce(rng);
    let new_manifest_file = manifest::sign_manifest(
        new_header,
        &open.manifest,
        &open.identity_block_key,
        &aead_nonce,
        open.manifest_file.author_fingerprint,
        &owner_ed_sk,
        &owner_pq_sk,
    )?;
    let manifest_bytes = manifest::encode_manifest_file(&new_manifest_file)?;
    let manifest_path = folder.join(MANIFEST_FILENAME);
    io::write_atomic(&manifest_path, &manifest_bytes).map_err(|e| VaultError::Io {
        context: "restore_block: failed to write manifest.cbor.enc",
        source: e,
    })?;

    // Step 12: refresh in-memory envelope.
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
        assert!(
            matches!(err, VaultError::Io { context, .. } if context.contains("not a directory"))
        );
    }

    #[test]
    fn ensure_empty_directory_accepts_empty_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        ensure_empty_directory(dir.path()).expect("empty tempdir must succeed");
    }

    // ------------------------------------------------------------------
    // verify_block_fingerprints — C.1.1b D6 (Task 4 of the merge plan)
    // ------------------------------------------------------------------
    //
    // These tests exercise the read-time fingerprint check that
    // `open_vault` will call (Task 5) to detect partial-commit
    // corruption. We materialise the `golden_vault_001` fixture into a
    // tempdir per test so the corruption test can mutate block files
    // without affecting the on-disk reference vector.

    /// Materialise `core/tests/data/golden_vault_001` into a tempdir,
    /// open it, and return `(folder, _tmp_guard, manifest)`.
    ///
    /// Inline (rather than reusing `core/tests/fixtures/mod.rs`) so
    /// lib-internal tests can exercise `pub(crate)` helpers without
    /// crossing the integration-test boundary.
    fn open_golden_vault_manifest_inline() -> (PathBuf, tempfile::TempDir, Manifest) {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join("golden_vault_001");
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().to_path_buf();
        copy_recursive(&src, &dest);

        let password = SecretBytes::new(read_golden_vault_001_password());
        let open = open_vault(&dest, Unlocker::Password(&password), None)
            .expect("open_vault must succeed on the golden fixture");
        (dest, tmp, open.manifest)
    }

    /// Read the master password from
    /// `core/tests/data/golden_vault_001_inputs.json`. Mirrors the
    /// integration-test fixture in `core/tests/fixtures/mod.rs` but
    /// lives in-crate so the lib-internal tests do not depend on the
    /// integration-test target.
    fn read_golden_vault_001_password() -> Vec<u8> {
        #[derive(serde::Deserialize)]
        struct Inputs {
            password: String,
        }
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join("golden_vault_001_inputs.json");
        let raw =
            std::fs::read_to_string(&path).expect("golden_vault_001_inputs.json must be readable");
        let inputs: Inputs =
            serde_json::from_str(&raw).expect("golden_vault_001_inputs.json must be valid JSON");
        inputs.password.into_bytes()
    }

    fn copy_recursive(src: &Path, dest: &Path) {
        if !dest.exists() {
            std::fs::create_dir_all(dest).expect("mkdir -p");
        }
        for entry in std::fs::read_dir(src).expect("read_dir") {
            let e = entry.expect("dir entry");
            let s = e.path();
            let d = dest.join(e.file_name());
            if e.file_type().expect("file_type").is_dir() {
                copy_recursive(&s, &d);
            } else {
                std::fs::copy(&s, &d).expect("copy");
            }
        }
    }

    #[test]
    fn verify_block_fingerprints_ok_on_consistent_vault() {
        let (folder, _tmp, manifest) = open_golden_vault_manifest_inline();
        verify_block_fingerprints(&folder, &manifest).expect("consistent vault must verify");
    }

    #[test]
    fn verify_block_fingerprints_detects_corrupted_block() {
        let (folder, _tmp, manifest) = open_golden_vault_manifest_inline();
        let block_uuid = manifest.blocks[0].block_uuid;
        let block_path = folder.join(BLOCKS_SUBDIR).join(format!(
            "{}{}",
            format_uuid_hyphenated(&block_uuid),
            BLOCK_FILE_EXTENSION
        ));

        // Flip the final byte — the AEAD tag tail of the on-disk block
        // file. This always changes the BLAKE3 fingerprint regardless of
        // file size, which is what the manifest check is supposed to
        // notice.
        let mut bytes = std::fs::read(&block_path).expect("read block");
        *bytes
            .last_mut()
            .expect("golden block file must be non-empty") ^= 0xFF;
        std::fs::write(&block_path, &bytes).expect("write corrupted block");

        let err = verify_block_fingerprints(&folder, &manifest)
            .expect_err("corrupted block must surface a typed mismatch");
        match err {
            VaultError::BlockFingerprintMismatch {
                block_uuid: got_uuid,
                expected,
                got,
            } => {
                assert_eq!(
                    got_uuid, block_uuid,
                    "uuid in error must match corrupted block"
                );
                assert_eq!(
                    expected, manifest.blocks[0].fingerprint,
                    "expected = manifest's recorded fingerprint"
                );
                assert_ne!(
                    expected, got,
                    "got must differ from expected on a corrupted block"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// Pins current behaviour: a missing block file surfaces as a
    /// generic [`VaultError::Io`] rather than a UUID-tagged
    /// `BlockFingerprintMismatch`. The static `context` string today
    /// does not carry the failing block's UUID; that gap is tracked in
    /// Issue #88. When #88 lands this test should flip to assert the
    /// new typed variant.
    #[test]
    fn verify_block_fingerprints_io_error_on_missing_block() {
        let (folder, _tmp, manifest) = open_golden_vault_manifest_inline();
        let block_uuid = manifest.blocks[0].block_uuid;
        let block_path = folder.join(BLOCKS_SUBDIR).join(format!(
            "{}{}",
            format_uuid_hyphenated(&block_uuid),
            BLOCK_FILE_EXTENSION
        ));
        std::fs::remove_file(&block_path).expect("remove block file");

        let err = verify_block_fingerprints(&folder, &manifest)
            .expect_err("missing block file must surface an error");
        match err {
            VaultError::Io { context, source } => {
                assert_eq!(
                    context, "failed to read block file for fingerprint check",
                    "context must identify the helper that produced the error"
                );
                assert_eq!(
                    source.kind(),
                    std::io::ErrorKind::NotFound,
                    "underlying io::Error must be NotFound for a deleted file"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    // ------------------------------------------------------------------
    // Unlocker::DeviceSecret — B.2 Task 1
    // ------------------------------------------------------------------

    /// Build a complete on-disk vault in a fresh tempdir from the
    /// `golden_vault_001` fixture (copy to tempdir so mutations don't
    /// affect the tracked KAT), open it via password to confirm the
    /// baseline, then enrol a device and assert that
    /// `Unlocker::DeviceSecret` recovers the same IBK, user_uuid, and
    /// vector_clock as `Unlocker::Password`.
    #[test]
    fn open_vault_with_device_secret_matches_password_open() {
        use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join("golden_vault_001");
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().to_path_buf();
        copy_recursive(&src, &dest);

        let password = SecretBytes::new(read_golden_vault_001_password());

        // Baseline: open via password to collect reference values.
        let pw_open = open_vault(&dest, Unlocker::Password(&password), None)
            .expect("password open must succeed on golden fixture");

        // Enrol a device using a seeded RNG for determinism.
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let enrolled = crate::vault::device_slot::add_device_slot(&dest, &password, &mut rng)
            .expect("add_device_slot must succeed with the correct password");

        // Open via the new DeviceSecret path.
        let ds_open = open_vault(
            &dest,
            Unlocker::DeviceSecret {
                device_uuid: &enrolled.device_uuid,
                secret: &enrolled.device_secret,
            },
            None,
        )
        .expect("open_vault via DeviceSecret must succeed");

        // All three observable outputs must be equal to the password-open.
        assert_eq!(
            ds_open.identity_block_key.expose(),
            pw_open.identity_block_key.expose(),
            "IBK from DeviceSecret open must equal IBK from password open"
        );
        assert_eq!(
            ds_open.identity.user_uuid, pw_open.identity.user_uuid,
            "user_uuid must be preserved across unlock paths"
        );
        assert_eq!(
            ds_open.manifest.vector_clock, pw_open.manifest.vector_clock,
            "vector_clock must be the same regardless of unlock path"
        );
    }

    /// Build a vault on disk with no enrolled device, then call
    /// `open_vault` with `Unlocker::DeviceSecret` for an arbitrary
    /// device_uuid that was never enrolled.  Expect the typed
    /// `VaultError::DeviceSlotNotFound` — not a generic I/O error.
    #[test]
    fn open_vault_with_device_secret_absent_slot_is_device_slot_not_found() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("data")
            .join("golden_vault_001");
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().to_path_buf();
        copy_recursive(&src, &dest);

        // No device has been enrolled — devices/ directory is absent.
        let absent_uuid = [0xABu8; 16];
        let dummy_secret = SecretBytes::new(vec![0u8; 32]);

        let err = open_vault(
            &dest,
            Unlocker::DeviceSecret {
                device_uuid: &absent_uuid,
                secret: &dummy_secret,
            },
            None,
        )
        .expect_err("absent device slot must return an error");

        assert!(
            matches!(err, VaultError::DeviceSlotNotFound),
            "expected VaultError::DeviceSlotNotFound, got {err:?}"
        );
    }
}
