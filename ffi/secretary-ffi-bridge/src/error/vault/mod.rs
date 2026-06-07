//! [`FfiVaultError`] — folder-in counterpart to
//! [`super::FfiUnlockError`]. See the parent module's docs for the
//! mirror property and the rationale for a separate type.

use thiserror::Error;

/// FFI-friendly thinned error type for the **folder-in** vault entry points
/// (`open_vault_with_password` and `open_vault_with_recovery`). Mirrors
/// [`super::FfiUnlockError`]'s 5 unlock-class variants byte-identically
/// (variant name + Display string) plus a new [`FfiVaultError::FolderInvalid`]
/// variant for missing or inaccessible vault folders.
///
/// # Why a separate error type
///
/// The bytes-in unlock entry points (B.2 / B.3a, returning
/// [`super::FfiUnlockError`]) cannot raise IO errors — they take owned byte
/// slices, not paths. The folder-in entry points (B.4a) read four files from
/// disk (`vault.toml`, `identity.bundle.enc`, `manifest.cbor.enc`,
/// `contacts/<owner_uuid>.card`) and need a way to surface "your path is
/// wrong" distinctly from "your data is corrupt". Promoting that distinction
/// to a separate variant with `detail: String` carrying the missing-file
/// name lets foreign UIs render the right affordance (fix the path vs.
/// re-pair from backups). Pre-unlock IO errors don't leak unlock-secret
/// information, so the §13 anti-oracle constraint allows the granularity.
///
/// # Mirror property
///
/// The 5 overlapping variants share **byte-identical** Display strings with
/// their [`super::FfiUnlockError`] counterparts. Foreign-side dispatch logic
/// on a folder-in `FfiVaultError` reads identically to dispatch on a
/// bytes-in [`super::FfiUnlockError`]. A code-quality tripwire test in the
/// sibling [`super::conversions`] module pins the strings byte-identical so
/// a future variant rename on [`super::FfiUnlockError`] cannot drift
/// unnoticed.
#[derive(Debug, Error)]
pub enum FfiVaultError {
    /// Wrong password OR vault corruption — deliberately conflated per
    /// `docs/threat-model.md` §13. Returned by `open_vault_with_password`.
    /// Mirrors [`super::FfiUnlockError::WrongPasswordOrCorrupt`] in name and
    /// Display text.
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,

    /// Wrong recovery phrase OR vault corruption — parallel anti-oracle
    /// conflation for `open_vault_with_recovery`. Mirrors
    /// [`super::FfiUnlockError::WrongMnemonicOrCorrupt`] in name and Display
    /// text.
    #[error("wrong recovery phrase or vault corruption")]
    WrongMnemonicOrCorrupt,

    /// Invalid recovery phrase — pre-decryption validation failure (wrong
    /// word count, unknown word, bad checksum, or invalid UTF-8 input).
    /// Mirrors [`super::FfiUnlockError::InvalidMnemonic`] in name and Display
    /// text.
    #[error("invalid recovery phrase: {detail}")]
    InvalidMnemonic {
        /// Diagnostic text from the inner `MnemonicError` variant's
        /// `Display` impl, or `"phrase contained invalid UTF-8"` when
        /// the FFI input slice is not valid UTF-8.
        detail: String,
    },

    /// `vault.toml` and `identity.bundle.enc` reference different vaults.
    /// Mirrors [`super::FfiUnlockError::VaultMismatch`] in name and Display
    /// text.
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    /// Vault data integrity failure — covers BOTH the unlock-time corruption
    /// cases mirrored from [`super::FfiUnlockError::CorruptVault`] AND the
    /// post-unlock integrity failures specific to folder-in: manifest
    /// decrypt/parse/verify, owner-card decode/self-verify, fingerprint
    /// cross-check, KDF-params cross-check. Display text is path-neutral
    /// and matches [`super::FfiUnlockError::CorruptVault`] exactly. Carries
    /// a diagnostic `detail` string for debugging; not pattern-matchable on
    /// the inner cause.
    #[error("vault data integrity failure: {detail}")]
    CorruptVault {
        /// Diagnostic text from the inner `core::VaultError` variant's
        /// `Display` impl. Free-form; not part of the API contract.
        detail: String,
    },

    /// Vault folder doesn't exist, isn't readable, or is missing one of
    /// the required files (`vault.toml`, `identity.bundle.enc`,
    /// `manifest.cbor.enc`, `contacts/<owner_uuid>.card`). New variant
    /// introduced by B.4a — no counterpart on [`super::FfiUnlockError`]
    /// (bytes-in callers cannot raise IO errors against their own filesystem
    /// through the bridge). The `detail` string carries the IO context
    /// (e.g. `"failed to read vault.toml: No such file or directory (os error 2)"`).
    #[error("vault folder is not accessible: {detail}")]
    FolderInvalid {
        /// IO context string: which file we tried to read + the underlying
        /// `io::Error`'s Display.
        detail: String,
    },

    /// The requested block UUID does not appear in the manifest's live
    /// blocks list (`manifest.blocks`). Trashed blocks live in a
    /// separate list (`manifest.trash`, holding `TrashEntry` records
    /// with their own `block_uuid`) which `read_block` does NOT
    /// search; a trashed UUID therefore naturally falls through to
    /// `BlockNotFound` here. Sub-project C will introduce the
    /// restore-from-trash flow with full vector-clock context, at
    /// which point trashed UUIDs may surface through a dedicated
    /// recovery path instead.
    ///
    /// `uuid_hex` is the 32-char lowercase hex of the requested UUID, e.g.
    /// `"112233445566778899aabbccddeeff00"`. Stored as a `String` for
    /// consistency with other variants' `detail: String` payloads; the
    /// foreign caller can `bytes.fromhex(uuid_hex)` if needed.
    ///
    /// Distinct from `CorruptVault` — `BlockNotFound` means "the manifest
    /// doesn't list this block" (legitimate caller error or stale UUID),
    /// while `CorruptVault` means "the manifest lists it but the file is
    /// missing or unreadable" (data integrity failure). The wrong-length
    /// UUID case (≠16 bytes) does NOT fold here either — that's a
    /// programmer error and surfaces as `ValueError` (PyO3) /
    /// `VaultError::InvalidArgument` (uniffi) at the binding layer; the
    /// bridge function takes `&[u8; 16]` (compile-time enforced).
    #[error("block not found in manifest: {uuid_hex}")]
    BlockNotFound {
        /// 32-char lowercase hex of the requested 16-byte block UUID.
        /// See the variant-level doc for the contract + counter-cases.
        uuid_hex: String,
    },

    /// The requested record UUID does not match any LIVE record in the
    /// target block. Raised by the D.1.4 `edit_record` primitive when the
    /// caller asks to edit a record that is absent or tombstoned. Distinct
    /// from [`Self::BlockNotFound`] (the block itself is missing) and from
    /// [`Self::CorruptVault`] (the block decrypted fine, the record just
    /// isn't there). Constructed directly inside the bridge — NOT reachable
    /// through `From<core::VaultError>`.
    ///
    /// `uuid_hex` is the 32-char lowercase hex of the requested 16-byte
    /// record UUID, for parity with [`Self::BlockNotFound`]'s `uuid_hex`.
    #[error("record not found in block: {uuid_hex}")]
    RecordNotFound {
        /// 32-char lowercase hex of the requested 16-byte record UUID.
        uuid_hex: String,
    },

    /// Save-time crypto failure on already-validated inputs. Distinguished
    /// from `CorruptVault` (which means on-disk bytes failed verification)
    /// because save failures here originate from in-memory state that
    /// passed `open_vault` checks, so the failure mode is post-unlock
    /// corruption / structural-impossibility rather than an on-disk corrupt
    /// envelope.
    ///
    /// Mapped from: `tick_clock` saturation, `MlKem768Public::from_bytes`
    /// failures on the owner card, canonical-CBOR encode failures,
    /// `encrypt_block` / `sign_manifest` / `encode_block_file` /
    /// `encode_manifest_file` failures, and post-unlock identity-bundle
    /// in-memory parse failures (e.g. `MlDsa65Secret::from_bytes` on
    /// already-validated bundle bytes).
    ///
    /// Constructed directly by `crate::save::save_block`'s error-mapping
    /// helper — NOT reachable through `From<core::VaultError>` (the read
    /// path's existing mapping correctly folds `core::VaultError` crypto
    /// failures onto `CorruptVault`, since for the read path the input is
    /// on-disk bytes).
    #[error("save-time crypto failure: {detail}")]
    SaveCryptoFailure {
        /// Diagnostic text describing which save-step failed. Free-form;
        /// not part of the API contract.
        detail: String,
    },

    /// Block-share authorization failure: the calling identity's
    /// `user_uuid` does not match the block's recorded `author_fingerprint`,
    /// OR the supplied `author_card`'s `contact_uuid` does not match the
    /// vault owner's `user_uuid`. v1 single-author: only the vault owner
    /// can share blocks they authored. The future "share-as-fork" path
    /// will lift this restriction; B.4d cements the v1 semantics.
    ///
    /// `expected_fingerprint_hex` is the 32-char lowercase hex of the
    /// fingerprint stored on disk in the block file's `author_fingerprint`
    /// field. `got_fingerprint_hex` is the 32-char lowercase hex of
    /// `fingerprint(author_card.to_canonical_cbor())`. Foreign callers can
    /// `bytes.fromhex(...)` either if needed.
    #[error("only the block author can share this block")]
    NotAuthor {
        /// 32-char lowercase hex of the on-disk author fingerprint.
        expected_fingerprint_hex: String,
        /// 32-char lowercase hex of the supplied author-card fingerprint.
        got_fingerprint_hex: String,
    },

    /// The supplied `new_recipient` is already in the block's wire-level
    /// recipient table (deduplication check performed by core, keyed on
    /// fingerprint). Foreign UX: idempotent — the recipient already has
    /// access; no further action needed.
    #[error("recipient is already present in the block's recipient set")]
    RecipientAlreadyPresent,

    /// Revoke target is not a current recipient of the block. Mirrors
    /// [`Self::RecipientAlreadyPresent`]; surfaced by the revoke path.
    #[error("recipient is not present on the block")]
    RecipientNotPresent,

    /// The caller asked to revoke the block owner/author, who is always a
    /// recipient and must remain one. Mirrors
    /// [`secretary_core::vault::VaultError::CannotRevokeOwner`]; surfaced
    /// by the revoke path.
    #[error("cannot revoke the block owner")]
    CannotRevokeOwner,

    /// The caller's `existing_recipient_cards` did not cover every
    /// recipient currently in the block's wire-level recipient table.
    /// `recipient_fingerprint_hex` is the 32-char lowercase hex of the
    /// missing recipient's fingerprint; foreign callers can use it to
    /// look up the contact card in their address book / contacts dir.
    #[error("missing contact card for recipient: {recipient_fingerprint_hex}")]
    MissingRecipientCard {
        /// 32-char lowercase hex of the missing recipient's fingerprint.
        recipient_fingerprint_hex: String,
    },

    /// One of the canonical-CBOR `ContactCard` byte slices passed to
    /// [`crate::share::share_block`] failed to decode via
    /// `ContactCard::from_canonical_cbor`. Constructed directly inside the
    /// bridge — NOT reachable through `From<core::VaultError>` (mirrors
    /// [`Self::SaveCryptoFailure`]'s bridge-internal pattern).
    #[error("failed to decode contact card: {detail}")]
    CardDecodeFailure {
        /// Diagnostic text from the inner `CardError` variant's `Display`
        /// impl. Free-form; not part of the API contract.
        detail: String,
    },

    /// A contact card with this `contact_uuid` is already present in the
    /// vault's `contacts/` directory. Import refuses to overwrite a trusted
    /// card (TOFU substitution guard, spec §3).
    #[error("contact already exists in vault: {uuid_hex}")]
    ContactAlreadyExists {
        /// 32-char lowercase hex of the contact UUID.
        uuid_hex: String,
    },

    /// A contact card referenced by a share operation (an existing recipient
    /// listed in the manifest, or the new recipient) has no `.card` file in
    /// `contacts/`. Spec §5, §9.3.
    #[error("contact not found in vault: {uuid_hex}")]
    ContactNotFound {
        /// 32-char lowercase hex of the contact UUID.
        uuid_hex: String,
    },

    /// `restore_block`: the UUID has both a `TrashEntry` and a live
    /// `BlockEntry`. The caller must first trash the live copy before
    /// restoring. Folder-in counterpart to
    /// [`secretary_core::vault::VaultError::BlockUuidAlreadyLive`].
    #[error("block is currently live and trashed: {detail}")]
    BlockUuidAlreadyLive {
        /// Diagnostic text including the UUID. Free-form; not part of
        /// the API contract.
        detail: String,
    },

    /// `restore_block`: no file matched `trash/<uuid>.cbor.enc.*` and
    /// no `TrashEntry` exists for this UUID. Folder-in counterpart to
    /// [`secretary_core::vault::VaultError::BlockNotInTrash`].
    #[error("block is not in trash: {detail}")]
    BlockNotInTrash {
        /// Diagnostic text including the UUID. Free-form; not part of
        /// the API contract.
        detail: String,
    },

    /// `delete_contact_card`: the requested uuid is the vault owner's own
    /// self-card, which must never be removed (removing it corrupts the
    /// vault's identity). Defense in depth — the contacts pane already omits
    /// the owner, but the primitive refuses it regardless. Spec §3, §5.
    #[error("the vault owner's own contact card cannot be deleted")]
    CannotDeleteOwnerContact,

    /// The on-disk `SyncState` cache (`<state-dir>/<vault_uuid>.state.cbor`)
    /// is for a different vault than the one being synced.
    #[error("sync state file belongs to a different vault")]
    SyncStateVaultMismatch,

    /// The `SyncState` CBOR could not be decoded or re-encoded — the local
    /// sync cache is corrupt. The vault itself is untouched.
    #[error("sync state cache is corrupt: {detail}")]
    SyncStateCorrupt {
        /// Diagnostic text (clock metadata only); kept off the wire for
        /// consistency with the other `detail` variants.
        detail: String,
    },

    /// A concurrent writer changed the canonical manifest between the read and
    /// the commit of a sync pass. No write occurred; retry the pass.
    #[error("vault changed on disk during sync; retry")]
    SyncEvidenceStale,

    /// Another process (a `secretary-sync` daemon, or a second client) holds
    /// the per-vault sync lockfile. No write occurred.
    #[error("another sync is already in progress for this vault")]
    SyncInProgress,

    /// A sync pass failed for an internal/unexpected reason (argument or
    /// invariant violation, conflict-copy scan I/O, etc.). The vault is unchanged.
    #[error("sync failed: {detail}")]
    SyncFailed {
        /// Diagnostic text. Free-form; not part of the API contract.
        detail: String,
    },

    /// `commit_with_decisions` could not match the supplied decisions to the
    /// recomputed veto set (a UI bug or a race). Distinct from `SyncFailed`
    /// so the desktop can show "couldn't apply your choices — try again".
    #[error("sync decisions did not cover the pending conflicts")]
    SyncDecisionsIncomplete,
}

impl From<secretary_core::vault::VaultError> for FfiVaultError {
    fn from(e: secretary_core::vault::VaultError) -> Self {
        use secretary_core::vault::VaultError as VE;

        match e {
            // Unlock-class errors: delegate to the FfiUnlockError translation
            // logic so the 5 mirrored variants stay drift-free. If a future
            // refactor adds a 6th variant to FfiUnlockError, the new variant
            // automatically picks up the right FfiVaultError mapping via the
            // private From<FfiUnlockError> arm in the conversions submodule.
            VE::Unlock(unlock_err) => {
                let intermediate: super::FfiUnlockError = unlock_err.into();
                intermediate.into()
            }

            // Pre-unlock IO errors → FolderInvalid. The matched ErrorKinds
            // are the foreign-caller-actionable ones (path is wrong, no
            // permission). Any other IO error kind (e.g. interrupted, broken
            // pipe) falls through to CorruptVault since it's neither
            // user-actionable nor data-integrity-clean.
            VE::Io { context, source }
                if matches!(
                    source.kind(),
                    std::io::ErrorKind::NotFound | std::io::ErrorKind::PermissionDenied
                ) =>
            {
                FfiVaultError::FolderInvalid {
                    detail: format!("{context}: {source}"),
                }
            }

            // Block-lookup failure (the manifest does not list this UUID).
            // core::read_block + core::share_block + core::save_block all
            // surface this; folding to CorruptVault would mask a benign
            // "stale UUID" / "trashed block" caller mistake as a data-
            // integrity failure.
            VE::BlockNotFound { block_uuid } => FfiVaultError::BlockNotFound {
                uuid_hex: hex::encode(block_uuid),
            },

            // Block-share authorization failure: caller's identity is not
            // the author. Both fingerprints are public material (BLAKE3 of
            // a non-secret contact card); rendering as hex preserves the
            // foreign-side debugging affordance without leaking secrets.
            VE::NotAuthor { expected, got } => FfiVaultError::NotAuthor {
                expected_fingerprint_hex: hex::encode(expected),
                got_fingerprint_hex: hex::encode(got),
            },

            // Block-share dedup failure: caller is trying to add a recipient
            // that already has access. Foreign UX: idempotent.
            VE::RecipientAlreadyPresent => FfiVaultError::RecipientAlreadyPresent,

            // Revoke precondition: caller asked to revoke a recipient that is
            // not on the block. Mirrors `RecipientAlreadyPresent`; surfaced by
            // the revoke path.
            VE::RecipientNotPresent => FfiVaultError::RecipientNotPresent,

            // Revoke precondition: caller asked to revoke the block owner,
            // who is always a recipient and must remain one. Surfaced by
            // the revoke path.
            VE::CannotRevokeOwner => FfiVaultError::CannotRevokeOwner,

            // Block-share input shape failure: caller's
            // `existing_recipient_cards` did not cover every recipient on
            // disk. The caller can recover by fetching the missing card
            // (e.g. from their contacts dir) and retrying. The core
            // variant's field is `fingerprint`; the FFI variant adds the
            // `recipient_` prefix for clarity at the foreign-API boundary.
            VE::MissingRecipientCard { fingerprint } => FfiVaultError::MissingRecipientCard {
                recipient_fingerprint_hex: hex::encode(fingerprint),
            },

            // trash/restore precondition: caller asked to restore a UUID
            // that is currently live. Typed surface so the foreign caller
            // can recover by trashing the live copy first. Hex-encoded
            // for parity with `BlockNotFound { uuid_hex }`.
            VE::BlockUuidAlreadyLive { block_uuid } => FfiVaultError::BlockUuidAlreadyLive {
                detail: hex::encode(block_uuid),
            },

            // trash/restore precondition: caller asked to restore a UUID
            // that isn't in the trash. Typed surface so foreign callers
            // can distinguish "already restored" from "data corruption".
            // Hex-encoded for parity with `BlockNotFound { uuid_hex }`.
            VE::BlockNotInTrash { block_uuid } => FfiVaultError::BlockNotInTrash {
                detail: hex::encode(block_uuid),
            },

            // restore_block: the trashed file failed hybrid sig / AEAD
            // verification — exactly the "data on disk doesn't match what
            // we signed" contract, so fold to CorruptVault. Hex-encoded
            // for parity with the other UUID renderings.
            VE::RestoreVerificationFailed { block_uuid, detail } => FfiVaultError::CorruptVault {
                detail: format!(
                    "trashed block {} failed verification: {detail}",
                    hex::encode(block_uuid),
                ),
            },

            // Post-unlock integrity / structural failures and IO kinds the
            // guarded `Io` arm above did not catch: fold to `CorruptVault`.
            // These cannot leak unlock-secret information (the IBK was
            // already recovered when they fire).
            //
            // Listed explicitly (no `_ =>` catchall) so adding a new
            // `core::VaultError` variant becomes a *compile* error here
            // rather than a silent fold to `CorruptVault` — issue #40 made
            // this drift surface explicit. Any future variant must make a
            // deliberate routing decision (typed FFI variant, fold to
            // CorruptVault, or fold to a new bucket); the compiler refuses
            // to let it slip through unnoticed.
            e @ (VE::Io { .. }
            | VE::Record(_)
            | VE::Block(_)
            | VE::Manifest(_)
            | VE::Conflict(_)
            | VE::Rollback { .. }
            | VE::Card(_)
            | VE::Sig(_)
            | VE::OwnerUuidMismatch { .. }
            | VE::ManifestAuthorMismatch
            | VE::ManifestVaultUuidMismatch { .. }
            | VE::KdfParamsMismatch
            | VE::ClockOverflow { .. }
            // C.1.1b: open_vault surfaces this when an on-disk block's
            // bytes do not BLAKE3-hash to the manifest's committed
            // fingerprint. Same "data on disk doesn't match what we
            // signed" semantic as RestoreVerificationFailed → fold to
            // CorruptVault.
            | VE::BlockFingerprintMismatch { .. }) => FfiVaultError::CorruptVault {
                detail: format!("{e}"),
            },
        }
    }
}

#[cfg(test)]
mod tests;
