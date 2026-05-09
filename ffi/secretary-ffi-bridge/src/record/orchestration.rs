//! [`read_block`] — free-function entry point that locks both handles,
//! looks up the manifest BlockEntry, reads + decodes + decrypts the
//! block file, and converts the [`BlockPlaintext`](secretary_core::vault::block::BlockPlaintext)
//! into the foreign-projection types ([`super::BlockReadOutput`],
//! [`super::Record`], [`super::FieldHandle`]).
//!
//! v1 single-author: sender = reader = vault owner. Multi-author flow
//! deferred to B.4d's `share_block`.

use secretary_core::crypto::sig::MlDsa65Public;
use secretary_core::identity::fingerprint::fingerprint;
use secretary_core::vault::block;
use secretary_core::vault::record::Record as CoreRecord;

use super::{BlockReadOutput, FieldHandle, Record};
use crate::error::FfiVaultError;
use crate::identity::{ReaderSecretKeysError, UnlockedIdentity};
use crate::vault::OpenVaultManifest;

/// Decrypt and return all records in one block of an open vault.
///
/// Borrows both handles; returns a fresh [`BlockReadOutput`] container
/// or a typed [`FfiVaultError`].
///
/// # Errors
///
/// - [`FfiVaultError::BlockNotFound`] — the requested UUID is not in
///   `manifest.blocks` (the live blocks list). `manifest.trash` is a
///   separate list and is NOT searched, so trashed UUIDs naturally
///   surface here too.
/// - [`FfiVaultError::CorruptVault`] — block file missing on disk,
///   malformed envelope, signature verification failure, decap
///   failure, AAD/tag failure, or `BlockUuidMismatch`.
/// - [`FfiVaultError::FolderInvalid`] — block file present but
///   unreadable for non-NotFound IO reasons (permissions, EBUSY, etc).
///
/// Wrong-length `block_uuid` is structurally impossible at this layer
/// (the parameter is `&[u8; 16]`); the binding-layer wrappers
/// (PyO3 / uniffi) are responsible for surfacing wrong-length input
/// as `ValueError` / `IllegalArgumentException`.
pub fn read_block(
    identity: &UnlockedIdentity,
    manifest: &OpenVaultManifest,
    block_uuid: &[u8; 16],
) -> Result<BlockReadOutput, FfiVaultError> {
    // Single-lock atomic snapshot — folds 3 sequential lock_or_recover
    // calls into 1, closing the theoretical TOCTOU window where another
    // thread could call manifest.wipe() between accessor invocations and
    // surface as a misleading CorruptVault on whichever accessor lost
    // the race.
    let (manifest_body, owner_card, vault_folder) = manifest
        .snapshot_for_read_block()
        .ok_or_else(handle_wiped)?;

    // Locate the manifest BlockEntry. Trash entries are not considered.
    let _entry = manifest_body
        .blocks
        .iter()
        .find(|b| b.block_uuid == *block_uuid)
        .ok_or_else(|| FfiVaultError::BlockNotFound {
            uuid_hex: hex::encode(block_uuid),
        })?;

    // Resolve the block file path using the standard 8-4-4-4-12 UUID
    // textual form — same convention core::vault::io uses for block files.
    let path = vault_folder
        .join("blocks")
        .join(format!("{}.cbor.enc", uuid_hyphenated(block_uuid)));

    // Read the block file from disk.
    let bytes = match std::fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(FfiVaultError::CorruptVault {
                detail: format!("block file missing for {}: {}", hex::encode(block_uuid), e),
            });
        }
        Err(e) => {
            return Err(FfiVaultError::FolderInvalid {
                detail: format!("failed to read block file: {e}"),
            });
        }
    };

    // Decode the BlockFile envelope.
    let block_file = block::decode_block_file(&bytes).map_err(|e| FfiVaultError::CorruptVault {
        detail: format!("malformed block file: {e}"),
    })?;

    // Prepare sender + reader handles. v1 single-author: sender =
    // reader = vault owner.
    let owner_canonical =
        owner_card
            .to_canonical_cbor()
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: format!("failed to canonicalize owner card: {e}"),
            })?;
    let owner_fp = fingerprint(&owner_canonical);
    let owner_pk_bundle =
        owner_card
            .pk_bundle_bytes()
            .map_err(|e| FfiVaultError::CorruptVault {
                detail: format!("failed to extract owner pk bundle: {e}"),
            })?;
    let owner_pq_pk = MlDsa65Public::from_bytes(&owner_card.ml_dsa_65_pk).map_err(|e| {
        FfiVaultError::CorruptVault {
            detail: format!("failed to parse owner ML-DSA-65 public key: {e}"),
        }
    })?;

    // Pull the reader's secret keys from the identity handle. The two
    // failure modes (closed handle vs. structurally-impossible ML-KEM-768
    // parse failure) get distinct detail strings so the foreign caller's
    // CorruptVault.detail isn't misleading when the actual failure was
    // post-unlock memory corruption rather than a deliberate close.
    let (reader_x_sk, reader_pq_sk) = identity.reader_secret_keys().map_err(|e| match e {
        ReaderSecretKeysError::HandleClosed => FfiVaultError::CorruptVault {
            detail: "identity handle has been closed".to_string(),
        },
        ReaderSecretKeysError::MlKem768ParseFailed => FfiVaultError::CorruptVault {
            detail: "identity ML-KEM-768 secret key parse failed (post-unlock memory corruption?)"
                .to_string(),
        },
    })?;

    // Hybrid verify-then-decrypt. All BlockError variants fold into
    // CorruptVault per the anti-conflation discipline.
    let plaintext = block::decrypt_block(
        &block_file,
        &owner_fp,
        &owner_pk_bundle,
        &owner_card.ed25519_pk,
        &owner_pq_pk,
        &owner_fp,
        &owner_pk_bundle,
        &reader_x_sk,
        &reader_pq_sk,
    )
    .map_err(|e| FfiVaultError::CorruptVault {
        detail: format!("block decryption failed: {e}"),
    })?;
    // Pin the drop point so the secret-key bytes are wiped HERE,
    // not at end-of-function scope (the comment-only version was
    // misleading because Rust 2021 NLL doesn't guarantee early drop
    // for bindings that aren't moved). Both Sensitive<[u8;32]> and
    // SecretBytes-wrapped MlKem768Secret implement ZeroizeOnDrop;
    // these explicit drops trigger that wipe right after decrypt
    // returns and BEFORE BlockReadOutput is constructed.
    drop(reader_x_sk);
    drop(reader_pq_sk);

    // Convert BlockPlaintext → BlockReadOutput. Preserve record order
    // (already canonical from decode_plaintext); within each record,
    // walk fields in BTreeMap iteration order.
    let mut records: Vec<Record> = Vec::with_capacity(plaintext.records.len());
    for r in plaintext.records {
        let CoreRecord {
            record_uuid,
            record_type,
            fields,
            tags,
            created_at_ms,
            last_mod_ms,
            tombstone,
            // unknown / tombstoned_at_ms intentionally not surfaced.
            ..
        } = r;

        let mut field_handles: Vec<FieldHandle> = Vec::with_capacity(fields.len());
        for (name, field) in fields {
            field_handles.push(FieldHandle::new(
                name,
                field.value,
                field.last_mod,
                field.device_uuid,
            ));
        }
        records.push(Record::new(
            record_uuid,
            record_type,
            tags,
            created_at_ms,
            last_mod_ms,
            tombstone,
            field_handles,
        ));
    }

    Ok(BlockReadOutput::new(
        plaintext.block_uuid,
        plaintext.block_name,
        records,
    ))
}

fn handle_wiped() -> FfiVaultError {
    FfiVaultError::CorruptVault {
        detail: "vault manifest handle has been wiped".to_string(),
    }
}

/// Format a 16-byte UUID in the standard 8-4-4-4-12 hyphenated form
/// (lowercase hex). Matches the on-disk filename convention used by
/// `core::vault::io` for block files.
fn uuid_hyphenated(uuid: &[u8; 16]) -> String {
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_hyphenated_formats_standard_8_4_4_4_12() {
        let uuid = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
            0xff, 0x00,
        ];
        assert_eq!(
            uuid_hyphenated(&uuid),
            "11223344-5566-7788-99aa-bbccddeeff00",
        );
        assert_eq!(
            uuid_hyphenated(&[0u8; 16]),
            "00000000-0000-0000-0000-000000000000",
        );
    }

    #[test]
    fn handle_wiped_returns_corrupt_vault_with_wiped_detail() {
        let err = handle_wiped();
        let FfiVaultError::CorruptVault { detail } = err else {
            panic!("expected CorruptVault");
        };
        assert!(detail.contains("wiped"), "detail: {detail}");
    }
}
