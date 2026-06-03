//! `enumerate_contact_cards`: list every OTHER party's verified contact card
//! in `contacts/`, omitting the owner's own self-card, counting unreadable /
//! unverifiable files rather than silently dropping them (spec §3, §9.5).

use crate::contacts::{handle_wiped, read_verified_card, ContactSummary};
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Returns `(verified non-owner summaries, count of unreadable/unverifiable
/// .card files)`. The owner's own card is omitted (the owner is implicitly the
/// author/recipient of their own blocks and is never a share target).
///
/// Each summary includes `shared_block_count`: how many of the owner's live
/// blocks list that contact as a recipient. This is an in-memory scan of
/// `manifest_body().blocks[].recipients` — no decryption, no I/O.
pub fn enumerate_contact_cards(
    manifest: &OpenVaultManifest,
) -> Result<(Vec<ContactSummary>, usize), FfiVaultError> {
    let folder = manifest.vault_folder().ok_or_else(handle_wiped)?;
    let owner_uuid = manifest.owner_card().ok_or_else(handle_wiped)?.contact_uuid;
    let body = manifest.manifest_body().ok_or_else(handle_wiped)?;
    let contacts_dir = folder.join("contacts");

    let mut summaries = Vec::new();
    let mut unreadable = 0usize;

    let read_dir = match std::fs::read_dir(&contacts_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((summaries, unreadable)); // no contacts/ yet → empty
        }
        Err(e) => {
            return Err(FfiVaultError::FolderInvalid {
                detail: format!("read_dir contacts/: {e}"),
            })
        }
    };

    for entry in read_dir {
        let entry = entry.map_err(|e| FfiVaultError::FolderInvalid {
            detail: format!("iterate contacts/: {e}"),
        })?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("card") {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            unreadable += 1;
            continue;
        };
        match read_verified_card(&bytes) {
            Ok(card) if card.contact_uuid == owner_uuid => { /* omit owner */ }
            Ok(card) => {
                let shared_block_count = body
                    .blocks
                    .iter()
                    .filter(|b| b.recipients.contains(&card.contact_uuid))
                    .count() as u32;
                summaries.push(ContactSummary {
                    contact_uuid: card.contact_uuid,
                    display_name: card.display_name,
                    shared_block_count,
                });
            }
            Err(_) => unreadable += 1,
        }
    }
    Ok((summaries, unreadable))
}
