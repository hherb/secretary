//! `owner_card_export`: serialize the vault owner's own PUBLIC contact card for
//! handing to a peer (the symmetric counterpart to `import_contact_card`).
//!
//! No secret material — a contact card holds only public keys + display name +
//! uuid. The destination (an external folder) is written by the desktop edge;
//! the bridge only yields the canonical file name + bytes (spec §3, §5).

use secretary_core::vault::format_uuid_hyphenated;

use crate::contacts::handle_wiped;
use crate::error::FfiVaultError;
use crate::vault::OpenVaultManifest;

/// Return the canonical export file name (`<hyphenated-owner-uuid>.card` — the
/// name a peer's `import_contact_card` re-derives from the card's own uuid)
/// and the canonical-CBOR bytes of the owner's contact card.
///
/// Single lock acquisition: `owner_card()` clones the verified card, and we
/// serialize that clone directly (avoiding a second `owner_card_bytes()` lock
/// and the wipe-between-accessors gap).
///
/// - manifest handle wiped → [`FfiVaultError::CorruptVault`] (via `handle_wiped`).
/// - `to_canonical_cbor` failure (unreachable for a card validated at unlock;
///   the `Result` is preserved per issue #41) → [`FfiVaultError::CorruptVault`].
pub fn owner_card_export(manifest: &OpenVaultManifest) -> Result<(String, Vec<u8>), FfiVaultError> {
    let card = manifest.owner_card().ok_or_else(handle_wiped)?;
    let file_name = format!("{}.card", format_uuid_hyphenated(&card.contact_uuid));
    let bytes = card
        .to_canonical_cbor()
        .map_err(|e| FfiVaultError::CorruptVault {
            detail: format!("owner card re-encode failed: {e}"),
        })?;
    Ok((file_name, bytes))
}
