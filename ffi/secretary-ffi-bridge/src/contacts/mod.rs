//! D.1.6 contacts subsystem: enumerate / import contact cards and share a
//! block by recipient UUID. All `contacts/` directory I/O lives here so the
//! desktop layer never learns the on-disk vault layout (spec §3).
//!
//! Trust model: TOFU. Cards are PARSED with `ContactCard::from_canonical_cbor`
//! then cryptographically self-verified with `verify_self()` (both Ed25519 ∧
//! ML-DSA-65 halves) before being trusted — mirroring `core::vault::restore_block`.

mod enumerate;
pub use enumerate::enumerate_contact_cards;

mod import;
pub use import::import_contact_card;

mod export;
pub use export::owner_card_export;

mod share;
pub use share::share_block_to;

use secretary_core::identity::card::ContactCard;

use crate::error::FfiVaultError;

/// Secret-free projection of one contact card — the only contact data that
/// crosses the IPC seam (spec §3: card bytes + public keys stay server-side).
///
/// `Debug` is safe to derive: both fields are non-secret public material (the
/// `contact_uuid` and the user-facing label), so no zeroize discipline applies.
#[derive(Debug)]
pub struct ContactSummary {
    /// 16-byte contact identity (the card's `contact_uuid`).
    pub contact_uuid: [u8; 16],
    /// User-facing label from the card.
    pub display_name: String,
    /// How many of the owner's blocks list this contact as a recipient.
    /// In-memory scan of `manifest_body().blocks[].recipients` — no
    /// decryption, no I/O. Feeds the contacts-pane delete warning (spec §3).
    pub shared_block_count: u32,
}

/// Parse + cryptographically self-verify one contact card. `from_canonical_cbor`
/// only parses; `verify_self()` is the both-halves gate. Either failure →
/// `CardDecodeFailure` (the caller decides skip-and-count vs. reject).
pub(crate) fn read_verified_card(bytes: &[u8]) -> Result<ContactCard, FfiVaultError> {
    let card =
        ContactCard::from_canonical_cbor(bytes).map_err(|e| FfiVaultError::CardDecodeFailure {
            detail: e.to_string(),
        })?;
    card.verify_self()
        .map_err(|e| FfiVaultError::CardDecodeFailure {
            detail: format!("contact card self-signature verification failed: {e:?}"),
        })?;
    Ok(card)
}

/// The error returned when an `OpenVaultManifest` accessor yields `None`
/// because the handle was wiped (zeroized on lock). Shared by every
/// `contacts` primitive so the observable error is identical across them.
pub(crate) fn handle_wiped() -> FfiVaultError {
    FfiVaultError::CorruptVault {
        detail: "vault manifest handle has been wiped".to_string(),
    }
}
