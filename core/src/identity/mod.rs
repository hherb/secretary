//! Contact Cards (§6) and fingerprints (§6.1).
//!
//! A Contact Card is the public, signed artifact a user shares to identify
//! themselves to others. Its byte form is a CBOR map serialized in a
//! deterministic field order so that the self-signature and the fingerprint
//! both have stable byte commitments. See `docs/crypto-design.md` §6 for the
//! map shape and §6.1 for the fingerprint construction.
//!
//! Two of the things later modules will need from here also live in this
//! module:
//! - [`card::ContactCard::pk_bundle_bytes`] — the canonical encoding of the
//!   four public-key fields used by §7's hybrid-KEM combiner as the
//!   `sender_pk_bundle` / `recipient_pk_bundle` HKDF inputs.
//! - [`fingerprint::fingerprint`] — the 16-byte short ID used as a recipient
//!   handle in §7's wire form.
//!
//! The Identity Bundle (§5) does *not* live here; it depends on the unlock
//! module (Argon2id-derived Master KEK and Recovery KEK) which is the next
//! build-sequence step.

pub mod card;
pub mod fingerprint;

mod bip39_wordlist;
