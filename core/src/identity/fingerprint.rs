//! Contact Card fingerprint (`docs/crypto-design.md` §6.1).
//!
//! The 16-byte fingerprint is a BLAKE3-keyed-hash over the canonical-CBOR
//! encoding of the *complete* (signed) card. It serves two purposes:
//!
//! 1. UI-side out-of-band verification ("read me your fingerprint over the
//!    phone") via the [`hex_form`] and [`mnemonic_form`] presentations.
//! 2. Wire-form recipient handle in §7's per-recipient block-key wrap. The
//!    16 bytes appear inline in each entry of the block file's recipients
//!    table, so the fingerprint length is part of the protocol surface — it
//!    cannot be widened or narrowed without a suite bump.
//!
//! The keyed-hash key is `SHA-256("secretary-v1-fingerprint")` (the §1.3
//! [`crate::crypto::kdf::TAG_FINGERPRINT`] tag, reduced to 32 bytes by
//! SHA-256). BLAKE3-keyed-hash already takes a 32-byte key, but reducing the
//! tag through SHA-256 first means the same construction works unchanged if
//! the tag is ever lengthened, and matches the §6.1 spec letter.
//!
//! ## Mnemonic encoding
//!
//! The 12-word mnemonic form is a deliberate *non*-standard BIP-39 use of
//! the English wordlist: 11 bits per word read MSB-first from the 128-bit
//! fingerprint, 12 × 11 = 132 bits total, the trailing 4 bits forced to
//! zero by the read-only-128-real-bits construction. There is no checksum
//! byte. This is documented in §6.1 and pinned by [`mnemonic_form`]'s KAT.
//! It is *not* a BIP-39 entropy-to-mnemonic round-trip; do not feed the
//! output to a standard BIP-39 validator.

use crate::crypto::hash::{keyed_hash, sha256};
use crate::crypto::kdf::TAG_FINGERPRINT;

use super::bip39_wordlist::BIP39_WORDS;

/// 16-byte (128-bit) Contact Card fingerprint. §6.1.
///
/// **Public value by design.** Fingerprints appear cleartext in the
/// recipient table of every block file (`docs/vault-format.md` §6.2),
/// in manifest signed-headers as `author_fingerprint` (§4.1), and in
/// any Contact Card the user shares for OOB verification. They are
/// `[u8; 16]` rather than [`crate::crypto::secret::Sensitive<[u8; 16]>`]
/// precisely because they are *not* secret — and `==` comparisons on
/// fingerprints (e.g. recipient-table lookup, author cross-check) are
/// intentionally non-constant-time. A side-channel timing leak on a
/// fingerprint comparison reveals at most "which entry matched in a
/// list whose contents are already visible to an observer reading the
/// cloud-folder bytes". See
/// `docs/manual/contributors/side-channel-audit-internal.md` §4 for
/// the full audit.
pub type Fingerprint = [u8; 16];

/// Compute the 16-byte fingerprint from the canonical-CBOR bytes of a
/// complete (signed) card. §6.1.
///
/// Pure function over bytes: callers produce the input via
/// [`super::card::ContactCard::to_canonical_cbor`]. Accepting raw bytes
/// (rather than `&ContactCard`) keeps this a hash primitive that can be
/// KAT-pinned against the spec without instantiating a card.
#[must_use]
pub fn fingerprint(canonical_card_bytes: &[u8]) -> Fingerprint {
    let key = sha256(TAG_FINGERPRINT);
    let h = keyed_hash(&key, canonical_card_bytes);
    let mut out = [0u8; 16];
    out.copy_from_slice(&h.as_bytes()[..16]);
    out
}

/// Lowercase hex of `fp`, grouped in 4-character blocks separated by single
/// ASCII spaces. 32 hex chars + 7 separators = 39 chars total. §6.1.
#[must_use]
pub fn hex_form(fp: &Fingerprint) -> String {
    let mut out = String::with_capacity(39);
    for (i, byte) in fp.iter().enumerate() {
        // A space appears before every byte whose pair starts a fresh 4-hex-char
        // group, except the first. Pairs sit in bytes (i = 0,1) (2,3) (4,5) ...
        // so a fresh group starts whenever i is even and i != 0.
        if i != 0 && i % 2 == 0 {
            out.push(' ');
        }
        // Two hex digits per byte; lowercase per §6.1.
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 12-word BIP-39 (English) mnemonic of `fp`. §6.1.
///
/// 11 bits per word, read MSB-first from the 128-bit fingerprint. 12 × 11 =
/// 132 bits — the trailing 4 bits are zero by construction (only 128 real
/// fingerprint bits exist; the read pads the missing bits with zero).
///
/// **Non-standard.** This is *not* the BIP-39 mnemonic-to-entropy round-trip:
/// no checksum byte. Do not validate the output with a standard BIP-39
/// validator. See module docs for context.
#[must_use]
pub fn mnemonic_form(fp: &Fingerprint) -> String {
    // Padded buffer so the (byte_offset + 2) read at the last word stays
    // in-bounds. 18 bytes is enough: 12 words × 11 bits ends at bit index
    // 131 (byte 16 bit 3), so the highest read is `extended[15..=17]`.
    let mut extended = [0u8; 18];
    extended[..16].copy_from_slice(fp);

    let mut words: Vec<&'static str> = Vec::with_capacity(12);
    for i in 0..12 {
        let bit_offset = i * 11;
        let byte_offset = bit_offset / 8;
        let bit_in_byte = bit_offset % 8;
        // Pull the 24-bit window starting at `byte_offset`. The 11 bits we
        // want sit at offset `bit_in_byte` from the window's MSB.
        let chunk = (u32::from(extended[byte_offset]) << 16)
            | (u32::from(extended[byte_offset + 1]) << 8)
            | u32::from(extended[byte_offset + 2]);
        let shift = 24 - bit_in_byte - 11;
        let word_idx = ((chunk >> shift) & 0x07ff) as usize;
        words.push(BIP39_WORDS[word_idx]);
    }
    words.join(" ")
}
