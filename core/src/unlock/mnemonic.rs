//! BIP-39 24-word mnemonic wrapper for the recovery-key path
//! (`docs/crypto-design.md` §4).
//!
//! At vault creation we draw 256 bits of OS-CSPRNG entropy and encode it as a
//! 24-word BIP-39 phrase from the standard English wordlist. That same 256-bit
//! entropy is the input keying material to [`crate::crypto::kdf::derive_recovery_kek`].
//! The phrase is the user-facing artefact (printed, written down, never stored
//! by the application); the entropy is what the cryptography consumes.
//!
//! The entropy lives inside [`Sensitive`] (zeroize-on-drop). The phrase
//! string is treated as sensitive too; explicit zeroization on drop is added
//! in a later task. There is no `Clone`, `Copy`, `Debug`, or `Display` on
//! [`Mnemonic`] derived publicly — callers that need the phrase use
//! [`Mnemonic::phrase`], which keeps every read of the secret grep-able.

use core::fmt;

use bip39::Mnemonic as Bip39Mnemonic;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize;

use crate::crypto::secret::Sensitive;

/// 24-word BIP-39 mnemonic carrying 256 bits of entropy.
pub struct Mnemonic {
    phrase: String,
    entropy: Sensitive<[u8; 32]>,
}

/// Errors returned by mnemonic parsing.
///
/// The variants describe what was wrong with the input phrase. They are
/// `PartialEq`/`Eq` so call sites can match on a specific failure mode in
/// tests; the string payload of [`MnemonicError::UnknownWord`] participates in
/// equality.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MnemonicError {
    /// The phrase did not contain exactly 24 whitespace-separated words.
    /// v1 fixes the word count at 24 (256-bit entropy); other valid BIP-39
    /// lengths (12/15/18/21) are rejected.
    #[error("expected 24 words, got {got}")]
    WrongLength { got: usize },

    /// One of the words was not in the BIP-39 English wordlist.
    #[error("word not in BIP-39 English list: {0}")]
    UnknownWord(String),

    /// Word count and wordlist were valid but the BIP-39 checksum did not
    /// match. Indicates a typo or a tampered phrase.
    #[error("BIP-39 checksum failed")]
    BadChecksum,
}

impl Mnemonic {
    /// The 24-word phrase, space-separated, lowercase.
    /// Reading this is reading sensitive material — keep call sites visible.
    #[must_use]
    pub fn phrase(&self) -> &str {
        &self.phrase
    }

    /// The 256-bit entropy that produced (or was recovered from) the phrase.
    /// This is the input to [`crate::crypto::kdf::derive_recovery_kek`].
    #[must_use]
    pub fn entropy(&self) -> &Sensitive<[u8; 32]> {
        &self.entropy
    }
}

/// Generate a fresh 24-word mnemonic from `rng`.
///
/// `rng` must be a CSPRNG; in production this is `rand_core::OsRng` (or
/// equivalent), in tests it is typically a seeded `ChaCha20Rng` so that the
/// generated phrase is reproducible.
///
/// The local 32-byte entropy buffer is zeroized after the BIP-39 mnemonic has
/// been constructed; the entropy survives only inside the returned
/// [`Mnemonic`]'s [`Sensitive`] field.
pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Mnemonic {
    let mut entropy_buf = [0u8; 32];
    rng.fill_bytes(&mut entropy_buf);

    // `from_entropy` accepts any 16/20/24/28/32-byte input; 32 bytes always
    // succeeds and yields a 24-word English mnemonic.
    let bip = Bip39Mnemonic::from_entropy(&entropy_buf)
        .expect("32 bytes is a valid BIP-39 entropy length (24 words)");

    let phrase = bip.to_string();

    // Re-extract the entropy from the parsed mnemonic so we can move it into
    // a `Sensitive` wrapper. `to_entropy_array` returns a `[u8; 33]` plus the
    // valid byte length; for 24 words the length is always 32.
    let (full, len) = bip.to_entropy_array();
    debug_assert_eq!(len, 32, "24-word BIP-39 must produce 32 bytes of entropy");
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&full[..32]);

    // `bip` is dropped at end of scope without zeroization (the bip39 crate's
    // `zeroize` feature is off in our build, and `bip39::Mnemonic` therefore
    // implements no `Drop`). The entropy bytes still live in its `[u16; 24]`
    // words array on the stack until the slot is reused. Acceptable for the
    // recovery path: the user is expected to be staring at the phrase on
    // screen at this moment anyway. Best-effort within current dep choices.
    entropy_buf.zeroize();

    Mnemonic {
        phrase,
        entropy: Sensitive::new(entropy),
    }
}

/// Redacted debug representation. Both the phrase and the entropy are
/// secrets; the only externally observable property is "this is a 24-word
/// mnemonic". A real `Debug` impl on the contents would defeat the
/// zeroize-on-drop discipline by leaking through formatting.
impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mnemonic")
            .field("phrase", &"<redacted>")
            .field("entropy", &"<redacted>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[test]
    fn generate_produces_24_words() {
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let m = generate(&mut rng);
        assert_eq!(m.phrase().split_whitespace().count(), 24);
    }

    #[test]
    fn generate_is_deterministic_with_seeded_rng() {
        let mut rng_a = ChaCha20Rng::from_seed([7u8; 32]);
        let mut rng_b = ChaCha20Rng::from_seed([7u8; 32]);
        let a = generate(&mut rng_a);
        let b = generate(&mut rng_b);
        assert_eq!(a.phrase(), b.phrase());
        assert_eq!(a.entropy().expose(), b.entropy().expose());
    }
}
