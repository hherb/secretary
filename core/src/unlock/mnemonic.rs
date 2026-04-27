//! BIP-39 24-word mnemonic wrapper for the recovery-key path
//! (`docs/crypto-design.md` §4).
//!
//! At vault creation we draw 256 bits of OS-CSPRNG entropy and encode it as a
//! 24-word BIP-39 phrase from the standard English wordlist. That same 256-bit
//! entropy is the input keying material to [`crate::crypto::kdf::derive_recovery_kek`].
//! The phrase is the user-facing artefact (printed, written down, never stored
//! by the application); the entropy is what the cryptography consumes.
//!
//! Both the phrase and the entropy are treated as sensitive: the entropy
//! lives inside [`Sensitive`] (zeroize-on-drop) and the phrase string is
//! zeroized in this module's [`Drop`] impl. There is no `Clone`, `Copy`,
//! `Display`, or content-revealing `Debug` on [`Mnemonic`] — callers that
//! need the phrase use [`Mnemonic::phrase`], which keeps every read of the
//! secret grep-able.

use core::fmt;

use bip39::{Language, Mnemonic as Bip39Mnemonic};
use rand_core::{CryptoRng, RngCore};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::crypto::secret::Sensitive;

/// 24-word BIP-39 mnemonic carrying 256 bits of entropy.
///
/// Owns both the human-readable phrase and the raw entropy. Both are
/// zeroized when the value is dropped: the entropy via [`Sensitive`]'s
/// `ZeroizeOnDrop`, the phrase via this type's explicit [`Drop`] impl.
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

/// Parse a mnemonic phrase, validating the wordlist and the BIP-39 checksum.
///
/// Input handling mirrors BIP-39 §3.1: the string is Unicode NFKD-normalized,
/// split on whitespace, and lowercased before lookup. This means the function
/// accepts mixed-case input, multiple/tabular whitespace separators, and
/// composed/decomposed Unicode forms equivalently.
///
/// Returns:
/// - [`MnemonicError::WrongLength`] if the normalized phrase is not exactly
///   24 words (other BIP-39 sizes are intentionally rejected — see §4).
/// - [`MnemonicError::UnknownWord`] if any token is not in the English
///   wordlist.
/// - [`MnemonicError::BadChecksum`] if the trailing checksum bits do not match
///   the entropy.
pub fn parse(words: &str) -> Result<Mnemonic, MnemonicError> {
    // BIP-39 §3.1: phrases are compared in Unicode NFKD form. We also
    // lowercase and collapse internal whitespace so that the canonicalized
    // string matches exactly what the bip39 crate expects.
    let nfkd: String = words.nfkd().collect();
    let normalized = nfkd
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ");

    let word_count = normalized.split_whitespace().count();
    if word_count != 24 {
        return Err(MnemonicError::WrongLength { got: word_count });
    }

    let bip = Bip39Mnemonic::parse_in_normalized(Language::English, &normalized)
        .map_err(map_bip39_error)?;

    let (full, len) = bip.to_entropy_array();
    debug_assert_eq!(len, 32, "24-word BIP-39 must produce 32 bytes of entropy");
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&full[..32]);

    Ok(Mnemonic {
        phrase: bip.to_string(),
        entropy: Sensitive::new(entropy),
    })
}

/// Map the bip39 crate's error enum onto our caller-facing variant set.
///
/// The crate reports an unknown word by *index* (position in the phrase),
/// not by content; we surface a placeholder string for now. A future
/// enhancement could re-tokenize the input to recover the offending word.
fn map_bip39_error(e: bip39::Error) -> MnemonicError {
    use bip39::Error::{
        AmbiguousLanguages, BadEntropyBitCount, BadWordCount, InvalidChecksum, UnknownWord,
    };
    match e {
        UnknownWord(_idx) => MnemonicError::UnknownWord("(unknown)".to_string()),
        InvalidChecksum => MnemonicError::BadChecksum,
        BadWordCount(n) => MnemonicError::WrongLength { got: n },
        // BadEntropyBitCount cannot arise from `parse_in_normalized` (it's a
        // from-entropy constructor failure); AmbiguousLanguages cannot arise
        // because we pin the language to English. Both are folded into
        // BadChecksum as a safe catch-all rejection — a parse failure is a
        // parse failure regardless of which structural rule was broken.
        BadEntropyBitCount(_) | AmbiguousLanguages(_) => MnemonicError::BadChecksum,
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

impl Drop for Mnemonic {
    fn drop(&mut self) {
        // `zeroize` 1.4+ provides a `Zeroize` impl for `String` that
        // overwrites the heap allocation in place (using isolated `unsafe`
        // inside the zeroize crate — this crate has `#![forbid(unsafe_code)]`
        // and does not introduce its own).
        //
        // The `entropy` field is a `Sensitive<[u8; 32]>`, which derives
        // `ZeroizeOnDrop` and is wiped automatically as part of this struct's
        // drop glue.
        self.phrase.zeroize();
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

    #[test]
    fn parse_roundtrips_generated_mnemonic() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let original = generate(&mut rng);
        let parsed = parse(original.phrase()).expect("valid mnemonic");
        assert_eq!(parsed.entropy().expose(), original.entropy().expose());
        assert_eq!(parsed.phrase(), original.phrase());
    }

    #[test]
    fn parse_normalizes_whitespace_and_case() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let m = generate(&mut rng);
        // Reformat: extra whitespace, mixed case
        let messy: String = m
            .phrase()
            .split_whitespace()
            .enumerate()
            .map(|(i, w)| if i % 2 == 0 { w.to_uppercase() } else { w.to_string() })
            .collect::<Vec<_>>()
            .join("   \t  ");
        let parsed = parse(&messy).expect("messy input must normalize");
        assert_eq!(parsed.entropy().expose(), m.entropy().expose());
    }

    #[test]
    fn parse_rejects_wrong_word_count() {
        let err = parse("abandon abandon abandon").unwrap_err();
        assert_eq!(err, MnemonicError::WrongLength { got: 3 });
    }

    #[test]
    fn parse_rejects_unknown_word() {
        // 24 words, all "valid-looking" syntactically but one is not in the list.
        // Take a real generated mnemonic and replace one word.
        let mut rng = ChaCha20Rng::from_seed([99u8; 32]);
        let m = generate(&mut rng);
        let mut words: Vec<&str> = m.phrase().split_whitespace().collect();
        words[5] = "notarealbip39word";
        let bad = words.join(" ");
        let err = parse(&bad).unwrap_err();
        assert!(matches!(err, MnemonicError::UnknownWord(_)));
    }

    #[test]
    fn mnemonic_drop_compiles() {
        // Compile-time check that `Mnemonic` has a Drop impl that runs on
        // scope exit. There is no observable behavior to assert without
        // reading freed memory; the value of this test is the implicit
        // "must call Drop" requirement on the type.
        let mut rng = ChaCha20Rng::from_seed([0u8; 32]);
        let _m = generate(&mut rng);
        // _m drops here — Drop runs.
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        // Take a valid mnemonic and swap two words from the wordlist — words
        // remain in the list but the checksum no longer matches.
        let mut rng = ChaCha20Rng::from_seed([100u8; 32]);
        let m = generate(&mut rng);
        let mut words: Vec<String> =
            m.phrase().split_whitespace().map(String::from).collect();
        words.swap(0, 1);
        let bad = words.join(" ");
        // It's possible the swap yields a still-valid checksum; for a fixed
        // seed this is deterministic. The asserted failure mode is "either
        // BadChecksum or UnknownWord", never Ok.
        let err = parse(&bad).unwrap_err();
        assert!(
            matches!(err, MnemonicError::BadChecksum | MnemonicError::UnknownWord(_)),
            "expected BadChecksum or UnknownWord, got {err:?}",
        );
    }
}
