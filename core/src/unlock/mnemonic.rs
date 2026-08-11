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

use crate::crypto::secret::{SecretString, Sensitive};

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
/// tests.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MnemonicError {
    /// The phrase did not contain exactly 24 whitespace-separated words.
    /// v1 fixes the word count at 24 (256-bit entropy); other valid BIP-39
    /// lengths (12/15/18/21) are rejected.
    #[error("expected 24 words, got {got}")]
    WrongLength { got: usize },

    /// One of the words was not in the BIP-39 English wordlist. Carries the
    /// 0-based `index` of the offending word, NOT its content: the word is
    /// recovery-phrase material and must never reach logs, crash reporters, or
    /// analytics via an error message (a typo is typically ~1 edit from the
    /// real word, leaking one of the 24 phrase words). See #358.
    #[error("recovery-phrase word #{} is not in the BIP-39 English list", .index + 1)]
    UnknownWord { index: usize },

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
/// Both the local entropy buffer and the entropy stored in the returned
/// [`Mnemonic`] are built in place inside a [`Sensitive`] wrapper via
/// `Sensitive::build`: the wrapper exists *before* it is filled, so its
/// `ZeroizeOnDrop` wipe covers every exit from this function, including an
/// unwinding panic (#513). This closes a gap a prior version of this
/// comment described inaccurately — it claimed a wipe that in fact covered
/// only the local scratch buffer (`entropy_buf`), while the copy handed to
/// the caller was moved into the returned [`Mnemonic`] via `Sensitive::new`,
/// which, since `[u8; 32]` is `Copy`, left the source stack slot holding a
/// dirty, unwiped copy with no wipe call anywhere for it — not an exit-path
/// leak like `parse`'s below, just a missing wipe (spec §3.4, tracked under
/// the #513 umbrella).
pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Mnemonic {
    let entropy_buf = Sensitive::build([0u8; 32], |buf| rng.fill_bytes(buf));

    // `from_entropy` accepts any 16/20/24/28/32-byte input; 32 bytes always
    // succeeds and yields a 24-word English mnemonic.
    let bip = Bip39Mnemonic::from_entropy(entropy_buf.expose())
        .expect("32 bytes is a valid BIP-39 entropy length (24 words)");

    let phrase = bip.to_string();

    // Re-extract the entropy from the parsed mnemonic so we can move it into
    // a `Sensitive` wrapper. `to_entropy_array` returns a `[u8; 33]` plus the
    // valid byte length; for 24 words the length is always 32. The 33-byte
    // buffer is on our stack — bind it `mut` so we can zeroize the full
    // 33-byte slot once the trimmed entropy has been copied out.
    let (mut full, len) = bip.to_entropy_array();
    debug_assert_eq!(len, 32, "24-word BIP-39 must produce 32 bytes of entropy");

    // The bip39 crate's `zeroize` feature is enabled in our build, so the
    // local `bip` value's internal `[u16; 24]` words array is wiped when it
    // goes out of scope. `entropy_buf` wipes itself on drop regardless of how
    // this function exits (`Sensitive` is `ZeroizeOnDrop`). `full`, the
    // 33-byte output buffer returned by `to_entropy_array`, is not under the
    // bip39 crate's automatic zeroize coverage once it leaves its API, so we
    // zeroize it explicitly once the trimmed entropy has been copied out
    // below.
    let entropy = Sensitive::build([0u8; 32], |slot| slot.copy_from_slice(&full[..32]));
    full.zeroize();

    Mnemonic { phrase, entropy }
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
    let mut nfkd: String = words.nfkd().collect();
    let mut parts: Vec<String> = nfkd.split_whitespace().map(str::to_lowercase).collect();
    let normalized = SecretString::new(parts.join(" "));
    // `nfkd` and the per-word lowercase `parts` hold recovery-phrase material;
    // wipe them now. `normalized` is a `SecretString`, whose `ZeroizeOnDrop`
    // wipes it on every exit from here on — both early-return branches
    // below, the happy path, and an unwinding panic (#518; the previous
    // explicit `normalized.zeroize()` near the end of this function only ran
    // on the path that reached it, which excluded both error returns). See
    // #357.
    nfkd.zeroize();
    parts.iter_mut().for_each(Zeroize::zeroize);

    let tokens: Vec<&str> = normalized.expose().split_whitespace().collect();
    if tokens.len() != 24 {
        return Err(MnemonicError::WrongLength { got: tokens.len() });
    }

    // The bip39 crate reports `UnknownWord` by index into the phrase. We carry
    // that index through verbatim — NOT the word content, which is
    // recovery-phrase material that must not leak into an error message (#358).
    let bip = Bip39Mnemonic::parse_in_normalized(Language::English, normalized.expose())
        .map_err(|e| match e {
            bip39::Error::UnknownWord(idx) => MnemonicError::UnknownWord { index: idx },
            other => map_bip39_error(other),
        })?;
    // `tokens` borrows `normalized`; drop that borrow explicitly rather than
    // let it ride to the end of the function, keeping the two bindings'
    // lifetimes as narrow as they were before this change. `normalized`
    // itself is no longer wiped here — its `SecretString` wipe now happens
    // via `Drop` regardless of which exit this function takes. See #357.
    drop(tokens);

    // Same 33-byte stack residue as `generate`: zeroize the full buffer
    // after the trimmed 32-byte entropy has been copied out, since the
    // bip39 crate's automatic zeroize coverage stops at its API boundary.
    let (mut full, len) = bip.to_entropy_array();
    debug_assert_eq!(len, 32, "24-word BIP-39 must produce 32 bytes of entropy");
    let mut entropy = [0u8; 32];
    entropy.copy_from_slice(&full[..32]);
    full.zeroize();

    let secret = Sensitive::new(entropy);
    // `Sensitive::new` copied `entropy` (`[u8; 32]: Copy`); wipe the source
    // stack slot so the entropy only lives inside `secret`. See #357.
    entropy.zeroize();
    Ok(Mnemonic {
        phrase: bip.to_string(),
        entropy: secret,
    })
}

/// Map the bip39 crate's error enum onto our caller-facing variant set.
///
/// The `UnknownWord` arm IS listed in the match below for exhaustiveness,
/// but it is intercepted at the call site in [`parse`] before reaching
/// this function (the call site maps the crate's word *index* straight onto
/// `MnemonicError::UnknownWord { index }`). The match arm here is therefore
/// unreachable in normal operation — see the comment on that arm for why
/// mapping to `BadChecksum` is the right fallback if the bip39 crate's
/// behaviour ever changes.
fn map_bip39_error(e: bip39::Error) -> MnemonicError {
    use bip39::Error::{
        AmbiguousLanguages, BadEntropyBitCount, BadWordCount, InvalidChecksum, UnknownWord,
    };
    match e {
        InvalidChecksum => MnemonicError::BadChecksum,
        BadWordCount(n) => MnemonicError::WrongLength { got: n },

        // The three remaining variants are unreachable from
        // `parse_in_normalized` in [`parse`]'s call pattern but must be
        // listed for exhaustiveness:
        //
        // - `UnknownWord`: caught and converted to
        //   `MnemonicError::UnknownWord { index }` (carrying only the word
        //   *index*, never the content, #358) at the [`parse`] call site
        //   BEFORE the result reaches this function. If the bip39 crate's
        //   contract ever changes such that
        //   `UnknownWord` slips past the call site, mapping to
        //   `BadChecksum` is a safe fallback — bad input is bad input.
        // - `BadEntropyBitCount`: only constructable by from-entropy
        //   constructors (e.g. `Mnemonic::from_entropy_in`), not by the
        //   parser.
        // - `AmbiguousLanguages`: only constructable when the language is
        //   auto-detected; we pin to English via `parse_in_normalized`.
        UnknownWord(_) | BadEntropyBitCount(_) | AmbiguousLanguages(_) => {
            MnemonicError::BadChecksum
        }
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
            .map(|(i, w)| {
                if i.is_multiple_of(2) {
                    w.to_uppercase()
                } else {
                    w.to_string()
                }
            })
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
        // The payload carries the 0-based index (word #6), NOT the content.
        assert_eq!(err, MnemonicError::UnknownWord { index: 5 });
        // #358: the offending word must never appear in the error message
        // (it would leak recovery-phrase material into logs / crash reporters).
        let rendered = err.to_string();
        assert!(
            !rendered.contains("notarealbip39word"),
            "error message leaked the phrase word: {rendered}",
        );
        assert!(
            rendered.contains("#6"),
            "expected 1-based position, got {rendered}"
        );
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
        let mut words: Vec<String> = m.phrase().split_whitespace().map(String::from).collect();
        words.swap(0, 1);
        let bad = words.join(" ");
        // It's possible the swap yields a still-valid checksum; for a fixed
        // seed this is deterministic. The asserted failure mode is "either
        // BadChecksum or UnknownWord", never Ok.
        let err = parse(&bad).unwrap_err();
        assert!(
            matches!(
                err,
                MnemonicError::BadChecksum | MnemonicError::UnknownWord { .. }
            ),
            "expected BadChecksum or UnknownWord, got {err:?}",
        );
    }

    // #518: `parse` used to return on these two paths WITHOUT wiping
    // `normalized`, the `String` (now `SecretString`) holding the user's
    // full recovery phrase — including `UnknownWord`, which is what fires
    // when a user mistypes one word while recovering a vault.
    //
    // A wipe of a freed heap buffer is not observable from safe Rust (spec
    // §5.4), so these two tests do NOT assert the wipe itself. Their job is
    // to pin that both leaking paths are reached and keep their exact error
    // variants, so the converted code is covered by execution rather than
    // by inspection alone. Do not read a passing `Ok`/error-variant result
    // here as evidence the memory was zeroed.
    //
    // Each duplicates an assertion `parse_rejects_wrong_word_count` /
    // `parse_rejects_unknown_word` above already made before this fix
    // existed (fix-round-1 review finding); they're kept anyway, named
    // explicitly after the two leaking paths, as the tests this fix's own
    // history point to. `parse_rejects_an_unknown_word_by_index_only` below
    // additionally carries over the #358 redaction assertion so it is a
    // strict superset of the test it duplicates, not merely a same-input
    // rerun of it.

    #[test]
    fn parse_rejects_a_short_phrase_with_wrong_length() {
        let err = parse("abandon abandon abandon").unwrap_err();
        assert!(
            matches!(err, MnemonicError::WrongLength { got: 3 }),
            "expected WrongLength {{ got: 3 }}, got {err:?}"
        );
    }

    #[test]
    fn parse_rejects_an_unknown_word_by_index_only() {
        // Take a valid 24-word phrase and corrupt exactly one word, which is
        // the realistic failure: a typo during vault recovery.
        let mut rng = ChaCha20Rng::from_seed([222u8; 32]);
        let good = generate(&mut rng);
        let mut words: Vec<&str> = good.phrase().split_whitespace().collect();
        words[7] = "notaword";
        let err = parse(&words.join(" ")).unwrap_err();

        assert!(
            matches!(err, MnemonicError::UnknownWord { index: 7 }),
            "expected UnknownWord {{ index: 7 }}, got {err:?}"
        );
        // #358: the offending word must never appear in the error message
        // (it would leak recovery-phrase material into logs / crash reporters).
        let rendered = err.to_string();
        assert!(
            !rendered.contains("notaword"),
            "error message leaked the phrase word: {rendered}",
        );
        assert!(
            rendered.contains("#8"),
            "expected 1-based position, got {rendered}"
        );
    }
}
