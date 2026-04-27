# `core/src/unlock/` Module Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the `unlock` module (`core/src/unlock/`) — five files providing pure-function APIs for vault creation, master-password unlock, and recovery-mnemonic unlock; plus the §15 BIP-39 recovery KAT.

**Architecture:** Bytes-in / bytes-out, no filesystem I/O, no clock reads. Five files split by purpose: `mnemonic.rs` (BIP-39 wrapper), `bundle.rs` (`IdentityBundle` plaintext + canonical CBOR), `bundle_file.rs` (`identity.bundle.enc` binary framing), `vault_toml.rs` (TOML ser/de), `mod.rs` (composition + `UnlockError`). Each submodule exposes free functions; `mod.rs` composes them into `create_vault`, `open_with_password`, `open_with_recovery`. RNG is injected — production passes `OsRng`, tests pass seeded `ChaCha20Rng`.

**Tech Stack:** Rust 2021 (stable). New crates: `bip39 = "2"`, `toml = "0.8"`, `base64 = "0.22"`. Existing primitives reused: `crypto::kdf::{derive_master_kek, derive_recovery_kek, Argon2idParams, TAG_*}`, `crypto::aead::{encrypt, decrypt, AeadKey, AeadNonce, AEAD_TAG_LEN}`, `crypto::secret::{SecretBytes, Sensitive}`, `crypto::sig::{generate_ed25519, generate_ml_dsa_65}`, `crypto::kem::{generate_x25519, generate_ml_kem_768}` (look up exact names per existing module).

**Spec:** `docs/superpowers/specs/2026-04-27-unlock-module-design.md`. Spec sections referenced as e.g. "spec §Error model" below.

**Verification at the end:** `cargo test --release --workspace` green; `cargo clippy --all-targets -- -D warnings` clean.

---

## Task 1: Add Cargo dependencies

**Files:**
- Modify: `core/Cargo.toml`

- [ ] **Step 1.1: Add three production dependencies**

In `core/Cargo.toml`, add to the `[dependencies]` table (alphabetical insertion in the existing list):

```toml
base64 = "0.22"
bip39 = "2"
toml = "0.8"
```

- [ ] **Step 1.2: Verify the dependency graph resolves**

Run: `cargo check -p secretary-core`
Expected: clean compile, three new crates appear in `Cargo.lock`. No code changes yet so no warnings other than the existing ones.

- [ ] **Step 1.3: Commit**

```bash
git add core/Cargo.toml Cargo.lock
git commit -m "feat(core): add bip39, toml, base64 deps for unlock module"
```

---

## Task 2: `mnemonic.rs` — Mnemonic type + generate

**Files:**
- Create: `core/src/unlock/mnemonic.rs`
- Modify: `core/src/unlock/mod.rs` (add `pub mod mnemonic;`)

- [ ] **Step 2.1: Write the failing test**

Create `core/src/unlock/mnemonic.rs` with module skeleton + a test that exercises generate.

> **Note on `bip39` crate API:** Method names below assume the public API of the `bip39` crate v2.x — specifically a constructor that takes 32 bytes of entropy and produces a 24-word English mnemonic, and a parser that validates a phrase string against the English wordlist with checksum. If the actual crate exposes different names (`from_entropy_in`, `parse_in`, `to_entropy`, etc.), substitute the correct ones — the spec is "convert between 32-byte entropy and 24-word phrase" regardless of how the crate spells it. Run `cargo doc --open -p bip39` if uncertain.

```rust
//! BIP-39 mnemonic wrapper for the recovery-key path (`docs/crypto-design.md` §4).
//!
//! The mnemonic is generated as 256 bits of OS-CSPRNG entropy at vault creation
//! and encoded as a 24-word BIP-39 phrase from the standard English wordlist.
//! The 256-bit entropy is the input to `derive_recovery_kek` (`crypto::kdf`).

use bip39::Mnemonic as Bip39Mnemonic;
use rand_core::{CryptoRng, RngCore};
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroize;

use crate::crypto::secret::Sensitive;

/// 24-word BIP-39 mnemonic carrying 256 bits of entropy.
pub struct Mnemonic {
    phrase: String,
    entropy: Sensitive<[u8; 32]>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MnemonicError {
    #[error("expected 24 words, got {got}")]
    WrongLength { got: usize },
    #[error("word not in BIP-39 English list: {0}")]
    UnknownWord(String),
    #[error("BIP-39 checksum failed")]
    BadChecksum,
}

pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Mnemonic {
    let mut entropy = [0u8; 32];
    rng.fill_bytes(&mut entropy);
    let bip = Bip39Mnemonic::from_entropy(&entropy)
        .expect("32 bytes is a valid BIP-39 entropy length (24 words)");
    let phrase = bip.to_string();
    entropy.zeroize();
    Mnemonic {
        phrase,
        entropy: Sensitive::new(*bip.to_entropy_array().0.as_ref()
            .first_chunk::<32>()
            .expect("BIP-39 24-word produces 32 bytes")),
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
}
```

Add `pub fn phrase(&self) -> &str { &self.phrase }` accessor.

In `core/src/unlock/mod.rs`, replace the stub with:

```rust
//! Master-password and recovery-key unlock paths.
//! See `docs/crypto-design.md` §3 (Master KEK), §4 (Recovery KEK), §5 (Identity Bundle wrap)
//! and `docs/vault-format.md` §2 (vault.toml), §3 (identity.bundle.enc).

pub mod mnemonic;
```

Also add `unicode-normalization = "0.1"` to `core/Cargo.toml` (needed by Step 4) — fold this into a single dep-update commit if Task 1 is still recent, or commit separately.

- [ ] **Step 2.2: Run test — verify it compiles and passes**

Run: `cargo test -p secretary-core --release unlock::mnemonic::tests::generate_produces_24_words`
Expected: PASS.

- [ ] **Step 2.3: Add a determinism assertion**

Append to `mod tests`:

```rust
#[test]
fn generate_is_deterministic_with_seeded_rng() {
    let mut rng_a = ChaCha20Rng::from_seed([7u8; 32]);
    let mut rng_b = ChaCha20Rng::from_seed([7u8; 32]);
    let a = generate(&mut rng_a);
    let b = generate(&mut rng_b);
    assert_eq!(a.phrase(), b.phrase());
    assert_eq!(a.entropy().expose(), b.entropy().expose());
}
```

Add `pub fn entropy(&self) -> &Sensitive<[u8; 32]> { &self.entropy }` accessor.

Run: `cargo test -p secretary-core --release unlock::mnemonic::tests::generate_is_deterministic_with_seeded_rng`
Expected: PASS.

- [ ] **Step 2.4: Commit**

```bash
git add core/Cargo.toml core/src/unlock/
git commit -m "feat(unlock): mnemonic::generate (BIP-39 24-word from CSPRNG)"
```

---

## Task 3: `mnemonic::parse` — happy path with NFKD normalization

**Files:**
- Modify: `core/src/unlock/mnemonic.rs`

- [ ] **Step 3.1: Write the failing test**

Append to `mod tests`:

```rust
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
    let messy: String = m.phrase()
        .split_whitespace()
        .enumerate()
        .map(|(i, w)| if i % 2 == 0 { w.to_uppercase() } else { w.to_string() })
        .collect::<Vec<_>>()
        .join("   \t  ");
    let parsed = parse(&messy).expect("messy input must normalize");
    assert_eq!(parsed.entropy().expose(), m.entropy().expose());
}
```

Run: `cargo test -p secretary-core --release unlock::mnemonic::tests::parse_roundtrips`
Expected: FAIL (`parse` not defined).

- [ ] **Step 3.2: Implement `parse`**

Add to `mnemonic.rs` (above `#[cfg(test)]`):

```rust
pub fn parse(words: &str) -> Result<Mnemonic, MnemonicError> {
    // BIP-39 §3.1 standardizes Unicode NFKD normalization on the phrase.
    let nfkd: String = words.nfkd().collect();
    let normalized = nfkd
        .split_whitespace()
        .map(|w| w.to_lowercase())
        .collect::<Vec<_>>()
        .join(" ");

    let word_count = normalized.split_whitespace().count();
    if word_count != 24 {
        return Err(MnemonicError::WrongLength { got: word_count });
    }

    let bip = Bip39Mnemonic::parse_in_normalized(bip39::Language::English, &normalized)
        .map_err(map_bip39_error)?;

    let entropy_bytes = bip.to_entropy_array().0;
    let entropy: [u8; 32] = entropy_bytes
        .as_ref()
        .first_chunk::<32>()
        .copied()
        .expect("24-word BIP-39 produces 32 bytes of entropy");

    Ok(Mnemonic {
        phrase: bip.to_string(),
        entropy: Sensitive::new(entropy),
    })
}

fn map_bip39_error(e: bip39::Error) -> MnemonicError {
    use bip39::Error::*;
    match e {
        UnknownWord(_idx) => {
            // The bip39 crate reports the index of the bad word, not the word
            // itself. Caller can re-tokenize to find the offending word if
            // needed; for now we surface a generic placeholder.
            MnemonicError::UnknownWord("(unknown)".to_string())
        }
        InvalidChecksum => MnemonicError::BadChecksum,
        BadWordCount(n) => MnemonicError::WrongLength { got: n },
        // Any other variant in this version of bip39: treat as checksum
        // failure (the catch-all is safe — bad-input means rejection).
        _ => MnemonicError::BadChecksum,
    }
}
```

- [ ] **Step 3.3: Run tests**

Run: `cargo test -p secretary-core --release unlock::mnemonic::tests`
Expected: all four tests PASS.

- [ ] **Step 3.4: Commit**

```bash
git add core/src/unlock/mnemonic.rs
git commit -m "feat(unlock): mnemonic::parse with NFKD normalization"
```

---

## Task 4: `mnemonic::parse` — error variants

**Files:**
- Modify: `core/src/unlock/mnemonic.rs`

- [ ] **Step 4.1: Write the failing tests**

Append to `mod tests`:

```rust
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
fn parse_rejects_bad_checksum() {
    // Take a valid mnemonic and swap two words from the wordlist — words
    // remain in the list but the checksum no longer matches.
    let mut rng = ChaCha20Rng::from_seed([100u8; 32]);
    let m = generate(&mut rng);
    let mut words: Vec<String> = m.phrase().split_whitespace().map(String::from).collect();
    words.swap(0, 1);
    let bad = words.join(" ");
    // It's possible the swap yields a still-valid checksum; if so, swap a
    // different pair. For a fixed seed this is deterministic; the asserted
    // failure mode is "either BadChecksum or UnknownWord", never Ok.
    let err = parse(&bad).unwrap_err();
    assert!(
        matches!(err, MnemonicError::BadChecksum | MnemonicError::UnknownWord(_)),
        "expected BadChecksum or UnknownWord, got {err:?}",
    );
}
```

Run: `cargo test -p secretary-core --release unlock::mnemonic::tests::parse_rejects`
Expected: PASS (the implementation in Task 3 already returns these variants).

- [ ] **Step 4.2: Verify and commit**

Run: `cargo test -p secretary-core --release unlock::mnemonic::tests`
Expected: all 7 tests PASS.

```bash
git add core/src/unlock/mnemonic.rs
git commit -m "test(unlock): mnemonic::parse error variants"
```

---

## Task 5: `mnemonic` — entropy zeroization on drop

**Files:**
- Modify: `core/src/unlock/mnemonic.rs`

- [ ] **Step 5.1: Add Drop impl for phrase zeroization**

The `entropy` field is already `Sensitive<[u8;32]>` which zeroizes on drop. The `phrase` field is a `String` containing the human-readable mnemonic — it should also be zeroed when the `Mnemonic` is dropped (treating the phrase as sensitive).

Add to `mnemonic.rs`:

```rust
impl Drop for Mnemonic {
    fn drop(&mut self) {
        // String doesn't have a stable zeroize-on-drop in std, but its
        // backing Vec<u8> can be zeroed via the underlying buffer.
        // SAFETY: we own the String; replacing its bytes does not affect
        // any outstanding &str borrow because Drop runs after all borrows
        // have ended.
        let bytes = unsafe { self.phrase.as_bytes_mut() };
        bytes.zeroize();
    }
}
```

Wait — `as_bytes_mut` is `unsafe` because writing arbitrary bytes can break UTF-8 invariants. We use it here for zeroization where `0x00` is valid UTF-8 (ASCII NUL), so the resulting String becomes a string of NULs — a valid (if odd) UTF-8 string. But the crate has `#![forbid(unsafe_code)]` at the root.

Replace with a safe alternative — use the `zeroize` crate's String support (which does the same thing internally with the unsafe block scoped):

```rust
impl Drop for Mnemonic {
    fn drop(&mut self) {
        // `zeroize` provides a Zeroize impl for String that overwrites the
        // underlying bytes. `Sensitive<[u8;32]>` handles the entropy field
        // automatically.
        self.phrase.zeroize();
    }
}
```

`zeroize::Zeroize` is implemented for `String` in zeroize ≥ 1.4. Verify in the existing `Cargo.lock` that the version supports it.

- [ ] **Step 5.2: Add a smoke test for Drop semantics**

This is a structural test — we can't directly observe zeroization without unsafe pointer reads, so the test only confirms the impl compiles and behaves on a fresh value:

```rust
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
```

- [ ] **Step 5.3: Run all mnemonic tests + clippy**

Run: `cargo test -p secretary-core --release unlock::mnemonic::tests`
Expected: 8 tests PASS.

Run: `cargo clippy -p secretary-core --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 5.4: Commit**

```bash
git add core/src/unlock/mnemonic.rs
git commit -m "feat(unlock): zeroize Mnemonic phrase + entropy on drop"
```

---

## Task 6: `bundle.rs` — `IdentityBundle` struct + generate

**Files:**
- Create: `core/src/unlock/bundle.rs`
- Modify: `core/src/unlock/mod.rs` (add `pub mod bundle;`)

- [ ] **Step 6.1: Inspect existing keypair generators**

Read `core/src/crypto/sig.rs` and `core/src/crypto/kem.rs` to find the exact names and return types of:
- X25519 keypair generation
- ML-KEM-768 keypair generation
- Ed25519 keypair generation
- ML-DSA-65 keypair generation

Pin those names; use them in Step 6.2. Do not invent names.

- [ ] **Step 6.2: Write the failing test + struct**

Create `core/src/unlock/bundle.rs`:

```rust
//! IdentityBundle plaintext (`docs/crypto-design.md` §5).
//!
//! The §5 record carries the four (sk, pk) pairs that constitute a user's
//! cryptographic identity, plus a UUID, a display name, and a creation
//! timestamp. Encoded as canonical CBOR per §6.2 (RFC 8949 §4.2.1).

use rand_core::{CryptoRng, RngCore};

use crate::crypto::secret::Sensitive;
// ... import the keypair generators identified in Step 6.1 ...

pub const USER_UUID_LEN: usize = 16;
pub const X25519_SK_LEN: usize = 32;
pub const X25519_PK_LEN: usize = 32;
pub const ML_KEM_768_SK_LEN: usize = 2400;
pub const ML_KEM_768_PK_LEN: usize = 1184;
pub const ED25519_SK_LEN: usize = 32;
pub const ED25519_PK_LEN: usize = 32;
pub const ML_DSA_65_SK_LEN: usize = 4032;
pub const ML_DSA_65_PK_LEN: usize = 1952;

pub struct IdentityBundle {
    pub user_uuid: [u8; USER_UUID_LEN],
    pub display_name: String,
    pub x25519_sk: Sensitive<[u8; X25519_SK_LEN]>,
    pub x25519_pk: [u8; X25519_PK_LEN],
    pub ml_kem_768_sk: Sensitive<Vec<u8>>,   // 2400 bytes; Vec since the
                                              // RustCrypto type is sized via
                                              // generic params, not const
    pub ml_kem_768_pk: Vec<u8>,               // 1184 bytes
    pub ed25519_sk: Sensitive<[u8; ED25519_SK_LEN]>,
    pub ed25519_pk: [u8; ED25519_PK_LEN],
    pub ml_dsa_65_sk: Sensitive<Vec<u8>>,     // 4032 bytes
    pub ml_dsa_65_pk: Vec<u8>,                // 1952 bytes
    pub created_at_ms: u64,
}

pub fn generate(
    display_name: &str,
    created_at_ms: u64,
    rng: &mut (impl RngCore + CryptoRng),
) -> IdentityBundle {
    let mut user_uuid = [0u8; USER_UUID_LEN];
    rng.fill_bytes(&mut user_uuid);

    // Use the existing crypto::sig and crypto::kem generators identified
    // in Step 6.1. Each returns (sk, pk) in some form; convert to the
    // byte-array shape declared above.
    todo!("call generate_x25519, generate_ml_kem_768, generate_ed25519, generate_ml_dsa_65 from rng")
}
```

Add a test:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[test]
    fn generate_produces_consistent_keypairs() {
        let mut rng = ChaCha20Rng::from_seed([5u8; 32]);
        let b = generate("Alice", 1_714_060_800_000, &mut rng);

        assert_eq!(b.display_name, "Alice");
        assert_eq!(b.created_at_ms, 1_714_060_800_000);
        assert_eq!(b.x25519_sk.expose().len(), X25519_SK_LEN);
        assert_eq!(b.x25519_pk.len(), X25519_PK_LEN);
        assert_eq!(b.ml_kem_768_sk.expose().len(), ML_KEM_768_SK_LEN);
        assert_eq!(b.ml_kem_768_pk.len(), ML_KEM_768_PK_LEN);
        assert_eq!(b.ed25519_sk.expose().len(), ED25519_SK_LEN);
        assert_eq!(b.ed25519_pk.len(), ED25519_PK_LEN);
        assert_eq!(b.ml_dsa_65_sk.expose().len(), ML_DSA_65_SK_LEN);
        assert_eq!(b.ml_dsa_65_pk.len(), ML_DSA_65_PK_LEN);
    }
}
```

In `core/src/unlock/mod.rs`:

```rust
pub mod mnemonic;
pub mod bundle;
```

Run: `cargo test -p secretary-core --release unlock::bundle::tests`
Expected: FAIL (compile error, `todo!()` in `generate`).

- [ ] **Step 6.3: Replace `todo!()` with real keypair generation**

Using the names identified in Step 6.1, fill in the four keypair calls. For each, the pattern is:
```rust
let (sk, pk) = generate_xxx(rng);
let xxx_sk = Sensitive::new(sk_bytes_array_or_vec);
let xxx_pk = pk_bytes_array_or_vec;
```

If a generator already returns `Sensitive<...>` for the secret key, use it directly without re-wrapping.

Run: `cargo test -p secretary-core --release unlock::bundle::tests`
Expected: PASS.

- [ ] **Step 6.4: Commit**

```bash
git add core/src/unlock/bundle.rs core/src/unlock/mod.rs
git commit -m "feat(unlock): IdentityBundle struct + generate"
```

---

## Task 7: `bundle.rs` — `to_canonical_cbor`

**Files:**
- Modify: `core/src/unlock/bundle.rs`

- [ ] **Step 7.1: Write the failing test**

Append to `mod tests`:

```rust
#[test]
fn canonical_cbor_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let b = generate("Bob", 1_714_060_800_001, &mut rng);
    let bytes = b.to_canonical_cbor().expect("encode");
    let parsed = IdentityBundle::from_canonical_cbor(&bytes).expect("decode");
    // Equality comparison: secret-key sensitive fields don't impl PartialEq,
    // so compare exposed contents explicitly.
    assert_eq!(parsed.user_uuid, b.user_uuid);
    assert_eq!(parsed.display_name, b.display_name);
    assert_eq!(parsed.x25519_sk.expose(), b.x25519_sk.expose());
    assert_eq!(parsed.x25519_pk, b.x25519_pk);
    assert_eq!(parsed.ml_kem_768_sk.expose(), b.ml_kem_768_sk.expose());
    assert_eq!(parsed.ml_kem_768_pk, b.ml_kem_768_pk);
    assert_eq!(parsed.ed25519_sk.expose(), b.ed25519_sk.expose());
    assert_eq!(parsed.ed25519_pk, b.ed25519_pk);
    assert_eq!(parsed.ml_dsa_65_sk.expose(), b.ml_dsa_65_sk.expose());
    assert_eq!(parsed.ml_dsa_65_pk, b.ml_dsa_65_pk);
    assert_eq!(parsed.created_at_ms, b.created_at_ms);
}

#[test]
fn canonical_cbor_is_byte_stable() {
    let mut rng = ChaCha20Rng::from_seed([6u8; 32]);
    let b = generate("Bob", 1_714_060_800_001, &mut rng);
    let bytes_1 = b.to_canonical_cbor().expect("encode");
    let bytes_2 = b.to_canonical_cbor().expect("encode");
    assert_eq!(bytes_1, bytes_2, "canonical encoding must be deterministic");
}
```

Run: expected FAIL (`to_canonical_cbor` and `from_canonical_cbor` do not exist).

- [ ] **Step 7.2: Implement encoder + decoder**

Use the same pattern as `core/src/identity/card.rs`: build a `ciborium::Value::Map` with bytewise-lex-sorted keys, write with `ciborium::ser::into_writer`, and on decode walk the map enforcing strict canonical form.

Add to `bundle.rs` (above `#[cfg(test)]`):

```rust
use ciborium::Value;

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("CBOR encode/decode error: {0}")]
    CborDecode(String),
    #[error("input was not in canonical CBOR form")]
    NonCanonicalCbor,
    #[error("unknown bundle field: {0}")]
    UnknownField(String),
    #[error("duplicate field: {0}")]
    DuplicateField(String),
    #[error("wrong key size for {field}: expected {expected}, got {got}")]
    WrongKeySize { field: &'static str, expected: usize, got: usize },
    #[error("invalid UUID")]
    InvalidUuid,
    #[error("invalid timestamp")]
    InvalidTimestamp,
}

const KEY_USER_UUID: &str = "user_uuid";
const KEY_DISPLAY_NAME: &str = "display_name";
const KEY_X25519_SK: &str = "x25519_sk";
const KEY_X25519_PK: &str = "x25519_pk";
const KEY_ML_KEM_768_SK: &str = "ml_kem_768_sk";
const KEY_ML_KEM_768_PK: &str = "ml_kem_768_pk";
const KEY_ED25519_SK: &str = "ed25519_sk";
const KEY_ED25519_PK: &str = "ed25519_pk";
const KEY_ML_DSA_65_SK: &str = "ml_dsa_65_sk";
const KEY_ML_DSA_65_PK: &str = "ml_dsa_65_pk";
const KEY_CREATED_AT: &str = "created_at";

impl IdentityBundle {
    pub fn to_canonical_cbor(&self) -> Result<Vec<u8>, BundleError> {
        // Sort key/value pairs bytewise lexicographically by key (RFC 8949
        // §4.2.1). For all-tstr keys: shorter first, then lex compare.
        let mut entries: Vec<(Value, Value)> = vec![
            (Value::Text(KEY_USER_UUID.into()), Value::Bytes(self.user_uuid.to_vec())),
            (Value::Text(KEY_DISPLAY_NAME.into()), Value::Text(self.display_name.clone())),
            (Value::Text(KEY_X25519_SK.into()), Value::Bytes(self.x25519_sk.expose().to_vec())),
            (Value::Text(KEY_X25519_PK.into()), Value::Bytes(self.x25519_pk.to_vec())),
            (Value::Text(KEY_ML_KEM_768_SK.into()), Value::Bytes(self.ml_kem_768_sk.expose().clone())),
            (Value::Text(KEY_ML_KEM_768_PK.into()), Value::Bytes(self.ml_kem_768_pk.clone())),
            (Value::Text(KEY_ED25519_SK.into()), Value::Bytes(self.ed25519_sk.expose().to_vec())),
            (Value::Text(KEY_ED25519_PK.into()), Value::Bytes(self.ed25519_pk.to_vec())),
            (Value::Text(KEY_ML_DSA_65_SK.into()), Value::Bytes(self.ml_dsa_65_sk.expose().clone())),
            (Value::Text(KEY_ML_DSA_65_PK.into()), Value::Bytes(self.ml_dsa_65_pk.clone())),
            (Value::Text(KEY_CREATED_AT.into()), Value::Integer(self.created_at_ms.into())),
        ];
        entries.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));

        let mut buf = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut buf)
            .map_err(|e| BundleError::CborDecode(e.to_string()))?;
        Ok(buf)
    }

    pub fn from_canonical_cbor(bytes: &[u8]) -> Result<Self, BundleError> {
        // Strict canonical-input rule, mirroring `card.rs`.
        let value: Value = ciborium::de::from_reader(bytes)
            .map_err(|e| BundleError::CborDecode(e.to_string()))?;
        let Value::Map(entries) = value else {
            return Err(BundleError::CborDecode("expected map".into()));
        };

        // Reject non-canonical key order
        let mut sorted = entries.clone();
        sorted.sort_by(|a, b| canonical_key_cmp(&a.0, &b.0));
        if sorted != entries {
            return Err(BundleError::NonCanonicalCbor);
        }

        // Walk entries; reject duplicates and unknown fields.
        let mut user_uuid: Option<[u8; USER_UUID_LEN]> = None;
        let mut display_name: Option<String> = None;
        let mut x25519_sk: Option<[u8; X25519_SK_LEN]> = None;
        let mut x25519_pk: Option<[u8; X25519_PK_LEN]> = None;
        let mut ml_kem_768_sk: Option<Vec<u8>> = None;
        let mut ml_kem_768_pk: Option<Vec<u8>> = None;
        let mut ed25519_sk: Option<[u8; ED25519_SK_LEN]> = None;
        let mut ed25519_pk: Option<[u8; ED25519_PK_LEN]> = None;
        let mut ml_dsa_65_sk: Option<Vec<u8>> = None;
        let mut ml_dsa_65_pk: Option<Vec<u8>> = None;
        let mut created_at_ms: Option<u64> = None;

        for (k, v) in entries {
            let Value::Text(key) = k else {
                return Err(BundleError::CborDecode("non-text map key".into()));
            };
            // (continue with one match arm per known KEY_* constant; per arm,
            // call set_once_*() helpers to guard against duplicates and
            // wrong-type/wrong-size; on default arm return UnknownField.)
            // For brevity in this plan: implement following the exact pattern
            // in `core/src/identity/card.rs::from_canonical_cbor`.
            todo!("walk entries — pattern from card.rs::from_canonical_cbor")
        }
        todo!("collect all fields, return constructed IdentityBundle or specific BundleError")
    }
}

fn canonical_key_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    let mut a_buf = Vec::new();
    let mut b_buf = Vec::new();
    let _ = ciborium::ser::into_writer(a, &mut a_buf);
    let _ = ciborium::ser::into_writer(b, &mut b_buf);
    a_buf.cmp(&b_buf)
}
```

Replace the `todo!()` calls with the literal pattern from `core/src/identity/card.rs` (lines around the `from_canonical_cbor` impl). Mirror it field-for-field.

Run: `cargo test -p secretary-core --release unlock::bundle::tests`
Expected: 3 tests PASS (generate_produces, canonical_cbor_roundtrip, canonical_cbor_is_byte_stable).

- [ ] **Step 7.3: Commit**

```bash
git add core/src/unlock/bundle.rs
git commit -m "feat(unlock): IdentityBundle canonical CBOR encode/decode"
```

---

## Task 8: `bundle.rs` — strict-decoder error variants

**Files:**
- Modify: `core/src/unlock/bundle.rs`

- [ ] **Step 8.1: Write the failing tests**

Append to `mod tests`. Mirror `core/tests/identity.rs::card_parse_rejects_*`:

```rust
#[test]
fn parse_rejects_unknown_field() {
    use ciborium::Value;
    let mut entries = vec![
        (Value::Text(KEY_USER_UUID.into()), Value::Bytes(vec![0u8; 16])),
        (Value::Text("rogue".into()), Value::Text("payload".into())),
    ];
    entries.sort_by(|a, b| super::canonical_key_cmp(&a.0, &b.0));
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
    let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
    assert!(matches!(err, BundleError::UnknownField(s) if s == "rogue"));
}

#[test]
fn parse_rejects_duplicate_field() {
    use ciborium::Value;
    let entries = vec![
        (Value::Text(KEY_DISPLAY_NAME.into()), Value::Text("Alice".into())),
        (Value::Text(KEY_DISPLAY_NAME.into()), Value::Text("Bob".into())),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
    let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
    assert!(matches!(err, BundleError::DuplicateField(s) if s == "display_name"));
}

#[test]
fn parse_rejects_wrong_x25519_pk_size() {
    use ciborium::Value;
    // Build a full-shape map but with x25519_pk truncated to 30 bytes.
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let b = generate("X", 0, &mut rng);
    let bytes = b.to_canonical_cbor().unwrap();
    let value: Value = ciborium::de::from_reader(&bytes[..]).unwrap();
    let Value::Map(mut entries) = value else { panic!() };
    for (k, v) in entries.iter_mut() {
        if let Value::Text(s) = k {
            if s == KEY_X25519_PK {
                *v = Value::Bytes(vec![0u8; 30]);
            }
        }
    }
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
    let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
    assert!(matches!(
        err,
        BundleError::WrongKeySize { field: "x25519_pk", expected: 32, got: 30 }
    ));
}

#[test]
fn parse_rejects_non_canonical_key_order() {
    use ciborium::Value;
    // Emit fields in spec listing order — which is NOT canonical.
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let b = generate("X", 0, &mut rng);
    let entries: Vec<(Value, Value)> = vec![
        (Value::Text(KEY_USER_UUID.into()), Value::Bytes(b.user_uuid.to_vec())),
        (Value::Text(KEY_DISPLAY_NAME.into()), Value::Text(b.display_name.clone())),
        (Value::Text(KEY_X25519_SK.into()), Value::Bytes(b.x25519_sk.expose().to_vec())),
        (Value::Text(KEY_X25519_PK.into()), Value::Bytes(b.x25519_pk.to_vec())),
        (Value::Text(KEY_ML_KEM_768_SK.into()), Value::Bytes(b.ml_kem_768_sk.expose().clone())),
        (Value::Text(KEY_ML_KEM_768_PK.into()), Value::Bytes(b.ml_kem_768_pk.clone())),
        (Value::Text(KEY_ED25519_SK.into()), Value::Bytes(b.ed25519_sk.expose().to_vec())),
        (Value::Text(KEY_ED25519_PK.into()), Value::Bytes(b.ed25519_pk.to_vec())),
        (Value::Text(KEY_ML_DSA_65_SK.into()), Value::Bytes(b.ml_dsa_65_sk.expose().clone())),
        (Value::Text(KEY_ML_DSA_65_PK.into()), Value::Bytes(b.ml_dsa_65_pk.clone())),
        (Value::Text(KEY_CREATED_AT.into()), Value::Integer(b.created_at_ms.into())),
    ];
    let mut buf = Vec::new();
    ciborium::ser::into_writer(&Value::Map(entries), &mut buf).unwrap();
    let err = IdentityBundle::from_canonical_cbor(&buf).unwrap_err();
    assert!(matches!(err, BundleError::NonCanonicalCbor));
}
```

(Need to make `canonical_key_cmp` `pub(super)` for the test, or duplicate it inline.)

- [ ] **Step 8.2: Implement / verify the strict-decode branches**

The implementation in Task 7 should already hit each of these. If a test fails, implement the missing guard.

Run: `cargo test -p secretary-core --release unlock::bundle::tests`
Expected: 7 tests PASS.

- [ ] **Step 8.3: Commit**

```bash
git add core/src/unlock/bundle.rs
git commit -m "test(unlock): IdentityBundle strict decoder error coverage"
```

---

## Task 9: `bundle_file.rs` — `BundleFile` struct + encode

**Files:**
- Create: `core/src/unlock/bundle_file.rs`
- Modify: `core/src/unlock/mod.rs` (add `pub mod bundle_file;`)

- [ ] **Step 9.1: Write the failing test**

Create `core/src/unlock/bundle_file.rs`:

```rust
//! `identity.bundle.enc` binary envelope (`docs/vault-format.md` §3).
//!
//! Big-endian integers throughout. Three AEAD payloads (wrap_pw, wrap_rec,
//! bundle), each stored as `nonce || ct_len || ct_with_tag`, where
//! ct_with_tag is the AEAD ciphertext concatenated with its 16-byte
//! Poly1305 tag (matching `crypto::aead::encrypt`'s output format).

pub const MAGIC: u32 = 0x53454352;             // "SECR"
pub const FORMAT_VERSION_V1: u16 = 0x0001;
pub const FILE_KIND_IDENTITY_BUNDLE: u16 = 0x0001;
pub const NONCE_LEN: usize = 24;
pub const WRAP_CT_PLUS_TAG_LEN: usize = 32 + 16;  // identity_block_key + tag

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    pub vault_uuid: [u8; 16],
    pub created_at_ms: u64,
    pub wrap_pw_nonce: [u8; NONCE_LEN],
    pub wrap_pw_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN],
    pub wrap_rec_nonce: [u8; NONCE_LEN],
    pub wrap_rec_ct_with_tag: [u8; WRAP_CT_PLUS_TAG_LEN],
    pub bundle_nonce: [u8; NONCE_LEN],
    pub bundle_ct_with_tag: Vec<u8>,
}

#[derive(Debug, thiserror::Error)]
pub enum BundleFileError {
    #[error("file truncated at offset {offset}")]
    Truncated { offset: usize },
    #[error("bad magic: expected SECR, got {got:#010x}")]
    BadMagic { got: u32 },
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unsupported file kind: {0}")]
    UnsupportedFileKind(u16),
    #[error("declared length for {field} ({declared}) does not match expected (32)")]
    WrapLengthMismatch { field: &'static str, declared: u32 },
}

pub fn encode(file: &BundleFile) -> Vec<u8> {
    todo!("emit bytes per vault-format §3")
}

pub fn decode(bytes: &[u8]) -> Result<BundleFile, BundleFileError> {
    todo!("parse bytes per vault-format §3")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BundleFile {
        BundleFile {
            vault_uuid: [0x11; 16],
            created_at_ms: 1_714_060_800_000,
            wrap_pw_nonce: [0x22; NONCE_LEN],
            wrap_pw_ct_with_tag: [0x33; WRAP_CT_PLUS_TAG_LEN],
            wrap_rec_nonce: [0x44; NONCE_LEN],
            wrap_rec_ct_with_tag: [0x55; WRAP_CT_PLUS_TAG_LEN],
            bundle_nonce: [0x66; NONCE_LEN],
            bundle_ct_with_tag: vec![0x77; 200],
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let f = sample();
        let bytes = encode(&f);
        let parsed = decode(&bytes).expect("decode");
        assert_eq!(parsed, f);
    }
}
```

In `core/src/unlock/mod.rs`:

```rust
pub mod mnemonic;
pub mod bundle;
pub mod bundle_file;
```

Run: expected FAIL.

- [ ] **Step 9.2: Implement encode**

Replace `encode` with:

```rust
pub fn encode(file: &BundleFile) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + 2 + 2 + 16 + 8
            + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN
            + NONCE_LEN + 4 + WRAP_CT_PLUS_TAG_LEN
            + NONCE_LEN + 4 + file.bundle_ct_with_tag.len()
    );
    out.extend_from_slice(&MAGIC.to_be_bytes());
    out.extend_from_slice(&FORMAT_VERSION_V1.to_be_bytes());
    out.extend_from_slice(&FILE_KIND_IDENTITY_BUNDLE.to_be_bytes());
    out.extend_from_slice(&file.vault_uuid);
    out.extend_from_slice(&file.created_at_ms.to_be_bytes());

    out.extend_from_slice(&file.wrap_pw_nonce);
    // wrap_pw_ct_len: u32 = 32 (the IdentityBlockKey size). Writing the
    // unwrapped key length, NOT the ciphertext-with-tag length, per §3.
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&file.wrap_pw_ct_with_tag);

    out.extend_from_slice(&file.wrap_rec_nonce);
    out.extend_from_slice(&32u32.to_be_bytes());
    out.extend_from_slice(&file.wrap_rec_ct_with_tag);

    out.extend_from_slice(&file.bundle_nonce);
    // bundle_ct_len = length of the AEAD ciphertext including the 16-byte
    // tag (the §3 "bundle_ct" field is the AEAD output as a single blob).
    out.extend_from_slice(&u32::try_from(file.bundle_ct_with_tag.len())
        .expect("bundle ct < 4 GiB").to_be_bytes());
    out.extend_from_slice(&file.bundle_ct_with_tag);

    out
}
```

- [ ] **Step 9.3: Implement decode**

Replace `decode` with a careful big-endian parser. Reads each field sequentially, returning `Truncated { offset }` on every short-read:

```rust
pub fn decode(bytes: &[u8]) -> Result<BundleFile, BundleFileError> {
    let mut pos = 0;
    let magic = read_u32_be(bytes, &mut pos)?;
    if magic != MAGIC {
        return Err(BundleFileError::BadMagic { got: magic });
    }
    let format_version = read_u16_be(bytes, &mut pos)?;
    if format_version != FORMAT_VERSION_V1 {
        return Err(BundleFileError::UnsupportedFormatVersion(format_version));
    }
    let file_kind = read_u16_be(bytes, &mut pos)?;
    if file_kind != FILE_KIND_IDENTITY_BUNDLE {
        return Err(BundleFileError::UnsupportedFileKind(file_kind));
    }
    let vault_uuid = read_array::<16>(bytes, &mut pos)?;
    let created_at_ms = read_u64_be(bytes, &mut pos)?;

    // wrap_pw
    let wrap_pw_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let wrap_pw_ct_len = read_u32_be(bytes, &mut pos)?;
    if wrap_pw_ct_len != 32 {
        return Err(BundleFileError::WrapLengthMismatch { field: "wrap_pw", declared: wrap_pw_ct_len });
    }
    let wrap_pw_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    // wrap_rec
    let wrap_rec_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let wrap_rec_ct_len = read_u32_be(bytes, &mut pos)?;
    if wrap_rec_ct_len != 32 {
        return Err(BundleFileError::WrapLengthMismatch { field: "wrap_rec", declared: wrap_rec_ct_len });
    }
    let wrap_rec_ct_with_tag = read_array::<WRAP_CT_PLUS_TAG_LEN>(bytes, &mut pos)?;

    // bundle
    let bundle_nonce = read_array::<NONCE_LEN>(bytes, &mut pos)?;
    let bundle_ct_len = read_u32_be(bytes, &mut pos)? as usize;
    if pos + bundle_ct_len > bytes.len() {
        return Err(BundleFileError::Truncated { offset: pos });
    }
    let bundle_ct_with_tag = bytes[pos..pos + bundle_ct_len].to_vec();
    pos += bundle_ct_len;

    if pos != bytes.len() {
        return Err(BundleFileError::Truncated { offset: pos });
        // Trailing bytes treated as truncation indicator — file is wrong shape.
    }

    Ok(BundleFile {
        vault_uuid,
        created_at_ms,
        wrap_pw_nonce,
        wrap_pw_ct_with_tag,
        wrap_rec_nonce,
        wrap_rec_ct_with_tag,
        bundle_nonce,
        bundle_ct_with_tag,
    })
}

fn read_u16_be(bytes: &[u8], pos: &mut usize) -> Result<u16, BundleFileError> {
    let arr = read_array::<2>(bytes, pos)?;
    Ok(u16::from_be_bytes(arr))
}
fn read_u32_be(bytes: &[u8], pos: &mut usize) -> Result<u32, BundleFileError> {
    let arr = read_array::<4>(bytes, pos)?;
    Ok(u32::from_be_bytes(arr))
}
fn read_u64_be(bytes: &[u8], pos: &mut usize) -> Result<u64, BundleFileError> {
    let arr = read_array::<8>(bytes, pos)?;
    Ok(u64::from_be_bytes(arr))
}
fn read_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N], BundleFileError> {
    if *pos + N > bytes.len() {
        return Err(BundleFileError::Truncated { offset: *pos });
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes[*pos..*pos + N]);
    *pos += N;
    Ok(out)
}
```

- [ ] **Step 9.4: Run roundtrip test**

Run: `cargo test -p secretary-core --release unlock::bundle_file::tests::encode_decode_roundtrip`
Expected: PASS.

- [ ] **Step 9.5: Commit**

```bash
git add core/src/unlock/bundle_file.rs core/src/unlock/mod.rs
git commit -m "feat(unlock): bundle_file::encode + decode (vault-format §3)"
```

---

## Task 10: `bundle_file.rs` — error variants

**Files:**
- Modify: `core/src/unlock/bundle_file.rs`

- [ ] **Step 10.1: Write the failing tests**

Append to `mod tests`:

```rust
#[test]
fn decode_rejects_bad_magic() {
    let mut bytes = encode(&sample());
    bytes[0] ^= 0xFF;
    let err = decode(&bytes).unwrap_err();
    assert!(matches!(err, BundleFileError::BadMagic { .. }));
}

#[test]
fn decode_rejects_bad_format_version() {
    let mut bytes = encode(&sample());
    bytes[5] = 0x02;  // bump format_version low byte from 0x01 to 0x02
    let err = decode(&bytes).unwrap_err();
    assert!(matches!(err, BundleFileError::UnsupportedFormatVersion(2)));
}

#[test]
fn decode_rejects_bad_file_kind() {
    let mut bytes = encode(&sample());
    bytes[7] = 0x02;
    let err = decode(&bytes).unwrap_err();
    assert!(matches!(err, BundleFileError::UnsupportedFileKind(2)));
}

#[test]
fn decode_rejects_truncated_at_every_boundary() {
    let bytes = encode(&sample());
    for n in 0..bytes.len() {
        let truncated = &bytes[..n];
        let result = decode(truncated);
        assert!(
            result.is_err(),
            "decode must fail on slice [..{n}] of {} bytes",
            bytes.len()
        );
    }
    // Full bytes — should succeed
    decode(&bytes).expect("full bytes decode");
}

#[test]
fn decode_rejects_wrap_pw_length_mismatch() {
    let bytes = encode(&sample());
    // wrap_pw_ct_len starts at offset 4+2+2+16+8 + NONCE_LEN = 32 + 24 = 56
    let mut tampered = bytes.clone();
    tampered[56..60].copy_from_slice(&64u32.to_be_bytes());
    let err = decode(&tampered).unwrap_err();
    assert!(matches!(
        err,
        BundleFileError::WrapLengthMismatch { field: "wrap_pw", declared: 64 }
    ));
}
```

- [ ] **Step 10.2: Run the tests**

Run: `cargo test -p secretary-core --release unlock::bundle_file::tests`
Expected: 6 PASS.

- [ ] **Step 10.3: Commit**

```bash
git add core/src/unlock/bundle_file.rs
git commit -m "test(unlock): bundle_file decode rejects malformed input"
```

---

## Task 11: `vault_toml.rs` — VaultToml + encode

**Files:**
- Create: `core/src/unlock/vault_toml.rs`
- Modify: `core/src/unlock/mod.rs` (add `pub mod vault_toml;`)

- [ ] **Step 11.1: Write the failing test**

Create `core/src/unlock/vault_toml.rs`:

```rust
//! `vault.toml` cleartext metadata (`docs/vault-format.md` §2).

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultToml {
    pub format_version: u16,
    pub suite_id: u16,
    pub vault_uuid: [u8; 16],
    pub created_at_ms: u64,
    pub kdf: KdfSection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KdfSection {
    pub algorithm: String,        // must be "argon2id"
    pub version: String,          // must be "1.3"
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub salt: [u8; 32],
}

#[derive(Debug, thiserror::Error)]
pub enum VaultTomlError {
    #[error("malformed TOML: {0}")]
    MalformedToml(String),
    #[error("unknown key in [kdf] section: {0}")]
    UnknownKdfKey(String),
    #[error("unsupported format version: {0}")]
    UnsupportedFormatVersion(u16),
    #[error("unsupported suite id: {0}")]
    UnsupportedSuiteId(u16),
    #[error("unsupported KDF algorithm: {0}")]
    UnsupportedKdfAlgorithm(String),
    #[error("unsupported KDF version: {0}")]
    UnsupportedKdfVersion(String),
    #[error("invalid salt length: expected 32 bytes, got {got}")]
    InvalidSaltLength { got: usize },
    #[error("invalid UUID")]
    InvalidUuid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> VaultToml {
        VaultToml {
            format_version: 1,
            suite_id: 1,
            vault_uuid: [0xAB; 16],
            created_at_ms: 1_714_060_800_000,
            kdf: KdfSection {
                algorithm: "argon2id".to_string(),
                version: "1.3".to_string(),
                memory_kib: 262144,
                iterations: 3,
                parallelism: 1,
                salt: [0xCD; 32],
            },
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let v = sample();
        let s = encode(&v);
        let parsed = decode(&s).expect("decode");
        assert_eq!(parsed, v);
    }
}
```

In `core/src/unlock/mod.rs`:

```rust
pub mod mnemonic;
pub mod bundle;
pub mod bundle_file;
pub mod vault_toml;
```

Run: expected FAIL.

- [ ] **Step 11.2: Implement encode**

Use `toml::to_string` with a serializable wire-format struct:

```rust
#[derive(Serialize)]
struct VaultTomlWire {
    format_version: u16,
    suite_id: u16,
    vault_uuid: String,
    created_at_ms: u64,
    kdf: KdfSectionWire,
}

#[derive(Serialize)]
struct KdfSectionWire {
    algorithm: String,
    version: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_b64: String,
}

pub fn encode(v: &VaultToml) -> String {
    let wire = VaultTomlWire {
        format_version: v.format_version,
        suite_id: v.suite_id,
        vault_uuid: format_uuid_canonical(&v.vault_uuid),
        created_at_ms: v.created_at_ms,
        kdf: KdfSectionWire {
            algorithm: v.kdf.algorithm.clone(),
            version: v.kdf.version.clone(),
            memory_kib: v.kdf.memory_kib,
            iterations: v.kdf.iterations,
            parallelism: v.kdf.parallelism,
            salt_b64: STANDARD.encode(v.kdf.salt),
        },
    };
    toml::to_string(&wire).expect("serializing primitive types cannot fail")
}

fn format_uuid_canonical(bytes: &[u8; 16]) -> String {
    // 8-4-4-4-12 hex grouping with hyphens — RFC 4122 textual form.
    let h = bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}
```

- [ ] **Step 11.3: Implement decode (happy path only for now)**

```rust
pub fn decode(s: &str) -> Result<VaultToml, VaultTomlError> {
    use toml::Value;

    let value: Value = toml::from_str(s).map_err(|e| VaultTomlError::MalformedToml(e.to_string()))?;
    let table = value.as_table().ok_or_else(|| VaultTomlError::MalformedToml("expected table".into()))?;

    let format_version = table.get("format_version").and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("format_version missing".into()))?;
    let format_version = u16::try_from(format_version)
        .map_err(|_| VaultTomlError::UnsupportedFormatVersion(0))?;
    if format_version != 1 {
        return Err(VaultTomlError::UnsupportedFormatVersion(format_version));
    }

    let suite_id = table.get("suite_id").and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("suite_id missing".into()))?;
    let suite_id = u16::try_from(suite_id)
        .map_err(|_| VaultTomlError::UnsupportedSuiteId(0))?;
    if suite_id != 1 {
        return Err(VaultTomlError::UnsupportedSuiteId(suite_id));
    }

    let vault_uuid_str = table.get("vault_uuid").and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("vault_uuid missing".into()))?;
    let vault_uuid = parse_uuid_canonical(vault_uuid_str)
        .ok_or(VaultTomlError::InvalidUuid)?;

    let created_at_ms = table.get("created_at_ms").and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("created_at_ms missing".into()))?
        as u64;

    // Strict [kdf] decode: every key must be known.
    let kdf_table = table.get("kdf").and_then(Value::as_table)
        .ok_or_else(|| VaultTomlError::MalformedToml("[kdf] missing".into()))?;

    const KNOWN_KDF_KEYS: &[&str] = &[
        "algorithm", "version", "memory_kib", "iterations", "parallelism", "salt_b64",
    ];
    for k in kdf_table.keys() {
        if !KNOWN_KDF_KEYS.contains(&k.as_str()) {
            return Err(VaultTomlError::UnknownKdfKey(k.clone()));
        }
    }

    let algorithm = kdf_table.get("algorithm").and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.algorithm missing".into()))?
        .to_string();
    if algorithm != "argon2id" {
        return Err(VaultTomlError::UnsupportedKdfAlgorithm(algorithm));
    }

    let version = kdf_table.get("version").and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.version missing".into()))?
        .to_string();
    if version != "1.3" {
        return Err(VaultTomlError::UnsupportedKdfVersion(version));
    }

    let memory_kib = kdf_table.get("memory_kib").and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.memory_kib missing".into()))? as u32;
    let iterations = kdf_table.get("iterations").and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.iterations missing".into()))? as u32;
    let parallelism = kdf_table.get("parallelism").and_then(Value::as_integer)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.parallelism missing".into()))? as u32;

    let salt_b64 = kdf_table.get("salt_b64").and_then(Value::as_str)
        .ok_or_else(|| VaultTomlError::MalformedToml("kdf.salt_b64 missing".into()))?;
    let salt_vec = STANDARD.decode(salt_b64)
        .map_err(|e| VaultTomlError::MalformedToml(format!("salt_b64: {e}")))?;
    let salt: [u8; 32] = salt_vec.as_slice().try_into()
        .map_err(|_| VaultTomlError::InvalidSaltLength { got: salt_vec.len() })?;

    Ok(VaultToml {
        format_version,
        suite_id,
        vault_uuid,
        created_at_ms,
        kdf: KdfSection {
            algorithm,
            version,
            memory_kib,
            iterations,
            parallelism,
            salt,
        },
    })
}

fn parse_uuid_canonical(s: &str) -> Option<[u8; 16]> {
    // Accept "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" form only.
    let stripped: String = s.chars().filter(|c| *c != '-').collect();
    if stripped.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let byte = u8::from_str_radix(&stripped[i*2..i*2+2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}
```

- [ ] **Step 11.4: Run the roundtrip test**

Run: `cargo test -p secretary-core --release unlock::vault_toml::tests::encode_decode_roundtrip`
Expected: PASS.

- [ ] **Step 11.5: Commit**

```bash
git add core/src/unlock/vault_toml.rs core/src/unlock/mod.rs
git commit -m "feat(unlock): vault_toml::encode + decode (vault-format §2)"
```

---

## Task 12: `vault_toml.rs` — error variants

**Files:**
- Modify: `core/src/unlock/vault_toml.rs`

- [ ] **Step 12.1: Write the failing tests**

Append to `mod tests`:

```rust
#[test]
fn decode_ignores_unknown_top_level_key() {
    let mut s = encode(&sample());
    s.push_str("\nfuture_key = \"some value\"\n");
    let parsed = decode(&s).expect("unknown top-level key must be ignored");
    assert_eq!(parsed, sample());
}

#[test]
fn decode_rejects_unknown_kdf_key() {
    let mut s = encode(&sample());
    // Inject a rogue key inside [kdf]
    s.push_str("\nrogue_param = 42\n");
    let err = decode(&s).unwrap_err();
    assert!(matches!(err, VaultTomlError::UnknownKdfKey(s) if s == "rogue_param"));
}

#[test]
fn decode_rejects_unsupported_format_version() {
    let s = encode(&sample()).replace("format_version = 1", "format_version = 2");
    let err = decode(&s).unwrap_err();
    assert!(matches!(err, VaultTomlError::UnsupportedFormatVersion(2)));
}

#[test]
fn decode_rejects_unsupported_suite_id() {
    let s = encode(&sample()).replace("suite_id = 1", "suite_id = 2");
    let err = decode(&s).unwrap_err();
    assert!(matches!(err, VaultTomlError::UnsupportedSuiteId(2)));
}

#[test]
fn decode_rejects_wrong_kdf_algorithm() {
    let s = encode(&sample()).replace("algorithm = \"argon2id\"", "algorithm = \"scrypt\"");
    let err = decode(&s).unwrap_err();
    assert!(matches!(err, VaultTomlError::UnsupportedKdfAlgorithm(s) if s == "scrypt"));
}

#[test]
fn decode_rejects_wrong_kdf_version() {
    let s = encode(&sample()).replace("version = \"1.3\"", "version = \"1.0\"");
    let err = decode(&s).unwrap_err();
    assert!(matches!(err, VaultTomlError::UnsupportedKdfVersion(s) if s == "1.0"));
}

#[test]
fn decode_rejects_short_salt() {
    let mut v = sample();
    let s = encode(&v);
    // Replace the salt_b64 with a short value
    let short_b64 = STANDARD.encode([0u8; 16]);
    let original_b64 = STANDARD.encode([0xCD; 32]);
    let s = s.replace(&original_b64, &short_b64);
    let err = decode(&s).unwrap_err();
    assert!(matches!(err, VaultTomlError::InvalidSaltLength { got: 16 }));
    let _ = v;
}
```

- [ ] **Step 12.2: Run + commit**

Run: `cargo test -p secretary-core --release unlock::vault_toml::tests`
Expected: 8 tests PASS.

```bash
git add core/src/unlock/vault_toml.rs
git commit -m "test(unlock): vault_toml decode error coverage"
```

---

## Task 13: `mod.rs` — `UnlockError` + `From` impls

**Files:**
- Modify: `core/src/unlock/mod.rs`

- [ ] **Step 13.1: Add `UnlockError` enum**

Append to `core/src/unlock/mod.rs`:

```rust
use crate::crypto::aead::AeadError;
use crate::crypto::kdf::KdfError;

#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    #[error("wrong password or vault corruption")]
    WrongPasswordOrCorrupt,
    #[error("wrong recovery mnemonic or vault corruption")]
    WrongMnemonicOrCorrupt,
    #[error("invalid mnemonic: {0}")]
    InvalidMnemonic(#[from] mnemonic::MnemonicError),
    #[error("vault data integrity failure")]
    CorruptVault,
    #[error("vault.toml and identity.bundle.enc reference different vaults")]
    VaultMismatch,

    #[error("malformed vault.toml: {0}")]
    MalformedVaultToml(#[from] vault_toml::VaultTomlError),
    #[error("malformed identity.bundle.enc: {0}")]
    MalformedBundleFile(#[from] bundle_file::BundleFileError),
    #[error("malformed identity bundle plaintext: {0}")]
    MalformedBundle(#[from] bundle::BundleError),

    #[error("KDF failure: {0}")]
    KdfFailure(#[from] KdfError),
    #[error("AEAD primitive failure")]
    AeadFailure,
}

impl From<AeadError> for UnlockError {
    fn from(_: AeadError) -> Self {
        // AEAD primitive errors collapse to AeadFailure — see spec §Error model.
        // Position-specific user-facing variants (WrongPasswordOrCorrupt etc.)
        // are produced explicitly at call sites, not via From.
        UnlockError::AeadFailure
    }
}
```

- [ ] **Step 13.2: Verify it compiles**

Run: `cargo check -p secretary-core`
Expected: clean.

- [ ] **Step 13.3: Commit**

```bash
git add core/src/unlock/mod.rs
git commit -m "feat(unlock): UnlockError enum with From impls"
```

---

## Task 14: `mod.rs` — `create_vault`

**Files:**
- Modify: `core/src/unlock/mod.rs`

- [ ] **Step 14.1: Write the failing test as an integration test stub**

Append to `core/src/unlock/mod.rs`:

```rust
use rand_core::{CryptoRng, RngCore};

use crate::crypto::aead::{decrypt, encrypt, AeadKey, AeadNonce, AEAD_TAG_LEN};
use crate::crypto::kdf::{
    derive_master_kek, derive_recovery_kek, Argon2idParams,
    TAG_ID_BUNDLE, TAG_ID_WRAP_PW, TAG_ID_WRAP_REC,
};
use crate::crypto::secret::{SecretBytes, Sensitive};

pub struct CreatedVault {
    pub vault_toml_bytes: Vec<u8>,
    pub identity_bundle_bytes: Vec<u8>,
    pub recovery_mnemonic: mnemonic::Mnemonic,
    pub identity_block_key: Sensitive<[u8; 32]>,
    pub identity: bundle::IdentityBundle,
}

pub struct UnlockedIdentity {
    pub identity_block_key: Sensitive<[u8; 32]>,
    pub identity: bundle::IdentityBundle,
}

pub fn create_vault(
    password: &SecretBytes,
    display_name: &str,
    created_at_ms: u64,
    kdf_params: Argon2idParams,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreatedVault, UnlockError> {
    todo!()
}
```

In a new inline test module at the bottom of `mod.rs`:

```rust
#[cfg(test)]
mod create_tests {
    use super::*;
    use crate::crypto::kdf::Argon2idParams;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    #[test]
    fn create_vault_produces_well_formed_artifacts() {
        let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
        let password = SecretBytes::new(b"correct horse battery staple".to_vec());
        // Use minimal Argon2id params for test speed (memory floor relaxed).
        let params = Argon2idParams::new(8, 1, 1);
        let v = create_vault(&password, "Alice", 1_714_060_800_000, params, &mut rng)
            .expect("create_vault");
        assert!(!v.vault_toml_bytes.is_empty());
        assert!(!v.identity_bundle_bytes.is_empty());
        assert_eq!(v.recovery_mnemonic.phrase().split_whitespace().count(), 24);
        assert_eq!(v.identity.display_name, "Alice");
    }
}
```

Run: expected FAIL (`todo!()`).

- [ ] **Step 14.2: Implement `create_vault`**

Replace `todo!()`:

```rust
pub fn create_vault(
    password: &SecretBytes,
    display_name: &str,
    created_at_ms: u64,
    kdf_params: Argon2idParams,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<CreatedVault, UnlockError> {
    // Step 1-2: identifiers and salt
    let mut vault_uuid = [0u8; 16];
    rng.fill_bytes(&mut vault_uuid);
    let mut argon2_salt = [0u8; 32];
    rng.fill_bytes(&mut argon2_salt);

    // Step 3: Master KEK
    let master_kek = derive_master_kek(password, &argon2_salt, &kdf_params)?;

    // Step 4-5: mnemonic + Recovery KEK
    let recovery_mnemonic = mnemonic::generate(rng);
    let recovery_kek = derive_recovery_kek(recovery_mnemonic.entropy());

    // Step 6: Identity Block Key
    let mut ibk = [0u8; 32];
    rng.fill_bytes(&mut ibk);
    let identity_block_key = Sensitive::new(ibk);

    // Step 7-8: identity + canonical CBOR
    let identity = bundle::generate(display_name, created_at_ms, rng);
    let bundle_plaintext = identity.to_canonical_cbor()?;

    // Step 9: nonces
    let mut nonce_id = [0u8; 24];
    rng.fill_bytes(&mut nonce_id);
    let mut nonce_pw = [0u8; 24];
    rng.fill_bytes(&mut nonce_pw);
    let mut nonce_rec = [0u8; 24];
    rng.fill_bytes(&mut nonce_rec);

    // Step 10: AEAD-encrypt bundle. `AeadKey` = `Sensitive<[u8;32]>`, and
    // `identity_block_key` already has that type — pass by reference, no
    // re-wrap needed. Same for master_kek and recovery_kek below.
    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vault_uuid);
    let bundle_ct_with_tag = encrypt(
        &identity_block_key,
        &nonce_id,
        &bundle_aad,
        &bundle_plaintext,
    )?;

    // Step 11: wrap_pw
    let wrap_pw_aad = compose_aad(TAG_ID_WRAP_PW, &vault_uuid);
    let wrap_pw_with_tag = encrypt(
        &master_kek,
        &nonce_pw,
        &wrap_pw_aad,
        identity_block_key.expose(),
    )?;
    let wrap_pw_arr: [u8; 48] = wrap_pw_with_tag.as_slice().try_into()
        .expect("32-byte plaintext + 16-byte tag = 48 bytes");

    // Step 12: wrap_rec
    let wrap_rec_aad = compose_aad(TAG_ID_WRAP_REC, &vault_uuid);
    let wrap_rec_with_tag = encrypt(
        &recovery_kek,
        &nonce_rec,
        &wrap_rec_aad,
        identity_block_key.expose(),
    )?;
    let wrap_rec_arr: [u8; 48] = wrap_rec_with_tag.as_slice().try_into()
        .expect("32-byte plaintext + 16-byte tag = 48 bytes");

    // Step 13: bundle_file
    let bf = bundle_file::BundleFile {
        vault_uuid,
        created_at_ms,
        wrap_pw_nonce: nonce_pw,
        wrap_pw_ct_with_tag: wrap_pw_arr,
        wrap_rec_nonce: nonce_rec,
        wrap_rec_ct_with_tag: wrap_rec_arr,
        bundle_nonce: nonce_id,
        bundle_ct_with_tag,
    };
    let identity_bundle_bytes = bundle_file::encode(&bf);

    // Step 14: vault_toml
    let vt = vault_toml::VaultToml {
        format_version: 1,
        suite_id: 1,
        vault_uuid,
        created_at_ms,
        kdf: vault_toml::KdfSection {
            algorithm: "argon2id".to_string(),
            version: "1.3".to_string(),
            memory_kib: kdf_params.memory_kib,
            iterations: kdf_params.iterations,
            parallelism: kdf_params.parallelism,
            salt: argon2_salt,
        },
    };
    let vault_toml_bytes = vault_toml::encode(&vt).into_bytes();

    // master_kek and recovery_kek go out of scope here → Sensitive Drop
    // zeroizes them automatically. No explicit zeroize call required.

    Ok(CreatedVault {
        vault_toml_bytes,
        identity_bundle_bytes,
        recovery_mnemonic,
        identity_block_key,
        identity,
    })
}

fn compose_aad(tag: &[u8], vault_uuid: &[u8; 16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + vault_uuid.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(vault_uuid);
    out
}
```

- [ ] **Step 14.3: Run the test**

Run: `cargo test -p secretary-core --release unlock::create_tests`
Expected: PASS.

- [ ] **Step 14.4: Commit**

```bash
git add core/src/unlock/mod.rs
git commit -m "feat(unlock): create_vault — generate identity + dual-wrap"
```

---

## Task 15: `mod.rs` — `open_with_password`

**Files:**
- Modify: `core/src/unlock/mod.rs`

- [ ] **Step 15.1: Write the failing test**

Append to `mod create_tests` (or a sibling `mod password_tests`):

```rust
#[test]
fn create_then_open_with_password_roundtrips() {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let password = SecretBytes::new(b"hunter2".to_vec());
    let params = Argon2idParams::new(8, 1, 1);
    let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

    let opened = open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &password)
        .expect("open");
    assert_eq!(opened.identity_block_key.expose(), v.identity_block_key.expose());
    assert_eq!(opened.identity.user_uuid, v.identity.user_uuid);
    assert_eq!(opened.identity.display_name, v.identity.display_name);
    assert_eq!(opened.identity.x25519_sk.expose(), v.identity.x25519_sk.expose());
}

#[test]
fn open_with_wrong_password_returns_wrong_password_or_corrupt() {
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);
    let password = SecretBytes::new(b"hunter2".to_vec());
    let params = Argon2idParams::new(8, 1, 1);
    let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

    let bad = SecretBytes::new(b"hunter3".to_vec());
    let err = open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &bad)
        .unwrap_err();
    assert!(matches!(err, UnlockError::WrongPasswordOrCorrupt));
}
```

Run: expected FAIL (`open_with_password` not defined).

- [ ] **Step 15.2: Implement `open_with_password`**

```rust
pub fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &SecretBytes,
) -> Result<UnlockedIdentity, UnlockError> {
    // Step 1: parse vault.toml (the From impl maps VaultTomlError into UnlockError)
    let vt_str = std::str::from_utf8(vault_toml_bytes)
        .map_err(|_| UnlockError::MalformedVaultToml(vault_toml::VaultTomlError::MalformedToml(
            "non-UTF-8 input".to_string(),
        )))?;
    let vt = vault_toml::decode(vt_str)?;

    // Step 2: parse identity.bundle.enc; check vault_uuid match
    let bf = bundle_file::decode(identity_bundle_bytes)?;
    if bf.vault_uuid != vt.vault_uuid {
        return Err(UnlockError::VaultMismatch);
    }

    // Step 3: derive Master KEK
    let kdf_params = Argon2idParams::new(vt.kdf.memory_kib, vt.kdf.iterations, vt.kdf.parallelism);
    let master_kek = derive_master_kek(password, &vt.kdf.salt, &kdf_params)?;

    // Step 4: AEAD-decrypt wrap_pw → identity_block_key
    let wrap_pw_aad = compose_aad(TAG_ID_WRAP_PW, &vt.vault_uuid);
    let ibk_bytes = decrypt(
        &master_kek,
        &bf.wrap_pw_nonce,
        &wrap_pw_aad,
        &bf.wrap_pw_ct_with_tag,
    )
    .map_err(|_| UnlockError::WrongPasswordOrCorrupt)?;

    let ibk_arr: [u8; 32] = ibk_bytes.expose().try_into()
        .map_err(|_| UnlockError::CorruptVault)?;
    let identity_block_key = Sensitive::new(ibk_arr);

    // Step 5: AEAD-decrypt bundle → plaintext
    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vt.vault_uuid);
    let bundle_plaintext = decrypt(
        &identity_block_key,
        &bf.bundle_nonce,
        &bundle_aad,
        &bf.bundle_ct_with_tag,
    )
    .map_err(|_| UnlockError::CorruptVault)?;

    // Step 6: CBOR decode
    let identity = bundle::IdentityBundle::from_canonical_cbor(bundle_plaintext.expose())?;

    Ok(UnlockedIdentity { identity_block_key, identity })
}
```

- [ ] **Step 15.3: Run the tests**

Run: `cargo test -p secretary-core --release unlock::create_tests`
Expected: 4 tests PASS (the 2 new + 2 from earlier).

- [ ] **Step 15.4: Commit**

```bash
git add core/src/unlock/mod.rs
git commit -m "feat(unlock): open_with_password"
```

---

## Task 16: `mod.rs` — `open_with_recovery`

**Files:**
- Modify: `core/src/unlock/mod.rs`

- [ ] **Step 16.1: Write the failing test**

Append:

```rust
#[test]
fn create_then_open_with_recovery_roundtrips() {
    let mut rng = ChaCha20Rng::from_seed([9u8; 32]);
    let password = SecretBytes::new(b"hunter2".to_vec());
    let params = Argon2idParams::new(8, 1, 1);
    let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

    let words = v.recovery_mnemonic.phrase().to_string();
    let opened = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, &words)
        .expect("open");
    assert_eq!(opened.identity_block_key.expose(), v.identity_block_key.expose());
    assert_eq!(opened.identity.user_uuid, v.identity.user_uuid);
}

#[test]
fn open_with_wrong_mnemonic_returns_wrong_mnemonic_or_corrupt() {
    let mut rng = ChaCha20Rng::from_seed([10u8; 32]);
    let password = SecretBytes::new(b"hunter2".to_vec());
    let params = Argon2idParams::new(8, 1, 1);
    let v = create_vault(&password, "Alice", 0, params, &mut rng).unwrap();

    // A different fresh mnemonic — valid checksum, just not this vault's.
    let mut other_rng = ChaCha20Rng::from_seed([99u8; 32]);
    let other = mnemonic::generate(&mut other_rng);
    let err = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, other.phrase())
        .unwrap_err();
    assert!(matches!(err, UnlockError::WrongMnemonicOrCorrupt));
}

#[test]
fn open_with_invalid_mnemonic_returns_invalid_mnemonic() {
    let mut rng = ChaCha20Rng::from_seed([11u8; 32]);
    let v = create_vault(
        &SecretBytes::new(b"x".to_vec()), "Alice", 0,
        Argon2idParams::new(8, 1, 1), &mut rng,
    ).unwrap();
    let err = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, "abandon abandon")
        .unwrap_err();
    assert!(matches!(err, UnlockError::InvalidMnemonic(mnemonic::MnemonicError::WrongLength { .. })));
}

#[test]
fn both_unlock_paths_yield_same_identity_block_key() {
    let mut rng = ChaCha20Rng::from_seed([12u8; 32]);
    let password = SecretBytes::new(b"hunter2".to_vec());
    let v = create_vault(&password, "Alice", 0, Argon2idParams::new(8, 1, 1), &mut rng).unwrap();

    let by_pw = open_with_password(&v.vault_toml_bytes, &v.identity_bundle_bytes, &password).unwrap();
    let by_rec = open_with_recovery(&v.vault_toml_bytes, &v.identity_bundle_bytes, v.recovery_mnemonic.phrase()).unwrap();
    assert_eq!(by_pw.identity_block_key.expose(), by_rec.identity_block_key.expose());
}
```

Run: expected FAIL.

- [ ] **Step 16.2: Implement `open_with_recovery`**

```rust
pub fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mnemonic_words: &str,
) -> Result<UnlockedIdentity, UnlockError> {
    // Steps 1-2: vault.toml + bundle file (same as open_with_password)
    let vt_str = std::str::from_utf8(vault_toml_bytes)
        .map_err(|_| UnlockError::MalformedVaultToml(vault_toml::VaultTomlError::MalformedToml(
            "non-UTF-8 input".to_string(),
        )))?;
    let vt = vault_toml::decode(vt_str)?;
    let bf = bundle_file::decode(identity_bundle_bytes)?;
    if bf.vault_uuid != vt.vault_uuid {
        return Err(UnlockError::VaultMismatch);
    }

    // Step 3: parse mnemonic
    let parsed = mnemonic::parse(mnemonic_words)?;

    // Step 4: derive Recovery KEK
    let recovery_kek = derive_recovery_kek(parsed.entropy());

    // Step 5: AEAD-decrypt wrap_rec
    let wrap_rec_aad = compose_aad(TAG_ID_WRAP_REC, &vt.vault_uuid);
    let ibk_bytes = decrypt(
        &recovery_kek,
        &bf.wrap_rec_nonce,
        &wrap_rec_aad,
        &bf.wrap_rec_ct_with_tag,
    )
    .map_err(|_| UnlockError::WrongMnemonicOrCorrupt)?;

    let ibk_arr: [u8; 32] = ibk_bytes.expose().try_into()
        .map_err(|_| UnlockError::CorruptVault)?;
    let identity_block_key = Sensitive::new(ibk_arr);

    // Step 6: AEAD-decrypt bundle
    let bundle_aad = compose_aad(TAG_ID_BUNDLE, &vt.vault_uuid);
    let bundle_plaintext = decrypt(
        &identity_block_key,
        &bf.bundle_nonce,
        &bundle_aad,
        &bf.bundle_ct_with_tag,
    )
    .map_err(|_| UnlockError::CorruptVault)?;

    let identity = bundle::IdentityBundle::from_canonical_cbor(bundle_plaintext.expose())?;
    Ok(UnlockedIdentity { identity_block_key, identity })
}
```

- [ ] **Step 16.3: Run the tests**

Run: `cargo test -p secretary-core --release unlock::create_tests`
Expected: 7 tests PASS.

- [ ] **Step 16.4: Commit**

```bash
git add core/src/unlock/mod.rs
git commit -m "feat(unlock): open_with_recovery"
```

---

## Task 17: Integration tests — corruption + vault mismatch

**Files:**
- Create: `core/tests/unlock.rs`

- [ ] **Step 17.1: Create the file**

Create `core/tests/unlock.rs`:

```rust
//! Integration tests for the unlock module — exercises the public surface
//! across realistic scenarios: corruption detection, vault mismatch, and the
//! full create→open round-trip with both unlock paths.

mod common;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

use secretary_core::crypto::kdf::Argon2idParams;
use secretary_core::crypto::secret::SecretBytes;
use secretary_core::unlock::{
    self, bundle_file, create_vault, open_with_password, open_with_recovery, UnlockError,
};

fn fast_params() -> Argon2idParams {
    // Below v1 floor — only legal via Argon2idParams::new (not try_new_v1).
    // Used here to keep tests fast (~ms instead of seconds).
    Argon2idParams::new(8, 1, 1)
}

fn create(seed: u8, pw: &[u8]) -> unlock::CreatedVault {
    let mut rng = ChaCha20Rng::from_seed([seed; 32]);
    create_vault(
        &SecretBytes::new(pw.to_vec()),
        "Alice",
        1_714_060_800_000,
        fast_params(),
        &mut rng,
    )
    .expect("create_vault")
}

#[test]
fn flipped_bundle_ct_byte_returns_corrupt_vault() {
    let pw = b"hunter2";
    let v = create(1, pw);

    // Decode the bundle file, flip a byte deep in bundle_ct_with_tag, re-encode.
    let mut bf = bundle_file::decode(&v.identity_bundle_bytes).unwrap();
    let mid = bf.bundle_ct_with_tag.len() / 2;
    bf.bundle_ct_with_tag[mid] ^= 0xFF;
    let tampered = bundle_file::encode(&bf);

    let err = open_with_password(&v.vault_toml_bytes, &tampered, &SecretBytes::new(pw.to_vec()))
        .unwrap_err();
    // wrap_pw decrypts fine (we didn't touch it) → bundle AEAD fails →
    // CorruptVault.
    assert!(matches!(err, UnlockError::CorruptVault));
}

#[test]
fn swapped_bundle_file_returns_vault_mismatch() {
    let pw = b"hunter2";
    let a = create(1, pw);
    let b = create(2, pw);

    // Open vault A's vault.toml with vault B's identity.bundle.enc.
    let err = open_with_password(
        &a.vault_toml_bytes, &b.identity_bundle_bytes,
        &SecretBytes::new(pw.to_vec()),
    ).unwrap_err();
    assert!(matches!(err, UnlockError::VaultMismatch));
}

#[test]
fn mnemonic_not_24_words_returns_invalid_mnemonic() {
    let v = create(3, b"x");
    let err = open_with_recovery(
        &v.vault_toml_bytes, &v.identity_bundle_bytes,
        "abandon abandon abandon",
    ).unwrap_err();
    assert!(matches!(err, UnlockError::InvalidMnemonic(_)));
}
```

- [ ] **Step 17.2: Run**

Run: `cargo test -p secretary-core --release --test unlock`
Expected: 3 tests PASS.

- [ ] **Step 17.3: Commit**

```bash
git add core/tests/unlock.rs
git commit -m "test(unlock): integration — corruption, swap, mnemonic shape"
```

---

## Task 18: BIP-39 recovery KAT — JSON file + KAT struct + test

**Files:**
- Create: `core/tests/data/bip39_recovery_kat.json`
- Modify: `core/tests/common/mod.rs` (add `Bip39RecoveryKat` struct)
- Modify: `core/tests/unlock.rs` (add `bip39_recovery_kat_vectors` test)

- [ ] **Step 18.1: Compute the KAT vectors out-of-band**

The KAT pins three relations:
1. `mnemonic ↔ entropy` per BIP-39 English wordlist + checksum
2. `entropy + info_tag → expected_recovery_kek` per HKDF-SHA-256 with `salt = [0u8;32]`
3. `info_tag` is exactly the bytes of `b"secretary-v1-recovery-kek"`

Use `uv` to run a Python script that produces all four vectors:

```bash
uv run --with bip39 --with cryptography python <<'PY'
import json
from bip39 import Mnemonic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

INFO = b"secretary-v1-recovery-kek"
mnemo = Mnemonic("english")

def derive_kek(entropy: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"\x00" * 32,
        info=INFO,
    ).derive(entropy)

vectors = []

# Vector 1: all-zero entropy
e = b"\x00" * 32
vectors.append({
    "name": "all_zero_entropy",
    "mnemonic": mnemo.to_mnemonic(e),
    "entropy": e.hex(),
    "info_tag": INFO.hex(),
    "expected_recovery_kek": derive_kek(e).hex(),
})

# Vector 2: all-FF entropy
e = b"\xFF" * 32
vectors.append({
    "name": "all_ff_entropy",
    "mnemonic": mnemo.to_mnemonic(e),
    "entropy": e.hex(),
    "info_tag": INFO.hex(),
    "expected_recovery_kek": derive_kek(e).hex(),
})

# Vectors 3 & 4: from the canonical Trezor BIP-39 vectors (24-word entries).
# https://github.com/trezor/python-mnemonic/blob/master/vectors.json
trezor_vectors = [
    ("0000000000000000000000000000000000000000000000000000000000000000",
     "abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon abandon "
     "abandon abandon abandon abandon abandon abandon abandon art"),
    ("8080808080808080808080808080808080808080808080808080808080808080",
     "letter advice cage absurd amount doctor acoustic avoid letter "
     "advice cage absurd amount doctor acoustic avoid letter advice "
     "cage absurd amount doctor acoustic bless"),
]
for i, (entropy_hex, expected_phrase) in enumerate(trezor_vectors, start=1):
    e = bytes.fromhex(entropy_hex)
    # Cross-check our wordlist matches Trezor's
    derived_phrase = mnemo.to_mnemonic(e)
    assert derived_phrase == expected_phrase, (
        f"vector {i}: bip39 phrase divergence — got {derived_phrase!r}, "
        f"expected {expected_phrase!r}"
    )
    vectors.append({
        "name": f"trezor_vector_24w_{i}",
        "mnemonic": expected_phrase,
        "entropy": entropy_hex,
        "info_tag": INFO.hex(),
        "expected_recovery_kek": derive_kek(e).hex(),
    })

print(json.dumps({"vectors": vectors}, indent=2))
PY
```

If the `bip39` package on PyPI under that name is not the canonical `mnemonic` package (Trezor's), substitute `--with mnemonic` and `from mnemonic import Mnemonic`. Both produce equivalent BIP-39 English output; the assertion against Trezor's expected phrase will surface a divergence immediately.

Save the script's stdout to `core/tests/data/bip39_recovery_kat.json`.

- [ ] **Step 18.2: Sanity-check the file structure**

Run: `cat core/tests/data/bip39_recovery_kat.json | python -m json.tool > /dev/null` (replace with `uv run python -m json.tool` if needed)
Expected: no output, no error.

Then run the existing JSON-parse smoke test:

Run: `cargo test -p secretary-core --release --test kat_loader`
Expected: PASS — the new file is now picked up by the smoke test.

- [ ] **Step 18.3: Add the `Bip39RecoveryKat` struct to `common/mod.rs`**

Append to `core/tests/common/mod.rs`:

```rust
#[derive(Debug, Deserialize)]
pub struct Bip39RecoveryKat {
    pub vectors: Vec<Bip39RecoveryVector>,
}

#[derive(Debug, Deserialize)]
pub struct Bip39RecoveryVector {
    pub name: String,
    pub mnemonic: String,
    #[serde(deserialize_with = "de_hex_array::<32, _>")]
    pub entropy: [u8; 32],
    #[serde(deserialize_with = "de_hex")]
    pub info_tag: Vec<u8>,
    #[serde(deserialize_with = "de_hex_array::<32, _>")]
    pub expected_recovery_kek: [u8; 32],
}
```

- [ ] **Step 18.4: Add the KAT test**

Append to `core/tests/unlock.rs`:

```rust
use common::{load_kat, Bip39RecoveryKat};
use secretary_core::crypto::kdf::{derive_recovery_kek, TAG_RECOVERY_KEK};
use secretary_core::crypto::secret::Sensitive;
use secretary_core::unlock::mnemonic;

#[test]
fn bip39_recovery_kat_vectors() {
    let kat: Bip39RecoveryKat = load_kat("bip39_recovery_kat.json");
    assert!(!kat.vectors.is_empty(), "KAT file has no vectors");
    for v in &kat.vectors {
        // Pin half 1: mnemonic → entropy
        let parsed = mnemonic::parse(&v.mnemonic).unwrap_or_else(|e| {
            panic!("vector {}: parse failed: {e}", v.name)
        });
        assert_eq!(
            parsed.entropy().expose(), &v.entropy,
            "vector {}: mnemonic→entropy mismatch", v.name,
        );

        // Pin half 2: info_tag matches our domain-separation tag
        assert_eq!(
            v.info_tag, TAG_RECOVERY_KEK,
            "vector {}: info_tag does not match TAG_RECOVERY_KEK", v.name,
        );

        // Pin half 3: entropy → recovery_kek
        let kek = derive_recovery_kek(&Sensitive::new(v.entropy));
        assert_eq!(
            kek.expose(), &v.expected_recovery_kek,
            "vector {}: HKDF output mismatch", v.name,
        );
    }
}
```

- [ ] **Step 18.5: Run**

Run: `cargo test -p secretary-core --release --test unlock bip39_recovery_kat_vectors`
Expected: PASS.

- [ ] **Step 18.6: Commit**

```bash
git add core/tests/data/bip39_recovery_kat.json core/tests/common/mod.rs core/tests/unlock.rs
git commit -m "test(unlock): §15 BIP-39 recovery KAT — pins mnemonic→entropy→KEK"
```

---

## Task 19: Property tests in `core/tests/proptest.rs`

**Files:**
- Modify: `core/tests/proptest.rs`

- [ ] **Step 19.1: Inspect existing proptest layout**

Read `core/tests/proptest.rs` head to confirm: macro import (`proptest! { ... }`), how strategies are constructed, and which submodules already exist. Match the file's style — do not introduce a new pattern.

- [ ] **Step 19.2: Add `mod unlock` block**

Append to `core/tests/proptest.rs`:

```rust
mod unlock {
    use proptest::prelude::*;
    use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};

    use secretary_core::crypto::kdf::Argon2idParams;
    use secretary_core::crypto::secret::SecretBytes;
    use secretary_core::unlock::{
        bundle, bundle_file, create_vault, open_with_password, vault_toml,
    };

    proptest! {
        #[test]
        fn identity_bundle_canonical_cbor_roundtrip(seed: [u8; 32]) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let b = bundle::generate("X", 0, &mut rng);
            let bytes_1 = b.to_canonical_cbor().unwrap();
            let bytes_2 = b.to_canonical_cbor().unwrap();
            prop_assert_eq!(&bytes_1, &bytes_2, "encoding non-deterministic");
            let parsed = bundle::IdentityBundle::from_canonical_cbor(&bytes_1).unwrap();
            prop_assert_eq!(parsed.user_uuid, b.user_uuid);
            prop_assert_eq!(parsed.x25519_pk, b.x25519_pk);
        }

        #[test]
        fn bundle_file_roundtrip(
            vault_uuid in any::<[u8; 16]>(),
            created_at_ms in any::<u64>(),
            wpw_nonce in any::<[u8; 24]>(),
            wpw_ct in any::<[u8; 48]>(),
            wrec_nonce in any::<[u8; 24]>(),
            wrec_ct in any::<[u8; 48]>(),
            bundle_nonce in any::<[u8; 24]>(),
            bundle_ct in proptest::collection::vec(any::<u8>(), 16..1024),
        ) {
            let f = bundle_file::BundleFile {
                vault_uuid,
                created_at_ms,
                wrap_pw_nonce: wpw_nonce,
                wrap_pw_ct_with_tag: wpw_ct,
                wrap_rec_nonce: wrec_nonce,
                wrap_rec_ct_with_tag: wrec_ct,
                bundle_nonce,
                bundle_ct_with_tag: bundle_ct,
            };
            let bytes = bundle_file::encode(&f);
            let parsed = bundle_file::decode(&bytes).unwrap();
            prop_assert_eq!(parsed, f);
        }

        #[test]
        fn vault_toml_roundtrip(
            vault_uuid in any::<[u8; 16]>(),
            created_at_ms in any::<u64>(),
            memory_kib in 8u32..1024u32,
            iterations in 1u32..16u32,
            parallelism in 1u32..8u32,
            salt in any::<[u8; 32]>(),
        ) {
            let v = vault_toml::VaultToml {
                format_version: 1,
                suite_id: 1,
                vault_uuid,
                created_at_ms,
                kdf: vault_toml::KdfSection {
                    algorithm: "argon2id".to_string(),
                    version: "1.3".to_string(),
                    memory_kib,
                    iterations,
                    parallelism,
                    salt,
                },
            };
            let s = vault_toml::encode(&v);
            let parsed = vault_toml::decode(&s).unwrap();
            prop_assert_eq!(parsed, v);
        }

        #[test]
        fn create_then_open_roundtrip_preserves_identity(seed: [u8; 32], pw_seed: [u8; 16]) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let pw = SecretBytes::new(pw_seed.to_vec());
            let v = create_vault(&pw, "X", 0, Argon2idParams::new(8, 1, 1), &mut rng).unwrap();
            let opened = open_with_password(
                &v.vault_toml_bytes, &v.identity_bundle_bytes, &pw,
            ).unwrap();
            prop_assert_eq!(opened.identity_block_key.expose(), v.identity_block_key.expose());
            prop_assert_eq!(opened.identity.user_uuid, v.identity.user_uuid);
        }
    }
}
```

(For the `bundle_file_roundtrip` strategy: use `proptest::collection::vec(any::<u8>(), 0..1024)` for `bundle_ct_with_tag` rather than synthesizing the array fields manually if it's simpler.)

- [ ] **Step 19.3: Run**

Run: `cargo test -p secretary-core --release --test proptest unlock`
Expected: each property runs default 256 cases, all PASS. Slow due to Argon2; acceptable.

- [ ] **Step 19.4: Commit**

```bash
git add core/tests/proptest.rs
git commit -m "test(unlock): proptest — CBOR/bundle-file roundtrip + create/open"
```

---

## Task 20: Final verification — full test suite + clippy

**Files:** none modified — verification only.

- [ ] **Step 20.1: Run the full test suite**

Run: `cargo test --release --workspace`
Expected: every test PASS. Total count = 122 (existing) + ~20 new unit tests + 3 integration tests + 1 KAT test + 3 properties.

- [ ] **Step 20.2: Run clippy**

Run: `cargo clippy --all-targets -- -D warnings`
Expected: clean.

- [ ] **Step 20.3: If clippy complains, fix issues and re-commit**

```bash
git add -p
git commit -m "chore(unlock): clippy fixes"
```

---

## Task 21: Update `secretary_next_session.md`

**Files:**
- Modify: `secretary_next_session.md`

- [ ] **Step 21.1: Mark Item 1a and Item 3 as completed**

Edit `secretary_next_session.md`:

- In Item 1a's section, change the heading to `### 1a. ~~bip39_recovery_kat.json~~ — DONE 2026-04-27` and append a one-line note: "Delivered as `core/tests/data/bip39_recovery_kat.json` plus the `bip39_recovery_kat_vectors` test in `core/tests/unlock.rs`."
- In Item 3's section, change the heading to `## ~~Item 3 — Build-sequence next: \`unlock\` module~~ — DONE 2026-04-27` and append a one-line note pointing at the spec doc and the implementation files.
- In the "What this session delivered" block at the bottom, append a new dated entry summarizing the unlock module work.

- [ ] **Step 21.2: Verify the file still parses cleanly as Markdown**

Run: visually scan in editor, or `cat secretary_next_session.md | head -50` to confirm structure. No tooling required.

- [ ] **Step 21.3: Commit**

```bash
git add secretary_next_session.md
git commit -m "docs: close out FIXME items 1a + 3 (unlock module + BIP-39 KAT)"
```

---

## Self-review notes

After completing all tasks, the following spec coverage should hold:

| Spec section | Implementing task |
|---|---|
| Public API surface | Tasks 14-16 |
| `mnemonic.rs` | Tasks 2-5 |
| `bundle.rs` | Tasks 6-8 |
| `bundle_file.rs` | Tasks 9-10 |
| `vault_toml.rs` | Tasks 11-12 |
| `mod.rs` (UnlockError + composers) | Tasks 13-16 |
| Layer 1 unit tests | Tasks 2-12 inline |
| Layer 2 integration tests | Task 17 + Tasks 14-16 (4 of 8 scenarios live in `mod.rs` `#[cfg(test)]`; Task 17 adds the rest) |
| Layer 3 property tests | Task 19 |
| Layer 4 BIP-39 recovery KAT | Task 18 |
| Layer 5 clippy clean | Task 20 |

Open items intentionally deferred (per spec "Out of scope"):
- Filesystem I/O — vault module
- Manifest decryption — vault module
- Block decryption — vault module
- Cross-language `conformance.py` — written after vault module exists
