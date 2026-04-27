# `core/src/unlock/` module — design

**Date:** 2026-04-27
**Scope:** Sub-project A, build-sequence step 5 (`unlock` module). Also delivers Item 1a from `secretary_next_session.md` (the BIP-39 recovery KAT — `bip39_recovery_kat.json`).
**Status:** approved design, awaiting implementation plan.

## Context

The unlock module is the next module in the build sequence per `docs/crypto-design.md` §3 + §4 and per the Sub-project A design anchor at `/Users/hherb/.claude/plans/we-are-starting-with-logical-newt.md`. The crypto primitives (`crypto/{kdf, aead, secret, hash, kem, sig}`) and identity-side modules (`identity/{card, fingerprint}`) are in place. The vault module is still a stub and is the next session's target after this one.

The byte-level format the unlock module reads and writes is fully specified:

- `vault.toml` — `docs/vault-format.md` §2 (cleartext TOML metadata)
- `identity.bundle.enc` — `docs/vault-format.md` §3 (binary envelope)
- `IdentityBundle` plaintext — `docs/crypto-design.md` §5 (canonical CBOR §6.2)
- Master KEK derivation — `docs/crypto-design.md` §3 (Argon2id)
- Recovery KEK derivation — `docs/crypto-design.md` §4 (HKDF-SHA-256)
- Domain-separation tags — `docs/crypto-design.md` §1.3 (already imported as `pub const` in `core/src/crypto/kdf.rs`)

This document contains no new spec material. It is purely an implementation design for code that realises the existing spec.

## Architecture

### Position in the dependency graph

```
crypto/{kdf, aead, secret, hash}   identity/{card, fingerprint}
                  │                              │
                  └──────────────┬───────────────┘
                                 ▼
                          unlock  ← this module
                                 │
                                 ▼
                              vault   (next session)
```

Unlock depends down on the crypto primitives and is depended on by the future `vault` module — `vault::manifest` will need the unwrapped `identity_block_key` to AEAD-decrypt the manifest, and the `IdentityBundle`'s Ed25519 + ML-DSA-65 public keys to verify the manifest's hybrid signature.

### Trust boundary and side-effect discipline

The module is a stateless byte-in / byte-out transformer. No filesystem I/O — atomic writes belong to the `vault` module per the design anchor. No clock reads — `created_at_ms` is an explicit parameter. All randomness comes through an injected `RngCore + CryptoRng`, so tests use a seeded RNG (`ChaCha20Rng`) for deterministic vault bytes and production callers pass `&mut OsRng`.

This shape matches the user's general design preference (pure functions in reusable modules) and makes the module straightforward to consume from the eventual FFI layers (PyO3, uniffi).

### Public API surface

```rust
// core/src/unlock/mod.rs

pub mod mnemonic;
pub mod bundle;
pub mod bundle_file;
pub mod vault_toml;

pub struct CreatedVault {
    pub vault_toml_bytes: Vec<u8>,
    pub identity_bundle_bytes: Vec<u8>,
    pub recovery_mnemonic: mnemonic::Mnemonic,        // show once, then drop
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
) -> Result<CreatedVault, UnlockError>;

pub fn open_with_password(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    password: &SecretBytes,
) -> Result<UnlockedIdentity, UnlockError>;

pub fn open_with_recovery(
    vault_toml_bytes: &[u8],
    identity_bundle_bytes: &[u8],
    mnemonic_words: &str,
) -> Result<UnlockedIdentity, UnlockError>;
```

`open_with_password` and `open_with_recovery` are deliberately separate functions, not a single function with auto-detection. The UX flow ("I forgot my password, I'll use the recovery mnemonic") is an explicit user choice. We never silently fall back from one to the other.

## File-level components

Five files, each independently testable. Approximate line counts are estimates; the actual constraint is "each file owns one purpose."

### `mod.rs` — public surface and composition (~150 lines)

- Re-exports the four submodules.
- `pub struct CreatedVault`, `pub struct UnlockedIdentity`.
- `pub enum UnlockError` (see Error model below).
- The three public free functions. Each is a short composer that calls into the submodules; no novel logic in `mod.rs` itself.
- One small private helper `wrap_identity_block_key(kek, key, aad_tag, vault_uuid, rng)` that performs the §5 wrap step shared between `wrap_pw` and `wrap_rec` — they differ only in their AAD tag and KEK.

### `mnemonic.rs` — BIP-39 wrapper (~100 lines)

- `pub struct Mnemonic` — opaque wrapper around `bip39::Mnemonic`. Holds the 24-word phrase and the 256-bit entropy. `Drop` zeroizes both the phrase string and the entropy (the latter via `Sensitive`'s `ZeroizeOnDrop`). No `Display`, no `Clone`, no derived `Debug`: every read of the phrase goes through an explicit `pub fn phrase(&self) -> &str` accessor (mirrors the `SecretBytes::expose()` convention in `crypto/secret.rs` — secret reads must be grep-able at use sites). A manual `Debug` impl is provided that prints `Mnemonic { phrase: "<redacted>", entropy: "<redacted>" }` so the type can appear in `Result::unwrap_err()` test assertions without leaking.
- `pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Mnemonic` — 256 bits → bip39 24-word phrase, English wordlist.
- `pub fn parse(words: &str) -> Result<Mnemonic, MnemonicError>` — apply Unicode NFKD normalization (BIP-39 standard), then collapse whitespace runs, trim, lowercase, then validate word-list membership and validate BIP-39 checksum. Returns parsed mnemonic with extracted entropy.
- `pub fn entropy(&self) -> &Sensitive<[u8; 32]>` — accessor for `derive_recovery_kek`.
- `pub enum MnemonicError { WrongLength { got: usize }, UnknownWord(String), BadChecksum }`.

This is the only file that depends on the external `bip39` crate. If we ever swap libraries, only this file changes.

### `bundle.rs` — IdentityBundle plaintext (~150 lines)

- `pub struct IdentityBundle` — the §5 plaintext fields: `user_uuid: [u8; 16]`, `display_name: String`, `(x25519_sk, x25519_pk)`, `(ml_kem_768_sk, ml_kem_768_pk)`, `(ed25519_sk, ed25519_pk)`, `(ml_dsa_65_sk, ml_dsa_65_pk)`, `created_at_ms: u64`. Secret-key fields wrapped in `Sensitive<...>`.
- `pub fn generate(display_name: &str, created_at_ms: u64, rng: &mut ...) -> IdentityBundle` — generate fresh `user_uuid` + four keypairs.
- `pub fn to_canonical_cbor(&self) -> Vec<u8>` — RFC 8949 §4.2.1 deterministic encoding (sorted keys, definite-length, shortest-form). Output is byte-stable and what the §15 KAT pins.
- `pub fn from_canonical_cbor(bytes: &[u8]) -> Result<IdentityBundle, BundleError>` — strict decoder. Rejects unknown fields (the bundle is fully-specified; an unknown field signals suite drift). Rejects duplicate map keys (RFC 8949 §5.4).

No crypto, no I/O. Pure translation between Rust struct ↔ CBOR bytes.

### `bundle_file.rs` — `identity.bundle.enc` framing (~200 lines)

- `pub struct BundleFile` — parsed envelope: `vault_uuid`, `created_at_ms`, three `(nonce, ct, tag)` triples (`wrap_pw`, `wrap_rec`, `bundle`).
- `pub fn encode(file: &BundleFile) -> Vec<u8>` — emit byte layout from `vault-format.md` §3.
- `pub fn decode(bytes: &[u8]) -> Result<BundleFile, BundleFileError>` — parse and validate magic (`0x53454352`), `format_version` (1), `file_kind` (0x0001), internal length fields. Rejects truncation, version mismatch, length-field disagreement.

No crypto here either — just framing. `mod.rs` does the AEAD calls using fields pulled out of `BundleFile`. Separating framing from crypto means we can fuzz the parser independently and a clean-room implementation can verify the parser without keys.

### `vault_toml.rs` — `vault.toml` ser/de (~80 lines)

- `pub struct VaultToml` — typed view: `format_version: u16`, `suite_id: u16`, `vault_uuid: [u8; 16]`, `created_at_ms: u64`, plus a `kdf: KdfSection` substruct holding `algorithm: String`, `version: String`, `memory_kib: u32`, `iterations: u32`, `parallelism: u32`, `salt: [u8; 32]` (decoded from `salt_b64`).
- `pub fn encode(v: &VaultToml) -> String` — produces a stable TOML string so the §15 KAT can pin bytes.
- `pub fn decode(s: &str) -> Result<VaultToml, VaultTomlError>` — strict parsing per `vault-format.md` §2:
  - Unknown top-level keys silently ignored (forward compat).
  - Unknown keys inside `[kdf]` are errors (misinterpreting KDF parameters would derive a wrong key — defense in depth against malformed or downgrade-tampered files).
  - `kdf.algorithm` must be exactly `"argon2id"` (else `UnsupportedKdfAlgorithm`); `kdf.version` must be exactly `"1.3"` (else `UnsupportedKdfVersion`). vault.toml is cleartext and attacker-writable per `threat-model.md` §2.1; we reject on any deviation rather than silently coercing.

## Data flows

### `create_vault`

```
1.  vault_uuid          ← 16 random bytes from rng
2.  argon2_salt         ← 32 random bytes from rng
3.  master_kek          ← derive_master_kek(password, argon2_salt, kdf_params)   [Argon2id]
4.  mnemonic            ← mnemonic::generate(rng)                                [256 bits → 24 words]
5.  recovery_kek        ← derive_recovery_kek(mnemonic.entropy())                [HKDF-SHA-256]
6.  identity_block_key  ← 32 random bytes from rng
7.  identity            ← bundle::generate(display_name, created_at_ms, rng)
8.  bundle_plaintext    ← identity.to_canonical_cbor()
9.  nonce_id, nonce_pw, nonce_rec ← three independent 24-byte nonces from rng
10. bundle_ct, bundle_tag ← AEAD-encrypt(identity_block_key, nonce_id,
                              aad = TAG_ID_BUNDLE   || vault_uuid, bundle_plaintext)
11. wrap_pw_ct, wrap_pw_tag ← AEAD-encrypt(master_kek, nonce_pw,
                              aad = TAG_ID_WRAP_PW  || vault_uuid, identity_block_key)
12. wrap_rec_ct, wrap_rec_tag ← AEAD-encrypt(recovery_kek, nonce_rec,
                              aad = TAG_ID_WRAP_REC || vault_uuid, identity_block_key)
13. bundle_file_bytes   ← bundle_file::encode(BundleFile { vault_uuid, created_at_ms,
                              all three (nonce, ct, tag) triples })
14. vault_toml_bytes    ← vault_toml::encode(VaultToml { ..., kdf.salt = argon2_salt })
15. zeroize: master_kek, recovery_kek
16. return CreatedVault { vault_toml_bytes, identity_bundle_bytes, mnemonic,
                          identity_block_key, identity }
```

### `open_with_password`

```
1. vault_toml          ← vault_toml::decode(vault_toml_bytes)
                          ↳ check format_version == 1, suite_id == 1, else UnsupportedFormatVersion / UnsupportedSuiteId
2. bundle_file         ← bundle_file::decode(identity_bundle_bytes)
                          ↳ check magic, file_kind, format_version
                          ↳ check bundle_file.vault_uuid == vault_toml.vault_uuid, else VaultMismatch
3. master_kek          ← derive_master_kek(password, vault_toml.kdf.salt, vault_toml.kdf params)
4. identity_block_key  ← AEAD-decrypt(master_kek, bundle_file.wrap_pw_nonce,
                          aad = TAG_ID_WRAP_PW || vault_uuid,
                          ct  = bundle_file.wrap_pw_ct, tag = bundle_file.wrap_pw_tag)
                          ↳ on AEAD failure: WrongPasswordOrCorrupt
5. bundle_plaintext    ← AEAD-decrypt(identity_block_key, bundle_file.bundle_nonce,
                          aad = TAG_ID_BUNDLE || vault_uuid,
                          ct  = bundle_file.bundle_ct, tag = bundle_file.bundle_tag)
                          ↳ on AEAD failure: CorruptVault (step 4 succeeded → wraps disagree → tampering)
6. identity            ← bundle::from_canonical_cbor(bundle_plaintext)
7. zeroize: master_kek, bundle_plaintext
8. return UnlockedIdentity { identity_block_key, identity }
```

### `open_with_recovery`

```
1. vault_toml          ← vault_toml::decode(...)                                [as above]
2. bundle_file         ← bundle_file::decode(...)                               [as above]
3. mnemonic            ← mnemonic::parse(mnemonic_words)
                          ↳ on MnemonicError: InvalidMnemonic(reason)
4. recovery_kek        ← derive_recovery_kek(mnemonic.entropy())
5. identity_block_key  ← AEAD-decrypt(recovery_kek, bundle_file.wrap_rec_nonce,
                          aad = TAG_ID_WRAP_REC || vault_uuid,
                          ct  = bundle_file.wrap_rec_ct, tag = bundle_file.wrap_rec_tag)
                          ↳ on AEAD failure: WrongMnemonicOrCorrupt
6. bundle_plaintext, identity ← (as steps 5-6 above)
7. zeroize: recovery_kek, mnemonic, bundle_plaintext
8. return UnlockedIdentity { identity_block_key, identity }
```

### Three runtime invariants worth naming

1. **`vault_uuid` is bound into every AAD.** An attacker who swaps `identity.bundle.enc` between two vaults causes AAD mismatch → AEAD tag failure → bundle rejected. Without this binding, a swap could silently succeed if both vaults shared a (password, salt) coincidence.
2. **The same `identity_block_key` is recovered via either unlock path.** That's the dual-wrap invariant — there is exactly one key encrypted twice, not two equivalent keys.
3. **`master_kek` and `recovery_kek` are zeroized at the end of every flow.** They are never stored, returned, or kept past the function boundary. Only `identity_block_key` and the `IdentityBundle` survive — the `vault` module needs them to decrypt the manifest and per-block keys.

## Error model

Following the existing `crypto/kdf.rs` pattern: `thiserror`-derived enums, one per submodule, composed into `UnlockError` via `From` impls. No `anyhow`, no `Box<dyn Error>`. Concrete enums everywhere — keeps the FFI layer's job straightforward (each variant maps to a Python exception class, a Swift enum case, etc.).

### Submodule errors

```rust
// mnemonic.rs
pub enum MnemonicError {
    WrongLength { got: usize },        // not 24 words
    UnknownWord(String),               // word not in BIP-39 English list
    BadChecksum,                       // 8-bit checksum doesn't match
}

// bundle.rs
pub enum BundleError {
    MalformedCbor(ciborium::de::Error),
    UnknownField(String),              // strict; bundle is fully-specified
    DuplicateField(String),            // RFC 8949 §5.4 violation
    WrongKeySize { field: &'static str, expected: usize, got: usize },
    InvalidUuid,
    InvalidTimestamp,
}

// bundle_file.rs
pub enum BundleFileError {
    Truncated { offset: usize },
    BadMagic { got: u32 },
    UnsupportedFormatVersion(u16),     // != 1
    UnsupportedFileKind(u16),          // != 0x0001 (identity-bundle)
    WrapLengthMismatch { field: &'static str, declared: u32 },  // ct_len != 32
}

// vault_toml.rs
pub enum VaultTomlError {
    MalformedToml(toml::de::Error),
    UnknownKdfKey(String),                 // strict inside [kdf] (vault-format §2)
    UnsupportedFormatVersion(u16),
    UnsupportedSuiteId(u16),
    UnsupportedKdfAlgorithm(String),       // != "argon2id"
    UnsupportedKdfVersion(String),         // != "1.3"
    InvalidSaltLength { got: usize },      // not 32 bytes after b64 decode
    InvalidUuid,
}
```

### Top-level `UnlockError`

```rust
pub enum UnlockError {
    // user-facing categories
    WrongPasswordOrCorrupt,
    WrongMnemonicOrCorrupt,
    InvalidMnemonic(MnemonicError),
    CorruptVault,
    VaultMismatch,

    // structural / format failures
    MalformedVaultToml(VaultTomlError),
    MalformedBundleFile(BundleFileError),
    MalformedBundle(BundleError),
    UnsupportedFormatVersion(u16),
    UnsupportedSuiteId(u16),

    // composition with existing crypto errors
    KdfFailure(crate::crypto::kdf::KdfError),
    AeadFailure,
}
```

### Three deliberate choices

1. **`WrongPasswordOrCorrupt` vs. `CorruptVault` are distinct variants** even though cryptographically a wrong-key AEAD failure is indistinguishable from corruption. The distinction is *positional*: if `wrap_pw` AEAD fails, the user almost certainly mistyped the password — UI prompts re-entry. If `wrap_pw` *succeeds* and the inner bundle AEAD then fails, the unwrapped key worked but the bundle plaintext is unverifiable — that's tampering or genuine corruption, and "try your password again" is the wrong UX.
2. **`InvalidMnemonic` carries the inner `MnemonicError`** so the UI can distinguish "you typed 22 words" from "the third word isn't in the list" from "checksum off — likely a transcription typo."
3. **AEAD primitive errors collapse to `AeadFailure`** without inner detail. The `chacha20poly1305` crate's error type carries no information beyond "failed," and AAD/key/nonce shapes are caller-controlled here, so an unexpected `AeadFailure` indicates a programming bug rather than a user-facing condition.

## Testing strategy

Five layers, mapping to the existing repo conventions.

### Layer 1 — unit tests inside each submodule

In-file `#[cfg(test)] mod tests`:

- `mnemonic.rs`: generate produces 24 words; `parse(generate)` round-trips entropy; parse normalizes whitespace and case; rejects each `MnemonicError` variant on the appropriate bad input.
- `bundle.rs`: canonical CBOR is byte-stable across runs and across `HashMap` iteration order; decode→encode round-trip is byte-identical; rejects unknown / duplicate fields and wrong-size keys.
- `bundle_file.rs`: encode/decode round-trip; rejects bad magic, wrong file_kind; sliced-truncation test (slice encoded bytes from `[..n]` for each `n` and assert all fail with `Truncated { offset }` matching `n` or `BadMagic` for very short slices); wrap length mismatches.
- `vault_toml.rs`: round-trip; unknown top-level key silently ignored (spec); unknown `[kdf]` key is a hard error (spec); bad salt b64 length rejected.

### Layer 2 — integration tests in `core/tests/unlock.rs`

New file modeled after `core/tests/identity.rs`. Eight scenarios:

1. `create → open_with_password` returns identical `IdentityBundle` and `identity_block_key`.
2. `create → open_with_recovery` returns identical `IdentityBundle` and `identity_block_key`.
3. Both unlock paths return the same `identity_block_key` (the dual-wrap invariant).
4. `open_with_password(wrong_password)` → `WrongPasswordOrCorrupt`.
5. `open_with_recovery(wrong_mnemonic)` → `WrongMnemonicOrCorrupt`.
6. `open_with_recovery(malformed_words)` → `InvalidMnemonic(_)` with the right inner variant.
7. Swap `identity.bundle.enc` from vault A into vault B's `vault.toml` → `VaultMismatch`.
8. Flip one byte in `bundle_ct` → `CorruptVault` (wrap unwrapped fine; body didn't).

All use a seeded `ChaCha20Rng` for deterministic vault bytes — a flake here means a real bug.

### Layer 3 — property tests in `core/tests/proptest.rs`

Extend the existing file with a new `mod unlock` block. Three round-trip properties using `proptest`:

- For any valid `IdentityBundle`: `from_canonical_cbor(to_canonical_cbor(b)) == b` and the canonical encoding is unique (encoding twice produces identical bytes).
- For any valid `BundleFile`: `decode(encode(f)) == f`.
- For any valid `VaultToml`: `decode(encode(t)) == t`.

Plus one composed property: for any `(password, display_name, seed)`, `open_with_password(create_vault(...))` returns the original `IdentityBundle` and the original `identity_block_key`. This is the central correctness claim of the whole module reduced to one assertion.

### Layer 4 — §15 KAT: `bip39_recovery_kat.json` (Item 1a)

New file `core/tests/data/bip39_recovery_kat.json`. Schema as proposed in `secretary_next_session.md`:

```json
{
  "vectors": [
    { "name": "all_zero_entropy",         "mnemonic": "...", "entropy": "<hex>",
      "info_tag": "<hex of TAG_RECOVERY_KEK>", "expected_recovery_kek": "<hex>" },
    { "name": "all_ones_entropy",         "..." },
    { "name": "trezor_vector_24w_random_1", "..." },
    { "name": "trezor_vector_24w_random_2", "..." }
  ]
}
```

Cross-verification, recorded in a comment in the test file:

- `mnemonic ↔ entropy` cross-checked against the `bip39` Python package.
- For at least two vectors, `(mnemonic, entropy)` lifted directly from the canonical Trezor BIP-39 test vectors, anchoring against an external reference rather than internal consistency only.
- `entropy + info_tag → expected_recovery_kek` cross-checked against Python `cryptography.hazmat.primitives.kdf.hkdf.HKDF`.

Loaded via existing `core/tests/kat_loader.rs` infrastructure. Test in `core/tests/unlock.rs`:

```rust
#[test]
fn bip39_recovery_kat_vectors() {
    let kat = load_kat::<Bip39RecoveryKat>("bip39_recovery_kat.json");
    for v in kat.vectors {
        let mnemonic = mnemonic::parse(&v.mnemonic).unwrap();
        assert_eq!(mnemonic.entropy().expose(), &v.entropy);
        let kek = derive_recovery_kek(mnemonic.entropy());
        assert_eq!(kek.expose(), &v.expected_recovery_kek, "vector {}", v.name);
    }
}
```

This pins both halves — `mnemonic → entropy` and `entropy → KEK` — and their composition. The existing `recovery_kek_test_vector_zero_entropy` in `core/tests/kdf.rs` only covered the second half.

### Layer 5 — `cargo clippy --all-targets -- -D warnings` clean

Same bar as the rest of the crate. No exceptions.

## Out of scope for this session

- **Filesystem I/O** — atomic writes, file locking, vault-folder layout. Belongs to the `vault` module per the design anchor.
- **Manifest decryption** — `manifest.cbor.enc` parsing/verification belongs to `vault::manifest` (which will use the `identity_block_key` and the `IdentityBundle`'s public keys returned by this module).
- **Block decryption** — per-block AEAD and per-recipient hybrid-KEM unwraps belong to `vault::block`.
- **Biometric / OS-keystore caching of `identity_block_key`** — per-platform clients (sub-projects C/D/E).
- **Password change / recovery-key rotation** — future enhancement; not in v1.
- **Cross-language conformance script** (`core/tests/python/conformance.py`). Sub-project A's "done" checklist requires it, but it's better written *after* the `vault` module exists. Verifying just unlock from Python alone covers half the spec, and the second half would be stale by next session.

## Spec compliance and references

| Spec section | Realised by |
|---|---|
| `crypto-design.md` §3 (Master KEK) | `mod.rs` calls existing `derive_master_kek` |
| `crypto-design.md` §4 (Recovery KEK) | `mod.rs` calls existing `derive_recovery_kek`; `mnemonic.rs` produces the entropy |
| `crypto-design.md` §5 (Identity Bundle wrap) | `mod.rs` orchestrates; `bundle.rs` produces canonical CBOR; `bundle_file.rs` produces the binary envelope |
| `crypto-design.md` §6.2 (canonical CBOR) | `bundle.rs::to_canonical_cbor` |
| `vault-format.md` §2 (`vault.toml`) | `vault_toml.rs` |
| `vault-format.md` §3 (`identity.bundle.enc`) | `bundle_file.rs` |
| §15 entry: BIP-39 recovery KAT | `core/tests/data/bip39_recovery_kat.json` + test in `core/tests/unlock.rs` |

## Verification of "done"

1. `cargo test --workspace` green.
2. `cargo test --release` green (existing convention; the integration tests are practical only at release with real Argon2id parameters in some scenarios).
3. `cargo clippy --all-targets -- -D warnings` clean.
4. New KAT file validated externally against `bip39` Python package and `cryptography` HKDF before commit.
5. `secretary_next_session.md` updated: Item 1a struck through, Item 3 marked done; Items 1b, 2, 4 carry forward.
