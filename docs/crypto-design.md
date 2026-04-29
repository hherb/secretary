# Secretary Cryptographic Design

This document specifies all cryptographic constructions used by Secretary at sufficient detail for an interoperable clean-room reimplementation. It is normative: the Rust reference implementation in `core/` follows this document, not the other way around.

For the byte-level on-disk format, see [vault-format.md](vault-format.md). For the threats motivating each construction, see [threat-model.md](threat-model.md). Terminology follows [glossary.md](glossary.md).

---

## 1. Suite v1: `secretary-v1-pq-hybrid` (suite-id `0x0001`)

All v1 vaults use this suite. Future suites will be assigned increasing IDs and may coexist within the same vault on a per-block basis.

### 1.1 Primitive choices

| Role | Algorithm | Specification | Reference Rust crate |
|---|---|---|---|
| Password KDF | Argon2id | RFC 9106 | `argon2` (RustCrypto) |
| Symmetric AEAD | XChaCha20-Poly1305 | RFC 8439 + XChaCha20 extension | `chacha20poly1305` (RustCrypto) |
| Classical KEM | X25519 | RFC 7748 | `x25519-dalek` |
| Post-quantum KEM | ML-KEM-768 | NIST FIPS 203 | `ml-kem` (RustCrypto) |
| Classical signature | Ed25519 | RFC 8032 | `ed25519-dalek` |
| Post-quantum signature | ML-DSA-65 | NIST FIPS 204 | `ml-dsa` (RustCrypto) |
| Hash (general / fingerprints) | BLAKE3-256 | BLAKE3 spec | `blake3` |
| Hash (HKDF instantiation) | SHA-256 | FIPS 180-4 | `sha2` (RustCrypto) |
| HKDF | HKDF-SHA-256 | RFC 5869 | `hkdf` (RustCrypto) |
| Recovery mnemonic encoding | BIP-39 (English wordlist) | BIP-39 | `bip39` |
| CSPRNG | OS-backed via `getrandom` | per-platform | `getrandom`, `rand_core::OsRng` |
| Memory hygiene | `zeroize` traits | n/a | `zeroize`, `secrecy`, `subtle` |

A clean-room implementation may substitute equivalent libraries provided the on-the-wire bytes are bit-identical and all test vectors pass.

### 1.2 Argon2id parameters (default)

```
algorithm  = Argon2id
version    = 0x13 (Argon2 v1.3)
memory     = 262144 KiB (256 MiB)
iterations = 3
parallelism = 1
salt       = 32 random bytes (per vault, stored cleartext in vault.toml)
output     = 32 bytes (master_kek)
```

Parameters are recorded in `vault.toml` so a vault is portable across devices regardless of the creating device's tuning. Memory may be reduced to 64 MiB on memory-constrained devices (mobile creating a new vault on an older phone), but never below 64 MiB. Iterations may be raised; never lowered.

### 1.3 Domain-separation tags

All KDF inputs, signature inputs, and AEAD AAD values are prefixed with a fixed ASCII tag identifying the construction. Domain separation prevents cross-protocol attacks where bytes valid in one role could be replayed in another.

| Tag | Role | Used in |
|---|---|---|
| `secretary-v1-recovery-kek` | HKDF info | Deriving Recovery KEK from BIP-39 entropy (§4) |
| `secretary-v1-id-wrap-pw` | AEAD AAD prefix | Wrapping Identity Block Key under Master KEK (§5) |
| `secretary-v1-id-wrap-rec` | AEAD AAD prefix | Wrapping Identity Block Key under Recovery KEK (§5) |
| `secretary-v1-id-bundle` | AEAD AAD prefix | Identity Bundle encryption (§5) |
| `secretary-v1-hybrid-kem` | HKDF salt | Combining classical and PQ shared secrets (§7) |
| `secretary-v1-hybrid-kem-transcript` | BLAKE3 prefix | Hybrid-KEM transcript hash (§7) |
| `secretary-v1-block-content-key-wrap` | HKDF info | Producing wrap key from hybrid-KEM combiner output (§7) |
| `secretary-v1-block-key-wrap` | AEAD AAD prefix | Wrapping per-recipient block content key (§7) |
| `secretary-v1-block-sig` | Signature message prefix | Hybrid signature on a block file (§8) |
| `secretary-v1-manifest-sig` | Signature message prefix | Hybrid signature on a manifest file (§8) |
| `secretary-v1-card-sig` | Signature message prefix | Self-signature on a Contact Card (§6) |
| `secretary-v1-fingerprint` | BLAKE3 keyed-hash key (via SHA-256 reduction) | Computing a Contact Card fingerprint (§6.1) |

All tags are encoded as ASCII bytes without trailing NUL or length prefix; they are concatenated directly with the bytes they domain-separate.

**Tag-disambiguation invariant.** No tag in this table may be a prefix of any other tag *when the tagged inputs could collide as bytes for the same primitive*. v1 has one prefix relation — `secretary-v1-hybrid-kem` is a strict prefix of `secretary-v1-hybrid-kem-transcript` — but the two are unambiguous because they feed different primitives in different positions: the former is consumed as the HMAC-SHA-256 salt input to HKDF-Extract (where it is keyed into HMAC's setup, never read as raw bytes), the latter is the initial 34 bytes of a BLAKE3 input followed by fixed-length fingerprints and ciphertexts. Any future tag added to this table that participates in a same-primitive same-position role with an existing tag MUST first break the prefix relation.

---

## 2. Key hierarchy

```
Master Password ──Argon2id(salt, params)──▶ Master KEK ────┐
                                                             ├─▶ wraps Identity Block Key
Recovery Mnemonic (BIP-39, 24w) ──HKDF─────▶ Recovery KEK ──┘

Identity Block Key ─AEAD─▶ Identity Bundle (containing all four secret keys)
                  │
                  └─AEAD─▶ Manifest

Per Block:
  Block Content Key (random 256-bit) ─AEAD─▶ Block plaintext (records)
  Block Content Key ─Hybrid KEM wrap─▶ recipient_1
                                     ─▶ recipient_2
                                     ─▶ ...
                                     ─▶ owner (always present as a recipient)
```

Each level isolates a different concern:

- **Master Password / Recovery Mnemonic** are user-held credentials, never persisted by Secretary.
- **Master KEK / Recovery KEK** are deterministic derivations from the credentials. Computed on demand, zeroized after use.
- **Identity Block Key** is a random 256-bit symmetric key that does not leave the owner's installation. Its job is to encrypt the Identity Bundle and the Manifest. It exists separately from the Master KEK so that changing the password does not require re-encrypting the manifest and bundle — only re-wrapping the Identity Block Key.
- **Block Content Keys** are random 256-bit symmetric keys, one per block (rotated on policy events such as recipient removal).

Rotation policy:
- Master password change: re-derive Master KEK, re-wrap Identity Block Key under new Master KEK. Identity Bundle and Manifest unchanged.
- Recovery mnemonic rotation: generate new mnemonic, re-derive Recovery KEK, re-wrap Identity Block Key under new Recovery KEK. Old mnemonic invalidated.
- Identity Block Key rotation: generate new key, re-encrypt Identity Bundle and Manifest, re-wrap under both Master KEK and Recovery KEK. Recommended on suspected device compromise.
- Block Content Key rotation: generate new key, re-encrypt block, re-wrap for all current recipients. Always done after removing a recipient (note: prior leaked key still decrypts prior cloud copies — see threat-model §4 limitation 2).

---

## 3. Master KEK derivation

Given `password : bytes`, `salt : 32 bytes`, `argon_params : (memory_kib, iterations, parallelism)`:

```
master_kek = Argon2id(
    password = password,
    salt     = salt,
    memory   = memory_kib,
    time     = iterations,
    parallel = parallelism,
    output_len = 32,
    type     = Argon2id,
    version  = 0x13,
)
```

The `master_kek` is a 32-byte symmetric key used directly as the AEAD key for the `wrap_pw` field of the Identity Bundle (see §5).

The `salt` is generated with the OS CSPRNG at vault creation and stored cleartext in `vault.toml`. The salt is *not* secret; its purpose is to prevent precomputation across different vaults using the same password.

---

## 4. Recovery KEK derivation

The recovery mnemonic is generated as 256 bits of OS-CSPRNG entropy at vault creation, then encoded as a 24-word BIP-39 phrase from the standard English wordlist for transcription. (BIP-39's 24-word phrases encode 256 bits + 8 checksum bits = 24 × 11 = 264 bits.)

To derive the Recovery KEK from a user-entered mnemonic:

```
1. Validate the BIP-39 word list and checksum. Reject on failure.
2. entropy = the 256-bit payload extracted from the validated mnemonic
3. recovery_kek = HKDF-SHA-256(
       ikm  = entropy,
       salt = 32 bytes of zero,
       info = "secretary-v1-recovery-kek",
       len  = 32,
   )
```

We deliberately do *not* run Argon2id on the recovery mnemonic. The mnemonic carries 256 bits of entropy from a CSPRNG; password stretching is unnecessary and would only slow legitimate use. (Argon2id is appropriate for low-entropy human-chosen passwords, not for high-entropy random secrets.)

The mnemonic itself is never persisted; the application discards both it and the derived `recovery_kek` from memory (zeroized) after wrapping or unwrapping the Identity Block Key.

---

## 5. Identity Bundle wrap

The Identity Bundle is the AEAD-encrypted CBOR-serialized record:

```cbor
{
  "user_uuid":       <bstr 16>,
  "display_name":    <tstr>,
  "x25519_sk":       <bstr 32>,
  "x25519_pk":       <bstr 32>,
  "ml_kem_768_sk":   <bstr 2400>,
  "ml_kem_768_pk":   <bstr 1184>,
  "ed25519_sk":      <bstr 32>,
  "ed25519_pk":      <bstr 32>,
  "ml_dsa_65_sk":    <bstr 32>,    ; FIPS 204 seed (xi); see note below
  "ml_dsa_65_pk":    <bstr 1952>,
  "created_at":      <u64 unix-millis>,
}
```

**Note on `ml_dsa_65_sk`:** The on-disk encoding is the 32-byte FIPS 204 KeyGen seed (`xi`), not the 4032-byte expanded signing-key form. The expanded form is a deterministic function of the seed (`MlDsa65::from_seed(xi)` recomputes it identically every time), so the seed is information-equivalent and 4 KiB smaller per identity bundle. We chose the seed because the upstream `ml-dsa` crate marks the 4032-byte expanded encoding `#[deprecated]` and our build runs `cargo clippy --all-targets -- -D warnings`. See `core/src/crypto/sig.rs` module docs for the full rationale, and §14 for the size-summary entry.

Encryption proceeds as follows:

```
1. Generate identity_block_key = 32 bytes from OS CSPRNG.
2. nonce_id = 24 random bytes from OS CSPRNG.
3. plaintext = canonical CBOR encoding of the bundle above.
4. aad_id    = "secretary-v1-id-bundle" || vault_uuid (16 bytes)
5. (ct_id, tag_id) = XChaCha20-Poly1305-Encrypt(
       key  = identity_block_key,
       nonce = nonce_id,
       aad  = aad_id,
       plaintext = plaintext)
```

Then the Identity Block Key is wrapped twice:

```
6. nonce_pw = 24 random bytes.
   (ct_pw, tag_pw) = XChaCha20-Poly1305-Encrypt(
       key  = master_kek,
       nonce = nonce_pw,
       aad  = "secretary-v1-id-wrap-pw" || vault_uuid,
       plaintext = identity_block_key)

7. nonce_rec = 24 random bytes.
   (ct_rec, tag_rec) = XChaCha20-Poly1305-Encrypt(
       key  = recovery_kek,
       nonce = nonce_rec,
       aad  = "secretary-v1-id-wrap-rec" || vault_uuid,
       plaintext = identity_block_key)
```

The `identity.bundle.enc` file structure is given in [vault-format.md](vault-format.md) §3.

Decryption is the obvious reverse: try `master_kek` first; on AEAD failure, try `recovery_kek`. AEAD failure with the correct password means file corruption, not wrong password — a wrong password produces tag failure, which is indistinguishable from corruption to the cryptography but distinguishable to the user (the UI prompts to re-enter the password before reporting corruption).

---

## 6. Contact Cards and fingerprints

A Contact Card is a public, signed artifact representing a user's identity to others. Cleartext (not encrypted; the public keys are the point of the card):

```cbor
{
  "card_version":  1,
  "contact_uuid":  <bstr 16>,           ; same as user_uuid in the bundle
  "display_name":  <tstr>,
  "x25519_pk":     <bstr 32>,
  "ml_kem_768_pk": <bstr 1184>,
  "ed25519_pk":    <bstr 32>,
  "ml_dsa_65_pk":  <bstr 1952>,
  "created_at":    <u64 unix-millis>,
  "self_sig_ed":   <bstr 64>,            ; over the canonical CBOR of all fields above (without sig fields)
  "self_sig_pq":   <bstr 3309>,           ; ML-DSA-65 signature, same message as above
}
```

The signed message for both `self_sig_ed` and `self_sig_pq` is:

```
"secretary-v1-card-sig" || canonical_cbor(card_without_sig_fields)
```

A card whose signatures don't both verify is rejected on import.

### 6.1 Card fingerprint

Fingerprints support OOB verification. The fingerprint is computed as:

```
fingerprint_bytes = BLAKE3-keyed-hash(
    key = SHA-256("secretary-v1-fingerprint")[..32],
    input = canonical_cbor(complete_card_including_sigs),
    out_len = 16,            ; 128 bits is sufficient for human verification
)
```

For UI presentation:

- **Mnemonic form**: 12 words from the BIP-39 English wordlist, derived from `fingerprint_bytes` by reading 11 bits at a time (12 × 11 = 132 bits; the trailing 4 bits are ignored). Used for verbal verification ("read me your fingerprint").
- **Hex form**: lowercase hex of `fingerprint_bytes`, grouped in 4-character blocks separated by spaces (`abcd 1234 ...`). Used for visual verification (showing on screen, comparing pasted text).

A clean-room implementation must produce identical mnemonic and hex strings for any given card.

### 6.2 Canonical CBOR encoding

Every byte string referenced as `canonical_cbor(...)` in this document — the §6 self-signed message, the §6.1 fingerprint input, the §5 Identity Bundle plaintext, the §9 block-record body, the §10 manifest, and `sender_pk_bundle` / `recipient_pk_bundle` in §7 — is produced by the **deterministic encoding profile of RFC 8949 §4.2.1**:

1. **Map keys are sorted bytewise lexicographically by their canonical encoded form.** For maps with text-string keys (the common case in this spec), this reduces to: shorter keys first; among keys of equal length, bytewise UTF-8 compare. The field listings in this document are descriptive of *which* fields exist; they are **not** normative for byte order.
2. **Definite-length encoding** for all maps, arrays, and byte/text strings.
3. **Shortest-form integer and length prefixes.** Integers and length headers use the smallest CBOR major-type-0 / major-type-1 / length encoding that fits. Negative integers are encoded as major type 1 with the same shortest-form rule.
4. **No tags, no floats, no indefinite-length items** anywhere in v1 records.
5. **Duplicate map keys are forbidden** (RFC 8949 §5.4); decoders MUST reject input that contains them.

A clean-room implementation passing the equivalent of `cbor2.dumps(record, canonical=True)` (Python) or sorting and shortest-form-encoding manually produces bit-identical bytes to this reference. The KAT files under `core/tests/data/` pin the byte form for v1 cards.

---

## 7. Hybrid KEM (per-recipient block-key wrap)

To wrap a *Block Content Key* `K` (32 bytes) for a recipient whose public keys are `pk_x` (X25519) and `pk_pq` (ML-KEM-768):

```
1. (ct_x,  ss_x ) = X25519-Encap(pk_x)         ; ct_x is 32 bytes (sender's ephemeral X25519 pk),
                                                ; ss_x is the 32-byte X25519 shared secret
2. (ct_pq, ss_pq) = ML-KEM-768-Encaps(pk_pq)   ; ct_pq is 1088 bytes, ss_pq is 32 bytes
3. transcript = BLAKE3(
       "secretary-v1-hybrid-kem-transcript"
       || sender_card_fingerprint (16 bytes)
       || recipient_card_fingerprint (16 bytes)
       || ct_x   (32 bytes)
       || ct_pq  (1088 bytes)
   )    ; 32 bytes
4. prk = HKDF-SHA-256-Extract(
       salt = "secretary-v1-hybrid-kem",
       ikm  = ss_x || ss_pq || ct_x || ct_pq || sender_pk_bundle || recipient_pk_bundle)
5. wrap_key = HKDF-SHA-256-Expand(
       prk  = prk,
       info = "secretary-v1-block-content-key-wrap" || transcript,
       len  = 32)
6. nonce_w  = 24 random bytes (OS CSPRNG)
7. (ct_w, tag_w) = XChaCha20-Poly1305-Encrypt(
       key   = wrap_key,
       nonce = nonce_w,
       aad   = "secretary-v1-block-key-wrap" || block_uuid (16 bytes) || transcript,
       plaintext = K)
```

`sender_pk_bundle` and `recipient_pk_bundle` are the canonical CBOR encodings of `(x25519_pk, ml_kem_768_pk, ed25519_pk, ml_dsa_65_pk)` in that order — these are the same bytes as appear in the Contact Card before signatures.

The **wire form** of the per-recipient wrap (the contents of one entry in the block file's recipients table) is:

```
recipient_fingerprint  (16 bytes)
ct_x                   (32 bytes)
ct_pq                  (1088 bytes)
nonce_w                (24 bytes)
ct_w + tag_w           (32 + 16 = 48 bytes)   ; AEAD ciphertext of K plus its tag
```

Total: 16 + 32 + 1088 + 24 + 48 = **1208 bytes per recipient**.

### 7.1 Decap (recipient side)

Given the recipient's secret keys `sk_x`, `sk_pq` and the wire form above:

```
1. ss_x  = X25519-Decap(sk_x, ct_x)
2. ss_pq = ML-KEM-768-Decaps(sk_pq, ct_pq)
3. Recompute transcript and wrap_key as in §7 steps 3–5 (sender_pk_bundle and recipient_pk_bundle are obtained from the sender's card and the recipient's own bundle).
4. K = XChaCha20-Poly1305-Decrypt(
       key   = wrap_key,
       nonce = nonce_w,
       aad   = "secretary-v1-block-key-wrap" || block_uuid || transcript,
       ciphertext = ct_w,
       tag   = tag_w)
```

If either KEM decap fails or the AEAD tag fails, the wrap is rejected.

### 7.2 Why include both ciphertexts and both public keys in the HKDF input?

Including both KEM ciphertexts in the HKDF input binds the wrap key to the exact transcript: an adversary who attempts to substitute one half of the hybrid (e.g., replace `ct_pq` with their own) will produce a different transcript, hence a different wrap key, hence AEAD tag failure. This defends against a class of "KEM-sneak" attacks where a flawed combiner allows an attacker to bypass the post-quantum half by malleating the classical half (or vice versa).

---

## 8. Hybrid signatures

To sign a message `m` with the user's identity:

```
1. message = "secretary-v1-{role}-sig" || canonical_bytes(m)
   where {role} is one of: "block", "manifest", "card"
2. sig_ed  = Ed25519-Sign(sk_ed, message)        ; 64 bytes
3. sig_pq  = ML-DSA-65-Sign(sk_pq, message)      ; 3309 bytes (FIPS 204 ML-DSA-65 fixed signature size)
4. The hybrid signature is the pair (sig_ed, sig_pq). Each is carried in its own length-prefixed field on disk; the length prefix exists for forward compatibility with future suites that may use larger PQ signature sizes.
```

To verify:

```
1. Reconstruct message exactly as above.
2. Verify both Ed25519-Verify(pk_ed, message, sig_ed) AND ML-DSA-65-Verify(pk_pq, message, sig_pq).
3. Both must return success. If either fails, the signature is invalid.
```

ML-DSA-65 signatures are variable-length (the ML-DSA spec allows rejection sampling, producing different signature lengths per attempt). The disk format records the actual length in a `sig_len_pq` field.

---

## 9. Block Content Key generation and AEAD

A block's plaintext is its CBOR-encoded record list (see [vault-format.md](vault-format.md) §4.2). Encryption:

```
1. block_content_key = 32 bytes from OS CSPRNG.
2. nonce_b = 24 random bytes from OS CSPRNG.
3. plaintext = canonical CBOR of the block body.
4. aad_b = serialized block header bytes — see vault-format.md §4.1
5. (ct_b, tag_b) = XChaCha20-Poly1305-Encrypt(
       key   = block_content_key,
       nonce = nonce_b,
       aad   = aad_b,
       plaintext = plaintext)
```

Then `block_content_key` is wrapped per-recipient via §7. The owner is always a recipient (otherwise the block would be unreadable to its creator).

After encryption, the entire block file (header + recipient table + nonce + ciphertext + tag) is signed via §8 with role `"block"`. The signing is over all bytes preceding the signature fields themselves.

Nonce reuse must never happen: a fresh `nonce_b` is generated on every block edit (every time a block is rewritten to disk). The combination `(block_content_key, nonce_b)` must be unique. Since the content key is rotated only on policy events and 24-byte nonces have a birthday bound at 2^96, nonce collision is statistically negligible.

---

## 10. Manifest signing and rollback resistance

The Manifest's plaintext (vault-format.md §4.2) is AEAD-encrypted under the *Identity Block Key*. The AAD is the manifest file header bytes (42 bytes from `magic` through `last_mod_ms` inclusive — see vault-format.md §4.1). Binding the header to the AEAD ensures that header fields including `file_kind = 0x0002` (which distinguishes manifest from other Secretary file types) and `vault_uuid` cannot be modified without invalidating the AEAD tag.

The entire encrypted manifest file is then hybrid-signed with role `"manifest"` over its complete bytes preceding the signature fields. The signature provides cross-vault and cross-author authenticity even if the AAD construction is somehow circumvented.

Rollback resistance is achieved at two levels:

1. **Per-block** — the manifest's `blocks` array carries a BLAKE3 fingerprint of each block file's complete bytes. Substituting an older block file invalidates the manifest signature.

2. **Per-manifest** — the manifest carries a vault-level vector clock. Each device maintains an OS-local "highest vector clock seen for this vault". On loading a manifest:
   - If the new clock is greater-than-or-equal-to (component-wise) the highest seen → accept and update highest seen.
   - If the new clock is *strictly dominated by* the highest seen → reject as rollback. UI offers explicit "I am restoring from a backup; accept anyway" override.
   - If the new clock is *concurrent* (some components higher, some lower) → trigger merge. The merged manifest's vector clock is the component-wise max of the two, plus one for the merging device.

The "highest seen" state is stored per-vault in the OS keystore (so it shares the device's tamper resistance) and persists across application restarts. Destroying it (e.g., re-installing Secretary on the same device) returns the device to a "no history" state — the next manifest is accepted regardless of its clock, and rollback resistance is reset on that device.

---

## 11. Per-record CRDT merge

When two devices have concurrently edited the same block (vector clocks are incomparable), Secretary performs field-level last-writer-wins merge:

```
merge(local_block, remote_block) -> merged_block:
    assert local_block.block_uuid == remote_block.block_uuid
    assert vector_clocks_concurrent(local, remote)
    merged_records = {}
    for record_uuid in union(local.record_uuids, remote.record_uuids):
        l = local.records.get(record_uuid)
        r = remote.records.get(record_uuid)
        if l and not r:
            merged_records[uuid] = l
        elif r and not l:
            merged_records[uuid] = r
        else:
            merged_records[uuid] = merge_record(l, r)
    merged_block.records = merged_records
    merged_block.vector_clock = component_wise_max(local.vc, remote.vc)
    merged_block.vector_clock[merging_device] += 1
    return merged_block

merge_record(l, r) -> record:
    # union fields; per-field LWW
    out_fields = {}
    for fname in union(l.fields, r.fields):
        lf = l.fields.get(fname)
        rf = r.fields.get(fname)
        if lf and not rf:    out_fields[fname] = lf
        elif rf and not lf:  out_fields[fname] = rf
        elif lf.last_mod > rf.last_mod: out_fields[fname] = lf
        elif rf.last_mod > lf.last_mod: out_fields[fname] = rf
        else:
            # last_mod tie — break by device_uuid lexicographically
            out_fields[fname] = (lf if lf.device_uuid < rf.device_uuid else rf)
    return record_with_fields(out_fields)
```

### 11.1 Per-record metadata merge

The pseudocode above pins the field-level merge core. The remaining record-level metadata follow these deterministic rules so the merge is total over well-formed inputs and remains commutative, associative, and idempotent.

| Field | Merge rule |
|---|---|
| `record_uuid` | Equal by precondition (records merge only when their UUIDs match). |
| `record_type` | Greater record-level `last_mod_ms` wins; on tie, the **lex-larger byte string** wins (compared as UTF-8 bytes). v1 writers SHOULD NOT change `record_type` after creation; the lex-larger tie-break only matters for adversarial / malformed inputs. |
| `fields` | Per-field LWW per the pseudocode (`last_mod` greater wins; ties broken by `device_uuid` lexicographically). |
| `tags` | Greater record-level `last_mod_ms` wins; on tie, the **set union** of both sides' tags is taken (canonical-CBOR sort applied on encode). Set union is itself commutative, associative, and idempotent, so it preserves the global merge invariant when ties occur. |
| `created_at_ms` | `min(l.created_at_ms, r.created_at_ms)` — the earliest creation observed across all replicas. |
| `last_mod_ms` | `max(l.last_mod_ms, r.last_mod_ms)`. |
| `tombstone` | Tombstone tie-break — see §11.3. |
| `unknown` (forward-compat) | Per-key. A key present in only one side is kept verbatim. A key present in both sides with differing values takes the **lex-larger canonical-CBOR-encoded value bytes**. v2 writers that need value-aware merging of new top-level keys MUST attach per-key CRDT metadata in the same shape as `RecordField` and bump the suite version. |

### 11.2 Per-block metadata merge

| Field | Merge rule |
|---|---|
| `block_uuid` | Equal by precondition. A `block_uuid` mismatch is a programmer error, not a mergeable conflict, and implementations MUST surface it as a typed error rather than attempting to merge. |
| `block_version`, `schema_version` | `max` of the two values. Both are monotonic version numbers that only increase across releases. |
| `block_name` | The **lex-larger byte string** wins (compared as UTF-8 bytes). v1 writers do not version `block_name`, so divergence here is rare; the deterministic rule keeps the merge commutative. |
| `records` | Per-record union + per-field LWW per the pseudocode. |
| `vector_clock` | Component-wise max of the two clocks, then `+1` for the merging device's component (a fresh entry is added when the merging device has none). |
| `unknown` (forward-compat) | Per-key. A key present in only one side is kept verbatim. A key present in both sides with differing values takes the **lex-larger canonical-CBOR-encoded value bytes**. |

### 11.3 Tombstone tie-break

For a pairwise merge where one side is tombstoned at record-level `last_mod_ms = T_d` and the other is live at `last_mod_ms = T_l`:

- The tombstone wins iff `T_d ≥ T_l`. This is the *tombstone-on-tie* rule: deletion is sticky.
- The merged record carries the tombstoning side's `tags`, empty `fields` per §6.3, and `last_mod_ms = max(T_d, T_l)`.
- When both sides are tombstoned, the merged record is tombstoned, `tags` follow record-level LWW per §11.1, and `fields` are empty.
- When both sides are live, the merged record is live and follows the per-field rules above.
- A live edit observed *strictly after* a tombstone (`T_l > T_d`) resurrects the record. This is intentional: the retention window in §11.4 ensures all devices have observed the deletion before tombstones are GC'd, so a post-deletion edit is a deliberate undelete.

Tombstones are garbage-collected only after a configurable retention window (default: 90 days) to ensure all syncing devices have observed the deletion before the on-disk evidence is removed.

### 11.4 Concurrent value collisions and UI resolution

When the per-field LWW resolves a field where both sides held differing values, the LWW winner is the persisted value, but implementations MAY surface the field name and the loser's value to a UI for explicit user resolution. The on-disk record carries no `_conflicts` shadow in suite v1; conflict surfacing is a Rust API affordance returned by the merge primitives, not a wire-format feature. This keeps the merge total and the persisted record canonical regardless of whether a UI is present to consume the collision report.

The merge function must be **commutative**, **associative**, and **idempotent**. These properties are enforced by property-based tests in `core/tests/`.

---

## 12. Cipher-suite migration

A new suite (e.g., suite `0x0002` adopting different parameters) can coexist with v1 in the same vault on a per-block basis. To migrate a block:

1. Read the block under its current suite (e.g., suite `0x0001`).
2. Re-encrypt under the new suite, generating a new content key, new wraps, new nonce, and new signature.
3. Write the new block file (same `block_uuid`).
4. Update the manifest to reflect the new fingerprint.
5. Sign the new manifest under the **new** suite.

A vault is fully migrated when no block remains under the old suite. The old suite ID may be removed from a future client release, at which point any straggling old blocks become unreadable until migrated by a still-supporting client.

The Identity Bundle and Manifest themselves are upgraded as part of suite migration: their suite ID is recorded and can be advanced together when the user explicitly migrates.

---

## 13. CSPRNG usage

Secretary uses `getrandom` (OS-provided entropy) for all random values:

- Salts (Argon2id, AEAD nonces, identity bundle nonces).
- Symmetric keys (Identity Block Key, Block Content Keys, ephemeral wrap keys are HKDF-derived, not random).
- Asymmetric secret keys (X25519 sk, ML-KEM-768 sk, Ed25519 sk, ML-DSA-65 sk).
- Recovery mnemonic entropy.
- Vault UUID, contact UUID, block UUID, record UUID, device UUID.

The `getrandom` crate calls into the OS CSPRNG (`getrandom(2)` on Linux, `arc4random_buf` on macOS / iOS / BSD, `BCryptGenRandom` on Windows, `/dev/urandom` fallback). Failure of the OS CSPRNG is treated as a fatal error — Secretary refuses to operate.

Random numbers are *never* derived from non-OS sources (e.g., process state, time, the existing vault contents).

---

## 14. Constants and sizes summary

For convenience, all magic constants and sizes used in v1:

```
magic                       = 0x53454352  ("SECR" big-endian)
format_version (u16)        = 1
suite_id (u16)              = 1
vault_uuid                  = 16 bytes
device_uuid                 = 16 bytes
contact_uuid / user_uuid    = 16 bytes
block_uuid                  = 16 bytes
record_uuid                 = 16 bytes

argon2id_salt               = 32 bytes
argon2id_output             = 32 bytes
master_kek                  = 32 bytes
recovery_kek                = 32 bytes
identity_block_key          = 32 bytes
block_content_key           = 32 bytes

xchacha20_nonce             = 24 bytes
poly1305_tag                = 16 bytes

x25519_pk                   = 32 bytes
x25519_sk                   = 32 bytes
ml_kem_768_pk               = 1184 bytes
ml_kem_768_sk               = 2400 bytes
ml_kem_768_ct (encap)       = 1088 bytes
ml_kem_768_ss               = 32 bytes

ed25519_pk                  = 32 bytes
ed25519_sk                  = 32 bytes
ed25519_sig                 = 64 bytes

ml_dsa_65_pk                = 1952 bytes
ml_dsa_65_sk_expanded       = 4032 bytes (FIPS 204 expanded form; not stored on disk in v1)
ml_dsa_65_sk_seed           = 32 bytes   (FIPS 204 KeyGen seed xi; this is what §5 stores)
ml_dsa_65_sig               = 3309 bytes (FIPS 204 fixed; length-prefixed on disk for forward compatibility)

blake3_fingerprint_full     = 32 bytes
blake3_fingerprint_short    = 16 bytes  (used for human-displayed card fingerprint)
hkdf_sha256_output          = up to 8160 bytes; we always use 32

bip39_words                 = 24 (256-bit recovery mnemonic) or 12 (128-bit fingerprint)
```

---

## 15. Test vectors

Secretary's `core/tests/data/` directory contains golden vectors covering each construction in this document:

| File | Coverage |
|---|---|
| `argon2id_kat.json` | Argon2id with v1 parameters; password / salt / params / expected output. |
| `xchacha20poly1305_kat.json` | XChaCha20-Poly1305 with various nonce / aad / plaintext combinations. |
| `x25519_kat.json` | RFC 7748 test vectors. |
| `ml_kem_768_kat.json` | NIST FIPS 203 KAT subset for ML-KEM-768. |
| `ed25519_kat.json` | RFC 8032 test vectors. |
| `ml_dsa_65_kat.json` | NIST FIPS 204 KAT subset for ML-DSA-65. |
| `hkdf_sha256_kat.json` | RFC 5869 vectors. |
| `bip39_recovery_kat.json` | Mnemonic encoding / decoding round-trip and HKDF derivation. |
| `hybrid_kem_kat.json` | Full §7 wrap and decap with fixed inputs (deterministic — KEM ephemerality is faked via fixed seeds). |
| `hybrid_sig_kat.json` | Full §8 sign and verify with fixed inputs. |
| `card_fingerprint_kat.json` | §6.1 fingerprint and mnemonic encoding for fixed cards. |
| `golden_vault_001/` | A complete v1 vault: `vault.toml`, `manifest.cbor.enc`, `identity.bundle.enc`, one block, one contact card. With known password and recovery mnemonic. The Python conformance script (`core/tests/python/conformance.py`) decrypts this vault from the spec alone. |

A clean-room implementation passes by reproducing all vector outputs and successfully decrypting `golden_vault_001/`.
