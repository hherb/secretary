# Secretary Vault Format Specification (v1)

This document defines the on-disk format of a Secretary vault at byte-level detail. It is paired with [crypto-design.md](crypto-design.md), which defines the cryptographic constructions referenced here. A clean-room implementation pairs the two documents to produce bit-identical files.

The format version described here is **`format_version = 1`**, **`suite_id = 1`** (`secretary-v1-pq-hybrid`). Other suite IDs may exist within the same vault on a per-block basis (see crypto-design §12).

All multi-byte integers are **big-endian** unless explicitly stated otherwise. All CBOR data uses the **deterministic encoding profile** of RFC 8949 §4.2.1 (preferred map key sorting, definite-length encoding, shortest integer encoding) wherever a signature covers the encoding.

---

## 1. Folder layout

A vault is a directory. The user chooses where it lives — typically inside their iCloud Drive / Google Drive / Dropbox / OneDrive / WebDAV mount, but a local directory works equally well.

```
<vault-folder>/
  vault.toml                              # cleartext metadata; see §2
  identity.bundle.enc                     # encrypted, dual-wrapped identity; see §3
  manifest.cbor.enc                       # encrypted, signed manifest; see §4
  contacts/
    <contact-uuid>.card                   # imported contact cards (signed, public); see §5
    ...
  devices/
    <device-uuid>.wrap                    # per-device IBK wrap (file_kind 0x0004); see §3a
    ...
  blocks/
    <block-uuid>.cbor.enc                 # one file per block; see §6
    ...
  trash/
    <block-uuid>.cbor.enc.<unix-millis>   # tombstoned blocks awaiting purge
    ...
```

UUIDs in filenames are encoded as lowercase hex with dashes in canonical 8-4-4-4-12 form (e.g., `1f3a4b2c-9d8e-4f7a-b6c5-1a2b3c4d5e6f.cbor.enc`).

Filenames are the only place where UUIDs appear in cleartext within the vault folder. The cloud-folder host therefore sees the *number* of blocks and the *UUID* of each block (which is opaque). It does not see block names, record counts, recipients, or any other metadata.

### 1.1 Sharing exports

When a user shares a block to another Secretary user, they place a copy of the block file (with the recipient's wrap added in the recipient table — see §6) into a folder both parties have access to. The destination folder need not be a Secretary vault; it can be any folder the recipient can read.

```
<shared-folder>/
  <block-uuid>.cbor.enc                   # the shared block, with recipient's wrap
  <sender-card>.card                      # optional; only if user pastes their card alongside
```

The recipient's Secretary client, on detecting the file, *does not auto-import it*. The recipient must explicitly import it, at which point the block is added to their own vault under `blocks/<block-uuid>.cbor.enc`. (See ADR 0005.)

---

## 2. `vault.toml` — cleartext metadata

A small TOML file containing only non-secret bootstrap metadata:

```toml
# vault.toml — Secretary vault metadata (cleartext; not secret)
format_version = 1
suite_id       = 1
vault_uuid     = "1f3a4b2c-9d8e-4f7a-b6c5-1a2b3c4d5e6f"
created_at_ms  = 1745594400000

[kdf]
algorithm   = "argon2id"
version     = "1.3"
memory_kib  = 262144
iterations  = 3
parallelism = 1
salt_b64    = "<base64 of 32 random bytes>"
```

`vault_uuid` is generated at vault creation. It is the canonical identifier for this vault. Sharing exports embed `vault_uuid` so a recipient's client can detect "this block came from vault X."

`kdf.salt_b64` is the Argon2id salt used to derive the *Master KEK* from the master password. It is not secret; it exists only to prevent precomputation attacks across vaults.

The file is parsed into a typed struct. Unknown top-level keys are ignored (forward compatibility); unknown keys *inside* `[kdf]` are an error (because misinterpreting KDF parameters would produce a wrong key).

---

## 3. `identity.bundle.enc` — dual-wrapped identity

A binary file containing the dual-wrapped *Identity Block Key* and the AEAD-encrypted *Identity Bundle*. The Identity Bundle's plaintext format is given in crypto-design §5.

Layout (all integers big-endian):

```
┌──────────────────────────────────────────────────────────────┐
│ magic              (4 bytes)  = 0x53454352 ("SECR")          │
│ format_version     (2 bytes)  = u16, v1: 0x0001              │
│ file_kind          (2 bytes)  = u16, identity-bundle: 0x0001 │
│ vault_uuid         (16 bytes)                                │
│ created_at_ms      (8 bytes)                                 │
│                                                              │
│ wrap_pw_nonce      (24 bytes) = XChaCha20 nonce              │
│ wrap_pw_ct_len     (4 bytes)  = u32, must be 32              │
│ wrap_pw_ct         (32 bytes) = AEAD ciphertext of identity_block_key under master_kek │
│ wrap_pw_tag        (16 bytes) = Poly1305 tag                 │
│                                                              │
│ wrap_rec_nonce     (24 bytes)                                │
│ wrap_rec_ct_len    (4 bytes)  = u32, must be 32              │
│ wrap_rec_ct        (32 bytes) = AEAD ciphertext under recovery_kek │
│ wrap_rec_tag       (16 bytes)                                │
│                                                              │
│ bundle_nonce       (24 bytes)                                │
│ bundle_ct_len      (4 bytes)                                 │
│ bundle_ct          (var)      = AEAD ciphertext of canonical CBOR(IdentityBundle) │
│ bundle_tag         (16 bytes)                                │
└──────────────────────────────────────────────────────────────┘
```

AAD values (per crypto-design §5):
- `wrap_pw`: `"secretary-v1-id-wrap-pw" || vault_uuid` (23 ASCII bytes + 16-byte UUID = 39 bytes)
- `wrap_rec`: `"secretary-v1-id-wrap-rec" || vault_uuid` (24 + 16 = 40 bytes)
- `bundle`: `"secretary-v1-id-bundle" || vault_uuid` (22 + 16 = 38 bytes)

The ASCII tag bytes are concatenated directly with the 16 raw UUID bytes; no length prefix and no NUL terminator.

The file has no signature of its own. Its integrity is protected by AEAD tags on each component; substituting any byte invalidates a tag on read. (The Identity Bundle does not need a separate signature because only the owner ever writes it — there is no cross-user authentication concern at this layer.)

A reader unable to decrypt either `wrap_pw` (master password) or `wrap_rec` (recovery mnemonic) cannot proceed. AEAD tag failure is reported to the UI as "wrong password" rather than "corrupt vault" — a wrong key produces tag failure indistinguishable from corruption to cryptography but the UI assumes wrong-key first.

---

## 3a. `devices/<device-uuid>.wrap` — per-device IBK wrap

An optional, additive file (ADR 0009). Each enrolled device has one. Big-endian integers,
same header discipline as §3. A vault with no enrolled devices has no `devices/` directory.

```
┌──────────────────────────────────────────────────────────────┐
│ magic              (4 bytes)  = 0x53454352 ("SECR")          │
│ format_version     (2 bytes)  = u16, v1: 0x0001              │
│ file_kind          (2 bytes)  = u16, device-wrap: 0x0004     │
│ vault_uuid         (16 bytes)                                 │
│ device_uuid        (16 bytes)                                 │
│ wrap_dev_nonce     (24 bytes) = XChaCha20 nonce              │
│ wrap_dev_ct_len    (4 bytes)  = u32, must be 32              │
│ wrap_dev_ct        (32 bytes) = AEAD ciphertext of the IBK   │
│ wrap_dev_tag       (16 bytes) = Poly1305 tag                 │
└──────────────────────────────────────────────────────────────┘
```

- `suite_id` is omitted, matching §3 (identity-layer files fix the suite at v1; only
  manifest/block *content* files carry `suite_id`).
- `wrap_dev_ct_len` MUST equal 32 (XChaCha20-Poly1305 ciphertext length equals plaintext length for the 32-byte IBK), matching the `wrap_pw_ct_len` / `wrap_rec_ct_len` convention in §3.
- `vault_uuid` MUST equal the vault's `vault.toml` `vault_uuid`; a mismatch is rejected.
- `device_uuid` in the header MUST equal the `<device-uuid>` in the filename.
- AEAD AAD = `"secretary-v1-id-wrap-dev" || vault_uuid`; `device_kek` derivation is
  `docs/crypto-design.md` §5a.

Filenames use the lowercase-hyphenated 8-4-4-4-12 UUID form, as for blocks/contacts (§1).

---

## 4. `manifest.cbor.enc` — encrypted, signed manifest

The manifest is the top-level vault index. It enumerates all blocks, records their fingerprints and recipient lists, and carries the vault's vector clock for rollback / merge.

### 4.1 File-level layout

```
┌──────────────────────────────────────────────────────────────┐
│ magic              (4 bytes)  = 0x53454352                   │
│ format_version     (2 bytes)  = u16, 0x0001                  │
│ suite_id           (2 bytes)  = u16, 0x0001                  │
│ file_kind          (2 bytes)  = u16, manifest: 0x0002        │
│ vault_uuid         (16 bytes)                                │
│ created_at_ms      (8 bytes)                                 │
│ last_mod_ms        (8 bytes)                                 │
│                                                              │
│ aead_nonce         (24 bytes)                                │
│ aead_ct_len        (4 bytes)  = u32                          │
│ aead_ct            (var)      = AEAD ciphertext of manifest CBOR │
│ aead_tag           (16 bytes)                                │
│                                                              │
│ author_fingerprint (16 bytes) = short fingerprint of the author's card │
│ sig_ed_len         (2 bytes)  = u16, must be 64              │
│ sig_ed             (64 bytes) = Ed25519 signature            │
│ sig_pq_len         (2 bytes)  = u16, 3309 (suite v1)         │
│ sig_pq             (var)      = ML-DSA-65 signature          │
└──────────────────────────────────────────────────────────────┘
```

AEAD details:
- Key: *Identity Block Key*
- AAD: bytes from `magic` through `last_mod_ms` inclusive (42 bytes), unchanged across the AEAD layer
- Plaintext: canonical CBOR encoding of the manifest body (§4.2)

Signature details (per crypto-design §8 with role `"manifest"`):
- Signed message: `"secretary-v1-manifest-sig" || (all bytes from magic through aead_tag inclusive)`
- The author's identity public keys (used for verification) are obtained from the author's contact card, looked up by `author_fingerprint`. For a single-user vault, the only author is the vault owner; the owner's card is held in the local Identity Bundle and need not appear in `contacts/`.

### 4.2 Manifest body (CBOR plaintext inside `aead_ct`)

```cbor
{
  "manifest_version":  1,                          ; reserved for future incompatible manifest changes
  "vault_uuid":        <bstr 16>,
  "format_version":    1,
  "suite_id":          1,
  "owner_user_uuid":   <bstr 16>,
  "vector_clock": [
    { "device_uuid": <bstr 16>, "counter": <u64> },
    ...
  ],
  "blocks": [                                     ; the block list
    {
      "block_uuid":      <bstr 16>,
      "block_name":      <tstr>,                  ; user-visible, plaintext within encrypted manifest
      "fingerprint":     <bstr 32>,                ; BLAKE3-256 of the complete block file bytes
      "recipients":      [<bstr 16>, ...],         ; contact_uuids of each recipient (always includes owner)
      "vector_clock_summary": [                    ; the block's own vector clock at last manifest update
        { "device_uuid": <bstr 16>, "counter": <u64> },
        ...
      ],
      "suite_id":        1,                       ; the suite the block file is encrypted under
      "created_at_ms":   <u64>,
      "last_mod_ms":     <u64>
    },
    ...
  ],
  "trash": [                                      ; tombstoned blocks
    {
      "block_uuid":     <bstr 16>,
      "tombstoned_at_ms": <u64>,
      "tombstoned_by":  <bstr 16>,                 ; device_uuid that performed the deletion
      "fingerprint":    <bstr 32, optional>        ; BLAKE3-256 of the trashed block file bytes,
                                                   ; captured at trash time. Binds restored content
                                                   ; freshness to the signed manifest (§7.1 step 3a).
                                                   ; Absent for entries written by pre-this-version
                                                   ; clients; restore then falls back to suffix +
                                                   ; hybrid-verify only.
      "purged_at_ms":   <u64, optional>            ; unix-millis this block was permanently purged
                                                   ; (local trash/ ciphertext removed). Terminal and
                                                   ; monotonic — a purged entry never un-purges.
                                                   ; Absent = still restorable. Additive optional key
                                                   ; (§6.3.2 forward-compat pattern, same shape as
                                                   ; `fingerprint` above): old clients round-trip it
                                                   ; verbatim via the unknown-keys map. See §7.2.
    },
    ...
  ],
  "kdf_params": {                                  ; mirrored from vault.toml for cross-validation
    "memory_kib":  262144,
    "iterations": 3,
    "parallelism": 1,
    "salt":       <bstr 32>
  }
}
```

`kdf_params` is duplicated here (also in `vault.toml`) so the manifest signature attests to them. A modified `vault.toml` cannot trick a reader into deriving a wrong `master_kek` without also producing an invalid manifest signature.

### 4.3 Reading the manifest

```
1. Read entire manifest.cbor.enc into memory.
2. Parse the file-level header (§4.1).
3. AEAD-decrypt aead_ct under identity_block_key with aad = bytes 0..42.
4. Parse the resulting plaintext as canonical CBOR (§4.2). Reject on parse failure.
5. Verify manifest_body.vault_uuid == header.vault_uuid (cross-check).
6. Verify manifest_body.kdf_params == vault_toml.kdf (cross-check).
7. Look up author_fingerprint:
    - If it matches the owner's own card fingerprint, use the Identity Bundle's pubkeys.
    - Otherwise, look in contacts/<author_uuid>.card; on miss, reject (unknown signer).
8. Reconstruct signed_message = "secretary-v1-manifest-sig" || header_bytes_through_aead_tag
9. Hybrid-verify (sig_ed, sig_pq) against the author's pubkeys. Reject on failure.
10. Compare manifest_body.vector_clock against the OS-local "highest seen" for this vault_uuid:
    - dominated → reject as rollback (with explicit user override option)
    - greater_or_equal → accept, update highest seen
    - concurrent → trigger merge (see crypto-design §10)
11. The manifest is now trusted. Use manifest.blocks to enumerate available blocks.
```

### 4.4 Writing the manifest

```
1. Construct manifest_body with current data and updated vector_clock for this device.
2. Canonical-CBOR-encode it to plaintext_bytes.
3. Generate fresh aead_nonce.
4. AEAD-encrypt to obtain (aead_ct, aead_tag) under identity_block_key with the same aad as on read.
5. Compute author_fingerprint (= short fingerprint of own contact card).
6. Construct signed_message and sign with both Ed25519 and ML-DSA-65.
7. Write the file.
8. Update OS-local "highest seen" vector_clock for this vault.
```

---

## 5. Contact cards (`contacts/<contact-uuid>.card`)

A single CBOR-encoded Contact Card per file (per crypto-design §6). The file is *not* encrypted (the public keys are public by intent) but is self-signed; an unsigned card or one whose signatures don't verify is rejected on import.

The filename's `<contact-uuid>` must match the card's `contact_uuid` field. Mismatch → reject.

A vault's `contacts/` directory contains exactly the cards the user has explicitly imported. Cards are never auto-discovered or auto-imported (ADR 0005). The owner's own card is *not* placed in `contacts/`; it is reconstructable from the Identity Bundle and is needed primarily for sharing exports (where the user pastes a copy alongside the shared block).

---

## 6. Block files (`blocks/<block-uuid>.cbor.enc`)

A single block per file. The block is the unit of both encryption and sharing.

### 6.1 File-level layout

```
┌──────────────────────────────────────────────────────────────┐
│ magic              (4 bytes)  = 0x53454352                   │
│ format_version     (2 bytes)  = u16, 0x0001                  │
│ suite_id           (2 bytes)  = u16, 0x0001                  │
│ file_kind          (2 bytes)  = u16, block: 0x0003           │
│ vault_uuid         (16 bytes) = source vault (for sharing exports) │
│ block_uuid         (16 bytes)                                │
│ created_at_ms      (8 bytes)                                 │
│ last_mod_ms        (8 bytes)                                 │
│                                                              │
│ vector_clock_count (2 bytes)  = u16                          │
│ vector_clock_entries (var)    = vector_clock_count × 24 bytes │
│   each entry: device_uuid (16) || counter (u64)              │
│                                                              │
│ recipient_count    (2 bytes)  = u16                          │
│ recipient_entries  (var)      = recipient_count × 1208 bytes │
│   each entry: see §6.2                                       │
│                                                              │
│ aead_nonce         (24 bytes)                                │
│ aead_ct_len        (4 bytes)  = u32                          │
│ aead_ct            (var)      = AEAD ciphertext of block CBOR (§6.3) │
│ aead_tag           (16 bytes)                                │
│                                                              │
│ author_fingerprint (16 bytes)                                │
│ sig_ed_len         (2 bytes)  = u16, 64                      │
│ sig_ed             (64 bytes)                                │
│ sig_pq_len         (2 bytes)  = u16, 3309 (suite v1)         │
│ sig_pq             (var)                                     │
└──────────────────────────────────────────────────────────────┘
```

AEAD details:
- Key: *Block Content Key* (each recipient must unwrap their entry to recover this key)
- AAD: bytes from `magic` through the end of `recipient_entries`. Binds the entire header (including the recipient table) to the ciphertext.
- Plaintext: canonical CBOR per §6.3.

Signature details:
- Signed message: `"secretary-v1-block-sig" || (all bytes from magic through aead_tag inclusive)`
- Author identity verified via `author_fingerprint` lookup as in manifest.

### 6.2 Recipient entry layout (§7 of crypto-design — wire form)

Each recipient entry is exactly **1208 bytes**:

```
recipient_fingerprint (16)         ; short fingerprint of recipient's contact card
hybrid_kem_ct_x       (32)         ; X25519 ephemeral pubkey
hybrid_kem_ct_pq      (1088)       ; ML-KEM-768 ciphertext
wrap_nonce            (24)         ; XChaCha20 nonce for the wrap AEAD
wrap_ct               (32)         ; AEAD ciphertext of block_content_key (32-byte key)
wrap_tag              (16)         ; Poly1305 tag
```

`wrap_ct` and `wrap_tag` are concatenated on disk with no separator or length prefix; the row split above is purely presentational. A clean-room parser must read 48 contiguous bytes and treat the first 32 as ciphertext and the last 16 as the Poly1305 tag.

Recipients are listed in a stable order: ascending lexicographic by `recipient_fingerprint`. The owner's own entry is always first if their fingerprint sorts first; otherwise it is included in its sorted position. The owner is *always* a recipient — a block with no owner-recipient is rejected as malformed.

### 6.3 Block plaintext (CBOR inside `aead_ct`)

```cbor
{
  "block_version":   1,                  ; reserved for future incompatible block-body changes
  "block_uuid":      <bstr 16>,           ; must match the file header
  "block_name":      <tstr>,              ; user-visible label
  "schema_version":  1,                   ; record schema version
  "records": [
    {
      "record_uuid":     <bstr 16>,
      "record_type":     <tstr>,           ; "login" | "secure_note" | "api_key" | "ssh_key" | "custom"
      "fields":          { <fname>: { "value": <text or bstr>,
                                       "last_mod": <u64>,
                                       "device_uuid": <bstr 16> }, ... },
      "tags":            [<tstr>, ...],    ; optional cross-cutting labels
      "created_at_ms":   <u64>,
      "last_mod_ms":     <u64>,
      "tombstone":       <bool, optional>, ; absent or false = live; true = deleted
      "tombstoned_at_ms": <u64, optional>  ; absent or 0 = never tombstoned; otherwise the high-water mark of every tombstone observation on this record (see crypto-design §11)
    },
    ...
  ]
}
```

#### 6.3.1 Standard `record_type` values and expected `fields`

The `record_type` string is open (custom types allowed), but standard types have well-known field names so cross-platform clients render them consistently:

| `record_type` | Expected fields (all optional) |
|---|---|
| `login` | `username`, `password`, `url`, `notes`, `totp_seed` |
| `secure_note` | `title`, `body` |
| `api_key` | `service`, `key_id`, `key_secret`, `notes` |
| `ssh_key` | `name`, `public_key`, `private_key`, `passphrase`, `notes` |
| `custom` | any |

A field's `value` is `tstr` for human-readable values and `bstr` for binary values (e.g., a parsed TOTP seed). Clients displaying an unrecognized field name show the field as a generic key/value pair.

#### 6.3.2 Forward compatibility

Decoders preserve unknown record types and unknown field names on round-trip. A v1 client that receives a v2 record (some new record_type) stores the record verbatim and renders it as a generic record list; on save, the v2 record is re-emitted unchanged.

This applies to any CBOR field in the block body: unknown keys at any level are preserved verbatim. Canonical-CBOR-on-write means that a v1 client re-saving a v2 record produces *bit-identical* bytes for the unchanged portions, so the v2 client's signature on the original block is preserved if no semantic change was made.

(Note: any change *requiring* re-signing — adding/removing a recipient, modifying records — will rewrite the block under the v1 client's signature, possibly downgrading any v2-only metadata. v2 features that need v1-survival must be designed to tolerate this.)

### 6.4 Reading a block

```
1. Read the file-level header.
2. Locate own entry in recipient_entries by matching own short fingerprint.
3. Hybrid-decap own entry to recover block_content_key (crypto-design §7.1).
4. AEAD-decrypt aead_ct under block_content_key with the header AAD.
5. Verify aead_tag matches.
6. Look up author_fingerprint to obtain verification keys.
7. Hybrid-verify the block signature (sig_ed, sig_pq).
8. Parse plaintext as canonical CBOR.
9. Cross-check plaintext.block_uuid == header.block_uuid; reject on mismatch.
```

A block whose recipient table does not include the reading user is unreadable by them. The error is reported as "this block is not shared with you" — distinct from corruption.

### 6.5 Writing a block

```
1. Generate fresh block_content_key (32 random bytes).
2. Bump own counter in vector_clock.
3. Canonical-CBOR-encode the block body.
4. Generate aead_nonce; AEAD-encrypt to obtain aead_ct, aead_tag.
5. For each recipient (always including self), compute hybrid_kem wrap (crypto-design §7).
6. Order recipient_entries lexicographically by recipient_fingerprint.
7. Compute author_fingerprint.
8. Construct signed_message and produce sig_ed + sig_pq.
9. Write the file atomically (write to a temp file, fsync, rename).
10. Update the manifest's blocks[<this_block>] entry and re-sign the manifest.
```

Steps 9 and 10 must be atomic-as-a-pair from the user's perspective: a crash between writing the block and updating the manifest leaves the manifest pointing at an old block fingerprint, which surfaces on the next read as a typed fingerprint-mismatch error naming the block (a manifest-listed block whose file is *absent* surfaces as a typed missing-file error instead). Recovery is an explicit repair operation (`repair_vault` in the reference implementation) that the client offers to the user: it re-runs the §1 open sequence (same credentials, same verify-before-decrypt), then evaluates the §10 rollback check on the committed (pre-adoption) manifest clock — keyed by the **verified** manifest `vault_uuid`, never the plaintext `vault.toml` value, and strictly **before** any manifest write (after repair's own clock tick a strictly-dominated clock would read as concurrent and the rollback would be laundered permanently); because repair mutates the manifest, an *existing but unreadable* per-device §10 baseline store MUST fail the repair closed — as must an *indeterminate* one (a store whose existence cannot be proven either way, e.g. an inaccessible store directory) — while a *provably* absent / never-synced baseline skips the check (destroying the baseline store remains §10's documented explicit reset); then — per mismatched block, all-or-nothing — re-loads the on-disk block and adopts it into a re-signed manifest **only if** (a) the block file passes the full §6.4 read flow under the owner's card (Ed25519 ∧ ML-DSA-65, both halves), (b) its header `vault_uuid`/`block_uuid` match, and (c) a **two-tier clock-freshness rule** holds AND, on **either** tier, the file's recipient set **adds no recipient** absent from the committed entry. Refusing a recipient *widening* is cross-cutting — independent of the clock relation — because re-granting access must never be automatic, with one narrow, explicit exception detailed below (an exactly-matching informed-consent approval for the crashed-share shape only; consent never widens access automatically). Tier 1: the file's header vector clock **strictly dominates** the manifest entry's `vector_clock_summary` — the exact shape an interrupted §6.5 content write leaves (the write ticked the block clock and re-encrypted to the *existing* recipient set, so a legitimate residue's recipients equal the committed set; a strictly-dominating file that nonetheless *widens* the recipient set is not a legitimate crashed content write — it is a planted owner-signed copy carrying a pre-revocation recipient set whose block clock dominates a clock-invisible revoke — and is refused). Tier 2: the clocks are **equal** AND the file's recipient set is a **strict subset** of the committed entry's — the shape an interrupted §6.5.1 revocation leaves, since re-keys re-encrypt the same plaintext without ticking the block clock, meaning the only possible equal-clock delta is the recipient set and a subset can only narrow access (fail-closed: a planted retained owner-signed copy can at worst un-share a recipient, never re-grant one). Everything else is refused by default: a dominated clock (rollback plant), a dominating clock that nonetheless widens the recipient set (the planted-dominating-copy shape above) — refused unconditionally, never consent-eligible, because a legitimate re-key preserves the clock so a widening file that dominates cannot be a genuine crashed share — an equal-clock delta that both adds and removes recipients (no single crashed operation produces this shape), an equal-clock equal-set byte difference (forgery shape), and concurrent clocks (torn multi-device state repair must not guess about). The sole remaining shape — an **equal** clock with a **strict superset** recipient delta (adds only, no removals) — is the residue of an interrupted *widening* re-key (§6.5.1's re-key mechanism run in the sharing direction, adding a recipient), i.e. a crashed `share_block`. This residue MAY be adopted, but **only** through an explicit informed-consent path: the client first runs a read-only preview that renders, for every recipient who would gain access, a human-recognizable identity — display name and card fingerprint, both read from the verified contact card. Consent MUST be bound to both the BLAKE3-256 fingerprint of the exact on-disk block file previewed and the exact added-recipient set shown, and any mismatch between the approval and the file being adopted at repair time MUST refuse. Consent is also scoped in time: an approval is minted by one preview for the immediately-following repair invocation, and clients MUST NOT persist approvals across preview/repair cycles or sessions — the bind above covers the file bytes and the recipient delta but deliberately not the committed manifest state the delta was computed against, so a persisted approval replayed after an intervening revocation of the same recipient would exactly match a re-planted copy of the previously-approved file and re-grant access without fresh consent. Every other widening shape enumerated above MUST be refused regardless of consent. Absent an exactly-matching approval, the default MUST remain the fail-closed refusal described above. The all-or-nothing rule and the §10 pre-write fail-closed gate apply unchanged to the consent path, and a read-only preview of this path MUST apply the same fail-closed §10 baseline posture as the mutating repair. Wall-clock `last_mod_ms` values MUST NOT be used as a freshness discriminator (they carry no monotonicity guarantee). The adopted entry's `recipients` are rebuilt from the file's §6.2 table (so an interrupted §6.5.1 revocation repairs to the *reduced* recipient set), and its `vector_clock_summary` is taken verbatim from the file header. The missing-file case is **not** repairable — repair cannot invent block bytes; the probable cause is a torn cloud sync and the recovery is a completed sync. Conformance: `core/tests/crash_recovery.rs::repair_vault_adopts_interrupted_save` / `repair_vault_adopts_interrupted_revocation` / `repair_vault_rejects_rollback_plant` / `repair_vault_rejects_concurrent_clock_transplant` / `repair_rejects_backward_clock_share_replay` / `repair_rejects_crashed_share_superset` / `repair_rejects_dominating_clock_recipient_widening` / `repair_rejects_equal_set_different_bytes` / `repair_passes_verified_manifest_uuid_to_baseline_provider` / `repair_aborts_when_baseline_provider_errors` / `repair_adopts_crashed_share_with_matching_approval` / `repair_rejects_approval_with_stale_fingerprint` / `repair_rejects_approval_with_wrong_added_set` / `repair_approval_does_not_license_dominating_widening` / `repair_approval_does_not_license_mixed_delta` / `repair_all_or_nothing_with_partial_approvals` / `preview_reports_widening_with_names_and_fingerprints` / `preview_propagates_hard_rejections` pin this contract.

#### 6.5.1 Revocation (removing a recipient)

Revoking a recipient re-keys the block: a fresh `block_content_key` is generated, the block body is re-encrypted under it, and fresh §6.2 recipient entries are produced for the **remaining** recipients only. The revoked recipient's entry is absent from the new §6.2 recipient table, and the manifest `BlockEntry.recipients` drops the revoked contact UUID. The block is written first, then the manifest (§9), and both are re-signed (Ed25519 ∧ ML-DSA-65). The on-disk format is identical to a §6.5 write to a smaller recipient set — there is no new field and no `format_version` bump.

The block owner/author is **always** a recipient (the author must be able to decrypt the block to re-key it — see §6.2, which rejects an owner-less recipient table as malformed) and **cannot** be revoked; an attempt to do so is rejected. Consequently the recipient set is never empty — revoking the last *non-owner* recipient leaves the block owner-only.

The same re-key mechanism also runs in the **widening** direction — sharing the block to an additional recipient generates a fresh `block_content_key` and a §6.2 recipient table with one more entry; the on-disk format is again identical to a §6.5 write. A re-key — in either direction — re-encrypts the **unchanged** block body and **preserves the block-level vector clock**: the content lineage did not advance (cf. §7.1's restore, which preserves the clock for the same reason). This clock preservation is normative and load-bearing: the §6.5 repair contract's equal-clock tier is sound only because an equal clock implies an identical plaintext, leaving the recipient set as the only possible delta. A writer that mutates the block body MUST tick the block's vector clock (§6.5 step 2). If this widening re-key is interrupted by a crash, the residue (equal clock, strict recipient superset) is refused by default under the §6.5 repair contract; it is never adopted automatically, but MAY be adopted through the §6.5 informed-consent path, which requires a bytes-and-delta-bound approval rather than inferring anything from the clock alone.

**Forward-secrecy boundary.** Revocation protects only block-versions written *after* it. The revoked party may retain plaintext it already decrypted and the prior `block_content_key` it already unwrapped; nothing in this format makes those unrecoverable. A conforming reader holding only the *new* on-disk bytes cannot decrypt as the revoked recipient — no §6.2 entry exists for them under the new `block_content_key`.

Conformance: `revoke_kat::after_block_rekeyed` (`core/tests/python/conformance.py`, clean-room — generic crypto primitives via PEP 723, no dependency on `secretary-core`) and `core/tests/revoke_block.rs::revoke_block_round_trip` / `core/tests/revoke_block.rs::revoke_block_non_recipient_rejected` / `core/tests/revoke_block.rs::revoke_block_owner_rejected` pin this re-key behavior. The Rust always-run guard `core/tests/revoke_kat.rs::revoke_kat_after_block_matches_inputs` and the conformance section both verify, from the committed `core/tests/data/revoke_kat/` fixture alone, that the revoked recipient's §6.2 wrap is gone, the remaining recipient decaps the new `block_content_key` and recovers the expected plaintext, and the body ciphertext changed (a real re-key, not just a table edit).

---

## 7. Tombstones and deletion

Deleting a block:

1. Add an entry to `manifest.trash`: `{block_uuid, tombstoned_at_ms, tombstoned_by, fingerprint}`, where `fingerprint` is the BLAKE3-256 of the (unchanged) block file bytes — i.e. the `BlockEntry.fingerprint` of the block being trashed. This is the content commitment §7.1 verifies on restore.
2. Remove the block's entry from `manifest.blocks`.
3. Re-sign and atomically write the manifest. **This write is the deletion's commit point**: from here the block is trashed regardless of what happens to the physical file.
4. Best-effort: move `blocks/<block-uuid>.cbor.enc` → `trash/<block-uuid>.cbor.enc.<unix-millis>`. A failure here (crash, cross-filesystem `EXDEV`, permissions) does **not** un-trash the block: the file remains in `blocks/` as a benign orphan that readers ignore (it is no longer manifest-listed), that §7.1 restore treats as its resume source, and that the open-time sweep (below) relocates once the move becomes possible.
5. After a retention window (default 90 days), `trash/` files older than the window are physically removed.

**Open-time completion sweep.** On each successful open, for every `manifest.trash` entry carrying a `fingerprint` whose expected `trash/` file is absent: if the `block_uuid` is not live in `manifest.blocks` and `blocks/<block-uuid>.cbor.enc` exists with bytes hashing to the signed `fingerprint`, the reader renames it to its step-4 trash path. The sweep is rename-only (no manifest change, no re-signing), idempotent, and best-effort; because the gate is the *signed* content commitment, a planted `blocks/` file cannot steer it. Conformance: `core/tests/crash_recovery.rs::open_vault_sweep_relocates_interrupted_trash` / `sweep_skips_orphan_with_wrong_fingerprint` / `sweep_skips_live_uuid` / `sweep_skips_legacy_entry_without_fingerprint`.

The tombstone entry in the manifest must persist for at least the retention window so that all syncing devices have a chance to observe the deletion.

The trash filename grammar is `<block-uuid-hyphenated>.cbor.enc.<unix-millis>` where `<unix-millis>` is the decimal ASCII representation of the deletion's `tombstoned_at_ms` (matches the manifest's `TrashEntry.tombstoned_at_ms`). Multiple files matching `<block-uuid-hyphenated>.cbor.enc.*` may co-exist when the same `block_uuid` is trashed → restored → re-trashed within the retention window. The filename is the canonical record of when a particular trashing happened; the manifest's `TrashEntry` carries the **most recent** `tombstoned_at_ms` only (older tombstone times are not tracked in the manifest).

The move in step 4 is `rename(2)` semantics — atomic on a single filesystem. On a cross-filesystem configuration (e.g., `blocks/` and `trash/` span a cloud-folder mount-point and a local filesystem) the move fails with `EXDEV`; the deletion still commits at step 3, and the physical move stays pending — the orphan is swept once the vault is re-located to a single filesystem.

### 7.1 Restoring a block

Restoring a block reverses the §7 deletion sequence. The trash retention window (default 90 days) makes restore meaningful: until physical purge, the encrypted block file is still on disk in `trash/`.

**Preconditions:**

- The `block_uuid` MUST have a corresponding `TrashEntry` in `manifest.trash` AND at least one file in `trash/` matching `<block-uuid>.cbor.enc.*`. A disagreement between the two (file without manifest entry, or vice versa) is an integrity failure and surfaces as a typed error.
- The `block_uuid` MUST NOT appear in `manifest.blocks`. A live-and-trashed UUID cannot be restored — the caller must first trash the live copy.

**Sequence:**

1. Scan `trash/` for files matching `<block-uuid>.cbor.enc.*`. Parse each suffix as a u64 of decimal unix millis in **canonical** form (no leading `+`, no leading zeros except for `0` itself — i.e., `suffix == u64::to_string()`). Files whose suffix is non-numeric, overflowing u64, or non-canonical (`007`, `+7`, etc.) are **skipped** during the scan: such files cannot be the trusted record of when this `block_uuid` was trashed, but their presence — likely cruft from a buggy peer client or filesystem noise on a shared sync folder — must not wedge restore for legitimate alongside files. Correctness is still gated by the §6.1 hybrid verify in step 3 on the file whose suffix equals the signed `TrashEntry.tombstoned_at_ms` (selected in step 2).
2. Pick the file whose suffix **equals** the manifest's signed `TrashEntry.tombstoned_at_ms` as the *restore target*. All other matching files (older stale copies **and** any larger-suffix copies) are *purge targets*. The authentic-current trashed file's suffix equals the signed `tombstoned_at_ms` by construction (§7 writes the file and the `TrashEntry` together). The largest-suffix file is **not** trusted: the suffix is unauthenticated filename metadata that a malicious sync-folder host can forge, so binding selection to the signed timestamp is what prevents an attacker-planted larger-suffix copy from being restored as authentic-but-stale content. If **no** file's suffix equals the signed `tombstoned_at_ms`, restore **fails** — the authentic-current trashed file is missing (removed or renamed) and only stale or planted copies remain. (Equality, not `>=`: the manifest carries only the most-recent `tombstoned_at_ms`, so a multi-cycle trash→restore→re-trash history with the legitimate copy purged could otherwise mis-select an older or planted file.)
3. Read the restore-target's bytes. Decode + AEAD-decrypt + §6.1 hybrid-verify (Ed25519 ∧ ML-DSA-65; **both** halves must verify) the file against the owner's contact-card pubkeys. Failure halts restore — the manifest is NOT modified and `trash/` is NOT modified.
3a. **Content-commitment check (rollback-freshness binding) — executed *before* step 3's decode/AEAD-decrypt, as a fail-fast guard (numbered 3a for cross-reference continuity; in execution it precedes the decode and hybrid-verify, so a stale-content overwrite surfaces as the content-commitment mismatch below rather than a decode/verify error).** If the matching `TrashEntry` carries a `fingerprint` (present for blocks trashed by this version or later), compute the BLAKE3-256 of the restore-target's bytes and require it to equal `TrashEntry.fingerprint`. A mismatch halts restore as an integrity failure (typed `RestoreVerificationFailed`) — the manifest and `trash/` are NOT modified. This binds the restored content's *freshness* to the signed manifest: §6.1 hybrid-verify proves *authenticity* (the bytes were genuinely owner-signed) but not *currency*, so without this step an attacker with write access to `trash/` could overwrite the suffix-matching file in place with a previously-retained, genuinely owner-signed *older* copy and roll the block back (e.g. a rotated password reverts). If the `TrashEntry` has no `fingerprint` (a legacy entry written before this commitment existed), this step is skipped and restore proceeds on the suffix-equality (step 2) + hybrid-verify (step 3) bindings alone — the residual rollback exposure is limited to blocks trashed by an older client and is documented in the threat model. An attacker cannot *induce* the legacy path: `TrashEntry` is inside the signed manifest, so stripping the `fingerprint` invalidates the signature and restore is never reached.
4. Map each `recipient_fingerprint` in the decrypted block file's §6.2 recipient table to a `contact_uuid` by: (a) matching against the owner card's fingerprint (already in memory), and (b) for any unmatched fingerprint, scanning `contacts/*.card`, decoding each card, **verifying its embedded Ed25519 ∧ ML-DSA-65 self-signature** (cards that fail self-verify are skipped — they cannot be trusted to mint a `contact_uuid`), and computing the verified card's fingerprint until a match is found. Any unresolved fingerprint halts restore — the trash file and manifest are still untouched at this point.
5. `rename(2)` the restore target to `blocks/<block-uuid>.cbor.enc`. Atomic per §9.
6. Physically remove every purge target via `fs::remove_file`. Best-effort: individual failures here are swallowed — the block is already live; a leftover older copy is only a retention-window cleanup item.
7. Build the `BlockEntry` from the decrypted block file:
    - `block_uuid`, `block_name` (from plaintext), `suite_id`, `created_at_ms`, and `vector_clock_summary` from the file's §6.1 header. **Block-level vector clock is preserved verbatim** — restore does not tick the per-block clock because the block's *content* did not change.
    - `fingerprint` = BLAKE3-256 of the restored file's bytes (matches the bytes that just passed verification; `rename(2)` is a move, not a rewrite).
    - `recipients` = the resolved `contact_uuid`s from step 4.
    - `last_mod_ms` = now (the restoring write's wall-clock).
8. Append the new `BlockEntry` to `manifest.blocks`; remove the matching `TrashEntry` from `manifest.trash`.
9. Tick the manifest-level vector clock for the restoring `device_uuid` (the manifest *did* change — its block set moved).
10. Re-sign the manifest with a fresh AEAD nonce; atomic-write per §9.

Atomic-write ordering mirrors §9: file move first (step 5), manifest write second (step 10). A crash between leaves the block live-on-disk but absent from the manifest — recoverable on next open by re-attempting the restore.

Restore preserves the block-level vector clock so that a sync of the restored block to another device is treated as a continuation, not a fork: the receiving device will see a block with the same `block_uuid` and a `vector_clock_summary` greater-or-equal to what it last observed, and will merge accordingly.

Deleting a record (within a block) sets `tombstone: true` on the record, updates `last_mod_ms`, and sets `tombstoned_at_ms = last_mod_ms`. The record's `fields` may be cleared on tombstoning (recommended) or kept for undelete; a tombstoned record is invisible to UI but its presence prevents resurrection on merge from a device that hadn't seen the deletion.

`tombstoned_at_ms` is the high-water mark of every tombstone observation this record has been part of. It is preserved (not reset) across merges and across resurrection: a record that was tombstoned at T1 and later resurrected by a live edit at T2 > T1 carries `tombstone = false`, `last_mod_ms = T2`, `tombstoned_at_ms = T1`. The merge primitive uses this field to drop fields whose `last_mod` is at or below the death-clock — see crypto-design §11.3 for the staleness filter that keeps merge associative under arbitrary tombstone histories.

### 7.2 Purging a block

Purge is a distinct, explicit user-initiated operation from trashing (§7) and restoring (§7.1): it permanently removes a trashed block's local ciphertext. There is no separate purge-time secret to destroy — a block's plaintext is recoverable only via its per-block **Block Content Key (BCK)**, and the BCK exists *only* wrapped per-recipient inside the block file itself (§6.2). Consequently:

- For an **owner-only** block (the §6.2 recipient table names only the owner), removing the local `trash/` ciphertext *is* the crypto-shred: once the file is gone, no key store or fallback exists from which the owner could re-derive the BCK.
- For a **shared/synced** block, any recipient holding their own copy of the ciphertext can still decrypt it independently. Purge cannot reach those copies — purging a shared block is **local cleanup only**, never a global "unshare" or "forget."

**One erasure mechanism, honestly described.** Purge does exactly one thing to the file bytes: `fs::remove_file` (unlink). There is no overwrite pass. This is deliberate, not an oversight: overwrite-then-unlink is not a reliable erasure guarantee on modern storage — SSD wear-leveling remaps writes instead of updating in place, copy-on-write/journaling filesystems (btrfs, APFS, ZFS) retain the old extent until garbage collection, and a filesystem snapshot or backup taken before the purge retains the original bytes regardless of what happens to the live copy. A conforming implementation MUST NOT claim that purge is a secure-overwrite / forensic-erase operation; its only guarantee is: (a) the local live-filesystem path to the plaintext is severed, and (b), for an owner-only block, that severing is what removes the last copy of the wrapped BCK anywhere the owner controls, which is the load-bearing property that actually renders the plaintext unrecoverable going forward.

**Owner-only vs. shared classification is reporting-only.** Before marking a block purged, the implementation MAY read the current trash file's §6.2 recipient table and classify it as `owner-only` or `shared` (with a recipient count) purely to inform the user honestly ("this was never shared" vs. "N other people may still hold a readable copy"). This classification never gates whether the purge proceeds — there is exactly one purge code path regardless of the outcome. If the file is already absent or fails to decode at classification time (crash residue, a prior partial purge), classification is reported as unknown rather than fabricated as `false`/`0`.

**`purge_block(block_uuid)` sequence** (manifest-first, mirroring §7 step 3's discipline, but inverted: mark unrestorable *before* removing bytes, so the manifest never advertises a restorable block whose file is mid-deletion):

**Preconditions:**

- `block_uuid` MUST have a `TrashEntry` in `manifest.trash`, else the operation fails (no signed record that this block was ever trashed).
- If that `TrashEntry` is already purged (`purged_at_ms` already `Some`), purge is an **idempotent no-op success**: the manifest is not re-signed; only a best-effort cleanup of any residual file runs. Re-purging a block must never fail.

**Sequence** (skipped when the idempotent case above applies):

1. Locate the current trash file for `block_uuid` (the file whose suffix equals the signed `tombstoned_at_ms`, per §7.1 step 2) and classify its §6.2 recipient table as above. Best-effort; a read/decode failure yields an unknown classification and does not block the purge.
2. Stage a manifest clone with `TrashEntry.purged_at_ms` set to the current unix-millis time; tick the vault-level vector clock; re-sign and atomically write the manifest. **This write is the commit point.** From here the block is purged regardless of what happens to the physical file below.
3. Best-effort: `fs::remove_file` every `trash/<block-uuid>.cbor.enc.*` copy matching this `block_uuid` (the current trashed copy and any stale crash-residue siblings). This step is unlink-only and performs **no** runtime manifest-liveness check — its safety rests entirely on the by-construction invariant established at step 1: the target is a `TrashEntry`, and a `TrashEntry`'s `block_uuid` is never simultaneously live in `manifest.blocks` (the two lists are mutually exclusive), so deleting its `trash/` files can never orphan a live block. (A runtime "not live in `manifest.blocks`" gate is required, and present, only in the open-time purge-cleanup sweep below — which runs against a possibly-merged manifest in which a concurrent restore may have re-made the UUID live — not here.) Individual file-removal failures are logged and tolerated: a crash between step 2 and step 3 leaves a purged-marked entry with a lingering file, which is a benign orphan — restore already refuses it via the marker (below), and the open-time purge-cleanup sweep removes the leftover file on a later open.

**`empty_trash()` — bulk purge.** Collects every `TrashEntry` with `purged_at_ms` absent and `block_uuid` not live in `manifest.blocks`, classifies each (best-effort, as above; an unreadable target does not abort the batch), then performs **one** manifest write for the whole batch: all collected entries are marked purged with a single shared timestamp, the vector clock is ticked once, and the manifest is re-signed and written once — not once per entry. Only after that single write succeeds does best-effort file removal run across every purged entry; a per-file failure never aborts the batch. An empty target set (nothing eligible to purge) returns without touching the manifest at all — no clock tick, no re-sign, no write.

**Restore interaction.** §7.1 restore gains a fail-fast precondition, checked *before* any `trash/` directory scan: if the matching `TrashEntry.purged_at_ms` is `Some`, restore fails immediately with a dedicated purged-block error, distinct from "not in trash at all" (no signed record) and from a restore-verification failure (an integrity problem with an otherwise-restorable file) — here the content is intentionally and permanently gone. Because `TrashEntry` lives inside the signed manifest body, an attacker cannot strip the purged marker without invalidating the manifest signature.

**Open-time purge-cleanup sweep.** On each successful open, for every `TrashEntry` with `purged_at_ms` set whose local `trash/` file(s) still exist **and** whose `block_uuid` is not live in `manifest.blocks`, the reader deletes the file(s) — best-effort, rename-free, no manifest mutation, no re-signing. This mirrors the §7 open-time relocation sweep's "not live in `manifest.blocks`" gate exactly, and that gate is what makes a concurrent restore win safely: if, concurrent with a purge on one device, another device restored the same block (removing the `TrashEntry`, adding a live `BlockEntry`), the merged manifest resolves liveness by the ordinary trash/restore and block-vector-clock rules — purge adds nothing to that decision — and the sweep, seeing the UUID live, leaves its file untouched. The sweep is also the mechanism that propagates a purge across the owner's own devices in the common single-writer case: the signed manifest is the synced artifact, so once one device's `purged_at_ms` write reaches another device via the ordinary manifest file sync, that device's own next open runs this sweep and converges to the purged state locally — no separate purge-propagation protocol exists or is needed.

The open-time purge sweep removes, for every purged `TrashEntry` whose `block_uuid` is **not live** in `blocks`, both the `trash/<uuid>.cbor.enc.*` residue and the `blocks/<uuid>.cbor.enc` residue. A `blocks/` residue arises only from a conflict-copy merge in which a concurrent restore on the merging device left the block file under `blocks/` after purge won at the manifest level (crypto-design §11.6); removing it completes the purge on that device. The sweep runs only after the manifest signature is verified, so a forged purge marker can never drive a deletion, and the "not live in `blocks`" gate means a restore that legitimately won is never touched.

**Documented limitation — conflict-copy trash-list merge-monotonicity.** The concurrent-write conflict-copy merge path does not reconcile trash lists at all today (a pre-existing gap that predates purge — plain, unpurged tombstones do not merge across conflict copies either), so a purged marker is not guaranteed to survive a manifest merge performed across a conflict copy. This is a **durability** gap, not a security hole: dropping a purged marker across that specific merge path at worst means the purge did not stick for that one device pairing — no plaintext or key is exposed to anyone who did not already hold a copy. Reconciling trash-list merge semantics (a purged-if-either-side-is, max-timestamp rule) is deferred to a follow-up.

Conformance: `core/tests/purge.rs::purge_owner_only_block_reports_not_shared_and_removes_file` / `purge_shared_block_reports_shared_and_count` / `purge_unknown_uuid_is_block_not_in_trash` / `re_purge_is_idempotent_no_second_resign` / `restore_of_purged_block_returns_block_purged` / `open_vault_sweep_removes_purged_file_when_not_live` / `open_vault_sweep_keeps_purged_file_when_uuid_is_live` / `open_vault_sweep_keeps_non_purged_trash_file` / `empty_trash_purges_all_unpurged_in_single_resign` / `empty_trash_on_empty_target_set_is_noop_no_resign`.

---

## 8. Sharing export bytes

The shared-block file is byte-identical to a regular block file (§6). The only difference is operational: it lives in a folder accessible to the recipient rather than in the sender's `blocks/`. The recipient's client validates the file on import using the standard read flow (§6.4) and, on success, copies it into their own `blocks/`.

If the recipient already has a block with the same `block_uuid`, the import is treated as a sync conflict: the recipient sees a UI flow asking whether to merge, replace, or import-as-copy (with a new UUID).

The vault_uuid in the file header tells the recipient where the block originated; if they already have an active relationship with the source vault (rare in v1; relevant in future "linked vaults" features), the import can be flagged accordingly.

---

## 9. Atomic-write discipline

All file writes in the vault MUST be performed atomically: write to `<filename>.tmp.<random>`, `fsync`, then `rename` over the target. This is required because:

- Cloud-folder hosts can observe partial writes; an incomplete file might be synced before a complete one and re-distributed in that state.
- Crashes mid-write must not leave the vault in an unreadable state.

When a block file and the manifest change together, the ordering rule is: **never persist a manifest state that references block bytes that are not on disk.** For content writes (§6.5) that means block first, manifest second — a crash leaves a fresh orphan or a stale-fingerprint entry, both detectable and recoverable (§6.5 repair). For deletion (§7) it means manifest first, move second — the same write that commits the trash removes the block's entry, so the manifest never points at the moved-away file; a crash leaves only an unlisted orphan (§7 sweep). The reverse orderings would leave the manifest pointing at a non-existent or wrong-fingerprint block with no recovery gate.

---

## 10. Format-version transition

When `format_version` advances to 2:

- `vault.toml` advances its `format_version` field. Old (v1) clients see `format_version = 2` and refuse to operate.
- The owner explicitly initiates migration; the migration is offline (no other devices may write during it).
- All blocks may be re-encrypted in place under the new format, or left under their existing `suite_id` and only the manifest format upgraded — both are valid migration strategies.
- The manifest signature is re-computed under the new format.

A vault whose `format_version` exceeds what a client supports is rejected with "this vault is from a newer Secretary version; please update."

---

## 11. Conformance checklist for a clean-room implementation

A new implementation is conformant if it can:

1. Read and write `vault.toml` with the v1 schema, preserving unknown top-level keys on round-trip.
2. Generate v1 Argon2id parameters and produce a `master_kek` matching the published KAT.
3. Generate a 24-word BIP-39 recovery mnemonic, derive `recovery_kek` via HKDF, match the KAT.
4. Generate, sign, and verify a v1 Identity Bundle file matching the layout in §3.
5. Generate, sign, encrypt, decrypt, and verify a v1 Manifest file matching §4.
6. Generate, parse, fingerprint, and verify a v1 Contact Card matching crypto-design §6.
7. Generate, sign, encrypt, decrypt, and verify a v1 Block file matching §6 and crypto-design §9.
8. Perform v1 Hybrid KEM wrap and decap matching crypto-design §7 and the published KAT.
9. Perform v1 Hybrid Signature sign and verify matching crypto-design §8 and the published KAT.
10. Implement the manifest rollback / merge logic from crypto-design §10.
11. Implement field-level CRDT merge from crypto-design §11.
12. Decrypt the `golden_vault_001/` reference vault using only the published password and recovery mnemonic.

The Python conformance script (`core/tests/python/conformance.py`) automates checks 1–9, 11, and 12 for the reference Rust implementation. A new implementation can be validated by porting that script's assertions or by writing a similar one that targets the new codebase.
