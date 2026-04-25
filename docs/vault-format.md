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
│ sig_pq_len         (2 bytes)  = u16                          │
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
      "tombstoned_by":  <bstr 16>                  ; device_uuid that performed the deletion
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
│ sig_pq_len         (2 bytes)                                 │
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
      "tombstone":       <bool, optional>  ; absent or false = live; true = deleted
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

Steps 9 and 10 must be atomic-as-a-pair from the user's perspective: a crash between writing the block and updating the manifest leaves the manifest pointing at an old block fingerprint (which fails verification on next read). The recovery path is: detect the inconsistency on next read, re-load the block, re-fingerprint, and offer to update the manifest.

---

## 7. Tombstones and deletion

Deleting a block:

1. Move `blocks/<block-uuid>.cbor.enc` → `trash/<block-uuid>.cbor.enc.<unix-millis>`.
2. Add an entry to `manifest.trash`: `{block_uuid, tombstoned_at_ms, tombstoned_by}`.
3. Remove the block's entry from `manifest.blocks`.
4. Re-sign the manifest.
5. After a retention window (default 90 days), `trash/` files older than the window are physically removed.

The tombstone entry in the manifest must persist for at least the retention window so that all syncing devices have a chance to observe the deletion.

Deleting a record (within a block) sets `tombstone: true` on the record and updates `last_mod_ms`. The record's `fields` may be cleared on tombstoning (recommended) or kept for undelete; a tombstoned record is invisible to UI but its presence prevents resurrection on merge from a device that hadn't seen the deletion.

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

When updating a block and the manifest together, the order is: write block first (atomically), then update manifest (atomically). A crash between the two leaves the block inconsistent with the manifest, which is detectable and recoverable. The reverse order would leave the manifest pointing at a non-existent block.

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
