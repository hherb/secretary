# Secretary Threat Model

This document enumerates the adversaries Secretary defends against, the attacks each can attempt, the defenses applied, and — equally important — the threats that are explicitly *out of scope*. Every defense listed here maps to a concrete mechanism in [crypto-design.md](crypto-design.md) and [vault-format.md](vault-format.md). When those documents change, this one must be re-read for consistency.

---

## 1. Assets

The things being protected, in order of importance:

| Asset | Description |
|---|---|
| Record fields | Username, password, API key, secret note, etc. The actual secrets the user entrusts to Secretary. |
| Identity secret keys | The four secret keys (X25519, ML-KEM-768, Ed25519, ML-DSA-65) that authenticate the user to other Secretary users and decrypt incoming shares. |
| Master password / recovery mnemonic | The two credentials the user holds outside Secretary, capable of unwrapping the Identity Block Key. |
| Vault metadata | Block names, record counts, recipient lists, contact display names, last-modified timestamps. Secondarily sensitive — could enable targeted social engineering. |
| Authenticity | The guarantee that records and shared blocks were written by the claimed author and have not been altered. |

## 2. Adversaries

### 2.1 Cloud-folder host (in scope, primary)
The operator of the user's cloud-folder service (Dropbox, Google Drive, iCloud, OneDrive, WebDAV server) or anyone with read/write access to the synced folder. Capabilities:
- Read every byte of every file in the folder, present and historical.
- Replace files with arbitrary content, including older valid versions.
- Delete files.
- Observe access patterns (which files are read, when, by which client IP).

### 2.2 Network observer (in scope)
Anyone with passive or active access to the link between the user's device and the cloud-folder host. In practice their attacks reduce to a subset of (2.1) for our purposes, since cloud sync is over TLS but the cloud-folder host sees plaintext bytes. Defenses against (2.1) cover this adversary.

### 2.3 Possessor of a locked device (in scope)
An attacker who has physical possession of one of the user's devices in its locked state — e.g., a stolen laptop. Capabilities:
- Read all on-disk files including the vault folder.
- Attempt offline brute-force of the master password.
- Cannot defeat OS keystore encryption without OS-level compromise (out of scope at 2.7).

### 2.4 Future quantum adversary, "harvest now, decrypt later" (in scope)
An adversary who copies ciphertext today and possesses a sufficiently large quantum computer at some future date (10–50 years). Capabilities:
- Run Shor's algorithm against captured X25519 ciphertexts and Ed25519 signatures.
- Run Grover's algorithm against symmetric ciphertexts (effective halving of key strength).

This is an unusually important adversary for Secretary because the canonical use case (parent shares blocks for a child to decrypt decades later) gives ciphertexts a 30+ year lifespan. A static blob written today must remain confidential and authentic against the technology of 2055.

### 2.5 Malicious or compromised contact, MITM on share (in scope)
A third party who attempts to substitute their own *Contact Card* for a legitimate user's, hoping that Alice will share a block to the attacker thinking they are Bob. Possibilities:
- Cloud-folder host inserts a fake card into a folder and hopes Alice imports it.
- Email/messaging channel used to deliver a card is compromised in transit.

### 2.6 Format / protocol downgrade attacker (in scope)
An adversary attempting to coerce a client into using an older, weaker version of the format or cipher suite, hoping to exploit weaknesses fixed in newer versions.

### 2.7 Out of scope
Secretary does *not* claim to defend against:

- **Kernel, firmware, or hardware compromise** of the user's device — including evil-maid attacks against an unlocked-and-unattended device, malicious USB peripherals, physical RAM extraction. The OS and hardware are part of the trusted computing base.
- **Active malware on an unlocked device** — once Secretary has decrypted secrets into process memory, a sufficiently privileged attacker can read them. The `zeroize` discipline reduces but does not eliminate the window.
- **Coercion of the user** — rubber-hose attacks. There is no plausible deniability mechanism in v1.
- **Compromise of build / supply chain** — a malicious crate or compromised release tooling could exfiltrate keys at compile or install time. Mitigations are reproducible builds, signed releases, and dependency review, but full supply-chain integrity is an industry-wide unsolved problem.
- **Side-channels on the user's hardware** — power analysis, EM emanations, acoustic, thermal. Secretary uses constant-time implementations where the underlying crates provide them, but does not test against side-channel adversaries.
- **Denial of service** — an adversary who deletes the cloud-folder copy or corrupts every file is a DoS adversary, not a confidentiality adversary. The user is responsible for their own backups; Secretary's job is to ensure that if a backup is restored, it is authentic and current (or detectably stale).
- **Anonymity / metadata privacy from the cloud-folder host** — the cloud-folder host knows the user has a Secretary vault, knows roughly how many blocks are in it, knows which blocks change when, and knows how often the user accesses the vault. Defending against traffic analysis is out of scope.
- **Pre-quantum cryptanalysis breakthrough on classical curves alone** — addressed by the post-quantum hybrid; if classical fails, the PQ component still protects.

---

## 3. Defense matrix

For each adversary above, the table below lists the attack and the specific defense mechanism. References to byte-level details point to [vault-format.md](vault-format.md); references to algorithm choices point to [crypto-design.md](crypto-design.md).

### 3.1 Cloud-folder host

| Attack | Defense |
|---|---|
| Read record contents | Per-block AEAD encryption (XChaCha20-Poly1305) with a fresh *Block Content Key*. The cloud host sees only ciphertext. |
| Read block names / metadata | The *Manifest* is itself AEAD-encrypted under the *Identity Block Key*. Block names live inside the encrypted manifest, not in filenames. |
| Read identity public keys directly | Identity public keys live only in *Contact Cards*, which the user controls. The vault folder contains only the (encrypted) Identity Bundle, not standalone copies of the public keys. (Note: file count and approximate sizes still leak; see §2.7.) |
| Tamper with a block (modify ciphertext) | XChaCha20-Poly1305 MAC tag on each block. The hybrid signature on the manifest covers a BLAKE3 fingerprint of every block file; tampering with a block invalidates both the block's MAC and the manifest signature on next read. |
| Add a fake block file | Manifest enumerates legitimate blocks by UUID and fingerprint. Files in `blocks/` not present in the manifest are ignored. Manifest is hybrid-signed. |
| Remove a block file | Manifest detects the missing entry on read. The user is alerted; manual restore from backup is the recovery path. |
| Substitute an older valid block file (rollback at block level) | Per-block fingerprint in the signed manifest binds the manifest's view of the block to specific bytes. An older block's bytes have an older fingerprint; manifest signature fails. |
| Substitute an older valid manifest (rollback at manifest level) | Each device maintains an OS-local "highest vector clock seen" per vault. A manifest whose vector clock is component-wise dominated by the highest-seen state is rejected. Concurrent (incomparable) manifests trigger merge rather than rejection. |
| Replay an old shared block in a shared folder | Shared blocks carry a vector clock; recipient compares against the highest version of that block they have ever processed and rejects strict regressions. |

### 3.2 Possessor of a locked device

| Attack | Defense |
|---|---|
| Read vault files directly | Files are encrypted at rest; the master password is required (or recovery mnemonic). |
| Brute-force the master password | Argon2id with m=256 MiB, t=3, p=1 makes each guess expensive in both time and memory. The work factor is calibrated so a consumer-GPU brute force is far slower than online password reset would be. |
| Extract a cached identity key from OS keystore | The OS keystore caches only the *Identity Block Key*, not the master password. The keystore entry is gated by biometric or hardware token (per platform). Defeating this requires OS-level compromise, which is out of scope. |
| Swap files between two of the user's vaults | Each vault has a unique `vault_uuid` recorded in cleartext metadata (`vault.toml`) and reflected in the encrypted manifest. Mismatched UUIDs are rejected. |

### 3.3 Future quantum adversary

| Attack | Defense |
|---|---|
| Decrypt harvested *hybrid KEM* ciphertext (used for recipient wraps) | Hybrid construction: shared secret = HKDF-SHA-256 of (X25519 shared secret ‖ ML-KEM-768 shared secret ‖ both ciphertexts ‖ both public keys). Breaking confidentiality requires breaking *both* X25519 and ML-KEM-768. |
| Decrypt harvested AEAD ciphertext (block bodies, identity bundle, manifest) | XChaCha20-Poly1305 with a 256-bit key. Grover's algorithm reduces effective security to ~128 bits — well above the 80-bit "comfortable" threshold for long-term secrets. |
| Forge a hybrid signature | Hybrid: Ed25519 ∧ ML-DSA-65. Both signatures must verify; forging requires breaking both. |
| Forge a *Contact Card* | A card carries both an Ed25519 self-signature and an ML-DSA-65 self-signature over its contents. The card's public-key set includes both classical and PQ verification keys. |
| Brute-force Argon2id (KDF) | Argon2id is memory-hard; quantum speedup against memory-hard functions is limited. The 256-MiB memory parameter caps achievable parallelism. (KDFs are not the dominant quantum threat anyway — symmetric and asymmetric primitives are.) |

### 3.4 MITM on contact cards

| Attack | Defense |
|---|---|
| Cloud-folder host inserts a fake card | Cards are *not* auto-discovered from shared folders. The Rust core exposes only `ContactCard::from_canonical_cbor` + `ContactCard::verify_self` — there is no "load card from shared-folder path" function in the public API. The platform UI (Sub-project D) is responsible for ensuring import is always an explicit user action via QR (in-person), file, or paste. |
| Email/messaging channel substitutes a card | The Rust core verifies the card's hybrid self-signature (`ContactCard::verify_self` enforces both Ed25519 and ML-DSA-65) and exposes the 12-word BIP-39-style fingerprint mnemonic (`fingerprint::mnemonic_form`) for OOB comparison via a different channel (phone call, in-person). The "verification state `unverified`" / "prominent UI warning" workflow is a Sub-project D (platform UI) concern; v1 Rust core does not persist trust state. |
| Long-term key compromise of a contact | Cards are not auto-rotating in v1. The Rust core's role is to verify self-signatures and produce fingerprint mnemonics; the contact-removal flow and "re-verified card required for future shares" policy are Sub-project D workflows. Already-shared blocks remain readable to the compromised key — no v1 forward secrecy at the block level (see §4). |

### 3.5 Format / protocol downgrade

| Attack | Defense |
|---|---|
| Substitute an older format version's manifest | `format_version` and `suite_id` are inside the signed manifest. A v1 client refuses to load a manifest claiming `format_version != 1` (errors as `ManifestError::UnsupportedFormatVersion`). Same applies at the block level: `BlockError::UnsupportedFormatVersion` rejects any non-v1 block on parse. Future v2 clients reading a v1 vault upgrade explicitly. |
| Mix-and-match suite IDs across blocks within a vault | **Not supported in v1.** Both the manifest and block decoders reject any `suite_id != 0x0001` at parse time (`ManifestError::UnsupportedSuiteId` / `BlockError::UnsupportedSuiteId`); a vault file with a heterogeneous suite-ID set will fail to open before any cryptographic operation runs. The on-wire `suite_id` field exists to enable per-block migration in a future format-version transition; until v2 introduces a second suite, the "weakest link" attack surface is empty. |

---

## 4. Known limitations of v1 (acknowledged tradeoffs, not bugs)

These are deliberate scope decisions. Each is reasonable for v1 but worth eyes-open acknowledgement.

1. **No forward secrecy at the record level.** A compromised current Identity Block Key decrypts all current and prior block content keys (which are wrapped under the recipient's identity, not under ephemeral keys). Mitigation: this is the standard model for a password manager (you don't want to lose access to old data on key rotation); compensating control is keeping the Identity Block Key in OS keystore + master password.

2. **No revocation of already-shared blocks.** Once Bob has the *Block Content Key* for a block (by virtue of the cloud-folder copy he has fetched), Alice cannot un-give him access to that block's current content. Alice can rotate the block's content key and not include Bob's wrap in the rotated version, but Bob's local copy of the prior content remains decryptable to him. This is mathematically inherent for a no-server design and matches the user's sharing intent.

3. **No defense against the cloud-folder host equivocating between two of the user's own devices.** If the cloud host serves device A a different manifest than device B, both might be valid (signed by the user) but inconsistent. The vector-clock + highest-seen mechanism detects the inconsistency on the next sync but cannot prevent it from arising. Mitigation: detection is sufficient — the user gets a clear "your vault has forked, please choose a side" UI.

4. **No anti-coercion / plausible deniability.** Secretary has one master password and one recovery mnemonic, and unlocking either reveals the entire vault. There is no "duress password" that reveals a decoy vault. This is reasonable for v1; a duress mode could be added later as a v2 format feature without breaking v1.

5. **Recovery mnemonic loss is unrecoverable.** If the user loses both the master password and the recovery mnemonic, the vault is unrecoverable. This is the design intent (true zero-knowledge); compensating control is the mandatory "save your recovery key" gate at vault creation.

6. **Metadata leak to cloud host.** File count, file sizes, modification times, and access patterns are all visible to the cloud-folder host. Mitigations would require constant-size files or a server-side oblivious-RAM construction; both are out of scope.

7. **No anti-CSPRNG-failure defense.** If the OS CSPRNG is broken on a device, randomly-generated keys (Block Content Keys, identity keypairs, nonces) lose their security properties. Detection of CSPRNG failure is an OS responsibility; Secretary trusts `getrandom`.

---

## 5. Verification trace

Each defense in §3 must correspond to either a specific test or a specific design feature. The Definition-of-Done for Sub-project A includes a check that this trace is complete:

- **Block AEAD confidentiality** → unit test `test_aead_decrypt_with_wrong_key_fails`; KAT against XChaCha20-Poly1305 published vectors.
- **Block AEAD integrity** → unit test `test_aead_tag_failure_on_byte_flip`.
- **Manifest signature integrity** → unit test `test_manifest_signature_fails_on_block_swap`.
- **Hybrid KEM correctness and PQ component** → KAT against NIST FIPS 203 ML-KEM-768 vectors.
- **Hybrid signature correctness and PQ component** → KAT against NIST FIPS 204 ML-DSA-65 vectors.
- **Hybrid signature AND-verification** → unit test `test_hybrid_sig_fails_when_only_one_half_valid`.
- **Vector-clock rollback rejection** → unit test `test_manifest_dominated_by_highest_seen_is_rejected`.
- **Contact card OOB-only invariant** → not a runtime check; verified by code review and by absence of any "load card from path in shared folder" function in the public Rust API.
- **Argon2id memory parameter** → set in `kdf.rs`, recorded in `vault.toml`, asserted by `test_kdf_params_minimum_memory_kib`.
- **Format-version downgrade rejection** → unit test `test_load_manifest_with_higher_format_version_is_rejected_when_we_dont_understand_it`.
- **Suite-ID per-block migration** → integration test `test_vault_with_mixed_suite_ids_loads_correctly`.

Each test name listed above is a contract; the test must exist by Sub-project A's Definition-of-Done.
