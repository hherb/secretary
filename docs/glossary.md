# Secretary Glossary

Definitions of terms used throughout the Secretary specifications. This file is normative — wherever a term appears in capitalized italic in the other docs (e.g. *Identity Block Key*), the meaning is the one given here.

---

**AAD** — Additional Authenticated Data. Bytes that are bound to an AEAD ciphertext via the MAC tag but are not themselves encrypted. Tampering with the AAD invalidates the tag.

**AEAD** — Authenticated Encryption with Associated Data. The combined primitive providing confidentiality (cipher) and integrity (MAC). Secretary uses XChaCha20-Poly1305 throughout.

**Argon2id** — The password-based key derivation function used to derive the *Master KEK* from the user's master password. Memory-hard, side-channel-resistant. Specified by RFC 9106.

**Block** — The unit of encryption and the unit of sharing. A block contains 1 or more *Records*. Each block is stored as one file on disk and may be shared with one or more *Recipients* (including the owner).

**Block Content Key** — The 256-bit symmetric AEAD key that encrypts a single block's plaintext. Generated freshly when the block is created or rotated. Wrapped per-recipient via *Hybrid KEM*.

**BIP-39** — Standard for encoding 256 bits of entropy as a 24-word mnemonic from a fixed wordlist. Used for the *Recovery Mnemonic* so it is transcribable on paper without typos.

**BLAKE3** — Cryptographic hash function. Used for fingerprints, transcript hashes, and general hashing where a stable specified hash is not required. Faster than SHA-3 with comparable security margins.

**CBOR** — Concise Binary Object Representation (RFC 8949). The structured-data serialization format used inside encrypted block bodies, manifests, and contact cards. Deterministic-encoding profile is used wherever signatures cover CBOR data.

**Clean-room reimplementation** — A new implementation written from a public specification without reading the reference Rust source. Secretary's vault format and crypto design must support this; it is verified by the Python conformance script in Sub-project A.

**Contact Card** — A signed, public artifact that represents a user's identity to others. Contains the four identity public keys, the user's UUID, display name, and self-signature. Fingerprint of the canonical CBOR encoding is what users compare for *OOB verification*.

**CRDT** — Conflict-free Replicated Data Type. A data structure that supports concurrent edits with deterministic merge. Secretary's blocks are CRDT-flavored: per-field last-writer-wins with vector-clock-based concurrency detection.

**CSPRNG** — Cryptographically Secure Pseudo-Random Number Generator. Secretary uses `getrandom` (OS-backed entropy) via Rust's `rand_core::OsRng`.

**DEK** — Data Encryption Key. Generic term for a key that encrypts user data. The *Block Content Key* is the DEK at the block level.

**Device** — A single installation of Secretary on a single hardware device (laptop, phone, etc.). Distinct from a *User*: one user owns multiple devices and they share one *Identity*.

**Domain separation** — Prefixing a signed or hashed message with a fixed string identifying the protocol context, so a signature for one purpose cannot be replayed in another. Secretary uses tags such as `"secretary-v1-block-sig"`.

**Ed25519** — Elliptic-curve digital signature algorithm. Classical-half of Secretary's *Hybrid Signature*.

**Field** — A named piece of data inside a *Record* (e.g., `username`, `password`, `url`, `notes`). Each field has a value, a `last_mod` timestamp, and the originating `device_uuid` for LWW tiebreak.

**FFI** — Foreign Function Interface. Secretary exposes the Rust core via `pyo3` (to Python) and `uniffi` (to Swift and Kotlin).

**Fingerprint** — BLAKE3-256 hash of the canonical CBOR encoding of a *Contact Card*, displayed as a 12-word BIP-39-style mnemonic (for verbal verification) and as hex (for visual verification).

**Format version** — The on-disk format revision number. Stored in `vault.toml` and in every block and manifest header. Upgrades require explicit migration.

**Hybrid KEM** — Key encapsulation that combines X25519 (classical) and ML-KEM-768 (post-quantum) so an attacker must break both to recover the shared secret. Used for wrapping *Block Content Keys* per *Recipient*.

**Hybrid Signature** — Signature that is the conjunction of an Ed25519 signature and an ML-DSA-65 signature over the same message. Verification requires both to verify (AND, not OR).

**HKDF** — HMAC-based Key Derivation Function (RFC 5869). Used in two roles: (a) the *Hybrid KEM* combiner (HKDF-SHA-256) and (b) deriving sub-keys from the *Recovery Mnemonic*.

**Identity** — One user's persistent identity across all their devices. Concretely: a 16-byte UUID, display name, four secret/public keypairs (X25519, ML-KEM-768, Ed25519, ML-DSA-65), all stored in the *Identity Bundle*.

**Identity Block Key** — A random 256-bit symmetric key generated once per vault. Encrypts the *Identity Bundle* and the *Manifest*. Itself wrapped twice — under the *Master KEK* and under the *Recovery KEK*.

**Identity Bundle** — The CBOR-encoded, AEAD-encrypted file containing the identity's secret keys. Stored at `<vault>/identity.bundle.enc`. Decryptable via password (Master KEK) or recovery key (Recovery KEK).

**KAT** — Known-Answer Test. Test vector with a fixed input and an expected output, used to verify a primitive matches its specification. Secretary uses NIST KATs for ML-KEM-768 and ML-DSA-65, and RFC test vectors for the classical primitives.

**KDF** — Key Derivation Function. Two distinct ones in Secretary: Argon2id (password → Master KEK) and HKDF-SHA-256 (recovery / hybrid combiner).

**KEK** — Key Encryption Key. A key whose only job is to encrypt other keys. Secretary has a *Master KEK* (from password) and a *Recovery KEK* (from recovery mnemonic), both of which wrap the *Identity Block Key*.

**KEM** — Key Encapsulation Mechanism. The asymmetric primitive used to deliver a symmetric key to a recipient via their public key.

**Manifest** — The encrypted, signed top-level vault index. Stored at `<vault>/manifest.cbor.enc`. Contains the list of blocks, their fingerprints, recipients, and a vault-level vector clock.

**Master KEK** — Key derived from the user's master password via Argon2id. Wraps the *Identity Block Key*. Never persisted; derived on demand and zeroized after use.

**Master Password** — The secret the user remembers. Argon2id-stretched into the *Master KEK*. Never stored anywhere in plaintext or hashed form; only AEAD MAC failure on the wrap reveals a wrong password.

**ML-DSA-65** — Module-Lattice Digital Signature Algorithm at security level 3 (NIST FIPS 204). Post-quantum half of Secretary's *Hybrid Signature*.

**ML-KEM-768** — Module-Lattice Key Encapsulation Mechanism at security level 3 (NIST FIPS 203). Post-quantum half of Secretary's *Hybrid KEM*.

**Nonce** — Number used once. XChaCha20 uses 24-byte nonces; Secretary samples a fresh nonce randomly for every encryption.

**OOB verification** — Out-of-band verification: confirming a *Fingerprint* via a separate channel from the one used to deliver the *Contact Card*. E.g., reading the 12-word mnemonic over a phone call after receiving the card by email. The only way to upgrade a contact's verification state from `unverified` to `fingerprint-verified`.

**PQC** — Post-Quantum Cryptography. Algorithms believed to resist attack by sufficiently large quantum computers. Secretary's PQC algorithms are ML-KEM-768 and ML-DSA-65.

**Record** — A single secret entry: a login, an API key, a secure note, an SSH key, etc. Composed of typed *Fields*. Lives inside exactly one *Block* at any time.

**Recipient** — A *Contact* (or the owner) entitled to decrypt a particular *Block*. Each recipient has their own wrap of the *Block Content Key* in the block's header.

**Recovery KEK** — Key derived from the *Recovery Mnemonic* via HKDF. Wraps the *Identity Block Key*. Independently sufficient to unlock the vault if the master password is forgotten.

**Recovery Mnemonic** — A BIP-39 24-word phrase encoding 256 bits of entropy. Generated once at vault creation, displayed to the user, never persisted by Secretary. Acts as the recovery credential.

**Rollback attack** — An adversary controlling cloud storage substitutes an older valid vault state for the current one, hoping to revert security-relevant changes (e.g., re-add a removed recipient). Defeated by per-device "highest vector clock seen" tracking.

**Secret type** — In Rust, a `SecretBytes` or `Sensitive<T>` wrapper that zeroizes the inner buffer on drop and disables `Debug` printing. Foundational for memory hygiene.

**Suite ID** — A `u16` identifying the cipher suite used for a particular block, manifest, or wrap. Suite `0x01` is the v1 hybrid post-quantum suite. Suites can coexist within the same vault; readers select the suite by ID.

**TOFU** — Trust On First Use. Accepting a key the first time it is presented and trusting subsequent uses. Secretary deliberately does *not* support TOFU for *Contact Cards*; cards are imported only via OOB channels, with explicit verification states.

**Tombstone** — A marker recording that a previously-existing record or block was deleted. Required for CRDT-correct deletion under sync; otherwise, devices that haven't seen the deletion would re-create the record.

**uniffi** — Mozilla's tool for generating Swift and Kotlin bindings from a Rust crate via an interface-definition language (`.udl`). Secretary's mobile clients use uniffi to call the Rust core.

**User** — One human, one *Identity*. May own multiple *Devices* and multiple *Vaults*.

**Vault** — One self-contained collection of secrets owned by one user, stored as a directory of files (cleartext metadata, encrypted manifest, encrypted identity bundle, encrypted blocks, contact cards). A user may have multiple vaults.

**Vector clock** — A map `{device_uuid → counter}` representing causal history. Secretary uses vector clocks at two levels: per-block (for record-level merge) and per-vault (for manifest-level rollback detection and merge).

**WebDAV** — A protocol that exposes a remote file system over HTTP. Secretary supports vaults stored on user-controlled WebDAV servers as an alternative to consumer cloud-folder services.

**X25519** — Elliptic-curve Diffie-Hellman key exchange on Curve25519. Classical half of Secretary's *Hybrid KEM*.

**XChaCha20-Poly1305** — Authenticated encryption with associated data, using the XChaCha20 stream cipher (24-byte nonces) and Poly1305 MAC. Secretary's symmetric AEAD throughout.

**Zeroize** — The act of overwriting a memory buffer with zeros to remove secret material before it is freed. The Rust crate `zeroize` provides `Drop` impls that do this automatically; Secretary's *Secret type* wrappers use it.
