# 13. Glossary

This glossary defines every technical term used in the primer, plus a number of related terms you may encounter in further reading. Definitions are written for readers without a cryptography background; precision is sometimes traded for clarity. For the normative, implementation-level glossary used by Secretary's specifications, see [docs/glossary.md](../../../glossary.md).

Cross-references between glossary entries are in *italics*.

---

### AAD

*Additional Authenticated Data.* Bytes that are bound to an [AEAD](#aead) ciphertext via the authentication tag but are not themselves encrypted. The classic use is metadata you want everyone to be able to read but no one to be able to alter without detection. In Secretary, the [block](#block) file's header bytes are AAD for the block's ciphertext. Tampering with the AAD invalidates the [MAC](#mac) tag.

### AEAD

*Authenticated Encryption with Associated Data.* A symmetric encryption primitive that provides both [confidentiality](#confidentiality) (the ciphertext hides the plaintext) and [integrity](#integrity) (any modification is detected). Secretary uses [XChaCha20-Poly1305](#xchacha20-poly1305) throughout. AEAD is the modern minimum standard; encryption-without-authentication is considered an anti-pattern.

### AES

*Advanced Encryption Standard.* A widely-used symmetric block cipher. Frequently combined with the GCM mode to form an [AEAD](#aead). Secretary uses [XChaCha20-Poly1305](#xchacha20-poly1305) instead, primarily because XChaCha20 is faster on hardware without AES-acceleration and has larger nonces.

### Argon2id

The password-based key derivation function Secretary uses for stretching the [master password](#master-password) into the [Master KEK](#master-kek). Memory-hard (requires substantial RAM per attempt, defeating GPU brute-force). Specified by RFC 9106. Secretary's default parameters: 256 MiB of memory, 3 iterations, 1 thread of parallelism.

### Asymmetric encryption

Encryption using a *key pair* — one [public key](#public-key), one [secret key](#secret-key) — where the public key encrypts (or verifies) and the secret key decrypts (or signs). Slow compared to [symmetric encryption](#symmetric-encryption), but solves the *key-distribution problem*. Also called *public-key cryptography*.

### Authenticity

The property that a piece of data demonstrably came from the claimed author and has not been altered. In Secretary, achieved via [digital signatures](#digital-signature).

### Birthday bound

The size of a random sample at which collisions become likely. For an output space of size 2^N, the birthday bound is about 2^(N/2). Important for nonce sizing: 12-byte (96-bit) nonces have a birthday bound of 2^48, which is reachable; 24-byte (192-bit) [XChaCha20](#xchacha20) nonces have a birthday bound of 2^96, which is not.

### BIP-39

The Bitcoin Improvement Proposal that defines a standard mnemonic encoding of a random number into a list of words from a fixed wordlist. Used in Secretary for the 24-word [recovery mnemonic](#recovery-mnemonic) (256 bits of entropy → 24 words) and the 12-word [fingerprint](#fingerprint) form (128 bits → 12 words).

### BLAKE3

The cryptographic hash function Secretary uses for general hashing, [fingerprints](#fingerprint), and transcript binding. Fast in software, well-analysed, and produces a 256-bit output.

### Block

(Secretary-specific.) The unit of encryption and the unit of sharing in Secretary. A block contains one or more [records](#record) and is stored as a single file. Each block has its own [Block Content Key](#block-content-key); sharing a block means delivering its content key to additional recipients.

### Block Content Key

A 256-bit symmetric key, generated freshly per [block](#block), that encrypts the block's plaintext via [AEAD](#aead). Wrapped per-recipient via the [hybrid KEM](#hybrid-kem).

### Brute force

Trying every possible candidate value of a secret. Defeated by making the secret space large enough (256-bit symmetric keys; high-entropy mnemonics) and, for human-chosen passwords, by making each guess expensive ([Argon2id](#argon2id); see [KDF](#kdf)).

### CBOR

*Concise Binary Object Representation.* A compact binary serialisation format defined in RFC 8949. Secretary uses CBOR (in its deterministic encoding profile) for all structured data, especially data that is signed.

### Cipher

Any algorithm that transforms plaintext into ciphertext. Loosely synonymous with "encryption algorithm." A *block cipher* (like AES) operates on fixed-size blocks; a *stream cipher* (like ChaCha20) produces a keystream that is XOR'd with the plaintext.

### Ciphertext

The encrypted form of data. Looks like random bytes; reveals nothing about the [plaintext](#plaintext) to someone without the key.

### Classical

(Of cryptography.) Cryptographic algorithms whose security relies on problems hard for ordinary (non-quantum) computers, but which would be broken by sufficiently large quantum computers. [X25519](#x25519), [Ed25519](#ed25519), [RSA](#rsa), [ECDSA](#ecdsa) are all classical. Contrast with [post-quantum](#post-quantum-cryptography).

### Collision

Two different inputs that produce the same hash output. A cryptographic hash function is collision-resistant if finding a collision requires infeasibly much computation.

### Confidentiality

The property that data cannot be read by anyone who lacks the key. The first thing most people mean by "encryption."

### Contact Card

(Secretary-specific.) A signed, public artifact representing a Secretary user's identity. Contains the user's UUID, display name, and four [public keys](#public-key) (X25519, ML-KEM-768, Ed25519, ML-DSA-65). Self-signed by the user. Carries a [fingerprint](#fingerprint) for [out-of-band verification](#oob-verification).

### CRDT

*Conflict-free Replicated Data Type.* A data structure with a deterministic merge operation that is *commutative*, *associative*, and *idempotent*, allowing multiple replicas to converge without central coordination. Secretary's vault state is CRDT-flavoured.

### CSPRNG

*Cryptographically Secure Pseudo-Random Number Generator.* A pseudo-random generator whose output cannot be predicted given any number of past outputs, even by a computationally bounded attacker. Modern operating systems provide one as a system call (`getrandom` on Linux; `arc4random_buf` on macOS; `BCryptGenRandom` on Windows). Secretary uses the OS CSPRNG and refuses to fall back to anything weaker.

### Death clock

(Secretary-specific.) The propagating tombstone marker `tombstoned_at_ms` that ensures deletions are not silently undone in concurrent merges. See [crypto-design.md §11](../../../crypto-design.md).

### Decryption

The inverse of [encryption](#encryption): turning [ciphertext](#ciphertext) back into [plaintext](#plaintext) using the appropriate key.

### Determinism

(In encoding.) The property that the same logical data always produces the same byte sequence when serialised. Necessary whenever a serialised form is signed, because a signature only verifies against the exact bytes that were signed.

### Diffie-Hellman

A *key-agreement* protocol in which two parties, each with a key pair, can compute a shared secret using only their own secret key and the other party's public key. [X25519](#x25519) is an elliptic-curve Diffie-Hellman variant.

### Digital signature

A cryptographic mechanism that lets the holder of a [secret key](#secret-key) produce a value (the signature) that anyone with the corresponding [public key](#public-key) can verify. Proves authorship of a specific message without revealing the secret key. See [Ed25519](#ed25519), [ML-DSA-65](#ml-dsa-65).

### Domain separation

The practice of including a fixed identifying tag in a cryptographic input so that the same algorithm used in two different roles cannot have its output replayed across roles. Secretary uses tags like `secretary-v1-block-sig` for exactly this purpose.

### ECDSA

*Elliptic-Curve Digital Signature Algorithm.* A classical signature scheme widely deployed in TLS, Bitcoin, and many other systems. Vulnerable to [Shor's algorithm](#shors-algorithm). Not used by Secretary; Secretary uses [Ed25519](#ed25519) for its classical signature.

### Ed25519

A digital signature algorithm based on the Edwards-curve form of Curve25519. Specified by RFC 8032. Fast, well-studied, widely deployed; the classical half of Secretary's [hybrid signature](#hybrid-signature).

### Elliptic-curve cryptography

A family of public-key algorithms whose security relies on the hardness of discrete logarithms over points on elliptic curves. Vulnerable to [Shor's algorithm](#shors-algorithm) on a sufficiently large quantum computer. Includes [X25519](#x25519), [Ed25519](#ed25519), [ECDSA](#ecdsa).

### Encryption

Transforming [plaintext](#plaintext) into [ciphertext](#ciphertext) using a key, in such a way that the plaintext can be recovered only with the appropriate key.

### Entropy

A measure of unpredictability, typically measured in bits. A truly random *N*-bit value has *N* bits of entropy. Human-chosen passwords usually have far less entropy than their length suggests.

### Equivocation

An attack where an adversary serves two different consistent versions of data to different parties (e.g., different versions of the vault to your laptop and your phone). Secretary detects but cannot prevent equivocation by a malicious cloud-folder host.

### Fingerprint

A short, fixed-size summary of a larger piece of data, computed via a [hash function](#hash-function). In Secretary, fingerprints identify [blocks](#block) (recorded in the manifest) and [Contact Cards](#contact-card) (used for [out-of-band verification](#oob-verification)). Card fingerprints are presented as 12 [BIP-39](#bip-39) words or as grouped hex.

### FIPS

*Federal Information Processing Standard.* A US standardisation series. [ML-KEM-768](#ml-kem-768) is FIPS 203 (2024); [ML-DSA-65](#ml-dsa-65) is FIPS 204 (2024).

### Forward secrecy

The property that compromise of long-term keys does not retroactively compromise past data. Achieved by using ephemeral session keys. Secretary's v1 does not have forward secrecy at the record level; see [chapter 12](12-limitations.md).

### Grover's algorithm

A quantum algorithm that provides a quadratic speedup for unstructured search. Reduces effective symmetric-key strength by half (256-bit key → 128 bits of effective security). The reason modern symmetric primitives target 256-bit keys.

### Hash function

A function that maps any input to a fixed-size output. Cryptographic hash functions additionally provide [preimage resistance](#preimage-resistance), [second-preimage resistance](#second-preimage-resistance), and [collision resistance](#collision-resistance). See [BLAKE3](#blake3), [SHA-256](#sha-256).

### Harvest-now-decrypt-later

An attack model in which an adversary captures encrypted data today (for cheap storage) and decrypts it later when more capable computers (especially quantum computers) become available. The motivation for [post-quantum](#post-quantum-cryptography) cryptography in long-lived applications.

### HKDF

*HMAC-based Key Derivation Function.* A standard [key derivation function](#kdf) for shaping or combining cryptographic key material. Specified by RFC 5869. Used in Secretary's [hybrid KEM](#hybrid-kem) combiner and to derive the [Recovery KEK](#recovery-kek).

### HMAC

A [MAC](#mac) construction based on a [hash function](#hash-function). Used inside [HKDF](#hkdf) and in many other protocols.

### Hybrid

(In cryptographic context.) Has two unrelated meanings, both used in Secretary:
1. *Hybrid encryption*: combining symmetric and asymmetric primitives (asymmetric to deliver a fresh symmetric key, symmetric to do the bulk encryption). The standard pattern in modern protocols.
2. *Post-quantum hybrid*: combining a [classical](#classical) algorithm with a [post-quantum](#post-quantum-cryptography) algorithm so an attacker must break both. Secretary's [hybrid KEM](#hybrid-kem) and [hybrid signature](#hybrid-signature) are post-quantum hybrids.

### Hybrid KEM

Secretary's per-recipient key wrapping mechanism: [X25519](#x25519) (classical) and [ML-KEM-768](#ml-kem-768) (post-quantum) run in parallel, with their outputs combined via [HKDF](#hkdf). See [chapter 6](06-key-encapsulation.md).

### Hybrid signature

Secretary's signature mechanism: an [Ed25519](#ed25519) signature *and* an [ML-DSA-65](#ml-dsa-65) signature, both required to verify. See [chapter 7](07-digital-signatures.md).

### Identity Block Key

(Secretary-specific.) A 256-bit symmetric key, generated once per vault. Encrypts the [Identity Bundle](#identity-bundle) and the [Manifest](#manifest). Itself wrapped twice — under the [Master KEK](#master-kek) and under the [Recovery KEK](#recovery-kek).

### Identity Bundle

(Secretary-specific.) The encrypted file containing a user's four secret keys and identity metadata. Stored at `<vault>/identity.bundle.enc`.

### Idempotent

A merge operation is idempotent if `merge(A, A) == A`. One of the three [CRDT](#crdt) properties.

### Integrity

The property that data cannot be altered without detection. [AEAD](#aead) provides integrity via the [MAC](#mac) tag; signatures provide integrity at the per-message level.

### KAT

*Known-Answer Test.* A test vector with a fixed input and an expected output. Used to verify that an implementation matches its specification. Secretary's `core/tests/data/` directory contains KATs from NIST and various RFCs.

### KDF

*Key Derivation Function.* A function that takes secret input and produces a cryptographic key. Two distinct KDFs in Secretary: [Argon2id](#argon2id) (for low-entropy passwords; deliberately slow) and [HKDF](#hkdf) (for high-entropy material; fast).

### KEK

*Key Encryption Key.* A key whose only job is to encrypt other keys. Secretary has a [Master KEK](#master-kek) (from the password) and a [Recovery KEK](#recovery-kek) (from the recovery mnemonic), both of which wrap the [Identity Block Key](#identity-block-key).

### KEM

*Key Encapsulation Mechanism.* An asymmetric primitive that delivers a fresh random secret to the holder of a [public key](#public-key). The standard interface for "encrypt a fresh symmetric key for this recipient." Secretary's KEM is hybrid: [X25519](#x25519) + [ML-KEM-768](#ml-kem-768).

### Key

A secret (or pair of values, in [asymmetric](#asymmetric-encryption) cryptography) that controls a cryptographic operation. Possession of the key is what distinguishes "can decrypt / can sign" from "cannot."

### Key-distribution problem

The chicken-and-egg problem of [symmetric encryption](#symmetric-encryption): to send an encrypted message you and the recipient must already share a secret key, which requires a way to share the key securely in the first place. Solved by [asymmetric encryption](#asymmetric-encryption) and [KEMs](#kem).

### Keystream

The pseudo-random sequence of bytes produced by a stream cipher under a given (key, nonce) pair. XOR'd with plaintext to produce ciphertext.

### Last-writer-wins

(LWW.) A merge rule that resolves conflicts by picking the side with the later timestamp. Used at the field level inside Secretary's per-record merge.

### MAC

*Message Authentication Code.* A symmetric primitive that produces a tag bound to a message and a secret key. Anyone with the key can verify the tag; without the key, neither producing a valid tag nor verifying one is feasible. [Poly1305](#poly1305) is the MAC inside Secretary's [AEAD](#aead).

### Manifest

(Secretary-specific.) The encrypted, signed top-level vault index. Lists all blocks, their fingerprints, and the vault-level vector clock. Stored at `<vault>/manifest.cbor.enc`.

### Master KEK

(Secretary-specific.) Key derived from the [master password](#master-password) via [Argon2id](#argon2id). Wraps the [Identity Block Key](#identity-block-key).

### Master password

The secret a Secretary user remembers. Stretched via [Argon2id](#argon2id) into the [Master KEK](#master-kek).

### Memory-hard

A property of a function that requires substantial RAM to compute, defeating GPU and ASIC parallel attacks that scale on compute but not on memory. [Argon2id](#argon2id) is memory-hard.

### MITM

*Man in the Middle.* An attacker who places themselves between two communicating parties and impersonates each to the other, typically by substituting their own [public key](#public-key) in place of the legitimate one. Defeated in Secretary by [out-of-band verification](#oob-verification) of [Contact Cards](#contact-card).

### ML-DSA-65

Module-Lattice Digital Signature Algorithm at security level 3, standardised by NIST in 2024 as [FIPS](#fips) 204. Formerly known as Dilithium. [Post-quantum](#post-quantum-cryptography) half of Secretary's [hybrid signature](#hybrid-signature).

### ML-KEM-768

Module-Lattice Key Encapsulation Mechanism at security level 3, standardised by NIST in 2024 as [FIPS](#fips) 203. Formerly known as Kyber. [Post-quantum](#post-quantum-cryptography) half of Secretary's [hybrid KEM](#hybrid-kem).

### Nonce

"Number used once." A value that, together with a key, must never be repeated. Critical for stream ciphers and [AEAD](#aead): nonce reuse with the same key is a fatal break. Secretary uses 24-byte random nonces ([XChaCha20](#xchacha20)), large enough that random repetition is statistically impossible.

### OOB verification

*Out-of-band verification.* Confirming a piece of cryptographic information through a channel different from the one used to deliver it. The way Secretary upgrades a [Contact Card](#contact-card) from `unverified` to `fingerprint-verified`.

### PKI

*Public Key Infrastructure.* The system of certificate authorities, certificates, and trust chains used by HTTPS to bind public keys to identities. Secretary deliberately does not use PKI; it relies on [out-of-band verification](#oob-verification) instead.

### Plaintext

The original, readable form of data, before [encryption](#encryption).

### Poly1305

A fast [MAC](#mac) designed for use with stream ciphers, particularly ChaCha20. Secretary's authentication tag.

### Post-quantum cryptography

(PQC.) Cryptographic algorithms believed to resist attack by sufficiently large quantum computers. Secretary's PQC primitives are [ML-KEM-768](#ml-kem-768) and [ML-DSA-65](#ml-dsa-65).

### Preimage resistance

A property of a cryptographic [hash function](#hash-function): given an output, finding any input that produces it is infeasible.

### Private key

Synonym for [secret key](#secret-key). Avoid the term "private key" when also using *public key* — *secret key* is less easily confused.

### PRNG

*Pseudo-Random Number Generator.* A deterministic algorithm that takes a small seed and stretches it into a long stream of apparently-random values. Output is only as good as the seed. A *cryptographically secure* PRNG is a [CSPRNG](#csprng).

### Pseudo-random

Output that statistically resembles randomness but is in fact produced by a deterministic algorithm (a [PRNG](#prng)) from a seed.

### Public key

The half of an [asymmetric](#asymmetric-encryption) key pair intended to be shared with others. Used to encrypt to the holder of the corresponding [secret key](#secret-key), or to verify signatures from them.

### Quantum computer

A computer whose computation uses quantum-mechanical phenomena. At sufficient scale, it would break classical asymmetric cryptography via [Shor's algorithm](#shors-algorithm) and weaken symmetric cryptography via [Grover's algorithm](#grovers-algorithm). Does not exist at scale today; may never exist at scale.

### Recipient

(Secretary-specific.) A contact (or the owner) entitled to decrypt a particular [block](#block). Each recipient has their own per-recipient wrap of the [Block Content Key](#block-content-key) in the block file.

### Record

(Secretary-specific.) A single entry: a login, a secure note, an API key, etc. Composed of fields. Lives inside exactly one [block](#block).

### Recovery KEK

(Secretary-specific.) Key derived from the [recovery mnemonic](#recovery-mnemonic) via [HKDF](#hkdf). Wraps the [Identity Block Key](#identity-block-key) independently of the [Master KEK](#master-kek).

### Recovery mnemonic

(Secretary-specific.) A 24-word [BIP-39](#bip-39) phrase encoding 256 bits of [entropy](#entropy). Generated at vault creation; the user's backup credential if the master password is lost.

### Replay

Re-presenting an old valid message in a new context, hoping it will be accepted. Defended by [domain separation](#domain-separation) (so messages can't cross contexts) and protocol-level mechanisms like [vector clocks](#vector-clock).

### Rollback

Substituting an older valid version of state in place of the current one. Secretary's [vector-clock](#vector-clock) + highest-seen mechanism detects rollback at the [manifest](#manifest) and [block](#block) levels.

### RSA

A classical asymmetric algorithm based on the hardness of integer factorisation. Broken by [Shor's algorithm](#shors-algorithm). Not used by Secretary.

### Salt

A non-secret random value used during [key derivation](#kdf) to ensure that two users with the same input (e.g., the same password) produce different keys. Defeats pre-computed attack tables.

### Second-preimage resistance

A property of a [hash function](#hash-function): given one input, finding a *different* input with the same hash is infeasible.

### Secret key

The half of an [asymmetric](#asymmetric-encryption) key pair that the user keeps private. Decrypts what the [public key](#public-key) encrypts, signs what the public key verifies.

### SHA-256

A cryptographic [hash function](#hash-function) from the SHA-2 family. Specified by FIPS 180-4. Used in Secretary inside [HKDF](#hkdf) (which is RFC-defined to use SHA-2).

### Shor's algorithm

A quantum algorithm that efficiently solves integer factorisation and discrete logarithm. Would break [RSA](#rsa) and [elliptic-curve cryptography](#elliptic-curve-cryptography) on a sufficiently large quantum computer.

### Side channel

Information leakage through paths the algorithm wasn't designed to use: timing, power, EM emissions. Defended by constant-time implementations and (for stronger threats) specialised hardware.

### Signature

See [digital signature](#digital-signature).

### Suite ID

(Secretary-specific.) A 16-bit identifier for the cipher suite used in a particular block, manifest, or wrap. Suite `0x0001` is the v1 hybrid post-quantum suite. Future suites can coexist with v1 in the same vault.

### Symmetric encryption

Encryption where the same key is used to encrypt and decrypt. Fast; the [key-distribution problem](#key-distribution-problem) is the catch.

### TOFU

*Trust on First Use.* Accepting a key the first time it is presented. Used by SSH; deliberately *not* used by Secretary for [Contact Cards](#contact-card).

### Tombstone

(Secretary-specific.) A marker recording that a record or block was deleted. Necessary for [CRDT](#crdt)-correct merge under concurrent edits; otherwise devices that haven't seen the deletion would re-create the record.

### Transcript hash

A hash of all the information exchanged during a cryptographic operation, used to bind subsequent steps to the exact context. Secretary's [hybrid KEM](#hybrid-kem) uses a transcript hash to prevent KEM-sneak attacks.

### Trusted computing base

(TCB.) The set of hardware and software a system trusts not to be compromised. Includes the OS, firmware, and CPU. Cryptography sits on top of the TCB; if the TCB is compromised, cryptography cannot help.

### Vault

(Secretary-specific.) One self-contained collection of secrets, owned by one user, stored as a directory of files (cleartext metadata, encrypted manifest, encrypted identity bundle, encrypted blocks, contact cards).

### Vector clock

A map from device identifiers to per-device counters, used to track causal history of edits. Secretary uses vector clocks at two levels: per-block (record-level merge) and per-vault ([manifest](#manifest) [rollback](#rollback) detection).

### Wrap

(Key wrap.) Encrypting a key under another key. Secretary wraps [Block Content Keys](#block-content-key) under per-recipient [hybrid-KEM](#hybrid-kem)-derived wrap keys, and wraps the [Identity Block Key](#identity-block-key) under both the [Master KEK](#master-kek) and [Recovery KEK](#recovery-kek).

### X25519

[Elliptic-curve](#elliptic-curve-cryptography) [Diffie-Hellman](#diffie-hellman) key agreement on Curve25519. Specified by RFC 7748. [Classical](#classical) half of Secretary's [hybrid KEM](#hybrid-kem).

### XChaCha20

An extension of the ChaCha20 stream cipher with a 24-byte (192-bit) [nonce](#nonce), large enough to be sampled randomly without collision risk.

### XChaCha20-Poly1305

Secretary's [AEAD](#aead) cipher: [XChaCha20](#xchacha20) for encryption, [Poly1305](#poly1305) for authentication, combined as a single primitive.

### Zeroize

To explicitly overwrite a buffer with zeros to remove secret material before the buffer is freed. Defends against later memory-disclosure attacks where leftover keys could be read by an attacker who gains memory access. The Rust `zeroize` crate provides this; Secretary uses it everywhere keys and plaintext live.

---

If a term you encounter elsewhere in Secretary's documentation isn't here, check [docs/glossary.md](../../../glossary.md) for the implementation-level glossary.
