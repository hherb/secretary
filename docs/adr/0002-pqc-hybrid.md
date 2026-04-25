# ADR 0002 — Hybrid post-quantum cryptography from v1

**Status:** Accepted (2026-04-25)
**Supersedes:** none
**Superseded by:** none

## Context

The canonical use case for Secretary includes a parent sharing blocks with a child who decrypts them decades later (inheritance). A vault written in 2026 may have its ciphertexts read in 2056 — and copies of those ciphertexts may sit in cloud-folder hosts (whose retention policies the user does not control) for the entire interim.

This sets up a textbook *harvest-now-decrypt-later* threat: an adversary with future quantum computing capability copies ciphertexts today and decrypts them when capability arrives. NIST standardized ML-KEM (FIPS 203) and ML-DSA (FIPS 204) in 2024; major cryptosystems (Signal, iMessage PQ3, Cloudflare TLS, Chrome) have begun deploying hybrid post-quantum constructions. Pure classical (X25519 + Ed25519) ciphertexts written in 2026 cannot be assumed confidential for the project's intended lifespan.

The candidates considered:

1. **Classical only, format-versioned migration to PQ later.** Fast, small, simple. Loses for any block written before the migration day — those blocks remain classically encrypted in cloud copies forever.
2. **Hybrid classical + PQ from v1.** Larger, more complex, but every block is protected against both classical surprises in PQ algorithms and future quantum attacks on classical ones.
3. **PQ only.** Smallest code surface, but bets entirely on the still-young ML-KEM / ML-DSA. No hedge.

## Decision

Use a hybrid construction from v1:

- **KEM (recipient wraps):** X25519 ⊕ ML-KEM-768. Combiner is HKDF-SHA-256 over both shared secrets, both ciphertexts, and both public-key bundles, with domain-separation tag `secretary-v1-hybrid-kem`. See [crypto-design §7](../crypto-design.md#7-hybrid-kem-per-recipient-block-key-wrap).
- **Signatures:** Ed25519 ∧ ML-DSA-65. Both signatures must verify; verification is AND, not OR. Each signature has its own length-prefixed field on disk.
- **Symmetric AEAD:** XChaCha20-Poly1305 with 256-bit keys. Already quantum-resistant at this key size (Grover's algorithm leaves ~128-bit effective security, well above the comfortable threshold).
- **KDF:** Argon2id. Memory-hard; quantum speedup against memory-hard functions is limited.

Per-block `suite_id` records which suite a block uses. v1 = `0x0001` = the suite above. Future suites may upgrade individual primitives without breaking already-written blocks.

## Consequences

**Positive:**
- Blocks written today survive a quantum break of either (or both) classical primitives.
- Hedges against the still-young ML-KEM and ML-DSA algorithms; if a flaw is found in one of them, the classical half still protects.
- Aligns with industry-standard hybrid constructions emerging in 2024–2026 (Signal, iMessage, Cloudflare, OpenSSH).
- Per-block suite ID enables incremental migration to future suites without a flag-day re-encryption.

**Negative:**
- Recipient wraps are ~1208 bytes each (vs. ~96 bytes for classical-only). A block shared with five recipients carries ~6 KB of header overhead. Acceptable: blocks are already structured as files, not bytes-on-the-wire.
- Hybrid signatures add ~3.4 KB per signature, vs. 64 bytes for Ed25519 alone. Block files grow by ~3.4 KB; manifest grows by the same.
- ML-KEM-768 and ML-DSA-65 have larger key sizes (1184-byte and 1952-byte public keys, respectively). Contact cards are ~3 KB instead of ~100 bytes.
- More code, more crypto surface, more places for implementation bugs. Mitigated by using audited RustCrypto crates and committing comprehensive test vectors (NIST KATs).

**Risks:**
- ML-KEM and ML-DSA are 2024-standardized; long-term cryptanalysis may reveal weaknesses. The hybrid construction is *exactly* the hedge against this risk: an attacker must break both halves.
- The HKDF combiner construction is inspired by deployed hybrid systems but is itself v1-of-Secretary specific. Domain separation tags and inclusion of full key bundles in the combiner input are best practices that defend against several known KEM-combiner pitfalls.

## Revisit when

- ML-KEM-1024 / ML-DSA-87 (higher security levels) become routinely deployed — consider raising parameters in a v2 suite.
- A weakness in either ML-KEM-768 or ML-DSA-65 is published — accelerate suite migration; classical half holds in the meantime.
- Apple, Google, or Microsoft expose native ML-KEM / ML-DSA primitives in their platform crypto frameworks — could simplify mobile FFI surface.
