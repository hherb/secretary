"""Spec constants, hard-coded from `docs/` rather than imported from Rust.

The §1.0/§14 wire constants, the §1.3 domain-separation tags, the §3
`file_kind` discriminants and the §6.2 key/signature lengths. This module
exists so a clean-room reader has ONE place to diff against the spec
documents.

Decoder-local schema constants deliberately do NOT live here -- the
`*_KNOWN_KEYS` / `*_REQUIRED_KEYS` frozensets are each decoder's own
strictness policy and travel with the decoder that enforces them
(`conformance_lib.codec.manifest_schema`, `conformance_lib.codec.record`),
where their rationale comments are readable beside the code they gate.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# §1.0 / §14 constants from docs/crypto-design.md and docs/vault-format.md.
# Hard-coded here (not imported from Rust) so this script is implementable
# from the spec documents alone.
# ---------------------------------------------------------------------------

MAGIC = 0x53454352  # "SECR" — vault-format.md §6.1.
FORMAT_VERSION = 0x0001
SUITE_ID = 0x0001  # secretary-v1-pq-hybrid.
FILE_KIND_BLOCK = 0x0003

VAULT_UUID_LEN = 16
BLOCK_UUID_LEN = 16
FINGERPRINT_LEN = 16
DEVICE_UUID_LEN = 16
VECTOR_CLOCK_ENTRY_LEN = DEVICE_UUID_LEN + 8  # device_uuid (16) + counter (u64).

# §6.2 recipient entry: 16 + 32 + 1088 + 24 + 32 + 16 = 1208.
X25519_PK_LEN = 32
ML_KEM_768_CT_LEN = 1088
WRAP_NONCE_LEN = 24
WRAP_CT_LEN = 32  # AEAD-encrypted 32-byte BCK.
WRAP_TAG_LEN = 16  # Poly1305.
RECIPIENT_ENTRY_LEN = (
    FINGERPRINT_LEN + X25519_PK_LEN + ML_KEM_768_CT_LEN
    + WRAP_NONCE_LEN + WRAP_CT_LEN + WRAP_TAG_LEN
)
assert RECIPIENT_ENTRY_LEN == 1208, "spec drift: §6.2 pins recipient entry at 1208 bytes"

AEAD_NONCE_LEN = 24  # XChaCha20.
AEAD_TAG_LEN = 16  # Poly1305.

ED25519_SIG_LEN = 64
ML_DSA_65_SIG_LEN = 3309  # FIPS 204 ML-DSA-65 signature length.
# §6.1 declares sig_pq_len as a u16 length-prefixed field but does not
# annotate the constant the way it annotates `sig_ed_len = 64`. Suite v1
# (`secretary-v1-pq-hybrid`, §1.3) pins ML-DSA-65 / FIPS 204, so the wire
# field is always 3309 bytes here. PR-B may add the explicit annotation
# in §6.1 to remove the asymmetry.

# Fixed prefix of header up to and including last_mod_ms (§6.1).
HEADER_PREFIX_LEN = 4 + 2 + 2 + 2 + VAULT_UUID_LEN + BLOCK_UUID_LEN + 8 + 8


# ---------------------------------------------------------------------------
# §2.0 Section 2 (PR-B, Task 15): full crypto verify against
# `core/tests/data/golden_vault_001/`.
#
# Layout below: pure functions, top-down. Crypto primitives wrap the
# external-library calls so a future swap (e.g. PyNaCl -> hand-rolled
# XChaCha) only touches one site. Domain-separation tags and field
# offsets are taken from `docs/crypto-design.md` §1.3 and
# `docs/vault-format.md` §3 / §4.1 / §6.1, mirroring the Rust source
# in `core/src/crypto/{kdf,aead,kem,sig}.rs` and
# `core/src/{unlock,vault}/`.
# ---------------------------------------------------------------------------

# §1.3 / kdf.rs domain-separation tags (ASCII bytes, no NUL, no length prefix).
# Mirrors the `pub const TAG_*: &[u8]` definitions in
# `core/src/crypto/kdf.rs`.
TAG_RECOVERY_KEK = b"secretary-v1-recovery-kek"
TAG_ID_WRAP_PW = b"secretary-v1-id-wrap-pw"
TAG_ID_WRAP_REC = b"secretary-v1-id-wrap-rec"
TAG_ID_BUNDLE = b"secretary-v1-id-bundle"
TAG_HYBRID_KEM = b"secretary-v1-hybrid-kem"
TAG_HYBRID_KEM_TRANSCRIPT = b"secretary-v1-hybrid-kem-transcript"
TAG_BLOCK_CONTENT_KEY_WRAP = b"secretary-v1-block-content-key-wrap"
TAG_BLOCK_KEY_WRAP = b"secretary-v1-block-key-wrap"
TAG_BLOCK_SIG = b"secretary-v1-block-sig"
TAG_MANIFEST_SIG = b"secretary-v1-manifest-sig"
TAG_CARD_SIG = b"secretary-v1-card-sig"
TAG_FINGERPRINT = b"secretary-v1-fingerprint"

# §3 / bundle_file.rs file_kind constants
FILE_KIND_IDENTITY_BUNDLE = 0x0001
FILE_KIND_MANIFEST = 0x0002
FILE_KIND_BLOCK_KIND = 0x0003  # reuse without colliding with FILE_KIND_BLOCK above

# §6.2 / kem.rs sizes
ML_KEM_768_PK_LEN = 1184
ML_KEM_768_SK_LEN = 2400
ML_DSA_65_PK_LEN = 1952
BLOCK_CONTENT_KEY_LEN = 32
BUNDLE_WRAP_CT_PLUS_TAG_LEN = 32 + 16  # IBK (32) + Poly1305 tag (16)
