#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = [
#   "cryptography>=42",
#   "pynacl>=1.5",
#   "pqcrypto>=0.3",
#   "argon2-cffi>=23",
#   "blake3>=0.4",
#   "cbor2>=5",
# ]
# ///
"""
secretary cross-language conformance script (§15).

Run with (PEP 723 inline deps; uv resolves them automatically):

    uv run core/tests/python/conformance.py

Or, equivalently with explicit `--with` flags (matches the harness call
style used by the PR-B verification gate):

    uv run \
        --with cryptography \
        --with pynacl \
        --with pqcrypto \
        --with argon2-cffi \
        --with blake3 \
        --with cbor2 \
        core/tests/python/conformance.py

This script implements two independent §15 conformance slices:

  Section 1 (PR-A, Task 8):
    Walk `core/tests/data/block_kat.json` and validate each vector's
    `expected.block_file` hex bytes parse cleanly under the §6.1 wire
    format declared in `docs/vault-format.md`. Byte-layout only -- no
    cryptographic verification. Cross-checks decoded headers,
    fingerprints, recipient counts, and signature lengths against the
    pinned JSON inputs.

  Section 2 (PR-B, Task 15):
    Walk `core/tests/data/golden_vault_001/` and run the *full*
    end-to-end open-vault path: parse `vault.toml`, derive the master
    KEK with Argon2id, unwrap the IBK, AEAD-decrypt the manifest body,
    AEAD-decrypt the block body via hybrid-KEM-decap of the owner's
    recipient wrap, hybrid-verify both the block and manifest
    signatures, and CBOR-cross-check every plaintext field against
    `golden_vault_001_inputs.json`. Three in-script tamper checks
    confirm that bit-flips and signature truncation are reliably
    rejected by the verify path.

The parser is intentionally written from the spec docs only (no `import`
of Rust types), which is the §15 conformance contract for AGPL
clean-room re-implementation rights. Cross-language libraries used:

  - `cryptography` for Ed25519 verify, X25519 DH, HKDF-SHA-256.
  - `pynacl` for XChaCha20-Poly1305-IETF AEAD (the `cryptography`
    module ships ChaCha20-Poly1305 only; the §1.3 suite uses the
    extended-nonce variant).
  - `pqcrypto` for ML-KEM-768 decap and ML-DSA-65 verify (FIPS 203 /
    FIPS 204 reference implementations).
  - `argon2-cffi` for Argon2id raw-hash (32-byte master KEK output).
  - `blake3` for the §6.1 fingerprint and the §4.2 block-fingerprint.
  - `cbor2` for canonical-CBOR round-trips.

Exit codes:

  0  every check passed in both sections.
  1  any check failed; one-line `FAIL: <reason>` written to stderr.
  2  a fixture file was missing or malformed; one-line
     `MISSING: <which>` written to stderr.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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
# Parsing primitives (big-endian throughout — §6.1 / §14).
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """Raised on any wire-format violation."""


@dataclass
class Cursor:
    """Read-only positional cursor over a bytes buffer.

    Pure data class -- the helpers below are free functions that return
    a new (value, cursor) pair so the caller threads state explicitly.
    """

    buf: bytes
    pos: int = 0

    def remaining(self) -> int:
        return len(self.buf) - self.pos


def take(cur: Cursor, n: int, field: str) -> tuple[bytes, Cursor]:
    if cur.remaining() < n:
        raise ParseError(
            f"truncated reading {field}: need {n} bytes, "
            f"have {cur.remaining()} at offset {cur.pos}"
        )
    out = cur.buf[cur.pos:cur.pos + n]
    return out, Cursor(cur.buf, cur.pos + n)


def take_u16(cur: Cursor, field: str) -> tuple[int, Cursor]:
    raw, cur = take(cur, 2, field)
    return int.from_bytes(raw, "big"), cur


def take_u32(cur: Cursor, field: str) -> tuple[int, Cursor]:
    raw, cur = take(cur, 4, field)
    return int.from_bytes(raw, "big"), cur


def take_u64(cur: Cursor, field: str) -> tuple[int, Cursor]:
    raw, cur = take(cur, 8, field)
    return int.from_bytes(raw, "big"), cur


# ---------------------------------------------------------------------------
# §6.1 binary layout parser
# ---------------------------------------------------------------------------


@dataclass
class VectorClockEntry:
    device_uuid: bytes  # 16 bytes
    counter: int


@dataclass
class BlockHeader:
    magic: int
    format_version: int
    suite_id: int
    file_kind: int
    vault_uuid: bytes
    block_uuid: bytes
    created_at_ms: int
    last_mod_ms: int
    vector_clock: list[VectorClockEntry]


@dataclass
class RecipientEntry:
    fingerprint: bytes
    ct_x: bytes
    ct_pq: bytes
    nonce_w: bytes
    ct_w: bytes  # wrap_ct (32) || wrap_tag (16) on disk; concatenated here.


@dataclass
class AeadSection:
    nonce: bytes
    ct: bytes  # without trailing tag
    tag: bytes


@dataclass
class SignatureSuffix:
    author_fingerprint: bytes
    sig_ed: bytes
    sig_pq: bytes


@dataclass
class ParsedBlockFile:
    header: BlockHeader
    recipients: list[RecipientEntry]
    aead: AeadSection
    signature: SignatureSuffix


def parse_header(cur: Cursor) -> tuple[BlockHeader, Cursor]:
    """Parse §6.1 file header through end of vector_clock_entries."""
    magic, cur = take_u32(cur, "magic")
    if magic != MAGIC:
        raise ParseError(f"bad magic: got 0x{magic:08x}, expected 0x{MAGIC:08x}")

    format_version, cur = take_u16(cur, "format_version")
    if format_version != FORMAT_VERSION:
        raise ParseError(f"unsupported format_version: 0x{format_version:04x}")

    suite_id, cur = take_u16(cur, "suite_id")
    if suite_id != SUITE_ID:
        raise ParseError(f"unsupported suite_id: 0x{suite_id:04x}")

    file_kind, cur = take_u16(cur, "file_kind")
    if file_kind != FILE_KIND_BLOCK:
        raise ParseError(
            f"wrong file_kind: 0x{file_kind:04x}, expected block 0x{FILE_KIND_BLOCK:04x}"
        )

    vault_uuid, cur = take(cur, VAULT_UUID_LEN, "vault_uuid")
    block_uuid, cur = take(cur, BLOCK_UUID_LEN, "block_uuid")
    created_at_ms, cur = take_u64(cur, "created_at_ms")
    last_mod_ms, cur = take_u64(cur, "last_mod_ms")

    vc_count, cur = take_u16(cur, "vector_clock_count")
    vector_clock: list[VectorClockEntry] = []
    for i in range(vc_count):
        device_uuid, cur = take(cur, DEVICE_UUID_LEN, f"vector_clock[{i}].device_uuid")
        counter, cur = take_u64(cur, f"vector_clock[{i}].counter")
        vector_clock.append(VectorClockEntry(device_uuid=device_uuid, counter=counter))

    # §6.1 strict invariant: ascending lexicographic by device_uuid, no dups.
    for prev, nxt in zip(vector_clock, vector_clock[1:]):
        if prev.device_uuid >= nxt.device_uuid:
            raise ParseError("vector_clock entries not strictly ascending by device_uuid")

    header = BlockHeader(
        magic=magic,
        format_version=format_version,
        suite_id=suite_id,
        file_kind=file_kind,
        vault_uuid=vault_uuid,
        block_uuid=block_uuid,
        created_at_ms=created_at_ms,
        last_mod_ms=last_mod_ms,
        vector_clock=vector_clock,
    )
    return header, cur


def parse_recipient_entry(cur: Cursor, idx: int) -> tuple[RecipientEntry, Cursor]:
    fp, cur = take(cur, FINGERPRINT_LEN, f"recipients[{idx}].fingerprint")
    ct_x, cur = take(cur, X25519_PK_LEN, f"recipients[{idx}].ct_x")
    ct_pq, cur = take(cur, ML_KEM_768_CT_LEN, f"recipients[{idx}].ct_pq")
    nonce_w, cur = take(cur, WRAP_NONCE_LEN, f"recipients[{idx}].nonce_w")
    # §6.2 presents wrap_ct (32) and wrap_tag (16) as two separate rows,
    # but they are adjacent on the wire with no separator or length
    # prefix — read as one 48-byte block. The two-row presentation is
    # purely structural; the AEAD-decrypt step treats them as a single
    # ciphertext-with-tag value.
    ct_w, cur = take(cur, WRAP_CT_LEN + WRAP_TAG_LEN, f"recipients[{idx}].ct_w||tag")
    return (
        RecipientEntry(fingerprint=fp, ct_x=ct_x, ct_pq=ct_pq, nonce_w=nonce_w, ct_w=ct_w),
        cur,
    )


def parse_recipient_table(cur: Cursor) -> tuple[list[RecipientEntry], Cursor]:
    count, cur = take_u16(cur, "recipient_count")
    if count == 0:
        raise ParseError("§6.2: recipient_count must be non-zero (owner is always a recipient)")

    recipients: list[RecipientEntry] = []
    for i in range(count):
        entry, cur = parse_recipient_entry(cur, i)
        recipients.append(entry)

    # §6.2: ascending by fingerprint, no dups.
    for prev, nxt in zip(recipients, recipients[1:]):
        if prev.fingerprint >= nxt.fingerprint:
            raise ParseError("recipient_entries not strictly ascending by fingerprint")

    return recipients, cur


def parse_aead_section(cur: Cursor) -> tuple[AeadSection, Cursor]:
    nonce, cur = take(cur, AEAD_NONCE_LEN, "aead_nonce")
    ct_len, cur = take_u32(cur, "aead_ct_len")
    ct, cur = take(cur, ct_len, "aead_ct")
    tag, cur = take(cur, AEAD_TAG_LEN, "aead_tag")
    return AeadSection(nonce=nonce, ct=ct, tag=tag), cur


def parse_signature_suffix(cur: Cursor) -> tuple[SignatureSuffix, Cursor]:
    author, cur = take(cur, FINGERPRINT_LEN, "author_fingerprint")
    sig_ed_len, cur = take_u16(cur, "sig_ed_len")
    if sig_ed_len != ED25519_SIG_LEN:
        raise ParseError(
            f"sig_ed_len: got {sig_ed_len}, expected {ED25519_SIG_LEN} (§14)"
        )
    sig_ed, cur = take(cur, sig_ed_len, "sig_ed")
    sig_pq_len, cur = take_u16(cur, "sig_pq_len")
    if sig_pq_len != ML_DSA_65_SIG_LEN:
        raise ParseError(
            f"sig_pq_len: got {sig_pq_len}, expected {ML_DSA_65_SIG_LEN} (§14)"
        )
    sig_pq, cur = take(cur, sig_pq_len, "sig_pq")
    return (
        SignatureSuffix(author_fingerprint=author, sig_ed=sig_ed, sig_pq=sig_pq),
        cur,
    )


def parse_block_file(buf: bytes) -> ParsedBlockFile:
    cur = Cursor(buf=buf, pos=0)
    header, cur = parse_header(cur)
    recipients, cur = parse_recipient_table(cur)
    aead, cur = parse_aead_section(cur)
    sig, cur = parse_signature_suffix(cur)
    if cur.remaining() != 0:
        raise ParseError(
            f"trailing bytes after signature suffix: {cur.remaining()} bytes left"
        )
    return ParsedBlockFile(header=header, recipients=recipients, aead=aead, signature=sig)


# ---------------------------------------------------------------------------
# Vector-level cross-checks
# ---------------------------------------------------------------------------


@dataclass
class VectorReport:
    name: str
    ok: bool
    issues: list[str]


def check_vector(vector: dict) -> VectorReport:
    name = vector["name"]
    issues: list[str] = []

    inputs = vector["inputs"]
    expected = vector["expected"]

    # 1. The hex bytes parse cleanly.
    try:
        block_bytes = bytes.fromhex(expected["block_file"])
    except ValueError as e:
        return VectorReport(name=name, ok=False, issues=[f"block_file hex invalid: {e}"])

    # 2. size_bytes sentinel matches the actual byte count.
    declared_size = expected["size_bytes"]
    if declared_size != len(block_bytes):
        issues.append(
            f"size_bytes sentinel mismatch: declared={declared_size}, "
            f"actual={len(block_bytes)}"
        )

    # 3. Structural parse.
    try:
        parsed = parse_block_file(block_bytes)
    except ParseError as e:
        return VectorReport(
            name=name, ok=False, issues=issues + [f"structural parse failed: {e}"]
        )

    # 4. Cross-check against the JSON inputs.

    if parsed.header.vault_uuid.hex() != inputs["vault_uuid"]:
        issues.append(
            f"vault_uuid mismatch: parsed={parsed.header.vault_uuid.hex()}, "
            f"input={inputs['vault_uuid']}"
        )
    if parsed.header.block_uuid.hex() != inputs["block_uuid"]:
        issues.append(
            f"block_uuid mismatch: parsed={parsed.header.block_uuid.hex()}, "
            f"input={inputs['block_uuid']}"
        )
    if parsed.header.created_at_ms != inputs["created_at_ms"]:
        issues.append(
            f"created_at_ms mismatch: parsed={parsed.header.created_at_ms}, "
            f"input={inputs['created_at_ms']}"
        )
    if parsed.header.last_mod_ms != inputs["last_mod_ms"]:
        issues.append(
            f"last_mod_ms mismatch: parsed={parsed.header.last_mod_ms}, "
            f"input={inputs['last_mod_ms']}"
        )

    # 5. Vector clock: count + each entry.
    expected_vc = inputs["vector_clock"]
    if len(parsed.header.vector_clock) != len(expected_vc):
        issues.append(
            f"vector_clock length mismatch: parsed={len(parsed.header.vector_clock)}, "
            f"input={len(expected_vc)}"
        )
    else:
        # Encoder sorts by device_uuid before emission, so on-disk order may
        # differ from JSON-input order. Compare as sets keyed by device_uuid.
        expected_vc_by_dev = {e["device_uuid"]: e["counter"] for e in expected_vc}
        for entry in parsed.header.vector_clock:
            dev_hex = entry.device_uuid.hex()
            if dev_hex not in expected_vc_by_dev:
                issues.append(f"unexpected vector_clock device_uuid {dev_hex}")
            elif expected_vc_by_dev[dev_hex] != entry.counter:
                issues.append(
                    f"vector_clock[{dev_hex}] counter mismatch: "
                    f"parsed={entry.counter}, input={expected_vc_by_dev[dev_hex]}"
                )

    # 6. Recipient table: count and the (single, in this fixture)
    #    fingerprint matches the JSON's author_fingerprint (the
    #    self-recipient is the author).
    if len(parsed.recipients) != expected["recipients_count"]:
        issues.append(
            f"recipients_count mismatch: parsed={len(parsed.recipients)}, "
            f"expected={expected['recipients_count']}"
        )
    if len(parsed.recipients) >= 1:
        if parsed.recipients[0].fingerprint.hex() != inputs["author_fingerprint"]:
            issues.append(
                f"recipients[0].fingerprint mismatch: "
                f"parsed={parsed.recipients[0].fingerprint.hex()}, "
                f"input.author_fingerprint={inputs['author_fingerprint']}"
            )

    # 7. Author fingerprint in the signature suffix matches the JSON.
    if parsed.signature.author_fingerprint.hex() != inputs["author_fingerprint"]:
        issues.append(
            f"signature.author_fingerprint mismatch: "
            f"parsed={parsed.signature.author_fingerprint.hex()}, "
            f"input.author_fingerprint={inputs['author_fingerprint']}"
        )

    # 8. Signature lengths (both already enforced inside the parser, but
    #    repeat as positive cross-checks for clarity in failure reports).
    if len(parsed.signature.sig_ed) != ED25519_SIG_LEN:
        issues.append(f"sig_ed length: {len(parsed.signature.sig_ed)} (expected {ED25519_SIG_LEN})")
    if len(parsed.signature.sig_pq) != ML_DSA_65_SIG_LEN:
        issues.append(
            f"sig_pq length: {len(parsed.signature.sig_pq)} (expected {ML_DSA_65_SIG_LEN})"
        )

    return VectorReport(name=name, ok=not issues, issues=issues)


# ---------------------------------------------------------------------------
# Section 1 entry point (PR-A): block_kat.json structural conformance
# ---------------------------------------------------------------------------


def block_kat_path() -> Path:
    """Resolve `core/tests/data/block_kat.json` from this script's location."""
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "block_kat.json"


def load_json_fixture(path: Path, label: str) -> dict:
    if not path.is_file():
        print(f"MISSING: {label}: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"MISSING: {label} is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)


def section1_block_kat() -> tuple[bool, list[str]]:
    """Run the PR-A block_kat.json structural conformance vectors.

    Returns (ok, lines_to_print). Lines are printed regardless of
    pass/fail so a CI log keeps the per-vector breakdown.
    """
    fixture = load_json_fixture(block_kat_path(), "block_kat.json")

    lines: list[str] = []

    if fixture.get("version") != 1:
        return False, [
            f"FAIL: unsupported block_kat.json version {fixture.get('version')!r}"
        ]

    vectors = fixture.get("vectors", [])
    if not vectors:
        return False, ["FAIL: block_kat.json has no vectors"]

    all_ok = True
    for v in vectors:
        report = check_vector(v)
        if report.ok:
            lines.append(f"PASS  block_kat::{report.name}")
        else:
            all_ok = False
            lines.append(f"FAIL  block_kat::{report.name}")
            for issue in report.issues:
                lines.append(f"      - {issue}")

    if all_ok:
        lines.append(
            f"OK: block_kat.json - {len(vectors)} vector(s) parsed and cross-checked."
        )
    else:
        lines.append("FAIL: one or more block_kat.json vectors did not pass.")

    return all_ok, lines


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


# ---------------------------------------------------------------------------
# §2.1 Crypto primitives (thin wrappers over external libs)
# ---------------------------------------------------------------------------


def hkdf_sha256(salt: bytes, ikm: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA-256 extract-and-expand.

    Mirrors `crypto::kdf::hkdf_sha256_extract_and_expand` (kdf.rs:267).
    """
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    kdf = HKDF(algorithm=SHA256(), length=length, salt=salt, info=info)
    return kdf.derive(ikm)


def aead_decrypt(key: bytes, nonce: bytes, aad: bytes, ct_with_tag: bytes) -> bytes:
    """XChaCha20-Poly1305-IETF decrypt.

    `key` is 32 bytes, `nonce` is 24 bytes, `ct_with_tag` is
    `ct || tag(16)`. Mirrors `crypto::aead::decrypt` (aead.rs:96)
    which is what `crypto::kem::decap` and the manifest / block body
    AEAD calls use.

    Raises ValueError on auth-tag failure (the AEAD security model
    collapses every "wrong input" case into a single failure mode --
    same discipline as the Rust side's `AeadError::Decryption`).
    """
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
    from nacl.exceptions import CryptoError

    if len(key) != 32:
        raise ValueError(f"AEAD key length: {len(key)} (expected 32)")
    if len(nonce) != 24:
        raise ValueError(f"AEAD nonce length: {len(nonce)} (expected 24)")
    if len(ct_with_tag) < 16:
        raise ValueError("AEAD ct_with_tag shorter than 16-byte tag")
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(
            ct_with_tag, aad, nonce, key
        )
    except CryptoError as e:
        raise ValueError(f"AEAD decryption failed: {e}") from e


def x25519_dh(sk: bytes, pk: bytes) -> bytes:
    """X25519 Diffie-Hellman: scalar `sk` * point `pk`.

    Returns the 32-byte shared secret. `cryptography`'s X25519 API
    works on opaque key objects; we round-trip raw bytes so this
    function stays a pure transform.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    priv = X25519PrivateKey.from_private_bytes(sk)
    pub = X25519PublicKey.from_public_bytes(pk)
    return priv.exchange(pub)


def ml_kem_768_decap(sk: bytes, ct: bytes) -> bytes:
    """ML-KEM-768 decapsulation. Returns the 32-byte shared secret.

    The `pqcrypto` package names the operation `decrypt`/`encrypt`
    rather than `decap`/`encap`, but they're the FIPS-203 KEM ops --
    same construction as `core/src/crypto/kem.rs` calls via
    `ml_kem::kem::DecapsulationKey::decapsulate`.
    """
    from pqcrypto.kem import ml_kem_768

    return ml_kem_768.decrypt(sk, ct)


def ed25519_verify(pk: bytes, sig: bytes, message: bytes) -> bool:
    """Ed25519 verify. Returns True iff the signature is valid."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def ml_dsa_65_verify(pk: bytes, sig: bytes, message: bytes) -> bool:
    """ML-DSA-65 verify. Returns True iff the signature is valid.

    `pqcrypto.sign.ml_dsa_65.verify(public_key, message, signature)`
    returns True/False on a well-formed input pair (a tampered or
    invalid signature returns False — it does NOT raise), and raises
    `TypeError` / `ValueError` only when the inputs are mis-typed or
    wrong-length. The previous implementation discarded the return
    value and reported "no exception" as success, which silently
    accepted invalid signatures; the Ed25519 path is unaffected
    because `cryptography` raises `InvalidSignature` on bad sigs.

    We propagate the boolean and narrow the except to the two
    documented input-format exceptions, matching the Rust side's
    typed-error → bool collapse.
    """
    from pqcrypto.sign import ml_dsa_65

    try:
        return ml_dsa_65.verify(pk, message, sig)
    except (TypeError, ValueError):
        return False


def argon2id_raw(
    password: bytes,
    salt: bytes,
    *,
    memory_kib: int,
    iterations: int,
    parallelism: int,
    hash_len: int = 32,
) -> bytes:
    """Argon2id raw-hash wrapper.

    Mirrors `crypto::kdf::derive_master_kek` (kdf.rs:188): Argon2id
    algorithm, version 0x13 (1.3), output length `hash_len`. The
    parameter ordering matches `Argon2idParams` -- memory in KiB,
    iterations (= passes / time_cost), and parallelism (= lanes).
    """
    from argon2.low_level import Type, hash_secret_raw

    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=iterations,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=hash_len,
        type=Type.ID,
        version=0x13,
    )


def blake3_keyed_16(key: bytes, data: bytes) -> bytes:
    """BLAKE3-keyed-hash truncated to 16 bytes -- §6.1 fingerprint."""
    import blake3

    return blake3.blake3(data, key=key).digest(16)


def blake3_256(data: bytes) -> bytes:
    """BLAKE3-256 of `data`. §4.2 block fingerprint."""
    import blake3

    return blake3.blake3(data).digest(32)


# ---------------------------------------------------------------------------
# §2.2 Domain-specific helpers
# ---------------------------------------------------------------------------


def fingerprint_key() -> bytes:
    """The 32-byte BLAKE3-keyed-hash key used for §6.1 fingerprints.

    Mirrors `identity::fingerprint::fingerprint` (fingerprint.rs:45):
    `key = SHA-256(TAG_FINGERPRINT)`, truncated to 32 bytes. (SHA-256
    output IS 32 bytes, so the truncation is a no-op for SHA-256.)
    """
    return hashlib.sha256(TAG_FINGERPRINT).digest()


def card_fingerprint(canonical_card_bytes: bytes) -> bytes:
    """16-byte fingerprint of a fully-signed canonical-CBOR card."""
    return blake3_keyed_16(fingerprint_key(), canonical_card_bytes)


def compose_aad(tag: bytes, vault_uuid: bytes) -> bytes:
    """`tag || vault_uuid` -- the §3 / §5 AAD shape used by every
    identity-bundle AEAD call (`unlock::compose_aad`, mod.rs:279).
    """
    return tag + vault_uuid


def hybrid_kem_transcript(
    sender_fp: bytes,
    recipient_fp: bytes,
    ct_x: bytes,
    ct_pq: bytes,
) -> bytes:
    """§7 step 3 — BLAKE3 transcript hash binding both fingerprints
    and both ciphertexts.

    Mirrors `crypto::kem::transcript` (kem.rs:206): sequential update
    with TAG_HYBRID_KEM_TRANSCRIPT || sender_fp || recipient_fp ||
    ct_x || ct_pq.
    """
    import blake3

    h = blake3.blake3()
    h.update(TAG_HYBRID_KEM_TRANSCRIPT)
    h.update(sender_fp)
    h.update(recipient_fp)
    h.update(ct_x)
    h.update(ct_pq)
    return h.digest(32)


def derive_wrap_key(
    ss_x: bytes,
    ss_pq: bytes,
    ct_x: bytes,
    ct_pq: bytes,
    sender_pk_bundle: bytes,
    recipient_pk_bundle: bytes,
    transcript_hash: bytes,
) -> bytes:
    """§7 steps 4-5 — HKDF-SHA-256 over the §7 IKM ordering.

    Mirrors `crypto::kem::derive_wrap_key` (kem.rs:233-273) bit-for-bit.
    The Rust order is normative (see kem.rs:225-227):

        salt = TAG_HYBRID_KEM
        ikm  = ss_x || ss_pq || ct_x || ct_pq
                     || sender_pk_bundle || recipient_pk_bundle
        info = TAG_BLOCK_CONTENT_KEY_WRAP || transcript_hash

    """
    ikm = (
        ss_x
        + ss_pq
        + ct_x
        + ct_pq
        + sender_pk_bundle
        + recipient_pk_bundle
    )
    info = TAG_BLOCK_CONTENT_KEY_WRAP + transcript_hash
    return hkdf_sha256(TAG_HYBRID_KEM, ikm, info, 32)


def hybrid_decap(
    *,
    ct_x: bytes,
    ct_pq: bytes,
    nonce_w: bytes,
    ct_w_with_tag: bytes,
    sender_fp: bytes,
    recipient_fp: bytes,
    sender_pk_bundle: bytes,
    recipient_pk_bundle: bytes,
    recipient_x_sk: bytes,
    recipient_pq_sk: bytes,
    block_uuid: bytes,
) -> bytes:
    """§7.1 hybrid decap. Returns the recovered 32-byte BCK.

    Mirrors `crypto::kem::decap` (kem.rs:408-468) -- both halves
    independently, then HKDF-combiner, then AEAD-unwrap with the
    transcript-and-block-uuid AAD (`build_aead_aad`, kem.rs:314-320).
    """
    ss_x = x25519_dh(recipient_x_sk, ct_x)
    ss_pq = ml_kem_768_decap(recipient_pq_sk, ct_pq)
    t = hybrid_kem_transcript(sender_fp, recipient_fp, ct_x, ct_pq)
    wrap_key = derive_wrap_key(
        ss_x, ss_pq, ct_x, ct_pq, sender_pk_bundle, recipient_pk_bundle, t
    )
    aad = TAG_BLOCK_KEY_WRAP + block_uuid + t
    pt = aead_decrypt(wrap_key, nonce_w, aad, ct_w_with_tag)
    if len(pt) != BLOCK_CONTENT_KEY_LEN:
        raise ValueError(
            f"BCK plaintext length {len(pt)} != {BLOCK_CONTENT_KEY_LEN}"
        )
    return pt


def hybrid_verify(
    role_tag: bytes,
    message: bytes,
    sig_ed: bytes,
    sig_pq: bytes,
    pk_ed: bytes,
    pk_pq: bytes,
) -> tuple[bool, str]:
    """§8 hybrid verify. *Both* primitives must succeed.

    Returns (ok, reason). On failure, `reason` names which half
    rejected so the FAIL diagnostic is specific (mirrors the Rust
    side's distinct `Ed25519VerifyFailed` / `MlDsa65VerifyFailed`
    variants -- sig.rs:225-249).
    """
    signed_msg = role_tag + message
    if not ed25519_verify(pk_ed, sig_ed, signed_msg):
        return False, "Ed25519 verify rejected"
    if not ml_dsa_65_verify(pk_pq, sig_pq, signed_msg):
        return False, "ML-DSA-65 verify rejected"
    return True, ""


# ---------------------------------------------------------------------------
# §2.3 Canonical CBOR encoding helpers
# ---------------------------------------------------------------------------


def _canonical_key_sort(entries: list[tuple[Any, Any]]) -> list[tuple[Any, Any]]:
    """Sort `(key, value)` pairs by their canonical-CBOR-encoded key
    bytes. RFC 8949 §4.2.1 deterministic-encoding rule.
    """
    import cbor2

    return sorted(entries, key=lambda kv: cbor2.dumps(kv[0], canonical=True))


def encode_canonical_map(entries: list[tuple[Any, Any]]) -> bytes:
    """Encode `entries` as a canonical CBOR map.

    `cbor2.dumps(..., canonical=True)` already emits map keys sorted
    by their canonical encoded form for `dict` inputs, BUT we need to
    feed an *ordered* dict so equal keys never collide. We sort
    ourselves and then build a dict (Python 3.7+ preserves insertion
    order); cbor2 then walks that dict in order and emits the same
    bytes.
    """
    import cbor2

    sorted_entries = _canonical_key_sort(entries)
    d: dict[Any, Any] = {}
    for k, v in sorted_entries:
        if k in d:
            raise ValueError(f"duplicate canonical CBOR key: {k!r}")
        d[k] = v
    return cbor2.dumps(d, canonical=True)


def encode_pk_bundle(
    x25519_pk: bytes,
    ml_kem_768_pk: bytes,
    ed25519_pk: bytes,
    ml_dsa_65_pk: bytes,
) -> bytes:
    """Canonical-CBOR pk bundle as per `card::pk_bundle_bytes`
    (card.rs:228-249). Map with the four §6 pk-field text keys.
    """
    return encode_canonical_map(
        [
            ("x25519_pk", x25519_pk),
            ("ml_kem_768_pk", ml_kem_768_pk),
            ("ed25519_pk", ed25519_pk),
            ("ml_dsa_65_pk", ml_dsa_65_pk),
        ]
    )


# ---------------------------------------------------------------------------
# §2.4 Binary parsers (vault.toml, identity bundle, manifest)
# ---------------------------------------------------------------------------


@dataclass
class VaultToml:
    format_version: int
    suite_id: int
    vault_uuid: bytes  # 16 bytes
    created_at_ms: int
    kdf_memory_kib: int
    kdf_iterations: int
    kdf_parallelism: int
    kdf_salt: bytes  # 32 bytes


def parse_vault_toml(text: str) -> VaultToml:
    """Parse `vault.toml` per `docs/vault-format.md` §2."""
    data = tomllib.loads(text)
    if data.get("format_version") != 1:
        raise ParseError(f"vault.toml format_version {data.get('format_version')!r}")
    if data.get("suite_id") != 1:
        raise ParseError(f"vault.toml suite_id {data.get('suite_id')!r}")
    vault_uuid_str = data.get("vault_uuid")
    if not isinstance(vault_uuid_str, str):
        raise ParseError("vault.toml missing or wrong-typed vault_uuid")
    vault_uuid = bytes.fromhex(vault_uuid_str.replace("-", ""))
    if len(vault_uuid) != 16:
        raise ParseError(f"vault.toml vault_uuid byte length {len(vault_uuid)}")

    kdf = data.get("kdf") or {}
    if kdf.get("algorithm") != "argon2id":
        raise ParseError(f"vault.toml kdf.algorithm {kdf.get('algorithm')!r}")
    if kdf.get("version") != "1.3":
        raise ParseError(f"vault.toml kdf.version {kdf.get('version')!r}")

    salt_b64 = kdf.get("salt_b64")
    if not isinstance(salt_b64, str):
        raise ParseError("vault.toml kdf.salt_b64 missing")
    salt = base64.b64decode(salt_b64)
    if len(salt) != 32:
        raise ParseError(f"vault.toml kdf salt length {len(salt)} (expected 32)")

    return VaultToml(
        format_version=int(data["format_version"]),
        suite_id=int(data["suite_id"]),
        vault_uuid=vault_uuid,
        created_at_ms=int(data["created_at_ms"]),
        kdf_memory_kib=int(kdf["memory_kib"]),
        kdf_iterations=int(kdf["iterations"]),
        kdf_parallelism=int(kdf["parallelism"]),
        kdf_salt=salt,
    )


@dataclass
class IdentityBundleEnvelope:
    """Parsed shape of `identity.bundle.enc` (§3 / bundle_file.rs).

    We carry only the fields needed to derive the IBK -- this script
    does not unwrap the inner identity bundle CBOR.
    """

    vault_uuid: bytes
    created_at_ms: int
    wrap_pw_nonce: bytes  # 24
    wrap_pw_ct_with_tag: bytes  # 48
    wrap_rec_nonce: bytes
    wrap_rec_ct_with_tag: bytes
    bundle_nonce: bytes
    bundle_ct_with_tag: bytes  # variable


def parse_identity_bundle_envelope(buf: bytes) -> IdentityBundleEnvelope:
    """Parse the §3 identity.bundle.enc binary envelope.

    Field order from `unlock::bundle_file::decode` (bundle_file.rs:102).
    """
    cur = Cursor(buf=buf, pos=0)
    magic, cur = take_u32(cur, "magic")
    if magic != MAGIC:
        raise ParseError(f"identity.bundle.enc bad magic 0x{magic:08x}")
    fmt, cur = take_u16(cur, "format_version")
    if fmt != FORMAT_VERSION:
        raise ParseError(f"identity.bundle.enc format_version 0x{fmt:04x}")
    kind, cur = take_u16(cur, "file_kind")
    if kind != FILE_KIND_IDENTITY_BUNDLE:
        raise ParseError(f"identity.bundle.enc file_kind 0x{kind:04x}")
    vault_uuid, cur = take(cur, 16, "vault_uuid")
    created_at_ms, cur = take_u64(cur, "created_at_ms")

    # wrap_pw
    wrap_pw_nonce, cur = take(cur, 24, "wrap_pw_nonce")
    wrap_pw_len, cur = take_u32(cur, "wrap_pw_ct_len")
    if wrap_pw_len != 32:
        raise ParseError(f"wrap_pw_ct_len {wrap_pw_len} (expected 32)")
    wrap_pw_ct_with_tag, cur = take(cur, BUNDLE_WRAP_CT_PLUS_TAG_LEN, "wrap_pw_ct||tag")

    # wrap_rec
    wrap_rec_nonce, cur = take(cur, 24, "wrap_rec_nonce")
    wrap_rec_len, cur = take_u32(cur, "wrap_rec_ct_len")
    if wrap_rec_len != 32:
        raise ParseError(f"wrap_rec_ct_len {wrap_rec_len} (expected 32)")
    wrap_rec_ct_with_tag, cur = take(
        cur, BUNDLE_WRAP_CT_PLUS_TAG_LEN, "wrap_rec_ct||tag"
    )

    # bundle
    bundle_nonce, cur = take(cur, 24, "bundle_nonce")
    bundle_ct_len, cur = take_u32(cur, "bundle_ct_len")
    bundle_total = bundle_ct_len + 16  # tag is a separate §3 field, adjacent on wire
    bundle_ct_with_tag, cur = take(cur, bundle_total, "bundle_ct||tag")

    if cur.remaining() != 0:
        raise ParseError(
            f"identity.bundle.enc trailing {cur.remaining()} bytes after parse"
        )
    return IdentityBundleEnvelope(
        vault_uuid=vault_uuid,
        created_at_ms=created_at_ms,
        wrap_pw_nonce=wrap_pw_nonce,
        wrap_pw_ct_with_tag=wrap_pw_ct_with_tag,
        wrap_rec_nonce=wrap_rec_nonce,
        wrap_rec_ct_with_tag=wrap_rec_ct_with_tag,
        bundle_nonce=bundle_nonce,
        bundle_ct_with_tag=bundle_ct_with_tag,
    )


@dataclass
class ManifestFile:
    """Parsed §4.1 manifest envelope (mirrors
    `vault::manifest::ManifestFile`, manifest.rs:1354)."""

    vault_uuid: bytes
    created_at_ms: int
    last_mod_ms: int
    aead_nonce: bytes
    aead_ct: bytes  # without trailing tag
    aead_tag: bytes
    author_fingerprint: bytes
    sig_ed: bytes
    sig_pq: bytes
    raw_bytes: bytes  # full file bytes (kept for sign-range re-derivation)


# §4.1 manifest header is 42 bytes: magic(4)+fmt(2)+suite(2)+kind(2)
# +vault_uuid(16)+created_at_ms(8)+last_mod_ms(8). manifest.rs:1143.
MANIFEST_HEADER_LEN = 4 + 2 + 2 + 2 + 16 + 8 + 8


def parse_manifest_file(buf: bytes) -> ManifestFile:
    """Parse the §4.1 ManifestFile binary envelope."""
    cur = Cursor(buf=buf, pos=0)
    magic, cur = take_u32(cur, "manifest.magic")
    if magic != MAGIC:
        raise ParseError(f"manifest bad magic 0x{magic:08x}")
    fmt, cur = take_u16(cur, "manifest.format_version")
    if fmt != FORMAT_VERSION:
        raise ParseError(f"manifest format_version 0x{fmt:04x}")
    suite, cur = take_u16(cur, "manifest.suite_id")
    if suite != SUITE_ID:
        raise ParseError(f"manifest suite_id 0x{suite:04x}")
    kind, cur = take_u16(cur, "manifest.file_kind")
    if kind != FILE_KIND_MANIFEST:
        raise ParseError(
            f"manifest file_kind 0x{kind:04x} (expected 0x{FILE_KIND_MANIFEST:04x})"
        )
    vault_uuid, cur = take(cur, 16, "manifest.vault_uuid")
    created_at_ms, cur = take_u64(cur, "manifest.created_at_ms")
    last_mod_ms, cur = take_u64(cur, "manifest.last_mod_ms")

    aead_nonce, cur = take(cur, 24, "manifest.aead_nonce")
    aead_ct_len, cur = take_u32(cur, "manifest.aead_ct_len")
    aead_ct, cur = take(cur, aead_ct_len, "manifest.aead_ct")
    aead_tag, cur = take(cur, AEAD_TAG_LEN, "manifest.aead_tag")
    author_fingerprint, cur = take(cur, FINGERPRINT_LEN, "manifest.author_fingerprint")
    sig_ed_len, cur = take_u16(cur, "manifest.sig_ed_len")
    if sig_ed_len != ED25519_SIG_LEN:
        raise ParseError(f"manifest sig_ed_len {sig_ed_len}")
    sig_ed, cur = take(cur, sig_ed_len, "manifest.sig_ed")
    sig_pq_len, cur = take_u16(cur, "manifest.sig_pq_len")
    if sig_pq_len != ML_DSA_65_SIG_LEN:
        raise ParseError(f"manifest sig_pq_len {sig_pq_len}")
    sig_pq, cur = take(cur, sig_pq_len, "manifest.sig_pq")

    if cur.remaining() != 0:
        raise ParseError(f"manifest trailing {cur.remaining()} bytes")

    return ManifestFile(
        vault_uuid=vault_uuid,
        created_at_ms=created_at_ms,
        last_mod_ms=last_mod_ms,
        aead_nonce=aead_nonce,
        aead_ct=aead_ct,
        aead_tag=aead_tag,
        author_fingerprint=author_fingerprint,
        sig_ed=sig_ed,
        sig_pq=sig_pq,
        raw_bytes=buf,
    )


def manifest_signed_range(file: ManifestFile) -> bytes:
    """Bytes from `magic` through `aead_tag` inclusive (manifest.rs:1386).

    Re-derived from the on-disk shape: 42-byte header + 24-byte nonce
    + 4-byte ct_len + len(aead_ct) + 16-byte tag.
    """
    return file.raw_bytes[
        : MANIFEST_HEADER_LEN + 24 + 4 + len(file.aead_ct) + AEAD_TAG_LEN
    ]


def manifest_aead_aad(file: ManifestFile) -> bytes:
    """AAD for the manifest body AEAD: the 42-byte header
    (`manifest.rs:1294`)."""
    return file.raw_bytes[:MANIFEST_HEADER_LEN]


def block_signed_range(parsed: ParsedBlockFile, raw_bytes: bytes) -> bytes:
    """Bytes from `magic` through `aead_tag` inclusive (block.rs:1561).

    The block file lays out: header (variable, depends on vector_clock
    count) || recipient_table || aead_nonce(24) || aead_ct_len(4)
    || aead_ct(declared) || aead_tag(16) || sig suffix (variable).

    We compute the offset by length-summing what the parser saw rather
    than re-encoding -- that catches any drift between parse and
    re-encode at the field level.
    """
    # Header byte length: 4+2+2+2+16+16+8+8 + 2 + N*(16+8)
    header_len = (
        4 + 2 + 2 + 2 + 16 + 16 + 8 + 8 + 2 + len(parsed.header.vector_clock) * 24
    )
    # Recipient table: 2 (count) + N * 1208
    rt_len = 2 + len(parsed.recipients) * RECIPIENT_ENTRY_LEN
    # AEAD section: 24 + 4 + ct_len + 16
    aead_len = 24 + 4 + len(parsed.aead.ct) + AEAD_TAG_LEN
    return raw_bytes[: header_len + rt_len + aead_len]


def block_aead_aad(parsed: ParsedBlockFile, raw_bytes: bytes) -> bytes:
    """AAD for the block body AEAD: bytes from `magic` through end of
    recipient_entries (block.rs:1684, `build_body_aad`)."""
    header_len = (
        4 + 2 + 2 + 2 + 16 + 16 + 8 + 8 + 2 + len(parsed.header.vector_clock) * 24
    )
    rt_len = 2 + len(parsed.recipients) * RECIPIENT_ENTRY_LEN
    return raw_bytes[: header_len + rt_len]


# ---------------------------------------------------------------------------
# §2.5 Contact-card parse + verify
# ---------------------------------------------------------------------------


def parse_and_verify_card(card_bytes: bytes) -> dict[str, Any]:
    """Parse a canonical-CBOR Contact Card and verify its self-signature.

    Returns a dict carrying the parsed fields plus the recomputed
    16-byte fingerprint. Raises ParseError on any structural or
    cryptographic failure.
    """
    import cbor2

    try:
        decoded = cbor2.loads(card_bytes)
    except cbor2.CBORDecodeError as e:
        raise ParseError(f"card CBOR decode failed: {e}") from e
    if not isinstance(decoded, dict):
        raise ParseError("card top-level CBOR is not a map")

    required = {
        "card_version",
        "contact_uuid",
        "display_name",
        "x25519_pk",
        "ml_kem_768_pk",
        "ed25519_pk",
        "ml_dsa_65_pk",
        "created_at",
        "self_sig_ed",
        "self_sig_pq",
    }
    missing = required - set(decoded.keys())
    if missing:
        raise ParseError(f"card missing fields: {sorted(missing)}")
    if decoded["card_version"] != 1:
        raise ParseError(f"card_version {decoded['card_version']!r}")

    # Recompute the canonical bytes that the self-signature commits to
    # (§6 -- everything except the two self_sig_* fields).
    pre_sig_entries = [
        ("card_version", decoded["card_version"]),
        ("contact_uuid", decoded["contact_uuid"]),
        ("display_name", decoded["display_name"]),
        ("x25519_pk", decoded["x25519_pk"]),
        ("ml_kem_768_pk", decoded["ml_kem_768_pk"]),
        ("ed25519_pk", decoded["ed25519_pk"]),
        ("ml_dsa_65_pk", decoded["ml_dsa_65_pk"]),
        ("created_at", decoded["created_at"]),
    ]
    signed_bytes = encode_canonical_map(pre_sig_entries)

    ok, reason = hybrid_verify(
        TAG_CARD_SIG,
        signed_bytes,
        decoded["self_sig_ed"],
        decoded["self_sig_pq"],
        decoded["ed25519_pk"],
        decoded["ml_dsa_65_pk"],
    )
    if not ok:
        raise ParseError(f"card self-signature: {reason}")

    fp = card_fingerprint(card_bytes)
    return {
        "decoded": decoded,
        "fingerprint": fp,
        "pk_bundle": encode_pk_bundle(
            decoded["x25519_pk"],
            decoded["ml_kem_768_pk"],
            decoded["ed25519_pk"],
            decoded["ml_dsa_65_pk"],
        ),
    }


# ---------------------------------------------------------------------------
# §2.6 The full golden_vault_001 verification
# ---------------------------------------------------------------------------


def golden_vault_path() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "golden_vault_001"


def golden_vault_inputs_path() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "golden_vault_001_inputs.json"


def _require_file(path: Path, label: str) -> bytes:
    if not path.is_file():
        print(f"MISSING: {label}: {path}", file=sys.stderr)
        sys.exit(2)
    return path.read_bytes()


def verify_block_and_manifest(
    *,
    block_bytes: bytes,
    manifest_bytes: bytes,
    inputs: dict[str, Any],
    vt: VaultToml,
    bundle: IdentityBundleEnvelope,
    owner_card: dict[str, Any],
) -> tuple[bool, list[str]]:
    """Run the full hybrid-decap + AEAD-decrypt + hybrid-verify path
    on both files. Returns (ok, issues).

    Pure(-ish) function: takes already-loaded inputs/files, returns
    diagnostics. Easy to call again on tampered copies.
    """
    issues: list[str] = []

    # ----- Block file -----
    try:
        parsed_block = parse_block_file(block_bytes)
    except ParseError as e:
        return False, [f"block parse: {e}"]

    # 1. Recompute signed range and verify §8 hybrid signature.
    block_signed = block_signed_range(parsed_block, block_bytes)
    expected_signed_len = (
        len(block_bytes)
        - FINGERPRINT_LEN
        - 2
        - ED25519_SIG_LEN
        - 2
        - ML_DSA_65_SIG_LEN
    )
    if len(block_signed) != expected_signed_len:
        issues.append(
            f"block signed-range length: recomputed={len(block_signed)},"
            f" file-implied={expected_signed_len}"
        )

    ok, reason = hybrid_verify(
        TAG_BLOCK_SIG,
        block_signed,
        parsed_block.signature.sig_ed,
        parsed_block.signature.sig_pq,
        owner_card["decoded"]["ed25519_pk"],
        owner_card["decoded"]["ml_dsa_65_pk"],
    )
    if not ok:
        issues.append(f"block signature: {reason}")

    # 2. Owner is the only recipient on this fixture (§14 generator
    # output). Locate the owner's wrap entry and decap.
    owner_fp = owner_card["fingerprint"]
    owner_entry = None
    for e in parsed_block.recipients:
        if e.fingerprint == owner_fp:
            owner_entry = e
            break
    if owner_entry is None:
        issues.append("block recipient table missing owner entry")
        return False, issues

    sender_pk_bundle = owner_card["pk_bundle"]
    recipient_pk_bundle = owner_card["pk_bundle"]
    try:
        bck = hybrid_decap(
            ct_x=owner_entry.ct_x,
            ct_pq=owner_entry.ct_pq,
            nonce_w=owner_entry.nonce_w,
            ct_w_with_tag=owner_entry.ct_w,
            sender_fp=owner_fp,
            recipient_fp=owner_fp,
            sender_pk_bundle=sender_pk_bundle,
            recipient_pk_bundle=recipient_pk_bundle,
            recipient_x_sk=bytes.fromhex(inputs["owner"]["x25519_sk"]),
            recipient_pq_sk=bytes.fromhex(inputs["owner"]["ml_kem_768_sk"]),
            block_uuid=parsed_block.header.block_uuid,
        )
    except ValueError as e:
        issues.append(f"block hybrid-decap: {e}")
        return False, issues

    # 3. AEAD-decrypt block body.
    body_aad = block_aead_aad(parsed_block, block_bytes)
    body_ct_with_tag = parsed_block.aead.ct + parsed_block.aead.tag
    try:
        block_pt_bytes = aead_decrypt(
            bck, parsed_block.aead.nonce, body_aad, body_ct_with_tag
        )
    except ValueError as e:
        issues.append(f"block body AEAD: {e}")
        return False, issues

    # 4. Parse plaintext + cross-check records.
    import cbor2

    try:
        block_pt = cbor2.loads(block_pt_bytes)
    except cbor2.CBORDecodeError as e:
        issues.append(f"block plaintext CBOR decode: {e}")
        return False, issues

    expected_pt = inputs["block_plaintext"]
    if block_pt.get("block_version") != expected_pt["block_version"]:
        issues.append(
            f"block_version: parsed={block_pt.get('block_version')},"
            f" expected={expected_pt['block_version']}"
        )
    if block_pt.get("block_name") != expected_pt["block_name"]:
        issues.append(
            f"block_name: parsed={block_pt.get('block_name')!r},"
            f" expected={expected_pt['block_name']!r}"
        )
    if block_pt.get("schema_version") != expected_pt["schema_version"]:
        issues.append(
            f"schema_version: parsed={block_pt.get('schema_version')},"
            f" expected={expected_pt['schema_version']}"
        )

    parsed_records = block_pt.get("records") or []
    expected_records = expected_pt["records"]
    if len(parsed_records) != len(expected_records):
        issues.append(
            f"records count: parsed={len(parsed_records)},"
            f" expected={len(expected_records)}"
        )
    else:
        for i, (got, want) in enumerate(zip(parsed_records, expected_records)):
            got_uuid = got.get("record_uuid")
            want_uuid = bytes.fromhex(want["record_uuid"].replace("-", ""))
            if got_uuid != want_uuid:
                issues.append(
                    f"records[{i}].record_uuid: parsed={got_uuid!r},"
                    f" expected={want_uuid!r}"
                )
            if got.get("record_type") != want["record_type"]:
                issues.append(
                    f"records[{i}].record_type: parsed={got.get('record_type')!r},"
                    f" expected={want['record_type']!r}"
                )
            if got.get("tags", []) != want.get("tags", []):
                issues.append(
                    f"records[{i}].tags: parsed={got.get('tags')!r},"
                    f" expected={want.get('tags')!r}"
                )
            # tombstone is omitted on the wire when False; defensively
            # treat absent == False (matches block.rs:408-410).
            got_tomb = bool(got.get("tombstone", False))
            want_tomb = bool(want.get("tombstone", False))
            if got_tomb != want_tomb:
                issues.append(
                    f"records[{i}].tombstone: parsed={got_tomb}, expected={want_tomb}"
                )
            got_fields = got.get("fields") or {}
            want_fields = want.get("fields") or {}
            if set(got_fields.keys()) != set(want_fields.keys()):
                issues.append(
                    f"records[{i}].fields keys: parsed={sorted(got_fields)},"
                    f" expected={sorted(want_fields)}"
                )
            for fname, want_field in want_fields.items():
                got_field = got_fields.get(fname) or {}
                if want_field.get("value_type") == "text":
                    got_v = got_field.get("value")
                    want_v = want_field.get("value_text")
                    if got_v != want_v:
                        issues.append(
                            f"records[{i}].fields[{fname}].value:"
                            f" parsed={got_v!r}, expected={want_v!r}"
                        )

    # ----- Manifest file -----
    try:
        manifest = parse_manifest_file(manifest_bytes)
    except ParseError as e:
        issues.append(f"manifest parse: {e}")
        return False, issues

    # 5. Recompute manifest signed range; sanity-length-check.
    manifest_signed = manifest_signed_range(manifest)
    expected_msigned_len = (
        len(manifest_bytes)
        - FINGERPRINT_LEN
        - 2
        - ED25519_SIG_LEN
        - 2
        - ML_DSA_65_SIG_LEN
    )
    if len(manifest_signed) != expected_msigned_len:
        issues.append(
            f"manifest signed-range length: recomputed={len(manifest_signed)},"
            f" file-implied={expected_msigned_len}"
        )

    # 6. Manifest hybrid-verify.
    ok, reason = hybrid_verify(
        TAG_MANIFEST_SIG,
        manifest_signed,
        manifest.sig_ed,
        manifest.sig_pq,
        owner_card["decoded"]["ed25519_pk"],
        owner_card["decoded"]["ml_dsa_65_pk"],
    )
    if not ok:
        issues.append(f"manifest signature: {reason}")

    # 7. Derive master KEK from password+salt+params, unwrap IBK.
    password = inputs["password"].encode("utf-8")
    master_kek = argon2id_raw(
        password,
        vt.kdf_salt,
        memory_kib=vt.kdf_memory_kib,
        iterations=vt.kdf_iterations,
        parallelism=vt.kdf_parallelism,
    )
    try:
        ibk = aead_decrypt(
            master_kek,
            bundle.wrap_pw_nonce,
            compose_aad(TAG_ID_WRAP_PW, vt.vault_uuid),
            bundle.wrap_pw_ct_with_tag,
        )
    except ValueError as e:
        issues.append(f"IBK unwrap (wrap_pw): {e}")
        return False, issues
    if len(ibk) != 32:
        issues.append(f"IBK length: {len(ibk)} (expected 32)")
        return False, issues

    # 8. AEAD-decrypt manifest body.
    manifest_aad = manifest_aead_aad(manifest)
    manifest_ct_with_tag = manifest.aead_ct + manifest.aead_tag
    try:
        manifest_pt_bytes = aead_decrypt(
            ibk, manifest.aead_nonce, manifest_aad, manifest_ct_with_tag
        )
    except ValueError as e:
        issues.append(f"manifest body AEAD: {e}")
        return False, issues

    try:
        manifest_pt = cbor2.loads(manifest_pt_bytes)
    except cbor2.CBORDecodeError as e:
        issues.append(f"manifest plaintext CBOR decode: {e}")
        return False, issues

    # 9. Cross-check manifest body fields.
    expected_vault_uuid = bytes.fromhex(inputs["vault_uuid"].replace("-", ""))
    expected_block_uuid = bytes.fromhex(inputs["block_uuid"].replace("-", ""))
    expected_owner_uuid = bytes.fromhex(inputs["owner"]["user_uuid"].replace("-", ""))

    if manifest_pt.get("vault_uuid") != expected_vault_uuid:
        issues.append(
            f"manifest.vault_uuid: parsed={manifest_pt.get('vault_uuid')!r},"
            f" expected={expected_vault_uuid!r}"
        )
    if manifest_pt.get("owner_user_uuid") != expected_owner_uuid:
        issues.append(
            f"manifest.owner_user_uuid: parsed={manifest_pt.get('owner_user_uuid')!r},"
            f" expected={expected_owner_uuid!r}"
        )
    if manifest_pt.get("manifest_version") != 1:
        issues.append(
            f"manifest.manifest_version: parsed={manifest_pt.get('manifest_version')!r}"
        )

    blocks = manifest_pt.get("blocks") or []
    if len(blocks) != 1:
        issues.append(f"manifest.blocks count: parsed={len(blocks)} (expected 1)")
    else:
        b0 = blocks[0]
        if b0.get("block_uuid") != expected_block_uuid:
            issues.append(
                f"manifest.blocks[0].block_uuid: parsed={b0.get('block_uuid')!r},"
                f" expected={expected_block_uuid!r}"
            )
        actual_block_fp = blake3_256(block_bytes)
        if b0.get("fingerprint") != actual_block_fp:
            issues.append(
                f"manifest.blocks[0].fingerprint: parsed={b0.get('fingerprint')!r},"
                f" expected (BLAKE3-256 of block file)={actual_block_fp!r}"
            )
        # Recipients in the manifest are USER UUIDs (not card
        # fingerprints) -- block.rs:333-338 + manifest.rs:336-338.
        # The owner is the only recipient in this fixture.
        recipients = b0.get("recipients") or []
        if len(recipients) != 1 or recipients[0] != expected_owner_uuid:
            issues.append(
                f"manifest.blocks[0].recipients: parsed={recipients!r},"
                f" expected=[{expected_owner_uuid!r}]"
            )

    # KDF params should mirror vault.toml.
    kdf = manifest_pt.get("kdf_params") or {}
    if kdf.get("memory_kib") != vt.kdf_memory_kib:
        issues.append(
            f"manifest.kdf_params.memory_kib: parsed={kdf.get('memory_kib')},"
            f" expected={vt.kdf_memory_kib}"
        )
    if kdf.get("iterations") != vt.kdf_iterations:
        issues.append(
            f"manifest.kdf_params.iterations: parsed={kdf.get('iterations')},"
            f" expected={vt.kdf_iterations}"
        )
    if kdf.get("parallelism") != vt.kdf_parallelism:
        issues.append(
            f"manifest.kdf_params.parallelism: parsed={kdf.get('parallelism')},"
            f" expected={vt.kdf_parallelism}"
        )
    if kdf.get("salt") != vt.kdf_salt:
        issues.append(
            f"manifest.kdf_params.salt: parsed={kdf.get('salt')!r},"
            f" expected={vt.kdf_salt!r}"
        )

    return (not issues), issues


def section2_golden_vault_001() -> tuple[bool, list[str]]:
    """Run Task 15's full crypto verify against golden_vault_001.

    Returns (ok, lines). Loads every input fixture, runs the verify
    path, then re-runs against three tampered in-memory copies to
    confirm the verify path reliably rejects mutation.
    """
    lines: list[str] = []
    inputs = load_json_fixture(golden_vault_inputs_path(), "golden_vault_001_inputs.json")

    base = golden_vault_path()
    vault_toml_bytes = _require_file(base / "vault.toml", "golden_vault_001/vault.toml")
    bundle_bytes = _require_file(
        base / "identity.bundle.enc", "golden_vault_001/identity.bundle.enc"
    )
    manifest_bytes = _require_file(
        base / "manifest.cbor.enc", "golden_vault_001/manifest.cbor.enc"
    )
    block_uuid_str = inputs["block_uuid"]
    block_path = base / "blocks" / f"{block_uuid_str}.cbor.enc"
    block_bytes = _require_file(block_path, f"golden_vault_001/blocks/{block_uuid_str}.cbor.enc")

    # Parse vault.toml + identity bundle envelope (sanity-only on the
    # bundle envelope -- we don't decrypt the inner identity bundle).
    try:
        vt = parse_vault_toml(vault_toml_bytes.decode("utf-8"))
    except (ParseError, UnicodeDecodeError, KeyError) as e:
        return False, [f"FAIL: vault.toml parse: {e}"]
    expected_vault_uuid = bytes.fromhex(inputs["vault_uuid"].replace("-", ""))
    if vt.vault_uuid != expected_vault_uuid:
        return False, [
            f"FAIL: vault.toml.vault_uuid {vt.vault_uuid!r} != inputs {expected_vault_uuid!r}"
        ]

    try:
        bundle = parse_identity_bundle_envelope(bundle_bytes)
    except ParseError as e:
        return False, [f"FAIL: identity.bundle.enc parse: {e}"]
    if bundle.vault_uuid != vt.vault_uuid:
        return False, [
            f"FAIL: identity bundle vault_uuid {bundle.vault_uuid!r}"
            f" != vault.toml {vt.vault_uuid!r}"
        ]
    if bundle.created_at_ms != vt.created_at_ms:
        return False, [
            f"FAIL: identity bundle created_at_ms {bundle.created_at_ms}"
            f" != vault.toml {vt.created_at_ms}"
        ]

    # Parse and verify each contact card.
    owner_card: dict[str, Any] | None = None
    for card_path in sorted((base / "contacts").iterdir()):
        if not card_path.is_file() or card_path.suffix != ".card":
            continue
        try:
            card = parse_and_verify_card(card_path.read_bytes())
        except ParseError as e:
            return False, [f"FAIL: contact card {card_path.name}: {e}"]
        if card["decoded"]["contact_uuid"] == bytes.fromhex(
            inputs["owner"]["user_uuid"].replace("-", "")
        ):
            owner_card = card
        lines.append(
            f"PASS  card {card_path.name} (fp={card['fingerprint'].hex()})"
        )

    if owner_card is None:
        return False, lines + [
            f"FAIL: owner card not found in {base / 'contacts'}"
        ]

    # Cross-check the owner card's embedded keys against the JSON inputs.
    owner_inputs = inputs["owner"]
    if owner_card["decoded"]["x25519_pk"] != bytes.fromhex(owner_inputs["x25519_pk"]):
        return False, lines + ["FAIL: owner card x25519_pk != inputs"]
    if owner_card["decoded"]["ml_kem_768_pk"] != bytes.fromhex(owner_inputs["ml_kem_768_pk"]):
        return False, lines + ["FAIL: owner card ml_kem_768_pk != inputs"]
    if owner_card["decoded"]["ed25519_pk"] != bytes.fromhex(owner_inputs["ed25519_pk"]):
        return False, lines + ["FAIL: owner card ed25519_pk != inputs"]
    if owner_card["decoded"]["ml_dsa_65_pk"] != bytes.fromhex(owner_inputs["ml_dsa_65_pk"]):
        return False, lines + ["FAIL: owner card ml_dsa_65_pk != inputs"]

    # Full crypto verify on the original (untampered) files.
    ok, issues = verify_block_and_manifest(
        block_bytes=block_bytes,
        manifest_bytes=manifest_bytes,
        inputs=inputs,
        vt=vt,
        bundle=bundle,
        owner_card=owner_card,
    )
    if ok:
        lines.append("PASS  golden_vault_001 hybrid-decap + AEAD-decrypt + hybrid-verify")
    else:
        lines.append("FAIL  golden_vault_001 hybrid-decap + AEAD-decrypt + hybrid-verify")
        for i in issues:
            lines.append(f"      - {i}")
        return False, lines

    # Tamper checks: every mutation must trigger a FAIL.
    tamper_cases = [
        (
            "flip byte 100 of manifest.cbor.enc",
            _bytes_flip(manifest_bytes, 100),
            block_bytes,
        ),
        (
            "flip byte 200 of block.cbor.enc",
            manifest_bytes,
            _bytes_flip(block_bytes, 200),
        ),
        (
            "truncate manifest signature by 5 bytes",
            manifest_bytes[:-5],
            block_bytes,
        ),
    ]
    for label, tampered_manifest, tampered_block in tamper_cases:
        ok2, _issues = verify_block_and_manifest(
            block_bytes=tampered_block,
            manifest_bytes=tampered_manifest,
            inputs=inputs,
            vt=vt,
            bundle=bundle,
            owner_card=owner_card,
        )
        if ok2:
            lines.append(f"FAIL  tamper-check: {label} -- verify did NOT reject")
            return False, lines
        lines.append(f"PASS  tamper-check: {label} (verify rejected as expected)")

    return True, lines


def _bytes_flip(buf: bytes, idx: int) -> bytes:
    """Return a copy of `buf` with byte `idx` XOR'd with 0xFF."""
    if idx >= len(buf):
        # Wrap to the last byte if the buffer is short -- still a
        # mutation, still must trip verify.
        idx = len(buf) - 1
    out = bytearray(buf)
    out[idx] ^= 0xFF
    return bytes(out)


# ---------------------------------------------------------------------------
# Section 3: ml_dsa_65_verify helper — direct tamper-rejection regression
# ---------------------------------------------------------------------------
#
# `pqcrypto.sign.ml_dsa_65.verify` returns True/False on a well-formed
# input pair (it does NOT raise on a tampered or invalid signature),
# whereas `cryptography`'s Ed25519.verify raises `InvalidSignature`.
# A previous version of `ml_dsa_65_verify` discarded the boolean return
# and reported "no exception" as success, silently accepting tampered
# ML-DSA signatures. The Section 2 tamper cases happen to fail at AEAD
# or Ed25519 verify before reaching ML-DSA verify, so they did not
# detect the bug. This section exercises the helper directly so any
# future regression of the same shape (re-broaden the except, drop the
# `return`, etc.) trips an in-CI failure.


def section3_ml_dsa_65_verify_regression() -> tuple[bool, list[str]]:
    """Direct round-trip + tamper checks against `ml_dsa_65_verify`.

    Locks in the post-fix contract: verify returns True on a clean sig,
    False on a sig whose bytes have been flipped, and False when the
    message has been tampered. No golden fixtures needed -- the
    keypair / signature are generated fresh inside the test so the
    suite stays deterministic against `pqcrypto`'s own keygen.
    """
    from pqcrypto.sign import ml_dsa_65

    lines: list[str] = []
    pk, sk = ml_dsa_65.generate_keypair()
    message = b"secretary-conformance ml_dsa_65 verify regression"
    sig = ml_dsa_65.sign(sk, message)

    if not ml_dsa_65_verify(pk, sig, message):
        lines.append("FAIL  ml_dsa_65_verify rejected a valid signature")
        return False, lines
    lines.append("PASS  ml_dsa_65_verify accepts a valid signature")

    tampered_sig = _bytes_flip(sig, len(sig) // 2)
    if ml_dsa_65_verify(pk, tampered_sig, message):
        lines.append(
            "FAIL  ml_dsa_65_verify accepted a tampered signature "
            "(silent-accept regression)"
        )
        return False, lines
    lines.append("PASS  ml_dsa_65_verify rejects a tampered signature")

    tampered_message = _bytes_flip(message, 0)
    if ml_dsa_65_verify(pk, sig, tampered_message):
        lines.append(
            "FAIL  ml_dsa_65_verify accepted a tampered message "
            "(silent-accept regression)"
        )
        return False, lines
    lines.append("PASS  ml_dsa_65_verify rejects a tampered message")

    return True, lines


# ---------------------------------------------------------------------------
# Section 4: conflict_kat.json — CRDT merge cross-language replay
# ---------------------------------------------------------------------------
#
# Implements crypto-design.md §11 (per-record / per-block CRDT merge) from
# the spec docs only and replays each KAT vector through the Python
# implementation, asserting bit-equal output against the JSON's `expected`.
#
# This is the §15 cross-language conformance witness for Phase A.6 / PR-C.
# A reader should be able to implement this section from §11 alone without
# consulting any Rust source. Tombstone interactions are exercised by the
# inline Rust unit tests + Rust integration tests; this section focuses on
# the four ClockRelation branches and the field-collision surface.


def conflict_kat_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "conflict_kat.json"


# §11 — clock_relation {Equal, IncomingDominates, IncomingDominated, Concurrent}.

def py_clock_relation(local: list[dict], incoming: list[dict]) -> str:
    """Component-wise comparison of two vector clocks. Missing device =
    counter 0. Returns "Equal", "IncomingDominates", "IncomingDominated",
    or "Concurrent" per §10 / §11."""
    counters: dict[bytes, list[int]] = {}
    for e in local:
        counters.setdefault(bytes.fromhex(e["device_uuid_hex"]), [0, 0])[0] = e["counter"]
    for e in incoming:
        counters.setdefault(bytes.fromhex(e["device_uuid_hex"]), [0, 0])[1] = e["counter"]
    local_greater = False
    incoming_greater = False
    for l, i in counters.values():
        if l > i:
            local_greater = True
        elif i > l:
            incoming_greater = True
        if local_greater and incoming_greater:
            return "Concurrent"
    if not local_greater and not incoming_greater:
        return "Equal"
    if incoming_greater:
        return "IncomingDominates"
    return "IncomingDominated"


def py_merge_vector_clocks(a: list[dict], b: list[dict]) -> list[dict]:
    """Component-wise max. Output sorted ascending by device_uuid bytes."""
    counters: dict[bytes, int] = {}
    for e in list(a) + list(b):
        d = bytes.fromhex(e["device_uuid_hex"])
        counters[d] = max(counters.get(d, 0), e["counter"])
    return [
        {"device_uuid_hex": d.hex(), "counter": c}
        for d, c in sorted(counters.items())
    ]


def py_tick_for_device(clock: list[dict], device_hex: str) -> list[dict]:
    """`+1` for `device_hex`; insert a fresh entry at counter 1 when
    absent. Output sorted ascending by device_uuid."""
    out = [dict(e) for e in clock]
    found = False
    for entry in out:
        if entry["device_uuid_hex"] == device_hex:
            entry["counter"] += 1
            found = True
            break
    if not found:
        out.append({"device_uuid_hex": device_hex, "counter": 1})
    out.sort(key=lambda e: bytes.fromhex(e["device_uuid_hex"]))
    return out


# §11.1 — per-record metadata and field merges.

def py_lww_picks_local_field(l: dict, r: dict) -> bool:
    """Return True iff the local field beats the remote per §11
    pseudocode: greater last_mod wins; on tie, smaller device_uuid
    wins; on full tie (different value), lex-larger value bytes wins."""
    if l["last_mod"] != r["last_mod"]:
        return l["last_mod"] > r["last_mod"]
    l_dev = bytes.fromhex(l["device_uuid_hex"])
    r_dev = bytes.fromhex(r["device_uuid_hex"])
    if l_dev != r_dev:
        return l_dev < r_dev
    return _value_lex_bytes(l) >= _value_lex_bytes(r)


def _value_lex_bytes(field: dict) -> bytes:
    """Same prefix-tag scheme as the Rust impl: 0x00 for Text, 0x01 for
    Bytes, then the raw content bytes. Used only as the malformed-input
    full-tie tiebreaker."""
    if field["value_type"] == "text":
        return b"\x00" + field["value_text"].encode("utf-8")
    if field["value_type"] == "bytes":
        return b"\x01" + bytes.fromhex(field["value_hex"])
    raise ValueError(f"unknown value_type: {field['value_type']}")


def py_merge_unknown_map(local_unk: dict, remote_unk: dict) -> dict:
    """Per-key forward-compat unknown merge per §11.1 (record-level)
    and §11.2 (block-level — same rule).

    A key present in only one side is kept verbatim. A key present in
    both with identical values is kept once. A key present in both
    with differing values takes the lex-larger canonical-CBOR-encoded
    value bytes.

    The KAT carries each value as a hex string of canonical-CBOR
    bytes (`unknown_hex: {key: "0a"}`). Rust's KAT loader decodes
    hex via `u8::from_str_radix(_, 16)` which is case-insensitive,
    so `"0A"` and `"0a"` both decode to byte `0x0a`. Raw lex compare
    on hex strings does NOT match byte compare across mixed case
    (e.g. `"a5"` vs `"B5"`: `'a' (0x61) > 'B' (0x42)` says L wins,
    but byte `0xb5 > 0xa5` says R wins). We decode each side to
    bytes for comparison and re-emit lowercase hex on output, so
    Python and Rust agree on every (case-permuted) input.
    """
    out: dict[str, str] = {}
    all_keys = set(local_unk.keys()) | set(remote_unk.keys())
    for key in sorted(all_keys):
        l_hex = local_unk.get(key)
        r_hex = remote_unk.get(key)
        if l_hex is not None and r_hex is not None:
            l_bytes = bytes.fromhex(l_hex)
            r_bytes = bytes.fromhex(r_hex)
            if l_bytes >= r_bytes:
                out[key] = l_bytes.hex()
            else:
                out[key] = r_bytes.hex()
        elif l_hex is not None:
            out[key] = bytes.fromhex(l_hex).hex()
        else:
            out[key] = bytes.fromhex(r_hex).hex()  # type: ignore[arg-type]
    return out


def py_clamp_death_clock(rec: dict) -> int:
    """Canonicalise a record's `tombstoned_at_ms` to the §11.5 invariant
    before the lattice join in `py_merge_record`. Mirrors Rust's
    `clamp_death_clock` in `core/src/vault/conflict.rs`.

    Returns `tombstoned_at_ms` clamped to `[0, last_mod_ms]`. For
    tombstoned inputs (`tombstone == true`), additionally enforces
    equality with `last_mod_ms` per §11.5: a currently-tombstoned
    record was tombstoned at its most recent edit. The two clamps
    collapse to the same `last_mod_ms` value on tombstoned inputs.

    Two malformations are defended against:

    * Tombstoned input with `tombstoned_at_ms != last_mod_ms`:
      violates `tombstone == true ⇒ tombstoned_at_ms == last_mod_ms`.
      Inflated DC propagates through merge; lowered DC suppresses
      the death clock's advance and lets pre-tombstone stale fields
      slip through the §11.3 staleness filter.
    * Live input with `tombstoned_at_ms > last_mod_ms`: violates
      `tombstoned_at_ms ≤ last_mod_ms`. With `tombstoned_at_ms =
      2**64 - 1` the merged DC would clamp every field with
      `last_mod < 2**64 - 1`, wiping the merged record's fields
      while keeping it live — a deniable data-loss attack from a
      hostile sync peer.

    No-op on well-formed inputs. Pure function of one record.
    """
    if rec["tombstone"]:
        return rec["last_mod_ms"]
    return min(rec.get("tombstoned_at_ms", 0), rec["last_mod_ms"])


def py_merge_record(local: dict, remote: dict) -> tuple[dict, list[dict]]:
    """Merge two records with the same record_uuid per §11. Returns the
    merged record dict and the list of field collisions (in sorted
    field_name order). Tombstone interactions follow §11.3.

    Per §11.3 the merge propagates a death clock
    (`tombstoned_at_ms = max(local, remote)`) and applies a staleness
    filter that drops fields with `last_mod ≤ death_clock`. The filter
    is the bit that makes the merge associative under arbitrary
    tombstone histories. `tombstoned_at_ms == 0` is the sentinel for
    "no tombstone observation"; in that case no filter applies."""
    # §11.3 tombstone tie-break.
    l_t, r_t = local["tombstone"], remote["tombstone"]
    if l_t and r_t:
        outcome = "BothTombstoned"
    elif not l_t and not r_t:
        outcome = "BothLive"
    elif l_t and not r_t:
        outcome = (
            "LocalTombstoneWins" if local["last_mod_ms"] >= remote["last_mod_ms"]
            else "LocalTombstoneLost"
        )
    else:
        outcome = (
            "RemoteTombstoneWins" if remote["last_mod_ms"] >= local["last_mod_ms"]
            else "RemoteTombstoneLost"
        )

    tombstone = outcome in ("BothTombstoned", "LocalTombstoneWins", "RemoteTombstoneWins")

    # Defensive clamp: enforce the §11.5 invariants on each input
    # before the lattice join. See `py_clamp_death_clock` (module
    # scope) for the rationale and the threat model.
    local_dc = py_clamp_death_clock(local)
    remote_dc = py_clamp_death_clock(remote)
    # §11.3 death clock: lattice join via max.
    death = max(local_dc, remote_dc)

    # §11.3 staleness predicate: a field is alive iff there's no death
    # observation (death_clock == 0) or its last_mod is strictly later.
    def alive(f: dict) -> bool:
        return death == 0 or f["last_mod"] > death

    # Field merge: tombstoned outcomes have empty fields per §6.3 / §11.3.
    fields: list[dict] = []
    collisions: list[dict] = []
    if not tombstone:
        # Apply LWW with the staleness filter uniformly across the
        # field union. The filter subsumes the previous
        # LocalTombstoneLost / RemoteTombstoneLost special cases:
        # a tombstoned side's "kept-for-undelete" fields all have
        # `last_mod ≤ tombstoned_at_ms = last_mod_ms ≤ death`, so
        # they are filtered out naturally.
        l_fields = {f["name"]: f for f in local["fields"]}
        r_fields = {f["name"]: f for f in remote["fields"]}
        for name in sorted(set(l_fields) | set(r_fields)):
            l = l_fields.get(name)
            r = r_fields.get(name)
            l_alive = l is not None and alive(l)
            r_alive = r is not None and alive(r)
            if not l_alive and not r_alive:
                continue
            if l_alive and not r_alive:
                merged_field = dict(l)
                merged_field["name"] = name
                fields.append(merged_field)
                continue
            if not l_alive and r_alive:
                merged_field = dict(r)
                merged_field["name"] = name
                fields.append(merged_field)
                continue
            # Both alive: per-field LWW + collision detection.
            pick_local = py_lww_picks_local_field(l, r)
            winner = l if pick_local else r
            loser = r if pick_local else l
            if l.get("value_type") != r.get("value_type") or l.get(
                "value_text", l.get("value_hex")
            ) != r.get("value_text", r.get("value_hex")):
                collisions.append(
                    {"field_name": name, "winner": winner, "loser": loser}
                )
            merged_field = dict(winner)
            merged_field["name"] = name
            fields.append(merged_field)

    # §11.3 identity-metadata override on tombstoning-wins outcomes:
    # record_type comes wholesale from the tombstoning side. Otherwise
    # §11.1 LWW: greater last_mod_ms wins; lex-larger UTF-8 on tie.
    if outcome == "LocalTombstoneWins":
        record_type = local["record_type"]
    elif outcome == "RemoteTombstoneWins":
        record_type = remote["record_type"]
    elif local["last_mod_ms"] > remote["last_mod_ms"]:
        record_type = local["record_type"]
    elif remote["last_mod_ms"] > local["last_mod_ms"]:
        record_type = remote["record_type"]
    elif local["record_type"].encode("utf-8") >= remote["record_type"].encode("utf-8"):
        record_type = local["record_type"]
    else:
        record_type = remote["record_type"]

    # tags: §11.3 mixed-tombstone override → tombstoning side wins; else
    # §11.1 (greater last_mod_ms; set union on tie).
    #
    # Output is always sorted+deduped per §11.5: even on the LWW-clone
    # branches, the merge canonicalises the chosen side's tags so that
    # self-merging the merged record is a fixed point (mirrors Rust
    # merge_tags).
    if outcome == "LocalTombstoneWins" or outcome == "RemoteTombstoneLost":
        source = local["tags"]
    elif outcome == "RemoteTombstoneWins" or outcome == "LocalTombstoneLost":
        source = remote["tags"]
    elif local["last_mod_ms"] > remote["last_mod_ms"]:
        source = local["tags"]
    elif remote["last_mod_ms"] > local["last_mod_ms"]:
        source = remote["tags"]
    else:
        # §11.1 set union of both sides on tie.
        source = list(set(local["tags"]) | set(remote["tags"]))
    # Canonicalise: sort + dedup.
    tags = sorted(set(source))

    # Record-level `unknown` merge per §11.1: per-key lattice join
    # (lex-larger canonical-CBOR bytes on collisions, single-side
    # preservation) on every outcome. Not subject to the §11.3
    # identity-metadata override — see the §11.3 carve-out and the
    # rationale at the override site in `core/src/vault/conflict.rs`.
    local_unknown = local.get("unknown_hex", {})
    remote_unknown = remote.get("unknown_hex", {})
    unknown = py_merge_unknown_map(local_unknown, remote_unknown)

    merged = {
        "record_uuid_hex": local["record_uuid_hex"],
        "record_type": record_type,
        "fields": fields,
        "tags": tags,
        "created_at_ms": min(local["created_at_ms"], remote["created_at_ms"]),
        "last_mod_ms": max(local["last_mod_ms"], remote["last_mod_ms"]),
        "tombstone": tombstone,
        "tombstoned_at_ms": death,
        "unknown_hex": unknown,
    }
    return merged, collisions


def py_merge_block(
    local_block: dict,
    local_clock: list[dict],
    remote_block: dict,
    remote_clock: list[dict],
    merging_device_hex: str,
) -> dict:
    """Per §11.2 — dispatch on clock_relation and emit a merged block
    plaintext + clock + relation + per-record collision list."""
    if local_block["block_uuid_hex"] != remote_block["block_uuid_hex"]:
        raise ValueError(
            f"block_uuid mismatch: local {local_block['block_uuid_hex']!r}, "
            f"remote {remote_block['block_uuid_hex']!r}"
        )

    relation = py_clock_relation(local_clock, remote_clock)

    if relation == "Equal":
        return {
            "relation": "Equal",
            "block": local_block,
            "vector_clock": list(local_clock),
            "collisions": [],
        }
    if relation == "IncomingDominates":
        return {
            "relation": "IncomingDominates",
            "block": remote_block,
            "vector_clock": list(remote_clock),
            "collisions": [],
        }
    if relation == "IncomingDominated":
        return {
            "relation": "IncomingDominated",
            "block": local_block,
            "vector_clock": list(local_clock),
            "collisions": [],
        }
    # Concurrent: union by record_uuid + per-record merge.
    l_recs = {r["record_uuid_hex"]: r for r in local_block["records"]}
    r_recs = {r["record_uuid_hex"]: r for r in remote_block["records"]}
    all_uuids = sorted(set(l_recs) | set(r_recs), key=bytes.fromhex)
    merged_records: list[dict] = []
    record_collisions: list[dict] = []
    for uuid in all_uuids:
        l = l_recs.get(uuid)
        r = r_recs.get(uuid)
        if l is not None and r is not None:
            merged, fcs = py_merge_record(l, r)
            if fcs:
                record_collisions.append(
                    {"record_uuid_hex": uuid, "field_collisions": fcs}
                )
            merged_records.append(merged)
        elif l is not None:
            merged_records.append(l)
        else:
            merged_records.append(r)

    merged_clock = py_merge_vector_clocks(local_clock, remote_clock)
    merged_clock = py_tick_for_device(merged_clock, merging_device_hex)
    merged_block = {
        "block_version": max(local_block["block_version"], remote_block["block_version"]),
        "block_uuid_hex": local_block["block_uuid_hex"],
        "block_name": local_block["block_name"]
        if local_block["block_name"].encode("utf-8")
        >= remote_block["block_name"].encode("utf-8")
        else remote_block["block_name"],
        "schema_version": max(local_block["schema_version"], remote_block["schema_version"]),
        "records": merged_records,
        # §11.2 forward-compat: same per-key lex-larger rule as
        # record-level (§11.1). No tombstone semantics at block level,
        # so no override.
        "unknown_hex": py_merge_unknown_map(
            local_block.get("unknown_hex", {}),
            remote_block.get("unknown_hex", {}),
        ),
    }
    return {
        "relation": "Concurrent",
        "block": merged_block,
        "vector_clock": merged_clock,
        "collisions": record_collisions,
    }


def _normalise_record(r: dict) -> dict:
    """Trim a record dict to the comparison keys used by the KAT
    `expected.block.records[*]` shape — strip per-field `name` to match
    the JSON's name-keyed-array layout."""
    fields = []
    for f in r["fields"]:
        nf = {
            "name": f["name"],
            "value_type": f["value_type"],
            "last_mod": f["last_mod"],
            "device_uuid_hex": f["device_uuid_hex"],
        }
        if "value_text" in f:
            nf["value_text"] = f["value_text"]
        if "value_hex" in f:
            nf["value_hex"] = f["value_hex"]
        fields.append(nf)
    return {
        "record_uuid_hex": r["record_uuid_hex"],
        "record_type": r["record_type"],
        "fields": fields,
        "tags": list(r["tags"]),
        "created_at_ms": r["created_at_ms"],
        "last_mod_ms": r["last_mod_ms"],
        "tombstone": r["tombstone"],
        "tombstoned_at_ms": r.get("tombstoned_at_ms", 0),
        # Record-level forward-compat unknown keys (canonical-CBOR
        # bytes encoded as hex). Absent in the JSON → empty dict.
        "unknown_hex": dict(r.get("unknown_hex", {})),
    }


def _normalise_block(b: dict) -> dict:
    return {
        "block_version": b["block_version"],
        "block_uuid_hex": b["block_uuid_hex"],
        "block_name": b["block_name"],
        "schema_version": b["schema_version"],
        "records": [_normalise_record(r) for r in b["records"]],
        # Block-level forward-compat unknown keys.
        "unknown_hex": dict(b.get("unknown_hex", {})),
    }


def section4_conflict_kat() -> tuple[bool, list[str]]:
    lines: list[str] = []
    path = conflict_kat_path()
    if not path.exists():
        print(f"MISSING: conflict_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "conflict_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        lines.append(f"FAIL  conflict_kat.json version={kat.get('version')}, expected 1")
        return False, lines
    vectors = kat.get("vectors") or []
    if not vectors:
        lines.append("FAIL  conflict_kat.json has no vectors")
        return False, lines

    all_ok = True
    for vector in vectors:
        name = vector["name"]
        local_block = vector["local"]["block"]
        local_clock = vector["local"]["vector_clock"]
        remote_block = vector["remote"]["block"]
        remote_clock = vector["remote"]["vector_clock"]
        merging_device_hex = vector["merging_device_hex"]
        expected = vector["expected"]

        try:
            got = py_merge_block(
                local_block, local_clock, remote_block, remote_clock, merging_device_hex
            )
        except Exception as exc:
            lines.append(f"FAIL  vector {name!r}: merge raised {exc!r}")
            all_ok = False
            continue

        if got["relation"] != expected["relation"]:
            lines.append(
                f"FAIL  vector {name!r}: relation got {got['relation']}, "
                f"expected {expected['relation']}"
            )
            all_ok = False
            continue

        got_block = _normalise_block(got["block"])
        expected_block = _normalise_block(expected["block"])
        if got_block != expected_block:
            lines.append(f"FAIL  vector {name!r}: merged block plaintext mismatch")
            lines.append(f"  got:      {json.dumps(got_block, sort_keys=True)}")
            lines.append(f"  expected: {json.dumps(expected_block, sort_keys=True)}")
            all_ok = False
            continue

        if got["vector_clock"] != expected["vector_clock"]:
            lines.append(f"FAIL  vector {name!r}: merged vector clock mismatch")
            lines.append(f"  got:      {got['vector_clock']}")
            lines.append(f"  expected: {expected['vector_clock']}")
            all_ok = False
            continue

        if len(got["collisions"]) != len(expected["collisions"]):
            lines.append(
                f"FAIL  vector {name!r}: collision count got "
                f"{len(got['collisions'])}, expected {len(expected['collisions'])}"
            )
            all_ok = False
            continue

        collisions_ok = True
        for g, e in zip(got["collisions"], expected["collisions"]):
            if g["record_uuid_hex"] != e["record_uuid_hex"]:
                lines.append(
                    f"FAIL  vector {name!r}: collision record_uuid mismatch "
                    f"{g['record_uuid_hex']!r} vs {e['record_uuid_hex']!r}"
                )
                collisions_ok = False
                break
            if len(g["field_collisions"]) != len(e["field_collisions"]):
                lines.append(
                    f"FAIL  vector {name!r}: field collision count mismatch"
                )
                collisions_ok = False
                break
            for gfc, efc in zip(g["field_collisions"], e["field_collisions"]):
                if gfc["field_name"] != efc["field_name"]:
                    lines.append(
                        f"FAIL  vector {name!r}: collision field_name "
                        f"{gfc['field_name']!r} vs {efc['field_name']!r}"
                    )
                    collisions_ok = False
                    break
                # Strip 'name' from winner/loser to match the KAT expected shape.
                got_w = {k: v for k, v in gfc["winner"].items() if k != "name"}
                got_l = {k: v for k, v in gfc["loser"].items() if k != "name"}
                if got_w != efc["winner"]:
                    lines.append(f"FAIL  vector {name!r}: collision winner mismatch")
                    lines.append(f"  got:      {got_w}")
                    lines.append(f"  expected: {efc['winner']}")
                    collisions_ok = False
                    break
                if got_l != efc["loser"]:
                    lines.append(f"FAIL  vector {name!r}: collision loser mismatch")
                    lines.append(f"  got:      {got_l}")
                    lines.append(f"  expected: {efc['loser']}")
                    collisions_ok = False
                    break
        if not collisions_ok:
            all_ok = False
            continue

        lines.append(f"PASS  conflict_kat.json {name!r}: {expected['relation']}")

    return all_ok, lines


# ---------------------------------------------------------------------------
# Section 5 — py_merge_unknown_map case-insensitivity self-tests
# ---------------------------------------------------------------------------


def section5_unknown_map_case_insensitivity() -> tuple[bool, list[str]]:
    """Cross-language drift guard for `py_merge_unknown_map`.

    The KAT carries each unknown-map value as a hex string of canonical-CBOR
    bytes (`"unknown_hex": {key: "0a"}`). Rust's KAT loader decodes hex via
    `u8::from_str_radix(_, 16)`, which is case-insensitive — so `"0A"` and
    `"0a"` both decode to byte `0x0a`. Python's `py_merge_unknown_map` must
    agree; otherwise a future KAT vector authored with uppercase or mixed
    hex would silently disagree across the two clean-room implementations.

    The cross-case adversarial pairing is `0xa5` (lowercase `"a5"`) vs
    `0xb5` (uppercase `"B5"`):
      * byte compare: `0xb5 > 0xa5` → R wins.
      * raw string compare: `'a' (0x61) > 'B' (0x42)` → would pick L,
        contradicting the byte order. The merge must not be raw-string
        compare.

    The same-bytes-different-case pair `("ff", "FF")` exercises the
    equality path: byte-equal inputs must be treated as equal, not as
    differing → collision branch.
    """
    lines: list[str] = []
    all_ok = True

    # 1. Cross-case adversarial: 0xa5 (lowercase) vs 0xb5 (uppercase).
    #    Byte-correct winner is R (0xb5 > 0xa5). Raw-string compare picks L.
    got = py_merge_unknown_map({"k": "a5"}, {"k": "B5"})
    # Either uppercase or lowercase representation of 0xb5 is acceptable —
    # what matters is that the *byte value* equals 0xb5, not 0xa5.
    if got["k"].lower() != "b5":
        lines.append(
            f"FAIL  cross-case adversarial: got {got['k']!r}, expected byte 0xb5 "
            "(byte-larger). Raw-string compare misordered."
        )
        all_ok = False
    else:
        lines.append("PASS  cross-case adversarial picks byte-larger value")

    # 2. Same byte, different case: 0xff (`"ff"` vs `"FF"`). Must treat as
    #    equal (no spurious collision; output is one of the inputs).
    got = py_merge_unknown_map({"k": "ff"}, {"k": "FF"})
    if got["k"].lower() != "ff":
        lines.append(
            f"FAIL  same-byte different-case: got {got['k']!r}, expected byte 0xff "
            "(should canonicalise to a single value, not corrupt to a different byte)."
        )
        all_ok = False
    else:
        lines.append("PASS  same-byte different-case canonicalises consistently")

    # 3. Single-side mixed case is kept verbatim by byte value.
    got = py_merge_unknown_map({"k": "AB"}, {})
    if got["k"].lower() != "ab":
        lines.append(
            f"FAIL  single-side uppercase: got {got['k']!r}, expected byte 0xab"
        )
        all_ok = False
    else:
        lines.append("PASS  single-side uppercase preserved as byte 0xab")

    return all_ok, lines


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------


def main() -> int:
    section1_ok, section1_lines = section1_block_kat()
    for ln in section1_lines:
        print(ln)

    print()
    print("--- Section 2: golden_vault_001 full crypto verify ---")
    section2_ok, section2_lines = section2_golden_vault_001()
    for ln in section2_lines:
        print(ln)

    print()
    print("--- Section 3: ml_dsa_65_verify tamper-rejection regression ---")
    section3_ok, section3_lines = section3_ml_dsa_65_verify_regression()
    for ln in section3_lines:
        print(ln)

    print()
    print("--- Section 4: conflict_kat.json CRDT merge cross-language replay ---")
    section4_ok, section4_lines = section4_conflict_kat()
    for ln in section4_lines:
        print(ln)

    print()
    print("--- Section 5: py_merge_unknown_map case-insensitivity guard ---")
    section5_ok, section5_lines = section5_unknown_map_case_insensitivity()
    for ln in section5_lines:
        print(ln)

    print()
    if section1_ok and section2_ok and section3_ok and section4_ok and section5_ok:
        print("PASS")
        return 0
    if not section1_ok:
        print("FAIL: block_kat.json structural conformance", file=sys.stderr)
    if not section2_ok:
        print("FAIL: golden_vault_001 full crypto verify", file=sys.stderr)
    if not section3_ok:
        print("FAIL: ml_dsa_65_verify tamper-rejection regression", file=sys.stderr)
    if not section4_ok:
        print("FAIL: conflict_kat.json CRDT merge cross-language replay", file=sys.stderr)
    if not section5_ok:
        print("FAIL: py_merge_unknown_map case-insensitivity guard", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
