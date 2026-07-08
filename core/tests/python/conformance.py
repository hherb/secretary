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

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
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


# Note: conformance.py verifies golden_vault_001/ only. core/tests/data/
# also contains a golden_vault_002/ fixture used by the FFI integration
# tests (secretary-ffi-bridge, secretary-ffi-py, secretary-ffi-uniffi)
# to exercise the VaultMismatch error path with a real second vault.
# That fixture is intentionally out of scope here — one canonical fixture
# is sufficient for the spec-clean-room contract this script enforces.
# §15 cross-language conformance is a per-fixture property; vault_002
# does not need its own conformance check because it shares vault_001's
# build pipeline (core/tests/common/fixture_builder.rs).

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


def aead_encrypt(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
    """XChaCha20-Poly1305-IETF encrypt -- inverse of `aead_decrypt`.

    Returns `ct || tag(16)`. Same primitive (`crypto_aead_xchacha20poly1305_ietf`)
    the decrypt path uses; reused here for the §5a device-slot enrol round-trip
    so the clean-room proof never reaches for a second AEAD construction.
    """
    from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt

    if len(key) != 32:
        raise ValueError(f"AEAD key length: {len(key)} (expected 32)")
    if len(nonce) != 24:
        raise ValueError(f"AEAD nonce length: {len(nonce)} (expected 24)")
    return crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


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


# §3a / §5a device-slot constants (crypto-design §5a, vault-format §3a).
FILE_KIND_DEVICE_WRAP = 0x0004
TAG_DEVICE_KEK = b"secretary-v1-device-kek"
TAG_ID_WRAP_DEV = b"secretary-v1-id-wrap-dev"
DEVICE_KEK_SALT = b"\x00" * 32  # §5a: 32 bytes of 0x00.
WRAP_DEV_CT_PLUS_TAG_LEN = 32 + 16  # IBK ciphertext (32) + Poly1305 tag (16).


def device_uuid_to_filename(uuid_hex: str) -> str:
    """32-hex-char device UUID -> lowercase-hyphenated 8-4-4-4-12 `<uuid>.wrap`
    filename (vault-format §1 / §3a)."""
    return (
        f"{uuid_hex[0:8]}-{uuid_hex[8:12]}-{uuid_hex[12:16]}"
        f"-{uuid_hex[16:20]}-{uuid_hex[20:32]}.wrap"
    )


def derive_device_kek(device_secret: bytes) -> bytes:
    """§5a `device_kek = HKDF-SHA-256(ikm=device_secret, salt=0x00*32,
    info="secretary-v1-device-kek", len=32)`. No Argon2id: the secret already
    carries 256 bits of CSPRNG entropy."""
    return hkdf_sha256(
        salt=DEVICE_KEK_SALT, ikm=device_secret, info=TAG_DEVICE_KEK, length=32
    )


def device_wrap_aad(vault_uuid: bytes) -> bytes:
    """§5a AEAD AAD: `"secretary-v1-id-wrap-dev" || vault_uuid`."""
    return TAG_ID_WRAP_DEV + vault_uuid


def encode_device_wrap(
    *, vault_uuid: bytes, device_uuid: bytes, nonce: bytes, ct_with_tag: bytes
) -> bytes:
    """Encode the §3a `devices/<uuid>.wrap` byte layout (the enrol direction).

    Big-endian throughout; `suite_id` omitted (identity-layer file, §3a). Inverse
    of `decode_device_wrap` below -- the two together prove the §3a container
    round-trips clean-room.
    """
    if len(vault_uuid) != 16:
        raise ValueError(f"device-wrap vault_uuid length {len(vault_uuid)} (expected 16)")
    if len(device_uuid) != 16:
        raise ValueError(f"device-wrap device_uuid length {len(device_uuid)} (expected 16)")
    if len(nonce) != 24:
        raise ValueError(f"device-wrap nonce length {len(nonce)} (expected 24)")
    if len(ct_with_tag) != WRAP_DEV_CT_PLUS_TAG_LEN:
        raise ValueError(
            f"device-wrap ct||tag length {len(ct_with_tag)} "
            f"(expected {WRAP_DEV_CT_PLUS_TAG_LEN})"
        )
    return (
        MAGIC.to_bytes(4, "big")
        + FORMAT_VERSION.to_bytes(2, "big")
        + FILE_KIND_DEVICE_WRAP.to_bytes(2, "big")
        + vault_uuid
        + device_uuid
        + nonce
        + (32).to_bytes(4, "big")  # wrap_dev_ct_len, MUST be 32 (§3a).
        + ct_with_tag
    )


def decode_device_wrap(blob: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """Decode the §3a `devices/<uuid>.wrap` byte layout.

    Returns `(vault_uuid, device_uuid, nonce, ct_with_tag)`. Asserts magic,
    format_version, file_kind 0x0004, and `wrap_dev_ct_len == 32` per §3a.
    """
    assert int.from_bytes(blob[0:4], "big") == MAGIC, "device wrap magic"
    assert int.from_bytes(blob[4:6], "big") == FORMAT_VERSION, "format_version"
    assert int.from_bytes(blob[6:8], "big") == FILE_KIND_DEVICE_WRAP, (
        "file_kind device-wrap"
    )
    vault_uuid = blob[8:24]
    device_uuid = blob[24:40]
    nonce = blob[40:64]
    assert int.from_bytes(blob[64:68], "big") == 32, "wrap_dev_ct_len"
    ct_with_tag = blob[68:68 + WRAP_DEV_CT_PLUS_TAG_LEN]
    return vault_uuid, device_uuid, nonce, ct_with_tag


def unwrap_device_slot(
    blob: bytes, device_secret: bytes, *, expected_device_uuid: bytes
) -> bytes:
    """Decode a §3a wrap file + §5a-unwrap the IBK it carries.

    Shared open-path core used by both the B.1 `verify_device_slot` cross-check
    and the B.2 `open_with_device_secret` replay. Asserts the §3a header
    `device_uuid` equals `expected_device_uuid` (the filename UUID). Returns the
    recovered IBK bytes.
    """
    vault_uuid, device_uuid_in_header, nonce, ct_with_tag = decode_device_wrap(blob)
    # §3a: the header device_uuid MUST equal the filename's UUID.
    assert device_uuid_in_header == expected_device_uuid, (
        f"device_uuid header/filename mismatch: "
        f"{device_uuid_in_header.hex()} != {expected_device_uuid.hex()}"
    )
    device_kek = derive_device_kek(device_secret)
    return aead_decrypt(device_kek, nonce, device_wrap_aad(vault_uuid), ct_with_tag)


def verify_device_slot(base: "Path", inputs: "dict[str, Any]", ibk_expected: bytes) -> None:
    """Clean-room vault-format §3a / crypto-design §5a: derive device_kek via
    HKDF-SHA-256 and AEAD-unwrap the IBK from devices/<uuid>.wrap, asserting it
    matches the IBK recovered via the password path. Proves §3a is implementable
    from docs/ alone."""
    secret = bytes.fromhex(inputs["device_slot_secret_hex"])
    uuid_hex = inputs["device_slot_uuid_hex"]
    with open(base / "devices" / device_uuid_to_filename(uuid_hex), "rb") as fh:
        blob = fh.read()
    ibk = unwrap_device_slot(
        blob, secret, expected_device_uuid=bytes.fromhex(uuid_hex)
    )
    assert ibk == ibk_expected, "device-slot IBK must match the password/recovery IBK"


def verify_device_slot_b2_ops(
    base: "Path", inputs: "dict[str, Any]", ibk_from_pw: bytes
) -> None:
    """Clean-room replay of the two B.2 device-slot operations (§3a / §5a).

    (a) open -- replays `open_with_device_secret`'s observable contract using the
        shared §3a decode + §5a unwrap helpers: derive device_kek from the pinned
        `device_slot_secret_hex`, decode the golden `devices/<uuid>.wrap`, unwrap
        the IBK, and assert it EQUALS the IBK independently recovered from the
        PASSWORD path (`ibk_from_pw`). Also asserts the §3a header `device_uuid`
        equals the filename UUID (enforced inside `unwrap_device_slot`).

    (b) enrol round-trip -- proves the ENROL direction is spec-implementable. Take
        the password-path IBK, pick a fresh deterministic test device secret +
        device UUID, derive device_kek, AEAD-ENCRYPT the IBK under the §5a AAD,
        ENCODE the §3a wrap-file byte layout, then DECODE it back and UNWRAP,
        asserting the recovered IBK equals the original. This closes the loop B.1
        only walked one-way (decode/unwrap). Purely in-memory -- no file is
        written into the fixture.
    """
    # (a) open: replay open_with_device_secret against the golden wrap file and
    #     cross-check the recovered IBK against the password-path IBK.
    secret = bytes.fromhex(inputs["device_slot_secret_hex"])
    uuid_hex = inputs["device_slot_uuid_hex"]
    device_uuid = bytes.fromhex(uuid_hex)
    with open(base / "devices" / device_uuid_to_filename(uuid_hex), "rb") as fh:
        golden_blob = fh.read()
    ibk_from_device = unwrap_device_slot(
        golden_blob, secret, expected_device_uuid=device_uuid
    )
    assert ibk_from_device == ibk_from_pw, (
        "B.2 open: device-path IBK must equal the password-path IBK"
    )

    # (b) enrol round-trip: encode a fresh §3a wrap in memory, then decode+unwrap.
    #     Deterministic literals are fine -- this is a clean-room round-trip proof,
    #     not a KAT. Choose values DISTINCT from the golden fixture's so a stray
    #     mix-up could not pass by coincidence.
    enrol_secret = bytes(range(32))  # 00 01 02 ... 1f
    enrol_device_uuid = bytes(range(0x20, 0x30))  # 16 distinct bytes 20..2f
    enrol_vault_uuid = bytes.fromhex(inputs["vault_uuid"].replace("-", ""))
    enrol_nonce = bytes(range(0x40, 0x58))  # 24 distinct nonce bytes 40..57

    enrol_kek = derive_device_kek(enrol_secret)
    enrol_ct_with_tag = aead_encrypt(
        enrol_kek, enrol_nonce, device_wrap_aad(enrol_vault_uuid), ibk_from_pw
    )
    assert len(enrol_ct_with_tag) == WRAP_DEV_CT_PLUS_TAG_LEN, (
        f"enrol ct||tag length {len(enrol_ct_with_tag)} "
        f"(expected {WRAP_DEV_CT_PLUS_TAG_LEN})"
    )

    enrol_blob = encode_device_wrap(
        vault_uuid=enrol_vault_uuid,
        device_uuid=enrol_device_uuid,
        nonce=enrol_nonce,
        ct_with_tag=enrol_ct_with_tag,
    )
    recovered_ibk = unwrap_device_slot(
        enrol_blob, enrol_secret, expected_device_uuid=enrol_device_uuid
    )
    assert recovered_ibk == ibk_from_pw, (
        "B.2 enrol round-trip: §3a encode -> decode -> §5a unwrap must recover the IBK"
    )


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

    # Device-slot §3a/§5a clean-room replay.
    # Re-derive the IBK from the password path independently, so verify_device_slot
    # cross-checks the device path against a spec-derived value (not a shared local).
    password = inputs["password"].encode("utf-8")
    master_kek = argon2id_raw(
        password,
        vt.kdf_salt,
        memory_kib=vt.kdf_memory_kib,
        iterations=vt.kdf_iterations,
        parallelism=vt.kdf_parallelism,
    )
    try:
        ibk_from_pw = aead_decrypt(
            master_kek,
            bundle.wrap_pw_nonce,
            compose_aad(TAG_ID_WRAP_PW, vt.vault_uuid),
            bundle.wrap_pw_ct_with_tag,
        )
    except ValueError as e:
        lines.append(f"FAIL  device-slot: IBK re-derivation from password path: {e}")
        return False, lines
    try:
        verify_device_slot(base, inputs, ibk_from_pw)
        lines.append("PASS  device-slot (§3a/§5a): OK")
    except (AssertionError, FileNotFoundError, ValueError) as e:
        lines.append(f"FAIL  device-slot (§3a/§5a): {e}")
        return False, lines

    # Device-slot B.2 operation-level clean-room replay: open (against the golden
    # wrap, cross-checked vs the password-path IBK) + enrol round-trip (in-memory
    # §3a encode -> decode -> §5a unwrap). Reuses the shared §3a/§5a helpers.
    try:
        verify_device_slot_b2_ops(base, inputs, ibk_from_pw)
        lines.append("PASS  device-slot B.2 ops (open + enrol round-trip): OK")
    except (AssertionError, FileNotFoundError, ValueError) as e:
        lines.append(f"FAIL  device-slot B.2 ops (open + enrol round-trip): {e}")
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
# Section R: revoke re-key clean-room verification (vault-format.md §6.5.1)
# ---------------------------------------------------------------------------
#
# Proves from docs/ + the committed fixture alone that revoking a recipient
# is a real re-key: the revoked recipient's §6.2 wrap is gone, the remaining
# recipient decaps+AEAD-decrypts the body under a FRESH block_content_key to
# the committed expected_plaintext, and the body ciphertext changed between
# the before- and after-revoke blocks. Mirrors the Rust always-run guard
# `revoke_kat_after_block_matches_inputs` (core/tests/revoke_kat.rs) but
# derives everything from the parsed after_block + inputs.json + the
# documented §7 hybrid-decap construction — no Rust-only knowledge.


def revoke_kat_dir() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "revoke_kat"


def section_revoke_kat() -> tuple[bool, list[str]]:
    """Clean-room verification of the revoke re-key (vault-format.md §6.5.1).

    Proves from docs/ + the fixture alone that revoking a recipient:
      (a) drops the revoked recipient's §6.2 wrap (absent in after_block) while
          keeping the remaining recipient's wrap;
      (b) lets the remaining recipient decap+AEAD-decrypt the body under the NEW
          block_content_key to the expected plaintext;
      (c) is a real re-key — before_block held the revoked wrap and the body
          ciphertext differs between before and after (fresh BCK).
    """
    lines: list[str] = []
    base = revoke_kat_dir()
    inputs = load_json_fixture(base / "inputs.json", "revoke_kat/inputs.json")

    before_bytes = _require_file(
        base / "before_block.cbor.enc", "revoke_kat/before_block.cbor.enc"
    )
    after_bytes = _require_file(
        base / "after_block.cbor.enc", "revoke_kat/after_block.cbor.enc"
    )

    try:
        before = parse_block_file(before_bytes)
        after = parse_block_file(after_bytes)
    except ParseError as e:
        return False, [f"FAIL  revoke_kat::after_block_rekeyed - block parse: {e}"]

    remaining_fp = bytes.fromhex(inputs["remaining_recipient"]["fingerprint"])
    revoked_fp = bytes.fromhex(inputs["revoked_recipient"]["fingerprint"])
    block_uuid = bytes.fromhex(inputs["block_uuid"])

    before_fps = [e.fingerprint for e in before.recipients]
    after_fps = [e.fingerprint for e in after.recipients]

    issues: list[str] = []

    # (a) revoked wrap dropped; remaining wrap kept.
    if revoked_fp in after_fps:
        issues.append("(a) revoked recipient's wrap must be absent from after_block")
    if remaining_fp not in after_fps:
        issues.append("(a) remaining recipient's wrap must be present in after_block")

    # (b) remaining recipient decaps the new BCK and AEAD-decrypts the body.
    after_entry = None
    for e in after.recipients:
        if e.fingerprint == remaining_fp:
            after_entry = e
            break

    # Skip the decap leg when the remaining wrap is absent (already reported by
    # (a)); there is nothing to decap. Control falls through to the single
    # terminal report block, which prints FAIL then the accumulated issues.
    if after_entry is not None:
        sender_fp = bytes.fromhex(inputs["author"]["fingerprint"])
        sender_pk_bundle = bytes.fromhex(inputs["author"]["pk_bundle"])
        recipient_pk_bundle = bytes.fromhex(
            inputs["remaining_recipient"]["pk_bundle"]
        )
        try:
            bck = hybrid_decap(
                ct_x=after_entry.ct_x,
                ct_pq=after_entry.ct_pq,
                nonce_w=after_entry.nonce_w,
                ct_w_with_tag=after_entry.ct_w,
                sender_fp=sender_fp,
                recipient_fp=remaining_fp,
                sender_pk_bundle=sender_pk_bundle,
                recipient_pk_bundle=recipient_pk_bundle,
                recipient_x_sk=bytes.fromhex(
                    inputs["remaining_recipient"]["x25519_sk"]
                ),
                recipient_pq_sk=bytes.fromhex(
                    inputs["remaining_recipient"]["ml_kem_768_sk"]
                ),
                block_uuid=block_uuid,
            )
        except ValueError as e:
            issues.append(f"(b) hybrid-decap of new BCK failed: {e}")
            bck = None

        if bck is not None:
            body_aad = block_aead_aad(after, after_bytes)
            body_ct_with_tag = after.aead.ct + after.aead.tag
            try:
                recovered = aead_decrypt(
                    bck, after.aead.nonce, body_aad, body_ct_with_tag
                )
            except ValueError as e:
                issues.append(f"(b) body AEAD-decrypt under new BCK failed: {e}")
                recovered = None
            if recovered is not None:
                expected_cbor = bytes.fromhex(inputs["expected_plaintext"]["cbor"])
                if recovered != expected_cbor:
                    issues.append(
                        "(b) recovered plaintext bytes != committed "
                        "expected_plaintext.cbor"
                    )

    # (c) before held the revoked wrap; body ciphertext changed (real re-key).
    if revoked_fp not in before_fps:
        issues.append("(c) before_block must have contained the revoked recipient's wrap")
    if remaining_fp not in before_fps:
        issues.append(
            "(c) before_block must have contained the remaining recipient's wrap"
        )
    if before.aead.ct == after.aead.ct:
        issues.append("(c) re-key must change the body ciphertext (fresh BCK)")

    if issues:
        lines.append("FAIL  revoke_kat::after_block_rekeyed")
        for i in issues:
            lines.append(f"      - {i}")
        return False, lines

    lines.append("PASS  revoke_kat::after_block_rekeyed")
    return True, lines


# ---------------------------------------------------------------------------
# Section S: sync-pass classification clean-room replay (D.1.13)
# ---------------------------------------------------------------------------
#
# Pure vector-clock classification — no crypto. Mirrors the Rust always-run
# guard in core/tests/sync_pass_kat.rs against the SAME cases.json fixture.
# Proves the pause-on-conflict truth table + post-merge LUB agree across the
# Rust primitives and this stdlib-only clean-room re-implementation.
#
# Direction note (the load-bearing detail): sync_once calls
# clock_relation(local_seen, disk_clock) — local FIRST, disk SECOND — and the
# relation is named from the disk (incoming) perspective. So "incoming
# dominates" (disk > local) -> AppliedAutomatically, and "incoming dominated"
# (local > disk) -> RollbackRejected.


def sync_pass_kat_dir() -> Path:
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "sync_pass_kat"


def _parse_clock(pairs: list) -> list[dict]:
    """[[hex, counter], ...] -> list[{"device_uuid_hex": hex, "counter": int}].
    The hex string is a single-byte fill of the 16-byte device_uuid. Output
    is in the canonical shape expected by py_clock_relation /
    py_merge_vector_clocks so those shared helpers can be called directly."""
    return [{"device_uuid_hex": pair[0], "counter": int(pair[1])} for pair in pairs]


def _derive_outcome(
    local: list[dict],
    disk: list[dict],
    diverging_blocks: int,
    veto_count: int,
) -> str:
    """Derive the sync-pass outcome label. Delegates to py_clock_relation
    (defined in the §11 conflict section) so the two sections share a single
    clock-comparison implementation.

    Direction note: local FIRST, disk SECOND — same as sync_once in
    core/src/sync/once.rs. For NothingToDo (Equal case) disk == local so the
    LUB check is vacuously true (disk); production writes nothing on that arm,
    but the fixture's expected_post_clock confirms schema consistency."""
    rel = py_clock_relation(local, disk)
    if rel == "Equal":
        return "NothingToDo"
    if rel == "IncomingDominates":
        return "AppliedAutomatically"
    if rel == "IncomingDominated":
        return "RollbackRejected"
    # Concurrent
    if diverging_blocks == 0:
        return "SilentMerge"
    if veto_count > 0:
        return "ConflictsPending"
    return "MergedClean"


def section_sync_pass_kat() -> tuple[bool, list[str]]:
    """Clean-room replay of the sync-pass classification KAT (D.1.13).

    For each case: derive the outcome label from clock_relation + flags via the
    truth table, and (for advancing arms) compute the post-merge LUB by folding
    disk + every copy clock + prior local-seen. Compare both to the fixture's
    expected fields. A FAIL here vs. the Rust guard passing is the cross-language
    bug this KAT exists to catch.
    """
    fixture = load_json_fixture(
        sync_pass_kat_dir() / "cases.json", "sync_pass_kat/cases.json"
    )
    lines: list[str] = []

    if fixture.get("schema") != "sync_pass_kat/v1":
        return False, [
            f"FAIL: unsupported sync_pass_kat schema {fixture.get('schema')!r}"
        ]

    cases = fixture.get("cases", [])
    if not cases:
        return False, ["FAIL: sync_pass_kat/cases.json has no cases"]

    advancing = {"NothingToDo", "AppliedAutomatically", "SilentMerge", "MergedClean"}
    all_ok = True

    for case in cases:
        name = case["name"]
        disk = _parse_clock(case["disk_clock"])
        local = _parse_clock(case["local_seen"])
        copies = [_parse_clock(c) for c in case["copy_clocks"]]
        diverging_blocks = int(case["diverging_blocks"])
        veto_count = int(case["veto_count"])
        expected = case["expected_outcome"]

        issues: list[str] = []

        derived = _derive_outcome(local, disk, diverging_blocks, veto_count)
        if derived != expected:
            issues.append(f"derived outcome {derived} != expected {expected}")

        post = case["expected_post_clock"]
        if expected in advancing:
            if post is None:
                issues.append(f"advancing arm {expected} must carry a post_clock")
            else:
                # Fold disk + copies + local via py_merge_vector_clocks (shared
                # §11 helper) — same order as post_merge_lub in sync_pass_kat.rs.
                lub = disk
                for copy in copies:
                    lub = py_merge_vector_clocks(lub, copy)
                lub = py_merge_vector_clocks(lub, local)
                expected_clock = _parse_clock(post)
                # Compare as frozensets of (hex, counter) tuples — order-independent.
                lub_set = frozenset(
                    (e["device_uuid_hex"], e["counter"]) for e in lub
                )
                exp_set = frozenset(
                    (e["device_uuid_hex"], e["counter"]) for e in expected_clock
                )
                if lub_set != exp_set:
                    issues.append(
                        f"computed LUB {sorted(lub_set)} != "
                        f"expected_post_clock {sorted(exp_set)}"
                    )
        else:
            if post is not None:
                issues.append(f"pausing arm {expected} must have null post_clock")

        if issues:
            all_ok = False
            lines.append(f"FAIL  sync_pass_kat::{name}")
            for i in issues:
                lines.append(f"      - {i}")
        else:
            lines.append(f"PASS  sync_pass_kat::{name}")

    return all_ok, lines


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
            assert r_hex is not None
            out[key] = bytes.fromhex(r_hex).hex()
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
# Section C — convergence_kat.json: two-client CRDT convergence (C.4)
# ---------------------------------------------------------------------------


def convergence_kat_path() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "convergence_kat.json"


def _converged_block(side_local: dict, side_remote: dict, merger_hex: str) -> dict:
    """Merge one ordering: `side_local` is the merger's own side, `side_remote`
    the canonical side; the merge ticks `merger_hex`. Returns the merged block
    plaintext (vector clock discarded — it differs by merger and is not part of
    the converged logical state)."""
    return py_merge_block(
        side_local["block"],
        side_local["vector_clock"],
        side_remote["block"],
        side_remote["vector_clock"],
        merger_hex,
    )["block"]


def section_convergence_kat() -> tuple[bool, list[str]]:
    """Clean-room two-client convergence (C.4). For each scenario, merge BOTH
    orderings via the spec-derived py_merge_block and assert (a) the converged
    logical blocks are order-independent and (b) they match the Rust-generated
    golden. KeepLocal veto is intentionally out of scope (sync-orchestration,
    not in the frozen merge spec) — see the design doc section 2."""
    lines: list[str] = []
    path = convergence_kat_path()
    if not path.exists():
        print(f"MISSING: convergence_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "convergence_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        lines.append(f"FAIL  convergence_kat.json version={kat.get('version')}, expected 1")
        return False, lines
    scenarios = kat.get("scenarios") or []
    if not scenarios:
        lines.append("FAIL  convergence_kat.json has no scenarios")
        return False, lines

    all_ok = True
    for sc in scenarios:
        name = sc["name"]
        a, b = sc["device_a"], sc["device_b"]
        a_hex, b_hex = sc["merging_device_a_hex"], sc["merging_device_b_hex"]
        try:
            # Ordering AB: A canonical, B merges (B local, A remote, merger=B).
            ab = _normalise_block(_converged_block(b, a, b_hex))
            # Ordering BA: B canonical, A merges (A local, B remote, merger=A).
            ba = _normalise_block(_converged_block(a, b, a_hex))
        except Exception as exc:
            # Surface any merge error as a FAIL line (mirrors section4_conflict_kat).
            lines.append(f"FAIL  scenario {name!r}: merge raised {exc!r}")
            all_ok = False
            continue

        if ab != ba:
            lines.append(f"FAIL  scenario {name!r}: orderings diverged (not order-independent)")
            lines.append(f"  AB: {json.dumps(ab, sort_keys=True)}")
            lines.append(f"  BA: {json.dumps(ba, sort_keys=True)}")
            all_ok = False
            continue

        golden = _normalise_block(sc["golden"]["block"])
        if ab != golden:
            lines.append(f"FAIL  scenario {name!r}: converged block != Rust golden")
            lines.append(f"  got:    {json.dumps(ab, sort_keys=True)}")
            lines.append(f"  golden: {json.dumps(golden, sort_keys=True)}")
            all_ok = False
            continue

        lines.append(f"PASS  convergence_kat.json {name!r}: order-independent + golden-match")

    return all_ok, lines


# ---------------------------------------------------------------------------
# Differential-replay helpers (--diff-replay mode)
# ---------------------------------------------------------------------------
# Each py_decode_<target> / py_encode_<target> pair implements a strict
# clean-room decoder/encoder that mirrors the Rust side's accept/reject
# behaviour and byte-identical canonical re-encoding output.  They are
# called by run_diff_replay() when the script is invoked as:
#
#   uv run conformance.py --diff-replay <target> <input-path>
#
# and also available as library helpers for future test sections.


def _validate_uuid_canonical(s: str) -> bytes:
    """Parse and validate a canonical RFC 4122 UUID string.

    Requires exactly 36 bytes, hyphens at indices 8/13/18/23, and every
    other character must be a lowercase hex digit (0-9 or a-f).
    Mirrors vault_toml.rs::parse_uuid_canonical.

    Raises ValueError on any violation.
    """
    if len(s) != 36:
        raise ValueError(f"uuid string length {len(s)}, expected 36")
    for i in (8, 13, 18, 23):
        if s[i] != '-':
            raise ValueError(f"uuid missing hyphen at position {i}: {s!r}")
    pattern = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')
    if not pattern.match(s):
        raise ValueError(f"uuid contains non-lowercase-hex chars: {s!r}")
    return bytes.fromhex(s.replace('-', ''))


def py_decode_vault_toml(text: str) -> dict:
    """Strict §2 vault.toml decoder matching vault_toml.rs::decode.

    Validates:
    - format_version == 1
    - suite_id == 1
    - vault_uuid: canonical lowercase hyphenated RFC 4122 form (rejects
      uppercase and non-standard separators)
    - created_at_ms: non-negative integer
    - [kdf]: algorithm == "argon2id", version == "1.3", no unknown keys,
      salt_b64 decodes to exactly 32 bytes.

    Returns the parsed fields as a dict. Raises on any violation.
    """
    data = tomllib.loads(text)

    # format_version
    fv = data.get("format_version")
    if not isinstance(fv, int) or fv != 1:
        raise ValueError(f"vault.toml format_version {fv!r}")

    # suite_id
    si = data.get("suite_id")
    if not isinstance(si, int) or si != 1:
        raise ValueError(f"vault.toml suite_id {si!r}")

    # vault_uuid — strict canonical form (lowercase hex, exact hyphens)
    vault_uuid_str = data.get("vault_uuid")
    if not isinstance(vault_uuid_str, str):
        raise ValueError("vault.toml vault_uuid missing or wrong type")
    vault_uuid = _validate_uuid_canonical(vault_uuid_str)

    # created_at_ms — must be a non-negative integer
    cat = data.get("created_at_ms")
    if not isinstance(cat, int) or cat < 0:
        raise ValueError(f"vault.toml created_at_ms {cat!r}")

    # [kdf] section — strict: no unknown keys
    kdf = data.get("kdf")
    if not isinstance(kdf, dict):
        raise ValueError("vault.toml missing [kdf] section")

    KNOWN_KDF_KEYS = {"algorithm", "version", "memory_kib", "iterations", "parallelism", "salt_b64"}
    for k in kdf:
        if k not in KNOWN_KDF_KEYS:
            raise ValueError(f"vault.toml unknown kdf key: {k!r}")

    alg = kdf.get("algorithm")
    if alg != "argon2id":
        raise ValueError(f"vault.toml kdf.algorithm {alg!r}")

    ver = kdf.get("version")
    if ver != "1.3":
        raise ValueError(f"vault.toml kdf.version {ver!r}")

    mem_kib = kdf.get("memory_kib")
    if not isinstance(mem_kib, int) or mem_kib < 0 or mem_kib > 0xFFFFFFFF:
        raise ValueError(f"vault.toml kdf.memory_kib {mem_kib!r}")

    iters = kdf.get("iterations")
    if not isinstance(iters, int) or iters < 0 or iters > 0xFFFFFFFF:
        raise ValueError(f"vault.toml kdf.iterations {iters!r}")

    par = kdf.get("parallelism")
    if not isinstance(par, int) or par < 0 or par > 0xFFFFFFFF:
        raise ValueError(f"vault.toml kdf.parallelism {par!r}")

    salt_b64_str = kdf.get("salt_b64")
    if not isinstance(salt_b64_str, str):
        raise ValueError("vault.toml kdf.salt_b64 missing")
    salt = base64.b64decode(salt_b64_str)
    if len(salt) != 32:
        raise ValueError(f"vault.toml kdf salt length {len(salt)} (expected 32)")

    return {
        "format_version": fv,
        "suite_id": si,
        "vault_uuid": vault_uuid,
        "created_at_ms": cat,
        "kdf": {
            "algorithm": alg,
            "version": ver,
            "memory_kib": mem_kib,
            "iterations": iters,
            "parallelism": par,
            "salt": salt,
        },
    }


def py_decode_record(data: bytes) -> dict:
    """Strict §6.3 canonical-CBOR record decoder matching record.rs::decode.

    Validates:
    - Top-level item is a CBOR map with text-string keys.
    - No floats, no CBOR tags anywhere in the tree.
    - No duplicate keys at any level.
    - Required fields: record_uuid (16-byte bstr), record_type (tstr),
      fields (map), created_at_ms (uint), last_mod_ms (uint).
    - Optional: tags (array of tstr), tombstone (bool), tombstoned_at_ms (uint).
    - Input is already canonical (re-encode == input).

    Returns a dict of parsed fields. Raises on any violation.
    """
    import cbor2

    # cbor2's decoder does not reject floats/tags by default; we check manually.
    try:
        decoded = cbor2.loads(data)
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"record CBOR decode: {e}") from e

    _reject_floats_and_tags_py(decoded)

    if not isinstance(decoded, dict):
        raise ValueError("record top-level CBOR is not a map")

    # Check for duplicate keys: cbor2 silently overwrites on duplicate,
    # so we need the raw map. Re-parse with object_pairs_hook to detect dups.
    _check_no_duplicate_keys(data)

    # Required fields
    REQUIRED = {"record_uuid", "record_type", "fields", "created_at_ms", "last_mod_ms"}
    for f in REQUIRED:
        if f not in decoded:
            raise KeyError(f"record missing required field: {f!r}")

    rec_uuid = decoded["record_uuid"]
    if not isinstance(rec_uuid, bytes) or len(rec_uuid) != 16:
        raise ValueError(f"record_uuid must be 16-byte bstr, got {type(rec_uuid).__name__}")

    rec_type = decoded["record_type"]
    if not isinstance(rec_type, str):
        raise ValueError("record_type must be tstr")

    fields_val = decoded["fields"]
    if not isinstance(fields_val, dict):
        raise ValueError("record fields must be a map")
    # Validate each field sub-map
    for fname, fval in fields_val.items():
        if not isinstance(fname, str):
            raise ValueError(f"record fields key must be tstr, got {type(fname).__name__}")
        if not isinstance(fval, dict):
            raise ValueError(f"record field {fname!r} must be a map")
        _validate_record_field(fname, fval)

    cat = decoded["created_at_ms"]
    if not isinstance(cat, int) or cat < 0:
        raise ValueError(f"created_at_ms must be uint, got {cat!r}")

    lmm = decoded["last_mod_ms"]
    if not isinstance(lmm, int) or lmm < 0:
        raise ValueError(f"last_mod_ms must be uint, got {lmm!r}")

    # Optional: tags
    if "tags" in decoded:
        tags_val = decoded["tags"]
        if not isinstance(tags_val, list):
            raise ValueError("record tags must be array")
        for t in tags_val:
            if not isinstance(t, str):
                raise ValueError("record tags entries must be tstr")

    # Optional: tombstone
    if "tombstone" in decoded:
        if not isinstance(decoded["tombstone"], bool):
            raise ValueError("record tombstone must be bool")

    # Optional: tombstoned_at_ms
    if "tombstoned_at_ms" in decoded:
        tam = decoded["tombstoned_at_ms"]
        if not isinstance(tam, int) or tam < 0:
            raise ValueError(f"tombstoned_at_ms must be uint, got {tam!r}")

    # Canonical-input check: re-encode and compare
    reencoded = py_encode_record(decoded)
    if reencoded != data:
        raise ValueError("record is not in canonical CBOR form")

    return decoded


def _validate_record_field(fname: str, fval: dict) -> None:
    """Validate a single §6.3 RecordField sub-map."""
    REQUIRED_FIELD_KEYS = {"value", "last_mod", "device_uuid"}
    for k in REQUIRED_FIELD_KEYS:
        if k not in fval:
            raise KeyError(f"record field {fname!r} missing {k!r}")
    v = fval["value"]
    if not isinstance(v, (str, bytes)):
        raise ValueError(f"field {fname!r} value must be tstr or bstr")
    lm = fval["last_mod"]
    if not isinstance(lm, int) or lm < 0:
        raise ValueError(f"field {fname!r} last_mod must be uint")
    du = fval["device_uuid"]
    if not isinstance(du, bytes) or len(du) != 16:
        raise ValueError(f"field {fname!r} device_uuid must be 16-byte bstr")


def _reject_floats_and_tags_py(v: Any) -> None:
    """Walk a cbor2-decoded value tree and raise on float or CBOR tag.

    Mirrors vault::canonical::reject_floats_and_tags.
    """
    import cbor2
    if isinstance(v, float):
        raise ValueError("float values are not permitted")
    if isinstance(v, cbor2.CBORTag):
        raise ValueError("CBOR tags are not permitted")
    if isinstance(v, dict):
        for k, val in v.items():
            _reject_floats_and_tags_py(k)
            _reject_floats_and_tags_py(val)
    elif isinstance(v, list):
        for item in v:
            _reject_floats_and_tags_py(item)


def _check_no_duplicate_keys(data: bytes) -> None:
    """Detect duplicate CBOR map keys at any level.

    cbor2 does not expose an object_pairs_hook; we use its object_hook
    callback which fires after each map is decoded but receives the final
    dict (already de-duplicated).  Instead we rely on the canonical
    re-encode check at the end of each decoder: if the input had duplicate
    keys cbor2 would collapse them, producing a shorter map on re-encode,
    which fails the bytes-equal comparison.  So this function is a no-op
    and the canonical-input invariant provides the protection.
    """
    pass


def py_encode_record(record: dict) -> bytes:
    """Re-encode a parsed record dict to canonical CBOR.

    The encoder must produce byte-identical output to record.rs::encode.
    Encoding rules:
    - Top-level map: canonical key sort.
    - Empty tags list: omit from encoding.
    - tombstone == False: omit from encoding.
    - tombstoned_at_ms == 0: omit from encoding.
    - Each field sub-map also encoded canonically.
    """
    entries: list[tuple[Any, Any]] = []

    entries.append(("record_uuid", record["record_uuid"]))
    entries.append(("record_type", record["record_type"]))

    # Encode fields map: each field is a canonical sub-map
    fields_entries: list[tuple[Any, Any]] = []
    for fname, fval in record["fields"].items():
        field_entries: list[tuple[Any, Any]] = [
            ("value", fval["value"]),
            ("last_mod", fval["last_mod"]),
            ("device_uuid", fval["device_uuid"]),
        ]
        # Forward-compat unknown field-level keys
        for k, v in fval.items():
            if k not in ("value", "last_mod", "device_uuid"):
                field_entries.append((k, v))
        fields_entries.append((fname, _encode_canonical_map_cbor(field_entries)))

    # fields outer map: each value is already an encoded bytes blob, but we
    # need a CBOR map-of-maps, not map-of-bytestrings. We build the entries
    # as (fname, decoded-sub-dict) so encode_canonical_map recurses correctly.
    # Actually: encode_canonical_map expects python objects. We need to keep
    # the sub-maps as dicts. Rebuild:
    fields_dict_entries: list[tuple[Any, Any]] = []
    for fname, fval in record["fields"].items():
        field_sub: dict = {"value": fval["value"], "last_mod": fval["last_mod"],
                           "device_uuid": fval["device_uuid"]}
        for k, v in fval.items():
            if k not in ("value", "last_mod", "device_uuid"):
                field_sub[k] = v
        fields_dict_entries.append((fname, field_sub))

    # Sort field names canonically, then build sorted sub-dicts
    import cbor2
    sorted_fields = sorted(fields_dict_entries, key=lambda kv: cbor2.dumps(kv[0], canonical=True))
    # Build fields value: a sorted dict of sorted dicts
    outer_fields: dict = {}
    for fname, fval in sorted_fields:
        sub_sorted = sorted(fval.items(), key=lambda kv: cbor2.dumps(kv[0], canonical=True))
        outer_fields[fname] = dict(sub_sorted)

    entries.append(("fields", outer_fields))

    # Optional: tags (omit if empty)
    tags = record.get("tags", [])
    if tags:
        entries.append(("tags", tags))

    entries.append(("created_at_ms", record["created_at_ms"]))
    entries.append(("last_mod_ms", record["last_mod_ms"]))

    # Optional: tombstone (omit if False)
    if record.get("tombstone", False):
        entries.append(("tombstone", True))

    # Optional: tombstoned_at_ms (omit if 0)
    if record.get("tombstoned_at_ms", 0) != 0:
        entries.append(("tombstoned_at_ms", record["tombstoned_at_ms"]))

    # Forward-compat unknown top-level keys
    KNOWN_KEYS = {"record_uuid", "record_type", "fields", "tags", "created_at_ms",
                  "last_mod_ms", "tombstone", "tombstoned_at_ms"}
    for k, v in record.items():
        if k not in KNOWN_KEYS:
            entries.append((k, v))

    return encode_canonical_map(entries)


def _encode_canonical_map_cbor(entries: list[tuple[Any, Any]]) -> bytes:
    """Helper: encode entries as a canonical CBOR map (bytes output)."""
    return encode_canonical_map(entries)


def py_decode_contact_card(data: bytes) -> dict:
    """Strict §6 contact card decoder matching card.rs::from_canonical_cbor.

    Validates:
    - Top-level item is a CBOR map with text-string keys.
    - No unknown keys (card.rs returns CborDecode error on unknown fields).
    - Required fields: card_version (uint == 1), contact_uuid (16-byte bstr),
      display_name (tstr), x25519_pk (32-byte bstr), ml_kem_768_pk (1184-byte bstr),
      ed25519_pk (32-byte bstr), ml_dsa_65_pk (1952-byte bstr), created_at (uint),
      self_sig_ed (64-byte bstr), self_sig_pq (3309-byte bstr).
    - Input is already canonical (re-encode == input).

    Does NOT verify self-signatures (matching from_canonical_cbor which
    separates parsing from signature verification).
    Returns the decoded dict. Raises on any violation.
    """
    import cbor2

    try:
        decoded = cbor2.loads(data)
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"contact_card CBOR decode: {e}") from e

    if not isinstance(decoded, dict):
        raise ValueError("contact_card top-level CBOR is not a map")

    # Detect duplicate keys
    _check_no_duplicate_keys(data)

    KNOWN_CARD_KEYS = {
        "card_version", "contact_uuid", "display_name", "x25519_pk",
        "ml_kem_768_pk", "ed25519_pk", "ml_dsa_65_pk", "created_at",
        "self_sig_ed", "self_sig_pq",
    }
    for k in decoded:
        if k not in KNOWN_CARD_KEYS:
            raise ValueError(f"contact_card unknown field: {k!r}")

    REQUIRED_CARD_FIELDS = KNOWN_CARD_KEYS  # all 10 are required
    for f in REQUIRED_CARD_FIELDS:
        if f not in decoded:
            raise KeyError(f"contact_card missing required field: {f!r}")

    cv = decoded["card_version"]
    if not isinstance(cv, int) or cv != 1:
        raise ValueError(f"card_version must be 1, got {cv!r}")

    cu = decoded["contact_uuid"]
    if not isinstance(cu, bytes) or len(cu) != 16:
        raise ValueError("contact_uuid must be 16-byte bstr")

    dn = decoded["display_name"]
    if not isinstance(dn, str):
        raise ValueError("display_name must be tstr")

    x25519 = decoded["x25519_pk"]
    if not isinstance(x25519, bytes) or len(x25519) != 32:
        raise ValueError("x25519_pk must be 32-byte bstr")

    mlkem = decoded["ml_kem_768_pk"]
    if not isinstance(mlkem, bytes) or len(mlkem) != 1184:
        raise ValueError(f"ml_kem_768_pk must be 1184-byte bstr, got {len(mlkem) if isinstance(mlkem, bytes) else type(mlkem).__name__}")

    ed = decoded["ed25519_pk"]
    if not isinstance(ed, bytes) or len(ed) != 32:
        raise ValueError("ed25519_pk must be 32-byte bstr")

    mldsa = decoded["ml_dsa_65_pk"]
    if not isinstance(mldsa, bytes) or len(mldsa) != 1952:
        raise ValueError(f"ml_dsa_65_pk must be 1952-byte bstr, got {len(mldsa) if isinstance(mldsa, bytes) else type(mldsa).__name__}")

    cat = decoded["created_at"]
    if not isinstance(cat, int) or cat < 0:
        raise ValueError(f"created_at must be uint, got {cat!r}")

    sig_ed = decoded["self_sig_ed"]
    if not isinstance(sig_ed, bytes) or len(sig_ed) != 64:
        raise ValueError("self_sig_ed must be 64-byte bstr")

    sig_pq = decoded["self_sig_pq"]
    if not isinstance(sig_pq, bytes) or len(sig_pq) != 3309:
        raise ValueError(f"self_sig_pq must be 3309-byte bstr, got {len(sig_pq) if isinstance(sig_pq, bytes) else type(sig_pq).__name__}")

    # Canonical-input check
    reencoded = py_encode_contact_card(decoded)
    if reencoded != data:
        raise ValueError("contact_card is not in canonical CBOR form")

    return decoded


def py_encode_contact_card(card: dict) -> bytes:
    """Re-encode a parsed contact card dict to canonical CBOR.

    Mirrors card.rs::to_canonical_cbor: all 10 fields in a canonical map.
    Field order in the entry list doesn't matter; encode_canonical_map
    sorts by encoded key bytes.
    """
    entries: list[tuple[Any, Any]] = [
        ("card_version", card["card_version"]),
        ("contact_uuid", card["contact_uuid"]),
        ("display_name", card["display_name"]),
        ("x25519_pk", card["x25519_pk"]),
        ("ml_kem_768_pk", card["ml_kem_768_pk"]),
        ("ed25519_pk", card["ed25519_pk"]),
        ("ml_dsa_65_pk", card["ml_dsa_65_pk"]),
        ("created_at", card["created_at"]),
        ("self_sig_ed", card["self_sig_ed"]),
        ("self_sig_pq", card["self_sig_pq"]),
    ]
    return encode_canonical_map(entries)


def py_decode_bundle_file(data: bytes) -> dict:
    """Strict §3 bundle file decoder matching bundle_file.rs::decode.

    Returns a dict with the parsed fields. Raises on any violation.
    """
    return vars(parse_identity_bundle_envelope(data))


def py_encode_bundle_file(parsed: dict) -> bytes:
    """Re-encode a parsed bundle file dict to its §3 binary form.

    Mirrors bundle_file.rs::encode exactly (big-endian throughout).
    """
    vault_uuid = parsed["vault_uuid"]
    created_at_ms = parsed["created_at_ms"]
    wrap_pw_nonce = parsed["wrap_pw_nonce"]
    wrap_pw_ct_with_tag = parsed["wrap_pw_ct_with_tag"]
    wrap_rec_nonce = parsed["wrap_rec_nonce"]
    wrap_rec_ct_with_tag = parsed["wrap_rec_ct_with_tag"]
    bundle_nonce = parsed["bundle_nonce"]
    bundle_ct_with_tag = parsed["bundle_ct_with_tag"]

    out = bytearray()
    out += MAGIC.to_bytes(4, "big")
    out += FORMAT_VERSION.to_bytes(2, "big")
    out += FILE_KIND_IDENTITY_BUNDLE.to_bytes(2, "big")
    out += vault_uuid
    out += created_at_ms.to_bytes(8, "big")

    out += wrap_pw_nonce
    out += (32).to_bytes(4, "big")           # wrap_pw_ct_len == 32 always
    out += wrap_pw_ct_with_tag

    out += wrap_rec_nonce
    out += (32).to_bytes(4, "big")           # wrap_rec_ct_len == 32 always
    out += wrap_rec_ct_with_tag

    out += bundle_nonce
    bundle_ct_len = len(bundle_ct_with_tag) - 16   # exclude the 16-byte tag
    out += bundle_ct_len.to_bytes(4, "big")
    out += bundle_ct_with_tag

    return bytes(out)


def py_decode_manifest_file(data: bytes) -> dict:
    """Strict §4.1 manifest file decoder matching manifest.rs::decode_manifest_file.

    Returns a dict with the parsed fields. Raises on any violation.
    """
    mf = parse_manifest_file(data)
    return {
        "vault_uuid": mf.vault_uuid,
        "created_at_ms": mf.created_at_ms,
        "last_mod_ms": mf.last_mod_ms,
        "aead_nonce": mf.aead_nonce,
        "aead_ct": mf.aead_ct,
        "aead_tag": mf.aead_tag,
        "author_fingerprint": mf.author_fingerprint,
        "sig_ed": mf.sig_ed,
        "sig_pq": mf.sig_pq,
        "raw_bytes": mf.raw_bytes,
    }


def py_encode_manifest_file(parsed: dict) -> bytes:
    """Re-encode a parsed manifest file dict to its §4.1 binary form.

    Mirrors manifest.rs::encode_manifest_file exactly.
    """
    vault_uuid = parsed["vault_uuid"]
    created_at_ms = parsed["created_at_ms"]
    last_mod_ms = parsed["last_mod_ms"]
    aead_nonce = parsed["aead_nonce"]
    aead_ct = parsed["aead_ct"]
    aead_tag = parsed["aead_tag"]
    author_fingerprint = parsed["author_fingerprint"]
    sig_ed = parsed["sig_ed"]
    sig_pq = parsed["sig_pq"]

    out = bytearray()
    # Header (MANIFEST_HEADER_LEN = 42 bytes):
    # magic(4) + format_version(2) + suite_id(2) + file_kind(2) +
    # vault_uuid(16) + created_at_ms(8) + last_mod_ms(8)
    out += MAGIC.to_bytes(4, "big")
    out += FORMAT_VERSION.to_bytes(2, "big")
    out += SUITE_ID.to_bytes(2, "big")
    out += FILE_KIND_MANIFEST.to_bytes(2, "big")
    out += vault_uuid
    out += created_at_ms.to_bytes(8, "big")
    out += last_mod_ms.to_bytes(8, "big")

    out += aead_nonce
    out += len(aead_ct).to_bytes(4, "big")
    out += aead_ct
    out += aead_tag
    out += author_fingerprint
    out += ED25519_SIG_LEN.to_bytes(2, "big")
    out += sig_ed
    out += ML_DSA_65_SIG_LEN.to_bytes(2, "big")
    out += sig_pq

    return bytes(out)


# ---------------------------------------------------------------------------
# Section P — manifest TrashEntry purge marker (vault-format.md §4.2 / §7.2,
# #399). Self-contained: the CBOR is constructed/decoded/re-encoded entirely
# in-script, mirroring how the record/contact-card codecs above prove clean-
# room sufficiency without a Rust-generated fixture.
# ---------------------------------------------------------------------------

# BLAKE3-256 content-commitment fingerprint carried by `TrashEntry.fingerprint`
# (vault-format.md §4.2, §7.1 step 3a) -- distinct from the 16-byte identity/
# card `FINGERPRINT_LEN` above (a truncated BLAKE3-keyed-hash, §14).
TRASH_ENTRY_FINGERPRINT_LEN = 32


def py_decode_trash_entry(data: bytes) -> dict:
    """Strict manifest §4.2 `TrashEntry` decoder matching
    manifest.rs::parse_trash_entry.

    Validates:
    - Top-level item is a CBOR map with text-string keys; no floats, no
      CBOR tags anywhere in the tree (§6.2 canonical-CBOR profile).
    - Required fields: block_uuid (16-byte bstr), tombstoned_at_ms (uint),
      tombstoned_by (16-byte bstr).
    - Optional: fingerprint (32-byte bstr), purged_at_ms (uint) -- §7.2:
      absent means "still restorable", present means "permanently purged".
    - Unrecognised keys are preserved verbatim under "unknown" (§6.3.2
      forward-compat pattern already used by contacts/records/blocks).
    - Input is already canonical (re-encode == input); this is also how
      the "decodes and re-encodes byte-identically" property is checked.

    Returns a dict of parsed fields. Raises on any violation.
    """
    import cbor2

    try:
        decoded = cbor2.loads(data)
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"TrashEntry CBOR decode: {e}") from e

    _reject_floats_and_tags_py(decoded)

    if not isinstance(decoded, dict):
        raise ValueError("TrashEntry top-level CBOR is not a map")

    REQUIRED = {"block_uuid", "tombstoned_at_ms", "tombstoned_by"}
    for f in REQUIRED:
        if f not in decoded:
            raise KeyError(f"TrashEntry missing required field: {f!r}")

    block_uuid = decoded["block_uuid"]
    if not isinstance(block_uuid, bytes) or len(block_uuid) != BLOCK_UUID_LEN:
        raise ValueError("TrashEntry block_uuid must be 16-byte bstr")

    tombstoned_at_ms = decoded["tombstoned_at_ms"]
    if not isinstance(tombstoned_at_ms, int) or tombstoned_at_ms < 0:
        raise ValueError(f"TrashEntry tombstoned_at_ms must be uint, got {tombstoned_at_ms!r}")

    tombstoned_by = decoded["tombstoned_by"]
    if not isinstance(tombstoned_by, bytes) or len(tombstoned_by) != DEVICE_UUID_LEN:
        raise ValueError("TrashEntry tombstoned_by must be 16-byte bstr")

    out: dict[str, Any] = {
        "block_uuid": block_uuid,
        "tombstoned_at_ms": tombstoned_at_ms,
        "tombstoned_by": tombstoned_by,
    }

    if "fingerprint" in decoded:
        fp = decoded["fingerprint"]
        if not isinstance(fp, bytes) or len(fp) != TRASH_ENTRY_FINGERPRINT_LEN:
            raise ValueError("TrashEntry fingerprint must be 32-byte bstr")
        out["fingerprint"] = fp

    if "purged_at_ms" in decoded:
        purged_at_ms = decoded["purged_at_ms"]
        if not isinstance(purged_at_ms, int) or purged_at_ms < 0:
            raise ValueError(f"TrashEntry purged_at_ms must be uint, got {purged_at_ms!r}")
        out["purged_at_ms"] = purged_at_ms

    KNOWN_KEYS = {
        "block_uuid", "tombstoned_at_ms", "tombstoned_by", "fingerprint", "purged_at_ms",
    }
    unknown = {k: v for k, v in decoded.items() if k not in KNOWN_KEYS}
    if unknown:
        out["unknown"] = unknown

    # Canonical-input check: re-encode and compare (also proves the "marker
    # round-trip" and "byte-identical when absent" properties this section
    # exists to demonstrate).
    reencoded = py_encode_trash_entry(out)
    if reencoded != data:
        raise ValueError("TrashEntry is not in canonical CBOR form")

    return out


def py_encode_trash_entry(entry: dict) -> bytes:
    """Re-encode a parsed `TrashEntry` dict to canonical CBOR.

    Mirrors manifest.rs::trash_entry_to_value: `fingerprint` and
    `purged_at_ms` are each omitted entirely when absent/`None` -- never
    encoded as an explicit CBOR null. This is the byte-identical
    forward-compat property §7.2 / §6.3.2 rely on: a `TrashEntry` that has
    never been purged carries no `purged_at_ms` key at all, so a legacy
    (pre-#399) client's encoding of the same entry round-trips unchanged.
    """
    entries: list[tuple[Any, Any]] = [
        ("block_uuid", entry["block_uuid"]),
        ("tombstoned_at_ms", entry["tombstoned_at_ms"]),
        ("tombstoned_by", entry["tombstoned_by"]),
    ]
    if entry.get("fingerprint") is not None:
        entries.append(("fingerprint", entry["fingerprint"]))
    if entry.get("purged_at_ms") is not None:
        entries.append(("purged_at_ms", entry["purged_at_ms"]))
    for k, v in entry.get("unknown", {}).items():
        entries.append((k, v))
    return encode_canonical_map(entries)


def is_trash_entry_restorable(entry: dict) -> bool:
    """§7.2 "Restore interaction": restore gains a fail-fast precondition --
    if the matching `TrashEntry.purged_at_ms` is `Some`, restore fails
    immediately (a dedicated purged-block error), *before* any `trash/`
    directory scan. Absent `purged_at_ms` means still restorable.

    This is the decision the verifier reproduces from the signed manifest
    marker alone, per the task brief's part (b).
    """
    return entry.get("purged_at_ms") is None


def section_purge_scenario() -> tuple[bool, list[str]]:
    """Clean-room purge-marker scenario (#399, vault-format.md §4.2 / §7.2).

    Self-contained -- constructs `TrashEntry` CBOR maps in-script (no
    fixture needed), proving from `docs/vault-format.md` alone that:

    (a) a `TrashEntry` with `purged_at_ms` present decodes and re-encodes
        byte-identically (marker round-trip); a `TrashEntry` with the key
        ABSENT decodes to "not purged" and re-encodes byte-identically,
        with no explicit CBOR null standing in for the missing key; and
    (b) the documented §7.2 restore-refusal rule is expressible: an entry
        carrying `purged_at_ms` classifies as non-restorable, distinct
        from an entry that never carried the marker.
    """
    lines: list[str] = []
    all_ok = True

    # Random (not hardcoded) UUID-shaped values -- these aren't secrets, but
    # keeping the convention avoids literal byte arrays that read like
    # planted crypto material.
    block_uuid = os.urandom(BLOCK_UUID_LEN)
    tombstoned_by = os.urandom(DEVICE_UUID_LEN)
    tombstoned_at_ms = 1_800_000_000_000  # arbitrary plausible unix-millis
    purged_at_ms = tombstoned_at_ms + 3_600_000  # purged an hour after trashing

    # --- (a) purged_at_ms PRESENT: marker round-trip ---
    purged_entry_in = {
        "block_uuid": block_uuid,
        "tombstoned_at_ms": tombstoned_at_ms,
        "tombstoned_by": tombstoned_by,
        "purged_at_ms": purged_at_ms,
    }
    purged_bytes = py_encode_trash_entry(purged_entry_in)
    try:
        purged_decoded = py_decode_trash_entry(purged_bytes)
    except Exception as e:
        return False, [f"FAIL: purged TrashEntry failed to decode its own encoding: {e}"]

    if purged_decoded.get("purged_at_ms") != purged_at_ms:
        lines.append(
            "FAIL  purge marker round-trip: got purged_at_ms="
            f"{purged_decoded.get('purged_at_ms')!r}, expected {purged_at_ms}"
        )
        all_ok = False
    else:
        lines.append("PASS  purge marker round-trip: purged_at_ms decodes correctly")

    reencoded = py_encode_trash_entry(purged_decoded)
    if reencoded != purged_bytes:
        lines.append("FAIL  purged TrashEntry re-encode is not byte-identical")
        all_ok = False
    else:
        lines.append("PASS  purged TrashEntry re-encode is byte-identical")

    # --- classification: purged entry must be refused for restore (§7.2) ---
    if is_trash_entry_restorable(purged_decoded):
        lines.append("FAIL  purged TrashEntry classified as restorable (must refuse restore)")
        all_ok = False
    else:
        lines.append("PASS  purged TrashEntry classified as non-restorable (restore refuses)")

    # --- (a) purged_at_ms ABSENT: "not purged" round-trip, no explicit null ---
    live_entry_in = {
        "block_uuid": block_uuid,
        "tombstoned_at_ms": tombstoned_at_ms,
        "tombstoned_by": tombstoned_by,
    }
    live_bytes = py_encode_trash_entry(live_entry_in)
    try:
        live_decoded = py_decode_trash_entry(live_bytes)
    except Exception as e:
        return False, lines + [
            f"FAIL: unpurged TrashEntry failed to decode its own encoding: {e}"
        ]

    if "purged_at_ms" in live_decoded:
        lines.append("FAIL  unpurged TrashEntry decoded an unexpected purged_at_ms key")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry decodes with purged_at_ms absent")

    reencoded_live = py_encode_trash_entry(live_decoded)
    if reencoded_live != live_bytes:
        lines.append("FAIL  unpurged TrashEntry re-encode is not byte-identical")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry re-encode is byte-identical (no explicit null)")

    # Belt-and-braces: the wire bytes themselves must not contain the
    # "purged_at_ms" key text anywhere -- the omission is structural (the
    # key is absent), not merely "the decoder happens to report None".
    if b"purged_at_ms" in live_bytes:
        lines.append("FAIL  unpurged TrashEntry wire bytes contain the purged_at_ms key text")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry wire bytes omit the purged_at_ms key entirely")

    # --- classification: unpurged entry must remain restorable ---
    if not is_trash_entry_restorable(live_decoded):
        lines.append("FAIL  unpurged TrashEntry classified as non-restorable")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry classified as restorable")

    return all_ok, lines


def py_decode_block_file(data: bytes) -> dict:
    """Strict §6.1 block file decoder matching block.rs::decode_block_file.

    Returns a dict with the parsed fields. Raises on any violation.
    """
    pf = parse_block_file(data)
    return {
        "header": pf.header,
        "recipients": pf.recipients,
        "aead": pf.aead,
        "signature": pf.signature,
    }


def py_encode_block_file(parsed: dict) -> bytes:
    """Re-encode a parsed block file dict to its §6.1 binary form.

    Mirrors block.rs::encode_block_file exactly.
    """
    header: BlockHeader = parsed["header"]
    recipients: list[RecipientEntry] = parsed["recipients"]
    aead: AeadSection = parsed["aead"]
    sig: SignatureSuffix = parsed["signature"]

    out = bytearray()

    # Header
    out += header.magic.to_bytes(4, "big")
    out += header.format_version.to_bytes(2, "big")
    out += header.suite_id.to_bytes(2, "big")
    out += header.file_kind.to_bytes(2, "big")
    out += header.vault_uuid
    out += header.block_uuid
    out += header.created_at_ms.to_bytes(8, "big")
    out += header.last_mod_ms.to_bytes(8, "big")
    out += len(header.vector_clock).to_bytes(2, "big")
    for vc in header.vector_clock:
        out += vc.device_uuid
        out += vc.counter.to_bytes(8, "big")

    # Recipient table
    out += len(recipients).to_bytes(2, "big")
    for r in recipients:
        out += r.fingerprint
        out += r.ct_x
        out += r.ct_pq
        out += r.nonce_w
        out += r.ct_w

    # AEAD section
    out += aead.nonce
    out += len(aead.ct).to_bytes(4, "big")
    out += aead.ct
    out += aead.tag

    # Signature suffix
    out += sig.author_fingerprint
    out += ED25519_SIG_LEN.to_bytes(2, "big")
    out += sig.sig_ed
    out += ML_DSA_65_SIG_LEN.to_bytes(2, "big")
    out += sig.sig_pq

    return bytes(out)


def run_diff_replay(target: str, input_path: str) -> int:
    """Differential replay one input through the Python decoder for `target`.

    Output (always to stdout, single line of JSON):
      {"status": "accept", "reencoded_b64": "..."}    # for non-TOML targets
      {"status": "accept", "reencoded_b64": ""}       # for vault_toml (no roundtrip)
      {"status": "reject", "error_class": "..."}

    Exit code: always 0 for accept|reject; nonzero only for unrecoverable
    script errors (e.g. unknown target).
    """
    try:
        with open(input_path, "rb") as f:
            data = f.read()
    except OSError as e:
        print(json.dumps({"status": "reject", "error_class": f"io: {type(e).__name__}"}))
        return 0

    try:
        if target == "vault_toml":
            # Crash-only target. Try to UTF-8 decode and parse.
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError as e:
                raise e
            py_decode_vault_toml(text)
            print(json.dumps({"status": "accept", "reencoded_b64": ""}))
            return 0
        elif target == "record":
            parsed = py_decode_record(data)
            reencoded = py_encode_record(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "contact_card":
            parsed = py_decode_contact_card(data)
            reencoded = py_encode_contact_card(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "bundle_file":
            parsed = py_decode_bundle_file(data)
            reencoded = py_encode_bundle_file(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "manifest_file":
            parsed = py_decode_manifest_file(data)
            reencoded = py_encode_manifest_file(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        elif target == "block_file":
            parsed = py_decode_block_file(data)
            reencoded = py_encode_block_file(parsed)
            print(json.dumps({
                "status": "accept",
                "reencoded_b64": base64.standard_b64encode(reencoded).decode("ascii"),
            }))
            return 0
        else:
            print(json.dumps({"status": "reject", "error_class": f"unknown target {target}"}))
            return 0
    except Exception as e:
        print(json.dumps({"status": "reject", "error_class": type(e).__name__}))
        return 0


# ---------------------------------------------------------------------------
# Combined entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument(
        "--diff-replay",
        nargs=2,
        metavar=("TARGET", "INPUT_PATH"),
        help="differential replay mode: decode one input file for one target, emit JSON",
    )
    args, _ = parser.parse_known_args()
    if args.diff_replay:
        target, input_path = args.diff_replay
        return run_diff_replay(target, input_path)

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
    print("--- Section R: revoke re-key clean-room verification (§6.5.1) ---")
    revoke_ok, revoke_lines = section_revoke_kat()
    for ln in revoke_lines:
        print(ln)

    print()
    print("--- Section S: sync-pass classification clean-room replay (D.1.13) ---")
    sync_pass_ok, sync_pass_lines = section_sync_pass_kat()
    for ln in sync_pass_lines:
        print(ln)

    print()
    print("--- Section C: convergence_kat.json two-client convergence (C.4) ---")
    convergence_ok, convergence_lines = section_convergence_kat()
    for ln in convergence_lines:
        print(ln)

    print()
    print("--- Section P: manifest TrashEntry purge marker (§7.2, #399) ---")
    purge_ok, purge_lines = section_purge_scenario()
    for ln in purge_lines:
        print(ln)

    print()
    if (
        section1_ok
        and section2_ok
        and section3_ok
        and section4_ok
        and section5_ok
        and revoke_ok
        and sync_pass_ok
        and convergence_ok
        and purge_ok
    ):
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
    if not revoke_ok:
        print("FAIL: revoke re-key clean-room verification", file=sys.stderr)
    if not sync_pass_ok:
        print("FAIL: sync-pass classification clean-room replay", file=sys.stderr)
    if not convergence_ok:
        print("FAIL: convergence_kat.json two-client convergence", file=sys.stderr)
    if not purge_ok:
        print("FAIL: manifest TrashEntry purge marker scenario", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
