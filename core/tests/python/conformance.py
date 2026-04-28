#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""
secretary block KAT conformance script.

Run with:

    cd core/tests/python
    uv run conformance.py

Or, equivalently, from the repo root:

    uv run --no-project core/tests/python/conformance.py

Loads `core/tests/data/block_kat.json` and validates each vector's
`expected.block_file` hex bytes parse cleanly under the §6.1 wire format
declared in `docs/vault-format.md`. The parser is intentionally written
from the spec doc only -- it does not import or call into the Rust core
-- which is the §15 conformance contract for AGPL clean-room
re-implementation rights.

Scope (Task 8):

  This first slice of the cross-language conformance scaffold validates
  the on-disk byte LAYOUT only:

  - File-level structure: magic, format_version, suite_id, file_kind.
  - Header field offsets, vector_clock entry count and ordering.
  - Recipient table: count, per-entry fixed length (1208 bytes).
  - AEAD section: nonce, ct_len, ct, tag.
  - Signature suffix: author_fingerprint, sig_ed_len/sig_ed,
    sig_pq_len/sig_pq.
  - Cross-checks: recipient fingerprint matches the JSON's
    `inputs.author_fingerprint`; declared lengths sum to file size; the
    decoded fingerprints / vault_uuid / block_uuid match the JSON
    inputs; sig_ed_len == 64 and sig_pq_len == 3309.

  Full hybrid-decap + AEAD-decrypt + hybrid-verify lands with PR-B's
  `golden_vault_001/` fixture and a richer Python conformance harness
  that reproduces the cryptographic operations end-to-end. That layer
  requires bit-identical Rust/Python keygen given the same RNG seed
  (X25519, ML-KEM-768, Ed25519, ML-DSA-65) which is not yet wired into
  this fixture.

Exit codes:

  0  all vectors parsed and cross-checked successfully.
  1  any vector failed structural parsing or a cross-check.
  2  fixture file missing or malformed JSON.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

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
# Entry point
# ---------------------------------------------------------------------------


def fixture_path() -> Path:
    """Resolve `core/tests/data/block_kat.json` from this script's location."""
    here = Path(__file__).resolve().parent
    return here.parent / "data" / "block_kat.json"


def load_fixture(path: Path) -> dict:
    if not path.is_file():
        print(f"FAIL: fixture not found: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"FAIL: fixture is not valid JSON: {e}", file=sys.stderr)
        sys.exit(2)


def main(argv: Iterable[str]) -> int:
    fixture = load_fixture(fixture_path())

    if fixture.get("version") != 1:
        print(
            f"FAIL: unsupported block_kat.json version {fixture.get('version')!r}",
            file=sys.stderr,
        )
        return 1

    vectors = fixture.get("vectors", [])
    if not vectors:
        print("FAIL: fixture has no vectors", file=sys.stderr)
        return 1

    all_ok = True
    for v in vectors:
        report = check_vector(v)
        if report.ok:
            print(f"PASS  {report.name}")
        else:
            all_ok = False
            print(f"FAIL  {report.name}")
            for issue in report.issues:
                print(f"      - {issue}")

    print()
    if all_ok:
        print(f"OK: {len(vectors)} vector(s) parsed and cross-checked.")
        return 0
    print("FAIL: one or more vectors did not pass.")
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
