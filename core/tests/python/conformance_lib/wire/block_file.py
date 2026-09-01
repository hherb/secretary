"""§6.1 BlockFile binary layout parser -- header, recipient table, AEAD body,
hybrid-signature suffix -- decoded into dataclasses for verification.

Distinct from `conformance_lib.codec.block_file`, which is the strict
decode/encode ROUND-TRIP pair behind `--diff-replay`. This one parses for
inspection; that one parses in order to re-emit byte-identically.
"""

from __future__ import annotations

from dataclasses import dataclass

from conformance_lib.constants import AEAD_NONCE_LEN, AEAD_TAG_LEN, BLOCK_UUID_LEN, DEVICE_UUID_LEN, ED25519_SIG_LEN, FILE_KIND_BLOCK, FINGERPRINT_LEN, FORMAT_VERSION, MAGIC, ML_DSA_65_SIG_LEN, ML_KEM_768_CT_LEN, SUITE_ID, VAULT_UUID_LEN, WRAP_CT_LEN, WRAP_NONCE_LEN, WRAP_TAG_LEN, X25519_PK_LEN
from conformance_lib.cursor import Cursor, ParseError, take, take_u16, take_u32, take_u64

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
