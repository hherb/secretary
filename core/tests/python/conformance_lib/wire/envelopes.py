"""§3 / §4.1 signed-envelope parsers: identity bundle and manifest file.

Also the four functions that reconstruct exactly which bytes are covered by
a signature (`*_signed_range`) and which form the AEAD's associated data
(`*_aad`). Those four are where a clean-room implementation most often
diverges, so they are stated once and shared.
"""

from __future__ import annotations

from dataclasses import dataclass

from conformance_lib.constants import AEAD_TAG_LEN, BUNDLE_WRAP_CT_PLUS_TAG_LEN, ED25519_SIG_LEN, FILE_KIND_IDENTITY_BUNDLE, FILE_KIND_MANIFEST, FINGERPRINT_LEN, FORMAT_VERSION, MAGIC, ML_DSA_65_SIG_LEN, RECIPIENT_ENTRY_LEN, SUITE_ID
from conformance_lib.cursor import Cursor, ParseError, take, take_u16, take_u32, take_u64
from conformance_lib.wire.block_file import ParsedBlockFile

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
