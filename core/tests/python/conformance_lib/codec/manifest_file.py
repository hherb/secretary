"""Strict §4.1 manifest-FILE decode/encode pair behind `--diff-replay`'s
`manifest_file` target -- the outer signed envelope, not the §4.2 body.
"""

from __future__ import annotations

from conformance_lib.constants import ED25519_SIG_LEN, FILE_KIND_MANIFEST, FORMAT_VERSION, MAGIC, ML_DSA_65_SIG_LEN, SUITE_ID
from conformance_lib.wire.envelopes import parse_manifest_file

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
