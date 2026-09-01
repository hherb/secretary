"""Strict identity-bundle-file decode/encode pair behind `--diff-replay`'s
`bundle_file` target.
"""

from __future__ import annotations

from conformance_lib.constants import FILE_KIND_IDENTITY_BUNDLE, FORMAT_VERSION, MAGIC
from conformance_lib.wire.envelopes import parse_identity_bundle_envelope

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
