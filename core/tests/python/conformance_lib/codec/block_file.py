"""Strict §6.1 block-file decode/encode pair behind `--diff-replay`'s
`block_file` target.
"""

from __future__ import annotations

from conformance_lib.constants import ED25519_SIG_LEN, ML_DSA_65_SIG_LEN
from conformance_lib.wire.block_file import AeadSection, BlockHeader, RecipientEntry, SignatureSuffix, parse_block_file

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
