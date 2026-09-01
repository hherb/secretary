"""The single byte-flip mutation helper, shared by two sections.

Section 2 uses it for its three golden-vault tamper checks; Section 3 uses
it to tamper an ML-DSA-65 signature and message. It is here rather than
inside either section so neither has to import the other.
"""

from __future__ import annotations

def _bytes_flip(buf: bytes, idx: int) -> bytes:
    """Return a copy of `buf` with byte `idx` XOR'd with 0xFF."""
    if idx >= len(buf):
        # Wrap to the last byte if the buffer is short -- still a
        # mutation, still must trip verify.
        idx = len(buf) - 1
    out = bytearray(buf)
    out[idx] ^= 0xFF
    return bytes(out)
