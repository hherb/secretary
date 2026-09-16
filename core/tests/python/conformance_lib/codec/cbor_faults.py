"""Typed CBOR well-formedness rejections, and the two predicates both walks
share (#641).

`MalformedCbor` is what every structural fault in `codec/scanner.py` and
`codec/well_formed.py` raises: truncation, an overrun, reserved
additional-info, a misplaced indefinite form or break, a bad chunk, invalid
UTF-8, a simple value outside false/true/null.  It carries the rule token
`malformed_cbor`, the one Rust's `CborDecode` variants map to.  Before #641
those were bare `ValueError`s carrying no token, so a malformed body on a
token-compared target would have been a harness failure rather than a
comparison.

Subclasses `ValueError` deliberately: `conformance_lib.rejection` admits
`ValueError` as a verdict, and Section CS asserts the base.  Messages are
unchanged from the raises it replaced.

The predicates live here, not in `scanner.py`, so the per-value check
(`_check_canonical_item`) and the whole-body walk (`walk_body`) call ONE
implementation of each rule -- the `_reject_rule4_head` move, for the same
reason: two hand-copies of one rule drift.
"""

from __future__ import annotations

# RFC 8949 §3.3: the only simple values this format admits.
SIMPLE_FALSE = 20
SIMPLE_TRUE = 21
SIMPLE_NULL = 22


class MalformedCbor(ValueError):
    """The bytes are not well-formed CBOR (RFC 8949 and vault-format §4.2's
    well-formedness precondition)."""

    token = "malformed_cbor"


def require_utf8(buf: bytes, start: int, end: int, head_at: int) -> None:
    """RFC 8949 §3.1: a text string's content MUST be valid UTF-8."""
    try:
        buf[start:end].decode("utf-8")
    except UnicodeDecodeError as e:
        raise MalformedCbor(
            f"RFC 8949 §3.1: invalid UTF-8 in text string at offset {head_at}: {e}"
        ) from e


def require_false_true_or_null(ai: int, off: int) -> None:
    """RFC 8949 §3.3: a major-7 item here must be false, true or null."""
    if ai not in (SIMPLE_FALSE, SIMPLE_TRUE, SIMPLE_NULL):
        raise MalformedCbor(
            f"RFC 8949 §3.3: major-7 value outside {{false, true, null}} "
            f"at offset {off} (ai={ai})"
        )
