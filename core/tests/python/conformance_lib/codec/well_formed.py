"""A whole-body well-formedness walk, run before anything is interpreted (#641).

The clean-room twin of `core/src/cbor/well_formed.rs`.  `py_decode_record` runs
it first, so a body that is not well-formed CBOR is reported as that, and a
well-formed body carrying a tag or a float as crypto-design §6.2 rule 4,
before any key is read -- the order `record::decode` reports them in.

WHAT IT CHECKS -- RFC 8949 well-formedness plus vault-format §4.2's
precondition list, then rule 4:
  * a truncated head, argument or payload, and an indefinite item with no break;
  * reserved additional-info 28-30, the indefinite form on majors 0, 1 and 6,
    and a stray break;
  * an indefinite-string chunk that is not a definite string of the same major
    (RFC 8949 §3.2.3) -- which rejects a NESTED indefinite chunk;
  * text that is not valid UTF-8, per string and per chunk (a sequence split
    across two chunks is invalid; ciborium holds the same, measured);
  * a major-7 simple value other than false/true/null;
  * then any tag (bignum tags 2 and 3 included) or float, as rule 4.

PRECEDENCE.  A well-formedness fault anywhere in the item outranks a rule-4
fault anywhere: the first tag or float is remembered and raised only once the
whole item has proven well-formed.

ITERATIVE on purpose.  `scanner._scan_item` recurses, so a deeply nested body
raises `RecursionError` -- a harness failure, not a verdict.  This walk keeps
an explicit stack and has no depth cap of its own, like its Rust twin.  That
keeps the WALK from failing, not the decoder: `py_decode_record` calls the
recursive `_scan_map_entries` right after it, so a record nested past Python's
recursion limit (about 1,000 levels) is still a harness failure.  That residual
is #667, beside ciborium's own 256-level limit on the Rust side.

SCOPE.  The first item only.  Trailing bytes are the caller's to judge, and
`py_decode_record` judges them LAST, where `record::decode` meets them: its
parse performs no EOF check.
"""

from __future__ import annotations

from dataclasses import dataclass

from conformance_lib.codec.cbor_faults import MalformedCbor, require_false_true_or_null, require_utf8
from conformance_lib.codec.scanner import CBOR_AI_INDEFINITE, CBOR_BREAK, NonCanonicalItem, _decode_head, _reject_rule4_head

MAJOR_UINT, MAJOR_NINT, MAJOR_BYTES, MAJOR_TEXT, MAJOR_ARRAY, MAJOR_MAP, MAJOR_TAG, MAJOR_SIMPLE = range(8)
# A map's items are keys and values.
ITEMS_PER_MAP_ENTRY = 2


@dataclass
class _Frame:
    """An open container.  A definite one counts the items it still needs (a
    map counts keys and values; a tag needs one); an indefinite map tracks
    whether a key is waiting for its value."""

    definite_left: int | None
    is_map: bool = False
    mid_entry: bool = False


def _rule4_at(major: int, ai: int, pos: int) -> NonCanonicalItem | None:
    try:
        _reject_rule4_head(major, ai, pos)
    except NonCanonicalItem as exc:
        return exc
    return None


def _payload_end(buf: bytes, head_at: int, start: int, length: int, text: bool) -> int:
    end = start + length
    if end > len(buf):
        raise MalformedCbor(f"string length {length} overruns buffer at offset {head_at}")
    if text:
        require_utf8(buf, start, end, head_at)
    return end


def _string_end(buf: bytes, pos: int, major: int, arg: int | None, head: int) -> int:
    text = major == MAJOR_TEXT
    if arg is not None:
        return _payload_end(buf, pos, pos + head, arg, text)
    at = pos + head
    while True:
        if at >= len(buf):
            raise MalformedCbor("unterminated indefinite-length string")
        if buf[at] == CBOR_BREAK:
            return at + 1
        chunk_major, _, chunk_arg, chunk_head = _decode_head(buf, at)
        if chunk_major != major or chunk_arg is None:
            raise MalformedCbor(f"bad chunk in indefinite-length string at {at}")
        at = _payload_end(buf, at, at + chunk_head, chunk_arg, text)


def _close_finished(buf: bytes, pos: int, stack: list[_Frame]) -> int:
    while stack:
        top = stack[-1]
        if top.definite_left == 0:
            stack.pop()
            continue
        at_break = pos < len(buf) and buf[pos] == CBOR_BREAK
        if top.definite_left is None and at_break:
            if top.is_map and top.mid_entry:
                raise MalformedCbor(
                    f"indefinite-length map ends between a key and its value at offset {pos}"
                )
            stack.pop()
            pos += 1
            continue
        break
    return pos


def _count_one_item(stack: list[_Frame]) -> None:
    if not stack:
        return
    top = stack[-1]
    if top.definite_left is not None:
        top.definite_left -= 1
    elif top.is_map:
        top.mid_entry = not top.mid_entry


def walk_body(buf: bytes, pos: int = 0) -> int:
    """Walk the CBOR item at `pos`; return the offset one past it.

    Raises `MalformedCbor` for a well-formedness fault anywhere in the item,
    else `NonCanonicalItem` (rule 4) for the first tag or float.
    """
    stack: list[_Frame] = []
    first_rule4: NonCanonicalItem | None = None
    started = False
    while True:
        pos = _close_finished(buf, pos, stack)
        if started and not stack:
            if first_rule4 is not None:
                raise first_rule4
            return pos
        started = True
        _count_one_item(stack)
        major, ai, arg, head = _decode_head(buf, pos)
        if major in (MAJOR_UINT, MAJOR_NINT):
            pos += head
        elif major in (MAJOR_BYTES, MAJOR_TEXT):
            pos = _string_end(buf, pos, major, arg, head)
        elif major in (MAJOR_ARRAY, MAJOR_MAP):
            is_map = major == MAJOR_MAP
            left = None if arg is None else arg * (ITEMS_PER_MAP_ENTRY if is_map else 1)
            stack.append(_Frame(definite_left=left, is_map=is_map))
            pos += head
        elif major == MAJOR_TAG:
            first_rule4 = first_rule4 or _rule4_at(major, ai, pos)
            stack.append(_Frame(definite_left=1))
            pos += head
        else:
            if ai == CBOR_AI_INDEFINITE:
                raise MalformedCbor(f"unexpected break at offset {pos}")
            rule4 = _rule4_at(major, ai, pos)
            if rule4 is None:
                require_false_true_or_null(ai, pos)
            first_rule4 = first_rule4 or rule4
            pos += head
