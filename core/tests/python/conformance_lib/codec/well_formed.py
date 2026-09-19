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
  * a chain of arrays, maps and tags nested past crypto-design §6.2 rule 6's
    limit of 256, as `NestingTooDeep` (see ITERATIVE below);
  * then any tag (bignum tags 2 and 3 included) or float, as rule 4.

PRECEDENCE.  A well-formedness fault anywhere in the item outranks a rule-4
fault anywhere: the first tag or float is remembered and raised only once the
whole item has proven well-formed.

ITERATIVE on purpose, and bounded by crypto-design §6.2 rule 6 (#667).
`scanner._scan_item` recurses, so a deeply nested body used to raise
`RecursionError` -- a harness failure, not a verdict.  This walk keeps an
explicit stack, and the stack is the depth count: a head that would open level
257 raises `NestingTooDeep` at once, like every well-formedness fault, so no
recursive phase after it ever sees more than 256 levels.  `reject_excessive_nesting`
is the same traversal with the content checks off, for the decoders that have
no `walk_body` of their own.

SCOPE.  The first item only.  Trailing bytes are the caller's to judge, and
`py_decode_record` judges them LAST, where `record::decode` meets them: its
parse performs no EOF check.
"""

from __future__ import annotations

from dataclasses import dataclass

from conformance_lib.codec.cbor_faults import MalformedCbor, NestingTooDeep, require_false_true_or_null, require_room_for_another_level, require_utf8
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


def _string_end(buf: bytes, pos: int, major: int, arg: int | None, head: int, check_utf8: bool) -> int:
    text = major == MAJOR_TEXT and check_utf8
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


def _walk(buf: bytes, pos: int, *, check_content: bool) -> int:
    """The one traversal both entry points share: item boundaries, crypto-design
    §6.2 rule 6 always, and -- when `check_content` -- UTF-8, simple values and
    rule 4.  The depth check lives here once, so it cannot drift between them."""
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
            pos = _string_end(buf, pos, major, arg, head, check_utf8=check_content)
        elif major in (MAJOR_ARRAY, MAJOR_MAP):
            require_room_for_another_level(len(stack), pos)
            is_map = major == MAJOR_MAP
            left = None if arg is None else arg * (ITEMS_PER_MAP_ENTRY if is_map else 1)
            stack.append(_Frame(definite_left=left, is_map=is_map))
            pos += head
        elif major == MAJOR_TAG:
            require_room_for_another_level(len(stack), pos)
            if check_content:
                first_rule4 = first_rule4 or _rule4_at(major, ai, pos)
            stack.append(_Frame(definite_left=1))
            pos += head
        else:
            if ai == CBOR_AI_INDEFINITE:
                raise MalformedCbor(f"unexpected break at offset {pos}")
            if check_content:
                rule4 = _rule4_at(major, ai, pos)
                if rule4 is None:
                    require_false_true_or_null(ai, pos)
                first_rule4 = first_rule4 or rule4
            pos += head


def walk_body(buf: bytes, pos: int = 0) -> int:
    """Walk the CBOR item at `pos`; return the offset one past it.

    Raises `MalformedCbor` for a well-formedness fault anywhere in the item --
    `NestingTooDeep`, a subclass, for a level past crypto-design §6.2 rule 6,
    at once -- else `NonCanonicalItem` (rule 4) for the first tag or float.
    """
    return _walk(buf, pos, check_content=True)


def reject_excessive_nesting(buf: bytes, *, later_phases_scan_in_byte_order: bool) -> None:
    """crypto-design §6.2 rule 6 over a whole document, and nothing else (#667).

    The first statement of every `codec/` decoder that has no `walk_body` of its
    own (the manifest, the contact card, the trash entry), so a document nested
    past the limit is refused before any RECURSIVE phase runs -- which is what
    turned a 995-level manifest into a `RecursionError` harness failure.

    It walks item boundaries only.  It reports no content-level fault (invalid
    UTF-8, a disallowed simple value, a tag or float as rule 4), since none of
    those moves a boundary; a tag still counts as a level.

    At a STRUCTURAL fault it cannot walk past -- a truncated head, an overrun, a
    bad chunk, a stray break -- what it does depends on the caller, which must
    say, because the answer is a property of the caller's later phases:

      * `later_phases_scan_in_byte_order=True` (the manifest, whose later phases
        are `scanner._scan_item`): it returns, leaving the fault to those phases
        to report as they always have.  They scan in byte order and raise at
        the same byte, so none of them can nest past 256 levels first.
      * `later_phases_scan_in_byte_order=False` (the contact card and the trash
        entry, whose next phase is `cbor2.loads`): it raises the fault.  cbor2
        is NOT a byte-order well-formedness check -- it accepts a stray break
        inside a definite array, returning a sentinel object -- so a body with
        a break ahead of a 300-level chain used to pass this pass silently and
        be rejected by the ENCODER failing on that sentinel (PR #684 review).
    """
    try:
        _walk(buf, 0, check_content=False)
    except NestingTooDeep:
        raise
    except MalformedCbor:
        if not later_phases_scan_in_byte_order:
            raise
