"""Typed §6.1/§6.2 block-file envelope rejections carrying a rule token (#641).

Subclasses of `cursor.ParseError`, deliberately NOT of a new base: every
existing `except ParseError` in this package -- `sections/block_kat.py`,
`sections/revoke.py`, the golden-vault verifier -- keeps catching them, and
`conformance_lib.rejection` already admits `ParseError` as a verdict.
`ParseError` itself keeps `container_malformed` for every other envelope
fault.

Only distinctions `core/src/vault/block.rs` also draws are drawn here -- the
vocabulary's standing rule that a token may only draw a distinction both
implementations can make.  `manifest_file`'s envelope is untouched; #640 is
about why that one cannot be refined the same way.
"""

from __future__ import annotations

from conformance_lib.cursor import ParseError


class UnsupportedEnvelopeVersion(ParseError):
    """`format_version` or `suite_id` is not the v1 value."""

    token = "unsupported_version"


class EnvelopeSortOrder(ParseError):
    """A vector-clock or recipient table is out of ascending order."""

    token = "array_sort_order"


class EnvelopeRepeatedValue(ParseError):
    """A vector-clock or recipient table repeats an id."""

    token = "repeated_array_value"


def check_ascending_distinct(ids: list[bytes], what: str, key: str) -> None:
    """Raise at the FIRST adjacent pair that is not strictly ascending.

    Classified the way `block.rs`'s `match w[0].cmp(&w[1])` classifies it:
    an equal pair is a repeat, a descending pair is disorder.  A merged
    `prev >= nxt` check could not tell the two apart, which is why this
    exists.  The disorder message is the one the merged check raised.
    """
    for index, (prev, nxt) in enumerate(zip(ids, ids[1:])):
        if prev == nxt:
            raise EnvelopeRepeatedValue(f"{what} repeat a {key} at positions {index} and {index + 1}")
        if prev > nxt:
            raise EnvelopeSortOrder(f"{what} not strictly ascending by {key}")
