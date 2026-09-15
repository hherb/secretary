"""Section WF -- `codec/well_formed.py`'s `walk_body`, case for case the twin
of `core/src/cbor/well_formed/tests.rs` (#641).

`py_decode_record` runs `walk_body` before it reads a key, so that a body that
is not well-formed CBOR is reported as that, and a well-formed body carrying a
tag or a float as rule 4 -- the order `record::decode` reports them in.
Section RTS reaches the walk only through the shapes the committed seeds
plant; this section pins every rule, the precedence in both directions, and
the depth behaviour directly.

Each case is `(label, body, outcome, value)`.  `outcome` is `"end"` (the walk
returns `value`, the offset one past the item), `"malformed"` (it raises
`MalformedCbor`), or `"tag"` / `"float"` (it raises `NonCanonicalItem` with
rule 4 for a tag or a float at offset `value` -- the Rust twin's
`WalkFault::Tag` / `WalkFault::Float`, both checked exactly, kind and offset).

The last eight cases pin branches the first cut of both test lists left
open, each mirroring an assertion in the Rust twin: the indefinite form on
major 1 and on major 6 (both a well-formedness fault, never a tag), reserved
additional-info 29 and 30, float32 and float64 (beside float16), tag 3 (beside
tags 1 and 2), and a byte-order-sensitive two-byte length argument -- a
little-endian argument fold would read `0x01 0x00` as length 1 and report the
item ending one payload byte in, at offset 4, rather than at 259.
"""

from __future__ import annotations

import re

from conformance_lib.codec.cbor_faults import MalformedCbor
from conformance_lib.codec.scanner import NonCanonicalItem
from conformance_lib.codec.well_formed import walk_body

# RFC 8949 initial bytes, named so each case reads as the shape it plants.
UINT_0 = 0x00
UINT_INDEFINITE = 0x1F
RESERVED_AI_28 = 0x1C
BYTES_1 = 0x41
BYTES_FOUR_BYTE_LENGTH = 0x5A
TEXT_1 = 0x61
TEXT_3 = 0x63
TEXT_INDEFINITE = 0x7F
ARRAY_1 = 0x81
ARRAY_2 = 0x82
ARRAY_INDEFINITE = 0x9F
MAP_1 = 0xA1
MAP_INDEFINITE = 0xBF
TAG_1 = 0xC1
TAG_BIGNUM_POSITIVE = 0xC2
SIMPLE_16 = 0xF0
FALSE, TRUE, NULL, UNDEFINED = 0xF4, 0xF5, 0xF6, 0xF7
SIMPLE_ONE_BYTE = 0xF8
SIMPLE_ARG_32 = 0x20
FLOAT16 = 0xF9
BREAK = 0xFF
ASCII_A = ord("a")
INVALID_UTF8 = 0xFF
UTF8_TWO_BYTE_LEAD, UTF8_CONTINUATION = 0xC3, 0xA9
# Deeper than ciborium's recursion limit, and than a recursive Python walk
# could be trusted with.
DEPTH_BEYOND_CIBORIUM_LIMIT = 300
MAX_U32 = 0xFFFFFFFF

# The bytes below are used only by the last eight rows the module docstring
# names.  `TAG_3_BIGNUM_NEGATIVE` is numerically the same byte as
# `UTF8_TWO_BYTE_LEAD` above -- CBOR gives 0xC3 two different meanings
# depending on whether it is a head or a string payload byte -- so each gets
# its own name for the case it plants.
NINT_INDEFINITE = 0x3F  # major 1 (negative int), ai 31.
TAG_INDEFINITE = 0xDF  # major 6 (tag), ai 31.
RESERVED_AI_29 = 0x1D
RESERVED_AI_30 = 0x1E
FLOAT32 = 0xFA
FLOAT64 = 0xFB
TAG_3_BIGNUM_NEGATIVE = 0xC3
BYTES_TWO_BYTE_LENGTH = 0x59  # major 2 (byte string), ai 25: two-byte length.
LENGTH_HIGH_BYTE = 0x01
LENGTH_LOW_BYTE = 0x00
# `0x0100` read big-endian is 256; a little-endian fold would misread it as 1.
BIG_ENDIAN_PAYLOAD_LEN = 256
BIG_ENDIAN_HEAD_LEN = 3  # the two-byte length head: one initial byte plus two argument bytes.
FILL_BYTE = 0x00  # any byte works: these rows check the argument-length head, not the payload.


def _b(*items: int) -> bytes:
    return bytes(items)


CASES: tuple[tuple[str, bytes, str, int | None], ...] = (
    ("uint", _b(UINT_0), "end", 1),
    ("false", _b(FALSE), "end", 1),
    ("true", _b(TRUE), "end", 1),
    ("null", _b(NULL), "end", 1),
    ("text", _b(TEXT_1, ASCII_A), "end", 2),
    ("map", _b(MAP_1, TEXT_1, ASCII_A, UINT_0), "end", 4),
    ("indefinite map", _b(MAP_INDEFINITE, TEXT_1, ASCII_A, UINT_0, BREAK), "end", 5),
    ("chunked text", _b(TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK), "end", 4),
    ("first item only", _b(UINT_0, UNDEFINED), "end", 1),
    ("empty input", b"", "malformed", None),
    ("text overruns", _b(TEXT_3, ASCII_A), "malformed", None),
    ("map value missing", _b(MAP_1, TEXT_1), "malformed", None),
    ("indefinite array unterminated", _b(ARRAY_INDEFINITE, UINT_0), "malformed", None),
    ("float truncated", _b(FLOAT16, UINT_0), "malformed", None),
    ("length past input", bytes([BYTES_FOUR_BYTE_LENGTH]) + MAX_U32.to_bytes(4, "big"), "malformed", None),
    ("reserved additional-info", _b(RESERVED_AI_28), "malformed", None),
    ("indefinite integer", _b(UINT_INDEFINITE), "malformed", None),
    ("stray break", _b(BREAK), "malformed", None),
    ("break in a definite array", _b(ARRAY_1, BREAK), "malformed", None),
    ("undefined", _b(UNDEFINED), "malformed", None),
    ("unassigned simple", _b(SIMPLE_16), "malformed", None),
    ("one-byte simple", _b(SIMPLE_ONE_BYTE, SIMPLE_ARG_32), "malformed", None),
    ("nested indefinite chunk",
     _b(TEXT_INDEFINITE, TEXT_INDEFINITE, TEXT_1, ASCII_A, BREAK, BREAK), "malformed", None),
    ("chunk of another major", _b(TEXT_INDEFINITE, BYTES_1, ASCII_A, BREAK), "malformed", None),
    ("invalid utf-8", _b(TEXT_1, INVALID_UTF8), "malformed", None),
    ("invalid utf-8 in a chunk", _b(TEXT_INDEFINITE, TEXT_1, INVALID_UTF8, BREAK), "malformed", None),
    ("utf-8 split across chunks",
     _b(TEXT_INDEFINITE, TEXT_1, UTF8_TWO_BYTE_LEAD, TEXT_1, UTF8_CONTINUATION, BREAK), "malformed", None),
    ("tag", _b(TAG_1, UINT_0), "tag", 0),
    ("bignum tag", _b(TAG_BIGNUM_POSITIVE, BYTES_1, ASCII_A), "tag", 0),
    ("float", _b(FLOAT16, UINT_0, UINT_0), "float", 0),
    ("malformed after a tag", _b(ARRAY_2, TAG_1, UINT_0, UNDEFINED), "malformed", None),
    ("malformed before a tag", _b(ARRAY_2, UNDEFINED, TAG_1, UINT_0), "malformed", None),
    ("first rule-4 fault wins", _b(ARRAY_2, FLOAT16, UINT_0, UINT_0, TAG_1, UINT_0), "float", 1),
    ("indefinite map ends mid-entry", _b(MAP_INDEFINITE, TEXT_1, ASCII_A, BREAK), "malformed", None),
    ("deep nesting",
     bytes([ARRAY_1] * DEPTH_BEYOND_CIBORIUM_LIMIT + [UINT_0]), "end", DEPTH_BEYOND_CIBORIUM_LIMIT + 1),
    # -- The branches the first cut of both test lists left open (see the
    # module docstring). --
    ("negative-int indefinite", _b(NINT_INDEFINITE), "malformed", None),
    ("tag indefinite", _b(TAG_INDEFINITE), "malformed", None),
    ("reserved additional-info 29", _b(RESERVED_AI_29), "malformed", None),
    ("reserved additional-info 30", _b(RESERVED_AI_30), "malformed", None),
    ("float32", _b(FLOAT32, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE), "float", 0),
    ("float64",
     _b(FLOAT64, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE, FILL_BYTE),
     "float", 0),
    ("tag 3 bignum negative", _b(TAG_3_BIGNUM_NEGATIVE, BYTES_1, ASCII_A), "tag", 0),
    ("two-byte length argument is big-endian",
     _b(BYTES_TWO_BYTE_LENGTH, LENGTH_HIGH_BYTE, LENGTH_LOW_BYTE) + bytes([FILL_BYTE]) * BIG_ENDIAN_PAYLOAD_LEN,
     "end", BIG_ENDIAN_HEAD_LEN + BIG_ENDIAN_PAYLOAD_LEN),
)

# The two rule-4 messages this walk can raise: `scanner._reject_rule4_head`
# composes "CBOR tag at offset N" or "float at offset N", and
# `NonCanonicalItem` prefixes "rule 4: ".  Both groups are read back and
# compared for EQUALITY -- the Rust twin asserts `WalkFault::Tag { offset }` /
# `WalkFault::Float { offset }` exactly, and a substring test for
# "at offset 1" would also have matched offsets 10 through 19.
_RULE4_MESSAGE = re.compile(r"rule 4: (?P<kind>CBOR tag|float) at offset (?P<offset>\d+)")
_RULE4_KIND = {"CBOR tag": "tag", "float": "float"}


def _case_issue(label: str, body: bytes, outcome: str, value: int | None) -> str | None:
    try:
        end = walk_body(body)
    except MalformedCbor:
        return None if outcome == "malformed" else f"{label}: raised MalformedCbor, expected {outcome}"
    except NonCanonicalItem as exc:
        match = _RULE4_MESSAGE.fullmatch(str(exc))
        if exc.rule != 4 or match is None:
            return f"{label}: raised {exc!r}, expected {outcome} {value}"
        got = (_RULE4_KIND[match["kind"]], int(match["offset"]))
        if got != (outcome, value):
            return f"{label}: reported a {got[0]} at offset {got[1]}, expected {outcome} {value}"
        return None
    except RecursionError:
        return f"{label}: RecursionError -- the walk must be iterative"
    if outcome != "end" or end != value:
        return f"{label}: returned {end}, expected {outcome} {value}"
    return None


def section_well_formed_walk() -> tuple[bool, list[str]]:
    issues = [issue for case in CASES if (issue := _case_issue(*case)) is not None]
    lines = [f"PASS: {len(CASES) - len(issues)}/{len(CASES)} walk cases behave as the Rust twin's"]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)
