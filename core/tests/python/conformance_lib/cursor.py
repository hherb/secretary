"""Big-endian parsing primitives shared by every §4.1/§6.1 binary parser.

`ParseError` is this package's own wire-format error. It is one of the four
types `conformance_lib.rejection` treats as a deliberate rejection VERDICT
rather than a harness failure, so raising it is a statement about the input,
never about this code.
"""

from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Parsing primitives (big-endian throughout — §6.1 / §14).
# ---------------------------------------------------------------------------


class ParseError(Exception):
    """Raised on any wire-format violation."""


@dataclass
class Cursor:
    """Read-only positional cursor over a bytes buffer.

    Pure data class -- the helpers below are free functions that return
    a new (value, cursor) pair so the caller threads state explicitly.
    """

    buf: bytes
    pos: int = 0

    def remaining(self) -> int:
        return len(self.buf) - self.pos


def take(cur: Cursor, n: int, field: str) -> tuple[bytes, Cursor]:
    if cur.remaining() < n:
        raise ParseError(
            f"truncated reading {field}: need {n} bytes, "
            f"have {cur.remaining()} at offset {cur.pos}"
        )
    out = cur.buf[cur.pos:cur.pos + n]
    return out, Cursor(cur.buf, cur.pos + n)


def take_u16(cur: Cursor, field: str) -> tuple[int, Cursor]:
    raw, cur = take(cur, 2, field)
    return int.from_bytes(raw, "big"), cur


def take_u32(cur: Cursor, field: str) -> tuple[int, Cursor]:
    raw, cur = take(cur, 4, field)
    return int.from_bytes(raw, "big"), cur


def take_u64(cur: Cursor, field: str) -> tuple[int, Cursor]:
    raw, cur = take(cur, 8, field)
    return int.from_bytes(raw, "big"), cur
