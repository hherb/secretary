"""Typed §6.3 record rejections carrying a rule token, and the per-key value
checks `py_decode_record` applies the moment it reads a key (#641).

WHY THE MOMENT IT READS A KEY.  `record.rs::parse_record_map` type- and
range-checks each value inside its entry loop, in wire order, and reports a
missing required key only after the loop.  This package used to check
presence first and types afterwards, so a body carrying both faults named a
different rule in each language.  The order is parity between our two
implementations -- vault-format §6.3 states none -- and Section RTS check 5
pins it.

COARSE ON PURPOSE.  `RecordNonCanonical` covers §6.2 rules 1, 2 and 3 and
trailing bytes alike, because Rust's fieldless
`RecordError::NonCanonicalEncoding` cannot tell them apart, and a token may
only draw a distinction both implementations can make.  The message keeps the
specific text.

`RecordMissingField` subclasses `KeyError` so `str()` renders exactly as the
bare `KeyError` it replaces; every other class is a `ValueError`.  Both bases
are in `conformance_lib.rejection`'s verdict allowlist.
"""

from __future__ import annotations

from typing import Any

# The one bool-excluding integer predicate, shared with every other
# integer position under `codec/` (#669). Kept under its original private
# name so this module's call sites are untouched.
from conformance_lib.codec.integer_rules import is_integer as _is_integer

# §6.3: `record_uuid` and each field's `device_uuid` are 16-byte bstr.
RECORD_UUID_LEN = 16


class RecordWrongType(ValueError):
    """A key or value has the wrong CBOR type, or a uuid the wrong length."""

    token = "wrong_type"


class RecordIntegerOutOfRange(ValueError):
    """An integer that must be a u64 is negative."""

    token = "integer_out_of_range"


class RecordDuplicateKey(ValueError):
    """A map this decoder interprets repeats a key."""

    token = "duplicate_map_key"


class RecordMissingField(KeyError):
    """A required key is absent."""

    token = "missing_field"


class RecordNonCanonical(ValueError):
    """The record is not in canonical form: §6.2 rule 1, 2 or 3, or trailing bytes."""

    token = "non_canonical_unclassified"


class UncheckedKnownKey(RuntimeError):
    """A caller passed a key these checks have no arm for -- a bug in this
    package, never a verdict on the input.

    Raised by the fall-through of `check_record_value` and `check_field_value`
    here, and of `codec/card.py`'s `check_card_value` (#691), so a key added
    to `RECORD_KNOWN_KEYS`, `RECORD_FIELD_KNOWN_KEYS` or `KNOWN_CARD_KEYS`
    without an arm in its own checker fails loudly instead of passing its
    value unchecked.  A
    `RuntimeError` deliberately: it is absent from
    `conformance_lib.rejection`'s verdict allowlist, so the differential
    replay scores it as a harness failure rather than as a rejection.
    """


def check_uint(value: Any, message: str) -> Any:
    """`record.rs::take_u64`: a non-integer is a wrong type; a negative
    integer does not fit a u64."""
    if not _is_integer(value):
        raise RecordWrongType(message)
    if value < 0:
        raise RecordIntegerOutOfRange(message)
    return value


def _is_uuid(value: Any) -> bool:
    return isinstance(value, bytes) and len(value) == RECORD_UUID_LEN


def check_record_value(key: str, value: Any) -> Any:
    """Check one known top-level value (not `fields`) as `parse_record_map`'s
    arm for `key` does, and return it."""
    if key == "record_uuid":
        if not _is_uuid(value):
            raise RecordWrongType(f"record_uuid must be 16-byte bstr, got {type(value).__name__}")
    elif key == "record_type":
        if not isinstance(value, str):
            raise RecordWrongType("record_type must be tstr")
    elif key in ("created_at_ms", "last_mod_ms", "tombstoned_at_ms"):
        check_uint(value, f"{key} must be uint, got {value!r}")
    elif key == "tags":
        if not isinstance(value, list):
            raise RecordWrongType("record tags must be array")
        if not all(isinstance(t, str) for t in value):
            raise RecordWrongType("record tags entries must be tstr")
    elif key == "tombstone":
        if not isinstance(value, bool):
            raise RecordWrongType("record tombstone must be bool")
    else:
        raise UncheckedKnownKey(f"no value check for known record key {key!r}")
    return value


def check_field_value(fname: str, key: str, value: Any) -> Any:
    """Check one known value inside `fields[fname]` as `parse_field_map`'s arm
    for `key` does, and return it."""
    if key == "value":
        if not isinstance(value, (str, bytes)):
            raise RecordWrongType(f"field {fname!r} value must be tstr or bstr")
    elif key == "last_mod":
        check_uint(value, f"field {fname!r} last_mod must be uint")
    elif key == "device_uuid":
        if not _is_uuid(value):
            raise RecordWrongType(f"field {fname!r} device_uuid must be 16-byte bstr")
    else:
        raise UncheckedKnownKey(f"no value check for known record field key {key!r}")
    return value
