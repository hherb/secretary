"""Section RDO -- vault-format §6.3: a default value is written by omission
(#670).

`tags`, `tombstone` and `tombstoned_at_ms` each have a default (the empty
array, `false`, `0`), and the canonical encoding of a record holding a
default leaves the key out. `record.rs`'s `record_to_canonical` has always
omitted all three, so `record::decode`'s re-encode comparison rejects a body
that spells one out. `py_encode_record` used to re-emit whatever it decoded,
so this reader ACCEPTED those bodies: an acceptance divergence no corpus
input reached.

THE MECHANISM IS THE RE-ENCODE, ON BOTH SIDES, DELIBERATELY.  §6.3 states no
reader check separate from canonical form, and Rust has none: its rejection
IS the comparison.  So this is not #608's backstop trap, where an encoder
refusal answered for a reader check §4.2 states on its own.  The writer half
is still asserted separately (check 3), so a reader-side special case cannot
stand in for the encoder.

Three checks, each reporting what it RAN:
  1. each key present at its default is rejected as `RecordNonCanonical`;
  2. controls: the same key absent, and the key at a non-default value, are
     each ACCEPTED -- without them a reader rejecting the key outright passes 1;
  3. the writer omits each default and keeps each non-default.
"""

from __future__ import annotations

from conformance_lib import fixtures
from conformance_lib.codec.record import py_decode_record, py_encode_record
from conformance_lib.codec.record_rules import RecordNonCanonical

# The accepting base every body is built from: no optional key present.
_BASE_SEED = "login.cbor"
# Each optional key's default, and one value that is not its default.
_DEFAULTS: tuple[tuple[str, object], ...] = (
    ("tags", []),
    ("tombstone", False),
    ("tombstoned_at_ms", 0),
)
_NON_DEFAULTS: tuple[tuple[str, object], ...] = (
    ("tags", ["x"]),
    ("tombstone", True),
    ("tombstoned_at_ms", 5),
)


def _base_bytes() -> bytes:
    return (fixtures.fuzz_seed_dir("record") / _BASE_SEED).read_bytes()


def _with_key(key: str, value: object) -> bytes:
    """The base with `key` set to `value`, in canonical key order.

    `cbor2`'s canonical mode reproduces the base byte for byte with nothing
    added (checked below), so the body differs from it by exactly one entry.
    """
    import cbor2

    record = cbor2.loads(_base_bytes())
    record[key] = value
    return cbor2.dumps(record, canonical=True)


def _base_round_trip_issue() -> str | None:
    import cbor2

    try:
        base = _base_bytes()
        if cbor2.dumps(cbor2.loads(base), canonical=True) != base:
            return f"{_BASE_SEED}: cbor2's canonical re-encode is not byte-identical, so a body would carry faults nobody planted"
    except Exception as exc:  # noqa: BLE001 -- a missing/corrupt base is an issue too
        return f"{_BASE_SEED}: raised {type(exc).__name__} while checking the base round-trip: {exc}"
    return None


def _reader_issues() -> tuple[list[str], int]:
    issues = []
    for key, value in _DEFAULTS:
        try:
            py_decode_record(_with_key(key, value))
        except RecordNonCanonical:
            continue
        except Exception as exc:  # noqa: BLE001 -- the wrong rejection is an issue too
            issues.append(f"{key}={value!r}: raised {type(exc).__name__}, expected RecordNonCanonical ({exc})")
            continue
        issues.append(f"{key}={value!r}: ACCEPTED; vault-format §6.3 requires the default to be omitted")
    return issues, len(_DEFAULTS)


def _control_issues() -> tuple[list[str], int]:
    issues = []
    bodies = [("absent (the base)", _base_bytes())]
    bodies.extend((f"{key}={value!r}", _with_key(key, value)) for key, value in _NON_DEFAULTS)
    for label, body in bodies:
        try:
            py_decode_record(body)
        except Exception as exc:  # noqa: BLE001 -- any rejection fails a control
            issues.append(f"control {label}: must be ACCEPTED, raised {type(exc).__name__}: {exc}")
    return issues, len(bodies)


def _writer_issues() -> tuple[list[str], int]:
    n = len(_DEFAULTS) + len(_NON_DEFAULTS)
    try:
        issues = []
        decoded = py_decode_record(_base_bytes())
        omitted = py_encode_record(decoded)
        for key, value in _DEFAULTS:
            if py_encode_record({**decoded, key: value}) != omitted:
                issues.append(f"writer: {key}={value!r} was emitted; §6.3 requires it omitted")
        for key, value in _NON_DEFAULTS:
            if py_encode_record({**decoded, key: value}) == omitted:
                issues.append(f"writer: {key}={value!r} was dropped; only a default is omitted")
        return issues, n
    except Exception as exc:  # noqa: BLE001 -- a decode/encode crash is an issue too
        return [f"writer: raised {type(exc).__name__} while building the writer cases: {exc}"], n


def section_record_default_omission() -> tuple[bool, list[str]]:
    issues = []
    if (issue := _base_round_trip_issue()) is not None:
        return False, [f"  ISSUE: {issue}"]
    reader, n_reader = _reader_issues()
    controls, n_controls = _control_issues()
    writer, n_writer = _writer_issues()
    issues = reader + controls + writer
    lines = [
        f"PASS 1: {n_reader - len(reader)}/{n_reader} present-default bodies rejected as RecordNonCanonical",
        f"PASS 2: {n_controls - len(controls)}/{n_controls} controls accepted (absent, and each non-default)",
        f"PASS 3: {n_writer - len(writer)}/{n_writer} writer cases (defaults omitted, non-defaults kept)",
    ]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)
