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

Three checks, each reporting what it RAN -- `passed`/`executed` counted per
case as it completes, and every case guarded on its own, so a crash is an
ISSUE naming that case and never a PASS line computed from the declared total
(PR #684 review: a raising writer printed "5/6 writer cases" having run none):
  1. each key present at its default is rejected as `RecordNonCanonical`;
  2. controls: the same key absent, and the key at a non-default value, are
     each ACCEPTED -- without them a reader rejecting the key outright passes 1;
  3. the writer omits each default and keeps each non-default, including a
     WRONG-TYPED look-alike (`tombstone: 0`, `tombstoned_at_ms: False`): in
     Python `False == 0`, so a value-only default test would drop them.
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
# Equal to a default under `==` but not of its type; the writer must keep them.
_WRONG_TYPED: tuple[tuple[str, object], ...] = (
    ("tombstone", 0),
    ("tombstoned_at_ms", False),
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


def _run(cases, check) -> tuple[list[str], int, int]:
    """Run `check(label, *case)` per case; it returns an issue or None.  A raise
    is an issue naming that case.  Returns `(issues, passed, executed)`."""
    issues: list[str] = []
    passed = executed = 0
    for case in cases:
        label = case[0]
        try:
            issue = check(*case)
        except Exception as exc:  # noqa: BLE001 -- guard: report, never propagate (#682)
            issue = f"{label}: raised {type(exc).__name__}: {exc}"
        executed += 1
        if issue is None:
            passed += 1
        else:
            issues.append(issue)
    return issues, passed, executed


def _reader_case(label: str, key: str, value: object) -> str | None:
    try:
        py_decode_record(_with_key(key, value))
    except RecordNonCanonical:
        return None
    except Exception as exc:  # noqa: BLE001 -- the wrong rejection is an issue too
        return f"{label}: raised {type(exc).__name__}, expected RecordNonCanonical ({exc})"
    return f"{label}: ACCEPTED; vault-format §6.3 requires the default to be omitted"


def _control_case(label: str, body: object) -> str | None:
    body = body() if callable(body) else body
    try:
        py_decode_record(body)
    except Exception as exc:  # noqa: BLE001 -- any rejection fails a control
        return f"control {label}: must be ACCEPTED, raised {type(exc).__name__}: {exc}"
    return None


def _writer_case(label: str, key: str, value: object, omit: bool) -> str | None:
    decoded = py_decode_record(_base_bytes())
    emitted = py_encode_record({**decoded, key: value}) != py_encode_record(decoded)
    if omit and emitted:
        return f"writer: {label} was emitted; §6.3 requires it omitted"
    if not omit and not emitted:
        return f"writer: {label} was dropped; only a default (of its own type) is omitted"
    return None


def section_record_default_omission() -> tuple[bool, list[str]]:
    if (issue := _base_round_trip_issue()) is not None:
        return False, [f"  ISSUE: {issue}"]
    reader = _run([(f"{k}={v!r}", k, v) for k, v in _DEFAULTS], _reader_case)
    controls = _run(
        [("absent (the base)", _base_bytes)]
        + [(f"{k}={v!r}", (lambda k=k, v=v: _with_key(k, v))) for k, v in _NON_DEFAULTS],
        _control_case,
    )
    writer = _run(
        [(f"{k}={v!r}", k, v, True) for k, v in _DEFAULTS]
        + [(f"{k}={v!r}", k, v, False) for k, v in _NON_DEFAULTS + _WRONG_TYPED],
        _writer_case,
    )
    lines = [
        f"PASS 1: {reader[1]}/{reader[2]} present-default bodies rejected as RecordNonCanonical",
        f"PASS 2: {controls[1]}/{controls[2]} controls accepted (absent, and each non-default)",
        f"PASS 3: {writer[1]}/{writer[2]} writer cases (defaults omitted; non-defaults and wrong-typed look-alikes kept)",
    ]
    issues = reader[0] + controls[0] + writer[0]
    lines.extend(f"  ISSUE: {issue}" for issue in issues)
    return (not issues, lines)
