"""Section RTS -- every committed single-fault seed for a token-compared
`block_file` or `record` target is rejected with the rule its file name
says, in this package as in Rust (#641).

WHAT THIS PINS.  `core/tests/rule_token_seeds.rs` generates one seed per
`(token, shape)` row, binds each committed file's BYTES to its row, and
requires the Rust decoder to name the file's token.  This section is the
Python half of the same binding: every `<token>__<shape>.bin` must be
REJECTED -- a verdict, never an `error` -- with exactly `<token>`, through
`diff_replay.replay_bytes`, the very function the differential replay's
worker calls.  So every committed seed is a strict cross-language comparison
in its own right, in the blocking `clean-room conformance` job, independent
of `differential_replay.rs`.

WHY IDENTITY TOO (check 1).  Label binding reaches only the classes some seed
exercises.  Section RTV's check 1 records why the expected token is written
out rather than read off the class: membership in the vocabulary is
satisfied by any of the seventeen.

WHY FLOORS (check 3) AND AN EXPECTED TOKEN SET (check 4).  An emptied
directory satisfies check 2 vacuously, and a directory whose seeds were all
relabelled onto one token satisfies checks 2 and 3.

CHECK 5 IS PARITY, NOT SPEC.  Seven two-fault `record` bodies are built in
this section and never committed, because vault-format §6.3 fixes no report
order and a committed cross-language row must not pin one (#618's lesson).
They pin the phase order `py_decode_record` shares with `record::decode` by
design -- walk, map, per-key checks in wire order, missing keys, canonical
form last -- so a drift in Python's order reds here rather than only in a
local full-corpus replay.  Every committed seed plants ONE fault, so the CI
replay cannot see an order drift at all; this check is what does.  Six rows
each name the drift they catch; the seventh is a regression pin that the
pre-#641 order also passed.
"""

from __future__ import annotations

import os

from pathlib import Path

from conformance_lib import fixtures
from conformance_lib.codec import cbor_faults, record_rules
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.wire import envelope_rules

# Mirrors `rule_token_seeds_helpers::LABEL_SEPARATOR`.
LABEL_SEPARATOR = "__"

# Per target: the minimum number of committed labelled seeds, and the exact
# set of tokens those seeds must name between them.
_TARGETS: dict[str, tuple[int, frozenset[str]]] = {
    "block_file": (
        15,
        frozenset(
            {"container_malformed", "unsupported_version", "array_sort_order", "repeated_array_value"}
        ),
    ),
    "record": (
        22,
        frozenset(
            {
                "malformed_cbor",
                "rule4_tag_or_float",
                "wrong_type",
                "integer_out_of_range",
                "missing_field",
                "duplicate_map_key",
                "non_canonical_unclassified",
            }
        ),
    ),
}

# Every typed class this slice adds, with the token written out.
_TOKENED_CLASSES: tuple[tuple[type, str], ...] = (
    (envelope_rules.UnsupportedEnvelopeVersion, "unsupported_version"),
    (envelope_rules.EnvelopeSortOrder, "array_sort_order"),
    (envelope_rules.EnvelopeRepeatedValue, "repeated_array_value"),
    (cbor_faults.MalformedCbor, "malformed_cbor"),
    (record_rules.RecordWrongType, "wrong_type"),
    (record_rules.RecordIntegerOutOfRange, "integer_out_of_range"),
    (record_rules.RecordDuplicateKey, "duplicate_map_key"),
    (record_rules.RecordMissingField, "missing_field"),
    (record_rules.RecordNonCanonical, "non_canonical_unclassified"),
)


def _labelled_seeds(target: str) -> list[Path]:
    directory = fixtures.fuzz_seed_dir(target)
    return sorted(p for p in directory.iterdir() if p.is_file() and LABEL_SEPARATOR in p.name)


def _label_token(path: Path) -> str:
    return path.name.split(LABEL_SEPARATOR, 1)[0]


def _identity_issues() -> list[str]:
    issues = []
    for cls, want in _TOKENED_CLASSES:
        got = getattr(cls, "token", None)
        if got != want:
            issues.append(f"{cls.__name__} carries token {got!r}, this section expects {want!r}")
    return issues


def _seed_issues(target: str, floor: int, want_tokens: frozenset[str]) -> tuple[list[str], str]:
    try:
        seeds = _labelled_seeds(target)
    except OSError as exc:
        return [f"{target}: cannot list seeds: {type(exc).__name__}: {exc}"], f"{target}: unlisted"
    issues = []
    for path in seeds:
        want = _label_token(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            issues.append(f"{target}/{path.name}: cannot read seed: {type(exc).__name__}: {exc}")
            continue
        verdict = replay_bytes(target, data).verdict
        if verdict.get("status") != "reject":
            issues.append(f"{target}/{path.name}: expected a rejection naming {want!r}, got {verdict}")
        elif verdict.get("rule") != want:
            issues.append(
                f"{target}/{path.name}: Python named {verdict.get('rule')!r}, the file name says "
                f"{want!r} ({verdict.get('error_class')}: {verdict.get('detail')})"
            )
    if len(seeds) < floor:
        issues.append(f"{target}: only {len(seeds)} labelled seeds, floor is {floor}")
    named = {_label_token(p) for p in seeds}
    if named != want_tokens:
        issues.append(
            f"{target}: the seeds name {sorted(named)}, this section expects {sorted(want_tokens)}"
        )
    return issues, f"{target}: {len(seeds)} labelled seeds covering {len(named)} tokens"


# Check 5 -- LOCAL parity-order assertions for `record`.  Two-fault bodies
# built here, never committed: vault-format §6.3 states no report order, and a
# committed cross-language row must not pin one (#618).  They pin the order
# `py_decode_record` shares with `record::decode` by design.
#
# A two-fault body pins an order only if its two faults, each ALONE, name
# DIFFERENT tokens, and a drifted order actually reaches the other one first.
# Each row therefore names the drift it catches, and every named drift was
# measured to move that row's token (single-fault controls, plus the drifted
# decoder run on the body).  A row naming `None` is a regression pin only: its
# body was measured to report the same token under the pre-#641 order, because
# the entry scan meets a truncated key before any key type is read.
_FLOAT16_ZERO = bytes([0xF9, 0x00, 0x00])
_ARRAY_1_HEAD = bytes([0x81])
_MAP_1_HEAD = bytes([0xA1])
_MAP_2_HEAD = bytes([0xA2])
_TAG_1_HEAD = bytes([0xC1])
# An unsigned integer 1, in a map-key position where only text is allowed.
_UINT_1 = bytes([0x01])
# RFC 8949 §3.3 simple value 23: well-formed nowhere in this format.
_UNDEFINED = bytes([0xF7])
# A text head declaring 3 bytes, followed by 1.
_TRUNCATED_TEXT = bytes([0x63, 0xFF])
_TRAILING_BYTE = bytes([0x00])
_UUID_LEN = record_rules.RECORD_UUID_LEN
# How many parity-order cases `_ordering_issues` declares; asserted there.
_ORDERING_CASES = 7


def _ordering_cases() -> tuple[tuple[str, bytes, str, str | None], ...]:
    """`(label, body, token the shared order names, the drift it catches)`."""
    import cbor2

    base = {
        "record_uuid": os.urandom(_UUID_LEN),
        "record_type": "t",
        "fields": {},
        "created_at_ms": 0,
        "last_mod_ms": 0,
    }
    no_last_mod = {k: v for k, v in base.items() if k != "last_mod_ms"}
    return (
        ("a wrong type beside a missing key",
         cbor2.dumps({**no_last_mod, "record_uuid": "text"}, canonical=True), "wrong_type",
         "missing required keys checked before each value"),
        ("a repeated key whose second copy is a float",
         _MAP_2_HEAD + cbor2.dumps("record_type") + cbor2.dumps("t")
         + cbor2.dumps("record_type") + _FLOAT16_ZERO, "rule4_tag_or_float",
         "no whole-body rule-4 walk before interpretation"),
        ("a truncated key behind a non-text key",
         _MAP_2_HEAD + cbor2.dumps(1) + cbor2.dumps(0) + _TRUNCATED_TEXT, "malformed_cbor",
         None),
        ("a schema fault followed by trailing bytes",
         cbor2.dumps(no_last_mod, canonical=True) + _TRAILING_BYTE, "missing_field",
         "trailing bytes judged before the schema"),
        ("a non-map top-level item holding a malformed item",
         _ARRAY_1_HEAD + _UNDEFINED, "malformed_cbor",
         "the top-level map head read before the walk"),
        ("a non-text key whose value is malformed",
         _MAP_1_HEAD + _UINT_1 + _UNDEFINED, "malformed_cbor",
         "key types read before the walk"),
        ("a tag wrapping an otherwise valid record map",
         _TAG_1_HEAD + cbor2.dumps(base, canonical=True), "rule4_tag_or_float",
         "the top-level map head read before the walk"),
    )


def _ordering_issues() -> list[str]:
    cases = _ordering_cases()
    if len(cases) != _ORDERING_CASES:
        raise AssertionError(f"_ORDERING_CASES is {_ORDERING_CASES}, the table holds {len(cases)}")
    issues = []
    for label, body, want, drift in cases:
        verdict = replay_bytes("record", body).verdict
        if verdict.get("status") != "reject" or verdict.get("rule") != want:
            caught = f" -- the drift this row catches: {drift}" if drift else ""
            issues.append(
                f"record order: {label} must report {want!r}, got {verdict.get('status')} "
                f"{verdict.get('rule')!r} ({verdict.get('error_class')}: {verdict.get('detail')}){caught}"
            )
    return issues


def section_rule_token_seeds() -> tuple[bool, list[str]]:
    issues = _identity_issues()
    lines = [f"PASS 1: {len(_TOKENED_CLASSES)} typed classes carry exactly their expected token"]
    for target, (floor, want_tokens) in _TARGETS.items():
        target_issues, summary = _seed_issues(target, floor, want_tokens)
        issues.extend(target_issues)
        lines.append(f"PASS 2-4: {summary}, each rejected with its file name's token")
    order_issues = _ordering_issues()
    issues.extend(order_issues)
    lines.append(
        f"PASS 5: {_ORDERING_CASES - len(order_issues)}/{_ORDERING_CASES} record parity-order cases"
    )
    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
