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
satisfied by any of the seventeen.  Check 1 also DISCOVERS every verdict
class `cbor_faults`, `record_rules` and `envelope_rules` define, and requires
each to declare `token` in its own body and to appear in the table: a new
subclass that forgot `token =` would otherwise inherit its base's coarse token
silently, and a class the table omits would never be identity-checked (PR
#673 review).

WHY A CLASS PER `block_file` SEED (check 2).  One token covers several
envelope checks: nine `container_malformed` seeds span seven `BlockError`
variants.  With one class for all of them, deleting the `sig_ed_len` check
let the parse fail a few bytes later as a truncation carrying the same token,
and this section stayed green (PR #673 review, measured).  Each `block_file`
seed's Python class is therefore required by name, default-deny, as
`rule_token_seeds.rs` requires its Rust variant.  The `record` classes map one
to one onto their tokens, so a class name there would add nothing.

WHY DISTINCT BYTES (check 2).  A label is bound to its bytes only on the Rust
side, by regeneration.  This side read the file name alone, and three
`malformed_cbor` seeds overwritten with `truncated`'s bytes still passed every
check (PR #673 review, measured).  No two labelled seeds of a target may be
byte-identical.

WHY FLOORS (check 3) AND AN EXPECTED TOKEN SET (check 4).  An emptied
directory satisfies check 2 vacuously, and a directory whose seeds were all
relabelled onto one token satisfies checks 2 and 3.

CHECK 5 IS PARITY, NOT SPEC.  Eight two-fault bodies -- seven `record`, one
`block_file` -- are built in this section and never committed, because
vault-format §6.1 and §6.3 fix no report order and a committed cross-language
row must not pin one (#618's lesson; #668).  The `record` rows pin the phase
order `py_decode_record` shares with `record::decode` by design -- walk, map,
per-key checks in wire order, missing keys, canonical form last -- and the
`block_file` row pins that a table is judged at its FIRST adjacent pair that
is not strictly ascending, as `block.rs` does.  So a drift in Python's order
reds here rather than only in a local full-corpus replay.  Every committed
seed plants ONE fault, so the CI replay cannot see an order drift at all; this
check is what does.  Seven rows each name the drift they catch; the eighth is
a regression pin that the pre-#641 order also passed.  Rust's side of the
`record` parity is pinned by `core/src/vault/record_order_tests.rs`, one
`#[test]` per row, each asserting the exact `RecordError` and its
single-fault controls.
"""

from __future__ import annotations

import os

from pathlib import Path

from conformance_lib import fixtures, rejection
from conformance_lib.codec import cbor_faults, record_rules
from conformance_lib.constants import VECTOR_CLOCK_ENTRY_LEN
from conformance_lib.cursor import Cursor, ParseError
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.wire import envelope_rules
from conformance_lib.wire.block_file import parse_header

# Mirrors `rule_token_seeds_helpers::LABEL_SEPARATOR`.
LABEL_SEPARATOR = "__"

# Per target: the minimum number of committed labelled seeds, and the exact
# set of tokens those seeds must name between them.
_TARGETS: dict[str, tuple[int, frozenset[str]]] = {
    "block_file": (
        23,
        frozenset(
            {"container_malformed", "unsupported_version", "array_sort_order", "repeated_array_value"}
        ),
    ),
    "record": (
        34,
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

# Every typed class the seeds reach, with the token written out.
_TOKENED_CLASSES: tuple[tuple[type, str], ...] = (
    (ParseError, "container_malformed"),
    (envelope_rules.EnvelopeBadMagic, "container_malformed"),
    (envelope_rules.EnvelopeWrongFileKind, "container_malformed"),
    (envelope_rules.EnvelopeNoRecipients, "container_malformed"),
    (envelope_rules.EnvelopeEd25519SignatureLength, "container_malformed"),
    (envelope_rules.EnvelopeMlDsaSignatureLength, "container_malformed"),
    (envelope_rules.EnvelopeTrailingBytes, "container_malformed"),
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


# The modules whose verdict classes check 1 discovers.
_TOKENED_MODULES = (cbor_faults, record_rules, envelope_rules)

# Check 2: the Python class every `block_file` seed must be rejected with,
# keyed by file stem.  Default-deny: a seed missing here is an issue.  A
# truncation is what `cursor.take` raises, the bare `ParseError`.
_BLOCK_FILE_CLASSES: dict[str, str] = {
    "container_malformed__bad_magic": "EnvelopeBadMagic",
    "container_malformed__wrong_file_kind": "EnvelopeWrongFileKind",
    "container_malformed__truncated_header": "ParseError",
    "container_malformed__truncated_recipient_table": "ParseError",
    "container_malformed__zero_recipients": "EnvelopeNoRecipients",
    "container_malformed__wrong_sig_ed_len": "EnvelopeEd25519SignatureLength",
    "container_malformed__wrong_sig_pq_len": "EnvelopeMlDsaSignatureLength",
    "container_malformed__truncated_signature_suffix": "ParseError",
    "container_malformed__trailing_bytes": "EnvelopeTrailingBytes",
    "unsupported_version__format_version": "UnsupportedEnvelopeVersion",
    "unsupported_version__suite_id": "UnsupportedEnvelopeVersion",
    "array_sort_order__vector_clock": "EnvelopeSortOrder",
    "array_sort_order__recipients": "EnvelopeSortOrder",
    "array_sort_order__vector_clock_second_pair": "EnvelopeSortOrder",
    "array_sort_order__recipients_second_pair": "EnvelopeSortOrder",
    "array_sort_order__vector_clock_first_pair_of_three": "EnvelopeSortOrder",
    "array_sort_order__recipients_first_pair_of_three": "EnvelopeSortOrder",
    "repeated_array_value__vector_clock": "EnvelopeRepeatedValue",
    "repeated_array_value__recipients": "EnvelopeRepeatedValue",
    "repeated_array_value__vector_clock_second_pair": "EnvelopeRepeatedValue",
    "repeated_array_value__recipients_second_pair": "EnvelopeRepeatedValue",
    "repeated_array_value__vector_clock_first_pair_of_three": "EnvelopeRepeatedValue",
    "repeated_array_value__recipients_first_pair_of_three": "EnvelopeRepeatedValue",
}


def _labelled_seeds(target: str) -> list[Path]:
    directory = fixtures.fuzz_seed_dir(target)
    return sorted(p for p in directory.iterdir() if p.is_file() and LABEL_SEPARATOR in p.name)


def _label_token(path: Path) -> str:
    return path.name.split(LABEL_SEPARATOR, 1)[0]


def _identity_issues() -> list[str]:
    issues = []
    for cls, want in _TOKENED_CLASSES:
        got = cls.__dict__.get("token")
        if got != want:
            issues.append(f"{cls.__name__} declares token {got!r}, this section expects {want!r}")
    declared = {cls for cls, _ in _TOKENED_CLASSES}
    for module in _TOKENED_MODULES:
        for cls in vars(module).values():
            if not (
                isinstance(cls, type)
                and cls.__module__ == module.__name__
                and issubclass(cls, rejection._REJECTION_EXCEPTIONS)
            ):
                continue
            if "token" not in cls.__dict__:
                issues.append(f"{module.__name__}.{cls.__name__} inherits its token instead of declaring one")
            if cls not in declared:
                issues.append(f"{module.__name__}.{cls.__name__} is a verdict class this section does not list")
    return issues


def _seed_issues(target: str, floor: int, want_tokens: frozenset[str]) -> tuple[list[str], str]:
    try:
        seeds = _labelled_seeds(target)
    except OSError as exc:
        return [f"{target}: cannot list seeds: {type(exc).__name__}: {exc}"], f"{target}: unlisted"
    issues = []
    by_bytes: dict[bytes, str] = {}
    for path in seeds:
        want = _label_token(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            issues.append(f"{target}/{path.name}: cannot read seed: {type(exc).__name__}: {exc}")
            continue
        if (twin := by_bytes.setdefault(data, path.name)) != path.name:
            issues.append(f"{target}: seeds {twin} and {path.name} are byte-identical")
        verdict = replay_bytes(target, data).verdict
        if verdict.get("status") != "reject":
            issues.append(f"{target}/{path.name}: expected a rejection naming {want!r}, got {verdict}")
        elif verdict.get("rule") != want:
            issues.append(
                f"{target}/{path.name}: Python named {verdict.get('rule')!r}, the file name says "
                f"{want!r} ({verdict.get('error_class')}: {verdict.get('detail')})"
            )
        elif target == "block_file":
            want_class = _BLOCK_FILE_CLASSES.get(path.stem)
            if want_class is None:
                issues.append(f"{target}/{path.name}: no expected class; add the seed to _BLOCK_FILE_CLASSES")
            elif verdict.get("error_class") != want_class:
                issues.append(
                    f"{target}/{path.name}: Python raised {verdict.get('error_class')}, the seed "
                    f"names the check {want_class} ({verdict.get('detail')})"
                )
    if len(seeds) < floor:
        issues.append(f"{target}: only {len(seeds)} labelled seeds, floor is {floor}")
    named = {_label_token(p) for p in seeds}
    if named != want_tokens:
        issues.append(
            f"{target}: the seeds name {sorted(named)}, this section expects {sorted(want_tokens)}"
        )
    return issues, f"{target}: {len(seeds)} labelled seeds covering {len(named)} tokens"


# Check 5 -- LOCAL parity-order assertions for `record` and `block_file`.
# Two-fault bodies built here, never committed: vault-format §6.1 and §6.3
# state no report order, and a committed cross-language row must not pin one
# (#618, #668).  They pin the order `py_decode_record` shares with
# `record::decode`, and the first-out-of-place-pair rule the block envelope
# reader shares with `block.rs`, by design.
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
# The committed accepting base the `block_file` case is spliced into.
_BLOCK_BASE = "golden.bin"
# §6.1: the vector-clock entry count is a big-endian u16.
_U16_LEN = 2
# Leading id bytes that compare strictly, whatever the rest of the id holds.
_LOW_LEAD = 0x00
_HIGH_LEAD = 0xFF
# How many parity-order cases each builder declares; asserted in `_ordering_issues`.
_ORDERING_CASES = {"record": 7, "block_file": 1}

_OrderingCase = tuple[str, bytes, str, "str | None"]


def _block_file_ordering_cases() -> tuple[_OrderingCase, ...]:
    """One two-fault `block_file` body: a vector clock `[high, low, low]`.

    Its first adjacent pair is out of order and its second is a repeat, each
    of which alone names a different token (the committed
    `array_sort_order__vector_clock` and `repeated_array_value__vector_clock`
    seeds are exactly those single faults).  §6.1 fixes no order between the
    two (#668), so this is parity only: both implementations report the FIRST
    adjacent pair that is not strictly ascending, as `block.rs`'s `match cmp`
    over `windows(2)` does, and a reader that scans the whole table for a
    repeat before judging order names `repeated_array_value` instead
    (measured).
    """
    base = (fixtures.fuzz_seed_dir("block_file") / _BLOCK_BASE).read_bytes()
    header, after = parse_header(Cursor(buf=base, pos=0))
    entries_at = after.pos - len(header.vector_clock) * VECTOR_CLOCK_ENTRY_LEN
    count_at = entries_at - _U16_LEN
    entry = base[entries_at:entries_at + VECTOR_CLOCK_ENTRY_LEN]
    table = [bytes([lead]) + entry[1:] for lead in (_HIGH_LEAD, _LOW_LEAD, _LOW_LEAD)]
    body = base[:count_at] + len(table).to_bytes(_U16_LEN, "big") + b"".join(table) + base[after.pos:]
    return (
        ("a vector clock out of order at its first pair and repeated at its second",
         body, "array_sort_order", "every pair checked for a repeat before any for order"),
    )


def _record_ordering_cases() -> tuple[_OrderingCase, ...]:
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


def _ordering_issues() -> tuple[list[str], str]:
    builders = (("record", _record_ordering_cases), ("block_file", _block_file_ordering_cases))
    issues: list[str] = []
    tallies = []
    for target, build in builders:
        try:
            cases = build()
        except (OSError, ParseError) as exc:
            issues.append(f"{target} order: cannot build the cases: {type(exc).__name__}: {exc}")
            tallies.append(f"0/{_ORDERING_CASES[target]} {target}")
            continue
        if len(cases) != _ORDERING_CASES[target]:
            # An issue, not a raise: `main()` has no per-section catch, so a
            # raise here would skip every later section, REG included, with no
            # `FAIL:` line (PR #673 review).
            issues.append(
                f"_ORDERING_CASES[{target!r}] is {_ORDERING_CASES[target]}, the table holds {len(cases)}"
            )
        failed = 0
        for label, body, want, drift in cases:
            verdict = replay_bytes(target, body).verdict
            if verdict.get("status") != "reject" or verdict.get("rule") != want:
                failed += 1
                caught = f" -- the drift this row catches: {drift}" if drift else ""
                issues.append(
                    f"{target} order: {label} must report {want!r}, got {verdict.get('status')} "
                    f"{verdict.get('rule')!r} ({verdict.get('error_class')}: {verdict.get('detail')}){caught}"
                )
        tallies.append(f"{len(cases) - failed}/{len(cases)} {target}")
    return issues, " and ".join(tallies)


def section_rule_token_seeds() -> tuple[bool, list[str]]:
    issues = _identity_issues()
    lines = [f"PASS 1: {len(_TOKENED_CLASSES)} typed classes carry exactly their expected token"]
    for target, (floor, want_tokens) in _TARGETS.items():
        target_issues, summary = _seed_issues(target, floor, want_tokens)
        issues.extend(target_issues)
        lines.append(f"PASS 2-4: {summary}, each rejected with its file name's token")
    order_issues, tally = _ordering_issues()
    issues.extend(order_issues)
    lines.append(f"PASS 5: {tally} parity-order cases")
    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
