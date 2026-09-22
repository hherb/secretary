"""Section RTS -- every committed single-fault seed for a token-compared
`block_file`, `record` or `contact_card` target is rejected with the rule
its file name says, in this package as in Rust (#641, task 10).

WHAT THIS PINS.  `core/tests/rule_token_seeds.rs` generates one seed per
`(token, shape)` row, binds each committed file's BYTES to its row, and
requires the Rust decoder to name the file's token and the row's exact error
variant.  This section is the
Python half of the same binding: every `<token>__<shape>.bin` must be
REJECTED -- a verdict, never an `error` -- with exactly `<token>`, through
`diff_replay.replay_bytes`, the very function the differential replay's
worker calls.  So every committed seed is a strict cross-language comparison
in its own right, in the blocking `clean-room conformance` job, independent
of `differential_replay.rs`.

WHY IDENTITY TOO (check 1).  Label binding reaches only the classes some seed
exercises.  Section RTV's check 1 records why the expected token is written
out rather than read off the class: membership in the vocabulary is
satisfied by any of the eighteen.  Check 1 also DISCOVERS every verdict
class `cbor_faults`, `record_rules` and `envelope_rules` define, and requires
each to declare `token` in its own body and to appear in the table: a new
subclass that forgot `token =` would otherwise inherit its base's coarse token
silently, and a class the table omits would never be identity-checked (PR
#673 review).

WHY A CLASS PER `block_file` AND `contact_card` SEED (check 2).  One token
covers several checks: nine `block_file` `container_malformed` seeds span
seven `BlockError` variants, and `card_rules.py`'s own docstring names the
same shape for the card -- `wrong_type` is carried by BOTH `CardWrongType`
and `CardDisplayNameTooLong`, and `malformed_cbor` by BOTH
`cbor_faults.MalformedCbor` and `cbor_faults.NestingTooDeep` (plus
`scanner.NonCanonicalItem` for `rule4_tag_or_float`, which the CARD and
`record` and `block_file` all route rule 4 through).  With one class for
all of them, deleting the `sig_ed_len` check let the parse fail a few bytes
later as a truncation carrying the same token, and this section stayed
green (PR #673 review, measured); the identical shape on the card side was
found in the fix round 1 review, measured the same way: repointing
`codec/card.py`'s `raise CardDisplayNameTooLong(...)` at `CardWrongType` --
deleting crypto-design §6's 4096-byte `display_name` bound as a NAMED check
-- left `uv run core/tests/python/conformance.py` and the gated differential
replay both green, because the TOKEN (`wrong_type`) is unchanged even
though the specific check is gone.  Each `block_file` and `contact_card`
seed's Python class is therefore required by name, default-deny, as
`rule_token_seeds.rs` requires its Rust variant.  The `record` classes map
one to one onto their tokens, so a class name there would add nothing.

WHY DISTINCT BYTES (check 2).  A label is bound to its bytes only on the Rust
side, by regeneration.  This side read the file name alone, and three
`malformed_cbor` seeds overwritten with `truncated`'s bytes still passed every
check (PR #673 review, measured).  No two labelled seeds of a target may be
byte-identical.

WHY FLOORS (check 3) AND AN EXPECTED TOKEN SET (check 4).  An emptied
directory satisfies check 2 vacuously, and a directory whose seeds were all
relabelled onto one token satisfies checks 2 and 3.

CHECK 5 IS PARITY, NOT SPEC, and lives in its own module,
`rule_token_seeds_ordering.py` (fix round 1: split out once this file's own
growth pushed it past the project's 500-line threshold).  It builds
two-fault bodies for `record`, `block_file` and `contact_card`, never
committed, because vault-format §6.1/§6.3 and crypto-design §6 fix no report
order and a committed cross-language row must not pin one (#618's lesson;
#668).  Read that module's docstring and `_card_ordering_cases`'s for the
per-target detail; `section_rule_token_seeds` below just calls it.
"""

from __future__ import annotations

from pathlib import Path

from conformance_lib import fixtures, rejection
from conformance_lib.codec import card_rules, cbor_faults, record_rules
from conformance_lib.cursor import ParseError
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.sections.nesting_depth_bodies import NESTING_SEED_PREFIX
from conformance_lib.sections.rule_token_seeds_ordering import ordering_issues
from conformance_lib.wire import envelope_rules

# Mirrors `rule_token_seeds_helpers::LABEL_SEPARATOR`.
LABEL_SEPARATOR = "__"

# `contact_card/` also holds two `valuetype__` seeds from #669's OLDER
# acceptance-divergence generator (`valuetype__card_version.bin`,
# `valuetype__created_at.bin`) -- a different table this section does not
# own.  Excluded the same way `NESTING_SEED_PREFIX` is, mirroring
# `rule_token_seeds.rs`'s `CONTACT_CARD_FOREIGN_PREFIX`.
_CONTACT_CARD_FOREIGN_PREFIX = "valuetype__"

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
        37,
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
    # Ruling (controller, task 10 pre-flight): EIGHT tokens, not the nine an
    # earlier draft of this table carried -- `CardError` has no
    # `rule_token()` arm reaching `integer_out_of_range`; every `Malformed(_)`
    # arm, including a negative `created_at`, collapses to `wrong_type`
    # (`core/src/vault/rule_tokens/card.rs`'s exhaustive match).
    #
    # 17, not 21 (fix round 1, IMPORTANT 1): `undefined`, `depth_257`,
    # `float` and `bignum_narrow` moved to Section RTS check 5
    # (`rule_token_seeds_ordering._card_ordering_cases`) once each was found
    # to also carry a competing, order-dependent verdict the card's own
    # schema cannot isolate a single-fault control for -- see that module's
    # docstring. 17 is the LABELLED count this section's table plants; the
    # directory also holds the two `valuetype__` seeds above plus the two
    # accepting bases (`with_sigs.cbor`, `pre_sig.cbor` -- the latter rejects
    # but is not `__`-labelled), for 21 files on disk (`MIN_CORPUS_INPUTS`'s
    # floor).
    "contact_card": (
        17,
        frozenset(
            {
                "malformed_cbor",
                "rule4_tag_or_float",
                "wrong_type",
                "missing_field",
                "duplicate_map_key",
                "unknown_field",
                "unsupported_version",
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
    (cbor_faults.NestingTooDeep, "malformed_cbor"),
    (record_rules.RecordWrongType, "wrong_type"),
    (record_rules.RecordIntegerOutOfRange, "integer_out_of_range"),
    (record_rules.RecordDuplicateKey, "duplicate_map_key"),
    (record_rules.RecordMissingField, "missing_field"),
    (record_rules.RecordNonCanonical, "non_canonical_unclassified"),
    (card_rules.CardWrongType, "wrong_type"),
    (card_rules.CardDuplicateKey, "duplicate_map_key"),
    (card_rules.CardMissingField, "missing_field"),
    (card_rules.CardUnknownField, "unknown_field"),
    (card_rules.CardUnsupportedVersion, "unsupported_version"),
    (card_rules.CardNonCanonical, "non_canonical_unclassified"),
    (card_rules.CardDisplayNameTooLong, "wrong_type"),
)


# The modules whose verdict classes check 1 discovers.
_TOKENED_MODULES = (card_rules, cbor_faults, record_rules, envelope_rules)

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

# Check 2 (CRITICAL, fix round 1): the Python class every `contact_card`
# seed must be rejected with, keyed by file stem -- the same default-deny
# discipline `_BLOCK_FILE_CLASSES` gives `block_file`, and for the identical
# reason: `wrong_type` is carried by both `CardWrongType` and
# `CardDisplayNameTooLong`, `malformed_cbor` by both `cbor_faults.MalformedCbor`
# and `cbor_faults.NestingTooDeep`, and `rule4_tag_or_float` entirely by
# `scanner.NonCanonicalItem` (a token check alone cannot tell those apart).
# Before this table, no `contact_card` seed had its Python class checked at
# all -- `_seed_issues`'s class branch fired only `elif target ==
# "block_file"`. Measured cost: repointing `codec/card.py`'s
# `raise CardDisplayNameTooLong(...)` at `CardWrongType` -- deleting
# crypto-design §6's 4096-byte `display_name` bound as a named check --
# left BOTH blocking CI gates (`clean-room conformance`, the gated
# differential replay) green.
_CONTACT_CARD_CLASSES: dict[str, str] = {
    "malformed_cbor__two_byte_simple": "MalformedCbor",
    "malformed_cbor__nested_indefinite_chunk": "MalformedCbor",
    "malformed_cbor__truncated": "MalformedCbor",
    "rule4_tag_or_float__bignum_wide": "NonCanonicalItem",
    "wrong_type__not_a_map": "CardWrongType",
    "wrong_type__non_text_key": "CardWrongType",
    "wrong_type__created_at_text": "CardWrongType",
    "wrong_type__x25519_pk_short": "CardWrongType",
    "wrong_type__display_name_over_cap": "CardDisplayNameTooLong",
    "wrong_type__card_version_text": "CardWrongType",
    "wrong_type__created_at_negative": "CardWrongType",
    "missing_field__no_x25519_pk": "CardMissingField",
    "duplicate_map_key__repeated_created_at": "CardDuplicateKey",
    "unknown_field__extra_key": "CardUnknownField",
    "unsupported_version__card_version_two": "CardUnsupportedVersion",
    "non_canonical_unclassified__trailing_bytes": "CardNonCanonical",
    "non_canonical_unclassified__non_shortest_created_at": "CardNonCanonical",
}

# Check 2's per-target class table, keyed by target name (fix round 1): one
# lookup instead of an `elif target == ...` per target, so a third
# class-checked target is one dict entry, not a new branch.
_SEED_CLASSES: dict[str, dict[str, str]] = {
    "block_file": _BLOCK_FILE_CLASSES,
    "contact_card": _CONTACT_CARD_CLASSES,
}


def _labelled_seeds(target: str) -> list[Path]:
    directory = fixtures.fuzz_seed_dir(target)
    # `nesting__` seeds belong to Section NDL and `nesting_depth_seeds.rs` (#667).
    # `valuetype__` seeds under `contact_card/` belong to #669's older
    # acceptance-divergence generator, a different table this section does
    # not own.
    return sorted(
        p for p in directory.iterdir()
        if p.is_file() and LABEL_SEPARATOR in p.name
        and not p.name.startswith(NESTING_SEED_PREFIX)
        and not (target == "contact_card" and p.name.startswith(_CONTACT_CARD_FOREIGN_PREFIX))
    )


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
    class_table = _SEED_CLASSES.get(target)
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
        elif class_table is not None:
            want_class = class_table.get(path.stem)
            if want_class is None:
                issues.append(
                    f"{target}/{path.name}: no expected class; add the seed to _SEED_CLASSES[{target!r}]"
                )
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


def section_rule_token_seeds() -> tuple[bool, list[str]]:
    issues = _identity_issues()
    lines = [f"PASS 1: {len(_TOKENED_CLASSES)} typed classes carry exactly their expected token"]
    for target, (floor, want_tokens) in _TARGETS.items():
        target_issues, summary = _seed_issues(target, floor, want_tokens)
        issues.extend(target_issues)
        lines.append(f"PASS 2-4: {summary}, each rejected with its file name's token")
    order_issues, tally = ordering_issues()
    issues.extend(order_issues)
    lines.append(f"PASS 5: {tally} parity-order cases")
    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
