"""Section MCC -- the `expect_cause` column of `manifest_canonicality_kat.json`.

#590 gave `ManifestError::NonCanonicalEncoding` a `NonCanonicalCause`, and
`manifest_canonicality_kat_replays` asserted one for each of the SIX
rejecting rows that reach the §4.3 step-4 re-encode.  (Six, not nine: the
three `rule4_float` rows are caught earlier by `reject_floats_and_tags`
and deliberately get no cause.)  That assertion lived only in Rust, and
the label-suffix -> cause mapping lived in one Rust test function, so a
clean-room reader had nothing to agree with -- even though #590's stated
audience *is* the clean-room implementer.  #604
moved the expectation into the fixture; this section is the second reader of
it.

What this section pins, stated exactly, because the obvious wider claim is
false: **the two implementations agree on WHICH §6.2 RULE a body violates,
having found it by DIFFERENT MECHANISMS.**  It is not a claim that they
classify by the same route, and they do not.
"""

from __future__ import annotations

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.scanner import NonCanonicalItem
from conformance_lib.fixtures import load_json_fixture, manifest_canonicality_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

# The fixture's `expect_cause` vocabulary -> the crypto-design §6.2 rule
# number a byte-retaining reader detects for that shape.
#
# `None` -- a rejecting row with no cause -- means "rejected BEFORE the §4.3
# step-4 re-encode comparison".  Mapping it to rule 4 is not a guess about
# Rust's internals: vault-format.md §4.2 makes it normative for EVERY reader
# ("Rule 4 is not an encoding-level choice -- a normalising parse *preserves*
# a tag or a float and re-encodes it identically, so the step-4 comparison
# cannot see one.  Every reader enforces rule 4 by the whole-body walk row 4
# of the table names, separately from the re-encode").  A null cause and rule
# 4 are therefore the same statement seen from the two sides.
#
# Rules 2 and 3 are where the mechanisms genuinely differ, and §4.2 states
# both halves: a normalising reader (ciborium) gets them for free, because a
# non-canonical head no longer re-encodes to its own bytes; a byte-retaining
# reader (this one) "reproduces its input unconditionally ... and it must
# therefore check crypto-design §6.2 rules 2, 3 and 4 itself to stay
# conformant".  That sentence is quoted from §6.3.2, which points back at
# §4.2 for the manifest; §4.2 states the same two-part obligation in its own
# words ("Retaining the subtree's raw input bytes and re-emitting them
# satisfies (1) but not (2), and is conformant only if the reader enforces
# (2) separately").  So Rust reaches rules 2 and 3 through the re-encode
# plus #590's classifier, and `_check_canonical_item` reaches them directly.
#
# The rule NUMBERS follow `docs/vault-format.md` §4.2's per-rule table, not
# crypto-design §6.2's prose.  §6.2 rule 4 reads "No tags, no floats, no
# indefinite-length items", so by §6.2's own text an indefinite item
# violates rules 2 AND 4; §4.2's table row 4 is spelled "no tags, no floats"
# and leaves indefinite lengths to row 2.  `scanner.py`'s `NonCanonicalItem`
# follows the same table for the same reason.  Without this, a clean-room
# implementer reading §6.2 literally would classify an indefinite item as
# rule 4 and this section would report a divergence against a CONFORMANT
# reader (#614 review).
#
# FAIL-CLOSED: a cause spelling absent from this table is an issue, never a
# skipped row.  That includes the two variants this corpus does not reach
# today -- `ArraySortOrder` and `Unclassified` (#613) -- as well as any
# variant added later.  NOTE for #613: neither of those two can simply be
# added as a row here.  `ArraySortOrder` is not a §6.2 rule at all (array
# sort disciplines are §4.2, and §6.2 says nothing about array elements),
# and `Unclassified` is usually outer-map key disorder, i.e. §6.2 rule 1,
# which `_check_canonical_item` deliberately never checks.  Both land in
# this reader as plain, unnumbered `ValueError`s, so #613 needs a second
# discriminator kind rather than two more rows.
_CAUSE_TO_RULE: dict[str | None, int] = {
    "IndefiniteLength": 2,
    "NonShortestForm": 3,
    None: 4,
}

_EXPECTED_ROWS = 21
_EXPECTED_CAUSED_REJECTS = 6
_EXPECTED_UNCAUSED_REJECTS = 3

# The corpus is a `<level>__<shape>` product. Checking the PRODUCT, not just
# the row count, is what stops 21 rows drawn from one nesting level passing
# (#614 review) -- the level dimension is the corpus's stated premise, and
# nothing on this side looked at it.
_EXPECTED_LEVELS = ("top", "block", "trash")

# Every column this section reads. Checked up front so a row-shape defect
# produces a FAIL line rather than a traceback out of `main()`: MCC runs
# before MUQ, RC, DET and REG, and an escaping exception silently skips all
# four -- including REG, which is what proves the registry is complete.
_REQUIRED_COLUMNS = ("label", "manifest_body_hex", "expect_accept", "expect_cause")


def section_manifest_canonicality_cause() -> tuple[bool, list[str]]:
    """Replay `manifest_canonicality_kat.json`'s `expect_cause` column (#604).

    For every REJECTING row, `py_decode_manifest` must raise
    `NonCanonicalItem` carrying the §6.2 rule number that the row's declared
    cause maps to.  The discriminator is the exception's `.rule` ATTRIBUTE,
    never its message text: a substring match on `"rule 2:"` keeps passing
    when the message is reworded, and keeps passing when an unrelated check
    grows a message containing the same fragment.  That is the failure #608's
    review found on the encoder side of this same corpus family, where adding
    a rule to one direction of a round trip silently made the other
    direction's assertion vacuous.

    For every ACCEPTING row the column must be present and `null` -- a body
    that decodes has no rejection to explain.  Present, not absent: the
    column is hard-indexed below, so a fixture that dropped it fails loudly
    rather than reading as `None` on every row.  Mirrors the Rust replay's
    assertion of the same property, so a fixture that grew a cause on an
    accepting row reds in both languages.

    Three floors keep the section from passing vacuously.  The 6/3 split
    between caused and uncaused rejections is asserted BY COUNT, mirroring
    the Rust replay's `re_encode`/`float_walk` totals against the same
    fixture.  The label set must be exactly the 7 shapes x 3 levels the
    corpus is built from -- the Python counterpart of Rust's
    `Level::ALL x SHAPES` assertion, without which 21 rows drawn from one
    nesting level pass.

    The third is a CORPUS-COVERAGE floor, and the obvious reading of it is
    wrong: a decoder that collapsed every violation onto one rule number is
    caught ABOVE it, per-row, and since this floor sits after
    `if issues: return` it is never evaluated on such a run (verified by
    mutation -- deleting it leaves the identical six per-row findings).
    What it catches is a FIXTURE that stopped exercising a rule: six caused
    rows all declaring one cause satisfies every per-row check and the 6/3
    counts, and reduces this section to a single-rule pin.  Rust catches
    that with its fixture-vs-`SHAPES` cross-check; this is the Python route
    to the same place.
    """
    path = manifest_canonicality_kat_path()
    doc = load_json_fixture(path, "manifest_canonicality_kat.json")
    rows = doc["rows"]
    issues: list[str] = []
    if not rows:
        return False, ["corpus is empty"]

    caused = 0
    uncaused = 0
    rules_seen: set[int] = set()

    labels: list[str] = []

    for index, row in enumerate(rows):
        # Shape first, so every later read is safe and every defect is a
        # FAIL line rather than a traceback. A fixture that lost a column
        # must fail LOUDLY: read with a default, every rejecting row would
        # score as "declares no cause", silently be checked against rule 4,
        # and the three that really are rule 4 would still pass -- a
        # partly-green section reporting on a column that no longer exists.
        # Same fail-open shape #608's review found in `parsed.get(array, [])`.
        if not isinstance(row, dict):
            issues.append(
                f"row {index}: expected a JSON object, got {type(row).__name__}"
            )
            continue
        missing = [k for k in _REQUIRED_COLUMNS if k not in row]
        if missing:
            issues.append(
                f"row {index}: fixture is missing column(s) {missing} -- regenerate "
                "it with `cargo test --release --workspace -- --ignored "
                "generate_manifest_canonicality_kat`"
            )
            continue

        label = row["label"]
        labels.append(label)
        declared = row["expect_cause"]
        # `declared` indexes `_CAUSE_TO_RULE` below, so a non-hashable value
        # (a JSON list, say) would raise `TypeError` -- outside
        # `_REJECTION_EXCEPTIONS`, hence straight out of `main()`.
        if not isinstance(declared, (str, type(None))):
            issues.append(
                f"row {label!r}: expect_cause must be a string or null, got "
                f"{type(declared).__name__}"
            )
            continue

        if row["expect_accept"]:
            if declared is not None:
                issues.append(
                    f"row {label!r}: an ACCEPTED row declares cause {declared!r}, "
                    "but a body that decodes has no rejection to explain"
                )
            continue

        if declared not in _CAUSE_TO_RULE:
            issues.append(
                f"row {label!r}: unrecognised expect_cause {declared!r} -- add it to "
                "_CAUSE_TO_RULE with the §6.2 rule a byte-retaining reader detects "
                "for it, rather than letting the row be skipped"
            )
            continue
        want_rule = _CAUSE_TO_RULE[declared]

        if declared is None:
            uncaused += 1
        else:
            caused += 1

        # Decoded OUTSIDE the verdict `try`. `_REJECTION_EXCEPTIONS` admits
        # both `KeyError` and `ValueError`, so with this inside it a broken
        # fixture was reported as "the reader rejected ..." -- the exact
        # vocabulary reserved for a genuine cross-language disagreement,
        # which is the most misleading thing this section can say (#614
        # review). Rust has always done it this way.
        try:
            body = bytes.fromhex(row["manifest_body_hex"])
        except (TypeError, ValueError) as e:
            issues.append(
                f"row {label!r}: manifest_body_hex is not valid hex -- this is a "
                f"FIXTURE defect, not a decoder verdict: {e}"
            )
            continue

        try:
            py_decode_manifest(body)
        except NonCanonicalItem as e:
            rules_seen.add(e.rule)
            if e.rule != want_rule:
                issues.append(
                    f"row {label!r}: corpus declares cause {declared!r} (§6.2 rule "
                    f"{want_rule}), byte-retaining reader detected rule {e.rule}: {e}"
                )
        except _REJECTION_EXCEPTIONS as e:
            # Rejected, but by a check that carries no rule number -- so the
            # two implementations do NOT agree on which rule this body
            # violates, which is precisely what this section exists to
            # detect. Narrow, for the reason `rejection.py` states: a bare
            # `except Exception` would score a NameError/AttributeError
            # inside the decoder as a verdict.
            issues.append(
                f"row {label!r}: corpus declares cause {declared!r} (§6.2 rule "
                f"{want_rule}), but the reader rejected with a non-numbered "
                f"{type(e).__name__}: {e}"
            )
        else:
            issues.append(
                f"row {label!r}: corpus declares cause {declared!r}, so the body must "
                "be REJECTED -- the byte-retaining reader accepted it"
            )

    if len(rows) != _EXPECTED_ROWS:
        issues.append(
            f"corpus must carry 7 shapes x 3 levels = {_EXPECTED_ROWS} rows, "
            f"found {len(rows)}"
        )

    # The label set must be a full `<level>__<shape>` product. A bare row
    # count is satisfied by 21 copies of one row, and -- the case that
    # actually mattered -- by 21 rows drawn from a single nesting level.
    if len(set(labels)) != len(labels):
        dupes = sorted({lbl for lbl in labels if labels.count(lbl) > 1})
        issues.append(f"corpus has duplicate labels: {dupes}")
    by_level: dict[str, set[str]] = {}
    for lbl in labels:
        level, _, shape = lbl.partition("__")
        if not shape:
            issues.append(f"row {lbl!r}: label is not <level>__<shape>")
            continue
        by_level.setdefault(level, set()).add(shape)
    if set(by_level) != set(_EXPECTED_LEVELS):
        issues.append(
            f"corpus must cover levels {sorted(_EXPECTED_LEVELS)}, "
            f"found {sorted(by_level)}"
        )
    elif len({frozenset(shapes) for shapes in by_level.values()}) != 1:
        issues.append(
            "every level must carry the SAME set of shapes: "
            + "; ".join(f"{lvl}={sorted(sh)}" for lvl, sh in sorted(by_level.items()))
        )
    if caused != _EXPECTED_CAUSED_REJECTS:
        issues.append(
            f"expected {_EXPECTED_CAUSED_REJECTS} rejecting rows WITH a cause "
            f"(rules 2 and 3, three levels each), found {caused}"
        )
    if uncaused != _EXPECTED_UNCAUSED_REJECTS:
        issues.append(
            f"expected {_EXPECTED_UNCAUSED_REJECTS} rejecting rows with a NULL cause "
            f"(rule 4, three levels), found {uncaused}"
        )
    if issues:
        return False, issues

    # Only meaningful once every row above agreed; a mismatched row already
    # reported its own issue and this would add noise rather than signal.
    if rules_seen != {2, 3, 4}:
        return False, [
            f"the byte-retaining reader reported rules {sorted(rules_seen)} across the "
            "corpus, expected exactly [2, 3, 4] -- a reader collapsing every violation "
            "onto one rule number satisfies the per-row checks and classifies nothing"
        ]

    return True, [
        f"PASS  manifest canonicality causes: {caused} caused + {uncaused} uncaused "
        f"rejections agree with the Rust NonCanonicalCause column, "
        f"§6.2 rules {sorted(rules_seen)} all exercised"
    ]
