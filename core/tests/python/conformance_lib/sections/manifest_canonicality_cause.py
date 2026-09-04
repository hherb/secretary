"""Section MCC -- the `expect_cause` column of `manifest_canonicality_kat.json`.

#590 gave `ManifestError::NonCanonicalEncoding` a `NonCanonicalCause`, and
`manifest_canonicality_kat_replays` asserted one per rejecting row.  That
assertion lived only in Rust, and the label-suffix -> cause mapping lived in
one Rust test function, so a clean-room reader had nothing to agree with --
even though #590's stated audience *is* the clean-room implementer.  #604
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
# conformant".  So Rust reaches rules 2 and 3 through the re-encode plus
# #590's classifier, and `_check_canonical_item` reaches them directly.
#
# FAIL-CLOSED: a cause spelling absent from this table is an issue, never a
# skipped row.  A fifth `NonCanonicalCause` variant reaching the corpus must
# red here rather than be waved through.
_CAUSE_TO_RULE: dict[str | None, int] = {
    "IndefiniteLength": 2,
    "NonShortestForm": 3,
    None: 4,
}

_EXPECTED_ROWS = 21
_EXPECTED_CAUSED_REJECTS = 6
_EXPECTED_UNCAUSED_REJECTS = 3


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

    For every ACCEPTING row, the column must be absent -- a body that decodes
    has no rejection to explain.  Mirrors the Rust replay's assertion of the
    same property, so a fixture that grew a cause on an accepting row reds in
    both languages.

    Two floors keep the section from passing vacuously, both mirroring the
    Rust side against the SAME fixture: the 6/3 split between caused and
    uncaused rejections is asserted BY COUNT, and the set of rule numbers
    actually observed must be exactly {2, 3, 4}.  Without the second, a
    decoder that collapsed every violation onto one rule number would satisfy
    every per-row assertion the fixture happens to contain for that rule and
    fail none -- the corpus would be agreeing with a classifier that
    classifies nothing.
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

    for row in rows:
        label = row["label"]

        # Hard-index. A fixture that lost the column must fail LOUDLY: with
        # `.get("expect_cause")` every row would read as `None`, every
        # rejecting row would silently be checked against rule 4, and the
        # three that really are rule 4 would still pass -- a partly-green
        # section reporting on a column that no longer exists. Same
        # fail-open shape #608's review found in `parsed.get(array, [])`.
        try:
            declared = row["expect_cause"]
        except KeyError:
            issues.append(
                f"row {label!r}: fixture has no 'expect_cause' column -- regenerate "
                "it with `cargo test --release --workspace -- --ignored "
                "generate_manifest_canonicality_kat`"
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

        try:
            py_decode_manifest(bytes.fromhex(row["manifest_body_hex"]))
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
