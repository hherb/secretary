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

from dataclasses import dataclass

from conformance_lib.codec.manifest_decode import (
    ArraySortOrderViolation,
    NonCanonicalBody,
    py_decode_manifest,
)
from conformance_lib.codec.scanner import NonCanonicalItem
from conformance_lib.fixtures import load_json_fixture, manifest_canonicality_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS
from conformance_lib.sections.manifest_canonicality_corpus import (
    expected_labels,
    label_issues,
)

# The fixture's `expect_cause` vocabulary -> what a byte-retaining reader
# must do with a row declaring it.
#
# TWO KINDS OF ENTRY, and the second one is what #613 needed.  Until then
# every cause mapped to a crypto-design §6.2 NUMBERED rule, so the table was
# `dict[str | None, int]`.  The two causes #613 added map to no numbered rule
# at all, and pretending otherwise would make this reader disagree with a
# conformant implementation over a rule neither document assigns:
#
#   * `ArraySortOrder` is `docs/vault-format.md` §4.2's own rule.  §6.2 says
#     nothing about array elements.
#   * `Unclassified` is the residue -- a real divergence with NO attributable
#     violation.  In practice outer-map key disorder, i.e. §6.2 rule 1, which
#     `_check_canonical_item` deliberately never checks (§4.2's table marks
#     rules 1 and 5 unenforced inside a forward-compat subtree, and checking
#     them would reintroduce the #592 divergence).
#
# So those two are pinned by the reader's exception TYPE instead.  That is a
# strictly structured discriminator, never message text: a substring match on
# `"is not sorted"` keeps passing when the message is reworded, and keeps
# passing when a DIFFERENT check grows a message containing the fragment --
# the failure #608's review found on the encoder side of this corpus family.
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
# `ArraySortOrder` has the same asymmetry one layer up: Rust classifies it
# off the PARSED manifest after the re-encode has already rejected, this
# reader checks the discipline directly and BEFORE the re-encode runs.  Same
# rule, different mechanism -- which is the whole claim of this section.
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
# skipped row.  That covers any variant added later -- and it is what caught
# #613's own two the moment the fixture grew them, rather than skipping nine
# rows silently.


@dataclass(frozen=True)
class RuleNumber:
    """The reader must raise `NonCanonicalItem` carrying this rule number."""

    rule: int

    def describe(self) -> str:
        return f"§6.2 rule {self.rule}"


@dataclass(frozen=True)
class ExceptionKind:
    """The reader must raise exactly this exception class.

    For the two causes that map to no §6.2 numbered rule.  `detects` is the
    §4.2 property the class stands for, used only in diagnostics.
    """

    exc: type[Exception]
    detects: str

    def describe(self) -> str:
        return f"{self.exc.__name__} ({self.detects})"


_CAUSE_EXPECTATION: dict[str | None, RuleNumber | ExceptionKind] = {
    "IndefiniteLength": RuleNumber(2),
    "NonShortestForm": RuleNumber(3),
    None: RuleNumber(4),
    "ArraySortOrder": ExceptionKind(
        ArraySortOrderViolation, "vault-format §4.2 array sort discipline"
    ),
    "Unclassified": ExceptionKind(
        NonCanonicalBody, "a §4.3 step-4 divergence with no attributable rule"
    ),
}


def _discriminator(e: Exception) -> str | None:
    """The structured discriminator `e` carries, or `None` if it carries none.

    One vocabulary for both kinds of expectation, so the coverage floor at
    the end of the section can be a single set comparison rather than two
    that could disagree about which rows counted.
    """
    if isinstance(e, NonCanonicalItem):
        return f"rule {e.rule}"
    if isinstance(e, (ArraySortOrderViolation, NonCanonicalBody)):
        return type(e).__name__
    return None


def _expected_discriminator(want: RuleNumber | ExceptionKind) -> str:
    """The discriminator string a conformant reader must produce for `want`."""
    if isinstance(want, RuleNumber):
        return f"rule {want.rule}"
    return want.exc.__name__


_EXPECTED_ROWS = len(expected_labels())
_EXPECTED_CAUSED_REJECTS = 15
_EXPECTED_UNCAUSED_REJECTS = 3

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
    discriminators_seen: set[str] = set()

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

        if declared not in _CAUSE_EXPECTATION:
            issues.append(
                f"row {label!r}: unrecognised expect_cause {declared!r} -- add it to "
                "_CAUSE_EXPECTATION with the §6.2 rule number a byte-retaining "
                "reader detects for it, or the exception type that stands for it "
                "when no numbered rule applies, rather than letting the row be "
                "skipped"
            )
            continue
        want = _CAUSE_EXPECTATION[declared]

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

        # ONE `except` clause, dispatching afterwards, rather than a
        # `NonCanonicalItem` clause ahead of the general one. With two kinds
        # of expectation the ordered form has an ordering trap: both #613
        # types are `ValueError` subclasses, so a future type that also
        # subclassed `NonCanonicalItem` would be silently captured by the
        # narrower clause and scored against the wrong expectation. Narrow
        # regardless, for the reason `rejection.py` states -- a bare
        # `except Exception` would score a NameError/AttributeError inside
        # the decoder as a verdict.
        try:
            py_decode_manifest(body)
        except _REJECTION_EXCEPTIONS as e:
            got = _discriminator(e)
            if got is not None:
                discriminators_seen.add(got)
            expected_discriminator = _expected_discriminator(want)
            if got is None:
                # Rejected, but by a check carrying no structured
                # discriminator at all -- so the two implementations do NOT
                # agree on why this body is non-conformant, which is
                # precisely what this section exists to detect.
                issues.append(
                    f"row {label!r}: corpus declares cause {declared!r} "
                    f"({want.describe()}), but the reader rejected with an "
                    f"undiscriminated {type(e).__name__}: {e}"
                )
            elif got != expected_discriminator:
                issues.append(
                    f"row {label!r}: corpus declares cause {declared!r} "
                    f"({want.describe()}), byte-retaining reader produced "
                    f"{got!r}: {e}"
                )
        else:
            issues.append(
                f"row {label!r}: corpus declares cause {declared!r}, so the body must "
                "be REJECTED -- the byte-retaining reader accepted it"
            )

    if len(rows) != _EXPECTED_ROWS:
        issues.append(
            f"corpus must carry the {_EXPECTED_ROWS}-row two-family case table, "
            f"found {len(rows)}"
        )

    # The label floor, shared with Section MCK so the two cannot drift onto
    # two ideas of the same corpus. A bare row count is satisfied by N
    # copies of one row, and -- the case that actually mattered -- by rows
    # drawn from a single nesting level (#614 review).
    issues.extend(label_issues(labels))

    if caused != _EXPECTED_CAUSED_REJECTS:
        issues.append(
            f"expected {_EXPECTED_CAUSED_REJECTS} rejecting rows WITH a cause "
            f"(rules 2 and 3 at three levels each, plus the 9 #613 mutation "
            f"rows), found {caused}"
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
    #
    # Derived from `_CAUSE_EXPECTATION` rather than written out, so a cause
    # added to that table without a corpus row reds here instead of being
    # declared covered by a literal nobody updated. This is the Python side
    # of Rust's `causes_seen == ALL_CAUSES` assertion, and #613 is what made
    # both of them non-vacuous: before it, two of the four causes had no row
    # and both sides recorded the gap in prose.
    want_discriminators = {
        _expected_discriminator(expectation) for expectation in _CAUSE_EXPECTATION.values()
    }
    if discriminators_seen != want_discriminators:
        return False, [
            f"the byte-retaining reader produced {sorted(discriminators_seen)} across "
            f"the corpus, expected exactly {sorted(want_discriminators)} -- a reader "
            "collapsing every violation onto one verdict satisfies the per-row checks "
            "and classifies nothing, and a cause with no corpus row has no "
            "cross-language agreement at all"
        ]

    return True, [
        f"PASS  manifest canonicality causes: {caused} caused + {uncaused} uncaused "
        f"rejections agree with the Rust NonCanonicalCause column; all "
        f"{len(want_discriminators)} discriminators exercised "
        f"({', '.join(sorted(want_discriminators))})"
    ]
