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
classify by the same route.

**With one exception since #618, and it is the three `rule4_float` rows.**
Those used to be the sharpest case of the sentence above: Rust caught them in
`reject_floats_and_tags`, a whole-body walk, while this reader caught them
per-value in `_check_canonical_item`.  §4.2's precedence paragraph then
required a byte-retaining reader to run its own whole-body rule-4 walk BEFORE
interpreting any key, so `py_decode_manifest` gained one -- and for these
three rows the two mechanisms are now the same.  That is the spec's doing, not
a regression, but it costs this section a detection it used to have:
deleting `_check_canonical_item`'s rule-4 arm reds Sections CS and MCC at
#618's merge-base and only CS here, because the pre-pass answers first.
Section CS's unit cases are now the SOLE pin for that arm on the manifest
path.  A future edit that weakens CS takes this cover with it, and this
paragraph is the only place that says so.
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
    body_issues,
    expected_labels,
    label_issues,
    row_issues,
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
    # The `ExceptionKind` types are tested FIRST, and the tuple is DERIVED
    # from `_CAUSE_EXPECTATION` rather than written out.  Both halves matter:
    # this function had `NonCanonicalItem` first, which is the exact ordering
    # trap the `except`-clause comment further down warns about -- a future
    # type subclassing both would have been scored against the wrong
    # expectation -- and a hand-written tuple is a second place for the set of
    # exception kinds to live.
    for expectation in _CAUSE_EXPECTATION.values():
        if isinstance(expectation, ExceptionKind) and isinstance(e, expectation.exc):
            return expectation.exc.__name__
    if isinstance(e, NonCanonicalItem):
        return f"rule {e.rule}"
    return None


def _expected_discriminator(want: RuleNumber | ExceptionKind) -> str:
    """The discriminator string a conformant reader must produce for `want`.

    Exhaustive by construction: a THIRD kind of expectation raises here
    rather than reaching `want.exc` and dying with an `AttributeError`,
    which is not in `_REJECTION_EXCEPTIONS` and would therefore escape
    `section_manifest_canonicality_cause` as a traceback out of `main()` --
    silently skipping MUQ, RC, DET and REG, the last of which is what
    proves the registry is complete.
    """
    if isinstance(want, RuleNumber):
        return f"rule {want.rule}"
    if isinstance(want, ExceptionKind):
        return want.exc.__name__
    raise TypeError(
        f"_CAUSE_EXPECTATION carries an unrecognised expectation kind "
        f"{type(want).__name__} -- add it here and to `_discriminator`"
    )


_EXPECTED_ROWS = len(expected_labels())
_EXPECTED_CAUSED_REJECTS = 17
_EXPECTED_UNCAUSED_REJECTS = 3

# Every column this section reads. Checked up front so a row-shape defect
# produces a FAIL line rather than a traceback out of `main()`: MCC runs
# before MUQ, RC, DET and REG, and an escaping exception silently skips all
# four -- including REG, which is what proves the registry is complete.
_REQUIRED_COLUMNS = ("label", "manifest_body_hex", "expect_accept", "expect_cause")


def section_manifest_canonicality_cause() -> tuple[bool, list[str]]:
    """Replay `manifest_canonicality_kat.json`'s `expect_cause` column (#604, #613).

    For every REJECTING row, `py_decode_manifest` must produce the
    STRUCTURED DISCRIMINATOR that the row's declared cause maps to.  There
    are TWO KINDS, and this docstring said there was one until #613's review
    caught it -- it was byte-identical to its pre-#613 version while the
    function under it had been rewritten:

    * `RuleNumber(n)` -- the reader must raise `NonCanonicalItem` whose
      `.rule` ATTRIBUTE is `n`.  Three of the five entries.
    * `ExceptionKind(cls)` -- the reader must raise exactly `cls`
      (`ArraySortOrderViolation` or `NonCanonicalBody`).  Two of the five,
      for the causes that map to no §6.2 numbered rule at all.

    Either way the discriminator is a TYPE or an attribute, never message
    text: a substring match on `"rule 2:"` keeps passing when the message is
    reworded, and keeps passing when an unrelated check grows a message
    containing the same fragment.  That is the failure #608's review found on
    the encoder side of this same corpus family, where adding a rule to one
    direction of a round trip silently made the other direction's assertion
    vacuous.

    For every ACCEPTING row the column must be present and `null` -- a body
    that decodes has no rejection to explain.  Present, not absent: `row_issues`
    requires the column, so a fixture that dropped it fails loudly rather than
    reading as `None` on every row.  Mirrors the Rust replay's assertion of the
    same property, so a fixture that grew a cause on an accepting row reds in
    both languages.

    **Floors, all evaluated only once every row agreed** (a mismatched row
    reports its own issue, and adding these on top would be noise):

    1. The 17/3 split between caused and uncaused rejections, BY COUNT,
       mirroring the Rust replay's `want_re_encode`/`want_float_walk` totals
       against the same fixture.  17 = 6 splice rows (rules 2 and 3 at three
       nesting levels) + 11 mutation rows.
    2. The LABEL set, shared with MCK via `label_issues`: the full
       `<level>__<shape>` product plus every mutation label.
    3. The BODY set, shared with MCK via `body_issues`: pairwise distinct.
       Floors 2 and 3 are not interchangeable -- #614's measured finding was a
       BODY substitution with labels retained, which no label check can see.
    4. PER-CAUSE coverage: every spelling in `_CAUSE_EXPECTATION` must have
       been exercised by a rejecting row.  This is the floor whose earlier
       version compared DISCRIMINATORS instead, and the table is many-to-one,
       so a new cause colliding with an existing discriminator was declared
       covered with no corpus row (measured: `RuleNumber(2)` PASSED, a unique
       `RuleNumber(9)` correctly red).
    5. Table INJECTIVITY, the counterpart of Rust's `cause_names_are_distinct`.
    6. Every discriminator must actually be PRODUCED, which catches the other
       direction: a reader collapsing every violation onto one verdict
       satisfies the per-row checks and classifies nothing.

    Floors 4-6 are what Rust reaches with `causes_seen == ALL_CAUSES` plus its
    fixture-vs-case-table cross-check.  Unlike the Rust side, floor 4 here is
    mutation-proven, because a `_CAUSE_EXPECTATION` entry can be added without
    adding a Rust enum variant.
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
    # Which CAUSE SPELLINGS the corpus actually exercised.  Distinct from
    # `discriminators_seen`: `_CAUSE_EXPECTATION` is MANY-TO-ONE, so a set of
    # discriminators cannot answer "does every cause have a row?".
    causes_checked: set[str | None] = set()

    labels: list[str] = []
    bodies: list[str] = []

    for index, row in enumerate(rows):
        # Shape first, so every later read is safe and every defect is a
        # FAIL line rather than a traceback. A fixture that lost a column
        # must fail LOUDLY: read with a default, every rejecting row would
        # score as "declares no cause", silently be checked against rule 4,
        # and the three that really are rule 4 would still pass -- a
        # partly-green section reporting on a column that no longer exists.
        # Same fail-open shape #608's review found in `parsed.get(array, [])`.
        #
        # SHARED with MCK (`row_issues`), which reads the same file and runs
        # FIRST: a guard living only here is unreachable for the very defects
        # it was written for.
        shape = row_issues(index, row)
        if shape:
            issues.extend(shape)
            continue
        label = row["label"]
        labels.append(label)
        bodies.append(row["manifest_body_hex"])
        declared = row["expect_cause"]
        # `declared` indexes `_CAUSE_EXPECTATION` above, so a non-hashable
        # value (a JSON list, say) would raise `TypeError` -- outside
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

        causes_checked.add(declared)
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
    issues.extend(body_issues(bodies))

    if caused != _EXPECTED_CAUSED_REJECTS:
        issues.append(
            f"expected {_EXPECTED_CAUSED_REJECTS} rejecting rows WITH a cause "
            f"(rules 2 and 3 at three levels each, plus the 11 mutation "
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
    # TWO floors, because one of them used to do the work of both and could
    # not. `_CAUSE_EXPECTATION` is MANY-TO-ONE -- several causes may map to
    # the same rule number, and legitimately so: the natural next
    # `NonCanonicalCause` variants are refinements of an existing one (say
    # `IndefiniteLength` splitting into map/string forms), and a
    # byte-retaining reader detects both as §6.2 rule 2.
    #
    # (1) PER-CAUSE coverage. Every spelling in the table must have been
    # exercised by a rejecting row. This is the floor the section's own
    # comment claimed, and it did not hold: the comparison was over
    # DISCRIMINATORS, so a new cause whose discriminator collided with an
    # existing entry's was declared covered with no corpus row at all
    # (measured: adding `"SomeFutureCause": RuleNumber(2)` PASSED, while a
    # unique `RuleNumber(9)` correctly red). That is the Python half of
    # Rust's `causes_seen == ALL_CAUSES`, and unlike the Rust half it is
    # mutation-proven, because a table entry can be added here without
    # adding a Rust enum variant.
    if causes_checked != set(_CAUSE_EXPECTATION):
        missing = sorted(str(c) for c in set(_CAUSE_EXPECTATION) - causes_checked)
        extra = sorted(str(c) for c in causes_checked - set(_CAUSE_EXPECTATION))
        return False, [
            f"every cause in _CAUSE_EXPECTATION must be exercised by a corpus row: "
            f"missing {missing}, unexpected {extra} -- a cause with no row has no "
            "cross-language agreement at all, which is the gap #613 closed"
        ]

    # (2) INJECTIVITY of the table, which is what makes (1) meaningful to a
    # reader and is the counterpart of Rust's `cause_names_are_distinct`.
    # Two causes sharing a discriminator is not itself an error -- see the
    # refinement case above -- but it must be a DELIBERATE entry rather than
    # a copy-paste, so it is reported here and the two rows are named.
    by_discriminator: dict[str, list[str]] = {}
    for cause, expectation in _CAUSE_EXPECTATION.items():
        by_discriminator.setdefault(_expected_discriminator(expectation), []).append(str(cause))
    collisions = {d: sorted(cs) for d, cs in by_discriminator.items() if len(cs) > 1}
    if collisions:
        return False, [
            f"_CAUSE_EXPECTATION is not injective: {collisions} -- two causes sharing "
            "one discriminator are indistinguishable to this section, so each is "
            "covered only by the other's corpus row. If that is deliberate (a cause "
            "REFINING another that a byte-retaining reader cannot tell apart), say so "
            "here and give each its own row."
        ]

    # (3) The reader must actually produce every discriminator. Catches the
    # other direction: a reader collapsing every violation onto one verdict
    # satisfies the per-row checks and classifies nothing.
    want_discriminators = {
        _expected_discriminator(expectation) for expectation in _CAUSE_EXPECTATION.values()
    }
    if discriminators_seen != want_discriminators:
        return False, [
            f"the byte-retaining reader produced {sorted(discriminators_seen)} across "
            f"the corpus, expected exactly {sorted(want_discriminators)} -- a reader "
            "collapsing every violation onto one verdict satisfies the per-row checks "
            "and classifies nothing"
        ]

    return True, [
        f"PASS  manifest canonicality causes: {caused} caused + {uncaused} uncaused "
        f"rejections agree with the Rust NonCanonicalCause column; all "
        f"{len(want_discriminators)} discriminators exercised "
        f"({', '.join(sorted(want_discriminators))})"
    ]
