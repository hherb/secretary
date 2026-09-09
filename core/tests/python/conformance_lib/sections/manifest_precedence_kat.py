"""Section MPR -- `manifest_precedence_kat.json` §4.2 rejection-precedence replay.

A manifest body can break more than one rule at once. Both implementations
then reject it, so nothing here is a safety property -- but until §4.2 gained
its precedence paragraph, nothing said WHICH rule either was required to
report, and the two DISAGREED. This section is the clean-room half of the pin.

The two orderings §4.2 fixes, and what each is worth:

1. **crypto-design §6.2 rule 4** (no tags, no floats) is enforced by a walk of
   the WHOLE body that completes before any key is interpreted, so it outranks
   everything below. This is the half that was genuinely divergent: this
   reader checked rule 4 per-value INSIDE its entry loop, so for a repeated
   key whose second copy was a float it reported the repeat and never looked
   at the float, while `decode_manifest` reported the float. Closed by
   `_reject_floats_and_tags`, which mirrors the Rust pre-pass of the same name.
2. **A repeated map key** is reported without interpreting its second copy, so
   it outranks the type, range and version checks on that key's value. This
   reader already agreed, but only BY CONSTRUCTION -- `_validate_manifest_shape`
   happens to run after the entry loop -- and nothing pinned it.

**Rules 1, 2 and 3 are deliberately outside that ordering**, and the reason is
architectural rather than an omission: a reader whose parse normalises
encoding-level choices can only detect them at the §4.3 step-4 re-encode,
which necessarily runs after interpretation, while a byte-retaining reader
like this one must detect them during its scan, before it. Measured, not
argued -- a body carrying a non-shortest-form head at an early key and a
repeat at a later one is reported by `decode_manifest` as the repeat and by
this reader as rule 3. Fixing an order between those and the two rules above
would outlaw one of the two reader architectures §4.2 itself admits, so §4.2
declares it unspecified and this corpus carries no such row.

# The #608 backstop trap, checked in both directions

The reader half must not be answerable by something OTHER than the property.
Two candidates were considered and each is ruled out by an assertion rather
than by argument:

- **The encoder.** `py_decode_manifest` re-encodes through `py_encode_manifest`
  for the §4.3 step-4 comparison, so an encoder-side check can stand in for a
  reader-side one -- the exact vacuity #608's review found in section MUQ.
  Ruled out by rejecting `ENCODER_REFUSAL_PREFIX`: no row here may be rejected
  by the writer. (No row can reach the re-encode anyway, since every one is
  rejected earlier -- but that is a property of today's decoder, and this
  assertion is a property of the row.)
- **A different rule firing first.** A bare "it was rejected" credits a row to
  whichever check happened to run first. Ruled out by discriminating on the
  TYPE `NonCanonicalItem` and its `.rule` attribute for the rule-4 rows, and
  on the typed `DuplicateMapKey` for the repeat rows -- never on message text,
  which is the substring trap #608's review found on this corpus family's
  encoder side.
"""

from __future__ import annotations

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import ENCODER_REFUSAL_PREFIX
from conformance_lib.codec.scanner import DuplicateMapKey, NonCanonicalItem
from conformance_lib.fixtures import load_json_fixture, manifest_precedence_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

# §6.2's rule number for "no tags, no floats", as `docs/vault-format.md`
# §4.2's table numbers it.
_RULE_NO_TAGS_NO_FLOATS = 4

# The closed `expect` vocabulary. An unrecognised word is a hard failure, not
# an unchecked row: default-deny, the posture every guard in this repo takes.
_EXPECT_ACCEPT = "accept"
_EXPECT_DUPLICATE = "duplicate_key"
_EXPECT_RULE4 = "rule4"
_EXPECT_WORDS = frozenset({_EXPECT_ACCEPT, _EXPECT_DUPLICATE, _EXPECT_RULE4})

# Every map the corpus plants a repeat in, and every second-copy shape it
# declares. A floor on the fixture rather than a restatement of it: without
# it, a corpus silently reduced to one nesting level would still pass, which
# is the collapse #614's review measured on the canonicality corpus.
_LEVELS = ("top", "kdf_params", "vector_clock", "block", "trash", "block_summary")
_SHAPES = ("well_typed", "wrong_type", "float", "tag")

# Outside the level product, because §4.2 makes it top-level-only rather than
# convenience doing so: at a nested level a byte-retaining reader checks the
# ENCLOSING value's canonicality before any nested parser sees its own repeat,
# and that ordering is the one §4.2 declares unspecified.
#
# It is the row that pins this walk's SCOPE. Widening `reject_floats_and_tags`
# to `_check_canonical_item` -- rules 2, 3 and 4 together -- makes it report
# rule 3 where `decode_manifest` reports the repeat. Measured: before this row
# existed, that widening left the entire verifier green.
_TOP_ONLY_SHAPES = ("non_shortest",)

# The key each level repeats, mirroring `Level::key` in the Rust helpers.
#
# This is what binds a row's `field` column to its LABEL, and it is the
# closest this reader can get to the Rust replay's rebuild-and-compare -- it
# cannot rebuild a body, having no encoder for one. Measured, because the
# weaker version was not obviously weaker: swapping five nested rows' bodies
# for the top-level one reds `field` on its own IF the column is left alone,
# but editing body and column in LOCKSTEP passed this section while the Rust
# replay red. With this table the lockstep edit reds here too, and defeating
# it additionally requires renaming the label -- which the coverage floor
# above catches.
_LEVEL_KEYS = {
    "top": "vault_uuid",
    "kdf_params": "iterations",
    "vector_clock": "counter",
    "block": "block_uuid",
    "trash": "block_uuid",
    "block_summary": "counter",
}


def _column_issues(row: dict) -> list[str]:
    """Check a row's columns against its LABEL before replaying it.

    A row whose `field` disagrees with the map its label names is not a
    weaker row -- it is a row testing a different body than it claims to.
    """
    label = row["label"]
    if row["expect"] != _EXPECT_DUPLICATE:
        return []
    level = label.split("__", 1)[0]
    want = _LEVEL_KEYS.get(level)
    if want is None:
        return [f"  {label}: label names no known map (levels: {sorted(_LEVEL_KEYS)})"]
    if row["field"] != want:
        return [
            f"  {label}: label says the repeat is in {level!r}, whose key is "
            f"{want!r}, but the row's field column says {row['field']!r}"
        ]
    return []


def _row_issues(row: dict) -> list[str]:
    """Replay one fixture row, returning a list of problems (empty = pass)."""
    label = row["label"]
    want = row["expect"]
    if want not in _EXPECT_WORDS:
        return [f"  {label}: unrecognised expect {want!r} (vocabulary: {sorted(_EXPECT_WORDS)})"]
    issues = _column_issues(row)
    if issues:
        return issues

    body = bytes.fromhex(row["manifest_body_hex"])

    try:
        py_decode_manifest(body)
    except _REJECTION_EXCEPTIONS as exc:
        if want == _EXPECT_ACCEPT:
            return [f"  {label}: §4.2 says this body is valid, but it was rejected: {exc}"]
        return _rejection_issues(label, want, row, exc)

    if want != _EXPECT_ACCEPT:
        return [f"  {label}: §4.2 requires rejection as {want}, but the reader ACCEPTED it"]
    return []


def _rejection_issues(label: str, want: str, row: dict, exc: Exception) -> list[str]:
    """Check that a rejection is the one §4.2's precedence paragraph requires."""
    issues: list[str] = []

    # The writer must never be the one that spoke -- see the module doc.
    if str(exc).startswith(ENCODER_REFUSAL_PREFIX):
        issues.append(
            f"  {label}: rejected by the ENCODER ({exc}), so the reader's own "
            f"precedence is untested on this row"
        )
        return issues

    if want == _EXPECT_RULE4:
        if not isinstance(exc, NonCanonicalItem):
            issues.append(
                f"  {label}: §4.2 requires §6.2 rule 4 (the whole-body tag/float "
                f"walk) to outrank the repeat, but the reader raised "
                f"{type(exc).__name__}: {exc}"
            )
        elif exc.rule != _RULE_NO_TAGS_NO_FLOATS:
            issues.append(
                f"  {label}: §4.2 requires §6.2 rule {_RULE_NO_TAGS_NO_FLOATS}, "
                f"but the reader reported rule {exc.rule}: {exc}"
            )
    elif want == _EXPECT_DUPLICATE:
        if not isinstance(exc, DuplicateMapKey):
            issues.append(
                f"  {label}: §4.2 requires the REPEAT to be reported without "
                f"interpreting its second copy, but the reader raised "
                f"{type(exc).__name__}: {exc}"
            )
        elif exc.key != row["field"]:
            issues.append(
                f"  {label}: the rejection must name the repeated key "
                f"{row['field']!r}, got {exc.key!r}"
            )
    return issues


def _coverage_issues(rows: list[dict]) -> list[str]:
    """The fixture must still hold every level, every shape and the control."""
    labels = {r["label"] for r in rows}
    issues = [
        f"  fixture has no row {level}__{shape}: a reader scoped to the levels "
        f"or shapes that ARE present would be conformant against it"
        for level in _LEVELS
        for shape in _SHAPES
        if f"{level}__{shape}" not in labels
    ]
    issues.extend(
        f"  fixture has no row top__{shape}: nothing then pins that the rule-4 "
        f"walk is rule-4 ONLY"
        for shape in _TOP_ONLY_SHAPES
        if f"top__{shape}" not in labels
    )
    if "control__no_repeat" not in labels:
        issues.append(
            "  fixture has no accept control: a reader that rejected every body "
            "would score a perfect result"
        )
    seen = {r["expect"] for r in rows}
    issues.extend(
        f"  no row expects {word!r}, so nothing pins that half of §4.2's "
        f"precedence paragraph"
        for word in sorted(_EXPECT_WORDS - seen)
    )
    return issues


def section_manifest_precedence_kat() -> tuple[bool, list[str]]:
    """Replay every `manifest_precedence_kat.json` row (#618)."""
    rows = load_json_fixture(
        manifest_precedence_kat_path(), "manifest_precedence_kat.json"
    )["rows"]

    issues = _coverage_issues(rows)
    for row in rows:
        issues.extend(_row_issues(row))

    lines = [f"  {len(rows)} precedence rows replayed"]
    if issues:
        lines.extend(issues)
        return False, lines
    lines.append("  PASS: rule 4 outranks a repeat; a repeat outranks the value's type")
    return True, lines
