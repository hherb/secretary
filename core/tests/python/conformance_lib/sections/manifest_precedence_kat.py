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
   `reject_floats_and_tags`, which mirrors the Rust pre-pass of the same name.
2. **A repeated map key** is reported without interpreting its second copy, so
   it outranks the type, range and version checks on that key's value. This
   reader already agreed, but only BY CONSTRUCTION -- `_validate_manifest_shape`
   happens to run after the entry loop -- and nothing pinned it. All THREE of
   those competing checks now have a row: `wrong_type`, `out_of_range` (a
   `u32` field given 2^40) and `bad_version` (`manifest_version` given 7).
   Enumerating only the type check left the other two agreeing by
   construction, which is the state this corpus exists to replace.

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

An earlier revision of this corpus DID carry one, a `top__non_shortest` row
requiring the repeat, in order to pin that `reject_floats_and_tags` is rule-4
ONLY. That scope is a property of one implementation rather than of `docs/`,
so a cross-language row was the wrong instrument: a conformant byte-retaining
reader that scans canonicality first reports rule 3 and failed it. Section CS
now pins the scope directly, by calling `reject_floats_and_tags` on a body
whose only fault is a rule-2 or rule-3 violation and requiring it to return
cleanly. That is a sharper pin, and it claims nothing of anyone else's reader.

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

**Applying that rule to this section is not applying it to the tree** (#631's
generalisation). `reject_floats_and_tags` runs on the manifest path ahead of
the per-value `_check_canonical_item`, so for the three `*__rule4_float` rows
of the CANONICALITY corpus it now answers where that per-value check used to.
Measured: deleting `_check_canonical_item`'s rule-4 arm reds Sections CS and
MCC at this branch's merge-base and only CS here. Nothing is unpinned
tree-wide -- Section CS's unit cases are the pin, and MCC's own docstring
records the changed mechanism -- but CS is now the SOLE pin for that arm on
the manifest path, and a future edit that weakens CS takes it with them.
"""

from __future__ import annotations

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import ENCODER_REFUSAL_PREFIX
from conformance_lib.codec.scanner import DuplicateMapKey, NonCanonicalItem
from conformance_lib.fixtures import load_json_fixture, manifest_precedence_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS
from conformance_lib.sections.manifest_canonicality_corpus import body_issues

# §6.2's rule number for "no tags, no floats", as `docs/vault-format.md`
# §4.2's table numbers it.
_RULE_NO_TAGS_NO_FLOATS = 4

# The closed `expect` vocabulary. An unrecognised word is a hard failure, not
# an unchecked row: default-deny, the posture every guard in this repo takes.
_EXPECT_ACCEPT = "accept"
_EXPECT_DUPLICATE = "duplicate_key"
_EXPECT_RULE4 = "rule4"
_EXPECT_WORDS = frozenset({_EXPECT_ACCEPT, _EXPECT_DUPLICATE, _EXPECT_RULE4})

# Every column the generator writes. Checked for PRESENCE before any is
# indexed, so a fixture regenerated by an older table produces a `FAIL:` line
# rather than a `KeyError` out of `main()` -- which would skip every section
# after this one, REG included. The sibling corpora learned this the same way
# (`manifest_canonicality_corpus.row_issues`).
_REQUIRED_COLUMNS = ("label", "manifest_body_hex", "expect", "field", "map", "dup_index")

# Every map the corpus plants a repeat in, and every second-copy shape it
# declares. A floor on the fixture rather than a restatement of it: without
# it, a corpus silently reduced to one nesting level would still pass, which
# is the collapse #614's review measured on the canonicality corpus.
_LEVELS = (
    "top",
    "top_version",
    "kdf_params",
    "vector_clock",
    "block",
    "trash",
    "block_summary",
)
_SHAPES = ("well_typed", "wrong_type", "float", "tag")

# Outside the level product because each needs a key the other levels do not
# have: a width-narrowed integer, and the one field carrying a version check.
# They are §4.2 ordering 2's second and third competing checks, so their
# absence would leave that ordering enumerated for the type check alone.
_LEVEL_RESTRICTED_LABELS = ("kdf_params__out_of_range", "top_version__bad_version")

# The key each level repeats and the map name this reader reports for it,
# mirroring `Level::key` and `Level::map_label` in the Rust helpers.
#
# NEITHER column identifies a level on its own, and that is why the corpus
# carries both. `block` and `trash` repeat the same key; `top` and
# `top_version` are the same map. Measured before the `map` column existed:
# swapping `block__well_typed` and `trash__well_typed` bodies -- no column
# edit needed, since their keys collide -- left this section PASS while the
# Rust replay red. The PAIR is unique per level, which is what the Rust
# `every_level_is_identified_by_its_map_and_key` pins.
_LEVEL_KEYS = {
    "top": "vault_uuid",
    "top_version": "manifest_version",
    "kdf_params": "iterations",
    "vector_clock": "counter",
    "block": "block_uuid",
    "trash": "block_uuid",
    "block_summary": "counter",
}
_LEVEL_MAPS = {
    "top": "manifest",
    "top_version": "manifest",
    "kdf_params": "kdf_params",
    "vector_clock": "vector_clock",
    "block": "blocks entry",
    "trash": "trash entry",
    "block_summary": "vector_clock_summary",
}


def _row_shape_issues(index: int, row: object) -> list[str]:
    """Check ONE row's SHAPE, before any column is indexed.

    A malformed fixture must produce a `FAIL:` line, not a traceback out of
    `main()`. This section runs before RC, DET and REG, so an escaping
    `KeyError` silently skips all three -- including the section that proves
    the registry is complete, which is exactly when a second, simultaneous
    defect would become invisible.
    """
    if not isinstance(row, dict):
        return [f"  row {index}: must be a JSON object, got {type(row).__name__}"]
    missing = [k for k in _REQUIRED_COLUMNS if k not in row]
    if missing:
        return [
            f"  row {index}: fixture is missing column(s) {missing} -- regenerate it "
            "with `cargo test --release --workspace -- --ignored "
            "generate_manifest_precedence_kat`"
        ]
    for key in ("label", "manifest_body_hex", "expect"):
        if not isinstance(row[key], str):
            return [
                f"  row {index}: {key} must be a string, got {type(row[key]).__name__}"
            ]
    for key in ("field", "map"):
        if row[key] is not None and not isinstance(row[key], str):
            return [
                f"  row {row['label']!r}: {key} must be a string or null, got "
                f"{type(row[key]).__name__}"
            ]
    try:
        bytes.fromhex(row["manifest_body_hex"])
    except ValueError as exc:
        return [f"  row {row['label']!r}: manifest_body_hex is not valid hex: {exc}"]
    return []


def _column_issues(row: dict) -> list[str]:
    """Check a row's columns against its LABEL before replaying it.

    A row whose `field` or `map` disagrees with the map its label names is not
    a weaker row -- it is a row testing a different body than it claims to.
    Both directions are checked: a non-duplicate row must carry NEITHER, which
    the Rust replay also asserts and this reader previously did not.
    """
    label = row["label"]
    if row["expect"] != _EXPECT_DUPLICATE:
        stray = [c for c in ("field", "map") if row[c] is not None]
        if stray:
            return [
                f"  {label}: expect is {row['expect']!r}, which reports no repeat, "
                f"but the row still declares {stray}"
            ]
        return []
    level = label.split("__", 1)[0]
    if level not in _LEVEL_KEYS:
        return [f"  {label}: label names no known map (levels: {sorted(_LEVEL_KEYS)})"]
    issues = []
    for column, table in (("field", _LEVEL_KEYS), ("map", _LEVEL_MAPS)):
        if row[column] != table[level]:
            issues.append(
                f"  {label}: label says the repeat is in {level!r}, whose {column} is "
                f"{table[level]!r}, but the row says {row[column]!r}"
            )
    return issues


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
        else:
            if exc.key != row["field"]:
                issues.append(
                    f"  {label}: the rejection must name the repeated key "
                    f"{row['field']!r}, got {exc.key!r}"
                )
            # `.label` is what tells `block` from `trash` and `vector_clock`
            # from `block_summary`: their KEYS collide, so without this the
            # four are mutually interchangeable on this side.
            if exc.label != row["map"]:
                issues.append(
                    f"  {label}: the rejection must name the map {row['map']!r}, "
                    f"got {exc.label!r}"
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
        f"  fixture has no row {want}: §4.2's second ordering names the type, "
        f"RANGE and VERSION checks, and without this row that ordering is "
        f"enumerated for the type check alone"
        for want in _LEVEL_RESTRICTED_LABELS
        if want not in labels
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
    want_rows = len(_LEVELS) * len(_SHAPES) + len(_LEVEL_RESTRICTED_LABELS) + 1
    if len(rows) != want_rows:
        issues.append(
            f"  fixture holds {len(rows)} rows, expected {want_rows} "
            f"({len(_LEVELS)} levels x {len(_SHAPES)} shapes, plus "
            f"{len(_LEVEL_RESTRICTED_LABELS)} level-restricted rows and the control)"
        )
    # Every row must carry a DISTINCT body. The label and column floors above
    # cannot see a body collapse: measured on this corpus before the check --
    # giving all 14 `rule4` rows one body, and giving `trash__*` their
    # `block__*` counterparts' bodies, each left this section PASS while the
    # Rust rebuild-and-compare red. Rust binds bytes to label by rebuilding
    # from the case table; this reader has no such oracle and must not import
    # `secretary-core`, so distinctness is the floor it CAN enforce.
    issues.extend(f"  {issue}" for issue in body_issues([r["manifest_body_hex"] for r in rows]))
    return issues


def section_manifest_precedence_kat() -> tuple[bool, list[str]]:
    """Replay every `manifest_precedence_kat.json` row (#618)."""
    rows = load_json_fixture(
        manifest_precedence_kat_path(), "manifest_precedence_kat.json"
    )["rows"]

    shape_issues = [i for n, row in enumerate(rows) for i in _row_shape_issues(n, row)]
    if shape_issues:
        return False, [f"  {len(rows)} precedence rows loaded", *shape_issues]

    issues = _coverage_issues(rows)
    for row in rows:
        issues.extend(_row_issues(row))

    lines = [f"  {len(rows)} precedence rows replayed"]
    if issues:
        lines.extend(issues)
        return False, lines
    lines.append("  PASS: rule 4 outranks a repeat; a repeat outranks its value's type, range and version")
    return True, lines
