"""The SHAPE of `manifest_canonicality_kat.json`, declared once for the two
sections that read it.

Sections MCK and MCC both replay this fixture and both need to know which
rows it is supposed to carry.  Declared here rather than twice, because two
copies of a corpus description drift -- and a section checking a corpus
against its own private idea of the corpus is checking nothing.

**Why the fixture is two families.**  Every row up to #604 was one of seven
canonical-CBOR subtree shapes spliced into a forward-compat `unknown` bag at
one of three nesting levels: 7 x 3 = 21 rows, labelled `<level>__<shape>`.
That construction can only reach two of Rust's four `NonCanonicalCause`
variants.  `ArraySortOrder` needs one of §4.2's five sorted arrays out of
order and `Unclassified` needs map-key disorder -- neither is an `unknown`
subtree at all -- so #613 added a second family of 11 whole-body MUTATIONS
of the same base manifest, in its own `arraysort__` / `keyorder__` label
namespace.  32 rows in total.

The two namespaces must stay disjoint: `<level>__` prefixes are `top`,
`block` and `trash`, and `label_issues` reports any mutation label that
collides with one.  Rust pins the same disjointness from the other side, in
`no_mutation_label_can_be_read_as_a_splice_row`.

This module defines no `section*` driver, so Section REG discovers it and
finds nothing to register -- see `completeness.py`'s `_NON_DRIVER_MODULES`.
"""

from __future__ import annotations

# The splice family: `<level>__<shape>`, a full product.
SPLICE_LEVELS: tuple[str, ...] = ("top", "block", "trash")
SPLICE_SHAPES: tuple[str, ...] = (
    "control_canonical",
    "control_array",
    "rule1_key_order",
    "rule5_duplicate_key",
    "rule2_indefinite_map",
    "rule3_non_shortest_int",
    "rule4_float",
)

# The mutation family (#613): not a product, so written out.  SEVEN array
# reversals and four map-key reversals.
#
# Seven, not five, for §4.2's five arrays: the two NESTED ones are planted at
# `blocks[0]` AND `blocks[1]`.  A corpus that only ever plants at the first
# block leaves a reader scoped to `blocks[0]` fully conformant -- measured in
# both languages, and the mirror of the defect #608's review fixed on
# `manifest_uniqueness_kat`, whose fixtures plant their repeat at `blocks[1]`
# for exactly this reason.  Block 0 is spelled without an index so the labels
# #613 committed keep their bytes.
#
# Four map positions because they are four different parsers on the RUST side
# (the outer body, `kdf_params`, and the two entry maps).  This reader has
# three -- `_decode_manifest_entry_map` serves both entry maps -- so do not
# write "four parsers on both sides".
MUTATION_LABELS: tuple[str, ...] = (
    "arraysort__vector_clock",
    "arraysort__blocks",
    "arraysort__trash",
    "arraysort__block_recipients",
    "arraysort__block_vector_clock_summary",
    "arraysort__block1_recipients",
    "arraysort__block1_vector_clock_summary",
    "keyorder__top",
    "keyorder__kdf_params",
    "keyorder__block",
    "keyorder__trash",
)


# Every column either section reads.  Declared here because `row_issues` is
# the shared guard and both sections depend on the same set.
_REQUIRED_COLUMNS = ("label", "manifest_body_hex", "expect_accept", "expect_cause")


def splice_labels() -> set[str]:
    """The splice family's full `<level>__<shape>` product."""
    return {f"{level}__{shape}" for level in SPLICE_LEVELS for shape in SPLICE_SHAPES}


def expected_labels() -> set[str]:
    """Every label the fixture must carry, both families."""
    return splice_labels() | set(MUTATION_LABELS)


def label_issues(labels: list[str]) -> list[str]:
    """Check a fixture's label list against the declared corpus shape.

    Returns a list of human-readable issues -- empty when the fixture is
    exactly right.  A pure function over the labels so both sections get
    the identical verdict and neither can drift onto a weaker check.

    Three things, and the first two are the ones a bare row COUNT misses:
    a fixture holding N copies of one row satisfies a count, and so does one
    drawn from a single nesting level.  The third is the namespace
    disjointness the two families depend on.

    **What a LABEL check structurally cannot see, stated because an earlier
    version of this docstring claimed otherwise.**  It said the nesting-level
    case was "the case that actually mattered (#614 review)".  #614's measured
    finding was a BODY substitution with every label retained -- replacing the
    `block__`/`trash__` bodies with their `top__` counterparts -- and no
    comparison of label SETS can detect that.  Rust catches it by rebuilding
    each row's bytes from its case; this reader cannot (it must not import
    `secretary-core`), so `body_issues` below carries the floor that it can.
    """
    issues: list[str] = []

    duplicates = sorted({label for label in labels if labels.count(label) > 1})
    if duplicates:
        issues.append(f"corpus has duplicate labels: {duplicates}")

    got, want = set(labels), expected_labels()
    if got != want:
        missing, extra = sorted(want - got), sorted(got - want)
        issues.append(
            "corpus label set must be exactly the "
            f"{len(SPLICE_LEVELS)} x {len(SPLICE_SHAPES)} splice product plus the "
            f"{len(MUTATION_LABELS)} mutation rows (#613): "
            f"missing={missing}, unexpected={extra}"
        )

    # Reported even when the set matched, because it is a property of this
    # module's own tables rather than of the fixture: a future mutation
    # label starting `top__`/`block__`/`trash__` would be counted into the
    # splice family and silently displace a real splice row.
    colliding = sorted(
        label
        for label in MUTATION_LABELS
        if label.split("__", 1)[0] in SPLICE_LEVELS
    )
    if colliding:
        issues.append(
            f"mutation labels {colliding} collide with the splice family's "
            f"`<level>__` namespace {sorted(SPLICE_LEVELS)}"
        )

    return issues


def row_issues(index: int, row: object) -> list[str]:
    """Check ONE fixture row's SHAPE, before any column is indexed.

    Shared by MCK and MCC because MCK runs FIRST and reads the same file: a
    guard that lives only in MCC is unreachable for exactly the defects it
    was written for.  Measured before this existed -- a row missing `label`,
    a row missing `manifest_body_hex`, and a row that is a string rather than
    an object each escaped MCK as an uncaught `KeyError`/`TypeError`, i.e. a
    traceback out of `main()` with no `FAIL:` line, silently skipping MCC,
    MUQ, RC, DET and REG.

    `label`'s TYPE is checked as well as its presence: a non-string label is
    collected into a set by both sections, so a JSON list reached
    `set(labels)` and raised `TypeError: unhashable type` -- outside
    `_REJECTION_EXCEPTIONS`, hence straight out of `main()` again.
    """
    if not isinstance(row, dict):
        return [f"row {index}: must be a JSON object, got {type(row).__name__}"]
    missing = [k for k in _REQUIRED_COLUMNS if k not in row]
    if missing:
        return [
            f"row {index}: fixture is missing column(s) {missing} -- regenerate it "
            "with `cargo test --release --workspace -- --ignored "
            "generate_manifest_canonicality_kat`"
        ]
    if not isinstance(row["label"], str):
        return [f"row {index}: label must be a string, got {type(row['label']).__name__}"]
    if not isinstance(row["manifest_body_hex"], str):
        return [
            f"row {row['label']!r}: manifest_body_hex must be a string, got "
            f"{type(row['manifest_body_hex']).__name__}"
        ]
    return []


def body_issues(bodies: list[str]) -> list[str]:
    """Every row must carry a DISTINCT manifest body.

    The floor this reader CAN enforce against the class `label_issues`
    cannot see.  Rust binds each row's bytes to its label by rebuilding from
    the case table; this reader has no such oracle (it must not import
    `secretary-core`), but it can still refuse a corpus that claims more
    positions than it exercises.

    Measured before this existed, with labels and columns untouched: giving
    all five `arraysort__*` rows one body, and giving every `block__`/
    `trash__` splice row its `top__` counterpart's body (#614's own
    scenario), each left Sections MCK and MCC GREEN.  The corpus's premise --
    one distinct body per array, per map position, per nesting level -- was
    unpinned on this side.
    """
    seen: dict[str, list[int]] = {}
    for i, body in enumerate(bodies):
        seen.setdefault(body, []).append(i)
    dupes = sorted(idxs for idxs in seen.values() if len(idxs) > 1)
    if not dupes:
        return []
    return [
        f"corpus rows {dupes} share a manifest body -- every corpus calling this "
        "floor claims one distinct body per position, and a label floor cannot see "
        "a body collapse (#614 was a body substitution, not a label one)"
    ]
