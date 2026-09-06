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
subtree at all -- so #613 added a second family of whole-body MUTATIONS of
the same base manifest, in its own `arraysort__` / `keyorder__` label
namespace.

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

# The mutation family (#613): not a product, so written out.  Five array
# reversals -- one per §4.2 sorted array -- and four map-key reversals, one
# per parser position that reads a map (the outer body, `kdf_params`, and
# the two entry maps).  A reader that checked key order at the top level
# only would satisfy a single-position corpus.
MUTATION_LABELS: tuple[str, ...] = (
    "arraysort__vector_clock",
    "arraysort__blocks",
    "arraysort__trash",
    "arraysort__block_recipients",
    "arraysort__block_vector_clock_summary",
    "keyorder__top",
    "keyorder__kdf_params",
    "keyorder__block",
    "keyorder__trash",
)


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
    a fixture holding N copies of one row satisfies a count, and -- the
    case that actually mattered -- so does one drawn from a single nesting
    level (#614 review).  The third is the namespace disjointness the two
    families depend on.
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
