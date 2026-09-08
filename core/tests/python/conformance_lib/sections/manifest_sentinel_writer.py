"""Section MSN -- §4.2's v1 sentinel rule, on the WRITER side (#587).

§4.2 fixes three fields of every v1 manifest body::

    manifest_version = 1
    format_version   = 1
    suite_id         = 1

and binds writers as well as readers.  Both implementations enforced only
the reader half until #587: `core`'s `encode_manifest` would serialise
``manifest_version: 7`` and `sign_manifest` would hybrid-sign the result,
and `py_encode_manifest` would emit the same bytes -- **a signed manifest no
v1 client can open**.  That is the identical defect #600 closed for §4.2's
repeated-value rules and #586/#602 closed for duplicate map keys, one field
group over, and it is the last member of that family.

Availability rather than confidentiality (the manifest is owner-signed, so
the producer is always a local caller building a body in memory).  But for a
format frozen for decades with a clean-room mandate, an encoder that emits a
signed document its own decoder rejects is a real defect -- and §4.2 states
the obligation, so an encoder ignoring it is formally non-conformant with
`docs/`.

# Why there is no JSON fixture, deliberately

Every other manifest corpus in this package -- `manifest_canonicality_kat`,
`manifest_uniqueness_kat` -- is a set of frozen BODIES, because for those
rules the bytes *are* the contract: the reader must reject a specific
encoding, and only committed bytes pin which one.  A sentinel rejection
happens **before any byte is produced**, so a byte corpus would assert
nothing that the three cases below do not.  The reader half needs no corpus
either -- but be careful WHY, because the obvious reason is wrong and an
earlier version of this docstring gave it.

Section MSH (`manifest_body_shape_guards`, not the near-identically named
`manifest_body_schema_guards`, which carries no sentinel mutation at all)
does mutate all three sentinels. It is **not** independent cover for the
reader, for two measured reasons: its `manifest_version` row never reaches
the sentinel comparison at all (the `u8` width check fires first on 999),
and its `format_version` / `suite_id` rows were answered by the ENCODER at
the §4.3 step-4 re-encode from the moment #587 landed -- that section scored
PASS with the reader's own sentinel check deleted, until the #631 review
gave it the `ENCODER_REFUSAL_PREFIX` discriminator.

So `_reader_is_not_backstopped_issues` below is the ONLY pin on this
package's reader-side sentinel comparison. Do not delete it as belt-and-
braces. The two implementations' agreement on non-v1 *bodies* is separately
covered by the differential replay.

What DOES need stating cross-language is that neither writer will emit one,
which is what this section is.

# The backstop trap, which this section is built around

`py_decode_manifest` re-encodes through `py_encode_manifest` for the §4.3
step-4 comparison, so the moment that encoder enforced §4.2 it began
BACKSTOPPING the reader -- the same mechanism #608's review found for the
uniqueness rule.  The discriminator is
`manifest_encode.ENCODER_REFUSAL_PREFIX`: a rejection carrying it did not
come from the reader.  This section's writer cases **require** the prefix;
`_reader_is_not_backstopped_issues` is its dual and **rejects** it.

Rust's answer to the same trap is a type rather than a prefix -- three
separate `ManifestError::Encode*` variants -- because there the two
directions' errors are otherwise indistinguishable.  Measured on that side:
with the variants collapsed onto the decoder's three and the decoder's own
check deleted, the whole `secretary-core --lib` suite stayed green.  Same
rule, two mechanisms, and §4.2's asymmetry paragraph is why neither is
required to adopt the other's.
"""

from __future__ import annotations

import copy

from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.codec.manifest_encode import (
    ENCODER_REFUSAL_PREFIX,
    py_encode_manifest,
)
from conformance_lib.codec.manifest_schema import MANIFEST_VERSION_V1
from conformance_lib.constants import FORMAT_VERSION, SUITE_ID
from conformance_lib.fixtures import load_json_fixture, manifest_uniqueness_kat_path
from conformance_lib.rejection import _REJECTION_EXCEPTIONS


# The corpus row this section borrows a valid manifest from. Reusing an
# existing control rather than hand-building a dict means the manifest under
# test is one both languages already agree decodes -- a hand-built fixture
# could drift from what `py_decode_manifest` actually produces without
# anything noticing.
_CONTROL_ROW = "control__all_distinct"

# A value that is neither v1 nor a plausible off-by-one, so a case cannot
# pass by accident against an encoder checking `!= 0` or `< 2`.
_NOT_V1 = 7

# (field, v1 value) in §4.2 declaration order -- the order both languages
# report a violation in, which `_field_order_issues` pins.
_SENTINELS: tuple[tuple[str, int], ...] = (
    ("manifest_version", MANIFEST_VERSION_V1),
    ("format_version", FORMAT_VERSION),
    ("suite_id", SUITE_ID),
)


def _control_manifest() -> tuple[dict | None, list[str]]:
    """Decode the borrowed control row, or say why this section cannot run."""
    doc = load_json_fixture(
        manifest_uniqueness_kat_path(), "manifest_uniqueness_kat.json"
    )
    row = next(
        (r for r in doc["rows"] if r["label"] == _CONTROL_ROW), None
    )
    if row is None:
        return None, [
            f"SKIPPED -- the borrowed corpus has no {_CONTROL_ROW!r} row, so no "
            "valid manifest could be built. This is a FAILURE rather than a "
            "silent skip: a section that quietly tests nothing is the fail-open "
            "shape this package keeps closing."
        ]
    try:
        return py_decode_manifest(bytes.fromhex(row["manifest_body_hex"])), []
    except _REJECTION_EXCEPTIONS as e:
        return None, [
            f"the borrowed control row does not decode ({type(e).__name__}: {e}), "
            "so no writer case can be built from it"
        ]


def _writer_issues(base: dict) -> list[str]:
    """Every sentinel must be refused by the writer, and v1 must not be."""
    issues: list[str] = []

    # The positive control FIRST. Without it, an encoder that refused
    # everything would satisfy all three cases below.
    try:
        py_encode_manifest(copy.deepcopy(base))
    except _REJECTION_EXCEPTIONS as e:
        issues.append(
            f"the v1 control must ENCODE, got {type(e).__name__}: {e} -- every "
            "case below would then pass against a writer that refuses everything"
        )

    for field, v1_value in _SENTINELS:
        mutated = copy.deepcopy(base)
        if field not in mutated:
            issues.append(
                f"{field}: the control manifest has no such key, so this case "
                "tested nothing"
            )
            continue
        mutated[field] = _NOT_V1
        if mutated == base:
            # The trap this repo keeps re-finding: a mutation that did not
            # apply is indistinguishable from one nothing caught. It fires
            # here if the corpus ever adopts _NOT_V1 as a real value.
            issues.append(f"{field}: the edit planted nothing")
            continue
        try:
            py_encode_manifest(mutated)
            emitted, detail = True, ""
        except _REJECTION_EXCEPTIONS as e:
            emitted, detail = False, str(e)

        if emitted:
            issues.append(
                f"the encoder EMITTED a body whose {field} is {_NOT_V1}, which its "
                "own decoder rejects -- §4.2 binds writers as well as readers, and "
                "`sign_manifest` would hybrid-sign this"
            )
        elif not detail.startswith(ENCODER_REFUSAL_PREFIX):
            issues.append(
                f"{field} was refused, but not by the ENCODER's own sentinel rule "
                f"-- expected a message starting {ENCODER_REFUSAL_PREFIX!r}, got "
                f"{detail!r}"
            )
        elif field not in detail:
            issues.append(
                f"{field} was refused by the encoder, but the message does not name "
                f"the offending field -- got {detail!r}. A clean-room implementer "
                "cannot act on a rejection that does not say which sentinel failed."
            )
        elif str(v1_value) == str(_NOT_V1):  # pragma: no cover - guards the table
            issues.append(
                f"{field}: the table's v1 value equals the probe value, so this "
                "case cannot discriminate"
            )
    return issues


def _field_order_issues(base: dict) -> list[str]:
    """A body violating all three sentinels must name the FIRST in §4.2 order.

    Not cosmetic: `core`'s decoder reports in this order too, so pinning it
    means a multi-sentinel body names the same field whichever language and
    whichever direction rejects it. Without this, the two implementations
    could disagree on a body violating two rules -- which is exactly the
    open divergence #621 records for the canonicality causes, and this
    section declines to add a second instance of it.
    """
    mutated = copy.deepcopy(base)
    for field, _ in _SENTINELS:
        mutated[field] = _NOT_V1
    try:
        py_encode_manifest(mutated)
    except _REJECTION_EXCEPTIONS as e:
        first = _SENTINELS[0][0]
        if not str(e).startswith(ENCODER_REFUSAL_PREFIX):
            # Same discriminator `_writer_issues` applies, for the same
            # reason: without it any rejection that merely happened to
            # contain the field name -- the reader's own, at the step-4
            # re-encode -- would satisfy this writer-side assertion.
            return [
                f"a body violating all three sentinels was refused, but not by "
                f"the ENCODER's own rule -- expected a message starting "
                f"{ENCODER_REFUSAL_PREFIX!r}, got {str(e)!r}"
            ]
        if first not in str(e):
            return [
                f"a body violating all three sentinels must name {first!r} (§4.2 "
                f"field order), got {str(e)!r}"
            ]
        return []
    return [
        "the encoder emitted a body violating all three sentinels"
    ]


def _reader_is_not_backstopped_issues(base: dict) -> list[str]:
    """The READER must reject a non-v1 body on its own account.

    `py_decode_manifest` re-encodes through `py_encode_manifest`, so once
    that encoder enforces §4.2 it can answer on the reader's behalf. This is
    the dual of `_writer_issues`: there the prefix is REQUIRED, here it is
    REJECTED. Without it, deleting the reader's own sentinel check would
    leave every case in this section green.
    """
    mutated = copy.deepcopy(base)
    mutated["manifest_version"] = _NOT_V1
    try:
        body = py_encode_manifest(mutated)
    except _REJECTION_EXCEPTIONS:
        # Expected once #587 landed: the encoder now refuses to build the
        # hostile body, exactly as #602 found for the contact card. Rebuild
        # it the way that slice did -- through the byte-level splice the
        # reader is meant to see, not through a sanctioned encoder.
        body = _splice_manifest_version(base, _NOT_V1)
        if body is None:
            return [
                "could not build a non-v1 body by splice, so the reader half of "
                "this section tested nothing"
            ]

    try:
        py_decode_manifest(body)
    except _REJECTION_EXCEPTIONS as e:
        if str(e).startswith(ENCODER_REFUSAL_PREFIX):
            return [
                "a non-v1 body was rejected by the ENCODER at the §4.3 step-4 "
                f"re-encode, not by the reader's own sentinel check -- got {str(e)!r}. "
                "The reader's check may have been deleted and this section would "
                "not otherwise say so."
            ]
        return []
    return ["the reader ACCEPTED a body whose manifest_version is not v1"]


def _splice_manifest_version(base: dict, value: int) -> bytes | None:
    """Re-emit the control body with `manifest_version` overwritten.

    Uses `cbor2` directly rather than `py_encode_manifest`, because that
    encoder now refuses exactly this body. A canonical whole-map re-encode
    is sufficient here: the control row carries no top-level `unknown`
    subtree whose raw bytes would need splicing, which is asserted rather
    than assumed.
    """
    import cbor2

    if base.get("unknown"):
        return None
    plain = {k: v for k, v in base.items() if k != "unknown"}
    plain["manifest_version"] = value
    try:
        return cbor2.dumps(plain, canonical=True)
    except (TypeError, ValueError):
        return None


def section_manifest_sentinel_writer() -> tuple[bool, list[str]]:
    """§4.2's v1 sentinel rule, enforced on the writer side (#587).

    Four things, and the last two are what keep the first two honest:

    1. Each of the three sentinels is refused by `py_encode_manifest`, with
       a message that carries the encoder's own refusal prefix and names the
       offending field.
    2. A v1 control still encodes, so 1 is not satisfied by an encoder that
       refuses everything.
    3. A body violating all three names the FIRST in §4.2 field order, so
       the two languages cannot drift into a #621-shaped divergence.
    4. The READER still rejects a non-v1 body on its own account, i.e. the
       encoder's new check is not standing in for it.
    """
    base, issues = _control_manifest()
    if base is None:
        return False, issues

    issues.extend(_writer_issues(base))
    issues.extend(_field_order_issues(base))
    issues.extend(_reader_is_not_backstopped_issues(base))

    if issues:
        return False, issues
    names = ", ".join(f for f, _ in _SENTINELS)
    return True, [
        f"PASS  §4.2 v1 sentinel writer half: all {len(_SENTINELS)} sentinels "
        f"({names}) refused by the encoder, by name and behind its own refusal "
        f"prefix, while the v1 control still encodes",
        "PASS  a body violating all three names the first in §4.2 field order, "
        "and the reader still rejects a non-v1 body on its own account rather "
        "than through the step-4 re-encode",
    ]
