"""Typed rejections for the §4.2 manifest-body decoder, each carrying the
language-neutral rule token `differential_replay.rs` compares (#634).

WHY TYPES AND NOT MESSAGES.  `conformance.py` already learned this twice.
Section MUQ keyed on a message fragment and was satisfied by the ENCODER's
refusal, which happened to contain the same words (#608); #604 replaced a
`"rule 2:"` substring match with `NonCanonicalItem.rule` for the same reason.
A substring match is blind to everything around the fragment: it keeps passing
when the message is reworded into something that no longer means what it did,
and keeps passing when a DIFFERENT check grows a message containing it.

WHY A CLASS ATTRIBUTE AND NOT A LOOKUP TABLE.  A table maps a class to a
token in a second place, so a new subclass silently gets no token; the
attribute travels with the raise site.  `token_for` deliberately reads the
attribute off ANY exception rather than off a base class, because
`cursor.ParseError` is shared with every other target's wire decoder and must
not be reparented under a manifest-specific base.

MESSAGE-PRESERVING.  Every class here is introduced by changing `ValueError`
to a subclass of it at an existing raise site with the message untouched, so
no section that reads `str(e)` moves.  All of these subclass `ValueError`, so
`conformance_lib.rejection`'s allowlist keeps scoring them as verdicts rather
than as harness failures.
"""

from __future__ import annotations


class ManifestRejection(ValueError):
    """A §4.2 manifest-body rejection carrying a rule token.

    `token` is a CLASS attribute: it is a property of the rule, never of the
    instance, so it cannot be set wrong at a raise site.
    """

    token: str = ""


class TrailingBytesAfterMap(ManifestRejection):
    """Bytes follow the manifest map.

    Deliberately shares Rust's coarse token rather than getting one of its
    own.  `ciborium`'s reader performs no EOF check, so the Rust parse
    discards these bytes before the §4.3 step-4 comparison and
    `classify_non_canonical` has nothing in the body to point at -- it can
    only ever report `Unclassified`.  A `trailing_bytes` token would be a
    distinction only ONE implementation can make, and the message below stays
    specific so no human reader loses the diagnostic.
    """

    token = "non_canonical_unclassified"


class NonTextMapKey(ManifestRejection):
    """A manifest map key is not a text string (§4.2)."""

    token = "wrong_type"


class MissingRequiredField(ManifestRejection):
    """A §4.2 required key is absent."""

    token = "missing_field"


class WrongFieldType(ManifestRejection):
    """A field's CBOR major type or byte-string length is not what §4.2 says."""

    token = "wrong_type"


class IntegerOutOfRange(ManifestRejection):
    """An integer field is outside the width §4.2 gives it."""

    token = "integer_out_of_range"


class UnsupportedVersion(ManifestRejection):
    """A v1 sentinel is not the v1 value."""

    token = "unsupported_version"


class RepeatedArrayValue(ManifestRejection):
    """One of §4.2's four repeated-value prohibitions.

    NOT the same rule as a repeated MAP key, and deliberately a different
    token: §4.2 orders the map-key rule against the type checks and leaves
    this one unordered.  `recipients` is §4.2's explicit exception and never
    reaches here.
    """

    token = "repeated_array_value"


def token_for(exc: BaseException) -> str | None:
    """The rule token this rejection carries, or `None` if it carries none.

    Reads the attribute off any exception rather than off a base class, so
    `scanner.NonCanonicalItem`, `scanner.DuplicateMapKey` and
    `cursor.ParseError` participate without being reparented.

    `None` is a real answer and the caller must treat it as a HARNESS
    FAILURE, not as "no divergence" -- the default-deny posture
    `conformance_lib.rejection` already takes.  A silently untokened
    rejection would restore exactly the blindness #634 exists to remove.
    """
    token = getattr(exc, "token", None)
    return token if isinstance(token, str) and token else None
