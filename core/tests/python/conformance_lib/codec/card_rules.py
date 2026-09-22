"""Typed §6 contact-card rejections carrying a rule token (#641).

WHY TYPED.  `differential_replay.rs` compares WHICH rule each implementation
names, and a section that keys on message TEXT is satisfied by any rejection
whose wording happens to overlap -- the substring trap #608's review found.
Each class carries a `token` class attribute whose value is a spelling from
`core/tests/data/rule_token_vocabulary.json`, which both languages read.

COARSE ON PURPOSE.  `CardDisplayNameTooLong` carries `wrong_type`, the same
token a fixed-size field at the wrong length takes, because both are length
bounds and `CardError::rule_token` makes the same call.  `CardNonCanonical`
covers §6.2 rules 1, 2 and 3 and trailing bytes alike, because
`CardError::NonCanonicalCbor` is fieldless and cannot tell them apart.

`CardMissingField` subclasses `KeyError` so `str()` renders exactly as the bare
`KeyError` it replaces; every other class is a `ValueError`.  Both bases are
in `conformance_lib.rejection`'s verdict allowlist.
"""

from __future__ import annotations


class CardWrongType(ValueError):
    """A key or value has the wrong CBOR type, or a fixed-size field the wrong
    length, or the body is not a map."""

    token = "wrong_type"


class CardIntegerOutOfRange(ValueError):
    """An integer that must be a u64 is negative or too wide."""

    token = "integer_out_of_range"


class CardDuplicateKey(ValueError):
    """The card map repeats a key (§6.2 rule 5)."""

    token = "duplicate_map_key"


class CardMissingField(KeyError):
    """A required §6 field is absent."""

    token = "missing_field"


class CardUnknownField(ValueError):
    """A key the §6 schema does not define.

    The card has no forward-compat `unknown` bag, so an unrecognised key is
    rejected outright rather than retained -- the only decoder in this package
    that does so, which is why this token has one producer (#641).
    """

    token = "unknown_field"


class CardUnsupportedVersion(ValueError):
    """`card_version` is an integer that is not 1.

    Split from `CardWrongType` deliberately: a `card_version` of the wrong
    TYPE is a type fault, and folding the two was one of the four measured
    corpus divergences (design §1.1).
    """

    token = "unsupported_version"


class CardNonCanonical(ValueError):
    """The card is not in canonical form: §6.2 rule 1, 2 or 3, or trailing
    bytes."""

    token = "non_canonical_unclassified"


class CardDisplayNameTooLong(ValueError):
    """`display_name` exceeds crypto-design §6's 4096-byte bound."""

    token = "wrong_type"
