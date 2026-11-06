"""Typed envelope rejections carrying a rule token (#641): the §6.1/§6.2
block file and, since `bundle_file` became token-compared, the §3
`identity.bundle.enc` envelope.

Subclasses of `cursor.ParseError`, deliberately NOT of a new base: every
existing `except ParseError` in this package -- `sections/block_kat.py`,
`sections/revoke.py`, the golden-vault verifier -- keeps catching them, and
`conformance_lib.rejection` already admits `ParseError` as a verdict.
`ParseError` itself keeps `container_malformed` for a TRUNCATION, which is
what `cursor.take` raises.

The seven `container_malformed` classes below draw no distinction the token
does not already draw -- they all carry that token, so no replay comparison
changes.  They exist so a check can be pinned to its SEED (PR #673 review):
with one class for every envelope fault, deleting the `sig_ed_len` check let
the parse fail a few bytes later as a truncation with the same token, and
Section RTS stayed green.  RTS now requires each `block_file` and
`bundle_file` seed's class by name, and `block.rs` or `bundle_file.rs` draws
every one of these distinctions as a variant.
Each class declares `token` itself rather than inheriting it, so Section
RTS can require that of every verdict class these modules define.

Only distinctions `core/src/vault/block.rs` or `core/src/unlock/bundle_file.rs`
also draws are drawn here -- the vocabulary's standing rule that a token may
only draw a distinction both implementations can make.  The bundle parser
reuses the block classes where the two Rust enums draw the same distinction
(magic, file kind, format version, trailing bytes); `EnvelopeWrapLength` is
the one §3-only check.  `manifest_file`'s envelope is untouched; #640 is
about why that one cannot be refined the same way.
"""

from __future__ import annotations

from conformance_lib.cursor import ParseError


class EnvelopeBadMagic(ParseError):
    """The file does not start with the magic (`BlockError::BadMagic`,
    `BundleFileError::BadMagic`)."""

    token = "container_malformed"


class EnvelopeWrongFileKind(ParseError):
    """`file_kind` is not the one this envelope requires
    (`BlockError::WrongFileKind`, `BundleFileError::UnsupportedFileKind`)."""

    token = "container_malformed"


class EnvelopeNoRecipients(ParseError):
    """The recipient table is empty (`BlockError::EmptyRecipientList`)."""

    token = "container_malformed"


class EnvelopeEd25519SignatureLength(ParseError):
    """`sig_ed_len` is not 64 (`BlockError::SigEdWrongLength`)."""

    token = "container_malformed"


class EnvelopeMlDsaSignatureLength(ParseError):
    """`sig_pq_len` is not ML-DSA-65's (`BlockError::SigPqWrongLength`)."""

    token = "container_malformed"


class EnvelopeTrailingBytes(ParseError):
    """Bytes follow the last field (`BlockError::TrailingBytes`,
    `BundleFileError::TrailingBytes`)."""

    token = "container_malformed"


class UnsupportedEnvelopeVersion(ParseError):
    """`format_version` or `suite_id` is not the v1 value
    (`BlockError::Unsupported*`, `BundleFileError::UnsupportedFormatVersion`)."""

    token = "unsupported_version"


class EnvelopeWrapLength(ParseError):
    """A §3 `wrap_pw_ct_len` / `wrap_rec_ct_len` is not 32
    (`BundleFileError::WrapLengthMismatch`)."""

    token = "container_malformed"


class EnvelopeSortOrder(ParseError):
    """A vector-clock or recipient table is out of ascending order."""

    token = "array_sort_order"


class EnvelopeRepeatedValue(ParseError):
    """A vector-clock or recipient table repeats an id."""

    token = "repeated_array_value"


def check_ascending_distinct(ids: list[bytes], what: str, key: str) -> None:
    """Raise at the FIRST adjacent pair that is not strictly ascending.

    Classified the way `block.rs`'s `match w[0].cmp(&w[1])` classifies it:
    an equal pair is a repeat, a descending pair is disorder.  A merged
    `prev >= nxt` check could not tell the two apart, which is why this
    exists.  The disorder message is the one the merged check raised.
    """
    for index, (prev, nxt) in enumerate(zip(ids, ids[1:])):
        if prev == nxt:
            raise EnvelopeRepeatedValue(f"{what} repeat a {key} at positions {index} and {index + 1}")
        if prev > nxt:
            raise EnvelopeSortOrder(f"{what} not strictly ascending by {key}")
