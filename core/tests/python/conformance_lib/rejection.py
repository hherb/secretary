"""The allowlist of exception types that mean "this input is non-conformant".

Shared by `conformance_lib.diff_replay`, the golden-vault verifier and four
guard sections, which is why it is its own module rather than a private
name inside the replay driver. Splitting it out is what keeps
`conformance_lib.wire.golden_vault_verify` from importing the replay
driver just to name one tuple.
"""

from __future__ import annotations

from conformance_lib.cursor import ParseError

def _rejection_exceptions() -> tuple:
    """The exception types a decoder in this file raises DELIBERATELY to
    mean "this input is non-conformant" (#595).

    An ALLOWLIST, not a denylist of programming errors: a type absent from
    here is treated as a harness failure, so a new decoder raising a new
    type fails loudly and visibly rather than being silently scored as a
    verdict. `ParseError` is this module's own wire-format error;
    `cbor2.CBORError` is the common base of `CBORDecodeError` /
    `CBOREncodeError`. `UnicodeDecodeError` is a `ValueError` subclass and
    so is already covered.
    """
    import cbor2

    return (ValueError, KeyError, ParseError, cbor2.CBORError)


_REJECTION_EXCEPTIONS = _rejection_exceptions()
