"""The one place `conformance_lib` decides whether a decoded value is an
integer (#669).

WHY A MODULE FOR ONE PREDICATE.  Python's `bool` subclasses `int`, so
`isinstance(True, int)` is `True`, while `ciborium` decodes a CBOR bool to
`Value::Bool` and `toml` to `Value::Boolean` -- neither of which any Rust
`take_u*` or `as_integer` accepts.  Before this module the exclusion was
hand-copied: four independent spellings across five files, of which two were
right (`codec/record_rules.py` and `codec/manifest_decode.py`, both written in
#641) and the rest omitted it, which let ten integer positions accept a
boolean the Rust decoder rejects -- an ACCEPTANCE divergence, measured on
`contact_card`, `vault_toml` and the standalone `codec/trash_entry.py`.

That is the #597 shape restated: not one rule with a gap, but several copies
of one sentence of which some are wrong.  The remedy is the same one #597
used for required-key ordering -- name the rule once, so a caller list does
not have to remember it.

WHAT THIS IS NOT.  It is not a claim that every integer position is checked;
a position with no check at all is invisible to a predicate, which is exactly
how `trash[].fingerprint` and `trash[].purged_at_ms` went unvalidated on a
token-compared target.  Section VT's check 4 covers that class separately.
"""

from __future__ import annotations


def is_integer(value: object) -> bool:
    """True iff `value` is a CBOR/TOML integer.

    A `bool` is NOT an integer here, though Python says `isinstance(True, int)`
    is `True`.  Mirrors `manifest/decode/extract.rs`'s `take_integer_i128`,
    which matches `Value::Integer` alone, and `unlock/vault_toml.rs`'s
    `toml::Value::as_integer`, which returns `None` for a boolean.

    Every integer-position check under `codec/` routes through this function.
    Section VT's check 3 denies a bare `isinstance(..., int)` anywhere else in
    that tree, so a fifth hand-copy cannot be written.
    """
    return isinstance(value, int) and not isinstance(value, bool)
