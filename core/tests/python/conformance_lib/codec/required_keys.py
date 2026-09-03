"""The one place a decoder decides WHICH absent required key to report (#597).

Every strict decoder in `codec/` ends its key loop by checking that nothing
mandatory is absent. When two or more are, the decoder has to pick one to name,
and the obvious spelling picks the wrong way:

    for key in REQUIRED:            # a set -- iterates in HASH order
        if key not in decoded:
            raise KeyError(...)

CPython salts string hashing once per process, so that loop reports a
different key from run to run for the same input. The verdict is unaffected
(the input is rejected either way, with the same exception type), but the
DETAIL is not reproducible -- #597 records one fuzz seed alternating between
`self_sig_ed` and `self_sig_pq` across six consecutive runs, which is enough
to make a byte-exact `--diff-replay` baseline impossible without pinning
`PYTHONHASHSEED`.

Sorting inside a helper, rather than writing `sorted(...)` at each of the
seven call sites, is the point: the rule then lives in one NAME instead of in
a caller list every future decoder has to remember to copy. Four of the seven
sites already sorted and three did not, which is what a hand-copied rule looks
like after a while.

Section DET pins both halves -- that the reported key is stable across hash
seeds, and that no `codec/` loop iterates a required-key set directly again.
"""

from __future__ import annotations

from collections.abc import Container, Iterable


def first_missing_key_in_sorted_order(
    present: Container[str], required: Iterable[str]
) -> str | None:
    """The lexicographically first key in `required` absent from `present`.

    Returns `None` when every required key is present, so a caller reads as
    "if something is missing, name it" and keeps its own exception type and
    message -- the decoders deliberately differ there (`KeyError` for the
    record/card/trash decoders, `ValueError` for the manifest ones), and
    unifying that would be a change in observable rejection behaviour rather
    than a determinism fix.

    `sorted` orders by code point, which for the ASCII wire key names in
    `docs/vault-format.md` is plain alphabetical order. It does NOT depend on
    the type of `required`: a `set`, `frozenset`, `list` or generator all give
    the same answer, which is exactly the property #597 needed.
    """
    for key in sorted(required):
        if key not in present:
            return key
    return None
