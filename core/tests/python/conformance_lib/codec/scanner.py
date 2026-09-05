"""Span-recording CBOR scanner (§4.2 forward-compat subtree support).

`cbor2.loads` decodes a map into a `dict`, which COLLAPSES duplicate keys
and cannot reproduce them. §4.2 requires an `unknown` subtree to be
retained and re-emitted VERBATIM, duplicates included, so the forward-compat
paths scan for BYTE SPANS instead of decoding to Python objects.

`_check_canonical_item` is the encoding-level canonicality check: indefinite
lengths and non-shortest-form heads are rejected at every nesting level.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Span-recording CBOR scanner (§4.2 forward-compat subtree support)
# ---------------------------------------------------------------------------
# `cbor2.loads` decodes a CBOR map into a `dict`, which COLLAPSES duplicate
# keys and cannot reproduce them.  `docs/vault-format.md` §4.2 makes it a
# reader MUST to reproduce an unknown subtree's entry order *and* its
# repeated entries, so a `dict`-based reader is structurally non-conformant:
# it rejects (via the §4.3 step-4 byte comparison) manifests the Rust
# decoder accepts.  See #592, and `core/src/vault/manifest/decode/tests.rs`'s
# `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`.
#
# These four functions are the conformant alternative: they record BYTE
# SPANS into the input rather than decoding, so a subtree can be re-emitted
# verbatim.  A `Span` is a `(start, end)` offset pair -- never a copy.

CBOR_BREAK = 0xFF          # RFC 8949 §3.2.1: the "break" stop code.
CBOR_AI_INDEFINITE = 31    # RFC 8949 §3: additional info 31 == indefinite.


class NonCanonicalItem(ValueError):
    """A crypto-design §6.2 NUMBERED-rule violation found by
    `_check_canonical_item`.

    Carries the rule number as a STRUCTURED attribute so a caller
    discriminates on `.rule` rather than on the message text (#604).  A
    substring match on `"rule 2:"` is blind to everything AROUND the
    fragment: it keeps passing when the message is reworded into something
    that no longer means rule 2, and keeps passing when a DIFFERENT check
    grows a message containing the same fragment.  That is the fragility
    #608's review diagnosed on the encoder side.

    **Which document numbers these rules.**  The numbers follow
    `docs/vault-format.md` §4.2's per-rule table, NOT crypto-design §6.2's
    prose, and the two differ on exactly the point this scanner raises
    most.  §6.2 rule 4 reads "No tags, no floats, **no indefinite-length
    items**", so by §6.2's own text an indefinite item violates rules 2
    AND 4; §4.2's table row 4 is spelled "no tags, no floats" and leaves
    indefinite lengths to row 2.  This class follows the TABLE, because
    the table is what states the per-rule enforcement split a reader
    implements.  Without this paragraph a clean-room implementer reading
    §6.2 literally would classify an indefinite item as rule 4 and Section
    MCC would report a divergence against a CONFORMANT reader (#614
    review).

    Defined in this module, beside its raise sites, so the number in the
    attribute and the number in the rendered message are composed from one
    source at construction and `rule` appears once per raise.  `.rule` is
    read-only for the same reason: a data descriptor wins over the
    instance `__dict__` every `BaseException` carries, so `e.rule = 9`
    raises rather than drifting from the message this class built from it.

    Subclasses `ValueError` deliberately: `conformance_lib.rejection`'s
    allowlist already admits `ValueError` as "this input is
    non-conformant", so every existing caller keeps scoring these as a
    verdict rather than as a harness failure.  That base class is a
    cross-cutting contract -- `diff_replay.py`'s reject-vs-error split
    keys on it too -- and Section CS asserts it, because losing it turns
    every scanner rejection into a harness failure.

    Only the five NUMBERED-rule raises use this type.  Inside
    `_check_canonical_item` the remaining three raises stay plain
    `ValueError`: the two well-formedness properties named in that
    function's own docstring (invalid UTF-8; a major-7 value outside
    {false, true, null}) plus a buffer-bounds check.  None is among §6.2's
    five rules, so none has a number to carry.  Other `raise ValueError`
    sites in this module belong to `_scan_item`, which is structure-only
    by design and enforces no §6.2 rule.
    """

    def __init__(self, rule: int, detail: str) -> None:
        super().__init__(f"rule {rule}: {detail}")
        self._rule = rule
        self._detail = detail

    @property
    def rule(self) -> int:
        """The §4.2-table rule number, read-only (see the class docstring)."""
        return self._rule

    def __reduce__(self):
        # `BaseException.__reduce__` returns `(cls, self.args)`, and
        # `self.args` here is the single COMPOSED message -- so the default
        # breaks `copy` and `pickle` for any exception whose `__init__`
        # takes more than that message.  No consumer crosses a process
        # boundary with one of these today (Section DET's subprocesses
        # marshal JSON text), but this package does spawn subprocesses.
        return (type(self), (self._rule, self._detail))


def _decode_head(buf: bytes, pos: int) -> tuple[int, int, int | None, int]:
    """Decode the CBOR head at `pos` (RFC 8949 §3).

    Returns `(major, ai, arg, head_len)`.  `arg` is None for the
    indefinite-length form; `head_len` counts the initial byte plus any
    argument bytes.
    """
    if pos >= len(buf):
        raise ValueError(f"truncated CBOR head at offset {pos}")
    ib = buf[pos]
    major, ai = ib >> 5, ib & 0x1F
    if ai < 24:
        return major, ai, ai, 1
    if ai == 24:
        n = 1
    elif ai == 25:
        n = 2
    elif ai == 26:
        n = 4
    elif ai == 27:
        n = 8
    elif ai == CBOR_AI_INDEFINITE:
        # RFC 8949 §3.2: the indefinite-length form (ai=31) is legal only for
        # majors 2/3/4/5 (byte string, text string, array, map); major 7's
        # ai=31 is a distinct thing -- the "break" stop code -- which
        # _scan_item / _scan_map_entries detect by reaching it, not by
        # decoding it as a head, so it must stay permitted here.
        if major not in (2, 3, 4, 5, 7):
            raise ValueError(
                f"RFC 8949 §3.2: indefinite-length form is not valid for "
                f"major type {major} at offset {pos}"
            )
        return major, ai, None, 1
    else:
        raise ValueError(f"reserved additional-info {ai} at offset {pos}")
    if pos + 1 + n > len(buf):
        raise ValueError(f"truncated {n}-byte argument at offset {pos}")
    return major, ai, int.from_bytes(buf[pos + 1 : pos + 1 + n], "big"), 1 + n


def _scan_item(buf: bytes, pos: int) -> int:
    """Return the offset one past the single CBOR item starting at `pos`.

    Structure only -- indefinite-length forms scan successfully here and are
    rejected by `_check_canonical_item`, because the two are different rules
    (§4.2 table rows 2 and 5 have opposite verdicts).
    """
    major, ai, arg, head = _decode_head(buf, pos)
    p = pos + head

    if major in (0, 1):                       # uint / negative int
        return p
    if major == 7:                            # simple value / float
        if ai == CBOR_AI_INDEFINITE:
            raise ValueError(f"unexpected break at offset {pos}")
        return p
    if major in (2, 3):                       # byte string / text string
        if arg is None:                       # indefinite: definite chunks to break
            while True:
                if p >= len(buf):
                    raise ValueError("unterminated indefinite-length string")
                if buf[p] == CBOR_BREAK:
                    return p + 1
                cmaj, _, carg, chead = _decode_head(buf, p)
                if cmaj != major or carg is None:
                    raise ValueError(f"bad chunk in indefinite-length string at {p}")
                p += chead + carg
        if p + arg > len(buf):
            raise ValueError(f"string length {arg} overruns buffer at offset {pos}")
        return p + arg
    if major in (4, 5):                       # array / map
        per = 1 if major == 4 else 2
        if arg is None:
            while True:
                if p >= len(buf):
                    raise ValueError("unterminated indefinite-length array/map")
                if buf[p] == CBOR_BREAK:
                    return p + 1
                for _ in range(per):
                    p = _scan_item(buf, p)
        for _ in range(arg * per):
            p = _scan_item(buf, p)
        return p
    if major == 6:                            # tag
        if arg is None:
            # Unreachable: `_decode_head` already rejects ai=31 (indefinite)
            # for every major outside (2, 3, 4, 5, 7), so a major-6 (tag)
            # head with ai=31 never reaches this point -- it raises inside
            # `_decode_head` first. Kept as defence in depth so this
            # primitive does not depend on a caller's validation.
            raise ValueError(f"indefinite-length tag at offset {pos}")
        return _scan_item(buf, p)
    raise ValueError(f"unreachable CBOR major type {major}")


def _scan_map_entries(
    buf: bytes, pos: int
) -> tuple[list[tuple[tuple[int, int], tuple[int, int]]], int]:
    """Entry spans for the CBOR map at `pos`, plus the offset one past it.

    Each element is `((key_start, key_end), (value_start, value_end))`.
    Entry ORDER and REPEATED entries are preserved -- the two properties a
    `dict` destroys and §4.2 part (1) requires a reader to reproduce.
    """
    major, _, arg, head = _decode_head(buf, pos)
    if major != 5:
        raise ValueError(f"expected a CBOR map at offset {pos}, got major type {major}")
    p = pos + head
    out: list[tuple[tuple[int, int], tuple[int, int]]] = []
    if arg is None:
        while True:
            if p >= len(buf):
                raise ValueError("unterminated indefinite-length map")
            if buf[p] == CBOR_BREAK:
                return out, p + 1
            ks = p
            ke = _scan_item(buf, p)
            ve = _scan_item(buf, ke)
            out.append(((ks, ke), (ke, ve)))
            p = ve
    for _ in range(arg):
        ks = p
        ke = _scan_item(buf, p)
        ve = _scan_item(buf, ke)
        out.append(((ks, ke), (ke, ve)))
        p = ve
    return out, p


def _scan_array_items(buf: bytes, pos: int) -> tuple[list[tuple[int, int]], int]:
    """Item spans for the CBOR array at `pos`, plus the offset one past it.

    Mirrors `_scan_map_entries` for major type 4 (array): records each
    element's `(start, end)` span rather than decoding it, so a manifest
    `blocks`/`trash` array can be walked entry by entry with each entry's
    own forward-compat subtree inspected and re-spliced, one nesting level
    below the top-level map (#585 fix round 1, Finding 1).
    """
    major, _, arg, head = _decode_head(buf, pos)
    if major != 4:
        raise ValueError(f"expected a CBOR array at offset {pos}, got major type {major}")
    p = pos + head
    out: list[tuple[int, int]] = []
    if arg is None:
        while True:
            if p >= len(buf):
                raise ValueError("unterminated indefinite-length array")
            if buf[p] == CBOR_BREAK:
                return out, p + 1
            s = p
            p = _scan_item(buf, p)
            out.append((s, p))
    for _ in range(arg):
        s = p
        p = _scan_item(buf, p)
        out.append((s, p))
    return out, p


def _shortest_ai(arg: int) -> int:
    """The additional-info value RFC 8949 §4.2.1 requires for `arg`."""
    if arg < 24:
        return arg
    if arg < 0x100:
        return 24
    if arg < 0x10000:
        return 25
    if arg < 0x100000000:
        return 26
    return 27


def _check_canonical_item(buf: bytes, pos: int) -> int:
    """Enforce crypto-design §6.2 rules 2, 3 and 4 over the item at `pos`,
    plus two ordinary CBOR well-formedness properties that are NOT among
    those five numbered rules but that `cbor2.loads` / `ciborium::Value`
    each enforce IMPLICITLY at parse time by construction of their own
    output types, and which this byte-retaining scanner must therefore
    check EXPLICITLY, since it never materialises either type (#592
    findings A/B): a major-3 text string's content must be valid UTF-8
    (a `str`/`String` cannot hold anything else), and a major-7 item must
    be one of false/true/null (`ciborium::Value`'s major-7 variants are
    exactly `Bool`/`Null`/`Float`, with no generic "other simple value"
    case -- `record.rs`/`block.rs`/manifest decode all reject the other
    six major-7 shapes wholesale, not just inside an `unknown` subtree).

    Rule 2 (definite lengths), rule 3 (shortest-form heads), rule 4 (no
    floats, no tags).  Returns the offset one past the item; raises
    `NonCanonicalItem` -- a `ValueError` subclass carrying the rule NUMBER
    as `.rule` -- on any numbered-rule violation, and a plain `ValueError`
    on the two well-formedness properties named above plus the
    buffer-bounds check, none of which carries a §6.2 number.

    Rules 1 and 5 -- map-key order and duplicate keys -- are deliberately
    NOT checked.  `docs/vault-format.md` §4.2's table marks both unenforced
    inside a forward-compat `unknown` subtree, and the Rust decoder accepts
    both (`decode/tests.rs`'s
    `unknown_subtree_tolerates_key_order_and_duplicates_but_not_encoding`).
    Checking them here would reintroduce exactly the #592 divergence this
    scanner exists to remove.
    """
    major, ai, arg, head = _decode_head(buf, pos)
    if ai == CBOR_AI_INDEFINITE:
        raise NonCanonicalItem(2, f"indefinite-length item at offset {pos}")
    if major == 6:
        raise NonCanonicalItem(4, f"CBOR tag at offset {pos}")
    if major == 7:
        if ai in (25, 26, 27):        # float16 / float32 / float64
            raise NonCanonicalItem(4, f"float at offset {pos}")
        if ai > 24:
            # Unreachable: ai in (28, 29, 30) is rejected by `_decode_head`
            # itself (reserved additional-info), and ai == 31 is caught by
            # the rule-2 check above -- so by the time control reaches
            # here, ai is always <= 24. Kept as defence in depth so this
            # primitive does not depend on a caller's validation.
            raise NonCanonicalItem(3, f"non-shortest simple value at offset {pos}")
        if ai not in (20, 21, 22):     # RFC 8949 §3.3: false(20)/true(21)/null(22) only
            raise ValueError(
                f"RFC 8949 §3.3: major-7 value outside {{false, true, null}} "
                f"at offset {pos} (ai={ai})"
            )
        return pos + head
    if ai != _shortest_ai(arg):
        raise NonCanonicalItem(3, f"non-shortest-form head at offset {pos} (ai={ai})")
    p = pos + head
    if major in (0, 1):
        return p
    if major in (2, 3):
        if p + arg > len(buf):
            raise ValueError(f"string length {arg} overruns buffer at offset {pos}")
        if major == 3:                 # RFC 8949 §3.1: text string content MUST be valid UTF-8
            try:
                buf[p : p + arg].decode("utf-8")
            except UnicodeDecodeError as e:
                raise ValueError(
                    f"RFC 8949 §3.1: invalid UTF-8 in text string at offset {pos}: {e}"
                ) from e
        return p + arg
    per = 1 if major == 4 else 2
    for _ in range(arg * per):
        p = _check_canonical_item(buf, p)
    return p
