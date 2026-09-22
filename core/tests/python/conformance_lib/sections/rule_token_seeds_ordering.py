"""Section RTS check 5 -- LOCAL parity-order assertions for `record`,
`block_file` and `contact_card`, split out of `rule_token_seeds.py` (fix
round 1, task 10) once this file's own growth pushed the parent past the
project's 500-line split threshold.

CHECK 5 IS PARITY, NOT SPEC. Two-fault bodies built here, never committed:
vault-format §6.1 and §6.3 fix no report order for `record`/`block_file`, and
crypto-design §6 fixes none for `contact_card` either (#618's lesson; #668).
The `record` rows pin the phase order `py_decode_record` shares with
`record::decode` by design -- walk, map, per-key checks in wire order,
missing keys, canonical form last -- the `block_file` row pins that a table
is judged at its FIRST adjacent pair that is not strictly ascending, as
`block.rs` does, and the `contact_card` rows pin the order
`py_decode_contact_card` shares with `card.rs::from_canonical_cbor`. So a
drift in Python's order reds here rather than only in a local full-corpus
replay. Every committed seed plants ONE fault, so the CI replay cannot see
an order drift at all; this check is what does.

Rust's side of the parity: `core/src/vault/record_order_tests.rs` for
`record`, one `#[test]` per row, each asserting the exact `RecordError` and
its single-fault controls; `core/src/identity/card_order_tests.rs` for
`contact_card`, the same shape.

Each row names the drift it catches. A row naming `None` is a regression pin
only: its body was measured to report the same token under the pre-#641
order, because the entry scan meets a truncated key before any key type is
read. The `record`/`block_file` rows need TWO single-fault controls to prove
a two-fault body actually discriminates; `contact_card`'s last four rows
(fix round 1) need only ONE, and that is structural rather than an
oversight -- see `_card_ordering_cases`'s own docstring.
"""

from __future__ import annotations

import os

from conformance_lib import fixtures
from conformance_lib.codec import record_rules
from conformance_lib.constants import VECTOR_CLOCK_ENTRY_LEN
from conformance_lib.cursor import Cursor, ParseError
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.wire.block_file import parse_header

_FLOAT16_ZERO = bytes([0xF9, 0x00, 0x00])
_ARRAY_1_HEAD = bytes([0x81])
_MAP_1_HEAD = bytes([0xA1])
_MAP_2_HEAD = bytes([0xA2])
_TAG_1_HEAD = bytes([0xC1])
# An unsigned integer 1, in a map-key position where only text is allowed.
_UINT_1 = bytes([0x01])
# RFC 8949 §3.3 simple value 23: well-formed nowhere in this format.
_UNDEFINED = bytes([0xF7])
# A text head declaring 3 bytes, followed by 1.
_TRUNCATED_TEXT = bytes([0x63, 0xFF])
_TRAILING_BYTE = bytes([0x00])
_UUID_LEN = record_rules.RECORD_UUID_LEN
# The committed accepting base the `block_file` case is spliced into.
_BLOCK_BASE = "golden.bin"
# §6.1: the vector-clock entry count is a big-endian u16.
_U16_LEN = 2
# Leading id bytes that compare strictly, whatever the rest of the id holds.
_LOW_LEAD = 0x00
_HIGH_LEAD = 0xFF
# A non-shortest-form encoding of the integer 5: RFC 8949 requires the
# immediate one-byte form (`0x05`) whenever the value fits it; this spells
# the same value with a redundant one-byte-following head instead.
_NON_SHORTEST_FIVE = bytes([0x18, 0x05])
# A bignum tag (2) over a definite 1-byte string: within the width `cbor2`
# (like `ciborium`) folds to a plain integer.
_BIGNUM_NARROW = bytes([0xC2, 0x41, 0x01])
# How many parity-order cases each builder declares; asserted in
# `ordering_issues`.
_ORDERING_CASES = {"record": 9, "block_file": 1, "contact_card": 8}

_OrderingCase = tuple[str, bytes, str, "str | None"]


def _block_file_ordering_cases() -> tuple[_OrderingCase, ...]:
    """One two-fault `block_file` body: a vector clock `[high, low, low]`.

    Its first adjacent pair is out of order and its second is a repeat, each
    of which alone names a different token (the committed
    `array_sort_order__vector_clock` and `repeated_array_value__vector_clock`
    seeds are exactly those single faults).  §6.1 fixes no order between the
    two (#668), so this is parity only: both implementations report the FIRST
    adjacent pair that is not strictly ascending, as `block.rs`'s `match cmp`
    over `windows(2)` does, and a reader that scans the whole table for a
    repeat before judging order names `repeated_array_value` instead
    (measured).
    """
    base = (fixtures.fuzz_seed_dir("block_file") / _BLOCK_BASE).read_bytes()
    header, after = parse_header(Cursor(buf=base, pos=0))
    entries_at = after.pos - len(header.vector_clock) * VECTOR_CLOCK_ENTRY_LEN
    count_at = entries_at - _U16_LEN
    entry = base[entries_at:entries_at + VECTOR_CLOCK_ENTRY_LEN]
    table = [bytes([lead]) + entry[1:] for lead in (_HIGH_LEAD, _LOW_LEAD, _LOW_LEAD)]
    body = base[:count_at] + len(table).to_bytes(_U16_LEN, "big") + b"".join(table) + base[after.pos:]
    return (
        ("a vector clock out of order at its first pair and repeated at its second",
         body, "array_sort_order", "every pair checked for a repeat before any for order"),
    )


def _record_ordering_cases() -> tuple[_OrderingCase, ...]:
    """`(label, body, token the shared order names, the drift it catches)`."""
    import cbor2

    base = {
        "record_uuid": os.urandom(_UUID_LEN),
        "record_type": "t",
        "fields": {},
        "created_at_ms": 0,
        "last_mod_ms": 0,
    }
    no_last_mod = {k: v for k, v in base.items() if k != "last_mod_ms"}
    device_uuid = os.urandom(_UUID_LEN)
    return (
        ("a wrong type beside a missing key",
         cbor2.dumps({**no_last_mod, "record_uuid": "text"}, canonical=True), "wrong_type",
         "missing required keys checked before each value"),
        ("a repeated key whose second copy is a float",
         _MAP_2_HEAD + cbor2.dumps("record_type") + cbor2.dumps("t")
         + cbor2.dumps("record_type") + _FLOAT16_ZERO, "rule4_tag_or_float",
         "no whole-body rule-4 walk before interpretation"),
        ("a truncated key behind a non-text key",
         _MAP_2_HEAD + cbor2.dumps(1) + cbor2.dumps(0) + _TRUNCATED_TEXT, "malformed_cbor",
         None),
        ("a schema fault followed by trailing bytes",
         cbor2.dumps(no_last_mod, canonical=True) + _TRAILING_BYTE, "missing_field",
         "trailing bytes judged before the schema"),
        ("a non-map top-level item holding a malformed item",
         _ARRAY_1_HEAD + _UNDEFINED, "malformed_cbor",
         "the top-level map head read before the walk"),
        ("a non-text key whose value is malformed",
         _MAP_1_HEAD + _UINT_1 + _UNDEFINED, "malformed_cbor",
         "key types read before the walk"),
        ("a tag wrapping an otherwise valid record map",
         _TAG_1_HEAD + cbor2.dumps(base, canonical=True), "rule4_tag_or_float",
         "the top-level map head read before the walk"),
        ("a field missing a key beside a wrong-typed field value",
         cbor2.dumps({**base, "fields": {"f": {"last_mod": "text", "device_uuid": device_uuid}}},
                     canonical=True), "wrong_type",
         "a field's missing keys checked before its values"),
        ("a fault inside a field before a later top-level wrong type",
         cbor2.dumps({**base, "record_uuid": "text",
                      "fields": {"f": {"last_mod": 0, "device_uuid": device_uuid}}}, canonical=True),
         "missing_field", "the fields map decoded after the top-level entries"),
    )


def _card_ordering_cases() -> tuple[_OrderingCase, ...]:
    """`(label, body, token the shared order names, the drift it catches)`.

    Seven two-fault card bodies. The first three (task 10) mirror
    `card.rs::from_canonical_cbor`'s own precedence -- the `card_version !=
    1` comparison deferred until after the whole entry loop, a repeated
    key's SECOND copy checked for its own type before the duplicate is
    reported, and trailing bytes judged only by the final canonical-form
    re-encode, after every entry fault. None is committed: crypto-design §6
    fixes no report order between them (#618's lesson, restated for the
    card).

    The last four (fix round 1) were committed single-fault seeds until
    this round found each ALSO carries a competing, order-dependent verdict:
    the card has no forward-compat `unknown` bag, so a simple-value / depth
    / rule-4 fault can only be planted inside a KNOWN field's value, where a
    per-field type check always also applies. `undefined`, an excessively
    deep array and a float each decode (via `cbor2`, without the walk) to a
    well-formed value that is simply not an integer -- exactly what
    `check_card_value` would then reject as `wrong_type`. A narrow bignum
    folds to a plain integer within the width `cbor2` treats as a native
    int, passing every type check and surviving only until the final
    re-encode -- exactly what a non-shortest-form integer already
    demonstrates as `non_canonical_unclassified`. There is therefore only
    ONE standalone control per row (the competing verdict): the walk's OWN
    verdict has no standalone control, because nothing in the §6 schema can
    isolate it from a competing type check the way `record`'s forward-compat
    bag lets record isolate an unknown-bag fault.

    WHERE THAT CONTROL LIVES, since it is NOT in this file (#698 review,
    S2). Each row below asserts only the two-fault body's token; nothing
    here demonstrates the competing verdict alone, so read the rows as one
    half of a two-sided property. The other half is:

    * the Rust twin, `core/src/identity/card_order_tests.rs`, where every
      `#[test]` asserts its controls AND the two-fault body; and
    * for four of the rows, a committed single-fault seed that IS the
      competing verdict -- `unsupported_version__card_version_two`,
      `wrong_type__created_at_text`,
      `non_canonical_unclassified__trailing_bytes` and
      `non_canonical_unclassified__non_shortest_created_at`.

    Naming them makes the linkage checkable; before this the docstring
    claimed a control the file does not contain.
    """
    import cbor2

    from conformance_lib.canonical import encode_canonical_map_raw

    def field(n: int) -> bytes:
        return os.urandom(n)

    base = {
        "card_version": 1,
        "contact_uuid": field(16),
        "display_name": "n",
        "x25519_pk": field(32),
        "ml_kem_768_pk": field(1184),
        "ed25519_pk": field(32),
        "ml_dsa_65_pk": field(1952),
        "created_at": 0,
        "self_sig_ed": field(64),
        "self_sig_pq": field(3309),
    }

    def canonical(d: dict) -> bytes:
        return cbor2.dumps(d, canonical=True)

    def with_created_at(value) -> bytes:
        return canonical({**base, "created_at": value})

    def raw_with_created_at(value_bytes: bytes) -> bytes:
        """`base`, with `created_at`'s value spliced in as raw bytes --
        needed whenever the value cannot be spelled as a `cbor2`-encodable
        Python object (a non-shortest-form integer; `cbor2` always emits
        shortest form)."""
        entries = [(k, cbor2.dumps(v, canonical=True)) for k, v in base.items() if k != "created_at"]
        entries.append(("created_at", value_bytes))
        return encode_canonical_map_raw(entries)

    def with_created_at_repeated(second_value: bytes) -> bytes:
        """`base`, canonical, with `created_at`'s entry repeated right after
        itself -- the only way to plant a repeat, since a Python `dict`
        cannot hold one. The second copy's VALUE bytes are `second_value`,
        so callers control whether it is well-typed or not.

        Built through `encode_canonical_map_raw` rather than a private
        `codec.scanner` byte-span scan (fix round 1, MINOR 4): that
        function's own sort is a stable Timsort over `(len(key_bytes),
        key_bytes)`, so the ONLY two entries sharing `created_at`'s key
        bytes stay adjacent, in the order given, without reading anything
        internal to another module.
        """
        entries = [(k, cbor2.dumps(v, canonical=True)) for k, v in base.items()]
        entries.append(("created_at", second_value))
        return encode_canonical_map_raw(entries)

    nested_257 = 0
    for _ in range(256):
        nested_257 = [nested_257]

    return (
        ("a wrong type beside a card_version the §6 value check has not yet run",
         canonical({**base, "display_name": 5, "card_version": 2}), "wrong_type",
         "card_version's value comparison runs once, after the whole entry loop"),
        ("a repeated key whose second copy is wrong-typed",
         with_created_at_repeated(cbor2.dumps("bad")), "wrong_type",
         "the second copy's own value is checked before the duplicate is reported"),
        ("a wrong-typed field beside trailing bytes",
         canonical({**base, "created_at": "bad"}) + _TRAILING_BYTE, "wrong_type",
         "trailing bytes are judged only by the final canonical-form re-encode"),
        ("an undefined created_at",
         with_created_at(cbor2.undefined), "malformed_cbor",
         "the well-formedness walk's ban on non-false/true/null simple values runs "
         "before any per-field type check"),
        ("an excessively deep created_at",
         with_created_at(nested_257), "malformed_cbor",
         "the well-formedness walk's depth limit runs before any per-field type check"),
        ("a float created_at",
         with_created_at(0.0), "rule4_tag_or_float",
         "the well-formedness walk's rule-4 check runs before any per-field type check"),
        ("a narrow bignum created_at",
         raw_with_created_at(_BIGNUM_NARROW), "rule4_tag_or_float",
         "the well-formedness walk's rule-4 check runs before the final canonical-form re-encode"),
        # #698 review, I7/I2: the order BOTH decoders implement here was
        # pinned by nothing. Row 1 above covers a wrong TYPE beside a
        # deferred `card_version`; this covers a MISSING KEY beside one,
        # which takes the other branch -- Rust answers `InvalidVersion`
        # because `parse_card_map` requires and compares `card_version`
        # before `first_missing_key_in_sorted_order` is ever consulted, and
        # Python defers the comparison to the same post-loop position ahead
        # of its own missing-key report. Reverse either and the pair reads
        # `unsupported_version` against `missing_field`, a live divergence
        # on a strictly compared target (measured both sides).
        ("a wrong card_version beside a missing required key",
         canonical({k: v for k, v in base.items() if k != "x25519_pk"} | {"card_version": 2}),
         "unsupported_version",
         "card_version's value comparison outranks the missing-key report"),
    )


def ordering_issues() -> tuple[list[str], str]:
    builders = (
        ("record", _record_ordering_cases),
        ("block_file", _block_file_ordering_cases),
        ("contact_card", _card_ordering_cases),
    )
    issues: list[str] = []
    tallies = []
    for target, build in builders:
        try:
            cases = build()
        except (OSError, ParseError) as exc:
            issues.append(f"{target} order: cannot build the cases: {type(exc).__name__}: {exc}")
            tallies.append(f"0/{_ORDERING_CASES[target]} {target}")
            continue
        if len(cases) != _ORDERING_CASES[target]:
            # An issue, not a raise: `main()` has no per-section catch, so a
            # raise here would skip every later section, REG included, with no
            # `FAIL:` line (PR #673 review).
            issues.append(
                f"_ORDERING_CASES[{target!r}] is {_ORDERING_CASES[target]}, the table holds {len(cases)}"
            )
        failed = 0
        for label, body, want, drift in cases:
            verdict = replay_bytes(target, body).verdict
            if verdict.get("status") != "reject" or verdict.get("rule") != want:
                failed += 1
                caught = f" -- the drift this row catches: {drift}" if drift else ""
                issues.append(
                    f"{target} order: {label} must report {want!r}, got {verdict.get('status')} "
                    f"{verdict.get('rule')!r} ({verdict.get('error_class')}: {verdict.get('detail')}){caught}"
                )
        tallies.append(f"{len(cases) - failed}/{len(cases)} {target}")
    return issues, " and ".join(tallies)
