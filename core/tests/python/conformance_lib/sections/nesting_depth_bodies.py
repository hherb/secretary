"""Bodies and seed names for Section NDL (crypto-design §6.2 rule 6, #667).

Pure builders, split out of `nesting_depth.py` before either was written, so
each file holds one job.  Section RTS imports `NESTING_SEED_PREFIX` from here
to exclude the nesting seeds from its own census, as `rule_token_seeds.rs`
does on the Rust side.

DEPTH ARITHMETIC.  A document's own root map is level 1, so a value holding
`d - 1` one-element arrays around a scalar takes the document to exactly `d`
levels.  A scalar is not a level.
"""

from __future__ import annotations

from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.cbor_faults import V1_MAX_NESTING_DEPTH
from conformance_lib.codec.scanner import _scan_map_entries

ARRAY_1 = 0x81
ARRAY_2 = 0x82
TEXT_1 = 0x61
TAG_1 = 0xC1
UINT_0 = 0x00
INVALID_UTF8 = 0xFF
# RFC 8949 §3.2.1's stop code; outside an indefinite container it is malformed.
BREAK = 0xFF

# A key no v1 document defines, so it lands in a forward-compat unknown bag
# where the schema accepts one.
FUTURE_KEY = "zz_future"
# Far past the limit and past Python's default recursion limit (~1,000), so a
# reader that recursed there would fail with `RecursionError` instead of a verdict.
FAR_PAST_THE_LIMIT = 2048
# The file-name prefix `core/tests/nesting_depth_seeds.rs` owns in
# `core/fuzz/seeds/{record,manifest_body}/`.  Mirrors that file's `SEED_PREFIX`.
NESTING_SEED_PREFIX = "nesting__"
SEED_EXTENSION = ".bin"


def nested_value(levels: int, innermost: bytes = bytes([UINT_0])) -> bytes:
    """`levels` one-element arrays around `innermost`."""
    return bytes([ARRAY_1]) * levels + innermost


def with_top_level_entry(base: bytes, key: str, value: bytes) -> bytes:
    """`base`, a canonical map, with one more entry `key: value` in canonical
    order.  Every existing entry keeps its own bytes, and `value` is spliced
    raw, so it may be deeper than any parser here would build."""
    import cbor2

    entries, _ = _scan_map_entries(base, 0)
    pairs = [(cbor2.loads(base[ks:ke]), base[vs:ve]) for (ks, ke), (vs, ve) in entries]
    return encode_canonical_map_raw(pairs + [(key, value)])


def document_nested_to(base: bytes, depth: int) -> bytes:
    """`base` with `FUTURE_KEY` holding a value that takes it to `depth` levels."""
    return with_top_level_entry(base, FUTURE_KEY, nested_value(depth - 1))


def expected_nesting_seeds() -> dict[str, frozenset[str]]:
    """The committed `nesting__` seed file names per target, spelled from the
    constants, as `nesting_depth_seeds_helpers::all_cases` builds them."""
    limit, past = V1_MAX_NESTING_DEPTH, V1_MAX_NESTING_DEPTH + 1

    def names(*shapes: str) -> frozenset[str]:
        return frozenset(f"{NESTING_SEED_PREFIX}{shape}{SEED_EXTENSION}" for shape in shapes)

    return {
        "record": names(
            f"{limit}_unknown", f"{past}_unknown", f"{past}_known_tags", f"{FAR_PAST_THE_LIMIT}_unknown"
        ),
        "manifest_body": names(
            f"{limit}_unknown",
            f"{past}_unknown",
            f"{FAR_PAST_THE_LIMIT}_unknown",
            # #666: the short-bignum depth edge, at both widths ciborium
            # takes a different path for (`nesting_depth_seeds_helpers`'s
            # `DeepestLevel`).
            f"{past}_unknown_bignum_narrow",
            f"{past}_unknown_bignum_wide",
        ),
    }
