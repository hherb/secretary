"""§4.2's repeated-value rule, expressed once for both directions.

`docs/vault-format.md` §4.2 forbids a repeated value in four of the
manifest's five sorted arrays -- `device_uuid` within `vector_clock` or
within any `vector_clock_summary`, `block_uuid` within `blocks`, and
`block_uuid` within `trash`. `recipients` is the explicit exception.

The rule binds **writers as well as readers** ("writers MUST NOT emit
them and readers MUST reject them"), so it has two call sites in this
package rather than one: `manifest_decode.py`'s
`_check_sorted_and_distinct` and `manifest_encode.py`'s
`check_no_repeated_array_values`. Naming the rule once is the same move
`required_keys.py` makes for #597's -- there, four of seven hand-copies
had drifted, and here the writer half was simply missing, which is the
Rust-side defect #600 records.

**Sortedness and distinctness are independent**, which is why this rule
needs its own function at all: `[x, x]` *is* sorted, so neither the §4.2
sort disciplines nor the §4.3 step-4 re-encode can see a repeat -- a body
carrying one re-encodes to itself byte for byte.
"""

from __future__ import annotations

from typing import Any


def first_repeated_value(ids: list) -> Any | None:
    """The lowest value appearing twice in `ids`, or `None` if all differ.

    Sorts a copy and scans adjacent pairs. Adjacency is exhaustive
    *because* the copy is sorted -- equal values cannot be separated by an
    unequal one -- which is what makes one sweep sufficient rather than a
    pairwise comparison.

    Sorting rather than requiring sorted input is what lets the WRITER
    share this: `check_no_repeated_array_values` runs before any sort has
    been applied. The decoder's caller has already established sortedness,
    so for it the sort is a no-op and the reported value is unchanged.

    Returning the LOWEST repeat rather than the first in input order is
    deliberate: the value reaches a rejection message, and a message whose
    content depends on input order is the #597 class of defect. Sorted
    order is a total order over `bytes`, so the answer is the same on
    every run and in every process.
    """
    ordered = sorted(ids)
    for i in range(1, len(ordered)):
        if ordered[i] == ordered[i - 1]:
            return ordered[i]
    return None
