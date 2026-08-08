"""Rule E3 shape 5's self-test control corpus (#486):
`WRAPPER_POSITIVE_CONTROLS` / `WRAPPER_NEGATIVE_CONTROLS`, run through
`payload_guard.selftest.scan_wrapper_control` — the wrapper-root rule set
(`bridge_mode=True` plus E2/E3, E3's `allow_field_access` ON, no E4).

Mirrors `payload_guard.controls.bridge`'s self-contained-fixture design.
The BRIDGE-scoping half of shape 5's story is NOT here: it is a BRIDGE
control (`BP43` in `payload_guard.controls.bridge`), because it asserts what
the bridge root does, not what a wrapper root does. Read the entry point's
module docstring first for the WHY.
"""

from __future__ import annotations

WRAPPER_POSITIVE_CONTROLS: list[tuple] = [
    (
        "WP1 shape 5 trusts the FINAL SEGMENT only: a field access whose "
        "last segment is NOT the gated field's own name is not a "
        "pass-through and must deny",
        ''' fn f(a: &A) -> E { E::V { uuid_hex: a.some_other_field } } ''',
        {"rule": "E3", "field": "uuid_hex"},
    ),
    (
        "WP2 a hand-rolled format! into a gated field denies in a wrapper "
        "root exactly as it does in the bridge — shape 5 widens the accepted "
        "set, it does not disable the rule",
        ''' fn f(n: usize) -> E { E::V { detail: format!("got {n}") } } ''',
        {"rule": "E3", "field": "detail"},
    ),
]

WRAPPER_NEGATIVE_CONTROLS: list[tuple] = [
    (
        "WN1 shape 5: the DTO pass-through `uuid_hex: a.uuid_hex` is the "
        "shape all four live sites take. It is arm 4's name-trust one level "
        "deeper — it trusts that a field named `uuid_hex` was gated where "
        "ITS type declared it, which rules E2/E3 in the bridge do establish "
        "for these four",
        ''' fn f(a: A) -> E { E::V { uuid_hex: a.uuid_hex } } ''',
    ),
]
