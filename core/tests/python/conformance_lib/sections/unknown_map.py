"""Section 5 -- `py_merge_unknown_map` case-insensitivity guard.

A self-test rather than a fixture replay: unknown-key collision resolution
is byte-lexicographic, and this pins that a cross-case pair resolves the
same way in both directions.
"""

from __future__ import annotations

from conformance_lib.merge.records import py_merge_unknown_map

# ---------------------------------------------------------------------------
# Section 5 — py_merge_unknown_map case-insensitivity self-tests
# ---------------------------------------------------------------------------


def section5_unknown_map_case_insensitivity() -> tuple[bool, list[str]]:
    """Cross-language drift guard for `py_merge_unknown_map`.

    The KAT carries each unknown-map value as a hex string of canonical-CBOR
    bytes (`"unknown_hex": {key: "0a"}`). Rust's KAT loader decodes hex via
    `u8::from_str_radix(_, 16)`, which is case-insensitive — so `"0A"` and
    `"0a"` both decode to byte `0x0a`. Python's `py_merge_unknown_map` must
    agree; otherwise a future KAT vector authored with uppercase or mixed
    hex would silently disagree across the two clean-room implementations.

    The cross-case adversarial pairing is `0xa5` (lowercase `"a5"`) vs
    `0xb5` (uppercase `"B5"`):
      * byte compare: `0xb5 > 0xa5` → R wins.
      * raw string compare: `'a' (0x61) > 'B' (0x42)` → would pick L,
        contradicting the byte order. The merge must not be raw-string
        compare.

    The same-bytes-different-case pair `("ff", "FF")` exercises the
    equality path: byte-equal inputs must be treated as equal, not as
    differing → collision branch.
    """
    lines: list[str] = []
    all_ok = True

    # 1. Cross-case adversarial: 0xa5 (lowercase) vs 0xb5 (uppercase).
    #    Byte-correct winner is R (0xb5 > 0xa5). Raw-string compare picks L.
    got = py_merge_unknown_map({"k": "a5"}, {"k": "B5"})
    # Either uppercase or lowercase representation of 0xb5 is acceptable —
    # what matters is that the *byte value* equals 0xb5, not 0xa5.
    if got["k"].lower() != "b5":
        lines.append(
            f"FAIL  cross-case adversarial: got {got['k']!r}, expected byte 0xb5 "
            "(byte-larger). Raw-string compare misordered."
        )
        all_ok = False
    else:
        lines.append("PASS  cross-case adversarial picks byte-larger value")

    # 2. Same byte, different case: 0xff (`"ff"` vs `"FF"`). Must treat as
    #    equal (no spurious collision; output is one of the inputs).
    got = py_merge_unknown_map({"k": "ff"}, {"k": "FF"})
    if got["k"].lower() != "ff":
        lines.append(
            f"FAIL  same-byte different-case: got {got['k']!r}, expected byte 0xff "
            "(should canonicalise to a single value, not corrupt to a different byte)."
        )
        all_ok = False
    else:
        lines.append("PASS  same-byte different-case canonicalises consistently")

    # 3. Single-side mixed case is kept verbatim by byte value.
    got = py_merge_unknown_map({"k": "AB"}, {})
    if got["k"].lower() != "ab":
        lines.append(
            f"FAIL  single-side uppercase: got {got['k']!r}, expected byte 0xab"
        )
        all_ok = False
    else:
        lines.append("PASS  single-side uppercase preserved as byte 0xab")

    return all_ok, lines
