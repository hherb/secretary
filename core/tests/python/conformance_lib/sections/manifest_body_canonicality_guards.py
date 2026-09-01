"""Sections MOC and MAS -- manifest-body CANONICALITY.

Outer-map canonicality, and the five §4.2 array sort disciplines. MAS
reverses each array and requires a rejection: without it `_check_sorted`
could be made a no-op with the whole suite still green.
"""

from __future__ import annotations

from conformance_lib.fixtures import manifest_body_seed


from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

def section_manifest_body_outer_canonicality_guard() -> tuple[bool, list[str]]:
    """Pin `py_decode_manifest`'s §4.3 step-4 re-encode-and-compare at the
    OUTER map (#595).

    `_check_canonical_item` is only ever called on VALUES, never on the body
    as a whole, so the outer map's own head and key order are checked by
    nothing but the final `py_encode_manifest(out) != data` comparison.
    That comparison was pinned by no test: replacing it with `if False:`
    left the entire conformance suite green while three inputs flipped from
    REJECT to ACCEPT -- all three of which Rust rejects.

    The three rows below are exactly those inputs. They sit at the outer
    map, which the 21-row canonicality corpus cannot reach: every corpus row
    splices its mutation INSIDE an `unknown` subtree.
    """
    import cbor2

    issues: list[str] = []
    seed = manifest_body_seed("top__control_canonical.bin")
    if not seed.is_file():
        return False, [f"fixture missing: {seed}"]
    base = seed.read_bytes()

    try:
        py_decode_manifest(base)
    except Exception as e:  # noqa: BLE001 - reported, not swallowed
        return False, [f"positive control: unmutated seed was REJECTED: {e!r}"]

    # The body is a definite-length map of N entries; N <= 23 so the head is
    # a single byte 0xA0|N. Assert that rather than assume it, so a future
    # manifest with more keys fails loudly here instead of silently
    # mutating the wrong byte.
    head = base[0]
    if not 0xA0 <= head <= 0xB7:
        return False, [
            f"fixture's outer head is {head:#04x}, not a small definite-length "
            "map -- the byte surgery below would target the wrong offset"
        ]
    n_entries = head - 0xA0

    decoded = cbor2.loads(base)
    reordered = {k: decoded[k] for k in reversed(list(decoded))}

    rows = [
        (
            "outer keys out of canonical order",
            # `canonical=False` preserves insertion order, so the outer map
            # is emitted largest-key-first. Nested maps were loaded from
            # canonical bytes and keep that order, so this isolates the
            # outer level.
            cbor2.dumps(reordered, canonical=False),
        ),
        (
            "indefinite-length outer map",
            bytes([0xBF]) + base[1:] + bytes([0xFF]),
        ),
        (
            "non-shortest-form outer map length",
            bytes([0xB8, n_entries]) + base[1:],
        ),
    ]

    for label, body in rows:
        if body == base:
            issues.append(f"{label}: mutation produced an identical body -- vacuous row")
            continue
        try:
            py_decode_manifest(body)
            issues.append(
                f"{label} was ACCEPTED -- the §4.3 step-4 re-encode check is "
                "not enforcing outer-map canonicality (Rust rejects this body)"
            )
        except _REJECTION_EXCEPTIONS:
            pass

    if issues:
        return False, issues
    return True, [
        f"PASS  manifest body outer-canonicality guard: {len(rows)} outer-map "
        "violations rejected, canonical control accepted"
    ]


def section_manifest_body_array_sort_guard() -> tuple[bool, list[str]]:
    """Pin the five §4.2 array sort disciplines (#595).

    `encode_manifest` sorts `vector_clock`, `blocks`, `trash`, per-block
    `recipients` and per-block `vector_clock_summary` on output, so a body
    whose arrays arrive out of order is REJECTED -- a wider rejection
    surface than plain canonical CBOR, and the *newly narrowing* half of
    the §4.2 reader contract (#572), i.e. exactly what a clean-room
    implementer reading `docs/` alone would get wrong.

    Nothing tested it. `_check_sorted` could be made a no-op and the whole
    conformance suite stayed green, because until #595 every corpus row had
    `vector_clock`/`recipients`/`vector_clock_summary` EMPTY and at most one
    `blocks`/`trash` entry -- and an array of length 0 or 1 is sorted no
    matter what any check does.

    Note the mechanism this does NOT rely on: `py_encode_manifest` re-emits
    array order verbatim, so a reversed array re-encodes byte-identically
    and the §4.3 step-4 comparison does not fire. `_check_sorted` is the
    only thing standing between this decoder and accepting what Rust
    rejects, which is why each row below asserts on the message as well as
    on the rejection.
    """
    import cbor2

    issues: list[str] = []
    seed = manifest_body_seed("top__control_canonical.bin")
    if not seed.is_file():
        return False, [f"fixture missing: {seed}"]
    base = seed.read_bytes()

    try:
        py_decode_manifest(base)
    except Exception as e:  # noqa: BLE001 - reported, not swallowed
        return False, [f"positive control: unmutated seed was REJECTED: {e!r}"]

    def reverse(outer, inner=None):
        def f(d):
            if inner is None:
                target = d[outer]
            else:
                target = d[outer][0][inner]
            if len(target) < 2:
                raise AssertionError(
                    f"{outer}/{inner} has {len(target)} element(s) -- a sort "
                    "discipline cannot be violated with fewer than 2, so this "
                    "row would be vacuous"
                )
            target.reverse()
        return f

    rows = [
        ("vector_clock", reverse("vector_clock"), "vector_clock"),
        ("blocks", reverse("blocks"), "blocks"),
        ("trash", reverse("trash"), "trash"),
        ("blocks[0].recipients", reverse("blocks", "recipients"), "recipients"),
        (
            "blocks[0].vector_clock_summary",
            reverse("blocks", "vector_clock_summary"),
            "vector_clock_summary",
        ),
    ]

    for label, mutate, want in rows:
        d = cbor2.loads(base)
        try:
            mutate(d)
        except AssertionError as e:
            issues.append(str(e))
            continue
        body = cbor2.dumps(d, canonical=True)
        if body == base:
            issues.append(f"{label}: reversal produced an identical body -- vacuous row")
            continue
        try:
            py_decode_manifest(body)
            issues.append(
                f"{label} reversed was ACCEPTED -- §4.2's sort discipline "
                "for it is not enforced (Rust rejects this body)"
            )
        except ValueError as e:
            if "sorted" not in str(e) or want not in str(e):
                issues.append(
                    f"{label} reversed was rejected, but not by the sort "
                    f"check: {e}"
                )

    if issues:
        return False, issues
    return True, [
        f"PASS  manifest body array sort guard: {len(rows)} arrays rejected "
        "when reversed, sorted control accepted"
    ]
