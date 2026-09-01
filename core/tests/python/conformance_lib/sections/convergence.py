"""Section C -- `convergence_kat.json` two-client convergence (C.4).

Merges BOTH orderings of each scenario and asserts order-independence as
well as a golden match: convergence is a property of the merge, not of who
merged first.
"""

from __future__ import annotations

import json
import sys

from conformance_lib.fixtures import convergence_kat_path, load_json_fixture
from conformance_lib.merge.records import _normalise_block, py_merge_block

# ---------------------------------------------------------------------------
# Section C — convergence_kat.json: two-client CRDT convergence (C.4)
# ---------------------------------------------------------------------------


def _converged_block(side_local: dict, side_remote: dict, merger_hex: str) -> dict:
    """Merge one ordering: `side_local` is the merger's own side, `side_remote`
    the canonical side; the merge ticks `merger_hex`. Returns the merged block
    plaintext (vector clock discarded — it differs by merger and is not part of
    the converged logical state)."""
    return py_merge_block(
        side_local["block"],
        side_local["vector_clock"],
        side_remote["block"],
        side_remote["vector_clock"],
        merger_hex,
    )["block"]


def section_convergence_kat() -> tuple[bool, list[str]]:
    """Clean-room two-client convergence (C.4). For each scenario, merge BOTH
    orderings via the spec-derived py_merge_block and assert (a) the converged
    logical blocks are order-independent and (b) they match the Rust-generated
    golden. KeepLocal veto is intentionally out of scope (sync-orchestration,
    not in the frozen merge spec) — see the design doc section 2."""
    lines: list[str] = []
    path = convergence_kat_path()
    if not path.exists():
        print(f"MISSING: convergence_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "convergence_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        lines.append(f"FAIL  convergence_kat.json version={kat.get('version')}, expected 1")
        return False, lines
    scenarios = kat.get("scenarios") or []
    if not scenarios:
        lines.append("FAIL  convergence_kat.json has no scenarios")
        return False, lines

    all_ok = True
    for sc in scenarios:
        name = sc["name"]
        a, b = sc["device_a"], sc["device_b"]
        a_hex, b_hex = sc["merging_device_a_hex"], sc["merging_device_b_hex"]
        try:
            # Ordering AB: A canonical, B merges (B local, A remote, merger=B).
            ab = _normalise_block(_converged_block(b, a, b_hex))
            # Ordering BA: B canonical, A merges (A local, B remote, merger=A).
            ba = _normalise_block(_converged_block(a, b, a_hex))
        except Exception as exc:
            # Surface any merge error as a FAIL line (mirrors section4_conflict_kat).
            lines.append(f"FAIL  scenario {name!r}: merge raised {exc!r}")
            all_ok = False
            continue

        if ab != ba:
            lines.append(f"FAIL  scenario {name!r}: orderings diverged (not order-independent)")
            lines.append(f"  AB: {json.dumps(ab, sort_keys=True)}")
            lines.append(f"  BA: {json.dumps(ba, sort_keys=True)}")
            all_ok = False
            continue

        golden = _normalise_block(sc["golden"]["block"])
        if ab != golden:
            lines.append(f"FAIL  scenario {name!r}: converged block != Rust golden")
            lines.append(f"  got:    {json.dumps(ab, sort_keys=True)}")
            lines.append(f"  golden: {json.dumps(golden, sort_keys=True)}")
            all_ok = False
            continue

        lines.append(f"PASS  convergence_kat.json {name!r}: order-independent + golden-match")

    return all_ok, lines
