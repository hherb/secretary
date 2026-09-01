"""Section S -- sync-pass classification clean-room replay (D.1.13).

Pure vector-clock classification, no crypto. Mirrors the Rust always-run
guard in `core/tests/sync_pass_kat.rs` against the same fixture.
"""

from __future__ import annotations

from conformance_lib.fixtures import load_json_fixture, sync_pass_kat_dir
from conformance_lib.merge.clocks import py_clock_relation, py_merge_vector_clocks

# ---------------------------------------------------------------------------
# Section S: sync-pass classification clean-room replay (D.1.13)
# ---------------------------------------------------------------------------
#
# Pure vector-clock classification — no crypto. Mirrors the Rust always-run
# guard in core/tests/sync_pass_kat.rs against the SAME cases.json fixture.
# Proves the pause-on-conflict truth table + post-merge LUB agree across the
# Rust primitives and this stdlib-only clean-room re-implementation.
#
# Direction note (the load-bearing detail): sync_once calls
# clock_relation(local_seen, disk_clock) — local FIRST, disk SECOND — and the
# relation is named from the disk (incoming) perspective. So "incoming
# dominates" (disk > local) -> AppliedAutomatically, and "incoming dominated"
# (local > disk) -> RollbackRejected.


def _parse_clock(pairs: list) -> list[dict]:
    """[[hex, counter], ...] -> list[{"device_uuid_hex": hex, "counter": int}].
    The hex string is a single-byte fill of the 16-byte device_uuid. Output
    is in the canonical shape expected by py_clock_relation /
    py_merge_vector_clocks so those shared helpers can be called directly."""
    return [{"device_uuid_hex": pair[0], "counter": int(pair[1])} for pair in pairs]


def _derive_outcome(
    local: list[dict],
    disk: list[dict],
    diverging_blocks: int,
    veto_count: int,
) -> str:
    """Derive the sync-pass outcome label. Delegates to py_clock_relation
    (defined in the §11 conflict section) so the two sections share a single
    clock-comparison implementation.

    Direction note: local FIRST, disk SECOND — same as sync_once in
    core/src/sync/once.rs. For NothingToDo (Equal case) disk == local so the
    LUB check is vacuously true (disk); production writes nothing on that arm,
    but the fixture's expected_post_clock confirms schema consistency."""
    rel = py_clock_relation(local, disk)
    if rel == "Equal":
        return "NothingToDo"
    if rel == "IncomingDominates":
        return "AppliedAutomatically"
    if rel == "IncomingDominated":
        return "RollbackRejected"
    # Concurrent
    if diverging_blocks == 0:
        return "SilentMerge"
    if veto_count > 0:
        return "ConflictsPending"
    return "MergedClean"


def section_sync_pass_kat() -> tuple[bool, list[str]]:
    """Clean-room replay of the sync-pass classification KAT (D.1.13).

    For each case: derive the outcome label from clock_relation + flags via the
    truth table, and (for advancing arms) compute the post-merge LUB by folding
    disk + every copy clock + prior local-seen. Compare both to the fixture's
    expected fields. A FAIL here vs. the Rust guard passing is the cross-language
    bug this KAT exists to catch.
    """
    fixture = load_json_fixture(
        sync_pass_kat_dir() / "cases.json", "sync_pass_kat/cases.json"
    )
    lines: list[str] = []

    if fixture.get("schema") != "sync_pass_kat/v1":
        return False, [
            f"FAIL: unsupported sync_pass_kat schema {fixture.get('schema')!r}"
        ]

    cases = fixture.get("cases", [])
    if not cases:
        return False, ["FAIL: sync_pass_kat/cases.json has no cases"]

    advancing = {"NothingToDo", "AppliedAutomatically", "SilentMerge", "MergedClean"}
    all_ok = True

    for case in cases:
        name = case["name"]
        disk = _parse_clock(case["disk_clock"])
        local = _parse_clock(case["local_seen"])
        copies = [_parse_clock(c) for c in case["copy_clocks"]]
        diverging_blocks = int(case["diverging_blocks"])
        veto_count = int(case["veto_count"])
        expected = case["expected_outcome"]

        issues: list[str] = []

        derived = _derive_outcome(local, disk, diverging_blocks, veto_count)
        if derived != expected:
            issues.append(f"derived outcome {derived} != expected {expected}")

        post = case["expected_post_clock"]
        if expected in advancing:
            if post is None:
                issues.append(f"advancing arm {expected} must carry a post_clock")
            else:
                # Fold disk + copies + local via py_merge_vector_clocks (shared
                # §11 helper) — same order as post_merge_lub in sync_pass_kat.rs.
                lub = disk
                for copy in copies:
                    lub = py_merge_vector_clocks(lub, copy)
                lub = py_merge_vector_clocks(lub, local)
                expected_clock = _parse_clock(post)
                # Compare as frozensets of (hex, counter) tuples — order-independent.
                lub_set = frozenset(
                    (e["device_uuid_hex"], e["counter"]) for e in lub
                )
                exp_set = frozenset(
                    (e["device_uuid_hex"], e["counter"]) for e in expected_clock
                )
                if lub_set != exp_set:
                    issues.append(
                        f"computed LUB {sorted(lub_set)} != "
                        f"expected_post_clock {sorted(exp_set)}"
                    )
        else:
            if post is not None:
                issues.append(f"pausing arm {expected} must have null post_clock")

        if issues:
            all_ok = False
            lines.append(f"FAIL  sync_pass_kat::{name}")
            for i in issues:
                lines.append(f"      - {i}")
        else:
            lines.append(f"PASS  sync_pass_kat::{name}")

    return all_ok, lines
