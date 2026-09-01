"""Sections 4, 4b and 4c -- CRDT merge, trash merge and retention replays.

Each replays a committed KAT that the Rust side replays too; the two
implementations are required to agree bit-for-bit.
"""

from __future__ import annotations

import json
import sys

from conformance_lib.fixtures import conflict_kat_path, load_json_fixture, retention_kat_path, trash_merge_kat_path
from conformance_lib.merge.records import _normalise_block, py_merge_block
from conformance_lib.merge.trash import py_expired_trash_entries, py_merge_trash

# ---------------------------------------------------------------------------
# Section 4: conflict_kat.json — CRDT merge cross-language replay
# ---------------------------------------------------------------------------
#
# Implements crypto-design.md §11 (per-record / per-block CRDT merge) from
# the spec docs only and replays each KAT vector through the Python
# implementation, asserting bit-equal output against the JSON's `expected`.
#
# This is the §15 cross-language conformance witness for Phase A.6 / PR-C.
# A reader should be able to implement this section from §11 alone without
# consulting any Rust source. Tombstone interactions are exercised by the
# inline Rust unit tests + Rust integration tests; this section focuses on
# the four ClockRelation branches and the field-collision surface.


def section4_conflict_kat() -> tuple[bool, list[str]]:
    lines: list[str] = []
    path = conflict_kat_path()
    if not path.exists():
        print(f"MISSING: conflict_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "conflict_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        lines.append(f"FAIL  conflict_kat.json version={kat.get('version')}, expected 1")
        return False, lines
    vectors = kat.get("vectors") or []
    if not vectors:
        lines.append("FAIL  conflict_kat.json has no vectors")
        return False, lines

    all_ok = True
    for vector in vectors:
        name = vector["name"]
        local_block = vector["local"]["block"]
        local_clock = vector["local"]["vector_clock"]
        remote_block = vector["remote"]["block"]
        remote_clock = vector["remote"]["vector_clock"]
        merging_device_hex = vector["merging_device_hex"]
        expected = vector["expected"]

        try:
            got = py_merge_block(
                local_block, local_clock, remote_block, remote_clock, merging_device_hex
            )
        except Exception as exc:
            lines.append(f"FAIL  vector {name!r}: merge raised {exc!r}")
            all_ok = False
            continue

        if got["relation"] != expected["relation"]:
            lines.append(
                f"FAIL  vector {name!r}: relation got {got['relation']}, "
                f"expected {expected['relation']}"
            )
            all_ok = False
            continue

        got_block = _normalise_block(got["block"])
        expected_block = _normalise_block(expected["block"])
        if got_block != expected_block:
            lines.append(f"FAIL  vector {name!r}: merged block plaintext mismatch")
            lines.append(f"  got:      {json.dumps(got_block, sort_keys=True)}")
            lines.append(f"  expected: {json.dumps(expected_block, sort_keys=True)}")
            all_ok = False
            continue

        if got["vector_clock"] != expected["vector_clock"]:
            lines.append(f"FAIL  vector {name!r}: merged vector clock mismatch")
            lines.append(f"  got:      {got['vector_clock']}")
            lines.append(f"  expected: {expected['vector_clock']}")
            all_ok = False
            continue

        if len(got["collisions"]) != len(expected["collisions"]):
            lines.append(
                f"FAIL  vector {name!r}: collision count got "
                f"{len(got['collisions'])}, expected {len(expected['collisions'])}"
            )
            all_ok = False
            continue

        collisions_ok = True
        for g, e in zip(got["collisions"], expected["collisions"]):
            if g["record_uuid_hex"] != e["record_uuid_hex"]:
                lines.append(
                    f"FAIL  vector {name!r}: collision record_uuid mismatch "
                    f"{g['record_uuid_hex']!r} vs {e['record_uuid_hex']!r}"
                )
                collisions_ok = False
                break
            if len(g["field_collisions"]) != len(e["field_collisions"]):
                lines.append(
                    f"FAIL  vector {name!r}: field collision count mismatch"
                )
                collisions_ok = False
                break
            for gfc, efc in zip(g["field_collisions"], e["field_collisions"]):
                if gfc["field_name"] != efc["field_name"]:
                    lines.append(
                        f"FAIL  vector {name!r}: collision field_name "
                        f"{gfc['field_name']!r} vs {efc['field_name']!r}"
                    )
                    collisions_ok = False
                    break
                # Strip 'name' from winner/loser to match the KAT expected shape.
                got_w = {k: v for k, v in gfc["winner"].items() if k != "name"}
                got_l = {k: v for k, v in gfc["loser"].items() if k != "name"}
                if got_w != efc["winner"]:
                    lines.append(f"FAIL  vector {name!r}: collision winner mismatch")
                    lines.append(f"  got:      {got_w}")
                    lines.append(f"  expected: {efc['winner']}")
                    collisions_ok = False
                    break
                if got_l != efc["loser"]:
                    lines.append(f"FAIL  vector {name!r}: collision loser mismatch")
                    lines.append(f"  got:      {got_l}")
                    lines.append(f"  expected: {efc['loser']}")
                    collisions_ok = False
                    break
        if not collisions_ok:
            all_ok = False
            continue

        lines.append(f"PASS  conflict_kat.json {name!r}: {expected['relation']}")

    return all_ok, lines


def _normalise_trash_entry(e: dict) -> dict:
    """Canonical comparison shape: fingerprint/purged/unknown normalised so
    absent-key and explicit-null compare equal, and unknown-hex is lowercase."""
    out = {
        "block_uuid_hex": e["block_uuid_hex"].lower(),
        "tombstoned_at_ms": e["tombstoned_at_ms"],
        "tombstoned_by_hex": e["tombstoned_by_hex"].lower(),
        # `.get` already yields None for absent-key and explicit-null alike.
        "fingerprint_hex": e.get("fingerprint_hex"),
        "purged_at_ms": e.get("purged_at_ms"),
    }
    unk = e.get("unknown_hex") or {}
    out["unknown_hex"] = {k: bytes.fromhex(v).hex() for k, v in sorted(unk.items())}
    if out["fingerprint_hex"] is not None:
        out["fingerprint_hex"] = out["fingerprint_hex"].lower()
    return out


def section4b_trash_merge_kat() -> tuple[bool, list[str]]:
    lines: list[str] = []
    path = trash_merge_kat_path()
    if not path.exists():
        print(f"MISSING: trash_merge_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "trash_merge_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        lines.append(f"FAIL  trash_merge_kat.json version={kat.get('version')}, expected 1")
        return False, lines
    vectors = kat.get("vectors") or []
    if not vectors:
        lines.append("FAIL  trash_merge_kat.json has no vectors")
        return False, lines

    all_ok = True
    for vector in vectors:
        name = vector["name"]
        try:
            got = py_merge_trash(vector["inputs"])
        except Exception as exc:  # noqa: BLE001
            lines.append(f"FAIL  vector {name!r}: merge raised {exc!r}")
            all_ok = False
            continue
        got_n = [_normalise_trash_entry(e) for e in got]
        exp_n = [_normalise_trash_entry(e) for e in vector["expected"]]
        if got_n != exp_n:
            lines.append(f"FAIL  vector {name!r}: merged trash mismatch")
            lines.append(f"  got:      {json.dumps(got_n, sort_keys=True)}")
            lines.append(f"  expected: {json.dumps(exp_n, sort_keys=True)}")
            all_ok = False
            continue
        lines.append(f"PASS  trash_merge_kat.json {name!r}")
    return all_ok, lines


def section4c_retention_kat() -> tuple[bool, list[str]]:
    """§4c: replay retention_kat.json; assert clean-room eligibility
    matches each vector's expected UUID set (cross-language with Rust
    core/tests/retention.rs::expired_trash_entries_kat_replays_match_rust)."""
    lines: list[str] = []
    path = retention_kat_path()
    if not path.exists():
        print(f"MISSING: retention_kat.json at {path}", file=sys.stderr)
        sys.exit(2)
    try:
        kat = load_json_fixture(path, "retention_kat.json")
    except (json.JSONDecodeError, OSError):
        sys.exit(2)
    if kat.get("version") != 1:
        return False, [f"unexpected retention_kat version {kat.get('version')}"]
    ok = True
    for v in kat["vectors"]:
        live = set(v.get("blocks", []))
        got = py_expired_trash_entries(v["trash"], live, v["window_ms"], v["now_ms"])
        expected = set(v["expected_uuids_hex"])
        status = "PASS" if got == expected else "FAIL"
        if got != expected:
            ok = False
        lines.append(f"  §4c {v['name']}: {status}")
    return ok, lines
