"""§11.6 trash-list merge: union, latest-tombstone-wins, monotone purge marker.

`purged_at_ms` is Some-if-either / max / None < Some -- monotone, so a
purge can never be un-done by a merge with a stale peer.
"""

from __future__ import annotations

from conformance_lib.merge.records import py_merge_unknown_map

def py_expired_trash_entries(
    trash: list[dict], live_uuids: set[str], window_ms: int, now_ms: int
) -> set[str]:
    """Clean-room retention eligibility (docs/vault-format.md §7 step 5).

    An entry is eligible iff: not already purged, its uuid is not live,
    and now_ms - tombstoned_at_ms > window_ms (saturating: a future-dated
    tombstone yields age 0). Returns the set of eligible block_uuid hex.
    """
    out: set[str] = set()
    for e in trash:
        if e.get("purged_at_ms") is not None:
            continue
        uuid_hex = e["block_uuid_hex"]
        if uuid_hex in live_uuids:
            continue
        age = max(0, now_ms - int(e["tombstoned_at_ms"]))  # saturating
        if age > window_ms:
            out.add(uuid_hex)
    return out


def _trash_triple_key(e: dict) -> tuple:
    """Total order for the tombstone triple (docs §11.6): tombstoned_at_ms
    asc, then tombstoned_by bytes asc, then fingerprint with None < Some
    and Some bytewise. Encode fingerprint as (0, b"") for None and
    (1, bytes) for Some so None sorts first."""
    fp = e.get("fingerprint_hex")
    fp_key = (0, b"") if fp is None else (1, bytes.fromhex(fp))
    return (e["tombstoned_at_ms"], bytes.fromhex(e["tombstoned_by_hex"]), fp_key)


def py_merge_trash_entry(a: dict, b: dict) -> dict:
    """Merge two trash entries with the same block_uuid (docs §11.6)."""
    winner = a if _trash_triple_key(a) >= _trash_triple_key(b) else b
    # purged: Some-if-either, max millis, None loses to Some.
    pa, pb = a.get("purged_at_ms"), b.get("purged_at_ms")
    if pa is None and pb is None:
        purged = None
    elif pa is None:
        purged = pb
    elif pb is None:
        purged = pa
    else:
        purged = max(pa, pb)
    merged = {
        "block_uuid_hex": a["block_uuid_hex"],
        "tombstoned_at_ms": winner["tombstoned_at_ms"],
        "tombstoned_by_hex": winner["tombstoned_by_hex"],
        "fingerprint_hex": winner.get("fingerprint_hex"),
        "purged_at_ms": purged,
    }
    unk = py_merge_unknown_map(a.get("unknown_hex", {}), b.get("unknown_hex", {}))
    if unk:
        merged["unknown_hex"] = unk
    return merged


def py_merge_trash(lists: list[list[dict]]) -> list[dict]:
    """Union + reconcile trash lists (docs §11.6). Output sorted ascending
    by block_uuid, no duplicates."""
    acc: dict[bytes, dict] = {}
    for lst in lists:
        for entry in lst:
            key = bytes.fromhex(entry["block_uuid_hex"])
            acc[key] = py_merge_trash_entry(acc[key], entry) if key in acc else dict(entry)
    return [acc[k] for k in sorted(acc.keys())]
