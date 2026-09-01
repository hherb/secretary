"""§10 / §11 vector-clock comparison and merge.

`py_clock_relation` returns the four-way relation the merge layer branches
on; a missing device reads as counter 0.
"""

from __future__ import annotations

# §11 — clock_relation {Equal, IncomingDominates, IncomingDominated, Concurrent}.

def py_clock_relation(local: list[dict], incoming: list[dict]) -> str:
    """Component-wise comparison of two vector clocks. Missing device =
    counter 0. Returns "Equal", "IncomingDominates", "IncomingDominated",
    or "Concurrent" per §10 / §11."""
    counters: dict[bytes, list[int]] = {}
    for e in local:
        counters.setdefault(bytes.fromhex(e["device_uuid_hex"]), [0, 0])[0] = e["counter"]
    for e in incoming:
        counters.setdefault(bytes.fromhex(e["device_uuid_hex"]), [0, 0])[1] = e["counter"]
    local_greater = False
    incoming_greater = False
    for l, i in counters.values():
        if l > i:
            local_greater = True
        elif i > l:
            incoming_greater = True
        if local_greater and incoming_greater:
            return "Concurrent"
    if not local_greater and not incoming_greater:
        return "Equal"
    if incoming_greater:
        return "IncomingDominates"
    return "IncomingDominated"


def py_merge_vector_clocks(a: list[dict], b: list[dict]) -> list[dict]:
    """Component-wise max. Output sorted ascending by device_uuid bytes."""
    counters: dict[bytes, int] = {}
    for e in list(a) + list(b):
        d = bytes.fromhex(e["device_uuid_hex"])
        counters[d] = max(counters.get(d, 0), e["counter"])
    return [
        {"device_uuid_hex": d.hex(), "counter": c}
        for d, c in sorted(counters.items())
    ]


def py_tick_for_device(clock: list[dict], device_hex: str) -> list[dict]:
    """`+1` for `device_hex`; insert a fresh entry at counter 1 when
    absent. Output sorted ascending by device_uuid."""
    out = [dict(e) for e in clock]
    found = False
    for entry in out:
        if entry["device_uuid_hex"] == device_hex:
            entry["counter"] += 1
            found = True
            break
    if not found:
        out.append({"device_uuid_hex": device_hex, "counter": 1})
    out.sort(key=lambda e: bytes.fromhex(e["device_uuid_hex"]))
    return out
