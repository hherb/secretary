"""§11 per-record and per-block CRDT merge, from the spec docs alone.

The non-obvious part is `tombstoned_at_ms`, the record-level death clock
that closes the associativity gap naive tombstone-on-tie semantics leave
open. The Rust equivalent is `core/src/vault/conflict.rs`; the two are
required to agree bit-for-bit on `conflict_kat.json`.
"""

from __future__ import annotations

from conformance_lib.merge.clocks import py_clock_relation, py_merge_vector_clocks, py_tick_for_device

# §11.1 — per-record metadata and field merges.

def py_lww_picks_local_field(l: dict, r: dict) -> bool:
    """Return True iff the local field beats the remote per §11
    pseudocode: greater last_mod wins; on tie, smaller device_uuid
    wins; on full tie (different value), lex-larger value bytes wins."""
    if l["last_mod"] != r["last_mod"]:
        return l["last_mod"] > r["last_mod"]
    l_dev = bytes.fromhex(l["device_uuid_hex"])
    r_dev = bytes.fromhex(r["device_uuid_hex"])
    if l_dev != r_dev:
        return l_dev < r_dev
    return _value_lex_bytes(l) >= _value_lex_bytes(r)


def _value_lex_bytes(field: dict) -> bytes:
    """Same prefix-tag scheme as the Rust impl: 0x00 for Text, 0x01 for
    Bytes, then the raw content bytes. Used only as the malformed-input
    full-tie tiebreaker."""
    if field["value_type"] == "text":
        return b"\x00" + field["value_text"].encode("utf-8")
    if field["value_type"] == "bytes":
        return b"\x01" + bytes.fromhex(field["value_hex"])
    raise ValueError(f"unknown value_type: {field['value_type']}")


def py_merge_unknown_map(local_unk: dict, remote_unk: dict) -> dict:
    """Per-key forward-compat unknown merge per §11.1 (record-level)
    and §11.2 (block-level — same rule).

    A key present in only one side is kept verbatim. A key present in
    both with identical values is kept once. A key present in both
    with differing values takes the lex-larger canonical-CBOR-encoded
    value bytes.

    The KAT carries each value as a hex string of canonical-CBOR
    bytes (`unknown_hex: {key: "0a"}`). Rust's KAT loader decodes
    hex via `u8::from_str_radix(_, 16)` which is case-insensitive,
    so `"0A"` and `"0a"` both decode to byte `0x0a`. Raw lex compare
    on hex strings does NOT match byte compare across mixed case
    (e.g. `"a5"` vs `"B5"`: `'a' (0x61) > 'B' (0x42)` says L wins,
    but byte `0xb5 > 0xa5` says R wins). We decode each side to
    bytes for comparison and re-emit lowercase hex on output, so
    Python and Rust agree on every (case-permuted) input.
    """
    out: dict[str, str] = {}
    all_keys = set(local_unk.keys()) | set(remote_unk.keys())
    for key in sorted(all_keys):
        l_hex = local_unk.get(key)
        r_hex = remote_unk.get(key)
        if l_hex is not None and r_hex is not None:
            l_bytes = bytes.fromhex(l_hex)
            r_bytes = bytes.fromhex(r_hex)
            if l_bytes >= r_bytes:
                out[key] = l_bytes.hex()
            else:
                out[key] = r_bytes.hex()
        elif l_hex is not None:
            out[key] = bytes.fromhex(l_hex).hex()
        else:
            assert r_hex is not None
            out[key] = bytes.fromhex(r_hex).hex()
    return out


def py_clamp_death_clock(rec: dict) -> int:
    """Canonicalise a record's `tombstoned_at_ms` to the §11.5 invariant
    before the lattice join in `py_merge_record`. Mirrors Rust's
    `clamp_death_clock` in `core/src/vault/conflict.rs`.

    Returns `tombstoned_at_ms` clamped to `[0, last_mod_ms]`. For
    tombstoned inputs (`tombstone == true`), additionally enforces
    equality with `last_mod_ms` per §11.5: a currently-tombstoned
    record was tombstoned at its most recent edit. The two clamps
    collapse to the same `last_mod_ms` value on tombstoned inputs.

    Two malformations are defended against:

    * Tombstoned input with `tombstoned_at_ms != last_mod_ms`:
      violates `tombstone == true ⇒ tombstoned_at_ms == last_mod_ms`.
      Inflated DC propagates through merge; lowered DC suppresses
      the death clock's advance and lets pre-tombstone stale fields
      slip through the §11.3 staleness filter.
    * Live input with `tombstoned_at_ms > last_mod_ms`: violates
      `tombstoned_at_ms ≤ last_mod_ms`. With `tombstoned_at_ms =
      2**64 - 1` the merged DC would clamp every field with
      `last_mod < 2**64 - 1`, wiping the merged record's fields
      while keeping it live — a deniable data-loss attack from a
      hostile sync peer.

    No-op on well-formed inputs. Pure function of one record.
    """
    if rec["tombstone"]:
        return rec["last_mod_ms"]
    return min(rec.get("tombstoned_at_ms", 0), rec["last_mod_ms"])


def py_merge_record(local: dict, remote: dict) -> tuple[dict, list[dict]]:
    """Merge two records with the same record_uuid per §11. Returns the
    merged record dict and the list of field collisions (in sorted
    field_name order). Tombstone interactions follow §11.3.

    Per §11.3 the merge propagates a death clock
    (`tombstoned_at_ms = max(local, remote)`) and applies a staleness
    filter that drops fields with `last_mod ≤ death_clock`. The filter
    is the bit that makes the merge associative under arbitrary
    tombstone histories. `tombstoned_at_ms == 0` is the sentinel for
    "no tombstone observation"; in that case no filter applies."""
    # §11.3 tombstone tie-break.
    l_t, r_t = local["tombstone"], remote["tombstone"]
    if l_t and r_t:
        outcome = "BothTombstoned"
    elif not l_t and not r_t:
        outcome = "BothLive"
    elif l_t and not r_t:
        outcome = (
            "LocalTombstoneWins" if local["last_mod_ms"] >= remote["last_mod_ms"]
            else "LocalTombstoneLost"
        )
    else:
        outcome = (
            "RemoteTombstoneWins" if remote["last_mod_ms"] >= local["last_mod_ms"]
            else "RemoteTombstoneLost"
        )

    tombstone = outcome in ("BothTombstoned", "LocalTombstoneWins", "RemoteTombstoneWins")

    # Defensive clamp: enforce the §11.5 invariants on each input
    # before the lattice join. See `py_clamp_death_clock` (module
    # scope) for the rationale and the threat model.
    local_dc = py_clamp_death_clock(local)
    remote_dc = py_clamp_death_clock(remote)
    # §11.3 death clock: lattice join via max.
    death = max(local_dc, remote_dc)

    # §11.3 staleness predicate: a field is alive iff there's no death
    # observation (death_clock == 0) or its last_mod is strictly later.
    def alive(f: dict) -> bool:
        return death == 0 or f["last_mod"] > death

    # Field merge: tombstoned outcomes have empty fields per §6.3 / §11.3.
    fields: list[dict] = []
    collisions: list[dict] = []
    if not tombstone:
        # Apply LWW with the staleness filter uniformly across the
        # field union. The filter subsumes the previous
        # LocalTombstoneLost / RemoteTombstoneLost special cases:
        # a tombstoned side's "kept-for-undelete" fields all have
        # `last_mod ≤ tombstoned_at_ms = last_mod_ms ≤ death`, so
        # they are filtered out naturally.
        l_fields = {f["name"]: f for f in local["fields"]}
        r_fields = {f["name"]: f for f in remote["fields"]}
        for name in sorted(set(l_fields) | set(r_fields)):
            l = l_fields.get(name)
            r = r_fields.get(name)
            l_alive = l is not None and alive(l)
            r_alive = r is not None and alive(r)
            if not l_alive and not r_alive:
                continue
            if l_alive and not r_alive:
                merged_field = dict(l)
                merged_field["name"] = name
                fields.append(merged_field)
                continue
            if not l_alive and r_alive:
                merged_field = dict(r)
                merged_field["name"] = name
                fields.append(merged_field)
                continue
            # Both alive: per-field LWW + collision detection.
            pick_local = py_lww_picks_local_field(l, r)
            winner = l if pick_local else r
            loser = r if pick_local else l
            if l.get("value_type") != r.get("value_type") or l.get(
                "value_text", l.get("value_hex")
            ) != r.get("value_text", r.get("value_hex")):
                collisions.append(
                    {"field_name": name, "winner": winner, "loser": loser}
                )
            merged_field = dict(winner)
            merged_field["name"] = name
            fields.append(merged_field)

    # §11.3 identity-metadata override on tombstoning-wins outcomes:
    # record_type comes wholesale from the tombstoning side. Otherwise
    # §11.1 LWW: greater last_mod_ms wins; lex-larger UTF-8 on tie.
    if outcome == "LocalTombstoneWins":
        record_type = local["record_type"]
    elif outcome == "RemoteTombstoneWins":
        record_type = remote["record_type"]
    elif local["last_mod_ms"] > remote["last_mod_ms"]:
        record_type = local["record_type"]
    elif remote["last_mod_ms"] > local["last_mod_ms"]:
        record_type = remote["record_type"]
    elif local["record_type"].encode("utf-8") >= remote["record_type"].encode("utf-8"):
        record_type = local["record_type"]
    else:
        record_type = remote["record_type"]

    # tags: §11.3 mixed-tombstone override → tombstoning side wins; else
    # §11.1 (greater last_mod_ms; set union on tie).
    #
    # Output is always sorted+deduped per §11.5: even on the LWW-clone
    # branches, the merge canonicalises the chosen side's tags so that
    # self-merging the merged record is a fixed point (mirrors Rust
    # merge_tags).
    if outcome == "LocalTombstoneWins" or outcome == "RemoteTombstoneLost":
        source = local["tags"]
    elif outcome == "RemoteTombstoneWins" or outcome == "LocalTombstoneLost":
        source = remote["tags"]
    elif local["last_mod_ms"] > remote["last_mod_ms"]:
        source = local["tags"]
    elif remote["last_mod_ms"] > local["last_mod_ms"]:
        source = remote["tags"]
    else:
        # §11.1 set union of both sides on tie.
        source = list(set(local["tags"]) | set(remote["tags"]))
    # Canonicalise: sort + dedup.
    tags = sorted(set(source))

    # Record-level `unknown` merge per §11.1: per-key lattice join
    # (lex-larger canonical-CBOR bytes on collisions, single-side
    # preservation) on every outcome. Not subject to the §11.3
    # identity-metadata override — see the §11.3 carve-out and the
    # rationale at the override site in `core/src/vault/conflict.rs`.
    local_unknown = local.get("unknown_hex", {})
    remote_unknown = remote.get("unknown_hex", {})
    unknown = py_merge_unknown_map(local_unknown, remote_unknown)

    merged = {
        "record_uuid_hex": local["record_uuid_hex"],
        "record_type": record_type,
        "fields": fields,
        "tags": tags,
        "created_at_ms": min(local["created_at_ms"], remote["created_at_ms"]),
        "last_mod_ms": max(local["last_mod_ms"], remote["last_mod_ms"]),
        "tombstone": tombstone,
        "tombstoned_at_ms": death,
        "unknown_hex": unknown,
    }
    return merged, collisions


def py_merge_block(
    local_block: dict,
    local_clock: list[dict],
    remote_block: dict,
    remote_clock: list[dict],
    merging_device_hex: str,
) -> dict:
    """Per §11.2 — dispatch on clock_relation and emit a merged block
    plaintext + clock + relation + per-record collision list."""
    if local_block["block_uuid_hex"] != remote_block["block_uuid_hex"]:
        raise ValueError(
            f"block_uuid mismatch: local {local_block['block_uuid_hex']!r}, "
            f"remote {remote_block['block_uuid_hex']!r}"
        )

    relation = py_clock_relation(local_clock, remote_clock)

    if relation == "Equal":
        return {
            "relation": "Equal",
            "block": local_block,
            "vector_clock": list(local_clock),
            "collisions": [],
        }
    if relation == "IncomingDominates":
        return {
            "relation": "IncomingDominates",
            "block": remote_block,
            "vector_clock": list(remote_clock),
            "collisions": [],
        }
    if relation == "IncomingDominated":
        return {
            "relation": "IncomingDominated",
            "block": local_block,
            "vector_clock": list(local_clock),
            "collisions": [],
        }
    # Concurrent: union by record_uuid + per-record merge.
    l_recs = {r["record_uuid_hex"]: r for r in local_block["records"]}
    r_recs = {r["record_uuid_hex"]: r for r in remote_block["records"]}
    all_uuids = sorted(set(l_recs) | set(r_recs), key=bytes.fromhex)
    merged_records: list[dict] = []
    record_collisions: list[dict] = []
    for uuid in all_uuids:
        l = l_recs.get(uuid)
        r = r_recs.get(uuid)
        if l is not None and r is not None:
            merged, fcs = py_merge_record(l, r)
            if fcs:
                record_collisions.append(
                    {"record_uuid_hex": uuid, "field_collisions": fcs}
                )
            merged_records.append(merged)
        elif l is not None:
            merged_records.append(l)
        else:
            merged_records.append(r)

    merged_clock = py_merge_vector_clocks(local_clock, remote_clock)
    merged_clock = py_tick_for_device(merged_clock, merging_device_hex)
    merged_block = {
        "block_version": max(local_block["block_version"], remote_block["block_version"]),
        "block_uuid_hex": local_block["block_uuid_hex"],
        "block_name": local_block["block_name"]
        if local_block["block_name"].encode("utf-8")
        >= remote_block["block_name"].encode("utf-8")
        else remote_block["block_name"],
        "schema_version": max(local_block["schema_version"], remote_block["schema_version"]),
        "records": merged_records,
        # §11.2 forward-compat: same per-key lex-larger rule as
        # record-level (§11.1). No tombstone semantics at block level,
        # so no override.
        "unknown_hex": py_merge_unknown_map(
            local_block.get("unknown_hex", {}),
            remote_block.get("unknown_hex", {}),
        ),
    }
    return {
        "relation": "Concurrent",
        "block": merged_block,
        "vector_clock": merged_clock,
        "collisions": record_collisions,
    }


def _normalise_record(r: dict) -> dict:
    """Trim a record dict to the comparison keys used by the KAT
    `expected.block.records[*]` shape — strip per-field `name` to match
    the JSON's name-keyed-array layout."""
    fields = []
    for f in r["fields"]:
        nf = {
            "name": f["name"],
            "value_type": f["value_type"],
            "last_mod": f["last_mod"],
            "device_uuid_hex": f["device_uuid_hex"],
        }
        if "value_text" in f:
            nf["value_text"] = f["value_text"]
        if "value_hex" in f:
            nf["value_hex"] = f["value_hex"]
        fields.append(nf)
    return {
        "record_uuid_hex": r["record_uuid_hex"],
        "record_type": r["record_type"],
        "fields": fields,
        "tags": list(r["tags"]),
        "created_at_ms": r["created_at_ms"],
        "last_mod_ms": r["last_mod_ms"],
        "tombstone": r["tombstone"],
        "tombstoned_at_ms": r.get("tombstoned_at_ms", 0),
        # Record-level forward-compat unknown keys (canonical-CBOR
        # bytes encoded as hex). Absent in the JSON → empty dict.
        "unknown_hex": dict(r.get("unknown_hex", {})),
    }


def _normalise_block(b: dict) -> dict:
    return {
        "block_version": b["block_version"],
        "block_uuid_hex": b["block_uuid_hex"],
        "block_name": b["block_name"],
        "schema_version": b["schema_version"],
        "records": [_normalise_record(r) for r in b["records"]],
        # Block-level forward-compat unknown keys.
        "unknown_hex": dict(b.get("unknown_hex", {})),
    }
