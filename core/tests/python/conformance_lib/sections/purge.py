"""Section P -- manifest `TrashEntry` purge marker (vault-format.md §7.2, #399).

Self-contained: the CBOR is constructed and decoded in-script, so the
section pins the wire shape without depending on a committed fixture.
"""

from __future__ import annotations

import os

from conformance_lib.codec.trash_entry import is_trash_entry_restorable, py_decode_trash_entry, py_encode_trash_entry
from conformance_lib.constants import BLOCK_UUID_LEN, DEVICE_UUID_LEN

def section_purge_scenario() -> tuple[bool, list[str]]:
    """Clean-room purge-marker scenario (#399, vault-format.md §4.2 / §7.2).

    Self-contained -- constructs `TrashEntry` CBOR maps in-script (no
    fixture needed), proving from `docs/vault-format.md` alone that:

    (a) a `TrashEntry` with `purged_at_ms` present decodes and re-encodes
        byte-identically (marker round-trip); a `TrashEntry` with the key
        ABSENT decodes to "not purged" and re-encodes byte-identically,
        with no explicit CBOR null standing in for the missing key; and
    (b) the documented §7.2 restore-refusal rule is expressible: an entry
        carrying `purged_at_ms` classifies as non-restorable, distinct
        from an entry that never carried the marker.
    """
    lines: list[str] = []
    all_ok = True

    # Random (not hardcoded) UUID-shaped values -- these aren't secrets, but
    # keeping the convention avoids literal byte arrays that read like
    # planted crypto material.
    block_uuid = os.urandom(BLOCK_UUID_LEN)
    tombstoned_by = os.urandom(DEVICE_UUID_LEN)
    tombstoned_at_ms = 1_800_000_000_000  # arbitrary plausible unix-millis
    purged_at_ms = tombstoned_at_ms + 3_600_000  # purged an hour after trashing

    # --- (a) purged_at_ms PRESENT: marker round-trip ---
    purged_entry_in = {
        "block_uuid": block_uuid,
        "tombstoned_at_ms": tombstoned_at_ms,
        "tombstoned_by": tombstoned_by,
        "purged_at_ms": purged_at_ms,
    }
    purged_bytes = py_encode_trash_entry(purged_entry_in)
    try:
        purged_decoded = py_decode_trash_entry(purged_bytes)
    except Exception as e:
        return False, [f"FAIL: purged TrashEntry failed to decode its own encoding: {e}"]

    if purged_decoded.get("purged_at_ms") != purged_at_ms:
        lines.append(
            "FAIL  purge marker round-trip: got purged_at_ms="
            f"{purged_decoded.get('purged_at_ms')!r}, expected {purged_at_ms}"
        )
        all_ok = False
    else:
        lines.append("PASS  purge marker round-trip: purged_at_ms decodes correctly")

    reencoded = py_encode_trash_entry(purged_decoded)
    if reencoded != purged_bytes:
        lines.append("FAIL  purged TrashEntry re-encode is not byte-identical")
        all_ok = False
    else:
        lines.append("PASS  purged TrashEntry re-encode is byte-identical")

    # --- classification: purged entry must be refused for restore (§7.2) ---
    if is_trash_entry_restorable(purged_decoded):
        lines.append("FAIL  purged TrashEntry classified as restorable (must refuse restore)")
        all_ok = False
    else:
        lines.append("PASS  purged TrashEntry classified as non-restorable (restore refuses)")

    # --- (a) purged_at_ms ABSENT: "not purged" round-trip, no explicit null ---
    live_entry_in = {
        "block_uuid": block_uuid,
        "tombstoned_at_ms": tombstoned_at_ms,
        "tombstoned_by": tombstoned_by,
    }
    live_bytes = py_encode_trash_entry(live_entry_in)
    try:
        live_decoded = py_decode_trash_entry(live_bytes)
    except Exception as e:
        return False, lines + [
            f"FAIL: unpurged TrashEntry failed to decode its own encoding: {e}"
        ]

    if "purged_at_ms" in live_decoded:
        lines.append("FAIL  unpurged TrashEntry decoded an unexpected purged_at_ms key")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry decodes with purged_at_ms absent")

    reencoded_live = py_encode_trash_entry(live_decoded)
    if reencoded_live != live_bytes:
        lines.append("FAIL  unpurged TrashEntry re-encode is not byte-identical")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry re-encode is byte-identical (no explicit null)")

    # Belt-and-braces: the wire bytes themselves must not contain the
    # "purged_at_ms" key text anywhere -- the omission is structural (the
    # key is absent), not merely "the decoder happens to report None".
    if b"purged_at_ms" in live_bytes:
        lines.append("FAIL  unpurged TrashEntry wire bytes contain the purged_at_ms key text")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry wire bytes omit the purged_at_ms key entirely")

    # --- classification: unpurged entry must remain restorable ---
    if not is_trash_entry_restorable(live_decoded):
        lines.append("FAIL  unpurged TrashEntry classified as non-restorable")
        all_ok = False
    else:
        lines.append("PASS  unpurged TrashEntry classified as restorable")

    return all_ok, lines
