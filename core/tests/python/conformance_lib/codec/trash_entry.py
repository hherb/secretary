"""§4.2 / §7.2 manifest `TrashEntry` codec, including the `purged_at_ms`
purge marker (#399).

`is_trash_entry_restorable` is the rule `restore_block` enforces: a purged
entry refuses restore, and the marker lives in the SIGNED manifest, so it
is unforgeable.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.canonical import encode_canonical_map
from conformance_lib.codec.record import _reject_floats_and_tags_py
from conformance_lib.constants import BLOCK_UUID_LEN, DEVICE_UUID_LEN

# ---------------------------------------------------------------------------
# Section P — manifest TrashEntry purge marker (vault-format.md §4.2 / §7.2,
# #399). Self-contained: the CBOR is constructed/decoded/re-encoded entirely
# in-script, mirroring how the record/contact-card codecs above prove clean-
# room sufficiency without a Rust-generated fixture.
# ---------------------------------------------------------------------------

# BLAKE3-256 content-commitment fingerprint carried by `TrashEntry.fingerprint`
# (vault-format.md §4.2, §7.1 step 3a) -- distinct from the 16-byte identity/
# card `FINGERPRINT_LEN` above (a truncated BLAKE3-keyed-hash, §14).
TRASH_ENTRY_FINGERPRINT_LEN = 32


def py_decode_trash_entry(data: bytes) -> dict:
    """Strict manifest §4.2 `TrashEntry` decoder matching
    manifest.rs::parse_trash_entry.

    Validates:
    - Top-level item is a CBOR map with text-string keys; no floats, no
      CBOR tags anywhere in the tree (§6.2 canonical-CBOR profile).
    - Required fields: block_uuid (16-byte bstr), tombstoned_at_ms (uint),
      tombstoned_by (16-byte bstr).
    - Optional: fingerprint (32-byte bstr), purged_at_ms (uint) -- §7.2:
      absent means "still restorable", present means "permanently purged".
    - Unrecognised keys are preserved verbatim under "unknown" (§6.3.2
      forward-compat pattern already used by contacts/records/blocks).
    - Input is already canonical (re-encode == input); this is also how
      the "decodes and re-encodes byte-identically" property is checked.

    Returns a dict of parsed fields. Raises on any violation.
    """
    import cbor2

    try:
        decoded = cbor2.loads(data)
    except cbor2.CBORDecodeError as e:
        raise ValueError(f"TrashEntry CBOR decode: {e}") from e

    _reject_floats_and_tags_py(decoded)

    if not isinstance(decoded, dict):
        raise ValueError("TrashEntry top-level CBOR is not a map")

    REQUIRED = {"block_uuid", "tombstoned_at_ms", "tombstoned_by"}
    for f in REQUIRED:
        if f not in decoded:
            raise KeyError(f"TrashEntry missing required field: {f!r}")

    block_uuid = decoded["block_uuid"]
    if not isinstance(block_uuid, bytes) or len(block_uuid) != BLOCK_UUID_LEN:
        raise ValueError("TrashEntry block_uuid must be 16-byte bstr")

    tombstoned_at_ms = decoded["tombstoned_at_ms"]
    if not isinstance(tombstoned_at_ms, int) or tombstoned_at_ms < 0:
        raise ValueError(f"TrashEntry tombstoned_at_ms must be uint, got {tombstoned_at_ms!r}")

    tombstoned_by = decoded["tombstoned_by"]
    if not isinstance(tombstoned_by, bytes) or len(tombstoned_by) != DEVICE_UUID_LEN:
        raise ValueError("TrashEntry tombstoned_by must be 16-byte bstr")

    out: dict[str, Any] = {
        "block_uuid": block_uuid,
        "tombstoned_at_ms": tombstoned_at_ms,
        "tombstoned_by": tombstoned_by,
    }

    if "fingerprint" in decoded:
        fp = decoded["fingerprint"]
        if not isinstance(fp, bytes) or len(fp) != TRASH_ENTRY_FINGERPRINT_LEN:
            raise ValueError("TrashEntry fingerprint must be 32-byte bstr")
        out["fingerprint"] = fp

    if "purged_at_ms" in decoded:
        purged_at_ms = decoded["purged_at_ms"]
        if not isinstance(purged_at_ms, int) or purged_at_ms < 0:
            raise ValueError(f"TrashEntry purged_at_ms must be uint, got {purged_at_ms!r}")
        out["purged_at_ms"] = purged_at_ms

    KNOWN_KEYS = {
        "block_uuid", "tombstoned_at_ms", "tombstoned_by", "fingerprint", "purged_at_ms",
    }
    unknown = {k: v for k, v in decoded.items() if k not in KNOWN_KEYS}
    if unknown:
        out["unknown"] = unknown

    # Canonical-input check: re-encode and compare (also proves the "marker
    # round-trip" and "byte-identical when absent" properties this section
    # exists to demonstrate).
    reencoded = py_encode_trash_entry(out)
    if reencoded != data:
        raise ValueError("TrashEntry is not in canonical CBOR form")

    return out


def py_encode_trash_entry(entry: dict) -> bytes:
    """Re-encode a parsed `TrashEntry` dict to canonical CBOR.

    Mirrors `vault/manifest/encode.rs::trash_entry_to_canonical`
    (named `manifest.rs::trash_entry_to_value` until #564 split the file
    and #569 path 2 moved the encoder onto borrowed `CanonicalMap`s):
    `fingerprint` and
    `purged_at_ms` are each omitted entirely when absent/`None` -- never
    encoded as an explicit CBOR null. This is the byte-identical
    forward-compat property §7.2 / §6.3.2 rely on: a `TrashEntry` that has
    never been purged carries no `purged_at_ms` key at all, so a legacy
    (pre-#399) client's encoding of the same entry round-trips unchanged.
    """
    entries: list[tuple[Any, Any]] = [
        ("block_uuid", entry["block_uuid"]),
        ("tombstoned_at_ms", entry["tombstoned_at_ms"]),
        ("tombstoned_by", entry["tombstoned_by"]),
    ]
    if entry.get("fingerprint") is not None:
        entries.append(("fingerprint", entry["fingerprint"]))
    if entry.get("purged_at_ms") is not None:
        entries.append(("purged_at_ms", entry["purged_at_ms"]))
    for k, v in entry.get("unknown", {}).items():
        entries.append((k, v))
    return encode_canonical_map(entries)


def is_trash_entry_restorable(entry: dict) -> bool:
    """§7.2 "Restore interaction": restore gains a fail-fast precondition --
    if the matching `TrashEntry.purged_at_ms` is `Some`, restore fails
    immediately (a dedicated purged-block error), *before* any `trash/`
    directory scan. Absent `purged_at_ms` means still restorable.

    This is the decision the verifier reproduces from the signed manifest
    marker alone, per the task brief's part (b).
    """
    return entry.get("purged_at_ms") is None
