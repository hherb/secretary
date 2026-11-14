"""§4.2 type-, range- and version-checks on a decoded manifest body.

Split out of `codec/manifest_decode.py` (#725) as a verbatim move; the
decoder calls `_validate_manifest_shape` at exactly the point it always did,
so no check is reordered.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.codec.integer_rules import is_integer
from conformance_lib.codec.manifest_rules import (
    IntegerOutOfRange,
    UnsupportedVersion,
    WrongFieldType,
)
from conformance_lib.codec.manifest_schema import (
    BLOCK_FINGERPRINT_LEN,
    MANIFEST_VERSION_V1,
    SALT_LEN,
    UUID_LEN,
)
from conformance_lib.constants import FORMAT_VERSION, SUITE_ID


def _check_uint(value: Any, field: str, bits: int) -> None:
    """Assert `value` is a CBOR unsigned integer that fits in `bits`.

    Mirrors `manifest/decode/extract.rs`'s `take_u8`/`take_u16`/`take_u32`/
    `take_u64`, each of which rejects a non-integer as `WrongType` and an
    out-of-range integer as `IntegerOutOfRange`. `bool` is excluded
    explicitly because Python's `bool` subclasses `int` -- `isinstance(True,
    int)` is `True` -- while ciborium decodes a CBOR bool to `Value::Bool`,
    which `take_u*` rejects. Without the guard a `true` would pass here and
    be rejected by Rust. The exclusion itself lives in
    `codec/integer_rules.py`, which is the only place under `codec/` allowed
    to write it (#669).
    """
    if not is_integer(value):
        raise WrongFieldType(f"{field} must be a uint, got {type(value).__name__}")
    if not 0 <= value < (1 << bits):
        raise IntegerOutOfRange(f"{field} is out of range for u{bits}: {value}")


def _check_fixed_bytes(value: Any, field: str, n: int) -> None:
    """Assert `value` is a byte string of exactly `n` bytes, mirroring
    `extract.rs`'s `take_fixed_bytes::<N>` (`WrongType` for a non-bstr,
    `InvalidByteLength` for the wrong size).
    """
    if not isinstance(value, bytes):
        raise WrongFieldType(f"{field} must be a bstr, got {type(value).__name__}")
    if len(value) != n:
        raise WrongFieldType(f"{field} must be {n} bytes, got {len(value)}")


def _validate_manifest_shape(out: dict) -> None:
    """Type-, range- and version-check every KNOWN manifest field (#595).

    Until this existed `py_decode_manifest` decoded the known scalars with a
    bare `cbor2.loads` and never looked at them, so it ACCEPTED bodies the
    Rust decoder rejects -- `manifest_version = 999`, a text `manifest_version`,
    a 5-byte `vault_uuid`, a 3-byte salt. That is a fail-OPEN divergence in
    the direction that matters: this file exists to prove `docs/` alone is
    enough to build a conformant reader, so a reader here that is LAXER than
    `decode_manifest` proves the opposite of what it claims.

    Nothing else in the file can catch this class. The §4.3 step-4 re-encode
    compares BYTES, and every mutation above re-encodes to itself; the splice family of the
    canonicality corpus mutates only `unknown` subtrees. The three version
    sentinels mirror `decode/mod.rs`'s `UnsupportedManifestVersion` /
    `UnsupportedFormatVersion` / `UnsupportedSuiteId`.
    """
    _check_uint(out["manifest_version"], "manifest_version", 8)
    if out["manifest_version"] != MANIFEST_VERSION_V1:
        raise UnsupportedVersion(f"unsupported manifest_version: {out['manifest_version']}")
    _check_uint(out["format_version"], "format_version", 16)
    if out["format_version"] != FORMAT_VERSION:
        raise UnsupportedVersion(f"unsupported format_version: {out['format_version']}")
    _check_uint(out["suite_id"], "suite_id", 16)
    if out["suite_id"] != SUITE_ID:
        raise UnsupportedVersion(f"unsupported suite_id: {out['suite_id']}")

    _check_fixed_bytes(out["vault_uuid"], "vault_uuid", UUID_LEN)
    _check_fixed_bytes(out["owner_user_uuid"], "owner_user_uuid", UUID_LEN)

    kdf = out["kdf_params"]
    for name in ("memory_kib", "iterations", "parallelism"):
        _check_uint(kdf[name], f"kdf_params.{name}", 32)
    _check_fixed_bytes(kdf["salt"], "kdf_params.salt", SALT_LEN)

    for i, e in enumerate(out["vector_clock"]):
        _check_fixed_bytes(e["device_uuid"], f"vector_clock[{i}].device_uuid", UUID_LEN)
        _check_uint(e["counter"], f"vector_clock[{i}].counter", 64)

    for i, blk in enumerate(out["blocks"]):
        _check_fixed_bytes(blk["block_uuid"], f"blocks[{i}].block_uuid", UUID_LEN)
        if not isinstance(blk["block_name"], str):
            raise WrongFieldType(f"blocks[{i}].block_name must be tstr")
        _check_fixed_bytes(
            blk["fingerprint"], f"blocks[{i}].fingerprint", BLOCK_FINGERPRINT_LEN
        )
        _check_uint(blk["suite_id"], f"blocks[{i}].suite_id", 16)
        _check_uint(blk["created_at_ms"], f"blocks[{i}].created_at_ms", 64)
        _check_uint(blk["last_mod_ms"], f"blocks[{i}].last_mod_ms", 64)
        if not isinstance(blk["recipients"], list):
            raise WrongFieldType(f"blocks[{i}].recipients must be an array")
        for j, r in enumerate(blk["recipients"]):
            _check_fixed_bytes(r, f"blocks[{i}].recipients[{j}]", UUID_LEN)
        for j, e in enumerate(blk["vector_clock_summary"]):
            _check_fixed_bytes(
                e["device_uuid"],
                f"blocks[{i}].vector_clock_summary[{j}].device_uuid",
                UUID_LEN,
            )
            _check_uint(
                e["counter"], f"blocks[{i}].vector_clock_summary[{j}].counter", 64
            )

    for i, t in enumerate(out["trash"]):
        _check_fixed_bytes(t["block_uuid"], f"trash[{i}].block_uuid", UUID_LEN)
        _check_uint(t["tombstoned_at_ms"], f"trash[{i}].tombstoned_at_ms", 64)
        _check_fixed_bytes(t["tombstoned_by"], f"trash[{i}].tombstoned_by", UUID_LEN)
        # `TrashEntry`'s two OPTIONAL keys (§4.2). An absent key decodes to
        # ABSENT here -- `_decode_manifest_entry_map` writes `out[key]` only for
        # keys present on the wire -- so `in` means PRESENT and a present CBOR
        # `null` IS checked. (Do not "simplify" to `t.get(k) is not None`: that
        # reads as the Rust `Option` and would silently skip a present null.)
        # They are therefore checked only when present -- but
        # when present they are checked, which until #669 they were not:
        # both accepted ANY CBOR value (bool, tstr, a short bstr, a negative
        # integer -- all four measured), while `decode/entries.rs` routes them
        # through `take_fixed_bytes::<32>` and `take_u64`. An acceptance
        # divergence, on `manifest_body`, a token-compared target replayed in
        # CI, reachable from no committed or corpus input -- which is why the
        # replay reported full agreement throughout.
        #
        # Neither check needs a new class or a new token: `_check_fixed_bytes`
        # raises `WrongFieldType` for a non-bstr AND for a wrong length, which
        # is exactly how Rust folds `WrongType` and `InvalidByteLength` onto
        # `wrong_type`; `_check_uint` raises `IntegerOutOfRange` for a negative
        # value, matching Rust's own. Measured against `manifest/token.rs`.
        #
        # These two were invisible to the census that found the bool class:
        # a grep keyed on `isinstance(..., int)` can only find positions that
        # HAVE a check. "Has no check to find" is its own search.
        if "fingerprint" in t:
            _check_fixed_bytes(
                t["fingerprint"], f"trash[{i}].fingerprint", BLOCK_FINGERPRINT_LEN
            )
        if "purged_at_ms" in t:
            _check_uint(t["purged_at_ms"], f"trash[{i}].purged_at_ms", 64)
