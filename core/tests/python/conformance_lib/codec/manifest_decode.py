"""§4.2/§4.3 manifest BODY decoder, plus its shape validation.

Distinct from `conformance_lib.codec.manifest_file`, which handles the §4.1
outer signed envelope. This decoder re-encodes the parsed body and requires
a byte-identical match against its input (§4.3 step 4) -- which is why it
imports the encoder rather than the other way round.

`_validate_manifest_shape` is separate from the structural decode on
purpose: it is the layer that was fail-OPEN on every known scalar field
until #595, accepting nine bodies the Rust decoder rejects.
"""

from __future__ import annotations

from typing import Any

from conformance_lib.codec.manifest_encode import py_encode_manifest
from conformance_lib.codec.array_uniqueness import first_repeated_value
from conformance_lib.codec.manifest_schema import BLOCK_ENTRY_KNOWN_KEYS, BLOCK_ENTRY_REQUIRED_KEYS, BLOCK_FINGERPRINT_LEN, KDF_PARAMS_KNOWN_KEYS, KDF_PARAMS_REQUIRED_KEYS, MANIFEST_KNOWN_KEYS, MANIFEST_REQUIRED_KEYS, MANIFEST_VERSION_V1, SALT_LEN, TRASH_ENTRY_KNOWN_KEYS, TRASH_ENTRY_REQUIRED_KEYS, UUID_LEN, VECTOR_CLOCK_ENTRY_KNOWN_KEYS, VECTOR_CLOCK_ENTRY_REQUIRED_KEYS, _decode_manifest_array, _decode_strict_array, _decode_strict_entry_map
from conformance_lib.codec.required_keys import first_missing_key_in_sorted_order
from conformance_lib.codec.scanner import (
    DuplicateMapKey,
    _check_canonical_item,
    _decode_head,
    _scan_map_entries,
    reject_floats_and_tags,
)
from conformance_lib.constants import FORMAT_VERSION, SUITE_ID

class ArraySortOrderViolation(ValueError):
    """One of `docs/vault-format.md` §4.2's five sorted arrays arrived out of
    its fixed order.

    **Deliberately NOT a `NonCanonicalItem`.**  That type carries a
    crypto-design §6.2 rule NUMBER, and array sort order is not one of §6.2's
    five rules -- §6.2 says nothing about array elements at all.  It is §4.2's
    own rule, so there is no number to carry and inventing one would make this
    reader disagree with a conformant implementation over a rule neither
    document assigns.  Section MCC therefore discriminates on the TYPE here,
    which is the second KIND of expectation entry #613 needed.

    **The two implementations reach this by different routes, and §4.2 makes
    that normative.**  Rust reaches it as `NonCanonicalCause::ArraySortOrder`,
    a classification of a §4.3 step-4 re-encode divergence that has ALREADY
    decided to reject (`encode_manifest` sorts all five arrays on output, so
    an unsorted input cannot re-encode to itself).  This byte-retaining reader
    re-emits its input unconditionally, so the re-encode can never see array
    disorder; it must check -- and does check -- the discipline directly,
    before that comparison runs.

    No custom `__init__`, unlike `NonCanonicalItem`: this type's IDENTITY is
    the whole discriminator, so there is no structured payload to carry, and
    `BaseException.__reduce__`'s `(cls, self.args)` therefore round-trips
    through `copy`/`pickle` correctly on its own.  Adding a payload later
    means adding a `__reduce__` with it (#614 review).

    Subclasses `ValueError` for the same cross-cutting reason
    `NonCanonicalItem` does: `conformance_lib.rejection`'s allowlist already
    admits `ValueError` as "this input is non-conformant", so every existing
    caller -- including `diff_replay.py`'s reject-vs-error split -- keeps
    scoring these as a verdict rather than as a harness failure.
    """


class NonCanonicalBody(ValueError):
    """The §4.3 step-4 re-encode did not reproduce the input byte for byte,
    and no numbered-rule violation accounts for it.

    The counterpart of Rust's `NonCanonicalCause::Unclassified`, and honest
    for the same reason: the body carries no encoding-level violation to find
    -- every head is canonical, every length definite -- so the divergence is
    real but unattributable.  Map-key disorder is the shape that reaches here
    in practice: it re-encodes to a different byte string while every
    individual head stays perfectly canonical.

    **The arm whose correctness argument is subtlest, which is why it wanted a
    second implementation to agree with it.**  #590's first Rust classifier
    read the CBOR head at the first differing byte, which for key disorder
    lands INSIDE a key's UTF-8 payload -- so an ordinary character (`_` =
    0x5F, `8` = 0x38, `x` = 0x78) was reported as an indefinite-length or
    non-shortest-form head, and because `unknown` keys are wire data a peer
    could CHOOSE which wrong cause a v1 client printed.

    Reaching this class is not a claim that rules 2, 3 and 4 were checked and
    passed -- `_check_canonical_item` runs on VALUES, never on the body as a
    whole, so the outer map's own head reaches only this comparison.  It is
    the residue: rejected, with nothing further to say.

    No custom `__init__`, for the reason `ArraySortOrderViolation` states.
    """


def py_decode_manifest(data: bytes) -> dict:
    """Strict §4.2/§4.3 manifest BODY decoder matching
    `manifest/decode/mod.rs::decode_manifest`.

    Validates:
    - Top level is a CBOR map with text-string keys.
    - No duplicate key at the top level, in any nested KNOWN map, or
      within a `blocks[i]`/`trash[i]` entry map (#568, #573) -- checked on
      the SPAN list, so a repeat is visible.
    - No float and no CBOR tag anywhere (§6.2 rule 4).
    - Known values are canonical per §6.2 rules 2 and 3.
    - Unknown subtrees -- at the top level AND inside each `blocks[i]` /
      `trash[i]` entry, per `BlockEntry`/`TrashEntry`'s OWN forward-compat
      bag -- are checked for rules 2, 3 and 4 only, and their raw bytes
      are RETAINED so they can be re-emitted verbatim (rules 1 and 5 are
      unenforced there -- §4.2's table applies at every nesting level, not
      only the top one; #585 fix round 1, Finding 1). `vector_clock` and
      every `vector_clock_summary` are NOT given this treatment: a
      `VectorClockEntry` has no unknown bag at all and rejects an unknown
      key outright (`manifest/decode/entries.rs::parse_vector_clock_entry`),
      so plain `cbor2` handling is correct for them.
    - All nine known top-level keys are present (#585 fix round 1,
      Finding 2) -- `Manifest` has no `Option` among them.
    - The whole body re-encodes byte-identically (§4.3 step 4). This
      catches KEY ORDER (and, per the array bullet above, an out-of-sort
      array) inside a nested KNOWN map. It does NOT catch a DUPLICATE key
      there: `_decode_manifest_entry_map` / `_decode_strict_entry_map`
      reject those explicitly from their own `seen` sets, before this
      check runs -- and since those maps are scanned rather than
      `cbor2.loads`-ed, a repeat is PRESERVED and would re-encode equal
      (#595).

    The returned dict maps `"unknown"` to `{key: raw_bytes}`, at the top
    level AND inside each `blocks[i]` / `trash[i]` entry.  That asymmetry
    is the design: a decoded object cannot reproduce what §4.2 requires
    reproducing (#592).
    """
    import cbor2

    # §6.2 rule 4 over the WHOLE body, BEFORE any key is interpreted --
    # §4.2's precedence paragraph (#618), and a byte-for-byte mirror of
    # `decode_manifest`'s own `reject_floats_and_tags` call, which sits
    # between the parse and `parse_manifest_map` for the same reason.
    #
    # It has to be a separate walk rather than the per-value
    # `_check_canonical_item` calls below. Those run INSIDE the entry loop,
    # so for a repeated key they never reach the second copy: the duplicate
    # check raises first. That made this reader report the repeat where
    # `decode_manifest` reported the float -- both rejecting, neither
    # interoperable. `manifest_precedence_kat.json`'s `top__float` and
    # `top__tag` rows are the two that measured it; the nested rows already
    # agreed, because a nested float is inside the top-level VALUE that the
    # loop's `_check_canonical_item` recurses into before any nested parser
    # sees its own repeat.
    reject_floats_and_tags(data)

    entries, end = _scan_map_entries(data, 0)
    if end != len(data):
        raise ValueError(f"trailing bytes after manifest map: {len(data) - end}")

    out: dict[str, Any] = {}
    unknown: dict[str, bytes] = {}
    seen: set[str] = set()

    for (ks, ke), (vs, ve) in entries:
        kmaj, _, _, _ = _decode_head(data, ks)
        if kmaj != 3:
            raise ValueError(f"manifest map key at offset {ks} is not a text string")
        key = cbor2.loads(data[ks:ke])
        if key in seen:
            raise DuplicateMapKey("manifest", key)
        seen.add(key)

        # Rules 2/3/4 apply to every value, known or unknown.
        _check_canonical_item(data, vs)

        if key in MANIFEST_KNOWN_KEYS:
            if key == "blocks":
                out[key] = _decode_manifest_array(
                    data, vs, ve, BLOCK_ENTRY_KNOWN_KEYS, BLOCK_ENTRY_REQUIRED_KEYS, "blocks"
                )
            elif key == "trash":
                out[key] = _decode_manifest_array(
                    data, vs, ve, TRASH_ENTRY_KNOWN_KEYS, TRASH_ENTRY_REQUIRED_KEYS, "trash"
                )
            elif key == "vector_clock":
                out[key] = _decode_strict_array(
                    data,
                    vs,
                    ve,
                    VECTOR_CLOCK_ENTRY_KNOWN_KEYS,
                    VECTOR_CLOCK_ENTRY_REQUIRED_KEYS,
                    "vector_clock",
                )
            elif key == "kdf_params":
                out[key] = _decode_strict_entry_map(
                    data,
                    vs,
                    ve,
                    KDF_PARAMS_KNOWN_KEYS,
                    KDF_PARAMS_REQUIRED_KEYS,
                    "kdf_params",
                )
            else:
                out[key] = cbor2.loads(data[vs:ve])
        else:
            unknown[key] = data[vs:ve]

    absent = first_missing_key_in_sorted_order(out, MANIFEST_REQUIRED_KEYS)
    if absent is not None:
        raise ValueError(f"manifest missing required field: {absent!r}")

    # Type/range/version checks on every known field. Must run AFTER the
    # presence loop above (it indexes `out` unconditionally) and BEFORE the
    # sort checks below (which index `row[key]` and would raise `KeyError`
    # on a malformed entry instead of a clean `ValueError`).
    _validate_manifest_shape(out)

    # The five §4.2 array sort disciplines. `encode_manifest` sorts all five
    # on output, so an array arriving out of order is rejected -- a WIDER
    # rejection surface than plain canonical CBOR, and deliberate.
    #
    # Four of the five ALSO forbid a repeated value, which is a separate
    # §4.2 rule and not a consequence of the sort: `[x, x]` IS sorted, and
    # the §4.3 step-4 re-encode cannot see a repeat either, because a body
    # carrying one re-encodes to itself byte for byte. Enforcing sortedness
    # alone is what made this reader ACCEPT four manifest bodies
    # `decode_manifest` rejects (#594), so the two checks live in one
    # function whose NAME carries both -- the four call sites below being
    # exactly the four positions is not something a caller list can be
    # relied on to keep true.
    _check_sorted_and_distinct(out.get("vector_clock", []), "device_uuid", "vector_clock")
    _check_sorted_and_distinct(out.get("blocks", []), "block_uuid", "blocks")
    _check_sorted_and_distinct(out.get("trash", []), "block_uuid", "trash")
    for i, blk in enumerate(out.get("blocks", [])):
        # `recipients` is §4.2's EXPLICIT exception and is checked for
        # sortedness ONLY: a repeated `contact_uuid` is accepted and
        # round-trips, since it denotes no additional grant.
        # `parse_recipients` in `core/src/vault/manifest/decode/entries.rs`
        # likewise has no uniqueness check. Do not "fix" this asymmetry --
        # adding one here would reject bodies the v1-frozen Rust decoder
        # accepts, which is the divergence this reader exists to detect.
        recips = blk.get("recipients", [])
        if recips != sorted(recips):
            raise ArraySortOrderViolation(f"blocks[{i}].recipients is not sorted")
        _check_sorted_and_distinct(
            blk.get("vector_clock_summary", []),
            "device_uuid",
            f"blocks[{i}].vector_clock_summary",
        )

    out["unknown"] = unknown

    # §4.3 step 4: the re-encode must reproduce the input byte for byte.
    # This is the ONLY thing checking the OUTER map's own head and key
    # order -- `_check_canonical_item` above runs on values, never on the
    # body as a whole -- which is why `section_manifest_body_outer_
    # canonicality_guard` pins it (#595).
    #
    # It does NOT reject a duplicate key inside a nested KNOWN map. An
    # earlier version of this comment said it did, reasoning that
    # `cbor2.loads` collapses the repeat so the re-encode comes back
    # shorter. That stopped being true in this same slice: those maps are
    # scanned by `_scan_map_entries`, which PRESERVES the repeat, so
    # `py_encode_manifest` re-emits it and the comparison passes. The
    # `seen`-set checks in `_decode_manifest_entry_map` /
    # `_decode_strict_entry_map` are what reject them, and they run first.
    #
    # Retained unknown subtrees -- top-level AND per-entry -- are spliced
    # verbatim and compare equal, so this check does not undo the
    # byte-retention design at either nesting level.
    if py_encode_manifest(out) != data:
        raise NonCanonicalBody("manifest body is not in canonical CBOR form")

    return out


def _check_uint(value: Any, field: str, bits: int) -> None:
    """Assert `value` is a CBOR unsigned integer that fits in `bits`.

    Mirrors `manifest/decode/extract.rs`'s `take_u8`/`take_u16`/`take_u32`/
    `take_u64`, each of which rejects a non-integer as `WrongType` and an
    out-of-range integer as `IntegerOutOfRange`. `bool` is excluded
    explicitly because Python's `bool` subclasses `int` -- `isinstance(True,
    int)` is `True` -- while ciborium decodes a CBOR bool to `Value::Bool`,
    which `take_u*` rejects. Without the guard a `true` would pass here and
    be rejected by Rust.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be a uint, got {type(value).__name__}")
    if not 0 <= value < (1 << bits):
        raise ValueError(f"{field} is out of range for u{bits}: {value}")


def _check_fixed_bytes(value: Any, field: str, n: int) -> None:
    """Assert `value` is a byte string of exactly `n` bytes, mirroring
    `extract.rs`'s `take_fixed_bytes::<N>` (`WrongType` for a non-bstr,
    `WrongLength` for the wrong size).
    """
    if not isinstance(value, bytes):
        raise ValueError(f"{field} must be a bstr, got {type(value).__name__}")
    if len(value) != n:
        raise ValueError(f"{field} must be {n} bytes, got {len(value)}")


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
        raise ValueError(f"unsupported manifest_version: {out['manifest_version']}")
    _check_uint(out["format_version"], "format_version", 16)
    if out["format_version"] != FORMAT_VERSION:
        raise ValueError(f"unsupported format_version: {out['format_version']}")
    _check_uint(out["suite_id"], "suite_id", 16)
    if out["suite_id"] != SUITE_ID:
        raise ValueError(f"unsupported suite_id: {out['suite_id']}")

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
            raise ValueError(f"blocks[{i}].block_name must be tstr")
        _check_fixed_bytes(
            blk["fingerprint"], f"blocks[{i}].fingerprint", BLOCK_FINGERPRINT_LEN
        )
        _check_uint(blk["suite_id"], f"blocks[{i}].suite_id", 16)
        _check_uint(blk["created_at_ms"], f"blocks[{i}].created_at_ms", 64)
        _check_uint(blk["last_mod_ms"], f"blocks[{i}].last_mod_ms", 64)
        if not isinstance(blk["recipients"], list):
            raise ValueError(f"blocks[{i}].recipients must be an array")
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


def _check_sorted_and_distinct(rows: list, key: str, label: str) -> None:
    """Assert `rows` is sorted STRICTLY ascending by `row[key]` (§4.2).

    Two independent §4.2 rules, and both are needed: an array must be
    sorted, and -- in four of the five arrays -- must not repeat a value.
    Neither implies the other, and the sortedness half alone is what this
    reader shipped with until #594, accepting four bodies the Rust decoder
    rejects (`DuplicateBlockUuid`, `DuplicateTrashUuid`,
    `VectorClockDuplicateDevice`).

    They are reported separately rather than as one strict-ascending
    compare so the diagnostic names which rule was broken, and the repeat
    names the offending id. An `ids != sorted(set(ids))` formulation would
    be shorter and is deliberately not used -- it collapses the two rules
    into one verdict and loses the id.

    **They also raise DIFFERENT types, and the asymmetry is deliberate.**
    The sort half raises `ArraySortOrderViolation`, because Section MCC
    discriminates on its type to pin Rust's `NonCanonicalCause::
    ArraySortOrder` cross-language (#613). The repeat half stays a plain
    `ValueError`: Section MUQ discriminates it by a message fragment naming
    the repeated id, which a bare type cannot carry, and the two rules must
    stay separable -- collapsing them onto one type would let a reader that
    checked only sortedness satisfy MUQ, which is exactly the #594
    divergence.

    The distinctness half is `first_repeated_value`, shared with the
    ENCODER (#600): §4.2 binds writers as well as readers, and the writer
    half of this rule was missing from this package until then. Sharing
    the function is what stops the two directions from drifting -- which
    is precisely what had happened on the Rust side, and what #594 had
    already had to repair between this reader and that one.
    """
    ids = [r[key] for r in rows]
    if ids != sorted(ids):
        raise ArraySortOrderViolation(f"{label} is not sorted by {key}")
    repeat = first_repeated_value(ids)
    if repeat is not None:
        raise ValueError(f"{label} has a repeated {key}: {repeat.hex()}")
