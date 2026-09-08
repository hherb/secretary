"""§4.2 manifest BODY encoder.

**This encoder does NOT sort arrays, and that is deliberate.**  An earlier
version of this docstring said it sorted all five of §4.2's arrays on
output, "which is what makes an out-of-order array a REJECTION rather than
a silent normalisation".  That describes Rust's `encode_manifest`, not this
one: the only `sorted` in this file is the comment at `_encode_body` saying
array ELEMENT order is never resorted here.

The distinction is load-bearing for Section MCC's whole claim.  This is a
BYTE-RETAINING reader: it re-emits array order verbatim, so the §4.3 step-4
re-encode comparison can never see array disorder, and `py_decode_manifest`
must therefore check the sort discipline DIRECTLY -- which it does, raising
`ArraySortOrderViolation` before the comparison runs.  Rust reaches the same
rule by the opposite route (its encoder does sort, so an unsorted input
fails to re-encode to itself, and `classify::arrays_are_sorted` then names
the cause).  Same rule, different mechanism; `docs/vault-format.md` §4.2
makes that asymmetry normative.

What this encoder DOES enforce is §4.2's writer half for repeated array
values (#600), via `check_no_repeated_array_values`.
"""

from __future__ import annotations

from conformance_lib.canonical import encode_canonical_map_raw
from conformance_lib.codec.array_uniqueness import first_repeated_value
from conformance_lib.codec.manifest_schema import MANIFEST_VERSION_V1
from conformance_lib.constants import FORMAT_VERSION, SUITE_ID


# The four arrays §4.2 forbids a repeat in, as (array key, id key) pairs.
# `recipients` is the EXPLICIT exception and is absent by design -- a
# repeated `contact_uuid` denotes no additional grant, is accepted by both
# decoders, and round-trips. Adding it here would make this encoder refuse
# a body the v1-frozen Rust encoder emits, which is the divergence this
# package exists to detect, pointing the wrong way.
# The prefix every §4.2 refusal from THIS module carries.
#
# Exported because Section MUQ keys on it in both directions, and it must
# not drift from the messages below: `py_decode_manifest` re-encodes
# through `py_encode_manifest` for the §4.3 step-4 comparison, so this
# encoder BACKSTOPS the reader. The reader half of that section rejects
# this prefix (a rejection carrying it did not come from the reader, and
# crediting it to the reader is what made that half vacuous -- #608
# review); the writer half requires it.
ENCODER_REFUSAL_PREFIX = "cannot encode:"


# §4.2's three v1 sentinel fields, as (key, expected value) pairs in the
# field order §4.2 declares them -- which is also the order both decoders
# report them in, so a body violating several names the same field
# whichever implementation and whichever direction rejects it.
_V1_SENTINELS: tuple[tuple[str, int], ...] = (
    ("manifest_version", MANIFEST_VERSION_V1),
    ("format_version", FORMAT_VERSION),
    ("suite_id", SUITE_ID),
)


def check_v1_sentinels(parsed: dict) -> None:
    """Reject a manifest whose §4.2 sentinel fields are not the v1 values.

    §4.2 fixes `manifest_version`, `format_version` and `suite_id` at 1 for
    a v1 body, and binds the WRITER as well as the reader.  Both
    implementations enforced only the reader half until #587: Rust's
    `encode_manifest` would serialise `manifest_version: 7` and
    `sign_manifest` would hybrid-sign the result, and this encoder would
    emit the same bytes -- a signed manifest no v1 client can open.  That is
    the identical defect #600 closed for §4.2's repeated-value rules, one
    field group over.

    Availability rather than confidentiality (the manifest is owner-signed,
    so the producer is always a local caller), but for a frozen format with
    a clean-room mandate an encoder that emits a signed document its own
    decoder rejects is a real defect -- and `docs/` states the obligation,
    so an encoder ignoring it is formally non-conformant.

    Raises `ValueError` prefixed with `ENCODER_REFUSAL_PREFIX`, for the
    reason that constant documents: `py_decode_manifest` re-encodes through
    `py_encode_manifest`, so this check BACKSTOPS the reader's own sentinel
    rejection.  Section MSN's reader half rejects the prefix and its writer
    half requires it, so a backstop can never satisfy a reader assertion.
    """
    for key, want in _V1_SENTINELS:
        # Hard subscript, not `.get()` -- the same fail-loud stance
        # `check_no_repeated_array_values` documents below. All three keys are
        # in `MANIFEST_REQUIRED_KEYS`, so a caller reaching here without one
        # has already gone wrong. The consequence is sharper here than there,
        # though: a `KeyError`'s `str()` is just the quoted key name, carrying
        # no `ENCODER_REFUSAL_PREFIX`, so Section MSN would read it as a
        # READER rejection rather than a writer one. It is in
        # `_REJECTION_EXCEPTIONS`, so `--diff-replay` still scores it a
        # reject rather than a harness error.
        got = parsed[key]
        if got != want:
            raise ValueError(
                f"{ENCODER_REFUSAL_PREFIX} unsupported {key}: {got}"
            )


_FLAT_UNIQUE_ARRAYS: tuple[tuple[str, str], ...] = (
    ("vector_clock", "device_uuid"),
    ("blocks", "block_uuid"),
    ("trash", "block_uuid"),
)


def check_no_repeated_array_values(parsed: dict) -> None:
    """Reject a manifest whose §4.2-constrained arrays repeat a value.

    §4.2's repeated-value paragraph binds BOTH directions -- "writers MUST
    NOT emit them and readers MUST reject them" -- and this package
    enforced only the reader half until #600, exactly as `core`'s
    `encode_manifest` did. An encoder that can emit a body its own decoder
    refuses is a divergence a clean-room implementation should not have to
    discover for itself.

    Mirrors `core/src/vault/manifest/uniqueness.rs`'s
    `check_no_repeated_array_values`, including the per-block walk: §4.2
    constrains "**each** block's" `vector_clock_summary`, so a writer that
    checked only `blocks[0]` would diverge on the corpus row that plants
    its repeat in `blocks[1]`.
    """
    # Hard-indexed, not `.get(array, [])`: a MISSING key would check
    # nothing and report nothing, while the `row[id_key]` one token later
    # is fail-loud -- two different failure stances inside one expression
    # (#608 review). All three arrays are in `MANIFEST_REQUIRED_KEYS` and
    # `Manifest`'s Rust twin holds typed `Vec`s, where absence is not
    # representable at all; a `KeyError` here is the honest report that
    # this function was handed something that is not a decoded manifest.
    for array, id_key in _FLAT_UNIQUE_ARRAYS:
        repeat = first_repeated_value([row[id_key] for row in parsed[array]])
        if repeat is not None:
            raise ValueError(
                f"{ENCODER_REFUSAL_PREFIX} {array} has a repeated {id_key}: "
                f"{repeat.hex()}"
            )
    for i, blk in enumerate(parsed["blocks"]):
        summary = blk["vector_clock_summary"]
        repeat = first_repeated_value([row["device_uuid"] for row in summary])
        if repeat is not None:
            raise ValueError(
                f"{ENCODER_REFUSAL_PREFIX} blocks[{i}].vector_clock_summary has "
                f"a repeated device_uuid: {repeat.hex()}"
            )


def _encode_array_header(n: int) -> bytes:
    """RFC 8949 §3.1: major type 4 (array) head byte is `0x80 |
    additional-info`, with the shortest-form encodings for the element
    count `n` (§4.2.1) -- the array-header analogue of
    `encode_canonical_map_raw`'s map-header construction.
    """
    if n < 24:
        return bytes([0x80 | n])
    if n < 0x100:
        return bytes([0x98, n])
    if n < 0x10000:
        return bytes([0x99]) + n.to_bytes(2, "big")
    return bytes([0x9A]) + n.to_bytes(4, "big")


def _encode_manifest_array(items: list, entry_encoder) -> bytes:
    """Encode a `blocks`/`trash` array from already-decoded entry dicts,
    each rebuilt to raw bytes by `entry_encoder` (`_encode_manifest_block_entry`
    or `_encode_manifest_trash_entry`). Array ELEMENT order is never
    resorted here -- `py_decode_manifest` already validated the incoming
    order against the §4.2 sort discipline, and canonical CBOR only
    constrains map KEY order, never array element order.
    """
    out = bytearray(_encode_array_header(len(items)))
    for item in items:
        out += entry_encoder(item)
    return bytes(out)


def _encode_manifest_block_entry(entry: dict) -> bytes:
    """Re-encode one `blocks[i]` entry dict (from `_decode_manifest_entry_map`)
    to canonical CBOR. All eight known fields are required (`BlockEntry` has
    no `Option` field); `unknown` values are spliced verbatim from their
    retained raw bytes, never re-encoded.
    """
    import cbor2

    entries: list[tuple[str, bytes]] = [
        ("block_uuid", cbor2.dumps(entry["block_uuid"], canonical=True)),
        ("block_name", cbor2.dumps(entry["block_name"], canonical=True)),
        ("fingerprint", cbor2.dumps(entry["fingerprint"], canonical=True)),
        ("recipients", cbor2.dumps(entry["recipients"], canonical=True)),
        (
            "vector_clock_summary",
            cbor2.dumps(entry["vector_clock_summary"], canonical=True),
        ),
        ("suite_id", cbor2.dumps(entry["suite_id"], canonical=True)),
        ("created_at_ms", cbor2.dumps(entry["created_at_ms"], canonical=True)),
        ("last_mod_ms", cbor2.dumps(entry["last_mod_ms"], canonical=True)),
    ]
    entries.extend(entry.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)


def _encode_manifest_trash_entry(entry: dict) -> bytes:
    """Re-encode one `trash[i]` entry dict (from `_decode_manifest_entry_map`)
    to canonical CBOR. `fingerprint` and `purged_at_ms` are each omitted
    entirely when absent/`None` -- never an explicit CBOR null -- matching
    `TrashEntry`'s §7/§7.2 optional-field semantics
    (`manifest/encode.rs::trash_entry_to_canonical`); `unknown` values are
    spliced verbatim from their retained raw bytes.
    """
    import cbor2

    entries: list[tuple[str, bytes]] = [
        ("block_uuid", cbor2.dumps(entry["block_uuid"], canonical=True)),
        ("tombstoned_at_ms", cbor2.dumps(entry["tombstoned_at_ms"], canonical=True)),
        ("tombstoned_by", cbor2.dumps(entry["tombstoned_by"], canonical=True)),
    ]
    if entry.get("fingerprint") is not None:
        entries.append(("fingerprint", cbor2.dumps(entry["fingerprint"], canonical=True)))
    if entry.get("purged_at_ms") is not None:
        entries.append(("purged_at_ms", cbor2.dumps(entry["purged_at_ms"], canonical=True)))
    entries.extend(entry.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)


def py_encode_manifest(parsed: dict) -> bytes:
    """Re-encode a `py_decode_manifest` result to canonical CBOR.

    Known values go through `cbor2.dumps(..., canonical=True)`, EXCEPT
    `blocks`/`trash`, each of which is rebuilt entry-by-entry through
    `_encode_manifest_array` so a per-entry `unknown` subtree is spliced
    from its retained raw bytes rather than collapsed through `cbor2`
    (#585 fix round 1, Finding 1). Top-level unknown subtrees are spliced
    from their retained bytes the same way, never re-encoded.

    Refuses a manifest violating §4.2's repeated-value rules before
    emitting anything (#600) -- see `check_no_repeated_array_values`.
    Refuses a non-v1 sentinel first (#587) -- see `check_v1_sentinels`.

    Observably a no-op for every caller that PRE-DATES #600. There are
    seven of them, not the two an earlier version of this docstring named
    (#608 review): `manifest_decode.py`'s §4.3 step-4 re-encode,
    `diff_replay.py`'s accept path, `manifest_body_schema_guards.py` (x2),
    `manifest_body_shape_guards.py`, and `wire/golden_vault_verify.py`.
    Every one of them passes a `py_decode_manifest` result, so the reader
    has already rejected any body this check could refuse -- which is the
    substance, and is why the enumeration being short did not make it
    harmless: the two-caller claim is exactly what a reader would use to
    reason about whether this check can fire, and it is what Section MUQ's
    `_ENCODER_PREFIX` had to be added to handle.

    Section MUQ is the EXCEPTION and the reason this is not dead code: it
    calls this function directly on a mutated manifest and requires it to
    raise. It is the writer half of a normative rule.

    **It also backstops the reader**, which is a consequence rather than a
    goal. Because `py_decode_manifest` re-encodes through here, deleting
    the decoder's own distinctness check no longer makes a repeat-carrying
    body decode `Ok` -- this refuses it one step later. Section MUQ
    distinguishes the two by the `cannot encode:` prefix; without that, its
    reader half would credit these rejections to the reader and go vacuous.
    """
    import cbor2

    # §4.2's two writer-side preconditions, sentinels FIRST (#587) --
    # the same order `core`'s `encode_manifest` applies them in, and
    # pinned there by `the_sentinel_check_outranks_the_repeated_value_check`.
    check_v1_sentinels(parsed)
    check_no_repeated_array_values(parsed)

    entries: list[tuple[str, bytes]] = []
    for k, v in parsed.items():
        if k == "unknown":
            continue
        if k == "blocks":
            entries.append((k, _encode_manifest_array(v, _encode_manifest_block_entry)))
        elif k == "trash":
            entries.append((k, _encode_manifest_array(v, _encode_manifest_trash_entry)))
        else:
            entries.append((k, cbor2.dumps(v, canonical=True)))
    entries.extend(parsed.get("unknown", {}).items())
    return encode_canonical_map_raw(entries)
