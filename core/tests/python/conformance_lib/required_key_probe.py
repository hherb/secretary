"""The inputs Section DET replays under several `PYTHONHASHSEED` values (#597).

WHY THIS IS A SEPARATE, SPAWNABLE MODULE. CPython salts string hashing once
per PROCESS, so set iteration order is fixed for the life of an interpreter
and cannot be varied from inside one. The only way to observe a decoder that
reports "whichever required key I reached first" is to decode the SAME input
in two processes started with different seeds -- which is exactly the
reproduction in #597. `section_required_key_determinism` therefore spawns this
module (`python -m conformance_lib.required_key_probe`) once per seed and
compares the JSON it prints.

WHAT A CASE IS. One case per required-key presence check in `codec/` -- seven,
listed in `CASES`. Not "in the verifier": there is an EIGHTH, `wire/card.py`,
deliberately outside this table and outside the helper, because it reports the
whole missing set already sorted and so has no first-key choice to make.
Section DET's own docstring records that exclusion. Each declares `missing`: two or more required keys
its input deliberately omits. Fewer than two would make the case VACUOUS, not
merely weak: with a single absent key there is only one key the decoder could
possibly name, so it reports the same thing under every hash seed whether or
not it sorts.

EACH CASE DECODES TWICE, AND THE SECOND DECODE IS THE CONTROL. `base` omits
every key in `missing`; `restored` adds back only `missing[0]`, the
lexicographically first. A decoder that reports the lex-first absent key must
therefore name `missing[0]` and then `missing[1]` -- two DIFFERENT keys from
two nearly identical inputs. That is what makes the ambiguity a property of
the DECODER rather than of this table: if a key listed in `missing` were not
in fact required, the second decode would accept, or reject naming something
else, and the section reds. A table-only `len(missing) >= 2` assertion would
have been satisfied by a wrong table.

Values here are structural placeholders, not cryptographic material -- but
"placeholder" does not mean "any width will do", and the obvious wider claim is
false. A decoder reaches its own required-key check before its own value-shape
checks, so a card's `x25519_pk` never has to be 32 bytes. It does NOT follow
that nothing here is load-bearing: the three NESTED cases (`record_field`,
`manifest_block_entry`, `manifest_kdf_params`) are reached through a decoder one
level up, whose shape checks run first. `_UUID` must therefore be a real 16
bytes -- narrowed to one byte, `record_field` stops reaching its check at all
and rejects with `record_uuid must be 16-byte bstr`. `_SALT` and the block
entry's `fingerprint`, by contrast, are never presented to a decoder by any
case (every key that would carry them is in that case's `missing`), so their
widths are documentation of the position rather than a constraint.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

# THE CROSS-PROCESS CONTRACT, declared once. Section DET imports these rather
# than spelling the keys again at its end, so the two cannot drift into a
# `KeyError` that takes the whole verifier down with a traceback.
PACKAGE_KEY = "package"
ROWS_KEY = "rows"
ROW_KEYS = frozenset({"label", "base", "restored"})
OUTCOME_KEYS = frozenset({"error_class", "detail"})

# Structural placeholder for any 16-byte uuid position.
_UUID = b"\x11" * 16
# Structural placeholder for the 32-byte Argon2id salt position.
_SALT = b"\x22" * 32


@dataclass(frozen=True)
class Case:
    """One required-key presence check, and the input that reaches it.

    `site` names the source location the case exercises; it is reported on a
    failure so the reader does not have to rediscover which decoder moved.
    `decode` takes the set of `missing` keys to ADD BACK and raises the
    decoder's own rejection.
    """

    label: str
    site: str
    missing: tuple[str, ...]
    decode: Callable[[frozenset[str]], None]


def _body_minus_absent(body: dict[str, Any], missing: tuple[str, ...],
                       restore: frozenset[str]) -> dict[str, Any]:
    """`body` with every key in `missing` dropped, except those in `restore`.

    THE ONE PLACE a case's absent keys are turned into an input. The three
    nested decoders used to build their sub-map as `{k: v for k, v in B.items()
    if k in restore}`, which never reads `missing` at all and only coincided
    with it while `missing == set(B)`. Dropping one key from
    `_BLOCK_ENTRY_MISSING` therefore left Section DET green while it printed
    `PASS manifest_block_entry: 7 absent` for an input omitting eight -- a
    fixture lying about itself, in the module whose whole job is being a
    truthful fixture.
    """
    return {k: v for k, v in body.items() if k in restore or k not in missing}


def _decode_flat(decoder: Callable[[bytes], Any], body: dict[str, Any],
                 missing: tuple[str, ...], restore: frozenset[str]) -> None:
    """Encode `body` minus (`missing` minus `restore`) and hand it to `decoder`."""
    import cbor2

    decoder(cbor2.dumps(_body_minus_absent(body, missing, restore), canonical=True))


_CARD_BODY: dict[str, Any] = {
    "card_version": 1, "contact_uuid": _UUID, "display_name": "d",
    "x25519_pk": b"", "ml_kem_768_pk": b"", "ed25519_pk": b"",
    "ml_dsa_65_pk": b"", "created_at": 0, "self_sig_ed": b"", "self_sig_pq": b"",
}
# The two keys #597's own reproduction input (`core/fuzz/seeds/contact_card/
# pre_sig.cbor`) is missing -- that file is a card captured before signing.
_CARD_MISSING = ("self_sig_ed", "self_sig_pq")


def _decode_card(restore: frozenset[str]) -> None:
    from conformance_lib.codec.card import py_decode_contact_card

    _decode_flat(py_decode_contact_card, _CARD_BODY, _CARD_MISSING, restore)


_RECORD_BODY: dict[str, Any] = {
    "record_uuid": _UUID, "record_type": "t", "fields": {},
    "created_at_ms": 0, "last_mod_ms": 0,
}
_RECORD_MISSING = ("created_at_ms", "fields", "last_mod_ms", "record_type", "record_uuid")


def _decode_record(restore: frozenset[str]) -> None:
    from conformance_lib.codec.record import py_decode_record

    _decode_flat(py_decode_record, _RECORD_BODY, _RECORD_MISSING, restore)


_RECORD_FIELD = {"value": "v", "last_mod": 0, "device_uuid": _UUID}
_RECORD_FIELD_MISSING = ("device_uuid", "last_mod", "value")


def _decode_record_field(restore: frozenset[str]) -> None:
    """A record whose five top-level required keys are all present, so decoding
    reaches the per-field sub-map check one level down."""
    import cbor2

    from conformance_lib.codec.record import py_decode_record

    field = _body_minus_absent(_RECORD_FIELD, _RECORD_FIELD_MISSING, restore)
    body = dict(_RECORD_BODY, fields={"f": field})
    py_decode_record(cbor2.dumps(body, canonical=True))


_TRASH_BODY: dict[str, Any] = {
    "block_uuid": _UUID, "tombstoned_at_ms": 0, "tombstoned_by": _UUID,
}
_TRASH_MISSING = ("block_uuid", "tombstoned_at_ms", "tombstoned_by")


def _decode_trash_entry(restore: frozenset[str]) -> None:
    from conformance_lib.codec.trash_entry import py_decode_trash_entry

    _decode_flat(py_decode_trash_entry, _TRASH_BODY, _TRASH_MISSING, restore)


_MANIFEST_BODY: dict[str, Any] = {
    "manifest_version": 1, "vault_uuid": _UUID, "format_version": 1,
    "suite_id": 1, "owner_user_uuid": _UUID, "vector_clock": [],
    "blocks": [], "trash": [],
    "kdf_params": {"memory_kib": 262144, "iterations": 3, "parallelism": 1, "salt": _SALT},
}
_MANIFEST_MISSING = (
    "blocks", "format_version", "kdf_params", "manifest_version",
    "owner_user_uuid", "suite_id", "trash", "vault_uuid", "vector_clock",
)


def _decode_manifest_body(restore: frozenset[str]) -> None:
    from conformance_lib.codec.manifest_decode import py_decode_manifest

    _decode_flat(py_decode_manifest, _MANIFEST_BODY, _MANIFEST_MISSING, restore)


_BLOCK_ENTRY: dict[str, Any] = {
    "block_uuid": _UUID, "block_name": "b", "fingerprint": b"\x33" * 32,
    "recipients": [], "vector_clock_summary": [], "suite_id": 1,
    "created_at_ms": 0, "last_mod_ms": 0,
}
_BLOCK_ENTRY_MISSING = (
    "block_name", "block_uuid", "created_at_ms", "fingerprint",
    "last_mod_ms", "recipients", "suite_id", "vector_clock_summary",
)


def _decode_block_entry(restore: frozenset[str]) -> None:
    """A manifest body carrying one `blocks` entry. The entry is decoded inside
    `py_decode_manifest`'s key loop, which runs BEFORE its own top-level
    required-key check, so the entry's rejection is the one that surfaces."""
    import cbor2

    from conformance_lib.codec.manifest_decode import py_decode_manifest

    entry = _body_minus_absent(_BLOCK_ENTRY, _BLOCK_ENTRY_MISSING, restore)
    py_decode_manifest(cbor2.dumps({"blocks": [entry]}, canonical=True))


_KDF_PARAMS: dict[str, Any] = {
    "memory_kib": 262144, "iterations": 3, "parallelism": 1, "salt": _SALT,
}
_KDF_PARAMS_MISSING = ("iterations", "memory_kib", "parallelism", "salt")


def _decode_kdf_params(restore: frozenset[str]) -> None:
    """`kdf_params` has no forward-compat bag, so it goes through the STRICT
    entry decoder -- a different helper from the block entry above."""
    import cbor2

    from conformance_lib.codec.manifest_decode import py_decode_manifest

    params = _body_minus_absent(_KDF_PARAMS, _KDF_PARAMS_MISSING, restore)
    py_decode_manifest(cbor2.dumps({"kdf_params": params}, canonical=True))


CASES: tuple[Case, ...] = (
    Case("contact_card", "codec/card.py::py_decode_contact_card",
         _CARD_MISSING, _decode_card),
    Case("record", "codec/record.py::py_decode_record",
         _RECORD_MISSING, _decode_record),
    Case("record_field", "codec/record.py::_validate_record_field",
         _RECORD_FIELD_MISSING, _decode_record_field),
    Case("trash_entry", "codec/trash_entry.py::py_decode_trash_entry",
         _TRASH_MISSING, _decode_trash_entry),
    Case("manifest_body", "codec/manifest_decode.py::py_decode_manifest",
         _MANIFEST_MISSING, _decode_manifest_body),
    Case("manifest_block_entry", "codec/manifest_schema.py::_decode_manifest_entry_map",
         _BLOCK_ENTRY_MISSING, _decode_block_entry),
    Case("manifest_kdf_params", "codec/manifest_schema.py::_decode_strict_entry_map",
         _KDF_PARAMS_MISSING, _decode_kdf_params),
)


def _run_one(case: Case, restore: frozenset[str]) -> dict[str, str]:
    """Decode once and describe the outcome.

    An ACCEPT is reported as its own outcome rather than raising: a case whose
    input stopped being rejected is a fixture that has silently stopped testing
    anything, and the section must see that as a failure, not as a crash.

    The catch is deliberately broad but stops at `Exception`: the decoders
    signal a wire-format violation with several types (`KeyError` here,
    `ValueError` for the manifest ones) and an unexpected one is still a datum
    the section should compare across seeds. `BaseException` would additionally
    swallow `KeyboardInterrupt`/`SystemExit`, which are not outcomes. Letting
    those propagate is right, but be precise about what catches them: a bare
    `sys.exit()` exits ZERO with empty stdout, so it is the section's JSON
    parse that reports it, not the exit code. Only `sys.exit(<non-zero>)` and
    `KeyboardInterrupt` are caught by the returncode branch.
    """
    try:
        case.decode(restore)
    except Exception as e:  # noqa: BLE001 -- the outcome is the datum
        return {"error_class": type(e).__name__, "detail": str(e)}
    return {"error_class": "", "detail": ""}


def run_probe() -> list[dict[str, Any]]:
    """Every case, decoded twice: `base` omits all of `missing`, `restored`
    adds back `missing[0]` only."""
    return [
        {
            "label": case.label,
            "base": _run_one(case, frozenset()),
            "restored": _run_one(case, frozenset({case.missing[0]})),
        }
        for case in CASES
    ]


def main() -> int:
    # `package` is not decoration: it is how Section DET proves the child
    # imported the same tree the section's structural scans read. `python -m`
    # puts the child's CWD on `sys.path[0]` ahead of `PYTHONPATH`, so without
    # this the two halves of that section can silently measure different code.
    # It is constant across hash seeds, so it does not disturb check 1.
    #
    # CONSEQUENCE: this stdout now embeds an ABSOLUTE PATH and so differs
    # between checkouts. That is fine for every consumer there is -- the
    # section only ever compares runs of one tree against each other, and
    # `--diff-replay` does not go through this module at all -- but do not
    # snapshot it as a golden file.
    payload = {
        PACKAGE_KEY: str(Path(__file__).resolve().parent),
        ROWS_KEY: run_probe(),
    }
    json.dump(payload, sys.stdout, sort_keys=True, indent=1)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
