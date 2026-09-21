"""Section VT -- every measured value-type acceptance divergence is closed,
and each case's control proves the decoder discriminates (#669).

WHAT THIS PINS.  `conformance.py` exists to prove `docs/` alone is sufficient
to build a conformant reader.  Where it ACCEPTS a body the Rust decoder
rejects, that claim is false in the quietest possible way: a clean-room
implementer following it builds a reader that is wrong, and the differential
replay cannot tell them, because no corpus input reaches the position.

A systematic sweep -- 439 bodies, each one substitution from a committed
accepting base, both decoders run and compared -- found 16 such divergences
across 10 positions, every one Python-accepts / Rust-rejects, behind two
mechanisms:

  M1  `isinstance(x, int)` with no bool exclusion.  Eight of the 16, on
      `contact_card` and `vault_toml`.  See `codec/integer_rules.py`.

  M2  the type check was never written.  `TrashEntry`'s two `Option` fields
      -- `fingerprint` and `purged_at_ms` -- were validated by nothing, so
      they accepted ANY CBOR value, on `manifest_body`, a target that is
      token-compared and replayed in CI.  Eight of the 16, four substitutions
      each.

`record` swept clean (52 bodies, 0 divergences), which is the negative
control for the method and for #641's record work.

WHY A CONTROL PER CASE (check 2).  A rejection case proves only that
SOMETHING was rejected.  A decoder that rejects the base body too satisfies
all 16 rows, and this section would report PASS on a verifier that accepts
nothing at all.  Each case therefore also replays its base body and requires
ACCEPT, so the fixture's discrimination is demonstrated by the decoder rather
than asserted by its table -- the arrangement Section DET's per-case
ambiguity control has for required keys.

WHY SOME ROWS CARRY A TOKEN AND SOME DO NOT.  `manifest_body` is
token-compared, so its rows require the exact rule Rust names -- measured
against `manifest/token.rs`: `WrongType` and `InvalidByteLength` both map to
`wrong_type`, `IntegerOutOfRange` to `integer_out_of_range`.  `contact_card`
and `vault_toml` have no token taxonomy yet (#641), so their rows require a
verdict and nothing finer.  A row must not pin a distinction its target
cannot make.

WHY `codec/trash_entry.py` IS CHECKED DIFFERENTLY.  It carries the same M1
defect at two positions, but it is a STANDALONE decoder -- Section PRG and
the required-key probe are its only callers, and the manifest replay path
goes through `codec/manifest_decode.py` instead.  No replay target reaches
it, so no committed seed can pin it and `replay_bytes` cannot see it.  Its
two positions are exercised by calling the decoder directly, in
`_trash_entry_issues`.

The structural half of this section -- the rules that stop either mechanism
recurring silently -- lives in `value_type_structure.py`, split out so each
rule and its LIMITS block sit in one file and cannot drift from a summary.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from conformance_lib import fixtures
from conformance_lib.codec.manifest_encode import ENCODER_REFUSAL_PREFIX
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.rejection import _REJECTION_EXCEPTIONS
from conformance_lib.sections.value_type_structure import (
    EXPECTED_OPTIONAL_KEY_COUNT,
    KEY_SET_PAIRS,
    MIN_SCANNED_CODEC_MODULES,
    dispatch_totality_issues,
    optional_key_issues,
    sanctioned_module_issues,
    scan_floor_issues,
    scanned_module_count,
)

# The committed accepting bases each family of cases is built from.
_CARD_BASE = "with_sigs.cbor"
_TOML_BASE = "golden.toml"
_MANIFEST_BASE = "uniq__control__all_distinct.bin"

#: What a body-builder can raise: ANY exception. `main()` has NO per-section
#: catch, so an escape here is a traceback with no `FAIL:` line that also skips
#: every LATER section, REG included. The guard used to be
#: `(OSError, ValueError)` while `_manifest_base` indexes `root["trash"][0]`
#: and `_cbor_sub` walks a path -- `KeyError`/`IndexError`/`TypeError` all
#: escaped, and so did `cbor2.CBORDecodeEOF`, which is an `EOFError` rather
#: than a `ValueError` (#679 review). Enumerating the classes is a denylist and
#: would drift again; a builder that fails is ALWAYS a harness problem, never a
#: verdict, so every class is reported as an issue naming itself.
_BODY_BUILD_ERRORS = Exception

# `manifest_body`'s two token spellings, measured against `manifest/token.rs`.
_WRONG_TYPE = "wrong_type"
_OUT_OF_RANGE = "integer_out_of_range"


# ---------------------------------------------------------------------------
# Plants
# ---------------------------------------------------------------------------


def _cbor_sub(base: bytes, path: tuple, value: object) -> bytes:
    """`base` with `path` replaced by `value`, re-encoded canonically.

    `cbor2.dumps(..., canonical=True)` reproduces every committed base byte
    for byte with nothing substituted, so a case body differs from its base
    at exactly the planted position.
    """
    import cbor2

    root = cbor2.loads(base)
    node = root
    for step in path[:-1]:
        node = node[step]
    # The LAST step must already exist. `node[key] = value` on a dict INSERTS
    # when the key is absent, so a misspelled position -- or a wire key renamed
    # in `codec/` later -- silently added an unrecognised key and left the real
    # value untouched. The body was then rejected as "unknown field", which
    # check 1 counted as a pass for a position it never exercised (measured,
    # #679 review). `_toml_sub` raises for the same reason, and the Rust twin
    # panics at `acceptance_seeds_helpers::set_at`.
    last = path[-1]
    if isinstance(node, dict):
        if last not in node:
            raise ValueError(
                f"_cbor_sub: no key {last!r} at path {path!r}; the plant would "
                f"INSERT rather than substitute, testing nothing"
            )
    else:
        node[last]  # IndexError if the index is out of range.
    node[last] = value
    return cbor2.dumps(root, canonical=True)


def _toml_sub(base: str, key: str, literal: str) -> bytes:
    """`base` with the assignment to `key` replaced by `key = literal`.

    Matches on the assignment's own key, not on a substring, so a value that
    happens to spell another key's name cannot be rewritten by accident.
    """
    out: list[str] = []
    replaced = False
    for line in base.splitlines():
        if not replaced and "=" in line and line.split("=", 1)[0].strip() == key:
            out.append(f"{key} = {literal}")
            replaced = True
        else:
            out.append(line)
    if not replaced:
        raise ValueError(f"no assignment to {key!r} in the base vault.toml")
    return ("\n".join(out) + "\n").encode()


def _card_base() -> bytes:
    return (fixtures.fuzz_seed_dir("contact_card") / _CARD_BASE).read_bytes()


def _toml_base_text() -> str:
    return (fixtures.fuzz_seed_dir("vault_toml") / _TOML_BASE).read_text()


def _manifest_base() -> bytes:
    """The committed all-distinct manifest, with `trash[0]`'s two OPTIONAL
    keys present so both are reachable.

    They are absent from every committed body, which is precisely why the
    corpus never reached them: an unvalidated key that nothing emits is
    invisible until someone plants one.
    """
    import cbor2

    raw = (fixtures.fuzz_seed_dir("manifest_body") / _MANIFEST_BASE).read_bytes()
    root = cbor2.loads(raw)
    root["trash"][0]["fingerprint"] = bytes(32)
    root["trash"][0]["purged_at_ms"] = 7
    return cbor2.dumps(root, canonical=True)


# ---------------------------------------------------------------------------
# The cases
# ---------------------------------------------------------------------------


#: Mirrors `core/tests/differential_replay_helpers/targets.rs`'s
#: `TOKEN_COMPARED_TARGETS`. Python had no copy of that classification, so the
#: rule "pin a token iff the target has a taxonomy" lived only in prose.
TOKEN_COMPARED_TARGETS = frozenset({"record", "manifest_body", "block_file"})


@dataclass(frozen=True)
class Case:
    """One measured acceptance divergence."""

    target: str
    position: str
    substitution: str
    #: Build the body carrying the fault.
    plant: Callable[[], bytes]
    #: Build the body with the base value restored -- check 2's control.
    base_body: Callable[[], bytes]
    #: The rule BOTH decoders must name, or `None` where the target has no
    #: token taxonomy (#641) and only the verdict is compared.
    token: str | None

    def __post_init__(self) -> None:
        # A row must pin a rule IFF its target is token-compared. `token=None`
        # on a token-compared target silently degrades the row to verdict-only
        # on the one target CI compares tokens for; a token on a target with no
        # taxonomy pins a distinction that target cannot make. Both were
        # representable and neither was checked (#679 review).
        if (self.token is not None) != (self.target in TOKEN_COMPARED_TARGETS):
            raise ValueError(
                f"{self.label()}: token={self.token!r} disagrees with target "
                f"{self.target!r} (token-compared: "
                f"{self.target in TOKEN_COMPARED_TARGETS})"
            )

    def label(self) -> str:
        return f"{self.target} {self.position} := {self.substitution}"

    def scope(self) -> str:
        """The `target:map` this case's position sits in.

        Check 4 credits a case to an optional key only within its own scope.
        A bare key name is a MANY-TO-ONE namespace: a `fingerprint` case
        planted in one map credited an optional `fingerprint` in another
        (measured) -- the mis-crediting the AST census was rejected for.
        """
        if "[" in self.position:
            return f"{self.target}:{self.position.split('[', 1)[0]}[]"
        return f"{self.target}:"

    def key(self) -> str:
        """The bare key name at the end of `position`."""
        return self.position.rsplit(".", 1)[-1]


def _card_case(position: str) -> Case:
    return Case(
        target="contact_card",
        position=position,
        substitution="bool",
        plant=lambda: _cbor_sub(_card_base(), (position,), True),
        base_body=_card_base,
        token=None,
    )


def _toml_case(key: str) -> Case:
    return Case(
        target="vault_toml",
        position=key,
        substitution="bool",
        plant=lambda: _toml_sub(_toml_base_text(), key, "true"),
        base_body=lambda: _toml_base_text().encode(),
        token=None,
    )


def _trash_case(key: str, substitution: str, value: object, token: str) -> Case:
    return Case(
        target="manifest_body",
        position=f"trash[0].{key}",
        substitution=substitution,
        plant=lambda: _cbor_sub(_manifest_base(), ("trash", 0, key), value),
        base_body=_manifest_base,
        token=token,
    )


def _build_cases() -> tuple[Case, ...]:
    cases: list[Case] = []

    # M1 -- `isinstance(x, int)` with no bool exclusion. Eight positions.
    cases.append(_card_case("card_version"))
    cases.append(_card_case("created_at"))
    for key in (
        "format_version",
        "suite_id",
        "created_at_ms",
        "memory_kib",
        "iterations",
        "parallelism",
    ):
        cases.append(_toml_case(key))

    # M2 -- `TrashEntry`'s two OPTIONAL keys, validated by nothing. Four
    # substitutions each, chosen so that a PARTIAL fix still reds: a
    # bool-only guard leaves `text` and `bytes` accepted, and a type check
    # without the length or range check leaves `short` / `negative` accepted.
    cases.append(_trash_case("fingerprint", "bool", True, _WRONG_TYPE))
    cases.append(_trash_case("fingerprint", "text", "x", _WRONG_TYPE))
    cases.append(_trash_case("fingerprint", "short-bstr", b"\x00", _WRONG_TYPE))
    cases.append(_trash_case("fingerprint", "negative", -1, _WRONG_TYPE))
    cases.append(_trash_case("purged_at_ms", "bool", True, _WRONG_TYPE))
    cases.append(_trash_case("purged_at_ms", "text", "x", _WRONG_TYPE))
    cases.append(_trash_case("purged_at_ms", "bstr", b"\x00", _WRONG_TYPE))
    cases.append(_trash_case("purged_at_ms", "negative", -1, _OUT_OF_RANGE))

    return tuple(cases)


DIVERGENCE_CASES: tuple[Case, ...] = _build_cases()

#: The measured population. Stated so a row lost in an edit is visible in the
#: run output rather than silently reducing what this section checks.
EXPECTED_CASE_COUNT = 16


# ---------------------------------------------------------------------------
# `codec/trash_entry.py` -- the same M1 defect, on a decoder no replay
# target reaches
# ---------------------------------------------------------------------------

#: The cases `_trash_entry_issues` runs, at module scope so the census can be
#: DERIVED from them. Hand-written, this was a DECLARATION certifying itself:
#: deleting a row left its key reported "covered", and deleting the row
#: together with the decoder check it pins left the whole section green while
#: `codec/trash_entry.py` lost a real type check that nothing else in the tree
#: covers (measured with a control, #679 review).
_TRASH_ENTRY_CASES: tuple[tuple[str, object, str], ...] = (
    ("tombstoned_at_ms", True, "a CBOR bool is not a uint"),
    ("purged_at_ms", True, "a CBOR bool is not a uint"),
    ("fingerprint", "x", "a tstr is not a 32-byte bstr"),
)

#: Its two OPTIONAL keys, derived from the cases that actually run.
#: `tombstoned_at_ms` is required, so it is not part of the census's optional
#: population -- the intersection with the map's optional keys is what check 4
#: consumes.
TRASH_ENTRY_DIRECT_KEYS = frozenset(key for key, _, _ in _TRASH_ENTRY_CASES)


def _trash_entry_issues() -> tuple[list[str], int]:
    """`codec/trash_entry.py`'s integer positions reject a CBOR bool.

    This decoder is checked by CALLING it, not by `replay_bytes`, and the
    reason is structural rather than a convenience: Section P and the
    required-key probe are its only callers, and the manifest replay path goes
    through `codec/manifest_decode.py` instead. No replay target reaches it, so
    no committed seed can pin it and the differential replay cannot see it --
    which is why its copy of the bool defect survived #641 untouched.

    Both its `tombstoned_at_ms` (required) and `purged_at_ms` (optional)
    positions accepted a boolean before #669; Rust's `take_u64` rejects both.
    `fingerprint` is covered too, since the census requires a case for every
    optional key and a bstr position is the other half of the same map.
    """
    import cbor2

    from conformance_lib.codec.trash_entry import py_decode_trash_entry

    base = {
        "block_uuid": bytes(16),
        "tombstoned_at_ms": 5,
        "tombstoned_by": bytes(16),
        "fingerprint": bytes(32),
        "purged_at_ms": 7,
    }

    issues: list[str] = []

    # The control first: the base body must round-trip, or every rejection
    # below would be satisfied by a decoder that rejects everything.
    try:
        py_decode_trash_entry(cbor2.dumps(base, canonical=True))
    except Exception as exc:  # noqa: BLE001 -- any raise at all fails the control
        issues.append(
            f"trash_entry control: the all-valid entry must decode, got "
            f"{type(exc).__name__}: {exc}"
        )

    for key, bad, why in _TRASH_ENTRY_CASES:
        entry = dict(base)
        entry[key] = bad
        try:
            py_decode_trash_entry(cbor2.dumps(entry, canonical=True))
        except _REJECTION_EXCEPTIONS:
            continue
        except Exception as exc:  # noqa: BLE001
            # "could not measure" is not "measured and fine". A class outside
            # `conformance_lib.rejection`'s verdict allowlist is this script
            # failing, not the decoder rejecting -- the split `diff_replay.py`
            # makes for every other decoder (#595), which this check had
            # collapsed back together (#679 review).
            issues.append(
                f"trash_entry {key} := {bad!r}: raised {type(exc).__name__}, which is a "
                f"HARNESS failure, not a rejection verdict: {exc}"
            )
            continue
        issues.append(
            f"trash_entry {key} := {bad!r}: must be REJECTED ({why}); "
            f"Rust's parse_trash_entry rejects it"
        )
    return issues, len(_TRASH_ENTRY_CASES)


def _shareable_tag_body() -> bytes:
    """A single-key map: an unknown key holding `tag28([tag29(0)])`.

    `walk_body` is a byte-level pass ahead of any interpretation, so this
    body need not be a valid `TrashEntry` otherwise -- the rule-4 fault must
    be found and reported before any required-field check ever runs.
    """
    import cbor2

    return (
        bytes([0xA1])
        + cbor2.dumps("zz_future", canonical=True)
        + bytes([0xD8, 0x1C, 0x81, 0xD8, 0x1D, 0x00])
    )


#: The body(ies) `_trash_entry_shareable_tag_issues` exercises. A tuple, like
#: `_TRASH_ENTRY_CASES` above, so a row dropped here is a row the loop below
#: does not run -- and `PASS 2c`'s count must come from that loop actually
#: running each one, not from `len()` of this table (#685 review: the first
#: version's `PASS 2c` was a hardcoded string, invisibly deletable).
_SHAREABLE_TAG_BODIES: tuple[tuple[str, Callable[[], bytes]], ...] = (
    ("shareable-tag body (tags 28/29)", _shareable_tag_body),
)


def _trash_entry_shareable_tag_issues() -> tuple[list[str], int]:
    """`codec/trash_entry.py` no longer hands a shareable-tag body to
    `cbor2.loads` before checking rule 4 (#685).

    `cbor2.loads` resolves CBOR tags 28 (shareable) and 29 (sharedref) into a
    genuinely CYCLIC Python list and strips both tags on the way, so a body
    carrying `tag28([tag29(0)])` under an unknown key made the recursive
    `_reject_floats_and_tags_py` walk a cycle and raise `RecursionError` -- a
    harness failure, not a verdict. Separately, tag 28 ALONE is stripped
    before that walk ever sees it, so it was never reported as rule 4 at
    all. `codec/manifest_decode.py` was immune to both: it never
    `cbor2.loads`s the whole body, only scans byte spans and keeps unknown
    subtrees raw.

    No replay target reaches `codec/trash_entry.py` (see this section's
    docstring), so this is the only pin for it, and "rejected somehow" is
    not enough: it must be `NonCanonicalItem` naming rule 4 and the tag --
    not a `RecursionError`, and not an `ENCODER_REFUSAL_PREFIX` writer-side
    refusal answering for the reader (#600/#608's backstop direction).

    Returns `(issues, checked)`, `checked` counted INSIDE the loop that runs
    each body -- not `len(_SHAREABLE_TAG_BODIES)` -- so the count on
    `PASS 2c` is a property of what this function actually ran, the same
    shape `PASS 2b`'s `trash_checked` already has.
    """
    from conformance_lib.codec.scanner import NonCanonicalItem
    from conformance_lib.codec.trash_entry import py_decode_trash_entry

    issues: list[str] = []
    checked = 0
    for label, build in _SHAREABLE_TAG_BODIES:
        checked += 1
        body = build()
        try:
            py_decode_trash_entry(body)
        except NonCanonicalItem as exc:
            if exc.rule != 4:
                issues.append(
                    f"trash_entry {label}: rejected as rule {exc.rule}, want "
                    f"rule 4 (a CBOR tag): {exc}"
                )
            if "tag" not in str(exc).lower():
                issues.append(
                    f"trash_entry {label}: rejected as rule 4, but the "
                    f"message does not name a tag: {exc}"
                )
        except RecursionError as exc:
            issues.append(
                f"trash_entry {label}: raised RecursionError (#685) -- cbor2 "
                f"resolved tags 28/29 into a cyclic value before rule 4 "
                f"could see it; a harness failure, not a verdict: {exc}"
            )
        except Exception as exc:  # noqa: BLE001
            detail = str(exc)
            if detail.startswith(ENCODER_REFUSAL_PREFIX):
                issues.append(
                    f"trash_entry {label}: answered by the ENCODER "
                    f"({detail!r}); this check asserts the READER rejects "
                    f"it as rule 4"
                )
            else:
                issues.append(
                    f"trash_entry {label}: raised {type(exc).__name__}, not "
                    f"a rule-4 NonCanonicalItem: {exc}"
                )
        else:
            issues.append(
                f"trash_entry {label}: must be REJECTED as rule 4 (a CBOR "
                f"tag); it was ACCEPTED"
            )
    return issues, checked


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def _plant_integrity_issues() -> list[str]:
    """Checks 1a/1b -- the plants are canonical and mutually distinct.

    Both are assertions the RUST half already makes
    (`the_cbor_round_trip_is_an_identity_on_every_base` and
    `assert_each_target_plants_distinct_bytes`) and the Python half only
    claimed in a docstring.

    1a  `cbor2.dumps(loads(base), canonical=True)` must reproduce each
        committed base byte for byte. Without it a re-encode that stopped
        being canonical would silently convert the token-less rows into
        canonicality tests -- they assert a rejection, and a non-canonical
        body is rejected.
    1b  no two rows may plant the same bytes. `EXPECTED_CASE_COUNT` counts
        ROWS, and `substitution` is free text used only in a label, so four
        rows collapsing onto two bodies still printed "16 divergences"
        (measured, #679 review).
    """
    import cbor2

    issues: list[str] = []

    for label, raw in (
        ("contact_card/" + _CARD_BASE, _card_base()),
        ("manifest_body/" + _MANIFEST_BASE,
         (fixtures.fuzz_seed_dir("manifest_body") / _MANIFEST_BASE).read_bytes()),
    ):
        if cbor2.dumps(cbor2.loads(raw), canonical=True) != raw:
            issues.append(
                f"{label}: cbor2's canonical re-encode is not byte-identical to the "
                f"committed base, so a case body differs from its base at more than "
                f"the planted position"
            )

    bodies: dict[bytes, str] = {}
    for case in DIVERGENCE_CASES:
        try:
            body = case.plant()
        except _BODY_BUILD_ERRORS:
            continue  # Reported by check 1.
        if body in bodies:
            issues.append(
                f"{case.label()} plants the same bytes as {bodies[body]}; two rows "
                f"claiming different substitutions test one body"
            )
            continue
        bodies[body] = case.label()
    return issues


def _wire_issues() -> tuple[list[str], int]:
    """Check 1c -- `wire/`'s integer positions reject a bool too.

    `wire/` parses to INSPECT the committed golden vault and enforces no
    acceptance set, so it has no Rust counterpart to diverge from and check 3
    deliberately does not scan it. But it carried both of #669's mechanisms --
    `wire/vault_toml.py` had six M1 positions and `wire/card.py` a bare
    `card_version != 1` (M1) plus NO check at all on `created_at` (M2) -- and
    fixing them left nothing to stop the fix being reverted: the only callers
    parse the VALID golden vault, so the whole hunk could be undone with the
    suite green. For a `!= 1` spelling, where `True != 1` is `False`, that is
    the quietest possible revert.
    """
    import cbor2

    from conformance_lib.cursor import ParseError
    from conformance_lib.wire.card import parse_and_verify_card
    from conformance_lib.wire.vault_toml import parse_vault_toml

    issues: list[str] = []
    checked = 0

    toml_base = _toml_base_text()
    try:
        parse_vault_toml(toml_base)
    except Exception as exc:  # noqa: BLE001
        issues.append(f"wire control: the base vault.toml must parse, got {exc!r}")

    def _expect_named_rejection(label: str, key: str, build, why: str) -> None:
        """Reject, AND for this position -- not for some other reason.

        The card arm needs this and does not merely benefit from it. Planting a
        bool changes the signed bytes, so `parse_and_verify_card` rejects the
        body at its hybrid self-signature check whatever the type check does:
        the first version of this helper asserted only `ParseError` and passed
        with `wire/card.py`'s fix fully reverted (measured). A rejection that
        does not name the position is the SIGNATURE answering for the type
        check -- the #600/#608 backstop direction, one layer down.
        """
        try:
            build()
        except ParseError as exc:
            if key not in str(exc):
                issues.append(
                    f"{label} {key} := true: rejected, but not for {key!r} -- "
                    f"{exc}. Something else is answering for the type check"
                )
            return
        except Exception as exc:  # noqa: BLE001
            issues.append(
                f"{label} {key} := true: raised {type(exc).__name__}, not ParseError: {exc}"
            )
            return
        issues.append(f"{label} {key} := true: must be REJECTED; {why}")

    for key in ("format_version", "suite_id", "created_at_ms",
                "memory_kib", "iterations", "parallelism"):
        checked += 1
        _expect_named_rejection(
            "wire/vault_toml", key,
            lambda k=key: parse_vault_toml(_toml_sub(toml_base, k, "true").decode()),
            "a TOML bool is not an integer and `unlock/vault_toml.rs`'s "
            "`as_integer` returns None for it",
        )

    card_base = _card_base()
    for key in ("card_version", "created_at"):
        checked += 1
        _expect_named_rejection(
            "wire/card", key,
            lambda k=key: parse_and_verify_card(_cbor_sub(card_base, (k,), True)),
            "`identity/card.rs`'s `take_u8`/`take_u64` match `Value::Integer` alone",
        )
    return issues, checked


def _rejection_issues() -> list[str]:
    """Check 1 -- every measured divergence is now REJECTED, with the rule
    Rust names where the target is token-compared."""
    issues: list[str] = []
    for case in DIVERGENCE_CASES:
        try:
            body = case.plant()
        except _BODY_BUILD_ERRORS as exc:
            # An issue, not a raise: `main()` has no per-section catch, so a
            # raise here would skip every later section, REG included, with
            # no `FAIL:` line.
            issues.append(f"{case.label()}: cannot build the body: {type(exc).__name__}: {exc}")
            continue
        verdict = replay_bytes(case.target, body).verdict
        if verdict.get("status") != "reject":
            issues.append(
                f"{case.label()}: must be REJECTED, got {verdict.get('status')} "
                f"-- Rust rejects this body, so accepting it is an acceptance divergence"
            )
            continue
        detail = str(verdict.get("detail") or "")
        if case.token is not None:
            if verdict.get("rule") != case.token:
                issues.append(
                    f"{case.label()}: must report {case.token!r}, got {verdict.get('rule')!r} "
                    f"({verdict.get('error_class')}: {verdict.get('detail')})"
                )
            continue
        # TOKEN-LESS TARGETS (`contact_card`, `vault_toml`) have no taxonomy to
        # compare, so "rejected" was the whole assertion -- and a rejection for
        # an UNRELATED reason satisfied it. Eight of the sixteen rows passed on
        # a tree carrying #669's defect in full, once the planted body was made
        # to reject some other way (measured, #679 review). Require the
        # rejection to name the position it is about.
        if case.key() not in detail:
            issues.append(
                f"{case.label()}: rejected, but the reason does not name "
                f"{case.key()!r} -- {verdict.get('error_class')}: {detail!r}. "
                f"A rejection for an unrelated reason is not evidence for this row"
            )
        # And it must be the READER's rejection, not an encoder refusal
        # answering for it (#600/#608's backstop direction).
        if detail.startswith(ENCODER_REFUSAL_PREFIX):
            issues.append(
                f"{case.label()}: answered by the ENCODER ({detail!r}); check 1 "
                f"asserts the DECODER rejects this body"
            )
    return issues


def _control_issues() -> list[str]:
    """Check 2 -- each case's position, restored to its base value, ACCEPTS.

    Without this a row proves only that something was rejected, and a decoder
    that rejects the base body satisfies all 16.
    """
    issues: list[str] = []
    seen: set[tuple[str, str]] = set()
    for case in DIVERGENCE_CASES:
        key = (case.target, case.position)
        if key in seen:
            continue
        seen.add(key)
        try:
            body = case.base_body()
        except _BODY_BUILD_ERRORS as exc:
            issues.append(
                f"{case.target} {case.position}: cannot build the control body: "
                f"{type(exc).__name__}: {exc}"
            )
            continue
        verdict = replay_bytes(case.target, body).verdict
        if verdict.get("status") != "accept":
            issues.append(
                f"{case.target} {case.position}: the CONTROL body (base value restored) "
                f"must be ACCEPTED, got {verdict.get('status')} "
                f"({verdict.get('error_class')}: {verdict.get('detail')})"
            )
    return issues


def section_value_type_discipline() -> tuple[bool, list[str]]:
    issues: list[str] = []

    if len(DIVERGENCE_CASES) != EXPECTED_CASE_COUNT:
        issues.append(
            f"EXPECTED_CASE_COUNT is {EXPECTED_CASE_COUNT}, the table holds "
            f"{len(DIVERGENCE_CASES)}"
        )

    issues.extend(_rejection_issues())
    issues.extend(_plant_integrity_issues())
    issues.extend(_control_issues())
    trash_issues, trash_checked = _trash_entry_issues()
    issues.extend(trash_issues)
    tag_issues, tag_checked = _trash_entry_shareable_tag_issues()
    issues.extend(tag_issues)
    wire_issues, wire_checked = _wire_issues()
    issues.extend(wire_issues)
    issues.extend(sanctioned_module_issues())
    issues.extend(scan_floor_issues())

    # DERIVED from the cases that actually run, and SCOPED to the map each one
    # was planted in. A flat set of bare key names is many-to-one and credited
    # a case in one map to an optional key in another (#679 review).
    case_keys = frozenset((c.scope(), c.key()) for c in DIVERGENCE_CASES)
    census_issues, optional_total = optional_key_issues(
        case_keys=case_keys, direct_keys=TRASH_ENTRY_DIRECT_KEYS
    )
    issues.extend(census_issues)
    issues.extend(dispatch_totality_issues())

    lines = [
        f"PASS 1: {len(DIVERGENCE_CASES)} measured acceptance divergences, each rejected",
        f"PASS 1a/1b: every committed base re-encodes byte-identically and all "
        f"{len(DIVERGENCE_CASES)} plants are distinct",
        f"PASS 1c: {wire_checked} wire/ integer position(s) reject a bool "
        f"(wire/vault_toml 6, wire/card 2)",
        f"PASS 2: {len({(c.target, c.position) for c in DIVERGENCE_CASES})} "
        f"control bodies accepted (the decoder discriminates)",
        f"PASS 2b: {trash_checked} codec/trash_entry.py position(s) rejected, "
        f"plus the all-valid control",
        f"PASS 2c: {tag_checked} trash_entry shareable-tag body(ies) "
        f"rejected as rule 4, not RecursionError (#685)",
        f"PASS 3: {scanned_module_count()} codec/ modules scanned (floor "
        f"{MIN_SCANNED_CODEC_MODULES}), none writes "
        f"`isinstance(..., int)` outside integer_rules.py",
        f"PASS 4: {optional_total} optional key(s) across {len(KEY_SET_PAIRS)} paired "
        f"key sets, each covered (expected {EXPECTED_OPTIONAL_KEY_COUNT})",
        "PASS 4b: record.py's wire-order dispatches have an arm for every declared key",
    ]
    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
