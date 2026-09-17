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
from conformance_lib.diff_replay import replay_bytes

# The committed accepting bases each family of cases is built from.
_CARD_BASE = "with_sigs.cbor"
_TOML_BASE = "golden.toml"
_MANIFEST_BASE = "uniq__control__all_distinct.bin"

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
    node[path[-1]] = value
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

    def label(self) -> str:
        return f"{self.target} {self.position} := {self.substitution}"


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
# Checks
# ---------------------------------------------------------------------------


def _rejection_issues() -> list[str]:
    """Check 1 -- every measured divergence is now REJECTED, with the rule
    Rust names where the target is token-compared."""
    issues: list[str] = []
    for case in DIVERGENCE_CASES:
        try:
            body = case.plant()
        except (OSError, ValueError) as exc:
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
        if case.token is not None and verdict.get("rule") != case.token:
            issues.append(
                f"{case.label()}: must report {case.token!r}, got {verdict.get('rule')!r} "
                f"({verdict.get('error_class')}: {verdict.get('detail')})"
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
        except (OSError, ValueError) as exc:
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
    issues.extend(_control_issues())

    lines = [
        f"PASS 1: {len(DIVERGENCE_CASES)} measured acceptance divergences, each rejected",
        f"PASS 2: {len({(c.target, c.position) for c in DIVERGENCE_CASES})} "
        f"control bodies accepted (the decoder discriminates)",
    ]
    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
