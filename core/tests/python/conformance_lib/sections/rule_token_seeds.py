"""Section RTS -- every committed single-fault seed for a token-compared
`block_file` or `record` target is rejected with the rule its file name
says, in this package as in Rust (#641).

WHAT THIS PINS.  `core/tests/rule_token_seeds.rs` generates one seed per
`(token, shape)` row, binds each committed file's BYTES to its row, and
requires the Rust decoder to name the file's token.  This section is the
Python half of the same binding: every `<token>__<shape>.bin` must be
REJECTED -- a verdict, never an `error` -- with exactly `<token>`, through
`diff_replay.replay_bytes`, the very function the differential replay's
worker calls.  So every committed seed is a strict cross-language comparison
in its own right, in the blocking `clean-room conformance` job, independent
of `differential_replay.rs`.

WHY IDENTITY TOO (check 1).  Label binding reaches only the classes some seed
exercises.  Section RTV's check 1 records why the expected token is written
out rather than read off the class: membership in the vocabulary is
satisfied by any of the seventeen.

WHY FLOORS (check 3) AND AN EXPECTED TOKEN SET (check 4).  An emptied
directory satisfies check 2 vacuously, and a directory whose seeds were all
relabelled onto one token satisfies checks 2 and 3.
"""

from __future__ import annotations

from pathlib import Path

from conformance_lib import fixtures
from conformance_lib.diff_replay import replay_bytes
from conformance_lib.wire import envelope_rules

# Mirrors `rule_token_seeds_helpers::LABEL_SEPARATOR`.
LABEL_SEPARATOR = "__"

# Per target: the minimum number of committed labelled seeds, and the exact
# set of tokens those seeds must name between them.
_TARGETS: dict[str, tuple[int, frozenset[str]]] = {
    "block_file": (
        15,
        frozenset(
            {"container_malformed", "unsupported_version", "array_sort_order", "repeated_array_value"}
        ),
    ),
}

# Every typed class this slice adds, with the token written out.
_TOKENED_CLASSES: tuple[tuple[type, str], ...] = (
    (envelope_rules.UnsupportedEnvelopeVersion, "unsupported_version"),
    (envelope_rules.EnvelopeSortOrder, "array_sort_order"),
    (envelope_rules.EnvelopeRepeatedValue, "repeated_array_value"),
)


def _labelled_seeds(target: str) -> list[Path]:
    directory = fixtures.fuzz_seed_dir(target)
    return sorted(p for p in directory.iterdir() if p.is_file() and LABEL_SEPARATOR in p.name)


def _label_token(path: Path) -> str:
    return path.name.split(LABEL_SEPARATOR, 1)[0]


def _identity_issues() -> list[str]:
    issues = []
    for cls, want in _TOKENED_CLASSES:
        got = getattr(cls, "token", None)
        if got != want:
            issues.append(f"{cls.__name__} carries token {got!r}, this section expects {want!r}")
    return issues


def _seed_issues(target: str, floor: int, want_tokens: frozenset[str]) -> tuple[list[str], str]:
    try:
        seeds = _labelled_seeds(target)
    except OSError as exc:
        return [f"{target}: cannot list seeds: {type(exc).__name__}: {exc}"], f"{target}: unlisted"
    issues = []
    for path in seeds:
        want = _label_token(path)
        verdict = replay_bytes(target, path.read_bytes()).verdict
        if verdict.get("status") != "reject":
            issues.append(f"{target}/{path.name}: expected a rejection naming {want!r}, got {verdict}")
        elif verdict.get("rule") != want:
            issues.append(
                f"{target}/{path.name}: Python named {verdict.get('rule')!r}, the file name says "
                f"{want!r} ({verdict.get('error_class')}: {verdict.get('detail')})"
            )
    if len(seeds) < floor:
        issues.append(f"{target}: only {len(seeds)} labelled seeds, floor is {floor}")
    named = {_label_token(p) for p in seeds}
    if named != want_tokens:
        issues.append(
            f"{target}: the seeds name {sorted(named)}, this section expects {sorted(want_tokens)}"
        )
    return issues, f"{target}: {len(seeds)} labelled seeds covering {len(named)} tokens"


def section_rule_token_seeds() -> tuple[bool, list[str]]:
    issues = _identity_issues()
    lines = [f"PASS 1: {len(_TOKENED_CLASSES)} typed classes carry exactly their expected token"]
    for target, (floor, want_tokens) in _TARGETS.items():
        target_issues, summary = _seed_issues(target, floor, want_tokens)
        issues.extend(target_issues)
        lines.append(f"PASS 2-4: {summary}, each rejected with its file name's token")
    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
