"""Section RTV -- the rule-token vocabulary agrees with Rust's, and every
manifest-body rejection the committed corpus REACHES carries one (#634).

WHAT THIS PINS, AND WHAT IT DOES NOT.  It pins the SPELLINGS and the
phase-dependence flags against the same JSON fixture
`core/src/vault/manifest/token/tests.rs` checks, so the two languages cannot
drift onto different words -- a drift that would make every cross-language
comparison a mismatch, or worse, a tolerated one.  It does NOT check that the
two implementations assign the same token to the same bytes; that is
`differential_replay.rs`'s job, and it runs only under the
`differential-replay` Cargo feature.

WHY A COVERAGE FLOOR.  Checks 1 and 2 alone pass on a reader that raises
tokened exceptions nowhere: a vocabulary agreeing with a vocabulary is
vacuous.  Check 3 drives the real decoder over the committed corpus and
requires every rejection to carry a token, which is what makes the pin
non-vacuous.

WHAT "EVERY REJECTION" MEANS HERE -- it is the corpus's reach, not the
decoder's.  Token coverage on this side is NOT total, and the honest sentence
is narrower than the one this docstring used to carry.  Two modules on
`py_decode_manifest`'s own import path raise untokened: `codec/scanner.py`
(18 bare `raise ValueError` well-formedness sites) and
`codec/manifest_schema.py` (9, two of them the NESTED twins of top-level
sites that DID get a typed class).  Two vocabulary rows have no Python
producer at all -- `malformed_cbor` and `encoder_refusal`.  This is
fail-closed and loud rather than silent: a body reaching one of those sites
emits `"rule": null`, which `differential_replay.rs` records as a HARNESS
FAILURE for a token-compared target, never as agreement.  Measured: a
40-byte prefix of `top__control_canonical.bin` rejects with
`ValueError("string length 13 overruns buffer at offset 37")` and
`"rule": null`.  So the posture is right and the coverage is partial; do not
restate the coverage as complete.
"""

from __future__ import annotations

import json

from conformance_lib import fixtures
from conformance_lib.codec import manifest_rules
from conformance_lib.codec.manifest_decode import py_decode_manifest
from conformance_lib.rejection import _REJECTION_EXCEPTIONS

# The `manifest_rules` classes, and only those: a hand-declared SAMPLE, not a
# census of what `py_decode_manifest` can raise.  Check 1 asserts each of
# these carries a token that is in the shared vocabulary; it asserts nothing
# about classes that are not listed.
#
# FOUR tokened classes reachable from `py_decode_manifest` are deliberately
# absent, because they are tokened at their own raise sites in other modules:
# `manifest_decode.ArraySortOrderViolation`, `manifest_decode.NonCanonicalBody`,
# `scanner.NonCanonicalItem` and `scanner.DuplicateMapKey`.
# `cursor.ParseError` also carries a token but is NOT reachable from
# `py_decode_manifest` -- nothing on that function's import path imports
# `cursor`; it belongs to the wire ENVELOPE decoders, which is why its token
# is `container_malformed`.
#
# WHAT THIS TUPLE CANNOT DO.  Because it is hand-declared rather than
# discovered, a class added WITHOUT a token is an ABSENCE here and not a
# failure -- check 1 iterates this tuple, so a class never added to it is
# never looked at.  The check that catches an untokened rejection is check 3,
# which drives the real decoder over the committed corpus, and it catches
# only what that corpus reaches.
_TOKENED_CLASSES = (
    manifest_rules.TrailingBytesAfterMap,
    manifest_rules.NonTextMapKey,
    manifest_rules.MissingRequiredField,
    manifest_rules.WrongFieldType,
    manifest_rules.IntegerOutOfRange,
    manifest_rules.UnsupportedVersion,
    manifest_rules.RepeatedArrayValue,
)


def _vocabulary() -> dict:
    path = fixtures.test_data_dir() / "rule_token_vocabulary.json"
    return json.loads(path.read_text())["tokens"]


def _corpus_bodies() -> list:
    seeds = fixtures.test_data_dir().parents[1] / "fuzz" / "seeds" / "manifest_body"
    return sorted(p for p in seeds.iterdir() if p.is_file() and p.name != ".gitkeep")


def section_rule_token_vocabulary() -> tuple[bool, list[str]]:
    lines: list[str] = []
    issues: list[str] = []
    vocab = _vocabulary()

    # --- check 1: every class token is a real token -----------------------
    for cls in _TOKENED_CLASSES:
        token = getattr(cls, "token", None)
        if not token:
            issues.append(f"{cls.__name__} carries no token")
        elif token not in vocab:
            issues.append(f"{cls.__name__} carries {token!r}, absent from the shared vocabulary")
    lines.append(f"PASS 1: {len(_TOKENED_CLASSES)} declared classes carry vocabulary tokens")

    # --- check 2: the phase-dependent set is the spec's -------------------
    # Hard-coded rather than read from the fixture, so an edit to the fixture
    # alone cannot redefine what this reader believes vault-format §4.2 says.
    # The Rust side pins the same set against its own enum; the fixture is
    # what makes the two comparable.
    want_phase_dependent = {
        "array_sort_order",
        "non_canonical_unclassified",
        "rule2_indefinite_length",
        "rule3_non_shortest_form",
    }
    got_phase_dependent = {k for k, v in vocab.items() if v.get("phase_dependent")}
    if got_phase_dependent != want_phase_dependent:
        issues.append(
            "phase-dependent set disagrees with vault-format §4.2: "
            f"fixture has {sorted(got_phase_dependent)}, §4.2 says {sorted(want_phase_dependent)}"
        )
    lines.append(f"PASS 2: {len(want_phase_dependent)} phase-dependent tokens match §4.2")

    # --- check 3: the coverage floor --------------------------------------
    bodies = _corpus_bodies()
    if len(bodies) < 20:
        issues.append(
            f"corpus floor: only {len(bodies)} manifest_body seeds found; "
            "a shrunken corpus makes checks 1 and 2 vacuous"
        )
    rejected = 0
    untokened = 0
    seen_tokens: set[str] = set()
    for path in bodies:
        try:
            py_decode_manifest(path.read_bytes())
        except _REJECTION_EXCEPTIONS as exc:
            rejected += 1
            token = manifest_rules.token_for(exc)
            if token is None:
                untokened += 1
                issues.append(
                    f"{path.name}: rejected by {type(exc).__name__} carrying no rule token"
                )
            elif token not in vocab:
                issues.append(f"{path.name}: token {token!r} absent from the shared vocabulary")
            else:
                seen_tokens.add(token)
    if rejected == 0:
        issues.append("coverage floor: no corpus body was rejected at all")
    lines.append(
        f"PASS 3: {rejected}/{len(bodies)} bodies rejected, "
        f"{rejected - untokened} carrying a vocabulary token, "
        f"{len(seen_tokens)} distinct tokens observed"
    )

    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
