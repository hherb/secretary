"""Section RTV -- the rule-token vocabulary agrees with Rust's, and every
manifest-body rejection the committed corpus REACHES carries one (#634).

WHAT THIS PINS, AND WHAT IT DOES NOT.  It pins the SPELLINGS and the
phase-dependence flags against the same JSON fixture
`core/src/vault/manifest/token/tests/vocabulary.rs` checks, so the two languages cannot
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
is narrower than the one this docstring used to carry -- and narrower again
than the version before this one, whose three counts were each measured and
each too small.  THREE modules on `py_decode_manifest`'s own import path
raise untokened: `codec/scanner.py` (18 bare `raise ValueError`
well-formedness sites, out of 19 grep hits, one of which is prose),
`codec/manifest_schema.py` (9, FOUR of them the NESTED twins of top-level
sites that DID get a typed class -- non-text key at `:148`/`:244` and
missing required field at `:163`/`:269`, two per entry-map parser), and
`codec/manifest_encode.py` (3), which is imported at `manifest_decode.py:17`
and CALLED for the §4.3 step-4 re-encode, so its refusals are on the decode
path even though it is an encoder.  FIVE of the seventeen vocabulary rows
have no Python producer at all: `malformed_cbor`, `encoder_refusal`,
`aead_failure`, `signature_invalid` and `internal_error` -- the last three
because `py_decode_manifest_file` is a wire parse that performs no AEAD or
signature verification.  This is
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
# these carries EXACTLY the token named beside it; it asserts nothing about
# classes that are not listed.
#
# The expected token is written out here rather than read off the class,
# because until #645's review check 1 asked only whether the token was
# somewhere IN the vocabulary.  Membership is satisfied by any of the
# seventeen, so `MissingRequiredField.token = "wrong_type"` -- a plausible
# copy-paste, since `NonTextMapKey` and `WrongFieldType` legitimately DO
# share `"wrong_type"` -- passed check 1, passed check 3, passed every Rust
# test, and was caught only by `differential_replay.rs`, which runs in no CI
# workflow (#647).  Identity is what makes this section a pin.
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
# WHAT THIS TUPLE CANNOT DO, AND WHAT NOW COVERS IT.  Being hand-declared, it
# cannot by itself notice a class that was never added -- check 1 iterates the
# tuple, so an omission is an ABSENCE and not a failure.  Check 1b closes that
# direction by DISCOVERING `ManifestRejection`'s subclasses and requiring the
# two sets to be equal, the two-way parity Section REG uses for the section
# registry.  What neither covers is a tokened class raised from some other
# module and never subclassed here; the check for that is check 3, which drives
# the real decoder over the committed corpus, and it catches only what that
# corpus reaches.
_TOKENED_CLASSES: tuple[tuple[type, str], ...] = (
    (manifest_rules.TrailingBytesAfterMap, "non_canonical_unclassified"),
    (manifest_rules.NonTextMapKey, "wrong_type"),
    (manifest_rules.MissingRequiredField, "missing_field"),
    (manifest_rules.WrongFieldType, "wrong_type"),
    (manifest_rules.IntegerOutOfRange, "integer_out_of_range"),
    (manifest_rules.UnsupportedVersion, "unsupported_version"),
    (manifest_rules.RepeatedArrayValue, "repeated_array_value"),
)

# The tokens the committed corpus actually reaches, as a SET.
#
# Check 3 required every rejection to carry a vocabulary token and then threw
# the observed set away, printing its size and asserting nothing about it, so
# a Python side that collapsed every manifest rejection onto one token passed.
# That is the `_HASH_SEEDS = ("0",)` shape recorded in CLAUDE.md: a figure
# computed, printed, and never compared.  Six of the seventeen tokens are
# reachable from `core/fuzz/seeds/manifest_body/`; the other eleven need
# bodies the corpus does not hold, which is why this is an equality against a
# named set rather than a count.
_CORPUS_TOKENS = frozenset(
    {
        "array_sort_order",
        "non_canonical_unclassified",
        "repeated_array_value",
        "rule2_indefinite_length",
        "rule3_non_shortest_form",
        "rule4_tag_or_float",
    }
)


def _vocabulary() -> dict:
    """The shared token table, or a raise carrying a readable reason.

    Both this and `_corpus_bodies` are called from `section_rule_token_vocabulary`
    inside a `try`, because `conformance.py`'s `main()` wraps no section call:
    a `FileNotFoundError` from a moved fixture, or a `KeyError` from a malformed
    one, escaped as a traceback with no `FAIL:` line and took Sections RC, DET
    and REG down with it, RTV being registered ahead of all three.  CLAUDE.md
    records that exact defect being fixed for Section MPR; this section did not
    adopt the pattern until #645's review.
    """
    path = fixtures.test_data_dir() / "rule_token_vocabulary.json"
    doc = json.loads(path.read_text())
    tokens = doc.get("tokens")
    if not isinstance(tokens, dict) or not tokens:
        raise ValueError(f"{path.name}: `tokens` is missing, empty or not an object")
    return tokens


def _corpus_bodies() -> list:
    seeds = fixtures.test_data_dir().parents[1] / "fuzz" / "seeds" / "manifest_body"
    if not seeds.is_dir():
        raise FileNotFoundError(f"manifest_body seed directory not found: {seeds}")
    return sorted(p for p in seeds.iterdir() if p.is_file() and p.name != ".gitkeep")


def section_rule_token_vocabulary() -> tuple[bool, list[str]]:
    lines: list[str] = []
    issues: list[str] = []

    # A missing fixture or a moved seed directory is one section's FAIL line,
    # never a traceback out of `main()` that would skip RC, DET and REG.
    try:
        vocab = _vocabulary()
        bodies = _corpus_bodies()
    except (OSError, ValueError, KeyError) as exc:
        return (False, [f"  ISSUE: cannot load RTV inputs: {type(exc).__name__}: {exc}"])

    # --- check 1: every declared class carries the token named for it ------
    if not _TOKENED_CLASSES:
        issues.append("_TOKENED_CLASSES is empty, so check 1 compares nothing")
    for cls, want in _TOKENED_CLASSES:
        token = getattr(cls, "token", None)
        if not token:
            issues.append(f"{cls.__name__} carries no token")
        elif token not in vocab:
            issues.append(f"{cls.__name__} carries {token!r}, absent from the shared vocabulary")
        elif token != want:
            issues.append(
                f"{cls.__name__} carries {token!r}, but this section expects {want!r} "
                "-- membership in the vocabulary is not enough, the rule must be the "
                "right one"
            )
    lines.append(
        f"PASS 1: {len(_TOKENED_CLASSES)} declared classes carry exactly their expected token"
    )

    # --- check 1b: the declared set is every subclass, both directions -----
    declared = {cls for cls, _ in _TOKENED_CLASSES}
    discovered = set(manifest_rules.ManifestRejection.__subclasses__())
    if declared != discovered:
        missing = sorted(c.__name__ for c in discovered - declared)
        extra = sorted(c.__name__ for c in declared - discovered)
        issues.append(
            "the declared class table is not every ManifestRejection subclass: "
            f"undeclared {missing}, declared-but-absent {extra}"
        )
    lines.append(
        f"PASS 1b: {len(discovered)} ManifestRejection subclasses, all declared with a token"
    )

    # --- check 2: the phase-dependent set is the spec's -------------------
    # Hard-coded rather than read from the fixture, so an edit to the fixture
    # alone cannot redefine what this reader believes vault-format §4.2 says.
    # The Rust side pins the same set against its own enum; the fixture is
    # what makes the two comparable.
    #
    # Note what this set is and is not.  It is the set of tokens whose ORDER
    # §4.2 leaves free.  It is NOT a statement that `tokens_agree` tolerates
    # only pairs §4.2 frees: that predicate is per-token, so it tolerates 58
    # of the 136 unequal pairs, four groups of which §4.2 does not license.
    # `RuleToken::is_phase_dependent`'s LIMITS block enumerates them and #646
    # tracks narrowing the predicate.
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

    # --- check 4: the observed tokens are the ones the corpus reaches ------
    # An equality, not a count: a count is satisfied by any six tokens, and
    # what this exists to catch is a raise site re-pointed at a different but
    # equally valid token, which leaves the count alone.
    if seen_tokens != _CORPUS_TOKENS:
        missing = sorted(_CORPUS_TOKENS - seen_tokens)
        extra = sorted(seen_tokens - _CORPUS_TOKENS)
        issues.append(
            "the tokens this corpus produces moved: "
            f"missing {missing}, unexpected {extra}. Either a raise site changed "
            "its rule, or the corpus did -- both need a deliberate edit here."
        )
    lines.append(
        f"PASS 3: {rejected}/{len(bodies)} bodies rejected, "
        f"{rejected - untokened} carrying a vocabulary token, "
        f"{len(seen_tokens)} distinct tokens, matching the expected set"
    )

    for issue in issues:
        lines.append(f"  ISSUE: {issue}")
    return (not issues, lines)
